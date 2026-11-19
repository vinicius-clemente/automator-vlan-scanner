#!/usr/bin/env python3
import os
import re
import sys
import socket
import threading
import queue
import csv
from datetime import datetime
from dataclasses import dataclass, field

import paramiko
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box
from rich.rule import Rule
from rich.live import Live

console = Console()
STOP_EVENT = threading.Event()
VLAN_DB = os.path.expanduser("~/.vlans.csv")


@dataclass
class VlanInfo:
    vlan_id: str
    name: str
    status: str = ""
    ports: str = ""
    mac_count: int = 0
    arp_count: int = 0
    svi_exists: bool = False
    svi_ip: str = ""
    port_channels: list[str] = field(default_factory=list)
    standalone_ports: list[str] = field(default_factory=list)
    po_member_ports: list[str] = field(default_factory=list)


@dataclass
class SwitchResult:
    host: str
    hostname: str = ""
    vlans: list[VlanInfo] = field(default_factory=list)
    po_members: dict = field(default_factory=dict)
    erro: str = ""
    sucesso: bool = False


def _ssh_exec(host: str, user: str, password: str,
              cmd: str, timeout: int = 15) -> tuple[int, str, str]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password,
                   timeout=timeout, look_for_keys=False, allow_agent=False)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    stdin.close()
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    client.close()
    return rc, output, err


def _normalize_output(output: str) -> str:
    lines = output.split("\n")
    normalized = []
    buf = ""
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^\d", stripped):
            if buf:
                normalized.append(buf)
            buf = stripped
        else:
            if buf:
                buf += " " + stripped
    if buf:
        normalized.append(buf)
    return "\n".join(normalized)


def _parse_vlans(output: str) -> list[VlanInfo]:
    vlans: dict[str, VlanInfo] = {}
    output = _normalize_output(output)

    for line in output.split("\n"):
        m = re.match(r"^(\d{1,4})\s+(\S[\w\-_. ]+?)\s+(active|act/unsup|suspended)\s+(.*)", line)
        if m:
            vid = m.group(1).strip()
            if vid in ("1002", "1003", "1004", "1005"):
                continue
            vlans[vid] = VlanInfo(vid, m.group(2).strip(), m.group(3).strip(), m.group(4).strip())
            continue
        m = re.match(r"\s*(\d+)\s+(\S[\w\-_. ]+?)\s+(Untagged|Tagged|Static)\s+(.*)", line)
        if m:
            v = VlanInfo(m.group(1).strip(), m.group(2).strip(),
                         m.group(3).strip().lower(), m.group(4).strip())
            vlans[v.vlan_id] = v
            continue
        m = re.match(r"\s*(\d+)\s+(\S[\w\-_. ]+?)\s+(\S+)\s+(Untagged|Tagged)\s+(.*)", line)
        if m:
            v = VlanInfo(m.group(1).strip(), m.group(2).strip(),
                         m.group(4).strip().lower(), m.group(5).strip())
            vlans[v.vlan_id] = v
    return list(vlans.values())


def _parse_mac_count(output: str) -> int:
    count = 0
    for line in output.split("\n"):
        if re.search(r'(?:[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5})', line):
            count += 1
    return count


def _parse_port_channel_summary(output: str) -> dict:
    """Parse 'show port-channel summary' output.
    Returns {Po_name: [member_port, ...]}"""
    members = {}
    for line in output.split("\n"):
        m = re.match(r"^\s*(\d+)\s+(Po\d+)\([^)]+\)\s+\S+\s+\S+(?:\s+(.*))?", line)
        if m:
            po_name = m.group(2)
            member_part = m.group(3)
            if member_part and member_part.strip() and member_part.strip() != "--":
                port_list = []
                for part in member_part.split():
                    port = re.sub(r"\([^)]*\)$", "", part)
                    if port and not re.match(r"^-+$", port):
                        port_list.append(port)
                if port_list:
                    members[po_name] = port_list
    return members


def _classify_vlan_ports(ports_str: str, po_members: dict) -> tuple[list[str], list[str], list[str]]:
    """Classify VLAN ports into port-channels, standalone physical, and Po member ports.
    Returns (port_channels, standalone_physical, po_member_ports)"""
    if not ports_str.strip():
        return [], [], []

    all_ports = [p.strip() for p in re.split(r"[, ]+", ports_str.strip()) if p.strip()]

    po_set = set()
    for po, membros in po_members.items():
        for m in membros:
            po_set.add(m)

    po_channels = [p for p in all_ports if p.startswith("Po")]
    po_member_ports = [p for p in all_ports if p not in po_channels and p in po_set]
    standalone = [p for p in all_ports if p not in po_channels and p not in po_set]

    return po_channels, standalone, po_member_ports


def _format_classified_ports(po_channels: list[str], standalone: list[str], po_member_ports: list[str]) -> str:
    """Format classified ports for display, marking Po members as dimmed."""
    parts = []
    if po_channels:
        parts.append(f"[bold cyan]{', '.join(po_channels)}[/bold cyan]")
    if standalone:
        parts.append(f"[green]{', '.join(standalone)}[/green]")
    if po_member_ports:
        parts.append(f"[dim](membros Po: {', '.join(po_member_ports)})[/dim]")
    return " ".join(parts)


def _scan_switch(host: str, user: str, password: str,
                 result_queue: queue.Queue, vlan_filter: str = ""):
    res = SwitchResult(host=host)
    try:
        if vlan_filter:
            cmds = [
                f"show vlan id {vlan_filter}",
                f"show vlan {vlan_filter}",
            ]
            out = ""
            for cmd in cmds:
                rc, out, _ = _ssh_exec(host, user, password, cmd, 15)
                if rc == 0 and out.strip():
                    break
            if rc != 0 or not out.strip():
                res.erro = f"VLAN {vlan_filter} nao encontrada"
                result_queue.put(res)
                return
            res.vlans = _parse_vlans(out)

            if res.vlans:
                mac_cmds = [
                    f"show mac address-table vlan {vlan_filter}",
                    f"show mac-address-table vlan {vlan_filter}",
                ]
                for mac_cmd in mac_cmds:
                    rc_mac, out_mac, _ = _ssh_exec(host, user, password, mac_cmd, 15)
                    if rc_mac == 0 and out_mac.strip():
                        for v in res.vlans:
                            v.mac_count = _parse_mac_count(out_mac)
                        break
                arp_cmds = [
                    f"show ip arp vlan {vlan_filter}",
                ]
                for arp_cmd in arp_cmds:
                    rc_arp, out_arp, _ = _ssh_exec(host, user, password, arp_cmd, 10)
                    if rc_arp == 0 and out_arp.strip():
                        m_arp = re.search(r'Total number of entries:\s*(\d+)', out_arp)
                        if m_arp:
                            arp_total = int(m_arp.group(1))
                            for v in res.vlans:
                                v.arp_count = max(0, arp_total - 1)
                        break
            res.sucesso = True
        else:
            rc, out, _ = _ssh_exec(host, user, password, "show vlan brief", 15)
            if rc != 0 or not out.strip():
                rc, out, _ = _ssh_exec(host, user, password, "show vlan", 15)
            if rc != 0 or not out.strip():
                res.erro = "Nenhum comando VLAN funcionou"
                result_queue.put(res)
                return
            res.vlans = _parse_vlans(out)
            res.sucesso = True

        if res.sucesso and res.vlans:
            try:
                rc_po, out_po, _ = _ssh_exec(host, user, password, "show port-channel summary", 15)
                if rc_po == 0 and out_po.strip():
                    res.po_members = _parse_port_channel_summary(out_po)
            except Exception:
                res.po_members = {}

            if vlan_filter:
                try:
                    rc_svi, out_svi, _ = _ssh_exec(host, user, password, f"show interface vlan {vlan_filter}", 8)
                    svi_exists = rc_svi == 0 and "Vlan" in out_svi[:200]
                except Exception:
                    svi_exists = False
                if svi_exists:
                    try:
                        rc_run, out_run, _ = _ssh_exec(host, user, password, f"show running-config interface vlan {vlan_filter}", 10)
                        if rc_run == 0:
                            m_ip = re.search(r"ip address ([\d.]+/\d+)", out_run)
                            svi_ip = m_ip.group(1) if m_ip else ""
                        else:
                            svi_ip = ""
                    except Exception:
                        svi_ip = ""
                else:
                    svi_ip = ""
            else:
                svi_exists = False
                svi_ip = ""

            for v in res.vlans:
                po, std, membros = _classify_vlan_ports(v.ports, res.po_members)
                v.port_channels = po
                v.standalone_ports = std
                v.po_member_ports = membros
                if vlan_filter:
                    v.svi_exists = svi_exists
                    v.svi_ip = svi_ip

    except paramiko.AuthenticationException:
        res.erro = "Auth falhou"
    except paramiko.SSHException as e:
        res.erro = f"SSH: {e}"
    except socket.timeout:
        res.erro = "Timeout"
    except socket.gaierror:
        res.erro = "Hostname invalido"
    except Exception as e:
        res.erro = str(e)[:120]

    result_queue.put(res)
    STOP_EVENT.wait(0.01)


def _tabela_geral(resultados: list[SwitchResult], total: int, processados: int) -> Table:
    t = Table(box=box.SQUARE, border_style="cyan",
              title=f"[bold]SCAN VLAN - {processados}/{total}[/bold]")
    t.add_column("Host", width=18)
    t.add_column("Status", width=8)
    t.add_column("VLANs", justify="right", width=5)
    t.add_column("MACs", justify="right", width=5)
    t.add_column("ARP", justify="right", width=5)
    t.add_column("Erro", width=32)
    for r in resultados:
        if r.erro:
            t.add_row(r.host, "[red]ERRO[/red]", "0", "0", "0", r.erro[:32])
        else:
            total_macs = sum(v.mac_count for v in r.vlans)
            mac_str = f"[green]{total_macs}[/green]" if total_macs > 0 else "[dim]0[/dim]"
            total_arp = sum(v.arp_count for v in r.vlans)
            arp_str = f"[green]{total_arp}[/green]" if total_arp > 0 else "[dim]0[/dim]"
            t.add_row(r.host, "[green]OK[/green]", str(len(r.vlans)), mac_str, arp_str, "")
    return t


def _format_ports_display(v: VlanInfo) -> str:
    parts = []
    if v.port_channels:
        parts.append(f"[bold cyan]{' '.join(v.port_channels)}[/bold cyan]")
    if v.standalone_ports:
        parts.append(f"[green]{' '.join(v.standalone_ports)}[/green]")
    if v.po_member_ports:
        parts.append(f"[dim](Po: {' '.join(v.po_member_ports)})[/dim]")
    if not parts:
        return "[dim]--[/dim]"
    return " ".join(parts)


def _tabela_detalhada(resultados: list[SwitchResult], filtro_vlan: str = "") -> Table:
    t = Table(box=box.SQUARE, border_style="bright_green",
              title="[bold]VLANS POR SWITCH[/bold]")
    t.add_column("Host", width=18)
    t.add_column("VLAN ID", width=7)
    t.add_column("Nome", width=20)
    t.add_column("Status", width=9)
    t.add_column("SVI", width=4)
    t.add_column("IP", width=16)
    t.add_column("Port-Channels", width=24)
    t.add_column("Fisicas Soltas", width=22)
    t.add_column("MACs", justify="right", width=5)
    t.add_column("ARP", justify="right", width=5)
    for r in resultados:
        if not r.sucesso:
            continue
        vlans = [v for v in r.vlans if not filtro_vlan or v.vlan_id == filtro_vlan]
        for v in vlans:
            cor = "yellow" if v.port_channels or v.standalone_ports else "dim"
            svi_str = "[red]sim[/red]" if v.svi_exists else "[dim]nao[/dim]"
            ip_str = f"[yellow]{v.svi_ip}[/yellow]" if v.svi_ip else "[dim]--[/dim]"
            pc_str = f"[bold cyan]{' '.join(v.port_channels)}[/bold cyan]" if v.port_channels else "[dim]--[/dim]"
            st_str = f"[green]{' '.join(v.standalone_ports)}[/green]" if v.standalone_ports else "[dim]--[/dim]"
            if v.po_member_ports:
                st_str += f"\n[dim](membros Po: {' '.join(v.po_member_ports)})[/dim]"
            mac_str = f"[green]{v.mac_count}[/green]" if v.mac_count > 0 else "[dim]0[/dim]"
            arp_str = f"[green]{v.arp_count}[/green]" if v.arp_count > 0 else "[dim]0[/dim]"
            t.add_row(f"[bold]{r.host}[/bold]", f"[cyan]{v.vlan_id}[/cyan]", v.name,
                      f"[{cor}]{v.status}[/{cor}]", svi_str, ip_str, pc_str, st_str, mac_str, arp_str)
    return t


def show_banner():
    console.clear()
    console.print("""
[bold cyan]
 █████   █████ █████         █████████   ██████   █████             █████████    █████████    █████████   ██████   █████ ██████   █████ ██████████ ███████████
░░███   ░░███ ░░███         ███░░░░░███ ░░██████ ░░███             ███░░░░░███  ███░░░░░███  ███░░░░░███ ░░██████ ░░███ ░░██████ ░░███ ░░███░░░░░█░░███░░░░░███
 ░███    ░███  ░███        ░███    ░███  ░███░███ ░███            ░███    ░░░  ███     ░░░  ░███    ░███  ░███░███ ░███  ░███░███ ░███  ░███  █ ░  ░███    ░███
 ░███    ░███  ░███        ░███████████  ░███░░███░███  ██████████░░█████████ ░███          ░███████████  ░███░░███░███  ░███░░███░███  ░██████    ░██████████
 ░░███   ███   ░███        ░███░░░░░███  ░███ ░░██████ ░░░░░░░░░░  ░░░░░░░░███░███          ░███░░░░░███  ░███ ░░██████  ░███ ░░██████  ░███░░█    ░███░░░░░███
  ░░░█████░    ░███      █ ░███    ░███  ░███  ░░█████             ███    ░███░░███     ███ ░███    ░███  ░███  ░░█████  ░███  ░░█████  ░███ ░   █ ░███    ░███
    ░░███      ███████████ █████   █████ █████  ░░█████           ░░█████████  ░░█████████  █████   █████ █████  ░░█████ █████  ░░█████ ██████████ █████   █████
     ░░░      ░░░░░░░░░░░ ░░░░░   ░░░░░ ░░░░░    ░░░░░             ░░░░░░░░░    ░░░░░░░░░  ░░░░░   ░░░░░ ░░░░░    ░░░░░ ░░░░░    ░░░░░ ░░░░░░░░░░ ░░░░░   ░░░░░

[bold white]
-----------------------------------------------------------------------------
SCANNER VLANS
Templates - CISCO NXOS/CATALYSTIC E HP/DELL
Autor - VINICIUS CLEMENTE
-----------------------------------------------------------------------------
[/bold white]
""")


def cabecalho(titulo: str):
    console.clear()
    console.print(Rule(style="cyan"))
    console.print(Align.center(Text(titulo, style="bold cyan", no_wrap=True)))
    console.print(Rule(style="cyan"))


def pausa():
    Prompt.ask("\n[dim]Pressione Enter para continuar[/dim]", default="")


def carregar_hosts(caminho: str) -> list[str]:
    hosts = []
    with open(caminho) as f:
        for linha in f:
            linha = linha.strip()
            if linha and not linha.startswith("#"):
                hosts.append(linha)
    return hosts


def exportar_csv(resultados: list[SwitchResult], caminho: str):
    with open(caminho, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "vlan_id", "vlan_name", "vlan_status",
                     "ports", "mac_count", "arp_count", "svi_exists", "svi_ip",
                     "port_channels", "standalone_ports", "po_member_ports"])
        for r in resultados:
            if not r.sucesso:
                w.writerow([r.host, "ERRO", r.erro, "", "", "", "", "", "", "", "", ""])
                continue
            for v in r.vlans:
                w.writerow([r.host, v.vlan_id, v.name, v.status,
                            v.ports, v.mac_count, v.arp_count, "sim" if v.svi_exists else "nao",
                            v.svi_ip,
                            " ".join(v.port_channels),
                            " ".join(v.standalone_ports),
                            " ".join(v.po_member_ports)])
    console.print(f"\n[green]CSV salvo: {caminho}[/green]")


def _executar_scan(hosts: list[str], user: str, password: str,
                   max_threads: int, vlan_filter: str = "") -> list[SwitchResult]:
    STOP_EVENT.clear()
    resultados: list[SwitchResult] = []
    q: queue.Queue = queue.Queue()

    def consumir():
        while True:
            try:
                resultados.append(q.get(timeout=0.1))
            except queue.Empty:
                if STOP_EVENT.is_set():
                    break

    consumer = threading.Thread(target=consumir, daemon=True)
    consumer.start()

    cabecalho(f"ESCANEANDO {len(hosts)} HOSTS..." +
              (f" [yellow](VLAN {vlan_filter})[/yellow]" if vlan_filter else ""))
    console.print(f"[dim]Threads: {max_threads}[/dim]")

    with Live(refresh_per_second=4, console=console) as live:
        for i in range(0, len(hosts), max_threads):
            if STOP_EVENT.is_set():
                break
            batch = hosts[i:i + max_threads]
            threads = []
            for h in batch:
                t = threading.Thread(target=_scan_switch, args=(h, user, password, q, vlan_filter), daemon=True)
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            live.update(_tabela_geral(resultados, len(hosts), min(i + max_threads, len(hosts))))

    STOP_EVENT.set()
    consumer.join()
    return resultados


def _exibir_resultados(resultados: list[SwitchResult], hosts: list[str]):
    sucessos = [r for r in resultados if r.sucesso]
    erros = [r for r in resultados if not r.sucesso]
    todas_vlans = set()
    for r in sucessos:
        for v in r.vlans:
            todas_vlans.add(v.vlan_id)

    console.clear()
    cabecalho("RESUMO")
    t = Table(box=box.SQUARE, border_style="green")
    t.add_column("Metrica", style="bold cyan", width=25)
    t.add_column("Valor")
    t.add_row("Total hosts", str(len(hosts)))
    t.add_row("Sucesso", f"[green]{len(sucessos)}[/green]")
    t.add_row("Erro", f"[red]{len(erros)}[/red]")
    t.add_row("VLANs unicas", str(len(todas_vlans)))
    total_macs = sum(v.mac_count for r in sucessos for v in r.vlans)
    t.add_row("Total MACs", f"[green]{total_macs}[/green]" if total_macs > 0 else "0")
    total_arp = sum(v.arp_count for r in sucessos for v in r.vlans)
    t.add_row("Total ARP", f"[green]{total_arp}[/green]" if total_arp > 0 else "0")
    console.print(t)

    if erros:
        console.print(f"\n[red]Falhas:[/red]")
        for r in erros:
            console.print(f"  {r.host} - {r.erro}")

    console.print()
    console.print(_tabela_geral(resultados, len(hosts), len(hosts)))
    console.print()
    if sucessos:
        console.print(_tabela_detalhada(sucessos))

    console.print()
    exportar_csv(resultados, f"vlan-scan-{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")


def _config_scan() -> tuple[list[str], str, str, int]:
    cabecalho("CONFIGURACAO DO SCAN")
    console.print(Panel(
        "[yellow]Arquivo[/yellow]: hostnames ou IPs, um por linha\n"
        "[yellow]Acesso[/yellow]: SSH (mesmo usuario/senha para todos)",
        border_style="cyan", title="SSH"
    ))

    default_file = "switches.txt"
    arquivo = Prompt.ask("[bold cyan]Arquivo com hosts[/bold cyan]", default=default_file)
    if not os.path.isfile(arquivo):
        console.print(f"[red]Arquivo nao existe: {arquivo}[/red]")
        pausa()
        return None

    hosts = carregar_hosts(arquivo)
    if not hosts:
        console.print("[red]Nenhum host no arquivo[/red]")
        pausa()
        return None
    console.print(f"[cyan]Total: {len(hosts)} hosts[/cyan]")

    user = Prompt.ask("[bold cyan]Usuario SSH[/bold cyan]")
    password = Prompt.ask("[bold cyan]Senha SSH[/bold cyan]", password=True)
    max_threads = int(Prompt.ask("[bold cyan]Threads[/bold cyan]", default="30"))

    return hosts, user, password, max_threads


def _validar(hosts, user, password, max_threads, vlan_filter):
    resultados = _executar_scan(hosts, user, password, max_threads, vlan_filter)
    _exibir_resultados(resultados, hosts)


def validar_uma_vlan():
    cfg = _config_scan()
    if not cfg:
        return
    hosts, user, password, max_threads = cfg

    vid = Prompt.ask("[bold cyan]VLAN ID[/bold cyan]")
    if not vid.isdigit() or not (1 <= int(vid) <= 4094):
        console.print("[red]VLAN invalida (1-4094)[/red]")
        pausa()
        return

    _validar(hosts, user, password, max_threads, vid)


def validar_multiplas_vlans():
    cfg = _config_scan()
    if not cfg:
        return
    hosts, user, password, max_threads = cfg

    entrada = Prompt.ask("[bold cyan]VLANs[/bold cyan] (ex: 100,200,300 ou 100-200)")
    vlans = []
    for parte in entrada.replace(" ", "").split(","):
        m = re.match(r"^(\d+)-(\d+)$", parte)
        if m:
            inicio, fim = int(m.group(1)), int(m.group(2))
            for v in range(inicio, fim + 1):
                if 1 <= v <= 4094:
                    vlans.append(str(v))
        elif parte.isdigit() and 1 <= int(parte) <= 4094:
            vlans.append(parte)

    if not vlans:
        console.print("[red]Nenhuma VLAN valida informada[/red]")
        pausa()
        return

    console.print(f"[cyan]Validando {len(vlans)} VLANs: {', '.join(vlans[:10])}{'...' if len(vlans) > 10 else ''}[/cyan]")

    todos_resultados = []
    for i, vid in enumerate(vlans, 1):
        cabecalho(f"VALIDANDO VLAN {vid} ({i}/{len(vlans)})")
        resultados = _executar_scan(hosts, user, password, max_threads, vid)
        todos_resultados.extend(resultados)

    _exibir_resultados(todos_resultados, hosts)


def validar_todas_vlans():
    cfg = _config_scan()
    if not cfg:
        return
    hosts, user, password, max_threads = cfg

    resultados = _executar_scan(hosts, user, password, max_threads)
    _exibir_resultados(resultados, hosts)


def reservar_vlan():
    cabecalho("RESERVAR VLAN")
    console.print(Panel(
        "[yellow]Integracao com vlan-manager[/yellow]\n"
        f"[dim]Banco: {VLAN_DB}[/dim]",
        border_style="cyan", title="Reserva"
    ))

    if not os.path.isfile(VLAN_DB):
        with open(VLAN_DB, "w") as f:
            f.write("vlan_id;nome;datacenter;status;estrutura_cliente\n")
        console.print(f"[dim]Arquivo criado: {VLAN_DB}[/dim]")

    vid = Prompt.ask("[bold cyan]VLAN ID (1-4094)[/bold cyan]")
    if not vid.isdigit() or not (1 <= int(vid) <= 4094):
        console.print("[red]VLAN invalida[/red]")
        pausa()
        return

    nome = Prompt.ask("[bold cyan]Nome[/bold cyan] (ex: ID-xxxx ou Cliente-Internet)")
    if not nome:
        console.print("[red]Nome obrigatorio[/red]")
        pausa()
        return

    dc = Prompt.ask("[bold cyan]Data Center[/bold cyan]", choices=["TB01", "TB02", "CTA"])

    cliente = Prompt.ask("[bold cyan]Estrutura/Cliente[/bold cyan] (ex: SVi, VCP)", default="-")

    with open(VLAN_DB, "r") as f:
        for linha in f:
            if linha.lower().startswith(f"{vid};") and dc in linha:
                console.print(f"[red]VLAN {vid} ja cadastrada em {dc}![/red]")
                pausa()
                return

    with open(VLAN_DB, "a") as f:
        f.write(f"{vid};{nome};{dc};reservada;{cliente}\n")

    console.print(f"\n[green]VLAN {vid} reservada em {dc} com sucesso![/green]")
    pausa()


def _ler_reservas() -> list[dict]:
    reservas = []
    if not os.path.isfile(VLAN_DB):
        return reservas
    with open(VLAN_DB) as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("vlan_id"):
                continue
            partes = linha.split(";")
            if len(partes) >= 5:
                reservas.append({
                    "vlan_id": partes[0],
                    "nome": partes[1],
                    "datacenter": partes[2],
                    "status": partes[3],
                    "cliente": partes[4],
                })
    return reservas


def listar_reservadas():
    cabecalho("VLANS RESERVADAS")
    reservas = _ler_reservas()
    if not reservas:
        console.print("[yellow]Nenhuma reserva encontrada[/yellow]")
        pausa()
        return

    t = Table(box=box.SQUARE, border_style="cyan")
    t.add_column("VLAN ID", style="bold cyan", width=8)
    t.add_column("Nome", width=28)
    t.add_column("DC", width=10)
    t.add_column("Status", width=12)
    t.add_column("Cliente", width=22)
    for r in reservas:
        cor_status = "green" if r["status"] == "reservada" else "yellow"
        t.add_row(r["vlan_id"], r["nome"], r["datacenter"],
                  f"[{cor_status}]{r['status']}[/{cor_status}]", r["cliente"])
    console.print(t)
    console.print(f"\n[dim]Total: {len(reservas)} reservas[/dim]")
    pausa()


def relatorio_reservas():
    cabecalho("RELATORIO DE RESERVAS")
    reservas = _ler_reservas()
    if not reservas:
        console.print("[yellow]Nenhuma reserva encontrada[/yellow]")
        pausa()
        return

    t = Table(box=box.SQUARE, border_style="green")
    t.add_column("Data Center", style="bold cyan", width=12)
    t.add_column("Total", justify="right", width=6)
    t.add_column("Reservadas", justify="right", width=10)
    t.add_column("Em uso", justify="right", width=8)
    for dc in sorted(set(r["datacenter"] for r in reservas)):
        dc_reservas = [r for r in reservas if r["datacenter"] == dc]
        total = len(dc_reservas)
        reservadas = len([r for r in dc_reservas if r["status"] == "reservada"])
        em_uso = len([r for r in dc_reservas if r["status"] == "em_uso"])
        t.add_row(dc, str(total), f"[green]{reservadas}[/green]", f"[yellow]{em_uso}[/yellow]")

    console.print(t)
    console.print(f"\n[dim]Total geral: {len(reservas)}[/dim]")
    pausa()


def marcar_em_uso():
    cabecalho("MARCAR COMO EM USO")
    if not os.path.isfile(VLAN_DB):
        console.print("[yellow]Nenhuma reserva encontrada[/yellow]")
        pausa()
        return

    vid = Prompt.ask("[bold cyan]VLAN ID[/bold cyan]")
    dc = Prompt.ask("[bold cyan]Data Center[/bold cyan]", choices=["TB01", "TB02", "CTA"])

    linhas = []
    achou = False
    with open(VLAN_DB, "r") as f:
        for linha in f:
            if re.match(rf"^{vid};.*;{dc};reservada;", linha):
                linha = linha.replace(";reservada;", ";em_uso;")
                achou = True
            linhas.append(linha)

    if not achou:
        console.print(f"[red]VLAN {vid} nao encontrada como reservada em {dc}[/red]")
        pausa()
        return

    with open(VLAN_DB, "w") as f:
        f.writelines(linhas)
    console.print(f"[green]VLAN {vid} marcada como em_uso em {dc}[/green]")
    pausa()


def liberar_vlan():
    cabecalho("LIBERAR VLAN")
    if not os.path.isfile(VLAN_DB):
        console.print("[yellow]Nenhuma reserva encontrada[/yellow]")
        pausa()
        return

    vid = Prompt.ask("[bold cyan]VLAN ID[/bold cyan]")
    dc = Prompt.ask("[bold cyan]Data Center[/bold cyan]", choices=["TB01", "TB02", "CTA"])

    linhas = []
    achou = False
    with open(VLAN_DB, "r") as f:
        for linha in f:
            if re.match(rf"^{vid};.*;{dc};", linha):
                achou = True
                continue
            linhas.append(linha)

    if not achou:
        console.print(f"[red]VLAN {vid} nao encontrada em {dc}[/red]")
        pausa()
        return

    with open(VLAN_DB, "w") as f:
        f.writelines(linhas)
    console.print(f"[green]VLAN {vid} liberada de {dc}[/green]")
    pausa()


def buscar_reservas():
    cabecalho("BUSCAR RESERVAS")
    if not os.path.isfile(VLAN_DB):
        console.print("[yellow]Nenhuma reserva encontrada[/yellow]")
        pausa()
        return

    termo = Prompt.ask("[bold cyan]Termo de busca[/bold cyan]")
    reservas = _ler_reservas()
    resultados = [r for r in reservas if termo.lower() in r["vlan_id"] or
                  termo.lower() in r["nome"].lower() or
                  termo.lower() in r["cliente"].lower() or
                  termo.lower() in r["datacenter"].lower()]

    if not resultados:
        console.print(f"[yellow]Nenhum resultado para '{termo}'[/yellow]")
        pausa()
        return

    t = Table(box=box.SQUARE, border_style="cyan")
    t.add_column("VLAN ID", style="bold cyan", width=8)
    t.add_column("Nome", width=28)
    t.add_column("DC", width=10)
    t.add_column("Status", width=12)
    t.add_column("Cliente", width=22)
    for r in resultados:
        cor_status = "green" if r["status"] == "reservada" else "yellow"
        t.add_row(r["vlan_id"], r["nome"], r["datacenter"],
                  f"[{cor_status}]{r['status']}[/{cor_status}]", r["cliente"])
    console.print(t)
    console.print(f"\n[dim]Encontrados: {len(resultados)}[/dim]")
    pausa()


def vlans_livres():
    cabecalho("VLANS LIVRES POR DC")
    reservas = _ler_reservas()

    t = Table(box=box.SQUARE, border_style="green")
    t.add_column("Data Center", style="bold cyan", width=12)
    t.add_column("Livres", justify="right", width=8)
    t.add_column("Total possivel", justify="right", width=14)

    for dc in sorted(set(r["datacenter"] for r in reservas)) or ["TB01", "TB02", "CTA"]:
        usadas = set()
        for r in reservas:
            if r["datacenter"] == dc:
                usadas.add(r["vlan_id"])
        livres = 4094 - len(usadas)
        t.add_row(dc, f"[green]{livres}[/green]", "4094")

    if not reservas:
        for dc in ["TB01", "TB02", "CTA"]:
            t.add_row(dc, "[green]4094[/green]", "4094")

    console.print(t)
    console.print("\n[dim]Total de VLANs possiveis: 1-4094 por DC[/dim]")
    pausa()


def menu_principal():
    while True:
        console.clear()
        show_banner()

        menu = Table(box=box.SIMPLE_HEAVY, border_style="bright_blue", show_header=False)
        menu.add_column("opt", style="bold yellow", width=4)
        menu.add_column("desc", style="white")
        menu.add_row("[1]", "Validar uma VLAN")
        menu.add_row("[2]", "Validar mais de uma VLAN")
        menu.add_row("[3]", "Validar todas as VLANs")
        menu.add_row("", "")
        menu.add_row("[0]", "Sair")

        console.print(Align.center(menu))

        op = Prompt.ask("[bold cyan]Escolha uma opcao",
                        choices=["0","1","2","3"])

        if op == "0":
            cabecalho("ATE LOGO!")
            console.print("[green]Saindo...[/green]")
            break
        elif op == "1":
            validar_uma_vlan()
        elif op == "2":
            validar_multiplas_vlans()
        elif op == "3":
            validar_todas_vlans()


def main():
    try:
        menu_principal()
    except KeyboardInterrupt:
        STOP_EVENT.set()
        console.print("\n[yellow]Interrompido[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
