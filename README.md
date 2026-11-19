# automator-vlan-scanner

Comprehensive Python scanner to audit single or all VLANs/LANs across network infrastructure, validating VLAN database entries, active MAC address learning, and traffic presence.



\# Automator VLAN Scanner (Full LAN \& MAC Table Auditor)



Ferramenta de automacao desenvolvida em Python para auditoria profunda de uma ou de todas as VLANs/LANs em uma topologia de rede, cruzando a existencia da VLAN na base do switch com o aprendizado ativo de MAC addresses para validar trafego real antes de migracoes ou descomissionamentos.



\## Funcionalidades



\- \*\*Escaneamento Flexivel (Unica ou Todas as VLANs):\*\* Permite auditar tanto uma VLAN especifica quanto realizar a varredura completa de todas as LANs configuradas nos equipamentos do inventario.

\- \*\*Correlacao VLAN + Tabela MAC:\*\* Verifica nao apenas se a VLAN esta criada (`VLAN database`), mas tambem se existem dispositivos ativos aprendidos na tabela CAM (`MAC address-table`) dentro daquele dominio de broadcast.

\- \*\*Diagnostico de Trafego Real:\*\* Identifica rapidamente VLANs ociosas ("fantasmas") sem MACs aprendidos versus segmentos em producao com trafego ativo.

\- \*\*Execucao Multi-Switch:\*\* Varre toda a infraestrutura em lote com tratamento robusto de falhas de conexao SSH e timeouts.



\## Tecnologias Utilizadas



\- \*\*Python 3.x\*\*

\- \*\*Netmiko / Paramiko:\*\* Gerenciamento automatizado de sessoes SSH e extracao de tabelas L2/CAM em switches de rede.



\## Como Utilizar



1\. Clone o repositorio:

&#x20;  ```bash

&#x20;  git clone \[https://github.com/vinicius-master/automator-vlan-scanner.git](https://github.com/vinicius-master/automator-vlan-scanner.git)

&#x20;  cd automator-vlan-scanner

