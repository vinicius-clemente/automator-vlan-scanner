# Automator VLAN Scanner (Full LAN & MAC Table Auditor)

Ferramenta de automação desenvolvida em Python para auditoria profunda de uma ou de todas as VLANs/LANs em uma topologia de rede, cruzando a existência da VLAN na base do switch com o aprendizado ativo de MAC addresses para validar tráfego real antes de migrações ou descomissionamentos.

## Funcionalidades

- **Escaneamento Flexível (Única ou Todas as VLANs):** Permite auditar tanto uma VLAN específica quanto realizar a varredura completa de todas as LANs configuradas nos equipamentos do inventário.
- **Correlação VLAN + Tabela MAC:** Verifica não apenas se a VLAN está criada (`VLAN database`), mas também se existem dispositivos ativos aprendidos na tabela CAM (`MAC address-table`) dentro daquele domínio de broadcast.
- **Diagnóstico de Tráfego Real:** Identifica rapidamente VLANs ociosas ("fantasmas") sem MACs aprendidos versus segmentos em produção com tráfego ativo.
- **Execução Multi-Switch:** Varre toda a infraestrutura em lote com tratamento robusto de falhas de conexão SSH e timeouts.

## Tecnologias Utilizadas

- **Python 3.x**
- **Netmiko / Paramiko:** Gerenciamento automatizado de sessões SSH e extração de tabelas L2/CAM em switches de rede.

## Como Utilizar

1. Clone o repositório:

       git clone https://github.com/vinicius-clemente/automator-vlan-scanner.git
       cd automator-vlan-scanner

2. Instale as dependências:

       pip install -r requirements.txt

3. Preencha o arquivo de inventário (`devices.txt`) com os endereços IP dos switches a serem escaneados.

4. Execute o script e escolha o modo de varredura (VLAN específica ou varredura total):

       python vlan-scanner.py

   *(Ajuste o nome do arquivo `.py` conforme o script principal na pasta).*

## Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
