# 🛡️ Análise de Tráfego de Rede e Detecção de Port-Scan

Este projeto fornece um script Python para capturar o tráfego de rede, analisar o fluxo de pacotes e detectar padrões de Port-Scan com base em uma janela de tempo deslizante.

## 🚀 Arquivos e Funcionalidades

| Arquivo | Descrição |
|---------|-----------|
| `analise_trafego.py` | Script Python principal (captura opcional e análise de dados) |
| `trafego.txt` | Arquivo de dump de tráfego gerado pelo tcpdump durante a captura |
| `relatorio.csv` | Resultado final da análise em formato CSV |

O script realiza: **Captura de Tráfego**, **Contagem de Eventos** e **Detecção de Port-Scan** (identificando quando um IP tenta conectar-se a múltiplas portas distintas em um curto período).

## 📋 Pré-requisitos

O ambiente de execução requer as seguintes dependências:

- **Sistema Operacional**: Linux (o script depende de comandos de sistema como tcpdump)
- **Privilégios**: A execução do script requer permissões de root (sudo) para a captura de pacotes
- **Ferramentas de Captura**: `tcpdump` (preferível) ou `tshark` deve estar instalado e acessível no PATH
- **Linguagem**: Python 3.8+

## 🛠️ Uso

### 1. Dando Permissão de Execução
Antes do uso, torne o script executável:

```bash
chmod +x analise_trafego.py
## 2. Captura e Análise (Modo Padrão)
Esta é a maneira mais comum de usar o script: capturar tráfego da interface e analisar imediatamente.

Exemplo de Execução (Captura de 60 segundos na interface enp0s3):

bash
sudo ./analise_trafego.py --interface enp0s3 --duration 60
Parâmetro	Descrição	Padrão
--interface <nome> ou -i	Obrigatório para captura. Nome da interface (ex: eth0, enp0s3)	-
--duration <segundos> ou -d	Tempo de captura em segundos	60
## 3. Somente Análise de Arquivo Existente
Para analisar um arquivo trafego.txt que já foi gerado:

bash
./analise_trafego.py --input trafego.txt --output relatorio.csv
## 4. Ajustes Finos de Detecção de Port-Scan
Os parâmetros de detecção são ajustáveis para otimizar a sensibilidade:

Detecção Padrão: Um IP tenta conectar a mais de 10 portas distintas em uma janela deslizante de 60 segundos.

Parâmetro	Descrição	Padrão
--threshold <num>	Número de portas distintas para acionar o alerta	10
--window <segundos>	Janela de tempo deslizante em segundos para a detecção	60
📊 Relatório CSV (relatorio.csv)
O arquivo CSV gerado fornece as seguintes colunas para cada IP de origem observado:

Coluna	Descrição
IP	Endereço IP de origem
Total_Eventos	Total de pacotes/linhas associadas a esse IP
Detectado_PortScan	"Sim" se o comportamento de port-scan foi detectado com base nos parâmetros definidos; "Não" caso contrário
⚠️ Observações de Formato e Limitações
A robustez do script depende do formato de saída do tcpdump. O parser foi ajustado para esperar a seguinte formatação:

Comando de Captura: tcpdump -i [interface] -nn -ttt tcp or udp -l

Formato de Linha Esperado: <timestamp> IP <SRCIP>.<SRCPORT> > <DSTIP>.<DSTPORT>: ...

Exemplo: 00:00:00.000000 IP 10.0.0.5.12345 > 192.168.1.2.80: S ...

Limitações
Falsos Positivos: Serviços legítimos (como scans de diagnóstico interno ou sistemas distribuídos) podem ser erroneamente classificados como port-scan

Falsos Negativos: Se um ataque for distribuído em um período maior que a --window definida, ele pode não atingir o threshold e passar despercebido

Compatibilidade de Parser: Se o tcpdump for configurado com opções diferentes de -nn (sem resolução de nomes) ou -ttt (timestamp delta formatado), o parser pode falhar ao extrair os campos

text
