
# 🛡️ Análise de Tráfego de Rede e Detecção de Port-Scan

Este projeto fornece um script Python para capturar o tráfego de rede, analisar o fluxo de pacotes e detectar padrões de Port-Scan com base em uma janela de tempo deslizante.

---

## 🚀 Arquivos e Funcionalidades

| Arquivo              | Descrição                                                       |
|----------------------|-----------------------------------------------------------------|
| `analise_trafego.py` | O script Python principal (captura opcional e análise de dados).|
| `trafego.txt`        | Arquivo de dump de tráfego gerado pelo `tcpdump` durante a captura. |
| `relatorio.csv`      | Resultado final da análise em formato CSV.                      |

O script realiza: **Captura de Tráfego**, **Contagem de Eventos** e **Detecção de Port-Scan** (identificando quando um IP tenta conectar-se a múltiplas portas distintas em um curto período).

---

## 📋 Pré-requisitos

O ambiente de execução requer as seguintes dependências:

- **Sistema Operacional:** Linux (o script depende de comandos de sistema como `tcpdump`).  
- **Privilégios:** A execução do script requer permissões de root (`sudo`) para captura de pacotes.  
- **Ferramentas de Captura:** `tcpdump` (preferível) ou `tshark`, instalado e acessível no PATH.  
- **Linguagem:** Python 3.8+  

---

## 🛠️ Uso

### 1. Dando Permissão de Execução

Antes do uso, torne o script executável:

```bash
chmod +x analise_trafego.py
