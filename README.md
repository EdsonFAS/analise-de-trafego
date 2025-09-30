# 🛡️ Análise de Tráfego de Rede e Detecção de Port-Scan

## 📋 Sobre o Projeto

Este projeto oferece uma solução Python para monitoramento de rede em tempo real, capturando tráfego de rede e detectando automaticamente padrões suspeitos de port-scan utilizando uma janela de tempo deslizante para análise comportamental.

---

## 🚀 Estrutura do Projeto

| Arquivo | Descrição |
|---------|-----------|
| `analise_trafego.py` | Script principal com funcionalidades de captura e análise |
| `trafego.txt` | Arquivo de log gerado pelo tcpdump durante a captura |
| `relatorio.csv` | Relatório final com resultados da análise |

### ⚡ Funcionalidades Principais
- **Captura de Tráfego em Tempo Real**
- **Contagem e Agregação de Eventos por IP**
- **Detecção Inteligente de Port-Scan**
- **Geração de Relatórios em CSV**

---

## 🛠️ Pré-requisitos

### Requisitos do Sistema
- **Sistema Operacional**: Linux
- **Privilégios**: Permissões de root para captura de pacotes
- **Python**: Versão 3.8 ou superior

### Dependências Externas
- `tcpdump` (recomendado) ou `tshark`
- Ferramenta instalada e disponível no PATH do sistema

---


## 📖 Guia de Uso

### 1. Preparação do Ambiente
`bash
chmod +x analise_trafego.py
`

# Manual de Captura e Análise de Tráfego

## 2. Modo de Captura e Análise (Recomendado)

`bash
sudo ./analise_trafego.py --interface enp0s3 --duration 60`


| Parâmetro   | Alternativo | Descrição                            | Valor Padrão |
| ----------- | ----------- | ------------------------------------ | ------------ |
| --interface | -i          | Interface de rede (ex: eth0, enp0s3) | Obrigatório  |
| --duration  | -d          | Tempo de captura em segundos         | 60           |


## 3. Análise de Arquivo Existente

`./analise_trafego.py --input trafego.txt --output relatorio.csv`








