# 📡 Captura de Tráfego de Rede

Este projeto realiza a captura de tráfego de rede utilizando `tcpdump` para analisar pacotes IP durante 60 segundos.

## 📋 Descrição

O script captura tráfego de rede na interface ativa, filtrando apenas pacotes IP e gerando um arquivo de log com timestamps, endereços IP de origem e portas de destino.

## 🛠 Pré-requisitos

- Linux (ou sistema Unix-like)
- `tcpdump` instalado
- Privilégios de superusuário (sudo)

## 🔧 Instalação do tcpdump

Se não tiver o `tcpdump` instalado:

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install tcpdump

# CentOS/RHEL
sudo yum install tcpdump

# Fedora
sudo dnf install tcpdump
```

## 🚀 Como Executar

### 1. Identificar a interface de rede

```bash
# Ver interfaces disponíveis
ip addr show
# ou
tcpdump -D
```

### 2. Executar a captura

```bash
# Substitua 'eth0' pela sua interface de rede
sudo timeout 60 tcpdump -i eth0 -nn -ttt ip > trafego.txt
```

### 3. Alternativa passo a passo

```bash
# Passo 1: Identificar interface (procure por "state UP")
ip addr show | grep "state UP"

# Passo 2: Capturar tráfego (exemplo com eth0)
sudo timeout 60 tcpdump -i eth0 -nn -ttt ip > trafego.txt

# Passo 3: Verificar resultado
head trafego.txt
```

## 📊 Formato do Arquivo de Saída

O arquivo `trafego.txt` conterá linhas no formato:

```
0.000000 192.168.1.100.51234 > 8.8.8.8.53: UDP, length 55
0.001234 10.0.0.5.44322 > 192.168.1.1.80: Flags [S], seq 123456789
0.003456 8.8.8.8.53 > 192.168.1.100.51234: UDP, length 71
```

**Campos:**

- **Timestamp**: Tempo relativo em segundos
- **IP Origem**: Endereço IP e porta de origem
- **IP Destino**: Endereço IP e porta de destino
- **Detalhes**: Informações do pacote (flags, protocolo, etc.)

## 🔍 Parâmetros do tcpdump

- `-i eth0`: Interface de rede
- `-nn`: Não resolve nomes de hosts ou serviços
- `-ttt`: Timestamp relativo entre pacotes
- `ip`: Filtro para capturar apenas pacotes IP
- `timeout 60`: Limita a captura a 60 segundos

## 📁 Estrutura de Arquivos

```
/
├── trafego.txt          # Arquivo de saída com a captura
├── analise_trafego.py          # script de análise de trafego
└── README.md           # Este arquivo
```

## 🎯 Exemplos de Uso

### Capturar em interface Wi-Fi

```bash
sudo timeout 60 tcpdump -i wlan0 -nn -ttt ip > trafego.txt
```

### Capturar com mais detalhes

```bash
sudo timeout 60 tcpdump -i eth0 -nn -ttt -v ip > trafego_detalhado.txt
```

### Capturar apenas tráfego TCP

```bash
sudo timeout 60 tcpdump -i eth0 -nn -ttt tcp > trafego_tcp.txt
```

## ⚠️ Observações Importantes

1. **Execute com sudo** - A captura de pacotes requer privilégios elevados
2. **Interface correta** - Use a interface que está realmente transmitindo dados
3. **Gere tráfego** - Se não houver tráfego, o arquivo ficará vazio (acesse sites, faça ping, etc.)
4. **Pare manualmente** - Use `Ctrl+C` para interromper antes dos 60 segundos

## 🔒 Considerações de Segurança

- Este script captura apenas metadados de rede (não o conteúdo dos pacotes)
- Execute apenas em redes próprias ou com autorização
- O arquivo de captura pode conter informações sensíveis

## 📈 Próximos Passos

Após a captura, você inicia o `analise_trafego.py`:

```bash

# Executar o script Python
python3 analise_trafego.py

```

### Verificar os Resultados

```bash
# Visualizar o relatório gerado
cat relatorio.csv

# Ou em formato tabular (se disponível)
column -t -s, relatorio.csv
```