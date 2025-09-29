# Analisador de Tráfego de Rede

Sistema interativo para captura e análise de tráfego de rede em tempo real com detecção de port scans.

## Pré-requisitos

- Sistema Linux
- Python 3.6+
- tcpdump instalado
- Privilégios de root/sudo

# Instalação das dependências:

## Scripts de Instalação e Execução

### 1. `iniciar.sh`

- Instala todas as dependências automaticamente
- Detecta a distribuição Linux
- Verifica instalações
- Menu interativo para execução
- Múltiplas opções de execução
- Verificação de dependências
- Execução com/sudo sudo

## 🚀 Como Usar

### Instalação Rápida:

```bash
# Tornar executável
chmod +x iniciar.sh

# Execute
sudo ./iniciar.sh
```

## Como Executar Manualmente

Instalando as dependencias

```bash
sudo apt update
sudo apt install tcpdump python3 python3-pip
```

1. Executar o sistema interativo:

```bash
# Recomendado (com privilégios completos):
sudo python3 analise_trafego.py

# Ou sem sudo (algumas funcionalidades limitadas):
python3 analise_trafego.py
```

2. Fluxo de uso recomendado:  
   Opção 1: Detectar interface de rede automaticamente

   Opção 2: Monitorar tráfego em tempo real (visualização)

   Opção 3: Capturar e Analisar tráfego e gerar relatório

   Opção 4: Visualizar resultados

   Opção 5: E

## Critério de Port Scan

Um IP é marcado como port scan quando:

- Tenta conectar a mais de 10 portas distintas

- Dentro de um intervalo de 60 segundos

- Considera apenas portas de destino únicas

## Limitações e Considerações

1. Tráfego Baixo
   Em ambientes com pouco tráfego, pode não detectar port scans reais

   Recomendado executar durante atividades normais de rede

2. Falsos Positivos
   Serviços legítimos que fazem varredura (ex: scanners de vulnerabilidade internos)

   Aplicações que conectam em múltiplas portas (ex: P2P, atualizações)

   Balanceadores de carga podem gerar múltiplas conexões

3. Falsos Negativos
   Port scans lentos (menos de 10 portas por minuto)

   Scans distribuídos entre múltiplos IPs

   Tráfego criptografado ou em portas não monitoradas

4. Dependências do Sistema
   Requer privilégios de root para captura completa

   Pode não detectar todas as interfaces em sistemas complexos

   Performance pode variar com volume de tráfego

## Exemplo de Saída

```csv
IP;Total_Eventos;Detectado_PortScan
192.168.1.100;45;Não
192.168.1.50;128;Sim
10.0.0.15;23;Não
```
