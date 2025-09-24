# ATR (Analisador de Tráfego de Rede)

Script Python para análise de tráfego de rede e detecção de port scans.

## Como Executar

### 1. Capturar Tráfego com tcpdump

**Opção A: Script automático**
```bash
chmod +x capturar_trafego.sh
./capturar_trafego.sh
```

**Opção B: Comando manual**
```bash
# Capturar tráfego TCP por 5 minutos
timeout 300 tcpdump -i any -t -n 'tcp' > trafego.txt

# Ou capturar para arquivo pcap e converter
tcpdump -i any -w trafego.pcap -c 1000
tcpdump -r trafego.pcap -t -n > trafego.txt
```

### 2. Executar Análise Python

```bash
python analise_trafego.py trafego.txt relatorio.csv
```

## Interpretação das Colunas do CSV

- **IP**: Endereço IP de origem do tráfego analisado
- **Total_Eventos**: Número total de conexões/eventos originados do IP
- **Detectado_PortScan**: Indica se foi detectado comportamento de port scan
  - "Sim": IP tentou conectar a mais de 10 portas distintas em 60 segundos
  - "Não": Não foi detectado comportamento suspeito

## Limitações e Considerações

### Limitações Técnicas
1. **Falsos Positivos**: Aplicativos legítimos podem gerar múltiplas conexões
2. **Tráfego Baixo**: Poucos dados podem não representar padrões reais
3. **Janela de Tempo**: Janela fixa de 60 segundos pode não capturar scans lentos

### Fatores que Afetam Detecção
- **Tráfego de Rede**: Volume insuficiente pode mascarar padrões
- **NAT/Firewall**: IPs compartilhados podem distorcer resultados
- **Protocolos**: Análise foca em TCP, ignorando outros protocolos


## Exemplo de Saída
O arquivo `relatorio.csv` classifica cada IP analisado, permitindo identificar rapidamente comportamentos suspeitos na rede.

## Como usar Linux:

1. **Salve os arquivos** em seu diretório de trabalho
2. **Torne executável**: `chmod +x capturar_trafego.sh`
3. **Capture tráfego**: `./capturar_trafego.sh` (ou use seu próprio arquivo trafego.txt)
4. **Execute análise**: `python analise_trafego.py trafego.txt relatorio.csv`
5. **Verifique resultados**: `cat relatorio.csv`

## Como Executar 
### Passo a Passo Windows:
```bash
# 1. Instalar Python e dependências
pip install psutil requests

# 2. Executar script completo
python analise_trafego_completo.py

# 3. Escolher opção 1 para captura real
# 4. Enquanto captura, gerar tráfego:
python gerar_trafego.py
```
Esta solução oferece uma análise robusta de tráfego com detecção eficiente de port scans e geração de relatórios detalhados.