#!/bin/bash
# Script para capturar tráfego de rede usando tcpdump

echo "Iniciando captura de tráfego de rede..."
echo "Pressione Ctrl+C para parar a captura"

# Nome do arquivo de saída
ARQUIVO_SAIDA="trafego.txt"

# Capturar tráfego por 5 minutos (300 segundos)
echo "Capturando tráfego por 5 minutos..."
tcpdump -i any -t -n 'tcp and (tcp-syn|tcp-ack) and not src and dst port 22' -w trafego_temp.pcap &
TCPDUMP_PID=$!

# Aguardar 5 minutos
sleep 300

# Parar tcpdump
kill $TCPDUMP_PID
wait $TCPDUMP_PID 2>/dev/null

# Converter pcap para texto legível
echo "Convertendo captura para formato texto..."
tcpdump -r trafego_temp.pcap -t -n > $ARQUIVO_SAIDA

# Limpar arquivo temporário
rm trafego_temp.pcap

echo "Captura concluída! Arquivo gerado: $ARQUIVO_SAIDA"
echo "Execute: python analise_trafego.py $ARQUIVO_SAIDA relatorio.csv"