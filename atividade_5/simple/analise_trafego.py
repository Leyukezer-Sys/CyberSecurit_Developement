#!/usr/bin/env python3
"""
Script para análise de tráfego de rede
Analisa capturas do tcpdump e detecta possíveis port scans
"""

import re
import csv
from collections import defaultdict, deque
from datetime import timedelta

def parse_traffic_file(filename):
    """
    Lê e parseia o arquivo de tráfego
    Retorna lista de tuplas (timestamp, ip_origem, porta_destino)
    """
    traffic_data = []
    
    # Regex para extrair os campos da linha do tcpdump
    # Formato esperado: "0.000000 IP 192.168.1.100.51234 > 8.8.8.8.53: ..."
    pattern = r'^\s*(\d+\.\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)\.\d+\s+>\s+\d+\.\d+\.\d+\.\d+\.(\d+).*$'
    
    try:
        with open(filename, 'r') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if not line:
                    continue
                
                match = re.match(pattern, line)
                if match:
                    timestamp = float(match.group(1))
                    ip_origem = match.group(2)
                    porta_destino = int(match.group(3))
                    
                    traffic_data.append((timestamp, ip_origem, porta_destino))
                else:
                    print(f"Aviso: Linha {line_num} não corresponde ao padrão esperado: {line}")
    
    except FileNotFoundError:
        print(f"Erro: Arquivo '{filename}' não encontrado.")
        return []
    except Exception as e:
        print(f"Erro ao ler arquivo: {e}")
        return []
    
    return traffic_data

def analyze_traffic(traffic_data):
    """
    Analisa os dados de tráfego e detecta port scans
    """
    # Contagem total de eventos por IP
    eventos_por_ip = defaultdict(int)
    
    # Para detecção de port scan: armazena eventos por IP com timestamps
    eventos_detalhados = defaultdict(list)
    
    # Processa cada evento
    for timestamp, ip_origem, porta_destino in traffic_data:
        eventos_por_ip[ip_origem] += 1
        eventos_detalhados[ip_origem].append((timestamp, porta_destino))
    
    # Detecta port scans
    portscan_detectado = {}
    
    for ip, eventos in eventos_detalhados.items():
        # Ordena eventos por timestamp
        eventos.sort(key=lambda x: x[0])
        
        # Usa uma janela deslizante de 60 segundos
        portas_unicas_janela = set()
        janela = deque()
        detectado = False
        
        for evento in eventos:
            timestamp, porta = evento
            janela.append(evento)
            portas_unicas_janela.add(porta)
            
            # Remove eventos fora da janela de 60 segundos
            while janela and timestamp - janela[0][0] > 60:
                evento_antigo = janela.popleft()
                # Se a porta do evento removido não aparece mais na janela, remove da contagem
                porta_antiga = evento_antigo[1]
                if all(evt[1] != porta_antiga for evt in janela):
                    portas_unicas_janela.discard(porta_antiga)
            
            # Verifica se há port scan (mais de 10 portas distintas em 60 segundos)
            if len(portas_unicas_janela) > 10:
                detectado = True
                break
        
        portscan_detectado[ip] = detectado
    
    return eventos_por_ip, portscan_detectado

def generate_report(eventos_por_ip, portscan_detectado, output_filename="relatorio.csv"):
    """
    Gera o arquivo CSV com o relatório
    """
    try:
        with open(output_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Cabeçalho
            writer.writerow(['IP', 'Total_Eventos', 'Detectado_PortScan'])
            
            # Dados
            for ip in sorted(eventos_por_ip.keys()):
                total_eventos = eventos_por_ip[ip]
                detectado = "Sim" if portscan_detectado.get(ip, False) else "Não"
                writer.writerow([ip, total_eventos, detectado])
        
        print(f"Relatório gerado com sucesso: {output_filename}")
        
    except Exception as e:
        print(f"Erro ao gerar relatório: {e}")

def main():
    """
    Função principal
    """
    input_file = "trafego.txt"
    output_file = "relatorio.csv"
    
    print("=== Análise de Tráfego de Rede ===")
    print(f"Lendo arquivo: {input_file}")
    
    # Passo 1: Ler e parsear o arquivo
    traffic_data = parse_traffic_file(input_file)
    
    if not traffic_data:
        print("Nenhum dado válido encontrado ou erro ao ler o arquivo.")
        return
    
    print(f"Total de eventos processados: {len(traffic_data)}")
    
    # Passo 2: Analisar tráfego
    print("Analisando tráfego...")
    eventos_por_ip, portscan_detectado = analyze_traffic(traffic_data)
    
    # Passo 3: Gerar relatório
    print("Gerando relatório...")
    generate_report(eventos_por_ip, portscan_detectado, output_file)
    
    # Estatísticas
    print(f"\n=== Estatísticas ===")
    print(f"IPs únicos encontrados: {len(eventos_por_ip)}")
    print(f"IPs com port scan detectado: {sum(1 for ip in portscan_detectado if portscan_detectado[ip])}")
    
    # Mostra os top 5 IPs por número de eventos
    print(f"\nTop 5 IPs por número de eventos:")
    top_ips = sorted(eventos_por_ip.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in top_ips:
        portscan = "SIM" if portscan_detectado.get(ip, False) else "não"
        print(f"  {ip}: {count} eventos (port scan: {portscan})")

if __name__ == "__main__":
    main()