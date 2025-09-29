#!/usr/bin/env python3
"""
Script para análise de tráfego de rede e detecção de port scan
Autor: Leyukezer
"""

import re
import csv
from collections import defaultdict, deque
from datetime import datetime
import sys

def parse_linha_trafego(linha):
    """
    Parseia uma linha do arquivo de tráfego
    Formato esperado: timestamp IP_origem:porta > IP_destino:porta
    """
    try:
        # Padrão para capturar timestamp, IP origem e porta destino
        padrao = r'^(\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+):\d+\s+>\s+\d+\.\d+\.\d+\.\d+:(\d+)'
        match = re.match(padrao, linha.strip())
        
        if match:
            timestamp = float(match.group(1))
            ip_origem = match.group(2)
            porta_destino = int(match.group(3))
            return timestamp, ip_origem, porta_destino
        else:
            # Tentativa com formato alternativo
            partes = linha.strip().split()
            if len(partes) >= 3:
                timestamp = float(partes[0])
                ip_porta_origem = partes[1].split(':')
                ip_porta_destino = partes[3].split(':')
                
                if len(ip_porta_origem) == 2 and len(ip_porta_destino) == 2:
                    ip_origem = ip_porta_origem[0]
                    porta_destino = int(ip_porta_destino[1])
                    return timestamp, ip_origem, porta_destino
            
            return None
    except (ValueError, IndexError) as e:
        print(f"Erro ao parsear linha: {linha.strip()} - {e}")
        return None

def detectar_port_scan(eventos_por_ip, limite_portas=10, janela_tempo=60):
    """
    Detecta port scan baseado em eventos por IP
    """
    resultados = {}
    
    for ip, eventos in eventos_por_ip.items():
        # Ordena eventos por timestamp
        eventos_ordenados = sorted(eventos, key=lambda x: x[0])
        
        # Usa uma janela deslizante para verificar portas distintas
        portas_detectadas = set()
        janela = deque()
        detectado = False
        
        for evento in eventos_ordenados:
            timestamp, porta = evento
            
            # Remove eventos fora da janela de 60 segundos
            while janela and timestamp - janela[0][0] > janela_tempo:
                porta_removida = janela.popleft()[1]
                if porta_removida in portas_detectadas:
                    portas_detectadas.remove(porta_removida)
            
            # Adiciona evento atual à janela
            janela.append(evento)
            portas_detectadas.add(porta)
            
            # Verifica se excedeu o limite de portas distintas
            if len(portas_detectadas) > limite_portas:
                detectado = True
                break
        
        resultados[ip] = detectado
    
    return resultados

def analisar_trafego(arquivo_entrada, arquivo_saida):
    """
    Função principal de análise de tráfego
    """
    # Estruturas para armazenar dados
    eventos_por_ip = defaultdict(list)
    total_eventos = defaultdict(int)
    
    # Contadores para estatísticas
    linhas_processadas = 0
    linhas_ignoradas = 0
    
    print("Processando arquivo de tráfego...")
    
    try:
        with open(arquivo_entrada, 'r') as arquivo:
            for numero_linha, linha in enumerate(arquivo, 1):
                resultado = parse_linha_trafego(linha)
                
                if resultado:
                    timestamp, ip_origem, porta_destino = resultado
                    eventos_por_ip[ip_origem].append((timestamp, porta_destino))
                    total_eventos[ip_origem] += 1
                    linhas_processadas += 1
                else:
                    linhas_ignoradas += 1
                
                # Progresso a cada 1000 linhas
                if numero_linha % 1000 == 0:
                    print(f"Processadas {numero_linha} linhas...")
    
    except FileNotFoundError:
        print(f"Erro: Arquivo '{arquivo_entrada}' não encontrado.")
        return False
    except Exception as e:
        print(f"Erro ao ler arquivo: {e}")
        return False
    
    print(f"\nEstatísticas do processamento:")
    print(f"- Linhas processadas com sucesso: {linhas_processadas}")
    print(f"- Linhas ignoradas: {linhas_ignoradas}")
    print(f"- IPs únicos detectados: {len(eventos_por_ip)}")
    
    # Detectar port scans
    print("Detectando port scans...")
    port_scans = detectar_port_scan(eventos_por_ip)
    
    # Gerar relatório CSV
    try:
        with open(arquivo_saida, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP', 'Total_Eventos', 'Detectado_PortScan'])
            
            for ip in sorted(eventos_por_ip.keys()):
                total = total_eventos[ip]
                detectado = "Sim" if port_scans[ip] else "Não"
                writer.writerow([ip, total, detectado])
        
        print(f"Relatório gerado com sucesso: {arquivo_saida}")
        return True
        
    except Exception as e:
        print(f"Erro ao gerar relatório CSV: {e}")
        return False

def main():
    """
    Função principal
    """
    if len(sys.argv) != 3:
        print("Uso: python analise_trafego.py <arquivo_entrada> <arquivo_saida>")
        print("Exemplo: python analise_trafego.py trafego.txt relatorio.csv")
        sys.exit(1)
    
    arquivo_entrada = sys.argv[1]
    arquivo_saida = sys.argv[2]
    
    print("=== Analisador de Tráfego de Rede ===")
    print(f"Arquivo de entrada: {arquivo_entrada}")
    print(f"Arquivo de saída: {arquivo_saida}")
    print("-" * 40)
    
    sucesso = analisar_trafego(arquivo_entrada, arquivo_saida)
    
    if sucesso:
        print("\nAnálise concluída com sucesso!")
    else:
        print("\nErro durante a análise.")
        sys.exit(1)

if __name__ == "__main__":
    main()