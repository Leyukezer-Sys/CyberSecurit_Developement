#!/usr/bin/env python3
"""
Script completo de análise de tráfego para Windows com captura integrada
"""

import subprocess
import time
import threading
import psutil
from datetime import datetime
import re
import csv
from collections import defaultdict, deque
import os
import sys

class CapturadorTrafego:
    """Classe para capturar tráfego de rede em tempo real"""
    
    def __init__(self):
        self.conexoes_ativas = []
        self.executando = False
        
    def monitorar_conexoes(self, duracao=300):
        """Monitora conexões de rede em tempo real"""
        print(f"Iniciando monitoramento por {duracao} segundos...")
        print("Execute atividades de rede (navegação, downloads, etc.)")
        
        conexoes_coletadas = []
        inicio = time.time()
        
        try:
            while time.time() - inicio < duracao:
                # Capturar conexões ativas
                conexoes = psutil.net_connections(kind='inet')
                
                for conn in conexoes:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        # Formatar dados da conexão
                        timestamp = time.time() - inicio
                        ip_origem = conn.laddr.ip
                        porta_destino = conn.raddr.port
                        ip_destino = conn.raddr.ip
                        
                        conexao_info = {
                            'timestamp': timestamp,
                            'ip_origem': ip_origem,
                            'porta_destino': porta_destino,
                            'ip_destino': ip_destino,
                            'pid': conn.pid
                        }
                        
                        # Evitar duplicatas
                        if conexao_info not in conexoes_coletadas:
                            conexoes_coletadas.append(conexao_info)
                
                time.sleep(1)  # Verificar a cada segundo
                
                # Mostrar progresso
                decorrido = time.time() - inicio
                progresso = (decorrido / duracao) * 100
                print(f"Progresso: {progresso:.1f}% - Conexões capturadas: {len(conexoes_coletadas)}", end='\r')
                
        except KeyboardInterrupt:
            print("\nCaptura interrompida pelo usuário")
        except Exception as e:
            print(f"Erro durante captura: {e}")
        
        return conexoes_coletadas
    
    def salvar_captura(self, conexoes, arquivo_saida):
        """Salva as conexões capturadas em arquivo"""
        with open(arquivo_saida, 'w', encoding='utf-8') as f:
            f.write("# Timestamp IP_Origem Porta_Destino IP_Destino PID\n")
            for conn in conexoes:
                linha = f"{conn['timestamp']:.3f} {conn['ip_origem']}:{conn.get('porta_origem', '0')} > {conn['ip_destino']}:{conn['porta_destino']} PID:{conn['pid']}\n"
                f.write(linha)
        
        print(f"Captura salva em: {arquivo_saida}")
        print(f"Total de conexões capturadas: {len(conexoes)}")

def gerar_trafego_exemplo():
    """Gera tráfego de exemplo para teste"""
    print("Gerando tráfego de exemplo...")
    
    # Simular diferentes tipos de tráfego
    exemplos = []
    timestamp_base = time.time()
    ips_origem = ['192.168.1.100', '192.168.1.101', '192.168.1.102']
    
    # IP normal - poucas portas
    for i in range(5):
        exemplos.append({
            'timestamp': timestamp_base + i,
            'ip_origem': '192.168.1.100',
            'porta_destino': 80 + i,
            'ip_destino': '8.8.8.8',
            'pid': 1234
        })
    
    # IP suspeito - port scan
    for i in range(15):
        exemplos.append({
            'timestamp': timestamp_base + i * 2,
            'ip_origem': '10.0.0.15',
            'porta_destino': 1000 + i,
            'ip_destino': '192.168.1.1',
            'pid': 5678
        })
    
    # Outro IP normal
    for i in range(3):
        exemplos.append({
            'timestamp': timestamp_base + i * 10,
            'ip_origem': '192.168.1.102',
            'porta_destino': 443,
            'ip_destino': '1.1.1.1',
            'pid': 9012
        })
    
    return exemplos

def analisar_trafego_windows():
    """Função principal para Windows"""
    print("=== ANALISADOR DE TRÁFEGO - WINDOWS ===")
    print()
    
    while True:
        print("Opções disponíveis:")
        print("1 - Capturar tráfego em tempo real (5 minutos)")
        print("2 - Usar arquivo existente")
        print("3 - Gerar dados de exemplo")
        print("4 - Sair")
        
        opcao = input("\nEscolha uma opção (1-4): ").strip()
        
        if opcao == "1":
            capturar_trafego_real()
        elif opcao == "2":
            usar_arquivo_existente()
        elif opcao == "3":
            usar_dados_exemplo()
        elif opcao == "4":
            print("Saindo...")
            break
        else:
            print("Opção inválida!")

def capturar_trafego_real():
    """Captura tráfego real do sistema"""
    try:
        import psutil
    except ImportError:
        print("Instalando dependência psutil...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
        import psutil
    
    capturador = CapturadorTrafego()
    
    # Capturar por 5 minutos
    conexoes = capturador.monitorar_conexoes(duracao=300)
    
    if conexoes:
        arquivo_captura = f"trafego_real_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        capturador.salvar_captura(conexoes, arquivo_captura)
        analisar_arquivo(arquivo_captura)
    else:
        print("Nenhuma conexão foi capturada. Tente gerar mais tráfego de rede.")

def usar_arquivo_existente():
    """Usa arquivo de tráfego existente"""
    arquivo = input("Digite o caminho do arquivo de tráfego: ").strip()
    
    if os.path.exists(arquivo):
        analisar_arquivo(arquivo)
    else:
        print("Arquivo não encontrado!")

def usar_dados_exemplo():
    """Gera e analisa dados de exemplo"""
    conexoes = gerar_trafego_exemplo()
    
    arquivo_exemplo = "trafego_exemplo.txt"
    capturador = CapturadorTrafego()
    capturador.salvar_captura(conexoes, arquivo_exemplo)
    
    analisar_arquivo(arquivo_exemplo)

def analisar_arquivo(arquivo_entrada):
    """Analisa o arquivo de tráfego"""
    # (Usar a função de análise do script anterior)
    from analise_trafego import analisar_trafego
    
    arquivo_saida = f"relatorio_{os.path.basename(arquivo_entrada).split('.')[0]}.csv"
    analisar_trafego(arquivo_entrada, arquivo_saida)

if __name__ == "__main__":
    # Verificar se é Windows
    if os.name != 'nt':
        print("Este script é otimizado para Windows.")
        print("Execute em um sistema Windows para melhor experiência.")
    
    analisar_trafego_windows()