#!/usr/bin/env python3
"""Script para gerar tráfego de rede real para testes"""

import requests
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

def gerar_trafego_normal():
    """Gera tráfego normal de navegação"""
    print("Gerando tráfego normal...")
    
    urls = [
        'http://www.google.com',
        'http://www.github.com',
        'http://www.stackoverflow.com',
        'http://www.python.org'
    ]
    
    def fazer_requisicao(url):
        try:
            response = requests.get(url, timeout=10)
            print(f"Conectado a {url} - Status: {response.status_code}")
        except:
            print(f"Falha ao conectar com {url}")
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        executor.map(fazer_requisicao, urls)

def testar_portas_locais():
    """Testa conexões em portas locais (simula port scan)"""
    print("Testando portas locais...")
    
    def testar_porta(porta):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                resultado = sock.connect_ex(('127.0.0.1', porta))
                if resultado == 0:
                    print(f"Porta {porta}: Aberta")
                else:
                    print(f"Porta {porta}: Fechada")
        except:
            pass
    
    # Testar algumas portas comuns
    portas = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 587, 3306, 5432, 8080]
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(testar_porta, portas)

if __name__ == "__main__":
    print("=== Gerador de Tráfego para Testes ===")
    
    print("1. Gerar tráfego normal de navegação")
    print("2. Testar portas locais (simular port scan)")
    print("3. Ambos")
    
    opcao = input("Escolha (1-3): ").strip()
    
    if opcao in ['1', '3']:
        gerar_trafego_normal()
        time.sleep(2)
    
    if opcao in ['2', '3']:
        testar_portas_locais()