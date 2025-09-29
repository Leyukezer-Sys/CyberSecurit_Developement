#!/usr/bin/env python3
import subprocess
import re
import csv
import time
import os
import json
from collections import defaultdict, deque
from datetime import datetime
import threading

class AnalisadorTrafego:
    def __init__(self):
        self.interface = None
        self.arquivo_trafego = "trafego.txt"
        self.arquivo_relatorio = "relatorio.csv"
        
    def verificar_interfaces(self):
        """Verifica e mostra interfaces de rede disponíveis de forma simplificada"""
        print("\n" + "="*60)
        print("INTERFACES DE REDE DISPONÍVEIS")
        print("="*60)
        
        try:
            # Executa ip addr show e captura a saída
            resultado = subprocess.run(['ip', 'addr', 'show'], 
                                    capture_output=True, text=True, check=True)
            
            linhas = resultado.stdout.split('\n')
            interface_atual = None
            dados_interface = {}
            interfaces = []
            
            for linha in linhas:
                linha = linha.strip()
                
                # Detecta nova interface (ex: "1: lo: ..." ou "2: eth0: ...")
                match_interface = re.match(r'^\d+:\s+([^:]+):', linha)
                if match_interface:
                    if interface_atual and dados_interface:
                        interfaces.append(dados_interface.copy())
                    
                    interface_atual = match_interface.group(1)
                    dados_interface = {
                        'nome': interface_atual,
                        'estado': 'DOWN',
                        'mac': '',
                        'ipv4': [],
                        'ipv6': []
                    }
                
                # Verifica estado da interface
                elif interface_atual and 'state' in linha.lower():
                    if 'UP' in linha.upper():
                        dados_interface['estado'] = 'UP'
                    elif 'DOWN' in linha.upper():
                        dados_interface['estado'] = 'DOWN'
                
                # Captura endereço MAC
                elif interface_atual and 'link/ether' in linha:
                    partes = linha.split()
                    if len(partes) >= 2:
                        dados_interface['mac'] = partes[1]
                
                # Captura IPv4
                elif interface_atual and 'inet ' in linha and 'scope global' in linha:
                    partes = linha.split()
                    if len(partes) >= 2:
                        ip = partes[1].split('/')[0]  # Remove máscara
                        dados_interface['ipv4'].append(ip)
                
                # Captura IPv6 global
                elif interface_atual and 'inet6 ' in linha and 'scope global' in linha:
                    partes = linha.split()
                    if len(partes) >= 2:
                        ipv6 = partes[1].split('/')[0]
                        dados_interface['ipv6'].append(ipv6)
            
            # Adiciona a última interface
            if interface_atual and dados_interface:
                interfaces.append(dados_interface)
            
            # Exibe interfaces de forma organizada
            for i, interface in enumerate(interfaces, 1):
                estado_color = "🟢 UP" if interface['estado'] == 'UP' else "🔴 DOWN"
                print(f"\n{i}. {interface['nome']:12} {estado_color}")
                
                if interface['mac']:
                    print(f"   MAC: {interface['mac']}")
                
                if interface['ipv4']:
                    for ip in interface['ipv4']:
                        print(f"   IPv4: {ip}")
                
                if interface['ipv6']:
                    for ipv6 in interface['ipv6'][:2]:  # Mostra apenas os 2 primeiros IPv6
                        print(f"   IPv6: {ipv6}")
                    if len(interface['ipv6']) > 2:
                        print(f"   ... e mais {len(interface['ipv6']) - 2} endereços IPv6")
            
            print("\n" + "="*60)
            
            # Sugere interface padrão
            interfaces_up = [iface for iface in interfaces if iface['estado'] == 'UP' and iface['nome'] != 'lo']
            if interfaces_up:
                print(f"💡 Interface sugerida: {interfaces_up[0]['nome']}")
                self.interface = interfaces_up[0]['nome']
            else:
                print("⚠️  Nenhuma interface UP encontrada (exceto loopback)")
            
            return interfaces
            
        except subprocess.CalledProcessError as e:
            print(f"Erro ao executar comando: {e}")
            return []
        except Exception as e:
            print(f"Erro inesperado: {e}")
            return []
    
    def detectar_interface(self):
        """Detecta automaticamente a interface de rede ativa"""
        try:
            # Tenta encontrar interface padrão pela rota
            resultado = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            linhas = resultado.stdout.split('\n')
            
            for linha in linhas:
                if 'default' in linha:
                    partes = linha.split()
                    if len(partes) >= 5:
                        self.interface = partes[4]
                        return self.interface
            
            # Fallback para interfaces comuns
            interfaces_comuns = ['eth0', 'wlan0', 'enp0s3', 'ens33', 'wlp2s0']
            for interface in interfaces_comuns:
                try:
                    subprocess.run(['ip', 'addr', 'show', interface], 
                                 capture_output=True, check=True)
                    self.interface = interface
                    return interface
                except:
                    continue
                    
            return None
        except Exception as e:
            print(f"Erro ao detectar interface: {e}")
            return None
    
    def capturar_trafego(self, duracao=60):
        """Captura tráfego de rede usando tcpdump"""
        if not self.interface:
            print("Nenhuma interface selecionada. Use a opção 1 primeiro.")
            return False
        
        print(f"\n🎯 Iniciando captura na interface {self.interface} por {duracao} segundos...")
        
        try:
            # Comando tcpdump para capturar apenas pacotes IP
            comando = [
                'sudo', 'tcpdump',
                '-i', self.interface,
                '-nn',           # Não resolver nomes
                '-ttt',          # Timestamp relativo em segundos
                'ip',            # Apenas pacotes IP
                '-w', 'captura.pcap'  # Salva em formato pcap para análise posterior
            ]
            
            print("📡 Capturando tráfego... (aguarde)")
            # Executa tcpdump em background
            processo = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Aguarda o tempo especificado
            for i in range(duracao):
                print(f"\r⏱️  Progresso: {i+1}/{duracao} segundos", end='', flush=True)
                time.sleep(1)
            
            # Envia sinal SIGTERM para parar o tcpdump
            processo.terminate()
            stdout, stderr = processo.communicate()
            
            if stderr:
                print(f"\n⚠️  Avisos do tcpdump: {stderr.decode()}")
            
            print(f"\n✅ Captura concluída! Convertendo para formato texto...")
            
            # Converte pcap para texto legível
            comando_convert = [
                'tcpdump',
                '-nn',
                '-ttt',
                '-r', 'captura.pcap'
            ]
            
            with open(self.arquivo_trafego, 'w') as f:
                subprocess.run(comando_convert, stdout=f, text=True)
            
            # Conta linhas capturadas
            with open(self.arquivo_trafego, 'r') as f:
                linhas = f.readlines()
            
            print(f"📊 Total de pacotes capturados: {len(linhas)}")
            print(f"💾 Tráfego salvo em {self.arquivo_trafego}")
            return True
            
        except Exception as e:
            print(f"❌ Erro na captura: {e}")
            return False
    
    def parse_linha(self, linha):
        """Parseia uma linha do tcpdump extraindo timestamp, IP origem e porta destino"""
        # Padrão: 00:00:00.000000 IP 192.168.1.100.12345 > 192.168.1.1.80: Flags [S], seq 123456
        padrao = r'^\s*(\d+\.\d+)\s+IP\s+([\d\.]+)\.(\d+)\s+>\s+[\d\.]+\.(\d+):'
        match = re.match(padrao, linha)
        
        if match:
            timestamp = float(match.group(1))
            ip_origem = match.group(2)
            porta_origem = match.group(3)
            porta_destino = match.group(4)
            
            return {
                'timestamp': timestamp,
                'ip_origem': ip_origem,
                'porta_destino': int(porta_destino)
            }
        return None
    
    def analisar_trafego(self):
        """Analisa o tráfego capturado e detecta port scans"""
        if not os.path.exists(self.arquivo_trafego):
            print("❌ Arquivo de tráfego não encontrado!")
            print("   Execute primeiro a captura (opção 3)")
            return False
        
        print("🔍 Analisando tráfego...")
        
        # Estruturas para análise
        eventos_por_ip = defaultdict(int)
        portas_por_ip = defaultdict(lambda: defaultdict(list))  # ip -> {timestamp: [portas]}
        
        # Lê e parseia o arquivo
        total_linhas = 0
        linhas_parseadas = 0
        
        with open(self.arquivo_trafego, 'r') as f:
            for num_linha, linha in enumerate(f, 1):
                total_linhas += 1
                dados = self.parse_linha(linha)
                if dados:
                    linhas_parseadas += 1
                    ip = dados['ip_origem']
                    timestamp = dados['timestamp']
                    porta = dados['porta_destino']
                    
                    # Conta eventos por IP
                    eventos_por_ip[ip] += 1
                    
                    # Armazena porta por timestamp para detecção de port scan
                    portas_por_ip[ip][timestamp].append(porta)
        
        print(f"📈 Estatísticas da análise:")
        print(f"   • Total de linhas no arquivo: {total_linhas}")
        print(f"   • Linhas parseadas com sucesso: {linhas_parseadas}")
        print(f"   • IPs únicos detectados: {len(eventos_por_ip)}")
        
        # Detecta port scans
        portscan_detectado = {}
        for ip, timestamps in portas_por_ip.items():
            portas_unicas_60s = set()
            timestamps_ordenados = sorted(timestamps.keys())
            
            # Verifica janela deslizante de 60 segundos
            for i, ts_inicio in enumerate(timestamps_ordenados):
                portas_janela = set()
                
                for ts in timestamps_ordenados[i:]:
                    if ts - ts_inicio <= 60.0:  # Janela de 60 segundos
                        portas_janela.update(timestamps[ts])
                    else:
                        break
                
                if len(portas_janela) > 10:
                    portscan_detectado[ip] = True
                    break
            else:
                portscan_detectado[ip] = False
        
        # Gera relatório CSV
        with open(self.arquivo_relatorio, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP', 'Total_Eventos', 'Detectado_PortScan'])
            
            for ip, total in sorted(eventos_por_ip.items(), key=lambda x: x[1], reverse=True):
                portscan = "Sim" if portscan_detectado.get(ip, False) else "Não"
                writer.writerow([ip, total, portscan])
        
        print(f"✅ Relatório gerado: {self.arquivo_relatorio}")
        return True
    
    def mostrar_estatisticas(self):
        """Mostra estatísticas do relatório gerado"""
        if not os.path.exists(self.arquivo_relatorio):
            print("❌ Relatório não encontrado!")
            print("   Execute primeiro a análise (opção 4)")
            return
        
        with open(self.arquivo_relatorio, 'r') as f:
            reader = csv.reader(f)
            linhas = list(reader)
        
        print("\n" + "="*50)
        print("📊 ESTATÍSTICAS DO TRÁFEGO")
        print("="*50)
        
        for linha in linhas[1:]:  # Pula cabeçalho
            ip, eventos, portscan = linha
            status = "🚨 SIM" if portscan == "Sim" else "✅ Não"
            print(f"IP: {ip:<15} | Eventos: {eventos:<6} | PortScan: {status}")
        
        total_ips = len(linhas) - 1
        portscans = sum(1 for linha in linhas[1:] if linha[2] == 'Sim')
        
        print(f"\n📈 Resumo:")
        print(f"   • Total de IPs únicos: {total_ips}")
        print(f"   • IPs com PortScan detectado: {portscans}")
        print("="*50)
    
    def realizar_analise_completa(self):
        """Realiza análise completa: captura por 60s e mostra estatísticas"""
        if not self.interface:
            print("❌ Nenhuma interface selecionada. Use a opção 1 primeiro.")
            return False
        
        print("\n" + "="*60)
        print("🔍 ANÁLISE COMPLETA DE TRÁFEGO")
        print("="*60)
        
        # Passo 1: Capturar tráfego
        print("\n🎯 FASE 1: Capturando tráfego por 60 segundos...")
        if not self.capturar_trafego(60):
            return False
        
        # Passo 2: Analisar tráfego
        print("\n🎯 FASE 2: Analisando tráfego capturado...")
        if not self.analisar_trafego():
            return False
        
        # Passo 3: Mostrar estatísticas
        print("\n🎯 FASE 3: Estatísticas da análise...")
        self.mostrar_estatisticas()
        
        print(f"\n✅ Análise completa concluída!")
        print(f"💾 Dados salvos em: {self.arquivo_trafego}")
        print(f"📊 Relatório gerado: {self.arquivo_relatorio}")
        print(f"📈 Use a opção 6 para exportar o relatório completo")
        
        return True
    
    def monitorar_tempo_real(self, duracao=30):
        """Monitora tráfego em tempo real (visualização básica)"""
        if not self.interface:
            print("❌ Nenhuma interface selecionada. Use a opção 1 primeiro.")
            return
        
        print(f"📡 Monitorando tráfego na interface {self.interface}...")
        print("   Pressione Ctrl+C para parar antecipadamente")
        print("-" * 50)
        
        try:
            comando = [
                'sudo', 'tcpdump',
                '-i', self.interface,
                '-nn',
                '-ttt',
                'ip',
                '-c', '50'  # Limite para demonstração
            ]
            
            processo = subprocess.Popen(comando, stdout=subprocess.PIPE, text=True)
            
            inicio = time.time()
            contador = 0
            
            for linha in processo.stdout:
                contador += 1
                dados = self.parse_linha(linha)
                if dados:
                    print(f"{contador:3d}. [{dados['timestamp']:8.6f}] {dados['ip_origem']:15} → Porta {dados['porta_destino']}")
                else:
                    # Mostra linha não parseada para debug
                    if len(linha.strip()) > 0 and 'IP' in linha:
                        print(f"{contador:3d}. [Não parseado] {linha.strip()[:80]}...")
                
                if time.time() - inicio > duracao:
                    processo.terminate()
                    break
                    
            print(f"\n✅ Monitoramento finalizado. Total de pacotes: {contador}")
                    
        except KeyboardInterrupt:
            print("\n⏹️  Monitoramento interrompido pelo usuário")
        except Exception as e:
            print(f"❌ Erro no monitoramento: {e}")
    
    def exportar_relatorio(self):
        """Exporta/mostra o relatório completo"""
        if not os.path.exists(self.arquivo_relatorio):
            print("❌ Nenhum relatório encontrado!")
            print("   Execute primeiro a análise completa (opção 3)")
            return
        
        print(f"\n📋 CONTEÚDO DO RELATÓRIO: {self.arquivo_relatorio}")
        print("="*50)
        
        with open(self.arquivo_relatorio, 'r') as f:
            conteudo = f.read()
            print(conteudo)
        
        print("="*50)
        print(f"✅ Relatório exportado: {self.arquivo_relatorio}")
        
        # Oferece opção para salvar com outro nome
        salvar_como = input("\nDeseja salvar com outro nome? (s/N): ").strip().lower()
        if salvar_como == 's':
            novo_nome = input("Novo nome do arquivo (ex: relatorio_scan.csv): ").strip()
            if novo_nome:
                import shutil
                shutil.copy2(self.arquivo_relatorio, novo_nome)
                print(f"✅ Relatório salvo como: {novo_nome}")

def main():
    analisador = AnalisadorTrafego()
    
    while True:
        print("\n" + "="*60)
        print("🛰️  ANALISADOR DE TRÁFEGO DE REDE")
        print("="*60)
        print("1 - Verificar interfaces disponíveis")
        print("2 - Monitorar tráfego em tempo real (30s)")
        print("3 - Realizar análise de tráfego (60s captura + análise)")
        print("4 - Mostrar estatísticas do último relatório")
        print("5 - Exportar relatório completo")
        print("0 - Sair")
        print("-"*60)
        
        if analisador.interface:
            print(f"🎯 Interface atual: {analisador.interface}")
        
        opcao = input("Escolha uma opção: ").strip()
        
        if opcao == '1':
            interfaces = analisador.verificar_interfaces()
            if interfaces:
                # Permite selecionar interface manualmente
                selecionar = input("\nDeseja selecionar uma interface? (s/N): ").strip().lower()
                if selecionar == 's':
                    try:
                        num = int(input("Número da interface: "))
                        if 1 <= num <= len(interfaces):
                            analisador.interface = interfaces[num-1]['nome']
                            print(f"✅ Interface selecionada: {analisador.interface}")
                        else:
                            print("❌ Número inválido!")
                    except ValueError:
                        print("❌ Por favor, digite um número válido")
        
        elif opcao == '2':
            analisador.monitorar_tempo_real(30)
        
        elif opcao == '3':
            analisador.realizar_analise_completa()
        
        elif opcao == '4':
            analisador.mostrar_estatisticas()
        
        elif opcao == '5':
            analisador.exportar_relatorio()
        
        elif opcao == '0':
            print("👋 Saindo...")
            break
        
        else:
            print("❌ Opção inválida!")

if __name__ == "__main__":
    # Verifica se está rodando como root
    import os
    if os.geteuid() != 0:
        print("⚠️  AVISO: Algumas funcionalidades requerem privilégios de root")
        print("   Execute com 'sudo python3 analise_trafego.py' para melhor experiência")
        print()
    
    main()