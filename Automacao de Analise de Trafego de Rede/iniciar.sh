#!/bin/bash

# =============================================
# ANALISADOR DE TRÁFEGO - INSTALADOR & EXECUTOR
# =============================================

set -e  # Para em caso de erro

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funções de log
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCESSO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[AVISO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERRO]${NC} $1"
}

# Banner de início
show_banner() {
    echo -e "${GREEN}"
    echo "============================================="
    echo "   ANALISADOR DE TRÁFEGO DE REDE"
    echo "============================================="
    echo -e "${NC}"
}

# Verificar dependências
check_dependencies() {
    local missing=0
    
    echo "Verificando dependências..."
    
    # Verificar tcpdump
    if ! command -v tcpdump &> /dev/null; then
        echo -e "${RED}✗ tcpdump não encontrado${NC}"
        missing=1
    else
        echo -e "${GREEN}✓ tcpdump instalado${NC}"
    fi
    
    # Verificar python3
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}✗ python3 não encontrado${NC}"
        missing=1
    else
        echo -e "${GREEN}✓ python3 instalado${NC}"
    fi
    
    # Verificar script principal
    if [ ! -f "analise_trafego.py" ]; then
        echo -e "${RED}✗ analise_trafego.py não encontrado${NC}"
        missing=1
    else
        echo -e "${GREEN}✓ Script principal encontrado${NC}"
    fi
    
    return $missing
}

# Verificar se é root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_info "Executando como root"
    else
        log_warning "Recomendado executar como root para instalação completa"
        read -p "Deseja continuar? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            log_info "Saindo..."
            exit 1
        fi
    fi
}

# Detectar distribuição
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    else
        log_error "Não foi possível detectar a distribuição"
        exit 1
    fi
}

# Instalar dependências
install_dependencies() {
    log_info "Detectada distribuição: $DISTRO"
    log_info "Atualizando repositórios..."
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt update
            log_info "Instalando dependências..."
            sudo apt install -y tcpdump python3 python3-pip
            ;;
        fedora|centos|rhel)
            if command -v dnf &> /dev/null; then
                sudo dnf update
                sudo dnf install -y tcpdump python3 python3-pip
            else
                sudo yum update
                sudo yum install -y tcpdump python3 python3-pip
            fi
            ;;
        arch|manjaro)
            sudo pacman -Sy
            sudo pacman -S --noconfirm tcpdump python python-pip
            ;;
        *)
            log_error "Distribuição não suportada: $DISTRO"
            log_info "Instale manualmente: tcpdump python3 python3-pip"
            exit 1
            ;;
    esac
    
    log_success "Dependências instaladas com sucesso"
}

# Verificar instalações
verify_installations() {
    log_info "Verificando instalações..."
    
    # Verificar tcpdump
    if command -v tcpdump &> /dev/null; then
        log_success "tcpdump instalado: $(tcpdump --version 2>&1 | head -n1)"
    else
        log_error "tcpdump não instalado corretamente"
        exit 1
    fi
    
    # Verificar python3
    if command -v python3 &> /dev/null; then
        log_success "Python3 instalado: $(python3 --version)"
    else
        log_error "Python3 não instalado corretamente"
        exit 1
    fi
    
    # Verificar pip3
    if command -v pip3 &> /dev/null; then
        log_success "pip3 instalado: $(pip3 --version)"
    else
        log_warning "pip3 não encontrado, algumas funcionalidades podem ser limitadas"
    fi
}

# Verificar se o script Python existe
check_python_script() {
    if [ ! -f "analise_trafego.py" ]; then
        log_error "Arquivo analise_trafego.py não encontrado!"
        log_info "Certifique-se de que o arquivo está no mesmo diretório"
        exit 1
    fi
    
    # Tornar executável
    chmod +x analise_trafego.py
    log_success "Script Python tornado executável"
}

# Testar funcionalidades básicas
test_functionality() {
    log_info "Testando funcionalidades básicas..."
    
    # Testar tcpdump
    if sudo tcpdump --version &> /dev/null; then
        log_success "tcpdump funcionando corretamente"
    else
        log_error "Problema com tcpdump"
    fi
    
    # Testar Python
    if python3 -c "import sys; print('Python OK')" &> /dev/null; then
        log_success "Python funcionando corretamente"
    else
        log_error "Problema com Python"
    fi
}

# Mostrar resumo da instalação
show_install_summary() {
    echo -e "${GREEN}"
    echo "============================================="
    echo "         INSTALAÇÃO CONCLUÍDA!"
    echo "============================================="
    echo -e "${NC}"
    
    log_success "Sistema pronto para uso!"
    echo
    log_info "FUNCIONALIDADES DISPONÍVEIS:"
    echo "  ✓ Verificação de interfaces de rede"
    echo "  ✓ Monitoramento em tempo real"
    echo "  ✓ Captura de tráfego"
    echo "  ✓ Detecção de port scans"
    echo "  ✓ Relatórios em CSV"
    echo
}

# Função de instalação completa
run_installation() {
    echo -e "${YELLOW}"
    echo "Iniciando instalação das dependências..."
    echo -e "${NC}"
    
    log_info "Iniciando instalação..."
    check_root
    detect_distro
    install_dependencies
    verify_installations
    check_python_script
    test_functionality
    show_install_summary
}

# Função para executar o analisador
run_analyzer() {
    echo -e "${GREEN}"
    echo "Todas as dependências OK!"
    echo "Iniciando analisador de tráfego..."
    echo -e "${NC}"
    
    # Verificar se está rodando como root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Aviso: Executando sem sudo, algumas funcionalidades podem ser limitadas${NC}"
        echo -e "${YELLOW}Para experiência completa, execute: sudo python3 analise_trafego.py${NC}"
        echo
        read -p "Pressione Enter para continuar sem sudo ou Ctrl+C para sair e executar com sudo..."
        python3 analise_trafego.py
    else
        python3 analise_trafego.py
    fi
}

# Função principal
main() {
    show_banner
    
    # Verificar dependências
    check_dependencies
    
    # Tomar ação baseada no resultado
    if [ $? -eq 0 ]; then
        run_analyzer
    else
        run_installation
        
        # Após instalação, verificar novamente e executar se estiver OK
        echo
        echo -e "${YELLOW}Verificando dependências após instalação...${NC}"
        if check_dependencies; then
            run_analyzer
        else
            echo -e "${RED}Erro: Ainda faltam dependências após instalação${NC}"
            echo -e "${YELLOW}Tente instalar manualmente: sudo apt install tcpdump python3 python3-pip${NC}"
            exit 1
        fi
    fi
}

# Executar função principal
main "$@"