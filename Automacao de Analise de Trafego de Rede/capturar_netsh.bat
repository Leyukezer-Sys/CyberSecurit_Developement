@echo off
echo === Captura de Tráfego com netsh ===
echo.

REM Configuracoes
set DURACAO=300
set ARQUIVO_SAIDA=trafego_netsh.txt

echo Capturando trafego por %DURACAO% segundos...
echo Execute algumas atividades de rede (navegar, downloads, etc.)

REM Capturar trafego de rede usando netsh
netsh trace start capture=yes provider=Microsoft-Windows-TCPIP level=5 maxsize=100

echo Aguardando %DURACAO% segundos...
timeout /t %DURACAO% /nobreak >nul

echo Parando captura...
netsh trace stop

REM Converter para formato legivel
netsh trace convert %ARQUIVO_SAIDA%

echo Captura concluida! Arquivo: %ARQUIVO_SAIDA%
pause