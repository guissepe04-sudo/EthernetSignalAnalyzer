# build.ps1 — Genera el .exe de Ethernet Signal Analyzer
# Ejecutar desde la carpeta SANDVIK:  .\build.ps1

Set-Location $PSScriptRoot

Write-Host "Activando entorno virtual..."
& ".\.venv\Scripts\Activate.ps1"

Write-Host "Instalando PyInstaller si no esta presente..."
pip install pyinstaller --quiet

Write-Host "Generando ejecutable..."
pyinstaller `
    --onedir `
    --windowed `
    --name "EthernetSignalAnalyzer" `
    --hidden-import "PyQt6.sip" `
    --hidden-import "matplotlib.backends.backend_qtagg" `
    --collect-all "matplotlib" `
    --collect-all "numpy" `
    main.py

Write-Host ""
Write-Host "Listo. El ejecutable esta en:  dist\EthernetSignalAnalyzer\"
Write-Host ""
Write-Host "IMPORTANTE: La maquina destino necesita Wireshark instalado"
Write-Host "  (tshark.exe en C:\Program Files\Wireshark\)"
Write-Host "  Descarga: https://www.wireshark.org/download.html"
