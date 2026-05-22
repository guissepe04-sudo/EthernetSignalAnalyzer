# build_linux.ps1 — Genera el binario Linux desde Windows usando Docker
# Requiere Docker Desktop instalado y corriendo
# Ejecutar desde la carpeta SANDVIK:  .\build_linux.ps1

Set-Location $PSScriptRoot

Write-Host "Construyendo imagen Docker..."
docker build -f Dockerfile.linux -t ethernet-analyzer-linux .

Write-Host "Extrayendo binario..."
docker create --name temp-linux-build ethernet-analyzer-linux | Out-Null
docker cp temp-linux-build:/app/dist/EthernetSignalAnalyzer ./dist/EthernetSignalAnalyzer
docker rm temp-linux-build | Out-Null

Write-Host ""
Write-Host "Listo. El binario Linux esta en:  dist\EthernetSignalAnalyzer"
Write-Host ""
Write-Host "IMPORTANTE: La maquina destino necesita tshark instalado:"
Write-Host "  Ubuntu/Debian:  sudo apt install tshark"
Write-Host "  Fedora:         sudo dnf install wireshark-cli"
