#!/bin/bash
# build.sh — Genera el binario de Ethernet Signal Analyzer para Linux
# Ejecutar desde la carpeta del proyecto:  bash build.sh

set -e
cd "$(dirname "$0")"

echo "Creando entorno virtual..."
python3 -m venv .venv

echo "Activando entorno virtual..."
source .venv/bin/activate

echo "Instalando dependencias..."
pip install --quiet -r requirements.txt pyinstaller

echo "Generando ejecutable..."
pyinstaller \
    --onefile \
    --windowed \
    --name "EthernetSignalAnalyzer" \
    --hidden-import "PyQt6.sip" \
    --hidden-import "matplotlib.backends.backend_qtagg" \
    --collect-all "matplotlib" \
    --collect-all "numpy" \
    main.py

echo ""
echo "Listo. El ejecutable esta en:  dist/EthernetSignalAnalyzer"
echo ""
echo "IMPORTANTE: La maquina necesita tshark instalado:"
echo "  Ubuntu/Debian:  sudo apt install tshark"
echo "  Fedora:         sudo dnf install wireshark-cli"
echo "  Arch:           sudo pacman -S wireshark-cli"
