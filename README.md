# EthernetSignalAnalyzer

Herramienta de escritorio para analizar señales de red desde archivos `.pcap`.
Lee capturas de Wireshark, decodifica dos protocolos propietarios binarios y visualiza las señales en tiempo real.

## Requisitos

- Python 3.11+
- [Wireshark](https://www.wireshark.org/download.html) instalado (para `tshark`)

## Instalación y ejecución

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
python main.py
```

## Generar ejecutable

**Windows:**
```powershell
.\build.ps1
```

**Linux:**
```bash
bash build.sh
```

El binario queda en `dist/`.
