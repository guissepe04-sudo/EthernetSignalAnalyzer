"""
Ethernet Signal Analyzer — punto de entrada.
Uso: python main.py
"""

import sys
from PyQt6.QtWidgets import QApplication
from app.window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
