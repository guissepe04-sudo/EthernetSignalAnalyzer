"""
Workers QObject para ejecutar tshark y el análisis en hilos separados.
El patrón QObject + moveToThread evita bloquear la UI durante el procesamiento.
"""

import traceback
from PyQt6.QtCore import QObject, pyqtSignal

from .tshark import run_tshark
from .analysis import analyze_signals


class AnalysisWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(list, dict, float, float)
    error    = pyqtSignal(str)

    def __init__(self, tshark: str, pcap: str, proto: str, src: str, dst: str):
        super().__init__()
        self._tshark = tshark
        self._pcap   = pcap
        self._proto  = proto
        self._src    = src
        self._dst    = dst

    def run(self):
        try:
            pkts = run_tshark(self._tshark, self._pcap)
            self.progress.emit(f"{len(pkts)} paquetes extraidos. Analizando senales...")
            sigs  = analyze_signals(pkts, self._proto, self._src, self._dst)
            all_t = [t for v in sigs.values() for t in v["ts"]]
            t0    = min(all_t) if all_t else 0.0
            dur   = (max(all_t) - t0) if all_t else 0.0
            self.finished.emit(pkts, sigs, t0, dur)
        except Exception as e:
            traceback.print_exc()
            self.error.emit(str(e))
