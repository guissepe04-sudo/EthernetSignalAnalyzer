"""
PCAP Player — reproduce un archivo .pcap enviando los payloads por UDP
para que el analizador en vivo los capture en tiempo real.

Uso: python pcap_player.py
"""

import sys
import struct
import socket
import time

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog,
    QDoubleSpinBox, QProgressBar, QFrame,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


# ── Lectura de PCAP ───────────────────────────────────────────────────────────

_LINKTYPE_ETHERNET  = 1
_LINKTYPE_RAW       = 101
_LINKTYPE_LINUX_SLL = 113


def read_pcap(path: str) -> list:
    """Devuelve lista de (timestamp_float, payload_bytes) con UDP y TCP payloads."""
    packets = []
    with open(path, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        elif magic in (0x0a0d0d0a, 0x4d3c2b1a):
            raise ValueError("Formato pcapng detectado. Guardalo como .pcap desde Wireshark:\n  Archivo → Guardar como → pcap")
        else:
            raise ValueError(f"Archivo no reconocido (magic: {magic:08X})")

        f.read(4)   # major + minor version
        f.read(8)   # timezone + accuracy
        f.read(4)   # snaplen
        linktype = struct.unpack(endian + 'I', f.read(4))[0]

        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + 'IIII', hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            ts = ts_sec + ts_usec / 1_000_000.0
            payload = _extract_payload(data, linktype)
            if payload:
                packets.append((ts, payload))

    return packets


def _extract_payload(data: bytes, linktype: int):
    try:
        if   linktype == _LINKTYPE_ETHERNET:  offset = 14
        elif linktype == _LINKTYPE_LINUX_SLL: offset = 16
        elif linktype == _LINKTYPE_RAW:       offset = 0
        else: return None

        if offset + 20 > len(data): return None
        if (data[offset] >> 4) != 4: return None   # not IPv4

        ihl   = (data[offset] & 0x0F) * 4
        proto = data[offset + 9]
        end   = offset + ihl

        if proto == 17:   # UDP
            payload = data[end + 8:]
        elif proto == 6:  # TCP
            tcp_hdr = ((data[end + 12] >> 4) & 0xF) * 4
            payload = data[end + tcp_hdr:]
        else:
            return None

        return payload if payload else None
    except Exception:
        return None


# ── Worker ────────────────────────────────────────────────────────────────────

class PlayerWorker(QThread):
    progress = pyqtSignal(int, int, float)   # actual, total, t_relativo
    finished = pyqtSignal()
    error    = pyqtSignal(str)

    def __init__(self, packets, dst_ip, dst_port, speed):
        super().__init__()
        self._packets  = packets
        self._dst_ip   = dst_ip
        self._dst_port = dst_port
        self._speed    = speed
        self._paused   = False
        self._stopped  = False

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            t0_pcap = self._packets[0][0]
            t0_real = time.perf_counter()
            total   = len(self._packets)

            for i, (ts, payload) in enumerate(self._packets):
                while self._paused:
                    if self._stopped: return
                    time.sleep(0.05)
                if self._stopped:
                    return

                t_pcap = (ts - t0_pcap) / self._speed
                t_real = time.perf_counter() - t0_real
                wait   = t_pcap - t_real
                if wait > 0:
                    time.sleep(wait)

                try:
                    sock.sendto(payload, (self._dst_ip, self._dst_port))
                except OSError:
                    pass

                if i % 10 == 0 or i == total - 1:
                    self.progress.emit(i + 1, total, ts - t0_pcap)

        except Exception as e:
            self.error.emit(str(e))
        finally:
            sock.close()
            self.finished.emit()

    def pause_resume(self):
        self._paused = not self._paused

    def stop(self):
        self._stopped = True
        self._paused  = False


# ── Ventana ───────────────────────────────────────────────────────────────────

class PcapPlayer(QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PCAP Player")
        self.setFixedSize(500, 260)
        self._packets = []
        self._worker  = None
        self._build_ui()

    def _build_ui(self):
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(18, 18, 18, 18)

        # ── Archivo ───────────────────────────────────────────────────────────
        row1 = QHBoxLayout()
        self._path_lbl = QLineEdit()
        self._path_lbl.setPlaceholderText("Selecciona un archivo .pcap...")
        self._path_lbl.setReadOnly(True)
        row1.addWidget(self._path_lbl, 1)
        btn_open = QPushButton("Abrir")
        btn_open.setFixedWidth(70)
        btn_open.clicked.connect(self._open)
        row1.addWidget(btn_open)
        lay.addLayout(row1)

        # ── Destino ───────────────────────────────────────────────────────────
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("IP destino:"))
        self._ip_edit = QLineEdit("127.0.0.1")
        self._ip_edit.setFixedWidth(120)
        row2.addWidget(self._ip_edit)
        row2.addWidget(QLabel("Puerto:"))
        self._port_edit = QLineEdit("3460")
        self._port_edit.setFixedWidth(60)
        row2.addWidget(self._port_edit)
        row2.addWidget(QLabel("Velocidad:"))
        self._speed = QDoubleSpinBox()
        self._speed.setRange(0.1, 100.0)
        self._speed.setValue(1.0)
        self._speed.setSingleStep(0.5)
        self._speed.setSuffix(" x")
        self._speed.setFixedWidth(75)
        row2.addWidget(self._speed)
        row2.addStretch()
        lay.addLayout(row2)

        # ── Separador ─────────────────────────────────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #333;")
        lay.addWidget(sep)

        # ── Progreso ──────────────────────────────────────────────────────────
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        lay.addWidget(self._bar)

        self._status = QLabel("Carga un archivo .pcap para comenzar.")
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._status)

        # ── Botones ───────────────────────────────────────────────────────────
        row3 = QHBoxLayout()
        self._btn_play  = QPushButton("▶  Play")
        self._btn_pause = QPushButton("⏸  Pausar")
        self._btn_stop  = QPushButton("⏹  Detener")
        self._btn_play.clicked.connect(self._play)
        self._btn_pause.clicked.connect(self._pause)
        self._btn_stop.clicked.connect(self._stop)
        self._btn_pause.setEnabled(False)
        self._btn_stop.setEnabled(False)
        row3.addWidget(self._btn_play)
        row3.addWidget(self._btn_pause)
        row3.addWidget(self._btn_stop)
        lay.addLayout(row3)

    # ── Acciones ──────────────────────────────────────────────────────────────

    def _open(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Abrir PCAP", "", "PCAP (*.pcap);;Todos (*.*)")
        if not path:
            return
        try:
            self._packets = read_pcap(path)
            dur = (self._packets[-1][0] - self._packets[0][0]) if len(self._packets) > 1 else 0
            self._path_lbl.setText(path)
            self._status.setText(f"{len(self._packets)} paquetes  ·  {dur:.1f} s de duracion")
            self._bar.setValue(0)
        except Exception as e:
            self._status.setText(str(e))

    def _play(self):
        if not self._packets:
            self._status.setText("Primero carga un archivo .pcap")
            return
        try:
            dst_ip   = self._ip_edit.text().strip()
            dst_port = int(self._port_edit.text().strip())
        except ValueError:
            self._status.setText("Puerto invalido")
            return

        self._worker = PlayerWorker(
            self._packets, dst_ip, dst_port, self._speed.value())
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(lambda m: self._status.setText(f"Error: {m}"))
        self._worker.start()

        self._btn_play.setEnabled(False)
        self._btn_pause.setEnabled(True)
        self._btn_stop.setEnabled(True)
        self._speed.setEnabled(False)
        self._status.setText(f"Enviando a {dst_ip}:{dst_port}  @ {self._speed.value()}x")

    def _pause(self):
        if not self._worker:
            return
        self._worker.pause_resume()
        self._btn_pause.setText(
            "▶  Reanudar" if self._worker._paused else "⏸  Pausar")

    def _stop(self):
        if self._worker:
            self._worker.stop()

    def _on_progress(self, current, total, elapsed):
        self._bar.setValue(int(current / total * 100))
        self._status.setText(f"Paquete {current} / {total}   t = {elapsed:.1f} s")

    def _on_finished(self):
        self._btn_play.setEnabled(True)
        self._btn_pause.setEnabled(False)
        self._btn_stop.setEnabled(False)
        self._btn_pause.setText("⏸  Pausar")
        self._speed.setEnabled(True)
        self._bar.setValue(100)
        if not self._worker or not self._worker._stopped:
            self._status.setText("Reproduccion finalizada.")
        self._worker = None


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = PcapPlayer()
    win.show()
    sys.exit(app.exec())
