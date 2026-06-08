import sys
import struct
import socket
import time
import argparse

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog,
    QDoubleSpinBox, QProgressBar, QFrame, QComboBox, QCheckBox,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


_LINKTYPE_ETHERNET  = 1
_LINKTYPE_RAW       = 101
_LINKTYPE_LINUX_SLL = 113


def read_pcap(path: str) -> list:
    packets = []
    with open(path, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
        if   magic == 0xa1b2c3d4: endian = '<'
        elif magic == 0xd4c3b2a1: endian = '>'
        elif magic in (0x0a0d0d0a, 0x4d3c2b1a):
            raise ValueError("Formato pcapng. Guardalo como .pcap desde Wireshark.")
        else:
            raise ValueError(f"Archivo no reconocido (magic: {magic:08X})")

        f.read(4); f.read(8); f.read(4)
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
            result = _extract_payload(data, linktype)
            if result:
                payload, ip_src, ip_dst, proto = result
                packets.append((ts, payload, ip_src, ip_dst, proto))

    return packets


def _extract_payload(data: bytes, linktype: int):
    try:
        if   linktype == _LINKTYPE_ETHERNET:  offset = 14
        elif linktype == _LINKTYPE_LINUX_SLL: offset = 16
        elif linktype == _LINKTYPE_RAW:       offset = 0
        else: return None

        if offset + 20 > len(data): return None
        if (data[offset] >> 4) != 4: return None

        ihl   = (data[offset] & 0x0F) * 4
        proto = data[offset + 9]
        ip_src = socket.inet_ntoa(data[offset + 12:offset + 16])
        ip_dst = socket.inet_ntoa(data[offset + 16:offset + 20])
        end   = offset + ihl

        if proto == 17:
            payload    = data[end + 8:]
            proto_str  = "UDP"
        elif proto == 6:
            tcp_hdr   = ((data[end + 12] >> 4) & 0xF) * 4
            payload   = data[end + tcp_hdr:]
            proto_str = "TCP"
        else:
            return None

        return (payload, ip_src, ip_dst, proto_str) if payload else None
    except Exception:
        return None


class PlayerWorker(QThread):
    progress = pyqtSignal(int, int, float)
    finished = pyqtSignal()
    error    = pyqtSignal(str)

    def __init__(self, packets, dst_ip, dst_port, speed, loop=False):
        super().__init__()
        self._packets  = packets
        self._dst_ip   = dst_ip
        self._dst_port = dst_port
        self._speed    = speed
        self._loop     = loop
        self._paused   = False
        self._stopped  = False

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            total     = len(self._packets)
            t0_pcap   = self._packets[0][0]
            iteration = 0

            while True:
                t0_real = time.perf_counter()
                for i, (ts, payload, *_) in enumerate(self._packets):
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

                if not self._loop:
                    break
                iteration += 1
                self.progress.emit(0, total, 0.0)

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


class PcapPlayer(QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PCAP Player")
        self.setFixedSize(560, 310)
        self._packets = []
        self._worker  = None
        self._build_ui()

    def _build_ui(self):
        lay = QVBoxLayout(self)
        lay.setSpacing(8)
        lay.setContentsMargins(18, 14, 18, 14)

        # ── Archivo ───────────────────────────────────────────────────────
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

        # ── Destino ───────────────────────────────────────────────────────
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("IP destino:"))
        self._ip_edit = QLineEdit("127.0.0.1")
        self._ip_edit.setFixedWidth(115)
        row2.addWidget(self._ip_edit)
        row2.addWidget(QLabel("Puerto:"))
        self._port_edit = QLineEdit("3460")
        self._port_edit.setFixedWidth(55)
        row2.addWidget(self._port_edit)
        row2.addWidget(QLabel("Vel:"))
        self._speed = QDoubleSpinBox()
        self._speed.setRange(0.1, 100.0)
        self._speed.setValue(1.0)
        self._speed.setSingleStep(0.5)
        self._speed.setSuffix(" x")
        self._speed.setFixedWidth(70)
        row2.addWidget(self._speed)
        self._loop_chk = QCheckBox("Bucle")
        self._loop_chk.setToolTip("Repetir la reproduccion indefinidamente")
        row2.addWidget(self._loop_chk)
        row2.addStretch()
        lay.addLayout(row2)

        # ── Filtros ───────────────────────────────────────────────────────
        row_f = QHBoxLayout()
        row_f.addWidget(QLabel("Proto:"))
        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["Todos", "UDP", "TCP"])
        self._proto_combo.setFixedWidth(68)
        self._proto_combo.currentTextChanged.connect(self._on_filter_changed)
        row_f.addWidget(self._proto_combo)
        row_f.addWidget(QLabel("Origen:"))
        self._src_edit = QLineEdit()
        self._src_edit.setPlaceholderText("vacío = todos")
        self._src_edit.setFixedWidth(115)
        self._src_edit.textChanged.connect(self._on_filter_changed)
        row_f.addWidget(self._src_edit)
        row_f.addWidget(QLabel("Destino:"))
        self._dst_edit = QLineEdit()
        self._dst_edit.setPlaceholderText("vacío = todos")
        self._dst_edit.setFixedWidth(115)
        self._dst_edit.textChanged.connect(self._on_filter_changed)
        row_f.addWidget(self._dst_edit)
        row_f.addStretch()
        lay.addLayout(row_f)

        # ── Separador ─────────────────────────────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #333;")
        lay.addWidget(sep)

        # ── Progreso ──────────────────────────────────────────────────────
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        lay.addWidget(self._bar)

        self._status = QLabel("Carga un archivo .pcap para comenzar.")
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._status)

        # ── Botones ───────────────────────────────────────────────────────
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

    def _filtered_packets(self):
        proto_f = self._proto_combo.currentText()
        src_f   = self._src_edit.text().strip()
        dst_f   = self._dst_edit.text().strip()
        result  = []
        for pkt in self._packets:
            _, _, ip_src, ip_dst, proto = pkt
            if proto_f not in ("Todos", "") and proto != proto_f:
                continue
            if src_f and ip_src != src_f:
                continue
            if dst_f and ip_dst != dst_f:
                continue
            result.append(pkt)
        return result

    def _on_filter_changed(self):
        if not self._packets:
            return
        n = len(self._filtered_packets())
        total = len(self._packets)
        self._status.setText(f"{n} / {total} paquetes con los filtros actuales")

    def _open(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Abrir PCAP", "", "PCAP (*.pcap);;Todos (*.*)")
        if not path:
            return
        try:
            self._packets = read_pcap(path)
            dur = (self._packets[-1][0] - self._packets[0][0]) if len(self._packets) > 1 else 0
            self._path_lbl.setText(path)
            self._status.setText(f"{len(self._packets)} paquetes  ·  {dur:.1f} s")
            self._bar.setValue(0)
            self._on_filter_changed()
        except Exception as e:
            self._status.setText(str(e))

    def _play(self):
        if not self._packets:
            self._status.setText("Primero carga un archivo .pcap")
            return
        filtered = self._filtered_packets()
        if not filtered:
            self._status.setText("Ningún paquete coincide con los filtros.")
            return
        try:
            dst_ip   = self._ip_edit.text().strip()
            dst_port = int(self._port_edit.text().strip())
        except ValueError:
            self._status.setText("Puerto invalido")
            return

        self._worker = PlayerWorker(filtered, dst_ip, dst_port, self._speed.value(),
                                    loop=self._loop_chk.isChecked())
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(lambda m: self._status.setText(f"Error: {m}"))
        self._worker.start()

        self._btn_play.setEnabled(False)
        self._btn_pause.setEnabled(True)
        self._btn_stop.setEnabled(True)
        self._speed.setEnabled(False)
        proto_f = self._proto_combo.currentText()
        self._status.setText(
            f"Enviando {len(filtered)} paquetes [{proto_f}] a {dst_ip}:{dst_port} "
            f"@ {self._speed.value()}x")

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
        if current == 0:
            self._bar.setValue(0)
            self._status.setText("Bucle — reiniciando...")
            return
        self._bar.setValue(int(current / total * 100))
        loop_txt = "  [bucle]" if self._loop_chk.isChecked() else ""
        self._status.setText(f"Paquete {current} / {total}   t = {elapsed:.1f} s{loop_txt}")

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


def _filter_packets(packets, proto, src, dst):
    result = []
    for pkt in packets:
        _, _, ip_src, ip_dst, p = pkt
        if proto and proto.upper() not in ("TODOS", "") and p != proto.upper():
            continue
        if src and ip_src != src:
            continue
        if dst and ip_dst != dst:
            continue
        result.append(pkt)
    return result


def run_cli(args):
    try:
        packets = read_pcap(args.file)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    filtered = _filter_packets(packets, args.proto, args.src, args.dst)
    if not filtered:
        print("Ningún paquete coincide con los filtros.")
        sys.exit(1)

    total = len(filtered)
    dur   = filtered[-1][0] - filtered[0][0] if total > 1 else 0
    print(f"Archivo : {args.file}")
    print(f"Paquetes: {total}  ·  Duración: {dur:.1f} s")
    print(f"Destino : {args.ip}:{args.port}  ·  Velocidad: {args.speed}x  ·  Bucle: {args.loop}")
    print()

    sock      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    iteration = 0
    BAR       = 30

    try:
        while True:
            t0_pcap = filtered[0][0]
            t0_real = time.perf_counter()

            for i, (ts, payload, *_) in enumerate(filtered):
                elapsed = ts - t0_pcap
                t_pcap  = elapsed / args.speed
                t_real  = time.perf_counter() - t0_real
                wait    = t_pcap - t_real
                if wait > 0:
                    time.sleep(wait)

                try:
                    sock.sendto(payload, (args.ip, args.port))
                except OSError as e:
                    print(f"\nError enviando: {e}")

                filled   = int(BAR * (i + 1) / total)
                bar      = '█' * filled + '░' * (BAR - filled)
                loop_txt = f"  [bucle #{iteration + 1}]" if args.loop else ""
                print(f"\r[{bar}] {(i+1)/total*100:5.1f}%  {i+1}/{total}  t={elapsed:.1f}s{loop_txt}",
                      end='', flush=True)

            print()
            if not args.loop:
                break
            iteration += 1
            print(f"Reiniciando bucle #{iteration + 1}...")

    except KeyboardInterrupt:
        print("\nDetenido.")
    finally:
        sock.close()

    print("Reproducción finalizada.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PCAP Player — sin argumentos abre la GUI",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("file",          nargs="?",           help="Archivo .pcap a reproducir")
    parser.add_argument("--ip",          default="127.0.0.1", help="IP destino        (default: 127.0.0.1)")
    parser.add_argument("--port",        default=3460, type=int, help="Puerto destino  (default: 3460)")
    parser.add_argument("--speed",       default=1.0,  type=float, help="Velocidad     (default: 1.0)")
    parser.add_argument("--loop",        action="store_true", help="Repetir indefinidamente")
    parser.add_argument("--proto",       default="",          help="Filtro protocolo: UDP | TCP")
    parser.add_argument("--src",         default="",          help="Filtro IP origen")
    parser.add_argument("--dst",         default="",          help="Filtro IP destino")

    args = parser.parse_args()

    if args.file:
        run_cli(args)
    else:
        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        win = PcapPlayer()
        win.show()
        sys.exit(app.exec())
