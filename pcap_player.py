import sys
import struct
import socket
import time
import argparse
import math
import threading


_LINKTYPE_ETHERNET  = 1
_LINKTYPE_RAW       = 101
_LINKTYPE_LINUX_SLL = 113


# ── PCAP reader ───────────────────────────────────────────────────────────────

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
            ts     = ts_sec + ts_usec / 1_000_000.0
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

        ihl    = (data[offset] & 0x0F) * 4
        proto  = data[offset + 9]
        ip_src = socket.inet_ntoa(data[offset + 12:offset + 16])
        ip_dst = socket.inet_ntoa(data[offset + 16:offset + 20])
        end    = offset + ihl

        if proto == 17:
            payload   = data[end + 8:]
            proto_str = "UDP"
        elif proto == 6:
            tcp_hdr   = ((data[end + 12] >> 4) & 0xF) * 4
            payload   = data[end + tcp_hdr:]
            proto_str = "TCP"
        else:
            return None

        return (payload, ip_src, ip_dst, proto_str) if payload else None
    except Exception:
        return None


# ── Signal decoders ───────────────────────────────────────────────────────────

def _val4_le(b: bytes):
    f = struct.unpack_from('<f', b)[0]
    return f if (not math.isnan(f) and not math.isinf(f) and 1e-3 < abs(f) < 1e7) \
             else struct.unpack_from('<I', b)[0]

def _val8_le(b: bytes):
    f = struct.unpack_from('<d', b)[0]
    return f if (not math.isnan(f) and not math.isinf(f)) \
             else struct.unpack_from('<Q', b)[0]


def decode_payload_udp(payload: bytes) -> list:
    results = []
    if len(payload) < 20:
        return results
    offset = 20
    while offset + 4 <= len(payload):
        tipo, cat, dlen = payload[offset], payload[offset + 1], payload[offset + 2]
        block = 4 + ((dlen + 3) // 4) * 4
        if block < 8:
            break
        if tipo == 0x01 and cat != 0x8F and dlen >= 5 and offset + 4 + dlen <= len(payload):
            sid = struct.unpack_from('<I', payload, offset + 4)[0]
            vb  = payload[offset + 8: offset + 4 + dlen]
            vl  = dlen - 4
            if   vl == 1: results.append((sid, vb[0]))
            elif vl == 2: results.append((sid, struct.unpack_from('<H', vb)[0]))
            elif vl == 4: results.append((sid, _val4_le(vb)))
            elif vl == 8: results.append((sid, _val8_le(vb)))
        offset += block
    return results


def decode_payload_tcp(payload: bytes) -> list:
    results = []
    offset = 0
    while offset + 12 <= len(payload):
        dlen   = payload[offset + 10]
        status = payload[offset + 11]
        rec    = 12 + max(4, ((dlen + 3) // 4) * 4)
        if rec < 12:
            break
        if status != 0x57 and dlen > 0 and offset + 12 + dlen <= len(payload):
            sid = struct.unpack_from('<I', payload, offset + 4)[0]
            vb  = payload[offset + 12: offset + 12 + dlen]
            if   dlen == 1: results.append((sid, vb[0]))
            elif dlen == 2: results.append((sid, struct.unpack_from('>H', vb)[0]))
            elif dlen == 4:
                f = struct.unpack_from('>f', vb)[0]
                results.append((sid, f if not math.isnan(f) and not math.isinf(f)
                                      else struct.unpack_from('>I', vb)[0]))
            elif dlen == 8:
                f = struct.unpack_from('>d', vb)[0]
                results.append((sid, f if not math.isnan(f) and not math.isinf(f)
                                      else struct.unpack_from('>Q', vb)[0]))
        offset += rec
    return results


# ── Shared helpers ────────────────────────────────────────────────────────────

def filter_packets(packets, proto, src, dst) -> list:
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


# ── CLI mode (no Qt) ──────────────────────────────────────────────────────────

def run_cli(args):
    try:
        packets = read_pcap(args.file)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    filtered = filter_packets(packets, args.proto, args.src, args.dst)
    if not filtered:
        print("Ningún paquete coincide con los filtros.")
        sys.exit(1)

    total = len(filtered)
    dur   = filtered[-1][0] - filtered[0][0] if total > 1 else 0
    print(f"Archivo : {args.file}")
    print(f"Paquetes: {total}  ·  Duración: {dur:.1f} s")
    print(f"Destino : {args.ip}:{args.port}  ·  Velocidad: {args.speed}x  ·  Bucle: {args.loop}")
    print("Presiona Ctrl+C para detener.")
    print()

    stop_evt = threading.Event()
    sock     = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    BAR      = 20

    def _send_loop():
        iteration = 0
        while not stop_evt.is_set():
            t0_pcap = filtered[0][0]
            t0_real = time.perf_counter()

            for i, (ts, payload, *_, proto) in enumerate(filtered):
                if stop_evt.is_set():
                    return

                elapsed = ts - t0_pcap
                wait    = elapsed / args.speed - (time.perf_counter() - t0_real)
                if wait > 0:
                    if stop_evt.wait(timeout=wait):
                        return

                try:
                    sock.sendto(payload, (args.ip, args.port))
                except OSError as e:
                    print(f"\nError enviando: {e}", flush=True)

                sigs    = decode_payload_udp(payload) if proto == "UDP" else decode_payload_tcp(payload)
                sig_str = "  ".join(f"0x{sid:04X}={val:.4g}" for sid, val in sigs[:4])
                if not sig_str:
                    sig_str = f"[{proto} {len(payload)}b sin señales]"

                filled   = int(BAR * (i + 1) / total)
                bar      = '█' * filled + '░' * (BAR - filled)
                loop_txt = f" [#{iteration + 1}]" if args.loop else ""
                line     = f"\r[{bar}] {(i+1)/total*100:5.1f}% t={elapsed:.1f}s{loop_txt} | {sig_str}"
                print(f"{line:<110}", end='', flush=True)

            print()
            if not args.loop:
                return
            iteration += 1
            print(f"Reiniciando bucle #{iteration + 1}...")

    t = threading.Thread(target=_send_loop, daemon=True)
    t.start()

    try:
        while t.is_alive():
            t.join(timeout=0.2)
    except KeyboardInterrupt:
        stop_evt.set()
        t.join(timeout=1)
        print("\nDetenido.")
    finally:
        sock.close()

    print("Reproducción finalizada.")


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        description="PCAP Player — sin argumentos abre la GUI",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("file",    nargs="?",              help="Archivo .pcap a reproducir")
    parser.add_argument("--ip",    default="127.0.0.1",    help="IP destino      (default: 127.0.0.1)")
    parser.add_argument("--port",  default=3460, type=int, help="Puerto destino  (default: 3460)")
    parser.add_argument("--speed", default=1.0, type=float,help="Velocidad       (default: 1.0)")
    parser.add_argument("--loop",  action="store_true",    help="Repetir indefinidamente")
    parser.add_argument("--proto", default="",             help="Filtro protocolo: UDP | TCP")
    parser.add_argument("--src",   default="",             help="Filtro IP origen")
    parser.add_argument("--dst",   default="",             help="Filtro IP destino")
    return parser


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.file:
        # CLI mode — Qt nunca se importa, Ctrl+C funciona normalmente
        run_cli(args)
        sys.exit(0)

    # GUI mode — Qt se importa solo cuando se necesita
    from PyQt6.QtWidgets import (
        QApplication, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QLineEdit, QFileDialog,
        QDoubleSpinBox, QProgressBar, QFrame, QComboBox, QCheckBox,
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal

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

            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.HLine)
            sep.setStyleSheet("color: #333;")
            lay.addWidget(sep)

            self._bar = QProgressBar()
            self._bar.setRange(0, 100)
            self._bar.setValue(0)
            self._bar.setTextVisible(False)
            lay.addWidget(self._bar)

            self._status = QLabel("Carga un archivo .pcap para comenzar.")
            self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(self._status)

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
            return filter_packets(self._packets, proto_f, src_f, dst_f)

        def _on_filter_changed(self):
            if not self._packets:
                return
            n = len(self._filtered_packets())
            self._status.setText(f"{n} / {len(self._packets)} paquetes con los filtros actuales")

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

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = PcapPlayer()
    win.show()
    sys.exit(app.exec())
