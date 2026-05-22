"""
Interfaz con tshark (CLI de Wireshark).

tshark lee archivos .pcap binarios, aplica filtros de protocolo,
y devuelve los campos de red como texto tab-separado.
El programa lo usa porque implementar el parser de libpcap + Ethernet/IP/UDP
desde cero sería equivalente a reescribir Wireshark.

Campos extraídos por paquete:
  frame.number, frame.time_epoch, ip.src, ip.dst, protocolo,
  tcp.stream, tcp.srcport, tcp.dstport, tcp.payload,
  udp.stream, udp.srcport, udp.dstport, udp.payload
"""

import subprocess

TSHARK_FIELDS = [
    "frame.number", "frame.time_epoch",
    "ip.src", "ip.dst", "_ws.col.Protocol",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.payload",
    "udp.stream", "udp.srcport", "udp.dstport", "udp.payload",
]


def run_tshark(tshark_bin: str, pcap_path: str) -> list:
    """
    Ejecuta tshark sobre el pcap y devuelve lista de dicts con:
      ts, ip_src, ip_dst, transport ("TCP"/"UDP"), src_port, dst_port, payload (hex)
    """
    cmd = [tshark_bin, "-r", pcap_path,
           "-Y", "tcp.payload or udp.payload",
           "-T", "fields"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "occurrence=f"]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise RuntimeError(f"No se encontro tshark en: {tshark_bin}")

    packets = []
    for raw in proc.stdout:
        parts = raw.rstrip("\n").split("\t")
        if len(parts) < len(TSHARK_FIELDS):
            continue
        (_, ts, ip_src, ip_dst, _,
         _, tcp_sp, tcp_dp, tcp_pay,
         _, udp_sp, udp_dp, udp_pay) = parts[:len(TSHARK_FIELDS)]
        payload   = tcp_pay or udp_pay
        if not payload:
            continue
        transport = "TCP" if tcp_pay else "UDP"
        try:
            ts_f = float(ts)
        except (ValueError, TypeError):
            ts_f = 0.0
        packets.append({
            "ts":        ts_f,
            "ip_src":    ip_src,
            "ip_dst":    ip_dst,
            "transport": transport,
            "src_port":  tcp_sp if transport == "TCP" else udp_sp,
            "dst_port":  tcp_dp if transport == "TCP" else udp_dp,
            "payload":   payload,
        })
    proc.wait()
    if proc.returncode != 0:
        stderr = proc.stderr.read().strip()
        raise RuntimeError(f"tshark termino con error (codigo {proc.returncode}):\n{stderr}")
    return packets


def get_ip_list(tshark_bin: str, pcap_path: str) -> list:
    """
    Devuelve lista de (ip_src, ip_dst, protocolo) únicos encontrados en el pcap.
    Se usa para poblar los combos de filtro antes del análisis completo.
    """
    cmd = [tshark_bin, "-r", pcap_path,
           "-Y", "tcp or udp",
           "-T", "fields",
           "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
           "-E", "separator=|", "-q"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      text=True, encoding="utf-8", errors="replace")
    except Exception:
        return []
    seen = set()
    for line in out.splitlines():
        p = line.strip().split("|")
        if len(p) >= 3:
            seen.add((p[0], p[1], p[2]))
    return sorted(seen)
