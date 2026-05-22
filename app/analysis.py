"""
Análisis de señales extraídas de paquetes de red.

Clave compuesta: (signal_id, transport, ip_src, ip_dst)
El mismo signal_id puede aparecer en UDP (ECU→gateway) y TCP (gateway→HMI)
con series temporales distintas; se almacenan por separado.
"""

from collections import defaultdict
import numpy as np
from .parser import parse_raw_packet, parse_tcp16_stream, _PROTO_TCP16


def analyze_signals(packets: list, transport_filter: str,
                    src_filter: str, dst_filter: str) -> dict:
    """
    Procesa paquetes y devuelve dict:
      (signal_id, transport, ip_src, ip_dst) -> info_dict

    info_dict contiene: signal_id (int), ts, val, is_float, cat,
                        min, max, std, range, n, transport, ip_src, ip_dst
    """
    sig_ts      = defaultdict(list)
    sig_val     = defaultdict(list)
    sig_float_n = defaultdict(int)   # votos a favor de float
    sig_int_n   = defaultdict(int)   # votos a favor de int
    sig_cat     = {}

    def _accept(pkt):
        if transport_filter not in ("Todos", "") and pkt["transport"] != transport_filter:
            return False
        if src_filter and pkt["ip_src"] != src_filter:
            return False
        if dst_filter and pkt["ip_dst"] != dst_filter:
            return False
        return True

    filtered = [p for p in packets if _accept(p)]

    # ── Protocol A: UDP TLV — un paquete = un frame completo ─────────────────
    for pkt in filtered:
        if pkt["transport"] != "UDP":
            continue
        ver, entries = parse_raw_packet(pkt["payload"])
        if ver != 2:
            continue
        for sig_id, val, is_f, cat in entries:
            key = (sig_id, "UDP", pkt["ip_src"], pkt["ip_dst"])
            sig_ts[key].append(pkt["ts"])
            sig_val[key].append(val)
            if is_f:
                sig_float_n[key] += 1
            else:
                sig_int_n[key] += 1
            sig_cat[key] = cat

    # ── Protocol B: TCP 16-byte — buffer acumulado por stream ────────────────
    # Se agrupan segmentos por (ip_src, ip_dst) y se procesan en orden temporal.
    # Así los registros partidos entre segmentos se reconstruyen correctamente.
    tcp_streams = defaultdict(list)
    for pkt in filtered:
        if pkt["transport"] == "TCP":
            tcp_streams[(pkt["ip_src"], pkt["ip_dst"])].append(pkt)

    for (ip_src, ip_dst), stream_pkts in tcp_streams.items():
        stream_pkts.sort(key=lambda p: p["ts"])
        buf = b''
        for pkt in stream_pkts:
            try:
                chunk = bytes.fromhex(
                    pkt["payload"].replace(" ", "").replace(":", ""))
            except ValueError:
                continue
            buf += chunk
            entries, buf = parse_tcp16_stream(buf)
            for sig_id, val, is_f, cat in entries:
                key = (sig_id, "TCP", ip_src, ip_dst)
                sig_ts[key].append(pkt["ts"])
                sig_val[key].append(val)
                if is_f:
                    sig_float_n[key] += 1
                else:
                    sig_int_n[key] += 1
                sig_cat[key] = cat

    # ── Construir resultado ───────────────────────────────────────────────────
    result = {}
    for key in sig_ts:
        vals = sig_val[key]
        if not vals:
            continue
        arr = np.array(vals, dtype=float)
        # Frames de suscripción TCP iniciales: todos ceros, sin dato real
        if arr.max() == 0 and arr.min() == 0:
            continue
        sig_id, transport, ip_src, ip_dst = key
        is_float = sig_float_n[key] >= sig_int_n[key]  # mayoría de votos
        result[key] = {
            "signal_id": sig_id,
            "ts":        sig_ts[key],
            "val":       vals,
            "is_float":  is_float,
            "cat":       sig_cat.get(key, 0),
            "min":       float(arr.min()),
            "max":       float(arr.max()),
            "std":       float(arr.std()),
            "range":     float(arr.max() - arr.min()),
            "n":         len(vals),
            "transport": transport,
            "ip_src":    ip_src,
            "ip_dst":    ip_dst,
        }
    return result


def find_duplicate_groups(signals: dict) -> dict:
    """
    Detecta señales con series temporales idénticas (mismo timestamp, mismo valor).
    Retorna dict: sig_key -> [lista de claves de señales gemelas].
    Solo compara señales dentro del mismo bucket estadístico para ser eficiente.
    """
    buckets = defaultdict(list)
    for k, v in signals.items():
        bkey = (round(v['min'], 2), round(v['max'], 2), v['n'], round(v['std'], 2))
        buckets[bkey].append(k)

    result = {}
    for candidates in buckets.values():
        if len(candidates) < 2:
            continue
        vals_cache = {k: np.array(signals[k]['val']) for k in candidates}
        ts_cache   = {k: np.array(signals[k]['ts'])  for k in candidates}
        for i in range(len(candidates)):
            for j in range(i + 1, len(candidates)):
                k1, k2 = candidates[i], candidates[j]
                if signals[k1]['n'] != signals[k2]['n']:
                    continue
                if not np.allclose(ts_cache[k1], ts_cache[k2], atol=0.05):
                    continue
                if np.allclose(vals_cache[k1], vals_cache[k2], rtol=1e-4, atol=0):
                    result.setdefault(k1, []).append(k2)
                    result.setdefault(k2, []).append(k1)
    return result


def sig_type(info: dict) -> str:
    return "float" if info["is_float"] else "int"


def is_digital(info: dict) -> bool:
    return not info["is_float"] and info["max"] <= 10
