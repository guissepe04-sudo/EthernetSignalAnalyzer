"""
Decodificación de dos protocolos binarios propietarios detectados en la captura.

─── Protocolo A: TLV sobre UDP (ECUs → gateway, versión 2) ───────────────────
  Cabecera 20 bytes: [Session:4][Version=2:4][Seq:4][Flags:4][SubCount:4]
  Payload: bloques TLV repetidos:
    [Tipo:1][Cat:1][DataLen:1][Pad:1][SignalID:4][Valor:DataLen-4]
    Tamaño bloque = 4 + ceil(DataLen/4)*4  (alineado a 4 bytes)

─── Protocolo B: registros de tamaño variable sobre TCP (gateway → HMI) ──────
  SYNC fijo 4 bytes: byte0 = tipo de mensaje (0x10, 0x11, 0x13...), bytes 1-3 = 0x00.
  Estructura: [SYNC:4][SignalID:4 LE][Flags:4][Valor:variable BE]
  Flags: [cat1:1][cat2:1][data_len:1][status:1]
  Tamaño total = 12 + ceil(max(4, data_len) / 4) * 4  (donde data_len = Flags[2])
    data_len=02 → valor=4 bytes → 16 bytes total
    data_len=05 → valor=8 bytes → 20 bytes total
    data_len=06 → valor=8 bytes → 20 bytes total
  El valor se lee como los primeros 4 bytes BE del campo valor (bytes 12-15).
  Flags[0]=cat1, Flags[1]=cat2, Flags[2]=data_len, Flags[3]=estado (0x57=sin dato).

─── Detección automática de tipo float vs int ────────────────────────────────
  Para valores de 4 bytes: se prueba como float32 BE.
  Si abs(float32) ∈ (1e-3, 1e7) y no es NaN/Inf → float. Si no → int (uint32).
"""

import struct
import math


def _is_plausible_float(f: float) -> bool:
    if math.isnan(f) or math.isinf(f):
        return False
    return 1e-3 < abs(f) < 1e7


def _decode_value(data: bytes, offset: int, vsize: int):
    """Devuelve (valor, es_float). Lógica de detección automática de tipo."""
    if vsize == 0:
        return None, False
    if vsize == 1:
        return data[offset], False
    if vsize == 2:
        return struct.unpack_from('<H', data, offset)[0], False
    if vsize == 4:
        u = struct.unpack_from('<I', data, offset)[0]
        f = struct.unpack_from('<f', data, offset)[0]
        return (f, True) if _is_plausible_float(f) else (u, False)
    if vsize == 8:
        f = struct.unpack_from('<d', data, offset)[0]
        return (f, True) if _is_plausible_float(f) else (struct.unpack_from('<Q', data, offset)[0], False)
    if offset + 4 <= len(data):
        return struct.unpack_from('<I', data, offset)[0], False
    return None, False


def parse_tlv_payload(payload: bytes) -> list:
    """Extrae lista de (signal_id, valor, es_float, categoria, raw_hex) del payload TLV."""
    entries = []
    i = 0
    while i + 4 <= len(payload):
        tipo = payload[i]
        cat  = payload[i + 1]
        dlen = payload[i + 2]
        block = 4 if dlen == 0 else 4 + (((dlen) + 3) // 4) * 4
        if i + block > len(payload):
            break
        if tipo == 1 and dlen >= 5 and i + 8 <= len(payload):
            sig_id = struct.unpack_from('<I', payload, i + 4)[0]
            val, is_f = _decode_value(payload, i + 8, dlen - 4)
            if val is not None:
                raw = payload[i:i + block].hex(' ')
                entries.append((sig_id, val, is_f, cat, raw))
        i += block
    return entries


_TCP_REC_MIN = 16   # tamaño mínimo de registro (data_len pequeño → valor=4 bytes)


def _tcp_rec_size(buf: bytes, i: int) -> int:
    """
    Devuelve el tamaño del registro Protocol B que empieza en buf[i], o 0 si inválido.
    SYNC: byte0 = tipo de mensaje, bytes 1-3 deben ser 0x00.
    Tamaño = 12 + ceil(max(4, data_len) / 4) * 4, donde data_len = buf[i+10].
    """
    if i + 12 > len(buf):
        return 0
    if buf[i+1:i+4] != b'\x00\x00\x00':
        return 0
    data_len = buf[i + 10]
    value_size = max(4, ((data_len + 3) // 4) * 4)
    return 12 + value_size


def parse_tcp16_payload(payload: bytes) -> list:
    """
    Protocolo B: registros de tamaño variable en el stream TCP gateway → HMI.
    SYNC fijo (bytes 1-3 = 0x00). Tamaño determinado por data_len en byte[10].
    Escanea byte a byte hasta encontrar SYNC válido.
    Solo extrae registros donde el valor (bytes 12-15 BE) es != 0.
    """
    entries = []
    i = 0
    while i + _TCP_REC_MIN <= len(payload):
        rec_size = _tcp_rec_size(payload, i)
        if rec_size and i + rec_size <= len(payload):
            sig_id = struct.unpack_from('<I', payload, i + 4)[0]
            cat    = payload[i + 8]
            u32 = struct.unpack_from('>I', payload, i + 12)[0]
            f32 = struct.unpack_from('>f', payload, i + 12)[0]
            if u32 != 0:
                is_f = _is_plausible_float(f32)
                val  = f32 if is_f else u32
                raw  = payload[i:i + rec_size].hex(' ')
                entries.append((sig_id, val, is_f, cat, raw))
            i += rec_size
        else:
            i += 1
    return entries


# Versión numérica para el protocolo B (distingue del TLV en el análisis)
_PROTO_TCP16 = 16


def parse_tcp16_stream(buf: bytes):
    """
    Versión streaming de parse_tcp16_payload para el buffer TCP acumulado.
    Maneja registros partidos entre segmentos TCP (tamaño variable via byte[10]).
    Devuelve (entries, remaining_bytes).
    remaining_bytes (< _TCP_REC_MIN bytes) debe prepend-earse al siguiente segmento.
    """
    entries = []
    i = 0
    while i + _TCP_REC_MIN <= len(buf):
        rec_size = _tcp_rec_size(buf, i)
        if rec_size:
            if i + rec_size > len(buf):
                break   # registro partido: esperar más datos
            sig_id = struct.unpack_from('<I', buf, i + 4)[0]
            cat    = buf[i + 8]
            u32 = struct.unpack_from('>I', buf, i + 12)[0]
            f32 = struct.unpack_from('>f', buf, i + 12)[0]
            if u32 != 0:
                is_f = _is_plausible_float(f32)
                val  = f32 if is_f else u32
                raw  = buf[i:i + rec_size].hex(' ')
                entries.append((sig_id, val, is_f, cat, raw))
            i += rec_size
        else:
            i += 1
    return entries, buf[i:]


def decode_frame_explanation(hex_str: str) -> str:
    """
    Devuelve texto explicando byte a byte la decodificación de una trama.
    Detecta automáticamente Protocol A (TLV UDP) o Protocol B (TCP 16-byte).
    """
    try:
        data = bytes.fromhex(
            hex_str.replace(' ', '').replace(':', '').replace('\n', '').replace('\t', ''))
    except ValueError:
        return "Error: bytes hexadecimales invalidos."
    if not data:
        return "Trama vacia."

    lines = [f"Longitud: {len(data)} bytes\n"]

    # ── Protocol B: registro de tamaño variable (SYNC fijo, tamaño via byte[10]) ──
    rec_size = _tcp_rec_size(data, 0)
    if rec_size and len(data) >= rec_size:
        sig_id    = struct.unpack_from('<I', data, 4)[0]
        cat       = data[8]
        data_len  = data[10]
        status    = data[11]
        u32       = struct.unpack_from('>I', data, 12)[0]
        f32       = struct.unpack_from('>f', data, 12)[0]
        is_f      = not (math.isnan(f32) or math.isinf(f32)) and 1e-3 < abs(f32) < 1e7
        val_bytes = rec_size - 12

        lines += [
            f"PROTOCOL B  —  TCP {rec_size} bytes  (gateway -> HMI)\n",
            f"  [00-03]  {' '.join(f'{b:02X}' for b in data[0:4])}",
            f"           SYNC (tipo=0x{data[0]:02X}, bytes 1-3 = 00 00 00)\n",
            f"  [04-07]  {' '.join(f'{b:02X}' for b in data[4:8])}",
            f"           Signal ID = 0x{sig_id:04X} = {sig_id}  (uint32 little-endian)\n",
            f"  [08-11]  {' '.join(f'{b:02X}' for b in data[8:12])}",
            f"           Flags: cat=0x{cat:02X}({cat}), data_len={data_len}, estado=0x{status:02X}\n",
            f"  [12-{rec_size-1:02d}]  {' '.join(f'{b:02X}' for b in data[12:rec_size])}",
            f"           Valor ({val_bytes} bytes, big-endian):",
        ]
        if u32 == 0:
            lines += ["           = 0  -> frame de suscripcion sin dato aun (DESCARTADO)"]
        elif is_f:
            lines.append(f"           = {f32:.7g}  (float32)")
        else:
            lines.append(f"           = {u32}  (uint32)")
        return '\n'.join(lines)

    # ── Protocol A: TLV UDP con cabecera 20 bytes ────────────────────────────
    if len(data) >= 8:
        version = struct.unpack_from('<I', data, 4)[0]
        if version in (1, 2) and len(data) >= 20:
            session  = struct.unpack_from('<I', data, 0)[0]
            seq      = struct.unpack_from('<I', data, 8)[0]
            flags_h  = struct.unpack_from('<I', data, 12)[0]
            subcount = struct.unpack_from('<I', data, 16)[0]
            hdr      = 20 if version == 2 else 12

            lines += [
                f"PROTOCOL A  —  UDP TLV  (ECU -> gateway, version {version})\n",
                "  CABECERA (20 bytes):",
                f"  [00-03]  {' '.join(f'{b:02X}' for b in data[0:4])}",
                f"           Session ID = 0x{session:08X}",
                f"  [04-07]  {' '.join(f'{b:02X}' for b in data[4:8])}",
                f"           Version = {version}",
                f"  [08-11]  {' '.join(f'{b:02X}' for b in data[8:12])}",
                f"           Secuencia = {seq}",
                f"  [12-15]  {' '.join(f'{b:02X}' for b in data[12:16])}",
                f"           Flags = 0x{flags_h:08X}",
                f"  [16-19]  {' '.join(f'{b:02X}' for b in data[16:20])}",
                f"           SubCount = {subcount}\n",
                "  PAYLOAD TLV (señales):",
            ]
            payload = data[hdr:]
            i = 0
            count = 0
            while i + 4 <= len(payload) and count < 20:
                tipo  = payload[i]
                cat   = payload[i + 1]
                dlen  = payload[i + 2]
                block = 4 if dlen == 0 else 4 + ((dlen + 3) // 4) * 4
                off   = i + hdr

                if i + block > len(payload):
                    lines.append(f"  [off {off}]  bloque incompleto, fin de trama")
                    break

                if tipo == 1 and dlen >= 5 and i + 8 <= len(payload):
                    sig_id = struct.unpack_from('<I', payload, i + 4)[0]
                    vsize  = dlen - 4
                    vb     = payload[i + 8: i + 8 + vsize]
                    if vsize == 1:
                        vs = str(vb[0])
                    elif vsize == 2:
                        vs = str(struct.unpack_from('<H', vb, 0)[0])
                    elif vsize == 4:
                        u = struct.unpack_from('<I', vb, 0)[0]
                        f = struct.unpack_from('<f', vb, 0)[0]
                        p = not (math.isnan(f) or math.isinf(f)) and 1e-3 < abs(f) < 1e7
                        vs = f"{f:.6g} (float)" if p else f"{u} (uint32)"
                    elif vsize == 8:
                        f = struct.unpack_from('<d', vb, 0)[0]
                        p = not (math.isnan(f) or math.isinf(f)) and 1e-3 < abs(f) < 1e7
                        vs = f"{f:.6g} (float64)" if p else f"{struct.unpack_from('<Q', vb, 0)[0]} (uint64)"
                    else:
                        vs = vb.hex()
                    lines.append(
                        f"  [{off:3d}-{off+block-1:3d}]  "
                        f"tipo=0x{tipo:02X} cat=0x{cat:02X} len={dlen}"
                        f"  ->  Signal 0x{sig_id:04X} ({sig_id}) = {vs}"
                    )
                    count += 1
                else:
                    lines.append(
                        f"  [{off:3d}-{off+block-1:3d}]  "
                        f"tipo=0x{tipo:02X} (no-dato)  cat=0x{cat:02X}  len={dlen}"
                    )
                i += block

            if count >= 20:
                lines.append("  ... (truncado, hay mas entradas TLV)")
            return '\n'.join(lines)

    return (f"Trama no reconocida ({len(data)} bytes).\n"
            f"Primeros bytes: {' '.join(f'{b:02X}' for b in data[:16])}")


def parse_raw_packet(hex_str: str):
    """
    Parsea el payload hex de un paquete y devuelve (version, entries).
    entries es lista de (signal_id, valor, es_float, categoria).

    version == 2  → Protocolo A (TLV UDP, ECUs)
    version == 16 → Protocolo B (16-byte TCP, gateway→HMI)
    Retorna (None, []) si el paquete no es reconocible.
    """
    try:
        data = bytes.fromhex(hex_str.replace(' ', '').replace(':', ''))
    except ValueError:
        return None, []
    if len(data) < 8:
        return None, []

    # Protocolo A: TLV con cabecera de 20 bytes
    version = struct.unpack_from('<I', data, 4)[0]
    if version == 2 and len(data) > 20:
        return 2, parse_tlv_payload(data[20:])
    if version == 1 and len(data) > 12:
        return 1, parse_tlv_payload(data[12:])

    # Protocolo B: SYNC fijo (bytes 1-3 = 0x00), tamaño via byte[10]
    if _tcp_rec_size(data, 0):
        entries = parse_tcp16_payload(data)
        if entries:
            return _PROTO_TCP16, entries

    return version, []
