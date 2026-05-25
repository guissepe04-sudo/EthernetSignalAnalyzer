# Documentación de Protocolos — Ethernet Signal Analyzer

Referencia de los dos protocolos binarios propietarios detectados en las capturas
de red de la máquina Sandvik.  Todos los ejemplos de bytes provienen del archivo
`Test4_ethernet_arm_boom1_boom2_drilling.pcap`.

---

## Topología de red

| IP               | Rol                                      | Paquetes enviados |
|------------------|------------------------------------------|-------------------|
| 192.168.20.10    | ECU (boom 1)                             | ~55 000           |
| 192.168.20.11    | ECU (boom 2 / drilling)                  | ~54 000           |
| 192.168.20.15    | ECU (brazo)                              | ~36 000           |
| 192.168.20.254   | ECU auxiliar                             | ~3 200            |
| 192.168.20.2     | Gateway (concentra señales, ↔ HMIs)     | ~92 000           |
| 192.168.20.6     | HMI / consumidor                         | ~15 000           |
| 224.0.0.30       | Grupo multicast (61 000 paquetes recibidos) — no decodificado |

El archivo contiene **256 018 paquetes**: 230 277 UDP + 25 741 TCP,
capturados durante aprox. 60 segundos.

---

## Protocolo A — UDP TLV  (ECU → gateway)

### Flujo de datos

```
ECU (.10 / .11 / .15 / .254)  ──UDP──▶  Gateway (.2)
```

Cada datagrama UDP transporta **múltiples señales** empaquetadas como bloques TLV
(Type-Length-Value) precedidos por una cabecera de 20 bytes.

### Estructura del paquete

```
Offset  Tamaño  Endian  Campo
──────  ──────  ──────  ────────────────────────────
  0       4     LE      Session ID
  4       4     LE      Version  (= 2 para todos los paquetes válidos)
  8       4     LE      Número de secuencia
 12       4     LE      Flags
 16       4     LE      SubCount
 20       …             Payload TLV  (señales)
```

> **Versión 1** existe pero tiene cabecera de solo 12 bytes; en esta captura
> todos los paquetes son versión 2.

### Bloque TLV — una señal

```
Offset  Tamaño  Campo
──────  ──────  ──────────────────────────────────────────────
  +0      1     tipo    (0x01 = entrada con dato de señal)
  +1      1     cat     (categoría / prioridad, e.g. 0x40)
  +2      1     dlen    (tamaño total de [SignalID + Value] en bytes)
  +3      1     pad     (siempre 0x00)
  +4      4     SignalID  (uint32 little-endian)
  +8   dlen-4   Value     (little-endian, tamaño variable)
```

**Tamaño total del bloque** = 4 + ⌈dlen / 4⌉ × 4  (alineado a 4 bytes)

| dlen | Tamaño de valor (bytes) | Tamaño total del bloque |
|------|------------------------|-------------------------|
|   5  | 1                      | 12 bytes                |
|   6  | 2                      | 12 bytes                |
|   8  | 4                      | 12 bytes                |
|  12  | 8                      | 16 bytes                |

### Ejemplo A-1 — señal entera (uint32)

Señal **0x009C (156)** = 12 620 239, del paquete  
`192.168.20.2 → 192.168.20.254`  ts = 1779389981.813883:

```
Bytes:  01  40  08  00  9C  00  00  00  CF  91  C0  00
        ──  ──  ──  ──  ──────────────  ──────────────
        tipo cat dlen pad  SignalID LE      Value LE

tipo    = 0x01  →  bloque con dato
cat     = 0x40  →  categoría 64
dlen    = 8     →  4 bytes SignalID + 4 bytes Value  →  bloque de 12 bytes
SignalID= 0x009C 00 00 (LE) = 156
Value   = CF 91 C0 00  (LE)  → uint32 = 12 620 239
                              → float32 = 1.768e-38  (fuera del rango plausible)
                              ⟹ se interpreta como uint32 = 12 620 239
```

### Ejemplo A-2 — señal flotante (float32)

Señal **0x15F7 (5623)** = 40.0 °C aprox., del mismo paquete  
`192.168.20.11 → 192.168.20.2`:

```
Bytes:  01  40  08  00  F7  15  00  00  00  00  20  42
        ──  ──  ──  ──  ──────────────  ──────────────
        tipo cat dlen pad  SignalID LE      Value LE

tipo    = 0x01
cat     = 0x40
dlen    = 8     →  bloque de 12 bytes
SignalID= 0xF7 0x15 0x00 0x00 (LE) = 5623  (0x15F7)
Value   = 00 00 20 42  (LE)  → uint32 = 1 109 393 408 (no útil)
                              → float32 = 40.0  (1e-3 < 40 < 1e7 ✓)
                              ⟹ se interpreta como float32 = 40.0
```

En la captura esta señal varía entre 40 °C y 79.6 °C con 1 951 muestras.

### Señales con dlen = 5 (valor de 1 byte)

```
Bytes:  01  40  05  00  B5  15  00  00  00  00  00  00
        tipo cat dlen pad  SignalID=0x15B5   Value=0x00
```

dlen = 5 → 1 byte de valor, bloque total = 12 bytes (relleno a 4 bytes).

---

## Protocolo B — TCP variable (gateway → HMI)

### Flujo de datos

```
Gateway (.2)  ──TCP──▶  HMI (.6 / .10 / .11 / .15)
```

El gateway retransmite señales seleccionadas a cada HMI. El stream TCP es
**continuo**: los registros se concatenan sin delimitador de paquete, por lo
que el analizador acumula un buffer y procesa cuando hay suficientes bytes.

### Estructura de un registro

```
Offset  Tamaño  Endian  Campo
──────  ──────  ──────  ────────────────────────────────────────
  0       1             tipo de mensaje  (0x10, 0x11, 0x13, …)
  1       3             siempre 0x00 0x00 0x00  (SYNC / padding)
  4       4     LE      SignalID  (uint32)
  8       1             cat1
  9       1             cat2
 10       1             data_len  (determina tamaño del campo Value)
 11       1             status    (0x57 = sin dato / suscripción)
 12    variable BE      Value
```

**Tamaño total del registro** = 12 + max(4, ⌈data_len / 4⌉ × 4)

| data_len | Tamaño de Value (bytes) | Tamaño total del registro |
|----------|------------------------|---------------------------|
|   2      | 4                      | 16 bytes                  |
|   5      | 8                      | 20 bytes                  |
|   6      | 8                      | 20 bytes                  |

El campo SYNC (`bytes[1-3] = 00 00 00`) es la firma usada para
localizar el inicio de cada registro al escanear el buffer.

### Ejemplo B-1 — registro con dato real

Señal **0x6D84 (28036)** = 1,  
`192.168.20.2 → 192.168.20.6`  ts = 1779389982.127407:

```
Bytes:  10  00  00  00  84  6D  00  00  63  64  02  25  00  00  00  01
        ──  ────────────  ──────────────  ──  ──  ──  ──  ──────────────
        tip    SYNC=000    SignalID LE    c1  c2  dl  st     Value BE

tipo    = 0x10
SYNC    = 00 00 00  ✓
SignalID= 0x84 0x6D 0x00 0x00 (LE) = 28036  (0x6D84)
cat1    = 0x63, cat2 = 0x64
data_len= 2  →  tamaño Value = 4 bytes  →  registro de 16 bytes
status  = 0x25  (dato válido)
Value   = 00 00 00 01  (BE) = 1  → uint32 = 1
                              → float32 BE = 1.401e-45  (fuera de rango)
                              ⟹ se interpreta como uint32 = 1
```

### Ejemplo B-2 — frame de suscripción (descartado)

Señal **0x6F8D (28557)**,  
`192.168.20.2 → 192.168.20.6`  ts = 1779389981.814212:

```
Bytes:  10  00  00  00  8D  6F  00  00  63  64  02  57  00  00  00  00
                                                        ──  ──────────────
                                                        st=0x57  Value=0

status  = 0x57  →  "sin dato aún" (frame de suscripción inicial)
Value   = 00 00 00 00  →  0
⟹ DESCARTADO por el analizador (Value == 0)
```

Los frames de suscripción aparecen al inicio de cada stream TCP cuando el HMI
se conecta. El gateway los envía con status `0x57` y valor 0 para confirmar
que la señal está suscrita pero aún no hay medición.

---

## Detección automática de tipo (float vs entero)

Para valores de **4 bytes**, el analizador prueba ambas interpretaciones:

```python
u32 = struct.unpack_from('<I', data, offset)[0]   # uint32 little-endian
f32 = struct.unpack_from('<f', data, offset)[0]   # float32 little-endian

if not isnan(f32) and not isinf(f32) and 1e-3 < abs(f32) < 1e7:
    tipo = "float"   # valor plausible para una señal física
else:
    tipo = "uint32"
```

| Bytes (LE)      | uint32        | float32 LE     | Decisión |
|-----------------|---------------|----------------|----------|
| `00 00 20 42`   | 1 109 393 408 | **40.0**       | float    |
| `CF 91 C0 00`   | 12 620 239    | 1.768e-38      | uint32   |
| `00 00 00 01`   | 1             | 1.401e-45      | uint32   |

El umbral `(1e-3, 1e7)` excluye números muy pequeños (ruido / no inicializados)
y muy grandes (contadores de alta resolución que son enteros).

Para valores de **1 o 2 bytes** siempre se trata como entero (no hay ambigüedad).  
Para valores de **8 bytes** se prueba como float64 con el mismo criterio.

---

## Señales descartadas por el analizador

El analizador filtra señales que no aportan información útil:

| Condición                              | Motivo                                    |
|----------------------------------------|-------------------------------------------|
| Todos los valores son `0`              | Señal no inicializada o siempre en reposo |
| TCP status = `0x57`, Value = `0`       | Frame de suscripción sin medición         |

---

## Paquetes multicast (224.0.0.30)

Los ~61 000 paquetes dirigidos a `224.0.0.30` tienen la misma estructura
Protocolo A (UDP TLV versión 2), pero el analizador los omite porque los
paquetes de tshark no reportan una IP origen ECU válida en esos datagramas
(el campo de versión en el payload puede tomar valores distintos).  Si en el
futuro se necesita decodificarlos, el flujo es idéntico al Protocolo A.

---

## Resumen de la captura Test4

| Métrica                    | Valor        |
|----------------------------|--------------|
| Paquetes totales           | 256 018      |
| Paquetes UDP               | 230 277      |
| Paquetes TCP               | 25 741       |
| Señales decodificadas      | 875          |
| — flotantes                | 33           |
| — enteras                  | 748          |
| — digitales (max ≤ 10)     | 94           |
| Señal float más activa     | 0x15F7 (5623) UDP .11→.2  min=40 max=79.6  n=1951 |
| Duración aprox.            | ~60 segundos |
