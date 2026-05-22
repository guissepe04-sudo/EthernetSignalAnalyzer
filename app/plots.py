"""
Funciones de graficación con matplotlib.
Todas reciben una Figure ya existente y la dibujan desde cero (fig.clear()).
"""

import math
import numpy as np

from .styles import (C_BG, C_CARD, C_SURF, C_TEXT, C_SUB, C_HDR,
                     C_BORDER, C_GRID, PLOT_COLORS)
from .analysis import sig_type, is_digital


# ── Helpers de estilo ─────────────────────────────────────────────────────────

def _style_fig(fig):
    fig.patch.set_facecolor(C_BG)


def _style_ax(ax):
    ax.set_facecolor(C_SURF)
    ax.tick_params(colors=C_HDR, labelsize=8)
    ax.xaxis.label.set_color(C_HDR)
    ax.yaxis.label.set_color(C_HDR)
    ax.title.set_color(C_TEXT)
    for sp in ax.spines.values():
        sp.set_edgecolor(C_BORDER)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def _prep(info: dict, t0: float):
    """Devuelve (ts_sorted, va_sorted) normalizados a t0."""
    ts = np.array(info["ts"]) - t0
    va = np.array(info["val"], dtype=float)
    order = np.argsort(ts)
    return ts[order], va[order]


# ── Vistas ────────────────────────────────────────────────────────────────────

def draw_empty(fig, msg="Sin datos. Carga un .pcap y presiona ANALIZAR."):
    fig.clear()
    _style_fig(fig)
    ax = fig.add_subplot(111)
    ax.set_facecolor(C_BG)
    ax.text(0.5, 0.5, msg, ha="center", va="center",
            fontsize=13, color=C_SUB, transform=ax.transAxes, style="italic")
    ax.axis("off")


def draw_individual(fig, sig_id: int, info: dict, t0: float = 0.0):
    """
    Dibuja la señal con datos crudos y devuelve (xlim, ylim) naturales.
    Los controles de escala/periodo/offset se aplican sobre los ejes en window.py.
    """
    fig.clear()
    _style_fig(fig)
    ax = fig.add_subplot(111)
    _style_ax(ax)

    ts, va    = _prep(info, t0)
    color     = C_TEXT
    ftype     = sig_type(info)
    transport = info.get("transport", "")
    ip_src    = info.get("ip_src", "")
    ip_dst    = info.get("ip_dst", "")

    if is_digital(info):
        ax.step(ts, va, where="post", color=color, lw=2.2, alpha=0.9)
        ax.fill_between(ts, va, step="post", alpha=0.12, color=color)
        ax.set_yticks(sorted(set(va.astype(int))))
        ax.set_ylim(-0.1, float(va.max()) + 0.3)
    else:
        ax.fill_between(ts, va, alpha=0.07, color=color)
        ax.plot(ts, va, "-", lw=1.6, color=color, alpha=0.9)
        ax.plot(ts, va, "o", ms=3.5, color=color, alpha=0.4, markeredgewidth=0)

    ax.set_title(
        f"Senal  0x{sig_id:04X}  ({sig_id})   [{ftype}]   "
        f"{transport}  {ip_src} -> {ip_dst}",
        fontsize=11, fontweight="bold", color=C_TEXT, pad=14
    )
    stats = (f"N = {info['n']} muestras\n"
             f"Min  =  {info['min']:.5g}\n"
             f"Max  =  {info['max']:.5g}\n"
             f"s    =  {info['std']:.4g}\n"
             f"Rango=  {info['range']:.4g}")
    ax.text(0.015, 0.975, stats, transform=ax.transAxes,
            fontsize=10.5, va="top", ha="left", family="monospace", color=C_HDR,
            bbox=dict(boxstyle="round,pad=0.6", facecolor=C_CARD,
                      edgecolor=C_BORDER, linewidth=1.5, alpha=0.95))
    ax.set_xlabel("Tiempo (s)", fontsize=11)
    ax.set_ylabel("Valor", fontsize=11)
    ax.grid(True, alpha=0.25, linestyle="--", color=C_GRID)
    fig.tight_layout(pad=2.5)
    # Devolver límites naturales para que window.py pueda aplicar zoom/offset
    return list(ax.get_xlim()), list(ax.get_ylim())


def draw_overview(fig, signals: dict, t0: float = 0.0,
                  only_varying: bool = False, max_n: int = 20):
    """Cuadrícula con las señales más activas."""
    fig.clear()
    _style_fig(fig)
    pool = {k: v for k, v in signals.items()
            if not only_varying or v["range"] > 0}
    if not pool:
        draw_empty(fig, "Sin senales. Desactiva 'solo variantes' o recarga.")
        return

    ids  = sorted(pool, key=lambda s: pool[s]["range"] + pool[s]["std"], reverse=True)[:max_n]
    n    = len(ids)
    cols = 4
    rows = math.ceil(n / cols)
    fig.suptitle(
        f"Panoramica — {n} senales principales  (clic en la lista para ver en detalle)",
        fontsize=10, fontweight="bold", color=C_HDR, y=1.01
    )
    for idx, sid in enumerate(ids):
        info   = pool[sid]
        ax     = fig.add_subplot(rows, cols, idx + 1)
        _style_ax(ax)
        ts, va = _prep(info, t0)
        color  = PLOT_COLORS[idx % len(PLOT_COLORS)]
        if is_digital(info):
            ax.step(ts, va, where="post", color=color, lw=1.1)
            ax.fill_between(ts, va, step="post", alpha=0.25, color=color)
        else:
            ax.fill_between(ts, va, alpha=0.15, color=color)
            ax.plot(ts, va, "-", lw=0.9, color=color)
        ax.set_title(
            f"0x{info['signal_id']:04X}  [{sig_type(info)}]\n"
            f"max={info['max']:.4g}  s={info['std']:.3g}",
            fontsize=7, pad=3, color=C_HDR
        )
        ax.tick_params(labelsize=6, pad=1, colors=C_SUB)
        ax.grid(True, alpha=0.18, linewidth=0.5, color=C_GRID)

    for idx in range(n, rows * cols):
        fig.add_subplot(rows, cols, idx + 1).set_visible(False)
    fig.tight_layout(pad=0.8, h_pad=1.6, w_pad=1.0)


def draw_compare(fig, sel_ids: list, signals: dict, t0: float = 0.0):
    """Compara múltiples señales: subplots si ≤4, normalizado si >4."""
    fig.clear()
    _style_fig(fig)
    valid = [s for s in sel_ids if s in signals]
    if not valid:
        draw_empty(fig, "Ctrl + clic en senales de la lista para compararlas.")
        return

    n = len(valid)
    if n <= 4:
        cols = min(2, n)
        rows = math.ceil(n / cols)
        for i, sid in enumerate(valid):
            info   = signals[sid]
            ax     = fig.add_subplot(rows, cols, i + 1)
            _style_ax(ax)
            ts, va = _prep(info, t0)
            color  = PLOT_COLORS[i % len(PLOT_COLORS)]
            if is_digital(info):
                ax.step(ts, va, where="post", color=color, lw=2)
                ax.fill_between(ts, va, step="post", alpha=0.2, color=color)
            else:
                ax.fill_between(ts, va, alpha=0.1, color=color)
                ax.plot(ts, va, "-", lw=1.5, color=color)
                ax.plot(ts, va, "o", ms=3, color=color, alpha=0.4)
            ax.set_title(f"0x{info['signal_id']:04X}  [{sig_type(info)}]",
                         fontsize=9, fontweight="bold", color=C_TEXT)
            ax.grid(True, alpha=0.2, linestyle="--", color=C_GRID)
    else:
        ax = fig.add_subplot(111)
        _style_ax(ax)
        for i, sid in enumerate(valid[:8]):
            info   = signals[sid]
            ts, va = _prep(info, t0)
            rng    = info["range"] or 1
            va_n   = (va - info["min"]) / rng
            color  = PLOT_COLORS[i % len(PLOT_COLORS)]
            ax.plot(ts, va_n, "-", lw=1.5, color=color, alpha=0.85,
                    label=f"0x{info['signal_id']:04X}")
        leg = ax.legend(fontsize=9)
        leg.get_frame().set_facecolor(C_CARD)
        leg.get_frame().set_edgecolor(C_BORDER)
        for t in leg.get_texts():
            t.set_color(C_TEXT)
        ax.set_ylabel("Valor normalizado (0-1)", fontsize=11)
        ax.set_xlabel("Tiempo (s)", fontsize=11)
        ax.grid(True, alpha=0.2, linestyle="--", color=C_GRID)

    fig.suptitle("Comparacion de senales", fontsize=11,
                 fontweight="bold", color=C_TEXT)
    fig.tight_layout(pad=2)


def draw_live(fig, ts: list, vals: list, signal_id: int, t0: float = 0.0):
    fig.clear()
    _style_fig(fig)
    ax = fig.add_subplot(111)
    _style_ax(ax)
    if not ts:
        ax.text(0.5, 0.5,
                "Esperando datos...\nInicia la captura y espera paquetes de la senal.",
                ha="center", va="center", fontsize=13, color=C_SUB,
                transform=ax.transAxes, style="italic")
        ax.axis("off")
        return
    t_arr = np.array(ts) - t0
    v_arr = np.array(vals, dtype=float)
    ax.plot(t_arr, v_arr, "-", lw=1.5, color=C_TEXT, alpha=0.9)
    ax.plot(t_arr[-1:], v_arr[-1:], "o", ms=7, color="#ff6b6b", zorder=10)
    ax.set_title(
        f"EN VIVO — Senal 0x{signal_id:04X} ({signal_id})   N={len(ts)}",
        fontsize=11, fontweight="bold", color=C_TEXT, pad=14
    )
    ax.set_xlabel("Tiempo (s)", fontsize=11)
    ax.set_ylabel("Valor", fontsize=11)
    ax.grid(True, alpha=0.25, linestyle="--", color=C_GRID)
    fig.tight_layout(pad=2.5)


