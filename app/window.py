"""
Ventana principal de la aplicación — Ethernet Signal Analyzer.
"""

import os
import sys
import json
import datetime

import matplotlib
matplotlib.use("QtAgg")
import matplotlib.ticker as mticker
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QSplitter,
    QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox,
    QTreeWidget, QTreeWidgetItem, QPlainTextEdit,
    QStatusBar, QProgressBar, QFileDialog, QMessageBox,
    QButtonGroup, QFrame, QDoubleSpinBox, QTimeEdit,
)
from PyQt6.QtCore import Qt, QThread, QTime
from PyQt6.QtGui import QColor, QFont, QBrush

from .styles import QSS, C_BG, C_CARD, C_TEXT, C_HDR, C_SUB, C_BORDER, C_SURF, TYPE_STYLE
from .analysis import sig_type, find_duplicate_groups
from .plots import (draw_empty, draw_individual, draw_overview, draw_compare)
from .workers import AnalysisWorker

# Columnas del árbol de señales
_TREE_COLS    = ["★", "Nombre", "ID Hex", "Tipo", "Proto", "Origen", "Destino", "Max", "s", "N"]
_TREE_WIDTHS  = [26, 115, 65, 42, 46, 110, 110, 58, 48, 38]

# Colores para señales favoritas
_C_FAV_BG = "#2a1f00"
_C_FAV_FG = "#f0c040"

# Archivo donde se guardan los favoritos (junto a window.py → raíz del proyecto)
_FAVORITES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "favorites.json")


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ethernet Signal Analyzer")
        self.resize(1480, 900)
        self.setMinimumSize(1000, 660)
        self.setStyleSheet(QSS)

        self._signals     = {}
        self._t0          = 0.0
        self._current_id  = None
        self._compare_ids = []
        self._view        = "overview"
        self._tshark      = self._find_tshark()
        self._thread = self._worker = None
        self._favorites   = self._load_favorites()

        self._build_ui()
        self._cursor_vline    = None
        self._cursor_hline    = None
        self._cursor_annot    = None
        self._dragging        = False
        self._drag_pixel_start = None
        self._drag_xlim       = None
        self._drag_ylim       = None
        self._drag_bbox       = None
        self._markers         = {}   # {signal_id: [(x_rel, y_val), ...]}
        self._mark_mode       = False
        self._duplicates      = {}   # {sig_key: [lista de claves gemelas]}
        self._canvas.mpl_connect('motion_notify_event',  self._on_mouse_move)
        self._canvas.mpl_connect('axes_leave_event',     self._on_axes_leave)
        self._canvas.mpl_connect('button_press_event',   self._on_mouse_press)
        self._canvas.mpl_connect('button_release_event', self._on_mouse_release)
        self._canvas.mpl_connect('scroll_event',         self._on_scroll)
        draw_empty(self._fig, "Carga un .pcap y presiona ANALIZAR para comenzar.")
        self._canvas.draw()

    # ── Construcción de la UI ─────────────────────────────────────────────────

    def _build_ui(self):
        root_w = QWidget()
        self.setCentralWidget(root_w)
        root = QVBoxLayout(root_w)
        root.setContentsMargins(8, 6, 8, 4)
        root.setSpacing(5)
        root.addWidget(self._build_topbar())

        spl = QSplitter(Qt.Orientation.Horizontal)
        spl.setHandleWidth(2)
        spl.addWidget(self._build_left())
        spl.addWidget(self._build_right())
        spl.setSizes([450, 1010])
        spl.setStretchFactor(0, 0)
        spl.setStretchFactor(1, 1)
        root.addWidget(spl, 1)

        sb = QStatusBar()
        self.setStatusBar(sb)
        self._status_lbl = QLabel("Listo. Carga un .pcap para comenzar.")
        self._status_lbl.setObjectName("subtext")
        sb.addWidget(self._status_lbl, 1)
        self._progress = QProgressBar()
        self._progress.setMaximumWidth(160)
        self._progress.setMaximumHeight(10)
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        sb.addPermanentWidget(self._progress)

    def _build_topbar(self):
        bar = QFrame()
        bar.setObjectName("topbar")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 7, 12, 7)
        lay.setSpacing(6)

        lay.addWidget(self._lbl("PCAP:"))
        self._pcap_edit = QLineEdit()
        self._pcap_edit.setPlaceholderText("Ruta al archivo .pcap...")
        self._pcap_edit.setMinimumWidth(300)
        lay.addWidget(self._pcap_edit, 2)
        b1 = QPushButton("Examinar")
        b1.clicked.connect(self._browse_pcap)
        lay.addWidget(b1)

        lay.addSpacing(8)
        self._btn_analyze = QPushButton("  ANALIZAR")
        self._btn_analyze.setObjectName("accent")
        self._btn_analyze.setMinimumWidth(120)
        self._btn_analyze.clicked.connect(self._on_analyze)
        lay.addWidget(self._btn_analyze)
        return bar

    def _build_left(self):
        frame = QFrame()
        frame.setObjectName("card")
        frame.setMinimumWidth(380)
        frame.setMaximumWidth(620)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(5)

        lay.addWidget(self._lbl("FILTROS"))
        form = QFormLayout()
        form.setSpacing(4)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["Todos", "UDP", "TCP"])
        form.addRow("Protocolo:", self._proto_combo)
        self._src_combo = QComboBox()
        self._src_combo.setEditable(True)
        self._src_combo.addItem("(todas)")
        form.addRow("IP origen:", self._src_combo)
        self._dst_combo = QComboBox()
        self._dst_combo.setEditable(True)
        self._dst_combo.addItem("(todas)")
        form.addRow("IP destino:", self._dst_combo)
        lay.addLayout(form)

        self._only_var = QCheckBox("Solo con variacion")
        self._only_var.stateChanged.connect(self._populate_tree)
        lay.addWidget(self._only_var)

        lay.addWidget(self._sep())
        lay.addWidget(self._lbl("SENALES"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Buscar por ID hex, tipo, IP...")
        self._search.textChanged.connect(self._populate_tree)
        lay.addWidget(self._search)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(len(_TREE_COLS))
        self._tree.setHeaderLabels(_TREE_COLS)
        self._tree.setAlternatingRowColors(True)
        self._tree.setSortingEnabled(True)
        self._tree.setRootIsDecorated(False)
        self._tree.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        for i, w in enumerate(_TREE_WIDTHS):
            self._tree.setColumnWidth(i, w)
        self._tree.itemClicked.connect(self._on_item_click)
        self._tree.currentItemChanged.connect(self._on_current_changed)
        lay.addWidget(self._tree, 1)

        lay.addWidget(self._sep())
        lay.addWidget(self._lbl("DETALLE"))
        self._detail = QPlainTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setMaximumHeight(160)
        self._detail.setFont(QFont("Consolas", 9))
        lay.addWidget(self._detail)

        self._note_frame = self._build_note_editor()
        self._note_frame.setVisible(False)
        lay.addWidget(self._note_frame)

        lay.addWidget(self._sep())
        self._cmp_lbl = QLabel("Comparando: ninguna")
        self._cmp_lbl.setObjectName("subtext")
        lay.addWidget(self._cmp_lbl)
        btn_clr = QPushButton("Limpiar comparacion")
        btn_clr.clicked.connect(self._clear_compare)
        lay.addWidget(btn_clr)

        lay.addWidget(self._sep())
        lay.addWidget(self._lbl("NOMBRES DE SENALES"))
        row_cfg = QHBoxLayout()
        btn_exp = QPushButton("Exportar .config")
        btn_exp.setToolTip("Guarda todos los nombres y notas en un archivo .config")
        btn_exp.clicked.connect(self._export_names)
        row_cfg.addWidget(btn_exp)
        btn_imp = QPushButton("Importar .config")
        btn_imp.setToolTip("Carga nombres y notas desde un archivo .config")
        btn_imp.clicked.connect(self._import_names)
        row_cfg.addWidget(btn_imp)
        lay.addLayout(row_cfg)

        return frame

    def _build_right(self):
        frame = QFrame()
        frame.setObjectName("card")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(6, 6, 6, 4)
        lay.setSpacing(4)

        vbar = QWidget()
        vlay = QHBoxLayout(vbar)
        vlay.setContentsMargins(4, 2, 4, 2)
        vlay.setSpacing(4)
        vlay.addWidget(self._lbl("Vista:"))
        self._view_group = QButtonGroup(self)
        self._view_group.setExclusive(True)
        self._view_btns = {}
        for mode, lbl in [("overview", "Panoramica"),
                           ("individual", "Individual"), ("compare", "Comparar")]:
            btn = QPushButton(lbl)
            btn.setObjectName("view")
            btn.setCheckable(True)
            btn.setChecked(mode == "overview")
            btn.clicked.connect(lambda _=False, m=mode: self._set_view(m))
            self._view_group.addButton(btn)
            self._view_btns[mode] = btn
            vlay.addWidget(btn)
        hint = QLabel("   Ctrl+clic para comparar")
        hint.setObjectName("subtext")
        vlay.addWidget(hint)
        vlay.addStretch()
        lay.addWidget(vbar)

        self._fig    = Figure(figsize=(11, 7), dpi=96)
        self._canvas = FigureCanvas(self._fig)
        self._canvas.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        lay.addWidget(self._canvas, 1)
        self._ind_controls = self._build_ind_controls()
        self._ind_controls.setVisible(False)
        lay.addWidget(self._ind_controls)
        return frame

    # ── Panel de controles vista individual ───────────────────────────────────

    def _build_ind_controls(self):
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(8, 4, 8, 4)
        lay.setSpacing(8)

        btn_fit = QPushButton("⊡ Encajar")
        btn_fit.setToolTip("Ajustar vista a la señal completa")
        btn_fit.clicked.connect(self._auto_fit)
        lay.addWidget(btn_fit)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet(f"color:{C_BORDER};")
        lay.addWidget(sep)

        lay.addWidget(self._lbl_small("Periodo ×:"))
        self._period_spin = QDoubleSpinBox()
        self._period_spin.setRange(0.001, 10000.0)
        self._period_spin.setValue(1.0)
        self._period_spin.setSingleStep(0.1)
        self._period_spin.setDecimals(4)
        self._period_spin.setFixedWidth(95)
        self._period_spin.setToolTip("Escala del eje de tiempo (scroll en zona inferior del gráfico)")
        self._period_spin.valueChanged.connect(lambda _: self._refresh())
        lay.addWidget(self._period_spin)

        lay.addWidget(self._lbl_small("Escala ×:"))
        self._scale_spin = QDoubleSpinBox()
        self._scale_spin.setRange(0.0001, 10000.0)
        self._scale_spin.setValue(1.0)
        self._scale_spin.setSingleStep(0.1)
        self._scale_spin.setDecimals(4)
        self._scale_spin.setFixedWidth(95)
        self._scale_spin.setToolTip("Escala del eje de valor (scroll en zona izquierda del gráfico)")
        self._scale_spin.valueChanged.connect(lambda _: self._refresh())
        lay.addWidget(self._scale_spin)

        lay.addWidget(self._lbl_small("Offset:"))
        self._offset_spin = QDoubleSpinBox()
        self._offset_spin.setRange(-1e6, 1e6)
        self._offset_spin.setValue(0.0)
        self._offset_spin.setSingleStep(1.0)
        self._offset_spin.setDecimals(4)
        self._offset_spin.setFixedWidth(95)
        self._offset_spin.setToolTip("Desplazamiento vertical de la señal")
        self._offset_spin.valueChanged.connect(lambda _: self._refresh())
        lay.addWidget(self._offset_spin)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.VLine)
        sep2.setStyleSheet(f"color:{C_BORDER};")
        lay.addWidget(sep2)

        lay.addWidget(self._lbl_small("T₀:"))
        self._time_edit = QTimeEdit()
        self._time_edit.setDisplayFormat("HH:mm:ss")
        self._time_edit.setFixedWidth(80)
        self._time_edit.setToolTip("Hora real correspondiente a t=0 en la grafica")
        self._time_edit.timeChanged.connect(lambda _: self._refresh())
        lay.addWidget(self._time_edit)

        btn_reset = QPushButton("Restablecer")
        btn_reset.clicked.connect(self._reset_ind_controls)
        lay.addWidget(btn_reset)

        sep3 = QFrame()
        sep3.setFrameShape(QFrame.Shape.VLine)
        sep3.setStyleSheet(f"color:{C_BORDER};")
        lay.addWidget(sep3)

        self._mark_btn = QPushButton("+ Marcar punto")
        self._mark_btn.setCheckable(True)
        self._mark_btn.setToolTip("Activa: clic para fijar punto con hora y valor  |  Clic derecho sobre un marcador para eliminarlo")
        self._mark_btn.toggled.connect(self._on_mark_toggled)
        lay.addWidget(self._mark_btn)

        btn_clr_marks = QPushButton("Borrar marcas")
        btn_clr_marks.setToolTip("Elimina todos los marcadores de esta senal")
        btn_clr_marks.clicked.connect(self._clear_markers)
        lay.addWidget(btn_clr_marks)

        lay.addStretch()

        self._cursor_lbl = QLabel("t = —     val = —")
        self._cursor_lbl.setObjectName("subtext")
        lay.addWidget(self._cursor_lbl)
        return w

    def _lbl_small(self, text):
        l = QLabel(text)
        l.setObjectName("subtext")
        return l

    def _x_to_time_str(self, x: float) -> str:
        """Convierte x (segundos relativos a t0) en string HH:MM:SS absoluto."""
        qt = self._time_edit.time()
        base_s = qt.hour() * 3600 + qt.minute() * 60 + qt.second()
        total_s = int(base_s + x) % 86400
        if total_s < 0:
            total_s += 86400
        h = total_s // 3600
        m = (total_s % 3600) // 60
        s = total_s % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _reset_ind_controls(self):
        for sp, val in [(self._period_spin, 1.0),
                        (self._scale_spin,  1.0),
                        (self._offset_spin, 0.0)]:
            sp.blockSignals(True)
            sp.setValue(val)
            sp.blockSignals(False)
        self._refresh()

    # ── Marcadores de puntos ──────────────────────────────────────────────────

    def _on_mark_toggled(self, checked):
        self._mark_mode = checked

    def _clear_markers(self):
        if self._current_id is not None:
            self._markers.pop(self._current_id, None)
        self._refresh()

    def _remove_nearest_marker(self, x, y):
        if self._current_id is None:
            return
        pts = self._markers.get(self._current_id, [])
        if not pts:
            return
        ax = self._fig.axes[0] if self._fig.axes else None
        if ax is None:
            return
        # Normaliza distancia usando el rango visible de cada eje
        xl = ax.get_xlim(); yl = ax.get_ylim()
        xr = (xl[1] - xl[0]) or 1.0
        yr = (yl[1] - yl[0]) or 1.0
        nearest = min(range(len(pts)),
                      key=lambda i: ((pts[i][0]-x)/xr)**2 + ((pts[i][1]-y)/yr)**2)
        pts.pop(nearest)
        if not pts:
            self._markers.pop(self._current_id, None)
        self._refresh()

    def _draw_markers(self):
        if self._current_id is None or not self._fig.axes:
            return
        pts = self._markers.get(self._current_id, [])
        if not pts:
            return
        ax = self._fig.axes[0]
        for x, y in pts:
            ax.plot(x, y, 'o', ms=9, color="#ff6b6b", zorder=15,
                    markeredgecolor="#ffffff", markeredgewidth=1.5)
            t_str = self._x_to_time_str(x)
            ax.annotate(
                f"{t_str}\n{y:.5g}",
                xy=(x, y), xytext=(12, 12), textcoords="offset points",
                fontsize=9, family="monospace", color="#ff6b6b",
                bbox=dict(boxstyle="round,pad=0.45", facecolor="#1a0a0a",
                          edgecolor="#ff6b6b", linewidth=1.3, alpha=0.96),
                arrowprops=dict(arrowstyle="-", color="#ff6b6b", lw=1.2),
                zorder=16
            )

    # ── Cursor interactivo ────────────────────────────────────────────────────

    def _setup_cursor(self):
        if not self._fig.axes:
            return
        ax = self._fig.axes[0]
        self._cursor_vline = ax.axvline(x=0, color=C_HDR, lw=0.9, ls="--",
                                         alpha=0.75, visible=False, zorder=5)
        self._cursor_hline = ax.axhline(y=0, color=C_HDR, lw=0.9, ls="--",
                                         alpha=0.75, visible=False, zorder=5)
        self._cursor_annot = ax.text(
            0.01, 0.01, "", transform=ax.transAxes,
            fontsize=9.5, va="bottom", ha="left", family="monospace",
            color=C_TEXT, visible=False, zorder=10,
            bbox=dict(boxstyle="round,pad=0.5", facecolor=C_CARD,
                      edgecolor=C_BORDER, linewidth=1.2, alpha=0.95),
        )

    def _on_mouse_press(self, event):
        if self._view != "individual" or event.inaxes is None:
            return
        if self._mark_mode:
            if event.button == 1 and self._current_id is not None:
                pts = self._markers.setdefault(self._current_id, [])
                pts.append((event.xdata, event.ydata))
                self._refresh()
            elif event.button == 3:
                self._remove_nearest_marker(event.xdata, event.ydata)
            return
        if event.button == 1 and self._fig.axes:
            self._dragging = True
            ax = self._fig.axes[0]
            self._drag_pixel_start = (event.x, event.y)
            self._drag_xlim  = list(ax.get_xlim())
            self._drag_ylim  = list(ax.get_ylim())
            self._drag_bbox  = ax.get_window_extent()

    def _on_mouse_release(self, event):
        if event.button == 1:
            self._dragging = False

    def _on_mouse_move(self, event):
        if self._view != "individual" or self._cursor_vline is None:
            return
        if self._dragging and self._drag_pixel_start is not None:
            if event.inaxes is None or not self._fig.axes:
                return
            bbox = self._drag_bbox
            x_range = self._drag_xlim[1] - self._drag_xlim[0]
            y_range = self._drag_ylim[1] - self._drag_ylim[0]
            dx = (event.x - self._drag_pixel_start[0]) / bbox.width  * x_range
            dy = (event.y - self._drag_pixel_start[1]) / bbox.height * y_range
            ax = self._fig.axes[0]
            ax.set_xlim(self._drag_xlim[0] - dx, self._drag_xlim[1] - dx)
            ax.set_ylim(self._drag_ylim[0] - dy, self._drag_ylim[1] - dy)
            self._canvas.draw_idle()
            return
        if event.inaxes is None:
            self._cursor_vline.set_visible(False)
            self._cursor_hline.set_visible(False)
            self._cursor_annot.set_visible(False)
            self._cursor_lbl.setText("t = —     val = —")
            self._canvas.draw_idle()
            return
        x, y = event.xdata, event.ydata
        t_str = self._x_to_time_str(x)
        self._cursor_vline.set_xdata([x, x])
        self._cursor_hline.set_ydata([y, y])
        self._cursor_annot.set_text(f"t  =  {t_str}\nval =  {y:.5g}")
        self._cursor_vline.set_visible(True)
        self._cursor_hline.set_visible(True)
        self._cursor_annot.set_visible(True)
        self._cursor_lbl.setText(f"t = {t_str}     val = {y:.5g}")
        self._canvas.draw_idle()

    def _on_axes_leave(self, event):
        if self._dragging or self._cursor_vline is None:
            return
        self._cursor_vline.set_visible(False)
        self._cursor_hline.set_visible(False)
        self._cursor_annot.set_visible(False)
        self._cursor_lbl.setText("t = —     val = —")
        self._canvas.draw_idle()

    def _on_scroll(self, event):
        if self._view != "individual" or not self._fig.axes:
            return
        # Factor de cambio basado en dirección del scroll
        if event.button == 'up':
            factor = 1.15
        elif event.button == 'down':
            factor = 1.0 / 1.15
        else:
            return
        ax  = self._fig.axes[0]
        pos = ax.get_position()   # Bbox normalizada en coords figura [0,1]
        cw  = self._canvas.width()
        ch  = self._canvas.height()
        if cw == 0 or ch == 0:
            return
        nx = event.x / cw          # posición normalizada del cursor
        ny = event.y / ch
        # Zona inferior (etiquetas eje X) o dentro de los ejes → periodo
        in_period = (pos.x0 < nx < pos.x1) and (ny < pos.y1)
        # Zona izquierda (etiquetas eje Y) → escala
        in_scale  = (nx < pos.x0) and (pos.y0 < ny < pos.y1)
        if in_period:
            sp = self._period_spin
        elif in_scale:
            sp = self._scale_spin
        else:
            return
        sp.setValue(max(sp.minimum(), min(sp.maximum(), sp.value() * factor)))

    def _auto_fit(self):
        """Restablece la vista al encuadre natural de la señal."""
        for sp, val in [(self._period_spin, 1.0),
                        (self._scale_spin,  1.0),
                        (self._offset_spin, 0.0)]:
            sp.blockSignals(True)
            sp.setValue(val)
            sp.blockSignals(False)
        self._refresh()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _lbl(self, text):
        l = QLabel(text)
        l.setObjectName("header")
        return l

    def _sep(self):
        f = QFrame()
        f.setFrameShape(QFrame.Shape.HLine)
        f.setStyleSheet(f"color:{C_BORDER};")
        return f

    def _fav_key(self, sid: tuple) -> str:
        """Serializa la clave compuesta de señal para usar como clave de favoritos."""
        return f"{sid[0]}|{sid[1]}|{sid[2]}|{sid[3]}"

    def _find_tshark(self):
        exe_dir = os.path.dirname(sys.executable)
        local = os.path.join(exe_dir, "tshark.exe")
        if os.path.exists(local):
            return local
        for candidate in [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            "tshark",
        ]:
            if os.path.exists(candidate):
                return candidate
        return "tshark"

    def _browse_pcap(self):
        p, _ = QFileDialog.getOpenFileName(
            self, "Selecciona PCAP", "", "PCAP (*.pcap *.pcapng);;Todos (*.*)")
        if p:
            self._pcap_edit.setText(p)

    def _set_status(self, msg):
        self._status_lbl.setText(msg)

    def _set_busy(self, busy):
        self._progress.setVisible(busy)
        self._btn_analyze.setEnabled(not busy)

    # ── Vistas ────────────────────────────────────────────────────────────────

    def _set_view(self, mode):
        self._view = mode
        for m, btn in self._view_btns.items():
            btn.setChecked(m == mode)
        self._refresh()

    def _refresh(self):
        m  = self._view
        ov = self._only_var.isChecked()
        self._cursor_vline = None
        self._cursor_hline = None
        self._cursor_annot = None
        if   m == "overview":
            draw_overview(self._fig, self._signals, self._t0, only_varying=ov)
        elif m == "individual":
            if self._current_id and self._current_id in self._signals:
                info = self._signals[self._current_id]
                xlim, ylim = draw_individual(
                    self._fig, info["signal_id"],
                    info, self._t0)
                self._apply_view_transforms(xlim, ylim)
                self._draw_markers()
                self._setup_cursor()
            else:
                draw_empty(self._fig, "Haz clic en una senal de la lista para verla aqui.")
        elif m == "compare":
            draw_compare(self._fig, self._compare_ids, self._signals, self._t0)
        self._ind_controls.setVisible(m == "individual")
        self._canvas.draw()

    def _apply_view_transforms(self, xlim, ylim):
        """Aplica periodo/escala/offset como transformaciones del eje, no de los datos."""
        if not self._fig.axes:
            return
        ax = self._fig.axes[0]
        period = self._period_spin.value()
        scale  = self._scale_spin.value()
        offset = self._offset_spin.value()
        # Periodo: escala el eje X (periodo mayor → señal más comprimida = zoom out X)
        xc     = (xlim[0] + xlim[1]) / 2
        xhalf  = (xlim[1] - xlim[0]) / 2
        ax.set_xlim(xc - xhalf / period, xc + xhalf / period)
        # Escala: zoom del eje Y (escala mayor → señal más grande = zoom in Y)
        yc     = (ylim[0] + ylim[1]) / 2 + offset
        yhalf  = (ylim[1] - ylim[0]) / 2
        ax.set_ylim(yc - yhalf / scale, yc + yhalf / scale)
        # Eje X en hora absoluta HH:MM:SS
        ax.xaxis.set_major_formatter(
            mticker.FuncFormatter(lambda x, _: self._x_to_time_str(x))
        )
        ax.set_xlabel("Hora", fontsize=11)

    # ── Árbol de señales ──────────────────────────────────────────────────────

    def _on_item_click(self, item, col):
        sid = item.data(0, Qt.ItemDataRole.UserRole)
        if col == 0:  # columna estrella: alternar favorito
            self._toggle_favorite(sid)
            return
        mods = QApplication.keyboardModifiers()
        if not (mods & Qt.KeyboardModifier.ControlModifier):
            self._tree.setFocus()
            return
        # Ctrl+clic: agregar/quitar de comparación
        if sid in self._compare_ids:
            self._compare_ids.remove(sid)
        else:
            self._compare_ids.append(sid)
        self._cmp_lbl.setText(f"Comparando: {len(self._compare_ids)} senal(es)")
        self._set_view("compare")
        self._tree.setFocus()

    def _on_current_changed(self, current, previous):
        """Se dispara tanto con clic normal como con teclas de flecha."""
        if current is None:
            return
        mods = QApplication.keyboardModifiers()
        if mods & Qt.KeyboardModifier.ControlModifier:
            return  # lo maneja _on_item_click
        sid = current.data(0, Qt.ItemDataRole.UserRole)
        if sid is None:
            return
        self._current_id = sid
        self._update_detail(sid)
        self._set_view("individual")
        self._tree.setFocus()

    def _clear_compare(self):
        self._compare_ids.clear()
        self._cmp_lbl.setText("Comparando: ninguna")
        if self._view == "compare":
            self._refresh()

    def _update_detail(self, sid):
        if sid not in self._signals:
            return
        info   = self._signals[sid]
        int_id = info["signal_id"]
        self._detail.setPlainText(
            f"ID:       0x{int_id:04X}  ({int_id})\n"
            f"Tipo:     {sig_type(info)}\n"
            f"Protocolo:{info.get('transport','')}\n"
            f"Origen:   {info.get('ip_src','')}\n"
            f"Destino:  {info.get('ip_dst','')}\n"
            f"N:        {info['n']} muestras\n"
            f"Min:      {info['min']:.5g}\n"
            f"Max:      {info['max']:.5g}\n"
            f"Sigma:    {info['std']:.4g}\n"
            f"Rango:    {info['range']:.4g}"
        )
        # Señales con serie temporal idéntica
        gemelas = self._duplicates.get(sid, [])
        if gemelas:
            lines = ["\nSENALES IDENTICAS:"]
            for g in gemelas[:8]:
                lines.append(f"  0x{g[0]:04X}  {g[1]}  {g[2]}->{g[3]}")
            if len(gemelas) > 8:
                lines.append(f"  ... ({len(gemelas)-8} mas)")
            self._detail.appendPlainText('\n'.join(lines))

        fk  = self._fav_key(sid)
        fav = fk in self._favorites
        self._note_frame.setVisible(fav)
        if fav:
            self._note_name.blockSignals(True)
            self._note_body.blockSignals(True)
            self._note_name.setText(self._favorites[fk].get("name", ""))
            self._note_body.setPlainText(self._favorites[fk].get("note", ""))
            self._note_name.blockSignals(False)
            self._note_body.blockSignals(False)

    def _populate_tree(self):
        self._tree.clear()
        if not self._signals:
            return
        search   = self._search.text().strip().lower()
        only_var = self._only_var.isChecked()
        # Favoritos primero, luego por variabilidad descendente
        ranked = sorted(
            self._signals.items(),
            key=lambda x: (self._fav_key(x[0]) not in self._favorites,
                           -(x[1]["range"] + x[1]["std"]))
        )
        for sid, info in ranked:
            t      = sig_type(info)
            hex_id = f"0x{info['signal_id']:04X}"
            proto  = info.get("transport", "")
            src    = info.get("ip_src", "")
            dst    = info.get("ip_dst", "")
            if search and not any(search in s.lower() for s in [hex_id, t, proto, src, dst]):
                continue
            if only_var and info["range"] == 0:
                continue
            fk   = self._fav_key(sid)
            fav  = fk in self._favorites
            star = "★" if fav else "☆"
            name = self._favorites[fk].get("name", "") if fav else ""
            note = self._favorites[fk].get("note", "") if fav else ""
            if fav:
                bg = QBrush(QColor(_C_FAV_BG))
                fg = QBrush(QColor(_C_FAV_FG))
            else:
                st = TYPE_STYLE.get(t, {"bg": C_CARD, "fg": C_TEXT})
                bg = QBrush(QColor(st["bg"]))
                fg = QBrush(QColor(st["fg"]))
            gemelas = self._duplicates.get(sid, [])
            n_col   = f"{info['n']} ≡{len(gemelas)}" if gemelas else str(info["n"])
            item = QTreeWidgetItem([
                star, name, hex_id, t, proto, src, dst,
                f"{info['max']:.4g}",
                f"{info['std']:.3g}",
                n_col,
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, sid)
            item.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)
            if note:
                item.setToolTip(1, note)
            if gemelas:
                gem_txt = "Identica a:\n" + "\n".join(
                    f"  0x{g[0]:04X} {g[1]} {g[2]}->{g[3]}" for g in gemelas[:6])
                item.setToolTip(2, gem_txt)
            for c in range(len(_TREE_COLS)):
                item.setBackground(c, bg)
                item.setForeground(c, fg)
            self._tree.addTopLevelItem(item)
        # Restaurar selección visual sin disparar eventos
        if self._current_id is not None:
            self._tree.blockSignals(True)
            for i in range(self._tree.topLevelItemCount()):
                it = self._tree.topLevelItem(i)
                if it.data(0, Qt.ItemDataRole.UserRole) == self._current_id:
                    self._tree.setCurrentItem(it)
                    break
            self._tree.blockSignals(False)

    # ── Favoritos ─────────────────────────────────────────────────────────────

    def _load_favorites(self) -> dict:
        try:
            with open(_FAVORITES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return {}
            # Formato nuevo: claves "sig_id|transport|ip_src|ip_dst"
            result = {}
            for k, v in data.items():
                if '|' in k:
                    result[k] = v
                # Claves antiguas (int puro) se descartan — formato incompatible
            return result
        except (FileNotFoundError, json.JSONDecodeError, ValueError, KeyError):
            return {}

    def _save_favorites(self):
        try:
            with open(_FAVORITES_FILE, "w", encoding="utf-8") as f:
                json.dump(self._favorites, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _toggle_favorite(self, sid):
        fk = self._fav_key(sid)
        if fk in self._favorites:
            del self._favorites[fk]
        else:
            self._favorites[fk] = {"name": "", "note": ""}
        self._save_favorites()
        self._populate_tree()
        if sid == self._current_id:
            self._update_detail(sid)

    def _build_note_editor(self):
        frame = QFrame()
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(0, 4, 0, 0)
        lay.setSpacing(3)
        lay.addWidget(self._sep())
        lay.addWidget(self._lbl("NOMBRE / NOTA"))
        self._note_name = QLineEdit()
        self._note_name.setPlaceholderText("Nombre de la senal...")
        self._note_name.textChanged.connect(self._save_fav_note)
        lay.addWidget(self._note_name)
        self._note_body = QPlainTextEdit()
        self._note_body.setPlaceholderText("Notas adicionales...")
        self._note_body.setMaximumHeight(70)
        self._note_body.setFont(QFont("Consolas", 9))
        self._note_body.textChanged.connect(self._save_fav_note)
        lay.addWidget(self._note_body)
        return frame

    def _save_fav_note(self):
        sid = self._current_id
        if sid is None:
            return
        fk = self._fav_key(sid)
        if fk not in self._favorites:
            return
        self._favorites[fk]["name"] = self._note_name.text()
        self._favorites[fk]["note"] = self._note_body.toPlainText()
        self._save_favorites()
        for i in range(self._tree.topLevelItemCount()):
            it = self._tree.topLevelItem(i)
            if it.data(0, Qt.ItemDataRole.UserRole) == sid:
                it.setText(1, self._note_name.text())
                it.setToolTip(1, self._note_body.toPlainText())
                break

    # ── Exportar / Importar nombres ───────────────────────────────────────────

    def _export_names(self):
        if not self._favorites:
            QMessageBox.information(self, "Exportar", "No hay senales con nombre asignado.\nMarca una senal como favorita (★) y ponle nombre primero.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Exportar nombres de senales", "signal_names.config",
            "Config (*.config);;Todos (*.*)")
        if not path:
            return
        data = {
            "version": 1,
            "signals": {
                k: {"name": v.get("name", ""), "note": v.get("note", "")}
                for k, v in self._favorites.items()
                if v.get("name") or v.get("note")
            }
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self._set_status(f"Exportado: {len(data['signals'])} senales → {path}")
        except OSError as e:
            QMessageBox.critical(self, "Error al exportar", str(e))

    def _import_names(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Importar nombres de senales", "",
            "Config (*.config);;Todos (*.*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Error al importar", str(e))
            return
        signals = data.get("signals", {})
        if not signals:
            QMessageBox.warning(self, "Importar", "El archivo no contiene senales.")
            return
        imported = 0
        for key, val in signals.items():
            if not isinstance(val, dict):
                continue
            if key not in self._favorites:
                self._favorites[key] = {}
            if val.get("name"):
                self._favorites[key]["name"] = val["name"]
            if val.get("note"):
                self._favorites[key]["note"] = val["note"]
            imported += 1
        self._save_favorites()
        self._populate_tree()
        self._set_status(f"Importado: {imported} nombres desde {path}")

    # ── Análisis ──────────────────────────────────────────────────────────────

    def _on_analyze(self):
        pcap = self._pcap_edit.text().strip()
        if not pcap or not os.path.exists(pcap):
            QMessageBox.warning(self, "Atencion", "Selecciona un archivo .pcap valido.")
            return
        src = self._src_combo.currentText().strip()
        dst = self._dst_combo.currentText().strip()
        if src in ("", "(todas)"):
            src = ""
        if dst in ("", "(todas)"):
            dst = ""
        self._set_status("Extrayendo paquetes con tshark...")
        self._set_busy(True)
        self._thread = QThread()
        self._worker = AnalysisWorker(
            self._tshark, pcap,
            self._proto_combo.currentText(), src, dst
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._set_status)
        self._worker.finished.connect(self._on_done)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._on_error)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(lambda: self._set_busy(False))
        self._thread.start()

    def _on_done(self, pkts, sigs, t0, dur):
        srcs = sorted({p["ip_src"] for p in pkts if p.get("ip_src")})
        dsts = sorted({p["ip_dst"] for p in pkts if p.get("ip_dst")})
        cur_src = self._src_combo.currentText()
        cur_dst = self._dst_combo.currentText()
        self._src_combo.blockSignals(True)
        self._dst_combo.blockSignals(True)
        self._src_combo.clear(); self._src_combo.addItem("(todas)"); self._src_combo.addItems(srcs)
        self._dst_combo.clear(); self._dst_combo.addItem("(todas)"); self._dst_combo.addItems(dsts)
        if cur_src in srcs:
            self._src_combo.setCurrentText(cur_src)
        if cur_dst in dsts:
            self._dst_combo.setCurrentText(cur_dst)
        self._src_combo.blockSignals(False)
        self._dst_combo.blockSignals(False)

        self._signals    = sigs
        self._t0         = t0
        self._duplicates = find_duplicate_groups(sigs)
        dt = datetime.datetime.fromtimestamp(t0)
        self._time_edit.blockSignals(True)
        self._time_edit.setTime(QTime(dt.hour, dt.minute, dt.second))
        self._time_edit.blockSignals(False)
        varying = sum(1 for s in sigs.values() if s["range"] > 0)
        self._set_status(
            f"{len(pkts)} paquetes  ·  {len(sigs)} senales  "
            f"·  {varying} con variacion  ·  {dur:.1f} s captura"
        )
        self._populate_tree()
        self._set_view("overview")

    def _on_error(self, msg):
        self._set_status(f"Error: {msg}")
        QMessageBox.critical(self, "Error en analisis", msg)
