"""
Ventana principal de la aplicación — Ethernet Signal Analyzer.
"""

import os
import sys
import json
import shutil
import datetime

import matplotlib
matplotlib.use("QtAgg")
import matplotlib.ticker as mticker
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QSplitter,
    QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox,
    QTreeWidget, QTreeWidgetItem, QPlainTextEdit, QListWidget,
    QStatusBar, QProgressBar, QFileDialog, QMessageBox,
    QButtonGroup, QFrame, QDoubleSpinBox, QTimeEdit,
    QWidgetAction, QInputDialog, QMenu, QDialog, QDialogButtonBox,
)
from PyQt6.QtCore import Qt, QThread, QTime, QTimer
from PyQt6.QtGui import QColor, QFont, QBrush, QAction

from .styles import QSS, C_BG, C_CARD, C_TEXT, C_HDR, C_SUB, C_BORDER, C_SURF, C_INPUT, TYPE_STYLE
from .analysis import sig_type, find_duplicate_groups
from .plots import (draw_empty, draw_individual, draw_overview, draw_compare, draw_live)
from .workers import AnalysisWorker, LiveCaptureWorker

# Columnas del árbol de señales
_TREE_COLS    = ["★", "Nombre", "ID Hex", "Tipo", "Proto", "Origen", "Destino", "Max", "s", "N"]
_TREE_WIDTHS  = [26, 115, 65, 42, 46, 110, 110, 58, 48, 38]

# Colores para señales favoritas
_C_FAV_BG = "#2a1f00"
_C_FAV_FG = "#f0c040"

# Archivo donde se guardan los favoritos (junto a window.py → raíz del proyecto)
_FAVORITES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "favorites.json")
_LIVE_BUFFER = 500


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
        self._live_thread      = None
        self._live_worker      = None
        self._live_timer       = None
        self._live_signals     = {}
        self._live_tcp_bufs    = {}
        self._live_t0          = 0.0
        self._live_raw_packets = []
        self._packets     = []
        self._favorites   = self._load_favorites()

        self._build_ui()
        self._check_tshark()
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
        draw_empty(self._fig, "Usa  Archivo → Abrir y analizar PCAP  para comenzar.")
        self._canvas.draw()

    # ── Construcción de la UI ─────────────────────────────────────────────────

    def _build_ui(self):
        root_w = QWidget()
        self.setCentralWidget(root_w)
        root = QVBoxLayout(root_w)
        root.setContentsMargins(8, 6, 8, 4)
        root.setSpacing(5)
        self._build_menus()

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
        self._status_lbl = QLabel("Listo. Usa  Archivo → Abrir y analizar PCAP  para comenzar.")
        self._status_lbl.setObjectName("subtext")
        sb.addWidget(self._status_lbl, 1)
        self._progress = QProgressBar()
        self._progress.setMaximumWidth(160)
        self._progress.setMaximumHeight(10)
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        sb.addPermanentWidget(self._progress)

    def _build_menus(self):
        mb = self.menuBar()

        # ── Archivo ───────────────────────────────────────────────────────────
        m_file = mb.addMenu("Archivo")

        self._act_open_analyze = QAction("Abrir y analizar PCAP...", self)
        self._act_open_analyze.setShortcut("Ctrl+O")
        self._act_open_analyze.triggered.connect(self._menu_open_analyze)
        m_file.addAction(self._act_open_analyze)

        self._act_export_csv = QAction("Exportar señal seleccionada a CSV...", self)
        self._act_export_csv.setShortcut("Ctrl+E")
        self._act_export_csv.setEnabled(False)
        self._act_export_csv.triggered.connect(self._export_signal_csv)
        m_file.addAction(self._act_export_csv)

        self._act_export_visible = QAction("Exportar señales visibles a CSV...", self)
        self._act_export_visible.setEnabled(False)
        self._act_export_visible.triggered.connect(self._export_signals_visible_csv)
        m_file.addAction(self._act_export_visible)

        self._act_export_pkts = QAction("Exportar paquetes a CSV...", self)
        self._act_export_pkts.setEnabled(False)
        self._act_export_pkts.triggered.connect(self._export_packets_csv)
        m_file.addAction(self._act_export_pkts)

        m_file.addSeparator()

        act_import_names = QAction("Importar nombres .config...", self)
        act_import_names.triggered.connect(self._import_names)
        m_file.addAction(act_import_names)

        act_export_names = QAction("Exportar nombres .config...", self)
        act_export_names.triggered.connect(self._export_names)
        m_file.addAction(act_export_names)

        m_file.addSeparator()

        act_quit = QAction("Salir", self)
        act_quit.setShortcut("Ctrl+Q")
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_quit)

        # ── Captura en vivo ───────────────────────────────────────────────────
        m_live = mb.addMenu("Captura en vivo")

        iface_widget = QWidget()
        iface_lay = QHBoxLayout(iface_widget)
        iface_lay.setContentsMargins(8, 4, 8, 4)
        iface_lay.setSpacing(6)
        iface_lay.addWidget(QLabel("Interfaz:"))
        self._iface_combo = QComboBox()
        self._iface_combo.setMinimumWidth(200)
        self._load_interfaces()
        iface_lay.addWidget(self._iface_combo)
        iface_action = QWidgetAction(self)
        iface_action.setDefaultWidget(iface_widget)
        m_live.addAction(iface_action)

        m_live.addSeparator()

        self._act_live_start = QAction("Iniciar captura", self)
        self._act_live_start.setShortcut("Ctrl+R")
        self._act_live_start.triggered.connect(self._start_live)
        m_live.addAction(self._act_live_start)

        self._act_live_stop = QAction("Detener captura", self)
        self._act_live_stop.setEnabled(False)
        self._act_live_stop.triggered.connect(self._stop_live)
        m_live.addAction(self._act_live_stop)

        m_live.addSeparator()

        act_clear = QAction("Limpiar datos capturados", self)
        act_clear.triggered.connect(self._clear_live_data)
        m_live.addAction(act_clear)

        act_save_pcap = QAction("Guardar PCAP...", self)
        act_save_pcap.triggered.connect(self._save_live_pcap)
        m_live.addAction(act_save_pcap)

    def _menu_open_analyze(self):
        p, _ = QFileDialog.getOpenFileName(
            self, "Selecciona PCAP", "", "PCAP (*.pcap *.pcapng);;Todos (*.*)")
        if p:
            self._start_analyze(p)

    def _build_left(self):
        frame = QFrame()
        frame.setObjectName("card")
        frame.setMinimumWidth(380)
        frame.setMaximumWidth(620)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(5)

        lay.addWidget(self._lbl("SENALES"))

        # ── Fila de filtros: proto + IPs ──────────────────────────────────────
        frow = QHBoxLayout()
        frow.setSpacing(4)
        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["Todos", "UDP", "TCP"])
        self._proto_combo.setFixedWidth(68)
        self._proto_combo.setToolTip("Filtrar por protocolo")
        self._proto_combo.currentTextChanged.connect(self._populate_tree)
        frow.addWidget(self._proto_combo)
        frow.addWidget(self._lbl_small("Orig:"))
        self._src_combo = QComboBox()
        self._src_combo.setEditable(True)
        self._src_combo.addItem("(todas)")
        self._src_combo.setToolTip("Filtrar por IP de origen")
        self._src_combo.currentTextChanged.connect(self._populate_tree)
        frow.addWidget(self._src_combo, 1)
        frow.addWidget(self._lbl_small("→"))
        self._dst_combo = QComboBox()
        self._dst_combo.setEditable(True)
        self._dst_combo.addItem("(todas)")
        self._dst_combo.setToolTip("Filtrar por IP de destino")
        self._dst_combo.currentTextChanged.connect(self._populate_tree)
        frow.addWidget(self._dst_combo, 1)
        lay.addLayout(frow)

        # ── Busqueda + checkbox ───────────────────────────────────────────────
        srow = QHBoxLayout()
        srow.setSpacing(5)
        self._search = QLineEdit()
        self._search.setPlaceholderText("Buscar ID hex, IP, tipo...")
        self._search.textChanged.connect(self._populate_tree)
        srow.addWidget(self._search, 1)
        self._only_var = QCheckBox("Solo variables")
        self._only_var.setToolTip("Mostrar solo señales que cambian de valor")
        self._only_var.stateChanged.connect(self._populate_tree)
        srow.addWidget(self._only_var)
        lay.addLayout(srow)

        # ── Árbol ─────────────────────────────────────────────────────────────
        self._tree = QTreeWidget()
        self._tree.setColumnCount(len(_TREE_COLS))
        self._tree.setHeaderLabels(_TREE_COLS)
        self._tree.setAlternatingRowColors(True)
        self._tree.setSortingEnabled(True)
        self._tree.setRootIsDecorated(False)
        self._tree.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_tree_context_menu)
        for i, w in enumerate(_TREE_WIDTHS):
            self._tree.setColumnWidth(i, w)
        self._tree.itemClicked.connect(self._on_item_click)
        self._tree.currentItemChanged.connect(self._on_current_changed)
        lay.addWidget(self._tree, 1)

        # ── Detalle ───────────────────────────────────────────────────────────
        lay.addWidget(self._sep())
        lay.addWidget(self._lbl("DETALLE"))
        self._detail = QPlainTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setMaximumHeight(148)
        self._detail.setFont(QFont("Consolas", 9))
        lay.addWidget(self._detail)

        # ── Comparar ──────────────────────────────────────────────────────────
        lay.addWidget(self._sep())
        cmp_row = QHBoxLayout()
        cmp_row.setSpacing(6)
        self._cmp_lbl = QLabel("Comparando: ninguna")
        self._cmp_lbl.setObjectName("subtext")
        cmp_row.addWidget(self._cmp_lbl, 1)
        btn_clr = QPushButton("Limpiar")
        btn_clr.setFixedWidth(68)
        btn_clr.setToolTip("Limpiar lista de comparacion")
        btn_clr.clicked.connect(self._clear_compare)
        cmp_row.addWidget(btn_clr)
        lay.addLayout(cmp_row)

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
                           ("individual", "Individual"), ("compare", "Comparar"),
                           ("live", "En Vivo")]:
            btn = QPushButton(lbl)
            btn.setObjectName("view")
            btn.setCheckable(True)
            btn.setChecked(mode == "overview")
            btn.clicked.connect(lambda _=False, m=mode: self._set_view(m))
            self._view_group.addButton(btn)
            self._view_btns[mode] = btn
            vlay.addWidget(btn)

        self._live_indicator = QLabel("")
        self._live_indicator.setFixedWidth(128)
        self._live_indicator.setStyleSheet(f"font-size:8pt; font-weight:bold; color:{C_SUB};")
        vlay.addWidget(self._live_indicator)

        vsep_vbar = QFrame()
        vsep_vbar.setFrameShape(QFrame.Shape.VLine)
        vsep_vbar.setStyleSheet(f"color:{C_BORDER};")
        vlay.addWidget(vsep_vbar)
        vlay.addWidget(self._lbl_small("Tipo señal:"))
        self._live_type_combo = QComboBox()
        self._live_type_combo.addItems(["Todos", "float", "int", "digital"])
        self._live_type_combo.setFixedWidth(80)
        vlay.addWidget(self._live_type_combo)
        vlay.addWidget(self._lbl_small("ID hex:"))
        self._live_id_edit = QLineEdit()
        self._live_id_edit.setPlaceholderText("ej. 0011")
        self._live_id_edit.setFixedWidth(110)
        vlay.addWidget(self._live_id_edit)

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
        if self._view not in ("individual", "compare") or event.inaxes is None:
            return
        if self._view == "individual" and self._mark_mode:
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
        if self._view not in ("individual", "compare") or self._cursor_vline is None:
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
        if self._view not in ("individual", "compare") or not self._fig.axes:
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
        for candidate in [
            os.path.join(os.path.dirname(sys.executable), "tshark.exe"),
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
        ]:
            if os.path.isfile(candidate):
                return candidate
        return shutil.which("tshark") or "tshark"

    def _load_interfaces(self):
        from .tshark import get_interfaces
        ifaces = get_interfaces(self._tshark)
        self._iface_combo.clear()
        self._iface_combo.addItems(ifaces if ifaces else ["(sin interfaces)"])

    def _start_live(self):
        iface = self._iface_combo.currentText()
        self._live_signals     = {}
        self._live_tcp_bufs    = {}
        self._live_t0          = 0.0
        self._live_raw_packets = []

        self._live_thread = QThread()
        self._live_worker = LiveCaptureWorker(self._tshark, iface, "", "", "", "")
        self._live_worker.moveToThread(self._live_thread)
        self._live_thread.started.connect(self._live_worker.run)
        self._live_worker.new_packet.connect(self._on_live_packet)
        self._live_worker.error.connect(self._on_live_error)
        self._live_worker.error.connect(self._live_thread.quit)
        self._live_thread.start()

        self._live_timer = QTimer()
        self._live_timer.setInterval(500)
        self._live_timer.timeout.connect(self._update_live_plot)
        self._live_timer.start()

        self._act_live_start.setEnabled(False)
        self._act_live_stop.setEnabled(True)
        self._live_indicator.setText("⬤ capturando")
        self._live_indicator.setStyleSheet("font-size:8pt; font-weight:bold; color:#60b060;")
        self._set_view("live")
        self._set_status(f"Capturando en {iface}...")

    def _stop_live(self):
        if self._live_timer:
            self._live_timer.stop()
            self._live_timer = None
        if self._live_worker:
            self._live_worker.stop()
            self._live_worker = None
        if self._live_thread:
            self._live_thread.quit()
            self._live_thread.wait(3000)
            self._live_thread = None
        self._act_live_start.setEnabled(True)
        self._act_live_stop.setEnabled(False)
        self._live_indicator.setText("○ detenida")
        self._live_indicator.setStyleSheet(f"font-size:8pt; font-weight:bold; color:{C_SUB};")
        n_sig = len(self._live_signals)
        n_pts = sum(v["n"] for v in self._live_signals.values())
        n_pkts = len(self._live_raw_packets)
        self._set_status(
            f"Captura detenida — {n_sig} senales, {n_pts} muestras, {n_pkts} paquetes raw"
        )

    def _clear_live_data(self):
        self._live_signals     = {}
        self._live_tcp_bufs    = {}
        self._live_t0          = 0.0
        self._live_raw_packets = []
        self._set_status("Datos de captura borrados.")
        if self._view == "live":
            draw_empty(self._fig, "Datos borrados. Esperando nuevos paquetes...")
            self._canvas.draw()

    def _on_live_packet(self, pkt):
        import numpy as np
        from .parser import parse_raw_packet, parse_tcp16_stream
        ts = pkt["ts"]
        if not self._live_t0:
            self._live_t0 = ts

        # Acumular para exportación PCAP (máximo 100 000 paquetes ~ ~50 MB)
        if len(self._live_raw_packets) < 100_000:
            self._live_raw_packets.append(pkt)

        if pkt["transport"] == "UDP":
            _, entries = parse_raw_packet(pkt["payload"])
            for sig_id, val, is_f, cat, *_ in entries:
                self._live_add(sig_id, val, is_f, cat, ts,
                               "UDP", pkt["ip_src"], pkt["ip_dst"])
        else:
            stream_key = (pkt["ip_src"], pkt["ip_dst"])
            try:
                chunk = bytes.fromhex(pkt["payload"].replace(" ", ""))
            except ValueError:
                return
            buf = self._live_tcp_bufs.get(stream_key, b"") + chunk
            entries, buf = parse_tcp16_stream(buf)
            self._live_tcp_bufs[stream_key] = buf
            for sig_id, val, is_f, cat, *_ in entries:
                self._live_add(sig_id, val, is_f, cat, ts,
                               "TCP", pkt["ip_src"], pkt["ip_dst"])

        n_sig = len(self._live_signals)
        n_pts = sum(v["n"] for v in self._live_signals.values())
        self._set_status(f"Capturando...  {n_sig} senales  ·  {n_pts} muestras")

    def _live_add(self, sig_id, val, is_f, cat, ts, transport, ip_src, ip_dst):
        import numpy as np
        key = (sig_id, transport, ip_src, ip_dst)
        if key not in self._live_signals:
            self._live_signals[key] = {
                "signal_id": sig_id, "ts": [], "val": [],
                "is_float": is_f, "cat": cat,
                "transport": transport, "ip_src": ip_src, "ip_dst": ip_dst,
                "min": 0.0, "max": 0.0, "std": 0.0, "range": 0.0, "n": 0,
            }
        info = self._live_signals[key]
        info["ts"].append(ts)
        info["val"].append(val)
        info["n"] += 1
        if len(info["ts"]) > _LIVE_BUFFER:
            info["ts"]  = info["ts"][-_LIVE_BUFFER:]
            info["val"] = info["val"][-_LIVE_BUFFER:]
        arr = np.array(info["val"], dtype=float)
        info["min"]   = float(arr.min())
        info["max"]   = float(arr.max())
        info["std"]   = float(arr.std())
        info["range"] = float(arr.max() - arr.min())

    def _on_live_error(self, msg):
        self._stop_live()
        QMessageBox.critical(self, "Error en captura en vivo", msg)

    def _save_live_pcap(self):
        if not self._live_raw_packets:
            QMessageBox.information(self, "Guardar PCAP",
                                    "No hay paquetes capturados todavia.")
            return
        default_name = f"live_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path, _ = QFileDialog.getSaveFileName(
            self, "Guardar captura como PCAP", default_name,
            "PCAP (*.pcap);;Todos (*.*)")
        if not path:
            return
        try:
            self._write_pcap_file(path, self._live_raw_packets)
            n = len(self._live_raw_packets)
            self._set_status(f"PCAP guardado: {n} paquetes → {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error al guardar PCAP", str(e))

    @staticmethod
    def _write_pcap_file(path: str, packets: list):
        import struct
        import socket as _socket

        def ip4(s):
            try:
                return _socket.inet_aton(s)
            except Exception:
                return b'\x00\x00\x00\x00'

        with open(path, 'wb') as f:
            # Global header (24 bytes): magic, ver_maj, ver_min, zone,
            #                           sigfigs, snaplen, linktype=101 (raw IPv4)
            f.write(struct.pack('<IHHiIII',
                0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))

            for pkt in packets:
                try:
                    payload_bytes = bytes.fromhex(
                        pkt['payload'].replace(':', '').replace(' ', ''))
                except (ValueError, AttributeError, KeyError):
                    continue

                src_ip = ip4(pkt.get('ip_src') or '')
                dst_ip = ip4(pkt.get('ip_dst') or '')
                try:
                    sp = int(pkt.get('src_port') or 0)
                    dp = int(pkt.get('dst_port') or 0)
                except (ValueError, TypeError):
                    sp = dp = 0

                transport = pkt.get('transport', 'UDP')
                if transport == 'UDP':
                    proto_num = 17
                    udp_len   = 8 + len(payload_bytes)
                    l4 = struct.pack('>HHHH', sp, dp, udp_len, 0) + payload_bytes
                else:
                    proto_num = 6
                    l4 = struct.pack('>HHIIBBHHH',
                        sp, dp, 0, 0,   # ports, seq, ack
                        0x50, 0x10,     # data offset=20, ACK flag
                        65535, 0, 0,    # window, checksum, urgent
                    ) + payload_bytes

                ip_total = 20 + len(l4)
                ip_hdr = struct.pack('>BBHHHBBH4s4s',
                    0x45, 0, ip_total, 0, 0, 64, proto_num, 0, src_ip, dst_ip)

                frame = ip_hdr + l4
                ts     = pkt.get('ts', 0.0)
                ts_sec = int(ts)
                ts_us  = int((ts - ts_sec) * 1_000_000)
                f.write(struct.pack('<IIII', ts_sec, ts_us,
                                    len(frame), len(frame)))
                f.write(frame)

    def _update_live_plot(self):
        if self._view != "live":
            return
        ftype   = self._live_type_combo.currentText()
        id_text   = self._live_id_edit.text().strip()
        filter_ids = set()
        for part in id_text.split(","):
            part = part.strip()
            if part:
                try:
                    filter_ids.add(int(part, 16))
                except ValueError:
                    pass
        if self._live_signals:
            sigs = self._live_signals
            if ftype != "Todos":
                sigs = {k: v for k, v in sigs.items() if sig_type(v) == ftype}
            if filter_ids:
                sigs = {k: v for k, v in sigs.items()
                        if v["signal_id"] in filter_ids}
            n_sig = len(self._live_signals)
            n_pts = sum(v["n"] for v in self._live_signals.values())
            self._live_indicator.setText(f"⬤ {n_sig} sen · {n_pts} pts")
            if sigs:
                draw_overview(self._fig, sigs, self._live_t0)
            else:
                draw_empty(self._fig, "Sin senales que coincidan con los filtros.")
        else:
            draw_empty(self._fig, "Esperando paquetes...")
        self._canvas.draw()

    def _check_tshark(self):
        import subprocess, platform
        try:
            subprocess.run([self._tshark, "--version"],
                           capture_output=True, timeout=5)
        except FileNotFoundError:
            if platform.system() == "Linux":
                hint = "Instalar con:\n  sudo apt install tshark\n\nO verificar con:  which tshark"
            elif platform.system() == "Darwin":
                hint = "Instalar con:\n  brew install wireshark"
            else:
                hint = "Descarga: https://www.wireshark.org/download.html"
            QMessageBox.critical(
                self, "tshark no encontrado",
                f"No se encontró tshark en: {self._tshark}\n\n{hint}"
            )

    def _set_status(self, msg):
        self._status_lbl.setText(msg)

    def _set_busy(self, busy):
        self._progress.setVisible(busy)
        self._act_open_analyze.setEnabled(not busy)

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
            if self._fig.axes:
                ax = self._fig.axes[0]
                self._apply_view_transforms(list(ax.get_xlim()), list(ax.get_ylim()))
                self._setup_cursor()
        elif m == "live":
            if self._live_timer is None:
                draw_empty(self._fig, "Captura en vivo no activa.\nUsa  Captura en vivo → Iniciar captura  (Ctrl+R).")
            elif self._live_signals:
                draw_overview(self._fig, self._live_signals, self._live_t0)
            else:
                draw_empty(self._fig, "Esperando paquetes...")
        self._ind_controls.setVisible(m in ("individual", "compare"))
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

    def _on_tree_context_menu(self, pos):
        item = self._tree.itemAt(pos)
        if item is None:
            return
        sid = item.data(0, Qt.ItemDataRole.UserRole)
        if sid is None:
            return
        menu = QMenu(self)
        fk = self._fav_key(sid)
        is_fav = fk in self._favorites
        act_fav    = menu.addAction("Quitar de favoritos ★" if is_fav else "Agregar a favoritos ★")
        menu.addSeparator()
        act_rename = menu.addAction("Renombrar señal...")
        act_note   = menu.addAction("Editar nota...")
        menu.addSeparator()
        act_frame  = menu.addAction("Ver trama...")
        act_csv    = menu.addAction("Exportar tramas a CSV...")
        menu.addSeparator()
        in_cmp  = sid in self._compare_ids
        act_cmp = menu.addAction("Quitar de comparacion" if in_cmp else "Agregar a comparacion")
        chosen = menu.exec(self._tree.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen == act_fav:
            self._toggle_favorite(sid)
        elif chosen == act_rename:
            self._rename_signal_dialog(sid)
        elif chosen == act_note:
            self._edit_note_dialog(sid)
        elif chosen == act_frame:
            self._show_frame_dialog(sid)
        elif chosen == act_csv:
            self._current_id = sid
            self._export_signal_csv()
        elif chosen == act_cmp:
            if in_cmp:
                self._compare_ids.remove(sid)
            else:
                self._compare_ids.append(sid)
            self._cmp_lbl.setText(f"Comparando: {len(self._compare_ids)} senal(es)")
            self._set_view("compare")

    @staticmethod
    def _frame_bytes_html(hex_str: str) -> str:
        """Devuelve HTML con los bytes de la trama coloreados por campo."""
        from .parser import _tcp_rec_size
        try:
            data = bytes.fromhex(hex_str.replace(' ', '').replace(':', ''))
        except ValueError:
            return f'<tt style="color:#f06060">{hex_str}</tt>'
        if not data:
            return ''

        BS = ('font-family:Consolas,monospace;font-size:10.5pt;'
              'padding:2px 5px;margin:1px;border-radius:3px;')

        def span(b, bg, fg):
            return (f'<span style="{BS}background:{bg};color:{fg}">'
                    f'{b:02X}</span>')

        parts = []

        # ── Protocol B (TCP) ──────────────────────────────────────────────
        if len(data) >= 12 and data[1:4] == b'\x00\x00\x00':
            rs = _tcp_rec_size(data, 0)
            if rs and len(data) >= rs:
                for i in range(4):
                    parts.append(span(data[i], '#161616', '#505050'))          # SYNC
                for i in range(4, 8):
                    parts.append(span(data[i], '#1a0830', '#b060e8'))          # SignalID
                for i in range(8, 10):
                    parts.append(span(data[i], '#001530', '#5090d8'))          # cat
                parts.append(span(data[10], '#001800', '#40c040'))             # data_len
                st_fg = '#e04040' if data[11] == 0x57 else '#f0a830'
                parts.append(span(data[11], '#1e1000', st_fg))                 # status
                for i in range(12, min(rs, len(data))):
                    parts.append(span(data[i], '#200a0a', '#e07060'))          # Value
                return ' '.join(parts)

        # ── Protocol A (UDP TLV single block) ─────────────────────────────
        if len(data) >= 8 and data[0] == 0x01 and data[2] >= 5:
            dlen       = data[2]
            block_size = 4 + ((dlen + 3) // 4) * 4
            if len(data) >= block_size:
                parts.append(span(data[0], '#1e1600', '#e8b830'))              # tipo
                parts.append(span(data[1], '#001530', '#5090d8'))              # cat
                parts.append(span(data[2], '#001800', '#40c040'))              # dlen
                parts.append(span(data[3], '#141414', '#383838'))              # pad
                for i in range(4, 8):
                    parts.append(span(data[i], '#1a0830', '#b060e8'))          # SignalID
                vsize = dlen - 4
                for i in range(8, 8 + vsize):
                    parts.append(span(data[i], '#200a0a', '#e07060'))          # Value
                for i in range(8 + vsize, block_size):
                    parts.append(span(data[i], '#141414', '#383838'))          # alineado
                return ' '.join(parts)

        # ── Desconocido ───────────────────────────────────────────────────
        for b in data:
            parts.append(span(b, '#1a1a1a', '#808080'))
        return ' '.join(parts)

    @staticmethod
    def _frame_legend_html(hex_str: str) -> str:
        """Leyenda de colores según el protocolo detectado."""
        from .parser import _tcp_rec_size
        try:
            data = bytes.fromhex(hex_str.replace(' ', '').replace(':', ''))
        except ValueError:
            return ''
        LS = 'font-size:8pt;padding:1px 6px;margin:1px;border-radius:3px;'

        def tag(label, bg, fg):
            return f'<span style="{LS}background:{bg};color:{fg}">{label}</span>'

        if len(data) >= 12 and data[1:4] == b'\x00\x00\x00':
            rs = _tcp_rec_size(data, 0)
            if rs:
                return ('&nbsp;'.join([
                    tag('SYNC', '#161616', '#505050'),
                    tag('SignalID', '#1a0830', '#b060e8'),
                    tag('cat', '#001530', '#5090d8'),
                    tag('data_len', '#001800', '#40c040'),
                    tag('status', '#1e1000', '#f0a830'),
                    tag('Value', '#200a0a', '#e07060'),
                ]) + '&nbsp;&nbsp;<span style="font-size:8pt;color:#505050">Protocolo B — TCP</span>')

        if len(data) >= 8 and data[0] == 0x01 and data[2] >= 5:
            return ('&nbsp;'.join([
                tag('tipo', '#1e1600', '#e8b830'),
                tag('cat', '#001530', '#5090d8'),
                tag('dlen', '#001800', '#40c040'),
                tag('pad', '#141414', '#505050'),
                tag('SignalID', '#1a0830', '#b060e8'),
                tag('Value', '#200a0a', '#e07060'),
            ]) + '&nbsp;&nbsp;<span style="font-size:8pt;color:#505050">Protocolo A — UDP TLV</span>')

        return ''

    def _show_frame_dialog(self, sid):
        from .parser import decode_frame_explanation
        if sid not in self._signals:
            return
        info     = self._signals[sid]
        payloads = info.get("payloads", [])
        if not payloads:
            QMessageBox.information(self, "Ver trama",
                                    "Esta señal no tiene tramas almacenadas.")
            return
        sig_id   = info["signal_id"]
        ts_list  = info["ts"]
        val_list = info["val"]

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Tramas — Señal 0x{sig_id:04X}  ({sig_id})")
        dlg.resize(760, 600)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(5)

        hdr = QLabel(
            f"<b>0x{sig_id:04X}</b>&nbsp;&nbsp;·&nbsp;&nbsp;"
            f"{info.get('transport','')}  "
            f"{info.get('ip_src','')} → {info.get('ip_dst','')}  "
            f"·  {len(payloads)} tramas"
        )
        hdr.setObjectName("subtext")
        hdr.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(hdr)

        # ── Lista de muestras ─────────────────────────────────────────────
        lst = QListWidget()
        lst.setFont(QFont("Consolas", 9))
        lst.setMaximumHeight(160)
        for i, (ts, val, raw) in enumerate(zip(ts_list, val_list, payloads)):
            t_rel   = ts - self._t0
            val_str = f"{val:.6g}" if info["is_float"] else str(val)
            n_bytes = len(raw.replace(" ", "")) // 2
            lst.addItem(
                f"[{i+1:4d}]  t=+{t_rel:10.3f}s   val={val_str:<14}  ({n_bytes} B)")
        lay.addWidget(lst)

        # ── Visualización de bytes coloreados ─────────────────────────────
        from PyQt6.QtWidgets import QTextEdit
        hex_view = QTextEdit()
        hex_view.setReadOnly(True)
        hex_view.setMaximumHeight(58)
        hex_view.setFont(QFont("Consolas", 10))
        hex_view.setStyleSheet(
            f"background:{C_INPUT};border:1px solid {C_BORDER};"
            "border-radius:4px;padding:4px;")
        lay.addWidget(hex_view)

        # ── Leyenda ───────────────────────────────────────────────────────
        legend_lbl = QLabel()
        legend_lbl.setTextFormat(Qt.TextFormat.RichText)
        legend_lbl.setContentsMargins(2, 0, 2, 2)
        lay.addWidget(legend_lbl)

        # ── Explicación texto ─────────────────────────────────────────────
        txt = QPlainTextEdit()
        txt.setReadOnly(True)
        txt.setFont(QFont("Consolas", 9))
        lay.addWidget(txt, 1)

        def on_select(row):
            if 0 <= row < len(payloads):
                raw = payloads[row]
                hex_view.setHtml(
                    f'<div style="margin:2px">{self._frame_bytes_html(raw)}</div>')
                legend_lbl.setText(self._frame_legend_html(raw))
                txt.setPlainText(decode_frame_explanation(raw))

        lst.currentRowChanged.connect(on_select)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)

        lst.setCurrentRow(0)
        dlg.exec()

    def _rename_signal_dialog(self, sid):
        fk = self._fav_key(sid)
        if fk not in self._favorites:
            self._favorites[fk] = {"name": "", "note": ""}
        current = self._favorites[fk].get("name", "")
        name, ok = QInputDialog.getText(
            self, "Renombrar señal", "Nombre:", text=current)
        if ok:
            self._favorites[fk]["name"] = name
            self._save_favorites()
            self._populate_tree()
            if sid == self._current_id:
                self._update_detail(sid)

    def _edit_note_dialog(self, sid):
        fk = self._fav_key(sid)
        if fk not in self._favorites:
            self._favorites[fk] = {"name": "", "note": ""}
        current = self._favorites[fk].get("note", "")
        note, ok = QInputDialog.getMultiLineText(
            self, "Editar nota", "Nota:", current)
        if ok:
            self._favorites[fk]["note"] = note
            self._save_favorites()
            self._populate_tree()
            if sid == self._current_id:
                self._update_detail(sid)

    def _update_detail(self, sid):
        if sid not in self._signals:
            return
        info   = self._signals[sid]
        int_id = info["signal_id"]
        fk     = self._fav_key(sid)
        name   = self._favorites.get(fk, {}).get("name", "")
        note   = self._favorites.get(fk, {}).get("note", "")
        lines = [
            f"ID:       0x{int_id:04X}  ({int_id})",
            f"Tipo:     {sig_type(info)}",
            f"Protocolo:{info.get('transport','')}",
            f"Origen:   {info.get('ip_src','')}",
            f"Destino:  {info.get('ip_dst','')}",
            f"N:        {info['n']} muestras",
            f"Min:      {info['min']:.5g}",
            f"Max:      {info['max']:.5g}",
            f"Sigma:    {info['std']:.4g}",
            f"Rango:    {info['range']:.4g}",
        ]
        if name:
            lines.insert(0, f"Nombre:   {name}")
        if note:
            lines.append(f"\nNota:\n{note}")
        self._detail.setPlainText('\n'.join(lines))
        gemelas = self._duplicates.get(sid, [])
        if gemelas:
            extra = ["\nSENALES IDENTICAS:"]
            for g in gemelas[:8]:
                extra.append(f"  0x{g[0]:04X}  {g[1]}  {g[2]}->{g[3]}")
            if len(gemelas) > 8:
                extra.append(f"  ... ({len(gemelas)-8} mas)")
            self._detail.appendPlainText('\n'.join(extra))

    def _populate_tree(self):
        self._tree.clear()
        if not self._signals:
            return
        search   = self._search.text().strip().lower()
        only_var = self._only_var.isChecked()
        proto_f  = self._proto_combo.currentText()
        src_f    = self._src_combo.currentText().strip()
        dst_f    = self._dst_combo.currentText().strip()
        if src_f in ("", "(todas)"):
            src_f = ""
        if dst_f in ("", "(todas)"):
            dst_f = ""
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
            if proto_f not in ("Todos", "") and proto != proto_f:
                continue
            if src_f and src != src_f:
                continue
            if dst_f and dst != dst_f:
                continue
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

    # ── Exportar / Importar nombres ───────────────────────────────────────────

    def _export_signal_csv(self):
        if self._current_id is None or self._current_id not in self._signals:
            QMessageBox.information(self, "Exportar CSV",
                                    "Selecciona una señal en la lista primero.")
            return
        info   = self._signals[self._current_id]
        sig_id = info["signal_id"]
        default_name = f"senal_0x{sig_id:04X}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Exportar tramas a CSV", default_name,
            "CSV (*.csv);;Todos (*.*)")
        if not path:
            return
        try:
            import csv
            payloads = info.get("payloads", [])
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "N", "timestamp_epoch", "tiempo_relativo_s",
                    "ip_src", "ip_dst", "transporte", "valor", "trama_hex",
                ])
                for i, (ts, val) in enumerate(zip(info["ts"], info["val"]), 1):
                    raw = payloads[i - 1] if i - 1 < len(payloads) else ""
                    writer.writerow([
                        i,
                        f"{ts:.6f}",
                        f"{ts - self._t0:.6f}",
                        info.get("ip_src", ""),
                        info.get("ip_dst", ""),
                        info.get("transport", ""),
                        val,
                        raw,
                    ])
            n = len(info["ts"])
            self._set_status(
                f"CSV exportado: señal 0x{sig_id:04X} — {n} tramas → {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error al exportar CSV", str(e))

    def _export_signals_visible_csv(self):
        """Exporta todas las señales visibles en el árbol (con los filtros actuales)."""
        if not self._signals:
            QMessageBox.information(self, "Exportar", "No hay señales. Analiza un PCAP primero.")
            return
        visible_keys = []
        for i in range(self._tree.topLevelItemCount()):
            sid = self._tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole)
            if sid is not None:
                visible_keys.append(sid)
        if not visible_keys:
            QMessageBox.information(self, "Exportar",
                                    "No hay señales visibles con los filtros actuales.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Exportar señales visibles a CSV",
            f"senales_{len(visible_keys)}.csv",
            "CSV (*.csv);;Todos (*.*)")
        if not path:
            return
        try:
            import csv
            rows = []
            for sid in visible_keys:
                info = self._signals[sid]
                payloads = info.get("payloads", [])
                for i, (ts, val) in enumerate(zip(info["ts"], info["val"])):
                    raw = payloads[i] if i < len(payloads) else ""
                    rows.append((ts, info["signal_id"], val, raw,
                                 info.get("ip_src", ""), info.get("ip_dst", ""),
                                 info.get("transport", "")))
            rows.sort(key=lambda r: r[0])
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "N", "signal_id", "timestamp_epoch", "tiempo_relativo_s",
                    "ip_src", "ip_dst", "transporte", "valor", "trama_hex",
                ])
                for n, (ts, sig_id, val, raw, ip_src, ip_dst, transport) in enumerate(rows, 1):
                    writer.writerow([
                        n, f"0x{sig_id:04X}",
                        f"{ts:.6f}", f"{ts - self._t0:.6f}",
                        ip_src, ip_dst, transport, val, raw,
                    ])
            self._set_status(
                f"CSV exportado: {len(visible_keys)} señales, {len(rows)} muestras → {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error al exportar CSV", str(e))

    def _export_packets_csv(self):
        """Exporta paquetes raw con filtro de protocolo e IP."""
        if not self._packets:
            QMessageBox.information(self, "Exportar",
                                    "No hay paquetes. Analiza un PCAP primero.")
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("Exportar paquetes a CSV")
        dlg.setMinimumWidth(320)
        dlg_lay = QVBoxLayout(dlg)
        form = QHBoxLayout()
        form.setSpacing(6)
        proto_c = QComboBox()
        proto_c.addItems(["Todos", "UDP", "TCP"])
        proto_c.setFixedWidth(72)
        form.addWidget(QLabel("Proto:"))
        form.addWidget(proto_c)
        form.addWidget(QLabel("Orig:"))
        src_e = QLineEdit()
        src_e.setPlaceholderText("vacío = todos")
        form.addWidget(src_e, 1)
        form.addWidget(QLabel("→"))
        dst_e = QLineEdit()
        dst_e.setPlaceholderText("vacío = todos")
        form.addWidget(dst_e, 1)
        dlg_lay.addLayout(form)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        dlg_lay.addWidget(btns)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        proto_f = proto_c.currentText()
        src_f   = src_e.text().strip()
        dst_f   = dst_e.text().strip()
        filtered = [p for p in self._packets
                    if (proto_f in ("Todos", "") or p.get("transport") == proto_f)
                    and (not src_f or p.get("ip_src") == src_f)
                    and (not dst_f or p.get("ip_dst") == dst_f)]
        if not filtered:
            QMessageBox.information(self, "Exportar",
                                    "Ningún paquete coincide con los filtros.")
            return
        parts = []
        if proto_f not in ("Todos", ""):
            parts.append(proto_f)
        if src_f:
            parts.append(f"src{src_f.replace('.', '_')}")
        if dst_f:
            parts.append(f"dst{dst_f.replace('.', '_')}")
        default_name = "paquetes" + ("_" + "_".join(parts) if parts else "") + ".csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Exportar paquetes a CSV", default_name,
            "CSV (*.csv);;Todos (*.*)")
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "N", "timestamp_epoch", "tiempo_relativo_s",
                    "ip_src", "ip_dst", "transporte",
                    "src_port", "dst_port", "payload_hex",
                ])
                for n, pkt in enumerate(filtered, 1):
                    ts = pkt.get("ts", 0.0)
                    writer.writerow([
                        n,
                        f"{ts:.6f}",
                        f"{ts - self._t0:.6f}",
                        pkt.get("ip_src", ""),
                        pkt.get("ip_dst", ""),
                        pkt.get("transport", ""),
                        pkt.get("src_port", ""),
                        pkt.get("dst_port", ""),
                        pkt.get("payload", ""),
                    ])
            self._set_status(f"CSV exportado: {len(filtered)} paquetes → {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error al exportar CSV", str(e))

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

    def _start_analyze(self, pcap: str):
        if not os.path.exists(pcap):
            QMessageBox.warning(self, "Atencion", "Archivo .pcap no encontrado.")
            return
        self._set_status("Extrayendo paquetes con tshark...")
        self._set_busy(True)
        self._thread = QThread()
        self._worker = AnalysisWorker(
            self._tshark, pcap, "Todos", "", ""
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

        self._packets    = pkts
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
        self._act_export_csv.setEnabled(True)
        self._act_export_visible.setEnabled(True)
        self._act_export_pkts.setEnabled(True)
        self._populate_tree()
        self._set_view("overview")

    def _on_error(self, msg):
        self._set_status(f"Error: {msg}")
        QMessageBox.critical(self, "Error en analisis", msg)
