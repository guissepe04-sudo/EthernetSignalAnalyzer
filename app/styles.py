

C_BG ="#0d0d0d"
C_CARD ="#161616"
C_SURF ="#111111"
C_INPUT ="#0a0a0a"
C_TEXT ="#e2e2e2"
C_SUB ="#505050"
C_HDR ="#b0b0b0"
C_BORDER ="#252525"
C_GRID ="#1c1c1c"
C_SEL ="#2a2a2a"
C_BTN ="#1e1e1e"


PLOT_COLORS =[
"#d4d4d4","#8ab4e8","#8ed0a0","#e0c878",
"#e09090","#b8a0d8","#80c8c0","#e0aa80",
"#c8c8c8","#708cb8","#70b870","#c8a840",
]


TYPE_STYLE ={
"float":{"bg":"#161616","fg":"#c8c8c8"},
"int":{"bg":"#121212","fg":"#888888"},
}


QSS =f"""
* {{ font-family: 'Segoe UI'; font-size: 9pt; color: {C_TEXT }; }}

QMainWindow, QWidget {{ background-color: {C_BG }; }}

QFrame#card {{
    background-color: {C_CARD };
    border: 1px solid {C_BORDER };
    border-radius: 7px;
}}
QFrame#topbar {{
    background-color: {C_CARD };
    border: 1px solid {C_BORDER };
    border-radius: 7px;
}}
QSplitter::handle {{ background-color: {C_BORDER }; }}
QSplitter::handle:horizontal {{ width: 2px; }}

QPushButton {{
    background-color: {C_BTN };
    color: {C_TEXT };
    border: 1px solid {C_BORDER };
    border-radius: 5px;
    padding: 5px 14px;
}}
QPushButton:hover   {{ background-color: #282828; border-color: #3a3a3a; }}
QPushButton:pressed {{ background-color: {C_SEL }; }}
QPushButton:disabled {{ color: {C_SUB }; background-color: {C_INPUT }; }}

QPushButton#accent {{
    background-color: {C_TEXT };
    color: {C_BG };
    border: none;
    border-radius: 5px;
    font-weight: bold;
    padding: 6px 20px;
}}
QPushButton#accent:hover    {{ background-color: #ffffff; }}
QPushButton#accent:disabled {{ background-color: #2a2a2a; color: {C_SUB }; }}

QPushButton#view {{
    background-color: {C_BTN };
    color: {C_SUB };
    border: 1px solid {C_BORDER };
    border-radius: 5px;
    padding: 5px 16px;
    font-weight: bold;
}}
QPushButton#view:hover   {{ background-color: #222222; color: {C_HDR }; }}
QPushButton#view:checked {{
    background-color: #2e2e2e;
    color: {C_TEXT };
    border: 1px solid #4a4a4a;
}}

QLineEdit {{
    background-color: {C_INPUT };
    color: {C_TEXT };
    border: 1px solid {C_BORDER };
    border-radius: 5px;
    padding: 4px 8px;
    selection-background-color: {C_SEL };
}}
QLineEdit:focus {{ border: 1px solid #4a4a4a; }}

QComboBox {{
    background-color: {C_INPUT };
    color: {C_TEXT };
    border: 1px solid {C_BORDER };
    border-radius: 5px;
    padding: 4px 8px;
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background-color: {C_CARD };
    color: {C_TEXT };
    selection-background-color: {C_SEL };
    border: 1px solid {C_BORDER };
}}

QCheckBox {{ color: {C_TEXT }; spacing: 6px; }}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    background-color: {C_INPUT };
    border: 1px solid {C_BORDER };
    border-radius: 3px;
}}
QCheckBox::indicator:checked {{
    background-color: {C_HDR };
    border-color: {C_HDR };
}}

QTreeWidget {{
    background-color: {C_BG };
    alternate-background-color: #111111;
    color: {C_TEXT };
    border: 1px solid {C_BORDER };
    border-radius: 5px;
    outline: 0;
}}
QTreeWidget::item {{ padding: 3px 2px; border: none; }}
QTreeWidget::item:selected {{ background-color: {C_SEL }; color: {C_TEXT }; }}
QTreeWidget::item:hover     {{ background-color: #1a1a1a; }}
QHeaderView::section {{
    background-color: {C_SURF };
    color: {C_HDR };
    padding: 5px 4px;
    border: none;
    border-right: 1px solid {C_BORDER };
    border-bottom: 1px solid {C_BORDER };
    font-weight: bold;
}}

QScrollBar:vertical {{
    background: {C_BG }; width: 7px; margin: 0; border-radius: 3px;
}}
QScrollBar::handle:vertical {{
    background: #2e2e2e; border-radius: 3px; min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{ background: #3a3a3a; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {C_BG }; height: 7px; margin: 0; border-radius: 3px;
}}
QScrollBar::handle:horizontal {{
    background: #2e2e2e; border-radius: 3px; min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{ background: #3a3a3a; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

QPlainTextEdit {{
    background-color: {C_INPUT };
    color: {C_TEXT };
    border: 1px solid {C_BORDER };
    border-radius: 5px;
    font-family: Consolas;
    font-size: 9pt;
    selection-background-color: {C_SEL };
}}

QStatusBar {{
    background-color: {C_INPUT };
    color: {C_SUB };
    border-top: 1px solid {C_BORDER };
    font-size: 8pt;
}}
QProgressBar {{
    background-color: {C_INPUT };
    border: 1px solid {C_BORDER };
    border-radius: 3px;
    height: 6px;
    text-align: center;
}}
QProgressBar::chunk {{ background-color: {C_HDR }; border-radius: 3px; }}

QLabel#header {{
    color: {C_HDR };
    font-weight: bold;
    font-size: 10pt;
}}
QLabel#subtext {{
    color: {C_SUB };
    font-size: 8pt;
    font-style: italic;
}}
QToolBar {{
    background-color: {C_SURF };
    border: none;
    spacing: 2px;
    padding: 2px;
}}
QToolBar QToolButton {{
    background-color: transparent;
    color: {C_HDR };
    border: none;
    padding: 3px;
    border-radius: 4px;
}}
QToolBar QToolButton:hover {{ background-color: {C_SEL }; }}
"""
