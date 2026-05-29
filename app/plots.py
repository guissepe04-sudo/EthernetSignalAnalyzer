
import math 
import numpy as np 
from matplotlib .lines import Line2D 

from .styles import (C_BG ,C_CARD ,C_SURF ,C_TEXT ,C_SUB ,C_HDR ,
C_BORDER ,C_GRID ,PLOT_COLORS )
from .analysis import sig_type ,is_digital 




def _style_fig (fig ):
    fig .patch .set_facecolor (C_BG )


def _style_ax (ax ):
    ax .set_facecolor (C_SURF )
    ax .tick_params (colors =C_HDR ,labelsize =8 )
    ax .xaxis .label .set_color (C_HDR )
    ax .yaxis .label .set_color (C_HDR )
    ax .title .set_color (C_TEXT )
    for sp in ax .spines .values ():
        sp .set_edgecolor (C_BORDER )
    ax .spines ["top"].set_visible (False )
    ax .spines ["right"].set_visible (False )


def _prep (info :dict ,t0 :float ):
    """Devuelve (ts_sorted, va_sorted) normalizados a t0."""
    ts =np .array (info ["ts"])-t0 
    va =np .array (info ["val"],dtype =float )
    order =np .argsort (ts )
    return ts [order ],va [order ]


def _plot_signal_on_ax (ax ,ts ,va ,info ,color ,lw =1.8 ):
    """Dibuja una señal en el eje dado con fill y línea media."""
    mean_val =float (np .mean (va ))
    if is_digital (info ):
        ax .step (ts ,va ,where ="post",color =color ,lw =lw ,alpha =0.9 )
        ax .fill_between (ts ,va ,step ="post",alpha =0.18 ,color =color )
        ax .set_yticks (sorted (set (va .astype (int ))))
    else :
        if info ["std"]>0 :
            ax .fill_between (ts ,mean_val -info ["std"],mean_val +info ["std"],
            alpha =0.06 ,color =color )
        ax .fill_between (ts ,va ,float (va .min ()),alpha =0.12 ,color =color )
        ax .plot (ts ,va ,"-",lw =lw ,color =color ,alpha =0.9 )
        ax .axhline (mean_val ,color =color ,lw =0.9 ,ls ="--",alpha =0.45 )




def draw_empty (fig ,msg ="Sin datos. Carga un .pcap y presiona ANALIZAR."):
    fig .clear ()
    _style_fig (fig )
    ax =fig .add_subplot (111 )
    ax .set_facecolor (C_BG )
    ax .text (0.5 ,0.5 ,msg ,ha ="center",va ="center",
    fontsize =13 ,color =C_SUB ,transform =ax .transAxes ,style ="italic")
    ax .axis ("off")


def draw_individual (fig ,sig_id :int ,info :dict ,t0 :float =0.0 ):
    """
    Dibuja la señal con datos crudos y devuelve (xlim, ylim) naturales.
    Los controles de escala/periodo/offset se aplican sobre los ejes en window.py.
    """
    fig .clear ()
    _style_fig (fig )
    ax =fig .add_subplot (111 )
    _style_ax (ax )

    ts ,va =_prep (info ,t0 )
    color =C_TEXT 
    ftype =sig_type (info )
    transport =info .get ("transport","")
    ip_src =info .get ("ip_src","")
    ip_dst =info .get ("ip_dst","")
    mean_val =float (np .mean (va ))

    if is_digital (info ):
        ax .step (ts ,va ,where ="post",color =color ,lw =2.2 ,alpha =0.9 )
        ax .fill_between (ts ,va ,step ="post",alpha =0.14 ,color =color )
        ax .set_yticks (sorted (set (va .astype (int ))))
        ax .set_ylim (-0.1 ,float (va .max ())+0.3 )

        ax .axhline (mean_val ,color ="#88aaff",lw =0.9 ,ls ="--",alpha =0.55 )
    else :

        if info ["std"]>0 :
            ax .fill_between (ts ,mean_val -info ["std"],mean_val +info ["std"],
            alpha =0.07 ,color ="#4488ff",
            label =f"±1σ  ({mean_val -info ['std']:.4g} – {mean_val +info ['std']:.4g})")
        ax .plot (ts ,va ,"-",lw =1.7 ,color =color ,alpha =0.9 )
        ax .plot (ts ,va ,"o",ms =3.2 ,color =color ,alpha =0.35 ,markeredgewidth =0 )

        if len (va )>=4 :
            try :
                p1 ,p99 =np .percentile (va ,[1 ,99 ])
                pad =max ((p99 -p1 )*0.25 ,1.0 )
                if np .isfinite (p1 )and np .isfinite (p99 )and np .isfinite (pad ):
                    ax .set_ylim (p1 -pad ,p99 +pad )
            except Exception :
                pass 

        ax .axhline (mean_val ,color ="#88aaff",lw =1.0 ,ls ="--",alpha =0.65 )
        ax .text (ts [-1 ]if len (ts )>0 else 0 ,mean_val ,
        f"  μ={mean_val :.4g}",va ="center",fontsize =8 ,
        color ="#88aaff",alpha =0.85 ,clip_on =True )

        ax .axhline (info ["min"],color ="#5577cc",lw =0.7 ,ls =":",alpha =0.5 )
        ax .axhline (info ["max"],color ="#cc5555",lw =0.7 ,ls =":",alpha =0.5 )


    if len (ts )>=1 :
        ax .plot (ts [0 ],va [0 ],"D",ms =6 ,color ="#55aaff",zorder =12 ,
        markeredgecolor =C_SURF ,markeredgewidth =1.2 ,alpha =0.9 )
    if len (ts )>=2 :
        ax .plot (ts [-1 ],va [-1 ],"D",ms =6 ,color ="#ff9944",zorder =12 ,
        markeredgecolor =C_SURF ,markeredgewidth =1.2 ,alpha =0.9 )

    ax .set_title (
    f"Senal  0x{sig_id :04X}  ({sig_id })   [{ftype }]   "
    f"{transport }  {ip_src } -> {ip_dst }",
    fontsize =11 ,fontweight ="bold",color =C_TEXT ,pad =14 
    )
    stats =(f"N = {info ['n']} muestras\n"
    f"Min  =  {info ['min']:.5g}\n"
    f"Max  =  {info ['max']:.5g}\n"
    f"μ    =  {mean_val :.5g}\n"
    f"σ    =  {info ['std']:.4g}\n"
    f"Rango=  {info ['range']:.4g}")
    ax .text (0.015 ,0.975 ,stats ,transform =ax .transAxes ,
    fontsize =10.5 ,va ="top",ha ="left",family ="monospace",color =C_HDR ,
    bbox =dict (boxstyle ="round,pad=0.6",facecolor =C_CARD ,
    edgecolor =C_BORDER ,linewidth =1.5 ,alpha =0.95 ))
    ax .set_xlabel ("Tiempo (s)",fontsize =11 )
    ax .set_ylabel ("Valor",fontsize =11 )
    ax .grid (True ,alpha =0.22 ,linestyle ="--",color =C_GRID )
    fig .tight_layout (pad =2.5 )
    return list (ax .get_xlim ()),list (ax .get_ylim ())


def draw_overview (fig ,signals :dict ,t0 :float =0.0 ,
only_varying :bool =False ,max_n :int =20 ):
    """Cuadrícula con las señales más activas."""
    fig .clear ()
    _style_fig (fig )
    pool ={k :v for k ,v in signals .items ()
    if not only_varying or v ["range"]>0 }
    if not pool :
        draw_empty (fig ,"Sin senales. Desactiva 'solo variantes' o recarga.")
        return 

    ids =sorted (pool ,key =lambda s :pool [s ]["range"]+pool [s ]["std"],reverse =True )[:max_n ]
    n =len (ids )
    cols =min (4 ,n )
    rows =math .ceil (n /cols )
    for idx ,sid in enumerate (ids ):
        info =pool [sid ]
        ax =fig .add_subplot (rows ,cols ,idx +1 )
        _style_ax (ax )
        ts ,va =_prep (info ,t0 )
        color =PLOT_COLORS [idx %len (PLOT_COLORS )]
        if is_digital (info ):
            ax .step (ts ,va ,where ="post",color =color ,lw =1.1 )
            ax .fill_between (ts ,va ,step ="post",alpha =0.25 ,color =color )
        else :
            mean_v =float (np .mean (va ))
            ax .plot (ts ,va ,"-",lw =0.9 ,color =color )
            ax .axhline (mean_v ,color =color ,lw =0.6 ,ls ="--",alpha =0.4 )

            if len (va )>=4 :
                p2 ,p98 =np .percentile (va ,[2 ,98 ])
                pad =max ((p98 -p2 )*0.25 ,1.0 )
                ax .set_ylim (p2 -pad ,p98 +pad )
        proto =info .get ("transport","")
        ax .set_title (
        f"0x{info ['signal_id']:04X}  [{sig_type (info )}]  {proto }\n"
        f"max={info ['max']:.4g}  σ={info ['std']:.3g}",
        fontsize =7 ,pad =3 ,color =C_HDR 
        )
        ax .tick_params (labelsize =6 ,pad =1 ,colors =C_SUB )
        ax .grid (True ,alpha =0.18 ,linewidth =0.5 ,color =C_GRID )

    for idx in range (n ,rows *cols ):
        fig .add_subplot (rows ,cols ,idx +1 ).set_visible (False )
    fig .tight_layout (pad =1.2 ,h_pad =2.0 ,w_pad =1.0 )
    fig .suptitle (
    f"Panoramica — {n } senales principales  (clic en la lista para ver en detalle)",
    fontsize =10 ,fontweight ="bold",color =C_HDR 
    )
    fig .tight_layout (rect =[0 ,0 ,1 ,0.96 ])


def draw_compare (fig ,sel_ids :list ,signals :dict ,t0 :float =0.0 ):
    """
    Compara señales seleccionadas:
      n=1 → individual con caja de stats
      n=2 → doble eje Y con valores reales (twinx)
      n≥3 → superposición normalizada 0-1 con marcadores de último valor
    """
    fig .clear ()
    _style_fig (fig )
    valid =[s for s in sel_ids if s in signals ]
    if not valid :
        draw_empty (fig ,"Ctrl + clic en senales de la lista para compararlas.")
        return 

    n =len (valid )


    if n ==1 :
        sid =valid [0 ]
        info =signals [sid ]
        ts ,va =_prep (info ,t0 )
        color =PLOT_COLORS [0 ]
        mean_val =float (np .mean (va ))
        ax =fig .add_subplot (111 )
        _style_ax (ax )
        _plot_signal_on_ax (ax ,ts ,va ,info ,color ,lw =2.0 )
        if len (ts )>=1 :
            ax .plot (ts [0 ],va [0 ],"D",ms =6 ,color ="#55aaff",zorder =12 ,
            markeredgecolor =C_SURF ,markeredgewidth =1.2 )
        if len (ts )>=2 :
            ax .plot (ts [-1 ],va [-1 ],"D",ms =6 ,color ="#ff9944",zorder =12 ,
            markeredgecolor =C_SURF ,markeredgewidth =1.2 )
        stats =(f"N = {info ['n']}\n"
        f"Min  = {info ['min']:.5g}\n"
        f"Max  = {info ['max']:.5g}\n"
        f"μ    = {mean_val :.5g}\n"
        f"σ    = {info ['std']:.4g}")
        ax .text (0.015 ,0.975 ,stats ,transform =ax .transAxes ,
        fontsize =10 ,va ="top",ha ="left",family ="monospace",color =C_HDR ,
        bbox =dict (boxstyle ="round,pad=0.5",facecolor =C_CARD ,
        edgecolor =C_BORDER ,linewidth =1.3 ,alpha =0.95 ))
        ax .set_xlabel ("Tiempo (s)",fontsize =11 )
        ax .set_ylabel ("Valor",fontsize =11 )
        ax .grid (True ,alpha =0.22 ,linestyle ="--",color =C_GRID )
        fig .suptitle (f"0x{info ['signal_id']:04X}  [{sig_type (info )}]  "
        f"{info .get ('transport','')}  "
        f"{info .get ('ip_src','')} → {info .get ('ip_dst','')}",
        fontsize =11 ,fontweight ="bold",color =C_TEXT )
        fig .tight_layout (pad =2.5 )
        return 


    if n ==2 :
        sid0 ,sid1 =valid [0 ],valid [1 ]
        info0 ,info1 =signals [sid0 ],signals [sid1 ]
        ts0 ,va0 =_prep (info0 ,t0 )
        ts1 ,va1 =_prep (info1 ,t0 )
        c0 ,c1 =PLOT_COLORS [0 ],PLOT_COLORS [1 ]

        ax1 =fig .add_subplot (111 )
        _style_ax (ax1 )


        _plot_signal_on_ax (ax1 ,ts0 ,va0 ,info0 ,c0 ,lw =2.0 )
        if len (ts0 )>=2 :
            ax1 .plot (ts0 [-1 ],va0 [-1 ],"D",ms =7 ,color =c0 ,zorder =12 ,
            markeredgecolor =C_SURF ,markeredgewidth =1.2 )
        ax1 .set_ylabel (
        f"0x{info0 ['signal_id']:04X}  [{sig_type (info0 )}]  "
        f"({info0 ['min']:.4g} – {info0 ['max']:.4g})",
        color =c0 ,fontsize =10 
        )
        ax1 .tick_params (axis ="y",colors =c0 ,labelsize =8 )
        ax1 .spines ["left"].set_edgecolor (c0 )
        ax1 .spines ["left"].set_linewidth (1.5 )


        ax2 =ax1 .twinx ()
        ax2 .set_facecolor ("none")
        ax2 .tick_params (colors =C_HDR ,labelsize =8 )
        for sp in ax2 .spines .values ():
            sp .set_edgecolor (C_BORDER )
        ax2 .spines ["top"].set_visible (False )
        ax2 .spines ["left"].set_visible (False )
        ax2 .spines ["right"].set_edgecolor (c1 )
        ax2 .spines ["right"].set_linewidth (1.5 )

        _plot_signal_on_ax (ax2 ,ts1 ,va1 ,info1 ,c1 ,lw =2.0 )
        if len (ts1 )>=2 :
            ax2 .plot (ts1 [-1 ],va1 [-1 ],"D",ms =7 ,color =c1 ,zorder =12 ,
            markeredgecolor =C_SURF ,markeredgewidth =1.2 )
        ax2 .set_ylabel (
        f"0x{info1 ['signal_id']:04X}  [{sig_type (info1 )}]  "
        f"({info1 ['min']:.4g} – {info1 ['max']:.4g})",
        color =c1 ,fontsize =10 
        )
        ax2 .tick_params (axis ="y",colors =c1 ,labelsize =8 )


        handles =[
        Line2D ([0 ],[0 ],color =c0 ,lw =2 ,
        label =f"0x{info0 ['signal_id']:04X}  [{sig_type (info0 )}]  "
        f"μ={np .mean (va0 ):.4g}  σ={info0 ['std']:.3g}"),
        Line2D ([0 ],[0 ],color =c1 ,lw =2 ,
        label =f"0x{info1 ['signal_id']:04X}  [{sig_type (info1 )}]  "
        f"μ={np .mean (va1 ):.4g}  σ={info1 ['std']:.3g}"),
        ]
        leg =ax1 .legend (handles =handles ,fontsize =9 ,loc ="upper left")
        leg .get_frame ().set_facecolor (C_CARD )
        leg .get_frame ().set_edgecolor (C_BORDER )
        for t in leg .get_texts ():
            t .set_color (C_TEXT )

        ax1 .set_xlabel ("Tiempo (s)",fontsize =11 )
        ax1 .grid (True ,alpha =0.18 ,linestyle ="--",color =C_GRID )
        fig .suptitle ("Comparacion — 2 senales  (escala real, doble eje Y)",
        fontsize =11 ,fontweight ="bold",color =C_TEXT )
        fig .tight_layout (pad =2 )
        return 


    ax =fig .add_subplot (111 )
    _style_ax (ax )

    for i ,sid in enumerate (valid ):
        info =signals [sid ]
        ts ,va =_prep (info ,t0 )
        color =PLOT_COLORS [i %len (PLOT_COLORS )]
        rng =info ["range"]or 1 
        va_n =(va -info ["min"])/rng 
        mean_n =float (np .mean (va_n ))
        label =(f"0x{info ['signal_id']:04X}  [{sig_type (info )}]  "
        f"({info ['min']:.4g} – {info ['max']:.4g})  "
        f"σ={info ['std']:.3g}")
        if is_digital (info ):
            ax .step (ts ,va_n ,where ="post",color =color ,lw =2 ,alpha =0.9 ,label =label )
            ax .fill_between (ts ,va_n ,step ="post",alpha =0.12 ,color =color )
        else :
            ax .fill_between (ts ,va_n ,alpha =0.07 ,color =color )
            ax .plot (ts ,va_n ,"-",lw =1.8 ,color =color ,alpha =0.9 ,label =label )
            ax .axhline (mean_n ,color =color ,lw =0.7 ,ls ="--",alpha =0.35 )

        if len (ts )>=1 :
            ax .plot (ts [-1 ],va_n [-1 ],"o",ms =7 ,color =color ,zorder =10 ,
            markeredgecolor =C_SURF ,markeredgewidth =1.2 )

    leg =ax .legend (fontsize =9 ,loc ="upper left",framealpha =0.95 )
    leg .get_frame ().set_facecolor (C_CARD )
    leg .get_frame ().set_edgecolor (C_BORDER )
    for t in leg .get_texts ():
        t .set_color (C_TEXT )

    ax .set_ylabel ("Valor normalizado (0 – 1)",fontsize =11 )
    ax .set_xlabel ("Tiempo (s)",fontsize =11 )
    ax .set_ylim (-0.05 ,1.10 )
    ax .grid (True ,alpha =0.2 ,linestyle ="--",color =C_GRID )
    fig .suptitle (f"Comparacion — {n } senales superpuestas (normalizadas 0-1)",
    fontsize =11 ,fontweight ="bold",color =C_TEXT )
    fig .tight_layout (pad =2 )


def draw_live (fig ,ts :list ,vals :list ,signal_id :int ,t0 :float =0.0 ):
    fig .clear ()
    _style_fig (fig )
    ax =fig .add_subplot (111 )
    _style_ax (ax )
    if not ts :
        ax .text (0.5 ,0.5 ,
        "Esperando datos...\nInicia la captura y espera paquetes de la senal.",
        ha ="center",va ="center",fontsize =13 ,color =C_SUB ,
        transform =ax .transAxes ,style ="italic")
        ax .axis ("off")
        return 
    t_arr =np .array (ts )-t0 
    v_arr =np .array (vals ,dtype =float )

    cut =max (0 ,len (t_arr )-60 )
    if cut >0 :
        ax .plot (t_arr [:cut +1 ],v_arr [:cut +1 ],"-",lw =1.2 ,color =C_SUB ,alpha =0.5 )
    ax .fill_between (t_arr [cut :],v_arr [cut :],float (v_arr [cut :].min ()),alpha =0.12 ,color =C_TEXT )
    ax .plot (t_arr [cut :],v_arr [cut :],"-",lw =1.8 ,color =C_TEXT ,alpha =0.9 )
    ax .plot (t_arr [-1 :],v_arr [-1 :],"o",ms =9 ,color ="#ff6b6b",zorder =10 ,
    markeredgecolor =C_SURF ,markeredgewidth =1.5 )
    mean_v =float (np .mean (v_arr ))
    ax .axhline (mean_v ,color ="#88aaff",lw =0.8 ,ls ="--",alpha =0.5 )
    ax .set_title (
    f"EN VIVO — Senal 0x{signal_id :04X} ({signal_id })   N={len (ts )}",
    fontsize =11 ,fontweight ="bold",color =C_TEXT ,pad =14 
    )
    ax .set_xlabel ("Tiempo (s)",fontsize =11 )
    ax .set_ylabel ("Valor",fontsize =11 )
    ax .grid (True ,alpha =0.25 ,linestyle ="--",color =C_GRID )
    fig .tight_layout (pad =2.5 )
