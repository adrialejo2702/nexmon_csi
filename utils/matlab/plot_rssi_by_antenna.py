"""plot_rssi_by_antenna.py

Script para leer un PCAP con formato de cabecera extendida (PR #256) y
plotear la evolución temporal del RSSI, separando por antena/core en una
única figura (una curva por antena).

Uso (ejemplo):
    python plot_rssi_by_antenna.py
"""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt
from matplotlib.widgets import CheckButtons
import numpy as np

from readpcap import ReadPcap
from csireader_master import _parse_csi_udp_header, ACCEPTED_CHIP_IDS


def collect_rssi_by_antenna(
    file_path: str,
    npkts_max: int = 50000,
) -> Dict[str, object]:
    """Lee un PCAP y agrupa el RSSI por antena/core.

    Devuelve un diccionario con:
        - packets_info: lista de headers válidos (uno por paquete CSI)
        - core_indices: dict core -> lista de índices de paquete
        - core_rssi: dict core -> lista de RSSI (dBm)
    """

    reader = ReadPcap()
    reader.open(file_path)

    frames = reader.all()
    limit = min(len(frames), npkts_max)

    reader.from_start()

    packets_info: List[dict] = []
    core_indices: Dict[int, List[int]] = {}
    core_rssi: Dict[int, List[int]] = {}

    processed = 0
    skipped = 0
    invalid_magic = 0

    while processed < limit:
        frame = reader.next()
        if frame is None:
            break

        payload = frame["payload"]

        try:
            # Usamos el mismo parser especializado que en `csireader_master.py`
            header, valid, header_offset = _parse_csi_udp_header(payload)
        except Exception:
            skipped += 1
            continue

        if not valid:
            invalid_magic += 1
            skipped += 1
            continue

        # Nos aseguramos de quedarnos sólo con paquetes del chip esperado (bcm4366c0)
        if header.get("chip_version") not in ACCEPTED_CHIP_IDS:
            skipped += 1
            continue

        # Extraer datos relevantes
        rssi = int(header.get("rssi", 0))
        core = int(header.get("core", -1))

        # Índice de este paquete dentro de la secuencia válida
        pkt_idx = len(packets_info)
        packets_info.append(header)

        if core not in core_indices:
            core_indices[core] = []
            core_rssi[core] = []

        core_indices[core].append(pkt_idx)
        core_rssi[core].append(rssi)

        processed += 1

    reader.close()

    print("\n========= RESUMEN RSSI =========")
    print(f"Archivo PCAP           : {file_path}")
    print(f"Total paquetes en PCAP : {len(frames)}")
    print(f"Procesados (válidos)   : {len(packets_info)}")
    print(f"Saltados               : {skipped}")
    print(f"Invalid magic (0x1111) : {invalid_magic}")

    # Estadísticas básicas por core
    for core, rssi_list in sorted(core_rssi.items()):
        if not rssi_list or core < 0:
            continue
        arr = np.asarray(rssi_list, dtype=float)
        print(
            f"Core {core}: N={len(arr):5d}  RSSI[min, max, mean, std] = "
            f"[{arr.min():5.1f}, {arr.max():5.1f}, {arr.mean():6.2f}, {arr.std():6.2f}] dBm"
        )

    return {
        "packets_info": packets_info,
        "core_indices": core_indices,
        "core_rssi": core_rssi,
    }


def plot_rssi_by_antenna(
    packets_info: List[dict],
    core_indices: Dict[int, List[int]],
    core_rssi: Dict[int, List[int]],
    title: str = "RSSI por antena (core)",
    save_path: str | None = None,
    show: bool = True,
    interactive: bool = True,
) -> None:
    """Genera una única figura con el RSSI temporal para cada antena/core.

    Similar a la distribución del mapa de calor: cada core tiene su propia
    secuencia temporal (1, 2, 3, ...) independiente del índice global del paquete.
    
    - Eje X: número de paquete dentro de la secuencia de cada core (1, 2, 3, ...)
    - Eje Y: RSSI en dBm.
    - Una curva por core, con color distinto.
    - Si interactive=True, incluye checkboxes para mostrar/ocultar cada core.
    """

    if not packets_info:
        print("No hay paquetes válidos para plotear RSSI.")
        return

    if interactive:
        _plot_rssi_interactive(packets_info, core_indices, core_rssi, title, save_path, show)
    else:
        _plot_rssi_static(packets_info, core_indices, core_rssi, title, save_path, show)


def _plot_rssi_static(
    packets_info: List[dict],
    core_indices: Dict[int, List[int]],
    core_rssi: Dict[int, List[int]],
    title: str,
    save_path: str | None,
    show: bool,
) -> None:
    """Versión estática de la gráfica RSSI (sin interactividad)."""
    print(f"Generando gráfica temporal de RSSI agrupada por core...")

    # Paleta de colores profesional
    colors_map = {
        0: '#1f77b4',  # Azul profundo
        1: '#ff7f0e',  # Naranja vibrante
        2: '#2ca02c',  # Verde brillante
        3: '#d62728',  # Rojo intenso
        4: '#9467bd',  # Púrpura
        5: '#8c564b',  # Marrón
    }
    
    # Aplicar estilo moderno
    plt.style.use('seaborn-v0_8-darkgrid')
    
    fig, ax = plt.subplots(figsize=(14, 7), facecolor='#f8f9fa')
    ax.set_facecolor('#ffffff')

    max_packets_per_core = 0
    
    for idx, (core, indices) in enumerate(sorted(core_indices.items())):
        if core < 0 or not indices:
            continue

        rssi_vals = core_rssi.get(core, [])
        if not rssi_vals:
            continue

        x_local = np.arange(1, len(rssi_vals) + 1, dtype=int)
        y = np.asarray(rssi_vals, dtype=float)
        
        max_packets_per_core = max(max_packets_per_core, len(rssi_vals))

        color = colors_map.get(core, colors_map[idx % len(colors_map)])
        ax.plot(x_local, y, 
                marker="o", 
                linestyle="-", 
                linewidth=2.0, 
                markersize=4,
                label=f"Antena {core} (N={len(rssi_vals):,})", 
                color=color,
                alpha=0.85,
                markeredgewidth=0.5,
                markeredgecolor='white')

    ax.set_xlabel("Número de Paquete (secuencia por antena)", 
                  fontsize=12, fontweight='bold', color='#2c3e50')
    ax.set_ylabel("RSSI (dBm)", 
                  fontsize=12, fontweight='bold', color='#2c3e50')
    ax.set_title(title, 
                 fontsize=14, fontweight='bold', color='#2c3e50', pad=20)
    
    ax.grid(True, alpha=0.25, linestyle='--', linewidth=0.8, color='#bdc3c7')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#95a5a6')
    ax.spines['bottom'].set_color('#95a5a6')
    
    legend = ax.legend(title="Antenas / Cores", 
                       loc='upper right', 
                       frameon=True,
                       fancybox=True,
                       shadow=True,
                       fontsize=10,
                       title_fontsize=11)
    legend.get_frame().set_facecolor('#ffffff')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#bdc3c7')

    if max_packets_per_core > 0:
        ax.set_xlim(0, max_packets_per_core + 1)
    
    # Ajustar límites del eje Y
    all_rssi = [rssi for rssi_list in core_rssi.values() for rssi in rssi_list]
    if all_rssi:
        rssi_min, rssi_max = min(all_rssi), max(all_rssi)
        ax.set_ylim(rssi_min - 2, rssi_max + 2)

    fig.tight_layout(rect=[0, 0, 1, 0.98])

    if save_path is not None:
        out_dir = os.path.dirname(save_path)
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        fig.savefig(save_path, dpi=200, facecolor='#f8f9fa', edgecolor='none', bbox_inches='tight')
        print(f"Figura RSSI guardada en: {save_path}")

    if show:
        plt.show(block=True)
    else:
        plt.close(fig)


def _plot_rssi_interactive(
    packets_info: List[dict],
    core_indices: Dict[int, List[int]],
    core_rssi: Dict[int, List[int]],
    title: str,
    save_path: str | None,
    show: bool,
) -> None:
    """Versión interactiva de la gráfica RSSI con checkboxes para seleccionar cores."""
    print(f"Generando gráfica interactiva de RSSI con checkboxes...")

    # Preparar datos de cores válidos
    valid_cores = sorted([c for c in core_indices.keys() if c >= 0 and core_rssi.get(c)])
    if not valid_cores:
        print("No hay cores válidos para visualizar.")
        return

    # Paleta de colores más profesional y diferenciada
    colors_map = {
        0: '#1f77b4',  # Azul profundo
        1: '#ff7f0e',  # Naranja vibrante
        2: '#2ca02c',  # Verde brillante
        3: '#d62728',  # Rojo intenso
        4: '#9467bd',  # Púrpura
        5: '#8c564b',  # Marrón
    }
    
    # Aplicar estilo moderno
    plt.style.use('seaborn-v0_8-darkgrid')
    
    # Crear figura con espacio para checkboxes y fondo suave
    fig = plt.figure(figsize=(15, 8), facecolor='#f8f9fa')
    ax = plt.subplot2grid((1, 6), (0, 0), colspan=5, fig=fig)
    ax_checkbox = plt.subplot2grid((1, 6), (0, 5), fig=fig)
    
    # Fondo del área de gráfico
    ax.set_facecolor('#ffffff')

    # Diccionario para almacenar las líneas de cada core
    lines_dict = {}
    max_packets_per_core = 0

    # Crear las líneas para cada core con estilo mejorado
    for idx, core in enumerate(valid_cores):
        rssi_vals = core_rssi[core]
        if not rssi_vals:
            continue

        x_local = np.arange(1, len(rssi_vals) + 1, dtype=int)
        y = np.asarray(rssi_vals, dtype=float)
        
        max_packets_per_core = max(max_packets_per_core, len(rssi_vals))

        color = colors_map.get(core, colors_map[idx % len(colors_map)])
        
        # Línea con sombra para mejor visualización
        line, = ax.plot(x_local, y, 
                        marker="o", 
                        linestyle="-", 
                        linewidth=2.0, 
                        markersize=4,
                        label=f"Antena {core} (N={len(rssi_vals):,})", 
                        color=color, 
                        visible=True,
                        alpha=0.85,
                        markeredgewidth=0.5,
                        markeredgecolor='white')
        lines_dict[core] = line

    # Mejorar etiquetas y título
    ax.set_xlabel("Número de Paquete (secuencia por antena)", 
                  fontsize=12, fontweight='bold', color='#2c3e50')
    ax.set_ylabel("RSSI (dBm)", 
                  fontsize=12, fontweight='bold', color='#2c3e50')
    ax.set_title(title, 
                 fontsize=14, fontweight='bold', color='#2c3e50', pad=20)
    
    # Grid más sutil y profesional
    ax.grid(True, alpha=0.25, linestyle='--', linewidth=0.8, color='#bdc3c7')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#95a5a6')
    ax.spines['bottom'].set_color('#95a5a6')
    
    # Leyenda mejorada
    legend = ax.legend(title="Antenas / Cores", 
                       loc='upper right', 
                       frameon=True,
                       fancybox=True,
                       shadow=True,
                       fontsize=10,
                       title_fontsize=11)
    legend.get_frame().set_facecolor('#ffffff')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#bdc3c7')

    if max_packets_per_core > 0:
        ax.set_xlim(0, max_packets_per_core + 1)
    
    # Añadir estadísticas en el título del eje Y
    all_rssi = [rssi for rssi_list in core_rssi.values() for rssi in rssi_list]
    if all_rssi:
        rssi_min, rssi_max = min(all_rssi), max(all_rssi)
        ax.set_ylim(rssi_min - 2, rssi_max + 2)

    # Crear checkboxes con estilo mejorado
    labels = [f"Antena {c}" for c in valid_cores]
    actives = [True] * len(valid_cores)
    
    # Ajustar posición de checkboxes
    ax_checkbox.set_xlim(0, 1)
    ax_checkbox.set_ylim(0, len(valid_cores) + 1)
    
    check = CheckButtons(ax_checkbox, labels, actives)
    
    # Colorear los checkboxes según los colores de las líneas (si el atributo existe)
    try:
        # Para versiones antiguas de matplotlib
        if hasattr(check, 'rectangles'):
            for i, (core, rect) in enumerate(zip(valid_cores, check.rectangles)):
                color = colors_map.get(core, colors_map[i % len(colors_map)])
                rect.set_facecolor(color)
                rect.set_edgecolor('#2c3e50')
                rect.set_linewidth(1.5)
    except (AttributeError, Exception):
        # Para versiones modernas de matplotlib, personalizar de otra forma
        pass
    
    # Mejorar el texto de los checkboxes
    try:
        for i, label_obj in enumerate(check.labels):
            label_obj.set_fontsize(11)
            label_obj.set_fontweight('bold')
            core = valid_cores[i]
            color = colors_map.get(core, colors_map[i % len(colors_map)])
            # Usar el color de la línea correspondiente
            label_obj.set_color(color)
    except (AttributeError, Exception):
        # Si falla, mantener estilo por defecto
        pass
    
    # Función callback para mostrar/ocultar líneas
    def func(label):
        # Encontrar el core correspondiente al label
        core_idx = labels.index(label)
        core = valid_cores[core_idx]
        
        # Cambiar visibilidad de la línea
        line = lines_dict[core]
        line.set_visible(not line.get_visible())
        
        # Actualizar leyenda solo con líneas visibles
        handles, lbls = ax.get_legend_handles_labels()
        visible_handles = [h for h in handles if h.get_visible()]
        visible_labels = [l for h, l in zip(handles, lbls) if h.get_visible()]
        
        if visible_handles:
            legend = ax.legend(visible_handles, visible_labels,
                              title="Antenas / Cores", 
                              loc='upper right', 
                              frameon=True,
                              fancybox=True,
                              shadow=True,
                              fontsize=10,
                              title_fontsize=11)
            legend.get_frame().set_facecolor('#ffffff')
            legend.get_frame().set_alpha(0.95)
            legend.get_frame().set_edgecolor('#bdc3c7')
        
        # Redibujar
        plt.draw()
    
    # Conectar el callback
    check.on_clicked(func)
    
    # Título para el panel de checkboxes
    ax_checkbox.text(0.5, len(valid_cores) + 0.5, 'Seleccionar:', 
                     ha='center', va='bottom', 
                     fontsize=12, fontweight='bold', color='#2c3e50')
    
    # Ocultar ejes del área de checkboxes
    ax_checkbox.set_xticks([])
    ax_checkbox.set_yticks([])
    ax_checkbox.spines['top'].set_visible(False)
    ax_checkbox.spines['right'].set_visible(False)
    ax_checkbox.spines['bottom'].set_visible(False)
    ax_checkbox.spines['left'].set_visible(False)
    
    # Ajustar layout
    plt.tight_layout(rect=[0, 0, 1, 0.98])

    if save_path is not None:
        out_dir = os.path.dirname(save_path)
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        fig.savefig(save_path, dpi=200, facecolor='#f8f9fa', edgecolor='none', bbox_inches='tight')
        print(f"Figura RSSI guardada en: {save_path}")

    if show:
        plt.show(block=True)
    else:
        plt.close(fig)


def plot_rssi_stats_by_antenna(
    core_rssi: Dict[int, List[int]],
    save_path: str | None = None,
    show: bool = True,
) -> None:
    """Boxplot opcional de RSSI por antena/core."""

    cores = sorted([c for c in core_rssi.keys() if c >= 0 and core_rssi[c]])
    if not cores:
        print("No hay datos suficientes para boxplot de RSSI.")
        return

    data = [np.asarray(core_rssi[c], dtype=float) for c in cores]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.boxplot(data, labels=[f"Core {c}" for c in cores], showmeans=True)
    ax.set_ylabel("RSSI (dBm)")
    ax.set_title("Distribución de RSSI por antena/core")
    ax.grid(True, axis="y", alpha=0.3)

    fig.tight_layout()

    if save_path is not None:
        out_dir = os.path.dirname(save_path)
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        fig.savefig(save_path, dpi=150)
        print(f"Figura de estadísticas RSSI guardada en: {save_path}")

    if show:
        plt.show(block=True)
    else:
        plt.close(fig)


def main() -> None:
    """Función principal de ejemplo.

    Configura el archivo PCAP a usar y genera:
      - Una gráfica temporal de RSSI por antena/core
      - Opcionalmente, un boxplot de estadísticas por antena
    """

    FILE = "./pcap_files/mydata/GOLD_DISK/captura_raspTest1_30000_120s_36_20.pcap"
    NPKTS_MAX = 50000
    SAVE_PNG = False

    print("RSSI Reader por antena/core")
    print("=" * 60)
    print(f"Archivo   : {FILE}")
    print(f"Máx. pkts : {NPKTS_MAX}")

    result = collect_rssi_by_antenna(FILE, NPKTS_MAX)
    packets_info = result["packets_info"]
    core_indices = result["core_indices"]
    core_rssi = result["core_rssi"]

    if not packets_info:
        print("Sin paquetes válidos, nada que visualizar.")
        return

    # Construir ruta para guardar figuras
    image_dir = "csireader_image"
    base_name = os.path.splitext(os.path.basename(FILE))[0]
    rssi_time_path = os.path.join(image_dir, f"{base_name}_rssi_by_antenna.png")
    rssi_box_path = os.path.join(image_dir, f"{base_name}_rssi_boxplot.png")

    plot_rssi_by_antenna(
        packets_info,
        core_indices,
        core_rssi,
        title=f"RSSI por antena/core - {base_name}",
        save_path=rssi_time_path if SAVE_PNG else None,
        show=True,
        interactive=True,  # Activar modo interactivo con checkboxes
    )

    # Boxplot opcional
    plot_rssi_stats_by_antenna(
        core_rssi,
        save_path=rssi_box_path if SAVE_PNG else None,
        show=False,
    )


if __name__ == "__main__":
    main()
