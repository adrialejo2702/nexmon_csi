from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib
import numpy as np

# Directorio utils/matlab (padre de csi_web) para poder importar csireader_master.
_MATLAB_DIR = Path(__file__).resolve().parent.parent
if str(_MATLAB_DIR) not in sys.path:
    sys.path.insert(0, str(_MATLAB_DIR))

import csireader_master as cm


def _force_interactive_backend() -> None:
    # En app.py usamos Agg para render servidor; aquí necesitamos una ventana real.
    for backend in ("MacOSX", "TkAgg", "QtAgg"):
        try:
            matplotlib.use(backend, force=True)
            return
        except Exception:
            continue


_force_interactive_backend()
import matplotlib.pyplot as plt


def _build_combined_core_matrix(core_groups: dict[int, list[np.ndarray]]) -> np.ndarray:
    core_items = [(core, vecs) for core, vecs in sorted(core_groups.items()) if vecs]
    if not core_items:
        return np.empty((0, 0), dtype=np.complex128)
    min_packets = min(len(vecs) for _, vecs in core_items)
    if min_packets <= 0:
        return np.empty((0, 0), dtype=np.complex128)
    max_subcarriers = max(len(vec) for _, vecs in core_items for vec in vecs[:min_packets])
    combined = np.zeros((min_packets, max_subcarriers), dtype=np.complex128)
    for _, vecs in core_items:
        mat = np.zeros((min_packets, max_subcarriers), dtype=np.complex128)
        for idx in range(min_packets):
            vec = vecs[idx]
            mat[idx, : len(vec)] = vec
        combined += mat
    return combined


def main() -> int:
    parser = argparse.ArgumentParser(description="Abrir preview CSI en ventana Python.")
    parser.add_argument("--pcap", required=True, help="Ruta al fichero pcap")
    parser.add_argument("--packet-range", default="", help="Rango de paquetes (formato csireader_master)")
    parser.add_argument("--bw-fallback", type=int, required=True, help="BW fallback en MHz")
    parser.add_argument("--combined", default="0", help="1 para combinar cores en una sola vista")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    pcap_name = pcap_path.name
    packet_start, packet_end = cm._parse_packet_range_spec(args.packet_range)
    result = cm._collect_csi_packets_interval(
        str(pcap_path),
        packet_start,
        packet_end,
        int(args.bw_fallback),
    )
    core_groups = result["core_groups"]
    core_items = [
        (core, core_groups[core])
        for core in sorted(core_groups.keys())
        if core_groups[core]
    ]
    if not core_items:
        raise SystemExit("Sin datos por core para visualizar.")

    combined_mode = str(args.combined).strip() in {"1", "true", "True", "yes"}
    if combined_mode:
        combined = _build_combined_core_matrix(core_groups)
        if combined.size == 0:
            raise SystemExit("Sin datos por core para visualización combinada.")
        fig, axes = plt.subplots(nrows=1, ncols=1, figsize=(8, 5), squeeze=False)
        cm._plot_heatmap(
            combined,
            title="Amplitude Heatmap — Combined",
            ax=axes[0][0],
            packet_numbers=None,
        )
        fig.suptitle(f"Mapa de calor combinado — {pcap_name}", fontsize=14)
    else:
        ncores = len(core_items)
        ncols = 2 if ncores > 1 else 1
        nrows = int(np.ceil(ncores / ncols))
        fig, axes = plt.subplots(
            nrows=nrows,
            ncols=ncols,
            figsize=(8 * ncols, 5 * nrows),
            squeeze=False,
        )

        for ax, (core, data) in zip(axes.flatten(), core_items):
            max_len_core = max(len(vec) for vec in data)
            array_core = np.zeros((len(data), max_len_core), dtype=np.complex128)
            for idx, vec in enumerate(data):
                array_core[idx, : len(vec)] = vec

            cm._plot_heatmap(
                array_core,
                title=f"Amplitude Heatmap — Core {core}",
                ax=ax,
                packet_numbers=None,  # Eje local por core: 1..N_core
            )

        total_axes = axes.size
        if total_axes > ncores:
            for ax in axes.flatten()[ncores:]:
                ax.axis("off")

        fig.suptitle(f"Mapas de calor por core — {pcap_name}", fontsize=14)
    try:
        fig.canvas.manager.set_window_title(f"CSI Preview — {pcap_name}")
    except Exception:
        pass
    fig.tight_layout()
    plt.show(block=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
