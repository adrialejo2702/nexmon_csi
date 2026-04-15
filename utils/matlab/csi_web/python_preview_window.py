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


def main() -> int:
    parser = argparse.ArgumentParser(description="Abrir preview CSI en ventana Python.")
    parser.add_argument("--pcap", required=True, help="Ruta al fichero pcap")
    parser.add_argument("--packet-range", default="", help="Rango de paquetes (formato csireader_master)")
    parser.add_argument("--bw-fallback", type=int, required=True, help="BW fallback en MHz")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    packet_start, packet_end = cm._parse_packet_range_spec(args.packet_range)
    result = cm._collect_csi_packets_interval(
        str(pcap_path),
        packet_start,
        packet_end,
        int(args.bw_fallback),
    )
    core_groups = result["core_groups"]
    core_packets = result["core_packets"]
    core_items = [
        (core, core_groups[core])
        for core in sorted(core_groups.keys())
        if core_groups[core]
    ]
    if not core_items:
        raise SystemExit("Sin datos por core para visualizar.")

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

        packet_numbers_core = [pkt.get("csi_packet_number") for pkt in core_packets.get(core, [])]
        packet_numbers_core = [pkt for pkt in packet_numbers_core if pkt is not None]

        cm._plot_heatmap(
            array_core,
            title=f"Amplitude Heatmap — Core {core}",
            ax=ax,
            packet_numbers=packet_numbers_core if len(packet_numbers_core) == len(data) else None,
        )

    total_axes = axes.size
    if total_axes > ncores:
        for ax in axes.flatten()[ncores:]:
            ax.axis("off")

    fig.suptitle("Mapas de calor por core", fontsize=14)
    fig.tight_layout()
    plt.show(block=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
