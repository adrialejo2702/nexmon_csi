"""
Exporta (en batch) las imágenes/figuras generadas a partir de capturas PCAP
usando el lector `csireader_master.py`.

Guarda un PNG por captura, con el mismo nombre base del PCAP, en la MISMA carpeta.
Si el PNG ya existe junto al PCAP, no vuelve a generarlo.

Uso: se le pasa UNA ruta de carpeta y busca .pcap de forma recursiva.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
from pathlib import Path


def _build_figure_for_pcap(
    pcap_path: Path,
    *,
    bw_fallback: int,
    max_packets: int | None,
    normalize: bool,
):
    import matplotlib

    # Backend no interactivo para poder guardar sin abrir ventanas.
    matplotlib.use("Agg", force=True)

    import matplotlib.pyplot as plt  # noqa: WPS433 (import dentro de función por backend)
    import numpy as np

    # Import local: mismo directorio que `csireader_master.py`
    from csireader_master import _collect_csi_packets, _plot_heatmap  # type: ignore

    # Silencia la salida "verbose" del lector base.
    with contextlib.redirect_stdout(io.StringIO()):
        result = _collect_csi_packets(str(pcap_path), max_packets, bw_fallback)
    core_groups = result["core_groups"]

    core_items = [(core, core_groups[core]) for core in sorted(core_groups.keys()) if core_groups[core]]
    if not core_items:
        return None

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

        _plot_heatmap(array_core, normalize, title=f"Amplitude Heatmap — Core {core}", ax=ax)

    # Apaga ejes sobrantes si la rejilla es mayor que el nº de cores.
    total_axes = axes.size
    if total_axes > ncores:
        for ax in axes.flatten()[ncores:]:
            ax.axis("off")

    fig.suptitle(f"Mapas de calor por core — {pcap_path.name}", fontsize=14)
    fig.tight_layout()
    return fig


def _iter_pcaps(input_dir: Path) -> list[Path]:
    pcaps: list[Path] = []
    for root, _dirs, files in os.walk(input_dir):
        for name in files:
            if name.lower().endswith(".pcap"):
                pcaps.append(Path(root) / name)
    pcaps.sort()
    return pcaps


def main() -> int:
    parser = argparse.ArgumentParser(description="Exporta heatmaps (PNG) para todas las capturas PCAP de una carpeta.")
    parser.add_argument("carpeta", type=Path, help="Carpeta raíz donde buscar capturas .pcap (recursivo).")
    parser.add_argument("--bw-fallback", type=int, default=20, help="BW fallback (MHz) cuando el header trae BW=0.")
    parser.add_argument("--max-packets", type=int, default=0, help="Máx. paquetes a procesar (0 = sin límite).")
    parser.add_argument("--no-normalize", action="store_true", help="No normalizar magnitud por paquete.")

    # Si el usuario no pasa la carpeta, se la pedimos de forma interactiva.
    if len(sys.argv) == 1:
        carpeta_txt = input("Introduce la ruta de la carpeta con capturas .pcap: ").strip()
        if not carpeta_txt:
            print("No se ha introducido ninguna ruta. Saliendo.")
            return 2
        args = parser.parse_args([carpeta_txt])
    else:
        args = parser.parse_args()

    input_dir: Path = args.carpeta.expanduser().resolve()

    # Asegura imports locales (readpcap, unpack_float, csireader_master) desde utils/matlab.
    this_dir = Path(__file__).resolve().parent
    if str(this_dir) not in sys.path:
        sys.path.insert(0, str(this_dir))

    try:
        import matplotlib  # noqa: F401
    except ModuleNotFoundError:
        print("Falta la dependencia 'matplotlib'. Instálala con:")
        print(f"  python3 -m pip install -r \"{this_dir / 'requirements.txt'}\"")
        return 3

    pcaps = _iter_pcaps(input_dir)
    if not pcaps:
        print(f"No se encontraron .pcap en: {input_dir}")
        return 2

    max_packets = None if args.max_packets <= 0 else int(args.max_packets)
    normalize = not bool(args.no_normalize)

    ok = 0
    skipped = 0
    skipped_existing = 0

    # Import aquí para que respete el backend Agg.
    import matplotlib.pyplot as plt  # noqa: WPS433

    for pcap in pcaps:
        out_png = pcap.with_suffix(".png")
        if out_png.is_file():
            print(f"Saltado (ya existe imagen): {out_png}")
            skipped_existing += 1
            continue

        print(f"Procesando: {pcap}")

        fig = _build_figure_for_pcap(
            pcap,
            bw_fallback=int(args.bw_fallback),
            max_packets=max_packets,
            normalize=normalize,
        )

        if fig is None:
            print("Omitido: sin datos CSI válidos.")
            skipped += 1
            continue

        fig.savefig(out_png, dpi=200)
        plt.close(fig)
        ok += 1
        print(f"Guardado: {out_png}")

    print("\n========= RESUMEN =========")
    print(f"Total PCAPs      : {len(pcaps)}")
    print(f"Exportados (nuevos): {ok}")
    print(f"Saltados (ya existían): {skipped_existing}")
    print(f"Omitidos (sin CSI)    : {skipped}")
    print("Destino     : misma carpeta de cada captura")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

