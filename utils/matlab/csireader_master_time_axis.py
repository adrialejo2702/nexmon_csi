"""Lector CSI (bcm4366c0) con heatmap cuyo eje horizontal es tiempo (s) real.

Este script usa las marcas de tiempo de cada frame en el PCAP:
`frame["header"]["ts_sec"]` + `frame["header"]["ts_usec"]`.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Optional

import numpy as np

import csireader_master as crm
from readpcap import ReadPcap


def _require_matplotlib():
    # Importación perezosa: evita fallos si sólo se quiere validar parseos/lecturas.
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "Falta matplotlib. Instálalo para poder generar los heatmaps (p. ej. `pip install matplotlib`)."
        ) from exc
    return plt


def parse_duration_seconds_from_filename(pcap_path: str | Path) -> Optional[float]:
    """Obtiene la duración en segundos a partir del nombre del .pcap.

    Busca el primer número seguido de ``s`` como sufijo de unidad de segundos,
    p. ej. ``..._30s_36_20...`` o ``..._120s_36_20.pcap``.
    """
    name = Path(pcap_path).stem
    # Preferir tokens delimitados (evita falsos positivos en nombres raros).
    m = re.search(r"(?:^|[_-])(\d+)s(?:$|[_\-.])", name, re.IGNORECASE)
    if m:
        return float(m.group(1))
    m2 = re.search(r"(\d+)\s*s(?:ec(?:onds?)?)?(?:$|[_\-.])", name, re.IGNORECASE)
    if m2:
        return float(m2.group(1))
    return None


def _time_edges_from_centers(times: np.ndarray) -> np.ndarray:
    """Convierte marcas de tiempo (centros) en bordes para `pcolormesh`."""
    times = np.asarray(times, dtype=float)
    n = int(times.size)
    if n <= 0:
        return np.asarray([0.0, 1.0], dtype=float)
    if n == 1:
        dt = 1e-3
        return np.asarray([times[0] - dt / 2.0, times[0] + dt / 2.0], dtype=float)

    edges = np.empty(n + 1, dtype=float)
    mid = (times[:-1] + times[1:]) / 2.0
    edges[1:-1] = mid
    edges[0] = times[0] - (times[1] - times[0]) / 2.0
    edges[-1] = times[-1] + (times[-1] - times[-2]) / 2.0
    return edges


def _plot_heatmap_time_real(
    csi_array: np.ndarray,
    packet_times_sec: np.ndarray,
    normalize: bool,
    title: str,
) -> None:
    """Heatmap de amplitudes: tiempo real vs subportadoras."""
    plt = _require_matplotlib()

    if csi_array.size == 0:
        print("No hay datos CSI para graficar.")
        return

    packet_times_sec = np.asarray(packet_times_sec, dtype=float)
    if packet_times_sec.size != csi_array.shape[0]:
        raise ValueError(
            "Inconsistencia: `packet_times_sec` debe tener un elemento por paquete CSI "
            f"(times={packet_times_sec.size}, pkts={csi_array.shape[0]})."
        )

    shifted = np.fft.fftshift(csi_array, axes=1)
    magnitude = np.abs(shifted)

    if normalize:
        max_vals = magnitude.max(axis=1, keepdims=True)
        max_vals[max_vals == 0] = 1
        magnitude = magnitude / max_vals

    num_packets, fft_len = magnitude.shape
    subcarrier_axis = np.arange(-fft_len // 2, fft_len // 2)

    # Bordes para eje X (tiempo) y eje Y (subportadoras) usando bordes entre celdas.
    x_edges = _time_edges_from_centers(packet_times_sec)
    y_edges = np.concatenate([subcarrier_axis - 0.5, [subcarrier_axis[-1] + 0.5]])

    # pcolormesh: Z con forma (len(Y)-1, len(X)-1) => (fft_len, num_packets)
    Z = magnitude.T

    fig, ax = plt.subplots(figsize=(10, 6))
    pcm = ax.pcolormesh(x_edges, y_edges, Z, shading="auto", cmap="jet")
    # Mantener la misma orientación que el `imshow` previo (subportadoras de menor a mayor centradas en 0).
    ax.set_ylim(y_edges[-1], y_edges[0])
    fig.colorbar(pcm, ax=ax, label="Magnitud (normalizada" if normalize else "Magnitud")
    ax.set_xlabel("Tiempo (s, real)")
    ax.set_ylabel("Índice de subportadora (centrado en 0)")
    ax.set_title(title)
    fig.tight_layout()
    plt.show(block=True)


def _collect_csi_packets_with_timestamps(
    file_path: str,
    max_packets: int | None,
    fallback_bw: int,
) -> dict:
    """Extrae CSI (bcm4366c0) y tiempos reales por paquete."""
    reader = ReadPcap()
    reader.open(file_path)

    frames = reader.all()
    if max_packets is None or max_packets <= 0:
        limit = len(frames)
    else:
        limit = min(len(frames), max_packets)

    reader.from_start()

    csi_vectors: list[np.ndarray] = []
    timestamps_sec: list[float] = []
    packets_info: list[dict] = []

    core_groups: dict[int, list[np.ndarray]] = {}
    core_times_sec: dict[int, list[float]] = {}

    processed = 0
    skipped = 0
    packet_idx = 0

    while processed < limit:
        frame = reader.next()
        if frame is None:
            break

        packet_idx += 1
        payload = frame["payload"]

        header_time = frame.get("header", {})
        ts_sec = float(header_time.get("ts_sec", 0))
        ts_usec = float(header_time.get("ts_usec", 0))
        timestamp = ts_sec + ts_usec * 1e-6

        try:
            header, valid, header_offset = crm._parse_csi_udp_header(payload)
        except Exception as exc:
            print(f"Paquete {packet_idx:04d}: error parseando cabecera -> {exc}")
            skipped += 1
            continue

        if not valid:
            skipped += 1
            continue

        if header["chip_version"] not in crm.ACCEPTED_CHIP_IDS:
            skipped += 1
            continue

        actual_bw = header["bandwidth"] or fallback_bw
        nfft = int(actual_bw * 3.2)
        csi_offset_bytes = header_offset + crm.HEADER_SIZE

        payload_bytes = payload.tobytes() if hasattr(payload, "tobytes") else bytes(payload)

        if payload.dtype == np.uint32:
            start_u32 = csi_offset_bytes // 4
            end_u32 = start_u32 + nfft
            if end_u32 > len(payload):
                skipped += 1
                continue
            raw_words = payload[start_u32:end_u32]
        else:
            start = csi_offset_bytes
            end = start + nfft * 4
            if end > len(payload):
                skipped += 1
                continue
            raw_slice = payload_bytes[start:end]
            raw_words = np.frombuffer(raw_slice, dtype=np.uint32)

        if len(raw_words) < nfft:
            skipped += 1
            continue

        csi_vec = crm._decode_csi4366(raw_words, nfft)
        csi_vectors.append(csi_vec)
        timestamps_sec.append(timestamp)
        packets_info.append(header)

        core = header["core"]
        core_groups.setdefault(core, []).append(csi_vec)
        core_times_sec.setdefault(core, []).append(timestamp)

        processed += 1

    reader.close()

    print("\n========= RESUMEN =========")
    print(f"Total frames en PCAP: {len(frames)}")
    print(f"Procesados           : {processed}")
    print(f"Saltados             : {skipped}")

    return {
        "csi_vectors": csi_vectors,
        "timestamps_sec": timestamps_sec,
        "packets_info": packets_info,
        "core_groups": core_groups,
        "core_times_sec": core_times_sec,
    }


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    PCAP_BASE_DIR = script_dir / "pcap_files" / "mydata" / "GOLD_DISK"
    DEFAULT_SUFFIX = "captura_ping1x4/captura_ping1x4_30s_36_20_20260315_170304.pcap"

    user = input(
        "Introduce la terminación de la ruta del .pcap (relativa a "
        f"{PCAP_BASE_DIR})\n"
        f"Ejemplo: {DEFAULT_SUFFIX}\n"
        f"Pulsa Enter para usar el ejemplo: "
    )
    pcap_path = crm._resolve_pcap_path(PCAP_BASE_DIR, user, DEFAULT_SUFFIX)
    FILE = str(pcap_path)

    duration_from_name = parse_duration_seconds_from_filename(pcap_path)
    if duration_from_name is None or duration_from_name <= 0:
        raw = input(
            "No se detectó duración en el nombre del .pcap (p. ej. _30s_). "
            "Introduce la duración del experimento en segundos (Enter = 30): "
        ).strip()
        if not raw:
            duration_from_name = 30.0
        else:
            duration_from_name = float(raw.replace(",", "."))

    BW_FALLBACK = 20
    NPKTS_MAX = None
    NORMALIZE = True
    SHOW_TABLE = True

    print("CSI Reader — eje temporal (heatmap real)")
    print("=" * 60)
    print(f"Archivo         : {FILE}")
    print(f"Duración (nom.) : {duration_from_name} s")
    print(f"Fallback BW     : {BW_FALLBACK} MHz")
    print(f"Máx. pkts       : {'sin límite' if (NPKTS_MAX is None or NPKTS_MAX <= 0) else NPKTS_MAX}")
    print(f"Normalize       : {NORMALIZE}")

    result = _collect_csi_packets_with_timestamps(FILE, NPKTS_MAX, BW_FALLBACK)
    csi_vectors = result["csi_vectors"]
    timestamps_sec = result["timestamps_sec"]
    packets_info = result["packets_info"]
    core_groups = result["core_groups"]
    core_times_sec = result["core_times_sec"]

    if not csi_vectors:
        print("Sin paquetes válidos (bcm4366c0) para visualizar.")
        return

    t0_abs = float(timestamps_sec[0])
    times_rel = np.asarray(timestamps_sec, dtype=float) - t0_abs
    duration_real = float(times_rel[-1]) if len(times_rel) > 0 else 0.0

    max_len = max(len(vec) for vec in csi_vectors)
    csi_array = np.zeros((len(csi_vectors), max_len), dtype=np.complex128)
    for idx, vec in enumerate(csi_vectors):
        csi_array[idx, : len(vec)] = vec

    n = len(csi_vectors)
    if n > 1:
        dt_median = float(np.median(np.diff(times_rel)))
    else:
        dt_median = 0.0
    print(f"Paquetes CSI    : {n}")
    print(f"Duración real   : {duration_real:.6f} s")
    if dt_median > 0:
        print(f"dt mediana      : ~{dt_median * 1e3:.3f} ms")

    bandwidth_counts = Counter(pkt["bandwidth"] for pkt in packets_info)
    print("Anchuras detectadas (MHz):", dict(bandwidth_counts))

    if SHOW_TABLE:
        limit = min(20, len(packets_info))
        print("\nPrimeros paquetes:")
        print("-" * 80)
        for idx, pkt in enumerate(packets_info[:limit], start=1):
            t_pkt = float(times_rel[idx - 1]) if n else 0.0
            print(
                f"{idx:04d} | t={t_pkt:9.6f}s | RSSI={pkt['rssi']:>4} | Seq={pkt['seq']:>5} | "
                f"Core={pkt['core']} | Chan={pkt['channel']:>3} | BW={pkt['bandwidth']:>3} | MAC={pkt['src_mac']}"
            )

    core_items = [(core, core_groups[core]) for core in sorted(core_groups.keys()) if core_groups[core]]

    if not core_items:
        print("Sin datos por core para visualizar.")
        return

    plt = _require_matplotlib()
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
        if not data:
            continue
        max_len_core = max(len(vec) for vec in data)
        array_core = np.zeros((len(data), max_len_core), dtype=np.complex128)
        for idx, vec in enumerate(data):
            array_core[idx, : len(vec)] = vec

        print(
            f"\nCore {core}: {len(data)} paquetes"
        )

        times_core_rel = np.asarray(core_times_sec[core], dtype=float) - t0_abs

        # Render dentro del subplot actual (misma figura).
        shifted = np.fft.fftshift(array_core, axes=1)
        magnitude = np.abs(shifted)
        if NORMALIZE:
            max_vals = magnitude.max(axis=1, keepdims=True)
            max_vals[max_vals == 0] = 1
            magnitude = magnitude / max_vals

        num_packets, fft_len = magnitude.shape
        subcarrier_axis = np.arange(-fft_len // 2, fft_len // 2)
        x_edges = _time_edges_from_centers(times_core_rel)
        y_edges = np.concatenate([subcarrier_axis - 0.5, [subcarrier_axis[-1] + 0.5]])

        Z = magnitude.T
        pcm = ax.pcolormesh(x_edges, y_edges, Z, shading="auto", cmap="jet")
        ax.set_ylim(y_edges[-1], y_edges[0])
        ax.set_xlabel("Tiempo (s, real)")
        ax.set_ylabel("Índice de subportadora (centrado en 0)")
        ax.set_title(f"Amplitud vs tiempo — Core {core}")
        fig.colorbar(pcm, ax=ax, label="Magnitud (normalizada" if NORMALIZE else "Magnitud")

    total_axes = axes.size
    if total_axes > ncores:
        for ax in axes.flatten()[ncores:]:
            ax.axis("off")

    fig.suptitle(
        f"Heatmaps por core (duración real: {duration_real:.3f} s; duración del nombre: {duration_from_name} s)",
        fontsize=14,
    )
    fig.tight_layout()
    plt.show(block=True)


if __name__ == "__main__":
    main()
