"""Lector de CSI específico para bcm4366c0 (formato extendido PR #256).

Se basa en la lógica de `csireader_extended.py`, pero restringido al chip
bcm4366c0 y mostrando únicamente un heatmap de amplitudes.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Tuple

import struct

import matplotlib.pyplot as plt
import numpy as np

from readpcap import ReadPcap
from unpack_float import unpack_float


HEADER_SIZE = 18
ACCEPTED_CHIP_IDS = {0x4366, 0x006A}  # 0x006A observado en capturas reales bcm4366c0

BANDWIDTH_MAP = {
    0: 5,
    1: 10,
    2: 20,
    3: 40,
    4: 80,
    5: 160,
    6: 80,
}


def _decode_csi4366(raw_words: np.ndarray, nfft: int) -> np.ndarray:
    """Decodifica palabras de 32 bits en complejos (formato float de bcm4366c0)."""
    decoded = unpack_float(1, nfft, raw_words)
    decoded = decoded.reshape(2, -1, order="F")
    return decoded[0, :nfft].astype(np.float64) + 1j * decoded[1, :nfft].astype(np.float64)


def _parse_csi_udp_header(payload: np.ndarray) -> Tuple[dict, bool, int]:
    """Parsea el header extendido (magic, rssi, mac, seq, core/ss, chanspec, chip)."""
    payload_bytes = payload.tobytes() if hasattr(payload, "tobytes") else bytes(payload)
    max_offset = min(len(payload_bytes) - HEADER_SIZE, 256)

    csi_offset = None
    for offset in range(max_offset):
        if len(payload_bytes) - offset < HEADER_SIZE:
            break
        magic_test = struct.unpack_from("<H", payload_bytes, offset)[0]
        if magic_test == 0x1111:
            csi_offset = offset
            break

    if csi_offset is None:
        return {}, False, 0

    magic = struct.unpack_from("<H", payload_bytes, csi_offset)[0]
    rssi = struct.unpack_from("<b", payload_bytes, csi_offset + 2)[0]
    fc = struct.unpack_from("<B", payload_bytes, csi_offset + 3)[0]
    src_mac_bytes = payload_bytes[csi_offset + 4 : csi_offset + 10]
    seq = struct.unpack_from("<H", payload_bytes, csi_offset + 10)[0]
    csiconf = struct.unpack_from("<H", payload_bytes, csi_offset + 12)[0]
    chanspec = struct.unpack_from("<H", payload_bytes, csi_offset + 14)[0]
    chip_version = struct.unpack_from("<H", payload_bytes, csi_offset + 16)[0]

    # Para bcm4366c0 en formato extendido, el core está en el byte alto de csiconf
    # Valores observados: 0x0000, 0x0100, 0x0200, 0x0300 -> core = 0, 1, 2, 3
    core = (csiconf >> 8) & 0xFF
    # Spatial stream en bits bajos (aunque en capturas reales suele ser 0)
    spatial_stream = csiconf & 0x7

    bw_code = (chanspec >> 11) & 0x7
    bandwidth = BANDWIDTH_MAP.get(bw_code, 0)
    channel = chanspec & 0xFF

    header = {
        "magic": magic,
        "rssi": rssi,
        "fc": fc,
        "src_mac": ":".join(f"{b:02X}" for b in src_mac_bytes),
        "src_mac_bytes": src_mac_bytes,
        "seq": seq,
        "core": core,
        "spatial_stream": spatial_stream,
        "csiconf": csiconf,
        "chanspec": chanspec,
        "channel": channel,
        "bandwidth": bandwidth,
        "chip_version": chip_version,
        "chip_name": f"bcm4366c0" if chip_version in ACCEPTED_CHIP_IDS else f"Unknown(0x{chip_version:04X})",
        "csi_offset": csi_offset,
    }

    return header, magic == 0x1111, csi_offset


def _plot_heatmap(csi_array: np.ndarray, normalize: bool, title: str, ax: plt.Axes | None = None) -> None:
    """Genera un heatmap de amplitudes (tiempo vs subportadoras)."""
    if csi_array.size == 0:
        print("No hay datos CSI para graficar.")
        return

    shifted = np.fft.fftshift(csi_array, axes=1)
    magnitude = np.abs(shifted)

    if normalize:
        max_vals = magnitude.max(axis=1, keepdims=True)
        max_vals[max_vals == 0] = 1
        magnitude = magnitude / max_vals

    num_packets, fft_len = magnitude.shape
    subcarrier_axis = np.arange(-fft_len // 2, fft_len // 2)

    own_axis = ax is None
    if own_axis:
        fig, ax = plt.subplots(figsize=(10, 6))
    else:
        fig = ax.figure

    im = ax.imshow(
        magnitude.T,
        aspect="auto",
        extent=[1, num_packets, subcarrier_axis[-1] + 0.5, subcarrier_axis[0] - 0.5],
        cmap="jet",
    )
    fig.colorbar(im, ax=ax, label="Magnitud (normalizada" if normalize else "Magnitud")
    ax.set_xlabel("Número de paquete")
    ax.set_ylabel("Índice de subportadora (centrado en 0)")
    ax.set_title(title)

    if own_axis:
        fig.tight_layout()
        plt.show(block=True)


def _collect_csi_packets(
    file_path: str,
    max_packets: int,
    fallback_bw: int,
) -> Dict[str, object]:
    """Extrae CSI y metadatos exclusivamente de paquetes bcm4366c0."""
    reader = ReadPcap()
    reader.open(file_path)

    frames = reader.all()
    limit = min(len(frames), max_packets)

    reader.from_start()

    csi_vectors: List[np.ndarray] = []
    packets_info: List[dict] = []
    core_groups: Dict[int, List[np.ndarray]] = {}
    core_packets: Dict[int, List[dict]] = {}
    debug_headers: List[Tuple[int, int, int, int]] = []

    processed = 0
    skipped = 0
    packet_idx = 0

    while processed < limit:
        frame = reader.next()
        if frame is None:
            break

        packet_idx += 1
        payload = frame["payload"]

        try:
            header, valid, header_offset = _parse_csi_udp_header(payload)
        except Exception as exc:
            print(f"Paquete {packet_idx:04d}: error parseando cabecera -> {exc}")
            skipped += 1
            continue

        if not valid:
            skipped += 1
            continue

        if header["chip_version"] not in ACCEPTED_CHIP_IDS:
            skipped += 1
            continue

        actual_bw = header["bandwidth"] or fallback_bw
        nfft = int(actual_bw * 3.2)
        csi_offset_bytes = header_offset + HEADER_SIZE

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

        csi_vec = _decode_csi4366(raw_words, nfft)
        csi_vectors.append(csi_vec)
        packets_info.append(header)
        core = header["core"]
        core_groups.setdefault(core, []).append(csi_vec)
        core_packets.setdefault(core, []).append(header)

        if len(debug_headers) < 8:
            debug_headers.append((packet_idx, header["core"], header["spatial_stream"], header["csiconf"], header["chanspec"]))
        processed += 1

    reader.close()

    print("\n========= RESUMEN =========")
    print(f"Total paquetes en PCAP: {len(frames)}")
    print(f"Procesados    : {processed}")
    print(f"Saltados      : {skipped}")

    if debug_headers:
        print("\nPrimeros paquetes decodificados (idx, core, ss, csiconf, chanspec):")
        for pkt_idx, core_val, ss_val, csiconf_val, chanspec_val in debug_headers:
            print(f"  #{pkt_idx:04d} -> core={core_val}, ss={ss_val}, csiconf=0x{csiconf_val:04X}, chanspec=0x{chanspec_val:04X}")

    return {
        "csi_vectors": csi_vectors,
        "packets_info": packets_info,
        "core_groups": core_groups,
        "core_packets": core_packets,
    }


def main() -> None:
    FILE = "./pcap_files/mydata/GOLD_DISK/captura_home_empty1_10000_60s_36_20.pcap"
    BW_FALLBACK = 20
    NPKTS_MAX = 40000
    NORMALIZE = True
    SHOW_TABLE = True

    print("CSI Reader — bcm4366c0 (formato extendido, heatmap)")
    print("=" * 60)
    print(f"Archivo   : {FILE}")
    print(f"Fallback BW (cuando header=0): {BW_FALLBACK} MHz")
    print(f"Máx. pkts : {NPKTS_MAX}")
    print(f"Normalize : {NORMALIZE}")

    result = _collect_csi_packets(FILE, NPKTS_MAX, BW_FALLBACK)
    csi_vectors = result["csi_vectors"]
    packets_info = result["packets_info"]
    core_groups = result["core_groups"]
    core_packets = result["core_packets"]

    if not csi_vectors:
        print("Sin paquetes válidos (bcm4366c0) para visualizar.")
        return

    max_len = max(len(vec) for vec in csi_vectors)
    csi_array = np.zeros((len(csi_vectors), max_len), dtype=np.complex128)
    for idx, vec in enumerate(csi_vectors):
        csi_array[idx, : len(vec)] = vec

    bandwidth_counts = Counter(pkt["bandwidth"] for pkt in packets_info)
    print("Anchuras detectadas (MHz):", dict(bandwidth_counts))

    if SHOW_TABLE:
        limit = min(20, len(packets_info))
        print("\nPrimeros paquetes:")
        print("-" * 80)
        for idx, pkt in enumerate(packets_info[:limit], start=1):
            print(
                f"{idx:04d} | RSSI={pkt['rssi']:>4} | Seq={pkt['seq']:>5} | Core={pkt['core']} | "
                f"SS={pkt['spatial_stream']} | Chan={pkt['channel']:>3} | BW={pkt['bandwidth']:>3} | MAC={pkt['src_mac']}"
            )

    core_items = [(core, core_groups[core]) for core in sorted(core_groups.keys()) if core_groups[core]]

    if not core_items:
        print("Sin datos por core para visualizar.")
        return

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

        print(f"\nVisualizando core {core} — paquetes: {len(data)}")
        _plot_heatmap(array_core, NORMALIZE, title=f"Amplitude Heatmap — Core {core}", ax=ax)

    total_axes = axes.size
    if total_axes > ncores:
        for ax in axes.flatten()[ncores:]:
            ax.axis("off")

    fig.suptitle("Mapas de calor por core", fontsize=14)
    fig.tight_layout()
    plt.show(block=True)


if __name__ == "__main__":
    main()
