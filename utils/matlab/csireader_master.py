"""Lector de CSI específico para bcm4366c0 (formato extendido PR #256).

Se basa en la lógica de `csireader_extended.py`, pero restringido al chip
bcm4366c0 y mostrando únicamente un heatmap de amplitudes.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

import re
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

    # Decodificación de core/SS:
    # - Formato genérico (docs Nexmon): bits 0-2 core, bits 3-5 spatial stream
    # - En capturas reales de bcm4366c0 (chip_version en ACCEPTED_CHIP_IDS),
    #   el core viene codificado en el byte alto de csiconf y el SS observado es 0.
    if chip_version in ACCEPTED_CHIP_IDS:
        core = (csiconf >> 8) & 0xFF
        spatial_stream = 0
    else:
        core = csiconf & 0x7
        spatial_stream = (csiconf >> 3) & 0x7

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


def _plot_heatmap(
    csi_array: np.ndarray,
    title: str,
    ax: plt.Axes | None = None,
    packet_numbers: List[int] | None = None,
) -> None:
    """Genera un heatmap de amplitudes (tiempo vs subportadoras)."""
    if csi_array.size == 0:
        print("No hay datos CSI para graficar.")
        return

    shifted = np.fft.fftshift(csi_array, axes=1)
    magnitude = np.abs(shifted)

    # Normalización siempre activa (flujo único de trabajo).
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
    fig.colorbar(im, ax=ax, label="Magnitud (normalizada)")
    ax.set_xlabel("Número de paquete")
    ax.set_ylabel("Índice de subportadora (centrado en 0)")
    ax.set_title(title)
    ax.set_xlim(1, num_packets)

    if packet_numbers and len(packet_numbers) == num_packets:
        # Mantener la geometría de imshow y mostrar etiquetas con IDs reales.
        nticks = min(8, num_packets)
        tick_positions = np.linspace(1, num_packets, nticks, dtype=int)
        tick_positions = np.unique(tick_positions)
        tick_labels = [str(packet_numbers[pos - 1]) for pos in tick_positions]
        ax.set_xticks(tick_positions)
        ax.set_xticklabels(tick_labels)

    if own_axis:
        fig.tight_layout()
        plt.show(block=True)

def _parse_packet_range_spec(spec: str) -> tuple[int, int | None]:
    """Convierte el formato del usuario en un rango de paquetes.

    Formatos soportados:
    - '' o Enter => (1, None) -> sin límite
    - 'fin'       => (1, fin)
    - 'inicio-'  => (inicio, None)
    - 'inicio-fin'=> (inicio, fin)

    Nota: se asume numeración 1..N y el extremo final es inclusivo.
    """
    raw = (spec or "").strip()
    if not raw:
        return 1, None

    if "-" in raw:
        left, right = raw.split("-", 1)
        left = left.strip()
        right = right.strip()

        start = int(left) if left else 1
        end = int(right) if right else None
    else:
        start = 1
        end = int(raw)

    if start < 1:
        raise ValueError("El inicio del rango debe ser >= 1.")
    if end is not None and end < start:
        raise ValueError("El final del rango debe ser >= al inicio.")

    return start, end


def _collect_csi_packets_interval(
    file_path: str,
    packet_start: int,
    packet_end: int | None,
    fallback_bw: int,
) -> Dict[str, object]:
    """Extrae CSI (bcm4366c0) seleccionando solo un intervalo de paquetes válidos.

    `packet_start` / `packet_end` siguen la numeración 1..N del usuario (fin inclusivo).
    """
    reader = ReadPcap()
    reader.open(file_path)

    frames = reader.all()
    reader.from_start()

    csi_vectors: List[np.ndarray] = []
    packets_info: List[dict] = []
    core_groups: Dict[int, List[np.ndarray]] = {}
    core_packets: Dict[int, List[dict]] = {}
    start_idx = packet_start - 1  # 0-based sobre paquetes CSI decodificados
    end_idx = None if packet_end is None else packet_end - 1

    decoded_count = 0  # nº de paquetes CSI decodificados encontrados (incluye los fuera del rango)
    included_count = 0  # nº de paquetes CSI que realmente se guardan (dentro del rango)
    skipped = 0
    packet_idx = 0

    while True:
        # Si ya hemos decodificado el último paquete del rango, no necesitamos seguir.
        if end_idx is not None and decoded_count > end_idx:
            break

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
        decoded_idx = decoded_count  # 0-based

        # Decide si guardarlo según el rango del usuario.
        if decoded_idx >= start_idx and (end_idx is None or decoded_idx <= end_idx):
            header["csi_packet_number"] = decoded_idx + 1
            csi_vectors.append(csi_vec)
            packets_info.append(header)
            core = header["core"]
            core_groups.setdefault(core, []).append(csi_vec)
            core_packets.setdefault(core, []).append(header)

            included_count += 1

        decoded_count += 1

    reader.close()

    print("\n========= RESUMEN =========")
    print(f"Total paquetes (frames) en PCAP: {len(frames)}")
    print(f"Decodificados CSI               : {decoded_count}")
    print(f"Guardados en el rango          : {included_count}")
    print(f"Saltados                         : {skipped}")

    return {
        "csi_vectors": csi_vectors,
        "packets_info": packets_info,
        "core_groups": core_groups,
        "core_packets": core_packets,
    }


def _resolve_pcap_path(base_dir: Path, user_input: str, default_suffix: str) -> Path:
    raw = (user_input or "").strip()
    if not raw:
        raw = default_suffix

    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = base_dir / raw

    if candidate.exists() and candidate.is_file():
        return candidate

    # Si el usuario solo puso el nombre del fichero, intentamos localizarlo dentro del base_dir.
    name_only = Path(raw).name
    matches = list(base_dir.rglob(name_only))
    matches = [p for p in matches if p.is_file() and p.suffix.lower() == ".pcap"]

    if len(matches) == 1:
        return matches[0]

    print("\nNo se encontró el archivo PCAP.")
    print(f"- Entrada          : {raw}")
    print(f"- Intento (base+in): {candidate}")
    if matches:
        print("\nCoincidencias encontradas (elige una y pégala como ruta relativa dentro de la base):")
        for p in matches[:25]:
            print(f"  - {p.relative_to(base_dir)}")
        if len(matches) > 25:
            print(f"  ... ({len(matches) - 25} más)")
    else:
        print(f"\nBase de búsqueda: {base_dir}")

    raise SystemExit(2)


def _extract_capture_seconds_from_filename(file_name: str) -> int | None:
    """Extrae la duración de captura desde nombres tipo '*_300s_*'."""
    match = re.search(r"_(\d+)s(?:_|\.|$)", file_name)
    if not match:
        raise ValueError(f"No se pudo extraer duración de captura desde: {file_name}")
    seconds = int(match.group(1))
    if seconds <= 0:
        raise ValueError(f"Duración de captura no válida ({seconds}s) en: {file_name}")
    return seconds


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
    FILE = str(_resolve_pcap_path(PCAP_BASE_DIR, user, DEFAULT_SUFFIX))
    BW_FALLBACK = 20
    packet_range_spec = input(
        "Introduce el intervalo de paquetes CSI a visualizar (Enter = sin límite). "
        "Formas: 'inicio-fin', 'fin' o 'inicio-': "
    ).strip()
    try:
        packet_start, packet_end = _parse_packet_range_spec(packet_range_spec)
    except ValueError as exc:
        print(f"Entrada no válida: {exc}")
        return

    print("CSI Reader — bcm4366c0 (formato extendido, heatmap)")
    print("=" * 60)
    print(f"Archivo   : {Path(FILE).name}")
    print(f"Fallback BW (cuando header=0): {BW_FALLBACK} MHz")
    rango_str = f"{packet_start}-{packet_end}" if packet_end is not None else f"{packet_start}-fin"
    print(f"Rango pkts : {rango_str}")
    print("Normalize : True")

    result = _collect_csi_packets_interval(FILE, packet_start, packet_end, BW_FALLBACK)
    csi_vectors = result["csi_vectors"]
    packets_info = result["packets_info"]
    core_groups = result["core_groups"]
    core_packets = result["core_packets"]

    if not csi_vectors:
        print("Sin paquetes válidos (bcm4366c0) para visualizar.")
        return

    bandwidth_counts = Counter(pkt["bandwidth"] for pkt in packets_info)
    print("Anchuras detectadas (MHz):", dict(bandwidth_counts))
    capture_seconds = _extract_capture_seconds_from_filename(Path(FILE).name)
    avg_rate = len(csi_vectors) / capture_seconds
    print(f"Tasa media captura: {avg_rate:.2f} paquetes/s ({len(csi_vectors)} paquetes en {capture_seconds}s)")

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

        packet_numbers_core = [pkt.get("csi_packet_number") for pkt in core_packets.get(core, [])]
        packet_numbers_core = [pkt for pkt in packet_numbers_core if pkt is not None]

        print(f"\nVisualizando core {core} — paquetes: {len(data)}")
        _plot_heatmap(
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


if __name__ == "__main__":
    main()
