"""Lector de CSI para bcm4366c0 (formato extendido PR #256).

Misma lógica que csireader_master.py pero sin representación gráfica.
Muestra por terminal la información de los primeros 8 paquetes y los 18 bytes
del header (magic incluido) a partir de la detección de los magic bits.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import struct

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

    # En las capturas reales de bcm4366c0:
    #  - el byte alto de csiconf (bits 8-15) codifica el core: 0x00, 0x01, 0x02, 0x03
    #  - el spatial stream observado es siempre 0
    core = (csiconf >> 8) & 0xFF
    spatial_stream = 0

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


def _collect_csi_packets(
    file_path: str,
    max_packets: int,
    fallback_bw: int,
    debug_count: int = 8,
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
    debug_data: List[Tuple[int, dict, bytes]] = []  # (packet_idx, header, header_bytes)

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

        if len(debug_data) < debug_count:
            header_bytes = payload_bytes[header_offset : header_offset + HEADER_SIZE]
            debug_data.append((packet_idx, header, header_bytes))

        processed += 1

    reader.close()

    print("\n========= RESUMEN =========")
    print(f"Total paquetes en PCAP: {len(frames)}")
    print(f"Procesados    : {processed}")
    print(f"Saltados      : {skipped}")

    return {
        "csi_vectors": csi_vectors,
        "packets_info": packets_info,
        "core_groups": core_groups,
        "core_packets": core_packets,
        "debug_data": debug_data,
    }


def main() -> None:
    FILE = "./pcap_files/mydata/GOLD_DISK/captura_noFilter_1x1_30s_36_20_20260310_201629.pcap"
    BW_FALLBACK = 20
    NPKTS_MAX = 40000
    DEBUG_PACKETS = 8

    print("CSI Reader — bcm4366c0 (datos decodificados, sin heatmap)")
    print("=" * 60)
    print(f"Archivo   : {FILE}")
    print(f"Fallback BW (cuando header=0): {BW_FALLBACK} MHz")
    print(f"Máx. pkts : {NPKTS_MAX}")
    print(f"Mostrando primeros {DEBUG_PACKETS} paquetes con 18 bytes de header (magic incluido)")
    print()

    result = _collect_csi_packets(FILE, NPKTS_MAX, BW_FALLBACK, debug_count=DEBUG_PACKETS)
    debug_data = result["debug_data"]

    if not debug_data:
        print("Sin paquetes válidos (bcm4366c0) para mostrar.")
        return

    print("\n========= PRIMEROS 8 PAQUETES — 18 BYTES DE HEADER (magic incluido) =========")
    print()

    for pkt_idx, _, header_bytes in debug_data:
        hex_str = " ".join(f"{b:02X}" for b in header_bytes)
        print(f"Paquete #{pkt_idx:04d}")
        print(hex_str)

    print("========= FIN =========")


if __name__ == "__main__":
    main()
