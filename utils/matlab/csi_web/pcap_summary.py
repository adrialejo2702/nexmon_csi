"""Resumen de PCAP: frames totales, CSI válidos (bcm4366c0) y tasa usando duración del nombre de fichero."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import numpy as np

from readpcap import ReadPcap

import csireader_master as cm

# Anchos típicos (MHz) en nombres tipo asus_auto: ..._${CANAL}_${BW}.pcap
_COMMON_BW_MHZ = frozenset({5, 10, 20, 40, 80, 160})


def extract_bw_mhz_from_filename(file_name: str) -> int | None:
    """
    Intenta leer el BW en MHz desde convenciones como:
    ``captura_*_*_*s_*_*_YYYYMMDD_HHMMSS.pcap`` (BW antes de la fecha) o
    ``..._${CANAL}_${BW}.pcap`` (últimos dos números).
    """
    # ..._30s_36_20_20260315_170304.pcap
    m = re.search(r"_(\d+)s_(\d+)_(\d+)_\d{8}_\d{6}\.pcap$", file_name, re.I)
    if m:
        return int(m.group(3))
    # ..._30s_36_20.pcap (sin fecha en el nombre)
    m = re.search(r"_(\d+)s_(\d+)_(\d+)\.pcap$", file_name, re.I)
    if m:
        return int(m.group(3))
    # ..._36_20.pcap (canal_BW al final)
    m = re.search(r"_(\d+)_(\d+)\.pcap$", file_name, re.I)
    if m:
        bw = int(m.group(2))
        if bw in _COMMON_BW_MHZ:
            return bw
    return None


def resolve_bw_fallback_mhz(file_name: str) -> int:
    """BW en MHz cuando el header trae 0: nombre del fichero o 20 por defecto."""
    ext = extract_bw_mhz_from_filename(file_name)
    return ext if ext is not None else 20


def summarize_pcap_file(file_path: str, *, name_for_bw: str | None = None) -> dict[str, Any]:
    """
    Un solo recorrido del PCAP: cuenta frames y paquetes CSI decodificables (misma lógica
    que ``_collect_csi_packets_interval`` pero sin construir vectores ni imprimir).

    ``name_for_bw``: nombre lógico del .pcap (p. ej. original al subir) si la ruta
    en disco no conserva el título (UUID).
    """
    path = Path(file_path)
    label = name_for_bw if name_for_bw is not None else path.name
    bw_fallback = resolve_bw_fallback_mhz(label)
    reader = ReadPcap()
    reader.open(str(path))
    frames_total = 0
    csi_packets_valid = 0
    skipped = 0
    try:
        while True:
            frame = reader.next()
            if frame is None:
                break
            frames_total += 1
            payload = frame["payload"]

            try:
                header, valid, header_offset = cm._parse_csi_udp_header(payload)
            except Exception:
                skipped += 1
                continue

            if not valid:
                skipped += 1
                continue

            if header["chip_version"] not in cm.ACCEPTED_CHIP_IDS:
                skipped += 1
                continue

            actual_bw = header["bandwidth"] or bw_fallback
            nfft = int(actual_bw * 3.2)
            csi_offset_bytes = header_offset + cm.HEADER_SIZE

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
                if end > len(payload_bytes):
                    skipped += 1
                    continue
                raw_slice = payload_bytes[start:end]
                raw_words = np.frombuffer(raw_slice, dtype=np.uint32)

            if len(raw_words) < nfft:
                skipped += 1
                continue

            csi_packets_valid += 1
    finally:
        reader.close()

    file_name = label
    duration_seconds: int | None = None
    duration_note: str | None = None
    try:
        duration_seconds = cm._extract_capture_seconds_from_filename(file_name)
    except ValueError as exc:
        duration_note = str(exc)

    avg_frames_per_second: float | None = None
    avg_csi_packets_per_second: float | None = None
    if duration_seconds is not None and duration_seconds > 0:
        avg_frames_per_second = round(frames_total / duration_seconds, 2)
        avg_csi_packets_per_second = round(csi_packets_valid / duration_seconds, 2)

    return {
        "file_name": file_name,
        "frames_total": frames_total,
        "csi_packets_valid": csi_packets_valid,
        "skipped_non_csi": skipped,
        "duration_seconds": duration_seconds,
        "duration_note": duration_note,
        "avg_frames_per_second": avg_frames_per_second,
        "avg_csi_packets_per_second": avg_csi_packets_per_second,
        "bw_fallback_mhz": bw_fallback,
    }
