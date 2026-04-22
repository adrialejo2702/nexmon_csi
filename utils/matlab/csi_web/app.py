"""
CSI Web — vista previa PNG al estilo csireader_master (bcm4366c0).

Ejecución local (desde esta carpeta ``csi_web``)::

    python3 -m venv .venv
    source .venv/bin/activate   # Windows: .venv\\Scripts\\activate
    pip install -r requirements.txt
    uvicorn app:app --reload --host 127.0.0.1 --port 8000

Abre http://127.0.0.1:8000/

Advertencias:
- Uso previsto: máquina local de confianza. El modo «ruta absoluta» y el
  explorador permiten leer ficheros que el usuario del proceso pueda leer.
- No expongas este servicio a Internet sin autenticación y hardening.
- Matplotlib con backend Agg: evita abrir ventanas; adecuado para servidor.
- Ficheros grandes: la subida está limitada por tamaño (ver MAX_UPLOAD_BYTES).
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Literal

# Directorio utils/matlab (padre de csi_web)
_MATLAB_DIR = Path(__file__).resolve().parent.parent
if str(_MATLAB_DIR) not in sys.path:
    sys.path.insert(0, str(_MATLAB_DIR))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from path_resolve import (
    browse_directory,
    get_gold_disk_base,
    resolve_pcap_under_gold_disk,
)

import csireader_master as cm
import export_csimaster_window_images as cwi

from pcap_summary import resolve_bw_fallback_mhz, summarize_pcap_file

logger = logging.getLogger(__name__)

# Tras subir, el .pcap en disco es ``{uuid}.pcap``; guardamos el nombre original para BW y etiquetas.
UPLOAD_ORIGINAL_NAMES: dict[str, str] = {}
ALLOWED_LABELS = {"movimiento", "vacio", "quieto"}
PYTHON_PREVIEW_PROCESS: subprocess.Popen | None = None

MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MiB

STATIC_DIR = Path(__file__).resolve().parent / "static"
UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
PYTHON_PREVIEW_LOG = UPLOAD_DIR / "python_preview.log"

GOLD_DISK_BASE = get_gold_disk_base(_MATLAB_DIR)

app = FastAPI(title="CSI Web", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


@app.get("/api/browse")
def api_browse(path: str = "") -> dict:
    try:
        return browse_directory(GOLD_DISK_BASE, path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _validate_upload_file_id(file_id: str) -> None:
    try:
        uuid.UUID(file_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="file_id inválido") from exc


def _ensure_upload_file_id(file_id: str) -> None:
    try:
        uuid.UUID(file_id)
    except ValueError as exc:
        raise ValueError("file_id inválido") from exc


@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)) -> dict:
    if not file.filename or not file.filename.lower().endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Se espera un archivo .pcap")
    file_id = str(uuid.uuid4())
    dest = UPLOAD_DIR / f"{file_id}.pcap"
    body = await file.read()
    if len(body) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Archivo demasiado grande (máx. {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB)",
        )
    dest.write_bytes(body)
    UPLOAD_ORIGINAL_NAMES[file_id] = file.filename or "upload.pcap"
    return {"file_id": file_id, "name": file.filename}


class PreviewBody(BaseModel):
    mode: Literal["browse", "upload"]
    """browse: ruta relativa bajo GOLD_DISK; upload: file_id."""

    browse_relative_path: str = Field(default="", description="Ruta relativa al .pcap bajo GOLD_DISK")
    file_id: str = Field(default="", description="UUID devuelto por POST /api/upload")
    packet_range: str = Field(default="", description="Mismo formato que en terminal")


def _resolve_pcap_common(
    mode: Literal["browse", "upload"],
    browse_relative_path: str,
    file_id: str,
) -> Path:
    if mode == "browse":
        return resolve_pcap_under_gold_disk(GOLD_DISK_BASE, browse_relative_path)
    if mode == "upload":
        if not file_id.strip():
            raise ValueError("Falta file_id (sube primero el .pcap)")
        _ensure_upload_file_id(file_id.strip())
        p = UPLOAD_DIR / f"{file_id.strip()}.pcap"
        if not p.is_file():
            raise ValueError("No existe la subida indicada (puede haber caducado si borraste uploads/)")
        return p
    raise ValueError("Modo desconocido")


def _resolve_pcap_for_preview(body: PreviewBody) -> Path:
    return _resolve_pcap_common(
        body.mode,
        body.browse_relative_path,
        body.file_id,
    )


def _logical_pcap_name(pcap_path: Path, mode: str, file_id: str) -> str:
    """Nombre para deducir BW (MHz) desde el título del fichero."""
    if mode == "upload":
        return UPLOAD_ORIGINAL_NAMES.get(file_id.strip(), pcap_path.name)
    return pcap_path.name


def _labels_json_path(pcap_path: Path, logical_name: str) -> Path:
    out_dir = pcap_path.parent / Path(logical_name).stem
    return out_dir / "labels.json"


def _load_labels(pcap_path: Path, logical_name: str) -> list[dict]:
    path = _labels_json_path(pcap_path, logical_name)
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    labels = data.get("labels", [])
    if not isinstance(labels, list):
        return []
    out = []
    for item in labels:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label", ""))
        start = int(item.get("start_packet", 0))
        end = int(item.get("end_packet", 0))
        core_raw = item.get("core", "all")
        core = str(core_raw).strip().lower()
        if core.startswith("core"):
            core = core[4:]
        if core not in {"all", "0", "1", "2", "3"}:
            core = "all"
        if label in ALLOWED_LABELS and start > 0 and end >= start:
            out.append({"label": label, "start_packet": start, "end_packet": end, "core": core})
    return out


def _save_labels(pcap_path: Path, logical_name: str, labels: list[dict]) -> Path:
    path = _labels_json_path(pcap_path, logical_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "pcap_name": logical_name,
        "labels": labels,
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


_WINDOW_FILE_RE = re.compile(r"^img_\d+_pkts_(\d+)_(\d+)(?:_gray)?\.png$", re.IGNORECASE)


def _parse_window_packet_interval_from_name(file_name: str) -> tuple[int, int] | None:
    m = _WINDOW_FILE_RE.match(file_name)
    if not m:
        return None
    start = int(m.group(1))
    end = int(m.group(2))
    if start <= 0 or end < start:
        return None
    return start, end


def _best_label_for_window(start: int, end: int, labels: list[dict], *, core: int | None = None) -> str | None:
    best_label = None
    best_overlap = 0
    for item in labels:
        item_core = str(item.get("core", "all")).strip().lower()
        if item_core.startswith("core"):
            item_core = item_core[4:]
        if core is not None and item_core not in {"all", str(core)}:
            continue
        ls = int(item["start_packet"])
        le = int(item["end_packet"])
        ov = min(end, le) - max(start, ls) + 1
        if ov > best_overlap:
            best_overlap = ov
            best_label = str(item["label"])
    return best_label if best_overlap > 0 else None


def _export_images_info(pcap_path: Path, logical_name: str) -> dict:
    """Estado de exportación existente para el fichero seleccionado."""
    out_dir = pcap_path.parent / Path(logical_name).stem
    rgb_dir = out_dir / "rgb"
    gray_dir = out_dir / "gray"
    rgb_count = len(list(rgb_dir.glob("*.png"))) if rgb_dir.exists() else 0
    gray_count = len(list(gray_dir.glob("*.png"))) if gray_dir.exists() else 0
    return {
        "export_images_exist": (rgb_count + gray_count) > 0,
        "export_rgb_count": rgb_count,
        "export_gray_count": gray_count,
    }


def export_window_images(
    pcap_path: Path,
    logical_name: str,
    *,
    generate_rgb: bool,
    generate_gray: bool,
    regenerate_existing: bool,
    export_with_label_name: bool,
) -> dict:
    """Exporta imágenes por ventanas de ~1s con solape del 50%."""
    if not generate_rgb and not generate_gray:
        raise ValueError("Debes seleccionar al menos una opción de exportación (RGB o Gray).")

    base_stem = Path(logical_name).stem
    out_stem = f"{base_stem}_edge_impulse" if export_with_label_name else base_stem
    out_dir = pcap_path.parent / out_stem
    labels: list[dict] = []
    if export_with_label_name:
        labels = _load_labels(pcap_path, logical_name)
        if not labels:
            raise ValueError(
                "No hay etiquetas guardadas para este fichero. "
                "Guárdalas antes de exportar con nombre de etiqueta."
            )

    bw = resolve_bw_fallback_mhz(logical_name)
    with contextlib.redirect_stdout(io.StringIO()):
        result = cm._collect_csi_packets_interval(
            str(pcap_path),
            packet_start=1,
            packet_end=None,
            fallback_bw=int(bw),
        )
    csi_vectors = result["csi_vectors"]
    if not csi_vectors:
        raise ValueError("No hay paquetes CSI válidos para generar imágenes.")
    duration_seconds = cm._extract_capture_seconds_from_filename(Path(logical_name).name)
    core_groups = result["core_groups"]
    core_packets = result["core_packets"]

    core_ids = sorted(core_groups.keys())
    represented_cores = max(1, len(core_ids))
    if export_with_label_name and not core_ids:
        raise ValueError("No hay cores disponibles para exportación Edge Impulse.")

    # Salidas siempre separadas por core (con y sin etiquetas).
    rgb_dirs = {core: (out_dir / f"core{core}" / "rgb") for core in core_ids}
    gray_dirs = {core: (out_dir / f"core{core}" / "gray") for core in core_ids}
    rgb_blocked = generate_rgb and any(cwi._has_png_files(d) for d in rgb_dirs.values())
    gray_blocked = generate_gray and any(cwi._has_png_files(d) for d in gray_dirs.values())

    if (rgb_blocked or gray_blocked) and not regenerate_existing:
        return {
            "status": "skipped_existing",
            "out_dir": str(out_dir),
            "rgb_dir": str(next(iter(rgb_dirs.values()))) if generate_rgb else None,
            "gray_dir": str(next(iter(gray_dirs.values()))) if generate_gray else None,
            "message": "La carpeta de salida ya contiene imágenes generadas.",
            "windows_generated": 0,
            "window_packets": None,
            "stride_packets": None,
            "packet_rate_real": None,
            "duration_seconds": None,
            "csi_packets_valid": None,
        }

    if generate_rgb:
        for d in rgb_dirs.values():
            d.mkdir(parents=True, exist_ok=True)
    if generate_gray:
        for d in gray_dirs.values():
            d.mkdir(parents=True, exist_ok=True)

    total_packets_sum = 0
    total_windows_sum = 0
    labeled_generated = 0
    unlabeled_skipped = 0
    packet_rate_real_last = 0.0
    window_packets_last = 0
    stride_packets_last = 0

    processing_cores = core_ids
    for core in processing_cores:
        core_vectors = core_groups.get(core, [])
        core_pkts = core_packets.get(core, [])
        if not core_vectors:
            continue

        csi_matrix = cwi._build_csi_matrix(core_vectors)
        total_packets = csi_matrix.shape[0]
        total_packets_sum += total_packets
        packet_rate_real = total_packets / float(duration_seconds)
        window_packets = cwi._round_down_to_ten(packet_rate_real)
        if window_packets <= 0:
            continue
        stride_packets = max(1, window_packets // 2)
        total_windows = cwi._window_count(total_packets, window_packets, stride_packets)
        if total_windows <= 0:
            continue

        packet_numbers_core_global = [pkt.get("csi_packet_number") for pkt in core_pkts]
        packet_numbers_core_global = [int(pkt) for pkt in packet_numbers_core_global if pkt is not None]
        if len(packet_numbers_core_global) != total_packets:
            packet_numbers_core_global = list(range(1, total_packets + 1))
        packet_numbers_core_local = list(range(1, total_packets + 1))

        packet_rate_real_last = packet_rate_real
        window_packets_last = window_packets
        stride_packets_last = stride_packets
        total_windows_sum += total_windows

        for window_idx in range(total_windows):
            start = window_idx * stride_packets
            end = start + window_packets
            window = csi_matrix[start:end, :]
            # Numeración local (1..N del core) para el nombre del archivo.
            start_pkt_local = packet_numbers_core_local[start]
            end_pkt_local = packet_numbers_core_local[end - 1]
            # Numeración global para lógica de solape con etiquetas.
            start_pkt_global = packet_numbers_core_global[start]
            end_pkt_global = packet_numbers_core_global[end - 1]

            label_prefix = ""
            if export_with_label_name:
                label = _best_label_for_window(start_pkt_global, end_pkt_global, labels, core=core)
                if not label:
                    unlabeled_skipped += 1
                    continue
                safe_label = re.sub(r"[^A-Za-z0-9_-]+", "_", label).strip("_") or "unlabeled"
                label_prefix = f"{safe_label}."

            if generate_rgb:
                image_name_rgb = (
                    f"{label_prefix}img_{window_idx + 1:06d}_pkts_{start_pkt_local:06d}_{end_pkt_local:06d}.png"
                )
                out_file_rgb = rgb_dirs[core] / image_name_rgb
                cwi._save_window_image(window, out_file_rgb, normalize=True, cmap="jet")
            if generate_gray:
                image_name_gray = (
                    f"{label_prefix}img_{window_idx + 1:06d}_pkts_{start_pkt_local:06d}_{end_pkt_local:06d}_gray.png"
                )
                out_file_gray = gray_dirs[core] / image_name_gray
                cwi._save_window_image_gray(window, out_file_gray, normalize=True)
            if export_with_label_name:
                labeled_generated += 1

    return {
        "status": "ok",
        "out_dir": str(out_dir),
        "rgb_dir": str(next(iter(rgb_dirs.values()))) if generate_rgb else None,
        "gray_dir": str(next(iter(gray_dirs.values()))) if generate_gray else None,
        "windows_generated": int(total_windows_sum),
        "window_packets": int(window_packets_last) if window_packets_last else None,
        "stride_packets": int(stride_packets_last) if stride_packets_last else None,
        "packet_rate_real": float(round(packet_rate_real_last, 6)) if packet_rate_real_last else None,
        "cores_detected": int(represented_cores),
        "duration_seconds": int(duration_seconds),
        "csi_packets_valid": int(total_packets_sum),
        "bw_fallback_mhz": int(bw),
        "export_with_label_name": bool(export_with_label_name),
        "labeled_windows_generated": int(labeled_generated if export_with_label_name else total_windows_sum),
        "unlabeled_windows_skipped": int(unlabeled_skipped if export_with_label_name else 0),
    }


def build_preview_png(pcap_path: Path, packet_range: str, bw_fallback: int) -> bytes:
    try:
        packet_start, packet_end = cm._parse_packet_range_spec(packet_range)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    result = cm._collect_csi_packets_interval(
        str(pcap_path),
        packet_start,
        packet_end,
        bw_fallback,
    )
    csi_vectors = result["csi_vectors"]
    core_groups = result["core_groups"]
    core_packets = result["core_packets"]

    if not csi_vectors:
        raise ValueError("Sin paquetes CSI válidos (bcm4366c0) para visualizar.")

    core_items = [
        (core, core_groups[core])
        for core in sorted(core_groups.keys())
        if core_groups[core]
    ]
    if not core_items:
        raise ValueError("Sin datos por core para visualizar.")

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

    fig.suptitle("Mapas de calor por core", fontsize=14)
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=100)
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def build_preview_plot_data(pcap_path: Path, packet_range: str, bw_fallback: int) -> dict:
    try:
        packet_start, packet_end = cm._parse_packet_range_spec(packet_range)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    result = cm._collect_csi_packets_interval(
        str(pcap_path),
        packet_start,
        packet_end,
        bw_fallback,
    )
    core_groups = result["core_groups"]
    core_packets = result["core_packets"]

    core_items = [
        (core, core_groups[core])
        for core in sorted(core_groups.keys())
        if core_groups[core]
    ]
    if not core_items:
        raise ValueError("Sin datos por core para visualizar.")

    cores_data = {}
    for core, data in core_items:
        max_len_core = max(len(vec) for vec in data)
        array_core = np.zeros((len(data), max_len_core), dtype=np.complex128)
        for idx, vec in enumerate(data):
            array_core[idx, : len(vec)] = vec
        mag, subcarrier_axis = cm._prepare_magnitude_for_plot(array_core)
        row_max = np.max(mag, axis=1, keepdims=True)
        row_max[row_max == 0.0] = 1.0
        mag = mag / row_max

        num_packets = len(data)
        x_positions = list(range(1, num_packets + 1))
        tick_text = [str(x) for x in x_positions]
        x_ticks = x_positions

        y_vals = subcarrier_axis.astype(int).tolist()
        cores_data[str(core)] = {
            "x": x_positions,
            "y": y_vals,
            "z": np.round(mag.T, 6).tolist(),
            "x_tickvals": x_ticks,
            "x_ticktext": tick_text,
            "num_packets": num_packets,
        }

    return {"cores": cores_data}


@app.post("/api/preview")
def api_preview(body: PreviewBody) -> Response:
    try:
        pcap_path = _resolve_pcap_for_preview(body)
        bw = resolve_bw_fallback_mhz(
            _logical_pcap_name(pcap_path, body.mode, body.file_id),
        )
        png = build_preview_png(pcap_path, body.packet_range, bw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error generando vista previa")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return StreamingResponse(
        io.BytesIO(png),
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/preview-data")
def api_preview_data(body: PreviewBody) -> dict:
    try:
        pcap_path = _resolve_pcap_for_preview(body)
        bw = resolve_bw_fallback_mhz(_logical_pcap_name(pcap_path, body.mode, body.file_id))
        return build_preview_plot_data(pcap_path, body.packet_range, bw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error generando datos de vista previa")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


class FilePickBody(BaseModel):
    mode: Literal["browse", "upload"]
    browse_relative_path: str = Field(default="")
    file_id: str = Field(default="")


class ExportBody(FilePickBody):
    generate_rgb: bool = Field(default=True)
    generate_gray: bool = Field(default=False)
    regenerate_existing: bool = Field(default=False)
    export_with_label_name: bool = Field(default=False)


class LabelsLoadBody(BaseModel):
    mode: Literal["browse", "upload"]
    browse_relative_path: str = Field(default="")
    file_id: str = Field(default="")


class LabelItem(BaseModel):
    label: Literal["movimiento", "vacio", "quieto"]
    start_packet: int = Field(ge=1)
    end_packet: int = Field(ge=1)
    core: str = Field(default="all")


class LabelsSaveBody(LabelsLoadBody):
    labels: list[LabelItem]


class LabelsEdgeImpulseBody(LabelsLoadBody):
    include_rgb: bool = Field(default=True)
    include_gray: bool = Field(default=True)


class PythonPreviewBody(PreviewBody):
    pass


@app.post("/api/file-summary")
def api_file_summary(body: FilePickBody) -> dict:
    try:
        pcap_path = _resolve_pcap_common(
            body.mode,
            body.browse_relative_path,
            body.file_id,
        )
        logical_name = _logical_pcap_name(pcap_path, body.mode, body.file_id)
        summary = summarize_pcap_file(str(pcap_path), name_for_bw=logical_name)
        summary.update(_export_images_info(pcap_path, logical_name))
        return summary
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error en resumen de PCAP")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/export-windows")
def api_export_windows(body: ExportBody) -> dict:
    try:
        pcap_path = _resolve_pcap_common(
            body.mode,
            body.browse_relative_path,
            body.file_id,
        )
        logical_name = _logical_pcap_name(pcap_path, body.mode, body.file_id)
        return export_window_images(
            pcap_path,
            logical_name,
            generate_rgb=body.generate_rgb,
            generate_gray=body.generate_gray,
            regenerate_existing=body.regenerate_existing,
            export_with_label_name=body.export_with_label_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error exportando ventanas")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/labels/load")
def api_labels_load(body: LabelsLoadBody) -> dict:
    try:
        pcap_path = _resolve_pcap_common(body.mode, body.browse_relative_path, body.file_id)
        logical_name = _logical_pcap_name(pcap_path, body.mode, body.file_id)
        return {"labels": _load_labels(pcap_path, logical_name)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error cargando etiquetas")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/labels/save")
def api_labels_save(body: LabelsSaveBody) -> dict:
    try:
        pcap_path = _resolve_pcap_common(body.mode, body.browse_relative_path, body.file_id)
        logical_name = _logical_pcap_name(pcap_path, body.mode, body.file_id)
        labels = [item.model_dump() for item in body.labels]
        for it in labels:
            if it["end_packet"] < it["start_packet"]:
                raise ValueError("Cada etiqueta debe cumplir: fin >= inicio.")
            if it["label"] not in ALLOWED_LABELS:
                raise ValueError(f"Etiqueta no permitida: {it['label']}")
            core = str(it.get("core", "all")).strip().lower()
            if core.startswith("core"):
                core = core[4:]
            if core not in {"all", "0", "1", "2", "3"}:
                raise ValueError("Core no permitido. Usa: all, 0, 1, 2 o 3.")
            it["core"] = core
        path = _save_labels(pcap_path, logical_name, labels)
        return {"status": "ok", "saved": len(labels), "labels_file": str(path)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error guardando etiquetas")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/labels/export-edge-impulse")
def api_labels_export_edge_impulse(body: LabelsEdgeImpulseBody) -> dict:
    try:
        if not body.include_rgb and not body.include_gray:
            raise ValueError("Selecciona al menos un formato de imagen (RGB o Gray).")
        pcap_path = _resolve_pcap_common(body.mode, body.browse_relative_path, body.file_id)
        logical_name = _logical_pcap_name(pcap_path, body.mode, body.file_id)
        labels = _load_labels(pcap_path, logical_name)
        if not labels:
            raise ValueError("No hay etiquetas guardadas para este fichero.")

        out_dir = pcap_path.parent / Path(logical_name).stem
        rgb_dir = out_dir / "rgb"
        gray_dir = out_dir / "gray"
        image_paths: list[Path] = []
        if body.include_rgb and rgb_dir.exists():
            image_paths.extend(sorted(rgb_dir.glob("*.png")))
        if body.include_gray and gray_dir.exists():
            image_paths.extend(sorted(gray_dir.glob("*.png")))
        if not image_paths:
            raise ValueError("No se encontraron imágenes exportadas para generar el CSV.")

        csv_path = out_dir / "edge_impulse_labels.csv"
        written = 0
        skipped_without_label = 0
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["file", "label", "start_packet", "end_packet", "pcap"])
            for img in image_paths:
                parsed = _parse_window_packet_interval_from_name(img.name)
                if parsed is None:
                    continue
                start_pkt, end_pkt = parsed
                label = _best_label_for_window(start_pkt, end_pkt, labels)
                if not label:
                    skipped_without_label += 1
                    continue
                writer.writerow([str(img.relative_to(out_dir)), label, start_pkt, end_pkt, logical_name])
                written += 1

        return {
            "status": "ok",
            "csv_path": str(csv_path),
            "rows_written": written,
            "images_total": len(image_paths),
            "images_without_label": skipped_without_label,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error exportando etiquetas para Edge Impulse")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/preview-python")
def api_preview_python(body: PythonPreviewBody) -> dict:
    """Abre una ventana interactiva de Matplotlib (local) como en csireader_master.py."""
    global PYTHON_PREVIEW_PROCESS
    try:
        # Si hay una representación abierta, obligamos a cerrarla antes de lanzar otra.
        if PYTHON_PREVIEW_PROCESS is not None and PYTHON_PREVIEW_PROCESS.poll() is None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Ya hay una representación abierta en Python. "
                    "Ciérrala para poder representar otro intervalo."
                ),
            )

        pcap_path = _resolve_pcap_for_preview(body)
        logical_name = _logical_pcap_name(pcap_path, body.mode, body.file_id)
        bw = resolve_bw_fallback_mhz(logical_name)
        script_path = Path(__file__).resolve().parent / "python_preview_window.py"

        env = os.environ.copy()
        # Evita que un backend no interactivo heredado impida abrir la ventana.
        env.pop("MPLBACKEND", None)
        with PYTHON_PREVIEW_LOG.open("w", encoding="utf-8") as logf:
            PYTHON_PREVIEW_PROCESS = subprocess.Popen(
            [
                sys.executable,
                str(script_path),
                "--pcap",
                str(pcap_path),
                "--packet-range",
                body.packet_range or "",
                "--bw-fallback",
                str(int(bw)),
            ],
            cwd=str(_MATLAB_DIR),
            stdout=logf,
            stderr=logf,
            env=env,
        )
        time.sleep(0.35)
        rc = PYTHON_PREVIEW_PROCESS.poll()
        if rc is not None and rc != 0:
            detail = "No se pudo abrir la ventana Python."
            try:
                text = PYTHON_PREVIEW_LOG.read_text(encoding="utf-8")
                if text.strip():
                    detail = f"{detail} Detalle: {text.strip().splitlines()[-1]}"
            except Exception:
                pass
            raise HTTPException(status_code=500, detail=detail)
        return {
            "status": "started",
            "message": (
                "Representación abierta en una ventana de Python. "
                "Para representar otro intervalo, cierra primero la ventana actual."
            ),
            "pid": int(PYTHON_PREVIEW_PROCESS.pid),
        }
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error lanzando representación Python")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/preview-python-status")
def api_preview_python_status() -> dict:
    global PYTHON_PREVIEW_PROCESS
    if PYTHON_PREVIEW_PROCESS is None:
        return {"running": False}
    rc = PYTHON_PREVIEW_PROCESS.poll()
    if rc is None:
        return {"running": True, "pid": int(PYTHON_PREVIEW_PROCESS.pid)}
    # Proceso finalizado: liberar referencia para próximos lanzamientos.
    PYTHON_PREVIEW_PROCESS = None
    return {"running": False, "exit_code": int(rc)}


@app.post("/api/file-summary-local")
async def api_file_summary_local(
    file: UploadFile = File(...),
) -> dict:
    if not file.filename or not file.filename.lower().endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Se espera un archivo .pcap")
    body = await file.read()
    if len(body) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Archivo demasiado grande (máx. {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB)",
        )
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(body)
            tmp_path = tmp.name
        try:
            return summarize_pcap_file(tmp_path, name_for_bw=file.filename)
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    except Exception as exc:
        logger.exception("Error en resumen de PCAP local")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
