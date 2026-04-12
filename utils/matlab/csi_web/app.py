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

import io
import logging
import sys
import uuid
import tempfile
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
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from path_resolve import (
    browse_directory,
    get_gold_disk_base,
    resolve_absolute_trusted,
    resolve_pcap_under_gold_disk,
)

import csireader_master as cm

from pcap_summary import resolve_bw_fallback_mhz, summarize_pcap_file

logger = logging.getLogger(__name__)

# Tras subir, el .pcap en disco es ``{uuid}.pcap``; guardamos el nombre original para BW y etiquetas.
UPLOAD_ORIGINAL_NAMES: dict[str, str] = {}

MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MiB

STATIC_DIR = Path(__file__).resolve().parent / "static"
UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

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
    mode: Literal["browse", "upload", "absolute"]
    """browse: ruta relativa bajo GOLD_DISK; upload: file_id; absolute: ruta en el servidor."""

    browse_relative_path: str = Field(default="", description="Ruta relativa al .pcap bajo GOLD_DISK")
    file_id: str = Field(default="", description="UUID devuelto por POST /api/upload")
    absolute_path: str = Field(default="", description="Ruta absoluta local (solo confianza)")
    packet_range: str = Field(default="", description="Mismo formato que en terminal")


def _resolve_pcap_common(
    mode: Literal["browse", "upload", "absolute"],
    browse_relative_path: str,
    file_id: str,
    absolute_path: str,
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
    if mode == "absolute":
        if not absolute_path.strip():
            raise ValueError("Falta la ruta absoluta del .pcap")
        return resolve_absolute_trusted(absolute_path)
    raise ValueError("Modo desconocido")


def _resolve_pcap_for_preview(body: PreviewBody) -> Path:
    return _resolve_pcap_common(
        body.mode,
        body.browse_relative_path,
        body.file_id,
        body.absolute_path,
    )


def _logical_pcap_name(pcap_path: Path, mode: str, file_id: str) -> str:
    """Nombre para deducir BW (MHz) desde el título del fichero."""
    if mode == "upload":
        return UPLOAD_ORIGINAL_NAMES.get(file_id.strip(), pcap_path.name)
    return pcap_path.name


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

        packet_numbers_core = [
            pkt.get("csi_packet_number") for pkt in core_packets.get(core, [])
        ]
        packet_numbers_core = [pkt for pkt in packet_numbers_core if pkt is not None]

        cm._plot_heatmap(
            array_core,
            title=f"Amplitude Heatmap — Core {core}",
            ax=ax,
            packet_numbers=packet_numbers_core
            if len(packet_numbers_core) == len(data)
            else None,
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


class FilePickBody(BaseModel):
    mode: Literal["browse", "upload", "absolute"]
    browse_relative_path: str = Field(default="")
    file_id: str = Field(default="")
    absolute_path: str = Field(default="")


@app.post("/api/file-summary")
def api_file_summary(body: FilePickBody) -> dict:
    try:
        pcap_path = _resolve_pcap_common(
            body.mode,
            body.browse_relative_path,
            body.file_id,
            body.absolute_path,
        )
        name_for_bw = None
        if body.mode == "upload":
            name_for_bw = UPLOAD_ORIGINAL_NAMES.get(body.file_id.strip())
        return summarize_pcap_file(str(pcap_path), name_for_bw=name_for_bw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error en resumen de PCAP")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


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
