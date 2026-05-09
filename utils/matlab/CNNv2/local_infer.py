#!/usr/bin/env python3
import json
import subprocess
import tempfile
import zlib
from pathlib import Path
from typing import Dict, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
EXPECTED_SIZE = (85, 50)
CORES = ("core0", "core1", "core2", "core3")


def _binary_for_core(core: str) -> Path:
    if core not in CORES:
        raise ValueError(f"Core no soportado: {core}")
    binary = BASE_DIR / "build" / core / "app"
    if not binary.exists():
        raise FileNotFoundError(
            f"No existe el binario local para {core}: {binary}. "
            "Compila primero con: python3 build_local_models.py"
        )
    return binary


def _read_png_pixels(image_path: Path) -> Tuple[int, int, list[int]]:
    data = image_path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError(f"Formato no soportado para inferencia local sin Pillow: {image_path.suffix}")

    pos = 8
    width = height = color_type = bit_depth = None
    compressed = bytearray()
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        chunk_type = data[pos + 4:pos + 8]
        chunk_data = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if chunk_type == b"IHDR":
            width = int.from_bytes(chunk_data[0:4], "big")
            height = int.from_bytes(chunk_data[4:8], "big")
            bit_depth = chunk_data[8]
            color_type = chunk_data[9]
        elif chunk_type == b"IDAT":
            compressed.extend(chunk_data)
        elif chunk_type == b"IEND":
            break

    if width is None or height is None or color_type is None or bit_depth is None:
        raise ValueError(f"PNG no valido: {image_path}")
    if bit_depth != 8:
        raise ValueError(f"PNG con bit depth {bit_depth} no soportado: {image_path}")
    channels_by_type = {0: 1, 2: 3, 4: 2, 6: 4}
    if color_type not in channels_by_type:
        raise ValueError(f"PNG color type {color_type} no soportado: {image_path}")

    channels = channels_by_type[color_type]
    row_bytes = width * channels
    raw = zlib.decompress(bytes(compressed))
    expected_len = height * (row_bytes + 1)
    if len(raw) != expected_len:
        raise ValueError(f"Tamano PNG inesperado en {image_path}: {len(raw)} != {expected_len}")

    rows: list[bytearray] = []
    idx = 0
    for _ in range(height):
        filter_type = raw[idx]
        idx += 1
        row = bytearray(raw[idx:idx + row_bytes])
        idx += row_bytes
        prev = rows[-1] if rows else bytearray(row_bytes)
        for i in range(row_bytes):
            left = row[i - channels] if i >= channels else 0
            up = prev[i]
            up_left = prev[i - channels] if i >= channels else 0
            if filter_type == 1:
                row[i] = (row[i] + left) & 0xFF
            elif filter_type == 2:
                row[i] = (row[i] + up) & 0xFF
            elif filter_type == 3:
                row[i] = (row[i] + ((left + up) // 2)) & 0xFF
            elif filter_type == 4:
                p = left + up - up_left
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - up_left)
                predictor = left if pa <= pb and pa <= pc else (up if pb <= pc else up_left)
                row[i] = (row[i] + predictor) & 0xFF
            elif filter_type != 0:
                raise ValueError(f"Filtro PNG {filter_type} no soportado: {image_path}")
        rows.append(row)

    pixels: list[int] = []
    for row in rows:
        for x in range(width):
            offset = x * channels
            if color_type == 0:
                gray = row[offset]
                pixels.append((gray << 16) | (gray << 8) | gray)
            elif color_type in (2, 6):
                r, g, b = row[offset], row[offset + 1], row[offset + 2]
                pixels.append((r << 16) | (g << 8) | b)
            elif color_type == 4:
                gray = row[offset]
                pixels.append((gray << 16) | (gray << 8) | gray)
    return width, height, pixels


def image_to_features(image_path: Path) -> str:
    if not image_path.exists() or not image_path.is_file():
        raise FileNotFoundError(f"La imagen no existe: {image_path}")

    width, height, values = _read_png_pixels(image_path)
    if (width, height) != EXPECTED_SIZE:
        raise ValueError(
            f"La imagen {image_path} mide {width}x{height}, "
            f"pero el modelo espera {EXPECTED_SIZE[0]}x{EXPECTED_SIZE[1]}."
        )
    if len(values) != EXPECTED_SIZE[0] * EXPECTED_SIZE[1]:
        raise ValueError(f"Numero de pixeles inesperado en {image_path}: {len(values)}")
    return "\n".join(str(v) for v in values)


def classify_image_local(core: str, image_path: Path, timeout_seconds: int = 60) -> Dict:
    binary = _binary_for_core(core)
    features = image_to_features(image_path)
    with tempfile.NamedTemporaryFile("w", suffix=".features.txt", encoding="utf-8", delete=True) as f:
        f.write(features)
        f.flush()
        completed = subprocess.run(
            [str(binary), f.name],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )

    output = completed.stdout.strip()
    if not output:
        stderr = completed.stderr.strip()
        raise RuntimeError(f"El clasificador local de {core} no devolvio salida. stderr={stderr}")
    try:
        payload = json.loads(output.splitlines()[-1])
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Salida JSON no valida de {core}: {output}") from exc

    if completed.returncode != 0 and payload.get("success") is not False:
        payload["success"] = False
        payload["error"] = payload.get("error") or completed.stderr.strip() or f"returncode={completed.returncode}"
    return payload


def extract_top_result(api_response: Dict) -> Tuple[Optional[str], Optional[float]]:
    result = api_response.get("result", {})
    if not isinstance(result, dict) or not result:
        return None, None
    top_label = max(result, key=result.get)
    return top_label, float(result[top_label])
