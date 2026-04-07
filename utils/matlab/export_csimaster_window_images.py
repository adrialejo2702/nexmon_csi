"""
Genera imágenes CSI por ventanas deslizantes para entrenamiento de redes neuronales.

Reutiliza la misma decodificación de `csireader_master.py` (bcm4366c0), y guarda
las imágenes en una carpeta con el mismo nombre base del archivo `.pcap`.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import sys
from pathlib import Path

import matplotlib
import numpy as np

# Backend no interactivo para exportar PNG sin abrir ventanas.
matplotlib.use("Agg", force=True)
import matplotlib.pyplot as plt  # noqa: E402


def _resolve_pcap_path(base_dir: Path, user_input: str) -> Path:
    raw = (user_input or "").strip()
    if not raw:
        raise ValueError("Debes indicar una ruta de archivo .pcap.")

    raw_path = Path(raw).expanduser()
    candidates: list[Path] = []

    if raw_path.is_absolute():
        candidates.append(raw_path.resolve())
    else:
        # 1) Relativa al directorio actual de ejecución (ej. utils/matlab/...).
        candidates.append(raw_path.resolve())
        # 2) Relativa a GOLD_DISK (comportamiento original).
        candidates.append((base_dir / raw_path).resolve())

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            if candidate.suffix.lower() != ".pcap":
                raise ValueError(f"El archivo no es .pcap: {candidate}")
            return candidate

    raise FileNotFoundError(
        "No existe el archivo PCAP en ninguna ruta probada:\n"
        + "\n".join(f"- {cand}" for cand in candidates)
    )


def _build_csi_matrix(csi_vectors: list[np.ndarray]) -> np.ndarray:
    if not csi_vectors:
        return np.empty((0, 0), dtype=np.complex128)

    max_len = max(len(vec) for vec in csi_vectors)
    matrix = np.zeros((len(csi_vectors), max_len), dtype=np.complex128)
    for idx, vec in enumerate(csi_vectors):
        matrix[idx, : len(vec)] = vec
    return matrix


def _window_count(num_packets: int, window_packets: int, stride_packets: int) -> int:
    if num_packets < window_packets:
        return 0
    return ((num_packets - window_packets) // stride_packets) + 1


def _extract_duration_seconds_from_name(pcap_path: Path) -> int:
    match = re.search(r"(\d+)s(?:_|$)", pcap_path.stem)
    if not match:
        raise ValueError(
            "No se pudo extraer la duración en segundos del nombre del archivo. "
            "Se esperaba un patrón como '1200s'."
        )
    seconds = int(match.group(1))
    if seconds <= 0:
        raise ValueError(f"Duración no válida en el nombre del archivo: {seconds}s")
    return seconds


def _round_down_to_ten(value: float) -> int:
    return int(value // 10) * 10


def _has_png_files(folder: Path) -> bool:
    return folder.exists() and any(folder.glob("*.png"))


def _save_window_image(
    window_csi: np.ndarray,
    out_file: Path,
    *,
    normalize: bool,
    cmap: str,
) -> None:
    shifted = np.fft.fftshift(window_csi, axes=1)
    magnitude = np.abs(shifted)

    if normalize:
        max_value = float(np.max(magnitude))
        if max_value > 0.0:
            magnitude = magnitude / max_value

    # Imagen "limpia" para red neuronal (sin ejes, títulos ni colorbar).
    plt.figure(figsize=(4, 4), dpi=100)
    plt.imshow(magnitude.T, aspect="auto", cmap=cmap, interpolation="nearest")
    plt.axis("off")
    plt.tight_layout(pad=0)
    plt.savefig(out_file, dpi=100, bbox_inches="tight", pad_inches=0)
    plt.close()


def _save_window_image_gray(
    window_csi: np.ndarray,
    out_file: Path,
    *,
    normalize: bool,
) -> None:
    shifted = np.fft.fftshift(window_csi, axes=1)
    magnitude = np.abs(shifted)

    if normalize:
        max_value = float(np.max(magnitude))
        if max_value > 0.0:
            magnitude = magnitude / max_value

    gray = np.clip(magnitude * 255.0, 0.0, 255.0).astype(np.uint8)
    plt.figure(figsize=(4, 4), dpi=100)
    plt.imshow(gray.T, aspect="auto", cmap="gray", interpolation="nearest", vmin=0, vmax=255)
    plt.axis("off")
    plt.tight_layout(pad=0)
    plt.savefig(out_file, dpi=100, bbox_inches="tight", pad_inches=0)
    plt.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Genera imágenes CSI por ventanas (1s aprox con tasa real), "
            "reutilizando la decodificación de csireader_master.py."
        )
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        help="Ruta del .pcap (absoluta o relativa a utils/matlab/pcap_files/mydata/GOLD_DISK).",
    )
    parser.add_argument("--bw-fallback", type=int, default=20, help="BW fallback (MHz) si header=0.")
    parser.add_argument("--no-normalize", action="store_true", help="Desactiva normalización por ventana.")
    parser.add_argument("--cmap", default="jet", help="Mapa de color para guardar imágenes (por defecto: jet).")
    parser.add_argument(
        "--generate-gray",
        action="store_true",
        help="Si se indica, además genera imágenes en escala de grises en la carpeta gray.",
    )
    parser.add_argument(
        "--regenerate-existing",
        action="store_true",
        help="Si se indica, regenera imágenes aunque la carpeta de salida ya tenga PNG.",
    )

    args = parser.parse_args()

    this_dir = Path(__file__).resolve().parent
    if str(this_dir) not in sys.path:
        sys.path.insert(0, str(this_dir))

    from csireader_master import _collect_csi_packets_interval  # type: ignore

    pcap_base = this_dir / "pcap_files" / "mydata" / "GOLD_DISK"
    pcap_input = args.pcap
    if not pcap_input:
        pcap_input = input(
            "Introduce la ruta del .pcap (relativa a "
            f"{pcap_base} o absoluta): "
        ).strip()

    try:
        pcap_path = _resolve_pcap_path(pcap_base, pcap_input)
    except (ValueError, FileNotFoundError) as exc:
        print(exc)
        return 2

    out_dir = pcap_path.parent / pcap_path.stem
    out_rgb_dir = out_dir / "rgb"
    out_gray_dir = out_dir / "gray"

    rgb_exists = _has_png_files(out_rgb_dir)
    gray_exists = _has_png_files(out_gray_dir)
    if (rgb_exists or gray_exists) and not args.regenerate_existing:
        print("La carpeta de salida ya contiene imágenes generadas.")
        print(f"Salida detectada: {out_dir}")
        print("No se regenera para evitar trabajo duplicado.")
        print("Usa --regenerate-existing si quieres regenerarlas.")
        return 0

    out_rgb_dir.mkdir(parents=True, exist_ok=True)
    if args.generate_gray:
        out_gray_dir.mkdir(parents=True, exist_ok=True)

    print("Generador de imágenes CSI por ventana")
    print("=" * 60)
    print(f"PCAP           : {pcap_path}")
    print(f"Salida         : {out_dir}")
    print(f"Gray activado  : {args.generate_gray}")

    # Silencia salida detallada del lector base.
    with contextlib.redirect_stdout(io.StringIO()):
        result = _collect_csi_packets_interval(
            str(pcap_path),
            packet_start=1,
            packet_end=None,
            fallback_bw=int(args.bw_fallback),
        )
    csi_vectors = result["csi_vectors"]
    if not csi_vectors:
        print("No hay paquetes CSI válidos para generar imágenes.")
        return 1

    csi_matrix = _build_csi_matrix(csi_vectors)
    total_packets = csi_matrix.shape[0]
    try:
        duration_seconds = _extract_duration_seconds_from_name(pcap_path)
    except ValueError as exc:
        print(exc)
        return 2

    packet_rate_real = total_packets / float(duration_seconds)
    window_packets = _round_down_to_ten(packet_rate_real)
    if window_packets <= 0:
        print(
            "La tasa real calculada es demasiado baja para redondear por decenas. "
            f"Tasa real: {packet_rate_real:.6f} pkt/s"
        )
        return 2
    stride_packets = max(1, window_packets // 2)

    print(f"Duración (s)   : {duration_seconds}")
    print(f"Tasa real (pkt/s): {packet_rate_real:.6f}")
    print(f"Ventana (pkts) : {window_packets} (1s aprox, redondeo por decenas hacia abajo)")
    print(f"Stride (pkts)  : {stride_packets} (solape 50%)")

    total_windows = _window_count(total_packets, window_packets, stride_packets)
    if total_windows <= 0:
        print(
            f"No hay suficientes paquetes CSI válidos: {total_packets}. "
            f"Se necesitan al menos {window_packets}."
        )
        return 1

    normalize = not bool(args.no_normalize)
    for window_idx in range(total_windows):
        start = window_idx * stride_packets
        end = start + window_packets
        window = csi_matrix[start:end, :]

        image_name_rgb = f"img_{window_idx + 1:06d}_pkts_{start + 1:06d}_{end:06d}.png"
        out_file_rgb = out_rgb_dir / image_name_rgb
        _save_window_image(window, out_file_rgb, normalize=normalize, cmap=args.cmap)
        if args.generate_gray:
            image_name_gray = f"img_{window_idx + 1:06d}_pkts_{start + 1:06d}_{end:06d}_gray.png"
            out_file_gray = out_gray_dir / image_name_gray
            _save_window_image_gray(window, out_file_gray, normalize=normalize)

    print("\n========= RESUMEN =========")
    print(f"Paquetes CSI válidos: {total_packets}")
    print(f"Imágenes generadas  : {total_windows}")
    print("Metadatos CSV       : desactivado")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
