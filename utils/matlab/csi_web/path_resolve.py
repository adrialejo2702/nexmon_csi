"""Resolución de rutas PCAP bajo GOLD_DISK y validación (sin SystemExit)."""

from __future__ import annotations

from pathlib import Path


def get_gold_disk_base(matlab_dir: Path) -> Path:
    return matlab_dir / "pcap_files" / "mydata" / "GOLD_DISK"


def _is_generated_export_dir(dir_path: Path, sibling_pcaps: set[str]) -> bool:
    """Detecta carpetas de salida generadas por la web (para ocultarlas en el explorador)."""
    name = dir_path.name
    if name.endswith("_edge_impulse"):
        return True
    if name in sibling_pcaps:
        return True
    if (dir_path / "rgb").is_dir() or (dir_path / "gray").is_dir():
        return True
    if (dir_path / "labels.json").is_file() or (dir_path / "edge_impulse_labels.csv").is_file():
        return True
    return False


def safe_relative_under_base(base: Path, rel: str) -> Path:
    """Resuelve `rel` dentro de `base`; rechaza .. y rutas absolutas."""
    raw = (rel or "").strip().replace("\\", "/")
    if not raw or raw == ".":
        rel_parts = ()
    else:
        rel_parts = tuple(p for p in raw.split("/") if p and p != ".")
    for part in rel_parts:
        if part == "..":
            raise ValueError("Ruta no permitida (..)")
        if part.startswith("/"):
            raise ValueError("Ruta no permitida")
    candidate = base.joinpath(*rel_parts).resolve()
    base_resolved = base.resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError("Ruta fuera del área permitida") from exc
    return candidate


def browse_directory(base: Path, rel: str = "") -> dict:
    """Lista subdirectorios y ficheros .pcap en `base/rel`."""
    current = safe_relative_under_base(base, rel)
    if not current.is_dir():
        raise ValueError("No es un directorio")
    dirs: list[str] = []
    pcaps: list[str] = []
    sibling_pcaps = {p.stem for p in current.iterdir() if p.is_file() and p.suffix.lower() == ".pcap"}
    for p in sorted(current.iterdir()):
        if p.name.startswith("."):
            continue
        if p.is_dir():
            if _is_generated_export_dir(p, sibling_pcaps):
                continue
            dirs.append(p.name)
        elif p.suffix.lower() == ".pcap":
            pcaps.append(p.name)
    prefix = rel.strip().replace("\\", "/").strip("/")
    return {"path": prefix, "directories": dirs, "pcaps": pcaps}


def resolve_pcap_under_gold_disk(base_dir: Path, user_input: str, default_suffix: str = "") -> Path:
    """Equivalente a `_resolve_pcap_path` de csireader_master pero con ValueError."""
    raw = (user_input or "").strip()
    if not raw and default_suffix:
        raw = default_suffix.strip()
    if not raw:
        raise ValueError("Indica una ruta relativa al área de datos o un nombre .pcap")

    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = (base_dir / raw).resolve()
    else:
        candidate = candidate.resolve()

    base_resolved = base_dir.resolve()
    if candidate.exists() and candidate.is_file():
        try:
            candidate.relative_to(base_resolved)
        except ValueError as exc:
            raise ValueError("El archivo debe estar dentro del área GOLD_DISK") from exc
        if candidate.suffix.lower() != ".pcap":
            raise ValueError("El archivo debe ser .pcap")
        return candidate

    name_only = Path(raw).name
    matches = [p for p in base_dir.rglob(name_only) if p.is_file() and p.suffix.lower() == ".pcap"]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ValueError(
            f"No se encontró el PCAP. Entrada: {raw!r}. "
            f"Comprueba la ruta relativa desde el área de datos."
        )
    lines = "\n".join(str(p.relative_to(base_resolved)) for p in matches[:25])
    extra = f"\n... ({len(matches) - 25} más)" if len(matches) > 25 else ""
    raise ValueError("Varias coincidencias; elige la ruta relativa exacta:\n" + lines + extra)


def resolve_absolute_trusted(path_str: str) -> Path:
    """Ruta absoluta en el servidor (solo uso local de confianza)."""
    p = Path(path_str.strip()).expanduser()
    if not p.is_absolute():
        p = p.resolve()
    else:
        p = p.resolve()
    if not p.is_file():
        raise ValueError("No existe o no es un fichero")
    if p.suffix.lower() != ".pcap":
        raise ValueError("Debe ser un archivo .pcap")
    return p
