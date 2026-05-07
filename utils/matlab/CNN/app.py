#!/usr/bin/env python3
import csv
import json
import os
import threading
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, jsonify, render_template, request

from edge_impulse_infer import classify_image, extract_top_result


BASE_DIR = Path(__file__).resolve().parent
# Data lives outside this folder (under the gitignored pcap_files/ tree).
# Allow override via env var GOLD_DISK_DIR for non-default layouts.
DEFAULT_GOLD_DISK_DIR = BASE_DIR.parent / "pcap_files" / "mydata" / "GOLD_DISK"
GOLD_DISK_DIR = Path(os.environ.get("GOLD_DISK_DIR", DEFAULT_GOLD_DISK_DIR)).resolve()
CONFIG_PATH = BASE_DIR / "config" / "projects.local.json"
OUTPUT_DIR = BASE_DIR / "outputs"
SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"}
CORES = ["core0", "core1", "core2", "core3"]

app = Flask(__name__)
JOBS: Dict[str, Dict] = {}
JOBS_LOCK = threading.Lock()


@dataclass
class ImagePrediction:
    core: str
    image_path: Path
    image_key: str
    expected_label: str
    predicted_label: Optional[str]
    score: Optional[float]
    success: bool
    error: Optional[str]
    result_dict: Dict[str, float]


def list_experiments() -> List[str]:
    return sorted([p.name for p in GOLD_DISK_DIR.iterdir() if p.is_dir() and p.name != "CNN"])


def list_experiment_subdirs(experiment: str) -> List[str]:
    experiment_path = GOLD_DISK_DIR / experiment
    if not experiment_path.exists():
        return []
    return sorted([p.name for p in experiment_path.iterdir() if p.is_dir()])


def list_ov_folders(base_path: Path) -> List[str]:
    if not base_path.exists() or not base_path.is_dir():
        return []
    # Keep it flexible: ov0, ov50, or any other folder name the user might have.
    return sorted([p.name for p in base_path.iterdir() if p.is_dir()])


def resolve_core_dirs(base_path: Path, ov_folder: str) -> Dict[str, Path]:
    ov_path = base_path / ov_folder
    selected: Dict[str, Path] = {}
    if not ov_path.exists() or not ov_path.is_dir():
        return selected
    for core in CORES:
        core_path = ov_path / core
        if core_path.exists() and core_path.is_dir():
            selected[core] = core_path
    return selected


def to_safe_token(value: str) -> str:
    safe_chars = []
    for ch in value:
        if ch.isalnum() or ch in ("-", "_"):
            safe_chars.append(ch)
        else:
            safe_chars.append("_")
    return "".join(safe_chars).strip("_") or "na"


def get_run_key(experiment: str, selected_folder: str, ov_folder: str) -> str:
    return (
        f"{to_safe_token(experiment)}__{to_safe_token(selected_folder)}__{to_safe_token(ov_folder)}"
    )


def get_output_paths(run_key: str) -> Dict[str, Path]:
    return {
        "detail_csv": OUTPUT_DIR / f"{run_key}_detalle_por_core.csv",
        "horizontal_csv": OUTPUT_DIR / f"{run_key}_comparativa_horizontal.csv",
        "disagreement_csv": OUTPUT_DIR / f"{run_key}_cores_con_diferencias.csv",
        "summary_json": OUTPUT_DIR / f"{run_key}_resumen_metricas.json",
    }


def outputs_exist(run_key: str) -> bool:
    paths = get_output_paths(run_key)
    return all(path.exists() for path in paths.values())


def load_existing_result(run_key: str) -> Dict:
    paths = get_output_paths(run_key)
    summary_data = json.loads(paths["summary_json"].read_text(encoding="utf-8"))
    horizontal_rows: List[Dict] = []
    with paths["horizontal_csv"].open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            horizontal_rows.append(row)
    return {
        "summary": summary_data.get("summary_per_core", {}),
        "horizontal_rows": horizontal_rows[:200],
        "output_files": {k: str(v) for k, v in paths.items()},
        "truncated": len(horizontal_rows) > 200,
        "total_horizontal_rows": len(horizontal_rows),
        "warnings": ["Resultados reutilizados: ya existían exportaciones para esta selección."],
        "exported_now": False,
    }


def load_project_config() -> Dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Config file not found: {CONFIG_PATH}")
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def parse_expected_label(file_name: str) -> str:
    return file_name.split(".", 1)[0] if "." in file_name else "unknown"


def build_image_key(file_name: str) -> str:
    # Keeps alignment across cores if prefix label differs or is noisy.
    return file_name.split(".", 1)[1] if "." in file_name else file_name


def classify_core_images(
    core: str,
    core_variant_dir: Path,
    core_cfg: Dict,
    timeout_seconds: int,
    progress_callback,
    should_cancel,
) -> List[ImagePrediction]:
    image_files = sorted(
        [
            p
            for p in core_variant_dir.iterdir()
            if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS
        ]
    )
    rows: List[ImagePrediction] = []
    for image_path in image_files:
        if should_cancel():
            break
        expected = parse_expected_label(image_path.name)
        image_key = build_image_key(image_path.name)
        try:
            response = classify_image(
                api_key=core_cfg["apiKey"],
                project_id=str(core_cfg["projectId"]),
                impulse_id=core_cfg.get("impulseId"),
                image_path=image_path,
                timeout_seconds=timeout_seconds,
            )
            top_label, score = extract_top_result(response)
            rows.append(
                ImagePrediction(
                    core=core,
                    image_path=image_path,
                    image_key=image_key,
                    expected_label=expected,
                    predicted_label=top_label,
                    score=score,
                    success=bool(response.get("success", False)),
                    error=response.get("error"),
                    result_dict=response.get("result", {}) if isinstance(response.get("result"), dict) else {},
                )
            )
            progress_callback(core, image_path.name, "processed_ok")
        except Exception as exc:  # pylint: disable=broad-except
            rows.append(
                ImagePrediction(
                    core=core,
                    image_path=image_path,
                    image_key=image_key,
                    expected_label=expected,
                    predicted_label=None,
                    score=None,
                    success=False,
                    error=str(exc),
                    result_dict={},
                )
            )
            progress_callback(core, image_path.name, "processed_error")
    return rows


def build_horizontal_table(core_rows: Dict[str, List[ImagePrediction]]) -> List[Dict]:
    per_key: Dict[str, Dict] = defaultdict(dict)
    for core, rows in core_rows.items():
        for row in rows:
            per_key[row.image_key]["image_key"] = row.image_key
            per_key[row.image_key]["expected_label"] = row.expected_label
            per_key[row.image_key][f"{core}_pred"] = row.predicted_label or "error"
            per_key[row.image_key][f"{core}_score"] = row.score
    output_rows = []
    for image_key in sorted(per_key.keys()):
        row = per_key[image_key]
        for core in CORES:
            row.setdefault(f"{core}_pred", "-")
            row.setdefault(f"{core}_score", None)
        output_rows.append(row)
    return output_rows


def summarize_per_core(core_rows: Dict[str, List[ImagePrediction]]) -> Dict[str, Dict]:
    summary = {}
    for core, rows in core_rows.items():
        total = len(rows)
        ok = sum(1 for r in rows if r.success)
        correct = sum(1 for r in rows if r.predicted_label and r.predicted_label == r.expected_label)
        avg_score = (
            sum(float(r.score) for r in rows if r.score is not None) / max(1, sum(1 for r in rows if r.score is not None))
        )
        summary[core] = {
            "total_images": total,
            "successful_calls": ok,
            "accuracy_vs_filename_label": (correct / total) if total else 0.0,
            "avg_top_score": avg_score,
        }
    return summary


def build_disagreement_rows(horizontal_rows: List[Dict]) -> List[Dict]:
    rows = []
    for row in horizontal_rows:
        ok_preds = {}
        for core in CORES:
            pred = row.get(f"{core}_pred")
            if pred and pred not in ("-", "error"):
                ok_preds[core] = pred

        # Need at least two successful core predictions to compare decisions.
        if len(ok_preds) < 2:
            continue

        distinct_labels = sorted(set(ok_preds.values()))
        if len(distinct_labels) <= 1:
            continue

        # Reference label: most common among successful cores.
        counts = defaultdict(int)
        for p in ok_preds.values():
            counts[p] += 1
        max_count = max(counts.values())
        reference_candidates = sorted([label for label, c in counts.items() if c == max_count])
        reference_label = reference_candidates[0]
        differing_cores = sorted([core for core, pred in ok_preds.items() if pred != reference_label])

        disagreement_row = {
            "image_key": row.get("image_key"),
            "expected_label": row.get("expected_label"),
            "reference_label": reference_label,
            "distinct_labels": "|".join(distinct_labels),
            "num_distinct_labels": len(distinct_labels),
            "cores_different": "|".join(differing_cores),
            "num_cores_different": len(differing_cores),
        }
        for core in CORES:
            disagreement_row[f"{core}_pred"] = row.get(f"{core}_pred")
        rows.append(disagreement_row)
    return rows


def export_results(
    run_key: str, core_rows: Dict[str, List[ImagePrediction]], horizontal_rows: List[Dict], summary: Dict
) -> Dict[str, Path]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    paths = get_output_paths(run_key)
    detail_csv = paths["detail_csv"]
    horizontal_csv = paths["horizontal_csv"]
    disagreement_csv = paths["disagreement_csv"]
    summary_json = paths["summary_json"]

    detail_records = []
    for core, rows in core_rows.items():
        for r in rows:
            detail_records.append(
                {
                    "core": core,
                    "image_path": str(r.image_path),
                    "image_key": r.image_key,
                    "expected_label": r.expected_label,
                    "predicted_label": r.predicted_label,
                    "score": r.score,
                    "success": r.success,
                    "error": r.error,
                    "result_json": json.dumps(r.result_dict, ensure_ascii=False),
                }
            )

    write_csv(detail_csv, detail_records)
    write_csv(horizontal_csv, horizontal_rows)
    write_csv(disagreement_csv, build_disagreement_rows(horizontal_rows))
    summary_json.write_text(
        json.dumps(
            {
                "run_key": run_key,
                "generated_at": datetime.now().isoformat(),
                "summary_per_core": summary,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return {
        "detail_csv": detail_csv,
        "horizontal_csv": horizontal_csv,
        "disagreement_csv": disagreement_csv,
        "summary_json": summary_json,
    }


def build_job_status_payload(job: Dict) -> Dict:
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "error": job.get("error"),
        "progress": job.get("progress", {}),
        "core_progress": job.get("core_progress", {}),
        "cancel_requested": job.get("cancel_requested", False),
    }


def run_job(
    job_id: str,
    experiment: str,
    selected_folder: str,
    ov_folder: str,
    timeout_seconds: int,
) -> None:
    with JOBS_LOCK:
        job = JOBS[job_id]
        job["status"] = "running"
        job["error"] = None

    def progress_callback(core: str, _image_name: str, _status: str) -> None:
        with JOBS_LOCK:
            current = JOBS[job_id]
            current["progress"]["done"] += 1
            current["core_progress"][core]["done"] += 1

    def should_cancel() -> bool:
        with JOBS_LOCK:
            return bool(JOBS[job_id].get("cancel_requested", False))

    try:
        config = load_project_config()
        base_path = (GOLD_DISK_DIR / experiment / selected_folder).resolve()
        if not base_path.exists() or not base_path.is_dir():
            raise ValueError(f"La carpeta seleccionada no existe: {base_path}")
        core_dirs = resolve_core_dirs(base_path, ov_folder)
        warnings = []
        core_total_map = {}
        for core in CORES:
            if core not in core_dirs:
                warnings.append(f"No se encontró carpeta para {core} en la carpeta '{ov_folder}'.")
                continue
            core_total_map[core] = len(
                [p for p in core_dirs[core].iterdir() if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS]
            )

        total = sum(core_total_map.values())
        with JOBS_LOCK:
            JOBS[job_id]["progress"] = {"done": 0, "total": total}
            JOBS[job_id]["core_progress"] = {
                core: {"done": 0, "total": core_total_map.get(core, 0)} for core in CORES
            }

        core_rows = {}
        for core in CORES:
            if should_cancel():
                break
            if core not in core_dirs:
                continue
            if core not in config:
                raise ValueError(f"Missing config for {core} in projects.local.json")
            core_rows[core] = classify_core_images(
                core, core_dirs[core], config[core], timeout_seconds, progress_callback, should_cancel
            )

        if should_cancel():
            with JOBS_LOCK:
                JOBS[job_id]["status"] = "cancelled"
                JOBS[job_id]["result"] = {
                    "summary": {},
                    "horizontal_rows": [],
                    "output_files": {},
                    "truncated": False,
                    "total_horizontal_rows": 0,
                    "warnings": warnings + ["Ejecución cancelada: no se guardaron archivos de resultados."],
                }
            return

        if not core_rows:
            raise ValueError("No se encontraron datos para procesar con la selección actual.")

        horizontal_rows = build_horizontal_table(core_rows)
        summary = summarize_per_core(core_rows)
        run_key = get_run_key(experiment, selected_folder, ov_folder)
        if should_cancel():
            with JOBS_LOCK:
                JOBS[job_id]["status"] = "cancelled"
                JOBS[job_id]["result"] = {
                    "summary": summary,
                    "horizontal_rows": horizontal_rows[:200],
                    "output_files": {},
                    "truncated": len(horizontal_rows) > 200,
                    "total_horizontal_rows": len(horizontal_rows),
                    "warnings": warnings + ["Ejecución cancelada: no se guardaron archivos de resultados."],
                }
            return
        output_files = export_results(run_key, core_rows, horizontal_rows, summary)
        result = {
            "summary": summary,
            "horizontal_rows": horizontal_rows[:200],
            "output_files": {k: str(v) for k, v in output_files.items()},
            "truncated": len(horizontal_rows) > 200,
            "total_horizontal_rows": len(horizontal_rows),
            "warnings": warnings,
            "exported_now": True,
        }
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "completed"
            JOBS[job_id]["result"] = result
    except Exception as exc:  # pylint: disable=broad-except
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = str(exc)


def write_csv(path: Path, rows: List[Dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    keys = sorted({k for row in rows for k in row.keys()})
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


@app.route("/", methods=["GET"])
def index():
    experiments = list_experiments()
    selected_experiment = request.args.get("experiment", experiments[0] if experiments else "")
    experiment_subdirs = list_experiment_subdirs(selected_experiment) if selected_experiment else []
    selected_folder = request.args.get("selected_folder", experiment_subdirs[0] if experiment_subdirs else "")
    base_path = (GOLD_DISK_DIR / selected_experiment / selected_folder).resolve() if selected_folder else None
    ov_folders = list_ov_folders(base_path) if base_path else []
    selected_ov_folder = request.args.get("ov_folder", ov_folders[0] if ov_folders else "")
    job_id = request.args.get("job_id", "").strip()
    job_status = None
    result = None
    error = None
    if job_id:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job:
                job_status = build_job_status_payload(job)
                if job["status"] == "completed":
                    result = job.get("result")
                elif job["status"] == "error":
                    error = job.get("error")
                elif job["status"] == "cancelled":
                    result = job.get("result")
    return render_template(
        "index.html",
        experiments=experiments,
        selected_experiment=selected_experiment,
        experiment_subdirs=experiment_subdirs,
        selected_folder=selected_folder,
        ov_folders=ov_folders,
        selected_ov_folder=selected_ov_folder,
        result=result,
        error=error,
        job_id=job_id,
        job_status=job_status,
    )


@app.route("/run", methods=["POST"])
def run_batch():
    experiment = request.form.get("experiment", "").strip()
    selected_folder = request.form.get("selected_folder", "").strip()
    ov_folder = request.form.get("ov_folder", "").strip()
    timeout_seconds = int(request.form.get("timeout_seconds", "60"))

    experiments = list_experiments()
    experiment_subdirs = list_experiment_subdirs(experiment) if experiment else []
    base_path = (GOLD_DISK_DIR / experiment / selected_folder).resolve() if selected_folder else None
    ov_folders = list_ov_folders(base_path) if base_path else []

    run_key = get_run_key(experiment, selected_folder, ov_folder)
    if outputs_exist(run_key):
        return render_template(
            "index.html",
            experiments=experiments,
            selected_experiment=experiment,
            experiment_subdirs=experiment_subdirs,
            selected_folder=selected_folder,
            ov_folders=ov_folders,
            selected_ov_folder=ov_folder,
            result=load_existing_result(run_key),
            error=None,
            job_id="",
            job_status=None,
        )

    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "progress": {"done": 0, "total": 0},
            "core_progress": {core: {"done": 0, "total": 0} for core in CORES},
            "result": None,
            "error": None,
            "cancel_requested": False,
        }
    thread = threading.Thread(
        target=run_job,
        args=(job_id, experiment, selected_folder, ov_folder, timeout_seconds),
        daemon=True,
    )
    thread.start()
    return render_template(
        "index.html",
        experiments=experiments,
        selected_experiment=experiment,
        experiment_subdirs=experiment_subdirs,
        selected_folder=selected_folder,
        ov_folders=ov_folders,
        selected_ov_folder=ov_folder,
        result=None,
        error=None,
        job_id=job_id,
        job_status=build_job_status_payload(JOBS[job_id]),
    )


@app.route("/status/<job_id>", methods=["GET"])
def job_status(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        payload = build_job_status_payload(job)
    return jsonify(payload)


@app.route("/cancel/<job_id>", methods=["POST"])
def cancel_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        if job.get("status") in ("completed", "error", "cancelled"):
            return jsonify({"ok": True, "status": job.get("status")})
        job["cancel_requested"] = True
        if job.get("status") == "queued":
            job["status"] = "cancelled"
    return jsonify({"ok": True, "status": "cancelling"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)
