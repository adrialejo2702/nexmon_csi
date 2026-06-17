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


def get_output_paths(run_key: str, experiment: str) -> Dict[str, Path]:
    out_dir = OUTPUT_DIR / to_safe_token(experiment)
    return {
        "detail_csv": out_dir / f"{run_key}_detalle_por_core.csv",
        "horizontal_csv": out_dir / f"{run_key}_comparativa_horizontal.csv",
        "disagreement_csv": out_dir / f"{run_key}_etiquetas_erroneas.csv",
        "summary_json": out_dir / f"{run_key}_resumen_metricas.json",
    }


def outputs_exist(run_key: str, experiment: str) -> bool:
    paths = get_output_paths(run_key, experiment)
    return all(path.exists() for path in paths.values())


def load_existing_result(run_key: str, experiment: str) -> Dict:
    paths = get_output_paths(run_key, experiment)
    summary_data = json.loads(paths["summary_json"].read_text(encoding="utf-8"))
    horizontal_rows: List[Dict] = []
    with paths["horizontal_csv"].open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            horizontal_rows.append(row)
    per_core_summary = summary_data.get("summary_per_core", {})
    # Recompute ensemble votes if columns are missing (old CSVs won't have them)
    for row in horizontal_rows:
        if "hard_vote" not in row:
            row["hard_vote"] = compute_hard_vote(row)
        if "soft_vote" not in row:
            row["soft_vote"] = compute_soft_vote(row)
    class_metrics = compute_class_metrics(horizontal_rows)
    return {
        "summary": per_core_summary,
        "horizontal_rows": horizontal_rows[:200],
        "output_files": {k: str(v) for k, v in paths.items()},
        "truncated": len(horizontal_rows) > 200,
        "total_horizontal_rows": len(horizontal_rows),
        "warnings": ["Resultados reutilizados: ya existían exportaciones para esta selección."],
        "exported_now": False,
        "class_labels": extract_class_labels(horizontal_rows),
        "comparison_accuracy": compute_comparison_accuracy(horizontal_rows, per_core_summary),
        "ensemble_error_rows": build_ensemble_error_rows(horizontal_rows),
        "confusion_matrices": compute_confusion_matrices(horizontal_rows),
        "class_metrics": class_metrics.get("by_method", {}),
        "class_metric_labels": class_metrics.get("labels", []),
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
            per_key[row.image_key][f"{core}_result_json"] = json.dumps(row.result_dict, ensure_ascii=False)
    output_rows = []
    for image_key in sorted(per_key.keys()):
        row = per_key[image_key]
        for core in CORES:
            row.setdefault(f"{core}_pred", "-")
            row.setdefault(f"{core}_score", None)
            row.setdefault(f"{core}_result_json", "{}")
        row["hard_vote"] = compute_hard_vote(row)
        row["soft_vote"] = compute_soft_vote(row)
        output_rows.append(row)
    return output_rows


def compute_mean_probs(row: Dict) -> Dict[str, float]:
    class_sums: Dict[str, float] = defaultdict(float)
    class_counts: Dict[str, int] = defaultdict(int)
    for core in CORES:
        raw = row.get(f"{core}_result_json", "{}")
        try:
            d = json.loads(raw) if isinstance(raw, str) else (raw or {})
            for label, prob in d.items():
                class_sums[label] += float(prob)
                class_counts[label] += 1
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    if not class_sums:
        return {}
    return {label: class_sums[label] / class_counts[label] for label in class_sums}


def compute_hard_vote(row: Dict) -> str:
    counts: Dict[str, int] = defaultdict(int)
    for core in CORES:
        pred = row.get(f"{core}_pred", "")
        if pred and pred not in ("-", "error"):
            counts[pred] += 1
    if not counts:
        return "-"
    max_count = max(counts.values())
    winners = sorted(label for label, c in counts.items() if c == max_count)
    return "uncertain" if len(winners) > 1 else winners[0]


def compute_soft_vote(row: Dict) -> str:
    avg_probs = compute_mean_probs(row)
    if not avg_probs:
        return "-"
    max_prob = max(avg_probs.values())
    winners = sorted(label for label, p in avg_probs.items() if abs(p - max_prob) < 1e-9)
    return "uncertain" if len(winners) > 1 else winners[0]


def build_ensemble_error_rows(horizontal_rows: List[Dict]) -> List[Dict]:
    rows = []
    for row in horizontal_rows:
        expected = row.get("expected_label", "")
        hard = row.get("hard_vote", "-")
        soft = row.get("soft_vote", "-")
        if hard == "-" and soft == "-":
            continue
        if hard == expected and soft == expected:
            continue
        mean_probs = compute_mean_probs(row)
        error_row: Dict = {
            "image_key": row.get("image_key"),
            "expected_label": expected,
            "hard_vote": hard,
            "soft_vote": soft,
            "mean_result_json": json.dumps(mean_probs, ensure_ascii=False),
        }
        for core in CORES:
            error_row[f"{core}_pred"] = row.get(f"{core}_pred", "-")
            error_row[f"{core}_result_json"] = row.get(f"{core}_result_json", "{}")
        rows.append(error_row)
    return rows


def compute_comparison_accuracy(horizontal_rows: List[Dict], per_core_summary: Dict) -> Dict[str, float]:
    comparison: Dict[str, float] = {}
    for core in CORES:
        if core in per_core_summary:
            comparison[core] = float(per_core_summary[core].get("accuracy_vs_filename_label", 0.0))
    total = 0
    hard_correct = 0
    soft_correct = 0
    for row in horizontal_rows:
        expected = row.get("expected_label", "")
        if not expected or expected == "unknown":
            continue
        total += 1
        if row.get("hard_vote") == expected:
            hard_correct += 1
        if row.get("soft_vote") == expected:
            soft_correct += 1
    if total > 0:
        comparison["hard_vote"] = hard_correct / total
        comparison["soft_vote"] = soft_correct / total
    return comparison


def compute_class_metrics(horizontal_rows: List[Dict]) -> Dict:
    method_predictions: Dict[str, List] = {core: [] for core in CORES}
    method_predictions["hard_vote"] = []
    method_predictions["soft_vote"] = []

    label_set = set()
    for row in horizontal_rows:
        expected = row.get("expected_label", "")
        if not expected or expected == "unknown":
            continue
        label_set.add(expected)
        for core in CORES:
            pred = row.get(f"{core}_pred", "-")
            if pred and pred not in ("-", "error"):
                method_predictions[core].append((expected, pred))
        for method in ("hard_vote", "soft_vote"):
            pred = row.get(method, "-")
            if pred and pred != "-":
                method_predictions[method].append((expected, pred))

    labels = sorted(label_set)
    metrics_by_method: Dict[str, Dict] = {}
    for method, data in method_predictions.items():
        if not data or not labels:
            continue
        per_class = {}
        uncertain_count = sum(1 for _, predicted in data if predicted == "uncertain")
        total = len(data)
        correct = sum(1 for actual, predicted in data if actual == predicted)
        f1_values = []
        for label in labels:
            tp = sum(1 for actual, predicted in data if actual == label and predicted == label)
            fp = sum(1 for actual, predicted in data if actual != label and predicted == label)
            fn = sum(1 for actual, predicted in data if actual == label and predicted != label)
            support = sum(1 for actual, _ in data if actual == label)
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
            per_class[label] = {
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "support": support,
            }
            f1_values.append(f1)
        metrics_by_method[method] = {
            "per_class": per_class,
            "macro_f1": sum(f1_values) / len(f1_values) if f1_values else 0.0,
            "accuracy": correct / total if total > 0 else 0.0,
            "n": total,
            "uncertain_count": uncertain_count,
        }

    return {"labels": labels, "by_method": metrics_by_method}


def _cm_cell_style(percentage: float, is_diagonal: bool) -> str:
    if percentage <= 0:
        return "background:#f8fafc;color:#cbd5e1"
    intensity = min(0.92, percentage / 100.0 * 0.82 + 0.10)
    r, g, b = (22, 163, 74) if is_diagonal else (220, 38, 38)
    text = "white" if intensity > 0.55 else "#111827"
    return f"background:rgba({r},{g},{b},{intensity:.2f});color:{text};font-weight:600"


def compute_confusion_matrices(horizontal_rows: List[Dict]) -> Dict:
    pairs: Dict[str, List] = {core: [] for core in CORES}
    pairs["hard_vote"] = []
    pairs["soft_vote"] = []

    for row in horizontal_rows:
        expected = row.get("expected_label", "")
        if not expected or expected == "unknown":
            continue
        for core in CORES:
            pred = row.get(f"{core}_pred", "-")
            if pred and pred not in ("-", "error"):
                pairs[core].append((expected, pred))
        for method in ("hard_vote", "soft_vote"):
            val = row.get(method, "-")
            if val and val != "-":
                pairs[method].append((expected, val))

    result: Dict = {}
    for method, data in pairs.items():
        if not data:
            continue
        all_labels = sorted(set(a for a, _ in data) | set(p for _, p in data))
        display_labels = all_labels
        if method == "hard_vote":
            display_labels = [label for label in all_labels if label != "uncertain"]
        if not display_labels:
            continue
        counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for actual, predicted in data:
            counts[actual][predicted] += 1
        rows_out = []
        for actual in display_labels:
            row_total = sum(counts[actual][predicted] for predicted in display_labels) or 1
            cells = []
            for predicted in display_labels:
                c = counts[actual][predicted]
                pct = (c * 100.0) / row_total
                cells.append({
                    "predicted": predicted,
                    "count": c,
                    "percentage": pct,
                    "style": _cm_cell_style(pct, predicted == actual),
                })
            rows_out.append({"actual": actual, "cells": cells})
        result[method] = {
            "labels": display_labels,
            "rows": rows_out,
            "uncertain_count": sum(1 for _, predicted in data if predicted == "uncertain"),
        }
    return result


def extract_class_labels(horizontal_rows: List[Dict]) -> List[str]:
    labels: set = set()
    for row in horizontal_rows:
        for core in CORES:
            raw = row.get(f"{core}_result_json", "{}")
            try:
                d = json.loads(raw) if isinstance(raw, str) else raw
                labels.update(d.keys())
            except (json.JSONDecodeError, AttributeError):
                pass
    return sorted(labels)


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
    run_key: str, experiment: str, core_rows: Dict[str, List[ImagePrediction]], horizontal_rows: List[Dict], summary: Dict
) -> Dict[str, Path]:
    paths = get_output_paths(run_key, experiment)
    next(iter(paths.values())).parent.mkdir(parents=True, exist_ok=True)
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
    write_csv(disagreement_csv, build_ensemble_error_rows(horizontal_rows))
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
                    "class_labels": [],
                    "comparison_accuracy": {},
                    "ensemble_error_rows": [],
                    "confusion_matrices": {},
                    "class_metrics": {},
                    "class_metric_labels": [],
                }
            return

        if not core_rows:
            raise ValueError("No se encontraron datos para procesar con la selección actual.")

        horizontal_rows = build_horizontal_table(core_rows)
        summary = summarize_per_core(core_rows)
        run_key = get_run_key(experiment, selected_folder, ov_folder)
        class_labels = extract_class_labels(horizontal_rows)
        comparison_accuracy = compute_comparison_accuracy(horizontal_rows, summary)
        ensemble_error_rows = build_ensemble_error_rows(horizontal_rows)
        confusion_matrices = compute_confusion_matrices(horizontal_rows)
        class_metrics = compute_class_metrics(horizontal_rows)
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
                    "class_labels": class_labels,
                    "comparison_accuracy": comparison_accuracy,
                    "ensemble_error_rows": ensemble_error_rows,
                    "confusion_matrices": confusion_matrices,
                    "class_metrics": class_metrics.get("by_method", {}),
                    "class_metric_labels": class_metrics.get("labels", []),
                }
            return
        output_files = export_results(run_key, experiment, core_rows, horizontal_rows, summary)
        result = {
            "summary": summary,
            "horizontal_rows": horizontal_rows[:200],
            "output_files": {k: str(v) for k, v in output_files.items()},
            "truncated": len(horizontal_rows) > 200,
            "total_horizontal_rows": len(horizontal_rows),
            "warnings": warnings,
            "exported_now": True,
            "class_labels": class_labels,
            "comparison_accuracy": comparison_accuracy,
            "ensemble_error_rows": ensemble_error_rows,
            "confusion_matrices": confusion_matrices,
            "class_metrics": class_metrics.get("by_method", {}),
            "class_metric_labels": class_metrics.get("labels", []),
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
    if outputs_exist(run_key, experiment):
        return render_template(
            "index.html",
            experiments=experiments,
            selected_experiment=experiment,
            experiment_subdirs=experiment_subdirs,
            selected_folder=selected_folder,
            ov_folders=ov_folders,
            selected_ov_folder=ov_folder,
            result=load_existing_result(run_key, experiment),
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
