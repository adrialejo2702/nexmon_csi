#!/usr/bin/env python3
import csv
import json
import os
import re
import threading
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from flask import Flask, abort, jsonify, render_template, request, send_file

from local_infer import classify_image_local, extract_top_result


BASE_DIR = Path(__file__).resolve().parent
# Data lives outside this folder (under the gitignored pcap_files/ tree).
# Allow override via env var GOLD_DISK_DIR for non-default layouts.
DEFAULT_GOLD_DISK_DIR = BASE_DIR.parent / "pcap_files" / "mydata" / "GOLD_DISK"
GOLD_DISK_DIR = Path(os.environ.get("GOLD_DISK_DIR", DEFAULT_GOLD_DISK_DIR)).resolve()
OUTPUT_DIR = BASE_DIR / "outputs"
SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"}
CORES = ["core0", "core1", "core2", "core3"]
ENSEMBLE_METHODS = ["hard_vote", "soft_vote", "weighted_soft_vote", "adaptive_weighted_soft_vote"]
ADAPTIVE_WINDOW_SIZE = 5
ADAPTIVE_GLOBAL_BETA = 0.6
JOB_TTL_SECONDS = 7200

app = Flask(__name__)
app.jinja_env.globals.update(
    adaptive_global_beta=ADAPTIVE_GLOBAL_BETA,
    adaptive_window_size=ADAPTIVE_WINDOW_SIZE,
)
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
    return sorted([p.name for p in GOLD_DISK_DIR.iterdir() if p.is_dir() and p.name not in {"CNN", "CNNv2"}])


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


def get_output_paths(run_key: str, experiment: str, selected_folder: str) -> Dict[str, Path]:
    out_dir = OUTPUT_DIR / to_safe_token(experiment) / to_safe_token(selected_folder)
    return {
        "detail_csv": out_dir / f"{run_key}_detalle_por_core.csv",
        "horizontal_csv": out_dir / f"{run_key}_comparativa_horizontal.csv",
        "disagreement_csv": out_dir / f"{run_key}_etiquetas_erroneas.csv",
        "summary_json": out_dir / f"{run_key}_resumen_metricas.json",
    }


def outputs_exist(run_key: str, experiment: str, selected_folder: str) -> bool:
    paths = get_output_paths(run_key, experiment, selected_folder)
    return all(path.exists() for path in paths.values())


def load_existing_result(run_key: str, experiment: str, selected_folder: str, use_labeled_weights: bool = False) -> Dict:
    paths = get_output_paths(run_key, experiment, selected_folder)
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
        if "soft_vote_result_json" not in row:
            row["soft_vote_result_json"] = json.dumps(compute_mean_probs(row), ensure_ascii=False)
    is_labeled = detect_labeled_dataset(horizontal_rows)
    has_weighted_vote = is_labeled
    if is_labeled:
        attach_core_weights(per_core_summary)
        apply_weighted_soft_vote(horizontal_rows, per_core_summary)
    elif use_labeled_weights:
        labeled_folder = selected_folder + "_edge_impulse"
        parts = run_key.split("__", 2)
        ov_s = parts[2] if len(parts) > 2 else ""
        labeled_weights = load_labeled_weights(experiment, labeled_folder, ov_s)
        if labeled_weights:
            apply_labeled_weights_soft_vote(horizontal_rows, labeled_weights, per_core_summary)
            has_weighted_vote = True
    if has_weighted_vote:
        apply_adaptive_weighted_soft_vote(horizontal_rows, per_core_summary)
    class_metrics = compute_class_metrics(horizontal_rows, is_labeled)
    parts = run_key.split("__", 2)
    experiment_s = parts[0] if len(parts) > 0 else ""
    folder_s = parts[1] if len(parts) > 1 else ""
    ov_s = parts[2] if len(parts) > 2 else ""
    counterpart = find_labeled_counterpart(experiment_s, folder_s, ov_s) if not is_labeled else None
    labeled_folder, labeled_ov = counterpart if counterpart else (None, None)
    cross_accuracy = compute_cross_accuracy(run_key, experiment_s, folder_s, labeled_folder, labeled_ov) if labeled_folder else {}
    if labeled_folder:
        label_map = load_cross_label_map(experiment_s, labeled_folder, labeled_ov)
        inject_cross_labels(horizontal_rows, label_map)
    return {
        "summary": per_core_summary,
        "horizontal_rows": horizontal_rows,
        "output_files": {k: str(v) for k, v in paths.items()},
        "truncated": False,
        "total_horizontal_rows": len(horizontal_rows),
        "warnings": ["Resultados reutilizados: ya existían exportaciones para esta selección."],
        "exported_now": False,
        "class_labels": extract_class_labels(horizontal_rows),
        "comparison_accuracy": compute_comparison_accuracy(horizontal_rows, per_core_summary, is_labeled),
        "ensemble_error_rows": build_ensemble_error_rows(horizontal_rows, is_labeled),
        "confusion_matrices": compute_confusion_matrices(horizontal_rows, is_labeled),
        "class_metrics": class_metrics.get("by_method", {}),
        "class_metric_labels": class_metrics.get("labels", []),
        "is_labeled": is_labeled,
        "has_weighted_vote": has_weighted_vote,
        "cross_accuracy": cross_accuracy,
    }



def parse_expected_label(file_name: str) -> str:
    if "." not in file_name:
        return "unknown"
    prefix, rest = file_name.split(".", 1)
    # If rest has no further dot it's just the extension → unlabeled file
    if "." not in rest:
        return "unknown"
    return prefix


def build_image_key(file_name: str) -> str:
    if "." not in file_name:
        return file_name
    prefix, rest = file_name.split(".", 1)
    # Labeled: "movimiento.img_001.png" → rest = "img_001.png" (has dot) → return rest
    # Unlabeled: "img_001.png" → rest = "png" (no dot) → return full name for unique key
    if "." not in rest:
        return file_name
    return rest


def natural_sort_key(value: str) -> List:
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", value)]


def classify_core_images(
    core: str,
    core_variant_dir: Path,
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
            response = classify_image_local(
                core=core,
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
    for image_key in sorted(per_key.keys(), key=natural_sort_key):
        row = per_key[image_key]
        for core in CORES:
            row.setdefault(f"{core}_pred", "-")
            row.setdefault(f"{core}_score", None)
            row.setdefault(f"{core}_result_json", "{}")
        row["hard_vote"] = compute_hard_vote(row)
        row["soft_vote"] = compute_soft_vote(row)
        row["soft_vote_result_json"] = json.dumps(compute_mean_probs(row), ensure_ascii=False)
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


def compute_core_weights(per_core_summary: Dict) -> Dict[str, float]:
    raw_weights: Dict[str, float] = {}
    for core in CORES:
        if core not in per_core_summary:
            continue
        try:
            accuracy = float(per_core_summary[core].get("accuracy_vs_filename_label", 0.0))
        except (TypeError, ValueError):
            accuracy = 0.0
        raw_weights[core] = max(0.0, accuracy)

    total_weight = sum(raw_weights.values())
    if total_weight <= 0 and raw_weights:
        equal_weight = 1.0 / len(raw_weights)
        return {core: equal_weight for core in raw_weights}
    if total_weight <= 0:
        return {}
    return {core: weight / total_weight for core, weight in raw_weights.items()}


def attach_core_weights(per_core_summary: Dict) -> Dict[str, float]:
    weights = compute_core_weights(per_core_summary)
    for core, weight in weights.items():
        if core in per_core_summary:
            per_core_summary[core]["weighted_soft_weight"] = weight
    return weights


def compute_weighted_probs(row: Dict, core_weights: Dict[str, float]) -> Dict[str, float]:
    class_sums: Dict[str, float] = defaultdict(float)
    used_weight = 0.0
    for core in CORES:
        weight = core_weights.get(core, 0.0)
        if weight <= 0:
            continue
        raw = row.get(f"{core}_result_json", "{}")
        try:
            d = json.loads(raw) if isinstance(raw, str) else (raw or {})
            if not d:
                continue
            used_weight += weight
            for label, prob in d.items():
                class_sums[label] += weight * float(prob)
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    if not class_sums or used_weight <= 0:
        return {}
    return {label: class_sums[label] / used_weight for label in class_sums}


def compute_weighted_soft_vote(row: Dict, core_weights: Dict[str, float]) -> str:
    weighted_probs = compute_weighted_probs(row, core_weights)
    if not weighted_probs:
        return "-"
    max_prob = max(weighted_probs.values())
    winners = sorted(label for label, p in weighted_probs.items() if abs(p - max_prob) < 1e-9)
    return "uncertain" if len(winners) > 1 else winners[0]


def apply_weighted_soft_vote(horizontal_rows: List[Dict], per_core_summary: Dict) -> Dict[str, float]:
    core_weights = attach_core_weights(per_core_summary)
    for row in horizontal_rows:
        weighted_probs = compute_weighted_probs(row, core_weights)
        row["weighted_soft_vote"] = compute_weighted_soft_vote(row, core_weights)
        row["weighted_soft_result_json"] = json.dumps(weighted_probs, ensure_ascii=False)
    return core_weights


def normalize_core_values(values: Dict[str, float], fallback_weights: Dict[str, float]) -> Dict[str, float]:
    clipped = {core: max(0.0, float(values.get(core, 0.0))) for core in CORES}
    total = sum(clipped.values())
    if total > 0:
        return {core: clipped[core] / total for core in CORES}
    return {core: fallback_weights.get(core, 0.0) for core in CORES}


def compute_recent_core_reliability(previous_rows: List[Dict]) -> Dict[str, float]:
    reliability: Dict[str, float] = {}
    for core in CORES:
        scores = []
        for row in previous_rows:
            expected = row.get("expected_label", "")
            raw = row.get(f"{core}_result_json", "{}")
            try:
                d = json.loads(raw) if isinstance(raw, str) else (raw or {})
                if not d:
                    continue
                if expected and expected in d:
                    # Labeled: prob assigned to the true class
                    scores.append(float(d[expected]))
                else:
                    # Unlabeled: top-1 confidence as proxy
                    scores.append(max(d.values()))
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
        reliability[core] = sum(scores) / len(scores) if scores else 0.0
    return reliability


def detect_labeled_dataset(horizontal_rows: List[Dict]) -> bool:
    for row in horizontal_rows[:20]:
        expected = row.get("expected_label", "")
        if not expected:
            continue
        for core in CORES:
            raw = row.get(f"{core}_result_json", "{}")
            try:
                d = json.loads(raw) if isinstance(raw, str) else (raw or {})
                if expected in d:
                    return True
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
    return False


def compute_adaptive_core_weights(
    global_weights: Dict[str, float],
    recent_reliability: Dict[str, float],
    beta: float = ADAPTIVE_GLOBAL_BETA,
) -> Dict[str, float]:
    recent_weights = normalize_core_values(recent_reliability, global_weights)
    mixed = {
        core: beta * global_weights.get(core, 0.0) + (1.0 - beta) * recent_weights.get(core, 0.0)
        for core in CORES
    }
    return normalize_core_values(mixed, global_weights)


def apply_adaptive_weighted_soft_vote(
    horizontal_rows: List[Dict],
    per_core_summary: Dict,
    window_size: int = ADAPTIVE_WINDOW_SIZE,
    beta: float = ADAPTIVE_GLOBAL_BETA,
) -> None:
    global_weights = compute_core_weights(per_core_summary)
    for idx, row in enumerate(horizontal_rows):
        previous_rows = horizontal_rows[max(0, idx - window_size):idx]
        recent_reliability = compute_recent_core_reliability(previous_rows)
        adaptive_weights = compute_adaptive_core_weights(global_weights, recent_reliability, beta)
        adaptive_probs = compute_weighted_probs(row, adaptive_weights)
        row["adaptive_weighted_soft_vote"] = compute_weighted_soft_vote(row, adaptive_weights)
        row["adaptive_weighted_result_json"] = json.dumps(adaptive_probs, ensure_ascii=False)
        row["adaptive_core_weights_json"] = json.dumps(adaptive_weights, ensure_ascii=False)
        row["adaptive_recent_reliability_json"] = json.dumps(recent_reliability, ensure_ascii=False)


def load_labeled_weights(experiment: str, labeled_folder: str, preferred_ov: str) -> Dict[str, float]:
    labeled_ov = resolve_labeled_ov(experiment, labeled_folder, preferred_ov)
    if not labeled_ov:
        return {}
    labeled_run_key = get_run_key(experiment, labeled_folder, labeled_ov)
    labeled_paths = get_output_paths(labeled_run_key, experiment, labeled_folder)
    try:
        labeled_summary = json.loads(labeled_paths["summary_json"].read_text(encoding="utf-8"))
        labeled_per_core = labeled_summary.get("summary_per_core", {})
        return compute_core_weights(labeled_per_core)
    except (OSError, json.JSONDecodeError):
        return {}


def apply_labeled_weights_soft_vote(
    horizontal_rows: List[Dict], core_weights: Dict[str, float], summary: Dict
) -> None:
    for row in horizontal_rows:
        weighted_probs = compute_weighted_probs(row, core_weights)
        row["weighted_soft_vote"] = compute_weighted_soft_vote(row, core_weights)
        row["weighted_soft_result_json"] = json.dumps(weighted_probs, ensure_ascii=False)
    for core, w in core_weights.items():
        if core in summary:
            summary[core]["weighted_soft_weight"] = w


def build_ensemble_error_rows(horizontal_rows: List[Dict], is_labeled: bool = True) -> List[Dict]:
    rows = []
    for row in horizontal_rows:
        expected = row.get("expected_label", "")
        hard = row.get("hard_vote", "-")
        soft = row.get("soft_vote", "-")
        weighted_soft = row.get("weighted_soft_vote", "-")
        adaptive_weighted_soft = row.get("adaptive_weighted_soft_vote", "-")
        if hard == "-" and soft == "-" and weighted_soft == "-" and adaptive_weighted_soft == "-":
            continue
        if is_labeled:
            if hard == expected and soft == expected and weighted_soft == expected and adaptive_weighted_soft == expected:
                continue
        else:
            # Unlabeled: only include rows where cores disagree with each other
            ok_preds = {
                core: row.get(f"{core}_pred")
                for core in CORES
                if row.get(f"{core}_pred") not in (None, "-", "error")
            }
            if len(set(ok_preds.values())) <= 1:
                continue
        mean_probs = compute_mean_probs(row)
        error_row: Dict = {
            "image_key": row.get("image_key"),
            "expected_label": expected if is_labeled else "-",
            "hard_vote": hard,
            "soft_vote": soft,
            "weighted_soft_vote": weighted_soft,
            "adaptive_weighted_soft_vote": adaptive_weighted_soft,
            "mean_result_json": json.dumps(mean_probs, ensure_ascii=False),
            "weighted_soft_result_json": row.get("weighted_soft_result_json", "{}"),
            "adaptive_weighted_result_json": row.get("adaptive_weighted_result_json", "{}"),
            "adaptive_core_weights_json": row.get("adaptive_core_weights_json", "{}"),
            "adaptive_recent_reliability_json": row.get("adaptive_recent_reliability_json", "{}"),
        }
        for core in CORES:
            error_row[f"{core}_pred"] = row.get(f"{core}_pred", "-")
            error_row[f"{core}_result_json"] = row.get(f"{core}_result_json", "{}")
        rows.append(error_row)
    return rows


def compute_comparison_accuracy(horizontal_rows: List[Dict], per_core_summary: Dict, is_labeled: bool = True) -> Dict[str, float]:
    if not is_labeled:
        return {}
    comparison: Dict[str, float] = {}
    for core in CORES:
        if core in per_core_summary:
            comparison[core] = float(per_core_summary[core].get("accuracy_vs_filename_label", 0.0))
    total = 0
    ensemble_correct: Dict[str, int] = {method: 0 for method in ENSEMBLE_METHODS}
    for row in horizontal_rows:
        expected = row.get("expected_label", "")
        if not expected or expected == "unknown":
            continue
        total += 1
        for method in ENSEMBLE_METHODS:
            if row.get(method) == expected:
                ensemble_correct[method] += 1
    if total > 0:
        for method, correct in ensemble_correct.items():
            comparison[method] = correct / total
    return comparison


def compute_class_metrics(horizontal_rows: List[Dict], is_labeled: bool = True) -> Dict:
    if not is_labeled:
        return {"labels": [], "by_method": {}}
    method_predictions: Dict[str, List] = {core: [] for core in CORES}
    for method in ENSEMBLE_METHODS:
        method_predictions[method] = []

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
        for method in ENSEMBLE_METHODS:
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


def compute_confusion_matrices(horizontal_rows: List[Dict], is_labeled: bool = True) -> Dict:
    if not is_labeled:
        return {}
    pairs: Dict[str, List] = {core: [] for core in CORES}
    for method in ENSEMBLE_METHODS:
        pairs[method] = []

    for row in horizontal_rows:
        expected = row.get("expected_label", "")
        if not expected or expected == "unknown":
            continue
        for core in CORES:
            pred = row.get(f"{core}_pred", "-")
            if pred and pred not in ("-", "error"):
                pairs[core].append((expected, pred))
        for method in ENSEMBLE_METHODS:
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


def resolve_labeled_ov(experiment: str, labeled_folder: str, preferred_ov: str) -> Optional[str]:
    """Return the OV folder to use inside the labeled counterpart.
    Tries preferred_ov first; falls back to any OV that has classified outputs."""
    labeled_path = GOLD_DISK_DIR / experiment / labeled_folder
    candidates = [preferred_ov] + [
        p.name for p in labeled_path.iterdir()
        if p.is_dir() and p.name != preferred_ov
    ] if labeled_path.exists() else []
    for ov in candidates:
        if outputs_exist(get_run_key(experiment, labeled_folder, ov), experiment, labeled_folder):
            return ov
    return None


def find_labeled_counterpart(experiment: str, selected_folder: str, ov_folder: str) -> Optional[Tuple[str, str]]:
    """Return (labeled_folder, labeled_ov) if a classified labeled counterpart exists, else None."""
    labeled_folder = selected_folder + "_edge_impulse"
    labeled_path = GOLD_DISK_DIR / experiment / labeled_folder
    if not labeled_path.exists():
        return None
    labeled_ov = resolve_labeled_ov(experiment, labeled_folder, ov_folder)
    if labeled_ov is None:
        return None
    return (labeled_folder, labeled_ov)


def load_cross_label_map(experiment: str, labeled_folder: str, ov_folder: str) -> Dict[str, str]:
    labeled_run_key = get_run_key(experiment, labeled_folder, ov_folder)
    labeled_paths = get_output_paths(labeled_run_key, experiment, labeled_folder)
    label_map: Dict[str, str] = {}
    try:
        with labeled_paths["horizontal_csv"].open(newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                stem = Path(r["image_key"]).stem
                label_map[stem] = r["expected_label"]
    except OSError:
        pass
    return label_map


def inject_cross_labels(horizontal_rows: List[Dict], label_map: Dict[str, str]) -> None:
    for row in horizontal_rows:
        stem = Path(row.get("image_key", "")).stem
        row["cross_expected_label"] = label_map.get(stem, "")


def compute_cross_accuracy(
    unlabeled_run_key: str,
    experiment: str,
    unlabeled_folder: str,
    labeled_folder: str,
    ov_folder: str,
) -> Dict:
    unlabeled_paths = get_output_paths(unlabeled_run_key, experiment, unlabeled_folder)
    labeled_run_key = get_run_key(experiment, labeled_folder, ov_folder)
    labeled_paths = get_output_paths(labeled_run_key, experiment, labeled_folder)

    try:
        unlabeled_rows: List[Dict] = []
        with unlabeled_paths["horizontal_csv"].open(newline="", encoding="utf-8") as f:
            unlabeled_rows = list(csv.DictReader(f))
        labeled_rows: List[Dict] = []
        with labeled_paths["horizontal_csv"].open(newline="", encoding="utf-8") as f:
            labeled_rows = list(csv.DictReader(f))
    except OSError:
        return {}

    # labeled stem → expected class
    labeled_by_stem: Dict[str, str] = {}
    for r in labeled_rows:
        stem = Path(r["image_key"]).stem
        labeled_by_stem[stem] = r["expected_label"]

    # unlabeled horizontal rows indexed by stem
    # image_key may be full filename (new CSVs) or stem (old CSVs)
    unlabeled_by_stem: Dict[str, Dict] = {}
    for r in unlabeled_rows:
        raw_key = r.get("image_key", "")
        stem = Path(raw_key).stem if "." in raw_key else raw_key
        if stem:
            unlabeled_by_stem[stem] = r

    common_stems = set(unlabeled_by_stem.keys()) & set(labeled_by_stem.keys())
    if not common_stems:
        return {}

    class_dist: Dict[str, int] = defaultdict(int)
    for s in common_stems:
        class_dist[labeled_by_stem[s]] += 1

    # Per-core accuracy
    per_core: Dict[str, Dict] = {}
    for core in CORES:
        correct = 0
        total = 0
        for stem in common_stems:
            pred = unlabeled_by_stem[stem].get(f"{core}_pred", "-")
            if pred not in ("-", "error", ""):
                total += 1
                if pred == labeled_by_stem[stem]:
                    correct += 1
        per_core[core] = {
            "correct": correct,
            "total": total,
            "accuracy": correct / total if total else 0.0,
        }

    # Per-method ensemble accuracy
    ensemble_methods = ["hard_vote", "soft_vote", "weighted_soft_vote", "adaptive_weighted_soft_vote"]
    per_method: Dict[str, Dict] = {}
    for method in ensemble_methods:
        if not any(unlabeled_by_stem[s].get(method, "-") not in ("-", "") for s in common_stems):
            continue
        correct = 0
        total = 0
        for stem in common_stems:
            vote = unlabeled_by_stem[stem].get(method, "-")
            if vote not in ("-", "uncertain", ""):
                total += 1
                if vote == labeled_by_stem[stem]:
                    correct += 1
        per_method[method] = {
            "correct": correct,
            "total": total,
            "accuracy": correct / total if total else 0.0,
        }

    return {
        "labeled_folder": labeled_folder,
        "n_unlabeled": len(unlabeled_by_stem),
        "n_labeled": len(labeled_by_stem),
        "n_common": len(common_stems),
        "class_distribution": dict(class_dist),
        "per_core": per_core,
        "per_method": per_method,
    }


def export_results(
    run_key: str,
    experiment: str,
    selected_folder: str,
    core_rows: Dict[str, List[ImagePrediction]],
    horizontal_rows: List[Dict],
    summary: Dict,
    is_labeled: bool = True,
    ov_folder: str = "",
) -> Dict[str, Path]:
    paths = get_output_paths(run_key, experiment, selected_folder)
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
                "is_labeled": is_labeled,
                "experiment_name": experiment,
                "folder_name": selected_folder,
                "ov_name": ov_folder,
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
        "started_at": job.get("started_at"),
    }


def _purge_old_jobs() -> None:
    cutoff = time.time() - JOB_TTL_SECONDS
    to_delete = [
        jid for jid, job in JOBS.items()
        if job.get("status") in ("completed", "error", "cancelled")
        and job.get("created_at", 0) < cutoff
    ]
    for jid in to_delete:
        del JOBS[jid]


def run_job(
    job_id: str,
    experiment: str,
    selected_folder: str,
    ov_folder: str,
    timeout_seconds: int,
    use_labeled_weights: bool = False,
) -> None:
    with JOBS_LOCK:
        job = JOBS[job_id]
        job["status"] = "running"
        job["started_at"] = time.time()
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
        cores_to_run = [c for c in CORES if c in core_dirs]
        if not should_cancel() and cores_to_run:
            with ThreadPoolExecutor(max_workers=len(cores_to_run)) as executor:
                futures = {
                    executor.submit(
                        classify_core_images, c, core_dirs[c], timeout_seconds, progress_callback, should_cancel
                    ): c
                    for c in cores_to_run
                }
                for future in as_completed(futures):
                    core = futures[future]
                    try:
                        core_rows[core] = future.result()
                    except Exception as exc:
                        warnings.append(f"Error al procesar {core}: {exc}")

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

        summary = summarize_per_core(core_rows)
        horizontal_rows = build_horizontal_table(core_rows)
        is_labeled = detect_labeled_dataset(horizontal_rows)
        has_weighted_vote = is_labeled
        if is_labeled:
            apply_weighted_soft_vote(horizontal_rows, summary)
        elif use_labeled_weights:
            labeled_folder_name = selected_folder + "_edge_impulse"
            labeled_weights = load_labeled_weights(experiment, labeled_folder_name, ov_folder)
            if labeled_weights:
                apply_labeled_weights_soft_vote(horizontal_rows, labeled_weights, summary)
                has_weighted_vote = True
        if has_weighted_vote:
            apply_adaptive_weighted_soft_vote(horizontal_rows, summary)
        run_key = get_run_key(experiment, selected_folder, ov_folder)
        class_labels = extract_class_labels(horizontal_rows)
        comparison_accuracy = compute_comparison_accuracy(horizontal_rows, summary, is_labeled)
        ensemble_error_rows = build_ensemble_error_rows(horizontal_rows, is_labeled)
        confusion_matrices = compute_confusion_matrices(horizontal_rows, is_labeled)
        class_metrics = compute_class_metrics(horizontal_rows, is_labeled)
        output_files = export_results(run_key, experiment, selected_folder, core_rows, horizontal_rows, summary, is_labeled, ov_folder)
        counterpart = find_labeled_counterpart(experiment, selected_folder, ov_folder) if not is_labeled else None
        labeled_folder, labeled_ov = counterpart if counterpart else (None, None)
        cross_accuracy = compute_cross_accuracy(run_key, experiment, selected_folder, labeled_folder, labeled_ov) if labeled_folder else {}
        if labeled_folder:
            label_map = load_cross_label_map(experiment, labeled_folder, labeled_ov)
            inject_cross_labels(horizontal_rows, label_map)
        if should_cancel():
            with JOBS_LOCK:
                JOBS[job_id]["status"] = "cancelled"
                JOBS[job_id]["result"] = {
                    "summary": summary,
                    "horizontal_rows": horizontal_rows,
                    "output_files": {},
                    "truncated": False,
                    "total_horizontal_rows": len(horizontal_rows),
                    "warnings": warnings + ["Ejecución cancelada: no se guardaron archivos de resultados."],
                    "class_labels": class_labels,
                    "comparison_accuracy": comparison_accuracy,
                    "ensemble_error_rows": ensemble_error_rows,
                    "confusion_matrices": confusion_matrices,
                    "class_metrics": class_metrics.get("by_method", {}),
                    "class_metric_labels": class_metrics.get("labels", []),
                    "is_labeled": is_labeled,
                    "has_weighted_vote": has_weighted_vote,
                    "cross_accuracy": cross_accuracy,
                }
            return
        result = {
            "summary": summary,
            "horizontal_rows": horizontal_rows,
            "output_files": {k: str(v) for k, v in output_files.items()},
            "truncated": False,
            "total_horizontal_rows": len(horizontal_rows),
            "warnings": warnings,
            "exported_now": True,
            "class_labels": class_labels,
            "comparison_accuracy": comparison_accuracy,
            "ensemble_error_rows": ensemble_error_rows,
            "confusion_matrices": confusion_matrices,
            "class_metrics": class_metrics.get("by_method", {}),
            "class_metric_labels": class_metrics.get("labels", []),
            "is_labeled": is_labeled,
            "has_weighted_vote": has_weighted_vote,
            "cross_accuracy": cross_accuracy,
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
        history=list_history(),
    )


@app.route("/run", methods=["POST"])
def run_batch():
    experiment = request.form.get("experiment", "").strip()
    selected_folder = request.form.get("selected_folder", "").strip()
    ov_folder = request.form.get("ov_folder", "").strip()
    timeout_seconds = int(request.form.get("timeout_seconds", "60"))
    force_retag = request.form.get("force_retag") == "1"
    use_labeled_weights = request.form.get("use_labeled_weights") == "1"

    experiments = list_experiments()
    experiment_subdirs = list_experiment_subdirs(experiment) if experiment else []
    base_path = (GOLD_DISK_DIR / experiment / selected_folder).resolve() if selected_folder else None
    ov_folders = list_ov_folders(base_path) if base_path else []

    run_key = get_run_key(experiment, selected_folder, ov_folder)
    if outputs_exist(run_key, experiment, selected_folder) and not force_retag:
        return render_template(
            "index.html",
            experiments=experiments,
            selected_experiment=experiment,
            experiment_subdirs=experiment_subdirs,
            selected_folder=selected_folder,
            ov_folders=ov_folders,
            selected_ov_folder=ov_folder,
            result=load_existing_result(run_key, experiment, selected_folder, use_labeled_weights),
            error=None,
            job_id="",
            job_status=None,
            history=list_history(),
        )

    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        _purge_old_jobs()
        JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "created_at": time.time(),
            "started_at": None,
            "progress": {"done": 0, "total": 0},
            "core_progress": {core: {"done": 0, "total": 0} for core in CORES},
            "result": None,
            "error": None,
            "cancel_requested": False,
        }
    thread = threading.Thread(
        target=run_job,
        args=(job_id, experiment, selected_folder, ov_folder, timeout_seconds, use_labeled_weights),
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
        history=list_history(),
    )


@app.route("/preflight", methods=["GET"])
def preflight():
    experiment = request.args.get("experiment", "").strip()
    selected_folder = request.args.get("selected_folder", "").strip()
    ov_folder = request.args.get("ov_folder", "").strip()
    if not experiment or not selected_folder or not ov_folder:
        return jsonify({"is_unlabeled": False, "labeled_folder": None, "is_classified": False})
    if selected_folder.endswith("_edge_impulse"):
        return jsonify({"is_unlabeled": False, "labeled_folder": None, "is_classified": False})
    labeled_folder_name = selected_folder + "_edge_impulse"
    labeled_path = GOLD_DISK_DIR / experiment / labeled_folder_name
    if not labeled_path.exists():
        return jsonify({"is_unlabeled": True, "labeled_folder": None, "is_classified": False})
    labeled_ovs = list_ov_folders(labeled_path)
    if not labeled_ovs:
        return jsonify({"is_unlabeled": True, "labeled_folder": None, "is_classified": False})
    labeled_ov = resolve_labeled_ov(experiment, labeled_folder_name, ov_folder)
    is_classified = labeled_ov is not None
    return jsonify({
        "is_unlabeled": True,
        "labeled_folder": labeled_folder_name,
        "is_classified": is_classified,
    })


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


@app.route("/delete/<run_key>", methods=["POST"])
def delete_run(run_key: str):
    parts = run_key.split("__", 2)
    if len(parts) < 2:
        return jsonify({"error": "invalid run_key"}), 400
    experiment_s, folder_s = parts[0], parts[1]
    paths = get_output_paths(run_key, experiment_s, folder_s)
    deleted = 0
    for path in paths.values():
        try:
            if path.exists():
                path.unlink()
                deleted += 1
        except OSError:
            pass
    # Remove the output directory if it is now empty
    try:
        out_dir = next(iter(paths.values())).parent
        if out_dir.exists() and not any(out_dir.iterdir()):
            out_dir.rmdir()
    except (OSError, StopIteration):
        pass
    return jsonify({"ok": True, "deleted": deleted})


def list_history(limit: int = 30) -> List[Dict]:
    if not OUTPUT_DIR.exists():
        return []
    candidates = []
    for p in OUTPUT_DIR.glob("**/*_resumen_metricas.json"):
        try:
            candidates.append((p.stat().st_mtime, p))
        except OSError:
            continue
    candidates.sort(reverse=True)
    runs: List[Dict] = []
    for _, summary_file in candidates[:limit]:
        try:
            data = json.loads(summary_file.read_text(encoding="utf-8"))
            per_core = data.get("summary_per_core", {})
            parts = data.get("run_key", "").split("__", 2)
            runs.append({
                "run_key": data.get("run_key", ""),
                "generated_at": data.get("generated_at", ""),
                "experiment": parts[0] if len(parts) > 0 else "",
                "folder": parts[1] if len(parts) > 1 else "",
                "ov": parts[2] if len(parts) > 2 else "",
                "experiment_name": data.get("experiment_name", parts[0] if len(parts) > 0 else ""),
                "folder_name": data.get("folder_name", parts[1] if len(parts) > 1 else ""),
                "ov_name": data.get("ov_name", parts[2] if len(parts) > 2 else ""),
                "per_core_accuracy": {
                    core: round(float(info.get("accuracy_vs_filename_label", 0.0)) * 100, 1)
                    for core, info in per_core.items()
                },
                "total_images": max(
                    (int(info.get("total_images", 0)) for info in per_core.values()),
                    default=0,
                ),
                "is_labeled": data.get("is_labeled", True),
            })
        except Exception:
            continue
    return runs


@app.template_filter("output_rel")
def output_rel_filter(full_path: str) -> str:
    try:
        return str(Path(full_path).resolve().relative_to(OUTPUT_DIR.resolve()))
    except ValueError:
        return ""


@app.route("/download")
def download_file():
    rel = request.args.get("path", "").strip()
    if not rel:
        abort(400)
    target = (OUTPUT_DIR / rel).resolve()
    try:
        target.relative_to(OUTPUT_DIR.resolve())
    except ValueError:
        abort(403)
    if not target.is_file():
        abort(404)
    return send_file(target, as_attachment=True)


@app.route("/history")
def history_json():
    return jsonify(list_history())


@app.route("/results/<run_key>")
def view_results(run_key: str):
    parts = run_key.split("__", 2)
    if len(parts) < 3:
        abort(404)
    experiment_safe, folder_safe = parts[0], parts[1]
    if not outputs_exist(run_key, experiment_safe, folder_safe):
        abort(404)
    try:
        parts3 = run_key.split("__", 2)
        ov_safe = parts3[2] if len(parts3) > 2 else ""
        auto_labeled = (
            not folder_safe.endswith("_edge_impulse")
            and bool(find_labeled_counterpart(experiment_safe, folder_safe, ov_safe))
        )
        result = load_existing_result(run_key, experiment_safe, folder_safe, use_labeled_weights=auto_labeled)
        error = None
    except Exception as exc:
        result = None
        error = str(exc)
    experiments = list_experiments()
    selected_experiment = experiment_safe if experiment_safe in experiments else (experiments[0] if experiments else "")
    experiment_subdirs = list_experiment_subdirs(selected_experiment)
    selected_folder = folder_safe if folder_safe in experiment_subdirs else (experiment_subdirs[0] if experiment_subdirs else "")
    base_path = (GOLD_DISK_DIR / selected_experiment / selected_folder).resolve() if selected_folder else None
    ov_folders = list_ov_folders(base_path) if base_path else []
    return render_template(
        "index.html",
        experiments=experiments,
        selected_experiment=selected_experiment,
        experiment_subdirs=experiment_subdirs,
        selected_folder=selected_folder,
        ov_folders=ov_folders,
        selected_ov_folder=parts[2],
        result=result,
        error=error,
        job_id="",
        job_status=None,
        history=list_history(),
        active_run_key=run_key,
    )


@app.route("/recalculate", methods=["POST"])
def recalculate():
    data = request.get_json(force=True) or {}
    run_key = data.get("run_key", "").strip()
    experiment = data.get("experiment", "").strip()
    folder = data.get("folder", "").strip()
    ov_folder = data.get("ov_folder", "").strip()
    try:
        beta = float(data.get("beta", ADAPTIVE_GLOBAL_BETA))
        window_size = int(data.get("window_size", ADAPTIVE_WINDOW_SIZE))
    except (TypeError, ValueError):
        return jsonify({"error": "Parámetros inválidos"}), 400
    beta = max(0.0, min(1.0, beta))
    window_size = max(1, min(100, window_size))

    if not outputs_exist(run_key, experiment, folder):
        return jsonify({"error": "No existen resultados para esta ejecución"}), 404

    paths = get_output_paths(run_key, experiment, folder)
    try:
        summary_data = json.loads(paths["summary_json"].read_text(encoding="utf-8"))
        horizontal_rows: List[Dict] = []
        with paths["horizontal_csv"].open(newline="", encoding="utf-8") as f:
            horizontal_rows = list(csv.DictReader(f))
    except OSError as exc:
        return jsonify({"error": str(exc)}), 500

    per_core_summary = summary_data.get("summary_per_core", {})
    apply_adaptive_weighted_soft_vote(horizontal_rows, per_core_summary, window_size=window_size, beta=beta)
    is_labeled = detect_labeled_dataset(horizontal_rows)

    # Accuracy metrics
    accuracy: Dict[str, float] = {}
    if is_labeled:
        total = 0
        correct = 0
        for row in horizontal_rows:
            expected = row.get("expected_label", "")
            if not expected or expected == "unknown":
                continue
            total += 1
            if row.get("adaptive_weighted_soft_vote") == expected:
                correct += 1
        accuracy["labeled"] = correct / total if total else 0.0
        accuracy["total"] = total
        accuracy["correct"] = correct
    else:
        # Cross-validation
        counterpart = find_labeled_counterpart(experiment, folder, ov_folder)
        if counterpart:
            labeled_folder, labeled_ov = counterpart
            cross = compute_cross_accuracy(run_key, experiment, folder, labeled_folder, labeled_ov)
            if cross:
                pm = cross.get("per_method", {})
                aw = pm.get("adaptive_weighted_soft_vote", {})
                accuracy["cross_accuracy"] = aw.get("accuracy", 0.0)
                accuracy["cross_correct"] = aw.get("correct", 0)
                accuracy["cross_total"] = aw.get("total", 0)

    # Per-frame predictions (first 200 for display)
    preview = [
        {
            "image_key": r.get("image_key"),
            "expected_label": r.get("expected_label", ""),
            "adaptive_weighted_soft_vote": r.get("adaptive_weighted_soft_vote", "-"),
            "adaptive_core_weights_json": r.get("adaptive_core_weights_json", "{}"),
        }
        for r in horizontal_rows[:200]
    ]

    return jsonify({
        "beta": beta,
        "window_size": window_size,
        "accuracy": accuracy,
        "is_labeled": is_labeled,
        "preview": preview,
    })


@app.route("/recalculate_weighted", methods=["POST"])
def recalculate_weighted():
    data = request.get_json(force=True) or {}
    run_key = data.get("run_key", "").strip()
    experiment = data.get("experiment", "").strip()
    folder = data.get("folder", "").strip()
    ov_folder = data.get("ov_folder", "").strip()
    raw_weights = data.get("weights", {}) or {}

    try:
        requested_weights = {
            core: max(0.0, float(raw_weights.get(core, 0.0)))
            for core in CORES
        }
    except (TypeError, ValueError):
        return jsonify({"error": "Pesos inválidos"}), 400

    if sum(requested_weights.values()) <= 0:
        return jsonify({"error": "Introduce al menos un peso mayor que cero"}), 400

    core_weights = normalize_core_values(requested_weights, {core: 1.0 / len(CORES) for core in CORES})

    if not outputs_exist(run_key, experiment, folder):
        return jsonify({"error": "No existen resultados para esta ejecución"}), 404

    paths = get_output_paths(run_key, experiment, folder)
    try:
        with paths["horizontal_csv"].open(newline="", encoding="utf-8") as f:
            horizontal_rows: List[Dict] = list(csv.DictReader(f))
    except OSError as exc:
        return jsonify({"error": str(exc)}), 500

    for row in horizontal_rows:
        if "soft_vote" not in row:
            row["soft_vote"] = compute_soft_vote(row)
        if "soft_vote_result_json" not in row:
            row["soft_vote_result_json"] = json.dumps(compute_mean_probs(row), ensure_ascii=False)
        weighted_probs = compute_weighted_probs(row, core_weights)
        row["manual_weighted_soft_vote"] = compute_weighted_soft_vote(row, core_weights)
        row["manual_weighted_result_json"] = json.dumps(weighted_probs, ensure_ascii=False)

    is_labeled = detect_labeled_dataset(horizontal_rows)
    accuracy: Dict[str, float] = {}

    if is_labeled:
        total = 0
        correct = 0
        soft_correct = 0
        for row in horizontal_rows:
            expected = row.get("expected_label", "")
            if not expected or expected == "unknown":
                continue
            total += 1
            if row.get("manual_weighted_soft_vote") == expected:
                correct += 1
            if row.get("soft_vote") == expected:
                soft_correct += 1
        accuracy["labeled"] = correct / total if total else 0.0
        accuracy["soft_vote"] = soft_correct / total if total else 0.0
        accuracy["total"] = total
        accuracy["correct"] = correct
        accuracy["soft_correct"] = soft_correct
    else:
        counterpart = find_labeled_counterpart(experiment, folder, ov_folder)
        if counterpart:
            labeled_folder, labeled_ov = counterpart
            label_map = load_cross_label_map(experiment, labeled_folder, labeled_ov)
            total = 0
            correct = 0
            soft_correct = 0
            for row in horizontal_rows:
                raw_key = row.get("image_key", "")
                stem = Path(raw_key).stem if "." in raw_key else raw_key
                expected = label_map.get(stem, "")
                if not expected:
                    continue
                manual_vote = row.get("manual_weighted_soft_vote", "-")
                if manual_vote in ("-", "uncertain", ""):
                    continue
                total += 1
                if manual_vote == expected:
                    correct += 1
                if row.get("soft_vote") == expected:
                    soft_correct += 1
            if total:
                accuracy["cross_accuracy"] = correct / total
                accuracy["cross_soft_vote"] = soft_correct / total
                accuracy["cross_correct"] = correct
                accuracy["cross_soft_correct"] = soft_correct
                accuracy["cross_total"] = total

    preview = [
        {
            "image_key": r.get("image_key"),
            "expected_label": r.get("expected_label", ""),
            "soft_vote": r.get("soft_vote", "-"),
            "manual_weighted_soft_vote": r.get("manual_weighted_soft_vote", "-"),
            "manual_weighted_result_json": r.get("manual_weighted_result_json", "{}"),
        }
        for r in horizontal_rows[:200]
    ]

    return jsonify({
        "weights": core_weights,
        "accuracy": accuracy,
        "is_labeled": is_labeled,
        "preview": preview,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5051, debug=True)
