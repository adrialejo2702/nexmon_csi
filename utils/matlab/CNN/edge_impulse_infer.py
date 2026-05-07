#!/usr/bin/env python3
"""
Run Edge Impulse Studio inference from local images.

Supports:
- Single image test
- Batch folder test with CSV/JSON export
"""

import argparse
import csv
import json
import mimetypes
import os
import pathlib
import uuid
from typing import Dict, List, Optional, Tuple
from urllib import error, parse, request


EDGE_IMPULSE_BASE_URL = "https://studio.edgeimpulse.com/v1/api"
SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"}


def build_multipart_form(image_path: pathlib.Path) -> Tuple[bytes, str]:
    boundary = f"----edgeimpulse-boundary-{uuid.uuid4().hex}"
    mime_type = mimetypes.guess_type(str(image_path))[0] or "application/octet-stream"
    file_name = image_path.name
    file_content = image_path.read_bytes()

    body_start = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="image"; filename="{file_name}"\r\n'
        f"Content-Type: {mime_type}\r\n\r\n"
    ).encode("utf-8")
    body_end = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = body_start + file_content + body_end
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def classify_image(
    api_key: str,
    project_id: str,
    image_path: pathlib.Path,
    impulse_id: Optional[str] = None,
    timeout_seconds: int = 60,
) -> Dict:
    if not image_path.exists() or not image_path.is_file():
        raise FileNotFoundError(f"Image does not exist or is not a file: {image_path}")

    query = {}
    if impulse_id:
        query["impulseId"] = impulse_id
    query_string = f"?{parse.urlencode(query)}" if query else ""
    endpoint = f"{EDGE_IMPULSE_BASE_URL}/{project_id}/classify/image{query_string}"

    body, content_type = build_multipart_form(image_path)

    req = request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "x-api-key": api_key,
            "Content-Type": content_type,
            "Accept": "application/json",
        },
    )

    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} calling Edge Impulse API: {detail}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Network error calling Edge Impulse API: {exc}") from exc


def extract_top_result(api_response: Dict) -> Tuple[Optional[str], Optional[float]]:
    result = api_response.get("result", {})
    if not isinstance(result, dict) or not result:
        return None, None
    top_label = max(result, key=result.get)
    return top_label, float(result[top_label])


def list_images(input_dir: pathlib.Path) -> List[pathlib.Path]:
    if not input_dir.exists() or not input_dir.is_dir():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")
    images = [
        p
        for p in sorted(input_dir.rglob("*"))
        if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS
    ]
    return images


def save_json(path: pathlib.Path, rows: List[Dict]) -> None:
    path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")


def save_csv(path: pathlib.Path, rows: List[Dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    keys = set()
    for row in rows:
        keys.update(row.keys())
    ordered_keys = sorted(keys)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ordered_keys)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test a trained Edge Impulse model with local images via API key."
    )
    parser.add_argument("--project-id", required=True, help="Edge Impulse project ID.")
    parser.add_argument("--api-key", required=True, help="Edge Impulse API key.")
    parser.add_argument("--impulse-id", help="Optional impulse ID.")
    parser.add_argument("--image", help="Path to a single image for one-shot inference.")
    parser.add_argument("--input-dir", help="Directory with images for batch inference.")
    parser.add_argument(
        "--output-json",
        default="edge_impulse_results.json",
        help="Output JSON file path for batch mode.",
    )
    parser.add_argument(
        "--output-csv",
        default="edge_impulse_results.csv",
        help="Output CSV file path for batch mode.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=60,
        help="HTTP timeout for each request.",
    )
    args = parser.parse_args()

    if bool(args.image) == bool(args.input_dir):
        raise ValueError("Use exactly one mode: --image or --input-dir.")

    if args.image:
        image_path = pathlib.Path(args.image).expanduser().resolve()
        response = classify_image(
            api_key=args.api_key,
            project_id=args.project_id,
            image_path=image_path,
            impulse_id=args.impulse_id,
            timeout_seconds=args.timeout_seconds,
        )
        label, score = extract_top_result(response)
        print(f"image: {image_path}")
        print(f"top_label: {label}")
        print(f"top_score: {score}")
        print(json.dumps(response, indent=2, ensure_ascii=False))
        return

    input_dir = pathlib.Path(args.input_dir).expanduser().resolve()
    images = list_images(input_dir)
    if not images:
        raise RuntimeError(f"No supported images found in directory: {input_dir}")

    rows: List[Dict] = []
    for image_path in images:
        try:
            response = classify_image(
                api_key=args.api_key,
                project_id=args.project_id,
                image_path=image_path,
                impulse_id=args.impulse_id,
                timeout_seconds=args.timeout_seconds,
            )
            label, score = extract_top_result(response)
            row = {
                "image_path": str(image_path),
                "top_label": label,
                "top_score": score,
                "success": response.get("success"),
                "error": response.get("error"),
                "result_json": json.dumps(response.get("result", {}), ensure_ascii=False),
            }
        except Exception as exc:  # pylint: disable=broad-except
            row = {
                "image_path": str(image_path),
                "top_label": None,
                "top_score": None,
                "success": False,
                "error": str(exc),
                "result_json": "{}",
            }
        rows.append(row)
        print(f"processed: {image_path}")

    output_json = pathlib.Path(args.output_json).expanduser().resolve()
    output_csv = pathlib.Path(args.output_csv).expanduser().resolve()
    save_json(output_json, rows)
    save_csv(output_csv, rows)
    print(f"batch_done: {len(rows)} images")
    print(f"json: {output_json}")
    print(f"csv: {output_csv}")


if __name__ == "__main__":
    main()
