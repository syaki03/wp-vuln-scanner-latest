from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


V111_ROOT = Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the current v1.11 scanner against one validated artifact manifest."
    )
    parser.add_argument("--artifact-manifest", type=Path, required=True)
    parser.add_argument("--plugin-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scanner_fingerprint() -> tuple[str, int]:
    paths = [V111_ROOT / "main.py", V111_ROOT / "config.py"]
    paths.extend(path for path in (V111_ROOT / "scanner").rglob("*.py") if path.is_file())
    paths.extend(path for path in (V111_ROOT / "rules").rglob("*.py") if path.is_file())
    digest = hashlib.sha256()
    unique_paths = sorted(set(paths), key=lambda path: path.relative_to(V111_ROOT).as_posix())
    for path in unique_paths:
        relative = path.relative_to(V111_ROOT).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
        digest.update(b"\0")
    return digest.hexdigest(), len(unique_paths)


def read_manifest(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"slug", "artifact_status", "scan_inclusion", "tree_sha256"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(f"artifact manifest is missing required columns: {sorted(required)}")
        rows = [dict(row) for row in reader]
    included = [row for row in rows if row["scan_inclusion"] == "included"]
    if any(row["artifact_status"] != "ready" for row in included):
        raise ValueError("included manifest row is not artifact_status=ready")
    slugs = [row["slug"] for row in included]
    if len(slugs) != len(set(slugs)):
        raise ValueError("artifact manifest has duplicate included slugs")
    return included


def validate_plugin_root(plugin_root: Path, rows: list[dict[str, str]]) -> None:
    actual = {path.name for path in plugin_root.iterdir() if path.is_dir() and not path.name.startswith(".")}
    expected = {row["slug"] for row in rows}
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"plugin root mismatch: missing={missing[:10]} extra={extra[:10]}")


def input_fingerprint(rows: list[dict[str, str]]) -> str:
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item["slug"]):
        digest.update(row["slug"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(row["tree_sha256"]))
        digest.update(b"\0")
    return digest.hexdigest()


def findings_summary(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    severity_counts: dict[str, int] = {}
    for row in rows:
        severity = row.get("severity", "")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {
        "finding_count": len(rows),
        "finding_plugins": len({row.get("plugin", "") for row in rows if row.get("plugin", "")}),
        "severity_counts": dict(sorted(severity_counts.items())),
        "scan_error_count": sum(row.get("type") == "SCAN_ERROR" for row in rows),
    }


def main() -> int:
    args = parse_args()
    artifact_manifest = args.artifact_manifest.resolve()
    plugin_root = args.plugin_root.resolve()
    output_dir = args.output_dir.resolve()
    if not artifact_manifest.is_file():
        raise ValueError(f"artifact manifest not found: {artifact_manifest}")
    if not plugin_root.is_dir():
        raise ValueError(f"plugin root not found: {plugin_root}")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"output directory must be absent or empty: {output_dir}")

    rows = read_manifest(artifact_manifest)
    validate_plugin_root(plugin_root, rows)
    scanner_sha256, scanner_file_count = scanner_fingerprint()
    started_at = datetime.now(timezone.utc)

    sys.path.insert(0, str(V111_ROOT))
    import config  # noqa: PLC0415

    config.PLUGIN_ROOT = plugin_root
    config.OUTPUT_DIR = output_dir
    import main as scanner_main  # noqa: PLC0415

    scanner_main.PLUGIN_ROOT = plugin_root
    scanner_main.OUTPUT_DIR = output_dir
    exit_code = scanner_main.main()
    if exit_code:
        return int(exit_code)

    findings_path = output_dir / "findings.csv"
    findings_json = output_dir / "findings.json"
    report_html = output_dir / "report.html"
    for path in (findings_path, findings_json, report_html):
        if not path.is_file():
            raise ValueError(f"scanner output missing: {path}")

    completed_at = datetime.now(timezone.utc)
    summary = {
        "schema_version": 1,
        "started_at_utc": started_at.isoformat(),
        "completed_at_utc": completed_at.isoformat(),
        "duration_seconds": round((completed_at - started_at).total_seconds(), 3),
        "artifact_manifest": str(artifact_manifest),
        "artifact_manifest_sha256": sha256_file(artifact_manifest),
        "plugin_root": str(plugin_root),
        "input_plugin_count": len(rows),
        "input_fingerprint_sha256": input_fingerprint(rows),
        "scanner_fingerprint_sha256": scanner_sha256,
        "scanner_file_count": scanner_file_count,
        **findings_summary(findings_path),
        "outputs": {
            "findings.csv": sha256_file(findings_path),
            "findings.json": sha256_file(findings_json),
            "report.html": sha256_file(report_html),
        },
    }
    run_path = output_dir / "scan_run.json"
    run_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
