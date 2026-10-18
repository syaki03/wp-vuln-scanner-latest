from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
from typing import Any


DEFAULT_ELIGIBLE_COMPATIBILITY = (
    "metadata_requires_php_le_7_1",
    "heuristic_no_post_7_1_syntax_detected",
)
REQUIRED_COLUMNS = {
    "slug",
    "artifact_status",
    "scan_inclusion",
    "tree_sha256",
    "source_php_compatibility",
}
SCANNER_SUFFIXES = {".php", ".inc", ".module"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a deterministic scan-ready tree from ready artifacts whose "
            "source PHP compatibility is eligible."
        )
    )
    parser.add_argument("--artifact-manifest", type=Path, required=True)
    parser.add_argument("--extracted-plugin-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--eligible-source-php-compatibility",
        action="append",
        default=[],
        help=(
            "repeatable compatibility value to include; default is "
            "metadata_requires_php_le_7_1 and "
            "heuristic_no_post_7_1_syntax_detected"
        ),
    )
    parser.add_argument(
        "--hold-slug",
        action="append",
        default=[],
        help=(
            "exact plugin slug to hold as WordPress requirement greater than 5.3; "
            "repeatable and duplicate values are rejected"
        ),
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda path: path.relative_to(root).as_posix().casefold(),
    )
    for path in files:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
        digest.update(b"\0")
    return digest.hexdigest()


def require_sha256(value: str, label: str) -> None:
    if len(value) != 64:
        raise ValueError(f"{label} must be a 64-character SHA-256 hex digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a 64-character SHA-256 hex digest") from exc


def read_manifest(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(reader.fieldnames):
            raise ValueError(
                "artifact manifest is missing required columns: "
                f"{sorted(REQUIRED_COLUMNS)}"
            )
        fieldnames = list(reader.fieldnames)
        rows = [dict(row) for row in reader]
    if not rows:
        raise ValueError("artifact manifest has no rows")
    slugs = [row["slug"].strip() for row in rows]
    if any(not slug for slug in slugs):
        raise ValueError("artifact manifest has a blank slug")
    if len(slugs) != len(set(slugs)):
        raise ValueError("artifact manifest has duplicate slugs")
    if any(row["artifact_status"] != "ready" for row in rows):
        raise ValueError("artifact manifest contains a non-ready artifact")
    for row in rows:
        require_sha256(row["tree_sha256"], f"tree_sha256 for {row['slug']}")
    return fieldnames, rows


def resolved_child(root: Path, slug: str) -> Path:
    if Path(slug).name != slug or slug in {".", ".."}:
        raise ValueError(f"unsafe plugin slug: {slug!r}")
    candidate = root / slug
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"plugin path escapes extracted root: {slug!r}") from exc
    return candidate


def validate_tree(root: Path, slug: str, expected_hash: str) -> Path:
    plugin = resolved_child(root, slug)
    if plugin.is_symlink() or not plugin.is_dir():
        raise ValueError(f"plugin directory is missing or symlinked: {slug}")
    seen: set[str] = set()
    for item in plugin.rglob("*"):
        relative = item.relative_to(plugin).as_posix()
        key = relative.casefold()
        if key in seen:
            raise ValueError(f"case-insensitive path collision in {slug}: {relative}")
        seen.add(key)
        if item.is_symlink():
            raise ValueError(f"symlink anomaly in {slug}: {relative}")
        mode = item.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError(f"unsupported filesystem entry in {slug}: {relative}")
    actual_hash = tree_fingerprint(plugin)
    if actual_hash != expected_hash:
        raise ValueError(f"tree hash mismatch for {slug}")
    return plugin


def inclusion_for(row: dict[str, str], eligible: set[str], hold_slugs: set[str]) -> str:
    if row["slug"] in hold_slugs:
        return "hold_wordpress_requirement_gt_5_3"
    compatibility = row["source_php_compatibility"]
    if compatibility in eligible:
        return "included"
    if compatibility == "post_7_1_syntax_detected":
        return "hold_post_php_7_1_syntax"
    return "hold_source_php_compatibility_not_eligible"


def copy_tree(source: Path, destination: Path) -> tuple[int, int]:
    files = 0
    hardlinked = 0
    destination.mkdir()
    for item in sorted(source.rglob("*"), key=lambda path: path.relative_to(source).as_posix().casefold()):
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_dir():
            target.mkdir()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(item, target)
            hardlinked += 1
        except OSError:
            shutil.copy2(item, target)
        files += 1
    return files, hardlinked


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def included_tree_fingerprint(rows: list[dict[str, str]]) -> str:
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item["slug"]):
        digest.update(row["slug"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(row["tree_sha256"]))
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    args = parse_args()
    manifest = args.artifact_manifest.resolve()
    source_root = args.extracted_plugin_root.resolve()
    output = args.output_dir.resolve()
    if not manifest.is_file():
        raise ValueError(f"artifact manifest not found: {manifest}")
    if not source_root.is_dir():
        raise ValueError(f"extracted plugin root not found: {source_root}")
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"output directory must be absent or empty: {output}")

    fieldnames, rows = read_manifest(manifest)
    eligible = set(args.eligible_source_php_compatibility or DEFAULT_ELIGIBLE_COMPATIBILITY)
    if not eligible:
        raise ValueError("at least one eligible source PHP compatibility value is required")
    hold_slug_values = list(args.hold_slug)
    if any(not slug or Path(slug).name != slug or slug in {".", ".."} for slug in hold_slug_values):
        raise ValueError("hold-slug must be a non-empty exact slug")
    if len(hold_slug_values) != len(set(hold_slug_values)):
        raise ValueError("duplicate hold-slug values are not allowed")
    hold_slugs = set(hold_slug_values)
    manifest_slugs = {row["slug"] for row in rows}
    unknown_holds = sorted(hold_slugs - manifest_slugs)
    if unknown_holds:
        raise ValueError(f"hold-slug is not present in artifact manifest: {unknown_holds[0]}")

    sources: dict[str, Path] = {}
    for row in rows:
        sources[row["slug"]] = validate_tree(source_root, row["slug"], row["tree_sha256"])

    prepared_rows: list[dict[str, str]] = []
    for row in rows:
        prepared = dict(row)
        prepared["scan_inclusion"] = inclusion_for(row, eligible, hold_slugs)
        prepared_rows.append(prepared)
    included = [row for row in prepared_rows if row["scan_inclusion"] == "included"]

    output.mkdir(parents=True, exist_ok=True)
    hardlinked_files = 0
    copied_files = 0
    for row in included:
        files, hardlinks = copy_tree(sources[row["slug"]], output / row["slug"])
        hardlinked_files += hardlinks
        copied_files += files - hardlinks
        if tree_fingerprint(output / row["slug"]) != row["tree_sha256"]:
            raise ValueError(f"prepared tree hash mismatch for {row['slug']}")

    actual_dirs = {item.name for item in output.iterdir() if item.is_dir()}
    expected_dirs = {row["slug"] for row in included}
    if actual_dirs != expected_dirs or any(not item.is_dir() for item in output.iterdir()):
        raise ValueError("prepared output root does not contain exactly included plugin directories")

    manifest_path = output / "scan_artifact_manifest.csv"
    write_csv(manifest_path, fieldnames, prepared_rows)
    summary = {
        "schema_version": 1,
        "input_artifact_manifest": str(manifest),
        "input_artifact_manifest_sha256": sha256_file(manifest),
        "extracted_plugin_root": str(source_root),
        "eligible_source_php_compatibility": sorted(eligible),
        "hold_slugs_wordpress_requirement_gt_5_3": sorted(hold_slugs),
        "artifact_count": len(prepared_rows),
        "included_count": len(included),
        "hold_count": len(prepared_rows) - len(included),
        "included_tree_fingerprint_sha256": included_tree_fingerprint(included),
        "scan_inclusion_counts": {
            value: sum(row["scan_inclusion"] == value for row in prepared_rows)
            for value in sorted({row["scan_inclusion"] for row in prepared_rows})
        },
        "tree_materialization": {
            "hardlinked_files": hardlinked_files,
            "copied_files": copied_files,
            "mode": "hardlink_with_copy_fallback",
        },
        "artifacts": {
            "scan_artifact_manifest.csv": sha256_file(manifest_path),
        },
    }
    summary_path = output / "scan_cohort_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
