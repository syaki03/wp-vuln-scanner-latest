from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import zipfile


USER_AGENT = "WP-Vulnerability-Research-Legacy-Artifact-Intake/1.0"
ALLOWED_HOSTS = {"downloads.wordpress.org"}
SCANNER_SUFFIXES = {".php", ".inc", ".module"}
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 25_000
MAX_COMPRESSION_RATIO = 2_000

MANIFEST_FIELDS = (
    "candidate_rank",
    "batch_id",
    "slug",
    "api_version",
    "plugin_header_version",
    "version_check",
    "active_installs",
    "last_updated",
    "requires",
    "tested",
    "requires_php",
    "source_php_compatibility",
    "post_7_1_syntax_hits",
    "download_url",
    "final_url",
    "zip_path",
    "artifact_sha256",
    "archive_bytes",
    "archive_members",
    "uncompressed_bytes",
    "archive_root",
    "plugin_path",
    "scanner_target_files",
    "tree_sha256",
    "artifact_status",
    "scan_inclusion",
    "error",
    "checked_at_utc",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download, validate and safely extract a fixed WordPress.org plugin cohort."
    )
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--limit", type=int, default=0)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda p: p.as_posix().casefold()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
        digest.update(b"\0")
    return digest.hexdigest()


def read_cohort(path: Path, limit: int) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "candidate_rank",
            "batch_id",
            "slug",
            "version",
            "active_installs",
            "last_updated",
            "requires",
            "tested",
            "requires_php",
            "download_link",
        }
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(f"cohort is missing required columns: {sorted(required)}")
        rows = [dict(row) for row in reader]
    if limit > 0:
        rows = rows[:limit]
    slugs = [row["slug"] for row in rows]
    if len(slugs) != len(set(slugs)):
        raise ValueError("cohort contains duplicate slugs")
    return rows


def validate_download_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"download URL is outside the HTTPS allowlist: {url}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"download URL contains unsupported authority/query data: {url}")
    if not parsed.path.startswith("/plugin/") or not parsed.path.lower().endswith(".zip"):
        raise ValueError(f"download URL is not a WordPress.org plugin ZIP: {url}")


def download(url: str, destination: Path, timeout: float, retries: int) -> tuple[str, int]:
    validate_download_url(url)
    if destination.exists():
        return url, destination.stat().st_size
    partial = destination.with_suffix(destination.suffix + ".partial")
    if partial.exists():
        partial.unlink()
    destination.parent.mkdir(parents=True, exist_ok=True)
    last_error = ""
    for attempt in range(1, retries + 1):
        try:
            request = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(request, timeout=timeout) as response, partial.open("wb") as handle:
                final_url = response.geturl()
                validate_download_url(final_url)
                total = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ValueError(f"download exceeds {MAX_DOWNLOAD_BYTES} bytes")
                    handle.write(chunk)
            with partial.open("rb") as handle:
                signature = handle.read(4)
            if total < 4 or signature != b"PK\x03\x04":
                raise ValueError("download is not a ZIP file")
            partial.replace(destination)
            return final_url, total
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if partial.exists():
                partial.unlink()
            if attempt < retries:
                time.sleep(min(3.0, attempt))
    raise RuntimeError(last_error or "download failed")


def safe_members(archive: zipfile.ZipFile, expected_slug: str) -> tuple[list[tuple[zipfile.ZipInfo, PurePosixPath]], str, int]:
    infos = archive.infolist()
    if len(infos) > MAX_MEMBERS:
        raise ValueError(f"archive has too many members: {len(infos)}")
    members: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
    roots: set[str] = set()
    seen: set[str] = set()
    uncompressed = 0
    compressed = 0
    for info in infos:
        pure = PurePosixPath(info.filename.replace("\\", "/"))
        if pure.is_absolute() or not pure.parts or ".." in pure.parts:
            raise ValueError(f"unsafe ZIP member: {info.filename}")
        if re.match(r"^[A-Za-z]:", pure.parts[0]):
            raise ValueError(f"drive-qualified ZIP member: {info.filename}")
        roots.add(pure.parts[0])
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode and stat.S_ISLNK(mode):
            raise ValueError(f"symlink ZIP member is not allowed: {info.filename}")
        if info.is_dir():
            continue
        key = pure.as_posix().casefold()
        if key in seen:
            raise ValueError(f"case-insensitive ZIP path collision: {info.filename}")
        seen.add(key)
        uncompressed += info.file_size
        compressed += info.compress_size
        if uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise ValueError(f"archive exceeds {MAX_UNCOMPRESSED_BYTES} uncompressed bytes")
        members.append((info, pure))
    if len(roots) != 1:
        raise ValueError(f"archive must have one top-level root, found: {sorted(roots)[:5]}")
    archive_root = next(iter(roots))
    if archive_root.casefold() != expected_slug.casefold():
        raise ValueError(f"archive root {archive_root!r} does not match slug {expected_slug!r}")
    if compressed and uncompressed / compressed > MAX_COMPRESSION_RATIO:
        raise ValueError("archive compression ratio exceeds safety limit")
    if not any(pure.suffix.lower() in SCANNER_SUFFIXES for _, pure in members):
        raise ValueError("archive has no scanner-target PHP files")
    return members, archive_root, uncompressed


def extract_archive(zip_path: Path, plugin_root: Path, slug: str) -> tuple[int, int, str]:
    destination = plugin_root / slug
    if destination.exists():
        return (
            sum(1 for item in destination.rglob("*") if item.is_file()),
            sum(item.stat().st_size for item in destination.rglob("*") if item.is_file()),
            slug,
        )
    staging = plugin_root / f".{slug}.staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    try:
        with zipfile.ZipFile(zip_path) as archive:
            bad = archive.testzip()
            if bad:
                raise ValueError(f"corrupt ZIP member: {bad}")
            members, archive_root, uncompressed = safe_members(archive, slug)
            for info, pure in members:
                relative = PurePosixPath(*pure.parts[1:])
                if not relative.parts:
                    continue
                target = staging.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("wb") as sink:
                    shutil.copyfileobj(source, sink, length=1024 * 1024)
        staging.replace(destination)
        return len(members), uncompressed, archive_root
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def plugin_header_version(root: Path, slug: str) -> str:
    candidates = sorted(root.glob("*.php"), key=lambda path: (path.name.casefold() != f"{slug}.php".casefold(), path.name.casefold()))
    pattern_name = re.compile(r"^[ \t/*#@]*Plugin Name:\s*(.+?)\s*$", re.I | re.M)
    pattern_version = re.compile(r"^[ \t/*#@]*Version:\s*([^\r\n*]+)", re.I | re.M)
    for path in candidates:
        text = path.read_bytes()[:64 * 1024].decode("utf-8", errors="surrogateescape")
        if not pattern_name.search(text):
            continue
        match = pattern_version.search(text)
        return match.group(1).strip() if match else ""
    return ""


POST_71_PATTERNS = (
    ("arrow_function", re.compile(r"\bfn\s*\([^)]*\)\s*=>")),
    ("null_coalescing_assignment", re.compile(r"\?\?=")),
    ("nullsafe_operator", re.compile(r"\?->")),
    ("php_attribute", re.compile(r"(?m)^\s*#\[")),
    ("match_expression", re.compile(r"\bmatch\s*\(")),
    ("enum_declaration", re.compile(r"\benum\s+[A-Za-z_]")),
    ("readonly_declaration", re.compile(r"\breadonly\s+(?:class|[A-Za-z_\\])")),
    ("constructor_property_promotion", re.compile(r"function\s+__construct\s*\([^)]*\b(?:public|protected|private)\s+[^)]*\$", re.S)),
    ("object_type_hint", re.compile(r"\bobject\s+\$[A-Za-z_]")),
    ("array_unpack", re.compile(r"\[\s*\.\.\.\s*\$")),
)


def post_71_syntax_hits(root: Path) -> list[str]:
    hits: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SCANNER_SUFFIXES:
            continue
        text = path.read_bytes().decode("utf-8", errors="surrogateescape")
        for label, pattern in POST_71_PATTERNS:
            if pattern.search(text):
                hits.add(label)
    return sorted(hits)


def scanner_target_count(root: Path) -> int:
    return sum(
        1
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in SCANNER_SUFFIXES
    )


def receipt_path(receipt_root: Path, slug: str) -> Path:
    return receipt_root / f"{slug}.json"


def write_receipt(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.partial")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def process_candidate(row: dict[str, str], args: argparse.Namespace) -> dict[str, Any]:
    slug = row["slug"]
    receipts = args.output_dir / "artifact-receipts"
    existing_receipt = receipt_path(receipts, slug)
    if existing_receipt.exists():
        previous = json.loads(existing_receipt.read_text(encoding="utf-8"))
        previous_zip = Path(str(previous.get("zip_path", "")))
        previous_plugin = Path(str(previous.get("plugin_path", "")))
        if (
            previous.get("artifact_status") == "ready"
            and previous_zip.is_file()
            and previous_plugin.is_dir()
            and sha256_file(previous_zip) == previous.get("artifact_sha256")
            and tree_fingerprint(previous_plugin) == previous.get("tree_sha256")
        ):
            return previous

    checked_at = datetime.now(timezone.utc).isoformat()
    zip_path = args.output_dir / "downloads" / f"{slug}.{row['version']}.zip"
    plugin_path = args.output_dir / "plugins" / slug
    base: dict[str, Any] = {
        "candidate_rank": row["candidate_rank"],
        "batch_id": row["batch_id"],
        "slug": slug,
        "api_version": row["version"],
        "plugin_header_version": "",
        "version_check": "not_checked",
        "active_installs": row["active_installs"],
        "last_updated": row["last_updated"],
        "requires": row["requires"],
        "tested": row["tested"],
        "requires_php": row["requires_php"],
        "source_php_compatibility": "not_checked",
        "post_7_1_syntax_hits": "",
        "download_url": row["download_link"],
        "final_url": "",
        "zip_path": str(zip_path.resolve()),
        "artifact_sha256": "",
        "archive_bytes": "",
        "archive_members": "",
        "uncompressed_bytes": "",
        "archive_root": "",
        "plugin_path": str(plugin_path.resolve()),
        "scanner_target_files": "",
        "tree_sha256": "",
        "artifact_status": "error",
        "scan_inclusion": "excluded_download_or_archive_error",
        "error": "",
        "checked_at_utc": checked_at,
    }
    try:
        final_url, archive_bytes = download(
            row["download_link"], zip_path, args.timeout, args.retries
        )
        archive_members, uncompressed_bytes, archive_root = extract_archive(
            zip_path, args.output_dir / "plugins", slug
        )
        header_version = plugin_header_version(plugin_path, slug)
        version_check = (
            "match"
            if header_version == row["version"]
            else "missing_header_version"
            if not header_version
            else "mismatch"
        )
        syntax_hits = post_71_syntax_hits(plugin_path) if not row["requires_php"] else []
        if row["requires_php"]:
            compatibility = "metadata_requires_php_le_7_1"
        elif syntax_hits:
            compatibility = "post_7_1_syntax_detected"
        else:
            compatibility = "heuristic_no_post_7_1_syntax_detected"
        target_count = scanner_target_count(plugin_path)
        base.update(
            {
                "plugin_header_version": header_version,
                "version_check": version_check,
                "source_php_compatibility": compatibility,
                "post_7_1_syntax_hits": ";".join(syntax_hits),
                "final_url": final_url,
                "artifact_sha256": sha256_file(zip_path),
                "archive_bytes": archive_bytes,
                "archive_members": archive_members,
                "uncompressed_bytes": uncompressed_bytes,
                "archive_root": archive_root,
                "scanner_target_files": target_count,
                "tree_sha256": tree_fingerprint(plugin_path),
                "artifact_status": "ready",
                "scan_inclusion": "included",
                "error": "",
            }
        )
    except Exception as exc:
        base["error"] = f"{type(exc).__name__}: {exc}"
    write_receipt(existing_receipt, base)
    return base


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    if args.workers < 1 or args.retries < 1:
        raise ValueError("workers and retries must be positive")
    rows = read_cohort(args.cohort, args.limit)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    cohort_hash = sha256_file(args.cohort)

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(process_candidate, row, args): row["slug"] for row in rows
        }
        for index, future in enumerate(as_completed(futures), start=1):
            results.append(future.result())
            if index % 25 == 0 or index == len(rows):
                ready = sum(item["artifact_status"] == "ready" for item in results)
                print(f"[{index}/{len(rows)}] ready={ready} errors={index-ready}", flush=True)

    results.sort(key=lambda item: int(item["candidate_rank"]))
    manifest_path = args.output_dir / "artifact_manifest.csv"
    write_csv(manifest_path, results)
    status_counts: dict[str, int] = {}
    compatibility_counts: dict[str, int] = {}
    version_counts: dict[str, int] = {}
    for item in results:
        status_counts[item["artifact_status"]] = status_counts.get(item["artifact_status"], 0) + 1
        compatibility_counts[item["source_php_compatibility"]] = compatibility_counts.get(item["source_php_compatibility"], 0) + 1
        version_counts[item["version_check"]] = version_counts.get(item["version_check"], 0) + 1

    summary = {
        "schema_version": 1,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "cohort_path": str(args.cohort.resolve()),
        "cohort_sha256": cohort_hash,
        "candidate_count": len(rows),
        "status_counts": dict(sorted(status_counts.items())),
        "scan_included": sum(item["scan_inclusion"] == "included" for item in results),
        "scanner_target_files": sum(int(item["scanner_target_files"] or 0) for item in results),
        "compatibility_counts": dict(sorted(compatibility_counts.items())),
        "version_check_counts": dict(sorted(version_counts.items())),
        "artifact_manifest_sha256": sha256_file(manifest_path),
        "allowed_download_hosts": sorted(ALLOWED_HOSTS),
        "safety_limits": {
            "max_download_bytes_per_plugin": MAX_DOWNLOAD_BYTES,
            "max_uncompressed_bytes_per_plugin": MAX_UNCOMPRESSED_BYTES,
            "max_archive_members_per_plugin": MAX_MEMBERS,
            "max_compression_ratio": MAX_COMPRESSION_RATIO,
            "zip_traversal_rejected": True,
            "zip_symlinks_rejected": True,
            "single_slug_root_required": True,
        },
    }
    summary_path = args.output_dir / "artifact_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if status_counts.get("error", 0) == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
