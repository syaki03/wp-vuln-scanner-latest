from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


API_URL = "https://api.wordpress.org/plugins/info/1.2/"
API_DOC_URL = "https://developer.wordpress.org/reference/functions/plugins_api/"
USER_AGENT = "WP-Vulnerability-Research-Legacy-Cohort/1.0"

AUDIT_FIELDS = (
    "slug",
    "name",
    "version",
    "active_installs",
    "last_updated",
    "requires",
    "tested",
    "requires_php",
    "download_link",
    "disposition",
    "reason",
)

CANDIDATE_FIELDS = (
    "candidate_rank",
    "batch_id",
    "batch_position",
    "slug",
    "name",
    "version",
    "active_installs",
    "last_updated",
    "requires",
    "tested",
    "requires_php",
    "download_link",
    "metadata_completeness",
    "missing_metadata_fields",
    "artifact_release_check",
    "source_wordpress_compatibility_check",
    "source_php_compatibility_check",
    "download_status",
    "artifact_sha256",
    "scan_status",
    "review_status",
    "matching_cve_path_check",
    "wordfence_scope_check",
    "selection_key_sha256",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a reproducible WordPress.org cohort of public, active-install, "
            "date-bounded plugin releases outside existing local corpora."
        )
    )
    parser.add_argument("--existing-plugin-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--min-active-installs", type=int, default=500)
    release_group = parser.add_mutually_exclusive_group()
    release_group.add_argument(
        "--release-cutoff",
        help="inclusive legacy cutoff date (default: 2019-12-31)",
    )
    release_group.add_argument(
        "--release-year",
        type=int,
        help="select exactly one WordPress.org last_updated calendar year",
    )
    parser.add_argument(
        "--existing-slug-csv",
        action="append",
        type=Path,
        default=[],
        help="additional CSV containing a slug column; repeatable",
    )
    parser.add_argument("--max-wordpress", default="5.3")
    parser.add_argument("--max-php", default="7.1")
    parser.add_argument(
        "--compatibility-policy",
        choices=("filter", "record-only"),
        default="filter",
        help="filter on WP/PHP metadata or retain it for post-download source checks",
    )
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--page-size", action="append", type=int, default=[])
    parser.add_argument("--page-block-size", type=int, default=10)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=3)
    return parser.parse_args()


def parse_series(value: Any) -> tuple[int, int] | None:
    if value is None or value is False:
        return None
    match = re.match(r"^\s*(\d+)(?:\.(\d+))?", str(value))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2) or 0)


def parse_last_updated(value: Any) -> datetime | None:
    if value is None or value is False:
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %I:%M%p GMT", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text.upper(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def normalized_text(value: Any) -> str:
    if value is None or value is False:
        return ""
    return str(value).strip()


def release_window(args: argparse.Namespace) -> tuple[datetime | None, datetime, str]:
    if args.release_year is not None:
        if args.release_year < 2003 or args.release_year > 9998:
            raise ValueError("release-year must be between 2003 and 9998")
        start = datetime(args.release_year, 1, 1, tzinfo=timezone.utc)
        end = datetime(args.release_year + 1, 1, 1, tzinfo=timezone.utc)
        return start, end, f"{args.release_year}-01-01 <= last_updated < {args.release_year + 1}-01-01"
    cutoff_text = args.release_cutoff or "2019-12-31"
    cutoff_inclusive = datetime.strptime(cutoff_text, "%Y-%m-%d").replace(
        tzinfo=timezone.utc
    )
    end = cutoff_inclusive + timedelta(days=1)
    return None, end, f"last_updated on or before {cutoff_text}"


def load_existing_slugs(plugin_root: Path, slug_csvs: list[Path]) -> tuple[set[str], dict[str, int]]:
    slugs = {
        path.name.casefold() for path in plugin_root.iterdir() if path.is_dir()
    }
    counts = {"plugin_root_directories": len(slugs)}
    for path in slug_csvs:
        if not path.is_file():
            raise ValueError(f"existing slug CSV not found: {path}")
        before = len(slugs)
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or "slug" not in reader.fieldnames:
                raise ValueError(f"existing slug CSV must contain a slug column: {path}")
            for row in reader:
                slug = normalized_text(row.get("slug"))
                if slug:
                    slugs.add(slug.casefold())
        counts[str(path.resolve())] = len(slugs) - before
    counts["unique_existing_slugs"] = len(slugs)
    return slugs, counts


def fetch_json(url: str, timeout: float, retries: int) -> dict[str, Any]:
    last_error = ""
    for attempt in range(1, retries + 1):
        try:
            request = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("non-object API response")
            return payload
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < retries:
                time.sleep(min(2.0, 0.5 * attempt))
    raise RuntimeError(last_error or "request failed")


def query_url(page_size: int, page: int) -> str:
    params: dict[str, Any] = {
        "action": "query_plugins",
        "request[page]": page,
        "request[per_page]": page_size,
        "request[browse]": "popular",
        "request[fields][active_installs]": 1,
        "request[fields][sections]": 0,
        "request[fields][short_description]": 0,
        "request[fields][description]": 0,
        "request[fields][icons]": 0,
        "request[fields][banners]": 0,
        "request[fields][tags]": 0,
        "request[fields][contributors]": 0,
        "request[fields][reviews]": 0,
    }
    return API_URL + "?" + urlencode(params)


def fetch_page(
    page_size: int,
    page: int,
    timeout: float,
    retries: int,
) -> tuple[int, int, list[dict[str, Any]], dict[str, Any]]:
    payload = fetch_json(query_url(page_size, page), timeout, retries)
    plugins = payload.get("plugins")
    info = payload.get("info")
    if not isinstance(plugins, list) or not isinstance(info, dict):
        raise ValueError(f"invalid query_plugins response for page_size={page_size} page={page}")
    return page_size, page, [item for item in plugins if isinstance(item, dict)], info


def collect_popular_pages(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    page_sizes = sorted(set(args.page_size or [100, 250]))
    collected: list[dict[str, Any]] = []
    fetch_counts: dict[str, int] = {}
    reported_results: set[int] = set()

    for page_size in page_sizes:
        page = 1
        fetched_for_size = 0
        while True:
            page_numbers = list(range(page, page + args.page_block_size))
            block: list[tuple[int, int, list[dict[str, Any]], dict[str, Any]]] = []
            with ThreadPoolExecutor(max_workers=min(args.workers, len(page_numbers))) as executor:
                futures = {
                    executor.submit(
                        fetch_page,
                        page_size,
                        page_number,
                        args.timeout,
                        args.retries,
                    ): page_number
                    for page_number in page_numbers
                }
                for future in as_completed(futures):
                    block.append(future.result())

            block.sort(key=lambda item: item[1])
            fetched_for_size += len(block)
            for _, _, plugins, info in block:
                collected.extend(plugins)
                if "results" in info:
                    reported_results.add(int(info["results"]))

            final_plugins = block[-1][2]
            final_max = max(
                (int(item.get("active_installs") or 0) for item in final_plugins),
                default=0,
            )
            if final_max < args.min_active_installs:
                break
            page += args.page_block_size

        fetch_counts[str(page_size)] = fetched_for_size

    if not reported_results:
        raise ValueError("WordPress.org did not report the directory result count")
    return collected, {
        "page_sizes": page_sizes,
        "pages_fetched_by_size": fetch_counts,
        "api_reported_plugins_min": min(reported_results),
        "api_reported_plugins_max": max(reported_results),
        "api_reported_plugins_changed_during_collection": len(reported_results) > 1,
    }


def canonical_plugins(
    rows: list[dict[str, Any]], min_active_installs: int
) -> tuple[list[dict[str, Any]], int, list[str]]:
    by_slug: dict[str, dict[str, Any]] = {}
    duplicate_slots = 0
    conflicts: set[str] = set()
    for item in rows:
        if int(item.get("active_installs") or 0) < min_active_installs:
            continue
        slug = normalized_text(item.get("slug"))
        if not slug:
            continue
        normalized = {
            "slug": slug,
            "name": normalized_text(item.get("name")),
            "version": normalized_text(item.get("version")),
            "active_installs": int(item.get("active_installs") or 0),
            "last_updated": normalized_text(item.get("last_updated")),
            "requires": normalized_text(item.get("requires")),
            "tested": normalized_text(item.get("tested")),
            "requires_php": normalized_text(item.get("requires_php")),
            "download_link": normalized_text(item.get("download_link")),
        }
        previous = by_slug.get(slug)
        if previous is not None:
            duplicate_slots += 1
            if previous != normalized:
                conflicts.add(slug)
            continue
        by_slug[slug] = normalized
    return sorted(by_slug.values(), key=lambda item: item["slug"]), duplicate_slots, sorted(conflicts)


def disposition(
    plugin: dict[str, Any],
    existing_slugs: set[str],
    window_start: datetime | None,
    window_end: datetime,
    max_wordpress: tuple[int, int],
    max_php: tuple[int, int],
    compatibility_policy: str = "filter",
) -> tuple[str, str]:
    slug = plugin["slug"]
    if slug.casefold() in existing_slugs:
        return "existing_corpus", "slug already exists in an excluded corpus or cohort"

    updated = parse_last_updated(plugin["last_updated"])
    if updated is None:
        return "hold_invalid_last_updated", "last_updated is missing or unparsable"
    if window_start is not None and updated < window_start:
        return "updated_before_window", "current release proxy is before the selected date window"
    if updated >= window_end:
        return "updated_after_window", "current release proxy is after the selected date window"

    if compatibility_policy == "filter":
        for field in ("requires", "tested"):
            parsed = parse_series(plugin[field])
            if parsed is not None and parsed > max_wordpress:
                return "wordpress_requirement_too_new", f"{field}={plugin[field]} exceeds the WordPress limit"

        parsed_php = parse_series(plugin["requires_php"])
        if parsed_php is not None and parsed_php > max_php:
            return "php_requirement_too_new", f"requires_php={plugin['requires_php']} exceeds the PHP limit"

    if not plugin["version"] or not plugin["download_link"]:
        return "hold_missing_artifact_identity", "version or official download_link is missing"
    return "candidate", "passes metadata prefilter; artifact checks remain pending"


def write_csv(path: Path, fieldnames: tuple[str, ...], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    args = parse_args()
    if args.min_active_installs < 1 or args.batch_size < 1:
        raise ValueError("min-active-installs and batch-size must be positive")
    if args.page_block_size < 1 or args.workers < 1 or args.retries < 1:
        raise ValueError("page-block-size, workers and retries must be positive")
    if not args.existing_plugin_root.is_dir():
        raise ValueError(f"existing plugin root not found: {args.existing_plugin_root}")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise ValueError(f"output directory must be absent or empty: {args.output_dir}")

    window_start, window_end, window_description = release_window(args)
    max_wordpress = parse_series(args.max_wordpress)
    max_php = parse_series(args.max_php)
    if max_wordpress is None or max_php is None:
        raise ValueError("max-wordpress and max-php must begin with numeric major.minor versions")

    existing_slugs, existing_slug_counts = load_existing_slugs(
        args.existing_plugin_root, args.existing_slug_csv
    )
    raw_rows, collection = collect_popular_pages(args)
    plugins, duplicate_slots, conflicts = canonical_plugins(raw_rows, args.min_active_installs)
    if conflicts:
        raise ValueError(f"metadata changed during collection for {len(conflicts)} slugs: {conflicts[:10]}")

    audit_rows: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    disposition_counts: dict[str, int] = {}
    for plugin in plugins:
        status, reason = disposition(
            plugin,
            existing_slugs,
            window_start,
            window_end,
            max_wordpress,
            max_php,
            args.compatibility_policy,
        )
        disposition_counts[status] = disposition_counts.get(status, 0) + 1
        audit_rows.append({**plugin, "disposition": status, "reason": reason})
        if status == "candidate":
            candidates.append(plugin)

    candidates.sort(
        key=lambda item: (
            -int(item["active_installs"]),
            parse_last_updated(item["last_updated"]) or datetime.max.replace(tzinfo=timezone.utc),
            hashlib.sha256(item["slug"].encode("utf-8")).hexdigest(),
        )
    )

    candidate_rows: list[dict[str, Any]] = []
    for index, plugin in enumerate(candidates, start=1):
        missing = [
            field
            for field in ("requires", "tested", "requires_php")
            if parse_series(plugin[field]) is None
        ]
        batch_number = (index - 1) // args.batch_size + 1
        batch_position = (index - 1) % args.batch_size + 1
        requires_wordpress = parse_series(plugin["requires"])
        requires_php = parse_series(plugin["requires_php"])
        candidate_rows.append(
            {
                "candidate_rank": index,
                "batch_id": f"batch-{batch_number:03d}",
                "batch_position": batch_position,
                **plugin,
                "metadata_completeness": "complete" if not missing else "incomplete",
                "missing_metadata_fields": ";".join(missing),
                "artifact_release_check": "pending",
                "source_wordpress_compatibility_check": (
                    "pending"
                    if requires_wordpress is None or requires_wordpress > max_wordpress
                    else "not_required_by_metadata"
                ),
                "source_php_compatibility_check": (
                    "pending"
                    if requires_php is None or requires_php > max_php
                    else "not_required_by_metadata"
                ),
                "download_status": "pending",
                "artifact_sha256": "",
                "scan_status": "pending",
                "review_status": "pending",
                "matching_cve_path_check": "defer_until_likely_vulnerable",
                "wordfence_scope_check": "defer_until_likely_vulnerable",
                "selection_key_sha256": hashlib.sha256(plugin["slug"].encode("utf-8")).hexdigest(),
            }
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    audit_path = args.output_dir / "selection_audit.csv"
    candidate_path = args.output_dir / "candidate_cohort.csv"
    write_csv(audit_path, AUDIT_FIELDS, audit_rows)
    write_csv(candidate_path, CANDIDATE_FIELDS, candidate_rows)

    batch_paths: list[Path] = []
    batch_ids = sorted({row["batch_id"] for row in candidate_rows})
    for batch_id in batch_ids:
        batch_path = args.output_dir / "batches" / f"{batch_id}.csv"
        write_csv(
            batch_path,
            CANDIDATE_FIELDS,
            [row for row in candidate_rows if row["batch_id"] == batch_id],
        )
        batch_paths.append(batch_path)

    checked_at = datetime.now(timezone.utc).isoformat()
    summary = {
        "schema_version": 1,
        "checked_at_utc": checked_at,
        "official_api": API_URL,
        "official_api_documentation": API_DOC_URL,
        "selection": {
            "min_active_installs": args.min_active_installs,
            "outside_existing_plugin_root": str(args.existing_plugin_root.resolve()),
            "release_date_proxy": f"WordPress.org {window_description}",
            "release_window_start_utc": (
                window_start.isoformat() if window_start is not None else None
            ),
            "release_window_end_exclusive_utc": window_end.isoformat(),
            "max_wordpress_if_present": args.max_wordpress,
            "max_php_if_present": args.max_php,
            "compatibility_policy": args.compatibility_policy,
            "missing_requires_php_requires_source_check": True,
            "batch_size": args.batch_size,
            "order": "active_installs_desc,last_updated_asc,sha256_slug_asc",
        },
        "collection": {
            **collection,
            "raw_records": len(raw_rows),
            "unique_active_install_plugins": len(plugins),
            "duplicate_page_slots": duplicate_slots,
            "metadata_conflicts": len(conflicts),
            "existing_slug_sources": existing_slug_counts,
        },
        "disposition_counts": dict(sorted(disposition_counts.items())),
        "candidate_count": len(candidate_rows),
        "batch_counts": {
            batch_id: sum(row["batch_id"] == batch_id for row in candidate_rows)
            for batch_id in batch_ids
        },
        "metadata_complete_candidates": sum(
            row["metadata_completeness"] == "complete" for row in candidate_rows
        ),
        "source_php_check_pending": sum(
            row["source_php_compatibility_check"] == "pending" for row in candidate_rows
        ),
        "source_wordpress_check_pending": sum(
            row["source_wordpress_compatibility_check"] == "pending"
            for row in candidate_rows
        ),
        "artifacts": {
            "selection_audit.csv": sha256_file(audit_path),
            "candidate_cohort.csv": sha256_file(candidate_path),
            **{
                f"batches/{path.name}": sha256_file(path)
                for path in batch_paths
            },
        },
    }
    summary_path = args.output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
