from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import hashlib
import html
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_FINDINGS = Path("output/findings.csv")
DEFAULT_OUTPUT_DIR = Path("review/cohorts/active500")
WPORG_PLUGIN_URL = "https://wordpress.org/plugins/{slug}/"
USER_AGENT = "WP-Vulnerability-Research-Cohort/1.0"

CLOSED_PATTERNS = (
    ("this_plugin_has_been_closed", re.compile(r"this\s+plugin\s+has\s+been\s+closed", re.I)),
    ("not_available_for_download", re.compile(r"not\s+available\s+for\s+download", re.I)),
    ("permanently_closed", re.compile(r"permanently\s+closed", re.I)),
)

FIELDNAMES = (
    "plugin",
    "active_installs_at_collection",
    "plugin_version",
    "last_updated_at_collection",
    "wporg_url",
    "http_status",
    "final_url",
    "page_state",
    "cohort_status",
    "exclusion_reason",
    "evidence_marker",
    "closure_notice",
    "checked_at_utc",
    "error",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a review cohort from finding-bearing plugins and exclude only "
            "WordPress.org pages that are verifiably closed or missing."
        )
    )
    parser.add_argument("--findings", type=Path, default=DEFAULT_FINDINGS)
    parser.add_argument("--download-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--min-active-installs", type=int, default=500)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--workers", type=int, default=6)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_finding_plugins(path: Path) -> set[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "plugin" not in reader.fieldnames:
            raise ValueError("findings CSV must contain a plugin column")
        return {
            str(row.get("plugin", "")).strip()
            for row in reader
            if str(row.get("plugin", "")).strip()
        }


def read_manifest(path: Path) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"slug", "active_installs"}.issubset(reader.fieldnames):
            raise ValueError("download manifest must contain slug and active_installs columns")
        return {
            str(row.get("slug", "")).strip(): row
            for row in reader
            if str(row.get("slug", "")).strip()
        }


def select_candidates(
    finding_plugins: Iterable[str],
    manifest: dict[str, dict[str, str]],
    min_active_installs: int,
) -> list[dict[str, str]]:
    selected: list[dict[str, str]] = []
    missing: list[str] = []

    for plugin in sorted(set(finding_plugins)):
        metadata = manifest.get(plugin)
        if metadata is None:
            missing.append(plugin)
            continue
        try:
            installs = int(str(metadata.get("active_installs", "")).strip())
        except ValueError as exc:
            raise ValueError(f"invalid active_installs for {plugin}") from exc
        if installs < min_active_installs:
            continue
        selected.append(
            {
                "plugin": plugin,
                "active_installs_at_collection": str(installs),
                "plugin_version": str(metadata.get("version", "") or ""),
                "last_updated_at_collection": str(metadata.get("last_updated", "") or ""),
            }
        )

    if missing:
        raise ValueError(
            f"{len(missing)} finding plugins are missing from the download manifest: "
            + ", ".join(missing[:10])
        )
    return selected


def closed_marker(body: str) -> str:
    for marker, pattern in CLOSED_PATTERNS:
        if pattern.search(body):
            return marker
    return ""


def extract_closure_notice(body: str) -> str:
    without_scripts = re.sub(r"(?is)<script.*?</script>|<style.*?</style>", " ", body)
    plain = html.unescape(re.sub(r"(?s)<[^>]+>", " ", without_scripts))
    plain = re.sub(r"\s+", " ", plain).strip()
    match = re.search(r"this plugin has been closed", plain, re.I)
    if not match:
        return ""
    notice = plain[match.start() : match.start() + 500]
    notice = re.split(r"\s+(?:Reviews|Contributors & Developers)\b", notice, maxsplit=1)[0]
    return notice.strip()


def classify_page(http_status: int, body: str) -> tuple[str, str, str, str]:
    marker = closed_marker(body)
    if marker:
        return "closed", "excluded", "wporg_page_closed", marker
    if http_status in {404, 410}:
        return "not_found", "excluded", f"wporg_http_{http_status}", ""
    if 200 <= http_status < 300:
        return "public", "included", "", ""
    return "unknown", "hold", f"wporg_http_{http_status}", ""


def fetch_page(url: str, timeout: float, retries: int) -> tuple[int, str, str, str]:
    last_error = ""
    for attempt in range(1, retries + 1):
        request = Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urlopen(request, timeout=timeout) as response:
                status = int(response.status)
                final_url = response.geturl()
                body = response.read().decode("utf-8", errors="replace")
                return status, final_url, body, ""
        except HTTPError as exc:
            status = int(exc.code)
            final_url = exc.geturl()
            body = exc.read().decode("utf-8", errors="replace")
            if status in {404, 410}:
                return status, final_url, body, ""
            last_error = f"HTTPError {status}: {exc.reason}"
        except (URLError, TimeoutError, OSError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        if attempt < retries:
            time.sleep(min(2.0, 0.5 * attempt))

    return 0, url, "", last_error or "request_failed"


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    if args.min_active_installs < 0:
        raise ValueError("--min-active-installs must be non-negative")
    if args.retries < 1:
        raise ValueError("--retries must be at least 1")
    if args.workers < 1:
        raise ValueError("--workers must be at least 1")
    if not args.findings.is_file():
        raise FileNotFoundError(args.findings)
    if not args.download_manifest.is_file():
        raise FileNotFoundError(args.download_manifest)

    finding_plugins = read_finding_plugins(args.findings)
    manifest = read_manifest(args.download_manifest)
    candidates = select_candidates(
        finding_plugins,
        manifest,
        args.min_active_installs,
    )

    def check_candidate(candidate: dict[str, str]) -> dict[str, str]:
        slug = candidate["plugin"]
        url = WPORG_PLUGIN_URL.format(slug=slug)
        checked_at = datetime.now(timezone.utc).isoformat()
        status, final_url, body, error = fetch_page(url, args.timeout, args.retries)
        if error:
            page_state, cohort_status, exclusion_reason, marker = (
                "unknown",
                "hold",
                "request_failed",
                "",
            )
        else:
            page_state, cohort_status, exclusion_reason, marker = classify_page(status, body)
        notice = extract_closure_notice(body) if marker else ""

        return {
            **candidate,
            "wporg_url": url,
            "http_status": str(status) if status else "",
            "final_url": final_url,
            "page_state": page_state,
            "cohort_status": cohort_status,
            "exclusion_reason": exclusion_reason,
            "evidence_marker": marker,
            "closure_notice": notice,
            "checked_at_utc": checked_at,
            "error": error,
        }

    checked_rows: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        pending = {executor.submit(check_candidate, candidate) for candidate in candidates}
        for index, future in enumerate(as_completed(pending), start=1):
            row = future.result()
            checked_rows.append(row)
            print(
                f"[{index:03d}/{len(candidates):03d}] {row['plugin']}: "
                f"{row['cohort_status']}/{row['page_state']} "
                f"status={row['http_status'] or '-'}",
                flush=True,
            )
            time.sleep(args.delay)

    checked_rows.sort(key=lambda row: row["plugin"])

    included = [row for row in checked_rows if row["cohort_status"] == "included"]
    excluded = [row for row in checked_rows if row["cohort_status"] == "excluded"]
    hold = [row for row in checked_rows if row["cohort_status"] == "hold"]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "active500_wporg_status.csv", checked_rows)
    write_csv(args.output_dir / "active500_public.csv", included)
    write_csv(args.output_dir / "active500_excluded.csv", excluded)
    write_csv(args.output_dir / "active500_hold.csv", hold)

    summary = {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "definition": {
            "finding_plugin_count": len(finding_plugins),
            "min_active_installs_at_collection": args.min_active_installs,
            "public_status_source": "https://wordpress.org/plugins/{slug}/",
            "excluded_states": ["closed", "not_found"],
            "unknown_policy": "hold_do_not_exclude",
        },
        "source": {
            "findings": str(args.findings.resolve()),
            "findings_sha256": sha256_file(args.findings),
            "download_manifest": str(args.download_manifest.resolve()),
            "download_manifest_sha256": sha256_file(args.download_manifest),
        },
        "counts": {
            "selected_before_wporg_check": len(candidates),
            "included_public": len(included),
            "excluded_closed_or_not_found": len(excluded),
            "hold_unknown": len(hold),
        },
    }
    summary_path = args.output_dir / "active500_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary["counts"], ensure_ascii=False, sort_keys=True))
    return 0 if not hold else 2


if __name__ == "__main__":
    raise SystemExit(main())
