import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import date
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse


CUTOFF = date(2019, 12, 31)
SHA_RE = re.compile(r"^[a-f0-9]{64}$")
SLUG_RE = re.compile(r"^[a-z0-9-]+$")
REQUIRED = {
    "candidate_id",
    "plugin_slug",
    "plugin_name",
    "vendor_or_author",
    "vulnerability_id",
    "vulnerability_class",
    "primary_advisory_urls",
    "vulnerable_version",
    "release_date",
    "artifact_source_url",
    "artifact_local_path",
    "sha256",
    "requires_php",
    "requires_wp",
    "tested_up_to",
    "persistence",
    "output_contexts",
    "attacker_role",
    "victim_role",
    "victim_action",
    "source_hint",
    "sink_hint",
    "evidence_summary",
    "code_lineage_hint",
    "uncertainty",
    "collection_status",
    "official_source_kind",
    "official_source_identity",
    "runtime_compatibility_evidence",
}
VERSION_RE = re.compile(r"^\s*(\d+)(?:\.(\d+))?")


def parse_records(path: Path):
    records = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append((line_no, json.loads(line)))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return records


def valid_https_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def parse_version(value):
    if value is None or value == "":
        return None
    match = VERSION_RE.match(str(value))
    if not match:
        raise ValueError(f"unparsable version: {value!r}")
    return int(match.group(1)), int(match.group(2) or 0)


def benchmark_root(path: Path) -> Path:
    for parent in path.resolve().parents:
        if parent.name == "legacy_xss_core_v1":
            return parent
    raise ValueError(f"candidate file is outside benchmark root: {path}")


def resolve_artifact(candidate_file: Path, value: str) -> Path:
    root = benchmark_root(candidate_file)
    project_root = root.parents[2]
    relative = Path(*PurePosixPath(value.replace("\\", "/")).parts)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("artifact path must be relative without traversal")
    resolved = (project_root / relative).resolve(strict=False)
    assigned_artifact_root = (candidate_file.resolve().parent / "artifacts").resolve(strict=False)
    if assigned_artifact_root != resolved and assigned_artifact_root not in resolved.parents:
        raise ValueError("artifact path must stay below the candidate workstream artifacts directory")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate_files", nargs="+", type=Path)
    args = parser.parse_args()
    errors = []
    downloaded = 0
    holds = 0
    global_candidates = {}

    for path in args.candidate_files:
        try:
            records = parse_records(path)
            root = benchmark_root(path)
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
            continue
        local_slugs = set()
        for line_no, record in records:
            prefix = f"{path}:{line_no}"
            missing = sorted(REQUIRED - set(record))
            if missing:
                errors.append(f"{prefix}: missing {', '.join(missing)}")
                continue
            slug = str(record["plugin_slug"])
            if not SLUG_RE.fullmatch(slug):
                errors.append(f"{prefix}: invalid plugin_slug")
            if slug in local_slugs:
                errors.append(f"{prefix}: duplicate slug in workstream: {slug}")
            local_slugs.add(slug)
            candidate_id = str(record["candidate_id"])
            if record["vulnerability_class"] != "XSS":
                errors.append(f"{prefix}: vulnerability_class must be XSS")
            status = record["collection_status"]
            if status == "hold":
                holds += 1
                if not str(record["uncertainty"]).strip():
                    errors.append(f"{prefix}: hold record requires an uncertainty reason")
                continue
            if status != "downloaded":
                errors.append(f"{prefix}: invalid collection_status")
                continue
            expected_candidate_id = (
                f"wp-plugin:{slug}:{record['vulnerability_id']}:"
                f"{record['vulnerable_version']}"
            )
            if candidate_id != expected_candidate_id:
                errors.append(f"{prefix}: candidate_id components mismatch")
            if candidate_id in global_candidates and global_candidates[candidate_id] != record["sha256"]:
                errors.append(f"{prefix}: duplicate downloaded candidate_id has different SHA-256: {candidate_id}")
            global_candidates[candidate_id] = record["sha256"]
            if record["official_source_kind"] not in {"wordpress_org_tag", "vendor_release", "official_repo_tag"}:
                errors.append(f"{prefix}: invalid official_source_kind")
            if not str(record["official_source_identity"]).strip():
                errors.append(f"{prefix}: empty official_source_identity")
            if record["persistence"] not in {"reflected", "stored"}:
                errors.append(f"{prefix}: invalid persistence")
            advisory_urls = record["primary_advisory_urls"]
            if not isinstance(advisory_urls, list) or not advisory_urls or not all(
                valid_https_url(str(value)) for value in advisory_urls
            ):
                errors.append(f"{prefix}: invalid primary_advisory_urls")
            downloaded += 1
            try:
                released = date.fromisoformat(str(record["release_date"]))
                if released > CUTOFF:
                    errors.append(f"{prefix}: release date after cutoff")
            except ValueError:
                errors.append(f"{prefix}: invalid release_date")
            for field, ceiling in (("requires_php", (7, 1)), ("requires_wp", (5, 3)), ("tested_up_to", (5, 3))):
                try:
                    parsed = parse_version(record[field])
                except ValueError as exc:
                    errors.append(f"{prefix}.{field}: {exc}")
                    continue
                if parsed is not None and parsed > ceiling:
                    errors.append(f"{prefix}.{field}: {parsed} exceeds {ceiling}")
            runtime_evidence = record["runtime_compatibility_evidence"]
            if not isinstance(runtime_evidence, dict):
                errors.append(f"{prefix}: runtime_compatibility_evidence must be an object")
            else:
                if not runtime_evidence.get("files_inspected") or not runtime_evidence.get("conclusion") or not runtime_evidence.get("reviewer_model"):
                    errors.append(f"{prefix}: incomplete runtime_compatibility_evidence")
            if not valid_https_url(str(record["artifact_source_url"])):
                errors.append(f"{prefix}: invalid artifact_source_url")
            expected_sha = str(record["sha256"])
            if not SHA_RE.fullmatch(expected_sha):
                errors.append(f"{prefix}: invalid sha256")
            try:
                artifact = resolve_artifact(path, str(record["artifact_local_path"]))
            except ValueError as exc:
                errors.append(f"{prefix}: {exc}")
                continue
            if not artifact.is_file():
                errors.append(f"{prefix}: missing artifact: {artifact}")
            elif hashlib.sha256(artifact.read_bytes()).hexdigest() != expected_sha:
                errors.append(f"{prefix}: sha256 mismatch")
            else:
                try:
                    with zipfile.ZipFile(artifact) as archive:
                        if archive.testzip():
                            errors.append(f"{prefix}: corrupt ZIP")
                        roots = {
                            PurePosixPath(name).parts[0]
                            for name in archive.namelist()
                            if name and PurePosixPath(name).parts
                        }
                        if slug not in roots:
                            errors.append(f"{prefix}: ZIP root does not contain plugin slug")
                except zipfile.BadZipFile:
                    errors.append(f"{prefix}: invalid ZIP")

    if errors:
        print("FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print(
        f"PASS downloaded_records={downloaded} unique_downloads={len(global_candidates)} "
        f"hold={holds} files={len(args.candidate_files)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
