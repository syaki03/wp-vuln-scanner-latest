import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path, PurePosixPath

from validate_manifest import load_jsonl, validate_records


def load_candidate_files(paths):
    records = {}
    for path in paths:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("collection_status") != "downloaded":
                continue
            candidate_id = record["candidate_id"]
            if candidate_id in records:
                if records[candidate_id].get("sha256") != record.get("sha256"):
                    raise ValueError(f"duplicate candidate_id has different SHA-256: {candidate_id}")
                continue
            records[candidate_id] = record
    return records


def project_artifact(benchmark_root, value):
    project_root = benchmark_root.parents[2]
    relative = Path(*PurePosixPath(str(value).replace("\\", "/")).parts)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("source artifact path must be workspace-relative without traversal")
    resolved = (project_root / relative).resolve(strict=False)
    workstreams = (benchmark_root / "workstreams").resolve()
    if workstreams not in resolved.parents:
        raise ValueError("source artifact must stay below benchmark workstreams")
    return resolved


def unique(values):
    return list(dict.fromkeys(values))


def final_record(candidate, terra, destination_relative, batch_name):
    if candidate["collection_status"] != "downloaded":
        raise ValueError(f"Terra eligible record is not Luna-downloaded: {candidate['candidate_id']}")
    for field, terra_field in (
        ("plugin_slug", "plugin_slug"),
        ("vulnerability_id", "vulnerability_id"),
        ("vulnerable_version", "vulnerable_version"),
        ("artifact_local_path", "artifact_local_path"),
        ("sha256", "artifact_sha256"),
    ):
        if candidate[field] != terra[terra_field]:
            raise ValueError(f"Luna/Terra mismatch {candidate['candidate_id']}: {field}")
    source = dict(terra["official_source"])
    if source["kind"] == "wordpress_org_tag":
        source["identity"] = f"{candidate['plugin_slug']}@{candidate['vulnerable_version']}"
    return {
        "schema_version": 1,
        "benchmark_id": "legacy_xss_core_v1",
        "case_id": candidate["candidate_id"],
        "selection_status": "eligible",
        "plugin_slug": candidate["plugin_slug"],
        "plugin_name": candidate["plugin_name"],
        "vendor_or_author": candidate["vendor_or_author"],
        "code_lineage_id": terra["code_lineage_id"],
        "vulnerability_id": candidate["vulnerability_id"],
        "vulnerability_class": "XSS",
        "primary_advisory_urls": unique(
            list(candidate["primary_advisory_urls"])
            + list(terra["affected_version_evidence"]["urls"])
        ),
        "affected_version_evidence": terra["affected_version_evidence"],
        "official_source": source,
        "vulnerable_artifact": {
            "version": candidate["vulnerable_version"],
            "release_date": candidate["release_date"],
            "source_url": candidate["artifact_source_url"],
            "local_path": destination_relative,
            "sha256": candidate["sha256"],
            "requires_php": candidate["requires_php"],
            "requires_wp": candidate["requires_wp"],
            "tested_up_to": candidate["tested_up_to"],
        },
        "runtime_compatibility_evidence": terra["runtime_compatibility_evidence"],
        "evaluation_mode": "positive_only",
        "attack_conditions": terra["attack_conditions"],
        "ground_truth": terra["ground_truth"],
        "strata": terra["strata"],
        "implementation_fit": "unclassified",
        "review": {
            "luna_collected": True,
            "terra_verified": True,
            "sol_approved": True,
            "notes": f"Sol integrated validated {batch_name} handoff. {terra['terra_review']['notes']}",
        },
    }


def write_pool_atomic(path, records):
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise ValueError(f"temporary pool output already exists: {temporary}")
    data = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        for record in sorted(records, key=lambda item: item["case_id"])
    )
    try:
        temporary.write_text(data, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("batch_dir", type=Path)
    parser.add_argument("--pool", required=True, type=Path)
    parser.add_argument("--candidate-file", action="append", required=True, type=Path)
    args = parser.parse_args()
    try:
        benchmark_root = args.pool.resolve().parent
        batch_dir = args.batch_dir.resolve()
        if (benchmark_root / "workstreams").resolve() not in batch_dir.parents:
            raise ValueError("batch_dir must stay below benchmark workstreams")
        candidates = load_candidate_files(args.candidate_file)
        terra_records = load_jsonl(batch_dir / "verified.jsonl")
        existing = load_jsonl(args.pool) if args.pool.exists() and args.pool.stat().st_size else []
        existing_ids = {record["case_id"] for record in existing}
        additions = []
        copies = []
        for terra in terra_records:
            candidate_id = terra["candidate_id"]
            if candidate_id in existing_ids:
                raise ValueError(f"case already exists in verified pool: {candidate_id}")
            if candidate_id not in candidates:
                raise ValueError(f"Terra case missing from candidate inputs: {candidate_id}")
            candidate = candidates[candidate_id]
            case_dir = candidate_id.replace(":", "__")
            destination_relative = f"cases/{case_dir}/artifacts/vulnerable.zip"
            source = project_artifact(benchmark_root, candidate["artifact_local_path"])
            destination = (benchmark_root / Path(*PurePosixPath(destination_relative).parts)).resolve()
            expected_sha = candidate["sha256"]
            if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != expected_sha:
                raise ValueError(f"source artifact missing or hash mismatch: {candidate_id}")
            if destination.exists():
                if hashlib.sha256(destination.read_bytes()).hexdigest() != expected_sha:
                    raise ValueError(f"existing destination hash mismatch: {candidate_id}")
            else:
                copies.append((source, destination))
            additions.append(
                final_record(candidate, terra, destination_relative, batch_dir.name)
            )
            existing_ids.add(candidate_id)
        for source, destination in copies:
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".tmp")
            if temporary.exists():
                raise ValueError(f"temporary artifact exists: {temporary}")
            try:
                shutil.copyfile(source, temporary)
                os.replace(temporary, destination)
            finally:
                if temporary.exists():
                    temporary.unlink()
        merged = existing + additions
        errors = validate_records(merged, args.pool.resolve(), frozen=False)
        if errors:
            raise ValueError("integrated pool validation failed:\n" + "\n".join(errors))
        write_pool_atomic(args.pool, merged)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL\n- {exc}")
        return 1
    print(f"PASS added={len(additions)} pool={len(merged)} batch={batch_dir.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
