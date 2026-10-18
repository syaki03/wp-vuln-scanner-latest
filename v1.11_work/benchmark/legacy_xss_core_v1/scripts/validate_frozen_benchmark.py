import argparse
import hashlib
import json
import sys
from pathlib import Path

from select_frozen_cases import SELECTOR_VERSION, select_records
from validate_manifest import load_jsonl, validate_records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("benchmark_root", type=Path)
    args = parser.parse_args()
    root = args.benchmark_root.resolve()
    manifest_path = root / "manifest.jsonl"
    pool_path = root / "verified_pool.jsonl"
    freeze_path = root / "freeze.json"
    errors = []
    try:
        manifest = load_jsonl(manifest_path)
        pool = load_jsonl(pool_path)
        freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
        errors.extend(validate_records(manifest, manifest_path, frozen=True))
        pool_errors = validate_records(pool, pool_path, frozen=False)
        errors.extend(f"pool: {error}" for error in pool_errors)
        if freeze.get("benchmark_id") != "legacy_xss_core_v1":
            errors.append("benchmark_id mismatch")
        if freeze.get("selector_version") != SELECTOR_VERSION:
            errors.append("selector_version mismatch")
        if freeze.get("input_pool_path") != pool_path.name:
            errors.append("input_pool_path mismatch")
        if freeze.get("manifest_path") != manifest_path.name:
            errors.append("manifest_path mismatch")
        if freeze.get("input_pool_sha256") != hashlib.sha256(pool_path.read_bytes()).hexdigest():
            errors.append("input pool digest mismatch")
        if freeze.get("manifest_sha256") != hashlib.sha256(manifest_path.read_bytes()).hexdigest():
            errors.append("manifest digest mismatch")
        recomputed = select_records(pool)
        expected_ids = [record["case_id"] for record in recomputed]
        actual_ids = [record["case_id"] for record in manifest]
        if actual_ids != expected_ids or freeze.get("selected_case_ids") != expected_ids:
            errors.append("manifest differs from deterministic selector output")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
    if errors:
        print("FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print("PASS frozen=100 deterministic=true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
