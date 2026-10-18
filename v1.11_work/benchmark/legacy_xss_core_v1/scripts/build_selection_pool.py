import argparse
import hashlib
import json
import os
from pathlib import Path


def load(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("candidate_files", nargs="*", type=Path)
    args = parser.parse_args()
    if args.output.exists() and args.output.stat().st_size:
        raise SystemExit(f"refusing to overwrite non-empty output: {args.output}")
    records = []
    slugs = set()
    candidate_ids = set()
    for path in args.candidate_files:
        for record in load(path):
            if record.get("collection_status") != "downloaded":
                continue
            if record["plugin_slug"] in slugs:
                raise SystemExit(f"duplicate downloaded plugin_slug: {record['plugin_slug']}")
            if record["candidate_id"] in candidate_ids:
                raise SystemExit(f"duplicate candidate_id: {record['candidate_id']}")
            slugs.add(record["plugin_slug"])
            candidate_ids.add(record["candidate_id"])
            case_id = (
                f"wp-plugin:{record['plugin_slug']}:"
                f"{record['vulnerability_id']}:{record['vulnerable_version']}"
            )
            record = dict(record)
            record["case_id"] = case_id
            record["selection_hash"] = hashlib.sha256(case_id.encode("utf-8")).hexdigest()
            record["source_workstream"] = str(path)
            records.append(record)
    records.sort(key=lambda item: (item["selection_hash"], item["case_id"]))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".tmp")
    if temporary.exists():
        raise SystemExit(f"temporary output already exists: {temporary}")
    try:
        temporary.write_text(
            "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records),
            encoding="utf-8",
        )
        os.replace(temporary, args.output)
    finally:
        if temporary.exists():
            temporary.unlink()
    print(f"WROTE records={len(records)} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
