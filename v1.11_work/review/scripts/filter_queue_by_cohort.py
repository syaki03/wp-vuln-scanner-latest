from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Filter a plugin review JSONL queue by a cohort CSV without rewriting records."
    )
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def read_cohort_plugins(path: Path) -> set[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "plugin" not in reader.fieldnames:
            raise ValueError("cohort CSV must contain a plugin column")
        plugins = {
            str(row.get("plugin", "")).strip()
            for row in reader
            if str(row.get("plugin", "")).strip()
        }
    if not plugins:
        raise ValueError("cohort CSV contains no plugins")
    return plugins


def main() -> int:
    args = parse_args()
    plugins = read_cohort_plugins(args.cohort)
    selected_lines: list[str] = []
    selected_plugins: list[str] = []

    with args.queue.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            record = json.loads(line)
            plugin = str(record.get("plugin", "")).strip()
            if not plugin:
                raise ValueError(f"queue line {line_number} has no plugin")
            if plugin in plugins:
                selected_lines.append(line)
                selected_plugins.append(plugin)

    duplicate_count = len(selected_plugins) - len(set(selected_plugins))
    missing = sorted(plugins - set(selected_plugins))
    if duplicate_count:
        raise ValueError(f"queue contains {duplicate_count} duplicate cohort records")
    if missing:
        raise ValueError(
            f"{len(missing)} cohort plugins are missing from the queue: "
            + ", ".join(missing[:10])
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(selected_lines) + "\n", encoding="utf-8")
    print(f"filtered_queue_records={len(selected_lines)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
