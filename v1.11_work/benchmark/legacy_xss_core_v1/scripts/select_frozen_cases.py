import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

from validate_manifest import load_jsonl, validate_records


SELECTOR_VERSION = "legacy-xss-stratified-sha256-v1"
MINIMUMS = {
    "persistence:reflected": 30,
    "persistence:stored": 30,
    "access:unauthenticated": 25,
    "access:low_privilege": 15,
    "context:html_text_or_textarea": 15,
    "context:html_or_url_attribute": 20,
    "context:javascript_or_event": 15,
    "context:shortcode_return": 10,
    "band:pre_2010": 1,
    "band:2010_2014": 1,
    "band:2015_2019": 1,
}


def record_hash(record):
    return hashlib.sha256(record["case_id"].encode("utf-8")).hexdigest()


def features(record):
    result = {
        f"persistence:{record['attack_conditions']['persistence']}",
        f"access:{record['strata']['access']}",
        f"band:{record['strata']['release_band']}",
    }
    contexts = set(record["strata"]["contexts"])
    if contexts & {"html_text", "textarea"}:
        result.add("context:html_text_or_textarea")
    if contexts & {"html_attribute", "url_attribute"}:
        result.add("context:html_or_url_attribute")
    if contexts & {"javascript", "event_attribute"}:
        result.add("context:javascript_or_event")
    if "shortcode_return" in contexts:
        result.add("context:shortcode_return")
    return result


def can_add(record, selected, vendors, lineages, bands):
    if record["plugin_slug"] in {item["plugin_slug"] for item in selected}:
        return False
    vendor = record["vendor_or_author"].strip().casefold()
    lineage = record["code_lineage_id"].strip().casefold()
    band = record["strata"]["release_band"]
    return vendors[vendor] < 3 and lineages[lineage] == 0 and bands[band] < 50


def add(record, selected, vendors, lineages, bands, counts):
    selected.append(record)
    vendors[record["vendor_or_author"].strip().casefold()] += 1
    lineages[record["code_lineage_id"].strip().casefold()] += 1
    bands[record["strata"]["release_band"]] += 1
    for feature in features(record):
        counts[feature] += 1


def select_records(records):
    eligible = [record for record in records if record.get("selection_status") == "eligible"]
    eligible.sort(key=lambda record: (record_hash(record), record["case_id"]))
    selected = []
    vendors = Counter()
    lineages = Counter()
    bands = Counter()
    counts = Counter()

    while any(counts[name] < required for name, required in MINIMUMS.items()):
        choices = []
        for record in eligible:
            if record in selected or not can_add(record, selected, vendors, lineages, bands):
                continue
            gain = sum(1 for feature in features(record) if counts[feature] < MINIMUMS.get(feature, 0))
            if gain:
                choices.append((-gain, record_hash(record), record["case_id"], record))
        if not choices:
            unmet = {name: required - counts[name] for name, required in MINIMUMS.items() if counts[name] < required}
            raise ValueError(f"cannot satisfy minimum strata: {unmet}")
        choices.sort(key=lambda item: item[:3])
        add(choices[0][3], selected, vendors, lineages, bands, counts)
        if len(selected) > 100:
            raise ValueError("minimum strata require more than 100 cases")

    for record in eligible:
        if len(selected) == 100:
            break
        if record not in selected and can_add(record, selected, vendors, lineages, bands):
            add(record, selected, vendors, lineages, bands, counts)
    if len(selected) != 100:
        raise ValueError(f"only {len(selected)} cases can be selected under caps")
    selected.sort(key=lambda record: (record_hash(record), record["case_id"]))
    return selected


def ensure_replaceable(path):
    if path.exists() and path.stat().st_size:
        raise ValueError(f"refusing to overwrite non-empty file: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise ValueError(f"temporary output already exists: {temporary}")


def write_freeze_outputs(manifest_path, manifest_data, freeze_path, freeze_data):
    for path in (manifest_path, freeze_path):
        ensure_replaceable(path)
        path.parent.mkdir(parents=True, exist_ok=True)
    manifest_temporary = manifest_path.with_name(manifest_path.name + ".tmp")
    freeze_temporary = freeze_path.with_name(freeze_path.name + ".tmp")
    try:
        manifest_temporary.write_bytes(manifest_data)
        freeze_temporary.write_bytes(freeze_data)
        os.replace(manifest_temporary, manifest_path)
        try:
            os.replace(freeze_temporary, freeze_path)
        except OSError:
            # A non-empty manifest without its commit marker is not a valid freeze.
            manifest_path.write_bytes(b"")
            raise
    finally:
        for temporary in (manifest_temporary, freeze_temporary):
            if temporary.exists():
                temporary.unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pool", type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--freeze", required=True, type=Path)
    args = parser.parse_args()
    try:
        records = load_jsonl(args.pool)
        errors = validate_records(records, args.pool.resolve(), frozen=False)
        if errors:
            raise ValueError("verified pool failed validation:\n" + "\n".join(errors))
        selected = select_records(records)
        frozen = []
        for record in selected:
            item = dict(record)
            item["selection_status"] = "frozen"
            if not all(item["review"][key] for key in ("luna_collected", "terra_verified", "sol_approved")):
                raise ValueError(f"missing approvals: {item['case_id']}")
            frozen.append(item)
        manifest_bytes = "".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in frozen
        ).encode("utf-8")
        pool_bytes = args.pool.read_bytes()
        freeze = {
            "benchmark_id": "legacy_xss_core_v1",
            "selector_version": SELECTOR_VERSION,
            "input_pool_path": args.pool.name,
            "input_pool_sha256": hashlib.sha256(pool_bytes).hexdigest(),
            "manifest_path": args.manifest.name,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "selected_case_ids": [record["case_id"] for record in frozen],
        }
        freeze_bytes = (json.dumps(freeze, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_freeze_outputs(args.manifest, manifest_bytes, args.freeze, freeze_bytes)
    except (OSError, ValueError) as exc:
        print(f"FAIL\n- {exc}")
        return 1
    print(f"PASS selected={len(frozen)} selector={SELECTOR_VERSION}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
