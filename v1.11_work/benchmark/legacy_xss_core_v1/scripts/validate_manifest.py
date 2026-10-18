import argparse
import hashlib
import json
import re
import sys
import zipfile
from collections import Counter
from datetime import date
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from schema_validation import validate as validate_schema


CUTOFF = date(2019, 12, 31)
VERSION_RE = re.compile(r"^\s*(\d+)(?:\.(\d+))?")
CONTEXT_GROUPS = {
    "html_text_or_textarea": {"html_text", "textarea"},
    "html_or_url_attribute": {"html_attribute", "url_attribute"},
    "javascript_or_event": {"javascript", "event_attribute"},
    "shortcode_return": {"shortcode_return"},
}


def load_jsonl(path):
    records = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return records


def parse_version(value):
    if value is None:
        return None
    match = VERSION_RE.match(value)
    if not match:
        raise ValueError(f"unparsable version: {value!r}")
    return int(match.group(1)), int(match.group(2) or 0)


def release_band(released):
    if released.year <= 2009:
        return "pre_2010"
    if released.year <= 2014:
        return "2010_2014"
    return "2015_2019"


def safe_artifact_path(benchmark_root, relative_path):
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("artifact path must be relative without traversal")
    resolved = (benchmark_root / relative).resolve(strict=False)
    root = benchmark_root.resolve()
    if root != resolved and root not in resolved.parents:
        raise ValueError("artifact path escapes benchmark root")
    return resolved


def zip_member_for(record, location):
    raw = PurePosixPath(location["path"])
    if raw.is_absolute() or ".." in raw.parts:
        raise ValueError("ground-truth path traversal")
    if not raw.parts or raw.parts[0] != record["plugin_slug"]:
        raise ValueError("ground-truth path must include the plugin ZIP root")
    return raw.as_posix()


def validate_artifact(record, artifact_key, benchmark_root, errors, prefix):
    artifact = record[artifact_key]
    expected_name = "vulnerable.zip" if artifact_key == "vulnerable_artifact" else "fixed.zip"
    case_dir = record["case_id"].replace(":", "__")
    expected_relative = f"cases/{case_dir}/artifacts/{expected_name}"
    if artifact["local_path"].replace("\\", "/") != expected_relative:
        errors.append(f"{prefix}.{artifact_key}: noncanonical local_path")
    try:
        local_path = safe_artifact_path(benchmark_root, artifact["local_path"])
    except ValueError as exc:
        errors.append(f"{prefix}.{artifact_key}: {exc}")
        return None
    if not local_path.is_file():
        errors.append(f"{prefix}.{artifact_key}: artifact missing: {local_path}")
        return None
    actual_hash = hashlib.sha256(local_path.read_bytes()).hexdigest()
    if actual_hash != artifact["sha256"]:
        errors.append(f"{prefix}.{artifact_key}: SHA-256 mismatch")
    try:
        released = date.fromisoformat(artifact["release_date"])
    except ValueError:
        errors.append(f"{prefix}.{artifact_key}: invalid release_date")
        return None
    if artifact_key == "vulnerable_artifact" and released > CUTOFF:
        errors.append(f"{prefix}: vulnerable release after cutoff")
    for field, ceiling in (("requires_php", (7, 1)), ("requires_wp", (5, 3)), ("tested_up_to", (5, 3))):
        try:
            parsed = parse_version(artifact[field])
        except ValueError as exc:
            errors.append(f"{prefix}.{artifact_key}.{field}: {exc}")
            continue
        if parsed is not None and parsed > ceiling:
            errors.append(f"{prefix}.{artifact_key}.{field}: {parsed} exceeds {ceiling}")
    try:
        archive = zipfile.ZipFile(local_path)
        bad_member = archive.testzip()
        if bad_member:
            errors.append(f"{prefix}.{artifact_key}: corrupt ZIP member {bad_member}")
        names = [name for name in archive.namelist() if name and not name.endswith("/")]
        roots = {PurePosixPath(name).parts[0] for name in names if PurePosixPath(name).parts}
        if record["plugin_slug"] not in roots:
            errors.append(f"{prefix}.{artifact_key}: ZIP root does not contain plugin slug")
        return archive
    except zipfile.BadZipFile:
        errors.append(f"{prefix}.{artifact_key}: invalid ZIP")
        return None


def validate_location(record, archive, location, label, errors, prefix):
    if archive is None:
        return
    names = set(archive.namelist())
    try:
        relative = zip_member_for(record, location)
    except ValueError as exc:
        errors.append(f"{prefix}.ground_truth.{label}: {exc}")
        return
    member = relative
    if member not in names:
        errors.append(f"{prefix}.ground_truth.{label}: missing ZIP member {member}")
        return
    try:
        lines = archive.read(member).decode("utf-8", errors="replace").splitlines()
    except KeyError:
        errors.append(f"{prefix}.ground_truth.{label}: unreadable ZIP member")
        return
    if location["line"] > len(lines):
        errors.append(f"{prefix}.ground_truth.{label}: line exceeds file length")
    elif location["expression"] not in lines[location["line"] - 1]:
        errors.append(f"{prefix}.ground_truth.{label}: expression not found on declared line")


def validate_locations(record, archive, errors, prefix):
    validate_location(record, archive, record["ground_truth"]["source"], "source", errors, prefix)
    validate_location(record, archive, record["ground_truth"]["sink"], "sink", errors, prefix)
    for index, location in enumerate(record["ground_truth"].get("additional_sinks", []), 1):
        validate_location(record, archive, location, f"additional_sinks[{index}]", errors, prefix)


def validate_records(records, manifest_path, frozen=False):
    benchmark_root = manifest_path.parent.resolve()
    schema = json.loads((benchmark_root / "manifest.schema.json").read_text(encoding="utf-8"))
    errors = []
    slugs = Counter()
    case_ids = Counter()
    vendors = Counter()
    lineages = Counter()
    persistence = Counter()
    access = Counter()
    contexts = Counter()
    bands = Counter()

    for index, record in enumerate(records, 1):
        prefix = f"record[{index}]"
        schema_errors = validate_schema(record, schema)
        errors.extend(f"{prefix}{error[1:]}" for error in schema_errors)
        if schema_errors:
            continue
        case_id = record["case_id"]
        expected_case_id = f"wp-plugin:{record['plugin_slug']}:{record['vulnerability_id']}:{record['vulnerable_artifact']['version']}"
        if case_id != expected_case_id:
            errors.append(f"{prefix}: case_id components mismatch")
        if not set(record["affected_version_evidence"]["urls"]) & set(record["primary_advisory_urls"]):
            errors.append(f"{prefix}: affected-version evidence must cite a primary advisory URL")
        slugs[record["plugin_slug"]] += 1
        case_ids[case_id] += 1
        vendors[record["vendor_or_author"].strip().casefold()] += 1
        lineages[record["code_lineage_id"].strip().casefold()] += 1
        source = record["official_source"]
        if source["tag"] != record["vulnerable_artifact"]["version"]:
            errors.append(f"{prefix}: official source tag/version mismatch")
        host = urlparse(source["final_url"]).hostname or ""
        if source["kind"] == "wordpress_org_tag":
            if host not in {"downloads.wordpress.org", "plugins.svn.wordpress.org"}:
                errors.append(f"{prefix}: invalid WordPress.org final host")
            if source["identity"] != f"{record['plugin_slug']}@{source['tag']}":
                errors.append(f"{prefix}: WordPress.org source identity mismatch")
        elif host not in {"github.com", "objects.githubusercontent.com", "codeload.github.com"}:
            errors.append(f"{prefix}: unsupported official repository final host")
        vulnerable_archive = validate_artifact(record, "vulnerable_artifact", benchmark_root, errors, prefix)
        if "fixed_artifact" in record:
            fixed_archive = validate_artifact(record, "fixed_artifact", benchmark_root, errors, prefix)
            if fixed_archive:
                fixed_archive.close()
        if ("fixed_artifact" in record) != (record["evaluation_mode"] == "paired"):
            errors.append(f"{prefix}: evaluation_mode/fixed_artifact mismatch")
        released = date.fromisoformat(record["vulnerable_artifact"]["release_date"])
        derived_band = release_band(released)
        if record["strata"]["release_band"] != derived_band:
            errors.append(f"{prefix}: release_band does not match release_date")
        declared_contexts = record["strata"]["contexts"]
        if len(declared_contexts) != len(set(declared_contexts)):
            errors.append(f"{prefix}: duplicate strata context")
        evidenced_contexts = {record["ground_truth"]["sink"]["context"]}
        evidenced_contexts.update(
            sink["context"] for sink in record["ground_truth"].get("additional_sinks", [])
        )
        if set(declared_contexts) != evidenced_contexts:
            errors.append(f"{prefix}: strata.contexts must exactly match evidenced sink contexts")
        if record["selection_status"] in {"eligible", "frozen"} and record["strata"]["access"] == "unknown":
            errors.append(f"{prefix}: eligible case requires a known access stratum")
        validate_locations(record, vulnerable_archive, errors, prefix)
        if vulnerable_archive:
            vulnerable_archive.close()
        persistence[record["attack_conditions"]["persistence"]] += 1
        access[record["strata"]["access"]] += 1
        for context in declared_contexts:
            contexts[context] += 1
        bands[derived_band] += 1
        if frozen:
            if record["selection_status"] != "frozen":
                errors.append(f"{prefix}: frozen validation requires frozen status")
            review = record["review"]
            if not all(review[field] for field in ("luna_collected", "terra_verified", "sol_approved")):
                errors.append(f"{prefix}: all review approvals are required")

    for name, counter in (("case_id", case_ids), ("plugin_slug", slugs)):
        for value, count in counter.items():
            if count > 1:
                errors.append(f"duplicate {name}: {value}")

    if frozen:
        for value, count in lineages.items():
            if count > 1:
                errors.append(f"duplicate code_lineage_id: {value}")
        for value, count in vendors.items():
            if count > 3:
                errors.append(f"vendor cap exceeded: {value}={count}")
        if len(records) != 100:
            errors.append(f"expected 100 records, got {len(records)}")
        minimums = {
            "reflected": (persistence["reflected"], 30),
            "stored": (persistence["stored"], 30),
            "unauthenticated": (access["unauthenticated"], 25),
            "low_privilege": (access["low_privilege"], 15),
        }
        for group, accepted in CONTEXT_GROUPS.items():
            required = {"html_text_or_textarea": 15, "html_or_url_attribute": 20, "javascript_or_event": 15, "shortcode_return": 10}[group]
            minimums[group] = (sum(contexts[value] for value in accepted), required)
        for name, (actual, required) in minimums.items():
            if actual < required:
                errors.append(f"stratum {name}: {actual} < {required}")
        if set(bands) != {"pre_2010", "2010_2014", "2015_2019"}:
            errors.append(f"all release bands required: {dict(bands)}")
        if any(count > 50 for count in bands.values()):
            errors.append(f"release band exceeds 50: {dict(bands)}")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--frozen", action="store_true")
    args = parser.parse_args()
    try:
        records = load_jsonl(args.manifest)
        errors = validate_records(records, args.manifest.resolve(), frozen=args.frozen)
    except (OSError, ValueError) as exc:
        print(f"FAIL\n- {exc}")
        return 1
    if errors:
        print("FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"PASS records={len(records)} frozen={args.frozen}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
