import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse


SHA_RE = re.compile(r"^[a-f0-9]{64}$")
CONTEXTS = {
    "html_text",
    "textarea",
    "html_attribute",
    "url_attribute",
    "javascript",
    "event_attribute",
    "shortcode_return",
}


def load_jsonl(path):
    records = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append((line_no, json.loads(line)))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return records


def benchmark_root(path):
    for parent in path.resolve().parents:
        if parent.name == "legacy_xss_core_v1":
            return parent
    raise ValueError(f"handoff is outside benchmark root: {path}")


def workspace_artifact(path, value):
    root = benchmark_root(path)
    project_root = root.parents[2]
    relative = Path(*PurePosixPath(str(value).replace("\\", "/")).parts)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("artifact path must be workspace-relative without traversal")
    resolved = (project_root / relative).resolve(strict=False)
    workstreams = (root / "workstreams").resolve()
    if workstreams not in resolved.parents:
        raise ValueError("artifact path must stay below benchmark workstreams")
    return resolved


def https_urls(values):
    return isinstance(values, list) and bool(values) and all(
        urlparse(str(value)).scheme == "https" and urlparse(str(value)).netloc
        for value in values
    )


def check_location(archive, slug, location, label, prefix, errors):
    required = {"path", "line", "function", "expression"}
    if label != "source":
        required.add("context")
    if not isinstance(location, dict) or not required <= set(location):
        errors.append(f"{prefix}.{label}: incomplete location")
        return
    if label != "source" and location["context"] not in CONTEXTS:
        errors.append(f"{prefix}.{label}: invalid context")
    raw = PurePosixPath(str(location["path"]))
    if raw.is_absolute() or ".." in raw.parts:
        errors.append(f"{prefix}.{label}: invalid path")
        return
    if not raw.parts or raw.parts[0] != slug:
        errors.append(f"{prefix}.{label}: path must include the plugin ZIP root")
        return
    member = raw.as_posix()
    if member not in archive.namelist():
        errors.append(f"{prefix}.{label}: missing ZIP member {member}")
        return
    lines = archive.read(member).decode("utf-8", errors="replace").splitlines()
    line_no = location["line"]
    if not isinstance(line_no, int) or isinstance(line_no, bool) or line_no < 1 or line_no > len(lines):
        errors.append(f"{prefix}.{label}: invalid line")
    elif not str(location["expression"]) or str(location["expression"]) not in lines[line_no - 1]:
        errors.append(f"{prefix}.{label}: expression not found on declared line")


def validate_eligible(path, records, errors):
    candidate_ids = set()
    slugs = set()
    for line_no, record in records:
        prefix = f"{path}:{line_no}"
        required = {
            "candidate_id", "decision", "plugin_slug", "vulnerability_id",
            "vulnerable_version", "artifact_local_path", "artifact_sha256",
            "affected_version_evidence", "official_source", "code_lineage_id",
            "runtime_compatibility_evidence", "attack_conditions", "ground_truth",
            "strata", "terra_review",
        }
        missing = sorted(required - set(record))
        if missing:
            errors.append(f"{prefix}: missing {', '.join(missing)}")
            continue
        if record["decision"] != "eligible":
            errors.append(f"{prefix}: verified handoff decision must be eligible")
        if record["candidate_id"] in candidate_ids:
            errors.append(f"{prefix}: duplicate candidate_id")
        if record["plugin_slug"] in slugs:
            errors.append(f"{prefix}: duplicate plugin_slug")
        candidate_ids.add(record["candidate_id"])
        slugs.add(record["plugin_slug"])
        expected_id = (
            f"wp-plugin:{record['plugin_slug']}:{record['vulnerability_id']}:"
            f"{record['vulnerable_version']}"
        )
        if record["candidate_id"] != expected_id:
            errors.append(f"{prefix}: candidate_id components mismatch")
        expected_sha = str(record["artifact_sha256"])
        if not SHA_RE.fullmatch(expected_sha):
            errors.append(f"{prefix}: invalid artifact_sha256")
        try:
            artifact = workspace_artifact(path, record["artifact_local_path"])
        except ValueError as exc:
            errors.append(f"{prefix}: {exc}")
            continue
        if not artifact.is_file():
            errors.append(f"{prefix}: artifact missing")
            continue
        if hashlib.sha256(artifact.read_bytes()).hexdigest() != expected_sha:
            errors.append(f"{prefix}: artifact SHA-256 mismatch")
        evidence = record["affected_version_evidence"]
        if not isinstance(evidence, dict) or not https_urls(evidence.get("urls")) or not str(evidence.get("conclusion", "")).strip():
            errors.append(f"{prefix}: invalid affected_version_evidence")
        source = record["official_source"]
        source_required = {"kind", "identity", "tag", "resolved_url", "final_url"}
        if not isinstance(source, dict) or not source_required <= set(source):
            errors.append(f"{prefix}: incomplete official_source")
        elif source.get("tag") != record["vulnerable_version"]:
            errors.append(f"{prefix}: official source tag/version mismatch")
        elif not https_urls([source.get("resolved_url"), source.get("final_url")]):
            errors.append(f"{prefix}: invalid official source URLs")
        conditions = record["attack_conditions"]
        if not isinstance(conditions, dict) or conditions.get("is_self_xss") is not False:
            errors.append(f"{prefix}: non-self-XSS decision is required")
        if conditions.get("persistence") not in {"reflected", "stored"}:
            errors.append(f"{prefix}: invalid persistence")
        review = record["terra_review"]
        if not isinstance(review, dict) or review.get("verified") is not True:
            errors.append(f"{prefix}: Terra verification flag is required")
        ground_truth = record["ground_truth"]
        additional = ground_truth.get("additional_sinks", []) if isinstance(ground_truth, dict) else []
        if not isinstance(additional, list):
            errors.append(f"{prefix}: additional_sinks must be an array")
            additional = []
        try:
            with zipfile.ZipFile(artifact) as archive:
                if archive.testzip():
                    errors.append(f"{prefix}: corrupt ZIP")
                check_location(archive, record["plugin_slug"], ground_truth.get("source"), "source", prefix, errors)
                check_location(archive, record["plugin_slug"], ground_truth.get("sink"), "sink", prefix, errors)
                for index, sink in enumerate(additional, 1):
                    check_location(archive, record["plugin_slug"], sink, f"additional_sinks[{index}]", prefix, errors)
        except zipfile.BadZipFile:
            errors.append(f"{prefix}: invalid ZIP")
            continue
        evidenced = {ground_truth.get("sink", {}).get("context")}
        evidenced.update(sink.get("context") for sink in additional if isinstance(sink, dict))
        declared = record["strata"].get("contexts") if isinstance(record["strata"], dict) else None
        if not isinstance(declared, list) or set(declared) != evidenced or len(declared) != len(set(declared)):
            errors.append(f"{prefix}: strata contexts do not exactly match evidenced sinks")
        access = record["strata"].get("access")
        if access not in {"unauthenticated", "low_privilege", "authenticated", "admin_victim"}:
            errors.append(f"{prefix}: invalid eligible access stratum")


def validate_noneligible(path, records, expected_decision, errors):
    for line_no, record in records:
        prefix = f"{path}:{line_no}"
        if record.get("decision") != expected_decision:
            errors.append(f"{prefix}: expected decision {expected_decision}")
        if not record.get("candidate_id") or not str(record.get("reason", "")).strip():
            errors.append(f"{prefix}: candidate_id and reason are required")
        if expected_decision == "hold" and not str(record.get("evidence_gap", "")).strip():
            errors.append(f"{prefix}: hold requires evidence_gap")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("batch_dir", type=Path)
    args = parser.parse_args()
    errors = []
    try:
        verified = load_jsonl(args.batch_dir / "verified.jsonl")
        holds = load_jsonl(args.batch_dir / "holds.jsonl")
        rejected = load_jsonl(args.batch_dir / "rejected.jsonl")
        validate_eligible(args.batch_dir / "verified.jsonl", verified, errors)
        validate_noneligible(args.batch_dir / "holds.jsonl", holds, "hold", errors)
        validate_noneligible(args.batch_dir / "rejected.jsonl", rejected, "rejected", errors)
        all_ids = [record.get("candidate_id") for _, record in verified + holds + rejected]
        if len(all_ids) != len(set(all_ids)):
            errors.append("candidate_id appears in multiple decision files")
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    if errors:
        print("FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"PASS eligible={len(verified)} hold={len(holds)} rejected={len(rejected)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
