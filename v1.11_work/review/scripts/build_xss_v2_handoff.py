from __future__ import annotations

import argparse
import difflib
import hashlib
import io
import json
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


class HandoffBuildError(ValueError):
    pass


ACTION_ID = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
REASON_CODE = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
ATTACKER_ROLES = {
    "anonymous", "subscriber", "customer", "contributor", "author",
    "editor", "shop_manager", "administrator",
}
VICTIM_ROLES = ATTACKER_ROLES - {"anonymous"}
ENVIRONMENT_ROLES = {
    "current_stable", "declared_minimum", "known_baseline", "legacy_condition",
}
SINK_ENCODERS = {
    "html_attribute": "esc_attr",
    "html_body": "esc_html",
    "url_attribute": "esc_url",
    "javascript": "wp_json_encode",
}


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json_strict(path: Path) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise HandoffBuildError(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise HandoffBuildError(f"invalid JSON constant in {path}: {value}")

    try:
        value = json.loads(
            path.read_bytes().decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise HandoffBuildError(f"strict UTF-8 JSON required: {path}") from error
    if not isinstance(value, dict):
        raise HandoffBuildError(f"JSON object required: {path}")
    return value


def safe_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or "\x00" in value:
        raise HandoffBuildError(f"unsafe relative path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise HandoffBuildError(f"unsafe relative path: {value!r}")
    return value


def read_tree(root: Path) -> dict[str, bytes]:
    resolved = root.resolve(strict=True)
    if resolved.is_symlink():
        raise HandoffBuildError(f"tree root may not be a symlink: {root}")
    result: dict[str, bytes] = {}
    for path in sorted(resolved.rglob("*")):
        if path.is_symlink():
            raise HandoffBuildError(f"tree symlink rejected: {path}")
        if path.is_file():
            relative = safe_relative_path(path.relative_to(resolved).as_posix())
            result[relative] = path.read_bytes()
    if not result:
        raise HandoffBuildError(f"non-empty tree required: {root}")
    return result


def extract_zip_tree(payload: bytes) -> dict[str, bytes]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except (zipfile.BadZipFile, OSError) as error:
        raise HandoffBuildError("valid ZIP artifact required") from error
    entries: list[tuple[tuple[str, ...], bytes]] = []
    total = 0
    with archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        if not infos or len(infos) > 10000:
            raise HandoffBuildError("bounded non-empty ZIP required")
        for info in infos:
            if info.flag_bits & 0x1:
                raise HandoffBuildError("encrypted ZIP entry rejected")
            if "\\" in info.filename or "\x00" in info.filename:
                raise HandoffBuildError("unsafe ZIP entry")
            path = PurePosixPath(info.filename)
            if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                raise HandoffBuildError("unsafe ZIP entry")
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if unix_mode and stat.S_ISLNK(unix_mode):
                raise HandoffBuildError("ZIP symlink rejected")
            total += info.file_size
            if total > 64 * 1024 * 1024:
                raise HandoffBuildError("ZIP extracted-byte budget exceeded")
            entries.append((path.parts, archive.read(info)))
    common_root = all(len(parts) > 1 for parts, _ in entries) and len({parts[0] for parts, _ in entries}) == 1
    result: dict[str, bytes] = {}
    for parts, content in entries:
        normalized = "/".join(parts[1:] if common_root else parts)
        safe_relative_path(normalized)
        if normalized in result:
            raise HandoffBuildError("duplicate normalized ZIP entry")
        result[normalized] = content
    return result


def tree_manifest(files: Mapping[str, bytes]) -> list[dict[str, str]]:
    return [
        {"path": path, "sha256": sha256_bytes(files[path])}
        for path in sorted(files)
    ]


def line_range_sha256(source: bytes, start_line: int, end_line: int) -> str:
    lines = source.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise HandoffBuildError(f"invalid source line range: {start_line}-{end_line}")
    return sha256_bytes(b"".join(lines[start_line - 1:end_line]))


def canonical_patch(
    vulnerable_files: Mapping[str, bytes],
    patched_files: Mapping[str, bytes],
    sink_file: str,
    start_line: int,
    end_line: int,
    encoding_function: str,
) -> bytes:
    changed = sorted(
        path
        for path in set(vulnerable_files) | set(patched_files)
        if vulnerable_files.get(path) != patched_files.get(path)
    )
    if changed != [sink_file]:
        raise HandoffBuildError("research patch must change only the bound sink file")
    before = vulnerable_files[sink_file].splitlines(keepends=True)
    after = patched_files[sink_file].splitlines(keepends=True)
    if len(before) != len(after):
        raise HandoffBuildError("research patch may not add or remove lines")
    for line_number, (old, new) in enumerate(zip(before, after), start=1):
        if not start_line <= line_number <= end_line and old != new:
            raise HandoffBuildError("research patch changed bytes outside the sink range")
    old_sink = b"".join(before[start_line - 1:end_line])
    new_sink = b"".join(after[start_line - 1:end_line])
    insertions: list[bytes] = []
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(None, old_sink, new_sink, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if tag != "insert":
            raise HandoffBuildError("research patch must be insertion-only output encoding")
        insertions.append(new_sink[j1:j2])
    if insertions != [(encoding_function + "(").encode("ascii"), b")"]:
        raise HandoffBuildError("research patch must only wrap the sink value in the declared encoder")
    return b"".join(
        difflib.diff_bytes(
            difflib.unified_diff,
            before,
            after,
            fromfile=("a/" + sink_file).encode("utf-8"),
            tofile=("b/" + sink_file).encode("utf-8"),
            lineterm=b"\n",
        )
    )


def normalize_patch_to_sink_range(
    vulnerable_files: Mapping[str, bytes],
    candidate_patched_files: Mapping[str, bytes],
    sink_file: str,
    start_line: int,
    end_line: int,
) -> dict[str, bytes]:
    """Retain only the candidate patch's sink-range bytes.

    Historical researcher controls may contain incidental EOF/newline changes.
    V2 derives a new control from the official vulnerable bytes and copies only
    the explicitly bound sink range before the insertion-only check runs.
    """
    if set(vulnerable_files) != set(candidate_patched_files):
        raise HandoffBuildError("candidate patched tree path set mismatch")
    vulnerable_lines = vulnerable_files[sink_file].splitlines(keepends=True)
    patched_lines = candidate_patched_files[sink_file].splitlines(keepends=True)
    if len(vulnerable_lines) != len(patched_lines):
        raise HandoffBuildError("candidate patched sink file line count mismatch")
    normalized = dict(vulnerable_files)
    normalized[sink_file] = b"".join(
        vulnerable_lines[: start_line - 1]
        + patched_lines[start_line - 1:end_line]
        + vulnerable_lines[end_line:]
    )
    return normalized


def validate_poc_xss_v2_contract(handoff: Mapping[str, Any]) -> None:
    """Reject the closed enum/identifier drift that the PoC v2 schema rejects.

    Full acceptance remains the responsibility of the canonical sibling PoC
    validator.  This local guard keeps the static builder from emitting values
    outside the shared contract before that integration check runs.
    """
    finding = handoff["finding"]
    if finding.get("vulnerability_class") != "stored_xss":
        raise HandoffBuildError("PoC v2 contract requires vulnerability_class stored_xss")

    principals = handoff["principals"]
    if principals.get("attacker_role") not in ATTACKER_ROLES:
        raise HandoffBuildError("PoC v2 contract rejects attacker_role")
    if principals.get("victim_role") not in VICTIM_ROLES:
        raise HandoffBuildError("PoC v2 contract rejects victim_role")
    for field in ("attacker_action", "victim_action"):
        value = principals.get(field)
        if not isinstance(value, str) or ACTION_ID.fullmatch(value) is None:
            raise HandoffBuildError(f"PoC v2 contract rejects {field}")

    matrix = handoff["environment_matrix"]
    environments = matrix.get("environments")
    if not isinstance(environments, list) or not environments:
        raise HandoffBuildError("PoC v2 contract requires environments")
    environment_ids: list[str] = []
    current_available = 0
    legacy_ids: set[str] = set()
    for environment in environments:
        if not isinstance(environment, Mapping):
            raise HandoffBuildError("PoC v2 contract rejects environment entry")
        environment_id = environment.get("environment_id")
        role = environment.get("role")
        if not isinstance(environment_id, str) or environment_id in environment_ids:
            raise HandoffBuildError("PoC v2 contract rejects environment_id")
        if role not in ENVIRONMENT_ROLES:
            raise HandoffBuildError("PoC v2 contract rejects environment role")
        environment_ids.append(environment_id)
        if role == "current_stable" and environment.get("available") is True:
            current_available += 1
        if role == "legacy_condition":
            legacy_ids.add(environment_id)
    if current_available != 1:
        raise HandoffBuildError("PoC v2 contract requires one available current_stable environment")

    conditions = matrix.get("legacy_conditions")
    if not isinstance(conditions, list):
        raise HandoffBuildError("PoC v2 contract rejects legacy_conditions")
    condition_ids: list[str] = []
    for condition in conditions:
        if not isinstance(condition, Mapping):
            raise HandoffBuildError("PoC v2 contract rejects legacy condition entry")
        environment_id = condition.get("environment_id")
        reason_code = condition.get("reason_code")
        if (
            environment_id not in legacy_ids
            or environment_id in condition_ids
            or not isinstance(reason_code, str)
            or REASON_CODE.fullmatch(reason_code) is None
            or condition.get("scope_status") != "conditional_only"
        ):
            raise HandoffBuildError("PoC v2 contract rejects legacy condition entry")
        condition_ids.append(environment_id)
    if set(condition_ids) != legacy_ids:
        raise HandoffBuildError("PoC v2 contract requires one condition per legacy environment")

    patched = handoff["patched_control"]
    sink_context = patched.get("sink_context")
    if sink_context not in SINK_ENCODERS:
        raise HandoffBuildError("PoC v2 contract rejects sink_context")
    if patched.get("encoding_function") != SINK_ENCODERS[sink_context]:
        raise HandoffBuildError("PoC v2 contract rejects context encoder")


def write_tree(root: Path, files: Mapping[str, bytes]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        path = root / PurePosixPath(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def build_handoff(
    *,
    spec: dict[str, Any],
    artifact_manifest: dict[str, Any],
    review: dict[str, Any],
    artifact_bytes: bytes,
    source_files: Mapping[str, bytes],
    patched_files: Mapping[str, bytes],
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    if spec.get("spec_schema_version") != 1:
        raise HandoffBuildError("spec_schema_version 1 required")
    plugin_spec = spec["plugin"]
    manifest_plugin = artifact_manifest.get("plugin", {})
    for field in ("slug", "version"):
        if manifest_plugin.get(field) != plugin_spec.get(field):
            raise HandoffBuildError(f"artifact manifest plugin {field} mismatch")
    artifact_sha256 = sha256_bytes(artifact_bytes)
    if manifest_plugin.get("source_hash") != artifact_sha256:
        raise HandoffBuildError("artifact bytes do not match manifest source_hash")
    if extract_zip_tree(artifact_bytes) != dict(source_files):
        raise HandoffBuildError("extracted source tree does not match official ZIP bytes")

    finding_spec = spec["finding"]
    if review.get("plugin") != plugin_spec["slug"] or review.get("version") != plugin_spec["version"]:
        raise HandoffBuildError("review plugin identity mismatch")
    if review.get("verdict") != finding_spec["static_verdict"]:
        raise HandoffBuildError("review verdict mismatch")
    if finding_spec["finding_id"] not in review.get("finding_ids", []):
        raise HandoffBuildError("finding_id is not covered by the bound review")

    source_manifest = tree_manifest(source_files)
    patched_manifest = tree_manifest(patched_files)
    source_tree_sha256 = sha256_bytes(canonical_json(source_manifest))
    patched_tree_sha256 = sha256_bytes(canonical_json(patched_manifest))
    if source_tree_sha256 == artifact_sha256 or source_tree_sha256 == patched_tree_sha256:
        raise HandoffBuildError("archive, vulnerable tree, and patched tree require distinct hashes")

    trace: list[dict[str, Any]] = []
    for expected_sequence, node in enumerate(finding_spec["source_to_sink_trace"]):
        if node.get("sequence") != expected_sequence:
            raise HandoffBuildError("trace sequences must be contiguous from zero")
        path = safe_relative_path(node["file"])
        if path not in source_files:
            raise HandoffBuildError(f"trace file absent from source tree: {path}")
        trace.append(
            {
                **node,
                "line_range_sha256": line_range_sha256(
                    source_files[path], node["start_line"], node["end_line"]
                ),
            }
        )
    kinds = [node["kind"] for node in trace]
    for required in ("source", "storage", "retrieval", "sink"):
        if kinds.count(required) != 1:
            raise HandoffBuildError(f"trace requires exactly one {required} node")
    if not kinds.index("source") < kinds.index("storage") < kinds.index("retrieval") < kinds.index("sink"):
        raise HandoffBuildError("trace must order source, storage, retrieval, sink")

    sink = next(node for node in trace if node["kind"] == "sink")
    patch_spec = spec["patched_control"]
    patch_bytes = canonical_patch(
        source_files,
        patched_files,
        sink["file"],
        sink["start_line"],
        sink["end_line"],
        patch_spec["encoding_function"],
    )
    safe_input_sha256 = spec["oracle"]["safe_input_sha256"]
    candidate_input_sha256 = spec["oracle"]["candidate_input_sha256"]
    lanes = [
        {
            "lane_id": "safe_input",
            "artifact_sha256": source_tree_sha256,
            "input_sha256": safe_input_sha256,
            "expected_impact": False,
            "fresh_browser_context": True,
            "patched_control_origin": "not_applicable",
        },
        {
            "lane_id": "candidate",
            "artifact_sha256": source_tree_sha256,
            "input_sha256": candidate_input_sha256,
            "expected_impact": True,
            "fresh_browser_context": True,
            "patched_control_origin": "not_applicable",
        },
        {
            "lane_id": "fresh_context",
            "artifact_sha256": source_tree_sha256,
            "input_sha256": candidate_input_sha256,
            "expected_impact": True,
            "fresh_browser_context": True,
            "patched_control_origin": "not_applicable",
        },
        {
            "lane_id": "patched_artifact",
            "artifact_sha256": patched_tree_sha256,
            "input_sha256": candidate_input_sha256,
            "expected_impact": False,
            "fresh_browser_context": True,
            "patched_control_origin": "researcher_created",
        },
    ]
    handoff = {
        "handoff_schema_version": "2.0",
        "kind": "wordpress_plugin_xss_candidate",
        "plugin": {
            **plugin_spec,
            "official_artifact_sha256": artifact_sha256,
            "source_tree_sha256": source_tree_sha256,
        },
        "finding": {
            **{key: value for key, value in finding_spec.items() if key != "source_to_sink_trace"},
            "source_to_sink_trace": trace,
            "required_evidence": ["transport", "storage", "sink", "impact", "browser", "cleanup"],
        },
        "principals": spec["principals"],
        "environment_matrix": spec["environment_matrix"],
        "oracle": {"lanes": lanes},
        "patched_control": {
            "origin": "researcher_created",
            "official_fix": False,
            "vulnerable_tree_sha256": source_tree_sha256,
            "patched_tree_sha256": patched_tree_sha256,
            "patch_diff_sha256": sha256_bytes(patch_bytes),
            "changed_files": [sink["file"]],
            "change_scope": "context_specific_output_encoding_only",
            "sink_context": patch_spec["sink_context"],
            "encoding_function": patch_spec["encoding_function"],
        },
        "safety": spec["safety"],
        "handoff_status": spec["handoff_status"],
    }
    validate_poc_xss_v2_contract(handoff)
    receipt = {
        "schema_version": 1,
        "kind": "static_xss_handoff_v2_build_receipt",
        "plugin": plugin_spec["slug"],
        "version": plugin_spec["version"],
        "finding_id": finding_spec["finding_id"],
        "candidate_id": finding_spec["candidate_id"],
        "official_artifact_sha256": artifact_sha256,
        "source_tree_sha256": source_tree_sha256,
        "patched_tree_sha256": patched_tree_sha256,
        "patch_diff_sha256": sha256_bytes(patch_bytes),
        "source_tree_file_count": len(source_files),
        "review_canonical_sha256": sha256_bytes(canonical_json(review)),
        "handoff_canonical_sha256": sha256_bytes(canonical_json(handoff)),
        "checks": [
            "manifest_identity",
            "review_identity_and_finding_coverage",
            "official_zip_to_tree_exact_bytes",
            "trace_line_range_hashes",
            "single_sink_file_insertion_only_patch",
            "four_lane_hash_binding",
        ],
        "plugin_code_executed": False,
        "runtime_invoked": False,
        "browser_invoked": False,
        "external_communication": False,
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical_json(receipt))
    return handoff, patch_bytes, receipt


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a strict stored-XSS v2 static handoff")
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--artifact-manifest", type=Path, required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--artifact-zip", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--patched-root", type=Path, required=True)
    parser.add_argument("--patched-output-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--patch-output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()

    spec_value = load_json_strict(args.spec)
    source_files = read_tree(args.source_root)
    candidate_patched_files = read_tree(args.patched_root)
    sink_spec = next(
        node for node in spec_value["finding"]["source_to_sink_trace"]
        if node["kind"] == "sink"
    )
    patched_files = normalize_patch_to_sink_range(
        source_files,
        candidate_patched_files,
        sink_spec["file"],
        sink_spec["start_line"],
        sink_spec["end_line"],
    )
    handoff, patch_bytes, receipt = build_handoff(
        spec=spec_value,
        artifact_manifest=load_json_strict(args.artifact_manifest),
        review=load_json_strict(args.review),
        artifact_bytes=args.artifact_zip.read_bytes(),
        source_files=source_files,
        patched_files=patched_files,
    )
    write_tree(args.patched_output_root, patched_files)
    write_json(args.output, handoff)
    args.patch_output.parent.mkdir(parents=True, exist_ok=True)
    args.patch_output.write_bytes(patch_bytes)
    receipt["handoff_raw_sha256"] = sha256_bytes(args.output.read_bytes())
    receipt["patch_raw_sha256"] = sha256_bytes(args.patch_output.read_bytes())
    receipt["spec_raw_sha256"] = sha256_bytes(args.spec.read_bytes())
    receipt["artifact_manifest_raw_sha256"] = sha256_bytes(args.artifact_manifest.read_bytes())
    receipt["review_raw_sha256"] = sha256_bytes(args.review.read_bytes())
    receipt["patched_tree_derivation"] = "official_vulnerable_tree_plus_bound_sink_range_only"
    receipt["receipt_sha256"] = sha256_bytes(canonical_json({key: value for key, value in receipt.items() if key != "receipt_sha256"}))
    write_json(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
