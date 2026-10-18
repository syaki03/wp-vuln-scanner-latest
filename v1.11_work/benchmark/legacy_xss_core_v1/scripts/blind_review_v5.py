"""Blind-review v5 overlay: unresolved-fact discipline and finding identity locks."""

from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any

try:
    import blind_review_v4 as base
except ImportError:  # copied blind bundle layout
    import REVIEW_VALIDATOR_V4_BASE as base  # type: ignore[no-redef]


PRECONDITION_KINDS = {
    "deployment",
    "server_normalization",
    "external_semantics",
    "core_version",
    "template_identity",
    "extension_callback",
}
RESOLUTION_BOUNDARIES = {
    "runtime_environment",
    "external_service",
    "deployment_configuration",
    "platform_contract",
    "template_override",
    "extension_implementation",
}
PRECONDITION_LINKS = {
    "deployment": {"reachability", "call", "sink"},
    "server_normalization": {"context_escape"},
    "external_semantics": {"source", "call", "sink", "reachability"},
    "core_version": {"source", "call", "sink", "reachability", "context_escape"},
    "template_identity": {"call", "sink", "reachability"},
    "extension_callback": {"source", "call", "sink", "context_escape"},
}
IDENTITY_KEYS = {
    "finding_global_rank",
    "path",
    "line",
    "anchor_kind",
    "anchor_match",
    "source_kind",
    "source_match",
    "sink_kind",
    "context",
}


def finding_identity(finding: dict[str, Any]) -> dict[str, Any]:
    """Return the public scanner identity that a v5 trace must preserve."""
    sink_kind = str(finding.get("sink_kind", ""))
    sink_match = str(finding.get("sink_match", ""))
    storage_match = str(finding.get("storage_match", ""))
    if sink_kind and sink_match:
        anchor_kind, anchor_match = "sink", sink_match
    elif str(finding.get("storage_kind", "")) == "writes" and storage_match:
        anchor_kind, anchor_match = "write", storage_match
    else:
        raise ValueError("finding has neither a sink nor storage-write anchor")
    rank = finding.get("global_rank")
    line = finding.get("line")
    if (
        isinstance(rank, bool)
        or not isinstance(rank, int)
        or rank < 1
        or isinstance(line, bool)
        or not isinstance(line, int)
        or line < 1
    ):
        raise ValueError("finding identity has an invalid rank or line")
    return {
        "finding_global_rank": rank,
        "path": str(finding.get("file", "")).replace("\\", "/"),
        "line": line,
        "anchor_kind": anchor_kind,
        "anchor_match": anchor_match,
        "source_kind": str(finding.get("source_kind", "")),
        "source_match": str(finding.get("source_match", "")),
        "sink_kind": sink_kind,
        "context": str(finding.get("context", "")),
    }


def _identity_schema() -> dict[str, Any]:
    return {
        "oneOf": [
            {"type": "null"},
            {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(IDENTITY_KEYS),
                "properties": {
                    "finding_global_rank": {"type": "integer", "minimum": 1},
                    "path": {"type": "string", "minLength": 1},
                    "line": {"type": "integer", "minimum": 1},
                    "anchor_kind": {"enum": ["sink", "write"]},
                    "anchor_match": {"type": "string", "minLength": 1},
                    "source_kind": {"type": "string"},
                    "source_match": {"type": "string", "minLength": 1},
                    "sink_kind": {"type": "string"},
                    "context": {"type": "string"},
                },
            },
        ]
    }


def _proof_schema() -> dict[str, Any]:
    return {
        "oneOf": [
            {"type": "null"},
            {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "claimed_source",
                    "sink_value",
                    "distinct_producer",
                    "non_alias_evidence_step_ids",
                ],
                "properties": {
                    "claimed_source": {"type": "string", "minLength": 1},
                    "sink_value": {"type": "string", "minLength": 1},
                    "distinct_producer": {"type": "string", "minLength": 1},
                    "non_alias_evidence_step_ids": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": {"type": "string", "pattern": "^step-[0-9]{2,}$"},
                    },
                },
            },
        ]
    }


def _candidate_schema() -> dict[str, Any]:
    schema = copy.deepcopy(base._candidate_schema())
    schema["required"].extend(["finding_identity", "field_mismatch_proof"])
    schema["properties"]["finding_identity"] = _identity_schema()
    schema["properties"]["field_mismatch_proof"] = _proof_schema()
    schema["properties"]["open_preconditions"] = {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "kind",
                "affected_link",
                "resolution_boundary",
                "unresolved_fact",
                "evidence_step_ids",
            ],
            "properties": {
                "kind": {"enum": sorted(PRECONDITION_KINDS)},
                "affected_link": {"enum": list(base.LINK_NAMES)},
                "resolution_boundary": {"enum": sorted(RESOLUTION_BOUNDARIES)},
                "unresolved_fact": {"type": "string", "minLength": 8},
                "evidence_step_ids": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {"type": "string", "pattern": "^step-[0-9]{2,}$"},
                },
            },
        },
    }
    return schema


def review_schema_v5() -> dict[str, Any]:
    schema = copy.deepcopy(base.review_schema_v4())
    schema["schema_version"] = "blind-review-v5-schema-1"
    schema["properties"]["schema_version"] = {"const": "blind-review-v5"}
    schema["properties"]["primary_candidate"] = _candidate_schema()
    schema["properties"]["independent_paths"] = {
        "type": "array",
        "items": _candidate_schema(),
    }
    return schema


def _strip_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(candidate)
    value.pop("finding_identity", None)
    value.pop("field_mismatch_proof", None)
    value["open_preconditions"] = [
        {
            "kind": (
                item["kind"]
                if item["kind"] in base.PRECONDITION_KINDS
                else "deployment"
            ),
            "evidence_step_ids": item["evidence_step_ids"],
        }
        for item in value.get("open_preconditions", [])
    ]
    return value


def _strip_review(review: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(review)
    value["schema_version"] = "blind-review-v4"
    value["primary_candidate"] = _strip_candidate(value["primary_candidate"])
    value["independent_paths"] = [
        _strip_candidate(candidate) for candidate in value["independent_paths"]
    ]
    return value


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    return base._require_exact_keys(value, keys, label)


def _validate_identity(value: Any, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    value = _exact_keys(value, IDENTITY_KEYS, label)
    if value["anchor_kind"] not in {"sink", "write"}:
        raise ValueError(f"{label}.anchor_kind is invalid")
    for name in ("path", "anchor_match", "source_match"):
        if not isinstance(value[name], str) or not value[name]:
            raise ValueError(f"{label}.{name} is required")
    for name in ("source_kind", "sink_kind", "context"):
        if not isinstance(value[name], str):
            raise ValueError(f"{label}.{name} must be a string")
    for name in ("finding_global_rank", "line"):
        if isinstance(value[name], bool) or not isinstance(value[name], int) or value[name] < 1:
            raise ValueError(f"{label}.{name} is invalid")
    try:
        re.compile(value["anchor_match"])
    except re.error as exc:
        raise ValueError(f"{label}.anchor_match is not a valid scanner pattern") from exc
    return value


def validate_candidate(candidate: Any, *, label: str, primary: bool) -> dict[str, Any]:
    required = set(base._candidate_schema()["required"]) | {
        "finding_identity",
        "field_mismatch_proof",
    }
    candidate = _exact_keys(candidate, required, label)
    base.validate_candidate(_strip_candidate(candidate), label=label, primary=primary)
    identity = _validate_identity(candidate["finding_identity"], f"{label}.finding_identity")
    rank = candidate["finding_global_rank"]
    if (rank is None) != (identity is None):
        raise ValueError(f"{label}: finding_identity must be present exactly when rank is present")
    if identity is not None and identity["finding_global_rank"] != rank:
        raise ValueError(f"{label}: finding_identity rank does not match candidate rank")

    step_ids = {step["step_id"] for step in candidate["trace_steps"]}
    for index, condition in enumerate(candidate["open_preconditions"], 1):
        condition = _exact_keys(
            condition,
            {
                "kind",
                "affected_link",
                "resolution_boundary",
                "unresolved_fact",
                "evidence_step_ids",
            },
            f"{label}.open_preconditions[{index}]",
        )
        kind = condition["kind"]
        affected = condition["affected_link"]
        if kind not in PRECONDITION_KINDS:
            raise ValueError(f"{label}.open_preconditions[{index}].kind is invalid")
        if affected not in PRECONDITION_LINKS[kind]:
            raise ValueError(f"{label}.open_preconditions[{index}] kind does not match affected_link")
        if condition["resolution_boundary"] not in RESOLUTION_BOUNDARIES:
            raise ValueError(f"{label}.open_preconditions[{index}].resolution_boundary is invalid")
        if not isinstance(condition["unresolved_fact"], str) or len(condition["unresolved_fact"].strip()) < 8:
            raise ValueError(f"{label}.open_preconditions[{index}].unresolved_fact is too short")
        refs = condition["evidence_step_ids"]
        if not isinstance(refs, list) or not refs or len(refs) != len(set(refs)) or any(
            ref not in step_ids for ref in refs
        ):
            raise ValueError(f"{label}.open_preconditions[{index}] needs cited trace evidence")
        if candidate["link_states"][affected] != "unknown":
            raise ValueError(f"{label}.open_preconditions[{index}] must name an unknown link")
        if kind == "server_normalization":
            gap = candidate["evidence_gap"]
            if not isinstance(gap, dict) or gap.get("missing_link") != "context_escape":
                raise ValueError(f"{label}: server_normalization requires a context_escape evidence gap")

    proof = candidate["field_mismatch_proof"]
    refutation = candidate["refutation"]
    needs_proof = isinstance(refutation, dict) and refutation.get("reason") == "field_mismatch"
    if needs_proof:
        proof = _exact_keys(
            proof,
            {"claimed_source", "sink_value", "distinct_producer", "non_alias_evidence_step_ids"},
            f"{label}.field_mismatch_proof",
        )
        for name in ("claimed_source", "sink_value", "distinct_producer"):
            if not isinstance(proof[name], str) or not proof[name].strip():
                raise ValueError(f"{label}.field_mismatch_proof.{name} is required")
        refs = proof["non_alias_evidence_step_ids"]
        if not isinstance(refs, list) or not refs or len(refs) != len(set(refs)) or any(
            ref not in step_ids for ref in refs
        ):
            raise ValueError(f"{label}.field_mismatch_proof needs non-alias evidence steps")
    elif proof is not None:
        raise ValueError(f"{label}.field_mismatch_proof must be null without field_mismatch")
    return candidate


def validate_review_shape(review: Any, eval_id: str) -> dict[str, Any]:
    keys = {
        "schema_version",
        "eval_id",
        "source_inventory_sha256",
        "primary_candidate",
        "independent_paths",
        "reviewed_files",
        "review_passes",
    }
    review = _exact_keys(review, keys, f"{eval_id} v5 review")
    if review["schema_version"] != "blind-review-v5" or review["eval_id"] != eval_id:
        raise ValueError(f"{eval_id}: invalid v5 review identity")
    base.validate_review_shape(_strip_review(review), eval_id)
    validate_candidate(review["primary_candidate"], label=f"{eval_id}.primary_candidate", primary=True)
    ids: set[str] = set()
    for index, candidate in enumerate(review["independent_paths"], 1):
        validate_candidate(candidate, label=f"{eval_id}.independent_paths[{index}]", primary=False)
        if candidate["candidate_id"] in ids:
            raise ValueError(f"{eval_id}: duplicate independent candidate_id")
        ids.add(candidate["candidate_id"])
    return review


def _anchor_matches(candidate: dict[str, Any], identity: dict[str, Any]) -> bool:
    rank = identity["finding_global_rank"]
    for step in candidate["trace_steps"]:
        expression = step["expression"]
        synthetic_attachment_accumulator = (
            identity["anchor_match"] == "attachment_exif_return_accumulator"
            and bool(re.search(r"\$[A-Za-z_][A-Za-z0-9_]*\s*=", expression))
            and any(
                token in expression
                for token in re.findall(
                    r"\$[A-Za-z_][A-Za-z0-9_]*", identity["source_match"]
                )
            )
        )
        if (
            step["kind"] == identity["anchor_kind"]
            and step["path"] == identity["path"]
            and step["line_start"] <= identity["line"] <= step["line_end"]
            and rank in step["finding_global_ranks"]
            and (
                synthetic_attachment_accumulator
                or re.search(identity["anchor_match"], expression, re.IGNORECASE | re.DOTALL)
            )
        ):
            return True
    return False


def _source_identity_matches(candidate: dict[str, Any], identity: dict[str, Any]) -> bool:
    source_kind = identity["source_kind"]
    if source_kind == "stored_read":
        return True
    expressions = [
        step["expression"]
        for step in candidate["trace_steps"]
        if step["kind"] in {"source", "transform", "write", "storage_read"}
        and identity["finding_global_rank"] in step["finding_global_ranks"]
    ]
    if source_kind == "variable_flow":
        tokens = re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", identity["source_match"])
        return bool(tokens) and any(token in expression for token in tokens for expression in expressions)
    try:
        pattern = re.compile(identity["source_match"], re.IGNORECASE | re.DOTALL)
    except re.error:
        return any(identity["source_match"] in expression for expression in expressions)
    return any(pattern.search(expression) for expression in expressions)


def _validate_candidate_binding(
    candidate: dict[str, Any], finding_by_rank: dict[int, dict[str, Any]], label: str
) -> None:
    rank = candidate["finding_global_rank"]
    identity = candidate["finding_identity"]
    if rank is None:
        return
    expected = finding_identity(finding_by_rank[rank])
    if identity != expected:
        raise ValueError(f"{label}: finding_identity does not exactly match bundle finding")
    if not _anchor_matches(candidate, expected):
        raise ValueError(f"{label}: trace does not preserve the finding file/line/anchor identity")
    if not _source_identity_matches(candidate, expected):
        raise ValueError(f"{label}: trace does not preserve the finding source identity")


def validate_review_against_bundle(
    review: Any, bundle: Any, *, blind_root: Path, eval_id: str
) -> dict[str, Any]:
    review = validate_review_shape(review, eval_id)
    if not isinstance(bundle, dict) or bundle.get("schema_version") != "blind-review-bundle-v5":
        raise ValueError(f"{eval_id}: invalid v5 bundle identity")
    base_bundle = copy.deepcopy(bundle)
    base_bundle["schema_version"] = "blind-review-bundle-v4"
    base_bundle.pop("primary_finding_identity", None)
    base.validate_review_against_bundle(
        _strip_review(review), base_bundle, blind_root=blind_root, eval_id=eval_id
    )
    finding_by_rank = {
        int(finding["global_rank"]): finding for finding in bundle.get("findings", [])
    }
    primary_rank = review["primary_candidate"]["finding_global_rank"]
    expected_primary = finding_identity(finding_by_rank[primary_rank]) if primary_rank is not None else None
    if bundle.get("primary_finding_identity") != expected_primary:
        raise ValueError(f"{eval_id}: bundle primary_finding_identity is inconsistent")
    _validate_candidate_binding(review["primary_candidate"], finding_by_rank, f"{eval_id}.primary_candidate")
    for index, candidate in enumerate(review["independent_paths"], 1):
        _validate_candidate_binding(candidate, finding_by_rank, f"{eval_id}.independent_paths[{index}]")
    return review


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate one blind-review v5 JSON file")
    parser.add_argument("review", type=Path)
    parser.add_argument("--eval-id", required=True)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()
    review = json.loads(args.review.read_text(encoding="utf-8"))
    if args.bundle is None:
        validate_review_shape(review, args.eval_id)
    else:
        bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
        validate_review_against_bundle(
            review,
            bundle,
            blind_root=args.bundle.resolve().parent.parent,
            eval_id=args.eval_id,
        )
    print(f"PASS review_v5={args.eval_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
