"""Closed blind-review v4 evidence contract and deterministic verdict rules."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any


VERDICTS = {
    "likely_vulnerable",
    "possible_vulnerability",
    "likely_false_positive",
    "insufficient_evidence",
}
LINK_NAMES = (
    "source",
    "write",
    "storage_read",
    "call",
    "sink",
    "reachability",
    "context_escape",
)
LINK_STATES = {"confirmed", "refuted", "unknown", "not_applicable"}
PATH_REQUIREMENTS = {
    "unresolved": {"source", "sink"},
    "direct": {"source", "sink"},
    "stored": {"source", "write", "storage_read", "sink"},
    "interprocedural": {"source", "call", "sink"},
    "stored_interprocedural": {"source", "write", "storage_read", "call", "sink"},
}
TRACE_KINDS = {
    "entrypoint",
    "source",
    "transform",
    "write",
    "storage_read",
    "call",
    "callback",
    "sink",
    "render",
    "defense",
    "refutation",
}
CONTEXT_KINDS = {
    "html_text",
    "html_attribute",
    "textarea",
    "url_attribute",
    "javascript_string",
    "javascript_code",
    "css",
    "unknown",
    "not_applicable",
}
DELIMITERS = {"none", "single_quote", "double_quote", "unquoted", "unknown", "not_applicable"}
ENTRYPOINT_KINDS = {
    "direct_php",
    "hook",
    "ajax",
    "rest",
    "shortcode",
    "admin_page",
    "template",
    "cron",
    "cli",
    "unknown",
}
PRIVILEGES = {
    "public",
    "unauthenticated",
    "subscriber",
    "contributor",
    "author",
    "editor",
    "administrator",
    "custom_capability",
    "unknown",
    "not_applicable",
}
PRECONDITION_KINDS = {
    "role",
    "setting",
    "deployment",
    "server_normalization",
    "external_semantics",
    "victim_action",
    "core_version",
}
REFUTATION_LINKS = set(LINK_NAMES)
REFUTATION_REASONS = {
    "fixed_literal",
    "nonflow",
    "field_mismatch",
    "context_correct_encoder",
    "unreachable",
}
REFUTATION_LINK_BY_REASON = {
    "fixed_literal": {"source", "sink"},
    "nonflow": {"source", "write", "storage_read", "call", "sink"},
    "field_mismatch": {"source", "write", "storage_read"},
    "context_correct_encoder": {"context_escape"},
    "unreachable": {"reachability"},
}
EVIDENCE_KINDS_BY_LINK = {
    "source": {"source", "refutation"},
    "write": {"write", "refutation"},
    "storage_read": {"storage_read", "refutation"},
    "call": {"call", "callback", "refutation"},
    "sink": {"sink", "refutation"},
    "reachability": {"entrypoint", "call", "callback", "refutation"},
    "context_escape": {"sink", "defense", "refutation"},
}


def _location_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "step_id",
            "kind",
            "path",
            "line_start",
            "line_end",
            "expression",
            "input_step_ids",
            "finding_global_ranks",
        ],
        "properties": {
            "step_id": {"type": "string", "pattern": "^step-[0-9]{2,}$"},
            "kind": {"enum": sorted(TRACE_KINDS)},
            "path": {"type": "string", "minLength": 1},
            "line_start": {"type": "integer", "minimum": 1},
            "line_end": {"type": "integer", "minimum": 1},
            "expression": {"type": "string", "minLength": 1},
            "input_step_ids": {
                "type": "array",
                "uniqueItems": True,
                "items": {"type": "string", "pattern": "^step-[0-9]{2,}$"},
            },
            "finding_global_ranks": {
                "type": "array",
                "uniqueItems": True,
                "items": {"type": "integer", "minimum": 1},
            },
        },
    }


def _candidate_schema() -> dict[str, Any]:
    descriptions = {
        "source": "confirmed when attacker-controlled input identity is established",
        "write": "confirmed when the same value reaches the required persistence write",
        "storage_read": "confirmed when the same stored identity is read for this path",
        "call": "confirmed when the required call/callback transfer is established",
        "sink": "confirmed when the carried value reaches the claimed output sink",
        "reachability": "confirmed when the relevant entrypoint is statically reachable",
        "context_escape": (
            "confirmed means a context-correct escape protects the exact sink; "
            "refuted means that context-correct escape is absent"
        ),
    }
    link_states = {
        "type": "object",
        "additionalProperties": False,
        "required": list(LINK_NAMES),
        "properties": {
            name: {"enum": sorted(LINK_STATES), "description": descriptions[name]}
            for name in LINK_NAMES
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "candidate_id",
            "finding_global_rank",
            "path_kind",
            "verdict",
            "confidence",
            "link_states",
            "trace_steps",
            "supporting_finding_global_ranks",
            "context",
            "exposure",
            "open_preconditions",
            "refutation",
            "evidence_gap",
            "summary",
        ],
        "properties": {
            "candidate_id": {"type": "string", "minLength": 1},
            "finding_global_rank": {"type": ["integer", "null"], "minimum": 1},
            "path_kind": {"enum": sorted(PATH_REQUIREMENTS)},
            "verdict": {"enum": sorted(VERDICTS)},
            "confidence": {"enum": ["high", "medium", "low"]},
            "link_states": link_states,
            "trace_steps": {"type": "array", "items": _location_schema()},
            "supporting_finding_global_ranks": {
                "type": "array",
                "uniqueItems": True,
                "items": {"type": "integer", "minimum": 1},
            },
            "context": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "delimiter"],
                "properties": {
                    "kind": {"enum": sorted(CONTEXT_KINDS)},
                    "delimiter": {"enum": sorted(DELIMITERS)},
                },
            },
            "exposure": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "entrypoint_kind",
                    "attacker_privilege",
                    "victim_privilege",
                    "configuration_requirement",
                ],
                "properties": {
                    "entrypoint_kind": {"enum": sorted(ENTRYPOINT_KINDS)},
                    "attacker_privilege": {"enum": sorted(PRIVILEGES)},
                    "victim_privilege": {"enum": sorted(PRIVILEGES)},
                    "configuration_requirement": {
                        "enum": ["none", "default", "non_default", "unknown"]
                    },
                },
            },
            "open_preconditions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["kind", "evidence_step_ids"],
                    "properties": {
                        "kind": {"enum": sorted(PRECONDITION_KINDS)},
                        "evidence_step_ids": {
                            "type": "array",
                            "uniqueItems": True,
                            "items": {"type": "string", "pattern": "^step-[0-9]{2,}$"},
                        },
                    },
                },
            },
            "refutation": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["reason", "blocked_link", "evidence_step_ids"],
                        "properties": {
                            "reason": {"enum": sorted(REFUTATION_REASONS)},
                            "blocked_link": {"enum": sorted(REFUTATION_LINKS)},
                            "evidence_step_ids": {
                                "type": "array",
                                "minItems": 1,
                                "uniqueItems": True,
                                "items": {"type": "string", "pattern": "^step-[0-9]{2,}$"},
                            },
                        },
                    },
                ]
            },
            "evidence_gap": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["missing_link", "searched_files"],
                        "properties": {
                            "missing_link": {"enum": [
                                "source", "write", "storage_read", "call", "sink", "context_escape"
                            ]},
                            "searched_files": {
                                "type": "array",
                                "minItems": 1,
                                "uniqueItems": True,
                                "items": {"type": "string", "minLength": 1},
                            },
                        },
                    },
                ]
            },
            "summary": {"type": "string"},
        },
        "allOf": [
            {
                "if": {"properties": {"verdict": {"const": "likely_false_positive"}}, "required": ["verdict"]},
                "then": {"properties": {"refutation": {"type": "object"}, "evidence_gap": {"type": "null"}}},
            },
            {
                "if": {"properties": {"verdict": {"const": "insufficient_evidence"}}, "required": ["verdict"]},
                "then": {"properties": {"refutation": {"type": "null"}, "evidence_gap": {"type": "object"}}},
            },
            {
                "if": {
                    "properties": {"verdict": {"enum": ["likely_vulnerable", "possible_vulnerability"]}},
                    "required": ["verdict"],
                },
                "then": {"properties": {"refutation": {"type": "null"}, "evidence_gap": {"type": "null"}}},
            },
            {
                "if": {"properties": {"path_kind": {"const": "direct"}}, "required": ["path_kind"]},
                "then": {"properties": {"link_states": {"properties": {
                    "write": {"const": "not_applicable"},
                    "storage_read": {"const": "not_applicable"},
                    "call": {"const": "not_applicable"},
                }}}},
            },
            {
                "if": {"properties": {"path_kind": {"const": "stored"}}, "required": ["path_kind"]},
                "then": {"properties": {"link_states": {"properties": {
                    "write": {"not": {"const": "not_applicable"}},
                    "storage_read": {"not": {"const": "not_applicable"}},
                    "call": {"const": "not_applicable"},
                }}}},
            },
            {
                "if": {"properties": {"path_kind": {"const": "interprocedural"}}, "required": ["path_kind"]},
                "then": {"properties": {"link_states": {"properties": {
                    "write": {"const": "not_applicable"},
                    "storage_read": {"const": "not_applicable"},
                    "call": {"not": {"const": "not_applicable"}},
                }}}},
            },
            {
                "if": {"properties": {"path_kind": {"const": "stored_interprocedural"}}, "required": ["path_kind"]},
                "then": {"properties": {"link_states": {"properties": {
                    "write": {"not": {"const": "not_applicable"}},
                    "storage_read": {"not": {"const": "not_applicable"}},
                    "call": {"not": {"const": "not_applicable"}},
                }}}},
            },
        ],
    }


def review_schema_v4() -> dict[str, Any]:
    """Return the self-contained schema shipped to blind reviewers."""
    required = [
        "schema_version",
        "eval_id",
        "source_inventory_sha256",
        "primary_candidate",
        "independent_paths",
        "reviewed_files",
        "review_passes",
    ]
    file_list = {
        "type": "array",
        "minItems": 1,
        "uniqueItems": True,
        "items": {"type": "string", "minLength": 1},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "blind-review-v4-schema-1",
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {
            "schema_version": {"const": "blind-review-v4"},
            "eval_id": {"type": "string", "pattern": "^eval-[0-9]{4}$"},
            "source_inventory_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "primary_candidate": _candidate_schema(),
            "independent_paths": {"type": "array", "items": _candidate_schema()},
            "reviewed_files": file_list,
            "review_passes": {
                "type": "object",
                "additionalProperties": False,
                "required": ["scanner_guided", "entrypoint_led", "sink_storage_led"],
                "properties": {
                    "scanner_guided": file_list,
                    "entrypoint_led": file_list,
                    "sink_storage_led": file_list,
                },
            },
        },
    }


def _require_exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    missing = keys.difference(value)
    extra = set(value).difference(keys)
    if missing:
        raise ValueError(f"{label} missing fields: {sorted(missing)}")
    if extra:
        raise ValueError(f"{label} unexpected fields: {sorted(extra)}")
    return value


def required_links(path_kind: str) -> set[str]:
    try:
        return set(PATH_REQUIREMENTS[path_kind])
    except KeyError as exc:
        raise ValueError(f"invalid path_kind: {path_kind}") from exc


def derive_verdict(candidate: dict[str, Any]) -> str:
    """Derive a verdict only from normalized primary/path evidence."""
    links = candidate["link_states"]
    required = required_links(candidate["path_kind"])
    blockers = required | {"reachability"}
    if any(links[name] == "refuted" for name in blockers) or links["context_escape"] == "confirmed":
        return "likely_false_positive"
    if any(links[name] == "unknown" for name in required) or links["context_escape"] == "unknown":
        return "insufficient_evidence"
    if links["reachability"] == "unknown" or candidate["open_preconditions"]:
        return "possible_vulnerability"
    return "likely_vulnerable"


def _validate_trace_step(step: Any, label: str, prior_ids: set[str]) -> None:
    keys = {
        "step_id", "kind", "path", "line_start", "line_end", "expression",
        "input_step_ids", "finding_global_ranks",
    }
    step = _require_exact_keys(step, keys, label)
    step_id = step["step_id"]
    if not isinstance(step_id, str) or not re.fullmatch(r"step-[0-9]{2,}", step_id):
        raise ValueError(f"{label}.step_id is invalid")
    if step_id in prior_ids:
        raise ValueError(f"{label}.step_id is duplicated")
    if step["kind"] not in TRACE_KINDS:
        raise ValueError(f"{label}.kind is invalid")
    if not isinstance(step["path"], str) or not step["path"]:
        raise ValueError(f"{label}.path is required")
    if (
        isinstance(step["line_start"], bool)
        or isinstance(step["line_end"], bool)
        or not isinstance(step["line_start"], int)
        or not isinstance(step["line_end"], int)
        or step["line_start"] < 1
        or step["line_end"] < step["line_start"]
        or step["line_end"] - step["line_start"] > 19
    ):
        raise ValueError(f"{label} has a non-tight line range")
    if not isinstance(step["expression"], str) or not step["expression"].strip():
        raise ValueError(f"{label}.expression is required")
    inputs = step["input_step_ids"]
    if not isinstance(inputs, list) or len(inputs) != len(set(inputs)):
        raise ValueError(f"{label}.input_step_ids must be a unique array")
    if any(not isinstance(item, str) or item not in prior_ids for item in inputs):
        raise ValueError(f"{label} must reference only earlier trace steps")
    ranks = step["finding_global_ranks"]
    if (
        not isinstance(ranks, list)
        or len(ranks) != len(set(ranks))
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in ranks)
    ):
        raise ValueError(f"{label}.finding_global_ranks is invalid")
    prior_ids.add(step_id)


def _has_connected_complete_trace(candidate: dict[str, Any]) -> bool:
    steps = candidate["trace_steps"]
    by_id = {step["step_id"]: step for step in steps}
    required_kinds = required_links(candidate["path_kind"])
    required_kinds.discard("sink")

    def ancestors(step_id: str, seen: set[str] | None = None) -> set[str]:
        seen = set() if seen is None else seen
        if step_id in seen:
            return seen
        seen.add(step_id)
        for parent in by_id[step_id]["input_step_ids"]:
            ancestors(parent, seen)
        return seen

    for sink in (step for step in steps if step["kind"] == "sink"):
        chain = ancestors(sink["step_id"])
        kinds = {by_id[step_id]["kind"] for step_id in chain}
        if required_kinds.issubset(kinds):
            return True
    return False


def validate_candidate(candidate: Any, *, label: str, primary: bool) -> dict[str, Any]:
    keys = {
        "candidate_id", "finding_global_rank", "path_kind", "verdict", "confidence",
        "link_states", "trace_steps", "supporting_finding_global_ranks", "context",
        "exposure", "open_preconditions", "refutation", "evidence_gap", "summary",
    }
    candidate = _require_exact_keys(candidate, keys, label)
    if primary and candidate["candidate_id"] != "primary":
        raise ValueError(f"{label}.candidate_id must be primary")
    if not primary and (
        not isinstance(candidate["candidate_id"], str)
        or not re.fullmatch(r"independent-[0-9]{2,}", candidate["candidate_id"])
    ):
        raise ValueError(f"{label}.candidate_id is invalid")
    rank = candidate["finding_global_rank"]
    if rank is not None and (isinstance(rank, bool) or not isinstance(rank, int) or rank < 1):
        raise ValueError(f"{label}.finding_global_rank is invalid")
    if candidate["path_kind"] not in PATH_REQUIREMENTS:
        raise ValueError(f"{label}.path_kind is invalid")
    if not primary and candidate["path_kind"] == "unresolved":
        raise ValueError(f"{label}: independent path cannot be unresolved")
    if candidate["verdict"] not in VERDICTS:
        raise ValueError(f"{label}.verdict is invalid")
    if candidate["confidence"] not in {"high", "medium", "low"}:
        raise ValueError(f"{label}.confidence is invalid")
    if not isinstance(candidate["summary"], str):
        raise ValueError(f"{label}.summary must be a string")

    links = _require_exact_keys(candidate["link_states"], set(LINK_NAMES), f"{label}.link_states")
    if any(value not in LINK_STATES for value in links.values()):
        raise ValueError(f"{label}.link_states contains an invalid state")
    required = required_links(candidate["path_kind"])
    for name in {"source", "sink", "reachability", "context_escape"}:
        if links[name] == "not_applicable":
            raise ValueError(f"{label}.link_states.{name} cannot be not_applicable")
    for name in {"write", "storage_read", "call"}:
        should_apply = name in required
        if should_apply == (links[name] == "not_applicable"):
            raise ValueError(f"{label}.link_states.{name} conflicts with path_kind")

    steps = candidate["trace_steps"]
    if not isinstance(steps, list):
        raise ValueError(f"{label}.trace_steps must be an array")
    prior_ids: set[str] = set()
    for index, step in enumerate(steps, 1):
        _validate_trace_step(step, f"{label}.trace_steps[{index}]", prior_ids)
    step_kinds = {step["kind"] for step in steps}
    for name in required | {"reachability", "context_escape"}:
        if links[name] in {"confirmed", "refuted"} and not (
            EVIDENCE_KINDS_BY_LINK[name] & step_kinds
        ):
            raise ValueError(f"{label}.link_states.{name} requires a matching evidence step")
    ranks = candidate["supporting_finding_global_ranks"]
    if (
        not isinstance(ranks, list)
        or len(ranks) != len(set(ranks))
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in ranks)
    ):
        raise ValueError(f"{label}.supporting_finding_global_ranks is invalid")
    if rank is not None and rank in ranks:
        raise ValueError(f"{label}: primary/anchor rank must not be duplicated as supporting")
    allowed_ranks = set(ranks)
    if rank is not None:
        allowed_ranks.add(rank)
    for step in steps:
        if not set(step["finding_global_ranks"]).issubset(allowed_ranks):
            raise ValueError(f"{label}: trace step references an unselected finding rank")

    context = _require_exact_keys(candidate["context"], {"kind", "delimiter"}, f"{label}.context")
    if context["kind"] not in CONTEXT_KINDS or context["delimiter"] not in DELIMITERS:
        raise ValueError(f"{label}.context contains an invalid enum")
    if links["context_escape"] != "unknown" and context["kind"] in {"unknown", "not_applicable"}:
        raise ValueError(f"{label}: resolved context_escape requires a concrete context")

    exposure = _require_exact_keys(
        candidate["exposure"],
        {"entrypoint_kind", "attacker_privilege", "victim_privilege", "configuration_requirement"},
        f"{label}.exposure",
    )
    if exposure["entrypoint_kind"] not in ENTRYPOINT_KINDS:
        raise ValueError(f"{label}.exposure.entrypoint_kind is invalid")
    if exposure["attacker_privilege"] not in PRIVILEGES or exposure["victim_privilege"] not in PRIVILEGES:
        raise ValueError(f"{label}.exposure privilege is invalid")
    if exposure["configuration_requirement"] not in {"none", "default", "non_default", "unknown"}:
        raise ValueError(f"{label}.exposure.configuration_requirement is invalid")

    preconditions = candidate["open_preconditions"]
    if not isinstance(preconditions, list):
        raise ValueError(f"{label}.open_preconditions must be an array")
    for index, condition in enumerate(preconditions, 1):
        condition = _require_exact_keys(
            condition, {"kind", "evidence_step_ids"}, f"{label}.open_preconditions[{index}]"
        )
        if condition["kind"] not in PRECONDITION_KINDS:
            raise ValueError(f"{label}.open_preconditions[{index}].kind is invalid")
        refs = condition["evidence_step_ids"]
        if not isinstance(refs, list) or len(refs) != len(set(refs)) or any(ref not in prior_ids for ref in refs):
            raise ValueError(f"{label}.open_preconditions[{index}] has invalid step references")

    derived = derive_verdict(candidate)
    if candidate["verdict"] != derived:
        raise ValueError(f"{label}.verdict must equal derived verdict {derived}")
    refutation = candidate["refutation"]
    if derived == "likely_false_positive":
        refutation = _require_exact_keys(
            refutation, {"reason", "blocked_link", "evidence_step_ids"}, f"{label}.refutation"
        )
        if refutation["reason"] not in REFUTATION_REASONS:
            raise ValueError(f"{label}.refutation.reason is invalid")
        blocked = refutation["blocked_link"]
        if blocked not in REFUTATION_LINK_BY_REASON[refutation["reason"]]:
            raise ValueError(f"{label}.refutation reason does not match blocked_link")
        expected_state = "confirmed" if blocked == "context_escape" else "refuted"
        if links[blocked] != expected_state:
            raise ValueError(f"{label}.refutation does not match link state")
        refs = refutation["evidence_step_ids"]
        if not isinstance(refs, list) or not refs or len(refs) != len(set(refs)) or any(ref not in prior_ids for ref in refs):
            raise ValueError(f"{label}.refutation requires concrete evidence steps")
    elif refutation is not None:
        raise ValueError(f"{label}.refutation must be null outside likely_false_positive")

    gap = candidate["evidence_gap"]
    if derived == "insufficient_evidence":
        gap = _require_exact_keys(gap, {"missing_link", "searched_files"}, f"{label}.evidence_gap")
        unknown_allowed = {name for name in required if links[name] == "unknown"}
        if links["context_escape"] == "unknown":
            unknown_allowed.add("context_escape")
        if gap["missing_link"] not in unknown_allowed:
            raise ValueError(f"{label}.evidence_gap must name an unknown required link")
        searched = gap["searched_files"]
        if (
            not isinstance(searched, list)
            or not searched
            or len(searched) != len(set(searched))
            or any(not isinstance(path, str) or not path for path in searched)
        ):
            raise ValueError(f"{label}.evidence_gap.searched_files is invalid")
    elif gap is not None:
        raise ValueError(f"{label}.evidence_gap must be null outside insufficient_evidence")

    if derived == "possible_vulnerability" and not preconditions:
        raise ValueError(f"{label}: possible_vulnerability requires an open precondition")
    if derived == "likely_vulnerable" and preconditions:
        raise ValueError(f"{label}: likely_vulnerable cannot have open preconditions")
    if derived in {"likely_vulnerable", "possible_vulnerability"}:
        if links["context_escape"] != "refuted":
            raise ValueError(f"{label}: positive verdict requires absent context-correct escape")
        if not _has_connected_complete_trace(candidate):
            raise ValueError(f"{label}: positive verdict requires a connected complete trace")
    return candidate


def validate_review_shape(review: Any, eval_id: str) -> dict[str, Any]:
    keys = {
        "schema_version", "eval_id", "source_inventory_sha256", "primary_candidate",
        "independent_paths", "reviewed_files", "review_passes",
    }
    review = _require_exact_keys(review, keys, f"{eval_id} v4 review")
    if review["schema_version"] != "blind-review-v4" or review["eval_id"] != eval_id:
        raise ValueError(f"{eval_id}: invalid v4 review identity")
    if not isinstance(review["source_inventory_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", review["source_inventory_sha256"]
    ):
        raise ValueError(f"{eval_id}: invalid source_inventory_sha256")
    validate_candidate(review["primary_candidate"], label=f"{eval_id}.primary_candidate", primary=True)
    independent = review["independent_paths"]
    if not isinstance(independent, list):
        raise ValueError(f"{eval_id}.independent_paths must be an array")
    ids: set[str] = set()
    for index, candidate in enumerate(independent, 1):
        validate_candidate(candidate, label=f"{eval_id}.independent_paths[{index}]", primary=False)
        candidate_id = candidate["candidate_id"]
        if candidate_id in ids:
            raise ValueError(f"{eval_id}: duplicate independent candidate_id")
        ids.add(candidate_id)
    reviewed = review["reviewed_files"]
    if (
        not isinstance(reviewed, list)
        or not reviewed
        or len(reviewed) != len(set(reviewed))
        or any(not isinstance(path, str) or not path for path in reviewed)
    ):
        raise ValueError(f"{eval_id}.reviewed_files must be a unique nonempty array")
    passes = _require_exact_keys(
        review["review_passes"], {"scanner_guided", "entrypoint_led", "sink_storage_led"},
        f"{eval_id}.review_passes",
    )
    for name, paths in passes.items():
        if (
            not isinstance(paths, list)
            or not paths
            or len(paths) != len(set(paths))
            or any(not isinstance(path, str) or not path for path in paths)
        ):
            raise ValueError(f"{eval_id}.review_passes.{name} must be a unique nonempty array")
        if not set(paths).issubset(set(reviewed)):
            raise ValueError(f"{eval_id}.review_passes.{name} must be included in reviewed_files")
    return review


def _normalized_code(value: str) -> str:
    return re.sub(r"\s+", "", value)


def _source_path(blind_root: Path, eval_id: str, value: str) -> Path:
    pure = PurePosixPath(value.replace("\\", "/"))
    if pure.is_absolute() or not pure.parts or pure.parts[0] != eval_id:
        raise ValueError(f"{eval_id}: path must stay inside the opaque case: {value}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"{eval_id}: path contains an unsafe segment: {value}")
    path = blind_root / "sources" / Path(*pure.parts)
    if not path.is_file():
        raise ValueError(f"{eval_id}: referenced source file does not exist: {value}")
    return path


def validate_review_against_bundle(
    review: Any, bundle: Any, *, blind_root: Path, eval_id: str
) -> dict[str, Any]:
    """Validate the closed contract against public blind inputs only."""
    review = validate_review_shape(review, eval_id)
    if not isinstance(bundle, dict) or bundle.get("eval_id") != eval_id:
        raise ValueError(f"{eval_id}: invalid v4 bundle identity")
    expected_inventory = bundle.get("source_inventory_sha256")
    if review["source_inventory_sha256"] != expected_inventory:
        raise ValueError(f"{eval_id}: source_inventory_sha256 does not match bundle")

    findings = bundle.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{eval_id}: bundle findings must be an array")
    available: set[int] = set()
    finding_files: dict[int, str] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError(f"{eval_id}: invalid finding object")
        rank = finding.get("global_rank")
        if isinstance(rank, bool) or not isinstance(rank, int) or rank < 1 or rank in available:
            raise ValueError(f"{eval_id}: invalid or duplicate finding global_rank")
        available.add(rank)
        finding_files[rank] = str(finding.get("file", "")).replace("\\", "/")

    primary = review["primary_candidate"]
    primary_rank = primary["finding_global_rank"]
    expected_primary_rank = min(available) if available else None
    if bundle.get("primary_finding_global_rank") != expected_primary_rank:
        raise ValueError(f"{eval_id}: bundle primary_finding_global_rank is inconsistent")
    if available:
        if primary_rank != expected_primary_rank:
            raise ValueError(f"{eval_id}: primary finding rank must be bundle minimum")
        if primary["path_kind"] == "unresolved":
            raise ValueError(f"{eval_id}: primary path_kind cannot be unresolved when findings exist")
    else:
        if primary_rank is not None:
            raise ValueError(f"{eval_id}: primary finding rank must be null without findings")
        if primary["path_kind"] != "unresolved":
            raise ValueError(f"{eval_id}: no-finding primary path_kind must be unresolved")

    primary_selected = set(primary["supporting_finding_global_ranks"])
    if primary_rank is not None:
        primary_selected.add(primary_rank)
        primary_file = finding_files[primary_rank]
        if primary_file not in review["review_passes"]["scanner_guided"]:
            raise ValueError(f"{eval_id}: scanner_guided pass must include primary finding file")
    if not primary_selected.issubset(available):
        raise ValueError(f"{eval_id}: primary selected finding rank not in bundle")
    for candidate in review["independent_paths"]:
        selected = set(candidate["supporting_finding_global_ranks"])
        if candidate["finding_global_rank"] is not None:
            selected.add(candidate["finding_global_rank"])
        if not selected.issubset(available):
            raise ValueError(f"{eval_id}: independent path finding rank not in bundle")
        if selected.intersection(primary_selected):
            raise ValueError(f"{eval_id}: independent path must not reuse primary finding ranks")

    inventory = bundle.get("source_files")
    if not isinstance(inventory, list):
        raise ValueError(f"{eval_id}: bundle source_files must be an array")
    inventory_paths = {
        str(item.get("path", "")).replace("\\", "/")
        for item in inventory if isinstance(item, dict)
    }
    reviewed = set(review["reviewed_files"])
    required = set(bundle.get("required_review_files", []))
    if not required.issubset(reviewed):
        raise ValueError(f"{eval_id}: reviewed_files omit required primary finding files")

    referenced = set(reviewed)
    for paths in review["review_passes"].values():
        referenced.update(paths)
    for candidate in [primary, *review["independent_paths"]]:
        if candidate["evidence_gap"] is not None:
            referenced.update(candidate["evidence_gap"]["searched_files"])
        step_paths = {step["path"] for step in candidate["trace_steps"]}
        if not step_paths.issubset(reviewed):
            raise ValueError(f"{eval_id}: every trace step file must be in reviewed_files")
        entrypoint_paths = {
            step["path"] for step in candidate["trace_steps"]
            if step["kind"] in {"entrypoint", "call", "callback"}
        }
        if not entrypoint_paths.issubset(set(review["review_passes"]["entrypoint_led"])):
            raise ValueError(f"{eval_id}: entrypoint/call steps must be covered by entrypoint_led")
        sink_paths = {
            step["path"] for step in candidate["trace_steps"]
            if step["kind"] in {"write", "storage_read", "sink", "render", "defense", "refutation"}
        }
        if not sink_paths.issubset(set(review["review_passes"]["sink_storage_led"])):
            raise ValueError(f"{eval_id}: sink/storage/refutation steps must be covered by sink_storage_led")
        for step in candidate["trace_steps"]:
            path = _source_path(blind_root, eval_id, step["path"])
            lines = path.read_text(encoding="utf-8", errors="surrogateescape").splitlines()
            start, end = step["line_start"], step["line_end"]
            if end > len(lines):
                raise ValueError(f"{eval_id}: cited line range exceeds file length")
            excerpt = _normalized_code("\n".join(lines[start - 1:end]))
            if _normalized_code(step["expression"]) not in excerpt:
                raise ValueError(f"{eval_id}: expression is not present in cited line range")
    if not referenced.issubset(inventory_paths):
        raise ValueError(f"{eval_id}: review references a file outside bundle inventory")
    for value in referenced:
        _source_path(blind_root, eval_id, value)
    return review


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate one blind-review v4 JSON file")
    parser.add_argument("review", type=Path)
    parser.add_argument("--eval-id", required=True)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()
    with args.review.open("r", encoding="utf-8") as handle:
        review = json.load(handle)
    if args.bundle is None:
        validate_review_shape(review, args.eval_id)
    else:
        with args.bundle.open("r", encoding="utf-8") as handle:
            bundle = json.load(handle)
        validate_review_against_bundle(
            review, bundle, blind_root=args.bundle.resolve().parent.parent,
            eval_id=args.eval_id,
        )
    print(f"PASS review_v4={args.eval_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
