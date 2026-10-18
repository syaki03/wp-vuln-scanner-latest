"""Compare two locked blind-review runs without reading private ground truth.

For each classification, Cohen's kappa is calculated as
``(P_o - P_e) / (1 - P_e)``.  ``P_o`` is the observed exact agreement and
``P_e`` is the sum, over labels, of the product of the two marginal label
proportions.  A null kappa denotes the mathematically undefined ``P_e == 1``
case.  Positive binary labels are likely_vulnerable and possible_vulnerability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


VERDICTS = (
    "likely_vulnerable",
    "possible_vulnerability",
    "likely_false_positive",
    "insufficient_evidence",
)
POSITIVE_VERDICTS = frozenset(("likely_vulnerable", "possible_vulnerability"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid UTF-8 JSON: {path}") from exc


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _resolve_pilot_root(value: Path) -> Path:
    root = value.resolve()
    if (root / "blind").is_dir() and (root / "private").is_dir():
        return root
    if root.name == "blind" and (root.parent / "private").is_dir():
        return root.parent
    raise ValueError(f"expected a pilot root or its blind directory: {root}")


def _mode(root: Path) -> tuple[str, Path, Path, str]:
    blind = root / "blind"
    private = root / "private"
    v5 = private / "review_lock_v5.json"
    v4 = private / "review_lock_v4.json"
    v3 = private / "review_lock_v3.json"
    v2 = private / "review_lock_v2.json"
    v1 = private / "review_lock.json"
    if v5.is_file():
        return "v5", v5, blind / "reviews_v5", "review_bundles_v5"
    if v4.is_file():
        return "v4", v4, blind / "reviews_v4", "review_bundles_v4"
    if v3.is_file():
        return "v3", v3, blind / "reviews_v3", "review_bundles_v3"
    if v2.is_file():
        return "v2", v2, blind / "reviews_v2", "review_bundles_v2"
    if v1.is_file():
        return "v1", v1, blind / "reviews", "review_bundles"
    raise ValueError(f"unlocked reviews: no review lock under {private}")


def _case_ids(index: dict[str, Any], path: Path) -> list[str]:
    cases = index.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"invalid pilot index cases: {path}")
    ids = [item.get("eval_id") if isinstance(item, dict) else None for item in cases]
    if any(not isinstance(case_id, str) or not case_id for case_id in ids):
        raise ValueError(f"invalid pilot index case ID: {path}")
    if len(set(ids)) != len(ids):
        raise ValueError(f"duplicate pilot index case ID: {path}")
    return sorted(ids)


def _available_ranks(findings: Any, path: Path) -> dict[str, set[int]]:
    if not isinstance(findings, list):
        raise ValueError(f"invalid findings array for v3 reviews: {path}")
    available: dict[str, set[int]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError(f"invalid finding for v3 reviews: {path}")
        eval_id = finding.get("plugin")
        rank = finding.get("global_rank")
        if not isinstance(eval_id, str) or not eval_id or isinstance(rank, bool):
            raise ValueError(f"invalid finding rank for v3 reviews: {path}")
        try:
            normalized_rank = int(rank)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid finding rank for v3 reviews: {path}") from exc
        available.setdefault(eval_id, set()).add(normalized_rank)
    return available


def _v3_selected_ranks(review: dict[str, Any], review_path: Path, available: set[int]) -> set[int]:
    primary = review.get("primary_selected_finding_global_rank")
    if available:
        if isinstance(primary, bool) or not isinstance(primary, int) or primary != min(available):
            raise ValueError(f"invalid locked primary selected rank: {review_path}")
    elif primary is not None:
        raise ValueError(f"invalid locked primary selected rank: {review_path}")

    secondary = review.get("secondary_selected_finding_global_ranks")
    if not isinstance(secondary, list):
        raise ValueError(f"invalid locked secondary selected rank set: {review_path}")
    if any(isinstance(rank, bool) or not isinstance(rank, int) for rank in secondary):
        raise ValueError(f"invalid locked secondary selected rank: {review_path}")
    selected = set(secondary)
    if primary is not None:
        selected.add(primary)
    if not selected.issubset(available):
        raise ValueError(f"invalid locked selected rank not in findings: {review_path}")
    return selected


def _v4_candidate_ranks(
    candidate: Any, review_path: Path, available: set[int], *, primary: bool
) -> set[int]:
    if not isinstance(candidate, dict):
        raise ValueError(f"invalid locked v4 candidate: {review_path}")
    rank = candidate.get("finding_global_rank")
    if primary:
        if available:
            if isinstance(rank, bool) or not isinstance(rank, int) or rank != min(available):
                raise ValueError(f"invalid locked primary selected rank: {review_path}")
        elif rank is not None:
            raise ValueError(f"invalid locked primary selected rank: {review_path}")
    elif rank is not None and (isinstance(rank, bool) or not isinstance(rank, int)):
        raise ValueError(f"invalid locked independent selected rank: {review_path}")

    supporting = candidate.get("supporting_finding_global_ranks")
    if not isinstance(supporting, list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in supporting
    ):
        raise ValueError(f"invalid locked supporting selected rank set: {review_path}")
    if len(supporting) != len(set(supporting)) or rank in supporting:
        raise ValueError(f"invalid locked duplicate selected rank: {review_path}")
    selected = set(supporting)
    if rank is not None:
        selected.add(rank)
    if not selected.issubset(available):
        raise ValueError(f"invalid locked selected rank not in findings: {review_path}")
    return selected


def _v4_review_fields(
    review: dict[str, Any], review_path: Path, available: set[int], *, mode: str = "v4"
) -> tuple[str, set[int], dict[str, set[int]]]:
    if mode not in {"v4", "v5"} or review.get("schema_version") != f"blind-review-{mode}":
        raise ValueError(f"invalid locked {mode} review schema: {review_path}")
    primary = review.get("primary_candidate")
    if (
        not isinstance(primary, dict)
        or primary.get("candidate_id") != "primary"
        or primary.get("verdict") not in VERDICTS
    ):
        raise ValueError(f"invalid locked primary verdict: {review_path}")
    primary_ranks = _v4_candidate_ranks(primary, review_path, available, primary=True)

    independent = review.get("independent_paths")
    if not isinstance(independent, list):
        raise ValueError(f"invalid locked independent path set: {review_path}")
    independent_rank_sets: dict[str, set[int]] = {}
    for candidate in independent:
        if not isinstance(candidate, dict):
            raise ValueError(f"invalid locked v4 candidate: {review_path}")
        candidate_id = candidate.get("candidate_id")
        if (
            not isinstance(candidate_id, str)
            or not re.fullmatch(r"independent-[0-9]{2,}", candidate_id)
            or candidate_id in independent_rank_sets
        ):
            raise ValueError(f"invalid locked independent candidate ID: {review_path}")
        independent_rank_sets[candidate_id] = _v4_candidate_ranks(
            candidate, review_path, available, primary=False
        )
        if independent_rank_sets[candidate_id].intersection(primary_ranks):
            raise ValueError(f"invalid locked independent path reuses primary ranks: {review_path}")
    return primary["verdict"], primary_ranks, dict(sorted(independent_rank_sets.items()))


def _load_locked_root(root_value: Path) -> dict[str, Any]:
    root = _resolve_pilot_root(root_value)
    mode, lock_path, reviews_dir, bundle_dir_name = _mode(root)
    blind = root / "blind"
    index_path = blind / "pilot_index.json"
    findings_path = blind / "scan" / "findings.json"
    bundle_lock_path = blind / bundle_dir_name / "lock.json"
    for path in (index_path, findings_path, bundle_lock_path, lock_path):
        if not path.is_file():
            raise ValueError(f"required locked-review artifact is missing: {path}")

    index = _read_json(index_path)
    findings = _read_json(findings_path)
    lock = _read_json(lock_path)
    bundle_lock = _read_json(bundle_lock_path)
    if not isinstance(index, dict) or not isinstance(lock, dict) or not isinstance(bundle_lock, dict):
        raise ValueError(f"locked-review metadata must be JSON objects: {root}")
    expected_schema = f"blind-review-lock-{mode}"
    if lock.get("schema_version") != expected_schema:
        raise ValueError(f"unsupported review lock schema: {lock_path}")
    if bundle_lock.get("schema_version") != f"blind-review-bundle-lock-{mode}":
        raise ValueError(f"unsupported bundle lock schema: {bundle_lock_path}")
    findings_hash = _sha256(findings_path)
    bundle_hash = _sha256(bundle_lock_path)
    if lock.get("findings_sha256") != findings_hash:
        raise ValueError(f"unlocked reviews: findings hash does not match lock: {root}")
    if lock.get("bundle_lock_sha256") != bundle_hash:
        raise ValueError(f"unlocked reviews: bundle hash does not match lock: {root}")
    if bundle_lock.get("findings_sha256") != findings_hash:
        raise ValueError(f"bundle findings hash does not match findings: {root}")
    available_ranks = (
        _available_ranks(findings, findings_path)
        if mode in {"v3", "v4", "v5"}
        else {}
    )

    ids = _case_ids(index, index_path)
    locked_reviews = lock.get("reviews")
    if not isinstance(locked_reviews, dict) or set(locked_reviews) != set(ids):
        raise ValueError(f"unlocked reviews: lock review IDs do not match pilot index: {root}")
    if lock.get("review_count") != len(ids):
        raise ValueError(f"unlocked reviews: review count does not match pilot index: {root}")
    reviews: dict[str, dict[str, Any]] = {}
    actual_ids = {path.stem for path in reviews_dir.glob("*.json")} if reviews_dir.is_dir() else set()
    if actual_ids != set(ids):
        raise ValueError(f"unlocked reviews: review files do not match pilot index: {root}")
    for case_id in ids:
        review_path = reviews_dir / f"{case_id}.json"
        expected_hash = locked_reviews[case_id]
        if not isinstance(expected_hash, str) or _sha256(review_path) != expected_hash:
            raise ValueError(f"unlocked reviews: review hash does not match lock: {review_path}")
        review = _read_json(review_path)
        if not isinstance(review, dict) or review.get("eval_id") != case_id:
            raise ValueError(f"invalid locked review identity: {review_path}")
        if mode == "v3":
            if review.get("verdict") not in VERDICTS:
                raise ValueError(f"invalid locked review verdict: {review_path}")
            normalized = _v3_selected_ranks(review, review_path, available_ranks.get(case_id, set()))
            verdict = review["verdict"]
            independent_rank_sets: dict[str, set[int]] = {}
        elif mode in {"v4", "v5"}:
            verdict, normalized, independent_rank_sets = _v4_review_fields(
                review, review_path, available_ranks.get(case_id, set()), mode=mode
            )
        else:
            if review.get("verdict") not in VERDICTS:
                raise ValueError(f"invalid locked review verdict: {review_path}")
            ranks = review.get("selected_finding_global_ranks")
            if not isinstance(ranks, list):
                raise ValueError(f"invalid locked selected rank set: {review_path}")
            normalized: set[int] = set()
            for rank in ranks:
                if isinstance(rank, bool):
                    raise ValueError(f"invalid locked selected rank: {review_path}")
                try:
                    normalized.add(int(rank))
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"invalid locked selected rank: {review_path}") from exc
            verdict = review["verdict"]
            independent_rank_sets = {}
        reviews[case_id] = {
            "verdict": verdict,
            "ranks": normalized,
            "independent_rank_sets": independent_rank_sets,
        }
    return {
        "root": str(root), "mode": mode, "pilot_index_sha256": _sha256(index_path),
        "findings_sha256": findings_hash, "bundle_lock_sha256": bundle_hash,
        "case_ids": ids, "reviews": reviews,
    }


def _kappa(left: list[str], right: list[str], labels: tuple[str, ...]) -> dict[str, Any]:
    total = len(left)
    matches = sum(a == b for a, b in zip(left, right))
    left_counts = Counter(left)
    right_counts = Counter(right)
    observed = matches / total
    expected = sum(left_counts[label] * right_counts[label] for label in labels) / (total * total)
    return {
        "matching_cases": matches, "total_cases": total, "observed_agreement": observed,
        "expected_agreement": expected,
        "cohen_kappa": None if expected == 1.0 else (observed - expected) / (1.0 - expected),
    }


def compare(left_root: Path, right_root: Path) -> dict[str, Any]:
    left = _load_locked_root(left_root)
    right = _load_locked_root(right_root)
    if left["mode"] != right["mode"]:
        raise ValueError("review lock schema mismatch")
    for key in ("pilot_index_sha256", "findings_sha256", "bundle_lock_sha256"):
        if left[key] != right[key]:
            raise ValueError(f"locked review roots differ in {key}")
    if left["case_ids"] != right["case_ids"]:
        raise ValueError("locked review roots differ in pilot case IDs")

    case_ids = left["case_ids"]
    left_verdicts = [left["reviews"][case_id]["verdict"] for case_id in case_ids]
    right_verdicts = [right["reviews"][case_id]["verdict"] for case_id in case_ids]
    binary_left = ["positive" if verdict in POSITIVE_VERDICTS else "negative" for verdict in left_verdicts]
    binary_right = ["positive" if verdict in POSITIVE_VERDICTS else "negative" for verdict in right_verdicts]
    transitions = {source: {target: 0 for target in VERDICTS} for source in VERDICTS}
    for source, target in zip(left_verdicts, right_verdicts):
        transitions[source][target] += 1
    disagreements = [case_id for case_id, a, b in zip(case_ids, left_verdicts, right_verdicts) if a != b]
    rank_disagreements = [
        case_id for case_id in case_ids
        if left["reviews"][case_id]["ranks"] != right["reviews"][case_id]["ranks"]
    ]
    result = {
        "schema_version": "blind-review-repeatability-comparison-v1",
        "review_schema": left["mode"],
        "case_ids": case_ids,
        "locked_inputs": {
            "pilot_index_sha256": left["pilot_index_sha256"], "findings_sha256": left["findings_sha256"],
            "bundle_lock_sha256": left["bundle_lock_sha256"],
        },
        "verdicts": {
            "labels": list(VERDICTS),
            "left_counts": {label: left_verdicts.count(label) for label in VERDICTS},
            "right_counts": {label: right_verdicts.count(label) for label in VERDICTS},
            "transitions": transitions, "disagreement_ids": disagreements,
            "exact": _kappa(left_verdicts, right_verdicts, VERDICTS),
        },
        "binary_positive": {
            "positive_verdicts": sorted(POSITIVE_VERDICTS),
            "left_counts": {label: binary_left.count(label) for label in ("positive", "negative")},
            "right_counts": {label: binary_right.count(label) for label in ("positive", "negative")},
            "agreement": _kappa(binary_left, binary_right, ("positive", "negative")),
        },
        "selected_rank_sets": {
            "matching_cases": len(case_ids) - len(rank_disagreements), "total_cases": len(case_ids),
            "exact_agreement": (len(case_ids) - len(rank_disagreements)) / len(case_ids),
            "disagreement_ids": rank_disagreements,
        },
    }
    if left["mode"] in {"v4", "v5"}:
        independent_disagreements = [
            case_id
            for case_id in case_ids
            if left["reviews"][case_id]["independent_rank_sets"]
            != right["reviews"][case_id]["independent_rank_sets"]
        ]
        result["independent_path_rank_sets"] = {
            "matching_cases": len(case_ids) - len(independent_disagreements),
            "total_cases": len(case_ids),
            "exact_agreement": (len(case_ids) - len(independent_disagreements)) / len(case_ids),
            "disagreement_ids": independent_disagreements,
        }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left_root", type=Path)
    parser.add_argument("right_root", type=Path)
    parser.add_argument("--output", type=Path, help="write canonical UTF-8 JSON instead of stdout")
    args = parser.parse_args(argv)
    try:
        payload = _canonical_json(compare(args.left_root, args.right_root))
        if args.output:
            args.output.write_bytes(payload)
        else:
            sys.stdout.buffer.write(payload)
        return 0
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
