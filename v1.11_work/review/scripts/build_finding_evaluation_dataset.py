from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1
DEFAULT_QUEUE = Path("review/cohorts/active500/active500_public_queue.jsonl")
DEFAULT_REVIEW_ROOT = Path("review")
DEFAULT_OUTPUT = Path("review/evaluation/active500_i53_finding_labels.jsonl")
DEFAULT_SUMMARY = Path("review/evaluation/active500_i53_finding_labels.summary.json")

# These are deliberately overlapping mechanical tags. They help locate review
# clusters; they are not vulnerability labels and must not replace source review.
REASON_TAG_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("terminal_control_only", (r"\b(?:die|exit|wp_die)\s*\(", r"fixed (?:denial )?message", r"no (?:request )?value is output")),
    ("context_correct_escape", (r"\besc_(?:html|attr|url|js|textarea|xml)\s*\(", r"\bwp_kses(?:_post)?\s*\(", r"(?:properly|correctly|is|are) escaped")),
    ("fixed_or_allowlisted_value", (r"\bfixed\b", r"\ballowlist(?:ed)?\b", r"known (?:key|value|option|template)")),
    ("admin_or_privileged_only", (r"\badmin(?:istration)?\b", r"current_user_can\s*\(", r"manage_[a-z_]+", r"edit_[a-z_]+")),
    ("storage_without_proven_render", (r"\b(?:update|add)_(?:option|post_meta|user_meta)\s*\(", r"stored? (?:only|but)", r"no (?:reachable )?(?:render|output|sink)")),
    ("source_sink_disconnect", (r"not (?:passed|used|an argument|the argument)", r"does not reach", r"different (?:value|variable|path)", r"scanner (?:joined|conflated|associated)")),
    ("core_or_framework_mitigation", (r"\bwordpress core\b", r"\bcore (?:applies|escapes|sanitizes|encodes|validates)\b", r"framework (?:applies|escapes|sanitizes|encodes|validates)")),
    ("json_or_non_html_output", (r"\bjson\b", r"wp_send_json", r"wp_json_encode", r"not an html sink")),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json_strict(path: Path) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key in {path}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant in {path}: {value}")

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate,
        parse_constant=reject_constant,
    )


def load_jsonl_strict(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            raise ValueError(f"blank JSONL line in {path}:{line_number}")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"JSONL row must be an object in {path}:{line_number}")
        rows.append(value)
    return rows


def reason_tags(reason: str) -> list[str]:
    # scanner_feedback is report-wide. Applying it to every finding in a report
    # would leak one assessment's rationale into unrelated findings.
    text = reason.lower()
    tags = [
        tag
        for tag, patterns in REASON_TAG_PATTERNS
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)
    ]
    return tags or ["other"]


def _finding_projection(finding: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "type", "severity", "score", "confidence", "poc_priority",
        "file_within_plugin", "line", "source_kind", "source_match",
        "source_origin", "sink_kind", "sink_match", "storage_kind",
        "storage_match", "entrypoint_kind", "entrypoint_name",
        "entrypoint_exposure", "entrypoint_role", "admin_only_hint",
        "flow_evidence", "sanitizer_matches", "security_checks", "snippet",
    )
    return {key: finding.get(key) for key in fields}


def build_records(queue_path: Path, review_root: Path) -> list[dict[str, Any]]:
    queue_rows = load_jsonl_strict(queue_path)
    queue_sha256 = sha256_file(queue_path)
    records: list[dict[str, Any]] = []
    seen_plugins: set[str] = set()

    for queue_row in queue_rows:
        plugin = str(queue_row.get("plugin", ""))
        if not plugin or plugin in seen_plugins:
            raise ValueError(f"missing or duplicate queue plugin: {plugin!r}")
        seen_plugins.add(plugin)

        findings = queue_row.get("findings")
        if not isinstance(findings, list) or not findings:
            raise ValueError(f"{plugin}: queue findings must be a non-empty list")
        finding_by_id: dict[str, dict[str, Any]] = {}
        finding_occurrences: Counter[str] = Counter()
        for finding in findings:
            finding_id = str(finding.get("finding_id", ""))
            if not re.fullmatch(r"[0-9a-f]{20}", finding_id):
                raise ValueError(f"{plugin}: invalid finding_id {finding_id!r}")
            if finding_id in finding_by_id and finding_by_id[finding_id] != finding:
                raise ValueError(f"{plugin}: conflicting queue rows share finding_id {finding_id!r}")
            finding_by_id.setdefault(finding_id, finding)
            finding_occurrences[finding_id] += 1
        if queue_row.get("selected_finding_count") != len(findings):
            raise ValueError(f"{plugin}: selected_finding_count does not match queue finding rows")

        review_info = queue_row.get("review")
        if not isinstance(review_info, dict) or review_info.get("status") != "reviewed":
            raise ValueError(f"{plugin}: queue row is not reviewed")
        report_relative = str(review_info.get("report_path", ""))
        report_path = review_root / Path(report_relative)
        if not report_path.is_file():
            raise ValueError(f"{plugin}: missing review report {report_path}")
        report = load_json_strict(report_path)
        schema_version = report.get("review_schema_version")
        if schema_version not in {1, 2}:
            raise ValueError(f"{plugin}: unsupported review schema {schema_version!r}")
        for field in ("plugin", "plugin_fingerprint", "selected_findings_fingerprint"):
            if report.get(field) != queue_row.get(field):
                raise ValueError(f"{plugin}: report {field} does not match queue")
        report_ids = report.get("finding_ids")
        if not isinstance(report_ids, list) or set(report_ids) != set(finding_by_id) or len(report_ids) != len(finding_by_id):
            raise ValueError(f"{plugin}: report finding_ids do not exactly cover queue findings")

        assessments = report.get("selected_finding_assessment")
        if not isinstance(assessments, list) or not assessments:
            raise ValueError(f"{plugin}: selected_finding_assessment must be non-empty")
        assessment_by_id: dict[str, dict[str, Any]] = {}
        for assessment in assessments:
            ids = assessment.get("finding_ids")
            verdict = assessment.get("verdict")
            reason = assessment.get("reason")
            if not isinstance(ids, list) or not ids or not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"{plugin}: malformed finding assessment")
            if verdict not in {"likely_false_positive", "possible_vulnerability", "likely_vulnerable"}:
                raise ValueError(f"{plugin}: unsupported assessment verdict {verdict!r}")
            for finding_id in ids:
                if finding_id not in finding_by_id or finding_id in assessment_by_id:
                    raise ValueError(f"{plugin}: unknown or duplicate assessed finding {finding_id!r}")
                assessment_by_id[finding_id] = assessment
        if set(assessment_by_id) != set(finding_by_id):
            missing = sorted(set(finding_by_id) - set(assessment_by_id))
            raise ValueError(f"{plugin}: assessments do not cover findings: {missing}")

        report_sha256 = sha256_file(report_path)
        scanner_feedback = report.get("scanner_feedback", [])
        if not isinstance(scanner_feedback, list):
            raise ValueError(f"{plugin}: scanner_feedback must be a list")
        for finding_id, finding in finding_by_id.items():
            assessment = assessment_by_id[finding_id]
            records.append(
                {
                    "dataset_schema_version": SCHEMA_VERSION,
                    "queue_sha256": queue_sha256,
                    "campaign": queue_row.get("campaign"),
                    "queue_rank": queue_row.get("queue_rank"),
                    "plugin": plugin,
                    "plugin_fingerprint": queue_row.get("plugin_fingerprint"),
                    "selected_findings_fingerprint": queue_row.get("selected_findings_fingerprint"),
                    "review_schema_version": schema_version,
                    "review_path": report_relative.replace("\\", "/"),
                    "review_sha256": report_sha256,
                    "reviewed_at": report.get("reviewed_at"),
                    "plugin_verdict": report.get("verdict"),
                    "reviewer_confidence": report.get("reviewer_confidence"),
                    "finding_id": finding_id,
                    "queue_occurrence_count": finding_occurrences[finding_id],
                    "assessment_verdict": assessment.get("verdict"),
                    "assessment_reason": assessment.get("reason"),
                    "assessment_citations": assessment.get("citations", []),
                    "reason_tags": reason_tags(str(assessment.get("reason"))),
                    "finding": _finding_projection(finding),
                }
            )
    return records


def summary_for(records: list[dict[str, Any]], output_path: Path) -> dict[str, Any]:
    verdicts = Counter(record["assessment_verdict"] for record in records)
    plugin_verdicts: dict[str, str] = {}
    schemas = Counter()
    tags = Counter()
    for record in records:
        plugin_verdicts[record["plugin"]] = record["plugin_verdict"]
        schemas[str(record["review_schema_version"])] += 1
        tags.update(record["reason_tags"])
    return {
        "dataset_schema_version": SCHEMA_VERSION,
        "dataset_path": output_path.as_posix(),
        "dataset_sha256": sha256_file(output_path),
        "queue_sha256": records[0]["queue_sha256"] if records else None,
        "plugin_count": len(plugin_verdicts),
        "finding_count": len(records),
        "assessment_verdict_counts": dict(sorted(verdicts.items())),
        "plugin_verdict_counts": dict(sorted(Counter(plugin_verdicts.values()).items())),
        "review_schema_finding_counts": dict(sorted(schemas.items())),
        "reason_tag_counts": dict(sorted(tags.items(), key=lambda item: (-item[1], item[0]))),
        "reason_tag_semantics": "overlapping mechanical search aids; not vulnerability ground truth",
    }


def write_dataset(records: list[dict[str, Any]], output_path: Path, summary_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(summary_for(records, output_path), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def validate_dataset(queue_path: Path, review_root: Path, output_path: Path, summary_path: Path) -> dict[str, Any]:
    expected = build_records(queue_path, review_root)
    actual = load_jsonl_strict(output_path)
    if actual != expected:
        raise ValueError("dataset content does not exactly match queue and review reports")
    expected_summary = summary_for(actual, output_path)
    actual_summary = load_json_strict(summary_path)
    if actual_summary != expected_summary:
        raise ValueError("dataset summary does not match dataset content")
    keys = [(record["plugin"], record["finding_id"]) for record in actual]
    if len(keys) != len(set(keys)):
        raise ValueError("dataset contains duplicate plugin/finding_id keys")
    return expected_summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build or validate the active500 finding-level evaluation dataset.")
    parser.add_argument("command", choices=("build", "validate"))
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--review-root", type=Path, default=DEFAULT_REVIEW_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "build":
        write_dataset(build_records(args.queue, args.review_root), args.output, args.summary)
    result = validate_dataset(args.queue, args.review_root, args.output, args.summary)
    print(json.dumps({"status": "valid", **result}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
