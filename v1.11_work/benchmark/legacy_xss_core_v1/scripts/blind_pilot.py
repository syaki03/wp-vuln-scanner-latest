#!/usr/bin/env python3
"""Prepare, scan, validate, and score the frozen blind benchmark pilot.

Only ``prepare`` and ``score`` read the private benchmark manifest.  ``scan``
operates exclusively on opaque source directories created by ``prepare``.
Reviewers must only receive files below ``pilot/blind``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import stat
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
BENCHMARK_ROOT = SCRIPT_DIR.parent
V111_ROOT = BENCHMARK_ROOT.parent.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from blind_review_v4 import (  # noqa: E402
    derive_verdict as derive_v4_verdict,
    review_schema_v4,
    validate_review_against_bundle as validate_review_v4_against_bundle,
    validate_review_shape as validate_review_v4_shape,
)
from blind_review_v5 import (  # noqa: E402
    finding_identity as finding_identity_v5,
    review_schema_v5,
    validate_review_against_bundle as validate_review_v5_against_bundle,
    validate_review_shape as validate_review_v5_shape,
)

DEFAULT_PILOT_ROOT = BENCHMARK_ROOT / "pilot"
TARGET_SUFFIXES = {".php", ".inc", ".module"}
FORBIDDEN_REVIEW_KEYS = {
    "attack_conditions",
    "case_id",
    "cve",
    "fix_diff",
    "ground_truth",
    "primary_advisory_urls",
    "vulnerability_id",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected an object")
        records.append(value)
    return records


def tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
        digest.update(b"\0")
    return digest.hexdigest()


def _safe_zip_members(archive: zipfile.ZipFile) -> list[tuple[zipfile.ZipInfo, PurePosixPath]]:
    eligible: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
    for info in archive.infolist():
        if info.is_dir():
            continue
        pure = PurePosixPath(info.filename.replace("\\", "/"))
        if pure.is_absolute() or not pure.parts or ".." in pure.parts:
            raise ValueError(f"unsafe ZIP member: {info.filename}")
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode and stat.S_ISLNK(mode):
            raise ValueError(f"symlink ZIP member is not allowed: {info.filename}")
        if pure.suffix.lower() in TARGET_SUFFIXES:
            eligible.append((info, pure))
    if not eligible:
        raise ValueError("artifact has no scanner-target PHP files")
    return eligible


def extract_opaque_php_tree(zip_path: Path, destination: Path) -> tuple[int, str | None]:
    with zipfile.ZipFile(zip_path) as archive:
        members = _safe_zip_members(archive)
        first_parts = {pure.parts[0] for _info, pure in members if len(pure.parts) > 1}
        strip_first = len(first_parts) == 1 and all(len(pure.parts) > 1 for _info, pure in members)
        seen: set[str] = set()
        for info, pure in members:
            relative = PurePosixPath(*pure.parts[1:]) if strip_first else pure
            collision_key = relative.as_posix().casefold()
            if collision_key in seen:
                raise ValueError(f"case-insensitive path collision: {relative}")
            seen.add(collision_key)
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
    artifact_root = next(iter(first_parts)) if strip_first else None
    return len(members), artifact_root


def verify_frozen_inputs() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    freeze_path = BENCHMARK_ROOT / "freeze.json"
    manifest_path = BENCHMARK_ROOT / "manifest.jsonl"
    freeze = read_json(freeze_path)
    if sha256_file(manifest_path) != freeze.get("manifest_sha256"):
        raise ValueError("manifest SHA-256 no longer matches freeze.json")
    pool_path = BENCHMARK_ROOT / str(freeze.get("input_pool_path", "verified_pool.jsonl"))
    if sha256_file(pool_path) != freeze.get("input_pool_sha256"):
        raise ValueError("input pool SHA-256 no longer matches freeze.json")
    manifest = read_jsonl(manifest_path)
    selected = list(freeze.get("selected_case_ids", []))
    manifest_ids = [record.get("case_id") for record in manifest]
    if selected != manifest_ids:
        raise ValueError("manifest order differs from frozen selected_case_ids")
    return freeze, manifest


def copy_scanner_reference(destination: Path) -> str:
    files = [V111_ROOT / "config.py", V111_ROOT / "main.py"]
    files.extend(sorted((V111_ROOT / "scanner").glob("*.py")))
    files.extend(sorted((V111_ROOT / "rules").glob("*.py")))
    for source in files:
        relative = source.relative_to(V111_ROOT)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return tree_fingerprint(destination)


def reviewer_agents_text() -> str:
    return """# Blind evaluation boundary

This directory is a sequestered source-review evaluation. The closest instructions
in this file override ancestor project routing for this evaluation task.

- Work only below this `blind` directory. Do not inspect parent or sibling paths.
- Do not access the internet, advisories, CVE databases, Git history, or other tasks.
- Treat every case as unknown; it may be vulnerable, safe, or inconclusive.
- Use only the opaque source tree, scanner findings, and scanner reference supplied here.
- Never try to infer or search for the original case identifier.
- Write only the requested review JSON below `reviews/`.
"""


def review_instructions_text() -> str:
    return """# Blind pilot review instructions

Review one opaque plugin as a complete source unit. Read all of its scanner findings,
the scanner implementation that generated them, and enough plugin code to verify the
real call path. Also search independently from entrypoints and sinks/storage so that a
scanner miss can still be identified.

Do not use the internet or any path outside this `blind` directory. You are not given
an advisory, expected path, attack conditions, fix diff, or vulnerability label.

Write `reviews/<eval_id>.json` with these fields:

```json
{
  "schema_version": "blind-review-v1",
  "eval_id": "eval-0001",
  "verdict": "likely_vulnerable | possible_vulnerability | likely_false_positive | insufficient_evidence",
  "reviewer_confidence": "high | medium | low",
  "selected_finding_global_ranks": [1],
  "source": {"path": "eval-0001/file.php", "line": 1, "function": "", "expression": ""},
  "sinks": [{"path": "eval-0001/file.php", "line": 2, "function": "", "context": "", "expression": ""}],
  "trace": "source through transformations/storage to final sink",
  "exposure": {"minimum_attacker_role": "", "victim_interaction": "", "reachability": ""},
  "defenses": [""],
  "scanner_assessment": "correct_detection | related_candidate_only | missed_path | likely_false_positive",
  "scanner_reason": "",
  "unresolved": [""],
  "reviewed_files": ["eval-0001/file.php"]
}
```

Use an empty source object or sink list only when evidence is genuinely insufficient.
Do not call a case confirmed; this is source-only review, not runtime PoC.
"""


def review_instructions_v2_text() -> str:
    return """# Blind pilot review instructions v2

Review one opaque plugin as a complete source unit. Use only this `blind` subtree.
Do not use the internet, parent paths, advisories, CVE data, Git history, fix diffs,
or any presumed answer. Treat every case as unknown.

Read the complete PHP source, all scanner findings, and the scanner reference. Perform
scanner-guided, entrypoint-led, and sink/storage-led passes. Record every location that
materially supports your chosen trace. A line range must tightly cover the exact PHP
statement or template expression; do not cite only a function declaration when the
relevant source or sink occurs later. Copy a short exact expression from the code.

Write `reviews_v2/<eval_id>.json`:

```json
{
  "schema_version": "blind-review-v2",
  "eval_id": "eval-0001",
  "verdict": "likely_vulnerable | possible_vulnerability | likely_false_positive | insufficient_evidence",
  "reviewer_confidence": "high | medium | low",
  "selected_finding_global_ranks": [1],
  "source_locations": [
    {"path": "eval-0001/file.php", "line_start": 10, "line_end": 10, "function": "name", "kind": "request | shortcode | storage_write | storage_read | other", "expression": "exact code"}
  ],
  "sink_locations": [
    {"path": "eval-0001/file.php", "line_start": 20, "line_end": 20, "function": "name", "context": "html_text | textarea | html_attribute | url_attribute | javascript | shortcode_return | other", "expression": "exact code"}
  ],
  "trace": "source through transformations/storage to final sink",
  "exposure": {"minimum_attacker_role": "", "victim_interaction": "", "reachability": ""},
  "defenses": [""],
  "scanner_assessment": "correct_detection | related_candidate_only | missed_path | likely_false_positive",
  "scanner_reason": "",
  "unresolved": [""],
  "reviewed_files": ["eval-0001/file.php"]
}
```

Use arrays because a real path may have duplicate request branches, writes/reads, or
multiple final sinks. Empty arrays are allowed only for genuinely insufficient evidence.
Every `selected_finding_global_ranks` value must be copied from that finding's numeric
`global_rank` field in the matching review bundle. Never copy `plugin_rank`; use an empty
array when you do not select a scanner finding. Before finishing, parse every output with
a strict JSON parser, assert each cited expression occurs in its cited source range after
whitespace normalization, and end the file with an actual newline rather than the two
literal characters `\\n`.
This is source-only review; never claim runtime confirmation.
"""


def review_instructions_v3_text() -> str:
    return """# Blind pilot review instructions v3

Review one opaque plugin using only this `blind` subtree. Do not access the internet,
parent paths, advisories, CVE data, Git history, fix diffs, or any presumed answer.
Every case is unknown. Complete scanner-guided, entrypoint-led, and sink/storage-led
passes over the real source files listed in the review bundle.

Write `reviews_v3/<eval_id>.json`. `primary_selected_finding_global_rank` is mandatory:
when the bundle has findings it must be the smallest numeric `global_rank` for this eval;
it is null only when the bundle has no findings. Cite that primary candidate even for a
likely false positive. `secondary_selected_finding_global_ranks` may add other findings.
`trace_anchor_global_rank` must be the primary or a secondary rank, except it may be null
only for `insufficient_evidence` or an independent `missed_path`.

All source/sink expressions must be exact code within a tight cited line range. For every
non-insufficient verdict, provide nonempty source locations, sink locations, trace, and
context analysis. `reviewed_files` and every pass file must be real files from this eval's
bundle inventory. Copy `source_inventory_sha256` from the pilot index. For an insufficient
verdict, record an `evidence_gap` object with one missing link and the real files searched;
otherwise set `evidence_gap` to null. This is source-only review: never claim runtime
confirmation.

The complete machine-readable contract is `REVIEW_SCHEMA_V3.json`. Its top-level
`required` list is also the exact allowed key set. Do not add prose outside the JSON.
"""


def review_schema_v3() -> dict[str, Any]:
    location = {
        "type": "object",
        "additionalProperties": False,
        "required": ["path", "line_start", "line_end", "expression"],
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "line_start": {"type": "integer", "minimum": 1},
            "line_end": {"type": "integer", "minimum": 1},
            "expression": {"type": "string", "minLength": 1},
        },
    }
    file_list = {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}}
    required = [
        "schema_version", "eval_id", "verdict", "confidence",
        "primary_selected_finding_global_rank", "secondary_selected_finding_global_ranks",
        "trace_anchor_global_rank", "source_inventory_sha256", "source_locations",
        "sink_locations", "trace", "exposure", "defenses", "context_analysis",
        "scanner_assessment", "scanner_reason", "unresolved", "reviewed_files",
        "review_passes", "evidence_gap",
    ]
    return {
        "schema_version": "blind-review-v3-schema-1",
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {
            "schema_version": {"const": "blind-review-v3"},
            "eval_id": {"type": "string", "pattern": "^eval-[0-9]{4}$"},
            "verdict": {"enum": [
                "likely_vulnerable", "possible_vulnerability",
                "likely_false_positive", "insufficient_evidence",
            ]},
            "confidence": {"enum": ["high", "medium", "low"]},
            "primary_selected_finding_global_rank": {"type": ["integer", "null"]},
            "secondary_selected_finding_global_ranks": {
                "type": "array", "uniqueItems": True, "items": {"type": "integer"},
            },
            "trace_anchor_global_rank": {"type": ["integer", "null"]},
            "source_inventory_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "source_locations": {"type": "array", "items": location},
            "sink_locations": {"type": "array", "items": location},
            "trace": {"type": "string"},
            "exposure": {"type": "object"},
            "defenses": {"type": "array", "items": {"type": "string"}},
            "context_analysis": {"type": "string"},
            "scanner_assessment": {"enum": [
                "correct_detection", "related_candidate_only", "missed_path",
                "likely_false_positive",
            ]},
            "scanner_reason": {"type": "string"},
            "unresolved": {"type": "array", "items": {"type": "string"}},
            "reviewed_files": file_list,
            "review_passes": {
                "type": "object", "additionalProperties": False,
                "required": ["scanner_guided", "entrypoint_led", "sink_storage_led"],
                "properties": {
                    "scanner_guided": file_list,
                    "entrypoint_led": file_list,
                    "sink_storage_led": file_list,
                },
            },
            "evidence_gap": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "object", "additionalProperties": False,
                        "required": ["missing_link", "searched_locations"],
                        "properties": {
                            "missing_link": {"enum": [
                                "source", "write", "storage_read", "sink",
                                "reachability", "context_escape",
                            ]},
                            "searched_locations": file_list,
                        },
                    },
                ]
            },
        },
    }


def review_instructions_v4_text() -> str:
    return """# Blind pilot review instructions v4

Review one opaque plugin using only this `blind` subtree. Do not access the internet,
parent paths, advisories, CVE data, Git history, fix diffs, or any presumed answer.
Complete scanner-guided, entrypoint-led, and sink/storage-led passes over real source
files from the bundle inventory.

Write `reviews_v4/<eval_id>.json` matching `REVIEW_SCHEMA_V4.json`. The
`primary_candidate.finding_global_rank` is `primary_finding_global_rank` from the
bundle, or null when there are no findings. When a finding exists, `path_kind` cannot
be `unresolved`; classify the scanner-claimed route and mark each link confirmed,
refuted, or unknown. Its verdict concerns only that primary
candidate. Put a distinct plugin-wide route in `independent_paths`; an independent path
must not repair, replace, or overturn the primary candidate's evidence.
Before handoff, run `python REVIEW_VALIDATOR_V4.py --eval-id <eval_id> --bundle
review_bundles_v4/<eval_id>.json reviews_v4/<eval_id>.json` and fix every reported
contract error.

Use ordered `trace_steps`. Every input step must appear earlier. A positive path must
connect a source to a sink and contain the links required by `path_kind`: direct requires
source/sink, stored adds write/storage_read, interprocedural adds call, and
stored_interprocedural adds all three. `reachability` and `context_escape` always apply.
For `context_escape`, confirmed means a context-correct escape is present; refuted means
the exact sink lacks a context-correct escape; unknown means the source alone cannot
decide it.

The validator derives the verdict in this order: a concrete refuted path/reachability
link or confirmed context escape is `likely_false_positive`; an unknown required static
link or unknown context escape is `insufficient_evidence`; a complete unsafe static path
with an open role/setting/deployment/other enumerated precondition is
`possible_vulnerability`; otherwise the complete reachable unsafe path is
`likely_vulnerable`. Runtime not being executed is not a missing link. A false positive
requires one concrete refutation reason and cited evidence steps.

All cited paths must be opaque eval paths, all ranges must be at most 20 lines, and every
expression must occur in its cited range after whitespace normalization. Copy
`source_inventory_sha256` from the same-named field in the case bundle. Do not add prose outside the JSON and do
not claim runtime confirmation.
"""


def reviewer_v4_agents_text() -> str:
    return """# Blind review v4 output boundary

The parent `blind/AGENTS.md` still applies. For this v4 pass, the requested review
directory is this `reviews_v4` directory (not the legacy `reviews` directory).

- Write only one requested `<eval_id>.json` file per assigned case in this directory.
- Follow `../REVIEW_INSTRUCTIONS_V4.md` and `../REVIEW_SCHEMA_V4.json` exactly.
- Validate every completed file with `../REVIEW_VALIDATOR_V4.py`.
- Read inputs only from `../review_bundles_v4`, `../sources`, and
  `../scanner_reference`.
- Do not access the internet, parent paths above `blind`, advisories, CVE data,
  Git history, fix diffs, or private mappings.
"""


def review_instructions_v5_text() -> str:
    return """# Blind pilot review instructions v5

Use only this `blind` subtree. Do not access the internet, parent paths, advisories,
CVE data, Git history, fix diffs, private mappings, or any presumed answer. Complete
scanner-guided, entrypoint-led, and sink/storage-led passes over real source files.

Write `reviews_v5/<eval_id>.json` matching `REVIEW_SCHEMA_V5.json`, then run
`python REVIEW_VALIDATOR_V5.py --eval-id <eval_id> --bundle
review_bundles_v5/<eval_id>.json reviews_v5/<eval_id>.json`.

The primary candidate must copy `primary_finding_identity` exactly. Its trace must
preserve the finding rank, file, line, scanner source identity, and sink or storage-write
anchor. A nearby output or a different source/sink route is an `independent_path`; it
must not replace or overturn the primary candidate.

`open_preconditions` are only for facts unresolved by the supplied source, trace, and
exposure. Do not put a literal capability/role, a source-visible setting, ordinary page
loading/rendering, or an entitled requester's normal route invocation there. Each true
open condition must name its affected unknown link, resolution boundary, unresolved
fact, and concrete trace evidence. Unknown server normalization requires
`context_escape=unknown` and a context-escape evidence gap. Runtime not being executed
is not an evidence gap.

For `field_mismatch`, provide structural non-alias evidence identifying the claimed
source, actual sink value, distinct producer, and supporting trace steps. Otherwise mark
the source link unknown and record an evidence gap. Literal includes and statically
resolved bundled endpoints are source-visible edges; do not call them external merely
because runtime was not executed. Missing extension implementations remain unknown,
not refuted.

All paths stay inside the opaque eval case, ranges are at most 20 lines, expressions
must occur in their cited ranges after whitespace normalization, and output must be
strict UTF-8 JSON with no extra prose or runtime-confirmation claim.
"""


def reviewer_v5_agents_text() -> str:
    return """# Blind review v5 output boundary

The parent `blind/AGENTS.md` still applies. For this v5 pass:

- Write only the assigned `<eval_id>.json` below this `reviews_v5` directory.
- Follow `../REVIEW_INSTRUCTIONS_V5.md` and `../REVIEW_SCHEMA_V5.json` exactly.
- Validate every file with `../REVIEW_VALIDATOR_V5.py`.
- Read only `../review_bundles_v5`, `../sources`, and `../scanner_reference`.
- Do not access the internet, parent paths, advisories, CVE data, Git history,
  fix diffs, or private mappings.
"""


def _source_file_inventory(blind_root: Path, eval_id: str) -> list[dict[str, str]]:
    source_root = blind_root / "sources" / eval_id
    return [
        {
            "path": f"{eval_id}/{path.relative_to(source_root).as_posix()}",
            "sha256": sha256_file(path),
        }
        for path in sorted(item for item in source_root.rglob("*") if item.is_file())
    ]


def command_prepare(args: argparse.Namespace) -> int:
    pilot_root = args.pilot_root.resolve()
    if pilot_root.exists():
        raise FileExistsError(f"pilot root already exists; refusing overwrite: {pilot_root}")
    freeze, manifest = verify_frozen_inputs()
    if args.count < 1 or args.count > len(manifest):
        raise ValueError(f"count must be between 1 and {len(manifest)}")

    blind_root = pilot_root / "blind"
    private_root = pilot_root / "private"
    sources_root = blind_root / "sources"
    mapping: list[dict[str, Any]] = []
    public_cases: list[dict[str, Any]] = []

    for index, record in enumerate(manifest[: args.count], 1):
        eval_id = f"eval-{index:04d}"
        artifact = record["vulnerable_artifact"]
        zip_path = (BENCHMARK_ROOT / artifact["local_path"]).resolve()
        try:
            zip_path.relative_to(BENCHMARK_ROOT.resolve())
        except ValueError as exc:
            raise ValueError(f"artifact outside benchmark root: {zip_path}") from exc
        actual_sha = sha256_file(zip_path)
        if actual_sha != artifact["sha256"]:
            raise ValueError(f"artifact SHA-256 mismatch for manifest index {index}")
        eval_root = sources_root / eval_id
        file_count, artifact_root = extract_opaque_php_tree(zip_path, eval_root)
        source_sha = tree_fingerprint(eval_root)
        mapping.append(
            {
                "eval_id": eval_id,
                "manifest_index": index,
                "case_id": record["case_id"],
                "artifact_sha256": actual_sha,
                "artifact_root": artifact_root,
                "source_tree_sha256": source_sha,
            }
        )
        public_cases.append(
            {
                "eval_id": eval_id,
                "php_file_count": file_count,
                "source_tree_sha256": source_sha,
            }
        )

    scanner_sha = copy_scanner_reference(blind_root / "scanner_reference")
    (blind_root / "AGENTS.md").write_text(reviewer_agents_text(), encoding="utf-8")
    (blind_root / "REVIEW_INSTRUCTIONS.md").write_text(
        review_instructions_text(), encoding="utf-8"
    )
    write_json(
        blind_root / "pilot_index.json",
        {
            "schema_version": "blind-pilot-index-v1",
            "benchmark_alias": "legacy-php-xss-pilot",
            "case_count": args.count,
            "cases": public_cases,
            "scanner_reference_sha256": scanner_sha,
        },
    )
    write_json(
        private_root / "case_map.json",
        {
            "schema_version": "blind-case-map-v1",
            "frozen_manifest_sha256": freeze["manifest_sha256"],
            "frozen_pool_sha256": freeze["input_pool_sha256"],
            "cases": mapping,
        },
    )
    write_json(
        private_root / "prepare_lock.json",
        {
            "case_map_sha256": sha256_file(private_root / "case_map.json"),
            "pilot_index_sha256": sha256_file(blind_root / "pilot_index.json"),
            "scanner_reference_sha256": scanner_sha,
        },
    )
    print(f"PASS prepared={args.count} blind_root={blind_root}")
    return 0


def _scan_error(path: Path, error: Exception) -> dict[str, Any]:
    return {
        "plugin": "",
        "file": str(path),
        "line": 0,
        "type": "SCAN_ERROR",
        "severity": "INFO",
        "score": 0,
        "confidence": "",
        "flow_evidence": "",
        "source_kind": "",
        "source_origin": "",
        "source_match": "",
        "sink_kind": "",
        "sink_match": "",
        "storage_kind": "",
        "storage_match": "",
        "sanitizer_matches": "",
        "security_checks": "",
        "tainted_vars": "",
        "entrypoint_kind": "",
        "entrypoint_name": "",
        "entrypoint_exposure": "",
        "entrypoint_role": "",
        "entrypoint_line": 0,
        "entrypoint_function": "",
        "admin_only_hint": "",
        "poc_priority": "",
        "context": "",
        "snippet": f"Scanner error: {error}",
    }


def command_scan(args: argparse.Namespace) -> int:
    pilot_root = args.pilot_root.resolve()
    blind_root = pilot_root / "blind"
    sources_root = blind_root / "sources"
    output_path = blind_root / "scan" / "findings.json"
    if output_path.exists():
        raise FileExistsError(f"scan output already exists; refusing overwrite: {output_path}")
    if not sources_root.is_dir():
        raise FileNotFoundError("run prepare before scan")

    sys.path.insert(0, str(V111_ROOT))
    import config  # pylint: disable=import-outside-toplevel

    config.PLUGIN_ROOT = sources_root
    from scanner.collector import collect_php_files  # pylint: disable=import-outside-toplevel
    from scanner.entrypoint_detector import (  # pylint: disable=import-outside-toplevel
        build_scanner_indexes,
    )
    from scanner.reporter import sort_findings  # pylint: disable=import-outside-toplevel
    from scanner.taint_engine import (  # pylint: disable=import-outside-toplevel
        analyze_php_file,
        build_tainted_storage_index,
    )
    from scanner.utils import plugin_name_from_path  # pylint: disable=import-outside-toplevel

    files = collect_php_files(sources_root)
    (
        shortcode_callbacks,
        registered_callbacks,
        unique_function_definitions,
    ) = build_scanner_indexes(
        files, sources_root
    )
    tainted_storage = build_tainted_storage_index(
        files, sources_root, shortcode_callbacks
    )
    findings: list[dict[str, Any]] = []
    for path in files:
        try:
            plugin = plugin_name_from_path(path, sources_root)
            findings.extend(
                analyze_php_file(
                    path,
                    shortcode_callbacks.get(plugin, set()),
                    tainted_storage.get(plugin, set()),
                    registered_callbacks.get(plugin, set()),
                    unique_function_definitions.get(plugin, {}),
                )
            )
        except Exception as exc:  # scanner contract records per-file failures
            findings.append(_scan_error(path, exc))

    ranked = sort_findings(findings)
    plugin_ranks: Counter[str] = Counter()
    for global_rank, finding in enumerate(ranked, 1):
        eval_id = str(finding.get("plugin", ""))
        plugin_ranks[eval_id] += 1
        finding["global_rank"] = global_rank
        finding["plugin_rank"] = plugin_ranks[eval_id]
        path = Path(str(finding.get("file", ""))).resolve()
        try:
            finding["file"] = path.relative_to(sources_root.resolve()).as_posix()
        except ValueError:
            finding["file"] = "outside-source-root"

    write_json(output_path, ranked)
    counts = Counter(str(finding.get("severity", "")) for finding in ranked)
    by_plugin = Counter(str(finding.get("plugin", "")) for finding in ranked)
    write_json(
        blind_root / "scan" / "summary.json",
        {
            "schema_version": "blind-scan-summary-v1",
            "php_files": len(files),
            "total_findings": len(ranked),
            "severity_counts": dict(sorted(counts.items())),
            "finding_counts_by_eval_id": dict(sorted(by_plugin.items())),
        },
    )
    write_json(
        blind_root / "scan" / "lock.json",
        {
            "findings_sha256": sha256_file(output_path),
            "summary_sha256": sha256_file(blind_root / "scan" / "summary.json"),
            "pilot_index_sha256": sha256_file(blind_root / "pilot_index.json"),
        },
    )
    print(f"PASS files={len(files)} findings={len(ranked)} output={output_path}")
    return 0


def command_bundle(args: argparse.Namespace) -> int:
    blind_root = args.pilot_root.resolve() / "blind"
    findings_path = blind_root / "scan" / "findings.json"
    findings = read_json(findings_path)
    index = read_json(blind_root / "pilot_index.json")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        grouped[str(finding.get("plugin", ""))].append(finding)
    bundle_root = blind_root / "review_bundles"
    if bundle_root.exists():
        raise FileExistsError(f"bundle directory already exists; refusing overwrite: {bundle_root}")
    bundle_hashes: dict[str, str] = {}
    for case in index["cases"]:
        eval_id = case["eval_id"]
        bundle = {
            "schema_version": "blind-review-bundle-v1",
            "eval_id": eval_id,
            "source_root": f"sources/{eval_id}",
            "source_tree_sha256": case["source_tree_sha256"],
            "scanner_reference_root": "scanner_reference",
            "scanner_reference_sha256": index["scanner_reference_sha256"],
            "findings": grouped.get(eval_id, []),
        }
        path = bundle_root / f"{eval_id}.json"
        write_json(path, bundle)
        bundle_hashes[eval_id] = sha256_file(path)
    (blind_root / "reviews").mkdir(parents=True, exist_ok=False)
    write_json(
        bundle_root / "lock.json",
        {
            "schema_version": "blind-review-bundle-lock-v1",
            "findings_sha256": sha256_file(findings_path),
            "bundles": bundle_hashes,
        },
    )
    print(f"PASS bundles={len(index['cases'])}")
    return 0


def command_bundle_v2(args: argparse.Namespace) -> int:
    blind_root = args.pilot_root.resolve() / "blind"
    findings_path = blind_root / "scan" / "findings.json"
    findings = read_json(findings_path)
    index = read_json(blind_root / "pilot_index.json")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        grouped[str(finding.get("plugin", ""))].append(finding)
    bundle_root = blind_root / "review_bundles_v2"
    review_root = blind_root / "reviews_v2"
    instructions_path = blind_root / "REVIEW_INSTRUCTIONS_V2.md"
    if bundle_root.exists() or review_root.exists() or instructions_path.exists():
        raise FileExistsError("v2 review artifacts already exist; refusing overwrite")
    instructions_path.write_text(review_instructions_v2_text(), encoding="utf-8")
    bundle_hashes: dict[str, str] = {}
    for case in index["cases"]:
        eval_id = case["eval_id"]
        bundle = {
            "schema_version": "blind-review-bundle-v2",
            "eval_id": eval_id,
            "source_root": f"sources/{eval_id}",
            "source_tree_sha256": case["source_tree_sha256"],
            "scanner_reference_root": "scanner_reference",
            "scanner_reference_sha256": index["scanner_reference_sha256"],
            "findings": grouped.get(eval_id, []),
        }
        path = bundle_root / f"{eval_id}.json"
        write_json(path, bundle)
        bundle_hashes[eval_id] = sha256_file(path)
    review_root.mkdir(parents=True, exist_ok=False)
    write_json(
        bundle_root / "lock.json",
        {
            "schema_version": "blind-review-bundle-lock-v2",
            "findings_sha256": sha256_file(findings_path),
            "instructions_sha256": sha256_file(instructions_path),
            "agents_sha256": sha256_file(blind_root / "AGENTS.md"),
            "bundles": bundle_hashes,
        },
    )
    print(f"PASS v2_bundles={len(index['cases'])}")
    return 0


def command_bundle_v3(args: argparse.Namespace) -> int:
    blind_root = args.pilot_root.resolve() / "blind"
    findings_path = blind_root / "scan" / "findings.json"
    findings = read_json(findings_path)
    index = read_json(blind_root / "pilot_index.json")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        grouped[str(finding.get("plugin", ""))].append(finding)
    bundle_root = blind_root / "review_bundles_v3"
    review_root = blind_root / "reviews_v3"
    instructions_path = blind_root / "REVIEW_INSTRUCTIONS_V3.md"
    schema_path = blind_root / "REVIEW_SCHEMA_V3.json"
    if (
        bundle_root.exists() or review_root.exists() or instructions_path.exists()
        or schema_path.exists()
    ):
        raise FileExistsError("v3 review artifacts already exist; refusing overwrite")
    instructions_path.write_text(review_instructions_v3_text(), encoding="utf-8")
    write_json(schema_path, review_schema_v3())
    bundle_hashes: dict[str, str] = {}
    for case in index["cases"]:
        eval_id = case["eval_id"]
        bundle = {
            "schema_version": "blind-review-bundle-v3",
            "eval_id": eval_id,
            "source_root": f"sources/{eval_id}",
            "source_tree_sha256": case["source_tree_sha256"],
            "source_files": _source_file_inventory(blind_root, eval_id),
            "scanner_reference_root": "scanner_reference",
            "scanner_reference_sha256": index["scanner_reference_sha256"],
            "findings": grouped.get(eval_id, []),
        }
        path = bundle_root / f"{eval_id}.json"
        write_json(path, bundle)
        bundle_hashes[eval_id] = sha256_file(path)
    review_root.mkdir(parents=True, exist_ok=False)
    write_json(
        bundle_root / "lock.json",
        {
            "schema_version": "blind-review-bundle-lock-v3",
            "findings_sha256": sha256_file(findings_path),
            "pilot_index_sha256": sha256_file(blind_root / "pilot_index.json"),
            "instructions_sha256": sha256_file(instructions_path),
            "review_schema_sha256": sha256_file(schema_path),
            "agents_sha256": sha256_file(blind_root / "AGENTS.md"),
            "bundles": bundle_hashes,
        },
    )
    print(f"PASS v3_bundles={len(index['cases'])}")
    return 0


def command_bundle_v4(args: argparse.Namespace) -> int:
    blind_root = args.pilot_root.resolve() / "blind"
    findings_path = blind_root / "scan" / "findings.json"
    findings = read_json(findings_path)
    index = read_json(blind_root / "pilot_index.json")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        grouped[str(finding.get("plugin", ""))].append(finding)
    bundle_root = blind_root / "review_bundles_v4"
    review_root = blind_root / "reviews_v4"
    instructions_path = blind_root / "REVIEW_INSTRUCTIONS_V4.md"
    schema_path = blind_root / "REVIEW_SCHEMA_V4.json"
    validator_path = blind_root / "REVIEW_VALIDATOR_V4.py"
    if (
        bundle_root.exists() or review_root.exists() or instructions_path.exists()
        or schema_path.exists() or validator_path.exists()
    ):
        raise FileExistsError("v4 review artifacts already exist; refusing overwrite")
    instructions_path.write_text(review_instructions_v4_text(), encoding="utf-8")
    write_json(schema_path, review_schema_v4())
    shutil.copyfile(Path(__file__).with_name("blind_review_v4.py"), validator_path)
    bundle_hashes: dict[str, str] = {}
    for case in index["cases"]:
        eval_id = case["eval_id"]
        source_files = _source_file_inventory(blind_root, eval_id)
        inventory_paths = {item["path"] for item in source_files}
        case_findings = grouped.get(eval_id, [])
        primary_finding = min(case_findings, key=lambda item: int(item["global_rank"])) if case_findings else None
        primary_file = (
            str(primary_finding.get("file", "")).replace("\\", "/")
            if primary_finding is not None else ""
        )
        required_files = [primary_file] if primary_file in inventory_paths else []
        bundle = {
            "schema_version": "blind-review-bundle-v4",
            "eval_id": eval_id,
            "source_root": f"sources/{eval_id}",
            "source_tree_sha256": case["source_tree_sha256"],
            "source_inventory_sha256": case["source_tree_sha256"],
            "primary_finding_global_rank": (
                int(primary_finding["global_rank"]) if primary_finding is not None else None
            ),
            "source_files": source_files,
            "required_review_files": required_files,
            "scanner_reference_root": "scanner_reference",
            "scanner_reference_sha256": index["scanner_reference_sha256"],
            "findings": case_findings,
        }
        path = bundle_root / f"{eval_id}.json"
        write_json(path, bundle)
        bundle_hashes[eval_id] = sha256_file(path)
    review_root.mkdir(parents=True, exist_ok=False)
    review_agents_path = review_root / "AGENTS.md"
    review_agents_path.write_text(reviewer_v4_agents_text(), encoding="utf-8")
    write_json(
        bundle_root / "lock.json",
        {
            "schema_version": "blind-review-bundle-lock-v4",
            "findings_sha256": sha256_file(findings_path),
            "pilot_index_sha256": sha256_file(blind_root / "pilot_index.json"),
            "instructions_sha256": sha256_file(instructions_path),
            "review_schema_sha256": sha256_file(schema_path),
            "review_validator_sha256": sha256_file(validator_path),
            "agents_sha256": sha256_file(blind_root / "AGENTS.md"),
            "review_agents_sha256": sha256_file(review_agents_path),
            "bundles": bundle_hashes,
        },
    )
    print(f"PASS v4_bundles={len(index['cases'])}")
    return 0


def command_bundle_v5(args: argparse.Namespace) -> int:
    blind_root = args.pilot_root.resolve() / "blind"
    findings_path = blind_root / "scan" / "findings.json"
    findings = read_json(findings_path)
    index = read_json(blind_root / "pilot_index.json")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        grouped[str(finding.get("plugin", ""))].append(finding)
    bundle_root = blind_root / "review_bundles_v5"
    review_root = blind_root / "reviews_v5"
    instructions_path = blind_root / "REVIEW_INSTRUCTIONS_V5.md"
    schema_path = blind_root / "REVIEW_SCHEMA_V5.json"
    validator_path = blind_root / "REVIEW_VALIDATOR_V5.py"
    base_validator_path = blind_root / "REVIEW_VALIDATOR_V4_BASE.py"
    if any(
        path.exists()
        for path in (
            bundle_root,
            review_root,
            instructions_path,
            schema_path,
            validator_path,
            base_validator_path,
        )
    ):
        raise FileExistsError("v5 review artifacts already exist; refusing overwrite")
    instructions_path.write_text(review_instructions_v5_text(), encoding="utf-8")
    write_json(schema_path, review_schema_v5())
    shutil.copyfile(Path(__file__).with_name("blind_review_v5.py"), validator_path)
    shutil.copyfile(Path(__file__).with_name("blind_review_v4.py"), base_validator_path)
    bundle_hashes: dict[str, str] = {}
    for case in index["cases"]:
        eval_id = case["eval_id"]
        source_files = _source_file_inventory(blind_root, eval_id)
        inventory_paths = {item["path"] for item in source_files}
        case_findings = grouped.get(eval_id, [])
        primary_finding = (
            min(case_findings, key=lambda item: int(item["global_rank"]))
            if case_findings
            else None
        )
        primary_file = (
            str(primary_finding.get("file", "")).replace("\\", "/")
            if primary_finding is not None
            else ""
        )
        bundle = {
            "schema_version": "blind-review-bundle-v5",
            "eval_id": eval_id,
            "source_root": f"sources/{eval_id}",
            "source_tree_sha256": case["source_tree_sha256"],
            "source_inventory_sha256": case["source_tree_sha256"],
            "primary_finding_global_rank": (
                int(primary_finding["global_rank"])
                if primary_finding is not None
                else None
            ),
            "primary_finding_identity": (
                finding_identity_v5(primary_finding)
                if primary_finding is not None
                else None
            ),
            "source_files": source_files,
            "required_review_files": (
                [primary_file] if primary_file in inventory_paths else []
            ),
            "scanner_reference_root": "scanner_reference",
            "scanner_reference_sha256": index["scanner_reference_sha256"],
            "findings": case_findings,
        }
        path = bundle_root / f"{eval_id}.json"
        write_json(path, bundle)
        bundle_hashes[eval_id] = sha256_file(path)
    review_root.mkdir(parents=True, exist_ok=False)
    review_agents_path = review_root / "AGENTS.md"
    review_agents_path.write_text(reviewer_v5_agents_text(), encoding="utf-8")
    write_json(
        bundle_root / "lock.json",
        {
            "schema_version": "blind-review-bundle-lock-v5",
            "findings_sha256": sha256_file(findings_path),
            "pilot_index_sha256": sha256_file(blind_root / "pilot_index.json"),
            "instructions_sha256": sha256_file(instructions_path),
            "review_schema_sha256": sha256_file(schema_path),
            "review_validator_sha256": sha256_file(validator_path),
            "base_validator_sha256": sha256_file(base_validator_path),
            "agents_sha256": sha256_file(blind_root / "AGENTS.md"),
            "review_agents_sha256": sha256_file(review_agents_path),
            "bundles": bundle_hashes,
        },
    )
    print(f"PASS v5_bundles={len(index['cases'])}")
    return 0


def _finding_identity(finding: dict[str, Any]) -> str:
    excluded = {"global_rank", "plugin_rank"}
    stable = {key: value for key, value in finding.items() if key not in excluded}
    return sha256_bytes(canonical_json_bytes(stable))


def command_reuse_reviews_v2(args: argparse.Namespace) -> int:
    target_root = args.pilot_root.resolve()
    source_root = args.from_pilot_root.resolve()
    target_blind = target_root / "blind"
    source_blind = source_root / "blind"
    source_review_lock = read_json(source_root / "private" / "review_lock_v2.json")
    target_index = read_json(target_blind / "pilot_index.json")
    source_index = read_json(source_blind / "pilot_index.json")
    if target_index["scanner_reference_sha256"] != source_index["scanner_reference_sha256"]:
        raise ValueError("scanner reference differs; v2 reviews cannot be reused")
    source_cases = {item["eval_id"]: item for item in source_index["cases"]}
    target_cases = {item["eval_id"]: item for item in target_index["cases"]}
    common_ids = sorted(set(source_cases).intersection(target_cases))
    if args.count:
        common_ids = common_ids[: args.count]
    source_findings = read_json(source_blind / "scan" / "findings.json")
    target_findings = read_json(target_blind / "scan" / "findings.json")
    source_by_rank = {int(item["global_rank"]): item for item in source_findings}
    target_by_identity = {_finding_identity(item): item for item in target_findings}
    reused = 0
    for eval_id in common_ids:
        if source_cases[eval_id]["source_tree_sha256"] != target_cases[eval_id]["source_tree_sha256"]:
            raise ValueError(f"source tree differs; cannot reuse {eval_id}")
        source_review_path = source_blind / "reviews_v2" / f"{eval_id}.json"
        if not source_review_path.is_file():
            continue
        if sha256_file(source_review_path) != source_review_lock.get("reviews", {}).get(eval_id):
            raise ValueError(f"source v2 review is not locked or changed: {eval_id}")
        target_review_path = target_blind / "reviews_v2" / f"{eval_id}.json"
        if target_review_path.exists():
            raise FileExistsError(f"target v2 review already exists: {eval_id}")
        review = read_json(source_review_path)
        _validate_review_v2(review, eval_id)
        remapped: list[int] = []
        for rank in review["selected_finding_global_ranks"]:
            source_finding = source_by_rank.get(int(rank))
            if source_finding is None or source_finding.get("plugin") != eval_id:
                raise ValueError(f"source review rank does not belong to {eval_id}: {rank}")
            target_finding = target_by_identity.get(_finding_identity(source_finding))
            if target_finding is None or target_finding.get("plugin") != eval_id:
                raise ValueError(f"finding fingerprint missing in target: {eval_id}:{rank}")
            remapped.append(int(target_finding["global_rank"]))
        review["selected_finding_global_ranks"] = sorted(set(remapped))
        _validate_v2_source_evidence(review, target_blind, eval_id)
        write_json(target_review_path, review)
        reused += 1
    print(f"PASS reused_reviews_v2={reused}")
    return 0


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)


def command_validate_blind(args: argparse.Namespace) -> int:
    pilot_root = args.pilot_root.resolve()
    blind_root = pilot_root / "blind"
    case_map = read_json(pilot_root / "private" / "case_map.json")
    forbidden_tokens: set[str] = set()
    for item in case_map["cases"]:
        case_id = item["case_id"]
        forbidden_tokens.add(case_id.casefold())
        parts = case_id.split(":", 3)
        if len(parts) == 4:
            forbidden_tokens.add(parts[2].casefold())

    violations: list[str] = []
    skip_names = {"AGENTS.md", "REVIEW_INSTRUCTIONS.md"}
    for path in sorted(p for p in blind_root.rglob("*") if p.is_file()):
        relative = path.relative_to(blind_root)
        if relative.parts[0] in {"sources", "scanner_reference", "reviews"}:
            continue
        if path.name in skip_names:
            continue
        if path.suffix.lower() not in {".json", ".jsonl", ".md", ".txt", ".csv"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace").casefold()
        for token in forbidden_tokens:
            if token and token in text:
                violations.append(f"{relative.as_posix()}: leaked token {token}")
    for path in blind_root.rglob("*"):
        lowered = path.relative_to(blind_root).as_posix().casefold()
        for token in forbidden_tokens:
            if token and token in lowered:
                violations.append(f"leaked filename token: {lowered}")
    if violations:
        raise ValueError("blind boundary violations:\n" + "\n".join(sorted(set(violations))))
    print(f"PASS blind_metadata_leaks=0 cases={len(case_map['cases'])}")
    return 0


def _normalize_location_path(path: str, eval_id: str) -> tuple[str, ...]:
    parts = [part.casefold() for part in path.replace("\\", "/").split("/") if part]
    if parts and parts[0] == eval_id.casefold():
        parts = parts[1:]
    return tuple(parts)


def _location_matches(
    observed: dict[str, Any] | None,
    expected: dict[str, Any],
    eval_id: str,
    tolerance: int,
) -> bool:
    if not observed or not observed.get("path"):
        return False
    observed_parts = _normalize_location_path(str(observed["path"]), eval_id)
    expected_parts = tuple(
        part.casefold()
        for part in str(expected.get("path", "")).replace("\\", "/").split("/")
        if part
    )
    if expected_parts and observed_parts:
        if not (
            observed_parts == expected_parts
            or observed_parts[-len(expected_parts) :] == expected_parts
            or expected_parts[-len(observed_parts) :] == observed_parts
        ):
            return False
    try:
        return abs(int(observed.get("line", 0)) - int(expected.get("line", 0))) <= tolerance
    except (TypeError, ValueError):
        return False


def _validate_review(review: dict[str, Any], eval_id: str) -> None:
    required = {
        "schema_version",
        "eval_id",
        "verdict",
        "reviewer_confidence",
        "selected_finding_global_ranks",
        "source",
        "sinks",
        "trace",
        "exposure",
        "defenses",
        "scanner_assessment",
        "scanner_reason",
        "unresolved",
        "reviewed_files",
    }
    missing = required.difference(review)
    if missing:
        raise ValueError(f"{eval_id}: missing review fields: {sorted(missing)}")
    if review.get("schema_version") != "blind-review-v1":
        raise ValueError(f"{eval_id}: invalid review schema_version")
    if review.get("eval_id") != eval_id:
        raise ValueError(f"{eval_id}: review eval_id mismatch")
    if review.get("verdict") not in {
        "likely_vulnerable",
        "possible_vulnerability",
        "likely_false_positive",
        "insufficient_evidence",
    }:
        raise ValueError(f"{eval_id}: invalid verdict")
    def keys(value: Any) -> Iterable[str]:
        if isinstance(value, dict):
            for key, item in value.items():
                yield str(key).casefold()
                yield from keys(item)
        elif isinstance(value, list):
            for item in value:
                yield from keys(item)

    leaked = FORBIDDEN_REVIEW_KEYS.intersection(keys(review))
    if leaked:
        raise ValueError(f"{eval_id}: forbidden review keys: {sorted(leaked)}")
    if review.get("reviewer_confidence") not in {"high", "medium", "low"}:
        raise ValueError(f"{eval_id}: invalid reviewer_confidence")
    if review.get("scanner_assessment") not in {
        "correct_detection",
        "related_candidate_only",
        "missed_path",
        "likely_false_positive",
    }:
        raise ValueError(f"{eval_id}: invalid scanner_assessment")
    for location in [review.get("source", {})] + list(review.get("sinks", [])):
        if not isinstance(location, dict):
            raise ValueError(f"{eval_id}: source/sink locations must be objects")
        path = str(location.get("path", ""))
        if path:
            pure = PurePosixPath(path.replace("\\", "/"))
            if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                raise ValueError(f"{eval_id}: unsafe review path: {path}")
            if pure.parts[0].casefold() != eval_id.casefold():
                raise ValueError(f"{eval_id}: review path outside opaque case: {path}")


def command_lock_reviews(args: argparse.Namespace) -> int:
    pilot_root = args.pilot_root.resolve()
    blind_root = pilot_root / "blind"
    private_root = pilot_root / "private"
    index = read_json(blind_root / "pilot_index.json")
    findings = read_json(blind_root / "scan" / "findings.json")
    available_ranks: dict[str, set[int]] = defaultdict(set)
    for finding in findings:
        available_ranks[str(finding.get("plugin", ""))].add(int(finding["global_rank"]))

    expected_ids = [item["eval_id"] for item in index["cases"]]
    case_map = read_json(private_root / "case_map.json")
    private_tokens: set[str] = set()
    for item in case_map["cases"]:
        case_id = str(item["case_id"])
        private_tokens.add(case_id.casefold())
        parts = case_id.split(":", 3)
        if len(parts) == 4:
            private_tokens.add(parts[2].casefold())
    actual_files = sorted((blind_root / "reviews").glob("*.json"))
    actual_ids = [path.stem for path in actual_files]
    if actual_ids != expected_ids:
        missing = sorted(set(expected_ids).difference(actual_ids))
        extra = sorted(set(actual_ids).difference(expected_ids))
        raise ValueError(f"review set mismatch; missing={missing} extra={extra}")

    hashes: dict[str, str] = {}
    for eval_id in expected_ids:
        path = blind_root / "reviews" / f"{eval_id}.json"
        review = read_json(path)
        _validate_review(review, eval_id)
        review_text = path.read_text(encoding="utf-8").casefold()
        leaked_tokens = sorted(token for token in private_tokens if token and token in review_text)
        if leaked_tokens or re.search(r"\bcve-\d{4}-\d+\b", review_text, re.IGNORECASE):
            raise ValueError(f"{eval_id}: review contains a vulnerability identifier")
        selected = review.get("selected_finding_global_ranks", [])
        if not isinstance(selected, list):
            raise ValueError(f"{eval_id}: selected_finding_global_ranks must be an array")
        normalized: set[int] = set()
        for value in selected:
            if isinstance(value, bool):
                raise ValueError(f"{eval_id}: boolean is not a finding rank")
            try:
                normalized.add(int(value))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{eval_id}: invalid finding rank: {value}") from exc
        unknown = normalized.difference(available_ranks.get(eval_id, set()))
        if unknown:
            raise ValueError(f"{eval_id}: selected finding ranks not in bundle: {sorted(unknown)}")
        hashes[eval_id] = sha256_file(path)

    lock_path = private_root / "review_lock.json"
    if lock_path.exists():
        raise FileExistsError(f"review lock already exists; refusing overwrite: {lock_path}")
    write_json(
        lock_path,
        {
            "schema_version": "blind-review-lock-v1",
            "review_count": len(hashes),
            "reviews": hashes,
            "findings_sha256": sha256_file(blind_root / "scan" / "findings.json"),
            "bundle_lock_sha256": sha256_file(blind_root / "review_bundles" / "lock.json"),
        },
    )
    print(f"PASS locked_reviews={len(hashes)}")
    return 0


def _validate_opaque_path(path: str, eval_id: str) -> None:
    pure = PurePosixPath(path.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ValueError(f"{eval_id}: unsafe review path: {path}")
    if pure.parts[0].casefold() != eval_id.casefold():
        raise ValueError(f"{eval_id}: review path outside opaque case: {path}")


def _validate_review_v2(review: dict[str, Any], eval_id: str) -> None:
    required = {
        "schema_version",
        "eval_id",
        "verdict",
        "reviewer_confidence",
        "selected_finding_global_ranks",
        "source_locations",
        "sink_locations",
        "trace",
        "exposure",
        "defenses",
        "scanner_assessment",
        "scanner_reason",
        "unresolved",
        "reviewed_files",
    }
    missing = required.difference(review)
    if missing:
        raise ValueError(f"{eval_id}: missing v2 review fields: {sorted(missing)}")
    if review.get("schema_version") != "blind-review-v2" or review.get("eval_id") != eval_id:
        raise ValueError(f"{eval_id}: invalid v2 review identity")
    if review.get("verdict") not in {
        "likely_vulnerable",
        "possible_vulnerability",
        "likely_false_positive",
        "insufficient_evidence",
    }:
        raise ValueError(f"{eval_id}: invalid verdict")
    if review.get("reviewer_confidence") not in {"high", "medium", "low"}:
        raise ValueError(f"{eval_id}: invalid reviewer_confidence")
    if review.get("scanner_assessment") not in {
        "correct_detection",
        "related_candidate_only",
        "missed_path",
        "likely_false_positive",
    }:
        raise ValueError(f"{eval_id}: invalid scanner_assessment")
    for field in ("source_locations", "sink_locations"):
        locations = review.get(field)
        if not isinstance(locations, list):
            raise ValueError(f"{eval_id}: {field} must be an array")
        for location in locations:
            if not isinstance(location, dict):
                raise ValueError(f"{eval_id}: {field} entries must be objects")
            path = str(location.get("path", ""))
            if not path:
                raise ValueError(f"{eval_id}: {field} path is required")
            _validate_opaque_path(path, eval_id)
            try:
                line_start = int(location["line_start"])
                line_end = int(location["line_end"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{eval_id}: invalid {field} line range") from exc
            if line_start < 1 or line_end < line_start or line_end - line_start > 19:
                raise ValueError(f"{eval_id}: non-tight {field} line range {line_start}-{line_end}")
            if not str(location.get("expression", "")).strip():
                raise ValueError(f"{eval_id}: {field} expression is required")
    for path in review.get("reviewed_files", []):
        _validate_opaque_path(str(path), eval_id)


def _read_source_text(path: Path) -> str:
    for encoding in ("utf-8", "utf-8-sig", "cp932", "latin-1"):
        try:
            return path.read_text(encoding=encoding, errors="strict")
        except (UnicodeError, OSError):
            continue
    return path.read_text(encoding="utf-8", errors="replace")


def _normalized_code(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _validate_v2_source_evidence(review: dict[str, Any], blind_root: Path, eval_id: str) -> None:
    for field in ("source_locations", "sink_locations"):
        for location in review[field]:
            pure = PurePosixPath(str(location["path"]).replace("\\", "/"))
            source_path = blind_root / "sources" / Path(*pure.parts)
            if not source_path.is_file():
                raise ValueError(f"{eval_id}: cited source file does not exist: {location['path']}")
            lines = _read_source_text(source_path).splitlines()
            line_start = int(location["line_start"])
            line_end = int(location["line_end"])
            if line_end > len(lines):
                raise ValueError(f"{eval_id}: cited line range exceeds file length")
            excerpt = _normalized_code("\n".join(lines[line_start - 1 : line_end]))
            expression = _normalized_code(str(location["expression"]))
            if expression not in excerpt:
                raise ValueError(
                    f"{eval_id}: {field} expression is not present in cited line range"
                )
    for value in review["reviewed_files"]:
        pure = PurePosixPath(str(value).replace("\\", "/"))
        if not (blind_root / "sources" / Path(*pure.parts)).is_file():
            raise ValueError(f"{eval_id}: reviewed file does not exist: {value}")


def _nonempty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return value is not None


def _validate_review_v3(review: dict[str, Any], eval_id: str) -> None:
    required = {
        "schema_version", "eval_id", "verdict", "confidence",
        "primary_selected_finding_global_rank", "secondary_selected_finding_global_ranks",
        "trace_anchor_global_rank", "source_inventory_sha256", "source_locations",
        "sink_locations", "trace", "exposure", "defenses", "context_analysis",
        "scanner_assessment", "scanner_reason", "unresolved", "reviewed_files",
        "review_passes", "evidence_gap",
    }
    missing = required.difference(review)
    if missing:
        raise ValueError(f"{eval_id}: missing v3 review fields: {sorted(missing)}")
    extra = set(review).difference(required)
    if extra:
        raise ValueError(f"{eval_id}: unexpected v3 review fields: {sorted(extra)}")
    if review.get("schema_version") != "blind-review-v3" or review.get("eval_id") != eval_id:
        raise ValueError(f"{eval_id}: invalid v3 review identity")
    if review.get("verdict") not in {
        "likely_vulnerable", "possible_vulnerability", "likely_false_positive", "insufficient_evidence",
    }:
        raise ValueError(f"{eval_id}: invalid verdict")
    if review.get("confidence") not in {"high", "medium", "low"}:
        raise ValueError(f"{eval_id}: invalid confidence")
    if review.get("scanner_assessment") not in {
        "correct_detection", "related_candidate_only", "missed_path", "likely_false_positive",
    }:
        raise ValueError(f"{eval_id}: invalid scanner_assessment")
    if not isinstance(review.get("source_inventory_sha256"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", review["source_inventory_sha256"]
    ):
        raise ValueError(f"{eval_id}: invalid source_inventory_sha256")
    for field in ("trace", "context_analysis", "scanner_reason"):
        if not isinstance(review[field], str):
            raise ValueError(f"{eval_id}: {field} must be a string")
    if not isinstance(review["exposure"], dict):
        raise ValueError(f"{eval_id}: exposure must be an object")
    for field in ("defenses", "unresolved"):
        if not isinstance(review[field], list) or any(
            not isinstance(value, str) for value in review[field]
        ):
            raise ValueError(f"{eval_id}: {field} must be an array of strings")
    leaked = FORBIDDEN_REVIEW_KEYS.intersection(
        value.casefold() for value in _iter_strings(review)
    )
    if leaked:
        raise ValueError(f"{eval_id}: forbidden review keys: {sorted(leaked)}")
    for field in ("source_locations", "sink_locations"):
        locations = review[field]
        if not isinstance(locations, list):
            raise ValueError(f"{eval_id}: {field} must be an array")
        for location in locations:
            if not isinstance(location, dict):
                raise ValueError(f"{eval_id}: {field} entries must be objects")
            location_keys = {"path", "line_start", "line_end", "expression"}
            if set(location) != location_keys:
                raise ValueError(f"{eval_id}: invalid {field} entry keys")
            path = str(location.get("path", ""))
            if not path:
                raise ValueError(f"{eval_id}: {field} path is required")
            _validate_opaque_path(path, eval_id)
            try:
                line_start, line_end = int(location["line_start"]), int(location["line_end"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{eval_id}: invalid {field} line range") from exc
            if line_start < 1 or line_end < line_start or line_end - line_start > 19:
                raise ValueError(f"{eval_id}: non-tight {field} line range {line_start}-{line_end}")
            if not str(location.get("expression", "")).strip():
                raise ValueError(f"{eval_id}: {field} expression is required")
    if not isinstance(review["reviewed_files"], list) or not review["reviewed_files"]:
        raise ValueError(f"{eval_id}: reviewed_files must be a nonempty array")
    if any(not isinstance(value, str) or not value for value in review["reviewed_files"]):
        raise ValueError(f"{eval_id}: reviewed_files entries must be nonempty strings")
    for value in review["reviewed_files"]:
        _validate_opaque_path(str(value), eval_id)
    passes = review["review_passes"]
    if not isinstance(passes, dict):
        raise ValueError(f"{eval_id}: review_passes must be an object")
    if set(passes) != {"scanner_guided", "entrypoint_led", "sink_storage_led"}:
        raise ValueError(f"{eval_id}: invalid review_passes keys")
    for name in ("scanner_guided", "entrypoint_led", "sink_storage_led"):
        files = passes.get(name)
        if not isinstance(files, list) or not files:
            raise ValueError(f"{eval_id}: review_passes.{name} must be a nonempty array")
        if any(not isinstance(value, str) or not value for value in files):
            raise ValueError(f"{eval_id}: review_passes.{name} entries must be nonempty strings")
        for value in files:
            _validate_opaque_path(str(value), eval_id)
    verdict = review["verdict"]
    if verdict != "insufficient_evidence":
        for field in ("source_locations", "sink_locations", "trace", "context_analysis"):
            if not _nonempty(review[field]):
                raise ValueError(f"{eval_id}: {field} must be nonempty for non-insufficient verdicts")
        if review["evidence_gap"] is not None:
            raise ValueError(f"{eval_id}: evidence_gap must be null outside insufficient_evidence")
    else:
        gap = review["evidence_gap"]
        if not isinstance(gap, dict):
            raise ValueError(f"{eval_id}: insufficient_evidence requires an evidence_gap object")
        if set(gap) != {"missing_link", "searched_locations"}:
            raise ValueError(f"{eval_id}: invalid evidence_gap keys")
        if gap.get("missing_link") not in {
            "source", "write", "storage_read", "sink", "reachability", "context_escape",
        }:
            raise ValueError(f"{eval_id}: invalid evidence_gap missing_link")
        searched = gap.get("searched_locations")
        if not isinstance(searched, list) or not searched:
            raise ValueError(f"{eval_id}: evidence_gap searched_locations must be nonempty")
        if any(not isinstance(value, str) or not value for value in searched):
            raise ValueError(
                f"{eval_id}: evidence_gap searched_locations entries must be nonempty strings"
            )
        for value in searched:
            _validate_opaque_path(str(value), eval_id)


def _validate_v3_source_evidence(review: dict[str, Any], blind_root: Path, eval_id: str) -> None:
    _validate_v2_source_evidence(review, blind_root, eval_id)
    paths = list(review["reviewed_files"])
    for files in review["review_passes"].values():
        paths.extend(files)
    if review["verdict"] == "insufficient_evidence":
        paths.extend(review["evidence_gap"]["searched_locations"])
    for value in paths:
        pure = PurePosixPath(str(value).replace("\\", "/"))
        if not (blind_root / "sources" / Path(*pure.parts)).is_file():
            raise ValueError(f"{eval_id}: referenced review file does not exist: {value}")


def _v4_candidates(review: dict[str, Any]) -> list[dict[str, Any]]:
    return [review["primary_candidate"], *review["independent_paths"]]


def _validate_v4_source_evidence(
    review: dict[str, Any], blind_root: Path, eval_id: str, bundle: dict[str, Any]
) -> None:
    reviewed = set(review["reviewed_files"])
    required = set(bundle.get("required_review_files", []))
    if not required.issubset(reviewed):
        raise ValueError(f"{eval_id}: reviewed_files omit required scanner finding files")
    referenced_files = set(reviewed)
    for files in review["review_passes"].values():
        referenced_files.update(files)
    for candidate in _v4_candidates(review):
        gap = candidate["evidence_gap"]
        if gap is not None:
            referenced_files.update(gap["searched_files"])
        step_paths = {step["path"] for step in candidate["trace_steps"]}
        if not step_paths.issubset(reviewed):
            raise ValueError(f"{eval_id}: every trace step file must be in reviewed_files")
        entrypoint_paths = {
            step["path"] for step in candidate["trace_steps"]
            if step["kind"] in {"entrypoint", "call", "callback"}
        }
        if not entrypoint_paths.issubset(set(review["review_passes"]["entrypoint_led"])):
            raise ValueError(f"{eval_id}: entrypoint/call steps must be covered by entrypoint_led")
        sink_storage_paths = {
            step["path"] for step in candidate["trace_steps"]
            if step["kind"] in {"write", "storage_read", "sink", "render", "defense", "refutation"}
        }
        if not sink_storage_paths.issubset(set(review["review_passes"]["sink_storage_led"])):
            raise ValueError(f"{eval_id}: sink/storage/refutation steps must be covered by sink_storage_led")
        for step in candidate["trace_steps"]:
            path = str(step["path"])
            _validate_opaque_path(path, eval_id)
            pure = PurePosixPath(path.replace("\\", "/"))
            source_path = blind_root / "sources" / Path(*pure.parts)
            if not source_path.is_file():
                raise ValueError(f"{eval_id}: v4 trace step file does not exist: {path}")
            lines = _read_source_text(source_path).splitlines()
            line_start = int(step["line_start"])
            line_end = int(step["line_end"])
            if line_end > len(lines):
                raise ValueError(f"{eval_id}: v4 cited line range exceeds file length")
            excerpt = re.sub(r"\s+", "", "\n".join(lines[line_start - 1 : line_end]))
            expression = re.sub(r"\s+", "", str(step["expression"]))
            if expression not in excerpt:
                raise ValueError(f"{eval_id}: v4 expression is not present in cited line range")
    for value in referenced_files:
        _validate_opaque_path(str(value), eval_id)
        pure = PurePosixPath(str(value).replace("\\", "/"))
        if not (blind_root / "sources" / Path(*pure.parts)).is_file():
            raise ValueError(f"{eval_id}: referenced v4 review file does not exist: {value}")


def _private_vulnerability_tokens(case_map: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for item in case_map["cases"]:
        case_id = str(item["case_id"])
        tokens.add(case_id.casefold())
        parts = case_id.split(":", 3)
        if len(parts) == 4:
            tokens.add(parts[2].casefold())
    return tokens


def command_lock_reviews_v2(args: argparse.Namespace) -> int:
    pilot_root = args.pilot_root.resolve()
    blind_root = pilot_root / "blind"
    private_root = pilot_root / "private"
    index = read_json(blind_root / "pilot_index.json")
    findings = read_json(blind_root / "scan" / "findings.json")
    available_ranks: dict[str, set[int]] = defaultdict(set)
    for finding in findings:
        available_ranks[str(finding.get("plugin", ""))].add(int(finding["global_rank"]))
    case_map = read_json(private_root / "case_map.json")
    private_tokens = _private_vulnerability_tokens(case_map)
    expected_ids = [item["eval_id"] for item in index["cases"]]
    review_root = blind_root / "reviews_v2"
    actual_ids = [path.stem for path in sorted(review_root.glob("*.json"))]
    if actual_ids != expected_ids:
        missing = sorted(set(expected_ids).difference(actual_ids))
        extra = sorted(set(actual_ids).difference(expected_ids))
        raise ValueError(f"v2 review set mismatch; missing={missing} extra={extra}")

    hashes: dict[str, str] = {}
    for eval_id in expected_ids:
        path = review_root / f"{eval_id}.json"
        review = read_json(path)
        _validate_review_v2(review, eval_id)
        _validate_v2_source_evidence(review, blind_root, eval_id)
        review_text = path.read_text(encoding="utf-8").casefold()
        if any(token and token in review_text for token in private_tokens) or re.search(
            r"\bcve-\d{4}-\d+\b", review_text, re.IGNORECASE
        ):
            raise ValueError(f"{eval_id}: v2 review contains a vulnerability identifier")
        selected: set[int] = set()
        for value in review.get("selected_finding_global_ranks", []):
            if isinstance(value, bool):
                raise ValueError(f"{eval_id}: boolean is not a finding rank")
            try:
                selected.add(int(value))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{eval_id}: invalid finding rank: {value}") from exc
        unknown = selected.difference(available_ranks.get(eval_id, set()))
        if unknown:
            raise ValueError(f"{eval_id}: selected finding ranks not in bundle: {sorted(unknown)}")
        hashes[eval_id] = sha256_file(path)

    lock_path = private_root / "review_lock_v2.json"
    if lock_path.exists():
        raise FileExistsError(f"v2 review lock already exists; refusing overwrite: {lock_path}")
    write_json(
        lock_path,
        {
            "schema_version": "blind-review-lock-v2",
            "review_count": len(hashes),
            "reviews": hashes,
            "findings_sha256": sha256_file(blind_root / "scan" / "findings.json"),
            "bundle_lock_sha256": sha256_file(blind_root / "review_bundles_v2" / "lock.json"),
        },
    )
    print(f"PASS locked_reviews_v2={len(hashes)}")
    return 0


def command_lock_reviews_v3(args: argparse.Namespace) -> int:
    pilot_root = args.pilot_root.resolve()
    blind_root, private_root = pilot_root / "blind", pilot_root / "private"
    index = read_json(blind_root / "pilot_index.json")
    case_by_id = {case["eval_id"]: case for case in index["cases"]}
    findings = read_json(blind_root / "scan" / "findings.json")
    ranks: dict[str, list[int]] = defaultdict(list)
    for finding in findings:
        ranks[str(finding.get("plugin", ""))].append(int(finding["global_rank"]))
    expected_ids = [case["eval_id"] for case in index["cases"]]
    review_root = blind_root / "reviews_v3"
    actual_ids = [path.stem for path in sorted(review_root.glob("*.json"))]
    if actual_ids != expected_ids:
        raise ValueError(
            f"v3 review set mismatch; missing={sorted(set(expected_ids).difference(actual_ids))} "
            f"extra={sorted(set(actual_ids).difference(expected_ids))}"
        )
    private_tokens = _private_vulnerability_tokens(read_json(private_root / "case_map.json"))
    hashes: dict[str, str] = {}
    for eval_id in expected_ids:
        path = review_root / f"{eval_id}.json"
        review = read_json(path)
        _validate_review_v3(review, eval_id)
        if review["source_inventory_sha256"] != case_by_id[eval_id]["source_tree_sha256"]:
            raise ValueError(f"{eval_id}: source_inventory_sha256 does not match pilot index")
        available = sorted(ranks.get(eval_id, []))
        primary = review["primary_selected_finding_global_rank"]
        if available:
            if isinstance(primary, bool) or primary != min(available):
                raise ValueError(f"{eval_id}: primary finding rank must be bundle minimum")
        elif primary is not None:
            raise ValueError(f"{eval_id}: primary finding rank must be null without findings")
        secondary = review["secondary_selected_finding_global_ranks"]
        if not isinstance(secondary, list):
            raise ValueError(f"{eval_id}: secondary finding ranks must be an array")
        if any(isinstance(value, bool) or not isinstance(value, int) for value in secondary):
            raise ValueError(f"{eval_id}: invalid secondary finding rank")
        selected = set(secondary)
        if primary is not None:
            if isinstance(primary, bool) or not isinstance(primary, int):
                raise ValueError(f"{eval_id}: invalid primary finding rank")
            selected.add(primary)
        if not selected.issubset(set(available)):
            raise ValueError(f"{eval_id}: selected finding ranks not in bundle")
        anchor = review["trace_anchor_global_rank"]
        if anchor is None:
            if review["verdict"] != "insufficient_evidence" and review["scanner_assessment"] != "missed_path":
                raise ValueError(f"{eval_id}: null trace anchor requires insufficient evidence or missed path")
        elif isinstance(anchor, bool) or anchor not in selected:
            raise ValueError(f"{eval_id}: trace anchor must be a selected finding rank")
        _validate_v3_source_evidence(review, blind_root, eval_id)
        review_text = path.read_text(encoding="utf-8").casefold()
        if any(token and token in review_text for token in private_tokens) or re.search(
            r"\bcve-\d{4}-\d+\b", review_text, re.IGNORECASE
        ):
            raise ValueError(f"{eval_id}: v3 review contains a vulnerability identifier")
        hashes[eval_id] = sha256_file(path)
    lock_path = private_root / "review_lock_v3.json"
    if lock_path.exists():
        raise FileExistsError(f"v3 review lock already exists; refusing overwrite: {lock_path}")
    write_json(lock_path, {
        "schema_version": "blind-review-lock-v3", "review_count": len(hashes),
        "reviews": hashes, "findings_sha256": sha256_file(blind_root / "scan" / "findings.json"),
        "bundle_lock_sha256": sha256_file(blind_root / "review_bundles_v3" / "lock.json"),
    })
    print(f"PASS locked_reviews_v3={len(hashes)}")
    return 0


def command_lock_reviews_v4(args: argparse.Namespace) -> int:
    pilot_root = args.pilot_root.resolve()
    blind_root, private_root = pilot_root / "blind", pilot_root / "private"
    index = read_json(blind_root / "pilot_index.json")
    case_by_id = {case["eval_id"]: case for case in index["cases"]}
    findings = read_json(blind_root / "scan" / "findings.json")
    ranks: dict[str, set[int]] = defaultdict(set)
    finding_files: dict[tuple[str, int], str] = {}
    for finding in findings:
        eval_id = str(finding.get("plugin", ""))
        rank = int(finding["global_rank"])
        ranks[eval_id].add(rank)
        finding_files[(eval_id, rank)] = str(finding.get("file", "")).replace("\\", "/")
    expected_ids = [case["eval_id"] for case in index["cases"]]
    review_root = blind_root / "reviews_v4"
    actual_ids = [path.stem for path in sorted(review_root.glob("*.json"))]
    if actual_ids != expected_ids:
        raise ValueError(
            f"v4 review set mismatch; missing={sorted(set(expected_ids).difference(actual_ids))} "
            f"extra={sorted(set(actual_ids).difference(expected_ids))}"
        )
    private_tokens = _private_vulnerability_tokens(read_json(private_root / "case_map.json"))
    hashes: dict[str, str] = {}
    for eval_id in expected_ids:
        path = review_root / f"{eval_id}.json"
        review = read_json(path)
        bundle = read_json(blind_root / "review_bundles_v4" / f"{eval_id}.json")
        validate_review_v4_against_bundle(
            review, bundle, blind_root=blind_root, eval_id=eval_id
        )
        if review["source_inventory_sha256"] != case_by_id[eval_id]["source_tree_sha256"]:
            raise ValueError(f"{eval_id}: source_inventory_sha256 does not match pilot index")
        available = ranks.get(eval_id, set())
        primary = review["primary_candidate"]
        primary_rank = primary["finding_global_rank"]
        if available:
            if isinstance(primary_rank, bool) or primary_rank != min(available):
                raise ValueError(f"{eval_id}: v4 primary finding rank must be bundle minimum")
        elif primary_rank is not None:
            raise ValueError(f"{eval_id}: v4 primary finding rank must be null without findings")
        primary_selected = set(primary["supporting_finding_global_ranks"])
        if primary_rank is not None:
            primary_selected.add(primary_rank)
            primary_file = finding_files.get((eval_id, primary_rank))
            if primary_file and primary_file not in review["review_passes"]["scanner_guided"]:
                raise ValueError(f"{eval_id}: scanner_guided pass must include primary finding file")
        if not primary_selected.issubset(available):
            raise ValueError(f"{eval_id}: v4 primary selected finding ranks not in bundle")
        for candidate in review["independent_paths"]:
            candidate_ranks = set(candidate["supporting_finding_global_ranks"])
            anchor = candidate["finding_global_rank"]
            if anchor is not None:
                candidate_ranks.add(anchor)
            if not candidate_ranks.issubset(available):
                raise ValueError(f"{eval_id}: independent path finding rank not in bundle")
            if primary_selected.intersection(candidate_ranks):
                raise ValueError(f"{eval_id}: independent path must not reuse primary finding ranks")
        _validate_v4_source_evidence(review, blind_root, eval_id, bundle)
        review_text = path.read_text(encoding="utf-8").casefold()
        if any(token and token in review_text for token in private_tokens) or re.search(
            r"\bcve-\d{4}-\d+\b", review_text, re.IGNORECASE
        ):
            raise ValueError(f"{eval_id}: v4 review contains a vulnerability identifier")
        hashes[eval_id] = sha256_file(path)
    lock_path = private_root / "review_lock_v4.json"
    if lock_path.exists():
        raise FileExistsError(f"v4 review lock already exists; refusing overwrite: {lock_path}")
    write_json(lock_path, {
        "schema_version": "blind-review-lock-v4",
        "review_count": len(hashes),
        "reviews": hashes,
        "findings_sha256": sha256_file(blind_root / "scan" / "findings.json"),
        "bundle_lock_sha256": sha256_file(blind_root / "review_bundles_v4" / "lock.json"),
    })
    print(f"PASS locked_reviews_v4={len(hashes)}")
    return 0


def command_lock_reviews_v5(args: argparse.Namespace) -> int:
    pilot_root = args.pilot_root.resolve()
    blind_root, private_root = pilot_root / "blind", pilot_root / "private"
    index = read_json(blind_root / "pilot_index.json")
    case_by_id = {case["eval_id"]: case for case in index["cases"]}
    expected_ids = [case["eval_id"] for case in index["cases"]]
    review_root = blind_root / "reviews_v5"
    actual_ids = [path.stem for path in sorted(review_root.glob("*.json"))]
    if actual_ids != expected_ids:
        raise ValueError(
            f"v5 review set mismatch; missing={sorted(set(expected_ids).difference(actual_ids))} "
            f"extra={sorted(set(actual_ids).difference(expected_ids))}"
        )
    private_tokens = _private_vulnerability_tokens(read_json(private_root / "case_map.json"))
    hashes: dict[str, str] = {}
    for eval_id in expected_ids:
        path = review_root / f"{eval_id}.json"
        review = read_json(path)
        bundle = read_json(blind_root / "review_bundles_v5" / f"{eval_id}.json")
        validate_review_v5_against_bundle(
            review, bundle, blind_root=blind_root, eval_id=eval_id
        )
        if review["source_inventory_sha256"] != case_by_id[eval_id]["source_tree_sha256"]:
            raise ValueError(f"{eval_id}: source_inventory_sha256 does not match pilot index")
        review_text = path.read_text(encoding="utf-8").casefold()
        if any(token and token in review_text for token in private_tokens) or re.search(
            r"\bcve-\d{4}-\d+\b", review_text, re.IGNORECASE
        ):
            raise ValueError(f"{eval_id}: v5 review contains a vulnerability identifier")
        hashes[eval_id] = sha256_file(path)
    lock_path = private_root / "review_lock_v5.json"
    if lock_path.exists():
        raise FileExistsError(f"v5 review lock already exists; refusing overwrite: {lock_path}")
    write_json(
        lock_path,
        {
            "schema_version": "blind-review-lock-v5",
            "review_count": len(hashes),
            "reviews": hashes,
            "findings_sha256": sha256_file(blind_root / "scan" / "findings.json"),
            "bundle_lock_sha256": sha256_file(
                blind_root / "review_bundles_v5" / "lock.json"
            ),
        },
    )
    print(f"PASS locked_reviews_v5={len(hashes)}")
    return 0


def command_score(args: argparse.Namespace) -> int:
    pilot_root = args.pilot_root.resolve()
    blind_root = pilot_root / "blind"
    private_root = pilot_root / "private"
    review_lock_path = private_root / "review_lock.json"
    if not review_lock_path.is_file():
        raise FileNotFoundError("lock reviews before scoring")
    review_lock = read_json(review_lock_path)
    for eval_id, expected_hash in review_lock.get("reviews", {}).items():
        actual_hash = sha256_file(blind_root / "reviews" / f"{eval_id}.json")
        if actual_hash != expected_hash:
            raise ValueError(f"review changed after lock: {eval_id}")
    if sha256_file(blind_root / "scan" / "findings.json") != review_lock.get(
        "findings_sha256"
    ):
        raise ValueError("scan findings changed after review lock")
    case_map = read_json(private_root / "case_map.json")
    manifest_by_id = {record["case_id"]: record for record in read_jsonl(BENCHMARK_ROOT / "manifest.jsonl")}
    findings = read_json(blind_root / "scan" / "findings.json")
    findings_by_eval: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        findings_by_eval[str(finding.get("plugin", ""))].append(finding)

    scored: list[dict[str, Any]] = []
    for mapping in case_map["cases"]:
        eval_id = mapping["eval_id"]
        review_path = blind_root / "reviews" / f"{eval_id}.json"
        review = read_json(review_path)
        _validate_review(review, eval_id)
        expected = manifest_by_id[mapping["case_id"]]
        expected_sinks = [expected["ground_truth"]["sink"]] + list(
            expected["ground_truth"].get("additional_sinks", [])
        )

        matched_findings: list[dict[str, Any]] = []
        for finding in findings_by_eval.get(eval_id, []):
            observed = {"path": finding.get("file"), "line": finding.get("line")}
            if any(
                _location_matches(observed, sink, eval_id, args.line_tolerance)
                for sink in expected_sinks
            ):
                matched_findings.append(finding)
        best_global = min((int(item["global_rank"]) for item in matched_findings), default=None)
        best_plugin = min((int(item["plugin_rank"]) for item in matched_findings), default=None)

        source_match = _location_matches(
            review.get("source"),
            expected["ground_truth"]["source"],
            eval_id,
            args.line_tolerance,
        )
        sink_match = any(
            _location_matches(observed, sink, eval_id, args.line_tolerance)
            for observed in review.get("sinks", [])
            for sink in expected_sinks
        )
        selected_ranks = {
            int(value)
            for value in review.get("selected_finding_global_ranks", [])
            if isinstance(value, int) or (isinstance(value, str) and value.isdigit())
        }
        selected_ground_truth_finding = any(
            int(item["global_rank"]) in selected_ranks for item in matched_findings
        )
        scored.append(
            {
                "eval_id": eval_id,
                "case_id": mapping["case_id"],
                "scanner_ground_truth_sink_hit": bool(matched_findings),
                "best_global_rank": best_global,
                "best_plugin_rank": best_plugin,
                "scanner_ranked_ground_truth_first_in_plugin": best_plugin == 1,
                "reviewer_source_match": source_match,
                "reviewer_sink_match": sink_match,
                "reviewer_exact_trace_match": source_match and sink_match,
                "reviewer_selected_ground_truth_finding": selected_ground_truth_finding,
                "reviewer_verdict": review["verdict"],
                "reviewer_positive_verdict": review["verdict"]
                in {"likely_vulnerable", "possible_vulnerability"},
                "implementation_fit": expected["implementation_fit"],
            }
        )

    summary = {
        "schema_version": "blind-pilot-score-v1",
        "case_count": len(scored),
        "line_tolerance": args.line_tolerance,
        "scanner_ground_truth_sink_hit_count": sum(
            item["scanner_ground_truth_sink_hit"] for item in scored
        ),
        "scanner_ranked_ground_truth_first_in_plugin_count": sum(
            item["scanner_ranked_ground_truth_first_in_plugin"] for item in scored
        ),
        "reviewer_exact_trace_match_count": sum(item["reviewer_exact_trace_match"] for item in scored),
        "reviewer_selected_ground_truth_finding_count": sum(
            item["reviewer_selected_ground_truth_finding"] for item in scored
        ),
        "reviewer_positive_verdict_count": sum(item["reviewer_positive_verdict"] for item in scored),
        "cases": scored,
    }
    output_path = private_root / "scored_results.json"
    if output_path.exists():
        raise FileExistsError(f"score output already exists; refusing overwrite: {output_path}")
    write_json(output_path, summary)
    write_json(
        private_root / "score_lock.json",
        {
            "scored_results_sha256": sha256_file(output_path),
            "reviews": {
                item["eval_id"]: sha256_file(blind_root / "reviews" / f"{item['eval_id']}.json")
                for item in case_map["cases"]
            },
            "scan_findings_sha256": sha256_file(blind_root / "scan" / "findings.json"),
        },
    )
    print(
        "PASS "
        f"scored={len(scored)} "
        f"scanner_hits={summary['scanner_ground_truth_sink_hit_count']} "
        f"trace_matches={summary['reviewer_exact_trace_match_count']}"
    )
    return 0


def _exact_relative_path_matches(
    observed_path: str,
    expected_path: str,
    eval_id: str,
    artifact_root: str | None = None,
) -> bool:
    observed = _normalize_location_path(observed_path, eval_id)
    expected = tuple(
        part.casefold()
        for part in expected_path.replace("\\", "/").split("/")
        if part
    )
    if not observed or not expected:
        return False
    allowed_expected = {expected}
    if artifact_root is not None:
        if expected[0] != artifact_root.casefold():
            return False
        if len(expected) > 1:
            allowed_expected.add(expected[1:])
    elif len(expected) > 1:
        allowed_expected.add(expected[1:])
    return observed in allowed_expected


def _range_location_matches(
    observed: dict[str, Any],
    expected: dict[str, Any],
    eval_id: str,
    artifact_root: str | None = None,
) -> bool:
    if not _exact_relative_path_matches(
        str(observed.get("path", "")),
        str(expected.get("path", "")),
        eval_id,
        artifact_root,
    ):
        return False
    try:
        line_start = int(observed.get("line_start", observed.get("line", 0)))
        line_end = int(observed.get("line_end", observed.get("line", 0)))
        expected_line = int(expected.get("line", 0))
    except (TypeError, ValueError):
        return False
    return line_start <= expected_line <= line_end


def _dedupe_locations(locations: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for location in locations:
        key = (
            str(location.get("path", "")).replace("\\", "/").casefold(),
            int(location.get("line", 0)),
            str(location.get("context", "")).casefold(),
        )
        if key not in seen:
            seen.add(key)
            result.append(location)
    return result


def command_score_v2(args: argparse.Namespace) -> int:
    pilot_root = args.pilot_root.resolve()
    blind_root = pilot_root / "blind"
    private_root = pilot_root / "private"
    review_lock_path = private_root / "review_lock_v2.json"
    if not review_lock_path.is_file():
        raise FileNotFoundError("lock v2 reviews before scoring")
    review_lock = read_json(review_lock_path)
    for eval_id, expected_hash in review_lock.get("reviews", {}).items():
        actual_hash = sha256_file(blind_root / "reviews_v2" / f"{eval_id}.json")
        if actual_hash != expected_hash:
            raise ValueError(f"v2 review changed after lock: {eval_id}")
    findings_path = blind_root / "scan" / "findings.json"
    if sha256_file(findings_path) != review_lock.get("findings_sha256"):
        raise ValueError("scan findings changed after v2 review lock")

    case_map = read_json(private_root / "case_map.json")
    manifest_by_id = {
        record["case_id"]: record for record in read_jsonl(BENCHMARK_ROOT / "manifest.jsonl")
    }
    findings = read_json(findings_path)
    findings_by_eval: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        findings_by_eval[str(finding.get("plugin", ""))].append(finding)

    scored: list[dict[str, Any]] = []
    for mapping in case_map["cases"]:
        eval_id = mapping["eval_id"]
        review = read_json(blind_root / "reviews_v2" / f"{eval_id}.json")
        _validate_review_v2(review, eval_id)
        expected = manifest_by_id[mapping["case_id"]]
        expected_sinks = _dedupe_locations(
            [expected["ground_truth"]["sink"]]
            + list(expected["ground_truth"].get("additional_sinks", []))
        )

        matched_findings: list[dict[str, Any]] = []
        for finding in findings_by_eval.get(eval_id, []):
            observed = {
                "path": finding.get("file"),
                "line_start": finding.get("line"),
                "line_end": finding.get("line"),
            }
            if any(_range_location_matches(observed, sink, eval_id) for sink in expected_sinks):
                matched_findings.append(finding)
        best_global = min((int(item["global_rank"]) for item in matched_findings), default=None)
        best_plugin = min((int(item["plugin_rank"]) for item in matched_findings), default=None)

        source_match = any(
            _range_location_matches(location, expected["ground_truth"]["source"], eval_id)
            for location in review["source_locations"]
        )
        sink_match = any(
            _range_location_matches(location, sink, eval_id)
            for location in review["sink_locations"]
            for sink in expected_sinks
        )
        selected_ranks = {int(value) for value in review["selected_finding_global_ranks"]}
        selected_ground_truth_finding = any(
            int(item["global_rank"]) in selected_ranks for item in matched_findings
        )
        scored.append(
            {
                "eval_id": eval_id,
                "case_id": mapping["case_id"],
                "scanner_ground_truth_sink_hit": bool(matched_findings),
                "best_global_rank": best_global,
                "best_plugin_rank": best_plugin,
                "scanner_ranked_ground_truth_first_in_plugin": best_plugin == 1,
                "reviewer_source_range_match": source_match,
                "reviewer_sink_range_match": sink_match,
                "reviewer_trace_range_match": source_match and sink_match,
                "reviewer_selected_ground_truth_finding": selected_ground_truth_finding,
                "reviewer_verdict": review["verdict"],
                "reviewer_positive_verdict": review["verdict"]
                in {"likely_vulnerable", "possible_vulnerability"},
                "implementation_fit": expected["implementation_fit"],
            }
        )

    summary = {
        "schema_version": "blind-pilot-score-v2",
        "case_count": len(scored),
        "location_policy": "exact-normalized-path-and-tight-line-range-v2",
        "scanner_ground_truth_sink_hit_count": sum(
            item["scanner_ground_truth_sink_hit"] for item in scored
        ),
        "scanner_ranked_ground_truth_first_in_plugin_count": sum(
            item["scanner_ranked_ground_truth_first_in_plugin"] for item in scored
        ),
        "reviewer_trace_range_match_count": sum(
            item["reviewer_trace_range_match"] for item in scored
        ),
        "reviewer_selected_ground_truth_finding_count": sum(
            item["reviewer_selected_ground_truth_finding"] for item in scored
        ),
        "reviewer_positive_verdict_count": sum(
            item["reviewer_positive_verdict"] for item in scored
        ),
        "cases": scored,
    }
    output_path = private_root / "scored_results_v2.json"
    if output_path.exists():
        raise FileExistsError(f"v2 score output already exists; refusing overwrite: {output_path}")
    write_json(output_path, summary)
    write_json(
        private_root / "score_lock_v2.json",
        {
            "scored_results_sha256": sha256_file(output_path),
            "review_lock_sha256": sha256_file(review_lock_path),
            "scan_findings_sha256": sha256_file(findings_path),
        },
    )
    print(
        "PASS "
        f"scored_v2={len(scored)} "
        f"scanner_hits={summary['scanner_ground_truth_sink_hit_count']} "
        f"trace_matches={summary['reviewer_trace_range_match_count']}"
    )
    return 0


_GENERIC_EXPRESSION_TOKENS = {
    "class",
    "div",
    "echo",
    "else",
    "function",
    "get_option",
    "html",
    "href",
    "input",
    "name",
    "php",
    "return",
    "script",
    "span",
    "src",
    "style",
    "text",
    "type",
    "value",
    "var",
}


def _expression_tokens(text: str) -> set[str]:
    return {
        token.casefold()
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text)
        if token.casefold() not in _GENERIC_EXPRESSION_TOKENS
    }


def _review_evidence_matches_expected(
    observed: dict[str, Any],
    expected: dict[str, Any],
    eval_id: str,
    artifact_root: str | None = None,
) -> bool:
    if not _range_location_matches(observed, expected, eval_id, artifact_root):
        return False
    expected_tokens = _expression_tokens(str(expected.get("expression", "")))
    observed_tokens = _expression_tokens(str(observed.get("expression", "")))
    if expected_tokens:
        return bool(expected_tokens.intersection(observed_tokens))
    return _normalized_code(str(expected.get("expression", ""))) in _normalized_code(
        str(observed.get("expression", ""))
    )


def _scanner_finding_matches_expected(
    finding: dict[str, Any], expected: dict[str, Any], eval_id: str
) -> bool:
    if not _exact_relative_path_matches(
        str(finding.get("file", "")), str(expected.get("path", "")), eval_id
    ):
        return False
    try:
        if int(finding.get("line", 0)) == int(expected.get("line", 0)):
            return True
    except (TypeError, ValueError):
        return False
    expression = _normalized_code(str(expected.get("expression", "")))
    snippet = _normalized_code(str(finding.get("snippet", "")))
    return bool(expression) and expression in snippet


def _scanner_statement_matches_expected(
    finding: dict[str, Any],
    expected: dict[str, Any],
    eval_id: str,
    blind_root: Path,
) -> bool:
    if not _exact_relative_path_matches(
        str(finding.get("file", "")), str(expected.get("path", "")), eval_id
    ):
        return False
    try:
        finding_line = int(finding.get("line", 0))
        expected_line = int(expected.get("line", 0))
    except (TypeError, ValueError):
        return False
    if finding_line == expected_line:
        return True
    source_path = blind_root / "sources" / Path(
        *PurePosixPath(str(finding.get("file", "")).replace("\\", "/")).parts
    )
    if not source_path.is_file():
        return False
    sys.path.insert(0, str(V111_ROOT))
    from scanner.taint_engine import _iter_statements  # pylint: disable=import-outside-toplevel

    expression = _normalized_code(str(expected.get("expression", "")))
    if not expression:
        return False
    text = _read_source_text(source_path)
    for statement in _iter_statements(text):
        if statement.start_line <= finding_line <= statement.end_line:
            if expression in _normalized_code(statement.text):
                return True
    return False


def _scanner_statement_span_matches_expected(
    finding: dict[str, Any],
    expected: dict[str, Any],
    eval_id: str,
    blind_root: Path,
    artifact_root: str | None = None,
) -> bool:
    """Match the scanner's own analysis statement to the manifest sink line."""
    if not _exact_relative_path_matches(
        str(finding.get("file", "")),
        str(expected.get("path", "")),
        eval_id,
        artifact_root,
    ):
        return False
    try:
        finding_line = int(finding.get("line", 0))
        expected_line = int(expected.get("line", 0))
    except (TypeError, ValueError):
        return False
    source_path = blind_root / "sources" / Path(
        *PurePosixPath(str(finding.get("file", "")).replace("\\", "/")).parts
    )
    if not source_path.is_file():
        return False
    sys.path.insert(0, str(V111_ROOT))
    from scanner.taint_engine import _iter_statements  # pylint: disable=import-outside-toplevel

    for statement in _iter_statements(_read_source_text(source_path)):
        if statement.start_line <= finding_line <= statement.end_line:
            if statement.start_line <= expected_line <= statement.end_line:
                return True
    return finding_line == expected_line


def _build_scanner_only_score(
    case_map: dict[str, Any],
    manifest_by_id: dict[str, dict[str, Any]],
    findings: list[dict[str, Any]],
    blind_root: Path,
) -> dict[str, Any]:
    """Score a new scanner snapshot without reusing or exposing LLM reviews."""
    findings_by_eval: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        findings_by_eval[str(finding.get("plugin", ""))].append(finding)

    scored: list[dict[str, Any]] = []
    for mapping in case_map["cases"]:
        eval_id = mapping["eval_id"]
        expected = manifest_by_id[mapping["case_id"]]
        expected_sinks = _dedupe_locations(
            [expected["ground_truth"]["sink"]]
            + list(expected["ground_truth"].get("additional_sinks", []))
        )
        matched_findings = [
            finding
            for finding in findings_by_eval.get(eval_id, [])
            if any(
                _scanner_statement_span_matches_expected(
                    finding,
                    sink,
                    eval_id,
                    blind_root,
                    mapping.get("artifact_root"),
                )
                for sink in expected_sinks
            )
        ]
        best_global = min(
            (int(item["global_rank"]) for item in matched_findings), default=None
        )
        best_plugin = min(
            (int(item["plugin_rank"]) for item in matched_findings), default=None
        )
        scored.append(
            {
                "eval_id": eval_id,
                "case_id": mapping["case_id"],
                "scanner_ground_truth_sink_hit": bool(matched_findings),
                "best_global_rank": best_global,
                "best_plugin_rank": best_plugin,
                "scanner_ranked_ground_truth_first_in_plugin": best_plugin == 1,
            }
        )

    ranks = [item["best_plugin_rank"] for item in scored if item["best_plugin_rank"]]
    return {
        "schema_version": "blind-scanner-score-v1",
        "case_count": len(scored),
        "scanner_location_policy": "exact-normalized-path-plus-overlap-of-reconstructed-scanner-statement-and-manifest-sink-line",
        "scanner_ground_truth_sink_hit_count": sum(
            item["scanner_ground_truth_sink_hit"] for item in scored
        ),
        "scanner_ranked_ground_truth_first_in_plugin_count": sum(
            item["scanner_ranked_ground_truth_first_in_plugin"] for item in scored
        ),
        "plugin_rank_counts": {
            "top_1": sum(rank <= 1 for rank in ranks),
            "top_3": sum(rank <= 3 for rank in ranks),
            "top_5": sum(rank <= 5 for rank in ranks),
            "top_10": sum(rank <= 10 for rank in ranks),
            "top_20": sum(rank <= 20 for rank in ranks),
            "top_50": sum(rank <= 50 for rank in ranks),
        },
        "cases": scored,
    }


def command_score_scanner(args: argparse.Namespace) -> int:
    """Score scanner-only iterations after scan, without an LLM review stage."""
    pilot_root = args.pilot_root.resolve()
    blind_root = pilot_root / "blind"
    private_root = pilot_root / "private"
    findings_path = blind_root / "scan" / "findings.json"
    scan_lock_path = blind_root / "scan" / "lock.json"
    output_path = private_root / "scanner_score_v1.json"
    if output_path.exists():
        raise FileExistsError(
            f"scanner score output already exists; refusing overwrite: {output_path}"
        )
    if not findings_path.is_file() or not scan_lock_path.is_file():
        raise FileNotFoundError("run prepare and scan before scanner-only scoring")
    scan_lock = read_json(scan_lock_path)
    if sha256_file(findings_path) != scan_lock.get("findings_sha256"):
        raise ValueError("scan findings changed after scan lock")

    case_map = read_json(private_root / "case_map.json")
    manifest_by_id = {
        record["case_id"]: record
        for record in read_jsonl(BENCHMARK_ROOT / "manifest.jsonl")
    }
    summary = _build_scanner_only_score(
        case_map, manifest_by_id, read_json(findings_path), blind_root
    )
    write_json(output_path, summary)
    write_json(
        private_root / "scanner_score_lock_v1.json",
        {
            "scanner_score_sha256": sha256_file(output_path),
            "scan_findings_sha256": sha256_file(findings_path),
            "scorer_sha256": sha256_file(Path(__file__).resolve()),
        },
    )
    print(
        "PASS "
        f"scanner_scored={summary['case_count']} "
        f"scanner_hits={summary['scanner_ground_truth_sink_hit_count']} "
        f"rank1={summary['scanner_ranked_ground_truth_first_in_plugin_count']}"
    )
    return 0


def command_score_v3(args: argparse.Namespace) -> int:
    """Production-candidate scorer using expression-aware statement matching."""
    pilot_root = args.pilot_root.resolve()
    blind_root = pilot_root / "blind"
    private_root = pilot_root / "private"
    review_lock_path = private_root / "review_lock_v2.json"
    if not review_lock_path.is_file():
        raise FileNotFoundError("lock v2 reviews before v3 scoring")
    review_lock = read_json(review_lock_path)
    for eval_id, expected_hash in review_lock.get("reviews", {}).items():
        if sha256_file(blind_root / "reviews_v2" / f"{eval_id}.json") != expected_hash:
            raise ValueError(f"v2 review changed after lock: {eval_id}")
    findings_path = blind_root / "scan" / "findings.json"
    if sha256_file(findings_path) != review_lock.get("findings_sha256"):
        raise ValueError("scan findings changed after v2 review lock")

    case_map = read_json(private_root / "case_map.json")
    manifest_by_id = {
        record["case_id"]: record for record in read_jsonl(BENCHMARK_ROOT / "manifest.jsonl")
    }
    findings = read_json(findings_path)
    findings_by_eval: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        findings_by_eval[str(finding.get("plugin", ""))].append(finding)

    scored: list[dict[str, Any]] = []
    for mapping in case_map["cases"]:
        eval_id = mapping["eval_id"]
        review = read_json(blind_root / "reviews_v2" / f"{eval_id}.json")
        _validate_review_v2(review, eval_id)
        expected = manifest_by_id[mapping["case_id"]]
        expected_sinks = _dedupe_locations(
            [expected["ground_truth"]["sink"]]
            + list(expected["ground_truth"].get("additional_sinks", []))
        )

        matched_findings = [
            finding
            for finding in findings_by_eval.get(eval_id, [])
            if any(
                _scanner_finding_matches_expected(finding, sink, eval_id)
                for sink in expected_sinks
            )
        ]
        best_global = min((int(item["global_rank"]) for item in matched_findings), default=None)
        best_plugin = min((int(item["plugin_rank"]) for item in matched_findings), default=None)
        source_match = any(
            _review_evidence_matches_expected(
                location, expected["ground_truth"]["source"], eval_id
            )
            for location in review["source_locations"]
        )
        sink_match = any(
            _review_evidence_matches_expected(location, sink, eval_id)
            for location in review["sink_locations"]
            for sink in expected_sinks
        )
        selected_ranks = {int(value) for value in review["selected_finding_global_ranks"]}
        selected_ground_truth_finding = any(
            int(item["global_rank"]) in selected_ranks for item in matched_findings
        )
        scored.append(
            {
                "eval_id": eval_id,
                "case_id": mapping["case_id"],
                "scanner_ground_truth_sink_hit": bool(matched_findings),
                "best_global_rank": best_global,
                "best_plugin_rank": best_plugin,
                "scanner_ranked_ground_truth_first_in_plugin": best_plugin == 1,
                "reviewer_source_expression_match": source_match,
                "reviewer_sink_expression_match": sink_match,
                "reviewer_trace_expression_match": source_match and sink_match,
                "reviewer_selected_ground_truth_finding": selected_ground_truth_finding,
                "reviewer_verdict": review["verdict"],
                "reviewer_positive_verdict": review["verdict"]
                in {"likely_vulnerable", "possible_vulnerability"},
                "implementation_fit": expected["implementation_fit"],
            }
        )

    summary = {
        "schema_version": "blind-pilot-score-v3",
        "case_count": len(scored),
        "scanner_location_policy": "exact-normalized-path-plus-exact-line-or-manifest-expression-in-snippet",
        "review_location_policy": "exact-normalized-path-plus-tight-line-range-plus-expression-token-overlap",
        "scanner_ground_truth_sink_hit_count": sum(
            item["scanner_ground_truth_sink_hit"] for item in scored
        ),
        "scanner_ranked_ground_truth_first_in_plugin_count": sum(
            item["scanner_ranked_ground_truth_first_in_plugin"] for item in scored
        ),
        "reviewer_trace_expression_match_count": sum(
            item["reviewer_trace_expression_match"] for item in scored
        ),
        "reviewer_selected_ground_truth_finding_count": sum(
            item["reviewer_selected_ground_truth_finding"] for item in scored
        ),
        "reviewer_positive_verdict_count": sum(
            item["reviewer_positive_verdict"] for item in scored
        ),
        "cases": scored,
    }
    output_path = private_root / "scored_results_v3.json"
    if output_path.exists():
        raise FileExistsError(f"v3 score output already exists; refusing overwrite: {output_path}")
    write_json(output_path, summary)
    write_json(
        private_root / "score_lock_v3.json",
        {
            "scored_results_sha256": sha256_file(output_path),
            "review_lock_sha256": sha256_file(review_lock_path),
            "scan_findings_sha256": sha256_file(findings_path),
        },
    )
    print(
        "PASS "
        f"scored_v3={len(scored)} "
        f"scanner_hits={summary['scanner_ground_truth_sink_hit_count']} "
        f"rank1={summary['scanner_ranked_ground_truth_first_in_plugin_count']} "
        f"trace_matches={summary['reviewer_trace_expression_match_count']}"
    )
    return 0


def command_score_v4(args: argparse.Namespace) -> int:
    """Production-candidate scorer using scanner statement reconstruction."""
    pilot_root = args.pilot_root.resolve()
    blind_root = pilot_root / "blind"
    private_root = pilot_root / "private"
    review_lock_path = private_root / "review_lock_v2.json"
    if not review_lock_path.is_file():
        raise FileNotFoundError("lock v2 reviews before v4 scoring")
    review_lock = read_json(review_lock_path)
    for eval_id, expected_hash in review_lock.get("reviews", {}).items():
        if sha256_file(blind_root / "reviews_v2" / f"{eval_id}.json") != expected_hash:
            raise ValueError(f"v2 review changed after lock: {eval_id}")
    findings_path = blind_root / "scan" / "findings.json"
    if sha256_file(findings_path) != review_lock.get("findings_sha256"):
        raise ValueError("scan findings changed after v2 review lock")

    case_map = read_json(private_root / "case_map.json")
    manifest_by_id = {
        record["case_id"]: record for record in read_jsonl(BENCHMARK_ROOT / "manifest.jsonl")
    }
    findings = read_json(findings_path)
    findings_by_eval: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        findings_by_eval[str(finding.get("plugin", ""))].append(finding)

    scored: list[dict[str, Any]] = []
    for mapping in case_map["cases"]:
        eval_id = mapping["eval_id"]
        review = read_json(blind_root / "reviews_v2" / f"{eval_id}.json")
        _validate_review_v2(review, eval_id)
        expected = manifest_by_id[mapping["case_id"]]
        expected_sinks = _dedupe_locations(
            [expected["ground_truth"]["sink"]]
            + list(expected["ground_truth"].get("additional_sinks", []))
        )
        matched_findings = [
            finding
            for finding in findings_by_eval.get(eval_id, [])
            if any(
                _scanner_statement_matches_expected(
                    finding, sink, eval_id, blind_root
                )
                for sink in expected_sinks
            )
        ]
        best_global = min((int(item["global_rank"]) for item in matched_findings), default=None)
        best_plugin = min((int(item["plugin_rank"]) for item in matched_findings), default=None)
        source_match = any(
            _review_evidence_matches_expected(
                location, expected["ground_truth"]["source"], eval_id
            )
            for location in review["source_locations"]
        )
        sink_match = any(
            _review_evidence_matches_expected(location, sink, eval_id)
            for location in review["sink_locations"]
            for sink in expected_sinks
        )
        selected_ranks = {int(value) for value in review["selected_finding_global_ranks"]}
        selected_ground_truth_finding = any(
            int(item["global_rank"]) in selected_ranks for item in matched_findings
        )
        scored.append(
            {
                "eval_id": eval_id,
                "case_id": mapping["case_id"],
                "scanner_ground_truth_sink_hit": bool(matched_findings),
                "best_global_rank": best_global,
                "best_plugin_rank": best_plugin,
                "scanner_ranked_ground_truth_first_in_plugin": best_plugin == 1,
                "reviewer_source_expression_match": source_match,
                "reviewer_sink_expression_match": sink_match,
                "reviewer_trace_expression_match": source_match and sink_match,
                "reviewer_selected_ground_truth_finding": selected_ground_truth_finding,
                "reviewer_verdict": review["verdict"],
                "reviewer_positive_verdict": review["verdict"]
                in {"likely_vulnerable", "possible_vulnerability"},
                "implementation_fit": expected["implementation_fit"],
            }
        )

    summary = {
        "schema_version": "blind-pilot-score-v4",
        "case_count": len(scored),
        "scanner_location_policy": "exact-normalized-path-plus-exact-line-or-manifest-expression-in-reconstructed-scanner-statement",
        "review_location_policy": "exact-normalized-path-plus-tight-line-range-plus-expression-token-overlap",
        "scanner_ground_truth_sink_hit_count": sum(
            item["scanner_ground_truth_sink_hit"] for item in scored
        ),
        "scanner_ranked_ground_truth_first_in_plugin_count": sum(
            item["scanner_ranked_ground_truth_first_in_plugin"] for item in scored
        ),
        "reviewer_trace_expression_match_count": sum(
            item["reviewer_trace_expression_match"] for item in scored
        ),
        "reviewer_selected_ground_truth_finding_count": sum(
            item["reviewer_selected_ground_truth_finding"] for item in scored
        ),
        "reviewer_positive_verdict_count": sum(
            item["reviewer_positive_verdict"] for item in scored
        ),
        "cases": scored,
    }
    output_path = private_root / "scored_results_v4.json"
    if output_path.exists():
        raise FileExistsError(f"v4 score output already exists; refusing overwrite: {output_path}")
    write_json(output_path, summary)
    write_json(
        private_root / "score_lock_v4.json",
        {
            "scored_results_sha256": sha256_file(output_path),
            "review_lock_sha256": sha256_file(review_lock_path),
            "scan_findings_sha256": sha256_file(findings_path),
            "scorer_sha256": sha256_file(Path(__file__).resolve()),
        },
    )
    print(
        "PASS "
        f"scored_v4={len(scored)} "
        f"scanner_hits={summary['scanner_ground_truth_sink_hit_count']} "
        f"rank1={summary['scanner_ranked_ground_truth_first_in_plugin_count']} "
        f"trace_matches={summary['reviewer_trace_expression_match_count']}"
    )
    return 0


def _selected_review_ranks(review: dict[str, Any], review_version: str) -> set[int]:
    if review_version == "v2":
        return {int(value) for value in review["selected_finding_global_ranks"]}
    if review_version == "v3":
        selected = {int(value) for value in review["secondary_selected_finding_global_ranks"]}
        primary = review["primary_selected_finding_global_rank"]
        if primary is not None:
            selected.add(int(primary))
        return selected
    if review_version in {"v4", "v5"}:
        candidate = review["primary_candidate"]
        selected = {int(value) for value in candidate["supporting_finding_global_ranks"]}
        primary = candidate["finding_global_rank"]
        if primary is not None:
            selected.add(int(primary))
        return selected
    raise ValueError(f"unsupported review version: {review_version}")


def _all_v4_review_ranks(review: dict[str, Any]) -> set[int]:
    selected = _selected_review_ranks(review, "v4")
    for candidate in review["independent_paths"]:
        selected.update(int(value) for value in candidate["supporting_finding_global_ranks"])
        if candidate["finding_global_rank"] is not None:
            selected.add(int(candidate["finding_global_rank"]))
    return selected


def _all_v5_review_ranks(review: dict[str, Any]) -> set[int]:
    selected = _selected_review_ranks(review, "v5")
    for candidate in review["independent_paths"]:
        selected.update(int(value) for value in candidate["supporting_finding_global_ranks"])
        if candidate["finding_global_rank"] is not None:
            selected.add(int(candidate["finding_global_rank"]))
    return selected


def _v4_locations(review: dict[str, Any], kind: str, *, all_paths: bool = False) -> list[dict[str, Any]]:
    candidates = _v4_candidates(review) if all_paths else [review["primary_candidate"]]
    return [
        {
            "path": step["path"],
            "line_start": step["line_start"],
            "line_end": step["line_end"],
            "expression": step["expression"],
        }
        for candidate in candidates
        for step in candidate["trace_steps"]
        if step["kind"] == kind
    ]


def _command_score_latest(
    args: argparse.Namespace, *, review_version: str, score_version: str
) -> int:
    """Score locked v2/v3/v4/v5 reviews with the final statement/expression policy."""
    pilot_root = args.pilot_root.resolve()
    blind_root = pilot_root / "blind"
    private_root = pilot_root / "private"
    review_lock_path = private_root / f"review_lock_{review_version}.json"
    if not review_lock_path.is_file():
        raise FileNotFoundError(
            f"lock {review_version} reviews before {score_version} scoring"
        )
    review_lock = read_json(review_lock_path)
    for eval_id, expected_hash in review_lock.get("reviews", {}).items():
        if sha256_file(
            blind_root / f"reviews_{review_version}" / f"{eval_id}.json"
        ) != expected_hash:
            raise ValueError(f"{review_version} review changed after lock: {eval_id}")
    findings_path = blind_root / "scan" / "findings.json"
    if sha256_file(findings_path) != review_lock.get("findings_sha256"):
        raise ValueError(f"scan findings changed after {review_version} review lock")

    case_map = read_json(private_root / "case_map.json")
    manifest_by_id = {
        record["case_id"]: record for record in read_jsonl(BENCHMARK_ROOT / "manifest.jsonl")
    }
    findings = read_json(findings_path)
    findings_by_eval: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        findings_by_eval[str(finding.get("plugin", ""))].append(finding)
    scored: list[dict[str, Any]] = []
    for mapping in case_map["cases"]:
        eval_id = mapping["eval_id"]
        review = read_json(
            blind_root / f"reviews_{review_version}" / f"{eval_id}.json"
        )
        if review_version == "v2":
            _validate_review_v2(review, eval_id)
        elif review_version == "v3":
            _validate_review_v3(review, eval_id)
        elif review_version == "v4":
            validate_review_v4_shape(review, eval_id)
        elif review_version == "v5":
            validate_review_v5_shape(review, eval_id)
        else:
            raise ValueError(f"unsupported review version: {review_version}")
        expected = manifest_by_id[mapping["case_id"]]
        expected_sinks = _dedupe_locations(
            [expected["ground_truth"]["sink"]]
            + list(expected["ground_truth"].get("additional_sinks", []))
        )
        matched_findings = [
            finding
            for finding in findings_by_eval.get(eval_id, [])
            if any(
                _scanner_statement_span_matches_expected(
                    finding,
                    sink,
                    eval_id,
                    blind_root,
                    mapping.get("artifact_root"),
                )
                for sink in expected_sinks
            )
        ]
        best_global = min((int(item["global_rank"]) for item in matched_findings), default=None)
        best_plugin = min((int(item["plugin_rank"]) for item in matched_findings), default=None)
        source_locations = (
            _v4_locations(review, "source") if review_version in {"v4", "v5"}
            else review["source_locations"]
        )
        sink_locations = (
            _v4_locations(review, "sink") if review_version in {"v4", "v5"}
            else review["sink_locations"]
        )
        source_match = any(
            _review_evidence_matches_expected(
                location,
                expected["ground_truth"]["source"],
                eval_id,
                mapping.get("artifact_root"),
            )
            for location in source_locations
        )
        sink_match = any(
            _review_evidence_matches_expected(
                location, sink, eval_id, mapping.get("artifact_root")
            )
            for location in sink_locations
            for sink in expected_sinks
        )
        selected_ranks = _selected_review_ranks(review, review_version)
        all_selected_ranks = (
            _all_v4_review_ranks(review)
            if review_version == "v4"
            else _all_v5_review_ranks(review)
            if review_version == "v5"
            else selected_ranks
        )
        selected_ground_truth_finding = any(
            int(item["global_rank"]) in selected_ranks for item in matched_findings
        )
        any_path_selected_ground_truth_finding = any(
            int(item["global_rank"]) in all_selected_ranks for item in matched_findings
        )
        verdict = (
            review["primary_candidate"]["verdict"]
            if review_version in {"v4", "v5"} else review["verdict"]
        )
        case_result = {
            "eval_id": eval_id,
            "case_id": mapping["case_id"],
            "scanner_ground_truth_sink_hit": bool(matched_findings),
            "best_global_rank": best_global,
            "best_plugin_rank": best_plugin,
            "scanner_ranked_ground_truth_first_in_plugin": best_plugin == 1,
            "reviewer_source_expression_match": source_match,
            "reviewer_sink_expression_match": sink_match,
            "reviewer_trace_expression_match": source_match and sink_match,
            "reviewer_selected_ground_truth_finding": selected_ground_truth_finding,
            "reviewer_verdict": verdict,
            "reviewer_positive_verdict": verdict
            in {"likely_vulnerable", "possible_vulnerability"},
            "implementation_fit": expected["implementation_fit"],
        }
        if review_version in {"v4", "v5"}:
            case_result["reviewer_any_path_selected_ground_truth_finding"] = (
                any_path_selected_ground_truth_finding
            )
        scored.append(case_result)
    summary = {
        "schema_version": f"blind-pilot-score-{score_version}",
        "case_count": len(scored),
        "scanner_location_policy": "exact-normalized-path-plus-overlap-of-reconstructed-scanner-statement-and-manifest-sink-line",
        "review_location_policy": "exact-normalized-path-plus-tight-line-range-plus-expression-token-overlap",
        "scanner_ground_truth_sink_hit_count": sum(
            item["scanner_ground_truth_sink_hit"] for item in scored
        ),
        "scanner_ranked_ground_truth_first_in_plugin_count": sum(
            item["scanner_ranked_ground_truth_first_in_plugin"] for item in scored
        ),
        "reviewer_trace_expression_match_count": sum(
            item["reviewer_trace_expression_match"] for item in scored
        ),
        "reviewer_selected_ground_truth_finding_count": sum(
            item["reviewer_selected_ground_truth_finding"] for item in scored
        ),
        "reviewer_positive_verdict_count": sum(
            item["reviewer_positive_verdict"] for item in scored
        ),
        "cases": scored,
    }
    if review_version in {"v4", "v5"}:
        summary["reviewer_any_path_selected_ground_truth_finding_count"] = sum(
            item["reviewer_any_path_selected_ground_truth_finding"] for item in scored
        )
    output_path = private_root / f"scored_results_{score_version}.json"
    if output_path.exists():
        raise FileExistsError(
            f"{score_version} score output already exists; refusing overwrite: {output_path}"
        )
    write_json(output_path, summary)
    write_json(
        private_root / f"score_lock_{score_version}.json",
        {
            "scored_results_sha256": sha256_file(output_path),
            "review_lock_sha256": sha256_file(review_lock_path),
            "scan_findings_sha256": sha256_file(findings_path),
            "scorer_sha256": sha256_file(Path(__file__).resolve()),
        },
    )
    print(
        "PASS "
        f"scored_{score_version}={len(scored)} "
        f"scanner_hits={summary['scanner_ground_truth_sink_hit_count']} "
        f"rank1={summary['scanner_ranked_ground_truth_first_in_plugin_count']} "
        f"trace_matches={summary['reviewer_trace_expression_match_count']}"
    )
    return 0


def command_score_v5(args: argparse.Namespace) -> int:
    """Final v2 pilot scorer: scanner statement spans plus reviewer evidence."""
    return _command_score_latest(args, review_version="v2", score_version="v5")


def command_score_v6(args: argparse.Namespace) -> int:
    """Final v3 pilot scorer with the same location policy as score-v5."""
    return _command_score_latest(args, review_version="v3", score_version="v6")


def command_score_v7(args: argparse.Namespace) -> int:
    """Score deterministic primary-candidate v4 reviews and report independent ranks separately."""
    return _command_score_latest(args, review_version="v4", score_version="v7")


def command_score_v8(args: argparse.Namespace) -> int:
    """Score identity-locked v5 reviews and report independent ranks separately."""
    return _command_score_latest(args, review_version="v5", score_version="v8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pilot-root", type=Path, default=DEFAULT_PILOT_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="prepare opaque source trees")
    prepare.add_argument("--count", type=int, default=20)
    prepare.set_defaults(func=command_prepare)

    scan = subparsers.add_parser("scan", help="run scanner on opaque source trees")
    scan.set_defaults(func=command_scan)

    bundle = subparsers.add_parser("bundle", help="build blind review bundles")
    bundle.set_defaults(func=command_bundle)

    bundle_v2 = subparsers.add_parser(
        "bundle-v2", help="build strict line-range blind review bundles"
    )
    bundle_v2.set_defaults(func=command_bundle_v2)

    bundle_v3 = subparsers.add_parser(
        "bundle-v3", help="build drift-resistant blind review bundles"
    )
    bundle_v3.set_defaults(func=command_bundle_v3)

    bundle_v4 = subparsers.add_parser(
        "bundle-v4", help="build deterministic evidence-link blind review bundles"
    )
    bundle_v4.set_defaults(func=command_bundle_v4)

    bundle_v5 = subparsers.add_parser(
        "bundle-v5", help="build identity-locked blind review bundles"
    )
    bundle_v5.set_defaults(func=command_bundle_v5)

    reuse_v2 = subparsers.add_parser(
        "reuse-reviews-v2", help="reuse locked blind v2 reviews by source/finding fingerprint"
    )
    reuse_v2.add_argument("--from-pilot-root", type=Path, required=True)
    reuse_v2.add_argument("--count", type=int, default=0)
    reuse_v2.set_defaults(func=command_reuse_reviews_v2)

    validate = subparsers.add_parser("validate-blind", help="check generated metadata for leaks")
    validate.set_defaults(func=command_validate_blind)

    lock_reviews = subparsers.add_parser(
        "lock-reviews", help="validate and lock blind review outputs before scoring"
    )
    lock_reviews.set_defaults(func=command_lock_reviews)

    lock_reviews_v2 = subparsers.add_parser(
        "lock-reviews-v2", help="validate and lock v2 review outputs before scoring"
    )
    lock_reviews_v2.set_defaults(func=command_lock_reviews_v2)

    lock_reviews_v3 = subparsers.add_parser(
        "lock-reviews-v3", help="validate and lock drift-resistant v3 reviews"
    )
    lock_reviews_v3.set_defaults(func=command_lock_reviews_v3)

    lock_reviews_v4 = subparsers.add_parser(
        "lock-reviews-v4", help="derive, validate, and lock evidence-link v4 reviews"
    )
    lock_reviews_v4.set_defaults(func=command_lock_reviews_v4)

    lock_reviews_v5 = subparsers.add_parser(
        "lock-reviews-v5", help="derive, validate, and lock identity-bound v5 reviews"
    )
    lock_reviews_v5.set_defaults(func=command_lock_reviews_v5)

    score = subparsers.add_parser("score", help="compare locked reviews with hidden ground truth")
    score.add_argument("--line-tolerance", type=int, default=3)
    score.set_defaults(func=command_score)

    score_v2 = subparsers.add_parser("score-v2", help="score strict line-range v2 reviews")
    score_v2.set_defaults(func=command_score_v2)

    score_v3 = subparsers.add_parser(
        "score-v3", help="score v2 reviews with expression-aware production-candidate matching"
    )
    score_v3.set_defaults(func=command_score_v3)

    score_v4 = subparsers.add_parser(
        "score-v4", help="score v2 reviews with reconstructed scanner statements"
    )
    score_v4.set_defaults(func=command_score_v4)

    score_v5 = subparsers.add_parser(
        "score-v5", help="final pilot scorer using scanner statement-span overlap"
    )
    score_v5.set_defaults(func=command_score_v5)

    score_v6 = subparsers.add_parser(
        "score-v6", help="score drift-resistant v3 reviews with the final location policy"
    )
    score_v6.set_defaults(func=command_score_v6)

    score_v7 = subparsers.add_parser(
        "score-v7", help="score deterministic primary-candidate v4 reviews"
    )
    score_v7.set_defaults(func=command_score_v7)

    score_v8 = subparsers.add_parser(
        "score-v8", help="score identity-locked primary-candidate v5 reviews"
    )
    score_v8.set_defaults(func=command_score_v8)

    score_scanner = subparsers.add_parser(
        "score-scanner",
        help="score a scanner-only iteration without exposing ground truth to an LLM",
    )
    score_scanner.set_defaults(func=command_score_scanner)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (FileExistsError, FileNotFoundError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
