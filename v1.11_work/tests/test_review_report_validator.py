"""Tests for strict v2 review-report validation and queue attachment."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".agents" / "skills" / "review-wp-vulnerability-candidates" / "scripts"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


VALIDATOR = load_module("validate_review_report", SCRIPTS / "validate_review_report.py")
QUEUE = load_module("build_review_queue", SCRIPTS / "build_review_queue.py")
RECORD = load_module("record_review_strict", SCRIPTS / "record_review.py")


class ReviewReportValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plugin = self.root / "plugins" / "example"
        self.plugin.mkdir(parents=True)
        self.source = self.plugin / "main.php"
        self.source.write_text("<?php\n// Version: 1.0.0\n$input = $_GET['q'];\necho $input;\n", encoding="utf-8")
        self.queue_path = self.root / "queue.jsonl"
        self.report_path = self.root / "report.json"
        self.queue_record = {
            "plugin": "example",
            "plugin_path": str(self.plugin),
            "plugin_fingerprint": QUEUE.source_inventory(self.plugin)["plugin_fingerprint"],
            "selected_findings_fingerprint": "2" * 64,
            "finding_count": 3,
            "selected_finding_count": 3,
            "findings": [
                {"finding_id": "0123456789abcdef0123"},
                {"finding_id": "abcdef0123456789abcd"},
                {"finding_id": "0123456789abcdef0123"},
            ],
            "review": {"status": "pending"},
        }
        self.write_queue()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_queue(self, raw: str | None = None) -> None:
        self.queue_path.write_text(
            raw if raw is not None else json.dumps(self.queue_record) + "\n", encoding="utf-8"
        )

    def report(self) -> dict[str, object]:
        citation = {"file": "main.php", "start_line": 3, "end_line": 4, "expression": "echo $input;"}
        return {
            "review_schema_version": 2,
            "plugin": "example",
            "version": "1.0.0",
            "version_citation": {"file": "main.php", "start_line": 2, "end_line": 2, "expression": "Version: 1.0.0"},
            "plugin_fingerprint": self.queue_record["plugin_fingerprint"],
            "selected_findings_fingerprint": "2" * 64,
            "finding_ids": ["0123456789abcdef0123", "abcdef0123456789abcd"],
            "reviewed_at": "2026-08-31",
            "verdict": "possible_vulnerability",
            "reviewer_confidence": "medium",
            "summary": "The claim has exact source citations.",
            "review_scope": {
                "unit": "plugin",
                "passes": ["sink-storage-led", "scanner-guided", "entrypoint-led"],
                "selected_finding_count": 3,
                "total_finding_count": 3,
                "runtime_poc_run": False,
                "scanner_run": False,
                "scanner_modified": False,
            },
            "scanner_claim": {
                "implementation": ["scanner finding"],
                "proved": ["source was selected"],
                "inferred_incorrectly": ["reachability needs source review"],
            },
            "selected_finding_assessment": [
                {"finding_ids": ["0123456789abcdef0123"], "verdict": "possible_vulnerability", "reason": "Path reaches output.", "citations": [citation]},
                {"finding_ids": ["abcdef0123456789abcd"], "verdict": "likely_false_positive", "reason": "Second finding shares the same trace.", "citations": [citation]},
            ],
            "source_to_sink_trace": [
                {"stage": "source", "conclusion": "Request value is assigned.", "citations": [{"file": "main.php", "start_line": 3, "end_line": 3, "expression": "$_GET['q']"}]},
                {"stage": "sink", "conclusion": "Value is sent to HTML output.", "citations": [citation]},
            ],
            "exposure": {
                "entrypoint": "public request handler",
                "reachability": "source review required",
                "victim_interaction": "victim loads the output page",
                "minimum_attacker_role": "unauthenticated",
                "output_context": "html_text",
            },
            "defenses_observed": [{"defense": "none", "effect": "No output encoding observed."}],
            "alternate_paths_checked": ["No alternate output path found."],
            "unresolved_assumptions": [],
            "scanner_feedback": [{"category": "correct_detection", "detail": "The source and output are both present."}],
            "next_safe_verification": "Use only an authorized local runtime target.",
            "authoritative_sources": [{"consulted_at": "2026-08-31", "title": "WordPress security", "url": "https://developer.wordpress.org/apis/security/", "relevance": "Output escaping guidance."}],
        }

    def write_report(self, report: dict[str, object] | None = None, raw: str | None = None) -> None:
        self.report_path.write_text(raw if raw is not None else json.dumps(report or self.report()), encoding="utf-8")

    def assert_rejected(self, mutate) -> None:
        report = self.report()
        mutate(report)
        self.write_report(report)
        with self.assertRaises(ValueError):
            VALIDATOR.validate_review_report(self.queue_path, self.report_path)

    def test_valid_report_accepts_and_cli_json_is_machine_readable(self) -> None:
        self.write_report()
        report, records, record = VALIDATOR.validate_review_report(self.queue_path, self.report_path)
        self.assertEqual("example", report["plugin"])
        self.assertEqual(1, len(records))
        self.assertIs(record, records[0])
        with patch.object(sys, "argv", ["validator", "--queue", str(self.queue_path), "--report", str(self.report_path), "--json"]), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(0, VALIDATOR.main())
        self.assertEqual({"plugin": "example", "review_schema_version": 2, "status": "valid"}, json.loads(output.getvalue()))

    def test_legacy_source_bytes_preserve_exact_citation_validation(self) -> None:
        self.source.write_bytes(
            b"<?php\n// Version: 1.0.0\n// legacy byte: \xfc\n$input = $_GET['q'];\necho $input;\n"
        )
        self.queue_record["plugin_fingerprint"] = QUEUE.source_inventory(self.plugin)["plugin_fingerprint"]
        self.write_queue()
        report = self.report()
        report["selected_finding_assessment"][0]["citations"][0].update(
            start_line=4, end_line=5
        )
        report["selected_finding_assessment"][1]["citations"][0].update(
            start_line=4, end_line=5
        )
        report["source_to_sink_trace"][0]["citations"][0].update(
            start_line=4, end_line=4
        )
        report["source_to_sink_trace"][1]["citations"][0].update(
            start_line=4, end_line=5
        )
        self.write_report(report)

        validated, _, _ = VALIDATOR.validate_review_report(
            self.queue_path, self.report_path
        )
        self.assertEqual("example", validated["plugin"])

        report["source_to_sink_trace"][1]["citations"][0]["expression"] = (
            "not in source"
        )
        self.write_report(report)
        with self.assertRaisesRegex(ValueError, "not a literal substring"):
            VALIDATOR.validate_review_report(self.queue_path, self.report_path)

    def test_rejects_current_source_change_even_when_all_citations_still_match(self) -> None:
        self.write_report()
        original_queue = self.queue_path.read_bytes()
        self.source.write_text(
            "<?php\n// Version: 1.0.0\n"
            "$input = $_GET['q']; $input = htmlspecialchars($input);\necho $input;\n",
            encoding="utf-8",
        )
        self.assertNotEqual(
            self.queue_record["plugin_fingerprint"],
            QUEUE.source_inventory(self.plugin)["plugin_fingerprint"],
        )
        with self.assertRaisesRegex(ValueError, "stale review.*current source"):
            VALIDATOR.validate_review_report(self.queue_path, self.report_path)
        with patch.object(sys, "argv", ["record_review", "--queue", str(self.queue_path), "--report", str(self.report_path)]):
            with self.assertRaisesRegex(ValueError, "stale review.*current source"):
                RECORD.main()
        self.assertEqual(original_queue, self.queue_path.read_bytes())

    def test_rejects_changed_module_even_when_report_cites_unchanged_php(self) -> None:
        module = self.plugin / "render.module"
        module.write_text("<?php echo $_GET['q'];\n", encoding="utf-8")
        self.queue_record["plugin_fingerprint"] = QUEUE.source_inventory(self.plugin)["plugin_fingerprint"]
        self.write_queue()
        self.write_report()
        module.write_text("<?php echo htmlspecialchars($_GET['q']);\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "stale review.*current source"):
            VALIDATOR.validate_review_report(self.queue_path, self.report_path)

    def test_rejects_schema_binding_and_finding_integrity_failures(self) -> None:
        for mutate in (
            lambda value: value.update(review_schema_version=1),
            lambda value: value.update(plugin_fingerprint="0" * 64),
            lambda value: value.update(finding_ids=["0123456789abcdef0123"]),
            lambda value: value.update(finding_ids=["0123456789abcdef0123", "0123456789abcdef0123"]),
            lambda value: value["selected_finding_assessment"].__setitem__(1, {"finding_ids": ["0123456789abcdef0123"], "verdict": "likely_false_positive", "reason": "duplicate", "citations": value["selected_finding_assessment"][0]["citations"]}),
        ):
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_rejects_json_ambiguity_and_bad_queue_rows(self) -> None:
        self.write_report(raw='{"plugin":"example","plugin":"other"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            VALIDATOR.validate_review_report(self.queue_path, self.report_path)
        self.write_report(raw="NaN")
        with self.assertRaisesRegex(ValueError, "JSON constant"):
            VALIDATOR.validate_review_report(self.queue_path, self.report_path)
        self.write_report()
        self.write_queue(json.dumps(self.queue_record) + "\n\n")
        with self.assertRaisesRegex(ValueError, "blank queue line"):
            VALIDATOR.validate_review_report(self.queue_path, self.report_path)
        self.write_queue(json.dumps(self.queue_record) + "\n" + json.dumps(self.queue_record) + "\n")
        with self.assertRaisesRegex(ValueError, "duplicate queue plugin row"):
            VALIDATOR.validate_review_report(self.queue_path, self.report_path)

    def test_rejects_scope_claim_exposure_and_source_metadata_failures(self) -> None:
        for mutate in (
            lambda value: value["review_scope"].update(runtime_poc_run=True),
            lambda value: value["review_scope"].update(passes=["scanner-guided"]),
            lambda value: value["scanner_claim"].update(proved=[]),
            lambda value: value["exposure"].update(minimum_attacker_role="guest"),
            lambda value: value["authoritative_sources"][0].update(url="file:///local"),
            lambda value: value.update(reviewed_at="2026-02-30"),
            lambda value: value.update(version="1.0"),
            lambda value: value["version_citation"].update(file="main.php", start_line=1, end_line=1, expression="<?php"),
        ):
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_rejects_non_integer_schema_bad_queue_integrity_and_record_overwrite(self) -> None:
        self.assert_rejected(lambda value: value.update(review_schema_version=2.0))

        self.write_report()
        self.queue_record["selected_finding_count"] = 2
        self.write_queue()
        with self.assertRaisesRegex(ValueError, "queue finding counts"):
            VALIDATOR.validate_review_report(self.queue_path, self.report_path)

        self.queue_record["selected_finding_count"] = 3
        self.queue_record["review"] = {"status": "reviewed"}
        self.write_queue()
        VALIDATOR.validate_review_report(self.queue_path, self.report_path)
        original = self.queue_path.read_bytes()
        with patch.object(sys, "argv", ["record_review", "--queue", str(self.queue_path), "--report", str(self.report_path)]):
            with self.assertRaisesRegex(ValueError, "existing reviews are immutable"):
                RECORD.main()
        self.assertEqual(original, self.queue_path.read_bytes())

    def test_rejects_citation_path_range_expression_and_shape(self) -> None:
        def alter(citation: dict[str, object], **changes: object) -> None:
            citation.update(changes)

        for changes in (
            {"file": "../main.php"}, {"file": "C:\\main.php"}, {"start_line": True},
            {"start_line": 1, "end_line": 25}, {"end_line": 99}, {"expression": "not in source"},
        ):
            def mutate(value, changes=changes):
                alter(value["source_to_sink_trace"][0]["citations"][0], **changes)
            with self.subTest(changes=changes):
                self.assert_rejected(mutate)
        self.assert_rejected(lambda value: value["source_to_sink_trace"][0]["citations"][0].update(extra="no"))

    def test_record_review_keeps_queue_unchanged_on_failure_and_attaches_valid_v2(self) -> None:
        invalid = self.report()
        invalid["source_to_sink_trace"] = []
        self.write_report(invalid)
        original = self.queue_path.read_bytes()
        with patch.object(sys, "argv", ["record_review", "--queue", str(self.queue_path), "--report", str(self.report_path)]):
            with self.assertRaises(ValueError):
                RECORD.main()
        self.assertEqual(original, self.queue_path.read_bytes())

        self.write_report()
        with patch.object(sys, "argv", ["record_review", "--queue", str(self.queue_path), "--report", str(self.report_path)]), redirect_stdout(io.StringIO()):
            self.assertEqual(0, RECORD.main())
        attached = json.loads(self.queue_path.read_text(encoding="utf-8"))
        self.assertEqual("reviewed", attached["review"]["status"])
        self.assertEqual("possible_vulnerability", attached["review"]["verdict"])
        self.assertTrue(attached["review_state_preserved"])


if __name__ == "__main__":
    unittest.main()
