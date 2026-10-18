from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


WORK_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = WORK_ROOT / "review" / "scripts" / "build_finding_evaluation_dataset.py"
spec = importlib.util.spec_from_file_location("finding_evaluation_dataset", SCRIPT)
assert spec and spec.loader
dataset = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = dataset
spec.loader.exec_module(dataset)


class FindingEvaluationDatasetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.review_root = self.root / "review"
        (self.review_root / "results").mkdir(parents=True)
        self.queue = self.root / "queue.jsonl"
        self.output = self.root / "labels.jsonl"
        self.summary = self.root / "summary.json"
        self.finding = {
            "finding_id": "0123456789abcdef0123",
            "type": "XSS",
            "sink_kind": "echo",
            "sink_match": "echo",
            "snippet": "echo esc_html($value);",
        }
        self.queue_row = {
            "campaign": "test",
            "queue_rank": 1,
            "plugin": "example",
            "plugin_fingerprint": "1" * 64,
            "selected_findings_fingerprint": "2" * 64,
            "selected_finding_count": 1,
            "findings": [self.finding],
            "review": {"status": "reviewed", "report_path": "results/example.json"},
        }
        self.report = {
            "review_schema_version": 2,
            "plugin": "example",
            "plugin_fingerprint": "1" * 64,
            "selected_findings_fingerprint": "2" * 64,
            "finding_ids": ["0123456789abcdef0123"],
            "reviewed_at": "2026-08-31",
            "verdict": "likely_false_positive",
            "reviewer_confidence": "high",
            "selected_finding_assessment": [{
                "finding_ids": ["0123456789abcdef0123"],
                "verdict": "likely_false_positive",
                "reason": "The value is correctly escaped with esc_html().",
                "citations": [],
            }],
            "scanner_feedback": [],
        }
        self.write_inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_inputs(self) -> None:
        self.queue.write_text(json.dumps(self.queue_row) + "\n", encoding="utf-8")
        (self.review_root / "results" / "example.json").write_text(
            json.dumps(self.report), encoding="utf-8"
        )

    def test_build_and_validate_exact_finding_coverage(self) -> None:
        records = dataset.build_records(self.queue, self.review_root)
        self.assertEqual(1, len(records))
        self.assertEqual("likely_false_positive", records[0]["assessment_verdict"])
        self.assertIn("context_correct_escape", records[0]["reason_tags"])
        dataset.write_dataset(records, self.output, self.summary)
        result = dataset.validate_dataset(
            self.queue, self.review_root, self.output, self.summary
        )
        self.assertEqual(1, result["finding_count"])
        self.assertEqual(1, result["plugin_count"])

    def test_rejects_duplicate_assessment_coverage(self) -> None:
        self.report["selected_finding_assessment"].append(
            dict(self.report["selected_finding_assessment"][0])
        )
        self.write_inputs()
        with self.assertRaisesRegex(ValueError, "duplicate assessed finding"):
            dataset.build_records(self.queue, self.review_root)

    def test_rejects_report_binding_mismatch(self) -> None:
        self.report["plugin_fingerprint"] = "0" * 64
        self.write_inputs()
        with self.assertRaisesRegex(ValueError, "plugin_fingerprint"):
            dataset.build_records(self.queue, self.review_root)

    def test_collapses_only_identical_duplicate_queue_rows(self) -> None:
        self.queue_row["findings"].append(dict(self.finding))
        self.queue_row["selected_finding_count"] = 2
        self.write_inputs()
        records = dataset.build_records(self.queue, self.review_root)
        self.assertEqual(1, len(records))
        self.assertEqual(2, records[0]["queue_occurrence_count"])

        self.queue_row["findings"][1]["snippet"] = "different"
        self.write_inputs()
        with self.assertRaisesRegex(ValueError, "conflicting queue rows"):
            dataset.build_records(self.queue, self.review_root)

    def test_validator_detects_dataset_tampering(self) -> None:
        records = dataset.build_records(self.queue, self.review_root)
        dataset.write_dataset(records, self.output, self.summary)
        changed = json.loads(self.output.read_text(encoding="utf-8"))
        changed["assessment_verdict"] = "likely_vulnerable"
        self.output.write_text(json.dumps(changed) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not exactly match"):
            dataset.validate_dataset(
                self.queue, self.review_root, self.output, self.summary
            )


if __name__ == "__main__":
    unittest.main()
