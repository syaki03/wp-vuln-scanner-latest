"""Regression tests for the plugin-level review queue campaign selection."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".agents" / "skills" / "review-wp-vulnerability-candidates" / "scripts" / "build_review_queue.py"
SPEC = importlib.util.spec_from_file_location("build_review_queue", SCRIPT)
assert SPEC and SPEC.loader
QUEUE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUEUE)
sys.modules["build_review_queue"] = QUEUE

RECORD_SCRIPT = ROOT / ".agents" / "skills" / "review-wp-vulnerability-candidates" / "scripts" / "record_review.py"
RECORD_SPEC = importlib.util.spec_from_file_location("record_review", RECORD_SCRIPT)
assert RECORD_SPEC and RECORD_SPEC.loader
RECORD = importlib.util.module_from_spec(RECORD_SPEC)
RECORD_SPEC.loader.exec_module(RECORD)


class ReviewQueueBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plugins = self.root / "plugins"
        self.plugins.mkdir()
        self.findings = self.root / "findings.csv"
        self.output = self.root / "queue.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_record_review_uses_relative_path_for_report_beside_queue(self) -> None:
        queue = self.root / "review" / "queue.jsonl"
        report = self.root / "review" / "results" / "plugin.json"
        self.assertEqual("results/plugin.json", RECORD.portable_report_path(report, queue))

        nested_queue = self.root / "review" / "cohorts" / "active500" / "queue.jsonl"
        self.assertEqual(
            "results/plugin.json",
            RECORD.portable_report_path(report, nested_queue),
        )

        outside = self.root / "other" / "plugin.json"
        self.assertEqual(str(outside), RECORD.portable_report_path(outside, queue))

    def row(self, plugin: str, priority: str, *, line: int = 10, flow: str = "same_statement", score: str = "70", file: str | None = None, kind: str = "XSS") -> dict[str, str]:
        path = file or str((self.plugins / plugin / "main.php").resolve())
        return {"plugin": plugin, "file": path, "line": str(line), "type": kind, "severity": "HIGH", "score": score, "confidence": "high", "flow_evidence": flow, "poc_priority": priority, "entrypoint_kind": "hook", "entrypoint_name": "render", "sink_kind": "html_output", "storage_match": ""}

    def write_findings(self, rows: list[dict[str, str]]) -> None:
        for plugin in {row["plugin"] for row in rows}:
            path = self.plugins / plugin
            path.mkdir(exist_ok=True)
            (path / "main.php").write_text("<?php\n", encoding="utf-8")
        with self.findings.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    def args(self, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {"findings": self.findings, "plugin_root": self.plugins, "output": self.output, "prior_review_dir": None, "campaign": "public-high", "severity": "HIGH", "priority": "high_unauthenticated,high_public", "plugin": None, "max_findings_per_plugin": None}
        values.update(overrides)
        return argparse.Namespace(**values)

    def write_prior_report(self, directory: Path, filename_plugin: str, **overrides: object) -> None:
        directory.mkdir(exist_ok=True)
        report: dict[str, object] = {
            "plugin": filename_plugin,
            "plugin_fingerprint": "unused",
            "selected_findings_fingerprint": "unused",
            "verdict": "possible_vulnerability",
            "reviewer_confidence": "medium",
            "reviewed_at": "2026-08-01T00:00:00Z",
        }
        report.update(overrides)
        (directory / f"{filename_plugin}.json").write_text(
            json.dumps(report), encoding="utf-8"
        )

    def test_default_is_backward_compatible_public_high_without_implicit_cap(self) -> None:
        self.write_findings([self.row("public", "high_public"), self.row("ignored", "medium_authenticated")])
        records, summary = QUEUE.build_queue(self.args())
        self.assertEqual(["public"], [record["plugin"] for record in records])
        self.assertEqual("public-high", records[0]["campaign"])
        self.assertEqual("A_public_or_unauthenticated", records[0]["review_band"])
        self.assertEqual(0, records[0]["selection"]["max_findings_per_plugin"])
        self.assertEqual("public-high", summary["campaign"])

    def test_operational_accepts_all_findings_and_defaults_to_twelve(self) -> None:
        rows = [self.row("all", "skip_admin_only", line=index, flow="variable_assignment") for index in range(1, 15)]
        rows.append(self.row("all", "review_unknown", line=20))
        self.write_findings(rows)
        records, summary = QUEUE.build_queue(self.args(campaign="operational-i53"))
        self.assertEqual(15, records[0]["finding_count"])
        self.assertEqual(12, records[0]["selected_finding_count"])
        self.assertEqual(3, records[0]["omitted_finding_count"])
        self.assertEqual([], records[0]["selection"]["severities"])
        self.assertEqual([], records[0]["selection"]["priorities"])
        self.assertEqual(12, records[0]["selection"]["max_findings_per_plugin"])
        self.assertEqual(3, summary["band_counts"]["C_unknown_reachability"]["omitted_findings"])

    def test_operational_bands_are_complete_and_sort_first(self) -> None:
        rows = [self.row("admin", "skip_admin_only"), self.row("unknown", "review_unknown"), self.row("member", "medium_contributor"), self.row("public", "high_public")]
        self.write_findings(rows)
        records, _ = QUEUE.build_queue(self.args(campaign="operational-i53"))
        self.assertEqual(["public", "member", "unknown", "admin"], [record["plugin"] for record in records])
        self.assertEqual(["A_public_or_unauthenticated", "B_low_privilege_or_authenticated", "C_unknown_reachability", "D_admin_only"], [record["review_band"] for record in records])

    def test_operational_respects_an_explicit_maximum(self) -> None:
        self.write_findings([self.row("limited", "high_public", line=index) for index in range(1, 5)])
        records, _ = QUEUE.build_queue(self.args(campaign="operational-i53", max_findings_per_plugin=2))
        self.assertEqual(2, records[0]["selected_finding_count"])
        self.assertEqual(2, records[0]["omitted_finding_count"])

    def test_path_diverse_selection_is_deterministic(self) -> None:
        rows = [self.row("diverse", "high_public", line=1, file=str((self.plugins / "diverse" / "a.php").resolve())), self.row("diverse", "high_public", line=2, file=str((self.plugins / "diverse" / "a.php").resolve())), self.row("diverse", "high_public", line=3, file=str((self.plugins / "diverse" / "b.php").resolve()))]
        self.write_findings(rows)
        args = self.args(campaign="operational-i53", max_findings_per_plugin=2)
        first, _ = QUEUE.build_queue(args)
        second, _ = QUEUE.build_queue(args)
        self.assertEqual([item["line"] for item in first[0]["findings"]], ["1", "3"])
        self.assertEqual(first[0]["findings"], second[0]["findings"])

    def test_prior_review_with_matching_source_and_changed_selection_needs_delta(self) -> None:
        self.write_findings([self.row("delta", "high_public")])
        baseline, _ = QUEUE.build_queue(self.args())
        prior_dir = self.root / "prior"
        self.write_prior_report(
            prior_dir,
            "delta",
            plugin_fingerprint=baseline[0]["plugin_fingerprint"],
            selected_findings_fingerprint="different-selection",
        )
        records, summary = QUEUE.build_queue(self.args(prior_review_dir=prior_dir))
        self.assertEqual("needs_delta_review", records[0]["prior_review"]["status"])
        self.assertTrue(records[0]["prior_review"]["source_fingerprint_match"])
        self.assertFalse(records[0]["prior_review"]["selected_findings_fingerprint_match"])
        self.assertEqual(str((prior_dir / "delta.json").resolve()), records[0]["prior_review"]["report_path"])
        self.assertEqual("pending", records[0]["review"]["status"])
        self.assertEqual(1, summary["prior_reviews_needing_delta"])

    def test_prior_review_with_both_fingerprints_matching_is_reusable(self) -> None:
        self.write_findings([self.row("reusable", "high_public")])
        baseline, _ = QUEUE.build_queue(self.args())
        prior_dir = self.root / "prior"
        self.write_prior_report(
            prior_dir,
            "reusable",
            plugin_fingerprint=baseline[0]["plugin_fingerprint"],
            selected_findings_fingerprint=baseline[0]["selected_findings_fingerprint"],
        )
        records, summary = QUEUE.build_queue(self.args(prior_review_dir=prior_dir))
        self.assertEqual("reusable", records[0]["prior_review"]["status"])
        self.assertEqual("pending", records[0]["review"]["status"])
        self.assertEqual(1, summary["prior_reviews_reusable"])

    def test_invalid_mismatched_prior_reviews_are_rejected(self) -> None:
        plugins = ("invalid", "wrong-plugin", "wrong-source")
        self.write_findings([self.row(plugin, "high_public") for plugin in plugins])
        baseline, _ = QUEUE.build_queue(self.args())
        fingerprints = {record["plugin"]: record["plugin_fingerprint"] for record in baseline}
        prior_dir = self.root / "prior"
        prior_dir.mkdir()
        (prior_dir / "invalid.json").write_text("{not-json", encoding="utf-8")
        self.write_prior_report(
            prior_dir,
            "wrong-plugin",
            plugin="another-plugin",
            plugin_fingerprint=fingerprints["wrong-plugin"],
        )
        self.write_prior_report(
            prior_dir,
            "wrong-source",
            plugin_fingerprint="different-source",
        )
        records, summary = QUEUE.build_queue(self.args(prior_review_dir=prior_dir))
        self.assertTrue(all(record["prior_review"] is None for record in records))
        self.assertEqual(3, summary["prior_reviews_rejected"])
        self.assertEqual(0, summary["prior_reviews_reusable"])
        self.assertEqual(0, summary["prior_reviews_needing_delta"])

    def test_unspecified_prior_review_directory_preserves_record_shape(self) -> None:
        self.write_findings([self.row("plain", "high_public")])
        records, summary = QUEUE.build_queue(self.args())
        self.assertNotIn("prior_review", records[0])
        self.assertEqual(0, summary["prior_reviews_reusable"])
        self.assertEqual(0, summary["prior_reviews_needing_delta"])
        self.assertEqual(0, summary["prior_reviews_rejected"])

    def test_prior_report_path_does_not_escape_or_recurse(self) -> None:
        prior_dir = (self.root / "prior").resolve()
        prior_dir.mkdir()
        nested = prior_dir / "nested"
        nested.mkdir()
        (nested / "plugin.json").write_text("{}", encoding="utf-8")
        outside = self.root / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        self.assertEqual((None, False), QUEUE.safe_prior_report_path(prior_dir, "nested/plugin"))
        self.assertEqual((None, False), QUEUE.safe_prior_report_path(prior_dir, "../outside"))


if __name__ == "__main__":
    unittest.main()
