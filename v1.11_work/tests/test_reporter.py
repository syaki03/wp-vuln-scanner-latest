"""CSV formula neutralization must not alter raw report evidence."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from scanner.reporter import FIELDNAMES, write_reports
from scanner.utils import html_escape


class ReporterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)

    def row(self, value):
        row = dict.fromkeys(FIELDNAMES, "")
        row.update(
            plugin=value, snippet=value, severity="MEDIUM", score=42,
            line=3, entrypoint_line=1, type="REFLECTED_XSS_CANDIDATE", context="html_text",
        )
        return row

    def csv_row(self):
        with (self.output / "findings.csv").open(encoding="utf-8-sig", newline="") as handle:
            return next(csv.DictReader(handle))

    def test_neutralizes_formula_prefixes_and_leading_controls_in_text(self):
        values = [
            "=1+1", "+1+1", "-1+1", "@SUM(1,1)", "  =1+1",
            "\u2003@SUM(1,1)", "\tplain", "\rplain", "\nplain",
            " \t=1+1", "\x00=1+1", "\x1fplain", "\x7fplain",
        ]
        for value in values:
            with self.subTest(value=value):
                row = self.row(value)
                write_reports([row], self.output)
                actual = self.csv_row()
                self.assertEqual("'" + value, actual["plugin"])
                self.assertEqual("'" + value, actual["snippet"])
                self.assertEqual("42", actual["score"])
                self.assertEqual("3", actual["line"])
                self.assertEqual("1", actual["entrypoint_line"])
                self.assertEqual(row, json.loads((self.output / "findings.json").read_text(encoding="utf-8"))[0])

    def test_applies_policy_to_all_text_columns(self):
        row = self.row("example")
        row.update(source_match="=1+1", file="@untrusted.php", entrypoint_name="+callback")
        write_reports([row], self.output)
        actual = self.csv_row()
        for field in ("source_match", "file", "entrypoint_name"):
            self.assertEqual("'" + row[field], actual[field])

    def test_benign_csv_and_raw_json_html_are_unchanged(self):
        value = "example,quoted \"name\" <script>alert(1)</script>"
        row = self.row(value)
        write_reports([row], self.output)
        actual = self.csv_row()
        self.assertEqual(value, actual["plugin"])
        self.assertEqual(value, actual["snippet"])
        self.assertEqual(row, json.loads((self.output / "findings.json").read_text(encoding="utf-8"))[0])
        html = (self.output / "report.html").read_text(encoding="utf-8")
        self.assertIn(html_escape(value), html)
        self.assertNotIn("<script>", html)


if __name__ == "__main__":
    unittest.main()
