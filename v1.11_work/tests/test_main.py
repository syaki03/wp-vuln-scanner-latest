"""Scanner completion must distinguish invalid and partially scanned inputs."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import main as scanner_main


class ScannerMainTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.plugins = self.root / "plugins"
        self.plugin = self.plugins / "example"
        self.plugin.mkdir(parents=True)
        self.source = self.plugin / "example.php"
        self.source.write_text("<?php\necho $_GET['q'];\n", encoding="utf-8")
        self.output = self.root / "output"

    def run_main(self, root=None):
        output = io.StringIO()
        with patch.object(scanner_main, "PLUGIN_ROOT", root or self.plugins), patch.object(
            scanner_main, "OUTPUT_DIR", self.output
        ), redirect_stdout(output):
            result = scanner_main.main()
        return result, output.getvalue()

    def test_rejects_existing_file_as_plugin_root(self):
        result, output = self.run_main(self.source)
        self.assertNotEqual(0, result)
        self.assertIn("[ERROR]", output)
        self.assertFalse(self.output.exists())

    def test_rejects_missing_plugin_root(self):
        result, output = self.run_main(self.root / "missing")
        self.assertNotEqual(0, result)
        self.assertIn("[ERROR]", output)
        self.assertFalse(self.output.exists())

    def test_rejects_directory_without_supported_sources(self):
        empty = self.root / "empty"
        empty.mkdir()
        result, output = self.run_main(empty)
        self.assertNotEqual(0, result)
        self.assertIn("[ERROR]", output)
        self.assertFalse(self.output.exists())

    def test_partial_failure_keeps_error_and_success_reports_but_fails(self):
        good = self.plugin / "good.php"
        good.write_text("<?php\necho $_GET['other'];\n", encoding="utf-8")
        original = scanner_main.analyze_php_file

        def fail_one(path, *args):
            if path == self.source:
                raise OSError("synthetic unreadable source")
            return original(path, *args)

        with patch.object(scanner_main, "analyze_php_file", side_effect=fail_one):
            result, output = self.run_main()
        self.assertNotEqual(0, result)
        self.assertIn("Scan incomplete", output)
        self.assertIn("ERRORS : 1", output)
        findings = json.loads((self.output / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(1, sum(row["type"] == "SCAN_ERROR" for row in findings))
        self.assertTrue(any(row["file"] == str(good) for row in findings))
        self.assertTrue((self.output / "findings.csv").is_file())
        self.assertTrue((self.output / "report.html").is_file())

    def test_successful_scan_with_no_candidates_still_succeeds(self):
        self.source.write_text("<?php\necho 'safe';\n", encoding="utf-8")
        result, output = self.run_main()
        self.assertEqual(0, result)
        self.assertIn("Scan completed", output)
        self.assertIn("ERRORS : 0", output)
        self.assertEqual([], json.loads((self.output / "findings.json").read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
