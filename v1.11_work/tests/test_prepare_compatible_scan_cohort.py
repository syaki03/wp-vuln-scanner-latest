from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "review"
    / "scripts"
    / "prepare_compatible_scan_cohort.py"
)
SPEC = importlib.util.spec_from_file_location("prepare_compatible_scan_cohort", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)

RUNNER_PATH = SCRIPT_PATH.with_name("run_scanner_for_artifact_manifest.py")
RUNNER_SPEC = importlib.util.spec_from_file_location("run_scanner_for_artifact_manifest", RUNNER_PATH)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner)


class PrepareCompatibleScanCohortTests(unittest.TestCase):
    def write_manifest(self, path: Path, rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=sorted(prepare.REQUIRED_COLUMNS))
            writer.writeheader()
            writer.writerows(rows)

    def row(self, slug: str, compatibility: str, tree_hash: str) -> dict[str, str]:
        return {
            "slug": slug,
            "artifact_status": "ready",
            "scan_inclusion": "included",
            "tree_sha256": tree_hash,
            "source_php_compatibility": compatibility,
        }

    def run_main(
        self,
        manifest: Path,
        root: Path,
        output: Path,
        hold_slug: list[str] | None = None,
    ) -> None:
        with patch.object(
            prepare,
            "parse_args",
            return_value=type("Args", (), {
                "artifact_manifest": manifest,
                "extracted_plugin_root": root,
                "output_dir": output,
                "eligible_source_php_compatibility": [],
                "hold_slug": hold_slug or [],
            })(),
        ):
            self.assertEqual(0, prepare.main())

    def test_default_eligibility_materializes_only_included_and_records_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "plugins"
            source.mkdir()
            compatible = source / "compatible"
            compatible.mkdir()
            (compatible / "main.php").write_text("<?php echo 'ok';\n", encoding="utf-8")
            held = source / "new-syntax"
            held.mkdir()
            (held / "main.php").write_text("<?php fn() => 1;\n", encoding="utf-8")
            manifest = base / "artifact_manifest.csv"
            self.write_manifest(manifest, [
                self.row("compatible", "metadata_requires_php_le_7_1", prepare.tree_fingerprint(compatible)),
                self.row("new-syntax", "post_7_1_syntax_detected", prepare.tree_fingerprint(held)),
            ])
            output = base / "scan-ready"

            self.run_main(manifest, source, output)

            self.assertEqual({"compatible"}, {item.name for item in output.iterdir() if item.is_dir()})
            with (output / "scan_artifact_manifest.csv").open(encoding="utf-8", newline="") as handle:
                rows = {row["slug"]: row for row in csv.DictReader(handle)}
            self.assertEqual("included", rows["compatible"]["scan_inclusion"])
            self.assertEqual("hold_post_php_7_1_syntax", rows["new-syntax"]["scan_inclusion"])
            runner_rows = runner.read_manifest(output / "scan_artifact_manifest.csv")
            runner.validate_plugin_root(output, runner_rows)
            summary = json.loads((output / "scan_cohort_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(1, summary["included_count"])
            self.assertEqual(1, summary["hold_count"])
            self.assertEqual("hardlink_with_copy_fallback", summary["tree_materialization"]["mode"])

    def test_hold_slug_marks_wordpress_hold_before_php_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "plugins"
            source.mkdir()
            held = source / "wp-newer"
            held.mkdir()
            (held / "main.php").write_text("<?php fn() => 1;\n", encoding="utf-8")
            compatible = source / "compatible"
            compatible.mkdir()
            (compatible / "main.php").write_text("<?php\n", encoding="utf-8")
            manifest = base / "artifact_manifest.csv"
            self.write_manifest(manifest, [
                self.row("wp-newer", "post_7_1_syntax_detected", prepare.tree_fingerprint(held)),
                self.row("compatible", "heuristic_no_post_7_1_syntax_detected", prepare.tree_fingerprint(compatible)),
            ])
            output = base / "scan-ready"

            self.run_main(manifest, source, output, hold_slug=["wp-newer"])

            with (output / "scan_artifact_manifest.csv").open(encoding="utf-8", newline="") as handle:
                rows = {row["slug"]: row for row in csv.DictReader(handle)}
            self.assertEqual("hold_wordpress_requirement_gt_5_3", rows["wp-newer"]["scan_inclusion"])
            summary = json.loads((output / "scan_cohort_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(["wp-newer"], summary["hold_slugs_wordpress_requirement_gt_5_3"])
            self.assertEqual(1, summary["scan_inclusion_counts"]["hold_wordpress_requirement_gt_5_3"])

            with self.assertRaisesRegex(ValueError, "duplicate hold-slug"):
                self.run_main(manifest, source, base / "duplicate-hold", hold_slug=["wp-newer", "wp-newer"])

    def test_rejects_duplicate_slugs_non_ready_and_tree_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "plugins"
            source.mkdir()
            plugin = source / "same"
            plugin.mkdir()
            (plugin / "main.php").write_text("<?php\n", encoding="utf-8")
            digest = prepare.tree_fingerprint(plugin)
            manifest = base / "artifact_manifest.csv"
            self.write_manifest(manifest, [self.row("same", "metadata_requires_php_le_7_1", digest)] * 2)
            with self.assertRaisesRegex(ValueError, "duplicate slugs"):
                prepare.read_manifest(manifest)

            self.write_manifest(manifest, [self.row("same", "metadata_requires_php_le_7_1", digest)])
            with manifest.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["artifact_status"] = "error"
            self.write_manifest(manifest, rows)
            with self.assertRaisesRegex(ValueError, "non-ready artifact"):
                prepare.read_manifest(manifest)

            self.write_manifest(manifest, [self.row("same", "metadata_requires_php_le_7_1", "0" * 64)])
            with self.assertRaisesRegex(ValueError, "tree hash mismatch"):
                prepare.validate_tree(source, "same", "0" * 64)

    def test_rejects_symlink_anomaly_and_nonempty_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "plugins"
            source.mkdir()
            plugin = source / "plugin"
            plugin.mkdir()
            (plugin / "main.php").write_text("<?php\n", encoding="utf-8")
            manifest = base / "artifact_manifest.csv"
            self.write_manifest(manifest, [self.row("plugin", "heuristic_no_post_7_1_syntax_detected", prepare.tree_fingerprint(plugin))])
            output = base / "output"
            output.mkdir()
            (output / "unrelated.txt").write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "absent or empty"):
                self.run_main(manifest, source, output)

            expected_hash = prepare.tree_fingerprint(plugin)
            with patch.object(
                Path,
                "is_symlink",
                autospec=True,
                side_effect=lambda path: path.name == "main.php",
            ):
                with self.assertRaisesRegex(ValueError, "symlink anomaly"):
                    prepare.validate_tree(source, "plugin", expected_hash)

    def test_tree_fingerprint_is_content_and_path_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tree"
            root.mkdir()
            (root / "b.php").write_text("<?php B", encoding="utf-8")
            (root / "a.php").write_text("<?php A", encoding="utf-8")
            first = prepare.tree_fingerprint(root)
            self.assertEqual(first, prepare.tree_fingerprint(root))
            self.assertEqual(64, len(first))
            self.assertEqual(hashlib.sha256(b"<?php A").hexdigest(), prepare.sha256_file(root / "a.php"))


if __name__ == "__main__":
    unittest.main()
