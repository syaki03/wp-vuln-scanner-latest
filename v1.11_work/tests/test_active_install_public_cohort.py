import csv
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


WORK_ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str):
    path = WORK_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cohort = load_module(
    "active_install_public_cohort",
    "review/scripts/build_active_install_public_cohort.py",
)
queue_filter = load_module(
    "filter_queue_by_cohort",
    "review/scripts/filter_queue_by_cohort.py",
)


class ActiveInstallPublicCohortTests(unittest.TestCase):
    def test_classify_page_excludes_only_closed_or_missing(self):
        self.assertEqual(
            cohort.classify_page(200, "This plugin has been closed as of today")[0:2],
            ("closed", "excluded"),
        )
        self.assertEqual(cohort.classify_page(404, "")[0:2], ("not_found", "excluded"))
        self.assertEqual(cohort.classify_page(410, "")[0:2], ("not_found", "excluded"))
        self.assertEqual(cohort.classify_page(200, "normal page")[0:2], ("public", "included"))
        self.assertEqual(cohort.classify_page(503, "")[0:2], ("unknown", "hold"))

    def test_extract_closure_notice_preserves_reason(self):
        body = (
            "<p>This plugin has been closed as of May 1, 2026 and is not available "
            "for download. Reason: Security Issue.</p><h2>Reviews</h2>"
        )
        self.assertEqual(
            cohort.extract_closure_notice(body),
            "This plugin has been closed as of May 1, 2026 and is not available "
            "for download. Reason: Security Issue.",
        )

    def test_select_candidates_uses_collection_time_threshold(self):
        manifest = {
            "included": {"active_installs": "500", "version": "1", "last_updated": "old"},
            "excluded": {"active_installs": "400", "version": "1", "last_updated": "old"},
        }
        selected = cohort.select_candidates({"included", "excluded"}, manifest, 500)
        self.assertEqual([row["plugin"] for row in selected], ["included"])

    def test_select_candidates_rejects_missing_manifest_plugin(self):
        with self.assertRaisesRegex(ValueError, "missing from the download manifest"):
            cohort.select_candidates({"missing"}, {}, 500)

    def test_queue_filter_reads_unique_plugin_cohort(self):
        with tempfile.TemporaryDirectory() as temporary:
            cohort_path = Path(temporary) / "cohort.csv"
            with cohort_path.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["plugin"])
                writer.writeheader()
                writer.writerow({"plugin": "a"})
                writer.writerow({"plugin": "a"})
                writer.writerow({"plugin": "b"})
            self.assertEqual(queue_filter.read_cohort_plugins(cohort_path), {"a", "b"})


if __name__ == "__main__":
    unittest.main()
