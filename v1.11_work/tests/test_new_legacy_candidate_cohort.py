from __future__ import annotations

import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "review"
    / "scripts"
    / "build_new_legacy_candidate_cohort.py"
)
SPEC = importlib.util.spec_from_file_location("build_new_legacy_candidate_cohort", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
cohort = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cohort)


class NewLegacyCandidateCohortTests(unittest.TestCase):
    def test_default_window_preserves_pre_2020_behavior(self):
        start, end, description = cohort.release_window(
            SimpleNamespace(release_year=None, release_cutoff=None)
        )
        self.assertIsNone(start)
        self.assertEqual(datetime(2020, 1, 1, tzinfo=timezone.utc), end)
        self.assertEqual("last_updated on or before 2019-12-31", description)

    def test_release_year_selects_exact_2020_calendar_window(self):
        start, end, description = cohort.release_window(
            SimpleNamespace(release_year=2020, release_cutoff=None)
        )
        self.assertEqual(datetime(2020, 1, 1, tzinfo=timezone.utc), start)
        self.assertEqual(datetime(2021, 1, 1, tzinfo=timezone.utc), end)
        self.assertIn("2020-01-01 <= last_updated < 2021-01-01", description)

    def test_existing_slug_csvs_are_repeatable_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugins = root / "plugins"
            plugins.mkdir()
            (plugins / "Alpha").mkdir()
            first = root / "first.csv"
            second = root / "second.csv"
            first.write_text("slug\nalpha\nbeta\n", encoding="utf-8-sig")
            second.write_text("slug\nbeta\ngamma\n", encoding="utf-8")

            slugs, counts = cohort.load_existing_slugs(plugins, [first, second])

            self.assertEqual({"alpha", "beta", "gamma"}, slugs)
            self.assertEqual(1, counts["plugin_root_directories"])
            self.assertEqual(1, counts[str(first.resolve())])
            self.assertEqual(1, counts[str(second.resolve())])
            self.assertEqual(3, counts["unique_existing_slugs"])

    def test_disposition_applies_year_window_before_compatibility_checks(self):
        start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        end = datetime(2021, 1, 1, tzinfo=timezone.utc)
        plugin = {
            "slug": "candidate",
            "last_updated": "2020-06-01 12:00:00",
            "requires": "5.3",
            "tested": "5.3",
            "requires_php": "7.1",
            "version": "1.0",
            "download_link": "https://downloads.wordpress.org/plugin/candidate.1.0.zip",
        }
        status, _ = cohort.disposition(plugin, set(), start, end, (5, 3), (7, 1))
        self.assertEqual("candidate", status)

        before = {**plugin, "last_updated": "2019-12-31 23:59:59"}
        status, _ = cohort.disposition(before, set(), start, end, (5, 3), (7, 1))
        self.assertEqual("updated_before_window", status)

        after = {**plugin, "last_updated": "2021-01-01 00:00:00"}
        status, _ = cohort.disposition(after, set(), start, end, (5, 3), (7, 1))
        self.assertEqual("updated_after_window", status)

        status, _ = cohort.disposition(plugin, {"candidate"}, start, end, (5, 3), (7, 1))
        self.assertEqual("existing_corpus", status)

    def test_record_only_policy_retains_newer_compatibility_metadata(self):
        start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        end = datetime(2021, 1, 1, tzinfo=timezone.utc)
        plugin = {
            "slug": "newer-metadata",
            "last_updated": "2020-06-01 12:00:00",
            "requires": "5.5",
            "tested": "5.6",
            "requires_php": "7.4",
            "version": "1.0",
            "download_link": "https://downloads.wordpress.org/plugin/newer-metadata.1.0.zip",
        }
        filtered, _ = cohort.disposition(
            plugin, set(), start, end, (5, 3), (7, 1), "filter"
        )
        retained, _ = cohort.disposition(
            plugin, set(), start, end, (5, 3), (7, 1), "record-only"
        )
        self.assertEqual("wordpress_requirement_too_new", filtered)
        self.assertEqual("candidate", retained)


if __name__ == "__main__":
    unittest.main()
