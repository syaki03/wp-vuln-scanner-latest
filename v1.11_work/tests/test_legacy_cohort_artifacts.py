from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "review/scripts/download_and_prepare_legacy_cohort.py"
SPEC = importlib.util.spec_from_file_location("legacy_artifact_intake", SCRIPT)
assert SPEC and SPEC.loader
intake = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(intake)


class LegacyCohortArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.args = argparse.Namespace(output_dir=self.root / "output", timeout=1, retries=1)
        self.row = dict(candidate_rank="1", batch_id="first", slug="example", version="1.0",
                        active_installs="0", last_updated="2020-01-01", requires="5.0", tested="5.3",
                        requires_php="7.1", download_link="https://downloads.wordpress.org/plugin/example.1.0.zip")
        self.network = patch.object(intake, "urlopen", side_effect=AssertionError("network forbidden"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.addCleanup(self.temporary.cleanup)

    def archive(self, version="1.0", header_version=None):
        archive = self.args.output_dir / "downloads" / f"example.{version}.zip"
        archive.parent.mkdir(parents=True, exist_ok=True)
        header_version = version if header_version is None else header_version
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("example/example.php", f"/*\nPlugin Name: Synthetic Example\nVersion: {header_version}\n*/\n")
        return archive

    def initial_ready(self):
        self.archive()
        result = intake.process_candidate(self.row, self.args)
        self.assertEqual("ready", result["artifact_status"])
        return result

    def test_same_request_reuses_valid_archive_and_tree_without_network(self):
        first = self.initial_ready()
        source = self.args.output_dir / "plugins/example/example.php"
        before = source.stat().st_mtime_ns
        second = intake.process_candidate(self.row, self.args)
        self.assertEqual("ready", second["artifact_status"])
        self.assertEqual(first["artifact_sha256"], second["artifact_sha256"])
        self.assertEqual(before, source.stat().st_mtime_ns)

    def test_new_version_never_returns_previous_ready_receipt(self):
        self.initial_ready()
        self.archive("2.0")
        row = dict(self.row, version="2.0", download_link="https://downloads.wordpress.org/plugin/example.2.0.zip")
        result = intake.process_candidate(row, self.args)
        self.assertEqual("2.0", result["api_version"])
        self.assertEqual("error", result["artifact_status"])
        self.assertNotEqual("included", result["scan_inclusion"])
        self.assertIn("1.0", (self.args.output_dir / "plugins/example/example.php").read_text())

    def test_changed_request_metadata_is_not_returned_from_old_receipt(self):
        self.initial_ready()
        result = intake.process_candidate(dict(self.row, batch_id="second", active_installs="10"), self.args)
        self.assertEqual("ready", result["artifact_status"])
        self.assertEqual("second", result["batch_id"])
        self.assertEqual("10", result["active_installs"])

    def test_same_version_changed_download_url_preserves_archive_and_receipt(self):
        self.initial_ready()
        archive = self.args.output_dir / "downloads/example.1.0.zip"
        receipt = self.args.output_dir / "artifact-receipts/example.json"
        original_archive = archive.read_bytes()
        original_receipt = receipt.read_bytes()
        changed = dict(self.row, download_link="https://downloads.wordpress.org/plugin/example.zip")
        with patch.object(intake, "download") as download:
            result = intake.process_candidate(changed, self.args)
            download.assert_not_called()
        self.assertEqual("error", result["artifact_status"])
        self.assertNotEqual("included", result["scan_inclusion"])
        self.assertIn("archive identity", result["error"])
        self.assertEqual(original_archive, archive.read_bytes())
        self.assertEqual(original_receipt, receipt.read_bytes())
        # A subsequent retry must keep rejecting the conflicting URL.
        retry = intake.process_candidate(changed, self.args)
        self.assertEqual("error", retry["artifact_status"])
        # The original request remains usable without downloading again.
        original = intake.process_candidate(self.row, self.args)
        self.assertEqual("ready", original["artifact_status"])

    def test_dangling_partial_link_is_removed_before_opening_download(self):
        destination = self.root / "download.zip"
        partial = destination.with_suffix(".zip.partial")
        url = self.row["download_link"]

        class Response(io.BytesIO):
            def geturl(self):
                return url

        # Represent a dangling link independently of Windows symlink privileges.
        # Path.exists() is false, but the lstat-based link check is true.
        with patch.object(intake, "is_link", side_effect=lambda path: path == partial), \
                patch.object(Path, "unlink", autospec=True) as unlink:
            def response(_request, timeout):
                unlink.assert_called_once_with(partial)
                return Response(b"PK\x03\x04synthetic archive bytes")

            with patch.object(intake, "urlopen", side_effect=response):
                intake.download(url, destination, timeout=1, retries=1)
        self.assertEqual(b"PK\x03\x04synthetic archive bytes", destination.read_bytes())

    def test_existing_tree_must_match_archive_even_if_receipt_hash_was_updated(self):
        result = self.initial_ready()
        source = self.args.output_dir / "plugins/example/example.php"
        source.write_bytes(source.read_bytes() + b"unrelated changed bytes\n")
        receipt = self.args.output_dir / "artifact-receipts/example.json"
        result["tree_sha256"] = intake.tree_fingerprint(source.parent)
        receipt.write_text(json.dumps(result), encoding="utf-8")
        checked = intake.process_candidate(self.row, self.args)
        self.assertEqual("error", checked["artifact_status"])
        self.assertIn("does not match", checked["error"])
        self.assertTrue(source.read_bytes().endswith(b"unrelated changed bytes\n"))

    def test_existing_extraction_without_receipt_cannot_be_bound_to_new_zip(self):
        self.initial_ready()
        (self.args.output_dir / "artifact-receipts/example.json").unlink()
        self.archive("2.0")
        row = dict(self.row, version="2.0", download_link="https://downloads.wordpress.org/plugin/example.2.0.zip")
        result = intake.process_candidate(row, self.args)
        self.assertEqual("error", result["artifact_status"])
        self.assertNotEqual("included", result["scan_inclusion"])

    def test_header_version_mismatch_or_missing_is_excluded(self):
        for header in ("2.0", ""):
            with self.subTest(header=header):
                self.args.output_dir = self.root / ("mismatch" if header else "missing")
                self.archive(header_version=header)
                result = intake.process_candidate(self.row, self.args)
                self.assertEqual("error", result["artifact_status"])
                self.assertNotEqual("included", result["scan_inclusion"])
                self.assertIn(result["version_check"], {"mismatch", "missing_header_version"})

    def test_invalid_slug_and_version_are_rejected_before_io(self):
        for field, value in (("slug", "x/../../victim"), ("slug", "../victim"),
                             ("slug", "/../victim"), ("version", "../../victim"),
                             ("version", ""), ("version", None)):
            with self.subTest(field=field, value=value), patch.object(intake, "download") as download, \
                    patch.object(intake, "write_receipt") as write_receipt:
                with self.assertRaises(ValueError):
                    intake.process_candidate(dict(self.row, **{field: value}), self.args)
                download.assert_not_called()
                write_receipt.assert_not_called()
                self.assertFalse(self.args.output_dir.exists())

    def test_invalid_cohort_slug_is_rejected_before_processing(self):
        cohort = self.root / "cohort.csv"
        with cohort.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(self.row))
            writer.writeheader()
            writer.writerow(dict(self.row, slug="x/../../victim"))
        with self.assertRaisesRegex(ValueError, "slug"):
            intake.read_cohort(cohort, 0)

    def test_extract_rejects_escaping_slug_without_deleting_staging(self):
        root = self.root / "plugins"
        root.mkdir()
        (root / ".x").mkdir()
        victim = self.root / "victim.staging"
        victim.mkdir()
        sentinel = victim / "sentinel.txt"
        sentinel.write_text("preserve me", encoding="utf-8")
        with patch.object(intake.shutil, "rmtree") as remove:
            with self.assertRaisesRegex(ValueError, "slug"):
                intake.extract_archive(self.root / "unused.zip", root, "x/../../victim")
            remove.assert_not_called()
        self.assertEqual("preserve me", sentinel.read_text())

    def test_existing_staging_directory_is_preserved_as_conflict(self):
        archive = self.archive()
        root = self.root / "plugins"
        staging = root / ".example.staging"
        staging.mkdir(parents=True)
        sentinel = staging / "sentinel.txt"
        sentinel.write_text("preserve me", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "staging"):
            intake.extract_archive(archive, root, "example")
        self.assertEqual("preserve me", sentinel.read_text())

    def test_extra_file_in_existing_tree_is_not_accepted(self):
        self.initial_ready()
        (self.args.output_dir / "plugins/example/extra.txt").write_text("unrelated", encoding="utf-8")
        result = intake.process_candidate(self.row, self.args)
        self.assertEqual("error", result["artifact_status"])
        self.assertIn("does not match", result["error"])

    def test_symlinked_extraction_is_rejected_and_target_is_preserved(self):
        archive = self.archive()
        root = self.root / "linked-plugins"
        root.mkdir()
        external = self.root / "external"
        external.mkdir()
        sentinel = external / "sentinel.txt"
        sentinel.write_text("preserve me", encoding="utf-8")
        try:
            (root / "example").symlink_to(external, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink creation is unavailable: {type(error).__name__}")
        with self.assertRaisesRegex(ValueError, "linked"):
            intake.extract_archive(archive, root, "example")
        self.assertEqual("preserve me", sentinel.read_text())

    def test_incomplete_cohort_version_is_rejected(self):
        cohort = self.root / "incomplete.csv"
        fields = list(self.row)
        # The last required field exists in the header but is missing in the row.
        fields.remove("version")
        fields.append("version")
        with cohort.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(fields)
            writer.writerow([self.row[field] for field in fields[:-1]])
        with self.assertRaisesRegex(ValueError, "version"):
            intake.read_cohort(cohort, 0)


if __name__ == "__main__":
    unittest.main()
