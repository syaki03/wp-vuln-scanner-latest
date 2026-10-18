from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


WORK_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = WORK_ROOT / "review" / "scripts" / "build_xss_v2_handoff.py"
spec = importlib.util.spec_from_file_location("build_xss_v2_handoff", SCRIPT)
assert spec and spec.loader
builder = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = builder
spec.loader.exec_module(builder)


class XssV2HandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = {"plugin.php": b"<?php\n$x = $_POST['x'];\nupdate_post_meta(1, 'x', $x);\n$x = get_post_meta(1, 'x', true);\necho '<input value=\"'.$x.'\">';\n"}
        self.patched = {"plugin.php": self.source["plugin.php"].replace(b"'.$x.'", b"'.esc_attr($x).'")}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("example/plugin.php", self.source["plugin.php"])
        self.zip_bytes = buffer.getvalue()
        self.finding_id = "0123456789abcdef0123"
        self.spec = {
            "spec_schema_version": 1,
            "plugin": {"name": "Example", "slug": "example", "version": "1.2", "artifact_origin": "wordpress_org"},
            "finding": {
                "finding_id": self.finding_id,
                "candidate_id": "example:1.2:stored-xss",
                "vulnerability_class": "stored_xss",
                "static_verdict": "likely_vulnerable",
                "claim": "Stored attribute XSS",
                "source_to_sink_trace": [
                    {"sequence": 0, "file": "plugin.php", "start_line": 2, "end_line": 2, "kind": "source", "symbol": "POST"},
                    {"sequence": 1, "file": "plugin.php", "start_line": 3, "end_line": 3, "kind": "storage", "symbol": "update_post_meta"},
                    {"sequence": 2, "file": "plugin.php", "start_line": 4, "end_line": 4, "kind": "retrieval", "symbol": "get_post_meta"},
                    {"sequence": 3, "file": "plugin.php", "start_line": 5, "end_line": 5, "kind": "sink", "symbol": "input value"},
                ],
            },
            "principals": {
                "attacker_role": "contributor", "victim_role": "editor",
                "minimum_privilege_claimed": True, "distinct_users_required": True,
                "distinct_browser_contexts_required": True,
                "attacker_action": "save_post_meta", "victim_action": "render_post_editor",
            },
            "environment_matrix": {
                "environments": [{
                    "environment_id": "current", "wordpress": "7.1", "php": "8.2.33",
                    "database": "MariaDB 11.7", "server": "Apache",
                    "image_digest": "sha256:" + "a" * 64, "role": "current_stable", "available": True,
                }],
                "legacy_conditions": [],
            },
            "oracle": {"safe_input_sha256": "b" * 64, "candidate_input_sha256": "c" * 64},
            "patched_control": {"sink_context": "html_attribute", "encoding_function": "esc_attr"},
            "safety": {
                "local_synthetic_only": True, "bounded_payload": True,
                "external_communication": False, "third_party_target": False,
                "production_target": False, "real_credentials": False,
                "raw_secret_retention": False, "cleanup_required": True,
                "zero_residue_required": True,
            },
            "handoff_status": "runtime_pending",
        }
        self.manifest = {"plugin": {"slug": "example", "version": "1.2", "source_hash": builder.sha256_bytes(self.zip_bytes)}}
        self.review = {"plugin": "example", "version": "1.2", "verdict": "likely_vulnerable", "finding_ids": [self.finding_id]}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self):
        return builder.build_handoff(
            spec=self.spec,
            artifact_manifest=self.manifest,
            review=self.review,
            artifact_bytes=self.zip_bytes,
            source_files=self.source,
            patched_files=self.patched,
        )

    def test_builds_hash_bound_four_lane_handoff(self) -> None:
        handoff, patch, receipt = self.build()
        self.assertEqual("2.0", handoff["handoff_schema_version"])
        self.assertEqual(4, len(handoff["oracle"]["lanes"]))
        self.assertEqual(self.finding_id, handoff["finding"]["finding_id"])
        self.assertEqual(builder.sha256_bytes(patch), handoff["patched_control"]["patch_diff_sha256"])
        self.assertFalse(receipt["plugin_code_executed"])

    def test_rejects_zip_tree_mismatch(self) -> None:
        with self.assertRaisesRegex(builder.HandoffBuildError, "official ZIP"):
            builder.build_handoff(
                spec=self.spec,
                artifact_manifest=self.manifest,
                review=self.review,
                artifact_bytes=self.zip_bytes,
                source_files={"plugin.php": self.source["plugin.php"] + b"drift"},
                patched_files=self.patched,
            )

    def test_rejects_unreviewed_finding(self) -> None:
        self.spec["finding"]["finding_id"] = "fedcba98765432100123"
        with self.assertRaisesRegex(builder.HandoffBuildError, "not covered"):
            self.build()

    def test_rejects_patch_outside_sink(self) -> None:
        self.patched["plugin.php"] = self.patched["plugin.php"].replace(b"<?php", b"<?PHP")
        with self.assertRaisesRegex(builder.HandoffBuildError, "outside the sink"):
            self.build()

    def test_normalizes_incidental_bytes_outside_sink(self) -> None:
        historical = dict(self.patched)
        historical["plugin.php"] = historical["plugin.php"].replace(b"<?php", b"<?PHP")
        normalized = builder.normalize_patch_to_sink_range(
            self.source, historical, "plugin.php", 5, 5
        )
        self.assertTrue(normalized["plugin.php"].startswith(b"<?php"))
        handoff, _patch, _receipt = builder.build_handoff(
            spec=self.spec,
            artifact_manifest=self.manifest,
            review=self.review,
            artifact_bytes=self.zip_bytes,
            source_files=self.source,
            patched_files=normalized,
        )
        self.assertNotEqual(
            handoff["plugin"]["source_tree_sha256"],
            handoff["patched_control"]["patched_tree_sha256"],
        )

    def test_rejects_values_outside_poc_v2_contract(self) -> None:
        cases = [
            (("finding", "vulnerability_class"), "csrf_to_stored_xss", "vulnerability_class"),
            (("principals", "attacker_role"), "unauthenticated", "attacker_role"),
            (("principals", "victim_role"), "editor_or_custom_role", "victim_role"),
            (("principals", "attacker_action"), "submit a form", "attacker_action"),
            (("environment_matrix", "environments", 0, "role"), "current_stable_image", "environment role"),
            (("environment_matrix", "legacy_conditions"), ["legacy runtime"], "legacy condition entry"),
            (("patched_control", "sink_context"), "html_text", "sink_context"),
        ]
        for path, value, message in cases:
            invalid = json.loads(json.dumps(self.spec))
            target = invalid
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaisesRegex(
                builder.HandoffBuildError, message
            ):
                builder.build_handoff(
                    spec=invalid,
                    artifact_manifest=self.manifest,
                    review=self.review,
                    artifact_bytes=self.zip_bytes,
                    source_files=self.source,
                    patched_files=self.patched,
                )


if __name__ == "__main__":
    unittest.main()
