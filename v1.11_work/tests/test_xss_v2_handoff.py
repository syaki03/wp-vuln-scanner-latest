from __future__ import annotations

import importlib.util
import io
import json
import sys
import contextlib
import tempfile
import unittest
from unittest.mock import patch
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

    def test_output_tree_rejects_existing_contents_without_modification(self) -> None:
        output = self.root / 'patched-output'
        output.mkdir()
        stale = output / 'stale.txt'
        stale.write_bytes(b'keep existing data')
        with self.assertRaisesRegex(builder.HandoffBuildError, 'absent or empty'):
            builder.write_tree(output, self.patched)
        self.assertEqual(b'keep existing data', stale.read_bytes())
        self.assertFalse((output / 'plugin.php').exists())

    def test_output_tree_exactly_matches_declared_hash(self) -> None:
        handoff, _, _ = self.build()
        output = self.root / 'new-output'
        builder.write_tree(output, self.patched)
        actual = builder.sha256_bytes(builder.canonical_json(builder.tree_manifest(builder.read_tree(output))))
        self.assertEqual(handoff['patched_control']['patched_tree_sha256'], actual)

    def test_output_tree_detects_written_byte_mismatch(self) -> None:
        with patch.object(builder, 'read_tree', return_value={'plugin.php': b'incorrect bytes'}):
            with self.assertRaisesRegex(builder.HandoffBuildError, 'written patched tree'):
                builder.write_tree(self.root / 'mismatch', self.patched)

    def test_metadata_outputs_cannot_pollute_patched_tree(self) -> None:
        output = self.root / 'patched-output'
        with self.assertRaisesRegex(builder.HandoffBuildError, 'outside the patched'):
            builder.validate_output_paths(output, [output / 'handoff.json', self.root / 'patch', self.root / 'receipt'])
        with self.assertRaisesRegex(builder.HandoffBuildError, 'distinct'):
            builder.validate_output_paths(output, [self.root / 'same', self.root / 'same', self.root / 'receipt'])

    def test_cli_receipt_describes_actual_output_after_all_writes(self) -> None:
        source = self.root / 'source'
        patched = self.root / 'candidate'
        builder.write_tree(source, self.source)
        builder.write_tree(patched, self.patched)
        for name, value in [('spec', self.spec), ('manifest', self.manifest), ('review', self.review)]:
            builder.write_json(self.root / f'{name}.json', value)
        archive = self.root / 'official.zip'
        archive.write_bytes(self.zip_bytes)
        output = self.root / 'patched-output'
        handoff_path = self.root / 'handoff.json'
        receipt_path = self.root / 'receipt.json'
        argv = ['builder', '--spec', str(self.root / 'spec.json'), '--artifact-manifest', str(self.root / 'manifest.json'),
                '--review', str(self.root / 'review.json'), '--artifact-zip', str(archive), '--source-root', str(source),
                '--patched-root', str(patched), '--patched-output-root', str(output), '--output', str(handoff_path),
                '--patch-output', str(self.root / 'patch.diff'), '--receipt', str(receipt_path)]
        with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, builder.main())
        handoff = builder.load_json_strict(handoff_path)
        receipt = builder.load_json_strict(receipt_path)
        actual = builder.sha256_bytes(builder.canonical_json(builder.tree_manifest(builder.read_tree(output))))
        self.assertEqual(handoff['patched_control']['patched_tree_sha256'], actual)
        self.assertIn('written_patched_tree_exact_bytes', receipt['checks'])
        self.assertEqual(builder.sha256_bytes(builder.canonical_json({k: v for k, v in receipt.items() if k != 'receipt_sha256'})),
                         receipt['receipt_sha256'])

    def test_outputs_must_preserve_all_input_files_and_trees(self) -> None:
        source = self.root / 'source'
        source.mkdir()
        original = source / 'plugin.php'
        original.write_bytes(self.source['plugin.php'])
        spec = self.root / 'spec.json'
        spec.write_bytes(b'{"preserve": true}')
        patched_output = self.root / 'output-tree'
        outputs = [self.root / 'handoff.json', self.root / 'patch.diff', self.root / 'receipt.json']
        for index in range(3):
            invalid = list(outputs)
            invalid[index] = spec
            with self.subTest(index=index), self.assertRaisesRegex(builder.HandoffBuildError, 'alias input'):
                builder.validate_output_paths(patched_output, invalid, input_files=[spec], input_trees=[source])
        with self.assertRaisesRegex(builder.HandoffBuildError, 'modify input trees'):
            builder.validate_output_paths(patched_output, [original, *outputs[1:]], input_trees=[source])
        with self.assertRaisesRegex(builder.HandoffBuildError, 'overlap input trees'):
            builder.validate_output_paths(source / 'nested-output', outputs, input_trees=[source])
        self.assertEqual(b'{"preserve": true}', spec.read_bytes())
        self.assertEqual(self.source['plugin.php'], original.read_bytes())

    def test_hardlinked_output_cannot_alias_input(self) -> None:
        spec = self.root / 'spec.json'
        spec.write_bytes(b'{"preserve": true}')
        alias = self.root / 'spec-hardlink.json'
        try:
            alias.hardlink_to(spec)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f'hardlink creation is unavailable: {type(error).__name__}')
        with self.assertRaisesRegex(builder.HandoffBuildError, 'alias input'):
            builder.validate_output_paths(self.root / 'output-tree', [alias, self.root / 'patch', self.root / 'receipt'], input_files=[spec])
        self.assertEqual(b'{"preserve": true}', spec.read_bytes())

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
