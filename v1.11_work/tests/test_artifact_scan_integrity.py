from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / 'review/scripts'


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load('run_scanner_for_artifact_manifest')
prepare = load('prepare_compatible_scan_cohort')


class ArtifactScanIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.plugins = self.root / 'plugins'
        self.plugin = self.plugins / 'example'
        self.plugin.mkdir(parents=True)
        self.php = self.plugin / 'main.php'
        self.php.write_bytes(b'<?php echo $_GET["q"];\n')
        self.rows = [{'slug': 'example', 'tree_sha256': prepare.tree_fingerprint(self.plugin)}]

    def test_current_tree_matches_and_changed_tree_is_rejected(self):
        runner.validate_plugin_root(self.plugins, self.rows)
        self.php.write_bytes(b'<?php echo "clean";\n')
        with self.assertRaisesRegex(ValueError, 'tree hash mismatch'):
            runner.validate_plugin_root(self.plugins, self.rows)

    def test_non_php_changes_are_also_part_of_artifact_identity(self):
        (self.plugin / 'readme.txt').write_text('new source metadata', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'tree hash mismatch'):
            runner.validate_plugin_root(self.plugins, self.rows)

    def test_unlisted_hidden_plugin_is_rejected(self):
        (self.plugins / '.unlisted').mkdir()
        with self.assertRaisesRegex(ValueError, 'plugin root mismatch'):
            runner.validate_plugin_root(self.plugins, self.rows)

    def test_loose_scannable_file_is_rejected(self):
        (self.plugins / 'unlisted.php').write_bytes(b'<?php echo $_GET["q"];')
        with self.assertRaisesRegex(ValueError, 'unlisted scanner file'):
            runner.validate_plugin_root(self.plugins, self.rows)

    def test_scan_time_source_drift_cannot_produce_success_receipt(self):
        manifest = self.root / 'manifest.csv'
        manifest.write_text('slug,artifact_status,scan_inclusion,tree_sha256\n'
                            f'example,ready,included,{self.rows[0]["tree_sha256"]}\n', encoding='utf-8')
        output = self.root / 'output'

        def fake_scan():
            output.mkdir()
            (output / 'findings.csv').write_text('plugin,severity,type\n', encoding='utf-8')
            (output / 'findings.json').write_text('[]', encoding='utf-8')
            (output / 'report.html').write_text('<html></html>', encoding='utf-8')
            self.php.write_bytes(b'<?php echo "changed during scan";')
            return 0

        args = types.SimpleNamespace(artifact_manifest=manifest, plugin_root=self.plugins, output_dir=output)
        with patch.object(runner, 'parse_args', return_value=args), patch.dict(
            runner.sys.modules, {'config': types.SimpleNamespace(), 'main': types.SimpleNamespace(main=fake_scan)}
        ), self.assertRaisesRegex(ValueError, 'tree hash mismatch'):
            runner.main()
        self.assertFalse((output / 'scan_run.json').exists())

    def test_summary_counts_raw_json_identities_before_csv_escaping(self):
        findings = self.root / 'findings.json'
        findings.write_text(json.dumps([
            {'plugin': '=1+1', 'severity': 'HIGH', 'type': 'XSS'},
            {'plugin': "'=1+1", 'severity': 'HIGH', 'type': 'XSS'},
        ]), encoding='utf-8')
        self.assertEqual(2, runner.findings_summary(findings)['finding_plugins'])


if __name__ == '__main__':
    unittest.main()
