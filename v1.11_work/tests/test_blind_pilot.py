import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "benchmark"
    / "legacy_xss_core_v1"
    / "scripts"
    / "blind_pilot.py"
)
SPEC = importlib.util.spec_from_file_location("blind_pilot", SCRIPT)
blind_pilot = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(blind_pilot)
blind_review_v5 = __import__("blind_review_v5")


class BlindPilotTests(unittest.TestCase):
    def test_v2_review_instructions_disambiguate_rank_and_strict_validation(self):
        instructions = blind_pilot.review_instructions_v2_text()

        self.assertIn("numeric\n`global_rank`", instructions)
        self.assertIn("Never copy `plugin_rank`", instructions)
        self.assertIn("strict JSON parser", instructions)
        self.assertIn("actual newline", instructions)
        self.assertIn("cited source range", instructions)

    def test_extracts_only_scanner_targets_and_removes_plugin_slug_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "plugin.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("known-plugin/plugin.php", "<?php echo $_GET['x'];")
                handle.writestr("known-plugin/includes/view.inc", "<?php echo $value;")
                handle.writestr("known-plugin/readme.txt", "CVE details")
            destination = root / "eval-0001"

            count, artifact_root = blind_pilot.extract_opaque_php_tree(archive, destination)

            self.assertEqual(2, count)
            self.assertEqual("known-plugin", artifact_root)
            self.assertTrue((destination / "plugin.php").is_file())
            self.assertTrue((destination / "includes" / "view.inc").is_file())
            self.assertFalse((destination / "readme.txt").exists())
            self.assertFalse((destination / "known-plugin").exists())

    def test_rejects_zip_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "plugin.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../escape.php", "<?php")

            with self.assertRaisesRegex(ValueError, "unsafe ZIP member"):
                blind_pilot.extract_opaque_php_tree(archive, root / "output")

    def test_location_match_accepts_hidden_slug_suffix_and_small_line_drift(self):
        observed = {"path": "eval-0001/includes/view.php", "line": 42}
        expected = {"path": "known-plugin/includes/view.php", "line": 40}

        self.assertTrue(
            blind_pilot._location_matches(observed, expected, "eval-0001", tolerance=3)
        )

    def test_location_match_rejects_different_file(self):
        observed = {"path": "eval-0001/includes/admin.php", "line": 40}
        expected = {"path": "known-plugin/includes/view.php", "line": 40}

        self.assertFalse(
            blind_pilot._location_matches(observed, expected, "eval-0001", tolerance=3)
        )

    def test_v2_path_match_removes_exactly_one_artifact_root(self):
        self.assertTrue(
            blind_pilot._exact_relative_path_matches(
                "eval-0001/includes/view.php",
                "known-plugin/includes/view.php",
                "eval-0001",
            )
        )
        self.assertFalse(
            blind_pilot._exact_relative_path_matches(
                "eval-0001/view.php",
                "known-plugin/includes/view.php",
                "eval-0001",
            )
        )

    def test_v2_range_match_requires_expected_line_inside_tight_range(self):
        expected = {"path": "known-plugin/includes/view.php", "line": 40}
        matching = {
            "path": "eval-0001/includes/view.php",
            "line_start": 39,
            "line_end": 41,
        }
        adjacent = {
            "path": "eval-0001/includes/view.php",
            "line_start": 41,
            "line_end": 42,
        }
        self.assertTrue(blind_pilot._range_location_matches(matching, expected, "eval-0001"))
        self.assertFalse(blind_pilot._range_location_matches(adjacent, expected, "eval-0001"))

    def test_v3_scanner_match_accepts_manifest_expression_in_multiline_snippet(self):
        finding = {
            "file": "eval-0001/view.php",
            "line": 9,
            "snippet": "<script>\nvar unsafe = '<?php echo $_GET['x']; ?>';\n</script>",
        }
        expected = {
            "path": "known-plugin/view.php",
            "line": 10,
            "expression": "var unsafe = '<?php echo $_GET['x']; ?>';",
        }
        self.assertTrue(
            blind_pilot._scanner_finding_matches_expected(finding, expected, "eval-0001")
        )

    def test_v4_scanner_match_requires_expression_in_same_reconstructed_statement(self):
        with tempfile.TemporaryDirectory() as directory:
            blind = Path(directory)
            source = blind / "sources" / "eval-0001" / "view.php"
            source.parent.mkdir(parents=True)
            source.write_text(
                "<?php\n"
                "$html = '<script>\n"
                "var unsafe = \'" + "' . $_GET['x'] . '" + "\';';\n"
                "$other = $_GET['other'];\n",
                encoding="utf-8",
            )
            expected = {
                "path": "known-plugin/view.php",
                "line": 3,
                "expression": "var unsafe = '" + "' . $_GET['x'] . '" + "';",
            }
            matching = {"file": "eval-0001/view.php", "line": 2}
            unrelated = {"file": "eval-0001/view.php", "line": 4}
            self.assertTrue(
                blind_pilot._scanner_statement_matches_expected(
                    matching, expected, "eval-0001", blind
                )
            )
            self.assertFalse(
                blind_pilot._scanner_statement_matches_expected(
                    unrelated, expected, "eval-0001", blind
                )
            )
            self.assertTrue(
                blind_pilot._scanner_statement_span_matches_expected(
                    matching, expected, "eval-0001", blind
                )
            )
            self.assertFalse(
                blind_pilot._scanner_statement_span_matches_expected(
                    unrelated, expected, "eval-0001", blind
                )
            )

    def test_scanner_only_score_does_not_require_review_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            blind = Path(directory)
            source = blind / "sources" / "eval-0001" / "view.php"
            source.parent.mkdir(parents=True)
            source.write_text("<?php echo $_GET['x'];", encoding="utf-8")
            case_map = {
                "cases": [
                    {
                        "eval_id": "eval-0001",
                        "case_id": "case-1",
                        "artifact_root": "known-plugin",
                    }
                ]
            }
            manifest = {
                "case-1": {
                    "ground_truth": {
                        "sink": {
                            "path": "known-plugin/view.php",
                            "line": 1,
                            "expression": "echo $_GET['x'];",
                        },
                        "additional_sinks": [],
                    }
                }
            }
            findings = [
                {
                    "plugin": "eval-0001",
                    "file": "eval-0001/view.php",
                    "line": 1,
                    "global_rank": 1,
                    "plugin_rank": 1,
                }
            ]

            score = blind_pilot._build_scanner_only_score(
                case_map, manifest, findings, blind
            )

            self.assertEqual(1, score["scanner_ground_truth_sink_hit_count"])
            self.assertEqual(1, score["scanner_ranked_ground_truth_first_in_plugin_count"])
            self.assertEqual(1, score["plugin_rank_counts"]["top_1"])

    def test_v3_reviewer_match_rejects_adjacent_different_option(self):
        observed = {
            "path": "eval-0001/view.php",
            "line_start": 45,
            "line_end": 48,
            "expression": "echo get_option('media_type');",
        }
        expected = {
            "path": "known-plugin/view.php",
            "line": 47,
            "expression": "echo get_option('subtitle');",
        }
        self.assertFalse(
            blind_pilot._review_evidence_matches_expected(observed, expected, "eval-0001")
        )

    def test_review_contract_rejects_ground_truth_fields(self):
        review = {
            "schema_version": "blind-review-v1",
            "eval_id": "eval-0001",
            "verdict": "possible_vulnerability",
            "reviewer_confidence": "medium",
            "selected_finding_global_ranks": [],
            "source": {},
            "sinks": [],
            "trace": "",
            "exposure": {},
            "defenses": [],
            "scanner_assessment": "missed_path",
            "scanner_reason": "",
            "unresolved": [],
            "reviewed_files": [],
            "ground_truth": {},
        }

        with self.assertRaisesRegex(ValueError, "forbidden review keys"):
            blind_pilot._validate_review(review, "eval-0001")

    def test_review_contract_rejects_path_outside_opaque_case(self):
        review = {
            "schema_version": "blind-review-v1",
            "eval_id": "eval-0001",
            "verdict": "insufficient_evidence",
            "reviewer_confidence": "low",
            "selected_finding_global_ranks": [],
            "source": {"path": "../private/case_map.json", "line": 1},
            "sinks": [],
            "trace": "",
            "exposure": {},
            "defenses": [],
            "scanner_assessment": "missed_path",
            "scanner_reason": "",
            "unresolved": [],
            "reviewed_files": [],
        }

        with self.assertRaisesRegex(ValueError, "unsafe review path"):
            blind_pilot._validate_review(review, "eval-0001")

    def test_v2_review_rejects_broad_line_range(self):
        review = {
            "schema_version": "blind-review-v2",
            "eval_id": "eval-0001",
            "verdict": "possible_vulnerability",
            "reviewer_confidence": "medium",
            "selected_finding_global_ranks": [],
            "source_locations": [
                {
                    "path": "eval-0001/plugin.php",
                    "line_start": 1,
                    "line_end": 30,
                    "expression": "$_GET['x']",
                }
            ],
            "sink_locations": [],
            "trace": "",
            "exposure": {},
            "defenses": [],
            "scanner_assessment": "missed_path",
            "scanner_reason": "",
            "unresolved": [],
            "reviewed_files": ["eval-0001/plugin.php"],
        }
        with self.assertRaisesRegex(ValueError, "non-tight"):
            blind_pilot._validate_review_v2(review, "eval-0001")

    def test_v2_evidence_expression_must_exist_in_cited_range(self):
        review = {
            "source_locations": [
                {
                    "path": "eval-0001/plugin.php",
                    "line_start": 1,
                    "line_end": 1,
                    "expression": "$_POST['missing']",
                }
            ],
            "sink_locations": [],
            "reviewed_files": ["eval-0001/plugin.php"],
        }
        with tempfile.TemporaryDirectory() as directory:
            blind = Path(directory)
            source = blind / "sources" / "eval-0001" / "plugin.php"
            source.parent.mkdir(parents=True)
            source.write_text("<?php echo $_GET['present'];", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "expression is not present"):
                blind_pilot._validate_v2_source_evidence(review, blind, "eval-0001")

    def _make_v3_pilot(self, root):
        blind = root / "blind"
        source = blind / "sources" / "eval-0001" / "plugin.php"
        source.parent.mkdir(parents=True)
        source.write_text("<?php\n echo $_GET['x'];\n", encoding="utf-8")
        source_hash = blind_pilot.tree_fingerprint(source.parent)
        blind_pilot.write_json(
            blind / "pilot_index.json",
            {
                "cases": [{"eval_id": "eval-0001", "source_tree_sha256": source_hash}],
                "scanner_reference_sha256": "a" * 64,
            },
        )
        blind_pilot.write_json(
            blind / "scan" / "findings.json",
            [{"plugin": "eval-0001", "global_rank": 7, "file": "eval-0001/plugin.php"}],
        )
        (blind / "AGENTS.md").write_text("blind", encoding="utf-8")
        blind_pilot.write_json(
            root / "private" / "case_map.json",
            {"cases": [{"eval_id": "eval-0001", "case_id": "opaque-case"}]},
        )
        blind_pilot.command_bundle_v3(blind_pilot.argparse.Namespace(pilot_root=root))
        return blind, source_hash

    @staticmethod
    def _valid_v3_review(source_hash):
        return {
            "schema_version": "blind-review-v3",
            "eval_id": "eval-0001",
            "verdict": "likely_false_positive",
            "confidence": "medium",
            "primary_selected_finding_global_rank": 7,
            "secondary_selected_finding_global_ranks": [],
            "trace_anchor_global_rank": 7,
            "source_inventory_sha256": source_hash,
            "source_locations": [{"path": "eval-0001/plugin.php", "line_start": 2, "line_end": 2, "expression": "$_GET['x']"}],
            "sink_locations": [{"path": "eval-0001/plugin.php", "line_start": 2, "line_end": 2, "expression": "echo $_GET['x'];"}],
            "trace": "request value reaches direct output",
            "exposure": {"reachability": "unknown"},
            "defenses": ["static source only"],
            "context_analysis": "PHP output expression is HTML text context.",
            "scanner_assessment": "likely_false_positive",
            "scanner_reason": "The selected candidate is anchored but its source is not attacker-controlled.",
            "unresolved": [],
            "reviewed_files": ["eval-0001/plugin.php"],
            "review_passes": {
                "scanner_guided": ["eval-0001/plugin.php"],
                "entrypoint_led": ["eval-0001/plugin.php"],
                "sink_storage_led": ["eval-0001/plugin.php"],
            },
            "evidence_gap": None,
        }

    def test_v3_bundle_inventory_lock_and_parser_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v3_pilot(root)
            bundle = blind_pilot.read_json(blind / "review_bundles_v3" / "eval-0001.json")
            schema = blind_pilot.read_json(blind / "REVIEW_SCHEMA_V3.json")
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), set(schema["properties"]))
            self.assertEqual(
                [{"path": "eval-0001/plugin.php", "sha256": blind_pilot.sha256_file(blind / "sources" / "eval-0001" / "plugin.php")}],
                bundle["source_files"],
            )
            blind_pilot.write_json(blind / "reviews_v3" / "eval-0001.json", self._valid_v3_review(source_hash))
            self.assertEqual(0, blind_pilot.command_lock_reviews_v3(blind_pilot.argparse.Namespace(pilot_root=root)))
            parser = blind_pilot.build_parser()
            self.assertIs(blind_pilot.command_bundle_v3, parser.parse_args(["bundle-v3"]).func)
            self.assertIs(blind_pilot.command_lock_reviews_v3, parser.parse_args(["lock-reviews-v3"]).func)
            self.assertIs(blind_pilot.command_score_v6, parser.parse_args(["score-v6"]).func)

    def test_v3_selected_review_ranks_include_primary_and_secondaries(self):
        review = {
            "primary_selected_finding_global_rank": 7,
            "secondary_selected_finding_global_ranks": [9, 11, 9],
        }
        self.assertEqual({7, 9, 11}, blind_pilot._selected_review_ranks(review, "v3"))
        review["primary_selected_finding_global_rank"] = None
        self.assertEqual({9, 11}, blind_pilot._selected_review_ranks(review, "v3"))

    def test_v3_lock_rejects_non_primary_anchor_and_incomplete_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v3_pilot(root)
            review = self._valid_v3_review(source_hash)
            review["primary_selected_finding_global_rank"] = 8
            blind_pilot.write_json(blind / "reviews_v3" / "eval-0001.json", review)
            with self.assertRaisesRegex(ValueError, "primary finding rank"):
                blind_pilot.command_lock_reviews_v3(blind_pilot.argparse.Namespace(pilot_root=root))
            review = self._valid_v3_review(source_hash)
            review["review_passes"]["sink_storage_led"] = []
            with self.assertRaisesRegex(ValueError, "sink_storage_led"):
                blind_pilot._validate_review_v3(review, "eval-0001")
            review = self._valid_v3_review(source_hash)
            review["trace_anchor_global_rank"] = None
            blind_pilot.write_json(blind / "reviews_v3" / "eval-0001.json", review)
            with self.assertRaisesRegex(ValueError, "null trace anchor"):
                blind_pilot.command_lock_reviews_v3(blind_pilot.argparse.Namespace(pilot_root=root))

    def test_v3_insufficient_evidence_requires_a_real_gap_record(self):
        review = self._valid_v3_review("a" * 64)
        review["verdict"] = "insufficient_evidence"
        review["trace_anchor_global_rank"] = None
        review["evidence_gap"] = None
        with self.assertRaisesRegex(ValueError, "requires an evidence_gap"):
            blind_pilot._validate_review_v3(review, "eval-0001")
        review["evidence_gap"] = {
            "missing_link": "sink",
            "searched_locations": ["eval-0001/plugin.php"],
        }
        blind_pilot._validate_review_v3(review, "eval-0001")

    def test_v3_contract_rejects_extra_fields_and_wrong_scalar_types(self):
        review = self._valid_v3_review("a" * 64)
        review["extra"] = "not allowed"
        with self.assertRaisesRegex(ValueError, "unexpected v3 review fields"):
            blind_pilot._validate_review_v3(review, "eval-0001")
        review = self._valid_v3_review("a" * 64)
        review["trace"] = {"not": "a string"}
        with self.assertRaisesRegex(ValueError, "trace must be a string"):
            blind_pilot._validate_review_v3(review, "eval-0001")

    @staticmethod
    def _v4_candidate(*, candidate_id="primary", rank=7):
        return {
            "candidate_id": candidate_id,
            "finding_global_rank": rank,
            "path_kind": "direct",
            "verdict": "likely_vulnerable",
            "confidence": "high",
            "link_states": {
                "source": "confirmed",
                "write": "not_applicable",
                "storage_read": "not_applicable",
                "call": "not_applicable",
                "sink": "confirmed",
                "reachability": "confirmed",
                "context_escape": "refuted",
            },
            "trace_steps": [
                {
                    "step_id": "step-01",
                    "kind": "entrypoint",
                    "path": "eval-0001/plugin.php",
                    "line_start": 1,
                    "line_end": 1,
                    "expression": "<?php",
                    "input_step_ids": [],
                    "finding_global_ranks": [],
                },
                {
                    "step_id": "step-02",
                    "kind": "source",
                    "path": "eval-0001/plugin.php",
                    "line_start": 1,
                    "line_end": 1,
                    "expression": "$_GET['x']",
                    "input_step_ids": ["step-01"],
                    "finding_global_ranks": [rank] if rank is not None else [],
                },
                {
                    "step_id": "step-03",
                    "kind": "sink",
                    "path": "eval-0001/plugin.php",
                    "line_start": 1,
                    "line_end": 1,
                    "expression": "echo $_GET['x'];",
                    "input_step_ids": ["step-02"],
                    "finding_global_ranks": [rank] if rank is not None else [],
                },
            ],
            "supporting_finding_global_ranks": [],
            "context": {"kind": "html_text", "delimiter": "none"},
            "exposure": {
                "entrypoint_kind": "direct_php",
                "attacker_privilege": "unauthenticated",
                "victim_privilege": "public",
                "configuration_requirement": "none",
            },
            "open_preconditions": [],
            "refutation": None,
            "evidence_gap": None,
            "summary": "complete source-only static path",
        }

    @classmethod
    def _valid_v4_review(cls, source_hash):
        return {
            "schema_version": "blind-review-v4",
            "eval_id": "eval-0001",
            "source_inventory_sha256": source_hash,
            "primary_candidate": cls._v4_candidate(),
            "independent_paths": [],
            "reviewed_files": ["eval-0001/plugin.php"],
            "review_passes": {
                "scanner_guided": ["eval-0001/plugin.php"],
                "entrypoint_led": ["eval-0001/plugin.php"],
                "sink_storage_led": ["eval-0001/plugin.php"],
            },
        }

    def _make_v4_pilot(self, root, *, with_finding=True):
        blind = root / "blind"
        source = blind / "sources" / "eval-0001" / "plugin.php"
        source.parent.mkdir(parents=True)
        source.write_text("<?php echo $_GET['x'];\n", encoding="utf-8")
        source_hash = blind_pilot.tree_fingerprint(source.parent)
        blind_pilot.write_json(
            blind / "pilot_index.json",
            {
                "cases": [{"eval_id": "eval-0001", "source_tree_sha256": source_hash}],
                "scanner_reference_sha256": "a" * 64,
            },
        )
        blind_pilot.write_json(
            blind / "scan" / "findings.json",
            ([{"plugin": "eval-0001", "global_rank": 7,
               "file": "eval-0001/plugin.php"}] if with_finding else []),
        )
        (blind / "AGENTS.md").write_text("blind", encoding="utf-8")
        blind_pilot.write_json(
            root / "private" / "case_map.json",
            {"cases": [{"eval_id": "eval-0001", "case_id": "opaque-case"}]},
        )
        blind_pilot.command_bundle_v4(blind_pilot.argparse.Namespace(pilot_root=root))
        return blind, source_hash

    def test_v4_schema_bundle_lock_and_parser_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v4_pilot(root)
            schema = blind_pilot.read_json(blind / "REVIEW_SCHEMA_V4.json")
            bundle = blind_pilot.read_json(blind / "review_bundles_v4" / "eval-0001.json")
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
            self.assertEqual(set(schema["required"]), set(schema["properties"]))
            self.assertTrue(schema["properties"]["primary_candidate"]["allOf"])
            self.assertTrue(all("if" in rule and "then" in rule for rule in
                                schema["properties"]["primary_candidate"]["allOf"]))
            self.assertEqual(["eval-0001/plugin.php"], bundle["required_review_files"])
            self.assertEqual(7, bundle["primary_finding_global_rank"])
            self.assertEqual(source_hash, bundle["source_inventory_sha256"])
            self.assertIn(
                "same-named field in the case bundle",
                (blind / "REVIEW_INSTRUCTIONS_V4.md").read_text(encoding="utf-8"),
            )
            self.assertTrue((blind / "reviews_v4" / "AGENTS.md").is_file())
            self.assertTrue((blind / "REVIEW_VALIDATOR_V4.py").is_file())
            bundle_lock = blind_pilot.read_json(blind / "review_bundles_v4" / "lock.json")
            self.assertEqual(
                blind_pilot.sha256_file(blind / "reviews_v4" / "AGENTS.md"),
                bundle_lock["review_agents_sha256"],
            )
            self.assertEqual(
                blind_pilot.sha256_file(blind / "REVIEW_VALIDATOR_V4.py"),
                bundle_lock["review_validator_sha256"],
            )
            blind_pilot.write_json(
                blind / "reviews_v4" / "eval-0001.json",
                self._valid_v4_review(source_hash),
            )
            self.assertEqual(
                0,
                blind_pilot.command_lock_reviews_v4(
                    blind_pilot.argparse.Namespace(pilot_root=root)
                ),
            )
            parser = blind_pilot.build_parser()
            self.assertIs(blind_pilot.command_bundle_v4, parser.parse_args(["bundle-v4"]).func)
            self.assertIs(
                blind_pilot.command_lock_reviews_v4,
                parser.parse_args(["lock-reviews-v4"]).func,
            )
            self.assertIs(blind_pilot.command_score_v7, parser.parse_args(["score-v7"]).func)

    def test_v4_decision_table_derives_all_four_verdicts(self):
        candidate = self._v4_candidate()
        self.assertEqual("likely_vulnerable", blind_pilot.derive_v4_verdict(candidate))

        possible = self._v4_candidate()
        possible["link_states"]["reachability"] = "unknown"
        possible["open_preconditions"] = [{"kind": "deployment", "evidence_step_ids": []}]
        possible["verdict"] = "possible_vulnerability"
        blind_pilot.validate_review_v4_shape(
            {**self._valid_v4_review("a" * 64), "primary_candidate": possible}, "eval-0001"
        )

        insufficient = self._v4_candidate()
        insufficient["link_states"]["source"] = "unknown"
        insufficient["verdict"] = "insufficient_evidence"
        insufficient["evidence_gap"] = {
            "missing_link": "source",
            "searched_files": ["eval-0001/plugin.php"],
        }
        blind_pilot.validate_review_v4_shape(
            {**self._valid_v4_review("a" * 64), "primary_candidate": insufficient},
            "eval-0001",
        )

        false_positive = self._v4_candidate()
        false_positive["link_states"]["context_escape"] = "confirmed"
        false_positive["verdict"] = "likely_false_positive"
        false_positive["refutation"] = {
            "reason": "context_correct_encoder",
            "blocked_link": "context_escape",
            "evidence_step_ids": ["step-03"],
        }
        blind_pilot.validate_review_v4_shape(
            {**self._valid_v4_review("a" * 64), "primary_candidate": false_positive},
            "eval-0001",
        )

    def test_v4_rejects_missing_refutation_and_irrelevant_path_links(self):
        false_positive = self._v4_candidate()
        false_positive["link_states"]["source"] = "refuted"
        false_positive["verdict"] = "likely_false_positive"
        review = {**self._valid_v4_review("a" * 64), "primary_candidate": false_positive}
        with self.assertRaisesRegex(ValueError, "refutation must be an object"):
            blind_pilot.validate_review_v4_shape(review, "eval-0001")

        invalid_direct = self._v4_candidate()
        invalid_direct["link_states"]["write"] = "confirmed"
        review = {**self._valid_v4_review("a" * 64), "primary_candidate": invalid_direct}
        with self.assertRaisesRegex(ValueError, "write conflicts with path_kind"):
            blind_pilot.validate_review_v4_shape(review, "eval-0001")

    def test_v4_closed_refutation_reasons_require_matching_blocked_links(self):
        cases = [
            ("fixed_literal", "source", "step-02", "source", "refuted"),
            ("nonflow", "sink", "step-03", "sink", "refuted"),
            ("unreachable", "reachability", "step-01", "reachability", "refuted"),
            ("context_correct_encoder", "context_escape", "step-03", "context_escape", "confirmed"),
        ]
        for reason, blocked, evidence, state_name, state in cases:
            with self.subTest(reason=reason):
                candidate = self._v4_candidate()
                candidate["link_states"][state_name] = state
                candidate["verdict"] = "likely_false_positive"
                candidate["refutation"] = {
                    "reason": reason,
                    "blocked_link": blocked,
                    "evidence_step_ids": [evidence],
                }
                blind_pilot.validate_review_v4_shape(
                    {**self._valid_v4_review("a" * 64), "primary_candidate": candidate},
                    "eval-0001",
                )

        invalid = self._v4_candidate()
        invalid["link_states"]["reachability"] = "refuted"
        invalid["verdict"] = "likely_false_positive"
        invalid["refutation"] = {
            "reason": "context_correct_encoder",
            "blocked_link": "reachability",
            "evidence_step_ids": ["step-01"],
        }
        with self.assertRaisesRegex(ValueError, "reason does not match blocked_link"):
            blind_pilot.validate_review_v4_shape(
                {**self._valid_v4_review("a" * 64), "primary_candidate": invalid},
                "eval-0001",
            )

    def test_v4_missing_static_links_are_insufficient_but_reachability_is_possible(self):
        for path_kind, missing_links in [
            ("direct", ["source", "sink", "context_escape"]),
            ("stored", ["write", "storage_read"]),
            ("interprocedural", ["call"]),
        ]:
            for missing_link in missing_links:
                with self.subTest(path_kind=path_kind, missing_link=missing_link):
                    candidate = self._v4_candidate()
                    candidate["path_kind"] = path_kind
                    if path_kind == "stored":
                        candidate["link_states"].update({"write": "unknown", "storage_read": "unknown"})
                    if path_kind == "interprocedural":
                        candidate["link_states"]["call"] = "unknown"
                    candidate["link_states"][missing_link] = "unknown"
                    candidate["verdict"] = "insufficient_evidence"
                    candidate["evidence_gap"] = {
                        "missing_link": missing_link,
                        "searched_files": ["eval-0001/plugin.php"],
                    }
                    blind_pilot.validate_review_v4_shape(
                        {**self._valid_v4_review("a" * 64), "primary_candidate": candidate},
                        "eval-0001",
                    )

        possible = self._v4_candidate()
        possible["link_states"]["reachability"] = "unknown"
        possible["verdict"] = "possible_vulnerability"
        possible["open_preconditions"] = [{"kind": "role", "evidence_step_ids": ["step-01"]}]
        self.assertEqual("possible_vulnerability", blind_pilot.derive_v4_verdict(possible))

    def test_v4_stored_and_interprocedural_paths_require_connected_steps(self):
        stored = self._v4_candidate()
        stored["path_kind"] = "stored_interprocedural"
        stored["link_states"].update({"write": "confirmed", "storage_read": "confirmed", "call": "confirmed"})
        def step(number, kind, inputs):
            return {
                "step_id": f"step-{number:02d}", "kind": kind,
                "path": "eval-0001/plugin.php", "line_start": 1, "line_end": 1,
                "expression": "$_GET['x']", "input_step_ids": inputs,
                "finding_global_ranks": [7],
            }
        stored["trace_steps"] = [
            step(1, "entrypoint", []), step(2, "source", ["step-01"]),
            step(3, "write", ["step-02"]), step(4, "storage_read", ["step-03"]),
            step(5, "call", ["step-04"]), step(6, "sink", ["step-05"]),
        ]
        review = {**self._valid_v4_review("a" * 64), "primary_candidate": stored}
        blind_pilot.validate_review_v4_shape(review, "eval-0001")

        stored["trace_steps"][-1]["input_step_ids"] = ["step-01"]
        with self.assertRaisesRegex(ValueError, "connected complete trace"):
            blind_pilot.validate_review_v4_shape(
                {**self._valid_v4_review("a" * 64), "primary_candidate": stored},
                "eval-0001",
            )

    def test_v4_independent_path_cannot_change_or_reuse_primary(self):
        independent = self._v4_candidate(candidate_id="independent-01", rank=9)
        review = self._valid_v4_review("a" * 64)
        review["independent_paths"] = [independent]
        blind_pilot.validate_review_v4_shape(review, "eval-0001")
        self.assertEqual("likely_vulnerable", review["primary_candidate"]["verdict"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v4_pilot(root)
            review = self._valid_v4_review(source_hash)
            review["independent_paths"] = [self._v4_candidate(candidate_id="independent-01", rank=7)]
            blind_pilot.write_json(blind / "reviews_v4" / "eval-0001.json", review)
            with self.assertRaisesRegex(ValueError, "must not reuse primary"):
                blind_pilot.command_lock_reviews_v4(
                    blind_pilot.argparse.Namespace(pilot_root=root)
                )

    def test_v4_no_finding_primary_is_null_and_unresolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v4_pilot(root, with_finding=False)
            candidate = self._v4_candidate(rank=None)
            candidate.update({
                "path_kind": "unresolved",
                "verdict": "insufficient_evidence",
                "confidence": "low",
                "trace_steps": [],
                "context": {"kind": "unknown", "delimiter": "unknown"},
                "evidence_gap": {
                    "missing_link": "source",
                    "searched_files": ["eval-0001/plugin.php"],
                },
                "summary": "no scanner finding and no complete static path",
            })
            candidate["link_states"].update({
                "source": "unknown", "sink": "unknown", "reachability": "unknown",
                "context_escape": "unknown",
            })
            review = self._valid_v4_review(source_hash)
            review["primary_candidate"] = candidate
            blind_pilot.write_json(blind / "reviews_v4" / "eval-0001.json", review)
            bundle = blind_pilot.read_json(
                blind / "review_bundles_v4" / "eval-0001.json"
            )
            self.assertIsNone(bundle["primary_finding_global_rank"])
            self.assertEqual(
                0,
                blind_pilot.command_lock_reviews_v4(
                    blind_pilot.argparse.Namespace(pilot_root=root)
                ),
            )

    def test_v4_finding_primary_cannot_use_unresolved_escape_hatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v4_pilot(root)
            review = self._valid_v4_review(source_hash)
            review["primary_candidate"]["path_kind"] = "unresolved"
            bundle = blind_pilot.read_json(
                blind / "review_bundles_v4" / "eval-0001.json"
            )
            with self.assertRaisesRegex(ValueError, "cannot be unresolved"):
                blind_pilot.validate_review_v4_against_bundle(
                    review, bundle, blind_root=blind, eval_id="eval-0001"
                )

    def test_v4_parent_lock_and_shipped_validator_share_multiline_whitespace_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v4_pilot(root)
            source = blind / "sources" / "eval-0001" / "plugin.php"
            source.write_text(
                "<?php\n$value = $_GET[\n  'x'\n];\necho(\n  $value\n);\n",
                encoding="utf-8",
            )
            review = self._valid_v4_review(source_hash)
            review["primary_candidate"]["trace_steps"] = [
                {
                    "step_id": "step-01", "kind": "entrypoint",
                    "path": "eval-0001/plugin.php", "line_start": 1, "line_end": 1,
                    "expression": "<?php", "input_step_ids": [],
                    "finding_global_ranks": [],
                },
                {
                    "step_id": "step-02", "kind": "source",
                    "path": "eval-0001/plugin.php", "line_start": 2, "line_end": 4,
                    "expression": "$value = $_GET['x'];", "input_step_ids": ["step-01"],
                    "finding_global_ranks": [7],
                },
                {
                    "step_id": "step-03", "kind": "sink",
                    "path": "eval-0001/plugin.php", "line_start": 5, "line_end": 7,
                    "expression": "echo($value);", "input_step_ids": ["step-02"],
                    "finding_global_ranks": [7],
                },
            ]
            bundle = blind_pilot.read_json(
                blind / "review_bundles_v4" / "eval-0001.json"
            )
            blind_pilot.validate_review_v4_against_bundle(
                review, bundle, blind_root=blind, eval_id="eval-0001"
            )
            blind_pilot._validate_v4_source_evidence(
                review, blind, "eval-0001", bundle
            )

    def test_v4_selected_ranks_exclude_independent_paths(self):
        review = self._valid_v4_review("a" * 64)
        review["primary_candidate"]["supporting_finding_global_ranks"] = [9]
        review["independent_paths"] = [
            self._v4_candidate(candidate_id="independent-01", rank=11)
        ]
        self.assertEqual({7, 9}, blind_pilot._selected_review_ranks(review, "v4"))
        self.assertEqual({7, 9, 11}, blind_pilot._all_v4_review_ranks(review))

    def test_v4_runtime_absence_is_not_a_missing_link(self):
        instructions = blind_pilot.review_instructions_v4_text()
        self.assertIn("Runtime not being executed is not a missing link", instructions)
        self.assertNotIn("runtime_not_run", blind_pilot.review_schema_v4()["properties"]["primary_candidate"]["properties"]["refutation"]["oneOf"][1]["properties"]["reason"]["enum"])

    @staticmethod
    def _v5_identity(rank=7):
        if rank is None:
            return None
        return {
            "finding_global_rank": rank,
            "path": "eval-0001/plugin.php",
            "line": 1,
            "anchor_kind": "sink",
            "anchor_match": r"\becho\b",
            "source_kind": "superglobals",
            "source_match": r"\$_GET\b",
            "sink_kind": "html_output",
            "context": "html",
        }

    @classmethod
    def _v5_candidate(cls, *, candidate_id="primary", rank=7):
        candidate = cls._v4_candidate(candidate_id=candidate_id, rank=rank)
        candidate["finding_identity"] = cls._v5_identity(rank)
        candidate["field_mismatch_proof"] = None
        return candidate

    @classmethod
    def _valid_v5_review(cls, source_hash):
        review = cls._valid_v4_review(source_hash)
        review["schema_version"] = "blind-review-v5"
        review["primary_candidate"] = cls._v5_candidate()
        return review

    def _make_v5_pilot(self, root, *, with_finding=True):
        blind = root / "blind"
        source = blind / "sources" / "eval-0001" / "plugin.php"
        source.parent.mkdir(parents=True)
        source.write_text("<?php echo $_GET['x'];\n", encoding="utf-8")
        source_hash = blind_pilot.tree_fingerprint(source.parent)
        blind_pilot.write_json(
            blind / "pilot_index.json",
            {
                "cases": [{"eval_id": "eval-0001", "source_tree_sha256": source_hash}],
                "scanner_reference_sha256": "a" * 64,
            },
        )
        finding = {
            "plugin": "eval-0001",
            "global_rank": 7,
            "file": "eval-0001/plugin.php",
            "line": 1,
            "source_kind": "superglobals",
            "source_match": r"\$_GET\b",
            "sink_kind": "html_output",
            "sink_match": r"\becho\b",
            "storage_kind": "",
            "storage_match": "",
            "context": "html",
        }
        blind_pilot.write_json(
            blind / "scan" / "findings.json", [finding] if with_finding else []
        )
        (blind / "AGENTS.md").write_text("blind", encoding="utf-8")
        blind_pilot.write_json(
            root / "private" / "case_map.json",
            {"cases": [{"eval_id": "eval-0001", "case_id": "opaque-case"}]},
        )
        blind_pilot.command_bundle_v5(blind_pilot.argparse.Namespace(pilot_root=root))
        return blind, source_hash

    def test_v5_schema_bundle_validator_lock_and_parser_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v5_pilot(root)
            bundle = blind_pilot.read_json(
                blind / "review_bundles_v5" / "eval-0001.json"
            )
            self.assertEqual(self._v5_identity(), bundle["primary_finding_identity"])
            self.assertTrue((blind / "REVIEW_VALIDATOR_V5.py").is_file())
            self.assertTrue((blind / "REVIEW_VALIDATOR_V4_BASE.py").is_file())
            lock = blind_pilot.read_json(blind / "review_bundles_v5" / "lock.json")
            self.assertEqual(
                blind_pilot.sha256_file(blind / "REVIEW_VALIDATOR_V4_BASE.py"),
                lock["base_validator_sha256"],
            )
            blind_pilot.write_json(
                blind / "reviews_v5" / "eval-0001.json",
                self._valid_v5_review(source_hash),
            )
            self.assertEqual(
                0,
                blind_pilot.command_lock_reviews_v5(
                    blind_pilot.argparse.Namespace(pilot_root=root)
                ),
            )
            parser = blind_pilot.build_parser()
            self.assertIs(blind_pilot.command_bundle_v5, parser.parse_args(["bundle-v5"]).func)
            self.assertIs(
                blind_pilot.command_lock_reviews_v5,
                parser.parse_args(["lock-reviews-v5"]).func,
            )
            self.assertIs(blind_pilot.command_score_v8, parser.parse_args(["score-v8"]).func)

    def test_v5_rejects_known_role_setting_and_ordinary_render_preconditions(self):
        for kind in ("role", "setting", "victim_action"):
            with self.subTest(kind=kind):
                candidate = self._v5_candidate()
                candidate["link_states"]["reachability"] = "unknown"
                candidate["verdict"] = "possible_vulnerability"
                candidate["open_preconditions"] = [{
                    "kind": kind,
                    "affected_link": "reachability",
                    "resolution_boundary": "platform_contract",
                    "unresolved_fact": "this fact is not established",
                    "evidence_step_ids": ["step-01"],
                }]
                with self.assertRaisesRegex(ValueError, "kind is invalid"):
                    blind_pilot.validate_review_v5_shape(
                        {**self._valid_v5_review("a" * 64), "primary_candidate": candidate},
                        "eval-0001",
                    )

    def test_v5_accepts_only_precondition_bound_to_unknown_link(self):
        candidate = self._v5_candidate()
        candidate["link_states"]["reachability"] = "unknown"
        candidate["verdict"] = "possible_vulnerability"
        candidate["open_preconditions"] = [{
            "kind": "deployment",
            "affected_link": "reachability",
            "resolution_boundary": "deployment_configuration",
            "unresolved_fact": "the required route registration is deployment-specific",
            "evidence_step_ids": ["step-01"],
        }]
        blind_pilot.validate_review_v5_shape(
            {**self._valid_v5_review("a" * 64), "primary_candidate": candidate},
            "eval-0001",
        )
        candidate["link_states"]["reachability"] = "confirmed"
        with self.assertRaisesRegex(ValueError, "must name an unknown link"):
            blind_pilot.validate_review_v5_shape(
                {**self._valid_v5_review("a" * 64), "primary_candidate": candidate},
                "eval-0001",
            )

    def test_v5_primary_trace_cannot_switch_to_nearby_sink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v5_pilot(root)
            source = blind / "sources" / "eval-0001" / "plugin.php"
            source.write_text(
                "<?php echo $_GET['x'];\necho $_POST['y'];\n", encoding="utf-8"
            )
            review = self._valid_v5_review(source_hash)
            review["primary_candidate"]["trace_steps"][2].update({
                "line_start": 2,
                "line_end": 2,
                "expression": "echo $_POST['y'];",
            })
            bundle = blind_pilot.read_json(
                blind / "review_bundles_v5" / "eval-0001.json"
            )
            with self.assertRaisesRegex(ValueError, "file/line/anchor identity"):
                blind_pilot.validate_review_v5_against_bundle(
                    review, bundle, blind_root=blind, eval_id="eval-0001"
                )

    def test_v5_primary_identity_must_exactly_match_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v5_pilot(root)
            review = self._valid_v5_review(source_hash)
            review["primary_candidate"]["finding_identity"]["source_match"] = r"\$_POST\b"
            bundle = blind_pilot.read_json(
                blind / "review_bundles_v5" / "eval-0001.json"
            )
            with self.assertRaisesRegex(ValueError, "exactly match bundle"):
                blind_pilot.validate_review_v5_against_bundle(
                    review, bundle, blind_root=blind, eval_id="eval-0001"
                )

    def test_v5_field_mismatch_requires_structural_non_alias_proof(self):
        candidate = self._v5_candidate()
        candidate["link_states"]["source"] = "refuted"
        candidate["verdict"] = "likely_false_positive"
        candidate["refutation"] = {
            "reason": "field_mismatch",
            "blocked_link": "source",
            "evidence_step_ids": ["step-02"],
        }
        review = {**self._valid_v5_review("a" * 64), "primary_candidate": candidate}
        with self.assertRaisesRegex(ValueError, "field_mismatch_proof must be an object"):
            blind_pilot.validate_review_v5_shape(review, "eval-0001")
        candidate["field_mismatch_proof"] = {
            "claimed_source": "$_GET['x']",
            "sink_value": "$record->name",
            "distinct_producer": "get_posts() result field",
            "non_alias_evidence_step_ids": ["step-02"],
        }
        blind_pilot.validate_review_v5_shape(review, "eval-0001")

    def test_v5_server_normalization_is_unknown_context_not_open_unsafe_path(self):
        candidate = self._v5_candidate()
        candidate["link_states"]["context_escape"] = "unknown"
        candidate["verdict"] = "insufficient_evidence"
        candidate["evidence_gap"] = {
            "missing_link": "context_escape",
            "searched_files": ["eval-0001/plugin.php"],
        }
        candidate["open_preconditions"] = [{
            "kind": "server_normalization",
            "affected_link": "context_escape",
            "resolution_boundary": "runtime_environment",
            "unresolved_fact": "request-target normalization is outside supplied source",
            "evidence_step_ids": ["step-03"],
        }]
        blind_pilot.validate_review_v5_shape(
            {**self._valid_v5_review("a" * 64), "primary_candidate": candidate},
            "eval-0001",
        )

    def test_v5_no_finding_has_null_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blind, source_hash = self._make_v5_pilot(root, with_finding=False)
            candidate = self._v5_candidate(rank=None)
            candidate.update({
                "path_kind": "unresolved",
                "verdict": "insufficient_evidence",
                "confidence": "low",
                "trace_steps": [],
                "context": {"kind": "unknown", "delimiter": "unknown"},
                "evidence_gap": {
                    "missing_link": "source",
                    "searched_files": ["eval-0001/plugin.php"],
                },
            })
            candidate["link_states"].update({
                "source": "unknown",
                "sink": "unknown",
                "reachability": "unknown",
                "context_escape": "unknown",
            })
            review = self._valid_v5_review(source_hash)
            review["primary_candidate"] = candidate
            bundle = blind_pilot.read_json(
                blind / "review_bundles_v5" / "eval-0001.json"
            )
            self.assertIsNone(bundle["primary_finding_identity"])
            blind_pilot.validate_review_v5_against_bundle(
                review, bundle, blind_root=blind, eval_id="eval-0001"
            )

    def test_v5_synthetic_attachment_accumulator_binds_to_assignment_and_source_token(self):
        identity = {
            "finding_global_rank": 4952,
            "path": "eval-0099/hk_exif_tags.php",
            "line": 180,
            "anchor_kind": "sink",
            "anchor_match": "attachment_exif_return_accumulator",
            "source_kind": "variable_flow",
            "source_match": "$pcamera, $pmake",
            "sink_kind": "html_output",
            "context": "html",
        }
        candidate = {
            "trace_steps": [{
                "kind": "sink",
                "path": "eval-0099/hk_exif_tags.php",
                "line_start": 180,
                "line_end": 180,
                "expression": "$result = $result . $pmake . ' ' . $pcamera;",
                "finding_global_ranks": [4952],
            }]
        }
        self.assertTrue(blind_review_v5._anchor_matches(candidate, identity))
        candidate["trace_steps"][0]["expression"] = "$result = $result . $other;"
        self.assertFalse(blind_review_v5._anchor_matches(candidate, identity))


if __name__ == "__main__":
    unittest.main()
