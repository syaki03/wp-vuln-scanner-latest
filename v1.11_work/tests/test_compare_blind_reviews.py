import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "benchmark" / "legacy_xss_core_v1" / "scripts" / "compare_blind_reviews.py"
SPEC = importlib.util.spec_from_file_location("compare_blind_reviews", SCRIPT)
compare_blind_reviews = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(compare_blind_reviews)


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _root(parent, name, verdicts, rank_sets, findings="same-findings"):
    root = parent / name
    blind = root / "blind"
    ids = sorted(verdicts)
    _write_json(blind / "pilot_index.json", {"schema_version": "blind-pilot-index-v1", "cases": [{"eval_id": case_id} for case_id in ids]})
    findings_path = blind / "scan" / "findings.json"
    _write_json(findings_path, {"fixture": findings})
    bundle_path = blind / "review_bundles_v2" / "lock.json"
    _write_json(bundle_path, {"schema_version": "blind-review-bundle-lock-v2", "findings_sha256": _hash(findings_path)})
    hashes = {}
    for case_id in ids:
        review_path = blind / "reviews_v2" / f"{case_id}.json"
        _write_json(review_path, {"schema_version": "blind-review-v2", "eval_id": case_id, "verdict": verdicts[case_id], "selected_finding_global_ranks": rank_sets[case_id]})
        hashes[case_id] = _hash(review_path)
    _write_json(root / "private" / "review_lock_v2.json", {
        "schema_version": "blind-review-lock-v2", "review_count": len(ids), "reviews": hashes,
        "findings_sha256": _hash(findings_path), "bundle_lock_sha256": _hash(bundle_path),
    })
    return root


def _root_v3(parent, name, verdicts, rank_sets):
    root = parent / name
    blind = root / "blind"
    ids = sorted(verdicts)
    _write_json(
        blind / "pilot_index.json",
        {"schema_version": "blind-pilot-index-v1", "cases": [{"eval_id": case_id} for case_id in ids]},
    )
    findings_path = blind / "scan" / "findings.json"
    findings = [
        {"plugin": case_id, "global_rank": rank}
        for case_id in ids
        for rank in sorted(rank_sets[case_id])
    ]
    _write_json(findings_path, findings)
    bundle_path = blind / "review_bundles_v3" / "lock.json"
    _write_json(
        bundle_path,
        {"schema_version": "blind-review-bundle-lock-v3", "findings_sha256": _hash(findings_path)},
    )
    hashes = {}
    for case_id in ids:
        ranks = sorted(rank_sets[case_id])
        review_path = blind / "reviews_v3" / f"{case_id}.json"
        _write_json(
            review_path,
            {
                "schema_version": "blind-review-v3",
                "eval_id": case_id,
                "verdict": verdicts[case_id],
                "primary_selected_finding_global_rank": ranks[0] if ranks else None,
                "secondary_selected_finding_global_ranks": ranks[1:],
            },
        )
        hashes[case_id] = _hash(review_path)
    _write_json(
        root / "private" / "review_lock_v3.json",
        {
            "schema_version": "blind-review-lock-v3",
            "review_count": len(ids),
            "reviews": hashes,
            "findings_sha256": _hash(findings_path),
            "bundle_lock_sha256": _hash(bundle_path),
        },
    )
    return root


def _root_v4(
    parent, name, primary_verdicts, primary_rank_sets, independent_rank_sets=None,
    available_rank_sets=None,
):
    root = parent / name
    blind = root / "blind"
    ids = sorted(primary_verdicts)
    independent_rank_sets = independent_rank_sets or {case_id: {} for case_id in ids}
    _write_json(
        blind / "pilot_index.json",
        {"schema_version": "blind-pilot-index-v1", "cases": [{"eval_id": case_id} for case_id in ids]},
    )
    findings_path = blind / "scan" / "findings.json"
    available_rank_sets = available_rank_sets or {
        case_id: (
            set(primary_rank_sets[case_id])
            | {rank for ranks in independent_rank_sets[case_id].values() for rank in ranks}
        )
        for case_id in ids
    }
    findings = [
        {"plugin": case_id, "global_rank": rank}
        for case_id in ids
        for rank in sorted(available_rank_sets[case_id])
    ]
    _write_json(findings_path, findings)
    bundle_path = blind / "review_bundles_v4" / "lock.json"
    _write_json(
        bundle_path,
        {"schema_version": "blind-review-bundle-lock-v4", "findings_sha256": _hash(findings_path)},
    )
    hashes = {}
    for case_id in ids:
        primary_ranks = sorted(primary_rank_sets[case_id])
        review_path = blind / "reviews_v4" / f"{case_id}.json"
        _write_json(
            review_path,
            {
                "schema_version": "blind-review-v4",
                "eval_id": case_id,
                "primary_candidate": {
                    "candidate_id": "primary",
                    "finding_global_rank": primary_ranks[0] if primary_ranks else None,
                    "supporting_finding_global_ranks": primary_ranks[1:],
                    "verdict": primary_verdicts[case_id],
                },
                "independent_paths": [
                    {
                        "candidate_id": candidate_id,
                        "finding_global_rank": sorted(ranks)[0] if ranks else None,
                        "supporting_finding_global_ranks": sorted(ranks)[1:],
                    }
                    for candidate_id, ranks in sorted(independent_rank_sets[case_id].items())
                ],
            },
        )
        hashes[case_id] = _hash(review_path)
    _write_json(
        root / "private" / "review_lock_v4.json",
        {
            "schema_version": "blind-review-lock-v4",
            "review_count": len(ids),
            "reviews": hashes,
            "findings_sha256": _hash(findings_path),
            "bundle_lock_sha256": _hash(bundle_path),
        },
    )
    return root


def _root_v5(parent, name, primary_verdicts, primary_rank_sets):
    root = _root_v4(parent, name, primary_verdicts, primary_rank_sets)
    blind = root / "blind"
    (blind / "review_bundles_v4").rename(blind / "review_bundles_v5")
    bundle_path = blind / "review_bundles_v5" / "lock.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["schema_version"] = "blind-review-bundle-lock-v5"
    _write_json(bundle_path, bundle)
    (blind / "reviews_v4").rename(blind / "reviews_v5")
    hashes = {}
    for review_path in sorted((blind / "reviews_v5").glob("*.json")):
        review = json.loads(review_path.read_text(encoding="utf-8"))
        review["schema_version"] = "blind-review-v5"
        _write_json(review_path, review)
        hashes[review_path.stem] = _hash(review_path)
    v4_lock = root / "private" / "review_lock_v4.json"
    lock = json.loads(v4_lock.read_text(encoding="utf-8"))
    lock.update({
        "schema_version": "blind-review-lock-v5",
        "reviews": hashes,
        "bundle_lock_sha256": _hash(bundle_path),
    })
    _write_json(root / "private" / "review_lock_v5.json", lock)
    v4_lock.unlink()
    return root


class CompareBlindReviewsTests(unittest.TestCase):
    def test_hand_computed_multiclass_and_binary_kappa(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            left = _root(parent, "left", {
                "eval-0001": "likely_vulnerable", "eval-0002": "possible_vulnerability",
                "eval-0003": "likely_false_positive", "eval-0004": "insufficient_evidence",
            }, {"eval-0001": [3, 1], "eval-0002": [], "eval-0003": [2], "eval-0004": []})
            right = _root(parent, "right", {
                "eval-0001": "likely_vulnerable", "eval-0002": "possible_vulnerability",
                "eval-0003": "insufficient_evidence", "eval-0004": "likely_false_positive",
            }, {"eval-0001": [1, 3], "eval-0002": [], "eval-0003": [], "eval-0004": []})

            result = compare_blind_reviews.compare(left, right)

            self.assertEqual(
                {
                    "schema_version", "review_schema", "case_ids", "locked_inputs", "verdicts",
                    "binary_positive", "selected_rank_sets",
                },
                set(result),
            )
            # P_o=2/4, P_e=4*(1/4*1/4)=1/4, so kappa=(1/2-1/4)/(1-1/4)=1/3.
            self.assertAlmostEqual(1 / 3, result["verdicts"]["exact"]["cohen_kappa"])
            self.assertEqual(2, result["verdicts"]["exact"]["matching_cases"])
            self.assertAlmostEqual(1.0, result["binary_positive"]["agreement"]["cohen_kappa"])
            self.assertEqual(["eval-0003", "eval-0004"], result["verdicts"]["disagreement_ids"])
            self.assertEqual(["eval-0003"], result["selected_rank_sets"]["disagreement_ids"])
            self.assertEqual(1, result["verdicts"]["transitions"]["likely_false_positive"]["insufficient_evidence"])

    def test_refuses_mismatched_findings_and_unlocked_review(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            verdicts = {"eval-0001": "likely_vulnerable"}
            ranks = {"eval-0001": [1]}
            left = _root(parent, "left", verdicts, ranks)
            different_findings = _root(parent, "different", verdicts, ranks, findings="different-findings")
            with self.assertRaisesRegex(ValueError, "findings_sha256"):
                compare_blind_reviews.compare(left, different_findings)

            review = left / "blind" / "reviews_v2" / "eval-0001.json"
            review.write_text(review.read_text(encoding="utf-8").replace("likely_vulnerable", "possible_vulnerability"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "review hash"):
                compare_blind_reviews.compare(left, left)

    def test_v3_compares_primary_and_secondary_rank_set(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            verdicts = {
                "eval-0001": "likely_vulnerable",
                "eval-0002": "likely_false_positive",
            }
            left = _root_v3(parent, "left", verdicts, {"eval-0001": [3, 7], "eval-0002": []})
            right = _root_v3(parent, "right", verdicts, {"eval-0001": [3, 7], "eval-0002": []})
            review_path = right / "blind" / "reviews_v3" / "eval-0001.json"
            review = json.loads(review_path.read_text(encoding="utf-8"))
            review["secondary_selected_finding_global_ranks"] = []
            _write_json(review_path, review)
            lock_path = right / "private" / "review_lock_v3.json"
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
            lock["reviews"]["eval-0001"] = _hash(review_path)
            _write_json(lock_path, lock)

            result = compare_blind_reviews.compare(left, right)

            self.assertEqual("v3", result["review_schema"])
            self.assertNotIn("independent_path_rank_sets", result)
            self.assertEqual(["eval-0001"], result["selected_rank_sets"]["disagreement_ids"])
            self.assertEqual(0.5, result["selected_rank_sets"]["exact_agreement"])

    def test_v3_refuses_selected_rank_outside_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = _root_v3(
                parent,
                "invalid",
                {"eval-0001": "likely_vulnerable"},
                {"eval-0001": [3]},
            )
            review_path = root / "blind" / "reviews_v3" / "eval-0001.json"
            review = json.loads(review_path.read_text(encoding="utf-8"))
            review["secondary_selected_finding_global_ranks"] = [99]
            _write_json(review_path, review)
            lock_path = root / "private" / "review_lock_v3.json"
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
            lock["reviews"]["eval-0001"] = _hash(review_path)
            _write_json(lock_path, lock)

            with self.assertRaisesRegex(ValueError, "selected rank not in findings"):
                compare_blind_reviews.compare(root, root)

    def test_v4_selects_v4_lock_and_uses_primary_verdict_and_ranks(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            verdicts = {"eval-0001": "likely_vulnerable", "eval-0002": "likely_false_positive"}
            left = _root_v4(parent, "left", verdicts, {"eval-0001": [3, 7], "eval-0002": []})
            right = _root_v4(parent, "right", verdicts, {"eval-0001": [3, 7], "eval-0002": []})
            _write_json(left / "private" / "review_lock_v3.json", {"fixture": "v4 must win"})

            result = compare_blind_reviews.compare(left, right)

            self.assertEqual("v4", result["review_schema"])
            self.assertEqual(2, result["verdicts"]["exact"]["matching_cases"])
            self.assertEqual([], result["selected_rank_sets"]["disagreement_ids"])

    def test_v4_independent_paths_are_isolated_and_reported_by_candidate_id(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            verdicts = {"eval-0001": "likely_vulnerable"}
            left = _root_v4(
                parent, "left", verdicts, {"eval-0001": [3]},
                {"eval-0001": {"independent-02": [7, 9], "independent-01": [5]}},
                {"eval-0001": {3, 5, 7, 9, 10}},
            )
            right = _root_v4(
                parent, "right", verdicts, {"eval-0001": [3]},
                {"eval-0001": {"independent-01": [5], "independent-02": [7, 10]}},
                {"eval-0001": {3, 5, 7, 9, 10}},
            )

            result = compare_blind_reviews.compare(left, right)

            self.assertEqual([], result["verdicts"]["disagreement_ids"])
            self.assertEqual([], result["selected_rank_sets"]["disagreement_ids"])
            self.assertEqual(["eval-0001"], result["independent_path_rank_sets"]["disagreement_ids"])

            same = _root_v4(
                parent, "same", verdicts, {"eval-0001": [3]},
                {"eval-0001": {"independent-02": [7, 9], "independent-01": [5]}},
                {"eval-0001": {3, 5, 7, 9, 10}},
            )
            review_path = same / "blind" / "reviews_v4" / "eval-0001.json"
            review = json.loads(review_path.read_text(encoding="utf-8"))
            review["independent_paths"].reverse()
            _write_json(review_path, review)
            lock_path = same / "private" / "review_lock_v4.json"
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
            lock["reviews"]["eval-0001"] = _hash(review_path)
            _write_json(lock_path, lock)

            reordered = compare_blind_reviews.compare(left, same)
            self.assertEqual([], reordered["independent_path_rank_sets"]["disagreement_ids"])

    def test_v4_refuses_primary_or_supporting_rank_outside_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _root_v4(
                Path(directory), "invalid", {"eval-0001": "likely_vulnerable"}, {"eval-0001": [3]}
            )
            review_path = root / "blind" / "reviews_v4" / "eval-0001.json"
            review = json.loads(review_path.read_text(encoding="utf-8"))
            review["primary_candidate"]["supporting_finding_global_ranks"] = [99]
            _write_json(review_path, review)
            lock_path = root / "private" / "review_lock_v4.json"
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
            lock["reviews"]["eval-0001"] = _hash(review_path)
            _write_json(lock_path, lock)

            with self.assertRaisesRegex(ValueError, "selected rank not in findings"):
                compare_blind_reviews.compare(root, root)

    def test_v4_refuses_bundle_lock_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _root_v4(
                Path(directory), "invalid", {"eval-0001": "likely_vulnerable"}, {"eval-0001": [3]}
            )
            bundle_path = root / "blind" / "review_bundles_v4" / "lock.json"
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            bundle["extra"] = "tampered"
            _write_json(bundle_path, bundle)

            with self.assertRaisesRegex(ValueError, "bundle hash"):
                compare_blind_reviews.compare(root, root)

    def test_v5_lock_takes_precedence_and_compares_primary_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            verdicts = {
                "eval-0001": "likely_vulnerable",
                "eval-0002": "likely_false_positive",
            }
            ranks = {"eval-0001": [3, 7], "eval-0002": []}
            left = _root_v5(parent, "left", verdicts, ranks)
            right = _root_v5(parent, "right", verdicts, ranks)

            result = compare_blind_reviews.compare(left, right)

            self.assertEqual("v5", result["review_schema"])
            self.assertEqual(2, result["verdicts"]["exact"]["matching_cases"])
            self.assertIn("independent_path_rank_sets", result)

    def test_canonical_json_is_utf8_and_deterministic(self):
        value = {"z": "日本語", "a": [2, 1]}
        self.assertEqual(b'{"a":[2,1],"z":"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e"}\n', compare_blind_reviews._canonical_json(value))


if __name__ == "__main__":
    unittest.main()
