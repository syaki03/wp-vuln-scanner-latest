import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".agents/skills/review-wp-vulnerability-candidates/scripts/plan_parallel_reviews.py"
SPEC = importlib.util.spec_from_file_location("parallel_review_planner", SCRIPT)
PLANNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PLANNER)


def fingerprint(seed):
    return hashlib.sha256(seed.encode("ascii")).hexdigest()


def record(plugin, rank, *, status="pending", selected=1, source_bytes=0, source_files=1):
    return {
        "queue_schema_version": 2,
        "plugin": plugin,
        "queue_rank": rank,
        "plugin_exists": True,
        "inventory_errors": [],
        "plugin_fingerprint": fingerprint(plugin),
        "selected_findings_fingerprint": fingerprint(plugin + "-selected"),
        "review": {"status": status},
        "finding_count": selected + 2,
        "selected_finding_count": selected,
        "source_bytes": source_bytes,
        "source_file_count": source_files,
    }


class ParallelReviewPlannerTests(unittest.TestCase):
    def write_queue(self, directory, records):
        path = directory / "queue.jsonl"
        path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
        return path

    def make_plan(self, records, agents=3):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        return PLANNER.create_plan(self.write_queue(root, records), root / "plan", agents), root / "plan"

    def test_deterministic_lpt_plan(self):
        records = [record("a", 2, selected=12), record("b", 1, selected=12), record("c", 3, selected=1)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            queue = self.write_queue(root, records)
            first_dir = root / "first"
            second_dir = root / "second"
            first = PLANNER.create_plan(queue, first_dir, 2)
            second = PLANNER.create_plan(queue, second_dir, 2)
            self.assertEqual(first, second)
            self.assertEqual((first_dir / "agent-01/queue.jsonl").read_bytes(), (second_dir / "agent-01/queue.jsonl").read_bytes())
            self.assertEqual(["b", "c"], first["agents"][0]["plugins"])
            self.assertEqual(["a"], first["agents"][1]["plugins"])

    def test_reviewed_records_are_excluded_and_eligible_are_exactly_once(self):
        plan, _ = self.make_plan([record("done", 1, status="reviewed"), record("one", 2), record("two", 3)], 2)
        assigned = [plugin for agent in plan["agents"] for plugin in agent["plugins"]]
        self.assertCountEqual(["one", "two"], assigned)
        self.assertNotIn("done", assigned)
        self.assertEqual(2, plan["eligible_plugins"])
        self.assertEqual(1, plan["skipped_reviewed_plugins"])

    def test_duplicate_plugin_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "duplicate plugin"):
                PLANNER.create_plan(self.write_queue(root, [record("same", 1), record("same", 2)]), root / "plan", 2)

    def test_schema_and_fingerprint_validation(self):
        invalid_cases = [
            ("schema", {"queue_schema_version": 1}),
            ("fingerprint", {"plugin_fingerprint": "A" * 64}),
            ("inventory", {"inventory_errors": ["error"]}),
        ]
        for name, update in invalid_cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                item = record("bad", 1)
                item.update(update)
                with self.assertRaises(ValueError):
                    PLANNER.create_plan(self.write_queue(root, [item]), root / "plan", 2)

    def test_existing_output_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "plan"
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "already exists"):
                PLANNER.create_plan(self.write_queue(root, [record("one", 1)]), output, 2)

    def test_fewer_eligible_plugins_than_agents_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "plan"
            queue = self.write_queue(root, [record("done", 1, status="reviewed"), record("one", 2)])
            with self.assertRaisesRegex(ValueError, r"eligible plugin count \(1\) is less than agent count \(2\)"):
                PLANNER.create_plan(queue, output, 2)
            self.assertFalse(output.exists())

    def test_agents_range_is_two_to_four(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            queue = self.write_queue(root, [record("one", 1)])
            for agents in (1, 5):
                with self.subTest(agents=agents):
                    with self.assertRaises(ValueError):
                        PLANNER.create_plan(queue, root / f"plan-{agents}", agents)


if __name__ == "__main__":
    unittest.main()
