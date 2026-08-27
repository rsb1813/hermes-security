# Verifies the deterministic zero-cost HermesBench runner Canary.

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks.hermesbench.adapters.fake import FakeAdapter
from benchmarks.hermesbench.contracts import (
    BenchmarkManifest,
    load_oracles,
    load_predictions,
    parse_manifest,
)
from benchmarks.hermesbench.receipts import RunConfig
from benchmarks.hermesbench.runner import (
    ExecutionPolicy,
    execution_policy_sha256,
    manifest_sha256,
    run_suite,
    task_order_sha256,
)
from benchmarks.hermesbench.sanitize import tree_sha256
from benchmarks.hermesbench.scoring import score_run


def _write_snapshot(root: Path, task_id: str, source: bytes) -> Path:
    snapshot = root / task_id
    snapshot.mkdir(parents=True)
    (snapshot / "service.py").write_bytes(source)
    return snapshot


def _manifest(snapshots: Path) -> BenchmarkManifest:
    tasks = []
    for task_id in ("canary-vulnerable", "canary-fixed"):
        snapshot = snapshots / task_id
        tasks.append(
            {
                "task_id": task_id,
                "snapshot_sha256": tree_sha256(snapshot),
                "language": "python",
                "allowed_commands": [["python", "-m", "unittest"]],
                "time_limit_seconds": 19,
            }
        )
    return parse_manifest(
        {
            "schema_version": 1,
            "suite": "canary",
            "manifest_id": "runner-canary",
            "tasks": tasks,
        }
    )


def _config(manifest: BenchmarkManifest, policy: ExecutionPolicy) -> RunConfig:
    return RunConfig(
        manifest_sha256=manifest_sha256(manifest),
        task_order_sha256=task_order_sha256(manifest),
        execution_policy_sha256=execution_policy_sha256(policy),
        grader_version="canary-test",
        model="fake",
        reasoning_effort="fixed",
        seed="canary-seed",
        seed_supported=True,
        tool_versions=(("fake-adapter", "1"),),
        time_limit_seconds=19,
    )


def _private_oracle_rows() -> tuple[dict[str, object], dict[str, object]]:
    path = {
        "path_id": "path-1",
        "entry_point": {"file": "service.py", "line": 2},
        "critical_operation": {"file": "service.py", "line": 3},
        "trace": [{"file": "service.py", "line": 2}],
    }
    return (
        {
            "schema_version": 1,
            "task_id": "canary-vulnerable",
            "kind": "vulnerable",
            "group_id": "canary-group",
            "split": "public_dev",
            "category": "synthetic",
            "language": "python",
            "paths": [path],
            "retired_paths": [],
        },
        {
            "schema_version": 1,
            "task_id": "canary-fixed",
            "kind": "fixed",
            "group_id": "canary-group",
            "split": "public_dev",
            "category": "synthetic",
            "language": "python",
            "paths": [],
            "retired_paths": [path],
        },
    )


class FakeCanaryTests(unittest.TestCase):
    def test_standard_and_hunt_match_a_private_zero_cost_canary_reproducibly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            outputs = root / "outputs"
            private = root / "private"
            snapshots.mkdir()
            outputs.mkdir()
            private.mkdir()
            _write_snapshot(
                snapshots,
                "canary-vulnerable",
                b"def process(request):\n"
                b"    value = request[\"value\"]\n"
                b"    execute(value)\n",
            )
            _write_snapshot(
                snapshots,
                "canary-fixed",
                b"def process(request):\n"
                b"    value = sanitize(request[\"value\"])\n"
                b"    execute(value)\n",
            )
            oracle_path = private / "oracle.jsonl"
            oracle_path.write_text(
                "".join(
                    json.dumps(row, sort_keys=True) + "\n"
                    for row in _private_oracle_rows()
                ),
                encoding="utf-8",
            )
            oracles = load_oracles(oracle_path)
            manifest = _manifest(snapshots)
            policy = ExecutionPolicy((("python",),))
            config = _config(manifest, policy)
            adapter = FakeAdapter()

            with patch("benchmarks.hermesbench.runner.time.monotonic", return_value=100):
                standard = run_suite(
                    manifest,
                    snapshots,
                    outputs,
                    "standard-001",
                    "standard",
                    "baseline",
                    config,
                    policy,
                    adapter,
                )
                hunt = run_suite(
                    manifest,
                    snapshots,
                    outputs,
                    "hunt-001",
                    "hunt",
                    "baseline",
                    config,
                    policy,
                    adapter,
                )
                repeat_root = root / "repeat-output"
                repeat_root.mkdir()
                repeat = run_suite(
                    manifest,
                    snapshots,
                    repeat_root,
                    "standard-001",
                    "standard",
                    "baseline",
                    config,
                    policy,
                    FakeAdapter(),
                )

            self.assertEqual(standard.status, "completed")
            self.assertEqual(hunt.status, "completed")
            self.assertEqual(standard.token_usage.cached_input_tokens, 14)
            self.assertEqual(standard.token_usage.uncached_input_tokens, 10)
            self.assertEqual(standard.token_usage.output_tokens, 6)
            self.assertEqual(standard.token_usage, hunt.token_usage)
            self.assertEqual(standard.elapsed_seconds, hunt.elapsed_seconds)
            self.assertEqual(standard.config, hunt.config)
            self.assertEqual(standard.config, repeat.config)

            standard_predictions = load_predictions(
                outputs / "standard-001" / "predictions.jsonl"
            )
            hunt_predictions = load_predictions(outputs / "hunt-001" / "predictions.jsonl")
            repeat_predictions = load_predictions(
                repeat_root / "standard-001" / "predictions.jsonl"
            )
            self.assertEqual(standard_predictions, hunt_predictions)
            self.assertEqual(standard_predictions, repeat_predictions)
            self.assertEqual(
                (outputs / "standard-001" / "predictions.jsonl").read_bytes(),
                (outputs / "hunt-001" / "predictions.jsonl").read_bytes(),
            )
            self.assertEqual(score_run(oracles, standard_predictions).composite_score, 1.0)
            self.assertEqual(score_run(oracles, hunt_predictions).composite_score, 1.0)

            private_text = str(oracle_path)
            for observation in adapter.observations:
                self.assertNotIn(
                    private_text, json.dumps(observation.request_json, sort_keys=True)
                )
                self.assertNotIn(private_text, observation.visible_directories)
            self.assertTrue(all(len(item.visible_directories) == 2 for item in adapter.observations))

            self.assertEqual(
                (outputs / "standard-001" / "predictions.jsonl").read_bytes(),
                (repeat_root / "standard-001" / "predictions.jsonl").read_bytes(),
            )
            self.assertEqual(
                (outputs / "standard-001" / "task-receipts.jsonl").read_bytes(),
                (repeat_root / "standard-001" / "task-receipts.jsonl").read_bytes(),
            )
            self.assertEqual(
                (outputs / "standard-001" / "receipt.json").read_bytes(),
                (repeat_root / "standard-001" / "receipt.json").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
