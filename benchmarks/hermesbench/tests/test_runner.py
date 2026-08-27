# Verifies fail-closed HermesBench snapshot execution.

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks.hermesbench.contracts import BenchmarkManifest, parse_manifest
from benchmarks.hermesbench.receipts import RECEIPT_SCHEMA_VERSION, RunConfig
from benchmarks.hermesbench.runner import (
    ExecutionPolicy,
    ExecutorResult,
    ExecutorTimeoutError,
    RunnerError,
    execution_policy_sha256,
    manifest_sha256,
    run_suite,
    task_order_sha256,
)
from benchmarks.hermesbench.sanitize import tree_sha256


def manifest_for(*task_ids: str, snapshots_root: Path) -> BenchmarkManifest:
    tasks = []
    for task_id in task_ids:
        snapshot = snapshots_root / task_id
        snapshot.mkdir(parents=True)
        (snapshot / "source.py").write_text("value = 1\n", encoding="utf-8")
        tasks.append(
            {
                "task_id": task_id,
                "snapshot_sha256": tree_sha256(snapshot),
                "language": "python",
                "allowed_commands": [["python", "-m", "unittest"]],
                "time_limit_seconds": 17,
            }
        )
    return parse_manifest(
        {
            "schema_version": 1,
            "suite": "canary",
            "manifest_id": "runner-test",
            "tasks": tasks,
        }
    )


def config_for(manifest: BenchmarkManifest, policy: ExecutionPolicy) -> RunConfig:
    return RunConfig(
        manifest_sha256=manifest_sha256(manifest),
        task_order_sha256=task_order_sha256(manifest),
        execution_policy_sha256=execution_policy_sha256(policy),
        grader_version="test",
        model="fake",
        reasoning_effort="low",
        seed="1",
        seed_supported=True,
        tool_versions=(("python", "3.14"),),
        time_limit_seconds=17,
    )


def raw_response(task_id: str) -> dict[str, object]:
    return {
        "prediction": {"schema_version": 1, "task_id": task_id, "findings": []},
        "usage": {
            "input_tokens": 10,
            "cached_input_tokens": 4,
            "output_tokens": 2,
        },
    }


class SnapshotPreflightTests(unittest.TestCase):
    def test_hash_mismatch_stops_before_adapter_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("task-a", snapshots_root=snapshots)
            (snapshots / "task-a" / "source.py").write_text("changed\n", encoding="utf-8")

            with self.assertRaisesRegex(RunnerError, "hash"):
                run_suite(
                    manifest,
                    snapshots,
                    output,
                    "run-001",
                    "standard",
                    "baseline",
                    config_for(manifest, ExecutionPolicy((("python",),))),
                    ExecutionPolicy((("python",),)),
                    lambda *_: self.fail("adapter must not run"),
                )
            self.assertFalse((output / "run-001").exists())

    def test_bundle_contamination_stops_before_adapter_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("task-a", snapshots_root=snapshots)
            (snapshots / "task-a" / "source.py").write_text("GHSA-2345-6789-cfgh\n", encoding="utf-8")

            with self.assertRaisesRegex(RunnerError, "contaminated"):
                run_suite(
                    manifest, snapshots, output, "run-001", "standard", "baseline",
                    config_for(manifest, ExecutionPolicy((("python",),))),
                    ExecutionPolicy((("python",),)), lambda *_: self.fail("adapter must not run"),
                )

    def test_missing_snapshot_stops_before_adapter_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = parse_manifest(
                {
                    "schema_version": 1, "suite": "canary", "manifest_id": "runner-test",
                    "tasks": [{"task_id": "missing", "snapshot_sha256": "a" * 64,
                               "language": "python", "allowed_commands": [["python"]],
                               "time_limit_seconds": 17}],
                }
            )
            policy = ExecutionPolicy((("python",),))

            with self.assertRaisesRegex(RunnerError, "missing"):
                run_suite(manifest, snapshots, output, "run-001", "standard", "baseline",
                          config_for(manifest, policy), policy, lambda *_: self.fail("adapter must not run"))

    def test_linked_output_root_stops_before_adapter_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("task-a", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))

            with patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaisesRegex(RunnerError, "link or junction"):
                    run_suite(manifest, snapshots, output, "run-001", "standard", "baseline",
                              config_for(manifest, policy), policy, lambda *_: self.fail("adapter must not run"))

    def test_snapshot_output_overlap_stops_before_adapter_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            snapshots.mkdir()
            manifest = manifest_for("task-a", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))

            with self.assertRaisesRegex(RunnerError, "overlap"):
                run_suite(manifest, snapshots, snapshots, "run-001", "standard", "baseline",
                          config_for(manifest, policy), policy, lambda *_: self.fail("adapter must not run"))


class SuiteExecutionTests(unittest.TestCase):
    def test_completed_task_writes_audited_artifacts_and_aggregates_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("nested/task-a", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))
            received: list[tuple[object, Path, int]] = []

            def executor(request: object, task_work_dir: Path, timeout: int) -> ExecutorResult:
                received.append((request, task_work_dir, timeout))
                return ExecutorResult(raw_response("nested/task-a"), ({"event": "done"},), (("python", "-m", "unittest"),))

            receipt = run_suite(manifest, snapshots, output, "run-001", "standard", "baseline",
                                config_for(manifest, policy), policy, executor)
            run_dir = output / "run-001"
            task_dirs = tuple((run_dir / "tasks").iterdir())
            self.assertEqual(receipt.status, "completed")
            self.assertEqual(receipt.token_usage.cached_input_tokens, 4)
            self.assertEqual(receipt.token_usage.uncached_input_tokens, 6)
            self.assertEqual(receipt.token_usage.output_tokens, 2)
            self.assertEqual(len(received), 1)
            self.assertEqual(received[0][2], 17)
            self.assertEqual(len(task_dirs), 1)
            self.assertNotIn("..", task_dirs[0].name)
            self.assertEqual(json.loads((task_dirs[0] / "request.json").read_text(encoding="utf-8"))["task_id"], "nested/task-a")
            self.assertTrue((task_dirs[0] / "adapter-response.json").is_file())
            self.assertTrue((task_dirs[0] / "events.jsonl").is_file())
            self.assertEqual(len((run_dir / "predictions.jsonl").read_text(encoding="utf-8").splitlines()), 1)
            self.assertEqual(len((run_dir / "task-receipts.jsonl").read_text(encoding="utf-8").splitlines()), 1)
            self.assertTrue((run_dir / "receipt.json").is_file())

    def test_timeout_and_protocol_failure_are_terminal_and_later_tasks_continue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("timeout", "bad", "good", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))

            def executor(request: object, *_: object) -> ExecutorResult:
                task_id = request.task_id
                if task_id == "timeout":
                    raise ExecutorTimeoutError("expired")
                if task_id == "bad":
                    return ExecutorResult({"wrong": "shape"}, (), ())
                return ExecutorResult(raw_response(task_id), (), ())

            receipt = run_suite(manifest, snapshots, output, "run-001", "standard", "baseline",
                                config_for(manifest, policy), policy, executor)
            records = [json.loads(line) for line in (output / "run-001" / "task-receipts.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(receipt.status, "timeout")
            self.assertEqual([row["status"] for row in records], ["timeout", "failed", "completed"])
            self.assertEqual(len((output / "run-001" / "predictions.jsonl").read_text(encoding="utf-8").splitlines()), 1)

    def test_post_run_mutation_or_command_violation_is_contaminated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("mutated", "command", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))

            def executor(request: object, *_: object) -> ExecutorResult:
                if request.task_id == "mutated":
                    Path(request.snapshot_path, "source.py").write_text("changed\n", encoding="utf-8")
                    return ExecutorResult(raw_response(request.task_id), (), ())
                return ExecutorResult(raw_response(request.task_id), (), (("curl", "https://example.test"),))

            receipt = run_suite(manifest, snapshots, output, "run-001", "standard", "baseline",
                                config_for(manifest, policy), policy, executor)
            records = [json.loads(line) for line in (output / "run-001" / "task-receipts.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(receipt.status, "contaminated")
            self.assertEqual([row["status"] for row in records], ["contaminated", "contaminated"])
            self.assertEqual((output / "run-001" / "predictions.jsonl").read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
