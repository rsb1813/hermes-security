# Verifies fail-closed HermesBench snapshot execution.

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import benchmarks.hermesbench.runner as runner
from benchmarks.hermesbench.contracts import BenchmarkManifest, parse_manifest
from benchmarks.hermesbench.receipts import RECEIPT_SCHEMA_VERSION, RunConfig
from benchmarks.hermesbench.runner import (
    ExecutionPolicy,
    ExecutorFailureError,
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
    def test_reparse_point_is_rejected_without_pathlib_junction_support(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            metadata = SimpleNamespace(
                st_mode=stat.S_IFDIR,
                st_file_attributes=0x0400,
            )
            with patch.object(runner.os, "lstat", return_value=metadata):
                with self.assertRaisesRegex(RunnerError, "link or"):
                    runner._assert_path_components_safe(target, "test root")

    def test_lstat_detected_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            metadata = SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
            with patch.object(runner.os, "lstat", return_value=metadata):
                with self.assertRaisesRegex(RunnerError, "link or"):
                    runner._assert_path_components_safe(target, "test root")

    def test_lstat_failure_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            with patch.object(runner.os, "lstat", side_effect=OSError("denied")):
                with self.assertRaisesRegex(RunnerError, "cannot be inspected"):
                    runner._assert_path_components_safe(target, "test root")

    @unittest.skipUnless(os.name == "nt", "Windows junction creation is unavailable")
    def test_actual_windows_junction_is_rejected_when_creation_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            junction = root / "junction"
            target.mkdir()
            created = subprocess.run(
                ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest("Windows junction creation is not permitted")
            with self.assertRaisesRegex(RunnerError, "link or"):
                runner._assert_path_components_safe(junction, "test root")

    def test_linked_snapshots_root_stops_before_adapter_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("task-a", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))

            with patch.object(
                runner,
                "_is_link_or_junction",
                side_effect=lambda path: path == snapshots,
            ):
                with self.assertRaisesRegex(RunnerError, "link or"):
                    run_suite(manifest, snapshots, output, "run-001", "standard", "baseline",
                              config_for(manifest, policy), policy, lambda *_: self.fail("adapter must not run"))

    def test_linked_task_snapshot_stops_before_adapter_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("task-a", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))
            linked_snapshot = snapshots / "task-a"

            with patch.object(
                runner,
                "_is_link_or_junction",
                side_effect=lambda path: path == linked_snapshot,
            ):
                with self.assertRaisesRegex(RunnerError, "link or"):
                    run_suite(manifest, snapshots, output, "run-001", "standard", "baseline",
                              config_for(manifest, policy), policy, lambda *_: self.fail("adapter must not run"))

    def test_dot_segment_task_id_cannot_select_snapshots_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            (snapshots / "nested").mkdir()
            (snapshots / "nested" / "source.py").write_text("value = 1\n", encoding="utf-8")
            manifest = parse_manifest(
                {
                    "schema_version": 1, "suite": "canary", "manifest_id": "runner-test",
                    "tasks": [{"task_id": "nested/.", "snapshot_sha256": tree_sha256(snapshots / "nested"),
                               "language": "python", "allowed_commands": [["python"]],
                               "time_limit_seconds": 17}],
                }
            )
            policy = ExecutionPolicy((("python",),))

            with self.assertRaisesRegex(RunnerError, "task_id"):
                run_suite(manifest, snapshots, output, "run-001", "standard", "baseline",
                          config_for(manifest, policy), policy, lambda *_: self.fail("adapter must not run"))

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

            with patch.object(runner, "_is_link_or_junction", return_value=True):
                with self.assertRaisesRegex(RunnerError, "link or"):
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
    def test_failed_task_persists_only_the_bounded_executor_failure_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("task-a", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))

            def executor(*_: object) -> ExecutorResult:
                raise ExecutorFailureError(
                    "private failure text must not persist",
                    failure_code="final_response_invalid",
                )

            receipt = run_suite(
                manifest,
                snapshots,
                output,
                "run-001",
                "standard",
                "baseline",
                config_for(manifest, policy),
                policy,
                executor,
            )
            task_dir = next((output / "run-001" / "tasks").iterdir())

            self.assertEqual(receipt.status, "failed")
            self.assertEqual(
                json.loads((task_dir / "failure.json").read_text(encoding="utf-8")),
                {"code": "final_response_invalid"},
            )
            self.assertNotIn(
                "private failure text",
                "".join(path.read_text(encoding="utf-8") for path in task_dir.iterdir()),
            )

    def test_reassigned_executor_failure_code_falls_back_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("task-a", "task-b", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))

            def executor(request: object, *_: object) -> ExecutorResult:
                if request.task_id == "task-a":
                    error = ExecutorFailureError(
                        "private executor detail",
                        failure_code="final_response_invalid",
                    )
                    error.failure_code = "unredacted_model_message"
                    raise error
                return ExecutorResult(raw_response(request.task_id), ({"event": "done"},), ())

            receipt = run_suite(
                manifest,
                snapshots,
                output,
                "run-001",
                "standard",
                "baseline",
                config_for(manifest, policy),
                policy,
                executor,
            )
            run_dir = output / "run-001"
            records = [
                json.loads(line)
                for line in (run_dir / "task-receipts.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            failure_path = next((run_dir / "tasks").rglob("failure.json"))

            self.assertEqual(receipt.status, "failed")
            self.assertEqual([record["status"] for record in records], ["failed", "completed"])
            self.assertEqual(json.loads(failure_path.read_text(encoding="utf-8")), {"code": "executor_failure"})
            self.assertNotIn("unredacted_model_message", failure_path.read_text(encoding="utf-8"))

    def test_partial_success_publication_is_replaced_with_failure_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("task-a", "task-b", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))
            original_write_jsonl = runner._write_jsonl
            failed_once = False

            def failing_write_jsonl(path: Path, rows: object) -> None:
                nonlocal failed_once
                if path.name == "events.jsonl" and not failed_once:
                    failed_once = True
                    raise OSError("simulated event write failure")
                original_write_jsonl(path, rows)

            def executor(request: object, *_: object) -> ExecutorResult:
                return ExecutorResult(raw_response(request.task_id), ({"event": "done"},), ())

            with patch.object(runner, "_write_jsonl", side_effect=failing_write_jsonl):
                receipt = run_suite(
                    manifest,
                    snapshots,
                    output,
                    "run-001",
                    "standard",
                    "baseline",
                    config_for(manifest, policy),
                    policy,
                    executor,
                )
            run_dir = output / "run-001"
            records = [
                json.loads(line)
                for line in (run_dir / "task-receipts.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            failed_task = next(path for path in (run_dir / "tasks").iterdir() if (path / "failure.json").exists())

            self.assertEqual(receipt.status, "failed")
            self.assertEqual([record["status"] for record in records], ["failed", "completed"])
            self.assertEqual({path.name for path in failed_task.iterdir()}, {"request.json", "failure.json"})
            self.assertEqual(json.loads((failed_task / "failure.json").read_text(encoding="utf-8")), {"code": "executor_failure"})


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
                (task_work_dir / "worker-only.txt").write_text("private\n", encoding="utf-8")
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
            self.assertNotEqual(received[0][1], task_dirs[0])
            self.assertNotIn("..", task_dirs[0].name)
            self.assertEqual(json.loads((task_dirs[0] / "request.json").read_text(encoding="utf-8"))["task_id"], "nested/task-a")
            self.assertTrue((task_dirs[0] / "adapter-response.json").is_file())
            self.assertTrue((task_dirs[0] / "events.jsonl").is_file())
            self.assertEqual(len((run_dir / "predictions.jsonl").read_text(encoding="utf-8").splitlines()), 1)
            self.assertEqual(len((run_dir / "task-receipts.jsonl").read_text(encoding="utf-8").splitlines()), 1)
            self.assertTrue((run_dir / "receipt.json").is_file())
            self.assertEqual(
                {path.name for path in task_dirs[0].iterdir()},
                {"request.json", "adapter-response.json", "events.jsonl", "commands.jsonl"},
            )
            self.assertEqual(
                json.loads((task_dirs[0] / "commands.jsonl").read_text(encoding="utf-8")),
                {"argv": ["python", "-m", "unittest"]},
            )
            self.assertEqual(
                json.loads((run_dir / "commands.jsonl").read_text(encoding="utf-8")),
                {"task_id": "nested/task-a", "argv": ["python", "-m", "unittest"]},
            )

    def test_malformed_response_and_sensitive_event_are_not_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = root / "snapshots"
            output = root / "output"
            snapshots.mkdir()
            output.mkdir()
            manifest = manifest_for("task-a", snapshots_root=snapshots)
            policy = ExecutionPolicy((("python",),))

            def executor(*_: object) -> ExecutorResult:
                return ExecutorResult(
                    raw_response("task-a") | {"oracle_path": "C:/private/oracle.json"},
                    ({"event": "done", "reasoning": "secret source text"},),
                    (),
                )

            receipt = run_suite(manifest, snapshots, output, "run-001", "standard", "baseline",
                                config_for(manifest, policy), policy, executor)
            task_dir = next((output / "run-001" / "tasks").iterdir())
            self.assertEqual(receipt.status, "failed")
            self.assertFalse((task_dir / "adapter-response.json").exists())
            self.assertFalse((task_dir / "events.jsonl").exists())
            self.assertNotIn("oracle.json", "".join(path.read_text(encoding="utf-8") for path in task_dir.iterdir()))

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
            task_dirs = sorted((output / "run-001" / "tasks").iterdir())
            self.assertEqual(receipt.status, "timeout")
            self.assertEqual([row["status"] for row in records], ["timeout", "failed", "completed"])
            self.assertEqual(len((output / "run-001" / "predictions.jsonl").read_text(encoding="utf-8").splitlines()), 1)
            self.assertEqual(
                sorted(
                    json.loads((path / "failure.json").read_text(encoding="utf-8"))["code"]
                    for path in task_dirs
                    if (path / "failure.json").exists()
                ),
                ["executor_failure", "executor_timeout"],
            )

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


class FailureEvidenceTests(unittest.TestCase):
    def _failure_evidence(self) -> tuple[Path, Path, object]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        tasks = Path(directory.name) / "tasks"
        task_id = "task-a"
        task_directory = tasks / runner._task_directory_name(task_id)
        task_directory.mkdir(parents=True)
        (task_directory / "request.json").write_text("{}\n", encoding="utf-8")
        failure_path = task_directory / "failure.json"
        failure_path.write_bytes(runner._failure_json_bytes("event_stream_failed"))
        record = runner.TaskRunReceipt(
            schema_version=RECEIPT_SCHEMA_VERSION,
            task_id=task_id,
            status="failed",
            pre_snapshot_sha256="a" * 64,
            post_snapshot_sha256="a" * 64,
            elapsed_seconds=0.0,
            token_usage=runner.TokenUsage(0, 0, 0),
        )
        return tasks, failure_path, record

    def test_failure_evidence_rejects_reparse_task_parent(self) -> None:
        tasks, _, record = self._failure_evidence()
        original_lstat = runner.os.lstat

        def reparse_task_parent(path: object) -> object:
            if Path(path) == tasks:
                return SimpleNamespace(
                    st_mode=stat.S_IFDIR,
                    st_file_attributes=runner._FILE_ATTRIBUTE_REPARSE_POINT,
                )
            return original_lstat(path)

        with patch.object(runner.os, "lstat", side_effect=reparse_task_parent):
            with self.assertRaisesRegex(RunnerError, "link or reparse"):
                runner.failure_evidence_sha256(tasks, (record,))

    def test_failure_evidence_rejects_multi_link_failure_file(self) -> None:
        _, failure_path, record = self._failure_evidence()
        tasks = failure_path.parents[1]
        original_lstat = runner.os.lstat

        def multi_link_failure(path: object) -> object:
            if Path(path) == failure_path:
                return SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0, st_nlink=2)
            return original_lstat(path)

        with patch.object(runner.os, "lstat", side_effect=multi_link_failure):
            with self.assertRaisesRegex(RunnerError, "single regular file"):
                runner.failure_evidence_sha256(tasks, (record,))

    def test_failure_evidence_rejects_replacement_after_path_inspection(self) -> None:
        tasks, failure_path, record = self._failure_evidence()
        original_lstat = runner.os.lstat
        original_assert_artifact_tree = runner._assert_artifact_tree
        inspection_complete = False
        replaced = False

        def mark_inspection_complete(path: Path, names: set[str]) -> None:
            nonlocal inspection_complete
            original_assert_artifact_tree(path, names)
            inspection_complete = True

        def replace_after_path_inspection(path: object) -> object:
            nonlocal replaced
            metadata = original_lstat(path)
            if inspection_complete and Path(path) == failure_path and not replaced:
                replacement = failure_path.with_name("replacement.json")
                replacement.write_bytes(runner._failure_json_bytes("event_stream_failed"))
                os.replace(replacement, failure_path)
                replaced = True
            return metadata

        with (
            patch.object(runner, "_assert_artifact_tree", side_effect=mark_inspection_complete),
            patch.object(runner.os, "lstat", side_effect=replace_after_path_inspection),
        ):
            with self.assertRaisesRegex(RunnerError, "identity"):
                runner.failure_evidence_sha256(tasks, (record,))

    def test_failure_evidence_rejects_noncanonical_and_invalid_json(self) -> None:
        tasks, failure_path, record = self._failure_evidence()
        for value in (
            '{"code":"event_stream_failed"}\n',
            '{\n  "code": "event_stream_failed",\n  "extra": true\n}\n',
            '{\n  "code": "unredacted_model_message"\n}\n',
        ):
            with self.subTest(value=value):
                failure_path.write_bytes(value.encode("utf-8"))
                with self.assertRaisesRegex(RunnerError, "failure evidence"):
                    runner.failure_evidence_sha256(tasks, (record,))


if __name__ == "__main__":
    unittest.main()
