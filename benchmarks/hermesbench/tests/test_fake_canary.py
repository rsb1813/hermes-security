# Verifies the deterministic zero-cost HermesBench runner Canary.

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks.hermesbench.adapters.fake import FakeAdapter
from benchmarks.hermesbench.contracts import BenchmarkManifest, load_oracles, load_predictions, parse_manifest
from benchmarks.hermesbench.receipts import RunConfig, TokenUsage
from benchmarks.hermesbench.runner import (
    ExecutionPolicy,
    execution_policy_sha256,
    manifest_sha256,
    run_suite,
    task_order_sha256,
)
from benchmarks.hermesbench.sanitize import tree_sha256
from benchmarks.hermesbench.scoring import score_run


TASKS = ("case-alpha", "case-beta")
SOURCE_NAMES = ("module-one.py", "module-two.py")
VULNERABLE_SOURCE = (
    b"def process(request):\n"
    b"    untrusted_value = request[\"value\"]\n"
    b"    execute(untrusted_value)\n"
)
FIXED_SOURCE = (
    b"def process(request):\n"
    b"    cleaned_value = sanitize(request[\"value\"])\n"
    b"    execute(cleaned_value)\n"
)


def _materialize_snapshots(
    root: Path,
    sources: tuple[bytes, bytes],
    names: tuple[str, str] = SOURCE_NAMES,
) -> Path:
    snapshots = root / "snapshots"
    snapshots.mkdir()
    for task_id, source_name, source in zip(TASKS, names, sources, strict=True):
        snapshot = snapshots / task_id
        snapshot.mkdir()
        (snapshot / source_name).write_bytes(source)
    return snapshots


def _manifest(snapshots: Path) -> BenchmarkManifest:
    return parse_manifest(
        {
            "schema_version": 1,
            "suite": "canary",
            "manifest_id": "runner-canary",
            "tasks": [
                {
                    "task_id": task_id,
                    "snapshot_sha256": tree_sha256(snapshots / task_id),
                    "language": "python",
                    "allowed_commands": [["python", "-m", "unittest"]],
                    "time_limit_seconds": 19,
                }
                for task_id in TASKS
            ],
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


def _write_private_oracles(private: Path, sentinel: str) -> tuple[Path, dict[str, object]]:
    path = {
        "path_id": "path-1",
        "entry_point": {"file": SOURCE_NAMES[0], "line": 2},
        "critical_operation": {"file": SOURCE_NAMES[0], "line": 3},
        "trace": [{"file": SOURCE_NAMES[0], "line": 2}],
    }
    rows = (
        {
            "schema_version": 1,
            "task_id": TASKS[0],
            "kind": "vulnerable",
            "group_id": "canary-group",
            "split": "public_dev",
            "category": sentinel,
            "language": "python",
            "paths": [path],
            "retired_paths": [],
        },
        {
            "schema_version": 1,
            "task_id": TASKS[1],
            "kind": "fixed",
            "group_id": "canary-group",
            "split": "public_dev",
            "category": sentinel,
            "language": "python",
            "paths": [],
            "retired_paths": [path],
        },
    )
    oracle_path = private / "oracle.jsonl"
    oracle_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    return oracle_path, load_oracles(oracle_path)


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _expected_usage(source: bytes) -> TokenUsage:
    digest = hashlib.sha256(source).digest()
    return TokenUsage(1 + digest[0] % 17, 1 + digest[1] % 17, 1 + digest[2] % 17)


def _task_artifact_names() -> set[str]:
    return {
        f"tasks/{hashlib.sha256(task_id.encode()).hexdigest()}/{name}"
        for task_id in TASKS
        for name in ("request.json", "adapter-response.json", "events.jsonl")
    }


def _run(
    manifest: BenchmarkManifest,
    snapshots: Path,
    outputs: Path,
    run_id: str,
    workflow: str,
    policy: ExecutionPolicy,
    adapter: FakeAdapter,
):
    with patch("benchmarks.hermesbench.runner.time.monotonic", return_value=100):
        return run_suite(
            manifest,
            snapshots,
            outputs,
            run_id,
            workflow,
            "baseline",
            _config(manifest, policy),
            policy,
            adapter,
        )


class FakeCanaryTests(unittest.TestCase):
    def test_source_bytes_control_predictions_under_neutral_ids_and_renamed_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = ExecutionPolicy((("python",),))
            outputs = root / "outputs"
            outputs.mkdir()
            snapshots = _materialize_snapshots(root, (VULNERABLE_SOURCE, FIXED_SOURCE))
            manifest = _manifest(snapshots)
            _run(manifest, snapshots, outputs, "base-001", "standard", policy, FakeAdapter())
            base = load_predictions(outputs / "base-001" / "predictions.jsonl")
            self.assertEqual({task_id for task_id, prediction in base.items() if prediction.findings}, {TASKS[0]})
            self.assertEqual(base[TASKS[0]].findings[0].entry_point.path, SOURCE_NAMES[0])

            swapped_root = root / "swapped"
            swapped_root.mkdir()
            swapped_outputs = swapped_root / "outputs"
            swapped_outputs.mkdir()
            swapped_snapshots = _materialize_snapshots(swapped_root, (FIXED_SOURCE, VULNERABLE_SOURCE))
            swapped_manifest = _manifest(swapped_snapshots)
            _run(swapped_manifest, swapped_snapshots, swapped_outputs, "base-001", "standard", policy, FakeAdapter())
            swapped = load_predictions(swapped_outputs / "base-001" / "predictions.jsonl")
            self.assertEqual({task_id for task_id, prediction in swapped.items() if prediction.findings}, {TASKS[1]})
            self.assertEqual(swapped[TASKS[1]].findings[0].entry_point.path, SOURCE_NAMES[1])

            renamed_root = root / "renamed"
            renamed_root.mkdir()
            renamed_outputs = renamed_root / "outputs"
            renamed_outputs.mkdir()
            renamed_names = ("renamed-left.py", "renamed-right.py")
            renamed_snapshots = _materialize_snapshots(renamed_root, (VULNERABLE_SOURCE, FIXED_SOURCE), renamed_names)
            renamed_manifest = _manifest(renamed_snapshots)
            _run(renamed_manifest, renamed_snapshots, renamed_outputs, "base-001", "standard", policy, FakeAdapter())
            renamed = load_predictions(renamed_outputs / "base-001" / "predictions.jsonl")
            self.assertEqual(renamed[TASKS[0]].findings[0].entry_point.path, renamed_names[0])

    def test_all_public_artifacts_are_private_free_and_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = _materialize_snapshots(root, (VULNERABLE_SOURCE, FIXED_SOURCE))
            outputs = root / "outputs"
            repeat_outputs = root / "repeat-outputs"
            private = root / "private-oracles"
            outputs.mkdir()
            repeat_outputs.mkdir()
            private.mkdir()
            sentinel = "private-oracle-sentinel-8be3c8f0"
            oracle_path, oracles = _write_private_oracles(private, sentinel)
            policy = ExecutionPolicy((("python",),))
            manifest = _manifest(snapshots)
            adapter = FakeAdapter()
            standard = _run(manifest, snapshots, outputs, "standard-001", "standard", policy, adapter)
            repeat = _run(manifest, snapshots, repeat_outputs, "standard-001", "standard", policy, FakeAdapter())

            standard_tree = _tree_bytes(outputs / "standard-001")
            self.assertEqual(standard_tree, _tree_bytes(repeat_outputs / "standard-001"))
            self.assertEqual(
                set(standard_tree),
                {"predictions.jsonl", "task-receipts.jsonl", "receipt.json"} | _task_artifact_names(),
            )
            for contents in standard_tree.values():
                self.assertNotIn(sentinel.encode(), contents)
                self.assertNotIn(str(oracle_path).encode(), contents)
                self.assertNotIn(str(private).encode(), contents)
            for observation in adapter.observations:
                self.assertNotIn(str(oracle_path), json.dumps(observation.request_json))
                self.assertNotIn(str(private), observation.visible_directories)
            predictions = load_predictions(outputs / "standard-001" / "predictions.jsonl")
            self.assertEqual(score_run(oracles, predictions).composite_score, 1.0)
            self.assertEqual(standard.status, repeat.status)

    def test_source_specific_usage_is_aggregated_once_for_each_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = _materialize_snapshots(root, (VULNERABLE_SOURCE, FIXED_SOURCE))
            outputs = root / "outputs"
            private = root / "private-oracles"
            outputs.mkdir()
            private.mkdir()
            policy = ExecutionPolicy((("python",),))
            manifest = _manifest(snapshots)
            adapter = FakeAdapter()
            _, oracles = _write_private_oracles(private, "usage-only-oracle-sentinel")
            standard = _run(manifest, snapshots, outputs, "standard-001", "standard", policy, adapter)
            hunt = _run(manifest, snapshots, outputs, "hunt-001", "hunt", policy, adapter)

            expected = {TASKS[0]: _expected_usage(VULNERABLE_SOURCE), TASKS[1]: _expected_usage(FIXED_SOURCE)}
            self.assertNotEqual(expected[TASKS[0]], expected[TASKS[1]])
            for receipt, run_id in ((standard, "standard-001"), (hunt, "hunt-001")):
                rows = [json.loads(line) for line in (outputs / run_id / "task-receipts.jsonl").read_text(encoding="utf-8").splitlines()]
                actual = {row["task_id"]: TokenUsage.from_json(row["token_usage"]) for row in rows}
                self.assertEqual(actual, expected)
                self.assertEqual(
                    receipt.token_usage,
                    TokenUsage(
                        sum(usage.cached_input_tokens for usage in actual.values()),
                        sum(usage.uncached_input_tokens for usage in actual.values()),
                        sum(usage.output_tokens for usage in actual.values()),
                    ),
                )
                for task_id in TASKS:
                    task_dir = outputs / run_id / "tasks" / hashlib.sha256(task_id.encode()).hexdigest()
                    response = json.loads((task_dir / "adapter-response.json").read_text(encoding="utf-8"))
                    response_usage = TokenUsage(
                        response["usage"]["cached_input_tokens"],
                        response["usage"]["input_tokens"] - response["usage"]["cached_input_tokens"],
                        response["usage"]["output_tokens"],
                    )
                    self.assertEqual(response_usage, actual[task_id])
            self.assertEqual(standard.token_usage, hunt.token_usage)
            self.assertEqual(standard.config, hunt.config)
            standard_predictions = load_predictions(outputs / "standard-001" / "predictions.jsonl")
            hunt_predictions = load_predictions(outputs / "hunt-001" / "predictions.jsonl")
            self.assertEqual(
                score_run(oracles, standard_predictions), score_run(oracles, hunt_predictions)
            )
            self.assertEqual(
                (outputs / "standard-001" / "predictions.jsonl").read_bytes(),
                (outputs / "hunt-001" / "predictions.jsonl").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
