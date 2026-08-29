# Verifies reproducible HermesBench run receipts.

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from benchmarks.hermesbench.receipts import (
    RECEIPT_SCHEMA_VERSION,
    RunConfig,
    RunReceipt,
    TaskRunReceipt,
    TokenUsage,
    comparison_mismatches,
    load_receipt,
    sha256_file,
    write_receipt,
)


CONFIG = RunConfig(
    manifest_sha256="a" * 64,
    task_order_sha256="b" * 64,
    execution_policy_sha256="c" * 64,
    grader_version="0.1.0",
    model="gpt-test",
    reasoning_effort="medium",
    seed="12345",
    seed_supported=True,
    tool_versions=(("python", "3.14.6"), ("scanner", "1.0.0")),
    time_limit_seconds=300,
)
USAGE = TokenUsage(
    cached_input_tokens=1200,
    uncached_input_tokens=300,
    output_tokens=90,
)
RECEIPT = RunReceipt(
    schema_version=RECEIPT_SCHEMA_VERSION,
    run_id="run-001",
    workflow="standard",
    profile="baseline",
    config=CONFIG,
    elapsed_seconds=12.5,
    status="completed",
    failure_evidence_sha256="d" * 64,
    token_usage=USAGE,
)


class TokenUsageTests(unittest.TestCase):
    def test_token_classes_remain_separate(self) -> None:
        self.assertEqual(
            USAGE.to_json(),
            {
                "cached_input_tokens": 1200,
                "uncached_input_tokens": 300,
                "output_tokens": 90,
            },
        )

    def test_negative_tokens_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-negative"):
            TokenUsage(-1, 0, 0)

    def test_boolean_tokens_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "integers"):
            TokenUsage(True, 0, 0)


class ComparisonTests(unittest.TestCase):
    def test_comparison_rejects_different_execution_policy(self) -> None:
        hunt = CONFIG.replace(execution_policy_sha256="d" * 64)
        self.assertEqual(
            comparison_mismatches(CONFIG, hunt), ["execution_policy_sha256"]
        )

    def test_comparison_rejects_different_reasoning_effort(self) -> None:
        hunt = CONFIG.replace(reasoning_effort="high")
        self.assertEqual(comparison_mismatches(CONFIG, hunt), ["reasoning_effort"])

    def test_comparison_reports_every_changed_control_in_sorted_order(self) -> None:
        changed = CONFIG.replace(model="other", seed="999", time_limit_seconds=600)
        self.assertEqual(
            comparison_mismatches(CONFIG, changed),
            ["model", "seed", "time_limit_seconds"],
        )

    def test_comparison_rejects_different_parallel_task_limits(self) -> None:
        parallel = CONFIG.replace(max_parallel_tasks=2)
        self.assertEqual(
            comparison_mismatches(CONFIG, parallel),
            ["max_parallel_tasks"],
        )

    def test_workflow_and_profile_do_not_change_the_control_config(self) -> None:
        hunt_receipt = RECEIPT.replace(workflow="hunt", profile="hunt-max")
        self.assertEqual(
            comparison_mismatches(RECEIPT.config, hunt_receipt.config), []
        )


class ReceiptSerializationTests(unittest.TestCase):
    def test_task_receipt_records_terminal_status_and_snapshot_hashes(self) -> None:
        receipt = TaskRunReceipt(
            schema_version=RECEIPT_SCHEMA_VERSION,
            task_id="task-001",
            status="contaminated",
            pre_snapshot_sha256="e" * 64,
            post_snapshot_sha256="f" * 64,
            elapsed_seconds=1.5,
            token_usage=USAGE,
        )

        self.assertEqual(
            receipt.to_json(),
            {
                "schema_version": RECEIPT_SCHEMA_VERSION,
                "task_id": "task-001",
                "status": "contaminated",
                "pre_snapshot_sha256": "e" * 64,
                "post_snapshot_sha256": "f" * 64,
                "elapsed_seconds": 1.5,
                "token_usage": USAGE.to_json(),
            },
        )

    def test_receipt_serialization_is_stable_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            write_receipt(output, RECEIPT)
            first = output.read_bytes()
            write_receipt(output, RECEIPT)
            self.assertEqual(output.read_bytes(), first)
            self.assertTrue(first.endswith(b"\n"))
            self.assertEqual(load_receipt(output), RECEIPT)

    def test_parallel_config_is_additive_and_legacy_shape_round_trips(self) -> None:
        legacy = CONFIG.to_json()
        parallel = CONFIG.replace(max_parallel_tasks=2)

        self.assertNotIn("max_parallel_tasks", legacy)
        self.assertEqual(CONFIG, RunConfig.from_json(legacy))
        self.assertEqual(2, parallel.to_json()["max_parallel_tasks"])
        self.assertEqual(parallel, RunConfig.from_json(parallel.to_json()))

    def test_file_hash_is_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_bytes(b"hermes\n")
            self.assertEqual(
                sha256_file(path),
                "d53ba9ce30ffd743f4f905a61ddcf2c4fe0e5c72a2cc57638657fdd4171d1f6f",
            )

    def test_seed_is_absent_when_backend_does_not_support_it(self) -> None:
        with self.assertRaisesRegex(ValueError, "seed must be absent"):
            CONFIG.replace(seed_supported=False)


if __name__ == "__main__":
    unittest.main()
