# Verifies the strict agent-visible HermesBench adapter boundary.

from __future__ import annotations

import unittest

from benchmarks.hermesbench.adapter_contract import (
    AdapterTaskRequest,
    parse_adapter_response,
    parse_adapter_task_request,
)
from benchmarks.hermesbench.contracts import ContractError


REQUEST = {
    "schema_version": 1,
    "task_id": "task-001",
    "snapshot_path": "/workspace/snapshot",
    "language": "python",
    "allowed_commands": [["python", "-m", "unittest"]],
    "time_limit_seconds": 300,
}
PREDICTION = {
    "schema_version": 1,
    "task_id": "task-001",
    "findings": [],
}
USAGE = {
    "input_tokens": 1500,
    "cached_input_tokens": 1200,
    "output_tokens": 90,
}


class AdapterTaskRequestTests(unittest.TestCase):
    def test_request_accepts_only_agent_visible_fields(self) -> None:
        request = parse_adapter_task_request(REQUEST)

        self.assertEqual(
            request,
            AdapterTaskRequest(
                task_id="task-001",
                snapshot_path="/workspace/snapshot",
                language="python",
                allowed_commands=(("python", "-m", "unittest"),),
                time_limit_seconds=300,
            ),
        )

    def test_request_rejects_oracle_data_and_unknown_fields(self) -> None:
        request = dict(REQUEST, oracle_path="/private/oracles/task-001.json")

        with self.assertRaisesRegex(ContractError, "exactly"):
            parse_adapter_task_request(request)

    def test_request_accepts_empty_task_local_commands(self) -> None:
        request = parse_adapter_task_request(dict(REQUEST, allowed_commands=[]))

        self.assertEqual(request.allowed_commands, ())

    def test_request_rejects_invalid_task_local_command_entries(self) -> None:
        invalid_values = (
            "python -m unittest",
            [[]],
            [["python", ""]],
        )

        for allowed_commands in invalid_values:
            with self.subTest(allowed_commands=allowed_commands):
                with self.assertRaises(ContractError):
                    parse_adapter_task_request(
                        dict(REQUEST, allowed_commands=allowed_commands)
                    )


class AdapterResponseTests(unittest.TestCase):
    def test_response_reuses_prediction_and_derives_uncached_usage(self) -> None:
        response = parse_adapter_response(
            {"prediction": PREDICTION, "usage": USAGE}, "task-001"
        )

        self.assertEqual(response.prediction.task_id, "task-001")
        self.assertEqual(response.token_usage.cached_input_tokens, 1200)
        self.assertEqual(response.token_usage.uncached_input_tokens, 300)
        self.assertEqual(response.token_usage.output_tokens, 90)

    def test_response_rejects_mismatched_task_id(self) -> None:
        prediction = dict(PREDICTION, task_id="task-002")

        with self.assertRaisesRegex(ContractError, "task_id"):
            parse_adapter_response({"prediction": prediction, "usage": USAGE}, "task-001")

    def test_response_rejects_too_many_findings(self) -> None:
        prediction = dict(
            PREDICTION,
            findings=[
                {
                    "finding_id": f"finding-{index}",
                    "entry_point": {"file": "app.py", "line": 1},
                    "critical_operation": {"file": "app.py", "line": 2},
                    "trace": [],
                    "confidence": 0.5,
                }
                for index in range(6)
            ],
        )

        with self.assertRaisesRegex(ContractError, "at most"):
            parse_adapter_response({"prediction": prediction, "usage": USAGE}, "task-001")

    def test_response_rejects_cached_input_above_total_input(self) -> None:
        usage = dict(USAGE, cached_input_tokens=1501)

        with self.assertRaisesRegex(ContractError, "cached_input_tokens"):
            parse_adapter_response({"prediction": PREDICTION, "usage": usage}, "task-001")

    def test_response_rejects_unknown_fields_and_negative_usage(self) -> None:
        with self.assertRaisesRegex(ContractError, "exactly"):
            parse_adapter_response(
                {"prediction": PREDICTION, "usage": USAGE, "oracle_label": "vulnerable"},
                "task-001",
            )
        with self.assertRaisesRegex(ContractError, "non-negative"):
            parse_adapter_response(
                {"prediction": PREDICTION, "usage": dict(USAGE, output_tokens=-1)},
                "task-001",
            )


if __name__ == "__main__":
    unittest.main()
