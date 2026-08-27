# Verifies strict HermesBench data contracts.

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.hermesbench.contracts import (
    ContractError,
    Location,
    load_oracles,
    load_predictions,
    parse_oracle,
    parse_prediction,
)


def location(path: str = "src/auth.py", line: object = 41) -> dict[str, object]:
    return {"file": path, "line": line}


def gold_path(path_id: str = "path-1") -> dict[str, object]:
    return {
        "path_id": path_id,
        "entry_point": location("src/api.py", 10),
        "critical_operation": location("src/db.py", "20-22"),
        "trace": [location("src/policy.py", 15)],
    }


def oracle(kind: str = "vulnerable") -> dict[str, object]:
    return {
        "schema_version": 1,
        "task_id": f"hb-{kind}",
        "kind": kind,
        "group_id": "group-a",
        "split": "hidden_test",
        "category": "authorization",
        "language": "python",
        "paths": [gold_path()] if kind == "vulnerable" else [],
        "retired_paths": [gold_path()] if kind == "fixed" else [],
    }


def finding(finding_id: str = "f-1") -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "entry_point": location("src/api.py", 10),
        "critical_operation": location("src/db.py", 20),
        "trace": [location("src/policy.py", 15)],
        "confidence": 0.8,
    }


def prediction(task_id: str = "hb-vulnerable") -> dict[str, object]:
    return {
        "schema_version": 1,
        "task_id": task_id,
        "findings": [finding()],
    }


class LocationContractTests(unittest.TestCase):
    def test_location_accepts_vulngym_line_ranges(self) -> None:
        self.assertEqual(
            Location.from_json(location(line="41-43")),
            Location(path="src/auth.py", start_line=41, end_line=43),
        )

    def test_location_normalizes_windows_separators(self) -> None:
        self.assertEqual(
            Location.from_json(location(path=r"src\auth.py")),
            Location(path="src/auth.py", start_line=41, end_line=41),
        )

    def test_location_rejects_parent_traversal(self) -> None:
        with self.assertRaisesRegex(ContractError, "repository-relative"):
            Location.from_json(location(path="../secret.py"))

    def test_location_rejects_windows_absolute_paths(self) -> None:
        with self.assertRaisesRegex(ContractError, "repository-relative"):
            Location.from_json(location(path="C:/secret.py"))

    def test_location_rejects_boolean_lines(self) -> None:
        with self.assertRaisesRegex(ContractError, "positive"):
            Location.from_json(location(line=True))


class PredictionContractTests(unittest.TestCase):
    def test_prediction_rejects_more_than_five_findings(self) -> None:
        value = prediction()
        value["findings"] = [finding(f"f-{index}") for index in range(6)]
        with self.assertRaisesRegex(ContractError, "at most 5 findings"):
            parse_prediction(value)

    def test_prediction_rejects_duplicate_finding_ids(self) -> None:
        value = prediction()
        value["findings"] = [finding(), finding()]
        with self.assertRaisesRegex(ContractError, "duplicate finding_id"):
            parse_prediction(value)

    def test_prediction_rejects_confidence_outside_unit_interval(self) -> None:
        value = prediction()
        value["findings"] = [finding() | {"confidence": 1.01}]
        with self.assertRaisesRegex(ContractError, "confidence"):
            parse_prediction(value)

    def test_prediction_rejects_unknown_top_level_fields(self) -> None:
        with self.assertRaisesRegex(ContractError, "exactly"):
            parse_prediction(prediction() | {"debug": True})


class OracleContractTests(unittest.TestCase):
    def test_vulnerable_oracle_requires_a_path(self) -> None:
        with self.assertRaisesRegex(ContractError, "paths"):
            parse_oracle(oracle("vulnerable") | {"paths": []})

    def test_fixed_oracle_requires_a_retired_path(self) -> None:
        with self.assertRaisesRegex(ContractError, "retired_paths"):
            parse_oracle(oracle("fixed") | {"retired_paths": []})

    def test_clean_oracle_requires_empty_path_collections(self) -> None:
        with self.assertRaisesRegex(ContractError, "empty"):
            parse_oracle(oracle("clean") | {"paths": [gold_path()]})

    def test_oracle_rejects_duplicate_path_ids_across_collections(self) -> None:
        value = oracle("fixed")
        value["paths"] = [gold_path()]
        with self.assertRaisesRegex(ContractError, "duplicate path_id"):
            parse_oracle(value)


class JsonlContractTests(unittest.TestCase):
    def test_load_oracles_rejects_duplicate_task_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oracles.jsonl"
            row = oracle()
            path.write_text(
                "\n".join(json.dumps(item) for item in (row, row)),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ContractError, "duplicate task_id"):
                load_oracles(path)

    def test_load_predictions_skips_blank_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "predictions.jsonl"
            path.write_text(
                f"\n{json.dumps(prediction())}\n\n",
                encoding="utf-8",
            )
            loaded = load_predictions(path)
            self.assertEqual(list(loaded), ["hb-vulnerable"])

    def test_load_predictions_reports_the_bad_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "predictions.jsonl"
            path.write_text(
                f"{json.dumps(prediction())}\nnot-json\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ContractError, "line 2"):
                load_predictions(path)


if __name__ == "__main__":
    unittest.main()
