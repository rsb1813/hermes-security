# Verifies HermesBench scoring behavior.

from __future__ import annotations

import json
import unittest

from benchmarks.hermesbench.contracts import parse_oracle, parse_prediction
from benchmarks.hermesbench.scoring import ScoringError, location_matches, score_run


def location(path: str, line: int) -> dict[str, object]:
    return {"file": path, "line": line}


GOLD_PATH = {
    "path_id": "path-1",
    "entry_point": location("src/api.py", 10),
    "critical_operation": location("src/db.py", 20),
    "trace": [location("src/policy.py", 15)],
}
VULNERABLE_ORACLE = {
    "schema_version": 1,
    "task_id": "hb-vulnerable",
    "kind": "vulnerable",
    "group_id": "group-a",
    "split": "hidden_test",
    "category": "authorization",
    "language": "python",
    "paths": [GOLD_PATH],
    "retired_paths": [],
}
FIXED_ORACLE = {
    "schema_version": 1,
    "task_id": "hb-fixed",
    "kind": "fixed",
    "group_id": "group-a",
    "split": "hidden_test",
    "category": "authorization",
    "language": "python",
    "paths": [],
    "retired_paths": [GOLD_PATH],
}
FINDING = {
    "finding_id": "f-1",
    "entry_point": location("src/api.py", 10),
    "critical_operation": location("src/db.py", 20),
    "trace": [location("src/policy.py", 15)],
    "confidence": 0.9,
}


def parsed_prediction(task_id: str, findings: list[dict[str, object]]):
    return parse_prediction(
        {"schema_version": 1, "task_id": task_id, "findings": findings}
    )


def score_fixture_with_trace(
    gold_trace: list[dict[str, object]], predicted_trace: list[dict[str, object]]
):
    oracle = parse_oracle(VULNERABLE_ORACLE | {"paths": [GOLD_PATH | {"trace": gold_trace}]})
    fixed = parse_oracle(FIXED_ORACLE)
    prediction = parsed_prediction(
        "hb-vulnerable", [FINDING | {"trace": predicted_trace}]
    )
    return score_run(
        {"hb-vulnerable": oracle, "hb-fixed": fixed},
        {
            "hb-vulnerable": prediction,
            "hb-fixed": parsed_prediction("hb-fixed", []),
        },
    )


def score_fixture_with_fixed_prediction(finding: dict[str, object]):
    return score_run(
        {
            "hb-vulnerable": parse_oracle(VULNERABLE_ORACLE),
            "hb-fixed": parse_oracle(FIXED_ORACLE),
        },
        {
            "hb-vulnerable": parsed_prediction("hb-vulnerable", [FINDING]),
            "hb-fixed": parsed_prediction("hb-fixed", [finding]),
        },
    )


class LocationMatchingTests(unittest.TestCase):
    def test_line_ranges_match_within_tolerance(self) -> None:
        left = parse_oracle(VULNERABLE_ORACLE).paths[0].critical_operation
        right_oracle = VULNERABLE_ORACLE | {
            "task_id": "hb-other",
            "paths": [GOLD_PATH | {"critical_operation": {"file": "src/db.py", "line": "25-27"}}],
        }
        right = parse_oracle(right_oracle).paths[0].critical_operation
        self.assertTrue(location_matches(left, right, tolerance=5))
        self.assertFalse(location_matches(left, right, tolerance=4))

    def test_different_paths_never_match(self) -> None:
        left = parse_oracle(VULNERABLE_ORACLE).paths[0].entry_point
        right_oracle = VULNERABLE_ORACLE | {
            "task_id": "hb-other",
            "paths": [GOLD_PATH | {"entry_point": location("src/other.py", 10)}],
        }
        right = parse_oracle(right_oracle).paths[0].entry_point
        self.assertFalse(location_matches(left, right, tolerance=100))


class ScoringTests(unittest.TestCase):
    def test_split_scores_preserve_unseen_split_metrics(self) -> None:
        hidden_vulnerable = VULNERABLE_ORACLE | {"task_id": "hb-hidden-vulnerable"}
        hidden_fixed = FIXED_ORACLE | {"task_id": "hb-hidden-fixed"}
        rotating_vulnerable = VULNERABLE_ORACLE | {
            "task_id": "hb-rotating-vulnerable",
            "split": "rotating_audit",
        }
        rotating_fixed = FIXED_ORACLE | {
            "task_id": "hb-rotating-fixed",
            "split": "rotating_audit",
        }
        rotating_clean = FIXED_ORACLE | {
            "task_id": "hb-rotating-clean",
            "kind": "clean",
            "split": "rotating_audit",
            "retired_paths": [],
        }
        result = score_run(
            {
                oracle["task_id"]: parse_oracle(oracle)
                for oracle in (
                    hidden_vulnerable,
                    hidden_fixed,
                    rotating_vulnerable,
                    rotating_fixed,
                    rotating_clean,
                )
            },
            {
                "hb-hidden-vulnerable": parsed_prediction(
                    "hb-hidden-vulnerable", [FINDING]
                ),
                "hb-hidden-fixed": parsed_prediction("hb-hidden-fixed", []),
                "hb-rotating-vulnerable": parsed_prediction(
                    "hb-rotating-vulnerable", []
                ),
                "hb-rotating-fixed": parsed_prediction("hb-rotating-fixed", [FINDING]),
                "hb-rotating-clean": parsed_prediction("hb-rotating-clean", [FINDING]),
            },
        )

        self.assertEqual(
            tuple(task.split for task in result.tasks),
            (
                "hidden_test",
                "hidden_test",
                "rotating_audit",
                "rotating_audit",
                "rotating_audit",
            ),
        )
        self.assertEqual(
            tuple(score.split for score in result.split_scores),
            ("hidden_test", "rotating_audit"),
        )
        hidden, rotating = result.split_scores
        self.assertEqual(
            (hidden.pair_true_positives, hidden.pair_false_positives, hidden.pair_false_negatives),
            (1, 0, 0),
        )
        self.assertEqual(
            (hidden.trace_true_positives, hidden.trace_false_positives, hidden.trace_false_negatives),
            (1, 0, 0),
        )
        self.assertEqual(
            (hidden.advisory_recall, hidden.fixed_snapshot_specificity, hidden.composite_score),
            (1.0, 1.0, 1.0),
        )
        self.assertEqual(
            (rotating.pair_true_positives, rotating.pair_false_positives, rotating.pair_false_negatives),
            (0, 0, 1),
        )
        self.assertEqual(
            (rotating.trace_true_positives, rotating.trace_false_positives, rotating.trace_false_negatives),
            (0, 0, 1),
        )
        self.assertEqual(
            (rotating.advisory_recall, rotating.fixed_snapshot_specificity, rotating.composite_score),
            (0.0, 0.0, 0.0),
        )
        self.assertEqual(
            (result.pair_true_positives, result.pair_false_positives, result.pair_false_negatives),
            (1, 0, 1),
        )
        self.assertEqual(
            (result.advisory_recall, result.fixed_snapshot_specificity, result.composite_score),
            (0.5, 0.5, 0.6),
        )
        encoded = result.to_json()
        self.assertEqual(encoded["split_scores"][0]["split"], "hidden_test")
        self.assertNotIn("tasks", encoded["split_scores"][0])
        json.dumps(encoded)

    def test_duplicate_predictions_do_not_inflate_pair_recall(self) -> None:
        duplicate = FINDING | {"finding_id": "f-2"}
        result = score_run(
            {
                "hb-vulnerable": parse_oracle(VULNERABLE_ORACLE),
                "hb-fixed": parse_oracle(FIXED_ORACLE),
            },
            {
                "hb-vulnerable": parsed_prediction(
                    "hb-vulnerable", [FINDING, duplicate]
                ),
                "hb-fixed": parsed_prediction("hb-fixed", []),
            },
        )

        self.assertEqual(result.pair_true_positives, 1)
        self.assertEqual(result.pair_false_positives, 1)
        self.assertEqual(result.pair_false_negatives, 0)
        self.assertAlmostEqual(result.pair_localization_f1, 2 / 3)

    def test_reversed_trace_nodes_receive_partial_trace_credit(self) -> None:
        result = score_fixture_with_trace(
            gold_trace=[location("src/a.py", 1), location("src/b.py", 2)],
            predicted_trace=[location("src/b.py", 2), location("src/a.py", 1)],
        )
        self.assertAlmostEqual(result.trace_node_f1, 0.5)

    def test_matching_prefers_the_assignment_with_more_trace_evidence(self) -> None:
        second_path = GOLD_PATH | {
            "path_id": "path-2",
            "trace": [location("src/other-policy.py", 15)],
        }
        oracle = parse_oracle(
            VULNERABLE_ORACLE | {"paths": [GOLD_PATH, second_path]}
        )
        predictions = parsed_prediction(
            "hb-vulnerable",
            [
                FINDING,
                FINDING
                | {
                    "finding_id": "f-2",
                    "trace": [location("src/other-policy.py", 15)],
                },
            ],
        )
        result = score_run(
            {"hb-vulnerable": oracle}, {"hb-vulnerable": predictions}
        )
        self.assertEqual(result.pair_true_positives, 2)
        self.assertEqual(result.trace_true_positives, 2)

    def test_retired_path_prediction_reduces_fixed_specificity(self) -> None:
        result = score_fixture_with_fixed_prediction(FINDING)
        self.assertEqual(result.fixed_true_negatives, 0)
        self.assertEqual(result.fixed_false_positives, 1)
        self.assertEqual(result.fixed_snapshot_specificity, 0.0)

    def test_unrelated_fixed_snapshot_finding_requires_adjudication(self) -> None:
        unrelated = FINDING | {
            "entry_point": location("src/other.py", 3),
            "critical_operation": location("src/other.py", 9),
        }
        result = score_fixture_with_fixed_prediction(unrelated)
        self.assertEqual(result.fixed_snapshot_specificity, 1.0)
        self.assertEqual(result.provisional_findings, 1)

    def test_missing_prediction_is_scored_as_empty(self) -> None:
        result = score_run({"hb-vulnerable": parse_oracle(VULNERABLE_ORACLE)}, {})
        self.assertEqual(result.pair_false_negatives, 1)
        self.assertEqual(result.advisory_recall, 0.0)

    def test_prediction_for_unknown_task_is_rejected(self) -> None:
        with self.assertRaisesRegex(ScoringError, "unknown task"):
            score_run(
                {"hb-vulnerable": parse_oracle(VULNERABLE_ORACLE)},
                {"unknown": parsed_prediction("unknown", [])},
            )

    def test_composite_uses_the_published_weights(self) -> None:
        result = score_run(
            {
                "hb-vulnerable": parse_oracle(VULNERABLE_ORACLE),
                "hb-fixed": parse_oracle(FIXED_ORACLE),
            },
            {
                "hb-vulnerable": parsed_prediction("hb-vulnerable", [FINDING]),
                "hb-fixed": parsed_prediction("hb-fixed", []),
            },
        )
        self.assertEqual(result.composite_score, 1.0)
        json.dumps(result.to_json())


if __name__ == "__main__":
    unittest.main()
