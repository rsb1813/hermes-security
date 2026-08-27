# Verifies the bounded Hunt candidate and terminal-decision protocol.

from __future__ import annotations

import unittest

from benchmarks.hermesbench.hunt_protocol import (
    HUNT_DISCOVERY_MAX_CANDIDATES,
    HuntProtocolError,
    parse_hunt_discovery_prediction,
    parse_hunt_verification_prediction,
)


def _candidate(number: int = 1) -> dict[str, object]:
    return {
        "finding_id": f"model-{number}",
        "entry_point": {"file": "source.py", "line": 1},
        "critical_operation": {"file": "source.py", "line": 3},
        "trace": [{"file": "source.py", "line": 2}],
        "confidence": 0.8,
        "vulnerability_family": "injection",
        "search_pass": "forward",
        "hypothesis": "Input reaches the critical operation without validation.",
        "evidence": "The trace connects the entry point to the operation.",
        "counterevidence": "No validation was found on this path.",
        "expected_control": "Validate the input before interpretation.",
    }


def _decision(candidate_id: str, disposition: str = "accepted") -> dict[str, object]:
    proofs = {
        "attacker_control": "proven",
        "reachability": "proven",
        "impact": "proven",
        "guard_failure": "proven",
    }
    value: dict[str, object] = {
        "candidate_id": candidate_id,
        "disposition": disposition,
        **proofs,
        "evidence": "Independent tracing confirms the candidate.",
        "counterevidence": "No contradictory guard was found.",
        "proof_gaps": "",
        "confidence": 0.9,
    }
    if disposition == "rejected":
        value["attacker_control"] = "disproven"
    if disposition == "inconclusive":
        value["impact"] = "unknown"
        value["proof_gaps"] = "Impact cannot be established from the snapshot."
    return value


class HuntCandidateProtocolTests(unittest.TestCase):
    def test_discovery_preserves_six_rich_candidates(self) -> None:
        prediction = parse_hunt_discovery_prediction(
            {
                "schema_version": 1,
                "task_id": "task-a",
                "candidates": [_candidate(number) for number in range(1, 7)],
            },
            "task-a",
        )

        self.assertEqual(len(prediction.candidates), 6)
        self.assertEqual(prediction.candidates[5].vulnerability_family, "injection")

    def test_discovery_rejects_thirteenth_and_invalid_rich_text(self) -> None:
        too_many = {
            "schema_version": 1,
            "task_id": "task-a",
            "candidates": [_candidate(number) for number in range(1, HUNT_DISCOVERY_MAX_CANDIDATES + 2)],
        }
        with self.assertRaisesRegex(HuntProtocolError, "at most"):
            parse_hunt_discovery_prediction(too_many, "task-a")

        malformed = _candidate()
        malformed["hypothesis"] = "bad\u0000text"
        with self.assertRaisesRegex(HuntProtocolError, "hypothesis"):
            parse_hunt_discovery_prediction(
                {"schema_version": 1, "task_id": "task-a", "candidates": [malformed]},
                "task-a",
            )

    def test_decision_dispositions_enforce_their_proof_rules(self) -> None:
        for disposition in ("accepted", "rejected", "inconclusive"):
            with self.subTest(disposition=disposition):
                prediction = parse_hunt_verification_prediction(
                    {
                        "schema_version": 1,
                        "task_id": "task-a",
                        "findings": [],
                        "decisions": [_decision("candidate-1", disposition)],
                    },
                    "task-a",
                )
                self.assertEqual(prediction.decisions[0].disposition, disposition)

        invalid = _decision("candidate-1", "accepted")
        invalid["impact"] = "unknown"
        with self.assertRaisesRegex(HuntProtocolError, "accepted"):
            parse_hunt_verification_prediction(
                {"schema_version": 1, "task_id": "task-a", "findings": [], "decisions": [invalid]},
                "task-a",
            )


if __name__ == "__main__":
    unittest.main()
