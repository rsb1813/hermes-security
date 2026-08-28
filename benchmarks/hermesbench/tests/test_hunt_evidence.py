"""Tests for deterministic Hunt artifact preparation and attestation."""

from __future__ import annotations

import tempfile
import unittest
import os
from pathlib import Path
from unittest.mock import patch

from benchmarks.hermesbench import hunt_evidence
from benchmarks.hermesbench.hunt_evidence import (
    HuntEvidenceError,
    attest_hunt_discovery,
    prepare_hunt_artifacts,
)
from benchmarks.hermesbench.hunt_protocol import parse_hunt_discovery_prediction


class HuntEvidencePreparationTests(unittest.TestCase):
    """Exercises the real bundled helpers through the public evidence interface."""

    def _snapshot(self, root: Path) -> Path:
        snapshot = root / "snapshot"
        (snapshot / "src").mkdir(parents=True)
        (snapshot / "docs").mkdir()
        (snapshot / "tests").mkdir()
        (snapshot / "src" / "entry.py").write_text("def handle(request):\n    return request.get('token')\n", encoding="utf-8")
        (snapshot / "src" / "sink.py").write_text("def store(value):\n    execute(value)\n", encoding="utf-8")
        (snapshot / "src" / "control.py").write_text("def allowed(value):\n    return value in {'safe'}\n", encoding="utf-8")
        (snapshot / "src" / "ordinary.py").write_text("VALUE = 1\n", encoding="utf-8")
        (snapshot / "docs" / "guide.md").write_text("documentation\n", encoding="utf-8")
        (snapshot / "tests" / "test_ignored.py").write_text("def test_value():\n    assert True\n", encoding="utf-8")
        (snapshot / "asset.bin").write_bytes(b"\x00\x01")
        return snapshot

    def test_preparation_preserves_inventory_and_frontier_deterministically(self) -> None:
        # Removing deterministic preparation would make this test fail.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self._snapshot(root)
            first = prepare_hunt_artifacts(snapshot, root / "scratch-one", "hunt-balanced")
            second = prepare_hunt_artifacts(snapshot, root / "scratch-two", "hunt-balanced")
            self.assertEqual(first.preparation_fingerprint, second.preparation_fingerprint)
            self.assertEqual(first.inventory_count, 7)
            self.assertEqual(first.frontier_count, 4)

    def test_priority_packet_is_bounded_without_reducing_frontier(self) -> None:
        # Removing the bounded priority projection would make this test fail.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self._snapshot(root)
            for number in range(600):
                (snapshot / "src" / f"module_{number:04d}.py").write_text("def read_input(value):\n    return value\n", encoding="utf-8")
            prepared = prepare_hunt_artifacts(snapshot, root / "scratch", "hunt-balanced")
            self.assertLessEqual(prepared.priority_count, 512)
            self.assertLessEqual(prepared.priority_bytes, 1024 * 1024)
            self.assertGreater(prepared.frontier_count, prepared.priority_count)


class HuntEvidenceAttestationTests(HuntEvidencePreparationTests):
    """Proves that post-execution artifact and provenance changes fail closed."""

    _PACKET_READ = ("cat", "/workspace/scratch/hermesbench-hunt/priority-packet.jsonl")

    def _prepared_prediction(self, root: Path):
        snapshot = self._snapshot(root)
        prepared = prepare_hunt_artifacts(snapshot, root / "scratch", "hunt-balanced")
        prediction = parse_hunt_discovery_prediction(
            {
                "schema_version": 1,
                "task_id": "task-1",
                "candidates": [
                    {
                        "finding_id": "candidate-1",
                        "entry_point": {"file": "src/entry.py", "line": 1},
                        "critical_operation": {"file": "src/sink.py", "line": 1},
                        "trace": [{"file": "src/control.py", "line": 1}],
                        "confidence": 0.5,
                        "vulnerability_family": "injection",
                        "search_pass": "forward",
                        "hypothesis": "bounded hypothesis",
                        "evidence": "bounded evidence",
                        "counterevidence": "bounded counterevidence",
                        "expected_control": "bounded control",
                    }
                ],
            },
            "task-1",
        )
        return prepared, prediction

    def test_missing_artifact_fails_closed(self) -> None:
        # Removing a trusted artifact after preparation must invalidate attestation.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            prepared.frontier.path.unlink()
            with self.assertRaises(HuntEvidenceError):
                attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))

    def test_byte_mutation_fails_closed(self) -> None:
        # Changing an artifact byte after preparation must invalidate attestation.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            prepared.priority_packet.path.write_bytes(prepared.priority_packet.path.read_bytes() + b" ")
            with self.assertRaises(HuntEvidenceError):
                attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))

    def test_oversized_artifact_fails_closed(self) -> None:
        # Exceeding the priority packet limit must invalidate attestation.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            prepared.priority_packet.path.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaises(HuntEvidenceError):
                attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))

    def test_symlink_artifact_fails_closed_when_supported(self) -> None:
        # Replacing an artifact with a symbolic link must be rejected.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            target = prepared.plan_directory / "target.jsonl"
            target.write_bytes(prepared.priority_packet.path.read_bytes())
            prepared.priority_packet.path.unlink()
            try:
                prepared.priority_packet.path.symlink_to(target)
            except OSError:
                self.skipTest("symbolic links are unavailable")
            with self.assertRaises(HuntEvidenceError):
                attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))

    def test_hardlink_artifact_fails_closed(self) -> None:
        # Increasing an artifact link count must be rejected.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            try:
                os.link(prepared.frontier.path, prepared.plan_directory / "frontier-copy.jsonl")
            except OSError as error:
                self.skipTest(f"hard links are unavailable: {error}")
            with self.assertRaises(HuntEvidenceError):
                attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))

    def test_low_level_read_replacement_fails_closed(self) -> None:
        # Replacing the file during a low-level read must invalidate its identity.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            original_read = hunt_evidence.os.read
            replaced = False

            def replace_after_open(descriptor: int, size: int) -> bytes:
                nonlocal replaced
                if not replaced:
                    replaced = True
                    prepared.frontier.path.unlink()
                    prepared.frontier.path.write_bytes(b"{}\n")
                return original_read(descriptor, size)

            with patch.object(hunt_evidence.os, "read", side_effect=replace_after_open):
                with self.assertRaises(HuntEvidenceError):
                    attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))

    def test_unknown_candidate_path_fails_closed(self) -> None:
        # A candidate location outside the inventory must be rejected.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            candidate = prediction.candidates[0]
            malformed = parse_hunt_discovery_prediction(
                {"schema_version": 1, "task_id": "task-1", "candidates": [{"finding_id": candidate.finding_id, "entry_point": {"file": "missing.py", "line": 1}, "critical_operation": {"file": "src/sink.py", "line": 1}, "trace": [], "confidence": candidate.confidence, "vulnerability_family": candidate.vulnerability_family, "search_pass": candidate.search_pass, "hypothesis": candidate.hypothesis, "evidence": candidate.evidence, "counterevidence": candidate.counterevidence, "expected_control": candidate.expected_control}]},
                "task-1",
            )
            with self.assertRaises(HuntEvidenceError):
                attest_hunt_discovery(prepared, malformed, (self._PACKET_READ,))

    def test_case_ambiguous_candidate_path_fails_closed(self) -> None:
        # Case changes must not be normalized into a frontier location.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            candidate = prediction.candidates[0]
            malformed = parse_hunt_discovery_prediction(
                {"schema_version": 1, "task_id": "task-1", "candidates": [{"finding_id": candidate.finding_id, "entry_point": {"file": "SRC/ENTRY.py", "line": 1}, "critical_operation": {"file": "src/sink.py", "line": 1}, "trace": [], "confidence": candidate.confidence, "vulnerability_family": candidate.vulnerability_family, "search_pass": candidate.search_pass, "hypothesis": candidate.hypothesis, "evidence": candidate.evidence, "counterevidence": candidate.counterevidence, "expected_control": candidate.expected_control}]},
                "task-1",
            )
            with self.assertRaises(HuntEvidenceError):
                attest_hunt_discovery(prepared, malformed, (self._PACKET_READ,))

    def test_incompatible_search_pass_fails_closed(self) -> None:
        # A search pass absent from every linked frontier row must be rejected.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            candidate = prediction.candidates[0]
            malformed = parse_hunt_discovery_prediction(
                {"schema_version": 1, "task_id": "task-1", "candidates": [{"finding_id": candidate.finding_id, "entry_point": {"file": "src/entry.py", "line": 1}, "critical_operation": {"file": "src/sink.py", "line": 1}, "trace": [], "confidence": candidate.confidence, "vulnerability_family": candidate.vulnerability_family, "search_pass": "state", "hypothesis": candidate.hypothesis, "evidence": candidate.evidence, "counterevidence": candidate.counterevidence, "expected_control": candidate.expected_control}]},
                "task-1",
            )
            with self.assertRaises(HuntEvidenceError):
                attest_hunt_discovery(prepared, malformed, (self._PACKET_READ,))

    def test_linkage_does_not_reduce_coverage_debt(self) -> None:
        # Packet presentation and candidate links must never become reviewed closure.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            evidence = attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))
            self.assertEqual(evidence.candidate_count, 1)
            self.assertEqual(evidence.linked_location_count, 3)
            self.assertEqual(evidence.coverage_debt_count, prepared.frontier_pass_count)
            self.assertEqual(evidence.validated_closure_count, 0)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(os.environ.get("HERMESBENCH_LARGE_ARTIFACT_SMOKE") == "1", "large artifact smoke is opt-in")
class HuntEvidenceLargeSmokeTests(unittest.TestCase):
    """Exercises fixed artifact limits with a synthetic large repository."""

    def test_preparation_is_deterministic_at_large_inventory_scale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            for number in range(11_277):
                (snapshot / f"source_{number:05d}.py").write_text("def request_handler(request):\n    return execute(request)\n", encoding="utf-8")
            for number in range(3_750):
                (snapshot / f"note_{number:05d}.txt").write_text("note\n", encoding="utf-8")
            first = prepare_hunt_artifacts(snapshot, root / "first", "hunt-balanced")
            second = prepare_hunt_artifacts(snapshot, root / "second", "hunt-balanced")
            self.assertEqual(first.inventory_count, 15_027)
            self.assertEqual(first.frontier_count, 11_277)
            self.assertEqual(first.preparation_fingerprint, second.preparation_fingerprint)
            self.assertLessEqual(first.priority_count, 512)
            self.assertLessEqual(first.priority_bytes, 1024 * 1024)
