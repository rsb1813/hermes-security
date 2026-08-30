"""Tests for deterministic Hunt artifact preparation and attestation."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import os
from pathlib import Path
from unittest.mock import patch

from benchmarks.hermesbench import hunt_evidence
from benchmarks.hermesbench.hunt_evidence import (
    HuntEvidenceError,
    attest_hunt_discovery,
    parse_hunt_evidence,
    prepare_hunt_artifacts,
)
from benchmarks.hermesbench.hunt_protocol import parse_hunt_discovery_prediction


class HuntEvidencePreparationTests(unittest.TestCase):
    """Exercises the real bundled helpers through the public evidence interface."""

    _PACKET_READ = ("cat", "/workspace/scratch/hermesbench-hunt/priority-packet.jsonl")

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

    def _prediction(self):
        return parse_hunt_discovery_prediction(
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

    def _evidence_payload(self, version: int) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": version,
            "profile": "hunt-balanced",
            "inventory_sha256": "0" * 64,
            "inventory_count": 3,
            "rank_input_sha256": "1" * 64,
            "frontier_sha256": "2" * 64,
            "frontier_count": 3,
            "frontier_pass_count": 3,
            "priority_packet_sha256": "3" * 64,
            "priority_packet_count": 3,
            "candidate_links_sha256": "4" * 64,
            "candidate_count": 1,
            "linked_location_count": 1,
            "coverage_debt_sha256": "5" * 64,
            "coverage_debt_count": 3,
            "validated_closure_count": 0,
        }
        if version in (2, 3, 4, 5):
            payload |= {
                "semantic_guidance_sha256": "6" * 64,
                "semantic_guidance_count": 2,
                "semantic_guidance_edge_count": 4,
                "semantic_guidance_scanned_file_count": 3,
                "semantic_guidance_skipped_file_count": 0,
            }
        return payload

    def _semantic_snapshot(self, root: Path) -> Path:
        snapshot = root / "semantic-snapshot"
        snapshot.mkdir()
        (snapshot / "app.py").write_text(
            "import subprocess\ndef handle(request):\n    return subprocess.run(request.args.get(\"q\"))\n",
            encoding="utf-8",
        )
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

    def test_protocol_one_preserves_legacy_artifact_set_and_evidence_fields(self) -> None:
        # A protocol two change must not alter any protocol one artifact or evidence bytes.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self._snapshot(root)
            prepared = prepare_hunt_artifacts(
                snapshot,
                root / "scratch",
                "hunt-balanced",
                evidence_protocol_version=1,
            )
            self.assertIsNone(prepared.semantic_guidance)
            self.assertEqual(
                sorted(path.name for path in prepared.plan_directory.iterdir()),
                [
                    "frontier-receipt.json",
                    "frontier.jsonl",
                    "in-scope-files.txt",
                    "priority-packet.jsonl",
                    "rank-input.jsonl",
                ],
            )
            self.assertEqual(
                prepared.preparation_fingerprint,
                "ebd0afda04ac4dc2b9d72294aff32eb0616f003a66eac892365b58b6c1cebbf5",
            )
            self.assertEqual(
                {
                    "inventory": prepared.inventory.sha256,
                    "rank_input": prepared.rank_input.sha256,
                    "frontier": prepared.frontier.sha256,
                    "frontier_receipt": prepared.frontier_receipt.sha256,
                    "priority_packet": prepared.priority_packet.sha256,
                },
                {
                    "inventory": "d974ee18bc2f3c6438d61cbe6925dc76a7f51d5ee7d2f75e23d2ad37f2047863",
                    "rank_input": "89f7777170042fa6979b6d6f33b593d736a933e2374d89d585123b5fd1a29b93",
                    "frontier": "a3e2464114f68c620072e327b91628ddfaa99d7655bbe478eaff25eb3c3ed7c8",
                    "frontier_receipt": "1dae429f9c27156a8fce5ab7d3e8593f24a76d17135564f996da4ab7f858a850",
                    "priority_packet": "cb047ea29da1af0dc9961a531acf4b518a25770c2daf1cd50f771c7154af6d6a",
                },
            )
            prediction = self._prediction()
            evidence = attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))
        self.assertEqual(evidence.to_json()["schema_version"], 1)
        self.assertEqual(set(evidence.to_json()), hunt_evidence.HUNT_EVIDENCE_FIELDS_V1)
        canonical = (json.dumps(evidence.to_json(), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            "0771c4297ed1ef8455dc90fa9e9bcdabedbe3be3b44b3ada9a43a4b434ee1ab2",
        )

    def test_protocol_two_records_deterministic_semantic_guidance(self) -> None:
        # Protocol two must add only one deterministic semantic artifact.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self._snapshot(root)
            first = prepare_hunt_artifacts(
                snapshot,
                root / "scratch-one",
                "hunt-balanced",
                evidence_protocol_version=2,
            )
            second = prepare_hunt_artifacts(
                snapshot,
                root / "scratch-two",
                "hunt-balanced",
                evidence_protocol_version=2,
            )
            self.assertEqual(first.semantic_guidance.sha256, second.semantic_guidance.sha256)
            self.assertEqual(first.preparation_fingerprint, second.preparation_fingerprint)
            self.assertEqual(
                sorted(path.name for path in first.plan_directory.iterdir()),
                [
                    "frontier-receipt.json",
                    "frontier.jsonl",
                    "in-scope-files.txt",
                    "priority-packet.jsonl",
                    "rank-input.jsonl",
                    "semantic-guidance.jsonl",
                ],
            )

    def test_protocol_two_semantic_bytes_and_preparation_fingerprint_remain_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = prepare_hunt_artifacts(
                self._semantic_snapshot(root),
                root / "scratch",
                "hunt-balanced",
                evidence_protocol_version=2,
            )
        self.assertEqual(prepared.preparation_fingerprint, "c6d4283ef55b841fd423400a6fa229e18637e5afc7b0506fb333b0905b75fe7f")
        self.assertEqual(prepared.semantic_guidance.sha256, "c7521cf55318dc1cc393c12e39c643fbabdd003d02329160f92861c257549a37")
        self.assertEqual(prepared.semantic_guidance_row_count, 1)
        self.assertEqual(prepared.semantic_guidance.byte_count, 394)

    def test_protocol_three_records_schema_two_semantic_guidance_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self._semantic_snapshot(root)
            protocol_two = prepare_hunt_artifacts(
                snapshot,
                root / "scratch-two",
                "hunt-balanced",
                evidence_protocol_version=2,
            )
            first = prepare_hunt_artifacts(
                snapshot,
                root / "scratch-three-one",
                "hunt-balanced",
                evidence_protocol_version=3,
            )
            second = prepare_hunt_artifacts(
                snapshot,
                root / "scratch-three-two",
                "hunt-balanced",
                evidence_protocol_version=3,
            )
            rows = [json.loads(line) for line in first.semantic_guidance.path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["schema_version"], 2)
        self.assertEqual(rows[0]["eligible_search_passes"], ["forward"])
        self.assertEqual(first.semantic_guidance.sha256, second.semantic_guidance.sha256)
        self.assertEqual(first.preparation_fingerprint, second.preparation_fingerprint)
        self.assertNotEqual(first.semantic_guidance.sha256, protocol_two.semantic_guidance.sha256)
        self.assertNotEqual(first.preparation_fingerprint, protocol_two.preparation_fingerprint)

    def test_protocol_four_records_schema_three_guidance_without_changing_legacy_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self._semantic_snapshot(root)
            protocol_two = prepare_hunt_artifacts(snapshot, root / "two", "hunt-balanced", evidence_protocol_version=2)
            protocol_three = prepare_hunt_artifacts(snapshot, root / "three", "hunt-balanced", evidence_protocol_version=3)
            protocol_four = prepare_hunt_artifacts(snapshot, root / "four", "hunt-balanced", evidence_protocol_version=4)
            row = json.loads(protocol_four.semantic_guidance.path.read_text(encoding="utf-8"))
        self.assertEqual(row["schema_version"], 3)
        self.assertEqual(row["hint_kind"], "call-route")
        self.assertEqual(row["component"], ".")
        self.assertNotEqual(protocol_four.semantic_guidance.sha256, protocol_three.semantic_guidance.sha256)
        self.assertEqual(protocol_two.semantic_guidance.sha256, "c7521cf55318dc1cc393c12e39c643fbabdd003d02329160f92861c257549a37")

    def test_protocol_five_records_deterministic_paired_flow_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self._semantic_snapshot(root)
            first = prepare_hunt_artifacts(snapshot, root / "first", "hunt-balanced", evidence_protocol_version=5)
            second = prepare_hunt_artifacts(snapshot, root / "second", "hunt-balanced", evidence_protocol_version=5)
            self.assertEqual(first.paired_flow_seeds.sha256, second.paired_flow_seeds.sha256)
            self.assertEqual(first.paired_flow_seeds_row_count, second.paired_flow_seeds_row_count)
            self.assertEqual(
                first.paired_flow_seeds.path.read_bytes(),
                second.paired_flow_seeds.path.read_bytes(),
            )
            self.assertIn("paired-flow-seeds.jsonl", {path.name for path in first.plan_directory.iterdir()})


class HuntEvidenceAttestationTests(HuntEvidencePreparationTests):
    """Proves that post-execution artifact and provenance changes fail closed."""

    def _prepared_prediction(self, root: Path):
        snapshot = self._snapshot(root)
        prepared = prepare_hunt_artifacts(
            snapshot,
            root / "scratch",
            "hunt-balanced",
            evidence_protocol_version=1,
        )
        return prepared, self._prediction()

    def _prepared_prediction_semantic(self, root: Path, version: int):
        snapshot = self._snapshot(root)
        prepared = prepare_hunt_artifacts(
            snapshot,
            root / "scratch",
            "hunt-balanced",
            evidence_protocol_version=version,
        )
        return prepared, self._prediction()

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
            with self.assertRaises(HuntEvidenceError) as caught:
                attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))
        self.assertEqual(caught.exception.category, "hunt_evidence_artifact_integrity")

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
            with self.assertRaises(HuntEvidenceError) as caught:
                attest_hunt_discovery(prepared, malformed, (self._PACKET_READ,))
        self.assertEqual(caught.exception.category, "hunt_evidence_candidate_location")

    def test_case_ambiguous_candidate_path_fails_closed(self) -> None:
        # Case changes must not be normalized into a frontier location.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            candidate = prediction.candidates[0]
            malformed = parse_hunt_discovery_prediction(
                {"schema_version": 1, "task_id": "task-1", "candidates": [{"finding_id": candidate.finding_id, "entry_point": {"file": "SRC/ENTRY.py", "line": 1}, "critical_operation": {"file": "src/sink.py", "line": 1}, "trace": [], "confidence": candidate.confidence, "vulnerability_family": candidate.vulnerability_family, "search_pass": candidate.search_pass, "hypothesis": candidate.hypothesis, "evidence": candidate.evidence, "counterevidence": candidate.counterevidence, "expected_control": candidate.expected_control}]},
                "task-1",
            )
            with self.assertRaises(HuntEvidenceError) as caught:
                attest_hunt_discovery(prepared, malformed, (self._PACKET_READ,))
        self.assertEqual(caught.exception.category, "hunt_evidence_candidate_location")

    def test_incompatible_search_pass_fails_closed(self) -> None:
        # A search pass absent from every linked frontier row must be rejected.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction_semantic(Path(directory), 3)
            candidate = prediction.candidates[0]
            malformed = parse_hunt_discovery_prediction(
                {"schema_version": 1, "task_id": "task-1", "candidates": [{"finding_id": candidate.finding_id, "entry_point": {"file": "src/entry.py", "line": 1}, "critical_operation": {"file": "src/sink.py", "line": 1}, "trace": [], "confidence": candidate.confidence, "vulnerability_family": candidate.vulnerability_family, "search_pass": "state", "hypothesis": candidate.hypothesis, "evidence": candidate.evidence, "counterevidence": candidate.counterevidence, "expected_control": candidate.expected_control}]},
                "task-1",
            )
            with self.assertRaises(HuntEvidenceError) as caught:
                attest_hunt_discovery(prepared, malformed, (self._PACKET_READ, hunt_evidence._REQUIRED_SEMANTIC_READ))
        self.assertEqual(caught.exception.category, "hunt_evidence_candidate_search_pass")
        self.assertEqual(malformed.candidates[0].search_pass, "state")

    def test_linkage_does_not_reduce_coverage_debt(self) -> None:
        # Packet presentation and candidate links must never become reviewed closure.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            evidence = attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))
            self.assertEqual(evidence.candidate_count, 1)
            self.assertEqual(evidence.linked_location_count, 3)
            self.assertEqual(evidence.coverage_debt_count, prepared.frontier_pass_count)
            self.assertEqual(evidence.validated_closure_count, 0)

    def test_duplicate_priority_packet_read_fails_closed(self) -> None:
        # The fixed packet may be presented exactly once, never repeatedly.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            with self.assertRaises(HuntEvidenceError) as caught:
                attest_hunt_discovery(prepared, prediction, (self._PACKET_READ, self._PACKET_READ))
        self.assertEqual(caught.exception.category, "hunt_evidence_packet_duplicate")

    def test_missing_priority_packet_read_has_its_own_category(self) -> None:
        # No packet read and duplicate reads must remain distinguishable failures.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            with self.assertRaises(HuntEvidenceError) as caught:
                attest_hunt_discovery(prepared, prediction, ())
        self.assertEqual(caught.exception.category, "hunt_evidence_packet_missing")

    def test_semantic_protocols_attest_one_semantic_guidance_read(self) -> None:
        for version in (2, 3, 4):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                prepared, prediction = self._prepared_prediction_semantic(Path(directory), version)
                evidence = attest_hunt_discovery(
                    prepared,
                    prediction,
                    (self._PACKET_READ, hunt_evidence._REQUIRED_SEMANTIC_READ),
                )
                self.assertEqual(evidence.protocol_version, version)
                self.assertEqual(set(evidence.to_json()), hunt_evidence.HUNT_EVIDENCE_FIELDS_V2)

    def test_parser_accepts_literal_evidence_for_each_supported_protocol(self) -> None:
        for version in (1, 2, 3, 4):
            with self.subTest(version=version):
                payload = self._evidence_payload(version)
                self.assertEqual(
                    parse_hunt_evidence(payload, "hunt-balanced", evidence_protocol_version=version),
                    payload,
                )

    def test_parser_rejects_mixed_version_fields(self) -> None:
        # Adding a protocol two field to a protocol one receipt must fail exact-field validation.
        mixed = self._evidence_payload(1)
        mixed["semantic_guidance_count"] = 2
        with self.assertRaises(HuntEvidenceError):
            parse_hunt_evidence(mixed, "hunt-balanced", evidence_protocol_version=1)

    def test_frontier_rows_reject_empty_duplicate_or_unsupported_search_passes(self) -> None:
        base = {
            "work_id": "work-1",
            "path": "app.py",
            "area": "application",
            "component": "app",
            "risk_score": 1,
            "rank_include": True,
            "rank_reason": "included",
            "signals": [],
            "priority": 1,
        }
        for passes in ([], ["forward", "forward"], [""], ["unsupported"]):
            with self.subTest(passes=passes), self.assertRaises(HuntEvidenceError):
                hunt_evidence._validate_frontier_rows([base | {"passes": passes}], {"app.py"})

    def test_parser_rejects_unsupported_and_mismatched_protocol_versions(self) -> None:
        # Unsupported schema values and receipt-version disagreement must both fail.
        for version in (0, 5):
            with self.subTest(unsupported=version):
                unsupported = self._evidence_payload(1)
                unsupported["schema_version"] = version
                with self.assertRaises(HuntEvidenceError):
                    parse_hunt_evidence(unsupported, "hunt-balanced")
        for row_version in (1, 2, 3, 4):
            for expected_version in (1, 2, 3, 4):
                if row_version == expected_version:
                    continue
                with self.subTest(row_version=row_version, expected_version=expected_version), self.assertRaises(HuntEvidenceError):
                    parse_hunt_evidence(
                        self._evidence_payload(row_version),
                        "hunt-balanced",
                        evidence_protocol_version=expected_version,
                    )

    def test_semantic_protocols_missing_semantic_guidance_read_have_their_own_category(self) -> None:
        for version in (2, 3, 4):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                prepared, prediction = self._prepared_prediction_semantic(Path(directory), version)
                with self.assertRaises(HuntEvidenceError) as caught:
                    attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))
                self.assertEqual(caught.exception.category, "hunt_semantic_guidance_missing")

    def test_semantic_protocols_duplicate_or_reversed_semantic_guidance_reads_fail(self) -> None:
        for version in (2, 3, 4):
            with self.subTest(version=version, reads="duplicate"), tempfile.TemporaryDirectory() as directory:
                prepared, prediction = self._prepared_prediction_semantic(Path(directory), version)
                with self.assertRaises(HuntEvidenceError) as caught:
                    attest_hunt_discovery(
                        prepared,
                        prediction,
                        (
                            self._PACKET_READ,
                            hunt_evidence._REQUIRED_SEMANTIC_READ,
                            hunt_evidence._REQUIRED_SEMANTIC_READ,
                        ),
                    )
                self.assertEqual(caught.exception.category, "hunt_semantic_guidance_duplicate")
            with self.subTest(version=version, reads="reversed"), tempfile.TemporaryDirectory() as directory:
                prepared, prediction = self._prepared_prediction_semantic(Path(directory), version)
                with self.assertRaises(HuntEvidenceError):
                    attest_hunt_discovery(
                        prepared,
                        prediction,
                        (hunt_evidence._REQUIRED_SEMANTIC_READ, self._PACKET_READ),
                    )

    def test_protocol_one_does_not_require_semantic_guidance_read(self) -> None:
        # Adding a protocol two requirement must not alter protocol one receipts.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            evidence = attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))
        self.assertEqual(evidence.protocol_version, 1)

    def test_semantic_guidance_byte_mutation_fails_closed(self) -> None:
        # Changing semantic bytes after preparation must invalidate protocol two attestation.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction_semantic(Path(directory), 2)
            prepared.semantic_guidance.path.write_bytes(prepared.semantic_guidance.path.read_bytes() + b" ")
            with self.assertRaises(HuntEvidenceError) as caught:
                attest_hunt_discovery(
                    prepared,
                    prediction,
                    (self._PACKET_READ, hunt_evidence._REQUIRED_SEMANTIC_READ),
                )
        self.assertEqual(caught.exception.category, "hunt_evidence_artifact_integrity")

    def test_oversized_semantic_guidance_replacement_fails_closed(self) -> None:
        # Exceeding the semantic guidance limit must invalidate protocol two attestation.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction_semantic(Path(directory), 2)
            prepared.semantic_guidance.path.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaises(HuntEvidenceError) as caught:
                attest_hunt_discovery(
                    prepared,
                    prediction,
                    (self._PACKET_READ, hunt_evidence._REQUIRED_SEMANTIC_READ),
                )
        self.assertEqual(caught.exception.category, "hunt_evidence_artifact_integrity")

    def test_symbolic_semantic_guidance_replacement_fails_closed_when_supported(self) -> None:
        # Replacing semantic guidance with a symbolic link must be rejected.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction_semantic(Path(directory), 2)
            target = prepared.plan_directory / "semantic-target.jsonl"
            target.write_bytes(prepared.semantic_guidance.path.read_bytes())
            prepared.semantic_guidance.path.unlink()
            try:
                prepared.semantic_guidance.path.symlink_to(target)
            except OSError:
                self.skipTest("symbolic links are unavailable")
            with self.assertRaises(HuntEvidenceError) as caught:
                attest_hunt_discovery(
                    prepared,
                    prediction,
                    (self._PACKET_READ, hunt_evidence._REQUIRED_SEMANTIC_READ),
                )
        self.assertEqual(caught.exception.category, "hunt_evidence_artifact_integrity")

    def test_hard_linked_semantic_guidance_fails_closed(self) -> None:
        # Increasing the semantic guidance link count must be rejected.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction_semantic(Path(directory), 2)
            try:
                os.link(
                    prepared.semantic_guidance.path,
                    prepared.plan_directory / "semantic-guidance-copy.jsonl",
                )
            except OSError as error:
                self.skipTest(f"hard links are unavailable: {error}")
            with self.assertRaises(HuntEvidenceError) as caught:
                attest_hunt_discovery(
                    prepared,
                    prediction,
                    (self._PACKET_READ, hunt_evidence._REQUIRED_SEMANTIC_READ),
                )
        self.assertEqual(caught.exception.category, "hunt_evidence_artifact_integrity")

    def test_low_level_semantic_guidance_replacement_fails_closed(self) -> None:
        # Replacing semantic guidance during a low-level read must invalidate identity.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction_semantic(Path(directory), 2)
            original_read = hunt_evidence.os.read
            replaced = False

            def replace_after_open(descriptor: int, size: int) -> bytes:
                nonlocal replaced
                if not replaced:
                    replaced = True
                    prepared.semantic_guidance.path.unlink()
                    prepared.semantic_guidance.path.write_bytes(b"{}\n")
                return original_read(descriptor, size)

            with patch.object(hunt_evidence.os, "read", side_effect=replace_after_open):
                with self.assertRaises(HuntEvidenceError) as caught:
                    attest_hunt_discovery(
                        prepared,
                        prediction,
                        (self._PACKET_READ, hunt_evidence._REQUIRED_SEMANTIC_READ),
                    )
        self.assertEqual(caught.exception.category, "hunt_evidence_artifact_integrity")

    def test_frontier_receipt_must_be_bounded_and_match_frontier_inputs(self) -> None:
        # The helper receipt is a bound artifact, not unvalidated metadata.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            prepared.frontier_receipt.path.write_bytes(b"{" + b"x" * (64 * 1024) + b"}")
            with self.assertRaises(HuntEvidenceError):
                attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            prepared.frontier_receipt.path.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(HuntEvidenceError):
                attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))

    def test_post_attestation_reopen_replacement_fails_closed(self) -> None:
        # A replacement between preflight and a later parsed artifact read must be detected.
        with tempfile.TemporaryDirectory() as directory:
            prepared, prediction = self._prepared_prediction(Path(directory))
            original_read = hunt_evidence.os.read
            replaced = False

            def replace_rank_input(descriptor: int, size: int) -> bytes:
                nonlocal replaced
                if not replaced:
                    replaced = True
                    prepared.rank_input.path.unlink()
                    prepared.rank_input.path.write_bytes(b"{}\n")
                return original_read(descriptor, size)

            with patch.object(hunt_evidence.os, "read", side_effect=replace_rank_input):
                with self.assertRaises(HuntEvidenceError):
                    attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))


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
