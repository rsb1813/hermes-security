# Verifies paired HermesBench discovery and verification execution.

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import benchmarks.hermesbench.phase_runner as phase_runner
from benchmarks.hermesbench.contracts import BenchmarkManifest, load_predictions, parse_manifest, parse_oracle
from benchmarks.hermesbench.phase_runner import (
    FrozenControls,
    PhaseRunnerError,
    WorkflowReceipt,
    canonicalize_candidates,
    compare_workflows,
    run_paired,
    run_workflow,
    validate_workflow_receipt,
)
from benchmarks.hermesbench.runner import (
    ExecutionPolicy,
    ExecutorFailureError,
    ExecutorResult,
    execution_policy_sha256,
    manifest_sha256,
    task_order_sha256,
)
from benchmarks.hermesbench.sanitize import tree_sha256
from benchmarks.hermesbench.receipts import TokenUsage, sha256_file
from benchmarks.hermesbench.scoring import score_run
from benchmarks.hermesbench.hunt_evidence import HUNT_EVIDENCE_PROTOCOL_VERSION, reproduce_hunt_evidence
from benchmarks.hermesbench.hunt_protocol import parse_hunt_discovery_prediction
from benchmarks.hermesbench.adapters.codex_exec import _normalize_command


def _manifest(root: Path) -> BenchmarkManifest:
    snapshots = root / "snapshots"
    snapshots.mkdir()
    for task_id in ("task-a", "task-b"):
        snapshot = snapshots / task_id
        snapshot.mkdir()
        (snapshot / "source.py").write_text("def request_handler(request):\n    value = request\n    return execute(value)\n", encoding="utf-8")
    return parse_manifest(
        {
            "schema_version": 1,
            "suite": "canary",
            "manifest_id": "phase-test",
            "tasks": [
                {
                    "task_id": task_id,
                    "snapshot_sha256": tree_sha256(snapshots / task_id),
                    "language": "python",
                    "allowed_commands": [["python", "-m", "unittest"]],
                    "time_limit_seconds": 13,
                }
                for task_id in ("task-a", "task-b")
            ],
        }
    )


def _controls() -> FrozenControls:
    return FrozenControls.from_json(
        {
            "schema_version": 2,
            "model": "fake-model",
            "reasoning_effort": "low",
            "seed_supported": False,
            "seed": None,
            "image_digest": "sha256:" + "a" * 64,
            "tool_versions": [["fake", "1"]],
            "time_limit_seconds": 13,
            "max_findings": 5,
            "grader_version": "test",
            "phase_protocol_version": 1,
            "hunt_candidate_protocol_version": 1,
            "invocations_per_task": 2,
        }
    )


def _parallel_controls(max_parallel_tasks: int = 2) -> FrozenControls:
    return FrozenControls.from_json(
        _controls().to_json()
        | {
            "schema_version": 3,
            "max_parallel_tasks": max_parallel_tasks,
        }
    )


def _prediction(task_id: str, *, finding_id: str = "model-id") -> dict[str, object]:
    return {
        "prediction": {
            "schema_version": 1,
            "task_id": task_id,
            "findings": [
                {
                    "finding_id": finding_id,
                    "entry_point": {"file": "source.py", "line": 1},
                    "critical_operation": {"file": "source.py", "line": 3},
                    "trace": [{"file": "source.py", "line": 2}],
                    "confidence": 0.8,
                }
            ],
        },
        "usage": {"input_tokens": 7, "cached_input_tokens": 2, "output_tokens": 3},
    }


def _hunt_candidate(number: int) -> dict[str, object]:
    return {
        "finding_id": f"model-{number}", "entry_point": {"file": "source.py", "line": 1},
        "critical_operation": {"file": "source.py", "line": 3}, "trace": [{"file": "source.py", "line": 2}],
        "confidence": 0.1 * number, "vulnerability_family": "injection", "search_pass": "forward",
        "hypothesis": f"Input reaches operation {number}.", "evidence": "Trace exists.",
        "counterevidence": "No guard found.", "expected_control": "Validate input.",
    }


def _hunt_discovery(task_id: str, count: int = 1) -> dict[str, object]:
    return {"prediction": {"schema_version": 1, "task_id": task_id, "candidates": [_hunt_candidate(number) for number in range(1, count + 1)]}, "usage": {"input_tokens": 7, "cached_input_tokens": 2, "output_tokens": 3}}


def _hunt_result(
    request: object,
    count: int = 1,
    evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION,
) -> ExecutorResult:
    response = _hunt_discovery(request.task_id, count)
    prediction = parse_hunt_discovery_prediction(response["prediction"], request.task_id)
    evidence = reproduce_hunt_evidence(
        Path(request.snapshot_path),
        "hunt-balanced",
        prediction,
        evidence_protocol_version=evidence_protocol_version,
    ).to_json()
    return ExecutorResult(response, ({"event": "done"},), (), evidence)


def _hunt_receipt(evidence_protocol_version: int) -> dict[str, object]:
    return {
        "schema_version": 3,
        "run_id": "receipt-test",
        "workflow": "hunt",
        "profile": "hunt-balanced",
        "frozen_controls_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
        "task_order_sha256": "c" * 64,
        "execution_policy_sha256": "d" * 64,
        "snapshot_set_sha256": "e" * 64,
        "discovery_receipt_sha256": "f" * 64,
        "discovery_commands_sha256": "0" * 64,
        "discovery_predictions_sha256": "1" * 64,
        "candidate_transfer_sha256": "2" * 64,
        "verification_receipt_sha256": "3" * 64,
        "verification_commands_sha256": "4" * 64,
        "verification_predictions_sha256": "5" * 64,
        "public_predictions_sha256": "6" * 64,
        "discovery_evidence_sha256": "7" * 64,
        "hunt_evidence_protocol_version": evidence_protocol_version,
        "phase_protocol_version": 1,
        "top_level_invocation_count": 2,
        "status": "completed",
        "elapsed_seconds": 0.0,
        "token_usage": {
            "cached_input_tokens": 0,
            "uncached_input_tokens": 0,
            "output_tokens": 0,
        },
    }


def _hunt_verification(task_id: str, candidate: object) -> dict[str, object]:
    finding = _prediction(task_id, finding_id=candidate.candidate_id)["prediction"]["findings"][0]
    finding["confidence"] = candidate.confidence
    decision = {"candidate_id": candidate.candidate_id, "disposition": "accepted", "attacker_control": "proven", "reachability": "proven", "impact": "proven", "guard_failure": "proven", "evidence": "Confirmed.", "counterevidence": "", "proof_gaps": "", "confidence": candidate.confidence}
    return {"prediction": {"schema_version": 1, "task_id": task_id, "findings": [finding], "decisions": [decision]}, "usage": {"input_tokens": 7, "cached_input_tokens": 2, "output_tokens": 3}}


def _vulnerable_oracles(*task_ids: str):
    return {
        task_id: parse_oracle(
            {
                "schema_version": 1,
                "task_id": task_id,
                "kind": "vulnerable",
                "group_id": task_id,
                "split": "hidden_test",
                "category": "injection",
                "language": "python",
                "paths": [
                    {
                        "path_id": "path-1",
                        "entry_point": {"file": "source.py", "line": 1},
                        "critical_operation": {"file": "source.py", "line": 3},
                        "trace": [{"file": "source.py", "line": 2}],
                    }
                ],
                "retired_paths": [],
            }
        )
        for task_id in task_ids
    }


class FrozenControlsTests(unittest.TestCase):
    def test_controls_reject_mutable_image_and_wrong_invocation_budget(self) -> None:
        value = _controls().to_json()
        with self.assertRaisesRegex(PhaseRunnerError, "image_digest"):
            FrozenControls.from_json(value | {"image_digest": "runtime:latest"})
        with self.assertRaisesRegex(PhaseRunnerError, "invocations_per_task"):
            FrozenControls.from_json(value | {"invocations_per_task": 1})

    def test_controls_bind_the_existing_run_config_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            policy = ExecutionPolicy((("python",),))
            config = _controls().run_config(manifest, policy)
        self.assertEqual(config.manifest_sha256, manifest_sha256(manifest))
        self.assertEqual(config.task_order_sha256, task_order_sha256(manifest))
        self.assertEqual(config.execution_policy_sha256, execution_policy_sha256(policy))

    def test_parallel_controls_are_versioned_and_legacy_bytes_stay_stable(self) -> None:
        legacy = _controls()
        parallel = _parallel_controls()

        self.assertEqual(
            "5cfed0c9b199f2009592c79afe8bcf5669b3018124dc07469c2c09148122c155",
            legacy.sha256(),
        )
        self.assertNotIn("max_parallel_tasks", legacy.to_json())
        self.assertEqual(1, legacy.max_parallel_tasks)
        self.assertEqual(2, parallel.to_json()["max_parallel_tasks"])
        self.assertEqual(2, parallel.max_parallel_tasks)
        self.assertNotEqual(legacy.sha256(), parallel.sha256())
        self.assertEqual(1, _parallel_controls(1).max_parallel_tasks)

        invalid_legacy = legacy.to_json() | {"max_parallel_tasks": 2}
        with self.assertRaisesRegex(PhaseRunnerError, "controls"):
            FrozenControls.from_json(invalid_legacy)
        with self.assertRaisesRegex(PhaseRunnerError, "max_parallel_tasks"):
            FrozenControls.from_json(parallel.to_json() | {"max_parallel_tasks": 3})

    def test_workflow_rejects_manifest_time_that_differs_from_frozen_controls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            altered = parse_manifest(
                {
                    "schema_version": 1,
                    "suite": manifest.suite,
                    "manifest_id": manifest.manifest_id,
                    "tasks": [
                        {
                            "task_id": task.task_id,
                            "snapshot_sha256": task.snapshot_sha256,
                            "language": task.language,
                            "allowed_commands": [list(command) for command in task.allowed_commands],
                            "time_limit_seconds": 14,
                        }
                        for task in manifest.tasks
                    ],
                }
            )
            outputs = root / "outputs"
            outputs.mkdir()
            with self.assertRaisesRegex(PhaseRunnerError, "time_limit_seconds"):
                run_workflow(
                    altered, root / "snapshots", outputs, "mismatch", "standard", "baseline",
                    _controls(), ExecutionPolicy((("python",),)), lambda *_: self.fail("must not execute"), lambda _: self.fail("must not execute"),
                )


class CandidateCanonicalizationTests(unittest.TestCase):
    def test_canonicalizes_stable_ids_and_rejects_untrusted_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            snapshots = root / "snapshots"
            discovery = {
                "task-a": _prediction("task-a", finding_id="attacker-supplied")["prediction"],
                "task-b": {"schema_version": 1, "task_id": "task-b", "findings": []},
            }
            candidates = canonicalize_candidates(manifest, snapshots, discovery)
            candidate = candidates["task-a"][0]
            self.assertEqual(candidate.candidate_id, "candidate-1")
            self.assertEqual(candidate.entry_point.path, "source.py")
            malformed = _prediction("task-a")["prediction"]
            malformed["findings"][0]["entry_point"] = {"file": "../private.txt", "line": 1}
            with self.assertRaisesRegex(PhaseRunnerError, "candidate"):
                canonicalize_candidates(manifest, snapshots, {"task-a": malformed, "task-b": discovery["task-b"]})
            backslash = _prediction("task-a")["prediction"]
            backslash["findings"][0]["entry_point"] = {"file": "source.py\\ignored", "line": 1}
            with self.assertRaisesRegex(PhaseRunnerError, "candidate path"):
                canonicalize_candidates(manifest, snapshots, {"task-a": backslash, "task-b": discovery["task-b"]})

    def test_rejects_six_candidates_and_duplicate_locations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            prediction = _prediction("task-a")["prediction"]
            prediction["findings"] = [prediction["findings"][0] | {"finding_id": f"id-{number}"} for number in range(6)]
            with self.assertRaisesRegex(PhaseRunnerError, "at most five"):
                canonicalize_candidates(manifest, root / "snapshots", {"task-a": prediction, "task-b": {"schema_version": 1, "task_id": "task-b", "findings": []}})


class WorkflowTests(unittest.TestCase):
    def test_parallel_workflow_matches_serial_outputs_and_revalidates_controls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            policy = ExecutionPolicy((("python",),))

            def discovery(request: object, *_: object) -> ExecutorResult:
                return ExecutorResult(
                    _prediction(request.task_id),
                    ({"event": "done"},),
                    (),
                )

            def verification_factory(candidate_sets: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    candidate = candidate_sets[request.task_id][0]
                    return ExecutorResult(
                        _prediction(
                            request.task_id,
                            finding_id=candidate.candidate_id,
                        ),
                        ({"event": "done"},),
                        (),
                    )

                return verification

            run_workflow(
                manifest,
                root / "snapshots",
                outputs,
                "serial",
                "standard",
                "baseline",
                _controls(),
                policy,
                discovery,
                verification_factory,
            )
            parallel = run_workflow(
                manifest,
                root / "snapshots",
                outputs,
                "parallel",
                "standard",
                "baseline",
                _parallel_controls(),
                policy,
                discovery,
                verification_factory,
            )
            validated = validate_workflow_receipt(
                manifest,
                root / "snapshots",
                outputs,
                outputs / "parallel-workflow-receipt.json",
                _parallel_controls(),
                policy,
            )
            discovery_receipt = json.loads(
                (outputs / "parallel-discovery" / "receipt.json").read_text(
                    encoding="utf-8"
                )
            )

            for suffix in (
                "candidates.jsonl",
                "discovery/predictions.jsonl",
                "verification/predictions.jsonl",
            ):
                with self.subTest(suffix=suffix):
                    self.assertEqual(
                        (outputs / f"serial-{suffix}").read_bytes(),
                        (outputs / f"parallel-{suffix}").read_bytes(),
                    )
            with self.assertRaisesRegex(PhaseRunnerError, "controls"):
                validate_workflow_receipt(
                    manifest,
                    root / "snapshots",
                    outputs,
                    outputs / "parallel-workflow-receipt.json",
                    _controls(),
                    policy,
                )

        self.assertEqual("completed", parallel.receipt.status)
        self.assertEqual("completed", validated.status)
        self.assertEqual(2, discovery_receipt["config"]["max_parallel_tasks"])

    def test_hunt_schema_three_receipt_accepts_each_supported_evidence_protocol(self) -> None:
        for version in (1, 2, 3, 4):
            with self.subTest(version=version):
                self.assertEqual(
                    WorkflowReceipt.from_json(
                        _hunt_receipt(version)
                    ).hunt_evidence_protocol_version,
                    version,
                )

    def test_hunt_schema_three_receipt_rejects_unsupported_evidence_protocol(self) -> None:
        for version in (0, 5):
            with self.subTest(version=version):
                with self.assertRaisesRegex(PhaseRunnerError, "protocol"):
                    WorkflowReceipt.from_json(_hunt_receipt(version))

    def test_standard_receipt_rejects_hunt_evidence_fields(self) -> None:
        receipt = _hunt_receipt(1) | {
            "schema_version": 2,
            "workflow": "standard",
            "profile": "baseline",
        }
        with self.assertRaisesRegex(PhaseRunnerError, "fields"):
            WorkflowReceipt.from_json(receipt)

    def test_hunt_workflow_reconstructs_each_selected_evidence_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            policy = ExecutionPolicy((("python",),))

            def verification_factory(candidates: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    return ExecutorResult(
                        _hunt_verification(request.task_id, candidates[request.task_id][0]),
                        ({"event": "done"},),
                        (),
                    )
                return verification

            for version in (1, 2, 3, 4):
                with self.subTest(version=version):
                    result = run_workflow(
                        manifest,
                        root / "snapshots",
                        outputs,
                        f"protocol-{version}",
                        "hunt",
                        "hunt-balanced",
                        _controls(),
                        policy,
                        lambda request, *_: _hunt_result(
                            request,
                            evidence_protocol_version=version,
                        ),
                        verification_factory,
                        hunt_evidence_protocol_version=version,
                    )
                    self.assertEqual(result.receipt.hunt_evidence_protocol_version, version)
                    validated = validate_workflow_receipt(
                        manifest,
                        root / "snapshots",
                        outputs,
                        outputs / f"protocol-{version}-workflow-receipt.json",
                        _controls(),
                        policy,
                    )
                    self.assertEqual(validated.hunt_evidence_protocol_version, version)

    def test_hunt_workflow_rejects_evidence_from_a_different_selected_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            result = run_workflow(
                manifest,
                root / "snapshots",
                outputs,
                "protocol-mismatch",
                "hunt",
                "hunt-balanced",
                _controls(),
                ExecutionPolicy((("python",),)),
                lambda request, *_: _hunt_result(request, evidence_protocol_version=1),
                lambda _: self.fail("verification must not run"),
                hunt_evidence_protocol_version=2,
            )

            self.assertEqual(result.receipt.status, "incomplete")
            self.assertFalse((outputs / "protocol-mismatch-verification").exists())
            self.assertFalse((outputs / "protocol-mismatch-public-predictions.jsonl").exists())

    def test_protocol_four_scores_recoverable_discovery_failure_as_empty_miss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            policy = ExecutionPolicy((("python",),))
            verification_model_calls: list[str] = []
            oracles = _vulnerable_oracles("task-a", "task-b")

            def discovery(request: object, *_: object) -> ExecutorResult:
                if request.task_id == "task-a":
                    raise ExecutorFailureError(
                        "private attestation detail",
                        failure_code="hunt_evidence_candidate_location",
                        token_usage=TokenUsage(11, 13, 17),
                    )
                return _hunt_result(request)

            def verification_factory(candidates: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    verification_model_calls.append(request.task_id)
                    return ExecutorResult(
                        _hunt_verification(request.task_id, candidates[request.task_id][0]),
                        ({"event": "done"},),
                        (),
                    )

                return verification

            result = run_workflow(
                manifest,
                root / "snapshots",
                outputs,
                "partial-v4",
                "hunt",
                "hunt-balanced",
                _parallel_controls(),
                policy,
                discovery,
                verification_factory,
                lambda path: {
                    "advisory_recall": score_run(
                        oracles,
                        load_predictions(path),
                    ).advisory_recall
                },
                hunt_evidence_protocol_version=4,
            )
            validated = validate_workflow_receipt(
                manifest,
                root / "snapshots",
                outputs,
                outputs / "partial-v4-workflow-receipt.json",
                _parallel_controls(),
                policy,
            )
            candidates = [
                json.loads(line)
                for line in (outputs / "partial-v4-candidates.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            predictions = [
                json.loads(line)
                for line in (outputs / "partial-v4-public-predictions.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            discovery_receipt = json.loads(
                (outputs / "partial-v4-discovery" / "receipt.json").read_text(encoding="utf-8")
            )
            score = json.loads(
                (outputs / "partial-v4-score.json").read_text(encoding="utf-8")
            )

        self.assertEqual("completed", result.receipt.status)
        self.assertEqual("completed", validated.status)
        self.assertEqual(["task-b"], verification_model_calls)
        self.assertEqual(["task-a", "task-b"], [row["task_id"] for row in candidates])
        self.assertEqual([], candidates[0]["candidates"])
        self.assertEqual(["task-a", "task-b"], [row["task_id"] for row in predictions])
        self.assertEqual([], predictions[0]["findings"])
        self.assertEqual(
            {"cached_input_tokens": 13, "uncached_input_tokens": 18, "output_tokens": 20},
            discovery_receipt["token_usage"],
        )
        self.assertEqual(TokenUsage(15, 23, 23), result.receipt.token_usage)
        self.assertEqual(0.5, score["advisory_recall"])

    def test_protocol_four_scores_recoverable_verification_failure_as_empty_miss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            policy = ExecutionPolicy((("python",),))
            oracles = _vulnerable_oracles("task-a", "task-b")

            def verification_factory(candidates: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    if request.task_id == "task-a":
                        raise ExecutorFailureError(
                            "private verification detail",
                            failure_code="final_response_invalid",
                            token_usage=TokenUsage(11, 13, 17),
                        )
                    return ExecutorResult(
                        _hunt_verification(request.task_id, candidates[request.task_id][0]),
                        ({"event": "done"},),
                        (),
                    )

                return verification

            result = run_workflow(
                manifest,
                root / "snapshots",
                outputs,
                "partial-verification-v4",
                "hunt",
                "hunt-balanced",
                _controls(),
                policy,
                lambda request, *_: _hunt_result(request),
                verification_factory,
                lambda path: {
                    "advisory_recall": score_run(
                        oracles,
                        load_predictions(path),
                    ).advisory_recall
                },
                hunt_evidence_protocol_version=4,
            )
            receipt_path = outputs / "partial-verification-v4-workflow-receipt.json"
            validated = validate_workflow_receipt(
                manifest,
                root / "snapshots",
                outputs,
                receipt_path,
                _controls(),
                policy,
            )
            predictions = load_predictions(
                outputs / "partial-verification-v4-public-predictions.jsonl"
            )
            score = json.loads(
                (outputs / "partial-verification-v4-score.json").read_text(encoding="utf-8")
            )
            original_receipt = receipt_path.read_bytes()
            for field in ("token_usage", "elapsed_seconds"):
                with self.subTest(field=field):
                    aggregate = json.loads(original_receipt)
                    if field == "token_usage":
                        aggregate[field]["output_tokens"] += 1
                    else:
                        aggregate[field] += 1
                    receipt_path.write_text(
                        json.dumps(aggregate, sort_keys=True, indent=2) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(PhaseRunnerError, "aggregate"):
                        validate_workflow_receipt(
                            manifest,
                            root / "snapshots",
                            outputs,
                            receipt_path,
                            _controls(),
                            policy,
                        )
                    receipt_path.write_bytes(original_receipt)

        self.assertEqual("completed", result.receipt.status)
        self.assertEqual("completed", validated.status)
        self.assertEqual((), predictions["task-a"].findings)
        self.assertEqual(1, len(predictions["task-b"].findings))
        self.assertEqual(0.5, score["advisory_recall"])
        self.assertEqual(TokenUsage(17, 28, 26), result.receipt.token_usage)

    def test_partial_discovery_recovery_rejects_contamination_all_failure_and_legacy(self) -> None:
        def record(status: str, task_id: str) -> phase_runner.TaskRunReceipt:
            return phase_runner.TaskRunReceipt(
                schema_version=phase_runner.RECEIPT_SCHEMA_VERSION,
                task_id=task_id,
                status=status,
                pre_snapshot_sha256="a" * 64,
                post_snapshot_sha256="a" * 64,
                elapsed_seconds=0.0,
                token_usage=TokenUsage(0, 0, 0),
            )

        completed = record("completed", "task-a")
        failed = record("failed", "task-b")
        contaminated = record("contaminated", "task-b")

        self.assertTrue(
            phase_runner._recoverable_partial_phase(
                (completed, failed), "hunt", 4
            )
        )
        self.assertFalse(
            phase_runner._recoverable_partial_phase(
                (completed, contaminated), "hunt", 4
            )
        )
        self.assertFalse(
            phase_runner._recoverable_partial_phase(
                (failed, failed), "hunt", 4
            )
        )
        self.assertFalse(
            phase_runner._recoverable_partial_phase(
                (completed, failed), "hunt", 3
            )
        )

    def test_hunt_workflow_revalidation_rejects_mixed_or_mismatched_evidence_protocols(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            policy = ExecutionPolicy((("python",),))

            def verification_factory(candidates: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    return ExecutorResult(
                        _hunt_verification(request.task_id, candidates[request.task_id][0]),
                        ({"event": "done"},),
                        (),
                    )
                return verification

            original_evidence: dict[int, bytes] = {}
            for version in (1, 2, 3, 4):
                run_id = f"mixed-{version}"
                run_workflow(
                    manifest,
                    root / "snapshots",
                    outputs,
                    run_id,
                    "hunt",
                    "hunt-balanced",
                    _controls(),
                    policy,
                    lambda request, *_: _hunt_result(
                        request,
                        evidence_protocol_version=version,
                    ),
                    verification_factory,
                    hunt_evidence_protocol_version=version,
                )
                receipt_path = outputs / f"{run_id}-workflow-receipt.json"
                evidence_path = outputs / f"{run_id}-discovery" / "evidence.jsonl"
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                original_evidence[version] = evidence_path.read_bytes()
                rows = [json.loads(line) for line in original_evidence[version].decode("utf-8").splitlines()]
                if version == 1:
                    rows[0]["semantic_guidance_count"] = 0
                else:
                    del rows[0]["semantic_guidance_sha256"]
                evidence_path.write_text(
                    "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
                    encoding="utf-8",
                )
                receipt["discovery_evidence_sha256"] = sha256_file(evidence_path)
                receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                with self.subTest(version=version), self.assertRaisesRegex(PhaseRunnerError, "evidence"):
                    validate_workflow_receipt(
                        manifest,
                        root / "snapshots",
                        outputs,
                        receipt_path,
                        _controls(),
                        policy,
                    )

            receipt_path = outputs / "mixed-1-workflow-receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            evidence_path = outputs / "mixed-1-discovery" / "evidence.jsonl"
            evidence_path.write_bytes(original_evidence[1])
            receipt["discovery_evidence_sha256"] = sha256_file(evidence_path)
            receipt["hunt_evidence_protocol_version"] = 2
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(PhaseRunnerError, "evidence"):
                validate_workflow_receipt(
                    manifest,
                    root / "snapshots",
                    outputs,
                    receipt_path,
                    _controls(),
                    policy,
                )

    def test_standard_command_audit_failure_revalidates_without_success_artifacts(self) -> None:
        # A classified command rejection must preserve the snapshot and receipt evidence.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            before = tree_sha256(root / "snapshots" / "task-a")

            def discovery(*_: object) -> ExecutorResult:
                _normalize_command("rg needle source.py | sort")
                self.fail("unsafe command must not produce a result")

            result = run_workflow(
                manifest, root / "snapshots", outputs, "command-audit", "standard", "baseline",
                _controls(), ExecutionPolicy((("python",),)), discovery, lambda _: self.fail("verification must not run"),
            )
            receipt_path = outputs / "command-audit-workflow-receipt.json"
            task_dir = next((outputs / "command-audit-discovery" / "tasks").iterdir())

            self.assertEqual(result.receipt.status, "incomplete")
            self.assertEqual(tree_sha256(root / "snapshots" / "task-a"), before)
            self.assertEqual({path.name for path in task_dir.iterdir()}, {"request.json", "failure.json"})
            self.assertEqual(
                json.loads((task_dir / "failure.json").read_text(encoding="utf-8")),
                {"code": "command_unquoted_pipe"},
            )
            self.assertEqual(
                validate_workflow_receipt(
                    manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),))
                ).status,
                "incomplete",
            )

    def test_hunt_schema_four_binds_reproducible_evidence_and_rejects_tampering(self) -> None:
        # Rewriting receipt or evidence bytes cannot replace host-reproduced evidence.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def discovery(request: object, *_: object) -> ExecutorResult:
                return _hunt_result(request)

            def verification_factory(candidates: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    return ExecutorResult(_hunt_verification(request.task_id, candidates[request.task_id][0]), ({"event": "done"},), ())
                return verification

            run_workflow(manifest, root / "snapshots", outputs, "evidence", "hunt", "hunt-balanced", _controls(), ExecutionPolicy((("python",),)), discovery, verification_factory)
            receipt_path = outputs / "evidence-workflow-receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema_version"], 3)
            self.assertEqual(receipt["hunt_evidence_protocol_version"], 4)
            self.assertIn("discovery_evidence_sha256", receipt)
            self.assertEqual(validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),))).status, "completed")
            evidence_path = outputs / "evidence-discovery" / "evidence.jsonl"
            original_evidence = evidence_path.read_bytes()
            evidence_rows = [json.loads(line) for line in original_evidence.decode("utf-8").splitlines()]
            for field in (
                "inventory_sha256", "rank_input_sha256", "frontier_sha256", "priority_packet_sha256",
                "candidate_links_sha256", "coverage_debt_sha256",
            ):
                with self.subTest(field=field):
                    altered = [row.copy() for row in evidence_rows]
                    altered[0][field] = "0" * 64
                    evidence_path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in altered), encoding="utf-8")
                    with self.assertRaisesRegex(PhaseRunnerError, "evidence"):
                        validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),)))
                    evidence_path.write_bytes(original_evidence)
            evidence_path.write_bytes(original_evidence + b"\n")
            with self.assertRaisesRegex(PhaseRunnerError, "evidence"):
                validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),)))

    def test_hunt_missing_evidence_rejects_completed_and_incomplete_receipts(self) -> None:
        # Both receipt states require the complete Hunt discovery evidence aggregate.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def discovery(request: object, *_: object) -> ExecutorResult:
                return _hunt_result(request)

            def verification_factory(_: object):
                def verification(*_: object) -> ExecutorResult:
                    raise ExecutorFailureError("failure", failure_code="final_response_invalid")
                return verification

            run_workflow(manifest, root / "snapshots", outputs, "missing-evidence", "hunt", "hunt-balanced", _controls(), ExecutionPolicy((("python",),)), discovery, verification_factory)
            evidence_path = outputs / "missing-evidence-discovery" / "evidence.jsonl"
            evidence_path.unlink()
            with self.assertRaisesRegex(PhaseRunnerError, "evidence"):
                validate_workflow_receipt(manifest, root / "snapshots", outputs, outputs / "missing-evidence-workflow-receipt.json", _controls(), ExecutionPolicy((("python",),)))

    def test_standard_receipt_remains_schema_two_without_evidence_artifacts(self) -> None:
        # Hunt evidence must not add fields or files to the Standard workflow.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def discovery(request: object, *_: object) -> ExecutorResult:
                return ExecutorResult(_prediction(request.task_id), ({"event": "done"},), ())

            def verification_factory(candidates: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    return ExecutorResult(_prediction(request.task_id, finding_id=candidates[request.task_id][0].candidate_id), ({"event": "done"},), ())
                return verification

            run_workflow(manifest, root / "snapshots", outputs, "standard-evidence", "standard", "baseline", _controls(), ExecutionPolicy((("python",),)), discovery, verification_factory)
            receipt = json.loads((outputs / "standard-evidence-workflow-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema_version"], 2)
            self.assertNotIn("discovery_evidence_sha256", receipt)
            self.assertNotIn("hunt_evidence_protocol_version", receipt)
            self.assertFalse((outputs / "standard-evidence-discovery" / "evidence.jsonl").exists())
    def test_incomplete_hunt_receipt_has_no_public_predictions_and_revalidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def discovery(request: object, *_: object) -> ExecutorResult:
                return _hunt_result(request)

            def verification_factory(_: object):
                def verification(*_: object) -> ExecutorResult:
                    raise ExecutorFailureError("public failure", failure_code="final_response_invalid")
                return verification

            result = run_workflow(manifest, root / "snapshots", outputs, "incomplete-hunt", "hunt", "hunt-balanced", _controls(), ExecutionPolicy((("python",),)), discovery, verification_factory)
            receipt_path = outputs / "incomplete-hunt-workflow-receipt.json"

            self.assertEqual(result.receipt.status, "incomplete")
            self.assertIsNone(result.receipt.public_predictions_sha256)
            self.assertFalse((outputs / "incomplete-hunt-public-predictions.jsonl").exists())
            self.assertEqual(validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),))).status, "incomplete")
            (outputs / "incomplete-hunt-public-predictions.jsonl").write_text("unexpected\n", encoding="utf-8")
            with self.assertRaisesRegex(PhaseRunnerError, "unexpected public predictions"):
                validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),)))

    def test_failed_hunt_discovery_revalidates_empty_completed_subset(self) -> None:
        # Discovery failure must retain no candidates or second-phase artifacts.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def discovery(*_: object) -> ExecutorResult:
                raise ExecutorFailureError("failure", failure_code="final_response_invalid")

            result = run_workflow(
                manifest, root / "snapshots", outputs, "failed-discovery", "hunt", "hunt-balanced",
                _controls(), ExecutionPolicy((("python",),)), discovery, lambda _: self.fail("verification must not run"),
                hunt_evidence_protocol_version=1,
            )
            receipt_path = outputs / "failed-discovery-workflow-receipt.json"

            self.assertEqual(result.receipt.status, "incomplete")
            self.assertEqual(result.receipt.hunt_evidence_protocol_version, 1)
            self.assertEqual((outputs / "failed-discovery-candidates.jsonl").read_bytes(), b"")
            self.assertFalse((outputs / "failed-discovery-verification").exists())
            self.assertFalse((outputs / "failed-discovery-public-predictions.jsonl").exists())
            self.assertEqual(
                validate_workflow_receipt(
                    manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),))
                ).status,
                "incomplete",
            )
            aggregate = json.loads(receipt_path.read_text(encoding="utf-8"))
            aggregate["token_usage"]["output_tokens"] += 1
            receipt_path.write_text(
                json.dumps(aggregate, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PhaseRunnerError, "aggregate"):
                validate_workflow_receipt(
                    manifest,
                    root / "snapshots",
                    outputs,
                    receipt_path,
                    _controls(),
                    ExecutionPolicy((("python",),)),
                )

    def test_partial_hunt_discovery_revalidates_manifest_ordered_subset_and_rejects_artifacts(self) -> None:
        # Only completed task receipts may contribute discovery prediction or evidence rows.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def discovery(request: object, *_: object) -> ExecutorResult:
                if request.task_id == "task-a":
                    return _hunt_result(request, evidence_protocol_version=1)
                raise ExecutorFailureError("failure", failure_code="final_response_invalid")

            result = run_workflow(
                manifest, root / "snapshots", outputs, "partial-discovery", "hunt", "hunt-balanced",
                _controls(), ExecutionPolicy((("python",),)), discovery, lambda _: self.fail("verification must not run"),
                hunt_evidence_protocol_version=1,
            )
            receipt_path = outputs / "partial-discovery-workflow-receipt.json"
            candidate_path = outputs / "partial-discovery-candidates.jsonl"
            evidence_path = outputs / "partial-discovery-discovery" / "evidence.jsonl"

            self.assertEqual(result.receipt.status, "incomplete")
            self.assertEqual(result.receipt.hunt_evidence_protocol_version, 1)
            self.assertEqual(
                [json.loads(line)["task_id"] for line in (outputs / "partial-discovery-discovery" / "predictions.jsonl").read_text(encoding="utf-8").splitlines()],
                ["task-a"],
            )
            self.assertEqual(len(evidence_path.read_text(encoding="utf-8").splitlines()), 1)
            self.assertEqual(candidate_path.read_bytes(), b"")
            self.assertEqual(
                validate_workflow_receipt(
                    manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),))
                ).status,
                "incomplete",
            )

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            candidate_path.write_text("tampered\n", encoding="utf-8")
            receipt["candidate_transfer_sha256"] = sha256_file(candidate_path)
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(PhaseRunnerError, "candidate transfer"):
                validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),)))

            candidate_path.write_bytes(b"")
            receipt["candidate_transfer_sha256"] = sha256_file(candidate_path)
            evidence_path.write_bytes(evidence_path.read_bytes() * 2)
            receipt["discovery_evidence_sha256"] = sha256_file(evidence_path)
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(PhaseRunnerError, "evidence is incomplete"):
                validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),)))

            evidence_path.write_bytes(evidence_path.read_bytes()[: len(evidence_path.read_bytes()) // 2])
            receipt["discovery_evidence_sha256"] = sha256_file(evidence_path)
            verification_dir = outputs / "partial-discovery-verification"
            verification_dir.mkdir()
            (verification_dir / "receipt.json").write_text("{}", encoding="utf-8")
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(PhaseRunnerError, "unexpected verification"):
                validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),)))

    def test_failed_hunt_discovery_retains_each_selected_evidence_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            policy = ExecutionPolicy((("python",),))

            def discovery(*_: object) -> ExecutorResult:
                raise ExecutorFailureError(
                    "failure",
                    failure_code="final_response_invalid",
                )

            for version in (1, 2, 3, 4):
                with self.subTest(version=version):
                    result = run_workflow(
                        manifest,
                        root / "snapshots",
                        outputs,
                        f"failed-protocol-{version}",
                        "hunt",
                        "hunt-balanced",
                        _controls(),
                        policy,
                        discovery,
                        lambda _: self.fail("verification must not run"),
                        hunt_evidence_protocol_version=version,
                    )
                    self.assertEqual(result.receipt.status, "incomplete")
                    self.assertEqual(result.receipt.hunt_evidence_protocol_version, version)

    def test_hunt_workflow_preserves_six_candidates_and_rejects_missing_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            received: dict[str, tuple[object, ...]] = {}

            def discovery(request: object, *_: object) -> ExecutorResult:
                return _hunt_result(request, 6)

            def valid_factory(candidate_sets: object):
                received.update(candidate_sets)

                def verification(request: object, *_: object) -> ExecutorResult:
                    candidates = candidate_sets[request.task_id]
                    findings = []
                    decisions = []
                    for number, candidate in enumerate(candidates, start=1):
                        disposition = "accepted" if number <= 5 else "rejected"
                        if disposition == "accepted":
                            finding = _prediction(request.task_id, finding_id=candidate.candidate_id)["prediction"]["findings"][0]
                            finding["confidence"] = candidate.confidence
                            findings.append(finding)
                        decisions.append({"candidate_id": candidate.candidate_id, "disposition": disposition, "attacker_control": "proven" if disposition == "accepted" else "disproven", "reachability": "proven", "impact": "proven", "guard_failure": "proven", "evidence": "Confirmed." if disposition == "accepted" else "", "counterevidence": "Blocked." if disposition == "rejected" else "", "proof_gaps": "", "confidence": candidate.confidence})
                    return ExecutorResult({"prediction": {"schema_version": 1, "task_id": request.task_id, "findings": findings, "decisions": decisions}, "usage": {"input_tokens": 7, "cached_input_tokens": 2, "output_tokens": 3}}, ({"event": "done"},), ())
                return verification

            result = run_workflow(manifest, root / "snapshots", outputs, "six", "hunt", "hunt-balanced", _controls(), ExecutionPolicy((("python",),)), discovery, valid_factory)
            rows = [json.loads(line) for line in (outputs / "six-candidates.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows[0]["candidates"]), 6)
            self.assertIn("expected_control", rows[0]["candidates"][5])
            rich_fields = {
                "confidence",
                "vulnerability_family",
                "search_pass",
                "hypothesis",
                "evidence",
                "counterevidence",
                "expected_control",
            }
            for row in rows:
                received_by_id = {
                    candidate.candidate_id: candidate for candidate in received[row["task_id"]]
                }
                for candidate in row["candidates"]:
                    self.assertTrue(rich_fields.issubset(candidate))
                    received_candidate = received_by_id[candidate["candidate_id"]]
                    self.assertEqual(candidate, received_candidate.to_json())
                    self.assertEqual(
                        {
                            key: candidate[key]
                            for key in (
                                "candidate_id",
                                "entry_point",
                                "critical_operation",
                                "trace",
                            )
                        },
                        received_candidate.to_verification_projection(),
                    )
            self.assertEqual(validate_workflow_receipt(manifest, root / "snapshots", outputs, outputs / "six-workflow-receipt.json", _controls(), ExecutionPolicy((("python",),))).status, "completed")
            self.assertEqual(result.receipt.status, "completed")
            receipt_path = outputs / "six-workflow-receipt.json"
            legacy_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            legacy_receipt["schema_version"] = 1
            receipt_path.write_text(json.dumps(legacy_receipt), encoding="utf-8")
            with self.assertRaisesRegex(PhaseRunnerError, "schema_version"):
                validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), ExecutionPolicy((("python",),)))

            def missing_factory(candidate_sets: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    candidate = candidate_sets[request.task_id][0]
                    return ExecutorResult(_hunt_verification(request.task_id, candidate), ({"event": "done"},), ())
                return verification

            with self.assertRaisesRegex(PhaseRunnerError, "terminal decision"):
                run_workflow(manifest, root / "snapshots", outputs, "missing", "hunt", "hunt-balanced", _controls(), ExecutionPolicy((("python",),)), discovery, missing_factory)

    def test_hunt_score_callback_receives_public_predictions_without_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def discovery(request: object, *_: object) -> ExecutorResult:
                return _hunt_result(request)

            def verification_factory(candidates: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    return ExecutorResult(_hunt_verification(request.task_id, candidates[request.task_id][0]), ({"event": "done"},), ())
                return verification

            def score(predictions_path: Path) -> dict[str, object]:
                return {"findings": sum(len(row.findings) for row in load_predictions(predictions_path).values())}

            result = run_workflow(manifest, root / "snapshots", outputs, "hunt-score", "hunt", "hunt-balanced", _controls(), ExecutionPolicy((("python",),)), discovery, verification_factory, score)

        self.assertEqual(result.artifact_paths["final_predictions"], "hunt-score-public-predictions.jsonl")
    def test_host_scoring_input_never_enters_executor_or_public_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            private_oracle = "host-only-oracle-sentinel"
            seen_requests: list[str] = []

            def discovery(request: object, *_: object) -> ExecutorResult:
                seen_requests.append(repr(request))
                return ExecutorResult(_prediction(request.task_id), ({"event": "done"},), ())

            def verification_factory(candidates: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    seen_requests.append(repr(request))
                    candidate = candidates[request.task_id][0]
                    response = _prediction(request.task_id, finding_id=candidate.candidate_id)
                    return ExecutorResult(response, ({"event": "done"},), ())
                return verification

            def score(predictions_path: Path) -> dict[str, object]:
                self.assertTrue(predictions_path.is_file())
                self.assertEqual(private_oracle, "host-only-oracle-sentinel")
                return {"composite_score": 1.0}

            result = run_workflow(
                manifest,
                root / "snapshots",
                outputs,
                "host-score",
                "standard",
                "baseline",
                _controls(),
                ExecutionPolicy((("python",),)),
                discovery,
                verification_factory,
                score,
            )
            public_bytes = b"".join(path.read_bytes() for path in outputs.rglob("*") if path.is_file())
        self.assertEqual(result.artifact_paths["score"], "host-score-score.json")
        self.assertTrue(seen_requests)
        self.assertTrue(all(private_oracle not in request for request in seen_requests))
        self.assertNotIn(private_oracle.encode("utf-8"), public_bytes)

    def test_workflow_runs_fresh_discovery_and_empty_candidate_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            calls: list[tuple[str, str, tuple[str, ...]]] = []

            def discovery(request: object, *_: object) -> ExecutorResult:
                calls.append(("discovery", request.task_id, ()))
                response = _prediction(request.task_id)
                response["prediction"]["findings"] = []
                return ExecutorResult(response, ({"event": "done"},), ())

            def verification_factory(candidate_sets: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    calls.append(("verification", request.task_id, tuple(item.candidate_id for item in candidate_sets[request.task_id])))
                    return ExecutorResult(_prediction(request.task_id) | {"prediction": {"schema_version": 1, "task_id": request.task_id, "findings": []}}, ({"event": "done"},), ())
                return verification

            result = run_workflow(
                manifest=manifest,
                snapshots_root=root / "snapshots",
                output_root=outputs,
                run_id="single",
                workflow="standard",
                profile="baseline",
                controls=_controls(),
                execution_policy=ExecutionPolicy((("python",),)),
                discovery_executor=discovery,
                verification_executor_factory=verification_factory,
            )
            artifact = json.loads((outputs / "single-result.json").read_text(encoding="utf-8"))
        self.assertEqual(result.receipt.status, "completed")
        self.assertEqual([phase for phase, _, _ in calls], ["discovery", "discovery", "verification", "verification"])
        self.assertEqual([ids for _, _, ids in calls[2:]], [(), ()])
        self.assertEqual(artifact["final_predictions"], "single-verification/predictions.jsonl")
        self.assertEqual(result.receipt.top_level_invocation_count, 4)

    def test_hashed_command_arguments_are_published_and_revalidated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            policy = ExecutionPolicy((("rg",),))
            command = (
                "rg",
                "-n",
                "sha256=b381aa9d75effd31bfd58154c941aa4dae2d8326bb40f7559368ffc63d77ea01",
                "source.py",
            )

            def discovery(request: object, *_: object) -> ExecutorResult:
                return ExecutorResult(_prediction(request.task_id), ({"event": "done"},), (command,))

            def verification_factory(candidate_sets: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    candidate = candidate_sets[request.task_id][0]
                    response = _prediction(request.task_id, finding_id=candidate.candidate_id)
                    return ExecutorResult(response, ({"event": "done"},), (command,))
                return verification

            result = run_workflow(
                manifest,
                root / "snapshots",
                outputs,
                "hashed-command",
                "standard",
                "baseline",
                _controls(),
                policy,
                discovery,
                verification_factory,
            )
            command_row = json.loads(
                (outputs / "hashed-command-discovery" / "commands.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()[0]
            )
            validated = validate_workflow_receipt(
                manifest,
                root / "snapshots",
                outputs,
                outputs / "hashed-command-workflow-receipt.json",
                _controls(),
                policy,
            )

        self.assertEqual(command_row["argv"], list(command))
        self.assertEqual(validated.status, "completed")
        self.assertEqual(result.receipt.status, "completed")

    def test_incomplete_verification_rejects_tampered_failure_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            policy = ExecutionPolicy((("python",),))

            def discovery(request: object, *_: object) -> ExecutorResult:
                return ExecutorResult(_prediction(request.task_id), ({"event": "done"},), ())

            def verification_factory(candidate_sets: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    if request.task_id == "task-a":
                        raise ExecutorFailureError(
                            "private verification detail",
                            failure_code="event_stream_failed",
                        )
                    candidate = candidate_sets[request.task_id][0]
                    response = _prediction(request.task_id, finding_id=candidate.candidate_id)
                    return ExecutorResult(response, ({"event": "done"},), ())
                return verification

            result = run_workflow(
                manifest,
                root / "snapshots",
                outputs,
                "incomplete",
                "standard",
                "baseline",
                _controls(),
                policy,
                discovery,
                verification_factory,
            )
            receipt_path = outputs / "incomplete-workflow-receipt.json"
            self.assertEqual(
                validate_workflow_receipt(
                    manifest, root / "snapshots", outputs, receipt_path, _controls(), policy
                ).status,
                "incomplete",
            )
            failure_path = next((outputs / "incomplete-verification" / "tasks").rglob("failure.json"))
            failure_path.write_text('{"code":"event_stream_invalid"}\n', encoding="utf-8")

            with self.assertRaisesRegex(PhaseRunnerError, "failure evidence"):
                validate_workflow_receipt(
                    manifest, root / "snapshots", outputs, receipt_path, _controls(), policy
                )

    def test_rejects_verification_mutation_and_comparison_control_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def discovery(request: object, *_: object) -> ExecutorResult:
                return ExecutorResult(_prediction(request.task_id), ({"event": "done"},), ())

            def bad_verification(_: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    response = _prediction(request.task_id)
                    response["prediction"]["findings"][0]["entry_point"] = {"file": "source.py", "line": 2}
                    return ExecutorResult(response, ({"event": "done"},), ())
                return verification

            with self.assertRaisesRegex(PhaseRunnerError, "verification"):
                run_workflow(manifest, root / "snapshots", outputs, "bad", "standard", "baseline", _controls(), ExecutionPolicy((("python",),)), discovery, bad_verification)

    def test_rehashes_tampered_candidate_and_phase_receipts_before_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()
            policy = ExecutionPolicy((("python",),))

            def discovery(request: object, *_: object) -> ExecutorResult:
                return ExecutorResult(_prediction(request.task_id), ({"event": "done"},), ())

            def verification_factory(candidate_sets: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    candidate = candidate_sets[request.task_id][0]
                    response = _prediction(request.task_id)
                    response["prediction"]["findings"][0]["finding_id"] = candidate.candidate_id
                    return ExecutorResult(response, ({"event": "done"},), ())
                return verification

            run_workflow(manifest, root / "snapshots", outputs, "bound", "standard", "baseline", _controls(), policy, discovery, verification_factory)
            receipt_path = outputs / "bound-workflow-receipt.json"
            self.assertEqual(
                validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), policy).status,
                "completed",
            )
            (outputs / "bound-candidates.jsonl").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(PhaseRunnerError, "candidate hash"):
                validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), policy)
            run_workflow(manifest, root / "snapshots", outputs, "bound-two", "standard", "baseline", _controls(), policy, discovery, verification_factory)
            task_receipts = outputs / "bound-two-discovery" / "task-receipts.jsonl"
            rows = [json.loads(line) for line in task_receipts.read_text(encoding="utf-8").splitlines()]
            rows[0]["token_usage"]["output_tokens"] = 99
            task_receipts.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaisesRegex(PhaseRunnerError, "phase receipt"):
                validate_workflow_receipt(manifest, root / "snapshots", outputs, outputs / "bound-two-workflow-receipt.json", _controls(), policy)
            run_workflow(manifest, root / "snapshots", outputs, "bound-three", "standard", "baseline", _controls(), policy, discovery, verification_factory)
            candidate_path = outputs / "bound-three-candidates.jsonl"
            candidate_rows = [json.loads(line) for line in candidate_path.read_text(encoding="utf-8").splitlines()]
            candidate_rows[0]["candidates"][0]["confidence"] = 0.7
            candidate_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in candidate_rows), encoding="utf-8")
            receipt_path = outputs / "bound-three-workflow-receipt.json"
            aggregate = json.loads(receipt_path.read_text(encoding="utf-8"))
            aggregate["candidate_transfer_sha256"] = sha256_file(candidate_path)
            receipt_path.write_text(json.dumps(aggregate, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(PhaseRunnerError, "candidate transfer"):
                validate_workflow_receipt(manifest, root / "snapshots", outputs, receipt_path, _controls(), policy)
            run_workflow(manifest, root / "snapshots", outputs, "bound-four", "standard", "baseline", _controls(), policy, discovery, verification_factory)
            predictions_path = outputs / "bound-four-verification" / "predictions.jsonl"
            predictions = [json.loads(line) for line in predictions_path.read_text(encoding="utf-8").splitlines()]
            predictions[0]["findings"][0]["entry_point"]["line"] = 2
            predictions_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in predictions), encoding="utf-8")
            with self.assertRaisesRegex(PhaseRunnerError, "verification predictions hash"):
                validate_workflow_receipt(
                    manifest,
                    root / "snapshots",
                    outputs,
                    outputs / "bound-four-workflow-receipt.json",
                    _controls(),
                    policy,
                )

    def test_seedless_pairs_follow_exact_ab_ba_ab_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def executor(request: object, *_: object) -> ExecutorResult:
                return ExecutorResult(_prediction(request.task_id), ({"event": "done"},), ())

            def factory(candidate_sets: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    candidates = candidate_sets[request.task_id]
                    response = _prediction(request.task_id)
                    response["prediction"]["findings"][0]["finding_id"] = candidates[0].candidate_id
                    return ExecutorResult(response, ({"event": "done"},), ())
                return verification

            def hunt_executor(request: object, *_: object) -> ExecutorResult:
                return _hunt_result(request)

            def hunt_factory(candidate_sets: object):
                def verification(request: object, *_: object) -> ExecutorResult:
                    candidate = candidate_sets[request.task_id][0]
                    finding = _prediction(request.task_id)["prediction"]["findings"][0]
                    finding["finding_id"] = candidate.candidate_id
                    finding["confidence"] = candidate.confidence
                    decision = {"candidate_id": candidate.candidate_id, "disposition": "accepted", "attacker_control": "proven", "reachability": "proven", "impact": "proven", "guard_failure": "proven", "evidence": "Confirmed.", "counterevidence": "", "proof_gaps": "", "confidence": candidate.confidence}
                    return ExecutorResult({"prediction": {"schema_version": 1, "task_id": request.task_id, "findings": [finding], "decisions": [decision]}, "usage": _prediction(request.task_id)["usage"]}, ({"event": "done"},), ())
                return verification

            paired = run_paired(
                manifest, root / "snapshots", outputs, "paired", _controls(),
                ExecutionPolicy((("python",),)),
                {"standard": executor, "hunt": hunt_executor},
                {"standard": factory, "hunt": hunt_factory},
                {"standard": "baseline", "hunt": "hunt-balanced"},
            )
            comparison_artifact = json.loads((outputs / "paired-comparison.json").read_text(encoding="utf-8"))
        self.assertEqual(paired.schedule, (("standard", "hunt"), ("hunt", "standard"), ("standard", "hunt")))
        self.assertTrue(all(comparison.comparable for comparison in paired.comparisons))
        self.assertEqual(len(comparison_artifact["evidence"]), 3)
        self.assertEqual(
            comparison_artifact["evidence"][0]["standard_artifacts"]["aggregate_receipt"],
            "paired-repeat-1-standard-workflow-receipt.json",
        )


if __name__ == "__main__":
    unittest.main()
