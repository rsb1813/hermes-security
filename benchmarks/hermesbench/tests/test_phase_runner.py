# Verifies paired HermesBench discovery and verification execution.

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.hermesbench.contracts import BenchmarkManifest, load_predictions, parse_manifest
from benchmarks.hermesbench.phase_runner import (
    FrozenControls,
    PhaseRunnerError,
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
from benchmarks.hermesbench.receipts import sha256_file


def _manifest(root: Path) -> BenchmarkManifest:
    snapshots = root / "snapshots"
    snapshots.mkdir()
    for task_id in ("task-a", "task-b"):
        snapshot = snapshots / task_id
        snapshot.mkdir()
        (snapshot / "source.py").write_text("one\ntwo\nthree\n", encoding="utf-8")
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


def _hunt_verification(task_id: str, candidate: object) -> dict[str, object]:
    finding = _prediction(task_id, finding_id=candidate.candidate_id)["prediction"]["findings"][0]
    finding["confidence"] = candidate.confidence
    decision = {"candidate_id": candidate.candidate_id, "disposition": "accepted", "attacker_control": "proven", "reachability": "proven", "impact": "proven", "guard_failure": "proven", "evidence": "Confirmed.", "counterevidence": "", "proof_gaps": "", "confidence": candidate.confidence}
    return {"prediction": {"schema_version": 1, "task_id": task_id, "findings": [finding], "decisions": [decision]}, "usage": {"input_tokens": 7, "cached_input_tokens": 2, "output_tokens": 3}}


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
    def test_incomplete_hunt_receipt_has_no_public_predictions_and_revalidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def discovery(request: object, *_: object) -> ExecutorResult:
                return ExecutorResult(_hunt_discovery(request.task_id), ({"event": "done"},), ())

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

    def test_hunt_workflow_preserves_six_candidates_and_rejects_missing_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _manifest(root)
            outputs = root / "outputs"
            outputs.mkdir()

            def discovery(request: object, *_: object) -> ExecutorResult:
                return ExecutorResult(_hunt_discovery(request.task_id, 6), ({"event": "done"},), ())

            def valid_factory(candidate_sets: object):
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
                return ExecutorResult(_hunt_discovery(request.task_id), ({"event": "done"},), ())

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
                candidate = _prediction(request.task_id)["prediction"]["findings"][0]
                candidate |= {
                    "vulnerability_family": "injection", "search_pass": "forward",
                    "hypothesis": "Input reaches the operation.", "evidence": "Trace exists.",
                    "counterevidence": "No guard found.", "expected_control": "Validate input.",
                }
                return ExecutorResult(
                    {"prediction": {"schema_version": 1, "task_id": request.task_id, "candidates": [candidate]}, "usage": _prediction(request.task_id)["usage"]},
                    ({"event": "done"},), (),
                )

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
