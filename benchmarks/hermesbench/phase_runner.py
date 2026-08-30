# Runs independent HermesBench discovery and verification phases.

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, fields
from pathlib import Path, PurePosixPath, PureWindowsPath

from .adapter_contract import AdapterTaskRequest
from .contracts import BenchmarkManifest, Finding, Location, TaskDescriptor, TaskPrediction, parse_prediction
from .hunt_protocol import (
    HUNT_CANDIDATE_PROTOCOL_VERSION,
    HUNT_DISCOVERY_MAX_CANDIDATES,
    HuntDiscoveryCandidate,
    HuntProtocolError,
    HuntTerminalDecision,
    parse_hunt_discovery_prediction,
    parse_hunt_verification_prediction,
)
from .hunt_evidence import (
    HUNT_EVIDENCE_PROTOCOL_VERSION,
    NESTED_OUTPUT_HUNT_EVIDENCE_PROTOCOL_VERSION,
    PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION,
    SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS,
    HuntEvidenceError,
    parse_hunt_evidence,
    reproduce_hunt_evidence,
)
from .receipts import (
    RECEIPT_SCHEMA_VERSION,
    RunConfig,
    RunReceipt,
    TaskRunReceipt,
    TokenUsage,
    load_receipt,
    sha256_file,
)
from .runner import (
    ExecutionPolicy,
    Executor,
    ExecutorResult,
    RunnerError,
    execution_policy_sha256,
    failure_evidence_sha256,
    manifest_sha256,
    run_suite,
    task_order_sha256,
)


PHASE_PROTOCOL_VERSION = 1
STANDARD_WORKFLOW_RECEIPT_SCHEMA_VERSION = 2
HUNT_WORKFLOW_RECEIPT_SCHEMA_VERSION = 3
_MAX_CANDIDATE_PATH_BYTES = 240
_MAX_CANDIDATE_TRACE = 16
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PUBLIC_COMMAND_TOKEN = re.compile(r"[-A-Za-z0-9_./:=@%+]+\Z")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_RECOVERABLE_PARTIAL_HUNT_PROTOCOL_VERSIONS = frozenset({
    NESTED_OUTPUT_HUNT_EVIDENCE_PROTOCOL_VERSION,
    PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION,
})


class PhaseRunnerError(ValueError):
    """Signals a paired-phase audit boundary failure."""


@dataclass(frozen=True)
class FrozenControls:
    schema_version: int
    model: str
    reasoning_effort: str
    seed_supported: bool
    seed: str | None
    image_digest: str
    tool_versions: tuple[tuple[str, str], ...]
    time_limit_seconds: int
    max_findings: int
    grader_version: str
    phase_protocol_version: int
    hunt_candidate_protocol_version: int
    invocations_per_task: int
    max_parallel_tasks: int = 1

    def __post_init__(self) -> None:
        if self.schema_version not in {2, 3} or isinstance(self.schema_version, bool):
            raise PhaseRunnerError("controls schema_version must be 2 or 3")
        _required_text(self.model, "model")
        _required_text(self.reasoning_effort, "reasoning_effort")
        if not isinstance(self.seed_supported, bool):
            raise PhaseRunnerError("seed_supported must be a boolean")
        if self.seed_supported:
            _required_text(self.seed, "seed")
        elif self.seed is not None:
            raise PhaseRunnerError("seed must be absent when seed_supported is false")
        if not isinstance(self.image_digest, str) or _IMAGE_DIGEST.fullmatch(self.image_digest) is None:
            raise PhaseRunnerError("image_digest must be an immutable sha256 digest")
        if not self.tool_versions or len({name for name, _ in self.tool_versions}) != len(self.tool_versions):
            raise PhaseRunnerError("tool_versions must contain unique tools")
        for name, version in self.tool_versions:
            _required_text(name, "tool name")
            _required_text(version, "tool version")
        _positive_int(self.time_limit_seconds, "time_limit_seconds")
        if self.max_findings != 5:
            raise PhaseRunnerError("max_findings must be exactly 5")
        _required_text(self.grader_version, "grader_version")
        if self.phase_protocol_version != PHASE_PROTOCOL_VERSION:
            raise PhaseRunnerError("phase_protocol_version is unsupported")
        if self.hunt_candidate_protocol_version != HUNT_CANDIDATE_PROTOCOL_VERSION:
            raise PhaseRunnerError("hunt_candidate_protocol_version is unsupported")
        if self.invocations_per_task != 2:
            raise PhaseRunnerError("invocations_per_task must be exactly 2")
        _positive_int(self.max_parallel_tasks, "max_parallel_tasks")
        if self.schema_version == 2 and self.max_parallel_tasks != 1:
            raise PhaseRunnerError(
                "max_parallel_tasks must be exactly 1 for controls schema 2"
            )
        if self.schema_version == 3 and self.max_parallel_tasks > 2:
            raise PhaseRunnerError("max_parallel_tasks must be at most 2")

    @classmethod
    def from_json(cls, value: object) -> "FrozenControls":
        data = _object(value, "controls")
        expected = {field.name for field in fields(cls)} - {"max_parallel_tasks"}
        if data.get("schema_version") == 3:
            expected.add("max_parallel_tasks")
        _exact_fields(data, expected, "controls")
        raw_tools = data["tool_versions"]
        if not isinstance(raw_tools, list):
            raise PhaseRunnerError("tool_versions must be an array")
        tools: list[tuple[str, str]] = []
        for item in raw_tools:
            if not isinstance(item, list) or len(item) != 2:
                raise PhaseRunnerError("tool_versions entries must have two strings")
            tools.append((item[0], item[1]))
        return cls(
            schema_version=data["schema_version"],
            model=data["model"],
            reasoning_effort=data["reasoning_effort"],
            seed_supported=data["seed_supported"],
            seed=data["seed"],
            image_digest=data["image_digest"],
            tool_versions=tuple(tools),
            time_limit_seconds=data["time_limit_seconds"],
            max_findings=data["max_findings"],
            grader_version=data["grader_version"],
            phase_protocol_version=data["phase_protocol_version"],
            hunt_candidate_protocol_version=data["hunt_candidate_protocol_version"],
            invocations_per_task=data["invocations_per_task"],
            max_parallel_tasks=data.get("max_parallel_tasks", 1),
        )

    def to_json(self) -> dict[str, object]:
        value = {
            "schema_version": self.schema_version,
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "seed_supported": self.seed_supported,
            "seed": self.seed,
            "image_digest": self.image_digest,
            "tool_versions": [list(item) for item in self.tool_versions],
            "time_limit_seconds": self.time_limit_seconds,
            "max_findings": self.max_findings,
            "grader_version": self.grader_version,
            "phase_protocol_version": self.phase_protocol_version,
            "hunt_candidate_protocol_version": self.hunt_candidate_protocol_version,
            "invocations_per_task": self.invocations_per_task,
        }
        if self.schema_version == 3:
            value["max_parallel_tasks"] = self.max_parallel_tasks
        return value

    def sha256(self) -> str:
        return _canonical_sha256(self.to_json())

    def run_config(self, manifest: BenchmarkManifest, policy: ExecutionPolicy) -> RunConfig:
        return RunConfig(
            manifest_sha256=manifest_sha256(manifest),
            task_order_sha256=task_order_sha256(manifest),
            execution_policy_sha256=execution_policy_sha256(policy),
            grader_version=self.grader_version,
            model=self.model,
            reasoning_effort=self.reasoning_effort,
            seed=self.seed,
            seed_supported=self.seed_supported,
            tool_versions=self.tool_versions,
            time_limit_seconds=self.time_limit_seconds,
            max_findings=self.max_findings,
            max_parallel_tasks=self.max_parallel_tasks,
        )


@dataclass(frozen=True)
class CanonicalCandidate:
    candidate_id: str
    entry_point: Location
    critical_operation: Location
    trace: tuple[Location, ...]
    confidence: float
    vulnerability_family: str | None = None
    search_pass: str | None = None
    hypothesis: str | None = None
    evidence: str | None = None
    counterevidence: str | None = None
    expected_control: str | None = None

    def to_json(self) -> dict[str, object]:
        value: dict[str, object] = {
            "candidate_id": self.candidate_id,
            "entry_point": _location_json(self.entry_point),
            "critical_operation": _location_json(self.critical_operation),
            "trace": [_location_json(location) for location in self.trace],
            "confidence": self.confidence,
        }
        if self.vulnerability_family is not None:
            value |= {
                "vulnerability_family": self.vulnerability_family,
                "search_pass": self.search_pass,
                "hypothesis": self.hypothesis,
                "evidence": self.evidence,
                "counterevidence": self.counterevidence,
                "expected_control": self.expected_control,
            }
        return value

    def to_verification_projection(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "entry_point": _location_json(self.entry_point),
            "critical_operation": _location_json(self.critical_operation),
            "trace": [_location_json(location) for location in self.trace],
        }


@dataclass(frozen=True)
class WorkflowReceipt:
    schema_version: int
    run_id: str
    workflow: str
    profile: str
    frozen_controls_sha256: str
    manifest_sha256: str
    task_order_sha256: str
    execution_policy_sha256: str
    snapshot_set_sha256: str
    discovery_receipt_sha256: str
    discovery_commands_sha256: str
    discovery_predictions_sha256: str
    candidate_transfer_sha256: str
    verification_receipt_sha256: str | None
    verification_commands_sha256: str | None
    verification_predictions_sha256: str | None
    public_predictions_sha256: str | None
    discovery_evidence_sha256: str | None
    hunt_evidence_protocol_version: int | None
    phase_protocol_version: int
    top_level_invocation_count: int
    status: str
    elapsed_seconds: float
    token_usage: TokenUsage

    def __post_init__(self) -> None:
        expected_schema = HUNT_WORKFLOW_RECEIPT_SCHEMA_VERSION if self.workflow == "hunt" else STANDARD_WORKFLOW_RECEIPT_SCHEMA_VERSION
        if self.schema_version != expected_schema:
            raise PhaseRunnerError("workflow receipt schema_version is unsupported")
        _required_text(self.run_id, "run_id")
        _workflow_profile(self.workflow, self.profile)
        for name in (
            "frozen_controls_sha256",
            "manifest_sha256",
            "task_order_sha256",
            "execution_policy_sha256",
            "snapshot_set_sha256",
            "discovery_receipt_sha256",
            "discovery_commands_sha256",
            "discovery_predictions_sha256",
            "candidate_transfer_sha256",
        ):
            _sha256(getattr(self, name), name)
        if self.verification_receipt_sha256 is not None:
            _sha256(self.verification_receipt_sha256, "verification_receipt_sha256")
        if self.verification_commands_sha256 is not None:
            _sha256(self.verification_commands_sha256, "verification_commands_sha256")
        if self.verification_predictions_sha256 is not None:
            _sha256(self.verification_predictions_sha256, "verification_predictions_sha256")
        if self.public_predictions_sha256 is not None:
            _sha256(self.public_predictions_sha256, "public_predictions_sha256")
        if self.workflow == "hunt":
            if (
                self.discovery_evidence_sha256 is None
                or not isinstance(self.hunt_evidence_protocol_version, int)
                or isinstance(self.hunt_evidence_protocol_version, bool)
                or self.hunt_evidence_protocol_version not in SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS
            ):
                raise PhaseRunnerError("Hunt workflow receipt evidence protocol is unsupported")
            _sha256(self.discovery_evidence_sha256, "discovery_evidence_sha256")
        elif self.discovery_evidence_sha256 is not None or self.hunt_evidence_protocol_version is not None:
            raise PhaseRunnerError("Standard workflow receipt must omit Hunt evidence")
        if self.phase_protocol_version != PHASE_PROTOCOL_VERSION:
            raise PhaseRunnerError("workflow receipt phase protocol is unsupported")
        if self.status not in {"completed", "incomplete"}:
            raise PhaseRunnerError("workflow receipt status is unsupported")
        _positive_int(self.top_level_invocation_count, "top_level_invocation_count")
        if self.status == "completed":
            if (
                self.verification_receipt_sha256 is None
                or self.verification_commands_sha256 is None
                or self.verification_predictions_sha256 is None
            ):
                raise PhaseRunnerError("completed workflow receipt must bind two phases")
        elif (
            (self.verification_receipt_sha256 is None and (self.verification_commands_sha256 is not None or self.verification_predictions_sha256 is not None))
            or (self.verification_receipt_sha256 is not None and (self.verification_commands_sha256 is None or self.verification_predictions_sha256 is None))
        ):
            raise PhaseRunnerError("incomplete workflow receipt has an invalid phase count")
        if self.workflow == "hunt" and self.status == "completed":
            if self.public_predictions_sha256 is None:
                raise PhaseRunnerError("completed Hunt workflow receipt must bind public predictions")
        elif self.public_predictions_sha256 is not None:
            raise PhaseRunnerError("only completed Hunt workflow receipts may bind public predictions")
        if not isinstance(self.elapsed_seconds, (int, float)) or isinstance(self.elapsed_seconds, bool) or not math.isfinite(self.elapsed_seconds) or self.elapsed_seconds < 0:
            raise PhaseRunnerError("elapsed_seconds must be finite and non-negative")
        if not isinstance(self.token_usage, TokenUsage):
            raise PhaseRunnerError("token_usage must be TokenUsage")

    def to_json(self) -> dict[str, object]:
        value = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "workflow": self.workflow,
            "profile": self.profile,
            "frozen_controls_sha256": self.frozen_controls_sha256,
            "manifest_sha256": self.manifest_sha256,
            "task_order_sha256": self.task_order_sha256,
            "execution_policy_sha256": self.execution_policy_sha256,
            "snapshot_set_sha256": self.snapshot_set_sha256,
            "discovery_receipt_sha256": self.discovery_receipt_sha256,
            "discovery_commands_sha256": self.discovery_commands_sha256,
            "discovery_predictions_sha256": self.discovery_predictions_sha256,
            "candidate_transfer_sha256": self.candidate_transfer_sha256,
            "verification_receipt_sha256": self.verification_receipt_sha256,
            "verification_commands_sha256": self.verification_commands_sha256,
            "verification_predictions_sha256": self.verification_predictions_sha256,
            "public_predictions_sha256": self.public_predictions_sha256,
            "phase_protocol_version": self.phase_protocol_version,
            "top_level_invocation_count": self.top_level_invocation_count,
            "status": self.status,
            "elapsed_seconds": self.elapsed_seconds,
            "token_usage": self.token_usage.to_json(),
        }
        if self.workflow == "hunt":
            value |= {"discovery_evidence_sha256": self.discovery_evidence_sha256, "hunt_evidence_protocol_version": self.hunt_evidence_protocol_version}
        return value

    @classmethod
    def from_json(cls, value: object) -> "WorkflowReceipt":
        data = _object(value, "workflow receipt")
        expected = {field.name for field in fields(cls)} if data.get("workflow") == "hunt" else {field.name for field in fields(cls)} - {"discovery_evidence_sha256", "hunt_evidence_protocol_version"}
        _exact_fields(data, expected, "workflow receipt")
        return cls(
            schema_version=data["schema_version"], run_id=data["run_id"], workflow=data["workflow"], profile=data["profile"],
            frozen_controls_sha256=data["frozen_controls_sha256"], manifest_sha256=data["manifest_sha256"],
            task_order_sha256=data["task_order_sha256"], execution_policy_sha256=data["execution_policy_sha256"],
            snapshot_set_sha256=data["snapshot_set_sha256"], discovery_receipt_sha256=data["discovery_receipt_sha256"],
            discovery_commands_sha256=data["discovery_commands_sha256"], candidate_transfer_sha256=data["candidate_transfer_sha256"],
            discovery_predictions_sha256=data["discovery_predictions_sha256"], verification_receipt_sha256=data["verification_receipt_sha256"], verification_commands_sha256=data["verification_commands_sha256"], verification_predictions_sha256=data["verification_predictions_sha256"], public_predictions_sha256=data["public_predictions_sha256"],
            discovery_evidence_sha256=data.get("discovery_evidence_sha256"), hunt_evidence_protocol_version=data.get("hunt_evidence_protocol_version"), phase_protocol_version=data["phase_protocol_version"], top_level_invocation_count=data["top_level_invocation_count"],
            status=data["status"], elapsed_seconds=data["elapsed_seconds"], token_usage=TokenUsage.from_json(data["token_usage"]),
        )


@dataclass(frozen=True)
class WorkflowResult:
    receipt: WorkflowReceipt
    artifact_paths: Mapping[str, str]


@dataclass(frozen=True)
class ComparisonResult:
    comparable: bool
    mismatches: tuple[str, ...]


@dataclass(frozen=True)
class PairedRunResult:
    schedule: tuple[tuple[str, str], ...]
    comparisons: tuple[ComparisonResult, ...]


VerificationExecutorFactory = Callable[[Mapping[str, tuple[CanonicalCandidate, ...]]], Executor]
HostScoreCallback = Callable[[Path], Mapping[str, object]]


def canonicalize_candidates(
    manifest: BenchmarkManifest,
    snapshots_root: Path,
    discovery_predictions: Mapping[str, object],
    workflow: str = "standard",
) -> dict[str, tuple[CanonicalCandidate, ...]]:
    """Converts discovery findings into the bounded verification-only contract."""
    if set(discovery_predictions) != {task.task_id for task in manifest.tasks}:
        raise PhaseRunnerError("discovery predictions must contain every manifest task exactly once")
    result: dict[str, tuple[CanonicalCandidate, ...]] = {}
    for task in manifest.tasks:
        raw_prediction = discovery_predictions[task.task_id]
        if workflow == "hunt":
            try:
                hunt_prediction = parse_hunt_discovery_prediction(raw_prediction, task.task_id)
            except HuntProtocolError as error:
                raise PhaseRunnerError("Hunt discovery prediction is invalid") from error
            snapshot = _snapshot_root(snapshots_root, task.task_id)
            candidates = [
                _canonical_hunt_candidate(candidate, number, snapshot)
                for number, candidate in enumerate(hunt_prediction.candidates, start=1)
            ]
        else:
            if workflow != "standard":
                raise PhaseRunnerError("candidate workflow is unsupported")
            if isinstance(raw_prediction, dict):
                raw_findings = raw_prediction.get("findings")
                if isinstance(raw_findings, list) and len(raw_findings) > 5:
                    raise PhaseRunnerError("discovery predictions may contain at most five candidates")
                _validate_raw_candidate_paths(raw_findings)
            prediction = _prediction_for_task(raw_prediction, task.task_id)
            snapshot = _snapshot_root(snapshots_root, task.task_id)
            if len(prediction.findings) > 5:
                raise PhaseRunnerError("discovery predictions may contain at most five candidates")
            candidates = [
                _canonical_candidate(finding, number, snapshot)
                for number, finding in enumerate(prediction.findings, start=1)
            ]
        if len(candidates) > (HUNT_DISCOVERY_MAX_CANDIDATES if workflow == "hunt" else 5):
            raise PhaseRunnerError("discovery candidate count exceeds the protocol limit")
        seen: set[tuple[object, ...]] = set()
        for candidate in candidates:
            identity = (
                candidate.entry_point, candidate.critical_operation, candidate.trace,
                candidate.confidence,
            )
            if identity in seen:
                raise PhaseRunnerError("discovery candidates must not duplicate locations")
            seen.add(identity)
        result[task.task_id] = tuple(candidates)
    return result


def _recoverable_partial_phase(
    records: Sequence[TaskRunReceipt],
    workflow: str,
    evidence_protocol_version: int | None,
) -> bool:
    statuses = tuple(record.status for record in records)
    return (
        _uses_recoverable_partial_hunt_protocol(
            workflow,
            evidence_protocol_version,
        )
        and any(status == "completed" for status in statuses)
        and any(status != "completed" for status in statuses)
        and all(status in {"completed", "failed", "timeout"} for status in statuses)
    )


def _uses_recoverable_partial_hunt_protocol(
    workflow: str,
    evidence_protocol_version: int | None,
) -> bool:
    return (
        workflow == "hunt"
        and evidence_protocol_version in _RECOVERABLE_PARTIAL_HUNT_PROTOCOL_VERSIONS
    )


def _full_manifest_candidates(
    manifest: BenchmarkManifest,
    snapshots_root: Path,
    discovery_predictions: Mapping[str, object],
    workflow: str,
    completed_tasks: Sequence[TaskDescriptor],
) -> dict[str, tuple[CanonicalCandidate, ...]]:
    completed = tuple(completed_tasks)
    if completed == manifest.tasks:
        return canonicalize_candidates(
            manifest,
            snapshots_root,
            discovery_predictions,
            workflow,
        )
    completed_ids = {task.task_id for task in completed}
    ordered = tuple(task for task in manifest.tasks if task.task_id in completed_ids)
    if not completed or completed != ordered:
        raise PhaseRunnerError("completed discovery tasks do not preserve manifest order")
    partial_manifest = BenchmarkManifest(
        schema_version=manifest.schema_version,
        suite=manifest.suite,
        manifest_id=manifest.manifest_id,
        tasks=completed,
    )
    partial = canonicalize_candidates(
        partial_manifest,
        snapshots_root,
        discovery_predictions,
        workflow,
    )
    return {
        task.task_id: partial.get(task.task_id, ())
        for task in manifest.tasks
    }


def _skip_empty_candidate_verification(
    executor: Executor,
    candidates: Mapping[str, tuple[CanonicalCandidate, ...]],
    workflow: str,
) -> Executor:
    if workflow != "hunt":
        raise PhaseRunnerError("local empty verification is Hunt-only")

    def execute(
        request: AdapterTaskRequest,
        scratch_path: Path,
        timeout_seconds: int,
    ) -> ExecutorResult:
        try:
            task_candidates = candidates[request.task_id]
        except KeyError as error:
            raise PhaseRunnerError("verification candidates are incomplete") from error
        if task_candidates:
            return executor(request, scratch_path, timeout_seconds)
        return ExecutorResult(
            raw_response={
                "prediction": {
                    "schema_version": 1,
                    "task_id": request.task_id,
                    "findings": [],
                    "decisions": [],
                },
                "usage": {
                    "input_tokens": 0,
                    "cached_input_tokens": 0,
                    "output_tokens": 0,
                },
            },
            event_rows=({"event": "local_empty"},),
            observed_argv=(),
        )

    return execute


def _full_manifest_verification_predictions(
    manifest: BenchmarkManifest,
    verification_predictions: Mapping[str, object],
    completed_tasks: Sequence[TaskDescriptor],
    workflow: str,
) -> dict[str, object]:
    completed = tuple(completed_tasks)
    if completed == manifest.tasks:
        return dict(verification_predictions)
    completed_ids = {task.task_id for task in completed}
    ordered = tuple(task for task in manifest.tasks if task.task_id in completed_ids)
    if not completed or completed != ordered or workflow != "hunt":
        raise PhaseRunnerError("completed verification tasks do not preserve manifest order")
    return {
        task.task_id: verification_predictions.get(
            task.task_id,
            {
                "schema_version": 1,
                "task_id": task.task_id,
                "findings": [],
                "decisions": [],
            },
        )
        for task in manifest.tasks
    }


def run_workflow(
    manifest: BenchmarkManifest,
    snapshots_root: Path,
    output_root: Path,
    run_id: str,
    workflow: str,
    profile: str,
    controls: FrozenControls,
    execution_policy: ExecutionPolicy,
    discovery_executor: Executor,
    verification_executor_factory: VerificationExecutorFactory,
    score_callback: HostScoreCallback | None = None,
    *,
    hunt_evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION,
) -> WorkflowResult:
    """Runs exactly one discovery suite and, when auditable, one verification suite."""
    _workflow_profile(workflow, profile)
    selected_hunt_evidence_protocol_version: int | None = None
    if workflow == "hunt":
        if (
            not isinstance(hunt_evidence_protocol_version, int)
            or isinstance(hunt_evidence_protocol_version, bool)
            or hunt_evidence_protocol_version not in SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS
        ):
            raise PhaseRunnerError("Hunt evidence protocol is unsupported")
        selected_hunt_evidence_protocol_version = hunt_evidence_protocol_version
    if not isinstance(controls, FrozenControls):
        raise PhaseRunnerError("controls must be FrozenControls")
    if not callable(discovery_executor) or not callable(verification_executor_factory):
        raise PhaseRunnerError("phase executors must be callable")
    if any(task.time_limit_seconds != controls.time_limit_seconds for task in manifest.tasks):
        raise PhaseRunnerError("manifest time_limit_seconds must equal frozen controls")
    config = controls.run_config(manifest, execution_policy)
    _safe_output_root(output_root)
    snapshot_hash = _snapshot_set_sha256(manifest)
    discovery_run_id = f"{run_id}-discovery"
    discovery_kind = "hunt-discovery" if workflow == "hunt" else "standard"
    account_failure_usage = _uses_recoverable_partial_hunt_protocol(
        workflow,
        selected_hunt_evidence_protocol_version,
    )
    discovery = run_suite(
        manifest,
        snapshots_root,
        output_root,
        discovery_run_id,
        workflow,
        profile,
        config,
        execution_policy,
        discovery_executor,
        discovery_kind,
        selected_hunt_evidence_protocol_version,
        account_failure_usage=account_failure_usage,
    )
    discovery_dir = output_root / discovery_run_id
    discovery_records = _validate_phase(
        manifest,
        discovery_dir,
        discovery,
        config,
        account_failure_usage=account_failure_usage,
    )

    candidate_path = output_root / f"{run_id}-candidates.jsonl"
    partial_discovery = _recoverable_partial_phase(
        discovery_records,
        workflow,
        selected_hunt_evidence_protocol_version,
    )
    if discovery.status != "completed" and not partial_discovery:
        _write_jsonl(candidate_path, ())
        receipt = _workflow_receipt(
            run_id, workflow, profile, controls, config, snapshot_hash, len(manifest.tasks), discovery_dir / "receipt.json",
            discovery_dir / "commands.jsonl", candidate_path, None, None, None, discovery.elapsed_seconds, discovery.token_usage,
            hunt_evidence_protocol_version=selected_hunt_evidence_protocol_version,
        )
        aggregate_path = output_root / f"{run_id}-workflow-receipt.json"
        _write_json(aggregate_path, receipt.to_json())
        paths = _artifact_paths(run_id, workflow, verification_started=False, completed=False)
        _write_json(output_root / f"{run_id}-result.json", paths)
        return WorkflowResult(receipt, paths)

    completed_discovery_tasks = tuple(
        task
        for task, record in zip(manifest.tasks, discovery_records, strict=True)
        if record.status == "completed"
    )
    discovery_predictions = _load_phase_predictions(
        manifest,
        discovery_dir / "predictions.jsonl",
        discovery_kind,
        completed_discovery_tasks if partial_discovery else None,
    )
    candidates = _full_manifest_candidates(
        manifest,
        snapshots_root,
        discovery_predictions,
        workflow,
        completed_discovery_tasks if partial_discovery else manifest.tasks,
    )
    _write_jsonl(candidate_path, (_candidate_row(task.task_id, candidates[task.task_id]) for task in manifest.tasks))
    verification_executor = verification_executor_factory(candidates)
    if not callable(verification_executor):
        raise PhaseRunnerError("verification executor factory returned an invalid executor")
    if account_failure_usage:
        verification_executor = _skip_empty_candidate_verification(
            verification_executor,
            candidates,
            workflow,
        )
    verification_run_id = f"{run_id}-verification"
    verification_kind = "hunt-verification" if workflow == "hunt" else "standard"
    verification = run_suite(
        manifest,
        snapshots_root,
        output_root,
        verification_run_id,
        workflow,
        profile,
        config,
        execution_policy,
        verification_executor,
        verification_kind,
        account_failure_usage=account_failure_usage,
    )
    verification_dir = output_root / verification_run_id
    verification_records = _validate_phase(
        manifest,
        verification_dir,
        verification,
        config,
        account_failure_usage=account_failure_usage,
    )
    partial_verification = _recoverable_partial_phase(
        verification_records,
        workflow,
        selected_hunt_evidence_protocol_version,
    )
    if verification.status != "completed" and not partial_verification:
        receipt = _workflow_receipt(
            run_id, workflow, profile, controls, config, snapshot_hash, len(manifest.tasks), discovery_dir / "receipt.json",
            discovery_dir / "commands.jsonl", candidate_path, verification_dir / "receipt.json", verification_dir / "commands.jsonl", None,
            discovery.elapsed_seconds + verification.elapsed_seconds,
            _add_usage(discovery.token_usage, verification.token_usage),
            status="incomplete",
            hunt_evidence_protocol_version=selected_hunt_evidence_protocol_version,
        )
        _write_json(output_root / f"{run_id}-workflow-receipt.json", receipt.to_json())
        paths = _artifact_paths(run_id, workflow, verification_started=True, completed=False)
        _write_json(output_root / f"{run_id}-result.json", paths)
        return WorkflowResult(receipt, paths)
    completed_verification_tasks = tuple(
        task
        for task, record in zip(manifest.tasks, verification_records, strict=True)
        if record.status == "completed"
    )
    raw_verification_predictions = _load_phase_predictions(
        manifest,
        verification_dir / "predictions.jsonl",
        verification_kind,
        completed_verification_tasks if partial_verification else None,
    )
    _validate_verification_subset(candidates, raw_verification_predictions, workflow)
    verification_predictions = _full_manifest_verification_predictions(
        manifest,
        raw_verification_predictions,
        completed_verification_tasks if partial_verification else manifest.tasks,
        workflow,
    )
    public_predictions_path: Path | None = None
    if workflow == "hunt":
        public_predictions_path = output_root / f"{run_id}-public-predictions.jsonl"
        _write_jsonl(
            public_predictions_path,
            (
                _public_hunt_prediction(
                    verification_predictions[task.task_id],
                    task.task_id,
                )
                for task in manifest.tasks
            ),
        )
    receipt = _workflow_receipt(
        run_id, workflow, profile, controls, config, snapshot_hash, len(manifest.tasks), discovery_dir / "receipt.json",
        discovery_dir / "commands.jsonl", candidate_path, verification_dir / "receipt.json", verification_dir / "commands.jsonl", public_predictions_path,
        discovery.elapsed_seconds + verification.elapsed_seconds,
        _add_usage(discovery.token_usage, verification.token_usage),
        hunt_evidence_protocol_version=selected_hunt_evidence_protocol_version,
    )
    aggregate_path = output_root / f"{run_id}-workflow-receipt.json"
    _write_json(aggregate_path, receipt.to_json())
    score_path: str | None = None
    if score_callback is not None:
        score = score_callback(public_predictions_path or verification_dir / "predictions.jsonl")
        if not isinstance(score, Mapping):
            raise PhaseRunnerError("host score callback returned an invalid result")
        score_file = output_root / f"{run_id}-score.json"
        _write_json(score_file, dict(score))
        score_path = score_file.name
    paths = _artifact_paths(run_id, workflow, verification_started=True, completed=True, score_path=score_path, public_predictions_path=public_predictions_path.name if public_predictions_path else None)
    _write_json(output_root / f"{run_id}-result.json", paths)
    return WorkflowResult(receipt, paths)


def run_paired(
    manifest: BenchmarkManifest,
    snapshots_root: Path,
    output_root: Path,
    run_id: str,
    controls: FrozenControls,
    execution_policy: ExecutionPolicy,
    discovery_executors: Mapping[str, Executor],
    verification_executor_factories: Mapping[str, VerificationExecutorFactory],
    profiles: Mapping[str, str],
    score_callbacks: Mapping[str, HostScoreCallback] | None = None,
    *,
    hunt_evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION,
) -> PairedRunResult:
    """Runs the frozen paired order without automatic retries."""
    if set(discovery_executors) != {"standard", "hunt"} or set(verification_executor_factories) != {"standard", "hunt"} or set(profiles) != {"standard", "hunt"}:
        raise PhaseRunnerError("paired execution requires exactly standard and hunt executors")
    _workflow_profile("standard", profiles["standard"])
    _workflow_profile("hunt", profiles["hunt"])
    if score_callbacks is not None and set(score_callbacks) != {"standard", "hunt"}:
        raise PhaseRunnerError("paired scoring requires exactly standard and hunt callbacks")
    schedule = (("standard", "hunt"),) if controls.seed_supported else (("standard", "hunt"), ("hunt", "standard"), ("standard", "hunt"))
    comparisons: list[ComparisonResult] = []
    evidence: list[dict[str, object]] = []
    for repeat, order in enumerate(schedule, start=1):
        results: dict[str, WorkflowResult] = {}
        for workflow in order:
            workflow_options = (
                {"hunt_evidence_protocol_version": hunt_evidence_protocol_version}
                if workflow == "hunt"
                else {}
            )
            results[workflow] = run_workflow(
                manifest, snapshots_root, output_root, f"{run_id}-repeat-{repeat}-{workflow}", workflow, profiles[workflow], controls,
                execution_policy, discovery_executors[workflow], verification_executor_factories[workflow],
                score_callbacks[workflow] if score_callbacks is not None else None,
                **workflow_options,
            )
            validate_workflow_receipt(
                manifest,
                snapshots_root,
                output_root,
                output_root / f"{results[workflow].receipt.run_id}-workflow-receipt.json",
                controls,
                execution_policy,
            )
        comparisons.append(compare_workflows(results["standard"].receipt, results["hunt"].receipt))
        evidence.append(
            {
                "repeat": repeat,
                "standard_artifacts": dict(results["standard"].artifact_paths),
                "hunt_artifacts": dict(results["hunt"].artifact_paths),
            }
        )
    _write_json(output_root / f"{run_id}-comparison.json", {
        "schedule": [list(order) for order in schedule],
        "hunt_evidence_protocol_version": hunt_evidence_protocol_version,
        "comparisons": [{"comparable": item.comparable, "mismatches": list(item.mismatches)} for item in comparisons],
        "evidence": evidence,
    })
    return PairedRunResult(schedule, tuple(comparisons))


def compare_workflows(standard: WorkflowReceipt, hunt: WorkflowReceipt) -> ComparisonResult:
    """Fails closed unless two completed workflow receipts share every control."""
    mismatches: list[str] = []
    if standard.workflow != "standard":
        mismatches.append("standard_workflow")
    if hunt.workflow != "hunt":
        mismatches.append("hunt_workflow")
    for field in (
        "frozen_controls_sha256", "manifest_sha256", "task_order_sha256", "execution_policy_sha256",
        "snapshot_set_sha256", "phase_protocol_version", "top_level_invocation_count",
    ):
        if getattr(standard, field) != getattr(hunt, field):
            mismatches.append(field)
    if standard.status != "completed":
        mismatches.append("standard_status")
    if hunt.status != "completed":
        mismatches.append("hunt_status")
    return ComparisonResult(not mismatches, tuple(sorted(mismatches)))


def load_workflow_receipt(path: Path) -> WorkflowReceipt:
    """Loads one exact aggregate receipt without accepting extra fields."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PhaseRunnerError("workflow receipt is unavailable or invalid") from error
    return WorkflowReceipt.from_json(value)


def validate_workflow_receipt(
    manifest: BenchmarkManifest,
    snapshots_root: Path,
    output_root: Path,
    receipt_path: Path,
    controls: FrozenControls,
    execution_policy: ExecutionPolicy,
) -> WorkflowReceipt:
    """Rehashes phase and candidate artifacts before accepting an aggregate receipt."""
    _safe_output_root(output_root)
    receipt = load_workflow_receipt(receipt_path)
    config = controls.run_config(manifest, execution_policy)
    expected = {
        "frozen_controls_sha256": controls.sha256(),
        "manifest_sha256": config.manifest_sha256,
        "task_order_sha256": config.task_order_sha256,
        "execution_policy_sha256": config.execution_policy_sha256,
        "snapshot_set_sha256": _snapshot_set_sha256(manifest),
    }
    if any(getattr(receipt, key) != value for key, value in expected.items()):
        raise PhaseRunnerError("workflow receipt controls or snapshots do not match")
    expected_invocations = len(manifest.tasks) * (
        2 if receipt.verification_receipt_sha256 is not None else 1
    )
    if receipt.top_level_invocation_count != expected_invocations:
        raise PhaseRunnerError("workflow receipt invocation count does not match phases")
    discovery_dir = output_root / f"{receipt.run_id}-discovery"
    discovery_path = discovery_dir / "receipt.json"
    if sha256_file(discovery_path) != receipt.discovery_receipt_sha256:
        raise PhaseRunnerError("workflow receipt discovery hash does not match")
    discovery_commands_path = discovery_dir / "commands.jsonl"
    if sha256_file(discovery_commands_path) != receipt.discovery_commands_sha256:
        raise PhaseRunnerError("workflow receipt discovery commands hash does not match")
    discovery_predictions_path = discovery_dir / "predictions.jsonl"
    if sha256_file(discovery_predictions_path) != receipt.discovery_predictions_sha256:
        raise PhaseRunnerError("workflow receipt discovery predictions hash does not match")
    discovery = load_receipt(discovery_path)
    account_failure_usage = _uses_recoverable_partial_hunt_protocol(
        receipt.workflow,
        receipt.hunt_evidence_protocol_version,
    )
    discovery_records = _validate_phase(
        manifest,
        discovery_dir,
        discovery,
        config,
        account_failure_usage=account_failure_usage,
    )
    candidate_path = output_root / f"{receipt.run_id}-candidates.jsonl"
    if sha256_file(candidate_path) != receipt.candidate_transfer_sha256:
        raise PhaseRunnerError("workflow receipt candidate hash does not match")
    discovery_kind = "hunt-discovery" if receipt.workflow == "hunt" else "standard"
    completed_discovery_tasks = tuple(
        task for task, record in zip(manifest.tasks, discovery_records, strict=True)
        if record.status == "completed"
    )
    discovery_predictions = _load_phase_predictions(
        manifest, discovery_predictions_path, discovery_kind, completed_discovery_tasks
    )
    if receipt.workflow == "hunt":
        evidence_path = discovery_dir / "evidence.jsonl"
        if not evidence_path.is_file() or receipt.discovery_evidence_sha256 is None or sha256_file(evidence_path) != receipt.discovery_evidence_sha256:
            raise PhaseRunnerError("workflow receipt discovery evidence hash does not match")
        if completed_discovery_tasks:
            evidence_rows = _read_jsonl(evidence_path, "discovery evidence")
        else:
            try:
                evidence_bytes = evidence_path.read_bytes()
            except OSError as error:
                raise PhaseRunnerError("discovery evidence is unavailable") from error
            if evidence_bytes != b"":
                raise PhaseRunnerError("discovery evidence is incomplete")
            evidence_rows = []
        if len(evidence_rows) != len(completed_discovery_tasks):
            raise PhaseRunnerError("discovery evidence is incomplete")
        try:
            evidence_rows = [
                parse_hunt_evidence(
                    row,
                    receipt.profile,
                    evidence_protocol_version=receipt.hunt_evidence_protocol_version,
                )
                for row in evidence_rows
            ]
        except HuntEvidenceError as error:
            raise PhaseRunnerError("discovery evidence is invalid") from error
        expected_evidence = _jsonl_bytes(
            reproduce_hunt_evidence(
                snapshots_root / task.task_id,
                receipt.profile,
                parse_hunt_discovery_prediction(discovery_predictions[task.task_id], task.task_id),
                evidence_protocol_version=receipt.hunt_evidence_protocol_version,
            ).to_json()
            for task in completed_discovery_tasks
        )
        if evidence_path.read_bytes() != expected_evidence:
            raise PhaseRunnerError("workflow receipt discovery evidence does not reproduce")
    _validate_phase_commands(manifest, discovery_commands_path, execution_policy)
    partial_discovery = _recoverable_partial_phase(
        discovery_records,
        receipt.workflow,
        receipt.hunt_evidence_protocol_version,
    )
    if discovery.status != "completed" and not partial_discovery:
        verification_dir = output_root / f"{receipt.run_id}-verification"
        public_predictions_path = output_root / f"{receipt.run_id}-public-predictions.jsonl"
        if receipt.status != "incomplete":
            raise PhaseRunnerError("failed discovery workflow receipt must be incomplete")
        if (
            receipt.verification_receipt_sha256 is not None
            or receipt.verification_commands_sha256 is not None
            or receipt.verification_predictions_sha256 is not None
            or receipt.public_predictions_sha256 is not None
            or verification_dir.exists()
            or public_predictions_path.exists()
        ):
            raise PhaseRunnerError("failed discovery workflow receipt has unexpected verification artifacts")
        if candidate_path.read_bytes() != b"":
            raise PhaseRunnerError("failed discovery workflow candidate transfer must be empty")
        _validate_workflow_aggregate(receipt, discovery)
        return receipt
    candidates = _full_manifest_candidates(
        manifest,
        snapshots_root,
        discovery_predictions,
        receipt.workflow,
        completed_discovery_tasks if partial_discovery else manifest.tasks,
    )
    expected_candidate_bytes = _jsonl_bytes(
        _candidate_row(task.task_id, candidates[task.task_id]) for task in manifest.tasks
    )
    actual_candidate_bytes = candidate_path.read_bytes()
    if actual_candidate_bytes != expected_candidate_bytes:
        raise PhaseRunnerError("workflow receipt candidate transfer does not match discovery")
    if receipt.verification_receipt_sha256 is not None:
        verification_dir = output_root / f"{receipt.run_id}-verification"
        verification_path = verification_dir / "receipt.json"
        if sha256_file(verification_path) != receipt.verification_receipt_sha256:
            raise PhaseRunnerError("workflow receipt verification hash does not match")
        verification_commands_path = verification_dir / "commands.jsonl"
        if receipt.verification_commands_sha256 is None or sha256_file(verification_commands_path) != receipt.verification_commands_sha256:
            raise PhaseRunnerError("workflow receipt verification commands hash does not match")
        verification_predictions_path = verification_dir / "predictions.jsonl"
        if receipt.verification_predictions_sha256 is None or sha256_file(verification_predictions_path) != receipt.verification_predictions_sha256:
            raise PhaseRunnerError("workflow receipt verification predictions hash does not match")
        public_predictions_path = output_root / f"{receipt.run_id}-public-predictions.jsonl"
        if receipt.workflow == "hunt" and receipt.status == "completed":
            if receipt.public_predictions_sha256 is None or sha256_file(public_predictions_path) != receipt.public_predictions_sha256:
                raise PhaseRunnerError("workflow receipt public predictions hash does not match")
        elif receipt.public_predictions_sha256 is not None or public_predictions_path.exists():
            raise PhaseRunnerError("workflow receipt has unexpected public predictions")
        verification = load_receipt(verification_path)
        verification_records = _validate_phase(
            manifest,
            verification_dir,
            verification,
            config,
            account_failure_usage=account_failure_usage,
        )
        _validate_workflow_aggregate(receipt, discovery, verification)
        _validate_phase_commands(manifest, verification_commands_path, execution_policy)
        partial_verification = _recoverable_partial_phase(
            verification_records,
            receipt.workflow,
            receipt.hunt_evidence_protocol_version,
        )
        if receipt.status == "completed":
            if (
                discovery.status != "completed" and not partial_discovery
            ) or (
                verification.status != "completed" and not partial_verification
            ):
                raise PhaseRunnerError("completed workflow receipt has an incomplete phase")
            verification_kind = "hunt-verification" if receipt.workflow == "hunt" else "standard"
            completed_verification_tasks = tuple(
                task
                for task, record in zip(manifest.tasks, verification_records, strict=True)
                if record.status == "completed"
            )
            raw_verification_predictions = _load_phase_predictions(
                manifest,
                verification_predictions_path,
                verification_kind,
                completed_verification_tasks if partial_verification else None,
            )
            _validate_verification_subset(
                candidates,
                raw_verification_predictions,
                receipt.workflow,
            )
            verification_predictions = _full_manifest_verification_predictions(
                manifest,
                raw_verification_predictions,
                completed_verification_tasks if partial_verification else manifest.tasks,
                receipt.workflow,
            )
            if receipt.workflow == "hunt" and receipt.status == "completed":
                expected_public = _jsonl_bytes(
                    _public_hunt_prediction(
                        verification_predictions[task.task_id],
                        task.task_id,
                    )
                    for task in manifest.tasks
                )
                if public_predictions_path.read_bytes() != expected_public:
                    raise PhaseRunnerError("workflow receipt public predictions do not match verification")
        elif (
            discovery.status != "completed" and not partial_discovery
        ) or verification.status == "completed":
            raise PhaseRunnerError("incomplete workflow receipt phase status is invalid")
    elif receipt.verification_receipt_sha256 is None and (
        discovery.status == "completed" or partial_discovery
    ):
        raise PhaseRunnerError("incomplete workflow receipt omitted a required phase")
    return receipt


def _validate_workflow_aggregate(
    receipt: WorkflowReceipt,
    discovery: RunReceipt,
    verification: RunReceipt | None = None,
) -> None:
    expected_usage = discovery.token_usage
    expected_elapsed = discovery.elapsed_seconds
    if verification is not None:
        expected_usage = _add_usage(expected_usage, verification.token_usage)
        expected_elapsed += verification.elapsed_seconds
    if (
        receipt.token_usage != expected_usage
        or receipt.elapsed_seconds != expected_elapsed
    ):
        raise PhaseRunnerError("workflow receipt aggregate does not match phase receipts")


def _workflow_receipt(
    run_id: str, workflow: str, profile: str, controls: FrozenControls, config: RunConfig, snapshot_hash: str,
    task_count: int, discovery_path: Path, discovery_commands_path: Path, candidate_path: Path,
    verification_path: Path | None, verification_commands_path: Path | None, public_predictions_path: Path | None, elapsed: float, usage: TokenUsage,
    status: str | None = None,
    hunt_evidence_protocol_version: int | None = None,
) -> WorkflowReceipt:
    return WorkflowReceipt(
        schema_version=HUNT_WORKFLOW_RECEIPT_SCHEMA_VERSION if workflow == "hunt" else STANDARD_WORKFLOW_RECEIPT_SCHEMA_VERSION, run_id=run_id, workflow=workflow, profile=profile,
        frozen_controls_sha256=controls.sha256(), manifest_sha256=config.manifest_sha256,
        task_order_sha256=config.task_order_sha256, execution_policy_sha256=config.execution_policy_sha256,
        snapshot_set_sha256=snapshot_hash, discovery_receipt_sha256=sha256_file(discovery_path),
        discovery_commands_sha256=sha256_file(discovery_commands_path),
        discovery_predictions_sha256=sha256_file(discovery_path.parent / "predictions.jsonl"),
        candidate_transfer_sha256=sha256_file(candidate_path),
        verification_receipt_sha256=sha256_file(verification_path) if verification_path else None,
        verification_commands_sha256=sha256_file(verification_commands_path) if verification_commands_path else None,
        verification_predictions_sha256=sha256_file(verification_path.parent / "predictions.jsonl") if verification_path else None,
        public_predictions_sha256=sha256_file(public_predictions_path) if public_predictions_path else None,
        discovery_evidence_sha256=sha256_file(discovery_path.parent / "evidence.jsonl") if workflow == "hunt" else None,
        hunt_evidence_protocol_version=hunt_evidence_protocol_version if workflow == "hunt" else None,
        phase_protocol_version=controls.phase_protocol_version,
        top_level_invocation_count=task_count * (2 if verification_path else 1),
        status=status or ("completed" if verification_path else "incomplete"), elapsed_seconds=elapsed, token_usage=usage,
    )


def _validate_phase(
    manifest: BenchmarkManifest,
    directory: Path,
    receipt: RunReceipt,
    config: RunConfig,
    *,
    account_failure_usage: bool = False,
) -> tuple[TaskRunReceipt, ...]:
    stored = load_receipt(directory / "receipt.json")
    if stored != receipt or stored.config != config:
        raise PhaseRunnerError("phase receipt does not match committed receipt bytes")
    rows = _read_jsonl(directory / "task-receipts.jsonl", "task receipts")
    if len(rows) != len(manifest.tasks):
        raise PhaseRunnerError("phase task receipt count is incomplete")
    records: list[TaskRunReceipt] = []
    for task, row in zip(manifest.tasks, rows, strict=True):
        task_receipt = TaskRunReceipt.from_json(row)
        if task_receipt.task_id != task.task_id:
            raise PhaseRunnerError("phase task receipts do not preserve manifest order")
        if task_receipt.status == "completed" and (
            task_receipt.pre_snapshot_sha256 != task.snapshot_sha256
            or task_receipt.post_snapshot_sha256 != task.snapshot_sha256
        ):
            raise PhaseRunnerError("phase task receipt snapshot binding is invalid")
        records.append(task_receipt)
    expected_status = _aggregate_task_status(record.status for record in records)
    accounted_records = records if account_failure_usage else tuple(
        record for record in records if record.status == "completed"
    )
    expected_usage = TokenUsage(
        sum(record.token_usage.cached_input_tokens for record in accounted_records),
        sum(record.token_usage.uncached_input_tokens for record in accounted_records),
        sum(record.token_usage.output_tokens for record in accounted_records),
    )
    if (
        receipt.status != expected_status
        or receipt.token_usage != expected_usage
        or receipt.elapsed_seconds != sum(record.elapsed_seconds for record in records)
    ):
        raise PhaseRunnerError("phase receipt does not match committed task evidence")
    try:
        actual_failure_evidence_sha256 = failure_evidence_sha256(directory / "tasks", records)
    except RunnerError as error:
        raise PhaseRunnerError("phase failure evidence is invalid") from error
    if receipt.failure_evidence_sha256 != actual_failure_evidence_sha256:
        raise PhaseRunnerError("phase failure evidence hash does not match")
    return tuple(records)


def _load_phase_predictions(
    manifest: BenchmarkManifest,
    path: Path,
    response_kind: str = "standard",
    tasks: Sequence[TaskDescriptor] | None = None,
) -> dict[str, object]:
    expected_tasks = tuple(manifest.tasks if tasks is None else tasks)
    if not expected_tasks:
        try:
            value = path.read_bytes()
        except OSError as error:
            raise PhaseRunnerError("phase predictions are unavailable") from error
        if value != b"":
            raise PhaseRunnerError("phase predictions are incomplete")
        rows: list[dict[str, object]] = []
    else:
        rows = _read_jsonl(path, "phase predictions")
    if len(rows) != len(expected_tasks):
        raise PhaseRunnerError("phase predictions are incomplete")
    loaded: dict[str, object] = {}
    for task, row in zip(expected_tasks, rows, strict=True):
        if response_kind == "hunt-discovery":
            prediction = parse_hunt_discovery_prediction(row, task.task_id)
        elif response_kind == "hunt-verification":
            prediction = parse_hunt_verification_prediction(row, task.task_id)
        else:
            prediction = _prediction_for_task(row, task.task_id)
        if prediction.task_id in loaded:
            raise PhaseRunnerError("phase predictions contain duplicate task IDs")
        loaded[prediction.task_id] = row
    if set(loaded) != {task.task_id for task in expected_tasks}:
        raise PhaseRunnerError("phase predictions do not match manifest tasks")
    return loaded


def _validate_verification_subset(
    candidates: Mapping[str, tuple[CanonicalCandidate, ...]], predictions: Mapping[str, object], workflow: str = "standard"
) -> None:
    for task_id, raw_prediction in predictions.items():
        if workflow == "hunt":
            try:
                hunt_prediction = parse_hunt_verification_prediction(raw_prediction, task_id)
            except HuntProtocolError as error:
                raise PhaseRunnerError("Hunt verification prediction is invalid") from error
            _validate_hunt_decisions(candidates[task_id], hunt_prediction.decisions, hunt_prediction.findings)
            continue
        prediction = _prediction_for_task(raw_prediction, task_id)
        allowed = {candidate.candidate_id: candidate for candidate in candidates[task_id]}
        seen: set[str] = set()
        for finding in prediction.findings:
            candidate = allowed.get(finding.finding_id)
            if candidate is None or finding.finding_id in seen:
                raise PhaseRunnerError("verification finding is not a unique transferred candidate")
            seen.add(finding.finding_id)
            if (finding.entry_point, finding.critical_operation, finding.trace) != (candidate.entry_point, candidate.critical_operation, candidate.trace):
                raise PhaseRunnerError("verification finding changed a transferred candidate")


def _validate_hunt_decisions(
    candidates: Sequence[CanonicalCandidate], decisions: Sequence[HuntTerminalDecision], findings: Sequence[Finding]
) -> None:
    allowed = {candidate.candidate_id: candidate for candidate in candidates}
    if set(decision.candidate_id for decision in decisions) != set(allowed) or len(decisions) != len(allowed):
        raise PhaseRunnerError("Hunt verification must contain one terminal decision per transferred candidate")
    accepted = {decision.candidate_id for decision in decisions if decision.disposition == "accepted"}
    if len(accepted) > 5:
        raise PhaseRunnerError("Hunt verification accepted findings exceed the final limit")
    finding_ids = {finding.finding_id for finding in findings}
    if finding_ids != accepted or len(findings) != len(accepted):
        raise PhaseRunnerError("Hunt verification findings do not exactly match accepted decisions")
    for finding in findings:
        candidate = allowed.get(finding.finding_id)
        if candidate is None or (finding.entry_point, finding.critical_operation, finding.trace) != (candidate.entry_point, candidate.critical_operation, candidate.trace):
            raise PhaseRunnerError("verification finding changed a transferred candidate")
        if finding.confidence != next(decision.confidence for decision in decisions if decision.candidate_id == finding.finding_id):
            raise PhaseRunnerError("verification finding confidence changed a terminal decision")


def _canonical_candidate(finding: Finding, number: int, snapshot: Path) -> CanonicalCandidate:
    locations = (finding.entry_point, finding.critical_operation, *finding.trace)
    if len(finding.trace) > _MAX_CANDIDATE_TRACE:
        raise PhaseRunnerError("candidate trace exceeds the bounded length")
    for location in locations:
        _validate_candidate_location(location, snapshot)
    return CanonicalCandidate(
        candidate_id=f"candidate-{number}", entry_point=finding.entry_point,
        critical_operation=finding.critical_operation, trace=finding.trace, confidence=finding.confidence,
    )


def _canonical_hunt_candidate(
    candidate: HuntDiscoveryCandidate, number: int, snapshot: Path
) -> CanonicalCandidate:
    locations = (candidate.entry_point, candidate.critical_operation, *candidate.trace)
    if len(candidate.trace) > _MAX_CANDIDATE_TRACE:
        raise PhaseRunnerError("candidate trace exceeds the bounded length")
    for location in locations:
        _validate_candidate_location(location, snapshot)
    return CanonicalCandidate(
        candidate_id=f"candidate-{number}",
        entry_point=candidate.entry_point,
        critical_operation=candidate.critical_operation,
        trace=candidate.trace,
        confidence=candidate.confidence,
        vulnerability_family=candidate.vulnerability_family,
        search_pass=candidate.search_pass,
        hypothesis=candidate.hypothesis,
        evidence=candidate.evidence,
        counterevidence=candidate.counterevidence,
        expected_control=candidate.expected_control,
    )


def _validate_candidate_location(location: Location, snapshot: Path) -> None:
    path = location.path
    if not isinstance(path, str) or not path or len(path.encode("utf-8")) > _MAX_CANDIDATE_PATH_BYTES:
        raise PhaseRunnerError("candidate path is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in path) or "\\" in path:
        raise PhaseRunnerError("candidate path is invalid")
    pure = PurePosixPath(path)
    windows = PureWindowsPath(path)
    raw_parts = path.split("/")
    if pure.is_absolute() or windows.is_absolute() or windows.drive or any(part in {"", ".", ".."} for part in raw_parts):
        raise PhaseRunnerError("candidate path is invalid")
    current = snapshot
    for part in pure.parts:
        names = _exact_directory_entries(current)
        if part not in names:
            raise PhaseRunnerError("candidate path is missing or has alternate casing")
        current = current / part
        if _is_link_or_reparse(current):
            raise PhaseRunnerError("candidate path must not cross a link or reparse point")
    if not current.is_file() or _is_link_or_reparse(current):
        raise PhaseRunnerError("candidate path must name a regular file")
    try:
        line_count = len(current.read_bytes().splitlines())
    except OSError as error:
        raise PhaseRunnerError("candidate source cannot be read") from error
    if location.end_line > line_count:
        raise PhaseRunnerError("candidate location exceeds the source file")


def _validate_raw_candidate_paths(raw_findings: object) -> None:
    if not isinstance(raw_findings, list):
        return
    for finding in raw_findings:
        if not isinstance(finding, dict):
            continue
        raw_locations = [finding.get("entry_point"), finding.get("critical_operation")]
        trace = finding.get("trace")
        if isinstance(trace, list):
            raw_locations.extend(trace)
        for location in raw_locations:
            if not isinstance(location, dict):
                continue
            path = location.get("file")
            if not isinstance(path, str) or not path or "\\" in path:
                raise PhaseRunnerError("candidate path is invalid")
            if any(ord(character) < 32 or ord(character) == 127 for character in path):
                raise PhaseRunnerError("candidate path is invalid")
            pure = PurePosixPath(path)
            windows = PureWindowsPath(path)
            parts = path.split("/")
            if pure.is_absolute() or windows.is_absolute() or windows.drive or any(part in {"", ".", ".."} for part in parts):
                raise PhaseRunnerError("candidate path is invalid")


def _exact_directory_entries(directory: Path) -> set[str]:
    try:
        with os.scandir(directory) as entries:
            return {entry.name for entry in entries}
    except OSError as error:
        raise PhaseRunnerError("candidate path cannot be inspected") from error


def _snapshot_root(snapshots_root: Path, task_id: str) -> Path:
    root = snapshots_root.resolve(strict=True)
    candidate = root.joinpath(*PurePosixPath(task_id).parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise PhaseRunnerError("candidate snapshot is unavailable") from error
    if not resolved.is_dir() or root not in resolved.parents:
        raise PhaseRunnerError("candidate snapshot is outside snapshots root")
    if _is_link_or_reparse(resolved):
        raise PhaseRunnerError("candidate snapshot must not be a link or reparse point")
    return resolved


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise PhaseRunnerError("candidate path cannot be inspected") from error
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", None)
    if attributes is None:
        if os.name == "nt":
            raise PhaseRunnerError("candidate path attributes are unavailable")
        return False
    return bool(int(attributes) & _REPARSE_POINT)


def _prediction_for_task(value: object, task_id: str) -> TaskPrediction:
    try:
        prediction = parse_prediction(value)
    except Exception as error:
        raise PhaseRunnerError("candidate prediction is invalid") from error
    if prediction.task_id != task_id:
        raise PhaseRunnerError("phase prediction task_id does not match manifest")
    return prediction


def _candidate_row(task_id: str, candidates: Sequence[CanonicalCandidate]) -> dict[str, object]:
    return {"schema_version": 1, "task_id": task_id, "candidates": [candidate.to_json() for candidate in candidates]}


def _artifact_paths(
    run_id: str, workflow: str, verification_started: bool, completed: bool, score_path: str | None = None,
    public_predictions_path: str | None = None,
) -> dict[str, object]:
    paths: dict[str, object] = {
        "discovery_predictions": f"{run_id}-discovery/predictions.jsonl",
        "discovery_task_receipts": f"{run_id}-discovery/task-receipts.jsonl",
        "discovery_commands": f"{run_id}-discovery/commands.jsonl",
        "discovery_receipt": f"{run_id}-discovery/receipt.json",
        "candidate_transfer": f"{run_id}-candidates.jsonl",
        "aggregate_receipt": f"{run_id}-workflow-receipt.json",
    }
    if workflow == "hunt":
        paths["discovery_evidence"] = f"{run_id}-discovery/evidence.jsonl"
    if verification_started:
        paths |= {
            "verification_predictions": f"{run_id}-verification/predictions.jsonl",
            "verification_task_receipts": f"{run_id}-verification/task-receipts.jsonl",
            "verification_commands": f"{run_id}-verification/commands.jsonl",
            "verification_receipt": f"{run_id}-verification/receipt.json",
        }
    if completed:
        paths["final_predictions"] = public_predictions_path or f"{run_id}-verification/predictions.jsonl"
    if score_path is not None:
        paths["score"] = score_path
    return paths


def _public_hunt_prediction(value: object, task_id: str) -> dict[str, object]:
    try:
        prediction = parse_hunt_verification_prediction(value, task_id)
    except HuntProtocolError as error:
        raise PhaseRunnerError("Hunt verification prediction is invalid") from error
    return {
        "schema_version": 1,
        "task_id": prediction.task_id,
        "findings": [
            {"finding_id": finding.finding_id, "entry_point": _location_json(finding.entry_point), "critical_operation": _location_json(finding.critical_operation), "trace": [_location_json(location) for location in finding.trace], "confidence": finding.confidence}
            for finding in prediction.findings
        ],
    }


def _snapshot_set_sha256(manifest: BenchmarkManifest) -> str:
    return _canonical_sha256([[task.task_id, task.snapshot_sha256] for task in manifest.tasks])


def _read_jsonl(path: Path, name: str) -> list[object]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise PhaseRunnerError(f"{name} are unavailable") from error
    if not lines or any(not line for line in lines):
        raise PhaseRunnerError(f"{name} are incomplete")
    rows: list[object] = []
    for line in lines:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise PhaseRunnerError(f"{name} contain invalid JSON") from error
    return rows


def _validate_phase_commands(
    manifest: BenchmarkManifest, path: Path, policy: ExecutionPolicy
) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise PhaseRunnerError("phase commands are unavailable") from error
    by_task = {task.task_id: task for task in manifest.tasks}
    order = {task.task_id: index for index, task in enumerate(manifest.tasks)}
    previous_index = -1
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise PhaseRunnerError("phase commands contain invalid JSON") from error
        if not isinstance(row, dict) or set(row) != {"task_id", "argv"}:
            raise PhaseRunnerError("phase commands have an invalid shape")
        task_id = row["task_id"]
        argv = row["argv"]
        if not isinstance(task_id, str) or task_id not in by_task or not isinstance(argv, list) or not argv:
            raise PhaseRunnerError("phase commands have an invalid task or argv")
        if any(not isinstance(token, str) or _PUBLIC_COMMAND_TOKEN.fullmatch(token) is None for token in argv):
            raise PhaseRunnerError("phase commands contain unsafe public tokens")
        current_index = order[task_id]
        if current_index < previous_index:
            raise PhaseRunnerError("phase commands do not preserve manifest order")
        previous_index = current_index
        command = tuple(argv)
        allowed = (*policy.allowed_command_prefixes, *by_task[task_id].allowed_commands)
        if not any(command[: len(prefix)] == prefix for prefix in allowed):
            raise PhaseRunnerError("phase commands violate the frozen policy")


def _safe_output_root(path: Path) -> None:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise PhaseRunnerError("output root is unavailable") from error
    if not resolved.is_dir() or _is_link_or_reparse(resolved):
        raise PhaseRunnerError("output root is unsafe")


def _write_json(path: Path, value: object) -> None:
    _write_new(path, json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n")


def _write_jsonl(path: Path, rows: Sequence[object] | object) -> None:
    _write_new(path, _jsonl_bytes(rows).decode("utf-8"))


def _jsonl_bytes(rows: object) -> bytes:
    return "".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows
    ).encode("utf-8")


def _write_new(path: Path, text: str) -> None:
    if path.exists() or _is_link_or_reparse(path.parent):
        raise PhaseRunnerError("artifact output already exists or is unsafe")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise PhaseRunnerError("artifact output cannot be created") from error
    try:
        encoded = text.encode("utf-8")
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
    finally:
        os.close(descriptor)


def _workflow_profile(workflow: object, profile: object) -> None:
    if workflow == "standard" and profile == "baseline":
        return
    if workflow == "hunt" and profile in {"hunt-balanced", "hunt-max"}:
        return
    raise PhaseRunnerError("workflow and profile are unsupported")


def _location_json(location: Location) -> dict[str, object]:
    line: int | str = location.start_line
    if location.start_line != location.end_line:
        line = f"{location.start_line}-{location.end_line}"
    return {"file": location.path, "line": line}


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _add_usage(left: TokenUsage, right: TokenUsage) -> TokenUsage:
    return TokenUsage(left.cached_input_tokens + right.cached_input_tokens, left.uncached_input_tokens + right.uncached_input_tokens, left.output_tokens + right.output_tokens)


def _aggregate_task_status(statuses: object) -> str:
    values = tuple(statuses)
    for status in ("contaminated", "timeout", "failed", "completed"):
        if status in values:
            return status
    raise PhaseRunnerError("phase task receipts are empty")


def _object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise PhaseRunnerError(f"{name} must be an object")
    return value


def _exact_fields(value: dict[str, object], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise PhaseRunnerError(f"{name} must contain exactly the required fields")


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise PhaseRunnerError(f"{name} must be a non-empty string")
    return value


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PhaseRunnerError(f"{name} must be a positive integer")
    return value


def _sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise PhaseRunnerError(f"{name} must be a lowercase SHA-256 digest")
    return value
