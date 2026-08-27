# Runs HermesBench tasks against audited, immutable snapshot directories.

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .adapter_contract import AdapterTaskRequest, parse_adapter_response
from .contracts import BenchmarkManifest, TaskDescriptor
from .receipts import RECEIPT_SCHEMA_VERSION, RunConfig, RunReceipt, TaskRunReceipt, TokenUsage, write_receipt
from .sanitize import BundleAuditError, audit_bundle, tree_sha256


_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ZERO_USAGE = TokenUsage(0, 0, 0)


class RunnerError(ValueError):
    """Signals a runner boundary failure before task execution begins."""


class ExecutorTimeoutError(TimeoutError):
    """Signals that the executor terminated its exact task for timeout."""


@dataclass(frozen=True)
class ExecutionPolicy:
    allowed_command_prefixes: tuple[tuple[str, ...], ...]

    def __post_init__(self) -> None:
        if not self.allowed_command_prefixes:
            raise ValueError("allowed_command_prefixes must not be empty")
        for prefix in self.allowed_command_prefixes:
            if not prefix or any(not isinstance(token, str) or not token for token in prefix):
                raise ValueError("each allowed command prefix must contain non-empty strings")

    def to_json(self) -> dict[str, object]:
        return {"allowed_command_prefixes": [list(prefix) for prefix in self.allowed_command_prefixes]}


@dataclass(frozen=True)
class ExecutorResult:
    raw_response: object
    event_rows: tuple[dict[str, object], ...]
    observed_argv: tuple[tuple[str, ...], ...]


Executor = Callable[[AdapterTaskRequest, Path, int], ExecutorResult]


@dataclass(frozen=True)
class _PreflightTask:
    descriptor: TaskDescriptor
    snapshot_path: Path
    snapshot_sha256: str


def run_suite(
    manifest: BenchmarkManifest,
    snapshots_root: Path,
    output_root: Path,
    run_id: str,
    workflow: str,
    profile: str,
    config: RunConfig,
    execution_policy: ExecutionPolicy,
    executor: Executor,
) -> RunReceipt:
    """Runs one manifest in order after completing every snapshot preflight."""
    _require_safe_run_id(run_id)
    _require_non_empty_text(workflow, "workflow")
    _require_non_empty_text(profile, "profile")
    if not isinstance(config, RunConfig):
        raise RunnerError("config must be a RunConfig")
    if not isinstance(execution_policy, ExecutionPolicy):
        raise RunnerError("execution_policy must be an ExecutionPolicy")
    if config.execution_policy_sha256 != execution_policy_sha256(execution_policy):
        raise RunnerError("execution policy hash does not match RunConfig")
    if config.manifest_sha256 != manifest_sha256(manifest):
        raise RunnerError("manifest hash does not match RunConfig")
    if config.task_order_sha256 != task_order_sha256(manifest):
        raise RunnerError("task order hash does not match RunConfig")

    resolved_output = _resolve_existing_directory(output_root, "output root")
    if _is_link_or_junction(output_root):
        raise RunnerError(f"output root must not be a link or junction: {output_root}")
    resolved_snapshots = _resolve_existing_directory(snapshots_root, "snapshots root")
    if _paths_overlap(resolved_output, resolved_snapshots):
        raise RunnerError("output root and snapshots root must not overlap")

    preflight = _preflight_manifest(manifest, resolved_snapshots, resolved_output)
    run_directory = resolved_output / run_id
    if run_directory.exists() or run_directory.is_symlink():
        raise RunnerError(f"run directory already exists: {run_directory}")
    run_directory.mkdir()
    tasks_directory = run_directory / "tasks"
    tasks_directory.mkdir()

    records: list[TaskRunReceipt] = []
    predictions: list[dict[str, object]] = []
    total_usage = _ZERO_USAGE
    for prepared in preflight:
        record, prediction = _run_task(
            prepared,
            tasks_directory,
            execution_policy,
            executor,
        )
        records.append(record)
        if prediction is not None:
            predictions.append(prediction)
            total_usage = _add_usage(total_usage, record.token_usage)

    _write_jsonl(run_directory / "predictions.jsonl", predictions)
    _write_jsonl(run_directory / "task-receipts.jsonl", (record.to_json() for record in records))
    receipt = RunReceipt(
        schema_version=RECEIPT_SCHEMA_VERSION,
        run_id=run_id,
        workflow=workflow,
        profile=profile,
        config=config,
        elapsed_seconds=sum(record.elapsed_seconds for record in records),
        status=_aggregate_status(record.status for record in records),
        token_usage=total_usage,
    )
    write_receipt(run_directory / "receipt.json", receipt)
    return receipt


def execution_policy_sha256(policy: ExecutionPolicy) -> str:
    """Returns the SHA-256 of the frozen canonical execution policy JSON."""
    if not isinstance(policy, ExecutionPolicy):
        raise ValueError("policy must be an ExecutionPolicy")
    return _canonical_sha256(policy.to_json())


def manifest_sha256(manifest: BenchmarkManifest) -> str:
    """Returns the SHA-256 of the canonical public manifest representation."""
    if not isinstance(manifest, BenchmarkManifest):
        raise ValueError("manifest must be a BenchmarkManifest")
    return _canonical_sha256(
        {
            "schema_version": manifest.schema_version,
            "suite": manifest.suite,
            "manifest_id": manifest.manifest_id,
            "tasks": [
                {
                    "task_id": task.task_id,
                    "snapshot_sha256": task.snapshot_sha256,
                    "language": task.language,
                    "allowed_commands": [list(command) for command in task.allowed_commands],
                    "time_limit_seconds": task.time_limit_seconds,
                }
                for task in manifest.tasks
            ],
        }
    )


def task_order_sha256(manifest: BenchmarkManifest) -> str:
    """Returns the SHA-256 of the manifest's ordered public task IDs."""
    if not isinstance(manifest, BenchmarkManifest):
        raise ValueError("manifest must be a BenchmarkManifest")
    return _canonical_sha256([task.task_id for task in manifest.tasks])


def _preflight_manifest(
    manifest: BenchmarkManifest, snapshots_root: Path, output_root: Path
) -> tuple[_PreflightTask, ...]:
    prepared: list[_PreflightTask] = []
    for descriptor in manifest.tasks:
        snapshot = _resolve_snapshot(snapshots_root, descriptor.task_id)
        if _paths_overlap(snapshot, output_root):
            raise RunnerError(f"snapshot and output root overlap for task {descriptor.task_id}")
        actual_sha256 = _audit_and_hash(snapshot, descriptor.task_id)
        if actual_sha256 != descriptor.snapshot_sha256:
            raise RunnerError(f"snapshot hash mismatch for task {descriptor.task_id}")
        prepared.append(_PreflightTask(descriptor, snapshot, actual_sha256))
    return tuple(prepared)


def _run_task(
    prepared: _PreflightTask,
    tasks_directory: Path,
    policy: ExecutionPolicy,
    executor: Executor,
) -> tuple[TaskRunReceipt, dict[str, object] | None]:
    descriptor = prepared.descriptor
    task_directory = tasks_directory / _task_directory_name(descriptor.task_id)
    task_directory.mkdir()
    request = AdapterTaskRequest(
        task_id=descriptor.task_id,
        snapshot_path=str(prepared.snapshot_path),
        language=descriptor.language,
        allowed_commands=descriptor.allowed_commands,
        time_limit_seconds=descriptor.time_limit_seconds,
    )
    _write_json(task_directory / "request.json", request.to_json())
    started = time.monotonic()
    pre_sha256 = prepared.snapshot_sha256
    usage = _ZERO_USAGE
    status = "failed"
    prediction: dict[str, object] | None = None
    try:
        pre_sha256 = _audit_and_hash(prepared.snapshot_path, descriptor.task_id)
    except RunnerError:
        status = "contaminated"
    else:
        if pre_sha256 != prepared.snapshot_sha256:
            status = "contaminated"
        else:
            try:
                result = executor(request, task_directory, descriptor.time_limit_seconds)
                _write_json(task_directory / "adapter-response.json", result.raw_response)
                _write_jsonl(task_directory / "events.jsonl", result.event_rows)
                parsed = parse_adapter_response(result.raw_response, descriptor.task_id)
                usage = parsed.token_usage
                try:
                    post_sha256 = _audit_and_hash(prepared.snapshot_path, descriptor.task_id)
                except RunnerError:
                    status = "contaminated"
                else:
                    if post_sha256 != pre_sha256 or not _commands_allowed(result.observed_argv, descriptor, policy):
                        status = "contaminated"
                    else:
                        status = "completed"
                        prediction = _prediction_json(parsed.prediction)
            except ExecutorTimeoutError:
                status = "timeout"
            except Exception:
                status = "failed"
    elapsed = time.monotonic() - started
    post_sha256 = _post_snapshot_sha256(prepared.snapshot_path, pre_sha256)
    return (
        TaskRunReceipt(
            schema_version=RECEIPT_SCHEMA_VERSION,
            task_id=descriptor.task_id,
            status=status,  # type: ignore[arg-type]
            pre_snapshot_sha256=pre_sha256,
            post_snapshot_sha256=post_sha256,
            elapsed_seconds=elapsed,
            token_usage=usage,
        ),
        prediction,
    )


def _prediction_json(prediction: object) -> dict[str, object]:
    return {
        "schema_version": 1,
        "task_id": prediction.task_id,
        "findings": [
            {
                "finding_id": finding.finding_id,
                "entry_point": _location_json(finding.entry_point),
                "critical_operation": _location_json(finding.critical_operation),
                "trace": [_location_json(location) for location in finding.trace],
                "confidence": finding.confidence,
            }
            for finding in prediction.findings
        ],
    }


def _location_json(location: object) -> dict[str, object]:
    line: object = location.start_line
    if location.start_line != location.end_line:
        line = f"{location.start_line}-{location.end_line}"
    return {"file": location.path, "line": line}


def _commands_allowed(
    observed: tuple[tuple[str, ...], ...],
    descriptor: TaskDescriptor,
    policy: ExecutionPolicy,
) -> bool:
    allowed = (*policy.allowed_command_prefixes, *descriptor.allowed_commands)
    for argv in observed:
        if not argv or any(not isinstance(token, str) or not token for token in argv):
            return False
        if not any(argv[: len(prefix)] == prefix for prefix in allowed):
            return False
    return True


def _post_snapshot_sha256(snapshot: Path, fallback: str) -> str:
    try:
        return tree_sha256(snapshot)
    except BundleAuditError:
        return fallback


def _audit_and_hash(snapshot: Path, task_id: str) -> str:
    try:
        violations = audit_bundle(snapshot)
        if violations:
            raise RunnerError(f"snapshot is contaminated for task {task_id}")
        return tree_sha256(snapshot)
    except BundleAuditError as error:
        raise RunnerError(f"snapshot is missing or unsafe for task {task_id}") from error


def _resolve_snapshot(snapshots_root: Path, task_id: str) -> Path:
    candidate = snapshots_root / task_id
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RunnerError(f"snapshot is missing for task {task_id}") from error
    if not resolved.is_dir() or not _is_within(resolved, snapshots_root):
        raise RunnerError(f"snapshot is missing or outside snapshots root for task {task_id}")
    return resolved


def _resolve_existing_directory(path: Path, name: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RunnerError(f"{name} must be an existing directory: {path}") from error
    if not resolved.is_dir():
        raise RunnerError(f"{name} must be an existing directory: {path}")
    return resolved


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction()) if callable(is_junction) else False


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _paths_overlap(left: Path, right: Path) -> bool:
    return _is_within(left, right) or _is_within(right, left)


def _task_directory_name(task_id: str) -> str:
    return hashlib.sha256(task_id.encode("utf-8", errors="surrogatepass")).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def _write_jsonl(path: Path, rows: Iterable[object]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
        newline="\n",
    )


def _aggregate_status(statuses: Iterable[str]) -> str:
    values = tuple(statuses)
    for status in ("contaminated", "timeout", "failed", "completed"):
        if status in values:
            return status
    raise RunnerError("manifest must contain at least one task")


def _add_usage(left: TokenUsage, right: TokenUsage) -> TokenUsage:
    return TokenUsage(
        cached_input_tokens=left.cached_input_tokens + right.cached_input_tokens,
        uncached_input_tokens=left.uncached_input_tokens + right.uncached_input_tokens,
        output_tokens=left.output_tokens + right.output_tokens,
    )


def _require_safe_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
        raise RunnerError("run_id must be a path-safe identifier")


def _require_non_empty_text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(f"{name} must be a non-empty string")
