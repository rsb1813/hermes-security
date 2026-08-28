# Runs HermesBench tasks against audited, immutable snapshot directories.

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, Iterable

from .adapter_contract import AdapterTaskRequest, parse_adapter_response
from .contracts import BenchmarkManifest, TaskDescriptor
from .receipts import RECEIPT_SCHEMA_VERSION, RunConfig, RunReceipt, TaskRunReceipt, TokenUsage
from .sanitize import BundleAuditError, audit_bundle, tree_sha256


_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_PUBLIC_COMMAND_TOKEN = re.compile(r"[-A-Za-z0-9_./:=@%+]+\Z")
_PUBLIC_FAILURE_CODES = frozenset(
    {
        "executor_failure",
        "executor_timeout",
        "container_execution_failed",
        "invalid_json_schema",
        "event_stream_invalid",
        "collaboration_event_not_allowed",
        "event_order_invalid",
        "event_stream_failed",
        "item_event_invalid",
        "command_event_invalid",
        "final_response_invalid",
        "terminal_usage_invalid",
        "terminal_response_incomplete",
        "terminal_response_invalid",
        "child_auth_unauthorized",
        "child_auth_unauthorized_before_replay",
        "child_auth_unauthorized_after_replay",
        "child_auth_token_unavailable",
        "child_auth_refresh",
        "child_auth_not_logged_in",
        "child_auth_account",
        "child_auth_other",
        "child_network",
        "child_sandbox",
        "child_filesystem",
        "child_configuration_cloud_auth_init",
        "child_configuration_cloud_auth_resolve",
        "child_configuration_bootstrap_load",
        "child_configuration_load",
        "child_configuration_schema",
        "child_configuration_cli_args",
        "child_configuration_other",
        "child_resource",
        "child_cli",
        "child_internal",
        "child_unknown",
        "setup_invalid_args",
        "setup_invalid_payload",
        "setup_auth_runtime",
        "setup_child_start",
        "setup_wrapper_os_error",
        "hunt_evidence_invalid",
    }
)
_SUCCESS_ARTIFACT_NAMES = frozenset({"adapter-response.json", "events.jsonl", "commands.jsonl", "evidence.json"})
_MAX_FAILURE_EVIDENCE_BYTES = 512
_ZERO_USAGE = TokenUsage(0, 0, 0)
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


class RunnerError(ValueError):
    """Signals a runner boundary failure before task execution begins."""


class ExecutorTimeoutError(TimeoutError):
    """Signals that the executor terminated its exact task for timeout."""


class ExecutorFailureError(RuntimeError):
    """Carries one bounded public failure code while keeping details private."""

    def __init__(self, message: str, *, failure_code: str = "executor_failure") -> None:
        if not _is_public_failure_code(failure_code):
            raise ValueError("executor failure code is invalid")
        super().__init__(message)
        self.failure_code = failure_code


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
    hunt_evidence: dict[str, object] | None = None


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
    response_kind: str = "standard",
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
    _assert_path_components_safe(output_root, "output root")
    resolved_snapshots = _resolve_existing_directory(snapshots_root, "snapshots root")
    _assert_path_components_safe(snapshots_root, "snapshots root")
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
    commands: list[dict[str, object]] = []
    evidence_rows: list[dict[str, object]] = []
    total_usage = _ZERO_USAGE
    for prepared in preflight:
        record, prediction, task_commands, task_evidence = _run_task(
            prepared,
            tasks_directory,
            execution_policy,
            executor,
            response_kind,
        )
        records.append(record)
        commands.extend(task_commands)
        if task_evidence is not None:
            evidence_rows.append(task_evidence)
        if prediction is not None:
            predictions.append(prediction)
            total_usage = _add_usage(total_usage, record.token_usage)

    _write_jsonl(run_directory / "predictions.jsonl", predictions)
    _write_jsonl(run_directory / "task-receipts.jsonl", (record.to_json() for record in records))
    _write_jsonl(run_directory / "commands.jsonl", commands)
    if response_kind == "hunt-discovery":
        _write_jsonl(run_directory / "evidence.jsonl", evidence_rows)
    receipt = RunReceipt(
        schema_version=RECEIPT_SCHEMA_VERSION,
        run_id=run_id,
        workflow=workflow,
        profile=profile,
        config=config,
        elapsed_seconds=sum(record.elapsed_seconds for record in records),
        status=_aggregate_status(record.status for record in records),
        failure_evidence_sha256=failure_evidence_sha256(tasks_directory, records),
        token_usage=total_usage,
    )
    _write_json(run_directory / "receipt.json", receipt.to_json())
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
    response_kind: str,
) -> tuple[TaskRunReceipt, dict[str, object] | None, tuple[dict[str, object], ...], dict[str, object] | None]:
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
    _assert_artifact_tree(task_directory, {"request.json"})
    started = time.monotonic()
    pre_sha256 = prepared.snapshot_sha256
    usage = _ZERO_USAGE
    status = "failed"
    prediction: dict[str, object] | None = None
    command_rows: tuple[dict[str, object], ...] = ()
    evidence: dict[str, object] | None = None
    try:
        pre_sha256 = _audit_and_hash(prepared.snapshot_path, descriptor.task_id)
    except RunnerError:
        status = "contaminated"
    else:
        if pre_sha256 != prepared.snapshot_sha256:
            status = "contaminated"
        else:
            try:
                with tempfile.TemporaryDirectory(prefix="hermesbench-executor-") as scratch:
                    result = executor(request, Path(scratch), descriptor.time_limit_seconds)
                _assert_artifact_tree(task_directory, {"request.json"})
                if response_kind == "standard":
                    parsed = parse_adapter_response(result.raw_response, descriptor.task_id)
                    prediction_value = _prediction_json(parsed.prediction)
                else:
                    from .hunt_protocol import (
                        HuntProtocolError,
                        parse_hunt_discovery_prediction,
                        parse_hunt_verification_prediction,
                    )

                    if not isinstance(result.raw_response, dict) or set(result.raw_response) != {"prediction", "usage"}:
                        raise HuntProtocolError("Hunt adapter response is invalid")
                    usage = parse_adapter_response(
                        {"prediction": {"schema_version": 1, "task_id": descriptor.task_id, "findings": []}, "usage": result.raw_response["usage"]},
                        descriptor.task_id,
                    ).token_usage
                    if response_kind == "hunt-discovery":
                        parsed_prediction = parse_hunt_discovery_prediction(result.raw_response["prediction"], descriptor.task_id)
                        prediction_value = result.raw_response["prediction"]
                    elif response_kind == "hunt-verification":
                        parsed_prediction = parse_hunt_verification_prediction(result.raw_response["prediction"], descriptor.task_id)
                        prediction_value = result.raw_response["prediction"]
                    else:
                        raise HuntProtocolError("Hunt response kind is invalid")
                    parsed = type("HuntParsed", (), {"token_usage": usage, "prediction": parsed_prediction})()
                event_rows = _normalize_event_rows(result.event_rows)
                command_rows = _command_rows(descriptor.task_id, result.observed_argv)
                if response_kind == "hunt-discovery":
                    if not isinstance(result.hunt_evidence, dict):
                        raise ExecutorFailureError("Hunt discovery evidence is required", failure_code="hunt_evidence_invalid")
                    evidence = result.hunt_evidence
                elif result.hunt_evidence is not None:
                    raise ExecutorFailureError("Hunt evidence is forbidden for this phase", failure_code="hunt_evidence_invalid")
                usage = parsed.token_usage
                _write_json(
                    task_directory / "adapter-response.json",
                    {
                        "prediction": prediction_value,
                        "usage": {
                            "input_tokens": usage.cached_input_tokens + usage.uncached_input_tokens,
                            "cached_input_tokens": usage.cached_input_tokens,
                            "output_tokens": usage.output_tokens,
                        },
                    },
                )
                _write_jsonl(task_directory / "events.jsonl", event_rows)
                _write_jsonl(
                    task_directory / "commands.jsonl",
                    ({"argv": row["argv"]} for row in command_rows),
                )
                if evidence is not None:
                    _write_json(task_directory / "evidence.json", evidence)
                _assert_artifact_tree(
                    task_directory,
                    {"request.json", "adapter-response.json", "events.jsonl", "commands.jsonl", *({"evidence.json"} if evidence is not None else set())},
                )
                try:
                    post_sha256 = _audit_and_hash(prepared.snapshot_path, descriptor.task_id)
                except RunnerError:
                    status = "contaminated"
                else:
                    if post_sha256 != pre_sha256 or not _commands_allowed(result.observed_argv, descriptor, policy):
                        status = "contaminated"
                    else:
                        status = "completed"
                        prediction = prediction_value
            except ExecutorTimeoutError:
                status = "timeout"
                _write_task_failure(task_directory, "executor_timeout")
            except ExecutorFailureError as error:
                status = "failed"
                _write_task_failure(task_directory, error.failure_code)
            except Exception:
                status = "failed"
                _write_task_failure(task_directory, "executor_failure")
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
        command_rows,
        evidence,
    )


def _write_task_failure(task_directory: Path, code: object) -> None:
    _remove_partial_success_artifacts(task_directory)
    public_code = _bounded_failure_code(code)
    _write_text_no_follow(task_directory / "failure.json", _failure_json_bytes(public_code).decode("utf-8"))
    _assert_artifact_tree(task_directory, {"request.json", "failure.json"})


def _bounded_failure_code(code: object) -> str:
    if _is_public_failure_code(code):
        return code
    return "executor_failure"


def _is_public_failure_code(code: object) -> bool:
    return isinstance(code, str) and code in _PUBLIC_FAILURE_CODES


def failure_evidence_sha256(tasks_directory: Path, records: Iterable[TaskRunReceipt]) -> str:
    """Returns the digest of every task's failure-sidecar state."""
    evidence: list[dict[str, str | None]] = []
    for record in records:
        task_directory = tasks_directory / _task_directory_name(record.task_id)
        _assert_task_directory_safe(task_directory, "failure evidence task directory")
        failure_path = task_directory / "failure.json"
        if record.status in {"failed", "timeout"}:
            _assert_artifact_tree(task_directory, {"request.json", "failure.json"})
            digest = hashlib.sha256(_failure_evidence_bytes(failure_path)).hexdigest()
        else:
            if _path_exists(failure_path):
                raise RunnerError("unexpected failure evidence")
            digest = None
        evidence.append({"task_id": record.task_id, "failure_sha256": digest})
    return _canonical_sha256(evidence)


def _remove_partial_success_artifacts(task_directory: Path) -> None:
    _assert_task_directory_safe(task_directory, "task artifact directory")
    partial_paths: list[Path] = []
    names: set[str] = set()
    try:
        with os.scandir(task_directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.name not in {"request.json", *_SUCCESS_ARTIFACT_NAMES}:
                    raise RunnerError("task artifact directory contains unexpected files")
                _assert_single_regular_file(path, "task artifact")
                names.add(entry.name)
                if entry.name in _SUCCESS_ARTIFACT_NAMES:
                    partial_paths.append(path)
    except OSError as error:
        raise RunnerError("task artifact directory cannot be inspected safely") from error
    if "request.json" not in names:
        raise RunnerError("task artifact directory is missing request.json")
    for path in partial_paths:
        try:
            os.unlink(path)
        except OSError as error:
            raise RunnerError("partial task artifact cannot be removed safely") from error
    _assert_artifact_tree(task_directory, {"request.json"})


def _failure_evidence_bytes(path: Path) -> bytes:
    before = _lstat_single_regular_file(path, "failure evidence")
    before_identity = _file_identity(before, "failure evidence")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RunnerError("failure evidence is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        _assert_single_regular_metadata(opened, "failure evidence")
        if _file_identity(opened, "failure evidence") != before_identity:
            raise RunnerError("failure evidence identity changed before open")
        value = _read_failure_evidence(descriptor)
    except OSError as error:
        raise RunnerError("failure evidence is unavailable") from error
    finally:
        os.close(descriptor)
    after = _lstat_single_regular_file(path, "failure evidence")
    if _file_identity(after, "failure evidence") != before_identity:
        raise RunnerError("failure evidence identity changed after read")
    try:
        decoded = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RunnerError("failure evidence is invalid") from error
    if not isinstance(decoded, dict) or set(decoded) != {"code"} or not _is_public_failure_code(decoded["code"]):
        raise RunnerError("failure evidence is invalid")
    if value != _failure_json_bytes(decoded["code"]):
        raise RunnerError("failure evidence is not canonical")
    return value


def _read_failure_evidence(descriptor: int) -> bytes:
    value = bytearray()
    while True:
        chunk = os.read(descriptor, min(256, _MAX_FAILURE_EVIDENCE_BYTES + 1 - len(value)))
        if not chunk:
            return bytes(value)
        value.extend(chunk)
        if len(value) > _MAX_FAILURE_EVIDENCE_BYTES:
            raise RunnerError("failure evidence exceeds the maximum size")


def _failure_json_bytes(code: str) -> bytes:
    return (json.dumps({"code": code}, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _path_exists(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RunnerError("artifact path cannot be inspected safely") from error
    return True


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


def _adapter_response_json(response: object) -> dict[str, object]:
    return {
        "prediction": _prediction_json(response.prediction),
        "usage": {
            "input_tokens": response.token_usage.cached_input_tokens + response.token_usage.uncached_input_tokens,
            "cached_input_tokens": response.token_usage.cached_input_tokens,
            "output_tokens": response.token_usage.output_tokens,
        },
    }


def _normalize_event_rows(rows: object) -> tuple[dict[str, object], ...]:
    if not isinstance(rows, tuple):
        raise RunnerError("executor event rows must be a tuple")
    normalized: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"event"}:
            raise RunnerError("executor event rows must contain only event")
        event = row["event"]
        if not isinstance(event, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", event) is None:
            raise RunnerError("executor event must be a short public token")
        normalized.append({"event": event})
    return tuple(normalized)


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


def _command_rows(
    task_id: str, observed: object
) -> tuple[dict[str, object], ...]:
    if not isinstance(observed, tuple):
        raise RunnerError("executor observed commands must be a tuple")
    rows: list[dict[str, object]] = []
    for argv in observed:
        if not isinstance(argv, tuple) or not argv or any(
            not isinstance(token, str)
            or _PUBLIC_COMMAND_TOKEN.fullmatch(token) is None
            for token in argv
        ):
            raise RunnerError("executor observed command is unsafe")
        rows.append({"task_id": task_id, "argv": list(argv)})
    return tuple(rows)


def _post_snapshot_sha256(snapshot: Path, fallback: str) -> str:
    try:
        return tree_sha256(snapshot)
    except BundleAuditError:
        return fallback


def _audit_and_hash(snapshot: Path, task_id: str) -> str:
    try:
        _assert_tree_has_no_links(snapshot, f"snapshot for task {task_id}")
        violations = audit_bundle(snapshot)
        if violations:
            raise RunnerError(f"snapshot is contaminated for task {task_id}")
        return tree_sha256(snapshot)
    except BundleAuditError as error:
        raise RunnerError(f"snapshot is missing or unsafe for task {task_id}") from error


def _resolve_snapshot(snapshots_root: Path, task_id: str) -> Path:
    _require_safe_task_id(task_id)
    candidate = snapshots_root / task_id
    _assert_path_components_safe(candidate, f"snapshot for task {task_id}")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RunnerError(f"snapshot is missing for task {task_id}") from error
    if not resolved.is_dir() or resolved == snapshots_root or not _is_within(resolved, snapshots_root):
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
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise RunnerError(f"path cannot be inspected safely: {path}") from error
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", None)
    if attributes is None:
        if os.name == "nt":
            raise RunnerError(f"Windows path attributes are unavailable: {path}")
        return False
    try:
        return bool(int(attributes) & _FILE_ATTRIBUTE_REPARSE_POINT)
    except (TypeError, ValueError) as error:
        raise RunnerError(f"path attributes cannot be inspected safely: {path}") from error


def _assert_task_directory_safe(path: Path, name: str) -> None:
    _assert_path_components_safe(path, name)
    if _is_link_or_junction(path) or not path.is_dir():
        raise RunnerError(f"{name} is unsafe: {path}")


def _assert_single_regular_file(path: Path, name: str) -> None:
    _lstat_single_regular_file(path, name)


def _lstat_single_regular_file(path: Path, name: str) -> object:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise RunnerError(f"{name} is unavailable") from error
    _assert_single_regular_metadata(metadata, name)
    return metadata


def _assert_single_regular_metadata(metadata: object, name: str) -> None:
    mode = getattr(metadata, "st_mode", None)
    links = getattr(metadata, "st_nlink", None)
    if isinstance(mode, bool) or not isinstance(mode, int) or not stat.S_ISREG(mode):
        raise RunnerError(f"{name} must be a single regular file")
    if isinstance(links, bool) or not isinstance(links, int) or links != 1:
        raise RunnerError(f"{name} must be a single regular file")
    attributes = getattr(metadata, "st_file_attributes", None)
    if attributes is None:
        if os.name == "nt":
            raise RunnerError(f"{name} attributes are unavailable")
        return
    try:
        if int(attributes) & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise RunnerError(f"{name} must be a single regular file")
    except (TypeError, ValueError) as error:
        raise RunnerError(f"{name} attributes are unavailable") from error


def _file_identity(metadata: object, name: str) -> tuple[int, int]:
    device = getattr(metadata, "st_dev", None)
    inode = getattr(metadata, "st_ino", None)
    if (
        isinstance(device, bool)
        or not isinstance(device, int)
        or isinstance(inode, bool)
        or not isinstance(inode, int)
    ):
        raise RunnerError(f"{name} identity is unavailable")
    return device, inode


def _assert_path_components_safe(path: Path, name: str) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if _is_link_or_junction(current):
            raise RunnerError(f"{name} must not contain a link or reparse point: {current}")


def _assert_tree_has_no_links(root: Path, name: str) -> None:
    if _is_link_or_junction(root):
        raise RunnerError(f"{name} must not be a link or reparse point: {root}")
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    child = Path(entry.path)
                    if _is_link_or_junction(child):
                        raise RunnerError(f"{name} must not contain a link or reparse point: {child}")
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(child)
        except OSError as error:
            raise RunnerError(f"{name} cannot be inspected safely") from error


def _assert_artifact_tree(directory: Path, expected_names: set[str]) -> None:
    _assert_task_directory_safe(directory, "task artifact directory")
    names: set[str] = set()
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if _is_link_or_junction(path) or not entry.is_file(follow_symlinks=False):
                    raise RunnerError(f"task artifact directory contains an unsafe entry: {path}")
                names.add(entry.name)
    except OSError as error:
        raise RunnerError("task artifact directory cannot be inspected safely") from error
    if names != expected_names:
        raise RunnerError("task artifact directory contains unexpected files")


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
    _write_text_no_follow(path, json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n")


def _write_jsonl(path: Path, rows: Iterable[object]) -> None:
    _write_text_no_follow(path, "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows))


def _write_text_no_follow(path: Path, text: str) -> None:
    _assert_path_components_safe(path.parent, "artifact parent")
    try:
        os.lstat(path)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise RunnerError(f"artifact path cannot be inspected safely: {path}") from error
    else:
        raise RunnerError(f"artifact path already exists or is unsafe: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        encoded = text.encode("utf-8")
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
    finally:
        os.close(descriptor)
    if _is_link_or_junction(path) or not path.is_file():
        raise RunnerError(f"artifact path became unsafe: {path}")


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


def _require_safe_task_id(task_id: str) -> None:
    if not isinstance(task_id, str) or not task_id or "\x00" in task_id or "\\" in task_id:
        raise RunnerError("task_id must be a safe relative snapshot path")
    raw_parts = task_id.split("/")
    posix = PurePosixPath(task_id)
    windows = PureWindowsPath(task_id)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or not posix.parts
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        raise RunnerError("task_id must be a safe relative snapshot path")


def _require_non_empty_text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(f"{name} must be a non-empty string")
