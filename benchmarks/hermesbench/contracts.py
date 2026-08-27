# Defines versioned HermesBench data contracts.

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal, TypeVar

SCHEMA_VERSION = 1
MAX_FINDINGS = 5

Split = Literal["public_dev", "hidden_test", "rotating_audit", "full_holdout"]
TaskKind = Literal["vulnerable", "fixed", "clean"]
Suite = Literal["canary", "mini", "full"]

_SPLITS = frozenset({"public_dev", "hidden_test", "rotating_audit", "full_holdout"})
_TASK_KINDS = frozenset({"vulnerable", "fixed", "clean"})
_SUITES = frozenset({"canary", "mini", "full"})


class ContractError(ValueError):
    """Signals invalid benchmark data at a trust boundary."""


@dataclass(frozen=True)
class Location:
    path: str
    start_line: int
    end_line: int

    @classmethod
    def from_json(cls, value: object) -> "Location":
        data = _require_object(value, "location")
        _require_exact_fields(data, {"file", "line"}, "location")

        raw_path = _require_non_empty_string(data["file"], "location file")
        normalized = raw_path.replace("\\", "/")
        pure = PurePosixPath(normalized)
        windows = PureWindowsPath(raw_path)
        if (
            "\x00" in raw_path
            or pure.is_absolute()
            or windows.drive
            or ".." in pure.parts
            or str(pure) == "."
        ):
            raise ContractError("location file must be repository-relative")

        start, end = _parse_line(data["line"])
        return cls(path=str(pure), start_line=start, end_line=end)


@dataclass(frozen=True)
class GoldPath:
    path_id: str
    entry_point: Location
    critical_operation: Location
    trace: tuple[Location, ...]


@dataclass(frozen=True)
class Finding:
    finding_id: str
    entry_point: Location
    critical_operation: Location
    trace: tuple[Location, ...]
    confidence: float


@dataclass(frozen=True)
class OracleTask:
    task_id: str
    kind: TaskKind
    group_id: str
    split: Split
    category: str
    language: str
    paths: tuple[GoldPath, ...]
    retired_paths: tuple[GoldPath, ...]


@dataclass(frozen=True)
class TaskPrediction:
    task_id: str
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class TaskDescriptor:
    task_id: str
    snapshot_sha256: str
    language: str
    allowed_commands: tuple[tuple[str, ...], ...]
    time_limit_seconds: int


@dataclass(frozen=True)
class BenchmarkManifest:
    schema_version: int
    suite: Suite
    manifest_id: str
    tasks: tuple[TaskDescriptor, ...]


def parse_manifest(value: object) -> BenchmarkManifest:
    data = _require_object(value, "manifest")
    _require_exact_fields(
        data,
        {"schema_version", "suite", "manifest_id", "tasks"},
        "manifest",
    )
    _require_schema_version(data["schema_version"])
    raw_suite = _require_non_empty_string(data["suite"], "suite")
    if raw_suite not in _SUITES:
        raise ContractError(f"unsupported benchmark suite: {raw_suite}")
    suite: Suite = raw_suite  # type: ignore[assignment]
    manifest_id = _require_non_empty_string(data["manifest_id"], "manifest_id")
    raw_tasks = _require_list(data["tasks"], "tasks")
    if not raw_tasks:
        raise ContractError("manifest tasks must not be empty")
    tasks = tuple(_parse_task_descriptor(task) for task in raw_tasks)
    task_ids = [task.task_id for task in tasks]
    if len(task_ids) != len(set(task_ids)):
        raise ContractError("manifest contains duplicate task_id values")
    return BenchmarkManifest(
        schema_version=SCHEMA_VERSION,
        suite=suite,
        manifest_id=manifest_id,
        tasks=tasks,
    )


def load_manifest(path: Path) -> BenchmarkManifest:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ContractError(f"{path}: invalid manifest JSON") from error
    try:
        return parse_manifest(value)
    except ContractError as error:
        raise ContractError(f"{path}: {error}") from error


def parse_oracle(value: object) -> OracleTask:
    data = _require_object(value, "oracle")
    _require_exact_fields(
        data,
        {
            "schema_version",
            "task_id",
            "kind",
            "group_id",
            "split",
            "category",
            "language",
            "paths",
            "retired_paths",
        },
        "oracle",
    )
    _require_schema_version(data["schema_version"])

    task_id = _require_non_empty_string(data["task_id"], "task_id")
    group_id = _require_non_empty_string(data["group_id"], "group_id")
    category = _require_non_empty_string(data["category"], "category")
    language = _require_non_empty_string(data["language"], "language")

    raw_kind = _require_non_empty_string(data["kind"], "kind")
    if raw_kind not in _TASK_KINDS:
        raise ContractError(f"unsupported oracle kind: {raw_kind}")
    kind: TaskKind = raw_kind  # type: ignore[assignment]

    raw_split = _require_non_empty_string(data["split"], "split")
    if raw_split not in _SPLITS:
        raise ContractError(f"unsupported oracle split: {raw_split}")
    split: Split = raw_split  # type: ignore[assignment]

    paths = _parse_gold_paths(data["paths"], "paths")
    retired_paths = _parse_gold_paths(data["retired_paths"], "retired_paths")
    path_ids = [path.path_id for path in (*paths, *retired_paths)]
    if len(path_ids) != len(set(path_ids)):
        raise ContractError("oracle contains duplicate path_id values")

    if kind == "vulnerable" and (not paths or retired_paths):
        raise ContractError("vulnerable oracle requires paths and empty retired_paths")
    if kind == "fixed" and (paths or not retired_paths):
        raise ContractError("fixed oracle requires empty paths and non-empty retired_paths")
    if kind == "clean" and (paths or retired_paths):
        raise ContractError("clean oracle requires empty paths and retired_paths")

    return OracleTask(
        task_id=task_id,
        kind=kind,
        group_id=group_id,
        split=split,
        category=category,
        language=language,
        paths=paths,
        retired_paths=retired_paths,
    )


def parse_prediction(value: object) -> TaskPrediction:
    data = _require_object(value, "prediction")
    _require_exact_fields(data, {"schema_version", "task_id", "findings"}, "prediction")
    _require_schema_version(data["schema_version"])
    task_id = _require_non_empty_string(data["task_id"], "task_id")

    raw_findings = _require_list(data["findings"], "findings")
    if len(raw_findings) > MAX_FINDINGS:
        raise ContractError(f"prediction must contain at most {MAX_FINDINGS} findings")
    findings = tuple(_parse_finding(item) for item in raw_findings)
    finding_ids = [finding.finding_id for finding in findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise ContractError("prediction contains duplicate finding_id values")
    return TaskPrediction(task_id=task_id, findings=findings)


def load_oracles(path: Path) -> dict[str, OracleTask]:
    return _load_jsonl(path, parse_oracle)


def load_predictions(path: Path) -> dict[str, TaskPrediction]:
    return _load_jsonl(path, parse_prediction)


def _parse_gold_paths(value: object, field_name: str) -> tuple[GoldPath, ...]:
    return tuple(_parse_gold_path(item) for item in _require_list(value, field_name))


def _parse_task_descriptor(value: object) -> TaskDescriptor:
    data = _require_object(value, "task descriptor")
    _require_exact_fields(
        data,
        {
            "task_id",
            "snapshot_sha256",
            "language",
            "allowed_commands",
            "time_limit_seconds",
        },
        "task descriptor",
    )
    task_id = _require_non_empty_string(data["task_id"], "task_id")
    snapshot_sha256 = _require_sha256(data["snapshot_sha256"], "snapshot_sha256")
    language = _require_non_empty_string(data["language"], "language")
    raw_commands = _require_list(data["allowed_commands"], "allowed_commands")
    commands: list[tuple[str, ...]] = []
    for raw_command in raw_commands:
        command = _require_list(raw_command, "allowed command")
        if not command:
            raise ContractError("allowed command must not be empty")
        commands.append(
            tuple(
                _require_non_empty_string(token, "allowed command token")
                for token in command
            )
        )
    time_limit_seconds = data["time_limit_seconds"]
    if (
        isinstance(time_limit_seconds, bool)
        or not isinstance(time_limit_seconds, int)
        or time_limit_seconds < 1
    ):
        raise ContractError("time_limit_seconds must be a positive integer")
    return TaskDescriptor(
        task_id=task_id,
        snapshot_sha256=snapshot_sha256,
        language=language,
        allowed_commands=tuple(commands),
        time_limit_seconds=time_limit_seconds,
    )


def _parse_gold_path(value: object) -> GoldPath:
    data = _require_object(value, "gold path")
    _require_exact_fields(
        data,
        {"path_id", "entry_point", "critical_operation", "trace"},
        "gold path",
    )
    return GoldPath(
        path_id=_require_non_empty_string(data["path_id"], "path_id"),
        entry_point=Location.from_json(data["entry_point"]),
        critical_operation=Location.from_json(data["critical_operation"]),
        trace=tuple(
            Location.from_json(item) for item in _require_list(data["trace"], "trace")
        ),
    )


def _parse_finding(value: object) -> Finding:
    data = _require_object(value, "finding")
    _require_exact_fields(
        data,
        {"finding_id", "entry_point", "critical_operation", "trace", "confidence"},
        "finding",
    )
    raw_confidence = data["confidence"]
    if (
        isinstance(raw_confidence, bool)
        or not isinstance(raw_confidence, (int, float))
        or not math.isfinite(raw_confidence)
        or not 0.0 <= raw_confidence <= 1.0
    ):
        raise ContractError("finding confidence must be between 0.0 and 1.0")
    return Finding(
        finding_id=_require_non_empty_string(data["finding_id"], "finding_id"),
        entry_point=Location.from_json(data["entry_point"]),
        critical_operation=Location.from_json(data["critical_operation"]),
        trace=tuple(
            Location.from_json(item) for item in _require_list(data["trace"], "trace")
        ),
        confidence=float(raw_confidence),
    )


def _parse_line(value: object) -> tuple[int, int]:
    if isinstance(value, bool):
        raise ContractError("location line must be positive")
    if isinstance(value, int):
        start = end = value
    elif isinstance(value, str) and value.count("-") == 1:
        left, right = value.split("-", 1)
        if not left.isdigit() or not right.isdigit():
            raise ContractError("location range must contain integers")
        start, end = int(left), int(right)
    else:
        raise ContractError("location line must be an integer or range")
    if start < 1 or end < start:
        raise ContractError("location line must be positive and ordered")
    return start, end


def _require_schema_version(value: object) -> None:
    if isinstance(value, bool) or value != SCHEMA_VERSION:
        raise ContractError(f"schema_version must be {SCHEMA_VERSION}")


def _require_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ContractError(f"{name} must be an object")
    return value


def _require_list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractError(f"{name} must be an array")
    return value


def _require_non_empty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{name} must be a non-empty string")
    return value


def _require_sha256(value: object, name: str) -> str:
    digest = _require_non_empty_string(value, name)
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ContractError(f"{name} must be a lowercase SHA-256 digest")
    return digest


def _require_exact_fields(
    value: dict[str, object], expected: set[str], name: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ContractError(
            f"{name} must contain exactly {sorted(expected)}; missing={missing}; extra={extra}"
        )


_ParsedTask = TypeVar("_ParsedTask", OracleTask, TaskPrediction)


def _load_jsonl(path: Path, parser: object) -> dict[str, _ParsedTask]:
    loaded: dict[str, _ParsedTask] = {}
    with path.open("r", encoding="utf-8") as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            if not raw_line.strip():
                continue
            try:
                value = json.loads(raw_line)
            except json.JSONDecodeError as error:
                raise ContractError(f"{path}: line {line_number}: invalid JSON") from error
            try:
                task = parser(value)  # type: ignore[operator]
            except ContractError as error:
                raise ContractError(f"{path}: line {line_number}: {error}") from error
            if task.task_id in loaded:
                raise ContractError(
                    f"{path}: line {line_number}: duplicate task_id {task.task_id}"
                )
            loaded[task.task_id] = task
    return loaded
