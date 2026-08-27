# Records comparable HermesBench run configuration and usage.

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Literal

RECEIPT_SCHEMA_VERSION = 1
RunStatus = Literal["completed", "failed", "timeout", "contaminated"]
_RUN_STATUSES = frozenset({"completed", "failed", "timeout", "contaminated"})


@dataclass(frozen=True)
class TokenUsage:
    cached_input_tokens: int
    uncached_input_tokens: int
    output_tokens: int

    def __post_init__(self) -> None:
        values = (
            self.cached_input_tokens,
            self.uncached_input_tokens,
            self.output_tokens,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise ValueError("token counts must be integers")
        if min(values) < 0:
            raise ValueError("token counts must be non-negative")

    def to_json(self) -> dict[str, int]:
        return {
            "cached_input_tokens": self.cached_input_tokens,
            "uncached_input_tokens": self.uncached_input_tokens,
            "output_tokens": self.output_tokens,
        }

    @classmethod
    def from_json(cls, value: object) -> "TokenUsage":
        data = _require_object(value, "token_usage")
        _require_exact_fields(
            data,
            {"cached_input_tokens", "uncached_input_tokens", "output_tokens"},
            "token_usage",
        )
        return cls(
            cached_input_tokens=data["cached_input_tokens"],  # type: ignore[arg-type]
            uncached_input_tokens=data["uncached_input_tokens"],  # type: ignore[arg-type]
            output_tokens=data["output_tokens"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class RunConfig:
    manifest_sha256: str
    task_order_sha256: str
    grader_version: str
    model: str
    reasoning_effort: str
    seed: str | None
    seed_supported: bool
    tool_versions: tuple[tuple[str, str], ...]
    time_limit_seconds: int
    max_findings: int = 5

    def __post_init__(self) -> None:
        _require_sha256(self.manifest_sha256, "manifest_sha256")
        _require_sha256(self.task_order_sha256, "task_order_sha256")
        _require_non_empty_string(self.grader_version, "grader_version")
        _require_non_empty_string(self.model, "model")
        _require_non_empty_string(self.reasoning_effort, "reasoning_effort")
        if not isinstance(self.seed_supported, bool):
            raise ValueError("seed_supported must be a boolean")
        if self.seed_supported:
            _require_non_empty_string(self.seed, "seed")
        elif self.seed is not None:
            raise ValueError("seed must be absent when seed_supported is false")
        if not self.tool_versions:
            raise ValueError("tool_versions must not be empty")
        for tool_name, tool_version in self.tool_versions:
            _require_non_empty_string(tool_name, "tool name")
            _require_non_empty_string(tool_version, "tool version")
        if len({name for name, _ in self.tool_versions}) != len(self.tool_versions):
            raise ValueError("tool_versions must contain unique tool names")
        _require_positive_integer(self.time_limit_seconds, "time_limit_seconds")
        _require_positive_integer(self.max_findings, "max_findings")

    def replace(self, **changes: object) -> "RunConfig":
        return replace(self, **changes)

    def to_json(self) -> dict[str, object]:
        return {
            "manifest_sha256": self.manifest_sha256,
            "task_order_sha256": self.task_order_sha256,
            "grader_version": self.grader_version,
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "seed": self.seed,
            "seed_supported": self.seed_supported,
            "tool_versions": [list(item) for item in self.tool_versions],
            "time_limit_seconds": self.time_limit_seconds,
            "max_findings": self.max_findings,
        }

    @classmethod
    def from_json(cls, value: object) -> "RunConfig":
        data = _require_object(value, "config")
        expected = {field.name for field in fields(cls)}
        _require_exact_fields(data, expected, "config")
        raw_tools = data["tool_versions"]
        if not isinstance(raw_tools, list):
            raise ValueError("tool_versions must be an array")
        tools: list[tuple[str, str]] = []
        for item in raw_tools:
            if not isinstance(item, list) or len(item) != 2:
                raise ValueError("each tool_versions item must contain a name and version")
            tools.append((item[0], item[1]))  # type: ignore[arg-type]
        return cls(
            manifest_sha256=data["manifest_sha256"],  # type: ignore[arg-type]
            task_order_sha256=data["task_order_sha256"],  # type: ignore[arg-type]
            grader_version=data["grader_version"],  # type: ignore[arg-type]
            model=data["model"],  # type: ignore[arg-type]
            reasoning_effort=data["reasoning_effort"],  # type: ignore[arg-type]
            seed=data["seed"],  # type: ignore[arg-type]
            seed_supported=data["seed_supported"],  # type: ignore[arg-type]
            tool_versions=tuple(tools),
            time_limit_seconds=data["time_limit_seconds"],  # type: ignore[arg-type]
            max_findings=data["max_findings"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class RunReceipt:
    schema_version: int
    run_id: str
    workflow: str
    profile: str
    config: RunConfig
    elapsed_seconds: float
    status: RunStatus
    token_usage: TokenUsage

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or self.schema_version != RECEIPT_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {RECEIPT_SCHEMA_VERSION}")
        _require_non_empty_string(self.run_id, "run_id")
        _require_non_empty_string(self.workflow, "workflow")
        _require_non_empty_string(self.profile, "profile")
        if not isinstance(self.config, RunConfig):
            raise ValueError("config must be a RunConfig")
        if not isinstance(self.token_usage, TokenUsage):
            raise ValueError("token_usage must be a TokenUsage")
        if (
            isinstance(self.elapsed_seconds, bool)
            or not isinstance(self.elapsed_seconds, (int, float))
            or not math.isfinite(self.elapsed_seconds)
            or self.elapsed_seconds < 0
        ):
            raise ValueError("elapsed_seconds must be a finite non-negative number")
        if not isinstance(self.status, str) or self.status not in _RUN_STATUSES:
            raise ValueError(f"unsupported run status: {self.status}")

    def replace(self, **changes: object) -> "RunReceipt":
        return replace(self, **changes)

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "workflow": self.workflow,
            "profile": self.profile,
            "config": self.config.to_json(),
            "elapsed_seconds": self.elapsed_seconds,
            "status": self.status,
            "token_usage": self.token_usage.to_json(),
        }

    @classmethod
    def from_json(cls, value: object) -> "RunReceipt":
        data = _require_object(value, "receipt")
        expected = {field.name for field in fields(cls)}
        _require_exact_fields(data, expected, "receipt")
        return cls(
            schema_version=data["schema_version"],  # type: ignore[arg-type]
            run_id=data["run_id"],  # type: ignore[arg-type]
            workflow=data["workflow"],  # type: ignore[arg-type]
            profile=data["profile"],  # type: ignore[arg-type]
            config=RunConfig.from_json(data["config"]),
            elapsed_seconds=data["elapsed_seconds"],  # type: ignore[arg-type]
            status=data["status"],  # type: ignore[arg-type]
            token_usage=TokenUsage.from_json(data["token_usage"]),
        )


def comparison_mismatches(left: RunConfig, right: RunConfig) -> list[str]:
    return sorted(
        field.name
        for field in fields(RunConfig)
        if getattr(left, field.name) != getattr(right, field.name)
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_receipt(path: Path, receipt: RunReceipt) -> None:
    serialized = json.dumps(
        receipt.to_json(), sort_keys=True, indent=2, ensure_ascii=False
    )
    path.write_text(f"{serialized}\n", encoding="utf-8", newline="\n")


def load_receipt(path: Path) -> RunReceipt:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid receipt JSON: {path}") from error
    return RunReceipt.from_json(value)


def _require_sha256(value: object, name: str) -> str:
    text = _require_non_empty_string(value, name)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return text


def _require_positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _require_non_empty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _require_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name} must be an object")
    return value


def _require_exact_fields(
    value: dict[str, object], expected: set[str], name: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(
            f"{name} must contain exactly {sorted(expected)}; missing={missing}; extra={extra}"
        )
