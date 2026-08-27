# Defines the strict agent-visible HermesBench adapter protocol.

from __future__ import annotations

from dataclasses import dataclass

from .contracts import (
    SCHEMA_VERSION,
    ContractError,
    TaskPrediction,
    parse_prediction,
)
from .receipts import TokenUsage


@dataclass(frozen=True)
class AdapterTaskRequest:
    task_id: str
    snapshot_path: str
    language: str
    allowed_commands: tuple[tuple[str, ...], ...]
    time_limit_seconds: int

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "task_id": self.task_id,
            "snapshot_path": self.snapshot_path,
            "language": self.language,
            "allowed_commands": [list(command) for command in self.allowed_commands],
            "time_limit_seconds": self.time_limit_seconds,
        }


@dataclass(frozen=True)
class AdapterResponse:
    prediction: TaskPrediction
    token_usage: TokenUsage


def parse_adapter_task_request(value: object) -> AdapterTaskRequest:
    data = _require_object(value, "adapter request")
    _require_exact_fields(
        data,
        {
            "schema_version",
            "task_id",
            "snapshot_path",
            "language",
            "allowed_commands",
            "time_limit_seconds",
        },
        "adapter request",
    )
    _require_schema_version(data["schema_version"])
    commands = _parse_allowed_commands(data["allowed_commands"])
    return AdapterTaskRequest(
        task_id=_require_non_empty_string(data["task_id"], "task_id"),
        snapshot_path=_require_non_empty_string(data["snapshot_path"], "snapshot_path"),
        language=_require_non_empty_string(data["language"], "language"),
        allowed_commands=commands,
        time_limit_seconds=_require_positive_integer(
            data["time_limit_seconds"], "time_limit_seconds"
        ),
    )


def parse_adapter_response(value: object, task_id: str) -> AdapterResponse:
    data = _require_object(value, "adapter response")
    _require_exact_fields(data, {"prediction", "usage"}, "adapter response")
    expected_task_id = _require_non_empty_string(task_id, "task_id")
    prediction = parse_prediction(data["prediction"])
    if prediction.task_id != expected_task_id:
        raise ContractError("adapter response prediction task_id must match request task_id")
    return AdapterResponse(prediction=prediction, token_usage=parse_model_usage(data["usage"]))


def parse_model_usage(value: object) -> TokenUsage:
    data = _require_object(value, "model usage")
    _require_exact_fields(
        data,
        {"input_tokens", "cached_input_tokens", "output_tokens"},
        "model usage",
    )
    input_tokens = _require_non_negative_integer(data["input_tokens"], "input_tokens")
    cached_input_tokens = _require_non_negative_integer(
        data["cached_input_tokens"], "cached_input_tokens"
    )
    output_tokens = _require_non_negative_integer(data["output_tokens"], "output_tokens")
    if cached_input_tokens > input_tokens:
        raise ContractError("cached_input_tokens must not exceed input_tokens")
    return TokenUsage(
        cached_input_tokens=cached_input_tokens,
        uncached_input_tokens=input_tokens - cached_input_tokens,
        output_tokens=output_tokens,
    )


def _parse_allowed_commands(value: object) -> tuple[tuple[str, ...], ...]:
    if not isinstance(value, list):
        raise ContractError("allowed_commands must be an array")
    commands: list[tuple[str, ...]] = []
    for command in value:
        if not isinstance(command, list) or not command:
            raise ContractError("each allowed command must be a non-empty array")
        commands.append(
            tuple(_require_non_empty_string(token, "allowed command token") for token in command)
        )
    return tuple(commands)


def _require_schema_version(value: object) -> None:
    if isinstance(value, bool) or value != SCHEMA_VERSION:
        raise ContractError(f"schema_version must be {SCHEMA_VERSION}")


def _require_positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ContractError(f"{name} must be a positive integer")
    return value


def _require_non_negative_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{name} must be a non-negative integer")
    return value


def _require_non_empty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{name} must be a non-empty string")
    return value


def _require_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ContractError(f"{name} must be an object")
    return value


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
