# Provides a deterministic source-only adapter for runner Canary tests.

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..adapter_contract import AdapterTaskRequest
from ..runner import ExecutorResult


@dataclass(frozen=True)
class FakeAdapterObservation:
    request_json: dict[str, object]
    visible_directories: tuple[str, str]


class FakeAdapter:
    """Returns deterministic predictions from synthetic snapshot source bytes."""

    def __init__(self) -> None:
        self.observations: list[FakeAdapterObservation] = []

    def __call__(
        self, request: AdapterTaskRequest, scratch_path: Path, timeout_seconds: int
    ) -> ExecutorResult:
        del timeout_seconds
        snapshot = Path(request.snapshot_path)
        self.observations.append(
            FakeAdapterObservation(
                request_json=request.to_json(),
                visible_directories=(str(snapshot), str(scratch_path)),
            )
        )
        findings = self._findings(snapshot)
        return ExecutorResult(
            raw_response={
                "prediction": {
                    "schema_version": 1,
                    "task_id": request.task_id,
                    "findings": findings,
                },
                "usage": {
                    "input_tokens": 12,
                    "cached_input_tokens": 7,
                    "output_tokens": 3,
                },
            },
            event_rows=({"event": "fake.completed"},),
            observed_argv=(),
        )

    @staticmethod
    def _findings(snapshot: Path) -> list[dict[str, object]]:
        for path in sorted(snapshot.rglob("*")):
            if not path.is_file():
                continue
            source = path.read_bytes()
            entry = b'value = request["value"]'
            operation = b"execute(value)"
            if entry not in source or operation not in source:
                continue
            relative_path = path.relative_to(snapshot).as_posix()
            entry_line = _line_number(source, entry)
            operation_line = _line_number(source, operation)
            return [
                {
                    "finding_id": "synthetic-source-flow",
                    "entry_point": {"file": relative_path, "line": entry_line},
                    "critical_operation": {"file": relative_path, "line": operation_line},
                    "trace": [{"file": relative_path, "line": entry_line}],
                    "confidence": 1.0,
                }
            ]
        return []


def _line_number(source: bytes, marker: bytes) -> int:
    return source[: source.index(marker)].count(b"\n") + 1
