# Provides a deterministic source-only adapter for runner Canary tests.

from __future__ import annotations

import hashlib
import re
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
        usage = self._usage(snapshot)
        return ExecutorResult(
            raw_response={
                "prediction": {
                    "schema_version": 1,
                    "task_id": request.task_id,
                    "findings": findings,
                },
                "usage": {
                    "input_tokens": usage["cached_input_tokens"]
                    + usage["uncached_input_tokens"],
                    "cached_input_tokens": usage["cached_input_tokens"],
                    "output_tokens": usage["output_tokens"],
                },
            },
            event_rows=({"event": "fake.completed"},),
            observed_argv=(),
        )

    @staticmethod
    def _findings(snapshot: Path) -> list[dict[str, object]]:
        entry_pattern = re.compile(
            rb"(?m)^[ \t]*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            rb"request\[\"value\"\]\s*$"
        )
        for path, source in _source_files(snapshot):
            entry = entry_pattern.search(source)
            if entry is None:
                continue
            variable = re.escape(entry.group("name"))
            operation = re.compile(
                rb"(?m)^[ \t]*execute\(\s*" + variable + rb"\s*\)\s*$"
            ).search(source, entry.end())
            if operation is None:
                continue
            relative_path = path.relative_to(snapshot).as_posix()
            entry_line = _line_number(source, entry.start())
            operation_line = _line_number(source, operation.start())
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

    @staticmethod
    def _usage(snapshot: Path) -> dict[str, int]:
        source = b"".join(contents for _, contents in _source_files(snapshot))
        digest = hashlib.sha256(source).digest()
        return {
            "cached_input_tokens": 1 + digest[0] % 17,
            "uncached_input_tokens": 1 + digest[1] % 17,
            "output_tokens": 1 + digest[2] % 17,
        }


def _source_files(snapshot: Path) -> tuple[tuple[Path, bytes], ...]:
    return tuple(
        (path, path.read_bytes())
        for path in sorted(snapshot.rglob("*"))
        if path.is_file()
    )


def _line_number(source: bytes, offset: int) -> int:
    return source[:offset].count(b"\n") + 1
