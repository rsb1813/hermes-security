#!/usr/bin/env python3
# Builds and validates deterministic artifacts for the experimental Hunt workflow.

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable

SCHEMA_VERSION = 1
PROFILES = ("hunt-balanced", "hunt-max")
SIGNAL_ORDER = ("entry", "sink", "control", "parser", "state")
SIGNAL_PATTERNS = {
    "entry": re.compile(
        r"\b(?:api|callback|consumer|controller|endpoint|handler|listener|request|route|rpc|webhook)\b",
        re.IGNORECASE,
    ),
    "sink": re.compile(
        r"\b(?:delete|deserialize|eval|exec|execute|fetch|load|open|query|render|save|send|subprocess|write)\b",
        re.IGNORECASE,
    ),
    "control": re.compile(
        r"\b(?:allowlist|auth|denylist|guard|permission|policy|principal|role|sanitize|token|validate)\b",
        re.IGNORECASE,
    ),
    "parser": re.compile(
        r"\b(?:archive|decode|deserialize|json|parse|template|unmarshal|xml|yaml|zip)\b",
        re.IGNORECASE,
    ),
    "state": re.compile(
        r"\b(?:create|delete|session|state|status|transaction|transition|update|workflow)\b",
        re.IGNORECASE,
    ),
}
PASS_BY_SIGNAL = {
    "entry": "forward",
    "sink": "backward",
    "control": "guard",
    "parser": "parser",
    "state": "state",
}

JsonRow = dict[str, object]
RowValidator = Callable[[JsonRow, Path, int], None]


class HuntWorkflowError(ValueError):
    """Signals an invalid or incomplete Hunt workflow artifact."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build deterministic experimental Hunt workflow artifacts."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    frontier = commands.add_parser(
        "make-frontier", help="Build a full-coverage risk-ordered review frontier."
    )
    frontier.add_argument("--rank-input", required=True)
    frontier.add_argument("--rank-output")
    frontier.add_argument("--profile", choices=PROFILES, required=True)
    frontier.add_argument("--out", required=True)
    frontier.add_argument("--receipt", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.command == "make-frontier":
            make_frontier(args)
            return 0
        raise AssertionError(f"unhandled command: {args.command}")
    except (HuntWorkflowError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"hunt_workflow: {error}", file=sys.stderr)
        return 2


def make_frontier(args: argparse.Namespace) -> None:
    rank_input_path = Path(args.rank_input).expanduser().resolve(strict=True)
    rank_output_path = (
        Path(args.rank_output).expanduser().resolve(strict=True)
        if args.rank_output is not None
        else None
    )
    output_path = Path(args.out).expanduser().resolve(strict=False)
    receipt_path = Path(args.receipt).expanduser().resolve(strict=False)
    _reject_output_collisions(
        inputs=tuple(
            path for path in (rank_input_path, rank_output_path) if path is not None
        ),
        outputs=(output_path, receipt_path),
    )

    rank_inputs = _load_jsonl(rank_input_path, "rank input", _validate_rank_input)
    _require_unique_paths(rank_inputs, "rank input")
    ranked_by_path: dict[str, JsonRow] = {}
    if rank_output_path is not None:
        rank_outputs = _load_jsonl(rank_output_path, "rank output", _validate_rank_output)
        _require_unique_paths(rank_outputs, "rank output")
        ranked_by_path = {str(row["path"]): row for row in rank_outputs}
        input_paths = {str(row["path"]) for row in rank_inputs}
        output_paths = set(ranked_by_path)
        if input_paths != output_paths:
            missing = sorted(input_paths - output_paths)
            unexpected = sorted(output_paths - input_paths)
            raise HuntWorkflowError(
                f"rank output must cover rank input exactly; missing={missing}; unexpected={unexpected}"
            )

    unordered: list[JsonRow] = []
    for input_row in rank_inputs:
        path = str(input_row["path"])
        area = str(input_row["area"])
        preview = str(input_row["preview"])
        ranked = ranked_by_path.get(path)
        if ranked is not None and ranked["area"] != area:
            raise HuntWorkflowError(f"rank output area does not match rank input for {path}")
        signals = _signals(path, preview)
        score = int(ranked["score"]) if ranked is not None else _heuristic_score(signals)
        rank_include = bool(ranked["include"]) if ranked is not None else True
        rank_reason = (
            str(ranked["reason"])
            if ranked is not None
            else "deterministic signal fallback"
        )
        component = _component(path, area)
        unordered.append(
            {
                "work_id": f"hunt-{hashlib.sha256(path.encode('utf-8')).hexdigest()[:16]}",
                "path": path,
                "area": area,
                "component": component,
                "risk_score": score,
                "rank_include": rank_include,
                "rank_reason": rank_reason,
                "signals": list(signals),
                "passes": list(_passes(args.profile, signals)),
            }
        )

    ordered = _coverage_order(unordered)
    frontier = [row | {"priority": index} for index, row in enumerate(ordered, 1)]
    rank_input_sha256 = _sha256_file(rank_input_path)
    rank_output_sha256 = (
        _sha256_file(rank_output_path) if rank_output_path is not None else None
    )
    cache_material = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "profile": args.profile,
            "rank_input_sha256": rank_input_sha256,
            "rank_output_sha256": rank_output_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "profile": args.profile,
        "cache_key": f"sha256:{hashlib.sha256(cache_material).hexdigest()}",
        "rank_input_sha256": rank_input_sha256,
        "rank_output_sha256": rank_output_sha256,
        "total_files": len(frontier),
        "components": len({str(row["component"]) for row in frontier}),
        "rank_excluded_but_retained": sum(
            not bool(row["rank_include"]) for row in frontier
        ),
        "signal_counts": {
            signal: sum(signal in row["signals"] for row in frontier)
            for signal in SIGNAL_ORDER
        },
        "coverage_strategy": "component_round_robin",
        "eligibility_dropped": 0,
    }
    _write_jsonl(output_path, frontier)
    _write_json(receipt_path, receipt)
    print(f"Wrote {len(frontier)} full-coverage Hunt rows to {output_path}")


def _validate_rank_input(row: JsonRow, path: Path, line_number: int) -> None:
    _require_exact_fields(row, {"path", "area", "preview"}, path, line_number)
    _require_relative_path(row["path"], path, line_number)
    _require_string(row["area"], "area", path, line_number, allow_empty=True)
    _require_string(row["preview"], "preview", path, line_number, allow_empty=True)


def _validate_rank_output(row: JsonRow, path: Path, line_number: int) -> None:
    _require_exact_fields(
        row, {"path", "area", "score", "include", "reason"}, path, line_number
    )
    _require_relative_path(row["path"], path, line_number)
    _require_string(row["area"], "area", path, line_number, allow_empty=True)
    score = row["score"]
    if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 10:
        raise HuntWorkflowError(f"{path}:{line_number}: score must be an integer from 1 to 10")
    if not isinstance(row["include"], bool):
        raise HuntWorkflowError(f"{path}:{line_number}: include must be a boolean")
    _require_string(row["reason"], "reason", path, line_number, allow_empty=False)


def _signals(path: str, preview: str) -> tuple[str, ...]:
    value = f"{path}\n{preview}"
    return tuple(
        signal for signal in SIGNAL_ORDER if SIGNAL_PATTERNS[signal].search(value)
    )


def _passes(profile: str, signals: tuple[str, ...]) -> tuple[str, ...]:
    passes: list[str] = []
    if profile == "hunt-max":
        passes.extend(("forward", "backward"))
    for signal in signals:
        review_pass = PASS_BY_SIGNAL[signal]
        if review_pass not in passes:
            passes.append(review_pass)
    if not passes:
        passes.append("general")
    return tuple(passes)


def _heuristic_score(signals: tuple[str, ...]) -> int:
    return min(10, 1 + 2 * len(signals))


def _component(path: str, area: str) -> str:
    if area.strip() and area.strip() != ".":
        return area.strip()
    parts = PurePosixPath(path).parts
    if len(parts) > 2 and parts[0].lower() in {
        "app",
        "apps",
        "lib",
        "modules",
        "packages",
        "services",
        "src",
    }:
        return "/".join(parts[:2])
    return parts[0] if len(parts) > 1 else "."


def _coverage_order(rows: list[JsonRow]) -> list[JsonRow]:
    by_component: dict[str, list[JsonRow]] = {}
    for row in rows:
        by_component.setdefault(str(row["component"]), []).append(row)
    for component_rows in by_component.values():
        component_rows.sort(
            key=lambda row: (
                -int(row["risk_score"]),
                not bool(row["rank_include"]),
                str(row["path"]),
            )
        )
    component_order = sorted(
        by_component,
        key=lambda component: (
            -int(by_component[component][0]["risk_score"]),
            component,
        ),
    )
    ordered: list[JsonRow] = []
    maximum_depth = max((len(rows) for rows in by_component.values()), default=0)
    for depth in range(maximum_depth):
        for component in component_order:
            component_rows = by_component[component]
            if depth < len(component_rows):
                ordered.append(component_rows[depth])
    return ordered


def _load_jsonl(path: Path, label: str, validator: RowValidator) -> list[JsonRow]:
    rows: list[JsonRow] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, raw_line in enumerate(stream, 1):
            if not raw_line.strip():
                continue
            try:
                value = json.loads(raw_line)
            except json.JSONDecodeError as error:
                raise HuntWorkflowError(
                    f"{path}:{line_number}: invalid {label} JSON"
                ) from error
            if not isinstance(value, dict) or not all(
                isinstance(key, str) for key in value
            ):
                raise HuntWorkflowError(f"{path}:{line_number}: {label} row must be an object")
            validator(value, path, line_number)
            rows.append(value)
    return rows


def _require_unique_paths(rows: list[JsonRow], label: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for row in rows:
        path = str(row["path"])
        if path in seen:
            duplicates.add(path)
        seen.add(path)
    if duplicates:
        raise HuntWorkflowError(
            f"{label} contains duplicate paths: {sorted(duplicates)}"
        )


def _require_exact_fields(
    row: JsonRow, expected: set[str], path: Path, line_number: int
) -> None:
    actual = set(row)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise HuntWorkflowError(
            f"{path}:{line_number}: missing fields {missing}; unexpected fields {unexpected}"
        )


def _require_relative_path(value: object, path: Path, line_number: int) -> str:
    text = _require_string(value, "path", path, line_number, allow_empty=False)
    normalized = text.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if (
        "\x00" in text
        or pure.is_absolute()
        or PureWindowsPath(text).drive
        or ".." in pure.parts
        or normalized != text
    ):
        raise HuntWorkflowError(
            f"{path}:{line_number}: path must be repository-relative POSIX text"
        )
    return text


def _require_string(
    value: object,
    field: str,
    path: Path,
    line_number: int,
    *,
    allow_empty: bool,
) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        requirement = "a string" if allow_empty else "a non-empty string"
        raise HuntWorkflowError(
            f"{path}:{line_number}: {field} must be {requirement}"
        )
    return value


def _reject_output_collisions(
    *, inputs: tuple[Path, ...], outputs: tuple[Path, ...]
) -> None:
    if len(set(outputs)) != len(outputs):
        raise HuntWorkflowError("output paths must be distinct")
    if any(output in set(inputs) for output in outputs):
        raise HuntWorkflowError("output paths must not overwrite input files")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_jsonl(path: Path, rows: list[JsonRow]) -> None:
    serialized = "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
        for row in rows
    )
    _write_text_atomic(path, serialized)


def _write_json(path: Path, value: object) -> None:
    serialized = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _write_text_atomic(path, serialized)


def _write_text_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(value)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
