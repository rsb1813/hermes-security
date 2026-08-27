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
CLOSURE_STATUSES = ("reviewed", "no_candidate", "deferred")
FRONTIER_PASSES = ("forward", "backward", "guard", "parser", "state", "general")
LOCATION_ROLES = (
    "entrypoint",
    "entrypoint/wrapper",
    "source",
    "root_control",
    "sink",
    "concrete_implementation",
    "evidence",
)
SAFE_VALIDATION_METHODS = (
    "static_trace",
    "existing_test",
    "build",
    "type_check",
    "safe_invariant",
)
PROOF_STATUSES = ("proven", "disproven", "unknown")
DISPOSITIONS = ("accepted", "rejected", "inconclusive")
CONFIDENCE_LEVELS = ("high", "medium", "low")

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
    closure = commands.add_parser(
        "close-frontier", help="Require a terminal closure for every review item."
    )
    closure.add_argument("--frontier", required=True)
    closure.add_argument("--closures", required=True)
    closure.add_argument("--out", required=True)
    preparation = commands.add_parser(
        "prepare-validation", help="Convert discoveries into unverified hypotheses."
    )
    preparation.add_argument("--candidates", required=True)
    preparation.add_argument("--out", required=True)
    validation = commands.add_parser(
        "validate-decisions", help="Validate independent terminal candidate decisions."
    )
    validation.add_argument("--candidates", required=True)
    validation.add_argument("--validations", required=True)
    validation.add_argument("--discovery-actor", required=True)
    validation.add_argument("--out", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.command == "make-frontier":
            make_frontier(args)
            return 0
        if args.command == "close-frontier":
            close_frontier(args)
            return 0
        if args.command == "prepare-validation":
            prepare_validation(args)
            return 0
        if args.command == "validate-decisions":
            validate_decisions(args)
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


def close_frontier(args: argparse.Namespace) -> None:
    frontier_path = Path(args.frontier).expanduser().resolve(strict=True)
    closures_path = Path(args.closures).expanduser().resolve(strict=True)
    output_path = Path(args.out).expanduser().resolve(strict=False)
    _reject_output_collisions(
        inputs=(frontier_path, closures_path), outputs=(output_path,)
    )
    frontier = _load_jsonl(frontier_path, "frontier", _validate_frontier)
    closures = _load_jsonl(closures_path, "closure", _validate_closure)
    _require_unique_field(frontier, "work_id", "frontier")
    _require_unique_field(frontier, "path", "frontier")
    _require_unique_field(closures, "work_id", "closures")
    priorities = sorted(int(row["priority"]) for row in frontier)
    if priorities != list(range(1, len(frontier) + 1)):
        raise HuntWorkflowError("frontier priorities must be unique and contiguous from 1")

    frontier_by_id = {str(row["work_id"]): row for row in frontier}
    closure_by_id = {str(row["work_id"]): row for row in closures}
    unknown = sorted(set(closure_by_id) - set(frontier_by_id))
    if unknown:
        raise HuntWorkflowError(f"closures contain unknown work ids: {unknown}")
    missing = sorted(set(frontier_by_id) - set(closure_by_id))
    if missing:
        raise HuntWorkflowError(f"frontier items are missing closures: {missing}")

    coverage_debt = []
    for work_id, closure in closure_by_id.items():
        if closure["status"] != "deferred":
            continue
        item = frontier_by_id[work_id]
        coverage_debt.append(
            {
                "work_id": work_id,
                "path": item["path"],
                "component": item["component"],
                "passes": item["passes"],
                "notes": closure["notes"],
            }
        )
    coverage_debt.sort(key=lambda item: str(item["work_id"]))
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "frontier_sha256": _sha256_file(frontier_path),
        "closures_sha256": _sha256_file(closures_path),
        "total_items": len(frontier),
        "reviewed": sum(row["status"] == "reviewed" for row in closures),
        "no_candidate": sum(row["status"] == "no_candidate" for row in closures),
        "deferred": sum(row["status"] == "deferred" for row in closures),
        "candidate_links": sum(len(row["candidate_ids"]) for row in closures),
        "component_counts": _coverage_counts(frontier, closure_by_id, "component"),
        "signal_counts": _multi_coverage_counts(frontier, closure_by_id, "signals"),
        "pass_counts": _multi_coverage_counts(frontier, closure_by_id, "passes"),
        "coverage_debt": coverage_debt,
    }
    _write_json(output_path, receipt)
    print(f"Closed all {len(frontier)} Hunt frontier rows in {output_path}")


def prepare_validation(args: argparse.Namespace) -> None:
    candidates_path = Path(args.candidates).expanduser().resolve(strict=True)
    output_path = Path(args.out).expanduser().resolve(strict=False)
    _reject_output_collisions(inputs=(candidates_path,), outputs=(output_path,))
    candidates = _load_jsonl(candidates_path, "candidate", _validate_candidate)
    _require_unique_field(candidates, "candidate_id", "candidates")
    hypotheses = []
    for candidate in candidates:
        hypothesis = {
            "candidate_id": candidate["candidate_id"],
            "cwe_ids": candidate["cwe_ids"],
            "claimed_locations": candidate["locations"],
            "hypothesis": candidate["summary"],
            "hypothesis_status": "unverified",
            "claimed_evidence": candidate["evidence"],
        }
        if "context" in candidate:
            hypothesis["context"] = candidate["context"]
        if "instance" in candidate:
            hypothesis["instance"] = candidate["instance"]
        hypotheses.append(hypothesis)
    _write_jsonl(output_path, hypotheses)
    print(f"Prepared {len(hypotheses)} unverified hypotheses in {output_path}")


def validate_decisions(args: argparse.Namespace) -> None:
    candidates_path = Path(args.candidates).expanduser().resolve(strict=True)
    validations_path = Path(args.validations).expanduser().resolve(strict=True)
    output_path = Path(args.out).expanduser().resolve(strict=False)
    discovery_actor = _standalone_identifier(args.discovery_actor, "discovery actor")
    _reject_output_collisions(
        inputs=(candidates_path, validations_path), outputs=(output_path,)
    )
    candidates = _load_jsonl(candidates_path, "candidate", _validate_candidate)
    validations = _load_jsonl(
        validations_path, "validation", _validate_validation
    )
    _require_unique_field(candidates, "candidate_id", "candidates")
    _require_unique_field(validations, "candidate_id", "validations")
    candidates_by_id = {str(row["candidate_id"]): row for row in candidates}
    validations_by_id = {str(row["candidate_id"]): row for row in validations}
    unknown = sorted(set(validations_by_id) - set(candidates_by_id))
    if unknown:
        raise HuntWorkflowError(f"validations reference unknown candidates: {unknown}")
    missing = sorted(set(candidates_by_id) - set(validations_by_id))
    if missing:
        raise HuntWorkflowError(f"candidates are missing validation decisions: {missing}")

    validated: list[JsonRow] = []
    for candidate in candidates:
        candidate_id = str(candidate["candidate_id"])
        validation = validations_by_id[candidate_id]
        if str(validation["verifier_actor"]).casefold() == discovery_actor.casefold():
            raise HuntWorkflowError(
                f"{candidate_id}: validation requires an independent verifier"
            )
        _require_disposition_evidence(candidate, validation)
        disposition = str(validation["disposition"])
        validated.append(
            candidate
            | {
                "validation": {
                    key: value
                    for key, value in validation.items()
                    if key != "candidate_id"
                },
                "state_history": [
                    "discovered",
                    "evidence_built",
                    "challenged",
                    disposition,
                ],
            }
        )
    _write_jsonl(output_path, validated)
    print(f"Validated {len(validated)} independent decisions in {output_path}")


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


def _validate_frontier(row: JsonRow, path: Path, line_number: int) -> None:
    _require_exact_fields(
        row,
        {
            "work_id",
            "path",
            "area",
            "component",
            "risk_score",
            "rank_include",
            "rank_reason",
            "signals",
            "passes",
            "priority",
        },
        path,
        line_number,
    )
    work_id = _require_string(
        row["work_id"], "work_id", path, line_number, allow_empty=False
    )
    if re.fullmatch(r"hunt-[0-9a-f]{16}", work_id) is None:
        raise HuntWorkflowError(f"{path}:{line_number}: invalid Hunt work_id")
    _require_relative_path(row["path"], path, line_number)
    _require_string(row["area"], "area", path, line_number, allow_empty=True)
    _require_string(
        row["component"], "component", path, line_number, allow_empty=False
    )
    score = row["risk_score"]
    if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 10:
        raise HuntWorkflowError(f"{path}:{line_number}: invalid risk_score")
    if not isinstance(row["rank_include"], bool):
        raise HuntWorkflowError(f"{path}:{line_number}: rank_include must be a boolean")
    _require_string(
        row["rank_reason"], "rank_reason", path, line_number, allow_empty=False
    )
    _require_string_array(
        row["signals"], "signals", SIGNAL_ORDER, path, line_number, allow_empty=True
    )
    _require_string_array(
        row["passes"], "passes", FRONTIER_PASSES, path, line_number, allow_empty=False
    )
    priority = row["priority"]
    if isinstance(priority, bool) or not isinstance(priority, int) or priority < 1:
        raise HuntWorkflowError(f"{path}:{line_number}: priority must be positive")


def _validate_closure(row: JsonRow, path: Path, line_number: int) -> None:
    _require_exact_fields(
        row, {"work_id", "status", "candidate_ids", "notes"}, path, line_number
    )
    _require_string(row["work_id"], "work_id", path, line_number, allow_empty=False)
    status = _require_string(
        row["status"], "status", path, line_number, allow_empty=False
    )
    if status not in CLOSURE_STATUSES:
        raise HuntWorkflowError(f"{path}:{line_number}: unsupported closure status")
    candidate_ids = _require_string_array(
        row["candidate_ids"],
        "candidate_ids",
        None,
        path,
        line_number,
        allow_empty=True,
    )
    _require_string(row["notes"], "notes", path, line_number, allow_empty=False)
    if status == "reviewed" and not candidate_ids:
        raise HuntWorkflowError(
            f"{path}:{line_number}: reviewed closure requires candidate_ids"
        )
    if status == "no_candidate" and candidate_ids:
        raise HuntWorkflowError(
            f"{path}:{line_number}: no_candidate closure cannot reference candidates"
        )


def _validate_candidate(row: JsonRow, path: Path, line_number: int) -> None:
    required = {"candidate_id", "cwe_ids", "locations", "summary", "evidence"}
    allowed = required | {"context", "instance"}
    actual = set(row)
    if not required <= actual or not actual <= allowed:
        raise HuntWorkflowError(
            f"{path}:{line_number}: invalid normalized candidate fields"
        )
    _require_identifier(
        row["candidate_id"], "candidate_id", path, line_number
    )
    cwe_ids = _require_string_array(
        row["cwe_ids"], "cwe_ids", None, path, line_number, allow_empty=True
    )
    if any(re.fullmatch(r"CWE-[1-9][0-9]*", cwe_id) is None for cwe_id in cwe_ids):
        raise HuntWorkflowError(f"{path}:{line_number}: invalid CWE identifier")
    locations = row["locations"]
    if not isinstance(locations, list) or not locations:
        raise HuntWorkflowError(
            f"{path}:{line_number}: candidate locations must be non-empty"
        )
    normalized_locations = [
        _validate_location(item, path, line_number) for item in locations
    ]
    identities = {
        (
            location["path"],
            location["start_line"],
            location["end_line"],
            location["role"],
        )
        for location in normalized_locations
    }
    if len(identities) != len(normalized_locations):
        raise HuntWorkflowError(f"{path}:{line_number}: duplicate candidate locations")
    _require_string(row["summary"], "summary", path, line_number, allow_empty=False)
    _require_string(row["evidence"], "evidence", path, line_number, allow_empty=False)
    for optional in ("context", "instance"):
        if optional in row:
            _require_string(
                row[optional], optional, path, line_number, allow_empty=False
            )


def _validate_location(
    value: object, path: Path, line_number: int
) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise HuntWorkflowError(f"{path}:{line_number}: location must be an object")
    _require_exact_fields(
        value, {"path", "start_line", "end_line", "role"}, path, line_number
    )
    _require_relative_path(value["path"], path, line_number)
    start_line = value["start_line"]
    end_line = value["end_line"]
    if (
        isinstance(start_line, bool)
        or not isinstance(start_line, int)
        or start_line < 1
        or isinstance(end_line, bool)
        or not isinstance(end_line, int)
        or end_line < start_line
    ):
        raise HuntWorkflowError(f"{path}:{line_number}: invalid location line range")
    role = _require_string(
        value["role"], "role", path, line_number, allow_empty=False
    )
    if role not in LOCATION_ROLES:
        raise HuntWorkflowError(f"{path}:{line_number}: unsupported location role")
    return value


def _validate_validation(row: JsonRow, path: Path, line_number: int) -> None:
    _require_exact_fields(
        row,
        {
            "candidate_id",
            "verifier_actor",
            "disposition",
            "method",
            "attacker_control",
            "reachability",
            "impact",
            "guard_failure",
            "evidence",
            "counterevidence",
            "proof_gaps",
            "preconditions",
            "impact_statement",
            "remediation",
            "uncertainty",
            "confidence",
        },
        path,
        line_number,
    )
    _require_identifier(row["candidate_id"], "candidate_id", path, line_number)
    _require_identifier(row["verifier_actor"], "verifier_actor", path, line_number)
    disposition = _require_string(
        row["disposition"], "disposition", path, line_number, allow_empty=False
    )
    if disposition not in DISPOSITIONS:
        raise HuntWorkflowError(f"{path}:{line_number}: unsupported disposition")
    method = _require_string(
        row["method"], "method", path, line_number, allow_empty=False
    )
    if method not in SAFE_VALIDATION_METHODS:
        raise HuntWorkflowError(
            f"{path}:{line_number}: unsupported safe validation method {method}"
        )
    for field in ("attacker_control", "reachability", "impact", "guard_failure"):
        status = _require_string(
            row[field], field, path, line_number, allow_empty=False
        )
        if status not in PROOF_STATUSES:
            raise HuntWorkflowError(f"{path}:{line_number}: unsupported {field} status")
    for field in ("evidence", "counterevidence", "proof_gaps", "preconditions"):
        _require_string_array(
            row[field], field, None, path, line_number, allow_empty=True
        )
    _require_string(
        row["impact_statement"],
        "impact_statement",
        path,
        line_number,
        allow_empty=False,
    )
    _require_string(
        row["remediation"], "remediation", path, line_number, allow_empty=True
    )
    _require_string(
        row["uncertainty"], "uncertainty", path, line_number, allow_empty=False
    )
    confidence = _require_string(
        row["confidence"], "confidence", path, line_number, allow_empty=False
    )
    if confidence not in CONFIDENCE_LEVELS:
        raise HuntWorkflowError(f"{path}:{line_number}: unsupported confidence")


def _require_disposition_evidence(
    candidate: JsonRow, validation: JsonRow
) -> None:
    candidate_id = str(candidate["candidate_id"])
    disposition = str(validation["disposition"])
    proof = tuple(
        str(validation[field])
        for field in ("attacker_control", "reachability", "impact", "guard_failure")
    )
    if disposition == "accepted":
        if any(status != "proven" for status in proof):
            raise HuntWorkflowError(
                f"{candidate_id}: accepted decision requires all four claims proven"
            )
        roles = {str(location["role"]) for location in candidate["locations"]}  # type: ignore[union-attr]
        source_roles = {"entrypoint", "entrypoint/wrapper", "source"}
        if not roles.intersection(source_roles) or not {"root_control", "sink"} <= roles:
            raise HuntWorkflowError(
                f"{candidate_id}: accepted decision requires source, root_control, and sink locations"
            )
        if not validation["evidence"]:
            raise HuntWorkflowError(
                f"{candidate_id}: accepted decision requires concrete evidence"
            )
        if not str(validation["remediation"]).strip():
            raise HuntWorkflowError(
                f"{candidate_id}: accepted decision requires remediation"
            )
    elif disposition == "rejected":
        if "disproven" not in proof or not validation["counterevidence"]:
            raise HuntWorkflowError(
                f"{candidate_id}: rejected decision requires a disproven claim and counterevidence"
            )
    elif "unknown" not in proof or not validation["proof_gaps"]:
        raise HuntWorkflowError(
            f"{candidate_id}: inconclusive decision requires an unknown claim and proof gaps"
        )


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


def _require_unique_field(rows: list[JsonRow], field: str, label: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for row in rows:
        value = str(row[field])
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    if duplicates:
        raise HuntWorkflowError(
            f"{label} contains duplicate {field} values: {sorted(duplicates)}"
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


def _require_identifier(
    value: object, field: str, path: Path, line_number: int
) -> str:
    identifier = _require_string(
        value, field, path, line_number, allow_empty=False
    )
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@/-]*", identifier) is None:
        raise HuntWorkflowError(f"{path}:{line_number}: invalid {field}")
    return identifier


def _standalone_identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._@/-]*", value
    ) is None:
        raise HuntWorkflowError(f"invalid {field}")
    return value


def _require_string_array(
    value: object,
    field: str,
    allowed: tuple[str, ...] | None,
    path: Path,
    line_number: int,
    *,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        requirement = "an array" if allow_empty else "a non-empty array"
        raise HuntWorkflowError(f"{path}:{line_number}: {field} must be {requirement}")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise HuntWorkflowError(
                f"{path}:{line_number}: {field} items must be non-empty strings"
            )
        if allowed is not None and item not in allowed:
            raise HuntWorkflowError(
                f"{path}:{line_number}: unsupported {field} item {item}"
            )
        items.append(item)
    if len(items) != len(set(items)):
        raise HuntWorkflowError(f"{path}:{line_number}: {field} items must be unique")
    return tuple(items)


def _coverage_counts(
    frontier: list[JsonRow], closures: dict[str, JsonRow], field: str
) -> dict[str, object]:
    keys = sorted({str(row[field]) for row in frontier})
    return {
        key: {
            "total": sum(str(row[field]) == key for row in frontier),
            "deferred": sum(
                str(row[field]) == key
                and closures[str(row["work_id"])]["status"] == "deferred"
                for row in frontier
            ),
        }
        for key in keys
    }


def _multi_coverage_counts(
    frontier: list[JsonRow], closures: dict[str, JsonRow], field: str
) -> dict[str, object]:
    keys = sorted({str(item) for row in frontier for item in row[field]})  # type: ignore[union-attr]
    return {
        key: {
            "total": sum(key in row[field] for row in frontier),  # type: ignore[operator]
            "deferred": sum(
                key in row[field]  # type: ignore[operator]
                and closures[str(row["work_id"])]["status"] == "deferred"
                for row in frontier
            ),
        }
        for key in keys
    }


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
