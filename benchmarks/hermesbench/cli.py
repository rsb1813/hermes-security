# Exposes the standalone HermesBench command line.

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .contracts import ContractError, load_oracles, load_predictions
from .corpus import load_vulngym_candidates
from .escalation import MiniEvidence, decide_escalation
from .receipts import comparison_mismatches, load_receipt
from .sanitize import BundleAuditError, audit_bundle
from .scoring import ScoringError, score_run


class CliError(ValueError):
    """Signals invalid command input without exposing private contents."""


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_PRIVATE_OUTPUT_ROOT = _REPOSITORY_ROOT / "benchmarks" / "hermesbench" / "private"


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(prog="hermesbench")
    commands = parser.add_subparsers(dest="command", required=True)

    audit = commands.add_parser("audit-bundle")
    audit.add_argument("--bundle", type=Path, required=True)

    score = commands.add_parser("score")
    score.add_argument("--oracles", type=Path, required=True)
    score.add_argument("--predictions", type=Path, required=True)
    score.add_argument("--out", type=Path, required=True)
    score.add_argument("--line-tolerance", type=int, default=5)

    compare = commands.add_parser("compare")
    compare.add_argument("--standard-receipt", type=Path, required=True)
    compare.add_argument("--hunt-receipt", type=Path, required=True)
    compare.add_argument("--evidence", type=Path, required=True)
    compare.add_argument("--out", type=Path, required=True)

    importer = commands.add_parser("import-vulngym")
    importer.add_argument("--entries", type=Path, required=True)
    importer.add_argument("--reports", type=Path, required=True)
    importer.add_argument("--dataset-revision", required=True)
    importer.add_argument("--key-file", type=Path, required=True)
    importer.add_argument("--private-out", type=Path, required=True)
    importer.add_argument("--summary-out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.command == "audit-bundle":
            return _audit_command(args.bundle)
        if args.command == "score":
            return _score_command(
                args.oracles,
                args.predictions,
                args.out,
                args.line_tolerance,
            )
        if args.command == "compare":
            return _compare_command(
                args.standard_receipt,
                args.hunt_receipt,
                args.evidence,
                args.out,
            )
        if args.command == "import-vulngym":
            return _import_command(
                args.entries,
                args.reports,
                args.dataset_revision,
                args.key_file,
                args.private_out,
                args.summary_out,
            )
        raise AssertionError(f"unhandled command: {args.command}")
    except (
        BundleAuditError,
        CliError,
        ContractError,
        json.JSONDecodeError,
        OSError,
        ScoringError,
        ValueError,
    ) as error:
        _print_json(
            {"error": str(error), "error_type": type(error).__name__},
            stream=sys.stderr,
        )
        return 2


def _audit_command(bundle: Path) -> int:
    violations = audit_bundle(bundle)
    _print_json({"violations": [asdict(item) for item in violations]})
    return 2 if violations else 0


def _score_command(
    oracles_path: Path,
    predictions_path: Path,
    output_path: Path,
    line_tolerance: int,
) -> int:
    oracles = load_oracles(oracles_path)
    predictions = load_predictions(predictions_path)
    score = score_run(oracles, predictions, line_tolerance)
    _write_json(output_path, score.to_json())
    return 0


def _compare_command(
    standard_receipt_path: Path,
    hunt_receipt_path: Path,
    evidence_path: Path,
    output_path: Path,
) -> int:
    standard = load_receipt(standard_receipt_path)
    hunt = load_receipt(hunt_receipt_path)
    mismatches = comparison_mismatches(standard.config, hunt.config)
    if standard.workflow != "standard":
        mismatches.append("standard_workflow")
    if hunt.workflow != "hunt":
        mismatches.append("hunt_workflow")
    mismatches.sort()
    if mismatches:
        _write_json(
            output_path,
            {"comparable": False, "mismatches": mismatches},
        )
        return 2

    decision = decide_escalation(_load_evidence(evidence_path))
    _write_json(
        output_path,
        {
            "comparable": True,
            "mismatches": [],
            "full_required": decision.full_required,
            "reasons": list(decision.reasons),
        },
    )
    return 0


def _import_command(
    entries_path: Path,
    reports_path: Path,
    dataset_revision: str,
    key_path: Path,
    private_output_path: Path,
    summary_output_path: Path,
) -> int:
    private_output_path = _require_private_output_path(private_output_path)
    _reject_output_collisions(
        inputs=(entries_path, reports_path, key_path),
        outputs=(private_output_path, summary_output_path),
    )
    key = key_path.read_bytes()
    candidates, summary = load_vulngym_candidates(
        entries_path,
        reports_path,
        dataset_revision=dataset_revision,
        anonymization_key=key,
    )
    _write_json(
        private_output_path,
        {
            "schema_version": 1,
            "candidates": [candidate.to_private_json() for candidate in candidates],
        },
    )
    _write_json(summary_output_path, summary.to_json())
    return 0


def _require_private_output_path(path: Path) -> Path:
    if _is_link_or_junction(_PRIVATE_OUTPUT_ROOT):
        raise CliError("private output root must not be a link or junction")
    resolved = path.expanduser().resolve(strict=False)
    repository = _REPOSITORY_ROOT.resolve(strict=True)
    private_root = _PRIVATE_OUTPUT_ROOT.resolve(strict=False)
    if resolved.is_relative_to(repository) and not resolved.is_relative_to(
        private_root
    ):
        raise CliError(
            "private output inside the repository must be under "
            "benchmarks/hermesbench/private"
        )
    return resolved


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return callable(is_junction) and bool(is_junction())


def _load_evidence(path: Path) -> MiniEvidence:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CliError("comparison evidence must be an object")
    expected = {
        "ci_low",
        "ci_high",
        "hidden_additional_localized",
        "repeat_winners",
        "category_recall_deltas",
        "comparison_semantics_changed",
        "final_stage",
        "release_candidate",
        "public_performance_claim",
    }
    if set(value) != expected:
        raise CliError("comparison evidence must contain the exact version 1 fields")
    winners = value["repeat_winners"]
    category_deltas = value["category_recall_deltas"]
    if not isinstance(winners, list):
        raise CliError("repeat_winners must be an array")
    if not isinstance(category_deltas, list):
        raise CliError("category_recall_deltas must be an array")
    parsed_deltas: list[tuple[str, float]] = []
    for item in category_deltas:
        if not isinstance(item, list) or len(item) != 2:
            raise CliError("each category recall delta must contain a category and delta")
        parsed_deltas.append((item[0], item[1]))  # type: ignore[arg-type]
    return MiniEvidence(
        ci_low=value["ci_low"],  # type: ignore[arg-type]
        ci_high=value["ci_high"],  # type: ignore[arg-type]
        hidden_additional_localized=value["hidden_additional_localized"],  # type: ignore[arg-type]
        repeat_winners=tuple(winners),  # type: ignore[arg-type]
        category_recall_deltas=tuple(parsed_deltas),
        comparison_semantics_changed=value["comparison_semantics_changed"],  # type: ignore[arg-type]
        final_stage=value["final_stage"],  # type: ignore[arg-type]
        release_candidate=value["release_candidate"],  # type: ignore[arg-type]
        public_performance_claim=value["public_performance_claim"],  # type: ignore[arg-type]
    )


def _reject_output_collisions(
    *, inputs: tuple[Path, ...], outputs: tuple[Path, ...]
) -> None:
    resolved_inputs = {path.resolve() for path in inputs}
    resolved_outputs = [path.resolve() for path in outputs]
    if len(set(resolved_outputs)) != len(resolved_outputs):
        raise CliError("output paths must be distinct")
    if any(path in resolved_inputs for path in resolved_outputs):
        raise CliError("output paths must not overwrite input files")


def _write_json(path: Path, value: object) -> None:
    serialized = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)
    path.write_text(f"{serialized}\n", encoding="utf-8", newline="\n")


def _print_json(value: object, stream: object = sys.stdout) -> None:
    print(json.dumps(value, sort_keys=True, ensure_ascii=False), file=stream)
