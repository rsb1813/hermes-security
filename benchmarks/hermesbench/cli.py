# Exposes the standalone HermesBench command line.

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .adapters.codex_exec import (
    CodexExecAdapter,
    load_managed_chatgpt_auth,
    validate_hunt_execution_policy,
)
from .container_runtime import ContainerRuntime
from .contracts import ContractError, load_manifest, load_oracles, load_predictions
from .corpus import load_vulngym_candidates
from .escalation import MiniEvidence, decide_escalation
from .receipts import comparison_mismatches, load_receipt
from .phase_runner import FrozenControls, PhaseRunnerError, run_paired, run_workflow
from .runner import ExecutionPolicy
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

    run = commands.add_parser("run")
    _add_run_arguments(run)
    run.add_argument("--workflow", choices=("standard", "hunt"), required=True)
    run.add_argument("--profile", required=True)

    paired = commands.add_parser("run-paired")
    _add_run_arguments(paired)
    paired.add_argument("--hunt-profile", choices=("hunt-balanced", "hunt-max"), required=True)
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
        if args.command == "run":
            return _run_command(args)
        if args.command == "run-paired":
            return _run_paired_command(args)
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


def _add_run_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--manifest", type=Path, required=True)
    command.add_argument("--snapshots-root", type=Path, required=True)
    command.add_argument("--output-root", type=Path, required=True)
    command.add_argument("--run-id", required=True)
    command.add_argument("--controls", type=Path, required=True)
    command.add_argument("--execution-policy", type=Path, required=True)
    command.add_argument("--auth", type=Path, required=True)
    command.add_argument("--oracles", type=Path)


def _run_command(args: argparse.Namespace) -> int:
    manifest, controls, policy = _run_inputs(args)
    if args.workflow == "hunt":
        validate_hunt_execution_policy(policy)
    adapter = _codex_adapter(
        args,
        controls,
        args.workflow,
        args.profile,
        allowed_command_prefixes=policy.allowed_command_prefixes,
    )
    result = run_workflow(
        manifest=manifest,
        snapshots_root=args.snapshots_root,
        output_root=args.output_root,
        run_id=args.run_id,
        workflow=args.workflow,
        profile=args.profile,
        controls=controls,
        execution_policy=policy,
        discovery_executor=adapter,
        verification_executor_factory=adapter.for_verification,
        score_callback=_host_score_callback(args.oracles) if args.oracles is not None else None,
    )
    _print_json({"artifacts": result.artifact_paths})
    return 0 if result.receipt.status == "completed" else 2


def _run_paired_command(args: argparse.Namespace) -> int:
    manifest, controls, policy = _run_inputs(args)
    validate_hunt_execution_policy(policy)
    standard = _codex_adapter(
        args,
        controls,
        "standard",
        "baseline",
        allowed_command_prefixes=policy.allowed_command_prefixes,
    )
    hunt = _codex_adapter(
        args,
        controls,
        "hunt",
        args.hunt_profile,
        allowed_command_prefixes=policy.allowed_command_prefixes,
    )
    result = run_paired(
        manifest,
        args.snapshots_root,
        args.output_root,
        args.run_id,
        controls,
        policy,
        {"standard": standard, "hunt": hunt},
        {"standard": standard.for_verification, "hunt": hunt.for_verification},
        {"standard": "baseline", "hunt": args.hunt_profile},
        (
            {"standard": _host_score_callback(args.oracles), "hunt": _host_score_callback(args.oracles)}
            if args.oracles is not None
            else None
        ),
    )
    _print_json(
        {
            "comparison": f"{args.run_id}-comparison.json",
            "schedule": [list(item) for item in result.schedule],
        }
    )
    return 0 if all(item.comparable for item in result.comparisons) else 2


def _run_inputs(args: argparse.Namespace) -> tuple[object, FrozenControls, ExecutionPolicy]:
    manifest = load_manifest(args.manifest)
    try:
        controls_value = json.loads(args.controls.read_text(encoding="utf-8"))
        policy_value = json.loads(args.execution_policy.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise CliError("run inputs must contain valid JSON") from error
    controls = FrozenControls.from_json(controls_value)
    if not isinstance(policy_value, dict) or set(policy_value) != {"allowed_command_prefixes"}:
        raise CliError("execution policy must contain only allowed_command_prefixes")
    raw_prefixes = policy_value["allowed_command_prefixes"]
    if not isinstance(raw_prefixes, list):
        raise CliError("allowed_command_prefixes must be an array")
    prefixes: list[tuple[str, ...]] = []
    for prefix in raw_prefixes:
        if not isinstance(prefix, list):
            raise CliError("each allowed command prefix must be an array")
        prefixes.append(tuple(prefix))
    return manifest, controls, ExecutionPolicy(tuple(prefixes))


def _codex_adapter(
    args: argparse.Namespace,
    controls: FrozenControls,
    workflow: str,
    profile: str,
    *,
    allowed_command_prefixes: tuple[tuple[str, ...], ...],
) -> CodexExecAdapter:
    return CodexExecAdapter(
        runtime=ContainerRuntime(controls.image_digest),
        auth_supplier=lambda: load_managed_chatgpt_auth(args.auth),
        workflow=workflow,
        profile=profile,
        model=controls.model,
        reasoning_effort=controls.reasoning_effort,
        allowed_command_prefixes=allowed_command_prefixes,
    )


def _host_score_callback(oracles_path: Path):
    oracles = load_oracles(oracles_path)

    def score(predictions_path: Path) -> dict[str, object]:
        result = score_run(oracles, load_predictions(predictions_path)).to_json()
        return {key: value for key, value in result.items() if key != "tasks"}

    return score


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
