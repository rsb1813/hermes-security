# Scores defensive vulnerability localization predictions.

from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache

from .contracts import Finding, GoldPath, Location, OracleTask, Split, TaskPrediction

DEFAULT_LINE_TOLERANCE = 5


class ScoringError(ValueError):
    """Signals an invalid scoring request."""


@dataclass(frozen=True)
class TaskScore:
    task_id: str
    kind: str
    group_id: str
    split: Split
    category: str
    pair_true_positives: int
    pair_false_positives: int
    pair_false_negatives: int
    trace_true_positives: int
    trace_false_positives: int
    trace_false_negatives: int
    advisory_detected: bool
    fixed_true_negatives: int
    fixed_false_positives: int
    provisional_findings: int

    def to_json(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScoreMetrics:
    pair_true_positives: int
    pair_false_positives: int
    pair_false_negatives: int
    pair_localization_f1: float
    advisories_detected: int
    vulnerable_tasks: int
    advisory_recall: float
    trace_true_positives: int
    trace_false_positives: int
    trace_false_negatives: int
    trace_node_f1: float
    fixed_true_negatives: int
    fixed_false_positives: int
    fixed_snapshot_specificity: float
    provisional_findings: int
    composite_score: float

    def to_json(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SplitScore(ScoreMetrics):
    split: Split


@dataclass(frozen=True)
class RunScore(ScoreMetrics):
    tasks: tuple[TaskScore, ...]
    split_scores: tuple[SplitScore, ...]


@dataclass(frozen=True)
class _Matching:
    assignments: tuple[tuple[int, int], ...]
    trace_matches: int
    path_ids: tuple[str, ...]


def location_matches(
    left: Location,
    right: Location,
    tolerance: int = DEFAULT_LINE_TOLERANCE,
) -> bool:
    _validate_line_tolerance(tolerance)
    if left.path != right.path:
        return False
    if left.end_line < right.start_line:
        distance = right.start_line - left.end_line
    elif right.end_line < left.start_line:
        distance = left.start_line - right.end_line
    else:
        distance = 0
    return distance <= tolerance


def pair_matches(
    finding: Finding,
    path: GoldPath,
    tolerance: int = DEFAULT_LINE_TOLERANCE,
) -> bool:
    return location_matches(finding.entry_point, path.entry_point, tolerance) and location_matches(
        finding.critical_operation, path.critical_operation, tolerance
    )


def score_run(
    oracles: dict[str, OracleTask],
    predictions: dict[str, TaskPrediction],
    line_tolerance: int = DEFAULT_LINE_TOLERANCE,
) -> RunScore:
    _validate_line_tolerance(line_tolerance)
    if not oracles:
        raise ScoringError("oracles must not be empty")
    _validate_task_maps(oracles, predictions)

    task_scores = tuple(
        _score_task(
            oracle,
            predictions.get(task_id, TaskPrediction(task_id=task_id, findings=())),
            line_tolerance,
        )
        for task_id, oracle in sorted(oracles.items())
    )

    overall = _aggregate_metrics(task_scores)
    split_scores = tuple(
        SplitScore(
            split=split,
            **asdict(
                _aggregate_metrics(
                    tuple(task for task in task_scores if task.split == split)
                )
            ),
        )
        for split in sorted({task.split for task in task_scores})
    )

    return RunScore(
        tasks=task_scores,
        split_scores=split_scores,
        **asdict(overall),
    )


def _aggregate_metrics(task_scores: tuple[TaskScore, ...]) -> ScoreMetrics:
    pair_true_positives = sum(task.pair_true_positives for task in task_scores)
    pair_false_positives = sum(task.pair_false_positives for task in task_scores)
    pair_false_negatives = sum(task.pair_false_negatives for task in task_scores)
    trace_true_positives = sum(task.trace_true_positives for task in task_scores)
    trace_false_positives = sum(task.trace_false_positives for task in task_scores)
    trace_false_negatives = sum(task.trace_false_negatives for task in task_scores)
    advisories_detected = sum(task.advisory_detected for task in task_scores)
    vulnerable_tasks = sum(task.kind == "vulnerable" for task in task_scores)
    fixed_true_negatives = sum(task.fixed_true_negatives for task in task_scores)
    fixed_false_positives = sum(task.fixed_false_positives for task in task_scores)
    provisional_findings = sum(task.provisional_findings for task in task_scores)

    pair_f1 = _f1(pair_true_positives, pair_false_positives, pair_false_negatives)
    trace_f1 = _f1(trace_true_positives, trace_false_positives, trace_false_negatives)
    advisory_recall = (
        advisories_detected / vulnerable_tasks if vulnerable_tasks else 1.0
    )
    fixed_denominator = fixed_true_negatives + fixed_false_positives
    specificity = (
        fixed_true_negatives / fixed_denominator if fixed_denominator else 1.0
    )

    return ScoreMetrics(
        pair_true_positives=pair_true_positives,
        pair_false_positives=pair_false_positives,
        pair_false_negatives=pair_false_negatives,
        pair_localization_f1=pair_f1,
        advisories_detected=advisories_detected,
        vulnerable_tasks=vulnerable_tasks,
        advisory_recall=advisory_recall,
        trace_true_positives=trace_true_positives,
        trace_false_positives=trace_false_positives,
        trace_false_negatives=trace_false_negatives,
        trace_node_f1=trace_f1,
        fixed_true_negatives=fixed_true_negatives,
        fixed_false_positives=fixed_false_positives,
        fixed_snapshot_specificity=specificity,
        provisional_findings=provisional_findings,
        composite_score=_composite(pair_f1, advisory_recall, trace_f1, specificity),
    )


def _validate_task_maps(
    oracles: dict[str, OracleTask], predictions: dict[str, TaskPrediction]
) -> None:
    for task_id, oracle in oracles.items():
        if task_id != oracle.task_id:
            raise ScoringError(f"oracle map key does not match task_id: {task_id}")
    unknown = sorted(set(predictions) - set(oracles))
    if unknown:
        raise ScoringError(f"prediction references unknown task: {unknown[0]}")
    for task_id, prediction in predictions.items():
        if task_id != prediction.task_id:
            raise ScoringError(f"prediction map key does not match task_id: {task_id}")


def _validate_line_tolerance(tolerance: int) -> None:
    if isinstance(tolerance, bool) or not isinstance(tolerance, int) or tolerance < 0:
        raise ScoringError("line tolerance must be a non-negative integer")


def _score_task(
    oracle: OracleTask, prediction: TaskPrediction, tolerance: int
) -> TaskScore:
    if oracle.kind == "vulnerable":
        matching = _best_matching(prediction.findings, oracle.paths, tolerance)
        pair_true_positives = len(matching.assignments)
        trace_true_positives = matching.trace_matches
        return TaskScore(
            task_id=oracle.task_id,
            kind=oracle.kind,
            group_id=oracle.group_id,
            split=oracle.split,
            category=oracle.category,
            pair_true_positives=pair_true_positives,
            pair_false_positives=len(prediction.findings) - pair_true_positives,
            pair_false_negatives=len(oracle.paths) - pair_true_positives,
            trace_true_positives=trace_true_positives,
            trace_false_positives=sum(
                len(finding.trace) for finding in prediction.findings
            )
            - trace_true_positives,
            trace_false_negatives=sum(len(path.trace) for path in oracle.paths)
            - trace_true_positives,
            advisory_detected=pair_true_positives > 0,
            fixed_true_negatives=0,
            fixed_false_positives=0,
            provisional_findings=0,
        )

    if oracle.kind == "fixed":
        target_predictions = tuple(
            finding
            for finding in prediction.findings
            if any(pair_matches(finding, path, tolerance) for path in oracle.retired_paths)
        )
        target_false_positive = bool(target_predictions)
        return TaskScore(
            task_id=oracle.task_id,
            kind=oracle.kind,
            group_id=oracle.group_id,
            split=oracle.split,
            category=oracle.category,
            pair_true_positives=0,
            pair_false_positives=0,
            pair_false_negatives=0,
            trace_true_positives=0,
            trace_false_positives=0,
            trace_false_negatives=0,
            advisory_detected=False,
            fixed_true_negatives=0 if target_false_positive else 1,
            fixed_false_positives=1 if target_false_positive else 0,
            provisional_findings=len(prediction.findings) - len(target_predictions),
        )

    return TaskScore(
        task_id=oracle.task_id,
        kind=oracle.kind,
        group_id=oracle.group_id,
        split=oracle.split,
        category=oracle.category,
        pair_true_positives=0,
        pair_false_positives=0,
        pair_false_negatives=0,
        trace_true_positives=0,
        trace_false_positives=0,
        trace_false_negatives=0,
        advisory_detected=False,
        fixed_true_negatives=0,
        fixed_false_positives=0,
        provisional_findings=len(prediction.findings),
    )


def _best_matching(
    findings: tuple[Finding, ...], paths: tuple[GoldPath, ...], tolerance: int
) -> _Matching:
    ordered_paths = tuple(sorted(enumerate(paths), key=lambda item: item[1].path_id))

    @lru_cache(maxsize=None)
    def search(finding_index: int, used_paths: int) -> _Matching:
        if finding_index == len(findings):
            return _Matching(assignments=(), trace_matches=0, path_ids=())

        best = search(finding_index + 1, used_paths)
        finding = findings[finding_index]
        for ordered_index, (path_index, path) in enumerate(ordered_paths):
            path_bit = 1 << ordered_index
            if used_paths & path_bit or not pair_matches(finding, path, tolerance):
                continue
            tail = search(finding_index + 1, used_paths | path_bit)
            candidate = _Matching(
                assignments=((finding_index, path_index), *tail.assignments),
                trace_matches=_trace_lcs(finding.trace, path.trace, tolerance)
                + tail.trace_matches,
                path_ids=(path.path_id, *tail.path_ids),
            )
            if _matching_is_better(candidate, best):
                best = candidate
        return best

    return search(0, 0)


def _matching_is_better(candidate: _Matching, current: _Matching) -> bool:
    if len(candidate.assignments) != len(current.assignments):
        return len(candidate.assignments) > len(current.assignments)
    if candidate.trace_matches != current.trace_matches:
        return candidate.trace_matches > current.trace_matches
    return candidate.path_ids < current.path_ids


def _trace_lcs(
    predicted: tuple[Location, ...], gold: tuple[Location, ...], tolerance: int
) -> int:
    @lru_cache(maxsize=None)
    def visit(predicted_index: int, gold_index: int) -> int:
        if predicted_index == len(predicted) or gold_index == len(gold):
            return 0
        if location_matches(predicted[predicted_index], gold[gold_index], tolerance):
            return 1 + visit(predicted_index + 1, gold_index + 1)
        return max(
            visit(predicted_index + 1, gold_index),
            visit(predicted_index, gold_index + 1),
        )

    return visit(0, 0)


def _f1(true_positives: int, false_positives: int, false_negatives: int) -> float:
    denominator = 2 * true_positives + false_positives + false_negatives
    return 1.0 if denominator == 0 else 2 * true_positives / denominator


def _composite(
    pair_f1: float, advisory_recall: float, trace_f1: float, specificity: float
) -> float:
    return (
        0.40 * pair_f1
        + 0.25 * advisory_recall
        + 0.20 * trace_f1
        + 0.15 * specificity
    )
