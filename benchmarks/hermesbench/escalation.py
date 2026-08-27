# Decides when the full HermesBench is required.

from __future__ import annotations

import math
from dataclasses import dataclass, replace

MIN_FULL_VULNERABLE_TASKS = 144
MIN_ADDED_DIVERSITY_AXES = 3
MAX_CATEGORY_RECALL_REGRESSION = -0.05


@dataclass(frozen=True)
class MiniEvidence:
    ci_low: float | None
    ci_high: float | None
    hidden_additional_localized: int
    repeat_winners: tuple[str, ...]
    category_recall_deltas: tuple[tuple[str, float], ...]
    comparison_semantics_changed: bool = False
    final_stage: bool = False
    release_candidate: bool = False
    public_performance_claim: bool = False

    def __post_init__(self) -> None:
        for name, value in (("ci_low", self.ci_low), ("ci_high", self.ci_high)):
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError(f"{name} must be a finite number or null")
        if (
            self.ci_low is not None
            and self.ci_high is not None
            and self.ci_low > self.ci_high
        ):
            raise ValueError("confidence interval bounds must be ordered")
        _require_non_negative_integer(
            self.hidden_additional_localized, "hidden_additional_localized"
        )
        if not self.repeat_winners or any(
            not isinstance(winner, str) or not winner.strip()
            for winner in self.repeat_winners
        ):
            raise ValueError("repeat_winners must contain non-empty workflow names")
        categories: set[str] = set()
        for category, delta in self.category_recall_deltas:
            if not isinstance(category, str) or not category.strip():
                raise ValueError("category names must be non-empty strings")
            if category in categories:
                raise ValueError("category_recall_deltas must contain unique categories")
            categories.add(category)
            if (
                isinstance(delta, bool)
                or not isinstance(delta, (int, float))
                or not math.isfinite(delta)
            ):
                raise ValueError("category recall deltas must be finite numbers")
        for name, value in (
            ("comparison_semantics_changed", self.comparison_semantics_changed),
            ("final_stage", self.final_stage),
            ("release_candidate", self.release_candidate),
            ("public_performance_claim", self.public_performance_claim),
        ):
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be a boolean")

    def replace(self, **changes: object) -> "MiniEvidence":
        return replace(self, **changes)


@dataclass(frozen=True)
class EscalationDecision:
    full_required: bool
    reasons: tuple[str, ...]


def decide_escalation(evidence: MiniEvidence) -> EscalationDecision:
    reasons: list[str] = []
    if evidence.final_stage:
        reasons.append("final_stage")
    if evidence.release_candidate:
        reasons.append("release_candidate")
    if evidence.public_performance_claim:
        reasons.append("public_performance_claim")
    if evidence.ci_low is None or evidence.ci_high is None:
        reasons.append("missing_confidence_interval")
    elif evidence.ci_low <= 0 <= evidence.ci_high:
        reasons.append("confidence_interval_includes_zero")
    if evidence.hidden_additional_localized < 2:
        reasons.append("hidden_gain_below_two")
    if len(set(evidence.repeat_winners)) > 1:
        reasons.append("repeat_winner_instability")
    if any(
        delta < MAX_CATEGORY_RECALL_REGRESSION
        for _, delta in evidence.category_recall_deltas
    ):
        reasons.append("category_recall_regression")
    if evidence.comparison_semantics_changed:
        reasons.append("comparison_semantics_changed")
    return EscalationDecision(full_required=bool(reasons), reasons=tuple(reasons))


def full_readiness_failures(
    vulnerable_tasks: int, added_diversity_axes: int
) -> tuple[str, ...]:
    _require_non_negative_integer(vulnerable_tasks, "vulnerable_tasks")
    _require_non_negative_integer(added_diversity_axes, "added_diversity_axes")
    failures: list[str] = []
    if vulnerable_tasks < MIN_FULL_VULNERABLE_TASKS:
        failures.append("full_task_count_below_144")
    if added_diversity_axes < MIN_ADDED_DIVERSITY_AXES:
        failures.append("full_diversity_axes_below_3")
    return tuple(failures)


def _require_non_negative_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value
