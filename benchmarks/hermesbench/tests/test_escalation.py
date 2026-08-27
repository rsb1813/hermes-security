# Verifies Mini-to-Full promotion rules.

from __future__ import annotations

import unittest

from benchmarks.hermesbench.escalation import (
    MiniEvidence,
    decide_escalation,
    full_readiness_failures,
)


BASE = MiniEvidence(
    ci_low=0.01,
    ci_high=0.08,
    hidden_additional_localized=2,
    repeat_winners=("hunt", "hunt", "hunt"),
    category_recall_deltas=(("python", 0.0),),
)


class EscalationTests(unittest.TestCase):
    def test_decisive_mini_evidence_does_not_require_full_for_iteration(self) -> None:
        self.assertEqual(
            decide_escalation(BASE).reasons,
            (),
        )

    def test_each_inconclusive_or_mandatory_signal_requires_full(self) -> None:
        cases = {
            "confidence_interval_includes_zero": BASE.replace(
                ci_low=-0.01, ci_high=0.04
            ),
            "missing_confidence_interval": BASE.replace(ci_low=None),
            "hidden_gain_below_two": BASE.replace(hidden_additional_localized=1),
            "repeat_winner_instability": BASE.replace(
                repeat_winners=("hunt", "standard", "hunt")
            ),
            "category_recall_regression": BASE.replace(
                category_recall_deltas=(("python", -0.051),)
            ),
            "comparison_semantics_changed": BASE.replace(
                comparison_semantics_changed=True
            ),
            "final_stage": BASE.replace(final_stage=True),
            "release_candidate": BASE.replace(release_candidate=True),
            "public_performance_claim": BASE.replace(public_performance_claim=True),
        }
        for reason, evidence in cases.items():
            with self.subTest(reason=reason):
                decision = decide_escalation(evidence)
                self.assertTrue(decision.full_required)
                self.assertIn(reason, decision.reasons)

    def test_five_percentage_point_category_drop_is_not_overtriggered(self) -> None:
        evidence = BASE.replace(category_recall_deltas=(("python", -0.05),))
        self.assertNotIn(
            "category_recall_regression", decide_escalation(evidence).reasons
        )

    def test_invalid_confidence_interval_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "ordered"):
            BASE.replace(ci_low=0.2, ci_high=0.1)


class FullReadinessTests(unittest.TestCase):
    def test_full_requires_144_vulnerable_tasks_and_three_new_axes(self) -> None:
        self.assertEqual(
            full_readiness_failures(vulnerable_tasks=143, added_diversity_axes=2),
            ("full_task_count_below_144", "full_diversity_axes_below_3"),
        )
        self.assertEqual(
            full_readiness_failures(vulnerable_tasks=144, added_diversity_axes=3),
            (),
        )

    def test_negative_readiness_counts_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-negative"):
            full_readiness_failures(vulnerable_tasks=-1, added_diversity_axes=3)


if __name__ == "__main__":
    unittest.main()
