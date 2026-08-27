# HermesBench Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reproducible, defensive benchmark foundation that imports reviewed VulnGym labels, scores bounded source-to-operation findings, records comparable usage receipts, audits agent-visible bundles for label leakage, and escalates inconclusive Mini results to the full HermesBench.

**Architecture:** A standalone Python standard-library package lives under `benchmarks/hermesbench` so it does not change the public Codex Security CLI or SDK. Strict dataclass contracts feed a deterministic scorer, run-receipt comparator, escalation engine, bundle auditor, and VulnGym importer; a small Bun integration test makes the repository's existing test command exercise the Python boundary.

**Tech Stack:** Python 3.10+ standard library, `unittest`, JSON/JSONL, HMAC-SHA256, Bun tests, TypeScript test fixtures, Git.

**Spec:** `docs/superpowers/specs/2026-08-27-hermes-security-design.md`

## Global Constraints

- Keep the existing Standard workflow, npm package name, executable, public CLI arguments, SDK types, and defaults unchanged.
- Do not generate exploits, proof-of-concept payloads, flags, crash-triggering inputs, or outbound target traffic.
- A prediction contains at most five findings per task.
- Endpoint matching is path-exact after normalization and line-tolerant by at most five lines.
- Record cached input, uncached input, and output tokens as separate non-negative integers.
- Public Dev and Canary results are diagnostic; promotion evidence comes from unseen groups.
- Final or release comparisons always require the full HermesBench.
- Generated repositories, hidden oracles, private keys, and third-party source snapshots never enter Git.
- New Python and TypeScript source comments and docstrings are English.
- Python implementation uses only the standard library in this milestone.

## File Structure

- `benchmarks/__init__.py` makes the benchmark tree importable from repository-root commands.
- `benchmarks/hermesbench/__init__.py` exports the benchmark and grader versions.
- `benchmarks/hermesbench/contracts.py` parses and validates manifests, grader-only oracles, and bounded predictions.
- `benchmarks/hermesbench/scoring.py` performs endpoint, trace, advisory, fixed-negative, and composite scoring.
- `benchmarks/hermesbench/receipts.py` writes stable run receipts and rejects uncontrolled comparisons.
- `benchmarks/hermesbench/escalation.py` applies Mini-to-Full triggers and Full readiness gates.
- `benchmarks/hermesbench/sanitize.py` audits agent-visible bundles without rewriting source code.
- `benchmarks/hermesbench/corpus.py` imports `verify=1` VulnGym rows and creates keyed anonymous candidate records.
- `benchmarks/hermesbench/cli.py` exposes the standalone benchmark commands.
- `benchmarks/hermesbench/__main__.py` supports `python -m benchmarks.hermesbench`.
- `benchmarks/hermesbench/tests/` contains direct standard-library unit and integration tests.
- `sdk/typescript/tests-ts/hermesbench.test.ts` executes the Python test suite and CLI through the repository's Bun suite.
- `.gitignore` excludes generated benchmark work, hidden data, keys, and snapshots.
- `benchmarks/hermesbench/README.md` documents safe preparation and offline scoring.

---

### Task 1: Versioned contracts for manifests, oracles, and predictions

**Files:**
- Create: `benchmarks/__init__.py`
- Create: `benchmarks/hermesbench/__init__.py`
- Create: `benchmarks/hermesbench/contracts.py`
- Create: `benchmarks/hermesbench/tests/__init__.py`
- Create: `benchmarks/hermesbench/tests/test_contracts.py`

**Interfaces:**
- Consumes: JSON objects and JSONL files using schema version `1`.
- Produces: `Location`, `GoldPath`, `Finding`, `OracleTask`, `TaskPrediction`, `TaskDescriptor`, `BenchmarkManifest`, `load_oracles(Path)`, and `load_predictions(Path)`.

- [ ] **Step 1: Write failing contract tests**

```python
# Verifies strict HermesBench data contracts.

import unittest

from benchmarks.hermesbench.contracts import ContractError, Location, parse_oracle, parse_prediction


class ContractTests(unittest.TestCase):
    def test_location_accepts_vulngym_line_ranges(self) -> None:
        self.assertEqual(
            Location.from_json({"file": "src/auth.py", "line": "41-43"}),
            Location(path="src/auth.py", start_line=41, end_line=43),
        )

    def test_prediction_rejects_more_than_five_findings(self) -> None:
        finding = {
            "finding_id": "f-1",
            "entry_point": {"file": "src/api.py", "line": 10},
            "critical_operation": {"file": "src/db.py", "line": 20},
            "trace": [],
            "confidence": 0.8,
        }
        with self.assertRaisesRegex(ContractError, "at most 5 findings"):
            parse_prediction(
                {"schema_version": 1, "task_id": "hb-task", "findings": [finding] * 6}
            )

    def test_location_rejects_parent_traversal(self) -> None:
        with self.assertRaisesRegex(ContractError, "repository-relative"):
            Location.from_json({"file": "../secret.py", "line": 1})
```

- [ ] **Step 2: Run the contract tests and verify RED**

Run: `python -m unittest benchmarks.hermesbench.tests.test_contracts -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'benchmarks.hermesbench.contracts'`.

- [ ] **Step 3: Implement the minimal strict contracts**

```python
# Defines versioned HermesBench data contracts.

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

SCHEMA_VERSION = 1
MAX_FINDINGS = 5


class ContractError(ValueError):
    pass


@dataclass(frozen=True)
class Location:
    path: str
    start_line: int
    end_line: int

    @classmethod
    def from_json(cls, value: object) -> "Location":
        if not isinstance(value, dict):
            raise ContractError("location must be an object")
        raw_path = value.get("file")
        if not isinstance(raw_path, str) or not raw_path:
            raise ContractError("location file must be a non-empty string")
        normalized = raw_path.replace("\\", "/")
        pure = PurePosixPath(normalized)
        if pure.is_absolute() or ".." in pure.parts:
            raise ContractError("location file must be repository-relative")
        raw_line = value.get("line")
        if isinstance(raw_line, bool):
            raise ContractError("location line must be positive")
        if isinstance(raw_line, int):
            start = end = raw_line
        elif isinstance(raw_line, str) and raw_line.count("-") == 1:
            left, right = raw_line.split("-", 1)
            if not left.isdigit() or not right.isdigit():
                raise ContractError("location range must contain integers")
            start, end = int(left), int(right)
        else:
            raise ContractError("location line must be an integer or range")
        if start < 1 or end < start:
            raise ContractError("location line must be positive and ordered")
        return cls(path=str(pure), start_line=start, end_line=end)
```

Use these exact immutable interfaces for the rest of the contract.

```python
Split = Literal["public_dev", "hidden_test", "rotating_audit", "full_holdout"]
TaskKind = Literal["vulnerable", "fixed", "clean"]


@dataclass(frozen=True)
class GoldPath:
    path_id: str
    entry_point: Location
    critical_operation: Location
    trace: tuple[Location, ...]


@dataclass(frozen=True)
class Finding:
    finding_id: str
    entry_point: Location
    critical_operation: Location
    trace: tuple[Location, ...]
    confidence: float


@dataclass(frozen=True)
class OracleTask:
    task_id: str
    kind: TaskKind
    group_id: str
    split: Split
    category: str
    language: str
    paths: tuple[GoldPath, ...]
    retired_paths: tuple[GoldPath, ...]


@dataclass(frozen=True)
class TaskPrediction:
    task_id: str
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class TaskDescriptor:
    task_id: str
    snapshot_sha256: str
    language: str
    allowed_commands: tuple[tuple[str, ...], ...]
    time_limit_seconds: int


@dataclass(frozen=True)
class BenchmarkManifest:
    schema_version: int
    suite: Literal["canary", "mini", "full"]
    manifest_id: str
    tasks: tuple[TaskDescriptor, ...]
```

`parse_prediction()` requires the exact top-level fields `schema_version`, `task_id`, and `findings`; it rejects unsupported schema versions, duplicate finding IDs, confidence outside `0.0..1.0`, and more than five findings. `parse_oracle()` requires non-empty `paths` for `vulnerable`, non-empty `retired_paths` for `fixed`, and empty path collections for `clean`. `load_oracles()` and `load_predictions()` parse non-empty JSONL lines and reject duplicate task IDs.

- [ ] **Step 4: Add tests for every oracle-kind invariant and JSONL duplicate task IDs**

```python
    def test_fixed_oracle_requires_a_retired_path(self) -> None:
        with self.assertRaisesRegex(ContractError, "retired_paths"):
            parse_oracle(
                {
                    "schema_version": 1,
                    "task_id": "hb-fixed",
                    "kind": "fixed",
                    "group_id": "group-a",
                    "split": "hidden_test",
                    "category": "authorization",
                    "language": "python",
                    "paths": [],
                    "retired_paths": [],
                }
            )
```

- [ ] **Step 5: Run the focused contract suite and verify GREEN**

Run: `python -m unittest benchmarks.hermesbench.tests.test_contracts -v`

Expected: all contract tests pass with no warnings.

- [ ] **Step 6: Commit the contract unit**

```bash
git add benchmarks/__init__.py benchmarks/hermesbench/__init__.py benchmarks/hermesbench/contracts.py benchmarks/hermesbench/tests/__init__.py benchmarks/hermesbench/tests/test_contracts.py
git commit -m "feat: add HermesBench data contracts"
```

---

### Task 2: Precision-aware endpoint and trace scorer

**Files:**
- Create: `benchmarks/hermesbench/scoring.py`
- Create: `benchmarks/hermesbench/tests/test_scoring.py`

**Interfaces:**
- Consumes: `dict[str, OracleTask]`, `dict[str, TaskPrediction]`, line tolerance, and finding cap from Task 1.
- Produces: `TaskScore`, `RunScore`, `location_matches()`, and `score_run()` with JSON-serializable `to_json()` output.

- [ ] **Step 1: Write failing tests for strict endpoint pairing and one-to-one matching**

```python
# Verifies HermesBench scoring behavior.

import unittest

from benchmarks.hermesbench.contracts import parse_oracle, parse_prediction
from benchmarks.hermesbench.scoring import score_run


def location(path: str, line: int) -> dict[str, object]:
    return {"file": path, "line": line}


GOLD_PATH = {
    "path_id": "path-1",
    "entry_point": location("src/api.py", 10),
    "critical_operation": location("src/db.py", 20),
    "trace": [location("src/policy.py", 15)],
}
VULNERABLE_ORACLE = {
    "schema_version": 1,
    "task_id": "hb-vulnerable",
    "kind": "vulnerable",
    "group_id": "group-a",
    "split": "hidden_test",
    "category": "authorization",
    "language": "python",
    "paths": [GOLD_PATH],
    "retired_paths": [],
}
FIXED_ORACLE = {
    "schema_version": 1,
    "task_id": "hb-fixed",
    "kind": "fixed",
    "group_id": "group-a",
    "split": "hidden_test",
    "category": "authorization",
    "language": "python",
    "paths": [],
    "retired_paths": [GOLD_PATH],
}
FINDING = {
    "finding_id": "f-1",
    "entry_point": location("src/api.py", 10),
    "critical_operation": location("src/db.py", 20),
    "trace": [location("src/policy.py", 15)],
    "confidence": 0.9,
}


def score_fixture_with_trace(
    gold_trace: list[dict[str, object]], predicted_trace: list[dict[str, object]]
):
    oracle = parse_oracle(VULNERABLE_ORACLE | {"paths": [GOLD_PATH | {"trace": gold_trace}]})
    fixed = parse_oracle(FIXED_ORACLE)
    prediction = parse_prediction(
        {
            "schema_version": 1,
            "task_id": "hb-vulnerable",
            "findings": [FINDING | {"trace": predicted_trace}],
        }
    )
    empty_fixed = parse_prediction(
        {"schema_version": 1, "task_id": "hb-fixed", "findings": []}
    )
    return score_run(
        {"hb-vulnerable": oracle, "hb-fixed": fixed},
        {"hb-vulnerable": prediction, "hb-fixed": empty_fixed},
    )


def score_fixture_with_fixed_prediction(finding: dict[str, object]):
    oracle = parse_oracle(VULNERABLE_ORACLE)
    fixed = parse_oracle(FIXED_ORACLE)
    vulnerable_prediction = parse_prediction(
        {"schema_version": 1, "task_id": "hb-vulnerable", "findings": [FINDING]}
    )
    fixed_prediction = parse_prediction(
        {"schema_version": 1, "task_id": "hb-fixed", "findings": [finding]}
    )
    return score_run(
        {"hb-vulnerable": oracle, "hb-fixed": fixed},
        {"hb-vulnerable": vulnerable_prediction, "hb-fixed": fixed_prediction},
    )


class ScoringTests(unittest.TestCase):
    def test_duplicate_predictions_do_not_inflate_pair_recall(self) -> None:
        oracle = parse_oracle(VULNERABLE_ORACLE)
        fixed = parse_oracle(FIXED_ORACLE)
        duplicate = FINDING | {"finding_id": "f-2"}
        vulnerable_prediction = parse_prediction(
            {
                "schema_version": 1,
                "task_id": "hb-vulnerable",
                "findings": [FINDING, duplicate],
            }
        )
        fixed_prediction = parse_prediction(
            {"schema_version": 1, "task_id": "hb-fixed", "findings": []}
        )

        result = score_run(
            {"hb-vulnerable": oracle, "hb-fixed": fixed},
            {"hb-vulnerable": vulnerable_prediction, "hb-fixed": fixed_prediction},
        )

        self.assertEqual(result.pair_true_positives, 1)
        self.assertEqual(result.pair_false_positives, 1)
        self.assertEqual(result.pair_false_negatives, 0)
        self.assertAlmostEqual(result.pair_localization_f1, 2 / 3)
```

- [ ] **Step 2: Run the scorer test and verify RED**

Run: `python -m unittest benchmarks.hermesbench.tests.test_scoring -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'benchmarks.hermesbench.scoring'`.

- [ ] **Step 3: Implement path normalization, line-range distance, and bounded maximum matching**

```python
# Scores defensive vulnerability localization predictions.

from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache

from .contracts import Finding, GoldPath, Location, OracleTask, TaskPrediction

DEFAULT_LINE_TOLERANCE = 5


def location_matches(left: Location, right: Location, tolerance: int) -> bool:
    if left.path != right.path:
        return False
    if left.end_line < right.start_line:
        distance = right.start_line - left.end_line
    elif right.end_line < left.start_line:
        distance = left.start_line - right.end_line
    else:
        distance = 0
    return distance <= tolerance


def pair_matches(finding: Finding, path: GoldPath, tolerance: int) -> bool:
    return location_matches(finding.entry_point, path.entry_point, tolerance) and location_matches(
        finding.critical_operation, path.critical_operation, tolerance
    )
```

Implement `_best_matching()` as memoized recursion over the at-most-five predictions. It may skip a prediction or assign it to one unused compatible gold path. Compare candidate assignments by matched-pair count first, ordered trace-node matches second, and deterministic path IDs third.

- [ ] **Step 4: Write failing tests for ordered trace scoring and fixed specificity**

```python
    def test_reversed_trace_nodes_receive_partial_trace_credit(self) -> None:
        result = score_fixture_with_trace(
            gold_trace=[location("src/a.py", 1), location("src/b.py", 2)],
            predicted_trace=[location("src/b.py", 2), location("src/a.py", 1)],
        )
        self.assertAlmostEqual(result.trace_node_f1, 0.5)

    def test_retired_path_prediction_reduces_fixed_specificity(self) -> None:
        result = score_fixture_with_fixed_prediction(FINDING)
        self.assertEqual(result.fixed_true_negatives, 0)
        self.assertEqual(result.fixed_false_positives, 1)
        self.assertEqual(result.fixed_snapshot_specificity, 0.0)

    def test_unrelated_fixed_snapshot_finding_requires_adjudication(self) -> None:
        unrelated = FINDING | {
            "entry_point": {"file": "src/other.py", "line": 3},
            "critical_operation": {"file": "src/other.py", "line": 9},
        }
        result = score_fixture_with_fixed_prediction(unrelated)
        self.assertEqual(result.fixed_snapshot_specificity, 1.0)
        self.assertEqual(result.provisional_findings, 1)
```

- [ ] **Step 5: Implement ordered trace LCS and the composite score**

```python
def _f1(true_positives: int, false_positives: int, false_negatives: int) -> float:
    denominator = 2 * true_positives + false_positives + false_negatives
    return 1.0 if denominator == 0 else 2 * true_positives / denominator


def _composite(pair_f1: float, advisory_recall: float, trace_f1: float, specificity: float) -> float:
    return 0.40 * pair_f1 + 0.25 * advisory_recall + 0.20 * trace_f1 + 0.15 * specificity
```

For matched pairs, compute trace true positives with longest-common-subsequence matching under `location_matches()`. Unmatched vulnerable gold traces contribute false negatives, unmatched vulnerable prediction traces contribute false positives, and a zero trace denominator scores `1.0`. On fixed tasks, only a prediction matching a retired path is an automatic target false positive; unrelated findings increment `provisional_findings` for adjudication.

- [ ] **Step 6: Run scorer tests and the contract regression suite**

Run: `python -m unittest benchmarks.hermesbench.tests.test_scoring benchmarks.hermesbench.tests.test_contracts -v`

Expected: all tests pass.

- [ ] **Step 7: Commit the scorer unit**

```bash
git add benchmarks/hermesbench/scoring.py benchmarks/hermesbench/tests/test_scoring.py
git commit -m "feat: score HermesBench discovery results"
```

---

### Task 3: Stable run receipts and controlled comparison checks

**Files:**
- Create: `benchmarks/hermesbench/receipts.py`
- Create: `benchmarks/hermesbench/tests/test_receipts.py`

**Interfaces:**
- Consumes: workflow/profile identity, frozen run configuration, elapsed time, status, and raw token classes.
- Produces: `TokenUsage`, `RunConfig`, `RunReceipt`, `sha256_file()`, `write_receipt()`, `load_receipt()`, and `comparison_mismatches()`.

- [ ] **Step 1: Write failing receipt tests**

```python
# Verifies reproducible HermesBench run receipts.

import tempfile
import unittest
from pathlib import Path

from benchmarks.hermesbench.receipts import RunConfig, TokenUsage, comparison_mismatches


class ReceiptTests(unittest.TestCase):
    def test_token_classes_remain_separate(self) -> None:
        usage = TokenUsage(
            cached_input_tokens=1200,
            uncached_input_tokens=300,
            output_tokens=90,
        )
        self.assertEqual(
            usage.to_json(),
            {
                "cached_input_tokens": 1200,
                "uncached_input_tokens": 300,
                "output_tokens": 90,
            },
        )

    def test_comparison_rejects_different_reasoning_effort(self) -> None:
        standard = CONFIG
        hunt = CONFIG.replace(reasoning_effort="high")
        self.assertEqual(comparison_mismatches(standard, hunt), ["reasoning_effort"])
```

- [ ] **Step 2: Run the receipt tests and verify RED**

Run: `python -m unittest benchmarks.hermesbench.tests.test_receipts -v`

Expected: FAIL because `benchmarks.hermesbench.receipts` does not exist.

- [ ] **Step 3: Implement immutable config and receipt types**

```python
# Records comparable HermesBench run configuration and usage.

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class TokenUsage:
    cached_input_tokens: int
    uncached_input_tokens: int
    output_tokens: int

    def __post_init__(self) -> None:
        if min(self.cached_input_tokens, self.uncached_input_tokens, self.output_tokens) < 0:
            raise ValueError("token counts must be non-negative")

    def to_json(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class RunConfig:
    manifest_sha256: str
    task_order_sha256: str
    grader_version: str
    model: str
    reasoning_effort: str
    seed: str | None
    seed_supported: bool
    tool_versions: tuple[tuple[str, str], ...]
    time_limit_seconds: int
    max_findings: int = 5

    def replace(self, **changes: object) -> "RunConfig":
        return replace(self, **changes)
```

`comparison_mismatches()` compares every `RunConfig` field and returns sorted field names. Workflow and profile live on `RunReceipt`, so Standard and Hunt may differ only there. `write_receipt()` writes UTF-8 JSON with `sort_keys=True`, indentation, and a final newline.

- [ ] **Step 4: Add stable serialization, negative-count, and model mismatch tests**

```python
    def test_negative_tokens_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-negative"):
            TokenUsage(-1, 0, 0)

    def test_receipt_serialization_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            write_receipt(output, RECEIPT)
            first = output.read_bytes()
            write_receipt(output, RECEIPT)
            self.assertEqual(output.read_bytes(), first)
            self.assertTrue(first.endswith(b"\n"))
```

- [ ] **Step 5: Run receipt tests and verify GREEN**

Run: `python -m unittest benchmarks.hermesbench.tests.test_receipts -v`

Expected: all tests pass.

- [ ] **Step 6: Commit the receipt unit**

```bash
git add benchmarks/hermesbench/receipts.py benchmarks/hermesbench/tests/test_receipts.py
git commit -m "feat: record comparable HermesBench runs"
```

---

### Task 4: Automatic Mini-to-Full escalation and readiness gates

**Files:**
- Create: `benchmarks/hermesbench/escalation.py`
- Create: `benchmarks/hermesbench/tests/test_escalation.py`

**Interfaces:**
- Consumes: `MiniEvidence` and full-suite task/diversity counts.
- Produces: `EscalationDecision`, `decide_escalation()`, and `full_readiness_failures()`.

- [ ] **Step 1: Write failing table-driven tests for every escalation reason**

```python
# Verifies Mini-to-Full promotion rules.

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
    def test_each_inconclusive_signal_requires_full(self) -> None:
        cases = {
            "confidence_interval_includes_zero": BASE.replace(ci_low=-0.01, ci_high=0.04),
            "hidden_gain_below_two": BASE.replace(hidden_additional_localized=1),
            "repeat_winner_instability": BASE.replace(repeat_winners=("hunt", "standard", "hunt")),
            "category_recall_regression": BASE.replace(category_recall_deltas=(("python", -0.051),)),
            "comparison_semantics_changed": BASE.replace(comparison_semantics_changed=True),
            "final_stage": BASE.replace(final_stage=True),
            "release_candidate": BASE.replace(release_candidate=True),
        }
        for reason, evidence in cases.items():
            with self.subTest(reason=reason):
                self.assertIn(reason, decide_escalation(evidence).reasons)
```

- [ ] **Step 2: Run the escalation tests and verify RED**

Run: `python -m unittest benchmarks.hermesbench.tests.test_escalation -v`

Expected: FAIL because `benchmarks.hermesbench.escalation` does not exist.

- [ ] **Step 3: Implement the exact decision rules**

```python
# Decides when the full HermesBench is required.

from __future__ import annotations

from dataclasses import dataclass, replace


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
    if evidence.ci_low is None or evidence.ci_high is None:
        reasons.append("missing_confidence_interval")
    elif evidence.ci_low <= 0 <= evidence.ci_high:
        reasons.append("confidence_interval_includes_zero")
    if evidence.hidden_additional_localized < 2:
        reasons.append("hidden_gain_below_two")
    if len(set(evidence.repeat_winners)) > 1:
        reasons.append("repeat_winner_instability")
    if any(delta < -0.05 for _, delta in evidence.category_recall_deltas):
        reasons.append("category_recall_regression")
    if evidence.comparison_semantics_changed:
        reasons.append("comparison_semantics_changed")
    return EscalationDecision(full_required=bool(reasons), reasons=tuple(reasons))
```

- [ ] **Step 4: Add Full readiness tests**

```python
    def test_full_requires_144_vulnerable_tasks_and_three_new_axes(self) -> None:
        self.assertEqual(
            full_readiness_failures(vulnerable_tasks=143, added_diversity_axes=2),
            ("full_task_count_below_144", "full_diversity_axes_below_3"),
        )
        self.assertEqual(
            full_readiness_failures(vulnerable_tasks=144, added_diversity_axes=3),
            (),
        )
```

- [ ] **Step 5: Run escalation tests and verify GREEN**

Run: `python -m unittest benchmarks.hermesbench.tests.test_escalation -v`

Expected: all tests pass.

- [ ] **Step 6: Commit the escalation unit**

```bash
git add benchmarks/hermesbench/escalation.py benchmarks/hermesbench/tests/test_escalation.py
git commit -m "feat: escalate inconclusive HermesBench runs"
```

---

### Task 5: Agent-visible bundle leakage audit

**Files:**
- Create: `benchmarks/hermesbench/sanitize.py`
- Create: `benchmarks/hermesbench/tests/test_sanitize.py`

**Interfaces:**
- Consumes: a prepared agent-visible task directory.
- Produces: `BundleViolation`, `audit_bundle(Path)`, and `tree_sha256(Path)`.

- [ ] **Step 1: Write failing tests for concrete contamination paths**

```python
# Verifies benchmark bundle contamination detection.

import tempfile
import unittest
from pathlib import Path

from benchmarks.hermesbench.sanitize import audit_bundle


class SanitizeTests(unittest.TestCase):
    def test_git_history_and_advisory_ids_contaminate_a_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            (root / "src").mkdir()
            (root / "src" / "handler.py").write_text(
                "# Fixed in CVE-2026-12345\n", encoding="utf-8"
            )
            codes = {violation.code for violation in audit_bundle(root)}
            self.assertEqual(codes, {"git_metadata", "advisory_identifier"})

    def test_clean_source_is_not_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "handler.py"
            source.write_bytes(b"def handle(value):\n    return value\n")
            before = source.read_bytes()
            self.assertEqual(audit_bundle(root), ())
            self.assertEqual(source.read_bytes(), before)
```

- [ ] **Step 2: Run the sanitizer tests and verify RED**

Run: `python -m unittest benchmarks.hermesbench.tests.test_sanitize -v`

Expected: FAIL because `benchmarks.hermesbench.sanitize` does not exist.

- [ ] **Step 3: Implement read-only contamination checks**

```python
# Audits agent-visible benchmark bundles for label leakage.

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

ADVISORY_PATTERN = re.compile(rb"(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2})", re.I)


@dataclass(frozen=True, order=True)
class BundleViolation:
    code: str
    path: str


def audit_bundle(root: Path) -> tuple[BundleViolation, ...]:
    resolved = root.resolve()
    violations: list[BundleViolation] = []
    for path in sorted(resolved.rglob("*")):
        relative = path.relative_to(resolved).as_posix()
        if path.is_symlink():
            violations.append(BundleViolation("symbolic_link", relative))
            continue
        if ".git" in path.relative_to(resolved).parts:
            if path.name == ".git":
                violations.append(BundleViolation("git_metadata", relative))
            continue
        if path.is_file():
            data = path.read_bytes()
            if ADVISORY_PATTERN.search(data) or b"github.com/advisories/" in data.lower():
                violations.append(BundleViolation("advisory_identifier", relative))
    return tuple(sorted(set(violations)))
```

`tree_sha256()` hashes sorted relative paths, NUL separators, and file bytes. It rejects symlinks rather than following them. Do not redact or mutate source; any violation excludes the task until corpus preparation fixes the source provenance safely.

- [ ] **Step 4: Add deterministic tree-hash and symlink tests**

```python
    def test_tree_hash_changes_when_source_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "a.py"
            source.write_text("value = 1\n", encoding="utf-8")
            first = tree_sha256(Path(directory))
            source.write_text("value = 2\n", encoding="utf-8")
            self.assertNotEqual(tree_sha256(Path(directory)), first)
```

- [ ] **Step 5: Run sanitizer tests and verify GREEN**

Run: `python -m unittest benchmarks.hermesbench.tests.test_sanitize -v`

Expected: all tests pass without modifying fixture bytes.

- [ ] **Step 6: Commit the bundle-audit unit**

```bash
git add benchmarks/hermesbench/sanitize.py benchmarks/hermesbench/tests/test_sanitize.py
git commit -m "feat: audit HermesBench bundles for label leakage"
```

---

### Task 6: Reviewed VulnGym importer and keyed anonymous IDs

**Files:**
- Create: `benchmarks/hermesbench/corpus.py`
- Create: `benchmarks/hermesbench/tests/test_corpus.py`

**Interfaces:**
- Consumes: local VulnGym `entries.jsonl`, `reports.jsonl`, pinned dataset revision, and a non-empty private HMAC key.
- Produces: `CorpusCandidate`, `load_vulngym_candidates()`, `anonymous_task_id()`, and aggregate `CorpusSummary` without exposing advisory IDs in agent-visible records.

- [ ] **Step 1: Write failing importer tests with literal synthetic VulnGym rows**

```python
# Verifies reviewed VulnGym import and anonymization.

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.hermesbench.corpus import anonymous_task_id, load_vulngym_candidates


REPORT = {
    "report_id": "GHSA-2345-6789-cfgh",
    "repo_url": "https://github.com/example/project",
    "commit": "1" * 40,
    "entry_ids": ["entry-00001", "entry-00002"],
}
VERIFIED_ENTRY = {
    "entry_id": "entry-00001",
    "report_id": REPORT["report_id"],
    "repo_url": REPORT["repo_url"],
    "commit": REPORT["commit"],
    "vuln_category_l1": "Authorization",
    "vuln_category_l2": "Missing authorization",
    "entry_point": {"file": "src/api.py", "line": 10, "code": "handle(request)"},
    "critical_operation": {"file": "src/db.py", "line": 20, "code": "save(record)"},
    "trace": [{"file": "src/policy.py", "line": 15, "code": "allow = True"}],
    "verify": 1,
}
UNVERIFIED_ENTRY = VERIFIED_ENTRY | {"entry_id": "entry-00002", "verify": 0}


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def load_fixture(entries: list[dict[str, object]], reports: list[dict[str, object]]):
    directory = tempfile.TemporaryDirectory()
    root = Path(directory.name)
    write_jsonl(root / "entries.jsonl", entries)
    write_jsonl(root / "reports.jsonl", reports)
    result = load_vulngym_candidates(
        root / "entries.jsonl",
        root / "reports.jsonl",
        dataset_revision="cd69f7e163e08485ab5496115ae03439cda6e27e",
        anonymization_key=b"fixture-key",
    )
    directory.cleanup()
    return result


class CorpusTests(unittest.TestCase):
    def test_importer_keeps_only_human_reviewed_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_jsonl(root / "reports.jsonl", [REPORT])
            write_jsonl(
                root / "entries.jsonl",
                [VERIFIED_ENTRY, UNVERIFIED_ENTRY],
            )
            candidates, summary = load_vulngym_candidates(
                root / "entries.jsonl",
                root / "reports.jsonl",
                dataset_revision="cd69f7e163e08485ab5496115ae03439cda6e27e",
                anonymization_key=b"fixture-key",
            )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(summary.verified_entries, 1)
        self.assertTrue(candidates[0].task_id.startswith("hb-"))

    def test_anonymous_id_is_keyed_and_deterministic(self) -> None:
        first = anonymous_task_id(b"key-a", "revision", "entry-00001")
        self.assertEqual(first, anonymous_task_id(b"key-a", "revision", "entry-00001"))
        self.assertNotEqual(first, anonymous_task_id(b"key-b", "revision", "entry-00001"))
        self.assertNotIn("00001", first)
```

- [ ] **Step 2: Run importer tests and verify RED**

Run: `python -m unittest benchmarks.hermesbench.tests.test_corpus -v`

Expected: FAIL because `benchmarks.hermesbench.corpus` does not exist.

- [ ] **Step 3: Implement strict join validation, `verify == 1` filtering, and HMAC IDs**

```python
# Imports reviewed VulnGym labels into private benchmark records.

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from .contracts import GoldPath, Location


def anonymous_task_id(key: bytes, dataset_revision: str, entry_id: str) -> str:
    if not key:
        raise ValueError("anonymization key must not be empty")
    message = f"{dataset_revision}\0{entry_id}".encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()[:20]
    return f"hb-{digest}"
```

`load_vulngym_candidates()` validates every referenced report, 40-character vulnerable commit, GitHub repository URL, `verify` value, and label location. It preserves `repo_url`, `commit`, `report_id`, and original entry ID only in the returned private `CorpusCandidate`; the agent-visible task descriptor is created separately and contains none of those fields.

- [ ] **Step 4: Add tests for missing reports, malformed commits, and range lines**

```python
    def test_missing_report_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing report"):
            load_fixture(entries=[VERIFIED_ENTRY], reports=[])

    def test_range_lines_survive_import(self) -> None:
        entry = VERIFIED_ENTRY | {
            "entry_point": VERIFIED_ENTRY["entry_point"] | {"line": "10-12"}
        }
        candidate = load_fixture(entries=[entry], reports=[REPORT])[0][0]
        self.assertEqual(candidate.gold_path.entry_point.start_line, 10)
        self.assertEqual(candidate.gold_path.entry_point.end_line, 12)
```

- [ ] **Step 5: Run importer tests and verify GREEN**

Run: `python -m unittest benchmarks.hermesbench.tests.test_corpus -v`

Expected: all tests pass.

- [ ] **Step 6: Commit the importer unit**

```bash
git add benchmarks/hermesbench/corpus.py benchmarks/hermesbench/tests/test_corpus.py
git commit -m "feat: import reviewed VulnGym records"
```

---

### Task 7: Standalone CLI, repository test integration, and safe storage rules

**Files:**
- Create: `benchmarks/hermesbench/cli.py`
- Create: `benchmarks/hermesbench/__main__.py`
- Create: `benchmarks/hermesbench/tests/test_cli.py`
- Create: `benchmarks/hermesbench/README.md`
- Create: `sdk/typescript/tests-ts/hermesbench.test.ts`
- Modify: `.gitignore`
- Modify: `checklist.md`
- Modify: `context-notes.md`

**Interfaces:**
- Consumes: the modules from Tasks 1-6 and local JSON/JSONL paths.
- Produces: `python -m benchmarks.hermesbench score`, `compare`, `audit-bundle`, and `import-vulngym` commands with machine-readable JSON output and nonzero exits for invalid or contaminated inputs.

- [ ] **Step 1: Write a failing CLI integration test**

```python
# Verifies the standalone HermesBench CLI.

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def test_audit_bundle_returns_nonzero_for_contamination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "source.py").write_text("# GHSA-2345-6789-cfgh\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "benchmarks.hermesbench", "audit-bundle", "--bundle", str(bundle)],
                cwd=Path(__file__).resolve().parents[3],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["violations"][0]["code"], "advisory_identifier")
```

- [ ] **Step 2: Run the CLI test and verify RED**

Run: `python -m unittest benchmarks.hermesbench.tests.test_cli -v`

Expected: FAIL because `benchmarks.hermesbench.__main__` does not exist.

- [ ] **Step 3: Implement the command parser and stable JSON output**

```python
# Exposes the standalone HermesBench command line.

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .sanitize import audit_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hermesbench")
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("audit-bundle")
    audit.add_argument("--bundle", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit-bundle":
        violations = audit_bundle(args.bundle)
        print(json.dumps({"violations": [asdict(item) for item in violations]}, sort_keys=True))
        return 2 if violations else 0
    raise AssertionError(f"unhandled command: {args.command}")
```

Add these exact subparsers in `build_parser()`.

```python
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
```

All commands write stable sorted JSON and return `2` for invalid contracts, contaminated bundles, or incomparable receipts. They never print the anonymization key or hidden oracle contents.

- [ ] **Step 4: Add a Bun test that runs the real Python suite and help entry point**

```typescript
// Verifies HermesBench through the repository's standard Bun suite.

import { join } from "node:path";
import { expect, test } from "bun:test";

const repositoryRoot = join(import.meta.dir, "..", "..", "..");

function pythonExecutable(): string | null {
  return process.env["PYTHON"] ?? Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
}

test("runs the HermesBench Python suite and CLI", () => {
  const python = pythonExecutable();
  expect(python).not.toBeNull();
  const tests = Bun.spawnSync(
    [python!, "-m", "unittest", "discover", "-s", "benchmarks/hermesbench/tests", "-v"],
    { cwd: repositoryRoot, stdout: "pipe", stderr: "pipe" },
  );
  expect(tests.exitCode, tests.stderr.toString()).toBe(0);
  const help = Bun.spawnSync([python!, "-m", "benchmarks.hermesbench", "--help"], {
    cwd: repositoryRoot,
    stdout: "pipe",
    stderr: "pipe",
  });
  expect(help.exitCode, help.stderr.toString()).toBe(0);
  expect(help.stdout.toString()).toContain("audit-bundle");
});
```

- [ ] **Step 5: Exclude private and generated benchmark material**

Append these exact rules to `.gitignore`.

```gitignore

# Never publish generated or hidden HermesBench material.
/benchmarks/hermesbench/work/
/benchmarks/hermesbench/private/
/benchmarks/hermesbench/keys/
/benchmarks/hermesbench/snapshots/
```

- [ ] **Step 6: Document safe local usage and current milestone limits**

`benchmarks/hermesbench/README.md` must state that corpus preparation uses a pinned local VulnGym checkout, agent-visible bundles are audited before use, evaluation is offline, hidden keys and oracles stay outside Git, the current foundation imports labels but does not infer fixed commits, and Full performance claims require at least 144 vulnerable tasks plus three expanded diversity axes.

- [ ] **Step 7: Run focused RED-to-GREEN verification**

Run: `python -m unittest discover -s benchmarks/hermesbench/tests -v`

Expected: all Python tests pass.

Run from `sdk/typescript`: `bun test --timeout 30000 tests-ts/hermesbench.test.ts`

Expected: the Bun integration test passes and invokes the same Python suite.

- [ ] **Step 8: Run package checks and full tests**

Run from `sdk/typescript`: `pnpm run types`

Expected: exit code `0`.

Run from `sdk/typescript`: `pnpm run format`

Expected: exit code `0`.

Run from `sdk/typescript`: `pnpm run test --seed 12345`

Expected: all tests pass with the fixed seed.

- [ ] **Step 9: Update project tracking and self-review the complete diff**

Mark benchmark-foundation contract, scorer, sanitizer, receipt, escalation, importer, and synthetic end-to-end checklist items complete. Append the VulnGym revision, commands run, exact test counts, and any remaining corpus-preparation work to `context-notes.md`. Search for debug output, private identifiers, hidden labels, generated snapshots, and unsupported public CLI changes before staging.

- [ ] **Step 10: Commit the integrated foundation**

```bash
git add .gitignore benchmarks/hermesbench/README.md benchmarks/hermesbench/cli.py benchmarks/hermesbench/__main__.py benchmarks/hermesbench/tests/test_cli.py sdk/typescript/tests-ts/hermesbench.test.ts checklist.md context-notes.md
git commit -m "feat: add the HermesBench foundation CLI"
```

## Plan Self-Review Record

- Spec coverage maps contracts, scoring, false-positive controls, separated usage, contamination checks, VulnGym import, escalation, and Full readiness to Tasks 1-7.
- Public CLI and SDK remain unchanged because HermesBench is a standalone module and Hunt integration is reserved for its own plan.
- Contract names are consistent across tasks: `Location`, `GoldPath`, `Finding`, `OracleTask`, `TaskPrediction`, `TokenUsage`, `RunConfig`, `RunReceipt`, `MiniEvidence`, and `EscalationDecision`.
- The plan contains no networked evaluation, exploit generation, fixed-commit guessing, or hidden-oracle publication.
- Actual vulnerable and fixed repository snapshot materialization is explicitly scoped to the corpus-preparation plan that follows this tested foundation.
