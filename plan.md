# Hermes Security Working Plan

Date: 2026-08-27

## Goal

Build and measure a defensive vulnerability-discovery workflow that finds materially more real vulnerabilities than the unchanged Codex Security Standard workflow, validates findings safely, and drafts reports without generating exploits.

## Phase 1. Lock the design and benchmark contract

- Approve the written design.
- Convert the design into a file-by-file implementation plan.
- Define the benchmark schema, safety boundary, scorer, receipt, and escalation rules.
- Verify that public and hidden benchmark data remain separated.

Verification: design review completed, no unresolved design gaps, and a committed implementation plan exists.

## Phase 2. Build the benchmark foundation

- Implement schemas, sanitizer, scorer, receipts, and synthetic fixtures with tests first.
- Implement Canary, Mini, and Full manifest handling.
- Implement paired comparison and Full escalation decisions.
- Keep model execution behind a narrow adapter so scoring can be tested without paid calls.

Verification: benchmark unit and integration tests pass, synthetic end-to-end scoring is reproducible, and contamination tests fail closed.

## Phase 3. Establish the Standard baseline

- Run Standard on Canary.
- Fix harness defects without changing Standard behavior.
- Run the frozen Standard baseline on Mini.
- Record raw outputs, category metrics, elapsed time, and separated token usage.

Verification: baseline receipt is complete and reruns can be compared under the same configuration.

## Phase 4. Implement Hunt

- Reuse the existing deterministic rank and shard pipeline.
- Add repository mapping, bidirectional discovery, coverage safeguards, independent validation, deduplication, and draft reporting.
- Preserve the current public CLI, SDK, and Standard defaults.
- Add focused compatibility and workflow tests.

Verification: all repository tests pass, Standard behavior is unchanged, and Hunt completes the synthetic and Canary suites.

## Phase 5. Tune with controlled Mini comparisons

- Compare Standard, `hunt-balanced`, and `hunt-max` with fixed tasks, model, effort, seed support, tools, and time.
- Change one material strategy variable per experiment.
- Promote only changes that improve paired discovery evidence without hiding category regressions.
- Apply caching and routing improvements that preserve coverage floors.

Verification: the selected Hunt configuration has a complete paired Mini receipt and an explicit escalation decision.

## Phase 6. Run HermesBench and finalize evidence

- Run the full suite whenever Mini is inconclusive and always for the final result.
- Adjudicate unmatched high-confidence findings.
- Recompute results from frozen raw outputs when an oracle changes.
- Produce an evidence-backed performance and cost report.

Verification: the Full result satisfies the design acceptance criteria or the report plainly states that the improvement was not confirmed.

## Delivery rule

Each logical implementation unit is tested, self-reviewed, and committed separately. Public pushes occur only after the material is safe for the public fork.
