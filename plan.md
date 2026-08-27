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

## Current live-run checkpoint

- Vendor the pinned Moby default seccomp profile and add only the syscalls observed during pinned Codex bubblewrap setup.
- Select a named Codex permission profile that reads the snapshot and plugin, writes only scratch, denies the private authentication runtime path, and disables tool networking.
- Extend the two-reader authentication deadline only after the filesystem denial is proven under the exact production container flags.
- Rebuild the pinned runtime image, rerun the no-model boundary smoke, and then use a new immutable output directory for the paid Canary smoke.

Verification: the internal sandbox starts without extra capabilities, task commands cannot read the authentication sentinel or write source mounts, no network reaches the host sentinel, and all focused and full HermesBench tests pass before any paid run.

Latest no-model verification: rebuilt `hermesbench-runtime-task5-local:latest` passed the named-permission/custom-seccomp boundary smoke and the full HermesBench Python suite. No paid Canary invocation was made.

## Current paid-smoke diagnostic checkpoint

- Revalidate a fixed public failure-code contract, safely replace partial runner artifacts, and bind descriptor-verified canonical failure-sidecar hashes through phase and workflow receipts.
- Reproduce the adapter failure on the two-task Canary smoke and use only status, elapsed time, event shape, command count, and separated token counts as diagnostics.
- Read the final schema-bound prediction from a bounded regular file written by pinned Codex `--output-last-message`; JSONL agent messages remain untrusted progress events.
- Split an unauthorized child failure into fixed pre-replay and post-replay categories without retaining stderr, then change the authentication contract only after the live category identifies the failing boundary.
- Keep the frozen model, effort, image, policy, timeout, manifest, and snapshot hashes unchanged while fixing the live response boundary.

Verification: focused RED/GREEN tests prove that sensitive exception text cannot enter task artifacts, the complete HermesBench suite remains green, the source snapshots retain their pre-run hashes, and the next paid smoke reaches independent verification.
