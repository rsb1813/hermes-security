# Hermes Security Checklist

## Research and repository setup

- [x] Inspect the upstream Codex Security repository and installed plugin behavior.
- [x] Review primary-source discovery benchmark candidates.
- [x] Select VulnGym `verify=1` records as the initial real-world corpus source.
- [x] Define a defensive, non-exploit benchmark boundary.
- [x] Create the public `rsb1813/hermes-security` fork.
- [x] Clone the fork and add the OpenAI repository as `upstream`.
- [x] Create the `hermes/benchmark-foundation` branch.

## Design

- [x] Receive approval for the in-conversation architecture.
- [x] Write and self-review the detailed design specification.
- [x] Receive approval for the written design specification.
- [x] Write the file-by-file HermesBench foundation implementation plan.
- [x] Write the file-by-file Hunt workflow implementation plan after the foundation is verified.
- [x] Write the file-by-file isolated HermesBench runner and Canary plan.

## Benchmark foundation

- [x] Write failing tests for benchmark schemas and scorer behavior.
- [x] Implement benchmark schemas and prediction contracts.
- [x] Implement source and metadata sanitization.
- [x] Implement paired endpoint and trace scoring.
- [x] Implement fixed-negative and adjudication handling.
- [x] Implement reproducible run receipts and separated token accounting.
- [x] Implement Canary, Mini, and Full manifest loaders.
- [x] Implement Mini-to-Full escalation decisions.
- [x] Implement the strict reviewed VulnGym importer and keyed anonymous IDs.
- [x] Add synthetic end-to-end fixtures.

## Standard baseline

- [ ] Define the strict model-adapter request, response, and task receipt contracts.
- [x] Implement the snapshot-safe paired runner and deterministic fake Canary.
- [ ] Implement and verify the hardened Docker execution boundary.
- [ ] Connect one common Codex non-interactive adapter to Standard and Hunt.
- [ ] Connect the benchmark runner to the unchanged Standard workflow.
- [ ] Run and verify Canary.
- [ ] Freeze the Mini task manifest and configuration.
- [ ] Run the Standard Mini baseline.

## Hunt workflow

- [x] Write failing tests for Hunt state transitions and coverage safeguards.
- [x] Run a fresh-context RED behavior test without the Hunt skill.
- [x] Reuse deterministic rank and shard infrastructure.
- [x] Implement repository mapping and risk frontier planning.
- [x] Implement forward and backward discovery passes.
- [x] Implement path joining and candidate evidence-slice guidance.
- [x] Implement independent validation.
- [x] Implement root-cause deduplication.
- [x] Implement validated draft reporting.
- [x] Bundle the explicit experimental Hunt skill and workflow contract.
- [x] Run fresh-context GREEN behavior tests with the bundled skill.
- [x] Verify Standard CLI and SDK compatibility.

## Performance work

- [ ] Measure `hunt-balanced` and `hunt-max` on Canary.
- [ ] Tune one material variable at a time on Mini.
- [ ] Add safe caching and progressive-context reuse.
- [ ] Add adaptive escalation without reducing coverage floors.
- [ ] Record cached input, uncached input, output, time, and cache hits separately.
- [ ] Run HermesBench when Mini is inconclusive.
- [ ] Run HermesBench for the final result regardless of Mini confidence.

## Completion

- [x] Run the complete repository test suite.
- [ ] Review the final diff for scope, safety, and public-data boundaries.
- [ ] Commit each verified logical unit.
- [ ] Publish the evidence-backed comparison report.
