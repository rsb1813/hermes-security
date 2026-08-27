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

## Reviewed corpus preparation

- [x] Build and test the generic reviewed-corpus materializer with synthetic Git fixtures.
- [x] Batch-read each reviewed Git tree's regular blobs with checked binary framing.
- [x] Exclude only explicitly quarantined Git symlink entries without reading their blobs.
- [x] Apply fixed-comment redactions only against fixed-tree retired-path coordinates.
- [x] Use short sibling corpus stage paths for Windows materialization budgets.
- [x] Disable Git lazy fetches so missing partial-clone objects fail closed.
- [x] Review real source provenance, create private ledger rows, and materialize real Canary or Mini snapshots.

## Standard baseline

- [x] Define the strict model-adapter request, response, and task receipt contracts.
- [x] Implement the snapshot-safe paired runner and deterministic fake Canary.
- [x] Implement and verify the hardened Docker execution boundary.
  - [x] Record Task 4 RED unit evidence.
  - [x] Verify the exact Docker lifecycle and mount boundary with unit tests.
  - [x] Verify the opt-in live Docker isolation smoke and private receipt.
- [x] Connect one common Codex non-interactive adapter to Standard and Hunt.
  - [x] Verify host `codex exec --output-schema` acceptance for the pinned prediction schema.
  - [x] Complete the managed-auth container model smoke with a valid public result.
  - [x] Preserve the Docker default seccomp boundary while enabling the pinned Codex internal sandbox.
  - [x] Deny tool access to the private authentication runtime with a named permission profile.
  - [x] Extend and verify the bounded two-reader authentication handshake.
  - [x] Rebuild the pinned image and pass the exact no-model filesystem and network boundary smoke.
  - [x] Persist only a bounded public failure code, safely replace partial runner artifacts, and bind descriptor-verified failure sidecars to phase receipts.
  - [ ] Diagnose the paid smoke failure without retaining model text or private identities.
  - [ ] Complete a fresh paid Canary smoke without retaining confidential output.
- [x] Implement paired discovery and verification runner.
  - [x] Record focused RED evidence.
  - [x] Bind canonical candidate transfer and independently auditable phase receipts.
  - [x] Verify single-workflow and exact seedless AB/BA/AB paired execution.
- [x] Connect the benchmark runner to the unchanged Standard workflow.
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
- [x] Review the final diff for scope, safety, and public-data boundaries.
- [x] Commit the verified Task 6 logical unit.
- [ ] Publish the evidence-backed comparison report.
