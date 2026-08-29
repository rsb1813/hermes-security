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
  - [x] Diagnose the paid smoke failure without retaining model text or private identities.
  - [x] Read the schema-bound result from Codex `--output-last-message` instead of intermediate agent events.
  - [x] Classify unauthorized failures before or after the bounded auth replay without retaining child stderr.
  - [x] Prove tmpfs regular-file storage under the existing external-token mode without crossing the host refresh-token boundary.
  - [x] Replace the production FIFO with a private tmpfs regular file while preserving isolation and bounded failure evidence.
  - [x] Accept quoted search metacharacters while rejecting real shell composition and hashing non-public command arguments in receipts.
  - [x] Complete a fresh paid Canary smoke without retaining confidential output.
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

- [x] Record a completed two-phase paid diagnostic baseline with separated token classes and post-run integrity evidence.
- [x] Preserve up to 12 bounded internal Hunt candidates with blinded hypothesis, family, pass, evidence, counterevidence, and expected-control fields.
- [x] Require one terminal verifier decision per internal candidate and project no more than five accepted findings to the public prediction contract.
- [x] Run the fixed paid diagnostic after the rich-candidate change and record its separated cost, candidate, decision, score, and integrity evidence.
- [x] Bind deterministic inventory, frontier, candidate references, and explicit coverage debt into the Hunt receipts.
- [x] Make discovery-failure workflow receipts independently revalidatable for completed-task subsets and empty candidate transfer.
- [x] Replace the broad live Hunt attestation failure with bounded path-free packet, artifact, location, and pass-linkage codes.
- [x] Revalidate the failed v12 receipt and run the fixed diagnostic once under a new immutable output root.
- [x] Classify command-event rejection origins with fixed path-free codes without changing any shell-composition rejection.
- [x] Revalidate the failed v12b receipt and run one fixed v12c diagnostic under a new immutable output root.
- [x] Rerun the fixed single-task diagnostic with one material strategy change at a time.
- [ ] Measure `hunt-balanced` and `hunt-max` on Canary.
- [ ] Tune one material variable at a time on Mini.
- [ ] Add safe caching and progressive-context reuse.
- [ ] Add adaptive escalation without reducing coverage floors.
- [x] Record cached input, uncached input, output, time, and cache hits separately.
- [x] Compare regex-only, lexical-graph, and language-specific AST guidance approaches.
- [x] Obtain approval for deterministic lexical semantic guidance.
- [x] Review and approve the written semantic-guidance specification.
- [x] Write the semantic-guidance implementation plan with RED and GREEN checkpoints.
- [x] Implement protocol-v2 semantic guidance while preserving protocol-v1 receipt reconstruction.
  - [x] Implement and independently review the deterministic lexical guidance builder.
  - [x] Bind semantic guidance into Hunt evidence protocol version 2.
  - [x] Require the guidance in Hunt discovery without changing Standard or verification prompts.
  - [x] Reconstruct retained Hunt receipts by their explicit evidence protocol version.
- [x] Complete independent review and all no-model boundary checks.
- [x] Run one fixed protocol-v2 paid diagnostic and classify its measurement-blocking pass-linkage failure against v10, v11, and v12c.
- [x] Obtain approval for deterministic frontier-pass annotations.
- [x] Write the frontier-pass annotation design specification.
- [x] Review and approve the written frontier-pass annotation specification.
- [x] Write the frontier-pass annotation implementation plan with RED and GREEN checkpoints.
- [x] Implement protocol-v3 frontier-pass annotations while preserving protocol-v1 and protocol-v2 receipt reconstruction.
- [x] Complete independent review and all protocol-v3 no-model boundary checks.
- [x] Run one fixed protocol-v3 paid diagnostic under a new immutable output root.
  - [x] Revalidate the two-invocation incomplete receipt, completed discovery evidence, three-candidate pass distribution, fixed verification failure code, and post-run integrity boundaries.
  - [x] Keep Mini and score claims blocked because verification produced no public prediction.
- [x] Obtain approval for the bounded Hunt verification command-compliance prompt change.
- [x] Add verification-only quoted-metacharacter guidance without relaxing the scanner or execution policy.
  - [x] Preserve the Standard and Hunt discovery prompt contracts and every fail-closed command rejection.
  - [x] Cover quoted and unquoted `<` and `>` behavior at the live adapter boundary.
- [x] Re-run one fixed diagnostic after that single reviewed variable changes.
  - [x] Revalidate the completed two-invocation receipt, separated token usage, candidate decisions, public projection, and score.
  - [x] Confirm the command-compliance change restores workflow completion without claiming an accuracy gain.
  - [x] Audit all Canary snapshots, retained artifacts, public projections, and container cleanup after the run.
- [x] Diagnose the completed protocol-v3 accuracy miss without publishing private paths, labels, or raw findings.
- [x] Compare the two-call Protocol-v4 design with multi-lane and map-reduce alternatives.
- [x] Receive in-chat approval for the two-call Protocol-v4 architecture.
- [x] Write and self-review the nested-output guidance Protocol-v4 design specification.
- [x] Receive approval for the written Protocol-v4 design specification.
- [x] Write the file-by-file Protocol-v4 implementation plan with RED and GREEN checkpoints.
- [x] Add the explicit Protocol-v4 and semantic-schema-3 compatibility spine while retaining the Protocol-v3 live default.
- [x] Approve the dependency-free bounded-tokenizer architecture correction after repeated lexical-boundary failures.
- [x] Implement schema-3 nested-output guidance with vulnerable, guarded, and decoy tests first.
- [ ] Implement deterministic strong-edge and family/component row allocation with budget tests first.
- [ ] Implement the v4 blind verifier projection and prompt golden test first.
- [ ] Preserve exact protocol-v1 through protocol-v3 artifact, prompt, and receipt reconstruction.
- [ ] Pass the label-independent retained-snapshot artifact build and separate private coverage gate.
- [ ] Complete independent review and all full no-model verification gates.
- [ ] Run exactly one fixed paid Protocol-v4 Canary diagnostic with no automatic retry.
- [ ] Report localized accuracy, separated phase cost, integrity, and public-boundary evidence.
- [ ] Run HermesBench when Mini is inconclusive.
- [ ] Run HermesBench for the final result regardless of Mini confidence.

## Completion

- [x] Run the complete repository test suite.
- [x] Review the final diff for scope, safety, and public-data boundaries.
- [x] Commit the verified Task 6 logical unit.
- [ ] Publish the evidence-backed comparison report.
