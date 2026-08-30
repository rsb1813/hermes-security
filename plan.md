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
- Retain the historical fixed pre-replay and post-replay receipt categories, but use the regular-file authentication runtime selected by the live boundary diagnostic without retaining stderr.
- Test a tmpfs regular authentication file under the existing external-token mode first, and test managed ChatGPT mode only if the storage-only variant still fails.
- Parse shell quoting before rejecting command-control syntax, reject only unquoted operators or substitutions, and hash non-public argument tokens before writing command evidence.
- Keep the frozen model, effort, image, policy, timeout, manifest, and snapshot hashes unchanged while fixing the live response boundary.

Verification: focused RED/GREEN tests prove that sensitive exception text cannot enter task artifacts, the complete HermesBench suite remains green, the source snapshots retain their pre-run hashes, the storage-only diagnostic identifies one viable boundary without persisting credentials or model text, and the next paid smoke reaches independent verification.

## Current discovery-performance checkpoint

- Treat paid diagnostic v10 as the first valid live baseline: the two-phase workflow completed and revalidated, but its single high-confidence candidate missed the advisory and was rejected by the fresh verifier.
- Reject a prompt-only correction because the documented Hunt artifact sequence is not a host-validated completion condition.
- Introduce a bounded internal discovery pool of at most 12 candidates while retaining the existing maximum of five final findings. Preserve a short blinded hypothesis, vulnerability family, search pass, evidence, counterevidence, and expected control with each candidate so the fresh verifier receives meaning rather than locations alone.
- Add a deterministic Hunt artifact gate as the next logical unit. Bind inventory, frontier, coverage debt, normalized candidates, and candidate-to-frontier references to receipts instead of claiming that every file in a large repository was manually reviewed.
- Keep the first performance experiment at two model invocations. Add complementary discovery scouts only for `hunt-max` if the richer packet and artifact gate still fail the fixed diagnostic.
- Change one material variable per paid rerun and keep model, effort, image, policy, timeout, manifest, and snapshot hashes fixed.

Verification: RED/GREEN tests prove that more than five internal candidates survive discovery, every packet is bounded and source-local, only five accepted findings can reach scoring, missing or mismatched Hunt evidence fails closed, and the fixed diagnostic improves recall before broader Canary or Mini promotion.

## Current Protocol-v4 accuracy checkpoint

- Treat the completed protocol-v3 diagnostic as evidence that workflow reliability is restored but target-localized recall is still insufficient.
- Add a bounded JavaScript/TypeScript `nested-output-context` hint because the current call-anchor graph cannot represent active template-literal output contexts.
- Allocate strong edges and semantic rows deterministically across declarations, operation families, and exact frontier components without raising current profile caps.
- Preserve the rich discovery candidate transfer for host attestation, but give the protocol-v4 verifier only candidate identity and exact locations.
- Keep the public CLI, SDK, Standard workflow, scorer, model-call count, runtime policy, candidate caps, and historical protocol-v1 through protocol-v3 reconstruction unchanged.
- Gate implementation with synthetic vulnerable, guarded, and decoy fixtures; exact legacy golden bytes; a label-independent retained-snapshot build; and a separate private coverage comparison.
- Make exactly one same-variable paid Canary rerun after all no-model and review gates pass. Do not retry automatically.

Verification: protocol-v4 semantic guidance contains the reviewed output-context pattern without oracle input, guarded and decoy cases stay negative, the verifier prompt contains no discovery conclusion fields, legacy receipts revalidate exactly, the full no-model suites pass, and the single paid result is reported with localized accuracy and separated cost evidence.

## Current Protocol-v4 partial-phase checkpoint

- Treat the one-shot paid Canary as an incomplete measurement, not an accuracy result. Seven of eight discovery tasks completed, one failed bounded host attestation, and the current workflow discarded every successful candidate before verification.
- Preserve the full manifest and normalize recoverable Protocol-v4 discovery failures or timeouts to explicit empty candidate sets. Keep contaminated snapshots fail-closed.
- Continue verification for the complete manifest, but synthesize a deterministic zero-token verification result whenever a task has no transferred candidate. Normalize recoverable verification failures or timeouts to explicit empty final predictions so every failed task remains a scored miss.
- Bind discovery task status, bounded failure evidence, and post-response token usage. Preserve Protocols 1 through 3 and Standard workflow behavior.
- Keep automatic retries at zero. The consumed Canary is immutable and must not be rerun.
- Add throughput work only after partial-result correctness is proven. A larger paid suite must not inherit the measured sequential tail unchanged.

Verification: partial discovery and partial verification fixtures both produce complete manifest-ordered final prediction rows, failed tasks are empty misses, zero-candidate verification makes no model call, failure evidence and all observed token classes revalidate, contamination still aborts, and all-completed legacy behavior remains unchanged.

## Current Protocol-v4 throughput checkpoint

- Keep task snapshots, scratch roots, authentication runtimes, and containers isolated per invocation.
- Prefer bounded phase-local task parallelism over container reuse, shared authentication caches, or discovery-to-verification pipelining. Those alternatives enlarge the security boundary or alter the current phase contract.
- Complete every snapshot preflight before starting any executor and publish every receipt, prediction, command, and evidence row in manifest order regardless of worker completion order.
- Freeze and hash-bind the worker limit with a compatibility path that keeps existing sequential controls and retained receipts reproducible.
- Start with two workers. Parallelism is a wall-time optimization; token-cost reductions must come from zero-candidate local verification and fewer paid failures, not from an unsupported billing claim.

Verification: deterministic fake executors prove real overlap, manifest-ordered byte-stable outputs, fail-before-start preflight behavior, isolated failure handling, frozen-control mismatch rejection, and identical logical results between one and two workers.

## Current structural-discovery checkpoint

- Protocol 4 now emits a schema-3-only compact `operation-index` for qualified calls, member mutations, and parameter-linked simple assignments. Compact `p`, `q`, and `s` fields retain path, eligible-pass, and exact structural-site information without source snippets or oracle data.
- The scanner follows declaration parameters through one local assignment hop, parses balanced same-line call arguments, and counts distinct identifiers. Scheduling favors signatures reused two through seven times, uses a 2:1 parameter-flow lane, prioritizes complex calls, rotates repeated signature occurrences, and rotates components.
- Existing direct, import-linked, and nested-output rows remain byte-for-byte first-class. Index rows replace only selected name-only rows inside the route-only row and byte footprint; structural-only output remains capped at 32 rows and 64 KiB. The discovery model-call count remains one.
- Aggregate-only evaluation on four retained vulnerable snapshots improved exact critical-operation guidance from 0/4 before the compact index to 3/4 overall, with 2/4 contributed directly by the structural index. This is host-side guidance coverage, not end-to-end model recall or a vulnerability finding.
- The final packet used 324,769 semantic bytes, 140 fewer than the 324,909-byte route-only baseline. It retained 144 index rows, 1,609 entries, and 10,144 exact structural sites; the largest row was 2,047 bytes. Snapshot integrity passed with two local preparation workers.
- A state-transition ranking experiment regressed aggregate coverage to 2/4 overall and 1/4 structural. A later adjacent-row packing experiment produced no retained-data gain. Both were removed instead of stacking benchmark-specific exceptions.
- Protocols 1 through 3, Standard, receipt validation, snapshot isolation, candidate caps, full-frontier eligibility, and the paid-run boundary remain unchanged. No model, network, container, or paid benchmark invocation was made for this unit.

Verification: 124 semantic-guidance tests and all 458 HermesBench Python tests pass, with three and ten documented platform skips respectively. The Bun bridge passes its real CLI integration test, Python compilation succeeds, and `git diff --check` is clean. The retained 4/4 host-side target remains unmet and must not be represented as end-to-end discovery performance.

## Current structural-selection checkpoint

- Aggregate-only revalidation confirms that all three call-shaped vulnerable critical operations already exist in the raw product structural-site set. The fourth operation is covered by an existing semantic route. The remaining 3/4 result is therefore a bounded index-selection failure, not a parser-coverage failure.
- Reject a new external AST dependency. The benchmark Python path has no dependency manifest, and adding grammars would enlarge Windows, container, packaging, and determinism boundaries without creating the already-present site.
- Reject a Python-standard-library AST hybrid. It would split Python behavior from Go and TypeScript while leaving the current selection problem unchanged.
- Compare only transformations over the unchanged full index: stable component novelty within a bounded lookahead, stable path novelty within the same lookahead, and deterministic site-per-byte density. Keep current order as the control.
- A production selector is eligible only if the same four retained snapshots reach 4/4 exact critical-operation guidance, every current hit remains present, total semantic bytes do not exceed the route-only baseline, rows stay at or below 2 KiB, snapshots remain unchanged, and the discovery model-call count stays one.
- If no general selector satisfies every gate, retain 3/4 and stop instead of adding target-shaped ranges or oracle-derived exceptions.

The equal-budget experiment selected bounded site-density lookahead 16. It was the only tested general reorder to raise direct structural coverage from 2/4 to 3/4 and total guidance from 3/4 to 4/4 with zero lost current hits. Aggregate selected bytes fell by 385 while encoded sites increased by 2,183. Production work therefore remains limited to this stable local row reorder and begins with a public failing behavior test.

The production-safe variant preserves the existing semantic priority lane sequence and applies stable density selection only within each lane. Retained-snapshot remeasurement confirmed the target: 3/4 direct structural coverage, 4/4 total semantic operation coverage, zero lost hits, 324,248 total bytes, 236,629 operation-index bytes, 133 index rows, 11,735 encoded sites, and unchanged 2,048-byte maximum rows.

Verification: the aggregate diagnostic exposes only anonymous ranks, budgets, and coverage counts. Any selected implementation must begin with a public failing behavior test and preserve exact Protocol 1 through 3 golden bytes plus strong schema-3 route bytes.

Final verification passes 125 focused semantic tests, 54 adapter tests, all 459 HermesBench Python tests, the Bun real-CLI bridge, six explicit legacy-byte and prompt-hash contracts, compileall, diff checks, aggregate snapshot integrity, and independent Critical/Important review.

## Current host-managed phase checkpoint

- Protocol 4 currently tells each model invocation to read the complete standalone Hunt skill. That skill directs one actor through inventory generation, frontier closure, independent validation, and report finalization even though the HermesBench host already owns those lifecycle stages.
- Prefer one concise host-managed Hunt phase skill over an inline prompt exception. A prompt-only override leaves contradictory high-level instructions in context, while shrinking semantic artifacts risks removing the newly recovered structural coverage.
- Select the managed skill only for Hunt evidence Protocol 4. Discovery must read the two fixed host packets exactly once, inspect immutable source, and return at most 12 candidates. Verification must inspect immutable source independently and terminate only the supplied candidates. Neither phase may regenerate host artifacts, close the frontier, invoke another verifier, or finalize a report.
- Preserve the standalone Hunt skill, Protocol 1 through Protocol 3 prompt bytes, Standard behavior, candidate and finding caps, two-call ceiling, schemas, attestation, scorer, and frozen runtime controls.
- Do not claim a recall or billed-cost improvement without a later same-variable model run. This unit proves only removal of contradictory lifecycle instructions and a smaller phase contract without a model, network, container, or paid invocation.

Verification: a public RED test must prove that Protocol 4 still selects the standalone skill before implementation. GREEN tests must prove phase-specific managed-skill selection for discovery and verification, exact legacy prompt hashes, shipped plugin contents, unchanged invocation counts and candidate projection, focused and full test success, compile success, and a clean diff.

Outcome: the managed phase contract is 2,852 bytes and no longer links the 12,666-byte standalone contract. Protocol 4 alone selects it in discovery and verification, while exact legacy prompt hashes and every two-call, candidate, projection, attestation, and packaging boundary remain covered by passing public tests. No model, network, container, or paid invocation was made, so end-to-end recall and billed-cost effects remain unmeasured.

## Current managed-skill paid Canary checkpoint

- Use the user's fresh authorization for exactly one Hunt-only Protocol-v4 Canary process. Automatic retry remains disabled, and any preflight failure must stop before a model invocation.
- Reuse the unique private live index and its immutable manifest, snapshots, oracles, frozen controls, execution policy, and managed authentication. Infer the comparison profile from the latest valid private aggregate receipt instead of changing a benchmark variable silently.
- Require protocol version 4, schema-3 controls, two phase-local parallel tasks, at most two model invocations per task, valid snapshot hashes, an existing safe output root, and a fresh path-safe non-existent run directory before starting.
- Keep private task identities, paths, labels, findings, raw model text, and credentials out of public artifacts and console summaries. Record only aggregate, path-free evidence in the tracked notes.
- After the single process exits, independently revalidate the aggregate receipt, task receipts, invocation count, usage totals, score fields, snapshot immutability, public projection boundary, and benchmark-container cleanup before making any performance claim.

Verification: focused public gates and the private no-model preflight pass first; the private start ledger proves one launched process; the immutable receipt and independent revalidation agree on completion status, aggregate metrics, and frozen controls; repository state remains reviewable and no second model attempt occurs.

The first guarded CLI process stopped before creating an output directory, container, model invocation, or receipt because the private launcher incorrectly passed a non-existent directory as `output-root`. The exact reproduced error is `PhaseRunnerError: output root is unavailable`. The corrected launcher now reuses the existing safe root and proves only its `run-id` child is absent. The consumed local process is retained in the private ledger, and no paid rerun is permitted without fresh authorization.

Outcome: the freshly authorized Canary launched exactly one paid process with no retry and completed the full eight-task workflow. Discovery completed 8/8 tasks and verification completed 7/8; the one recoverable verification failure was retained under the fixed public code `command_unquoted_pipe`, and Protocol 4 produced a complete scored output through its partial-phase contract. Independent validation passed the workflow receipt, token and invocation aggregation, score recomputation after normal JSON serialization, snapshot rehash, frozen-control binding, public-data boundary, and container cleanup.

The operational result improved completion and end-to-end wall time, but the accuracy result did not improve. Discovery emitted 32 candidates and the public projection emitted 22 findings, yet candidate entry, critical-operation, pair, and trace localization all had zero true matches. The final pair and trace F1 values and advisory recall were all zero; the 0.15 composite came only from 4/4 fixed-snapshot specificity. The next performance unit must therefore target oracle-blind discovery localization and verifier command normalization before any Mini or Full promotion. No additional paid run is authorized by this measurement.

## Current Protocol-v5 paired-flow checkpoint

- Treat the Protocol-v4 Canary as evidence that host semantic coverage alone is insufficient. Every retained vulnerable critical operation was present in selected guidance, but discovery produced zero exact entry, critical, pair, or trace matches.
- Add a separate Protocol 5 rather than changing Protocol 4 bytes. Build compact paired-flow and sink-only investigation seeds from the existing single-pass scan, bind the full semantic and seed artifacts, and require exact seed identity and endpoints for seed-derived candidates.
- Keep source inspection mandatory and guidance non-probative. Preserve up to four unseeded whole-frontier fallbacks, require at least one seeded candidate when non-empty seeds and candidates coexist, and retain the global 12-candidate and five-finding caps.
- Make the full semantic artifact host-only for Protocol 5. Discovery reads the priority packet and bounded seed artifact exactly once, while verification receives only candidate identity and exact locations.
- Preserve Protocol 1 through Protocol 4 reconstruction, Standard, schemas, scorer, two-call ceiling, sandbox, network denial, authentication, partial-phase recovery, zero retries, and strict unquoted-operator rejection.
- Perform no model, network, container, or paid run in this unit. Promote Protocol 5 only after deterministic artifact, mutation, compatibility, full-suite, snapshot-integrity, aggregate-only host coverage, and independent review gates pass.

Verification: public RED/GREEN tests prove deterministic bounded route, source-linked, parameter-flow, sink-only, and fallback behavior; seed ID and endpoint mutations fail closed; Protocol 1 through Protocol 4 golden bytes and receipts remain unchanged; the full no-model suite passes; and only aggregate path-free host coverage is recorded before requesting any future paid Canary authority.
