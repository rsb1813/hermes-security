# Hermes Security Discovery and Benchmark Design

Date: 2026-08-27
Status: Proposed for written-design approval
Branch: `hermes/benchmark-foundation`

## 1. Objective

Hermes Security is a public fork of Codex Security focused on materially improving vulnerability discovery while retaining automatic validation, deduplication, and draft reporting.

The first milestone must answer two questions with reproducible evidence.

1. Does the experimental Hunt workflow find more real vulnerabilities than the unchanged Standard workflow?
2. Can it achieve that improvement without hiding false positives, unstable runs, or token cost?

Detection quality is the primary objective. Cost efficiency is a measured secondary objective and must not silently reduce coverage in the maximum-performance profile.

## 2. Scope

The first milestone includes the following work.

- Preserve the existing Standard workflow as a compatibility baseline.
- Add an experimental Hunt workflow that organizes discovery, validation, and reporting.
- Build `HermesBench-mini` for fast paired iteration.
- Build the larger and more diverse `HermesBench` for escalation and release decisions.
- Record reproducible run receipts, discovery metrics, false-positive controls, elapsed time, and token usage.
- Automatically validate candidates with static evidence, reachability evidence, and safe local checks.
- Produce a draft report only after independent validation and root-cause deduplication.

The first milestone does not include the following work.

- Generating exploits, proof-of-concept payloads, flags, or crash-triggering inputs.
- Attacking remote systems or contacting arbitrary network targets.
- Renaming the existing npm package, executable, or public API.
- Replacing the Standard workflow.
- Requiring CodeQL, Fuzz Introspector, or OSS-Fuzz-Gen for the first usable result.
- Publishing hidden benchmark labels, private findings, or generated third-party source snapshots.

## 3. Safety and Evaluation Boundary

HermesBench evaluates defensive source-code discovery, not exploitation.

- The agent receives only an anonymized vulnerable or fixed source snapshot and the allowed build metadata.
- The agent does not receive CVE or GHSA identifiers, patches, commit messages, issue text, proof-of-concept code, exploit instructions, or flags.
- Evaluation runs are local and offline after corpus preparation.
- Validation may use parsing, static analysis, type checking, builds, existing tests, and bounded reachability checks.
- Validation must not create a weaponized payload, trigger a crash as the success oracle, open an outbound connection, or execute an attack against a service.
- Commands used during validation must run in an isolated workspace with an explicit allowlist and a no-network policy.

This boundary allows Hermes to confirm that a reported source-to-sensitive-operation path is real without turning the benchmark into an exploitation task.

## 4. Benchmark Family

### 4.1 Shared task contract

Each benchmark task contains the following agent-visible inputs.

- An anonymized repository snapshot.
- A stable task identifier that does not encode project or advisory identity.
- The language and permitted local build or analysis commands.
- A time limit, model configuration, tool policy, and output schema.

Each grader-only oracle contains the following fields.

- One or more valid entry points.
- One or more sensitive or critical operations.
- Valid ordered trace nodes connecting an entry point to a critical operation.
- The vulnerability family and advisory grouping.
- A paired fixed-snapshot mapping when available.
- Provenance, license, source hashes, and reproducibility metadata.

Predictions use a bounded schema with at most five findings per task. Every finding must include an entry point, a critical operation, an ordered trace, a root-cause explanation, validation evidence, confidence, and report-ready remediation guidance.

### 4.2 HermesBench-mini

`HermesBench-mini` is the fast optimization suite.

- 48 human-reviewed vulnerable entries selected from reproducible `verify=1` VulnGym records that have a reliable fixed revision.
- One anonymously fixed negative snapshot paired with every vulnerable entry, for 96 evaluated snapshots in a complete Mini run.
- 16 Public Dev entries for transparent scorer and workflow development.
- 16 Hidden Test entries for paired promotion decisions.
- 16 Rotating Audit entries sampled from a reserved pool by a recorded selection seed.
- An eight-entry Canary subset of Public Dev for the cheapest smoke comparison.

Selection is grouped by advisory and repository before splitting. Closely related instances must not cross the Public Dev, Hidden Test, and Rotating Audit boundaries.

The public repository may contain Public Dev metadata and synthetic scorer fixtures. Hidden Test and Rotating Audit oracles remain outside the public repository. Generated source snapshots are ignored by Git and rebuilt from pinned public sources.

Public Dev and Canary results are diagnostic only. Promotion statistics use Hidden Test and Rotating Audit groups that were not exposed during tuning.

### 4.3 HermesBench

`HermesBench` is the full decision suite. It is larger and intentionally more diverse than the mini suite.

The initial full edition contains these lanes.

1. A core lane containing all eligible, deduplicated, human-reviewed `verify=1` VulnGym entries that pass reproducibility and license checks.
2. A matched-fixed lane that measures persistence of the target false positive after the vulnerable code has been fixed.
3. A curated-clean lane that measures unsupported-report behavior on reviewed negative snapshots.
4. A diversity lane that may add compatible defensive discovery cases from primary-source datasets such as IRIS or CWE-Bench-Java after the same sanitization and reproducibility gates pass.

The full manifest is stratified across vulnerability family, language, repository size, interprocedural depth, framework boundary, authentication or business-logic behavior, and source-to-sensitive-operation path shape. Dataset lanes share one prediction contract and one grader so additional diversity does not change the meaning of the score.

The first Full edition is not ready for a final claim unless it contains at least 144 vulnerable tasks after deduplication and expands Mini with previously absent cases on at least three stratification axes. If the core corpus cannot meet those gates, compatible diversity lanes must fill the gap or the final claim remains blocked. A run receipt states the eligible count, exclusions, and lane distribution.

### 4.4 Escalation policy

The benchmark runner promotes a comparison from `HermesBench-mini` to `HermesBench` when any of these conditions is true. Mini confidence and effect-size checks use only Hidden Test and Rotating Audit groups.

- The comparison is for a final milestone, release candidate, or public performance claim.
- The 95% paired bootstrap confidence interval for the primary score difference includes zero.
- Hunt finds fewer than two additional correctly localized advisories among the 16 Hidden Test entries. This is a promotion heuristic, not a claim of statistical significance.
- The winner changes across three paired repeats or fixed seeds.
- Overall score improves while any reportable language or vulnerability-family recall decreases by more than five percentage points.
- The change modifies the benchmark grader, candidate-generation strategy, validation acceptance rule, or routing policy enough to invalidate direct historical comparison.

The full suite is always the final authority. Mini results are optimization evidence only.

## 5. Scoring

### 5.1 Matching

A predicted finding matches a gold path only when all of these conditions hold.

- The predicted entry point is within five lines of a gold entry point in the same file.
- The predicted critical operation is within five lines of a gold critical operation in the same file.
- Both endpoints belong to the same valid gold trace.
- Predicted key trace nodes preserve the gold source-to-operation order.

The grader uses maximum one-to-one matching between predictions and gold paths. Duplicate findings cannot earn additional credit. Predictions above the five-finding limit remain unmatched.

### 5.2 Primary score

The primary score is a weighted composite.

```text
0.40 * pair_localization_f1
+ 0.25 * advisory_recall
+ 0.20 * trace_node_f1
+ 0.15 * fixed_snapshot_specificity
```

- `pair_localization_f1` measures precise entry-point and critical-operation pairing.
- `advisory_recall` measures whether at least one valid path was found for each advisory group.
- `trace_node_f1` measures ordered key-node coverage for matched findings.
- `fixed_snapshot_specificity` measures whether the retired target root cause is correctly absent from its fixed pair.

Unmatched high-confidence findings are provisional false positives until adjudicated. If review confirms a previously unknown vulnerability, the oracle is versioned rather than penalizing the discovery system. Curated-clean cases may count unsupported findings as false positives only after the case has been reviewed for that scope.

Confidence intervals are clustered by advisory or repository group so repeated instances do not create false confidence.

For a final Full decision, the confirmation statistic excludes Public Dev and any other case whose labels or outputs were used to tune Hunt. Aggregate results still report every lane, but tuning-exposed cases cannot establish the improvement claim.

### 5.3 Diagnostic metrics

The report also records metrics that do not alter the primary score.

- Vulnerability-family and language recall.
- Accepted, rejected, and inconclusive validation counts.
- Findings per task and duplicate reduction rate.
- Draft-report evidence completeness.
- Wall-clock time.
- Cached input tokens, uncached input tokens, and output tokens as separate values.
- Tool invocations and cache-hit rates.
- Score per unit of uncached input and output cost.

## 6. Controlled Comparison Protocol

Every Standard-versus-Hunt comparison is paired. The following values remain fixed within a comparison.

- Task manifest and snapshot hashes.
- Task order.
- Model and reasoning effort.
- Seed when the backend supports one.
- Tool versions and tool policy.
- Time and finding-count limits.
- Benchmark grader version.
- Prompt-visible repository content.

When a backend does not expose deterministic seeds, the receipt marks the seed as unsupported and the runner performs three paired repeats with alternating workflow order. Cached input, uncached input, and output usage are never collapsed into one raw-token number.

## 7. Hunt Workflow

Hunt is an experimental workflow alongside Standard. It reuses existing deterministic ranking and shard infrastructure in `generate_rank_input.py` instead of replacing the current scan system.

### 7.1 Pipeline

1. Repository mapping builds a reusable inventory of entry points, trust boundaries, sensitive operations, parsers, state transitions, and high-risk components.
2. Risk ranking uses deterministic signals and bounded model ranking to order work without discarding uncovered components.
3. Bidirectional discovery traces forward from attacker-controlled or low-trust entry points and backward from sensitive operations.
4. Path joining prioritizes intersections, missing authorization checks, broken invariants, unsafe state transitions, and cross-component dataflow.
5. Independent validation receives a candidate-specific slice and attempts to disprove reachability, impact, or attacker control.
6. Root-cause reduction merges duplicate symptoms and preserves the strongest evidence path.
7. Draft reporting converts only accepted findings into the existing report contract.

### 7.2 Coverage safeguards

Ranking controls order, not eligibility. Hunt must retain coverage floors for components, trust boundaries, and vulnerability families so a low initial rank cannot permanently hide a real issue.

The search frontier promotes work when any of these signals appears.

- A reachable sensitive operation has no reviewed predecessor path.
- An entry point crosses a trust boundary without a verified guard.
- Static evidence and model judgment disagree.
- A component has materially less analysis coverage than its peers.
- A candidate remains high impact but uncertain after the first validation pass.

### 7.3 Validation states

Candidates move through explicit states.

```text
discovered -> evidence_built -> challenged -> accepted | rejected | inconclusive
```

The independent verifier must not inherit the discovery conclusion as fact. Acceptance requires concrete code locations, a plausible source-to-operation path, attacker or low-trust influence, impact, and evidence that the relevant guard is absent or ineffective.

Safe local builds, static queries, existing tests, and non-triggering invariant checks may strengthen the result. A candidate remains inconclusive when safe evidence cannot separate it from a false positive.

### 7.4 Reporting

The draft report is generated last and contains only accepted findings. It includes a concise title, affected locations, preconditions, source-to-operation trace, security impact, validation evidence, confidence, remediation direction, and explicit uncertainty. It must not include a weaponized payload or exploitation procedure.

## 8. Cost and Throughput Strategy

The maximum-performance path preserves broad discovery coverage. Savings come from eliminating repeated work rather than truncating promising search.

- Cache repository maps, static-query results, source slices, ranking inputs, and validation evidence by source hash, tool version, prompt schema, and model configuration.
- Share one deterministic repository map across discovery workers.
- Use progressive context slices and expand only when call edges or dataflow leave the slice.
- Route routine mapping and obvious rejection work to deterministic tools or a cheaper model, while escalating high-impact, uncertain, or coverage-critical candidates.
- Apply early stop only to candidates with decisive rejection evidence or already accepted duplicate roots.
- Batch candidates that share the same component and context.
- Generate prose only after validation and deduplication.
- Record a coverage debt item whenever budget ends before a frontier is resolved.

Two internal benchmark profiles are permitted.

- `hunt-balanced` optimizes score per cost while obeying the same coverage floors.
- `hunt-max` maximizes discovery quality and is the primary profile requested for final evaluation.

The initial public CLI and package API remain unchanged. Profiles stay in the experimental benchmark and skill configuration until evidence supports a stable public interface.

## 9. Data and Publication Boundary

The public fork may contain the following material.

- Benchmark schemas, builders, sanitizers, scorers, and synthetic fixtures.
- Public Dev metadata that has passed license and leakage review.
- Aggregate benchmark results and reproducible run receipts.
- Hunt workflow code, prompts, and tests.

The public fork must not contain the following material.

- Hidden Test or Rotating Audit oracles.
- Private customer source, findings, or scan artifacts.
- Generated third-party repository snapshots unless redistribution is explicitly permitted.
- Credentials, service tokens, or account-specific logs.

Corpus preparation may access pinned public sources. Evaluation runs use the already prepared local bundle with outbound network disabled.

## 10. Failure Handling

- A task with a hash mismatch, missing oracle, failed sanitization, or unreproducible snapshot is excluded before the run and recorded as an exclusion.
- A workflow crash, timeout, or malformed result scores as a task failure and remains visible in the receipt.
- A build failure does not automatically prove or disprove a vulnerability; the validator records the failed check and continues with safe evidence when possible.
- A cache entry with mismatched source, tool, schema, prompt, or model identity is ignored.
- A scorer version change invalidates direct comparison unless both workflows are rescored from their raw outputs.
- Hidden-label access from the agent workspace aborts the run as contaminated.

## 11. Verification Strategy

Benchmark implementation follows test-driven development.

- Unit tests cover schema validation, endpoint tolerance, ordered-trace matching, one-to-one deduplication, score weighting, and token accounting.
- Sanitizer tests inject forbidden identifiers and confirm their removal or task rejection.
- Corpus-builder tests use tiny synthetic repositories and pinned fixture hashes.
- Receipt tests prove that task, model, effort, seed support, tools, time limits, and scorer version are recorded.
- Runner tests prove evaluation is offline and that hidden oracle paths are not mounted into the agent workspace.
- Hunt tests cover deterministic sharding, ranking-schema rejection, coverage floors, state transitions, verifier independence, and report filtering.
- Compatibility tests prove Standard behavior and existing public CLI and SDK contracts remain unchanged.
- End-to-end smoke tests run Canary with a fake deterministic model before any paid or long benchmark run.

Before claiming a performance improvement, the project must retain raw predictions, score both workflows with the same grader, run the escalation policy, and publish category-level regressions alongside the aggregate result.

## 12. Milestone Acceptance

The benchmark-foundation milestone is complete when all of these conditions hold.

- Canary, Mini, and Full manifests use one versioned schema.
- Mini can be built reproducibly from pinned inputs without leaking forbidden metadata.
- The scorer and receipt writer pass unit and integration tests.
- A Standard baseline and Hunt comparison can be run under the paired protocol.
- Mini automatically recommends or starts Full according to the escalation policy.
- Final or release mode always requires a completed Full result.
- Standard remains compatible and unchanged by default.
- Hunt produces only validated, deduplicated draft findings.
- Results report discovery quality, false-positive controls, elapsed time, and separated token classes.

A Hunt improvement is not considered confirmed until the Full suite shows a positive paired result, the confidence interval excludes zero, advisory recall improves, and no material category regression is hidden by the composite score.

## 13. Expected Implementation Areas

Exact paths will be confirmed during implementation planning. The likely minimal areas are listed below.

- `benchmarks/hermesbench/` for public schemas, builders, sanitizer, scorer, runner, and fixtures.
- `sdk/typescript/_bundled_plugin/references/` for the Hunt workflow contract.
- `sdk/typescript/_bundled_plugin/skills/` for an experimental Hunt skill entry point.
- `sdk/typescript/_bundled_plugin/scripts/generate_rank_input.py` for reuse or narrowly scoped extension of rank and shard behavior.
- `sdk/typescript/tests-ts/` and benchmark-local tests for compatibility and behavior.
- `sdk/typescript/plugin-files.json` only if new bundled plugin files must ship.

## 14. Primary References

- [Codex Security public repository](https://github.com/openai/codex-security)
- [VulnGym repository](https://github.com/Tencent/VulnGym)
- [VulnGym schema](https://github.com/Tencent/VulnGym/blob/main/SCHEMA.md)
- [IRIS](https://github.com/iris-sast/iris)
- [QLPro paper](https://arxiv.org/abs/2506.23644)
- [Fuzz Introspector sink analysis](https://fuzz-introspector.readthedocs.io/en/latest/user-guides/analyse-sink-function.html)
- [OSS-Fuzz-Gen](https://github.com/google/oss-fuzz-gen)
- [SWE-Router paper](https://arxiv.org/abs/2607.00053)
