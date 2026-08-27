# Hermes Security Context Notes

## 2026-08-27

### Repository state

- The upstream repository is `openai/codex-security` under Apache-2.0.
- The public fork is `rsb1813/hermes-security`.
- Development uses an isolated local Git worktree.
- `origin` points to the Hermes fork and `upstream` points to OpenAI.
- Foundation work uses the branch `hermes/benchmark-foundation`.
- The starting upstream commit is `fd98a9009b0a3a919b6cbce7c541b09d543dcaec`.

### User intent

- The main goal is materially higher vulnerability discovery quality.
- Cost reduction remains useful, but it must not cap the maximum-performance path.
- Hermes should validate candidates automatically and produce a draft report.
- The benchmark must avoid exploit generation and offensive success criteria.
- `HermesBench-mini` is for fast, economical iteration.
- If Mini cannot distinguish configurations, the larger and more diverse `HermesBench` must decide.
- The final-stage result always requires `HermesBench`, even when Mini appears decisive.

### Evidence gathered

- VulnGym v0.1.4 exposes human-review status and entry-point, critical-operation, and trace labels suitable for defensive localization scoring.
- The inspected VulnGym data reports 393 human-reviewed entries out of 408 and covers 178 of 184 advisories.
- The upstream evaluator emphasizes recall and endpoint tolerance, so Hermes adds precision-aware matching, trace scoring, fixed negatives, and adjudication.
- IRIS demonstrates a useful architecture pattern that combines generated source and sink specifications, CodeQL paths, and model-based false-positive filtering.
- Fuzz Introspector and OSS-Fuzz-Gen provide optional future signals for reachable sinks and coverage gaps; they are not first-milestone dependencies.
- The bundled Codex Security plugin already contains deterministic rank-input generation, sharding, schema validation, merge receipts, and deep-review selection in `generate_rank_input.py`.

### Design decisions

- Standard remains unchanged and is the compatibility baseline.
- Hunt is an experimental sibling workflow.
- Ranking changes processing order but cannot permanently exclude low-ranked components.
- Discovery searches both forward from low-trust entry points and backward from sensitive operations.
- An independent verifier challenges each candidate before reporting.
- Only accepted, deduplicated findings reach the draft report.
- Public CLI and npm package names remain unchanged in the first milestone.
- CodeQL, Fuzz Introspector, and OSS-Fuzz-Gen are optional adapters after the benchmark and core Hunt loop work.

### Benchmark decisions

- Mini uses 48 vulnerable entries split into 16 Public Dev, 16 Hidden Test, and 16 Rotating Audit entries, with an eight-entry Canary subset.
- Every Mini vulnerable snapshot has an anonymously fixed negative, for 96 evaluated snapshots in a complete run.
- Public Dev and Canary are diagnostic only; promotion statistics use unseen Hidden Test and Rotating Audit groups.
- Full uses every eligible deduplicated VulnGym `verify=1` case, matched fixed negatives, curated clean controls, and compatible diversity lanes.
- Full is not ready for a final claim below 144 vulnerable tasks or without adding previously absent cases on at least three diversity axes.
- Splits are grouped by repository and advisory to reduce leakage.
- The agent never receives labels, patches, advisory IDs, commit history, PoCs, or flags.
- Predictions are capped at five findings per task.
- The primary score combines pair localization F1, advisory recall, trace-node F1, and fixed-snapshot specificity.
- Paired comparisons hold task, model, effort, seed support, tools, time, and grader constant.
- Cached input, uncached input, and output tokens are recorded separately.

### Escalation decision

- Full is mandatory for final or release evidence.
- Full is triggered when the paired confidence interval includes zero, the Hidden Test gain is below two additional localized advisories, repeat winners are unstable, a category recall regression exceeds five percentage points, or comparison semantics changed.
- The two-of-sixteen rule is an iteration heuristic. It is not treated as statistical proof.

### Public and private boundary

- Public code may include builders, schemas, scorers, synthetic fixtures, safe aggregate results, and reviewed Public Dev metadata.
- Hidden oracles, generated third-party snapshots, customer code, private findings, credentials, and account-specific logs are never committed.
- Corpus preparation may use pinned public network sources, but evaluation is offline.

### Open implementation questions

- Confirm the narrowest integration point for invoking Hunt without changing the public CLI.
- Confirm the exact VulnGym revision and eligible corpus count during corpus preparation.
- Decide whether the first runner adapter invokes the existing CLI, plugin skill, or internal SDK after reading the actual call boundaries.
- Decide which optional diversity lane is reproducible enough for the first full edition.

### Written design approval and implementation decomposition

- The user approved the written design on 2026-08-27 and explicitly authorized development.
- The implementation is split into independently testable benchmark-foundation and Hunt-workflow plans.
- `docs/superpowers/plans/2026-08-27-hermesbench-foundation.md` is the first executable plan.
- The benchmark foundation remains outside the public SDK and CLI surface under `benchmarks/hermesbench/`.
- Hunt will initially enter through a standalone bundled skill because adding it to `ScanMode` would change the public CLI and SDK contracts.
- The pre-change TypeScript baseline on Windows completed with 1,800 passing, 63 skipped, and 79 failing tests. The failures are dominated by credential-home ACL checks and unavailable symlink creation, with one CLI color test timeout, so HermesBench validation must use focused tests while retaining this baseline as environmental evidence.
- HermesBench contracts use schema version `1`, exact top-level field sets, repository-relative normalized locations, immutable parsed objects, a five-finding cap, and task-kind-specific oracle invariants.
- Scoring uses bounded one-to-one endpoint matching, ordered trace LCS credit, advisory-level recall, and per-fixed-snapshot specificity. Findings unrelated to the retired path remain provisional instead of becoming automatic false positives.
- Run receipts compare every frozen control field while leaving workflow and profile identities outside that equivalence check. Cached input, uncached input, and output token counts remain separate serialized values.
- Mini-to-Full escalation is mandatory for final, release, and public-performance decisions, and also triggers on inconclusive confidence, hidden gain below two, repeat instability, category regression beyond five points, or comparison-semantic changes. Full readiness requires at least 144 vulnerable tasks and three new diversity axes.
- Agent-visible bundle auditing is read-only. It rejects or records VCS metadata, advisory identifiers in paths or bytes, symbolic links, and non-regular hash inputs without redacting or rewriting source files.
- The strict importer was exercised against all 408 rows at VulnGym revision `cd69f7e163e08485ab5496115ae03439cda6e27e`: 393 reviewed candidates across 178 advisories were accepted and 15 unverified entries were excluded. This was an in-memory local check; no generated IDs or private labels were written into Git.
- Canary, Mini, and Full now share one strict manifest parser with snapshot hashes, ordered task descriptors, explicit command allowlists, time limits, and duplicate task rejection.
- The standalone CLI now exposes scoring, controlled receipt comparison, bundle auditing, and private VulnGym import without changing the existing Codex Security CLI or SDK surface.
- Foundation verification on 2026-08-27 passed 70 Python tests, the focused Bun bridge test, TypeScript type checking, repository formatting, and Python bytecode compilation. The unchanged full TypeScript baseline remains separately known to fail 79 environment-dependent Windows tests.
- Hunt will use a new bundled skill and standalone deterministic helper, not a new `ScanMode`. Its frontier retains every ranked input file, `hunt-max` applies both directions everywhere, independent validation accepts only safe evidence methods, and finalization deduplicates only exact root-control and sink tuples.
- The first Hunt helper unit preserves every authoritative rank-input path, retains `include: false` rows, orders work by component coverage rounds, and emits stable cache-bound receipts. Default repository areas are subdivided by source-tree component so a single `.` area cannot defeat the coverage floor.
- Frontier closure now requires one terminal row per work item and reports component, signal, and pass coverage. Deferred work remains explicit coverage debt; duplicate, unknown, or missing work IDs fail closed.
- Validation preparation labels discovery output as an unverified hypothesis. Terminal decisions require a distinct verifier identity, safe non-exploit methods, complete candidate coverage, and disposition-specific proof; accepted findings additionally require proven attacker control, reachability, impact, guard failure, concrete evidence, and remediation.
- The current deterministic repository inventory, rank shards, bounded worker plan, validation, and merge commands can be reused without modifying `generate_rank_input.py`.
- `select-deep-review-input` is not suitable for Hunt coverage because its top-percent behavior can discard low-ranked files. Hunt must preserve the whole inventory and use ranking only for processing order.
- The locally inspected VulnGym revision is `cd69f7e163e08485ab5496115ae03439cda6e27e`.
