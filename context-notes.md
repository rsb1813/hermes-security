# Hermes Security Context Notes

## 2026-08-27

### HermesBench runner task

- Task 4 implementation contract: the Docker runtime accepts only an audited snapshot path, executor scratch path, optional plugin path, command argv, and exact timeout. It resolves a mutable image reference to an immutable image ID before create, and it never accepts final artifact, grader, or oracle paths.
- Task 4 live validation on Docker 29.7.2 Linux amd64 built the pinned runtime image, resolved `sha256:b4bf636d4217de499cbe1d193b6ad3c6e79078dcdb35ff6b340ee2390fecdcd2`, and proved read-only inputs/root, writable scratch, absent Docker socket, non-`none` outer network, and Codex sandbox child denial of a reachable host-local sentinel. Docker does not accept `--pid private`; its default private PID namespace is retained by omitting only that invalid flag.
- Independent Task 4 review fixes reject all pairwise snapshot/plugin/scratch overlaps before Docker, audit original and resolved mount paths, bound Docker CLI control calls, and report exact-container cleanup failures. The opt-in smoke now writes a receipt only to its explicit environment path after marker-based sandbox denial and non-host PID namespace checks pass.

- The runner must complete a full read-only snapshot preflight before it creates run output or calls an adapter. Snapshot hash, bundle audit, path containment, output-root link checks, and snapshot/output disjointness are all fail-closed boundaries.
- Task output uses a digest of the raw task ID rather than the task ID as a filesystem component. The adapter request and task receipt retain the original task ID.
- The runner receives an executor seam that reports raw protocol data, scrubbed event rows, and observed command argument vectors. It records timeout as a terminal receipt but delegates process termination to the later Docker executor.
- The host runner, executor wrapper, and same-user local session are trusted in the runner threat model. The untrusted model receives only an isolated Docker scratch directory and never the final artifact root.
- Runner path checks before and after execution are defense in depth, not an atomic guarantee against a hostile same-user parent-swap process. Such a host process is outside this boundary because it can also access the runner, hidden oracles, and inputs.
- Task 4 live Docker validation must prove that the final artifact root is absent from mounts, argv, environment variables, and cwd, and that only the task scratch directory is writable.

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
- Hunt finalization emits only accepted findings, groups only identical CWE/root-control/sink tuples, preserves every candidate ID, instance, and affected location, and creates a deterministic defensive Markdown draft. Rejected and inconclusive candidate prose never enters that draft.
- The current deterministic repository inventory, rank shards, bounded worker plan, validation, and merge commands can be reused without modifying `generate_rank_input.py`.
- `select-deep-review-input` is not suitable for Hunt coverage because its top-percent behavior can discard low-ranked files. Hunt must preserve the whole inventory and use ranking only for processing order.
- The locally inspected VulnGym revision is `cd69f7e163e08485ab5496115ae03439cda6e27e`.
- The fresh-context Hunt skill RED evaluation combined time, sunk-cost, authority, and cost pressure. Without the skill, the evaluator selected option `A`, invoked `select-deep-review-input`, discarded low-ranked files, and proposed executable PoC or crash-input validation.
- The exact unsafe baseline rationale included `25분 안에 실제 취약점 보고 수를 최대화하려면` and `PoC 재현으로 보고 품질을 확보합니다`. The bundled skill must directly close both the coverage-pruning and offensive-validation loopholes rather than add generic security prose.
- Five fresh-context no-skill control samples and five skill-loaded treatment samples were manually reviewed. Two controls selected rank pruning plus PoC or crash-input validation, while all five treatments selected the contract-compliant full-coverage or balanced-cache option with independent safe validation.
- The Hunt skill was refactored to 493 words after the GREEN samples. A fresh post-refactor pressure test still selected full-file bidirectional review and independent non-destructive validation.
- Bundled-skill verification currently passes all 17 focused Bun tests with 125 assertions and the system `quick_validate.py` skill validator. These checks validate packaging, contracts, deterministic helpers, and pressure behavior; they are not yet an end-to-end repository scan measurement.
- Packaging validation includes the bundled Hunt skill, contract, and helper in the npm archive while excluding Python bytecode caches. The structural package contract passes with 286 entries; the installed-package smoke remains blocked by the same pre-existing Windows credential-home ACL condition seen in the baseline suite.
- The combined Hunt and HermesBench focused suite passes 18 Bun tests with 129 assertions, and HermesBench passes 70 Python tests. Type checking and repository formatting also pass.
- The fixed-seed full suite (`12345`) completed with 1,819 passing, 63 skipped, and 78 failing tests across 1,960 tests in 100 files. The pre-change baseline had 1,800 passing, 63 skipped, and 79 failing tests across 1,942 tests in 98 files.
- Exact failure-list comparison found no current-only failure. The only baseline-only failure was `CLI > styles terminal scan summaries and respects color settings`, which had previously timed out. The remaining failures match the known Windows ACL, symlink-permission, and report-encoding environment categories.
- Standard compatibility is therefore verified as a no-regression result for this Windows environment, not as a claim that all upstream tests pass on this host.
- Independent review found two Important safety gaps and no Critical issue. Hunt helper outputs could previously escape the requested work directory, and bundle auditing did not identify raw VulnGym row markers.
- Every Hunt helper command now requires disjoint `--work-dir` and `--repository` roots and rejects inputs or outputs outside the work directory before writing. The regression test proves a repository source file remains unchanged when selected as an output.
- Bundle auditing now rejects `entry-xxxxx` and `VulnGym` source markers, while private imports inside the repository are restricted to the ignored `benchmarks/hermesbench/private/` root. External private paths remain supported.
- The final review found that a linked private root could redirect ignored logical paths into tracked public storage. The importer now rejects a `benchmarks/hermesbench/private/` symbolic link or junction before resolving the output path, with a regression test for the bypass.
- The runner architecture uses one benchmark-only `codex exec --ephemeral --json --output-schema` adapter for both arms. Standard reads the unchanged bundled `security-scan` skill and Hunt reads `hunt-security-scan`; public `ScanMode`, CLI, and SDK APIs remain unchanged.
- Scored runs require an external container boundary with only snapshot and plugin read-only mounts plus a task-local writable work mount. Hidden oracles are graded outside the container and are never mounted.
- A deterministic fake Canary validates orchestration before model spend. Fake results are wiring evidence only and cannot support a discovery-performance claim.
- Runner receipts will include an execution-policy hash, task-level terminal status, pre-run and post-run snapshot hashes, separated usage, and scrubbed command events. A source change or allowlist violation contaminates the task and excludes its prediction.
- The deterministic Canary uses a single callable fake adapter for both workflows. It determines the synthetic finding only by inspecting snapshot source bytes, records only the snapshot and executor scratch as abstract visible directories, and returns fixed non-zero cached input, uncached input, and output usage. The private oracle remains outside all runner-visible paths; Docker mount proof remains Task 4 work.
- The Canary now uses neutral task IDs and source names. Its fake adapter recognizes the synthetic request-to-operation flow and calculates separated usage from source bytes only, while the regression suite compares every public artifact byte for same-workflow repeats and checks an oracle-only sentinel never crosses the boundary.
- Canary receipt aggregation validates raw task-receipt row count and manifest order before calculating totals. It uses the validated ordered rows directly so a duplicated ID cannot overwrite a missing task in a dictionary.
- Docker runtime cleanup treats a second `KeyboardInterrupt` as a cleanup failure but continues the remaining exact-ID cleanup steps. `SystemExit` remains outside that catch boundary.
- The opt-in Docker smoke treats a pre-existing receipt target as a failure and never removes an environment-selected path. The operator removes only the known ignored receipt before a deliberate rerun; successful evidence is atomically published after container and image cleanup.
- Receipt publication audits the target with `lstat`, not `Path.exists`, so dangling target links are rejected. It also rejects symbolic-link, junction, and reparse-point receipt parents and ancestors before temporary creation and immediately before atomic replacement.
