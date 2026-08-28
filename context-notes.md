# Hermes Security Context Notes

## 2026-08-28

- Hunt discovery now prepares a host-owned deterministic inventory, rank input, full frontier, and bounded priority packet before the container starts. It records pre-execution identities and hashes, requires the exact packet read command, and persists only path-free evidence.
- Hunt workflow receipts use schema version 3 with a discovery-evidence aggregate hash and evidence protocol version 1. Standard workflow receipts retain their exact schema version 2 field set.
- Receipt validation reproduces Hunt discovery evidence from the audited snapshot and prediction, so changing both a persisted evidence artifact and its receipt hash cannot establish acceptance.

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
- Task 5 uses the pinned Codex `0.150.0-alpha.8` external `chatgptAuthTokens` file shape only as a version-locked compatibility boundary. It passes the access token, account ID, and canonical host installation identity with an empty refresh token and never copies the host auth file or Codex home.
- Confidential adapter input travels only through `docker start --attach --interactive` stdin. The container wrapper creates its isolated Codex home in a private `/tmp/hb-runtime-*` tmpfs directory, writes `auth.json` and `installation_id` as mode-0600 regular files with exclusive creation, replaces stdin with `/dev/null`, and removes the directory in `finally`; no credential-bearing bind-mounted artifact exists.
- A harmless structurally valid JWT proved that the pinned image accepts the FIFO-backed `chatgptAuthTokens` payload for `codex login status`; the command exited zero, reported ChatGPT authentication, and the auth path was absent immediately afterward. This is parser and lifecycle evidence, not a live account or model-call result.
- The Task 5 Codex process starts from task scratch rather than the source root. The source remains an explicit read-only absolute path, while `project_doc_max_bytes=0`, isolated config, disabled project rules, and disabled ambient tools prevent snapshot instructions or configuration from changing the benchmark controls.
- Strict-config parsing in the pinned image accepted the frozen network, environment, feature-disable, model, and effort overrides. The no-network diagnostic was stopped after configuration parsing and its exact temporary container was removed.
- Native multi-agent capability is disabled inside a single audited `codex exec` call. In pinned Codex `0.150.0-alpha.8`, `should_process_notification` filters JSONL notifications to the primary thread and turn, while `--ephemeral` removes the child rollout fallback. Child shell commands would therefore be invisible to the post-run command-policy audit.
- Fresh-context verification is preserved as separate top-level container invocations in Task 6. Each phase has its own complete JSONL command and usage evidence, and Standard and Hunt receive the same frozen invocation budget, model, effort, tools, and timeout. This keeps the performance benefit without silently weakening the execution boundary.
- The initial Task 5 adapter added one `codex exec` invocation for both workflows. It transferred only a bounded external-auth payload through interactive attach stdin, used a private unlinked FIFO in `/tmp`, and kept Docker argv, mounts, environment, public receipts, and wrapper errors free of credential values. The adapter disables native multi-agent execution and rejects collaboration events because the pinned root JSONL cannot audit child commands.
- Task 5 RED evidence recorded missing confidential stdin, FIFO wrapper, and adapter modules, followed by oversized confidential input, mismatched token fields, stderr-drain, usage normalization, shell-wrapper, timeout, and host-auth-boundary regressions. The focused suite subsequently passed 43 tests with 3 platform skips.
- The rebuilt pinned image accepted a harmless structurally valid JWT through the FIFO for `codex login status`; the follow-up check verified that the FIFO auth path was absent. The Docker create boundary must request interactive stdin whenever confidential bytes are present because Docker cannot restore closed stdin at start time. A managed access-token-and-account-ID login-status smoke succeeded after that correction without forwarding a host refresh token, ID token, or Codex home.
- Host `codex exec` accepted the final output schema after replacing unsupported `oneOf` and string `minLength` keywords, declaring the `schema_version` integer type, and retaining the Python-side non-empty prediction validation. The container failure was isolated to the isolated runtime's newly generated installation identity, not to the access-token-only external-auth compatibility boundary.
- At the initial FIFO stage, Task 5 read only the canonical UUID from the host auth file's sibling `installation_id` file. The bounded confidential envelope contained exactly the compact external auth object and that identity. The wrapper wrote the identity as mode 0600 inside its private runtime directory, fed only compact auth bytes to the two-reader FIFO, and removed the directory on every completion path.
- The initial one-shot managed-auth schema-bounded no-tool defensive smoke exited zero with a valid public prediction, no audited command, two completed FIFO readers, and cleanup confirmed. Its scrubbed event counts were one each of `thread.started`, `turn.started`, `item.completed`, and `turn.completed`; separated usage was 8,972 uncached input, zero cached input, and 28 output tokens. No raw stdout, stderr, credential, installation identity, or path was retained.
- Final local verification passed 64 focused HermesBench tests with 4 platform skips, all 167 HermesBench Python tests with 4 platform skips, Python bytecode compilation, Dockerfile checking, and `git diff --check`.

### Task 6 paired runner

- Task 6 uses two independent `run_suite` calls per workflow. A separate aggregate receipt binds their committed bytes and the deterministic candidate-transfer artifact so the existing phase `RunReceipt` contract remains unchanged.
- The verification executor is created only after canonicalizing discovery output. This preserves fresh top-level phase invocation while making the bounded candidate data explicit and testable.
- RED evidence covered the missing phase module, a manifest/control time-limit mismatch, and a tampered task receipt whose usage no longer matched the committed phase receipt. Each path was made GREEN with deterministic fakes only.
- Task 6 review hardened the aggregate validation by rebuilding canonical candidates from discovery predictions and comparing the exact LF JSONL bytes before accepting the candidate hash. Verification predictions are then rechecked against that rebuilt subset, so candidate and aggregate rewrites cannot be combined to change the transferred finding locations.
- Phase command JSONL persists the public-safe observed argv vectors for each task and the aggregate receipt binds and revalidates each phase file. The actual top-level invocation count is task count times the number of started phases, rather than a fixed constant.
- Oracle scoring is a host-only callback over verification predictions. It cannot enter adapter requests, prompts, container inputs, or public artifacts; public results and comparison evidence name only identity-free score and phase artifact paths.
- Windows `os.open` must include `O_BINARY` for the canonical candidate JSONL. Without it, the C runtime rewrites LF to CRLF and a strict byte-level candidate reconstruction check fails.
- Final Task 6 verification passed 181 HermesBench Python tests with four platform skips, the focused Bun HermesBench bridge, Python bytecode compilation, and `git diff --check`. TypeScript lint and formatting could not start because this worktree lacks `tsc` and `prettier`; the broader Bun suite retains its known Windows credential ACL and missing `fast-check` environment failures.

### Task 7 generic reviewed corpus builder

- The generic builder consumes exact private ledger rows and pinned local Git objects only. It verifies commits, trees, ancestry, license blob hash, candidate identity, vulnerable gold lines, explicit fixed retired-path locations, and a changed critical root file before publication.
- Vulnerable gold stays solely in `CorpusCandidate`; the ledger stores only the corresponding explicit fixed locations. Anonymous vulnerable, fixed, and group IDs use separate HMAC domains.
- Fixed-only comment redactions bind tree, original blob hash, line range, and expected line bytes. They accept only comment-only lines, preserve line count and newline style, and reject gold/root/trace/retired-location overlaps. Explicit quarantine paths remove only non-gold files from both snapshots; `.patch` and `.diff` paths require quarantine.
- The implementation uses independent snapshot copies rather than hard-link reuse. Real ledger rows, source caches, snapshots, oracles, and provenance receipts remain a main-owned private materialization step.
- Review follow-up hardens the builder output boundary: in-repository output is limited to an actually ignored `corpora/` child with no link or reparse ancestors, while external real directories remain allowed. Git subprocesses strip inherited routing state and disable replacement objects.
- The selected ledger now binds a safe `license_path`; both pinned trees must contain that same blob with the reviewed SHA-256. Quarantine paths may be fixed-only or vulnerable-only, but must exist in at least one tree and remain absent from both materialized snapshots.
- Tree materialization reads the complete `ls-tree -r -z` object set through one argument-vector `git cat-file --batch` invocation per tree. The parser requires each requested object ID, blob type, declared byte length, payload separator, response order, and full-stream exhaustion to match exactly; malformed or missing frames fail closed without exposing source bytes.
- A quarantined mode `120000` blob symlink is represented as tree metadata only and omitted before batch object reading, materialization, audit, and redaction. Its exact path may be one-sided or paired, but ordinary quarantine paths remain symmetric; every path still receives safety and case-fold validation, and all other non-regular modes remain rejected. Gold/root/fixed locations and the reviewed license path cannot be quarantined.
- Comment redactions rewrite only fixed snapshot bytes, so their protected coordinates are exactly `fixed_locations`. Vulnerable gold lines remain the vulnerable oracle source and must not block a reviewed non-retired fixed comment merely because a line number matches after the fix shifts code.
- Corpus publication stages under `output_root.parent` with the fixed short `.hb-` prefix. Windows real corpus builds should use a short external root outside the repository; no source path is removed or shortened to compensate for host path-length limits.
- Builder Git subprocesses scrub inherited `GIT_*` state and then force `GIT_NO_LAZY_FETCH=1`. Missing partial-clone objects now fail locally instead of invoking a promisor remote; real corpus preparation must hydrate objects or use a full clone beforehand.

### Task 8 real corpus and live-run readiness

- The real Canary contains four reviewed vulnerable/fixed pairs and eight snapshots. Independent post-build verification found zero bundle-audit violations and exact tree-hash matches for all eight snapshots.
- The current Mini materialization target is a 24-pair, 48-snapshot Public Dev calibration slice. It is not the complete 48-pair, 96-snapshot Mini and cannot support a promotion or final performance claim until Hidden Test and Rotating Audit groups are added.
- One calibration row was rejected because its reviewed vulnerable and fixed commits were on divergent branches. The strict-descendant invariant remained unchanged, and a previously reviewed Canary Python path-traversal pair was promoted into the Mini subset to preserve task count, language balance, and vulnerability-family coverage.
- Live Hunt CLI runs now fail before adapter creation unless the execution policy contains the exact read-only `rg` prefix and all six bundled Hunt helper prefixes. Standard-only runs retain their independent minimal-policy behavior.
- Score schema version 2 preserves deterministic per-split aggregates after task-level details are removed from the host-visible score. Overall scalar fields remain backward compatible, and cached input, uncached input, and output usage remain separate.

### Task 9 live Codex sandbox boundary

- The paid Canary setup failure occurred at the fixed 30-second two-reader authentication deadline before any receipt tokens were recorded. The pinned Codex path constructs two authentication managers and does not expose a supported switch that disables the managed cloud configuration reader.
- The pinned image cannot start a named permission profile under Docker's built-in seccomp profile because bubblewrap's namespace clone is rejected. A no-model diagnostic with `seccomp=unconfined` progressed immediately, proving seccomp is the discriminating boundary rather than the kernel user-namespace sysctl.
- Disabling seccomp is rejected. The chosen design derives from `moby/profiles` default seccomp at commit `de2c5158b0d0203e9a29f2117f62e97b38813ecd` and adds only the exact pinned bubblewrap clone flags, `unshare(CLONE_NEWUSER)`, and the mount, pivot-root, and unmount setup calls observed with `strace`.
- The diagnostic custom profile started the pinned Codex sandbox with zero added capabilities and `no-new-privileges`. The named filesystem profile read the snapshot and plugin, wrote scratch, and denied both direct and dot-dot-resolved reads of `/tmp/hb-runtime-sentinel/auth.json`.
- The authentication reader deadline may be extended only after that deny rule is part of the production adapter and is proven under the exact runtime create arguments. The outer Docker network remains available for the Codex service, while the inner named permission profile disables model-tool networking.
- Task 9 vendors the Moby default seccomp derivative at commit `de2c5158b0d0203e9a29f2117f62e97b38813ecd` as `containers/seccomp-hermesbench.json`, pins its production-byte SHA-256 to `be61bd3d6278d6cf5c5a78ae68a8b6d483d0d23f98dc7edaf47a9f01d20a5943`, and rejects missing, changed, linked, junction, or reparse paths before Docker create. It adds only exact bubblewrap clone flags, `unshare(CLONE_NEWUSER)`, and mount setup calls.
- Rebuilt `hermesbench-runtime-task5-local:latest` passed the no-model named-profile smoke. The child read snapshot/plugin and wrote scratch, while snapshot/plugin/root writes, direct and dot-dot authentication sentinel reads, and host-local networking were denied. Under uid 10001 with cap-drop ALL and no-new-privileges, `unshare --user --map-root-user` succeeded; mount-only, combined user+mount, and direct mount attempts failed. The two-reader deadline is a bounded 60 seconds.

### Task 10 paid-smoke observability

- The rebuilt runtime image used for live calibration is pinned in the private controls by its resolved image ID. Rebuilding the existing Dockerfile changed the ID because package resolution is not fully reproducible, so all comparisons must continue to bind the exact resolved ID rather than the mutable tag.
- The two-task `hunt-balanced` paid smoke reached live container execution but ended before verification. One discovery task timed out after approximately 496 seconds and one failed after approximately 247 seconds. The aggregate status was incomplete and every recorded token class remained zero.
- Raw model text, source identities, credentials, and private oracle data were not retained. Snapshot pre/post hashes matched, and the failed run produced only public-safe requests, receipts, and empty candidate transfer.
- The current runner collapses all non-timeout executor exceptions into `failed` and discards the scrubbed adapter reason. The next logical unit adds only a fixed public failure code so protocol debugging does not require retaining confidential output.
- A read-only implementation audit found that the current Hunt adapter differs from Standard mainly by skill and profile prompt while both use the same single-agent two-phase structure. After the live boundary is stable, the highest-impact performance work is to preserve a larger internal candidate pool, carry evidence and counterevidence into verification, and require explicit verifier dispositions before projecting the existing five-finding public schema.
- The runner now revalidates an executor failure code immediately before writing `failure.json`; a reassigned value outside the public code contract is recorded as `executor_failure`, and later tasks still execute.
- Receipt schema version 3 binds each phase's ordered task failure-sidecar hashes. Workflow receipts already hash phase receipts, and incomplete verification validation now rehashes its phase, so a changed failure code is rejected without changing scores or comparisons.
- If success artifact publication fails mid-task, the runner removes only its exact known regular single-link artifact names after validating the task tree; unexpected or linked entries remain fail-closed. Failure evidence now verifies every task-directory component, the sidecar's regular single-link metadata, and canonical allowlisted JSON bytes before hashing those same bytes.
- Failure evidence reads through a no-follow binary descriptor, verifies descriptor metadata and identity against both pre-open and post-close path metadata, and rejects oversized sidecars before JSON parsing. This narrows replacement races without changing score or comparison semantics.
- Paid smoke v6 reproduced one bounded task timeout and classified the other task as `final_response_invalid`; both sidecars matched the phase failure-evidence digest and the phase receipt matched the workflow receipt.
- Pinned Codex `0.150.0-alpha.8` exposes `-o, --output-last-message <FILE>`. The adapter will use that explicit final-message channel rather than treating the first JSONL `agent_message` event as the schema-bound final response. This preserves command and usage auditing while allowing unstructured progress messages.
- A one-task paid diagnostic with the final-message boundary ended after approximately 35 seconds with `child_auth_unauthorized` and zero recorded token usage, before verification. A host-side invocation of the same pinned Codex version, model, strict config, disabled features, and managed ChatGPT credentials succeeded, so account entitlement and the access-token expiry check are not the differentiator.
- The next diagnostic keeps `chatgptAuthTokens`, the refresh-token exclusion, the FIFO, and every runtime control fixed. It exposes only whether the child failed before the second bounded auth read or after the replay completed; no stderr bytes or credential-derived values enter artifacts.
- Paid single-task diagnostic v8 ended after approximately 33 seconds with `child_auth_unauthorized_after_replay`; both bounded FIFO reads completed before the second server rejection, and every recorded token class remained zero. This rules out a missing replay opportunity and narrows the live incompatibility to the isolated auth representation or mode rather than the final-response channel.
- The next bounded diagnostic compares two tmpfs regular-file variants using the same access token, account identity, installation identity, image, Codex version, strict configuration, and minimal prompt. Variant A changes only FIFO storage to a regular file while retaining `chatgptAuthTokens`; variant B additionally changes only `auth_mode` to managed `chatgpt`. The host refresh token and host auth path remain excluded, and raw child output is never persisted.
- Variant A succeeded in approximately 7 seconds while retaining `chatgptAuthTokens`, the access-token-as-ID representation, account identity, installation identity, image, strict configuration, and feature controls. It used 9,001 uncached input tokens, zero cached input tokens, and five output tokens; the host scratch directory remained empty and no container remained. This identifies FIFO file semantics as the live incompatibility, so the managed-mode variant was intentionally skipped to avoid a second variable and unnecessary cost.
- The production fix will replace only the FIFO with a mode-0600 regular file inside the existing container `/tmp` tmpfs. The private directory remains mode 0700, the host refresh token and auth path remain excluded, the named permission profile continues to deny `/tmp/hb-runtime-*`, and the exact container is still removed after every invocation.
- The production wrapper now uses the private regular-file runtime contract. It removed FIFO reader and replay machinery and emits the ordinary fixed `auth_unauthorized` category for a future live failure, while the runner continues to accept historical replay-specific receipt codes.
- The regular-file implementation passed its focused wrapper and adapter suite, then all 220 HermesBench Python tests with four platform skips, bytecode compilation, and `git diff --check`. It deliberately did not rebuild the image or make another paid invocation.
- The rebuilt regular-file image resolved to the immutable local ID recorded in the private controls. A no-model image smoke verified a mode-0700 tmpfs runtime, mode-0600 single-link regular auth and installation files, and two independent reads of identical auth bytes. The named Codex permission smoke again denied direct and dot-dot auth-path reads and tool networking, and the full 220-test suite remained green with four platform skips.
- Paid single-task diagnostic v9 passed the former 33-second authentication failure boundary and ran discovery for approximately 347 seconds, but ended before verification with fixed code `command_event_invalid` and zero recorded token classes. The source snapshot set still passed the pre-run audit and hash check.
- Pinned Codex source defines exec JSONL `command_execution.command` as a string. The adapter currently applies a raw-character blacklist before shell quote parsing, so quoted vulnerability-search regex metacharacters such as alternation, grouping, or an end anchor are indistinguishable from actual composition at that stage. The correction must parse quoting first, reject genuine unquoted pipelines, redirects, control operators, and substitutions, then replace any non-public argument token with a stable SHA-256 token before command evidence is written.
- TDD RED confirmed the v9 correction: a single-quoted `rg` regex containing `|`, `(`, `)`, `$`, and `>` was rejected before parsing, while an unquoted `#` comment was accepted. GREEN replaced the raw blacklist with a bounded quote-aware scanner and bounded `/bin/sh` or `/bin/bash -c` unwrap. It rejects unquoted composition plus double-quoted substitution, retains escaped literals, and hashes every final argument outside the runner's public-token contract. Focused adapter, runner, and workflow tests prove the exact safe argv behavior, compound-command failure before success artifacts, hashed `commands.jsonl` publication, and receipt revalidation.
- The SHA-256 boundary initially leaked `UnicodeEncodeError` for a lone UTF-8 surrogate. A separate RED/GREEN cycle now maps that encoding failure to the same fixed `command_event_invalid` code, so neither the malformed argument nor interpreter exception text can enter artifacts or receipts.
- Paid single-task diagnostic v10 completed discovery and fresh-context verification in approximately 318 seconds with two top-level invocations. It recorded 1,209,856 cached input tokens, 107,605 uncached input tokens, and 7,197 output tokens. The aggregate receipt revalidated against the frozen controls, policy, manifest, phase receipts, commands, candidate transfer, and source snapshots.
- The live pipeline transferred and verified one candidate but did not detect the benchmark advisory. The score was 0.15, entirely from fixed-snapshot specificity; advisory recall, localization, and trace scores were zero. Discovery used inventory and rank helpers plus direct source search, but did not execute the frontier, closure, candidate-normalization, or validation-artifact helpers described by the Hunt contract. This is now the performance baseline rather than a harness failure.
- After v10, all eight Canary snapshots again had zero audit violations and matching manifest hashes. Twenty retained public artifacts contained neither any bounded host-auth value nor the host auth path, and no container remained.
- The v10 candidate was a single 0.88-confidence, three-hop hypothesis that did not overlap the hidden expected path and was rejected by verification. The hidden defect belongs to an input-to-interpretation injection family, so the primary failure is hypothesis formation and boundary tracing rather than an over-strict verifier alone.
- Three changes were compared. Prompt-only enforcement is cheap but unauditable; rich candidate packets preserve discovery meaning but do not prove Hunt coverage; a persistent artifact gate binds the documented Hunt process but requires a broader protocol change. The chosen staged design implements the rich internal pool first, then binds deterministic inventory, frontier, candidate references, and coverage debt. A second discovery call is reserved for `hunt-max` only if those two changes still miss the fixed diagnostic.
- Full per-file closure is not a credible 480-second completion rule for the diagnostic's roughly 15,000-file, 98 MB source tree. The benchmark must preserve the full inventory while distinguishing prioritized evidence from explicit unreviewed debt; it must not convert machine-generated closure rows into a false claim of manual review.

### Task 13 rich candidate protocol RED

- RED: `python -m unittest benchmarks.hermesbench.tests.test_hunt_candidate_protocol` failed with `ModuleNotFoundError: No module named 'benchmarks.hermesbench.hunt_protocol'`. The failing test requires six bounded Hunt discovery candidates and phase-specific terminal-decision parsing; the existing public prediction contract only supports five findings and has no rich protocol module.
- GREEN: the new strict Hunt protocol accepts six internally bounded rich candidates, rejects a thirteenth candidate and invalid rich text, and enforces accepted/rejected/inconclusive proof rules. Hunt-only discovery and verification schemas are selected by the Codex adapter, transfer JSONL retains the rich candidate fields, the verifier requires an exact terminal-decision set and accepted-finding projection, and workflow receipts bind both phase prediction SHA-256 digests.
- Verification: `python -m unittest discover -s benchmarks/hermesbench/tests -p 'test_*.py'` passed 227 tests with four platform skips; `python -m compileall -q benchmarks/hermesbench` and `git diff --check` also passed. No Docker build, model invocation, network call, or private benchmark/auth path access was performed.

### Task 13 follow-up review RED

- RED: the new Hunt score-callback integration test completed without a public final-predictions artifact because the old Hunt search-pass vocabulary rejected the existing `forward` frontier pass before scoring. The new adapter test also proved that the Hunt discovery prompt inherited the contradictory `Use at most five findings` sentence from the shared Standard prompt body.
- GREEN: Hunt now emits a receipt-bound `*-public-predictions.jsonl` projection without terminal decisions, and only that public file reaches scoring and `final_predictions`; receipt validation rehashes it and checks it against the decision-bearing verification artifact. The workflow receipt schema is v2 and frozen controls are v2 because both shapes changed; v1 receipts and controls are rejected rather than ambiguously parsed. Hunt uses the existing `forward/backward/guard/parser/state/general` frontier vocabulary, and the adapter performs phase-specific response parsing before runner handoff.
- Follow-up verification: a real synthetic Hunt workflow preserves six rich candidates through transfer and verification, accepts only five public findings, rejects a missing terminal decision, and validates its public scorer projection. The full HermesBench suite passed 230 tests with four platform skips, followed by successful compileall and diff checks. No Docker build, model invocation, network call, or private benchmark/auth path access was performed.

### Task 13 incomplete Hunt receipt RED

- RED: `test_incomplete_hunt_receipt_has_no_public_predictions_and_revalidates` produced a normal incomplete Hunt workflow after fixed `final_response_invalid` verification failures, but `validate_workflow_receipt` incorrectly required a nonexistent public-projection hash and raised `workflow receipt public predictions hash does not match`.
- GREEN: public projections and hashes are now mandatory only for completed Hunt workflows. Incomplete Hunt and every Standard workflow must have neither a public hash nor a public-predictions artifact; receipt validation rejects an unexpected artifact fail-closed. The full suite passed 231 tests with four platform skips, and compileall plus diff checks passed without Docker, model, network, or private/auth-path access.

### Task 13 paid diagnostic v11

- The rebuilt rich-protocol runtime image passed direct schema mode checks and the existing named-permission smoke before the paid run. Its immutable image ID is held only in the ignored private controls.
- Paid single-task diagnostic v11 completed two top-level Hunt invocations in approximately 687 seconds. Discovery used approximately 466 seconds and verification used approximately 221 seconds.
- v11 recorded 2,760,960 cached input tokens, 184,782 uncached input tokens, and 16,183 output tokens. The discovery phase recorded 2,007,808 cached, 106,615 uncached, and 9,684 output tokens; verification recorded 753,152 cached, 78,167 uncached, and 6,499 output tokens.
- The rich protocol increased the internal pool from one candidate to three and produced one terminal verifier decision for every candidate. All three candidates were rejected, leaving zero public findings, zero advisory recall, zero localization credit, and the unchanged 0.15 composite score from fixed-snapshot specificity.
- Relative to v10, elapsed time increased by about 2.16 times and uncached input increased by about 1.72 times without any discovery gain. Candidate-count expansion alone is therefore rejected as a sufficient performance strategy.
- The v11 workflow receipt revalidated at schema version 2. All eight Canary snapshots retained zero audit violations and exact manifest hashes; 21 retained artifacts contained no bounded host-auth value or host path, and no container remained.
- Discovery invoked the deterministic frontier helper once, but the workflow did not retain or receipt-bind the resulting inventory, frontier, candidate references, or unreviewed debt. The next material change is an adapter-enforced artifact gate, not an additional model call.

### Task 14 artifact-gate design

- A read-only architecture review selected host-precomputed artifacts over model-authored closure files or model-authored coverage summaries. The host can reproduce and validate the evidence while the model cannot inflate reviewed coverage.
- A no-model probe over the fixed diagnostic generated a 15,027-row full inventory in 0.112 seconds, an 11,277-row rank input in 16.607 seconds, and an 11,277-row frontier in 0.614 seconds. Their raw sizes were approximately 1.08 MB, 4.43 MB, and 3.34 MB, so bounded host preparation is practical relative to the 480-second task budget.
- Ruling: Standard keeps exact workflow-receipt schema version 2 and unchanged artifacts, while Hunt alone advances to receipt schema version 3 with evidence hash and protocol fields. Frozen controls remain schema version 2 because the existing paired controls are shared by Standard and Hunt. If this ruling is wrong, receipt parsing will need separate public types rather than conditional exact fields.
- The bounded priority packet presents at most 512 rows for `hunt-balanced` and 1,024 for `hunt-max`, with at most 384 UTF-8 preview bytes per row and a one-MiB total cap. It changes initial review order only; the full inventory and frontier remain eligible and every unvalidated frontier pass stays debt.
- Candidate linkage never counts as reviewed closure. The host links every candidate location and search pass to the precomputed frontier, but `validated_closure_count` remains zero until a later independently verified closure protocol is added.
