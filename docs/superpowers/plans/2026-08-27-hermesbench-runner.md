# HermesBench Runner and Canary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with test-driven development.

**Goal:** Run Standard and Hunt on identical anonymized snapshots under a reproducible isolation boundary, verify the runner with a zero-cost deterministic Canary, then support paid Canary, Mini, and Full comparisons with exact usage accounting.

**Architecture:** A Python standard-library orchestrator validates manifests, audits and hashes every agent-visible snapshot, creates disjoint task work directories, and invokes one strict adapter protocol. Real model runs execute through `codex exec --ephemeral --json --output-schema` inside a hardened Docker container. Standard loads the unchanged bundled `security-scan` skill; Hunt loads the bundled `hunt-security-scan` skill. The container receives the snapshot, selected plugin, schema, and task work directory, but never receives grader oracles. Both workflows use the same resolved image, model, reasoning effort, tool policy, timeout, task order, and grader. A deterministic fake adapter exercises the complete orchestration path before any model spend.

**Tech Stack:** Python 3.10+ standard library, `unittest`, JSON/JSONL, Docker Engine, Codex CLI non-interactive mode, Bun integration tests, Git.

**Spec:** `docs/superpowers/specs/2026-08-27-hermes-security-design.md`

## Decisions and rejected alternatives

- Use a benchmark-only adapter instead of adding Hunt to public `ScanMode`. This keeps the npm API and existing CLI unchanged.
- Use the actual bundled Standard skill through its supported prompt-only headless path. Do not rewrite or fork the Standard instructions.
- Use one Codex executable adapter for both workflows. An SDK-only Standard path plus a direct Hunt path was rejected because it would change the available tools and host behavior between paired arms.
- Use an external container boundary. A host-local subprocess was rejected for scored runs because hidden oracles elsewhere on the host would still be readable.
- Keep scoring outside the execution container. Mounting a grader or oracle read-only would still leak it to an agent that can read files.
- Allow model-service egress only to the parent Codex process. Agent shell commands run with `sandbox_workspace_write.network_access=false`, web search disabled, secret-like environment variables excluded, and no host Docker socket.
- Treat the deterministic fake Canary as runner validation only. It is not vulnerability-discovery evidence.

## Global constraints

- Never mount or copy hidden oracles, VulnGym metadata, patches, advisory identifiers, credentials, or host session logs into an agent-visible task filesystem.
- Mount the snapshot and plugin read-only. Mount only the task work directory writable.
- Keep source bundles free of VCS metadata, symbolic links, advisory identifiers, and VulnGym source identifiers.
- Do not run exploits, proof-of-concept payloads, crash inputs, or remote target traffic.
- Permit only static reads and manifest-declared safe build, type-check, or existing-test commands during validation.
- Preserve scrubbed command events and mark a task contaminated when an executed validation command is outside its manifest allowlist.
- Record total input, cached input, derived uncached input, and output tokens without collapsing the classes.
- When the backend has no deterministic seed, run three paired repeats and alternate which workflow runs first.
- Full remains mandatory for a final result even when Mini is decisive.
- Every output path must be outside every snapshot. All generated results remain under ignored benchmark work directories.

## File structure

- `benchmarks/hermesbench/adapter_contract.py` defines strict task requests and responses.
- `benchmarks/hermesbench/runner.py` validates inputs, schedules paired runs, aggregates receipts, and owns task timeouts.
- `benchmarks/hermesbench/container_runtime.py` creates, attaches to, kills, and removes exact Docker containers.
- `benchmarks/hermesbench/adapters/fake.py` provides the deterministic zero-cost adapter.
- `benchmarks/hermesbench/adapters/codex_exec.py` launches the selected bundled skill through non-interactive Codex and parses JSONL usage.
- `benchmarks/hermesbench/schemas/prediction-response.schema.json` constrains the final model response.
- `benchmarks/hermesbench/containers/Dockerfile` pins the execution runtime and required static tools.
- `benchmarks/hermesbench/fixtures/runner-canary/` contains public synthetic source and oracle fixtures for orchestration tests only.
- `benchmarks/hermesbench/tests/test_adapter_contract.py` validates protocol boundaries.
- `benchmarks/hermesbench/tests/test_runner.py` validates audit, hash, ordering, timeout, and receipt behavior.
- `benchmarks/hermesbench/tests/test_container_runtime.py` validates exact Docker arguments and cleanup without starting a real container.
- `benchmarks/hermesbench/tests/test_codex_exec_adapter.py` validates command construction and JSONL usage parsing without a model call.
- `benchmarks/hermesbench/cli.py` adds benchmark-only `run` and `run-paired` commands.

---

### Task 1: Strict adapter protocol and token conversion

**Files:**
- Create: `benchmarks/hermesbench/adapter_contract.py`
- Create: `benchmarks/hermesbench/tests/test_adapter_contract.py`
- Modify: `benchmarks/hermesbench/receipts.py`
- Modify: `benchmarks/hermesbench/tests/test_receipts.py`

- [ ] Write failing tests for exact request and response fields, task ID equality, bounded predictions, non-negative usage, and `uncached = input - cached`.
- [ ] Reject cached input greater than total input and reject unknown fields.
- [ ] Ensure the request contains only agent-visible task data and cannot contain an oracle path or labels.
- [ ] Add `execution_policy_sha256` to frozen run controls and a task receipt containing terminal status plus pre-run and post-run snapshot hashes.
- [ ] Run `python -m unittest benchmarks.hermesbench.tests.test_adapter_contract benchmarks.hermesbench.tests.test_receipts -v` and verify GREEN.
- [ ] Commit as `feat: define the HermesBench adapter protocol`.

### Task 2: Snapshot-safe suite runner

**Files:**
- Create: `benchmarks/hermesbench/runner.py`
- Create: `benchmarks/hermesbench/tests/test_runner.py`

- [ ] Write failing tests proving a hash mismatch, bundle contamination, missing snapshot, linked output root, and snapshot/output overlap stop before adapter invocation.
- [ ] Resolve each snapshot as `<snapshots-root>/<task_id>`, run `audit_bundle`, and require `tree_sha256` to equal the manifest value.
- [ ] Create one disjoint work directory per run and task, then write only a request JSON, adapter response JSON, scrubbed event log, prediction JSONL, task receipt JSONL, and aggregate run receipt.
- [ ] Enforce each task timeout and convert adapter protocol failures into terminal task records without fabricating empty successful predictions.
- [ ] Re-audit and re-hash the snapshot after execution; mark any change or command-policy violation contaminated and exclude its prediction from scoring.
- [ ] Aggregate token classes and elapsed time exactly once per task.
- [ ] Run `python -m unittest benchmarks.hermesbench.tests.test_runner -v` and verify GREEN.
- [ ] Commit as `feat: run audited HermesBench task suites`.

### Task 3: Deterministic zero-cost Canary

**Files:**
- Create: `benchmarks/hermesbench/adapters/__init__.py`
- Create: `benchmarks/hermesbench/adapters/fake.py`
- Create: `benchmarks/hermesbench/fixtures/runner-canary/README.md`
- Create: `benchmarks/hermesbench/tests/test_fake_canary.py`

- [ ] Write a failing end-to-end test that materializes synthetic vulnerable and fixed snapshots, builds their manifest hashes, runs both workflows, scores private test oracles outside the task work directory, and compares identical controls.
- [ ] Make the fake adapter derive its answer only from the mounted synthetic source bytes. Do not pass expected findings in the request.
- [ ] Give Standard and Hunt identical deterministic predictions and separated non-zero fake usage so receipt aggregation is exercised.
- [ ] Prove the adapter request and container-visible directory list contain no oracle path.
- [ ] Run the full Python HermesBench suite and verify GREEN.
- [ ] Commit as `test: add the zero-cost HermesBench runner Canary`.

### Task 4: Hardened Docker runtime

**Files:**
- Create: `benchmarks/hermesbench/container_runtime.py`
- Create: `benchmarks/hermesbench/tests/test_container_runtime.py`
- Create: `benchmarks/hermesbench/containers/Dockerfile`

- [ ] Write failing tests for read-only snapshot and plugin mounts, writable task-only output, read-only root filesystem, dropped capabilities, no-new-privileges, PID and resource limits, absent Docker socket, and resolved image ID recording.
- [ ] Use `docker create` followed by `docker start --attach`. On timeout or interruption, kill and remove only the exact container ID returned by `docker create`.
- [ ] Never construct a shell command. Pass every Docker token as an argument vector.
- [ ] Add a live isolation smoke that verifies snapshot writes and outbound shell traffic fail while task-output writes succeed. Skip with an explicit reason when Docker is unavailable.
- [ ] Build the pinned runtime image and record its image ID in a private run receipt rather than committing a mutable local tag as evidence.
- [ ] Commit as `feat: isolate HermesBench adapters in Docker`.

### Task 5: Codex non-interactive adapter

**Files:**
- Modify: `benchmarks/hermesbench/container_runtime.py`
- Modify: `benchmarks/hermesbench/tests/test_container_runtime.py`
- Modify: `benchmarks/hermesbench/containers/Dockerfile`
- Create: `benchmarks/hermesbench/containers/codex_auth_fifo.py`
- Create: `benchmarks/hermesbench/tests/test_codex_auth_fifo.py`
- Create: `benchmarks/hermesbench/adapters/codex_exec.py`
- Create: `benchmarks/hermesbench/schemas/prediction-response.schema.json`
- Create: `benchmarks/hermesbench/tests/test_codex_exec_adapter.py`

- [ ] Write failing tests for a bounded confidential-stdin transport that never places credentials in Docker argv, environment, inspect metadata, bind mounts, or public output.
- [ ] Feed only the current ChatGPT access token and account ID into a FIFO under the container `/tmp` tmpfs. Never pass a refresh token, the full host `auth.json`, or the host `CODEX_HOME`.
- [ ] Make the FIFO feeder cancellation-safe, unlink the authentication path immediately after the reader handshake, and replace Codex stdin with `/dev/null` before launching the child.
- [ ] Reject malformed, expired, or insufficient-lifetime access tokens before container launch and fail closed on authentication errors without logging credentials.
- [ ] Write failing tests for Standard and Hunt skill selection, identical non-workflow flags, explicit model and effort, `--ephemeral`, `--json`, `--output-schema`, isolated config, workspace-write sandbox, and disabled command network access.
- [ ] Disable web search, connectors, ambient project configuration, persistent sessions, and inherited secret-like shell variables.
- [ ] Disable native multi-agent execution inside each audited `codex exec` call and fail closed if collaboration events appear. The pinned root JSONL stream omits child-thread command executions, so enabling it would make command-policy enforcement incomplete.
- [ ] Give both arms the same defensive task prompt and exact prediction schema. Change only the selected skill and Hunt profile.
- [ ] Parse the final structured response into `TaskPrediction`; parse `turn.completed.usage.input_tokens`, `cached_input_tokens`, and `output_tokens` from JSONL; fail closed on missing or inconsistent usage.
- [ ] Preserve scrubbed event types and command counts, but never copy raw reasoning, credentials, source snippets, or session logs into public results.
- [ ] Run adapter unit tests without a model call, a fixed-image FIFO parser regression, and then one authenticated synthetic task smoke in the container.
- [ ] Commit as `feat: connect HermesBench to Codex exec`.

### Task 6: Paired CLI and repeat policy

**Files:**
- Modify: `benchmarks/hermesbench/cli.py`
- Modify: `benchmarks/hermesbench/tests/test_cli.py`
- Create: `benchmarks/hermesbench/phase_runner.py`
- Create: `benchmarks/hermesbench/tests/test_phase_runner.py`
- Modify: `benchmarks/hermesbench/README.md`

- [ ] Write failing CLI tests for a single workflow run and a paired run.
- [ ] Run discovery and independent verification as separate top-level adapter invocations, each with its own complete command and usage stream. Give Standard and Hunt the same frozen invocation budget, model, effort, tools, and timeout; vary only the selected skill and Hunt profile.
- [ ] Pass only a bounded, schema-validated candidate set from discovery to verification as untrusted data. Aggregate every phase's separated usage and observed command vectors, and fail the task when any phase is unauditable or incomplete.
- [ ] Require one frozen control document containing model, effort, seed support, image, tool versions, time limit, finding cap, and grader version.
- [ ] Resolve the task order once. When seed support is false, schedule `standard,hunt`, `hunt,standard`, and `standard,hunt` across three repeats.
- [ ] Reject a paired comparison when any frozen control, snapshot hash, task order, or adapter version differs.
- [ ] Emit machine-readable paths for predictions, task records, aggregate receipts, scores, and comparison evidence.
- [ ] Run all Python and focused Bun tests, type checking, formatting, and `git diff --check`.
- [ ] Commit as `feat: run paired HermesBench comparisons`.

### Task 7: Real Canary and Mini corpus preparation

**Files:**
- Create: `benchmarks/hermesbench/corpus_builder.py`
- Create: `benchmarks/hermesbench/tests/test_corpus_builder.py`
- Modify: `benchmarks/hermesbench/README.md`
- Modify: `.gitignore`

- [ ] Add a private reviewed ledger requiring vulnerable commit, independently verified fixed commit, repository license, source hash, group, split, and exclusion reason.
- [ ] Never guess fixed revisions from version strings or branch heads. Require a primary advisory or upstream patch reference and verify the retired root path changed.
- [ ] Materialize snapshots from pinned public Git objects into ignored directories without `.git`, advisory text, patch metadata, or source identifiers.
- [ ] Audit and hash every snapshot, group-split by repository and advisory, then freeze the eight-entry real Canary and 48-entry Mini manifests.
- [ ] Run the zero-cost Canary against the materialized corpus before spending model tokens.
- [ ] Commit only builders, public synthetic fixtures, and identity-free aggregate metadata.

### Task 8: Paid tuning and final Full decision

- [ ] Run paired Standard and `hunt-balanced` real Canary with one frozen model and effort.
- [ ] Run paired Standard and `hunt-max` real Canary.
- [ ] Promote the stronger profile to Mini and change one material variable per iteration.
- [ ] Record localization score, advisory recall, trace score, fixed specificity, accepted/rejected/inconclusive counts, elapsed time, cached input, uncached input, output, and command counts.
- [ ] If Mini is inconclusive under the written escalation rules, run Full immediately.
- [ ] Regardless of Mini confidence, build and run a ready Full suite before making a final performance claim.
- [ ] Independently review the final diff and evidence, run the complete repository regression suite, and publish only identity-free aggregate results.

## Acceptance checks

- A contaminated or hash-mismatched task launches no adapter.
- A model container cannot see an oracle path, write the snapshot, open outbound shell traffic, or access the host Docker socket.
- Standard and Hunt receipts compare equal on every frozen control.
- The fake Canary completes without a model call and produces reproducible bytes.
- A real task run has a valid bounded prediction and exact separated token usage.
- Mini automatically produces a Full escalation decision.
- No final claim is emitted before a ready Full run completes.
