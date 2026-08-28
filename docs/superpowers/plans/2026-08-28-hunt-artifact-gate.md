# Hunt Artifact Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every HermesBench Hunt discovery invocation consume a deterministic, bounded review packet while receipt-binding the complete inventory, full frontier, candidate provenance, and honest unreviewed coverage debt.

**Architecture:** The trusted host adapter prepares immutable scratch artifacts from the audited snapshot before starting Codex. The model must read a bounded priority packet, but the complete inventory and frontier remain eligible; after discovery, the host links every candidate location and search pass to those artifacts and emits a path-free attestation. Hunt workflow receipt validation independently rebuilds the artifacts from the snapshot and prediction, while Standard behavior and the public finding schema remain byte-compatible.

**Tech Stack:** Python 3 standard library, existing bundled Hunt Python helpers, Docker-backed Codex exec adapter, JSONL receipts, `unittest`.

**Spec:** `docs/superpowers/specs/2026-08-27-hermes-security-design.md`

## Global Constraints

- Standard adapter prompts, response schema, finding contract, runner artifacts, and scoring semantics must not change.
- Only authorized local snapshots may be read. Snapshots remain read-only and model-tool networking remains disabled.
- Do not generate or run exploits, proof-of-concept payloads, crash inputs, remote attacks, or credential probes.
- Ranking and the priority packet change order and initial exposure only; every authoritative inventory and frontier item remains eligible.
- Packet presence, candidate linkage, and model claims never count as reviewed closure. Without independent closure evidence, every frontier pass remains explicit coverage debt.
- Scratch artifacts containing source paths or previews never leave the task scratch directory. Persisted evidence contains only counts, protocol tokens, and SHA-256 digests.
- Every artifact read is bounded and fail-closed for missing, extra, truncated, oversized, linked, reparse, or identity-changing files.
- The complete task timeout includes deterministic preparation time. The container receives only the remaining positive whole-second budget.
- New or modified code comments and docstrings are English.
- Use TDD. Each production behavior must first be demonstrated by a focused failing test.
- Do not access private manifests, oracles, snapshots, authentication files, or paid model execution in the implementation subtask.

---

### Task 1: Host-precomputed Hunt artifact gate and receipt binding

**Files:**

- Create: `benchmarks/hermesbench/hunt_evidence.py`
- Create: `benchmarks/hermesbench/tests/test_hunt_evidence.py`
- Modify: `benchmarks/hermesbench/runner.py`
- Modify: `benchmarks/hermesbench/phase_runner.py`
- Modify: `benchmarks/hermesbench/adapters/codex_exec.py`
- Modify: `benchmarks/hermesbench/tests/test_runner.py`
- Modify: `benchmarks/hermesbench/tests/test_phase_runner.py`
- Modify: `benchmarks/hermesbench/tests/test_codex_exec_adapter.py`
- Modify: `benchmarks/hermesbench/README.md`
- Modify: `sdk/typescript/_bundled_plugin/skills/hunt-security-scan/SKILL.md`
- Modify only where required by the strict controls-version change: `benchmarks/hermesbench/tests/test_cli.py`, `benchmarks/hermesbench/tests/test_receipts.py`, and other existing HermesBench fixtures that construct frozen controls.

**Interfaces:**

- `PreparedHuntArtifacts` owns the exact plan directory, immutable pre-execution file identities and hashes, profile, preparation duration, and container-visible priority-packet path.
- `prepare_hunt_artifacts(snapshot_path: Path, scratch_path: Path, profile: str) -> PreparedHuntArtifacts` runs only the trusted bundled helpers and writes the fixed artifact tree under `scratch_path / "hermesbench-hunt"`.
- `attest_hunt_discovery(prepared: PreparedHuntArtifacts, prediction: object, observed_argv: tuple[tuple[str, ...], ...]) -> HuntEvidence` verifies post-execution identities and bytes, proves the packet was read, links every candidate location, checks search-pass compatibility, and computes path-free evidence.
- `reproduce_hunt_evidence(snapshot_path: Path, profile: str, prediction: object) -> HuntEvidence` creates a temporary plan and returns the same canonical evidence without a model invocation; receipt validation uses it.
- `HuntEvidence.to_json() -> dict[str, object]` emits exactly the fields defined below and no source paths, previews, work IDs, candidate prose, or task identity.
- `ExecutorResult.hunt_evidence` is `dict[str, object] | None` with default `None`. It is required only for successful `hunt-discovery` responses and forbidden for Standard and `hunt-verification` responses.
- Hunt discovery phase output adds `evidence.jsonl`; each successful task directory adds `evidence.json`. Hunt workflow receipt schema version `3` adds `discovery_evidence_sha256` and `hunt_evidence_protocol_version == 1`.
- Standard workflow receipts remain exact schema version `2` and omit both Hunt-only fields. Frozen controls remain exact schema version `2`; model, effort, seed, image, tool versions, timeout, candidate protocol, and phase protocol do not change.

- [ ] **Step 1: Add focused RED tests for deterministic preparation and bounded artifacts.**

Read `superpowers:test-driven-development` and its `writing-good-tests.md` reference before editing tests. Build a small synthetic repository with ordinary source, entry-like, sink-like, control-like, excluded, and non-source files. The tests must call the real bundled helpers through the wished-for public interface and assert both repetitions return byte-identical evidence.

```python
class HuntEvidencePreparationTests(unittest.TestCase):
    def test_preparation_preserves_inventory_and_frontier_deterministically(self) -> None:
        first = prepare_hunt_artifacts(snapshot, scratch_one, "hunt-balanced")
        second = prepare_hunt_artifacts(snapshot, scratch_two, "hunt-balanced")
        self.assertEqual(first.preparation_fingerprint, second.preparation_fingerprint)
        self.assertEqual(first.inventory_count, expected_inventory_count)
        self.assertEqual(first.frontier_count, expected_source_count)

    def test_priority_packet_is_bounded_without_reducing_frontier(self) -> None:
        prepared = prepare_hunt_artifacts(snapshot, scratch, "hunt-balanced")
        self.assertLessEqual(prepared.priority_count, 512)
        self.assertLessEqual(prepared.priority_bytes, 1024 * 1024)
        self.assertGreater(prepared.frontier_count, prepared.priority_count)
```

Run.

```powershell
python -m unittest benchmarks.hermesbench.tests.test_hunt_evidence
```

Expected RED: import failure for `benchmarks.hermesbench.hunt_evidence` or missing `prepare_hunt_artifacts`.

- [ ] **Step 2: Implement the minimal deterministic preparation module and make Step 1 GREEN.**

Use the fixed artifact names below.

```python
PLAN_DIRECTORY = "hermesbench-hunt"
INVENTORY_NAME = "in-scope-files.txt"
RANK_INPUT_NAME = "rank-input.jsonl"
FRONTIER_NAME = "frontier.jsonl"
FRONTIER_RECEIPT_NAME = "frontier-receipt.json"
PRIORITY_PACKET_NAME = "priority-packet.jsonl"
HUNT_EVIDENCE_PROTOCOL_VERSION = 1
MAX_INVENTORY_ROWS = 100_000
MAX_INVENTORY_BYTES = 8 * 1024 * 1024
MAX_RANK_INPUT_BYTES = 32 * 1024 * 1024
MAX_FRONTIER_ROWS = 100_000
MAX_FRONTIER_BYTES = 32 * 1024 * 1024
MAX_PRIORITY_PACKET_BYTES = 1024 * 1024
PRIORITY_ROW_LIMITS = {"hunt-balanced": 512, "hunt-max": 1024}
PRIORITY_PREVIEW_BYTES = 384
```

Invoke these exact trusted helper operations with `sys.executable`, argument vectors, `shell=False`, captured output, and no inherited repository command execution.

```text
generate_in_scope_files.py --repo SNAPSHOT --scope . --out INVENTORY
generate_rank_input.py make-repo-rank-input --repo SNAPSHOT --scope . --out RANK_INPUT
hunt_workflow.py make-frontier --work-dir PLAN_DIR --repository SNAPSHOT --rank-input RANK_INPUT --profile PROFILE --out FRONTIER --receipt FRONTIER_RECEIPT
```

Join frontier rows to rank-input previews by exact case-sensitive path. Emit priority rows in frontier priority order with exactly `work_id`, `path`, `component`, `risk_score`, `signals`, `passes`, and a UTF-8-safe preview truncated to `PRIORITY_PREVIEW_BYTES`. Stop at the profile row limit or before the canonical JSONL bytes would exceed `MAX_PRIORITY_PACKET_BYTES`; require at least one row when the frontier is non-empty. Preserve the complete full frontier separately.

Validate every fixed artifact as a single regular file with one link, no reparse attribute, bounded byte and row counts, strict UTF-8, LF canonical JSONL where applicable, exact fields, unique case-sensitive paths and work IDs, contiguous priorities, and exact inventory/frontier path membership. Record the file identity and SHA-256 before container execution.

Run the Step 1 test until GREEN, then run.

```powershell
python -m unittest benchmarks.hermesbench.tests.test_hunt_evidence
python -m compileall -q benchmarks/hermesbench
```

- [ ] **Step 3: Add RED tests for post-execution integrity, candidate provenance, and honest debt.**

Tests must independently cover missing artifact, byte mutation, oversized artifact, symlink when supported, hardlink, post-open identity replacement through a patched low-level reader, unknown candidate path, ambiguous case, and a search pass absent from every candidate-path frontier row.

The positive prediction uses every location role and proves exact linkage without leaking raw values.

```python
evidence = attest_hunt_discovery(prepared, prediction, (required_packet_read,))
self.assertEqual(evidence.candidate_count, 1)
self.assertEqual(evidence.linked_location_count, 3)
self.assertEqual(evidence.validated_closure_count, 0)
self.assertEqual(evidence.coverage_debt_count, expected_frontier_pass_count)
serialized = json.dumps(evidence.to_json(), sort_keys=True)
self.assertNotIn("src/", serialized)
self.assertNotIn("hunt-", serialized)
```

Assert packet presentation and candidate linkage do not reduce `coverage_debt_count`. Assert the exact required observed command is.

```python
("cat", "/workspace/scratch/hermesbench-hunt/priority-packet.jsonl")
```

Run.

```powershell
python -m unittest benchmarks.hermesbench.tests.test_hunt_evidence
```

Expected RED: missing `attest_hunt_discovery`, missing strict artifact checks, or missing provenance/debt fields.

- [ ] **Step 4: Implement the minimal attestation and reproduction logic and make Step 3 GREEN.**

`HuntEvidence.to_json()` must emit exactly.

```python
{
    "schema_version": 1,
    "profile": profile,
    "inventory_sha256": inventory_sha256,
    "inventory_count": inventory_count,
    "rank_input_sha256": rank_input_sha256,
    "frontier_sha256": frontier_sha256,
    "frontier_count": frontier_count,
    "frontier_pass_count": frontier_pass_count,
    "priority_packet_sha256": priority_packet_sha256,
    "priority_packet_count": priority_packet_count,
    "candidate_links_sha256": candidate_links_sha256,
    "candidate_count": candidate_count,
    "linked_location_count": linked_location_count,
    "coverage_debt_sha256": coverage_debt_sha256,
    "coverage_debt_count": coverage_debt_count,
    "validated_closure_count": 0,
}
```

For every discovery candidate, link the entry point, critical operation, and every trace location by exact path to the full inventory. Require every unique location path to have one full-frontier work ID, and require at least one linked frontier row whose `passes` contains the candidate's `search_pass`. Hash canonical internal candidate-link rows containing candidate ID, location role, trace index, line range, work ID, and matching pass work ID, but never return those rows from `to_json()`.

Build coverage debt from every distinct `(work_id, pass)` in the full frontier. Because this task adds no independently verified frontier closure, `validated_closure_count` is always zero and every unit remains debt. Hash the canonical internal debt rows but expose only their hash and count.

`reproduce_hunt_evidence` uses a private temporary directory, prepares the same artifacts, and attests the prediction using the fixed packet-read tuple without running a model. It must remove the temporary directory on every path.

Run all focused evidence tests until GREEN.

- [ ] **Step 5: Add adapter RED tests for mandatory packet consumption and whole-task timeout accounting.**

Extend the fake runtime tests so Hunt discovery receives the precomputed directory and the prompt names the exact packet path. A successful event stream without the exact `cat` command must fail with fixed public code `hunt_evidence_invalid`. A mutated plan after the fake runtime returns must fail with the same code. A builder consuming `17.2` seconds from a `480` second task must pass `462` seconds to the container by flooring the positive remaining budget; preparation that leaves less than one second must fail before Docker execution. Standard and Hunt verification must not prepare artifacts or alter their existing prompt bytes.

Run.

```powershell
python -m unittest benchmarks.hermesbench.tests.test_codex_exec_adapter
```

Expected RED: no preparation call, no packet-read gate, unchanged timeout, or missing public failure code.

- [ ] **Step 6: Integrate the adapter and runner evidence channel and make focused tests GREEN.**

Add `hunt_evidence_invalid` to the runner's bounded public failure codes. Add `hunt_evidence: dict[str, object] | None = None` to `ExecutorResult` without changing its first three positional fields.

For Hunt discovery only, prepare before container execution, append this exact prompt contract, and subtract all monotonic preparation time from the task timeout.

```text
The host prepared the complete Hunt inventory and frontier. Read /workspace/scratch/hermesbench-hunt/priority-packet.jsonl once with exactly `cat /workspace/scratch/hermesbench-hunt/priority-packet.jsonl` before forming hypotheses. The packet is priority guidance only; every file in /workspace/snapshot remains eligible. Do not claim packet rows or candidate links as reviewed coverage.
```

After `_parse_result`, run `attest_hunt_discovery` against the parsed prediction and observed normalized argv, then return its path-free JSON as `ExecutorResult.hunt_evidence`. Convert every preparation or attestation failure to `CodexExecError(..., failure_code="hunt_evidence_invalid")` without retaining helper stdout, stderr, paths, or source text.

In `run_suite`, require evidence for each successful `hunt-discovery`, prohibit it for Standard and `hunt-verification`, write canonical task `evidence.json`, and aggregate manifest-ordered `evidence.jsonl`. Update exact task artifact allowlists and partial-success cleanup without loosening unexpected-file rejection.

Run.

```powershell
python -m unittest benchmarks.hermesbench.tests.test_hunt_evidence benchmarks.hermesbench.tests.test_codex_exec_adapter benchmarks.hermesbench.tests.test_runner
```

- [ ] **Step 7: Add workflow-receipt RED tests for exact evidence reconstruction and Standard compatibility.**

Create synthetic Hunt runs whose fake discovery executor supplies path-free evidence reproduced from the fixture snapshot. Assert the workflow receipt is schema version `3`, contains `discovery_evidence_sha256`, and revalidates by rebuilding exact evidence. Independently alter each persisted evidence hash field and the aggregate evidence bytes and assert revalidation rejects each mutation. Assert missing Hunt evidence fails closed for completed and incomplete Hunt workflows.

Capture the exact Standard phase artifact name sets and workflow-receipt bytes and assert they remain unchanged, contain no `evidence.json` or `evidence.jsonl`, retain schema version `2`, and omit the Hunt-only receipt fields.

Run.

```powershell
python -m unittest benchmarks.hermesbench.tests.test_phase_runner benchmarks.hermesbench.tests.test_runner
```

Expected RED: workflow receipt lacks evidence binding or validator accepts a changed artifact.

- [ ] **Step 8: Bind evidence into strict controls and workflow receipts and make all tests GREEN.**

Define `STANDARD_WORKFLOW_RECEIPT_SCHEMA_VERSION = 2` and `HUNT_WORKFLOW_RECEIPT_SCHEMA_VERSION = 3`. Hunt receipt JSON adds exact fields `discovery_evidence_sha256` and `hunt_evidence_protocol_version`; require a non-null evidence SHA-256 and version `1` for every Hunt workflow, including incomplete runs. Standard receipt JSON remains the existing exact schema version `2` field set with neither Hunt field. Hash `discovery/evidence.jsonl` in `_workflow_receipt` and expose it in `_artifact_paths` only for Hunt.

Keep frozen controls schema version `2` and its exact field set unchanged. Do not change model, effort, seed, image, tool versions, timeout, finding limits, grader, candidate semantics, phase protocol, candidate protocol, or phase invocation count.

During `validate_workflow_receipt`, rehash the evidence file, parse exact path-free rows, and call `reproduce_hunt_evidence` for each persisted Hunt discovery prediction against its audited snapshot. Compare exact canonical LF JSONL bytes. A receipt rewrite plus artifact rewrite must still fail because the reproduced bytes differ.

Run.

```powershell
python -m unittest discover -s benchmarks/hermesbench/tests -p 'test_*.py'
python -m compileall -q benchmarks/hermesbench
git diff --check
```

- [ ] **Step 9: Update the Hunt skill and benchmark documentation without changing Standard guidance.**

Add a Hunt-only benchmark paragraph explaining that when the fixed precomputed packet exists, the agent reads it exactly once, uses it as priority guidance, retains the full repository as eligible, and never treats presented or candidate-linked work as reviewed closure. Document the new path-free evidence artifact, schema versions, four security hashes, separate packet hash, and timeout accounting in `benchmarks/hermesbench/README.md`.

Run the focused bundled-skill package test and HermesBench suite.

```powershell
cd sdk/typescript
bun test --timeout 30000 tests-ts/hunt-workflow.test.ts tests-ts/hermesbench.test.ts
cd ../..
python -m unittest discover -s benchmarks/hermesbench/tests -p 'test_*.py'
git diff --check
```

- [ ] **Step 10: Run opt-in large-artifact and no-model integration verification.**

Add an opt-in test guarded by `HERMESBENCH_LARGE_ARTIFACT_SMOKE=1` that creates 15,027 tiny regular files with 11,277 source-like files, runs preparation twice, and asserts deterministic evidence plus the fixed byte and row limits. It must not assert a wall-clock threshold in the unit test; print elapsed time only in the main-owned verification record.

The implementation subagent runs the synthetic large smoke but does not build Docker or access private state.

```powershell
$env:HERMESBENCH_LARGE_ARTIFACT_SMOKE='1'
python -m unittest benchmarks.hermesbench.tests.test_hunt_evidence.HuntEvidenceLargeSmokeTests
Remove-Item Env:HERMESBENCH_LARGE_ARTIFACT_SMOKE
python -m unittest discover -s benchmarks/hermesbench/tests -p 'test_*.py'
python -m compileall -q benchmarks/hermesbench
git diff --check
```

The main agent, after task review, reuses the already pinned image because the Dockerfile, wrapper, and three response schemas are unchanged. It runs no-model filesystem, permission, evidence-preparation, and receipt-reproduction smokes before any paid invocation; a rebuild or private-control edit is required only if the reviewed diff unexpectedly changes an image input.

- [ ] **Step 11: Self-review and commit the logical unit.**

Review the full diff against this plan. Confirm no path, preview, candidate prose, helper output, raw work ID, private identifier, or credential-derived value enters persisted evidence or failure artifacts. Confirm every changed line is required by the Hunt-only gate and no Standard schema or prompt changed.

Commit.

```powershell
git add benchmarks/hermesbench sdk/typescript/_bundled_plugin/skills/hunt-security-scan/SKILL.md docs/superpowers/plans/2026-08-28-hunt-artifact-gate.md checklist.md context-notes.md
git commit -m "Bind Hunt discovery evidence"
```

The implementation report must record each RED command and expected failure, each GREEN command and result, the large-smoke counts, the commit hash, and any concern. It must not include private paths, private identifiers, or source-derived text.

---

### Task 2: Main-owned performance acceptance after Task 1 review

**Files:**

- Modify: `checklist.md`
- Modify: `context-notes.md`
- Modify only if an image input changed: ignored `benchmarks/hermesbench/private/controls-terra-high.json`

**Interfaces:**

- Consumes: the reviewed Task 1 Hunt evidence gate, the fixed private single-task diagnostic, and the already pinned runtime image.
- Produces: a receipt-revalidated v12 result, post-run integrity evidence, a v10/v11/v12 comparison, and the next single-variable performance decision.

The main agent keeps the same single-task diagnostic manifest, model, reasoning effort, profile, candidate protocol, verifier semantics, and `480` second per-phase limit. Only the artifact gate, priority packet, evidence channel, and required controls/receipt version change.

- [ ] **Step 1: Reconfirm the immutable Docker image ID still matches ignored private controls; do not rebuild when no image input changed.**
- [ ] **Step 2: Prove the image contains the three unchanged response schemas, prove the host-mounted updated skill is visible read-only, and preserve the named permission boundary.**
- [ ] **Step 3: Run one paid `hunt-balanced` v12 diagnostic.**
- [ ] **Step 4: Revalidate the workflow receipt by regenerating the evidence from the snapshot and discovery predictions.**
- [ ] **Step 5: Re-audit all Canary snapshots and confirm exact pre/post hashes, no retained auth or host-path values, and no remaining container.**
- [ ] **Step 6: Compare v12 with v10 and v11 using advisory recall, localization, trace score, candidate count, terminal decisions, cached input, uncached input, output, and elapsed seconds. Discovery quality decides success; cost is reported separately.**
- [ ] **Step 7: If recall remains zero, retain the gate and move to the next single material strategy, a deterministic source-to-sensitive-operation semantic graph. Do not add a second discovery model call until that graph has been measured.**
