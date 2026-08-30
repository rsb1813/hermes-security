# Protocol 5 Paired-Flow Seeds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an oracle-blind Protocol 5 that gives Hunt discovery a compact factorized entry, critical, and adjacency packet, attests exact retained join or sink use, keeps two model calls, and preserves Protocol 1 through Protocol 4 byte compatibility.

**Architecture:** Extend the existing single-pass schema-3 semantic builder to emit one bounded canonical factorized packet under the existing Protocol 5 artifact path. The packet deduplicates paths, components, entries, and criticals, retains at most four graph adjacencies per critical, preserves standalone critical roots, and fills the largest semantic-operation-ordered critical prefix under the profile budget. Protocol 5 keeps the full semantic artifact host-only, attests exact join or sink identity and endpoints, permits at most four whole-frontier fallbacks, and reuses Protocol 4 partial-phase behavior.

**Tech Stack:** Python 3 standard library, `unittest`, existing HermesBench JSON schemas, Bun/TypeScript bridge tests, Git.

**Spec:** `docs/superpowers/specs/2026-08-30-protocol5-paired-flow-seeds-design.md`

**Execution status:** Tasks 1 through 6 are complete. The factorized product passed the pinned host gate at two exact critical tasks, two exact entry tasks, one exact pair, and 262,028 aggregate bytes. The final public tree passed 492 Python tests, the Bun bridge, compilation, type checking, explicit legacy contracts, and independent Critical/Important review, then was pushed to `origin/hermes/runner-canary`.

## Global Constraints

- Make no model, network, container, or paid benchmark invocation in this plan.
- Do not read private labels, task identities, raw findings, model output, or oracle contents during product implementation.
- Use `apply_patch` for edits and begin every shell command with `rtk`.
- Preserve Protocol 1 through Protocol 4 exact prompt, semantic, evidence, and receipt reconstruction.
- Keep Standard, discovery and verification schemas, scorer, candidate caps, final finding caps, sandbox policy, and retry count unchanged.
- Add only English comments and developer-facing annotations.
- Commit each completed task as one semantic change and push verified commits to `origin/hermes/runner-canary`.

---

## Task 1. Add Protocol 5 and canonical paired seed generation

**Files:**

- Modify: `benchmarks/hermesbench/semantic_guidance.py`
- Modify: `benchmarks/hermesbench/hunt_evidence.py`
- Test: `benchmarks/hermesbench/tests/test_semantic_guidance.py`
- Test: `benchmarks/hermesbench/tests/test_hunt_evidence.py`

- [x] Add a RED test asserting Protocol 5 preparation is rejected and a RED test describing deterministic paired, parameter-flow, sink-only, and component-balanced seed rows.
- [x] Run `python -m unittest benchmarks.hermesbench.tests.test_semantic_guidance benchmarks.hermesbench.tests.test_hunt_evidence` and confirm the failures are caused by missing Protocol 5 behavior.
- [x] Add the Protocol 5 constant and supported-version mapping without changing the Protocol 1 through Protocol 4 constants or default yet.
- [x] Add immutable seed-result and structural-owner data, then derive route, source-linked, parameter-flow, and sink-only seed pools from the existing scan.
- [x] Add canonical seed IDs, fixed public reason codes, deterministic lane/component scheduling, and the profile row/byte limits.
- [x] Reuse the schema-3 scan and write `paired-flow-seeds.jsonl` only for Protocol 5.
- [x] Add determinism, frontier-order, collision, bounds, empty, disconnected, and oracle-like-file-independence tests.
- [x] Run the focused tests until GREEN, then run Protocol 1 through Protocol 4 semantic golden tests.
- [x] Review the diff for any second scan, target-shaped token, source snippet, or legacy-byte change.
- [x] Commit as `feat: add Protocol 5 paired-flow seed artifact`.

## Task 2. Bind seed identity and endpoints into Hunt evidence

**Files:**

- Modify: `benchmarks/hermesbench/hunt_evidence.py`
- Test: `benchmarks/hermesbench/tests/test_hunt_evidence.py`

- [x] Add RED tests for the exact Protocol 5 evidence fields and successful paired, sink-only, and fallback attestation.
- [x] Add mutation RED tests for missing and duplicate seed reads, unknown seed IDs, cross-seed endpoints, changed lines, pass mismatch, seed-shaped fallback IDs, no seeded candidate, more than four fallbacks, and artifact replacement.
- [x] Record the seed artifact identity and counts in `PreparedHuntArtifacts` and its preparation fingerprint.
- [x] Parse canonical seed rows from the pinned artifact and classify each candidate as paired, sink-only, or fallback.
- [x] Require exact one-line endpoints and seed-supported passes while retaining the existing frontier rules.
- [x] Add path-free seed-link hashing and the three fixed public failure codes.
- [x] Extend `HuntEvidence`, `to_json`, and `parse_hunt_evidence` only for explicit Protocol 5 evidence.
- [x] Run the focused Hunt evidence tests until GREEN and revalidate retained Protocol 1 through Protocol 4 evidence fixtures.
- [x] Commit as `feat: attest Protocol 5 seed linkage`.

## Task 3. Wire Protocol 5 through discovery and verification adapters

**Files:**

- Modify: `benchmarks/hermesbench/adapters/codex_exec.py`
- Modify: `sdk/typescript/_bundled_plugin/skills/hunt-security-scan-managed/SKILL.md` only if the fixed phase contract needs one protocol-neutral sentence
- Test: `benchmarks/hermesbench/tests/test_codex_exec_adapter.py`
- Test: `sdk/typescript/test/hermesbench.test.ts`

- [x] Add a RED adapter test for Protocol 5 managed-skill selection and exact priority-then-seed reads with no model-visible semantic file.
- [x] Add RED tests for seed instructions, unchanged response schema, unchanged verifier projection, two-call ceiling, and strict unquoted-operator rejection.
- [x] Add the Protocol 5 prompt branch while leaving all existing prompt strings byte-for-byte unchanged.
- [x] Select the managed skill for Protocol 4 and Protocol 5 only.
- [x] Preserve Protocol 5 on the fresh verification adapter without sending seed metadata or discovery conclusions to verification.
- [x] If the skill changes, keep it protocol-neutral and verify the bundled plugin projection exactly.
- [x] Run all adapter and HermesBench bridge tests until GREEN, including explicit legacy prompt-hash tests.
- [x] Commit as `feat: route Protocol 5 through managed Hunt phases`.

## Task 4. Extend partial-phase receipts and make Protocol 5 the default

**Files:**

- Modify: `benchmarks/hermesbench/phase_runner.py`
- Modify: `benchmarks/hermesbench/runner.py` if required by the public failure-code boundary
- Modify: `benchmarks/hermesbench/hunt_evidence.py`
- Test: `benchmarks/hermesbench/tests/test_phase_runner.py`
- Test: `benchmarks/hermesbench/tests/test_cli.py`
- Test: `benchmarks/hermesbench/tests/test_receipt.py`

- [x] Add RED tests showing Protocol 5 discovery failure, zero-candidate verification, verification failure, and complete workflow behavior.
- [x] Replace Protocol-4-only partial-recovery checks with one explicit helper covering Protocol 4 and Protocol 5.
- [x] Preserve failure usage only after strict terminal output validation; do not retry or execute rejected commands.
- [x] Add the Protocol 5 public failure codes to the fixed runner boundary.
- [x] Switch the default Hunt evidence protocol from 4 to 5 only after all focused tests pass.
- [x] Verify explicit Protocol 1 through Protocol 4 controls still reconstruct their original evidence and prompts.
- [x] Run focused phase, CLI, and receipt tests until GREEN.
- [x] Commit as `feat: complete Protocol 5 workflow integration`.

## Task 5. Verify, measure host-only coverage, document, review, and push

**Files:**

- Modify: `plan.md`
- Modify: `checklist.md`
- Modify: `context-notes.md`
- Modify: protocol documentation only when verified evidence requires it

- [x] Run all HermesBench Python tests.
- [x] Run the HermesBench Bun/TypeScript bridge and Hunt workflow tests.
- [x] Run Python compilation, TypeScript checking, changed-artifact formatting, `git diff --check`, and worktree status checks.
- [x] Run explicit Protocol 1 through Protocol 4 golden semantic, prompt-hash, and receipt compatibility checks.
- [x] Perform an aggregate-only private build comparison with zero model, network, container, or paid calls; retain only counts and integrity results.
- [x] Confirm snapshot hashes are unchanged and no private path, task ID, source label, raw finding, model text, or oracle content entered tracked files.
- [x] Request one read-only Terra high Critical/Important diff review and apply findings in one batch.
- [x] Re-run affected focused tests and the full verification suite after review.
- [x] Update the checklist and context notes with exact verified results and calibrated claims.
- [x] Commit documentation as a separate semantic unit when it records new evidence.
- [x] Push all verified commits to `origin/hermes/runner-canary` and confirm the branch matches its upstream.

No paid Canary, Mini, or Full run is part of this plan. A future paid Canary requires fresh explicit authorization after every no-model gate passes.

## Task 6. Replace the Protocol 5 explicit-row packet with factorized hybrid flow guidance

**Files:**

- Modify: `benchmarks/hermesbench/semantic_guidance.py`
- Modify: `benchmarks/hermesbench/hunt_evidence.py`
- Modify: `benchmarks/hermesbench/adapters/codex_exec.py`
- Test: `benchmarks/hermesbench/tests/test_semantic_guidance.py`
- Test: `benchmarks/hermesbench/tests/test_hunt_evidence.py`
- Test: `benchmarks/hermesbench/tests/test_codex_exec_adapter.py`
- Test: `benchmarks/hermesbench/tests/test_phase_runner.py`
- Modify: `plan.md`
- Modify: `checklist.md`
- Modify: `context-notes.md`

- [x] Prove with aggregate-only host diagnostics that the hybrid factorized packet retains the Protocol 4 critical floor, increases exact entry and pair coverage, and fits every balanced packet bound.
- [x] Amend the binding specification and implementation plan before touching product code.
- [x] Add RED tests for deterministic dictionaries, entry and critical banks, standalone criticals, graph adjacency, fixed codes, maximum four entries per critical, and the balanced and max profile bounds.
- [x] Implement factorized packet schema 2 only when Protocol 5 paired-flow guidance is requested; leave Protocol 1 through Protocol 4 builders and bytes unchanged.
- [x] Add RED mutation tests for noncanonical rows, duplicate or nonconsecutive IDs, unknown references, invalid family and pass codes, nonadjacent join IDs, changed endpoints, pass mismatch, reserved-shaped fallbacks, and reproduction mismatch.
- [x] Decode and attest `join-e<entry_id>-c<critical_id>` and `sink-c<critical_id>` without changing discovery or verification response schemas.
- [x] Update only the Protocol 5 discovery prompt to explain compact packet codes and exact candidate rules; preserve the exact Protocol 1 through Protocol 4 prompt hashes and the managed skill bytes.
- [x] Revalidate completed, partial, zero-candidate, and failed Protocol 5 workflows without changing `phase_runner.py` production behavior unless a failing RED test proves it necessary.
- [x] Run focused tests, the full HermesBench Python suite, Bun/TypeScript bridge, compilation, diff checks, explicit legacy-byte contracts, and snapshot-integrity checks.
- [x] Rebuild the aggregate-only host gate from product code and require at least two exact critical tasks, two exact entry tasks, one exact pair, fewer than 324,248 aggregate model-visible bytes, and zero model, network, container, or paid calls.
- [x] Request one read-only Terra high Critical/Important diff review, apply findings once, rerun affected and full gates, then commit and push semantic units to `origin/hermes/runner-canary`.
