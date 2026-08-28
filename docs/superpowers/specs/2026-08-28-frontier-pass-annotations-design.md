# HermesBench Frontier Pass Annotations Design

Date: 2026-08-28
Status: Approved in chat; pending written-spec review
Branch: `hermes/runner-canary`

## 1. Objective

Prevent otherwise useful Hunt discovery results from failing the existing candidate-to-frontier evidence boundary because the model selected a `search_pass` that no submitted candidate location supports.

The host will add deterministic frontier-pass eligibility to semantic guidance. The model still chooses one pass, and the host still rejects any unsupported choice. The host must never infer, replace, or repair a model-selected pass after execution.

## 2. Evidence From the Fixed Protocol-v2 Diagnostic

The first fixed semantic-guidance diagnostic completed one discovery invocation but stopped before candidate publication or verification.

- Workflow status was `incomplete` after 378.122 seconds.
- The receipt recorded one top-level invocation and Hunt evidence protocol version 2.
- Candidate, prediction, evidence, and command publications were empty.
- Verification and scoring did not run.
- The fixed public failure code was `hunt_evidence_candidate_search_pass`.
- Published token usage was zero because failure publication intentionally discarded partial-success usage.
- The result is a measurement-blocking evidence-boundary failure, not a zero benchmark score.

Independent path-free analysis of the prepared semantic artifact found 238 guidance rows. Every route overlapped the priority-packet path set, but no row stated which frontier passes were eligible. Forty-five route-location unions supported four passes and 193 supported five passes. `general` remained part of the global pass vocabulary but was absent from every analyzed route-location union.

No raw model prediction, hidden label, benchmark identity, authentication value, or host path is required to justify this change.

## 3. Scope

This change includes the following work.

- Add a canonical `eligible_search_passes` field to new semantic-guidance rows.
- Derive the field only from validated immutable frontier rows.
- Introduce Hunt evidence protocol version 3 and semantic-guidance row schema version 2.
- Preserve exact protocol-v1 and protocol-v2 artifact reconstruction and prompt bytes.
- Give protocol-v3 Hunt discovery explicit pass-selection instructions.
- Retain the existing fail-closed candidate-location and candidate-pass attestation.
- Run one fixed paid diagnostic after all no-model and compatibility gates pass.

This change does not include the following work.

- Auto-correcting, replacing, or defaulting a model-selected `search_pass`.
- Adding `general` as a fallback when no exact frontier row supplies it.
- Treating semantic guidance or pass eligibility as proof of a vulnerability.
- Changing the candidate schema, candidate cap, verifier schema, scoring, frontier eligibility, or coverage debt.
- Adding a model invocation, increasing the 480-second per-phase timeout, or changing pinned runtime controls.
- Exposing raw predictions, hidden labels, task identities, source paths, or findings in public evidence.
- Generating exploits, proof-of-concept payloads, crash inputs, or remote traffic.

## 4. Alternatives

### 4.1 Mutate protocol version 2

Adding the field directly to protocol-v2 guidance is the smallest implementation. It would change deterministic v2 guidance bytes and preparation fingerprints, so completed retained v2 receipts could no longer be reconstructed from their recorded version. This violates the existing explicit-version invariant and is rejected.

### 4.2 Introduce protocol version 3

The selected design keeps the current v2 builder and prompt behavior available, adds annotated guidance only for v3, and makes v3 the default for new Hunt runs. This requires explicit version branches but preserves reproducibility for both earlier protocols.

### 4.3 Repair the pass during host attestation

The host could replace an invalid model pass with any pass found on a linked location. That would publish evidence the model did not submit, conceal a discovery-contract failure, and make performance results incomparable. This is rejected.

### 4.4 Add per-location pass maps

A pass map for every route location would reduce ambiguity further but would duplicate frontier data and increase prompt bytes. The first measured change uses one bounded union plus an exact-frontier lookup rule. Per-location maps remain a later option only if a completed v3 diagnostic demonstrates a concrete residual mismatch.

## 5. Versioning Contract

The evidence protocol version and semantic row schema version are explicit and independent.

| Hunt evidence protocol | Semantic artifact | Semantic row schema | Discovery prompt behavior |
| --- | --- | --- | --- |
| 1 | Absent | Absent | Exact legacy priority-only prompt |
| 2 | Present | 1 | Exact current semantic-guidance prompt |
| 3 | Present | 2 | Pass-annotated semantic-guidance prompt |

`HUNT_EVIDENCE_PROTOCOL_VERSION` becomes 3 for new runs. `SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS` becomes `{1, 2, 3}`. Version-aware helpers must distinguish protocols that use semantic guidance from the single current version instead of relying on equality with the default.

Protocol-v3 path-free evidence retains the exact protocol-v2 semantic hash and count field names. The semantic artifact SHA-256 already binds the additional row field, so no new public evidence field or receipt schema version is required.

The retained incomplete v2 diagnostic remains revalidatable because its recorded protocol remains 2 and its completed discovery subset is empty. More generally, both complete and incomplete v1, v2, and v3 receipts must reconstruct by their recorded protocol rather than the current default.

## 6. Canonical Pass Vocabulary

`benchmarks/hermesbench/hunt_protocol.py` will expose one ordered tuple and derive the existing membership set from it.

```python
HUNT_SEARCH_PASS_ORDER = (
    "forward",
    "backward",
    "guard",
    "parser",
    "state",
    "general",
)
HUNT_SEARCH_PASSES = frozenset(HUNT_SEARCH_PASS_ORDER)
```

The order matches the bundled frontier generator's `FRONTIER_PASSES` contract. Tests must assert that the generator and host vocabulary remain identical.

Every pass collection supplied to the v3 builder must be non-empty, unique, and contain only members of this tuple. Output order always follows `HUNT_SEARCH_PASS_ORDER`, regardless of input row order. Unknown values fail before the model runtime starts.

## 7. Builder Input and Row Contract

### 7.1 Ordered frontier-pass input

`benchmarks/hermesbench/hunt_evidence.py` already validates generated frontier rows before semantic preparation. It will project those rows, in frontier priority order, into an immutable sequence.

```python
tuple[tuple[str, tuple[str, ...]], ...]
```

Each outer item contains one canonical relative path and that frontier row's validated passes. Paths must be unique. This ordered representation preserves the current scan and resource-bound behavior while preventing the builder from receiving a path without its pass evidence.

The builder interface becomes explicit about both inputs and output schema.

```python
def build_semantic_guidance(
    snapshot_path: Path,
    frontier_passes: tuple[tuple[str, tuple[str, ...]], ...],
    profile: str,
    *,
    guidance_schema_version: int,
) -> SemanticGuidance:
```

There is no implicit schema default. Protocol 2 requests guidance schema 1, and protocol 3 requests guidance schema 2. Protocol 1 does not call the builder.

### 7.2 Eligibility derivation

For each schema-2 semantic route, the builder performs these steps.

1. Collect the exact relative paths from `source`, every `trace` location, and `operation`.
2. Deduplicate the paths without changing route semantics.
3. Look up every path in the validated frontier-pass input.
4. Union only the passes present on those exact rows.
5. Emit the union in `HUNT_SEARCH_PASS_ORDER`.

`controls` are not included merely because they appear as nearby guidance. Candidate attestation links the entry point, critical operation, and candidate trace, so eligibility is derived from the corresponding route locations only.

If any route path is absent, any pass is unknown or duplicated, or the exact union is empty, preparation fails closed before the model runtime. The builder does not infer from operation family, route strength, filename, or neighboring rows. It never inserts `general` unless an exact route-location frontier row contains `general`.

### 7.3 Schema-2 row

Schema-2 rows retain every schema-1 field and add exactly one field.

```json
"eligible_search_passes":["forward","guard","state"]
```

The field is a non-empty canonical array. `proof_status` remains `investigation_only`. The existing `hint_id` remains the identity of the semantic route and does not incorporate pass annotations; canonical row bytes and the artifact hash bind the annotations themselves.

Schema-1 serialization remains byte-identical to the current implementation and must reject the new field during strict validation. Schema-2 validation requires the new field and rejects its absence, extra values, duplicates, or non-canonical ordering.

## 8. Artifact Preparation and Attestation

`prepare_hunt_artifacts` will use explicit version helpers.

- Protocol 1 prepares the existing five artifacts and no semantic artifact.
- Protocol 2 prepares schema-1 semantic guidance from the same ordered frontier paths and preserves current canonical bytes.
- Protocol 3 prepares schema-2 semantic guidance with `eligible_search_passes`.

Protocols 2 and 3 retain the existing semantic artifact identity checks, size limit, required single read, and read ordering after the priority packet. Preparation fingerprints continue to bind the exact artifact hashes and profile.

Candidate attestation remains authoritative and unchanged in meaning. A submitted `search_pass` must occur on at least one exact frontier row linked to the submitted entry point, critical operation, or trace. A mismatch continues to fail with `hunt_evidence_candidate_search_pass`. No candidate field is modified after parsing.

The annotated union helps the model select a valid value but does not weaken this final location-specific check.

## 9. Protocol-v3 Prompt Contract

Standard discovery, Standard verification, Hunt verification, protocol-v1 discovery, and protocol-v2 discovery prompt bytes remain unchanged. The adapter must use explicit v1, v2, and v3 branches rather than one legacy branch plus a mutable default branch.

The protocol-v3 Hunt discovery prompt adds these requirements.

- For a candidate based on one semantic-guidance row, copy one value from `eligible_search_passes` that is supported by at least one submitted candidate location.
- Preserve the route's source, operation, and relevant trace locations when they support the candidate hypothesis.
- If submitted locations differ from the guidance row, query immutable `frontier.jsonl` by exact path using an allowed single command and copy one listed pass that occurs on at least one submitted location.
- For a candidate outside semantic guidance or the priority packet, perform the same exact-path frontier lookup before submission.
- Never invent, generalize, substitute, or default a pass.

The prompt does not claim that an eligible pass proves attacker control, reachability, impact, or guard failure. Actual source inspection, control review, counterevidence review, and fresh verification remain mandatory.

## 10. Security and Public-Data Boundaries

- Frontier and semantic artifacts remain trusted host-generated scratch inputs mounted under the existing immutable plan boundary.
- Repository contents and guidance strings remain untrusted data, not instructions.
- Only path-free hashes and aggregate counts persist in public evidence.
- Existing artifact-integrity, candidate-location, command-audit, authentication, network, and output-isolation controls remain unchanged.
- Failure publication remains atomic and may not retain partial candidates, commands, evidence, predictions, or raw model output.
- The two-call ceiling, independent verification, maximum 12 discovery candidates, maximum five public findings, and 480-second phase timeout remain unchanged.

## 11. Test Strategy

Implementation follows RED then GREEN checkpoints.

### 11.1 Semantic builder tests

- Reproduce exact schema-1 bytes from existing synthetic fixtures.
- Produce deterministic schema-2 bytes across repeated builds.
- Derive eligibility only from source, trace, and operation paths.
- Preserve canonical pass order independent of input order.
- Reject missing paths, empty pass sets, duplicate passes, unknown passes, and empty unions before runtime.
- Confirm `general` appears only when an exact route-location row contains it.
- Keep current row, byte, source, edge, traversal, and graph-depth bounds.

### 11.2 Prompt and attestation tests

- Freeze exact protocol-v1 and protocol-v2 Hunt discovery prompt bytes.
- Freeze exact Standard discovery, Standard verification, and Hunt verification prompt bytes.
- Require the protocol-v3 pass-copy and exact-frontier lookup instructions.
- Accept a candidate whose selected pass occurs on one submitted location.
- Keep a mismatched or invented pass rejected with `hunt_evidence_candidate_search_pass`.
- Confirm that no host fallback or candidate rewrite occurs.

### 11.3 Receipt compatibility tests

- Reconstruct completed and incomplete protocol-v1 receipts exactly.
- Reconstruct completed and incomplete protocol-v2 receipts exactly, including the retained empty-completed-subset diagnostic.
- Reconstruct completed, partial, and failed protocol-v3 receipts.
- Reject protocol field mixing, unsupported versions, prompt-version mismatches, and rehashed tampering.
- Keep workflow receipt schema 3 and frozen controls schema 2 unchanged.

### 11.4 Full verification

- Run focused builder, evidence, adapter, runner, phase, CLI, and receipt tests.
- Run the complete repository test suite and compile checks.
- Prepare protocol 2 and protocol 3 twice from the fixed snapshot and compare all non-time fields and canonical hashes.
- Revalidate all retained protocol-v1 and protocol-v2 receipts.
- Repeat snapshot audit, retained-output scan, authentication-boundary smoke, image-schema hash, reparse-point, and residual-container checks.
- Review the final diff for private benchmark data, hidden labels, raw predictions, credentials, and host paths before committing.

## 12. Benchmark Gate

After implementation and no-model verification, run one new immutable single-task paid diagnostic with the same snapshot, task manifest, model, reasoning effort, profile, candidate protocol, scorer, timeout, pinned image, execution policy, and two-call workflow used for the protocol-v2 diagnostic. The only intended strategy changes are protocol-v3 pass annotations and their discovery instructions.

Record cached input, uncached input, output, elapsed time, invocation count, candidate count, terminal decisions, public score components, failure code, and post-run integrity separately.

- If the run fails before valid discovery publication, classify it as another measurement-blocking boundary result and do not assign a performance score or expand to Mini.
- If the run completes but produces no discovery-quality signal, change only one diagnosed variable before another paid run.
- If the run produces a valid positive discovery signal without a fixed-snapshot false positive, expand to the full eight-task Canary set before HermesBench Mini.
- Run HermesBench Mini only after Canary demonstrates that the strategy is measurable and promising.
- Run the full HermesBench suite when Mini is inconclusive and for the final performance claim.

## 13. Expected Implementation Files

- `benchmarks/hermesbench/hunt_protocol.py`
- `benchmarks/hermesbench/semantic_guidance.py`
- `benchmarks/hermesbench/hunt_evidence.py`
- `benchmarks/hermesbench/adapters/codex_exec.py`
- Focused builder, evidence, adapter, receipt, phase, runner, and CLI tests under `benchmarks/hermesbench/tests/`
- Public progress and benchmark documentation after verified results exist

Production changes to `phase_runner.py`, `runner.py`, or `cli.py` are unnecessary unless a focused RED test identifies a direct version assumption that imported constants and shared helpers do not cover. No public CLI flag, model setting, candidate schema, scoring schema, or external dependency is added.

## 14. Acceptance Criteria

This design is ready for implementation when the user approves the written specification and all of these conditions are represented in the implementation plan.

- New Hunt runs select evidence protocol version 3 explicitly.
- Protocol-v3 guidance contains a deterministic, non-empty, exact frontier-derived `eligible_search_passes` field.
- Protocol-v1 and protocol-v2 artifact bytes, prompts, evidence, and receipts remain exactly reconstructible.
- Invalid or unsupported model-selected passes still fail closed without host correction.
- Standard behavior, verification behavior, scoring, coverage debt, sandboxing, timeout, and model-call count remain unchanged.
- Focused and full tests, no-model boundaries, retained receipts, and one fixed paid diagnostic provide the evidence for any completion or performance claim.
