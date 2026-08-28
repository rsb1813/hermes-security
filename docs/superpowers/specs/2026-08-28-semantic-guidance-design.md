# HermesBench Deterministic Semantic Guidance Design

Date: 2026-08-28
Status: Approved in chat; pending written-spec review
Branch: `hermes/runner-canary`

## 1. Objective

Improve Hunt vulnerability discovery by giving the discovery model a deterministic, bounded investigation order for source-to-sensitive-operation paths without adding a model invocation, weakening sandbox boundaries, or treating lexical inference as proof.

The first release of semantic guidance must materially change the information available to discovery while preserving the current two-call workflow.

1. Discovery receives one host-generated priority packet and one host-generated semantic-guidance packet.
2. Verification remains a fresh second invocation and receives only bounded candidates.
3. The model must inspect actual source before it may submit a candidate.
4. Existing protocol-v1 workflow receipts remain independently revalidatable.

## 2. Evidence From the Current Diagnostic

The completed v12c diagnostic proved that the schema-3 artifact gate, independent verification, receipt reconstruction, and output isolation work. It did not prove a discovery improvement.

- Discovery generated one candidate.
- Verification accepted the candidate and produced one public finding.
- The finding received zero advisory recall, zero pair-localization F1, and zero trace-node F1.
- The composite score remained 0.15 from fixed-snapshot specificity.
- Candidate expansion in v11 and deterministic frontier prioritization in v12c both failed to improve discovery accuracy.

The next experiment must therefore improve path formation rather than increase candidate count or add another free-form model pass.

## 3. Scope

This change includes the following work.

- Build deterministic lexical declarations, references, imports, calls, boundary anchors, control anchors, and sensitive-operation anchors from immutable snapshot bytes.
- Connect bounded source-to-operation investigation routes across files.
- Write a canonical `semantic-guidance.jsonl` scratch artifact.
- Require Hunt discovery to read the artifact exactly once.
- Bind the artifact hash and path-free counts into Hunt evidence protocol version 2.
- Preserve exact protocol-v1 preparation and receipt reconstruction.
- Add synthetic Python, Go, TypeScript, and generic-fallback tests.
- Run one fixed paid Canary diagnostic after all no-model gates pass.

This change does not include the following work.

- Claiming that a lexical route proves reachability, attacker control, impact, or a missing guard.
- Automatically accepting or increasing confidence for a candidate because it overlaps guidance.
- Reducing the complete frontier, coverage debt, or candidate location checks.
- Adding CodeQL, Semgrep, tree-sitter, language servers, compiler frontends, or network services.
- Adding a third model invocation.
- Running HermesBench Mini before the fixed Canary diagnostic shows a discovery-quality signal.
- Generating exploits, proof-of-concept payloads, crash inputs, or remote requests.

## 4. Alternatives

### 4.1 Regex-only signal expansion

Adding more names to the existing entry, sink, parser, control, and state patterns is the smallest change. It cannot connect wrappers, imports, or callers, so it is unlikely to correct the observed localization and trace failures.

### 4.2 Lightweight lexical graph

The selected approach extracts language-shaped declarations, imports, and call references, then resolves only bounded and explainable edges. It supports the current multi-language benchmark without adding parser dependencies. Ambiguous edges remain low-strength investigation hints.

### 4.3 Language-specific AST graph

Dedicated AST frontends could provide more precise symbol resolution. They would introduce multiple parser stacks, version policies, failure fallbacks, and container inputs before the lexical hypothesis has been measured. AST frontends are deferred until benchmark evidence identifies a language-specific lexical ceiling.

## 5. Architecture

### 5.1 Module boundary

Create `benchmarks/hermesbench/semantic_guidance.py` as a focused host-side component. It owns source scanning, lexical extraction, graph construction, route projection, canonical serialization, and version-2 guidance limits.

`benchmarks/hermesbench/hunt_evidence.py` remains the artifact coordinator. It records the new artifact, includes it in the preparation fingerprint, verifies immutable bytes after execution, enforces the read cardinality, and emits path-free evidence.

`benchmarks/hermesbench/adapters/codex_exec.py` changes only the Hunt discovery prompt and attestation mapping. Standard and Hunt verification prompts remain unchanged except for shared constants that do not alter their text.

### 5.2 Data flow

1. The trusted host creates the existing inventory, rank input, complete frontier, frontier receipt, and priority packet.
2. The semantic builder processes eligible inventory paths in deterministic order under profile-specific byte and row budgets.
3. The builder emits canonical guidance rows and aggregate build statistics.
4. The discovery container receives the immutable plan directory.
5. The discovery prompt requires exactly one read of the priority packet followed by exactly one read of the semantic-guidance packet.
6. The model treats guidance as an investigation order, opens actual source, checks controls and counterevidence, and returns bounded candidates through the existing schema.
7. Host attestation rehashes every prepared artifact, checks both required reads, and performs the existing candidate-to-frontier linkage.
8. Fresh verification and public finding projection continue unchanged.

## 6. Lexical Graph Contract

### 6.1 Supported extraction families

The first implementation has explicit extractors for these file families.

- Python source files.
- Go source files.
- TypeScript and JavaScript source files, including common module variants.
- A conservative generic text fallback for other inventory files that pass existing source-file eligibility.

The extractors identify these facts with relative path and one-based line number.

- Function, method, class, and assigned-callable declarations.
- Import, export, module, and package references.
- Call-like identifier references.
- Input and entry-boundary anchors.
- Validation, authorization, escaping, and sanitization control anchors.
- Sensitive-operation anchors grouped into stable defensive families such as command execution, query construction, file access, template rendering, deserialization, outbound request, and state mutation.

Comments and string literals are ignored where the bounded family scanner can do so deterministically. The generic fallback never creates a high-strength route.

### 6.2 Edge strengths

Every graph edge has one of three strengths.

- `direct` means the source and operation occur in one lexical declaration or a call resolves to one declaration in the same file.
- `import-linked` means a module reference and unique symbol declaration provide a bounded cross-file connection.
- `name-only` means only an otherwise ambiguous declaration or call name connects the sites.

These strengths express investigation priority only. They do not express vulnerability confidence.

### 6.3 Route construction

The builder performs deterministic breadth-first traversal from source anchors toward sensitive-operation anchors and backward from sensitive operations toward entry anchors.

- `hunt-balanced` uses a maximum call depth of 4.
- `hunt-max` uses a maximum call depth of 6.
- Cycles are cut by stable node identity.
- A route contains no repeated node.
- Stable sorting uses strength, route length, operation family, source location, operation location, and trace locations.
- Duplicate endpoint pairs retain the strongest and shortest route.
- Control anchors found on or adjacent to a route are included as review locations, never as proof that the route is safe.

### 6.4 Guidance row

Each canonical JSONL row contains exactly these public scratch fields.

- `schema_version`.
- `hint_id` derived from canonical route content.
- `strength`.
- `operation_family`.
- `source` with relative path, line, symbol, and anchor category.
- `operation` with relative path, line, symbol, and anchor category.
- `trace` containing bounded relative locations and symbols.
- `controls` containing bounded relative control locations.
- `reason_codes` from a fixed vocabulary.
- `proof_status` fixed to `investigation_only`.

Rows contain no source snippets, advisory identifiers, oracle values, absolute paths, model-authored text, or vulnerability verdicts.

## 7. Resource Bounds

All bounds are enforced before container execution and are part of deterministic preparation.

- Each file is limited to 1 MiB of UTF-8 source. Larger or invalid UTF-8 files are skipped for guidance but remain in the complete frontier.
- `hunt-balanced` scans at most 64 MiB, retains at most 50,000 declarations, 200,000 graph edges, 1,024 route candidates, 256 guidance rows, and 512 KiB of canonical guidance output.
- `hunt-max` scans at most 128 MiB, retains at most 100,000 declarations, 400,000 graph edges, 2,048 route candidates, 512 guidance rows, and 1 MiB of canonical guidance output.
- A route contains at most 12 trace locations and 8 nearby control locations after graph-depth enforcement.
- Budget exhaustion is recorded as path-free counts and never removes frontier eligibility or coverage debt.
- An empty guidance artifact is valid when no bounded route is found.
- Changing any limit after the first paid run is a separate benchmark variable.

## 8. Artifact and Evidence Versioning

### 8.1 Protocol version 1

Protocol version 1 keeps the exact current artifact set, priority bytes, evidence fields, and reconstruction algorithm. Retained v12 and v12c receipts must continue to revalidate byte-for-byte.

### 8.2 Protocol version 2

New live Hunt discovery runs use protocol version 2. Version-2 evidence adds these path-free fields.

- `semantic_guidance_sha256`.
- `semantic_guidance_count`.
- `semantic_guidance_edge_count`.
- `semantic_guidance_scanned_file_count`.
- `semantic_guidance_skipped_file_count`.

The workflow receipt remains schema version 3 because it already contains an explicit Hunt evidence protocol version and binds the complete evidence artifact hash. Its parser accepts supported protocol versions 1 and 2, then selects the corresponding evidence field set and reproduction algorithm.

Frozen controls remain schema version 2. A result comparison records the evidence protocol and must not present protocol-1 and protocol-2 runs as the same discovery strategy.

## 9. Attestation and Failure Handling

Version-2 discovery adds two fixed, path-free failure codes.

- `hunt_semantic_guidance_missing`.
- `hunt_semantic_guidance_duplicate`.

Mutation, replacement, hard-link, symbolic-link, reparse-point, size, canonicalization, or hash failures use the existing prepared-artifact-integrity category. Unknown failures continue to use the existing broad fallback.

A semantic failure never persists exception text, source paths, command text, or partial success artifacts. Discovery failure remains independently revalidatable from canonical task receipts.

## 10. Prompt Contract

The Hunt discovery prompt adds these requirements.

- Read the priority packet and semantic-guidance packet exactly once each, with the priority packet first in the requested workflow.
- Treat semantic guidance as an investigation queue, not evidence.
- Open and trace actual source before producing a candidate.
- Check reachable controls and counterevidence before asserting guard failure.
- Do not raise confidence because a route is `direct` or `import-linked`.
- Continue beyond guidance when source inspection identifies a better route because the complete frontier remains eligible.

The prompt does not reveal hidden labels and does not request exploitation, payload construction, or unsafe execution.

## 11. Testing Strategy

Implementation follows test-driven development.

### 11.1 Semantic builder tests

- Identical snapshots prepared under different scratch roots produce identical guidance bytes and hashes.
- Python, Go, and TypeScript single-file source-to-operation paths produce `direct` guidance.
- Python, Go, and TypeScript cross-file paths with explicit module links produce `import-linked` guidance.
- Ambiguous same-name declarations never become `direct` or `import-linked` routes.
- Generic fallback output is at most `name-only`.
- Cycles, duplicate endpoints, oversized files, invalid UTF-8, and empty graphs remain deterministic and bounded.
- Guidance rows contain only relative paths and the exact schema.

### 11.2 Artifact and adapter tests

- Version-2 preparation records the guidance artifact and includes its hash in the fingerprint.
- Missing, duplicate, mutated, replaced, linked, or oversized guidance fails closed with the expected public category.
- Discovery reads both packets exactly once; missing and duplicate semantic reads receive their fixed categories.
- The discovery prompt contains the investigation-only warning.
- Standard and Hunt verification prompts remain byte-identical to their pre-change behavior.

### 11.3 Receipt compatibility tests

- A committed synthetic protocol-v1 fixture revalidates after protocol v2 becomes current.
- Version-1 reconstruction emits the exact legacy field set and bytes.
- Version-2 reconstruction reproduces guidance hash and counts from snapshot bytes.
- Evidence field mixing, unsupported versions, or protocol mismatches fail closed.
- Incomplete version-2 discovery receipts remain independently revalidatable.

### 11.4 Full verification

- Run the full Python HermesBench suite.
- Run the TypeScript HermesBench suite.
- Run compile checks and diff checks.
- Run deterministic no-model preparation twice.
- Run named permission and regular-auth smoke checks when adapter or container boundaries change.
- Confirm no retained authentication value, host path, reparse entry, snapshot mutation, or residual container.

## 12. Benchmark Gate

The first paid protocol-v2 run changes only semantic guidance. It reuses the same diagnostic task, model, effort, timeout, snapshot, scorer, candidate protocol, and two-call workflow as v12c.

The run is a discovery improvement only if at least one of these public metrics becomes positive without a fixed-snapshot false positive.

- Advisory recall.
- Pair-localization F1.
- Trace-node F1.

Pipeline completion, candidate count, verifier acceptance, or draft-report count alone is not an improvement.

If the fixed diagnostic remains at zero discovery metrics, do not run Mini. Inspect only path-free guidance counts and public prediction metrics, then change one graph variable at a time.

If the diagnostic improves, compare `hunt-balanced` and `hunt-max` on the complete eight-snapshot Canary. Advance to HermesBench Mini only when the Canary comparison identifies a profile with a real discovery signal. HermesBench Full remains mandatory for the final claim.

## 13. Expected Implementation Files

- `benchmarks/hermesbench/semantic_guidance.py`.
- `benchmarks/hermesbench/hunt_evidence.py`.
- `benchmarks/hermesbench/adapters/codex_exec.py`.
- `benchmarks/hermesbench/phase_runner.py`.
- `benchmarks/hermesbench/runner.py` only for the two new public failure codes.
- `benchmarks/hermesbench/tests/test_semantic_guidance.py`.
- Existing Hunt evidence, adapter, runner, and phase-runner tests.
- `benchmarks/hermesbench/README.md` and the bundled Hunt contract only where the public protocol changes.

Standard schemas, Standard prompts, public prediction schemas, scoring weights, corpus inputs, and execution-policy command prefixes are outside the expected diff.

## 14. Acceptance Criteria

The semantic-guidance milestone is complete when all of these conditions hold.

- Protocol-v2 semantic guidance is deterministic, bounded, path-safe, and immutable.
- Discovery receives the guidance in one additional audited read without another model invocation.
- Guidance never counts as validation evidence, coverage closure, or automatic confidence.
- Protocol-v1 retained receipts still revalidate.
- Standard behavior and verification behavior remain unchanged.
- All unit, integration, compatibility, compile, and boundary checks pass.
- The fixed paid diagnostic is scored and compared with v10, v11, and v12c using separated token classes.
- Mini is run only after a positive Canary discovery signal, and Full is required before a final performance claim.
