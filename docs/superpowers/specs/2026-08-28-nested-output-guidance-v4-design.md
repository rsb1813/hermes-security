# HermesBench Nested-Output Guidance Protocol v4 Design

Date: 2026-08-28
Status: Approved for implementation
Branch: `hermes/runner-canary`

## 1. Objective

Increase Hunt discovery recall for context-sensitive output vulnerabilities without adding a model invocation, weakening independent verification, changing the public CLI, or exposing private benchmark material.

Protocol v4 combines three host-side changes behind one explicit evidence-protocol version.

1. A deterministic TypeScript/JavaScript `nested-output-context` investigation hint for interpolations that enter active embedded output contexts.
2. Fair deterministic allocation of semantic edges and rows so early, high-fanout code cannot erase later operation families or components.
3. A blind verification projection that gives the fresh verifier only candidate identity and submitted locations, not the discovery model's conclusion or confidence.

The workflow remains exactly two model invocations per task: one discovery call and one independent verification call.

## 2. Confirmed Failure Mechanism

The latest fixed diagnostic completed discovery and verification, but its submitted candidates did not overlap the reviewed vulnerable location. The verifier accepted unrelated candidates with higher confidence, so workflow completion did not produce a discovery-accuracy gain.

Host-side, label-independent inspection established the following facts.

- The relevant source files were present in the immutable inventory and full frontier.
- They were absent from both the bounded priority packet and the emitted semantic-guidance rows.
- The discovery and verification command evidence did not show source inspection at those locations.
- The current extractor found source-like anchors in the relevant code but no operation anchor.
- The existing masking pass hides template-literal bodies, while operation extraction recognizes only a fixed set of call-like sinks.

The reviewed vulnerability pattern is a context mismatch. A low-trust or configured value is interpolated into an active nested language inside HTML-like output. An outer HTML sanitizer or tag allowlist does not necessarily make script, style, URL, or event-handler semantics safe when that active container remains allowed.

Increasing the current graph edge cap cannot repair a missing operation anchor. A dedicated template-aware detector is therefore the primary correction. Fair allocation is still required because global first-seen truncation can independently erase valid long-tail routes once an operation is extractable.

No raw prediction, hidden label, benchmark identity, source path, authentication value, or private output root is required to justify this design.

## 3. Success Criteria

Protocol v4 is successful only if all of the following are true.

- Synthetic vulnerable fixtures emit a bounded `nested-output-context` hint at the correct interpolation.
- Context-correct encoding, statically forbidden active containers, static markup, and lexical decoys do not emit that hint.
- The latest retained diagnostic snapshot produces the expected label-independent v4 artifact before a separate host-only oracle comparison checks coverage.
- Strong semantic edges and operation families retain representation under the existing edge, row, and byte caps.
- The v4 verifier prompt contains only the blind candidate projection and requires independent source inspection.
- Retained protocol-v1, protocol-v2, and protocol-v3 artifacts and receipts remain exactly revalidatable by their recorded versions.
- Standard workflow prompts, behavior, CLI, and SDK remain unchanged.
- The full no-model Python and TypeScript bridge checks pass before any paid call.
- Exactly one same-variable paid Canary rerun is made after the gates pass, with no automatic retry.

The paid rerun may support an accuracy-improvement claim only if localized true-positive discovery improves. Completion, higher confidence, specificity alone, or acceptance of unrelated candidates is not an accuracy gain.

## 4. Scope

### 4.1 Included

- Protocol-v4 evidence preparation and exact-version revalidation.
- Semantic-guidance schema version 3 for new v4 runs.
- A bounded JavaScript/TypeScript template-literal scanner with lexical-state awareness.
- Static classification of `script`, `style`, URL-valued attribute, and event-handler attribute contexts.
- Bounded local provenance for parameters, configuration-like values, property reads, and sanitizer-return values.
- Conservative suppression for context-correct local transforms and statically unavailable active containers.
- At most one deterministic explicit import-linked caller companion for a nested-output hint.
- Strong-edge-first round-robin allocation across declarations.
- Semantic-row round-robin allocation across hint families and frontier components.
- A v4-only blind candidate projection for Hunt verification.
- Synthetic, compatibility, prompt-golden, retained-receipt, and offline diagnostic gates.
- One fixed paid Canary rerun after every no-model gate passes.

### 4.2 Excluded

- Additional scout, synthesizer, or verifier model calls.
- Exploit generation, proof-of-concept payloads, crash inputs, remote traffic, or active target interaction.
- A general JavaScript or TypeScript parser replacement.
- Arbitrary interprocedural taint analysis or semantic claims about unknown helper implementations.
- Automatic relocalization, repair, or replacement of model-submitted candidate locations.
- Changes to the discovery response schema, final finding schema, scorer, oracle, candidate caps, timeout, model, effort, runtime image, or sandbox policy.
- Public CLI, SDK, or Standard workflow changes.
- Automatic paid retries after an incomplete or failed Canary rerun.
- Mini or Full promotion before the paid Canary evidence is reviewed.

## 5. Alternatives Considered

### 5.1 Selected: two-call Protocol v4

The selected design improves the information available to discovery and removes discovery prose from verification while preserving the existing two-call topology. It has the smallest cost and receipt-surface increase that directly addresses the confirmed failure.

### 5.2 Three independent discovery lanes plus verification

Forward, backward, and output-context discovery lanes could increase diversity, but they require four calls per task and a new multi-prediction merge receipt. They also confound whether a gain came from guidance quality or call count. This remains a later `hunt-max` option only if the completed v4 measurement still shows insufficient recall.

### 5.3 Scout, synthesizer, and verifier map-reduce

A multi-stage map-reduce workflow could expose more hypotheses but requires five or more calls, introduces another model-mediated bottleneck, and substantially expands failure and reproducibility contracts. It is rejected for this iteration.

### 5.4 Increase only edge, row, or token budgets

The missed pattern has no current operation anchor, so larger existing budgets would spend more resources on the same incomplete representation. This is rejected as the primary fix.

## 6. Versioning and Compatibility Contract

The explicit Hunt evidence protocol selects both semantic preparation and Hunt verifier projection.

| Hunt evidence protocol | Semantic artifact | Semantic row schema | Hunt verifier candidate view |
| --- | --- | --- | --- |
| 1 | Absent | Absent | Exact retained rich view |
| 2 | Present | 1 | Exact retained rich view |
| 3 | Present | 2 | Exact retained rich view |
| 4 | Present | 3 | Blind location-only view |

`HUNT_EVIDENCE_PROTOCOL_VERSION` becomes 4 for new runs and supported versions become `{1, 2, 3, 4}`. Semantic-guidance schema version 3 becomes the current schema while schemas 1 and 2 remain supported for exact reconstruction.

The discovery response schema and `HUNT_CANDIDATE_PROTOCOL_VERSION` remain unchanged. Discovery still supplies bounded hypothesis, family, pass, evidence, counterevidence, expected control, confidence, and exact locations. The host retains that canonical rich candidate transfer for attestation and receipt reproduction. Protocol v4 changes only the projection serialized into the verification prompt.

The existing Hunt workflow receipt schema remains sufficient because it already binds the evidence protocol version, canonical candidate transfer hash, semantic artifact hash through discovery evidence, frozen controls, and phase outputs. No new public receipt field is added. The v4 projection is a pure deterministic function of the recorded candidate transfer and recorded evidence protocol version, and its exact prompt bytes are protected by golden tests.

Version selection must be explicit. No helper may infer a historical artifact schema from the current default, and no legacy prompt may flow through a mutable default branch. Protocols 1 through 3 must preserve their current semantic bytes, prompt bytes, candidate projection, preparation fingerprint, failure behavior, and receipt reconstruction.

## 7. Template-Aware Nested-Output Detector

### 7.1 Language and resource boundary

The first detector applies only to canonical frontier paths with JavaScript or TypeScript source extensions. It reuses the existing pinned, regular-file, size, parent-identity, UTF-8, aggregate-source, and snapshot-containment checks.

It does not run a package manager, compiler, language server, or third-party parser. It performs a bounded single pass over each already accepted source file and stores only bounded location and reason metadata.

The detector has explicit per-file limits for template count, interpolation count, nested interpolation depth, and expression bytes. Hitting one of those limits skips the unfinished template and increments a path-free skip counter; it must not produce a partial hint or fail open.

### 7.2 Lexical states

The scanner distinguishes at least these states.

- Executable code.
- Line and block comments.
- Single- and double-quoted strings.
- Template raw text.
- Template interpolation expressions with balanced braces.
- Nested strings, comments, regex-like literals, and template literals inside an interpolation.

Escaped backticks, escaped interpolation markers, nested braces, and line continuations must be handled deterministically. Ordinary quoted strings, comments, and escaped template text are decoys and may not create hints.

Unlike the existing call-route extractor, this detector examines the raw and expression spans of a real template literal before template content is masked for other anchor extraction. Legacy schema preparation continues to use the existing masking path unchanged.

### 7.3 Static output-context classification

The classifier uses only static raw template text surrounding an interpolation. It never guesses a dynamically constructed tag name, attribute name, or quote boundary.

The initial context vocabulary is fixed and ordered.

```text
script
style
url_attribute
event_handler
```

An interpolation is eligible when its static surroundings place it in one of these contexts.

- Between a static opening and closing `script` element.
- Between a static opening and closing `style` element.
- Inside a statically named, quoted URL-bearing attribute value.
- Inside a statically named, quoted event-handler attribute value.

The URL-bearing attribute set is a small audited constant. Dynamic tag names, dynamic attribute names, unclosed markup, ambiguous quoting, and interpolation-created container boundaries are skipped rather than guessed.

### 7.4 Low-trust provenance

A nested context alone is not enough. The interpolation expression must have one of these bounded, syntactically supported origins.

- A formal parameter or destructured parameter of the containing declaration.
- A property or member read rooted in a parameter or locally named configuration-like binding.
- A direct configuration or environment-like read recognized by the existing source vocabulary.
- The direct return value of an outer HTML sanitizer or sanitizer-like local binding.
- A one-hop local alias of one of the preceding origins within the same declaration.

The detector does not claim that an identifier name proves attacker control. These origins only justify investigation. Unknown calls, more than one alias hop, dynamic property names, and ambiguous assignment histories do not create inferred provenance.

If a helper receives the value from an explicit import-linked caller, the detector may add at most one caller companion to the trace. The caller must be resolved by the existing exact import linkage, not name-only resolution. When multiple callers qualify, the canonical route sort selects exactly one. The companion cannot create a hint when the local nested-output criteria are absent.

### 7.5 Conservative suppressions

The detector suppresses a nested-output hint only when one of these conditions is syntactically established.

- The active interpolation is compile-time static or contains no supported low-trust origin.
- A context-specific transform from a small audited map wraps the complete interpolation expression and the map explicitly matches the classified output context.
- A statically applied sanitizer policy excludes the relevant active container or attribute from the rendered result.
- The apparent markup occurs only in a comment, ordinary quoted string, escaped template segment, type-only construct, or other lexical decoy.

Unknown helper names never suppress a hint. A generic HTML escape, generic HTML sanitizer, tag allowlist that retains the active container, or sanitizer-return value does not count as a context-specific transform. Instead, a locally visible outer HTML sanitization step adds a context-mismatch reason code.

The initial context-transform map is intentionally narrow. It recognizes only a full-expression URL-component transform when static template text fixes a relative path or query boundary before the interpolation, so the interpolated value cannot control a scheme or authority. Script, style, and event-handler contexts start with no name-based encoder suppression; a later entry requires an independently reviewed exact syntactic contract and paired positive and negative fixtures.

Static container or attribute removal is recognized only when an import-qualified sanitizer from an audited constant map receives a literal policy object at the same call site and that map defines the exact option semantics. A helper name, nearby policy object, default policy, or unknown option shape cannot suppress a hint.

This is an investigation heuristic, not a proof engine. A missed transform can create a false-positive hint, but the fresh verifier must independently inspect and may reject it. Suppression rules therefore prefer avoiding false negatives over recognizing unproven helper semantics.

## 8. Semantic-Guidance Schema Version 3

Schema-3 rows retain all schema-2 fields and add uniform classification fields.

```json
{
  "hint_kind": "nested-output-context",
  "output_context": "style",
  "component": "canonical-frontier-component"
}
```

The exact additions are as follows.

- `hint_kind` is `call-route` or `nested-output-context`.
- `output_context` is `null` for call routes and one value from the fixed context vocabulary for nested-output hints.
- `component` is copied from the validated exact frontier row for the operation path.

Nested-output rows use `operation_family: "output-context"`. Their `source` points to the bounded local provenance location, `operation` points to the interpolation location, and `trace` contains the containing declaration plus the optional single explicit import-linked caller. `controls` may record a locally visible outer sanitizer, but no control location changes `proof_status`.

Stable reason codes describe only observed syntax.

- `nested_output_context`.
- One context code matching the classified context.
- One provenance code matching the supported origin.
- `outer_html_sanitizer_context_mismatch` when applicable.
- `explicit_import` when the optional caller companion is present.

Every schema-3 row retains `proof_status: "investigation_only"`. Guidance strength, reason count, component, and context may not raise candidate confidence or serve as verification evidence.

The hint identity binds hint kind, output context, source, operation, trace, and operation family. Eligible search passes remain derived only from exact source, operation, and trace frontier rows in canonical pass order.

Schema-1 and schema-2 field sets and bytes remain unchanged. Their validators reject schema-3-only fields. Schema 3 requires all new fields, rejects unknown contexts or hint kinds, and preserves the existing strict extra-field rejection.

## 9. Fair Semantic Budget Allocation

Protocol v4 keeps the current profile limits. It changes selection order, not caps.

### 9.1 Reference and edge allocation

The current first-seen global reference truncation can spend the edge budget on early declarations. Schema-3 preparation instead uses deterministic rounds.

1. Scan and validate declarations in canonical frontier order under the existing declaration and source-byte limits.
2. Retain direct same-declaration routes without consuming a call edge.
3. Resolve explicit same-file and import-linked references for all declarations.
4. Allocate one strong resolved edge per declaration per round in stable declaration order until no strong edge remains or the edge cap is reached.
5. Spend any remaining budget on name-only edges with the same round-robin rule.

No declaration receives a second edge from a tier before every declaration with a remaining edge in that tier has had one opportunity. Duplicate endpoints retain the strongest route under the canonical route key. Input ordering, hash-map iteration, platform path syntax, and filesystem enumeration may not change the result.

### 9.2 Row allocation

Schema-3 candidate rows are divided into a strong tier and a weak tier. Nested-output, direct, and import-linked rows are strong. Name-only call routes are weak.

Within each tier, rows are queued by `(hint_kind, operation_family)`. Each family queue is itself round-robin across exact frontier components. Global selection takes one row from each family queue before a second row from the same family, and each family takes one row from each component before a second row from the same component.

All queues use canonical keys and the existing route ordering as tie-breakers. The strong tier is exhausted or reaches the row or byte cap before the weak tier begins. If an encoded row cannot fit the remaining byte budget, the allocator skips that row and continues to later bounded rows instead of terminating the entire selection.

This policy guarantees family representation before repeated rows from a dominant family whenever the row cap can hold one row per present family. It improves component breadth without inventing a benchmark-specific path quota. Rows omitted by the semantic artifact remain eligible in the complete frontier; guidance truncation never removes source from Hunt eligibility.

Legacy schema-1 and schema-2 preparation retains the existing edge and row selection exactly so retained artifacts remain byte-identical.

## 10. Blind Hunt Verification Projection

Protocol v4 continues to persist and attest the rich canonical candidate transfer. Immediately before constructing the Hunt verification prompt, the host derives a separate immutable view with exactly these fields.

```json
{
  "candidate_id": "candidate-N",
  "entry_point": {"file": "relative/path", "line": 1},
  "critical_operation": {"file": "relative/path", "line": 1},
  "trace": [{"file": "relative/path", "line": 1}]
}
```

The projection excludes discovery confidence, vulnerability family, search pass, hypothesis, evidence, counterevidence, and expected control. It preserves candidate order and exact locations and rejects any extra field.

The v4 Hunt verification prompt instructs the verifier to inspect the immutable source independently and reconstruct attacker control, reachability, impact, guard failure, supporting evidence, counterevidence, and proof gaps. It must terminate every candidate as accepted, rejected, or inconclusive and may not discover candidates outside the supplied set.

Existing location immutability remains authoritative. The verifier cannot add, remove, or relocalize a candidate, and every accepted finding must exactly match one supplied candidate's identity and locations. Relocalization is deliberately deferred because it is a separate candidate-schema and scoring decision.

Standard verification and Hunt protocol-v1 through protocol-v3 verification prompt bytes remain unchanged. Only a protocol-v4 Hunt verifier receives the blind view.

## 11. Artifact, Receipt, and Failure Boundaries

- Semantic guidance remains a trusted host-generated scratch artifact mounted under the existing immutable plan boundary.
- Repository text, identifiers, comments, strings, template contents, and candidate fields remain untrusted data, never instructions.
- Existing semantic read count, read order, size cap, descriptor validation, preparation fingerprint, candidate-location attestation, and post-run snapshot-integrity checks remain mandatory.
- Path-free hashes and aggregate counts are the only semantic details eligible for public evidence.
- Rich candidate transfer, source paths, private snapshots, raw model output, verifier decisions, and oracle comparisons remain private run artifacts.
- Failure publication stays atomic and bounded. It may not persist partial model text or sensitive exception strings.
- Existing fixed failure categories are reused unless implementation demonstrates a genuinely distinct host boundary that cannot be classified safely.
- No source-derived text may enter a public failure code.

## 12. Test-Driven Implementation Strategy

Implementation proceeds through RED and GREEN checkpoints. Production code is not written before a failing focused test establishes each behavior.

### 12.1 Nested-output fixtures

- Vulnerable examples for each of the four output contexts.
- Parameter, property, configuration, sanitizer-return, and one-hop alias provenance.
- A context-mismatch case where outer HTML handling retains the active nested context.
- Context-correct full-expression transforms for their matching contexts.
- A statically applied policy that removes the active container or attribute.
- Static markup with no interpolation.
- Comment, ordinary-string, escaped-template, and type-only decoys.
- Escaped backticks, nested braces, nested templates, and bounded malformed input.
- A single exact import-linked caller companion and rejection of name-only fanout.

### 12.2 Determinism and budget fixtures

- Repeated schema-3 builds produce identical bytes and hashes.
- Strong edges from late declarations survive early high fanout.
- Every present operation family receives a row before one family receives a second row when capacity permits.
- Components rotate within a family before repetition.
- Weak name-only rows cannot displace strong or nested-output rows.
- A row that exceeds the remaining byte budget does not block later bounded rows.
- Existing source, declaration, edge, route, row, output-byte, graph-depth, trace, and file-size limits remain enforced.

### 12.3 Protocol and prompt fixtures

- Exact protocol-v1, protocol-v2, and protocol-v3 semantic and prompt golden bytes remain unchanged.
- Protocol v4 selects schema 3 and refuses schema substitution.
- The v4 verifier candidate JSON has exactly four top-level fields and contains none of the excluded discovery fields.
- A golden prompt test proves the verifier is told to inspect source independently.
- Candidate decision completeness, maximum accepted findings, and exact location immutability remain enforced.
- Standard discovery and verification prompt hashes remain unchanged.

### 12.4 Receipt compatibility

- Revalidate retained complete and incomplete protocol-v1 receipts.
- Revalidate retained complete and incomplete protocol-v2 receipts.
- Revalidate retained complete and incomplete protocol-v3 receipts.
- Recompute protocol-v4 semantic bytes and blind projections from the immutable snapshot, recorded candidate transfer, and recorded protocol version.
- Reject cross-version semantic artifacts, prompts, projections, or preparation fingerprints.

## 13. Offline Diagnostic Gate

Before a paid call, the host runs schema-3 preparation against the latest retained immutable diagnostic snapshot without reading or supplying any oracle data to the builder.

The gate is split into two processes.

1. The ordinary v4 builder receives only the audited snapshot, validated frontier metadata, profile, and schema version. It writes the same canonical artifact that discovery would receive.
2. A separate private host-only evaluator compares the completed artifact to the held-out expected locations and records only a bounded pass/fail result plus aggregate counts.

The oracle may not select files, seed anchors, alter ordering, add rows, or affect artifact bytes. Public files and commits may contain only synthetic fixture evidence and path-free aggregate statements.

The paid gate remains closed unless the ordinary artifact contains relevant nested-output guidance, the vulnerable synthetic cases are positive, guarded and decoy cases are negative, deterministic budget tests pass, and the hidden comparison does not expose its locations.

## 14. Paid Canary Gate and Measurement

After all no-model gates and independent review pass, run exactly one paid Canary comparison under a fresh immutable output root.

The model, reasoning effort, profile, timeout, runtime image, sandbox policy, task set, snapshot hashes, scorer, candidate limits, and two-invocation topology remain fixed. Protocol v4 is the only material strategy bundle that changes. There is no automatic retry, even for an incomplete result.

The report separates the following evidence.

- Discovery and verification elapsed time.
- Cached input, uncached input, and output tokens for each phase.
- Candidate count, verifier disposition counts, and public finding count.
- Endpoint and trace true positives, false positives, and false negatives.
- Post-run snapshot, receipt, artifact, public-boundary, and container-cleanup checks.

The result must distinguish `candidate`, `reproduced`, `verified`, and `reportable` evidence levels. It must not call a partial, unlocalized, or specificity-only result a vulnerability-discovery improvement.

If v4 localizes the reviewed vulnerability and the verifier accepts it with the required proof, the next decision is whether Canary evidence is strong enough for Mini. If v4 still misses it, the next design review may consider independent discovery lanes, but no additional paid run is implied by this approval.

## 15. Acceptance Checklist

- Protocol v4 is explicit and legacy versions are exact.
- Template scanning is lexical, bounded, deterministic, and JavaScript/TypeScript-only.
- Nested contexts and provenance are observed syntax, not proof.
- Guard and decoy suppressions are conservative and covered by negative tests.
- Edge and row allocation are strong-first and fair under unchanged caps.
- The verifier sees only candidate identity and locations.
- The host still attests rich discovery data and exact candidate locations.
- Standard, CLI, SDK, scorer, sandbox, and call count remain unchanged.
- The offline diagnostic gate is oracle-independent during artifact creation.
- One paid Canary rerun is allowed only after every no-model gate passes.
- No private benchmark identity, path, label, raw finding, or credential enters Git or public evidence.
