# HermesBench Nested-Output Guidance Protocol v4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Increase Hunt target-localized vulnerability recall with deterministic nested-output guidance, fair semantic budgets, and blind independent verification while retaining the existing two-call cost ceiling and exact protocol-v1 through protocol-v3 reconstruction.

**Architecture:** Hunt evidence protocol version 4 selects semantic-guidance schema version 3 and a Hunt-only location projection at the verification prompt boundary. A bounded JavaScript/TypeScript lexical scanner emits investigation-only nested-output observations before existing template masking, while schema-3-only strong-edge and family/component round-robin allocation prevents early high fanout from erasing long-tail guidance. Rich discovery candidates remain in the private canonical transfer for attestation and receipt reproduction; only the fresh verifier receives the blind projection.

**Tech Stack:** Python 3 standard library, `unittest`, existing HermesBench contracts and receipts, Bun TypeScript bridge test, existing pinned Docker/Codex runtime for the final paid gate only, Git.

**Spec:** `docs/superpowers/specs/2026-08-28-nested-output-guidance-v4-design.md`

## Global Constraints

- Perform defensive local-source discovery only. Do not generate exploits, proof-of-concept payloads, crash inputs, remote traffic, or credential access.
- Keep exactly two top-level model invocations per completed Hunt task: one discovery call and one fresh verification call.
- New live Hunt runs use evidence protocol version 4 and semantic row schema version 3. Protocol versions 1, 2, and 3 must reproduce their current artifact, prompt, evidence, candidate projection, failure, and receipt behavior by recorded version.
- Keep the discovery response schema and `HUNT_CANDIDATE_PROTOCOL_VERSION` unchanged. Rich discovery candidates remain canonical private transfer data.
- The protocol-v4 verifier receives exactly `candidate_id`, `entry_point`, `critical_operation`, and `trace`; it receives no discovery confidence, vulnerability family, search pass, hypothesis, evidence, counterevidence, or expected control.
- Keep at most 12 discovery candidates, at most five public findings, and the existing 480-second per-phase production timeout.
- Keep each source file bounded to 1 MiB. Preserve `hunt-balanced` limits of 64 MiB source, 50,000 declarations, 200,000 edges, 1,024 route work items, 256 rows, 512 KiB output, and graph depth 4. Preserve `hunt-max` limits of 128 MiB source, 100,000 declarations, 400,000 edges, 2,048 route work items, 512 rows, 1 MiB output, and graph depth 6.
- Schema-3 template scanning applies only to JavaScript and TypeScript source extensions and uses no compiler, package manager, language server, parser dependency, network service, model call, or SAST service.
- Every semantic row remains `proof_status: "investigation_only"`. Hint kind, context, reason codes, strength, component, and eligible passes never prove attacker control, reachability, impact, or guard failure and never raise confidence.
- Keep Standard prompt bytes, CLI and SDK behavior, scorer, public prediction schema, frontier eligibility, coverage debt, candidate-location attestation, sandbox, authentication, network, and container cleanup boundaries unchanged.
- Persist only path-free hashes and aggregate counts in public evidence. Do not commit or publish private task identities, snapshot paths, oracle locations, raw model predictions, findings, credentials, authentication values, or host paths.
- The retained-snapshot artifact build must not receive oracle data. A separate host-only process may compare the finished canonical artifact to the oracle.
- Run exactly one same-variable paid Canary after all no-model gates pass. Never retry it automatically.
- Write all new or modified code comments and docstrings in English.
- Use `apply_patch` for source edits, prefix every executed shell command with `rtk`, run RED before GREEN, and make one semantic commit per completed task.

## File Structure

- Create `benchmarks/hermesbench/nested_output_guidance.py` for the bounded JavaScript/TypeScript template-literal state machine and local observations. It does not know frontier paths, receipts, candidates, or oracles.
- Modify `benchmarks/hermesbench/semantic_guidance.py` to select schema 3 explicitly, map local observations to canonical routes, attach exact frontier component/pass data, allocate v4 edges and rows fairly, and preserve schema-1/schema-2 bytes.
- Modify `benchmarks/hermesbench/hunt_evidence.py` to support explicit evidence protocols 1 through 4 and pass component-aware frontier rows to schema 3.
- Modify `benchmarks/hermesbench/adapters/codex_exec.py` to add an explicit v4 discovery branch and derive the blind v4 verification projection immediately before prompt serialization.
- Modify `benchmarks/hermesbench/phase_runner.py` only to expose a deterministic location-only projection from `CanonicalCandidate`; keep `to_json()` and candidate-transfer bytes unchanged.
- Modify `benchmarks/hermesbench/tests/test_semantic_guidance.py` for schema 3, nested contexts, provenance, suppressions, lexical decoys, limits, determinism, and fair allocation.
- Modify `benchmarks/hermesbench/tests/test_hunt_evidence.py` for protocol-v4 preparation, parsing, attestation, and exact v1-v3 compatibility.
- Modify `benchmarks/hermesbench/tests/test_codex_exec_adapter.py` for explicit v1-v4 discovery prompts, blind v4 verification, and legacy/Standard golden prompts.
- Modify `benchmarks/hermesbench/tests/test_phase_runner.py`, `test_cli.py`, and only directly failing supported-version tests to propagate protocol 4 and prove rich candidate-transfer preservation.
- Modify `benchmarks/hermesbench/README.md` and `sdk/typescript/_bundled_plugin/skills/hunt-security-scan/references/hunt-contract.md` after behavior is green.
- Update `checklist.md` and `context-notes.md` only with evidence actually produced.
- Create two ignored host-only gate scripts under `benchmarks/hermesbench/private/` during Task 5. They must remain untracked and must not be pushed.

---

### Task 1: Explicit Protocol-v4 and Semantic Schema-3 Spine

**Files:**
- Modify: `benchmarks/hermesbench/semantic_guidance.py:15-17,91-118,156-187,1000-1140`
- Modify: `benchmarks/hermesbench/hunt_evidence.py:17-36,51-66,190-215,235-310,399-415,575-620`
- Modify: `benchmarks/hermesbench/adapters/codex_exec.py:454-525`
- Modify: `benchmarks/hermesbench/tests/test_semantic_guidance.py:1-195`
- Modify: `benchmarks/hermesbench/tests/test_hunt_evidence.py:100-278,414-535`
- Modify: `benchmarks/hermesbench/tests/test_codex_exec_adapter.py:139-325`
- Modify: `benchmarks/hermesbench/tests/test_phase_runner.py:250-360,660-725`

**Interfaces:**
- Consumes: `frontier_contexts: tuple[tuple[str, str, tuple[str, ...]], ...]`, where each row is exact canonical path, exact validated component, and exact validated pass tuple.
- Produces: `build_semantic_guidance(snapshot_path: Path, frontier_contexts: tuple[tuple[str, str, tuple[str, ...]], ...], profile: str, *, guidance_schema_version: int) -> SemanticGuidance`.
- Produces: schema-3 call-route rows with `hint_kind: "call-route"`, `output_context: None`, and the exact operation-path frontier `component`.
- Produces: explicit protocol mapping `1 -> no semantic artifact`, `2 -> schema 1`, `3 -> schema 2`, and `4 -> schema 3`.

- [ ] **Step 1: Write RED schema-3 row tests with hand-derived fields**

Change the test frontier helper to provide a literal component and add a schema-3 call-route assertion.

```python
def _frontier_contexts(
    files: dict[str, str | bytes],
    passes: dict[str, tuple[str, ...]] | None = None,
    components: dict[str, str] | None = None,
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    selected_passes = passes or {}
    selected_components = components or {}
    return tuple(
        (
            path,
            selected_components.get(path, "component-default"),
            selected_passes.get(path, ("forward",)),
        )
        for path in files
    )

def _build(
    self,
    name: str,
    files: dict[str, str | bytes],
    profile: str = "hunt-balanced",
    *,
    guidance_schema_version: int = 1,
    passes: dict[str, tuple[str, ...]] | None = None,
    components: dict[str, str] | None = None,
) -> SemanticGuidance:
    snapshot = self._root / name
    snapshot.mkdir()
    for relative, value in files.items():
        path = snapshot / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode("utf-8"))
    return build_semantic_guidance(
        snapshot,
        _frontier_contexts(files, passes, components),
        profile,
        guidance_schema_version=guidance_schema_version,
    )

def test_schema_three_classifies_call_routes_and_exact_operation_component(self) -> None:
    result = self._build(
        "schema-three-call",
        {"src/app.ts": "export function handle(request: Request) { return child_process.exec(request.query.q); }\n"},
        guidance_schema_version=3,
        components={"src/app.ts": "component-api"},
    )
    row = json.loads(result.canonical_bytes)
    self.assertEqual(row["schema_version"], 3)
    self.assertEqual(row["hint_kind"], "call-route")
    self.assertIsNone(row["output_context"])
    self.assertEqual(row["component"], "component-api")
    self.assertEqual(row["eligible_search_passes"], ["forward"])
    self.assertEqual(row["proof_status"], "investigation_only")
```

Retain the current literal schema-1 canonical bytes and the current protocol-2 semantic SHA-256 and preparation fingerprint. Retain the existing schema-2 pass-union assertions without computing an expected value through production helpers.

- [ ] **Step 2: Run schema tests and confirm RED**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_semantic_guidance -v
```

Expected: the builder rejects schema version 3 or the three-field frontier row. The legacy tests remain green.

- [ ] **Step 3: Implement explicit schema constants, frontier normalization, and schema-3 call rows**

Use explicit constants rather than comparing a historical version to the mutable current default.

```python
LEGACY_SEMANTIC_GUIDANCE_SCHEMA_VERSION = 1
PASS_ANNOTATED_SEMANTIC_GUIDANCE_SCHEMA_VERSION = 2
SEMANTIC_GUIDANCE_SCHEMA_VERSION = 3
SUPPORTED_SEMANTIC_GUIDANCE_SCHEMA_VERSIONS = frozenset({1, 2, 3})
```

Extend `_Route` with defaults so current positional construction remains valid.

```python
@dataclass(frozen=True)
class _Route:
    strength: str
    operation_family: str
    source: _Location
    operation: _Location
    trace: tuple[_Location, ...]
    controls: tuple[_Location, ...]
    reason_codes: tuple[str, ...]
    hint_kind: str = "call-route"
    output_context: str | None = None
```

Normalize every frontier row before source scanning. Preserve first-seen canonical path order, canonical pass order, and exact duplicate behavior. Reject malformed components for schema 3, but do not let component data alter schema-1 or schema-2 row bytes.

For schema 3, `_canonical_row` adds exactly `hint_kind`, `output_context`, and `component`. For schema 1 and 2, it retains the current exact field sets and hint identity. For schema 3, the hint identity additionally binds hint kind and output context.

- [ ] **Step 4: Run semantic tests and confirm GREEN**

Run the focused module. Expected: schema-1, schema-2, and schema-3 tests pass, including current literal legacy bytes.

- [ ] **Step 5: Write RED evidence-protocol-v4 tests**

Add explicit behavior tests.

```python
def test_protocol_four_records_schema_three_guidance_without_changing_legacy_hashes(self) -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        snapshot = self._semantic_snapshot(root)
        protocol_two = prepare_hunt_artifacts(snapshot, root / "two", "hunt-balanced", evidence_protocol_version=2)
        protocol_three = prepare_hunt_artifacts(snapshot, root / "three", "hunt-balanced", evidence_protocol_version=3)
        protocol_four = prepare_hunt_artifacts(snapshot, root / "four", "hunt-balanced", evidence_protocol_version=4)
        row = json.loads(protocol_four.semantic_guidance.path.read_text(encoding="utf-8"))
    self.assertEqual(row["schema_version"], 3)
    self.assertEqual(row["hint_kind"], "call-route")
    self.assertEqual(row["component"], ".")
    self.assertNotEqual(protocol_four.semantic_guidance.sha256, protocol_three.semantic_guidance.sha256)
    self.assertEqual(protocol_two.semantic_guidance.sha256, "c7521cf55318dc1cc393c12e39c643fbabdd003d02329160f92861c257549a37")
```

Update supported-version loops to `(1, 2, 3, 4)` and unsupported values to `(0, 5)`. Add an explicit v4 discovery prompt hash slot and assert that v4 retains v3 pass-selection instructions plus the terms `nested-output-context`, `output_context`, and `investigation only`. Keep the live default at protocol 3 until Task 4 completes the blind verifier boundary.

- [ ] **Step 6: Run protocol tests and confirm RED**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_hunt_evidence benchmarks.hermesbench.tests.test_codex_exec_adapter benchmarks.hermesbench.tests.test_phase_runner -v
```

Expected: protocol 4 is unsupported and the adapter has no explicit v4 discovery branch.

- [ ] **Step 7: Implement explicit evidence-version mapping and v4 discovery prompt**

Define fixed semantic protocol names.

```python
LEGACY_HUNT_EVIDENCE_PROTOCOL_VERSION = 1
SEMANTIC_GUIDANCE_HUNT_EVIDENCE_PROTOCOL_VERSION = 2
PASS_ANNOTATED_HUNT_EVIDENCE_PROTOCOL_VERSION = 3
NESTED_OUTPUT_HUNT_EVIDENCE_PROTOCOL_VERSION = 4
HUNT_EVIDENCE_PROTOCOL_VERSION = PASS_ANNOTATED_HUNT_EVIDENCE_PROTOCOL_VERSION
SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS = frozenset({1, 2, 3, 4})
_SEMANTIC_HUNT_EVIDENCE_PROTOCOL_VERSIONS = frozenset({2, 3, 4})
```

Make `_semantic_guidance_schema_version` branch on all three semantic protocols explicitly. Project frontier rows as `(path, component, passes)` after `_validate_frontier_rows`. Keep evidence and workflow receipt field sets unchanged but select them with explicit version-aware helpers.

Add a separate v4 discovery prompt branch. It retains the v3 exact-pass instructions and tells discovery to prioritize actual source inspection for `nested-output-context` rows without treating context or reason codes as proof.

- [ ] **Step 8: Run focused protocol tests and confirm GREEN**

Run the Task 1 test command again. Expected: all tests pass and explicit v1-v3 golden hashes remain unchanged.

- [ ] **Step 9: Self-review and commit Task 1**

Run `rtk git diff --check`, inspect every caller of `build_semantic_guidance`, and commit only Task 1 files.

```powershell
rtk git commit -m "feat: add Hunt evidence protocol v4 spine"
```

---

### Task 2: Bounded JavaScript and TypeScript Nested-Output Detector

**Files:**
- Create: `benchmarks/hermesbench/nested_output_guidance.py`
- Modify: `benchmarks/hermesbench/semantic_guidance.py:220-280,700-870,1000-1140`
- Modify: `benchmarks/hermesbench/tests/test_semantic_guidance.py`

**Interfaces:**
- Produces: `scan_nested_output_contexts(source: str) -> tuple[NestedOutputObservation, ...]`.
- Produces: frozen `NestedOutputObservation(context, declaration_line, declaration_symbol, source_line, source_symbol, operation_line, control_lines, reason_codes)` with no source snippet or free-form prose.
- Consumes in `semantic_guidance.py`: schema version 3 only. Legacy schemas never call the new scanner.
- Produces schema-3 `_Route` values with `hint_kind="nested-output-context"`, `operation_family="output-context"`, a fixed output context, local declaration trace, and `proof_status="investigation_only"` after serialization.

- [ ] **Step 1: Write RED tests for the four observable output contexts**

Add one literal fixture per context and assert the real builder output.

```python
def test_schema_three_emits_each_nested_output_context(self) -> None:
    fixtures = {
        "script": "export function render(request) { return `<script>const value = '${request.query.value}'</script>`; }\n",
        "style": "export function render(options) { return `<style>.card { color: ${options.color}; }</style>`; }\n",
        "url_attribute": "export function render(config) { return `<a href=\"/go?next=${config.next}\">go</a>`; }\n",
        "event_handler": "export function render(params) { return `<button onclick=\"show('${params.name}')\">go</button>`; }\n",
    }
    for context, source in fixtures.items():
        with self.subTest(context=context):
            result = self._build(
                f"nested-{context}",
                {"src/render.ts": source},
                guidance_schema_version=3,
            )
            rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
            nested = [row for row in rows if row["hint_kind"] == "nested-output-context"]
            self.assertEqual(len(nested), 1)
            self.assertEqual(nested[0]["output_context"], context)
            self.assertEqual(nested[0]["operation_family"], "output-context")
            self.assertEqual(nested[0]["proof_status"], "investigation_only")
```

- [ ] **Step 2: Run the context test and confirm RED**

Run the single test. Expected: no nested-output row exists, not an import or fixture error.

- [ ] **Step 3: Create the lexical state machine and minimal context classifier**

Create the new module with an English module role docstring and these exact bounds.

```python
JAVASCRIPT_TYPESCRIPT_EXTENSIONS = frozenset({
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"
})
OUTPUT_CONTEXT_ORDER = ("script", "style", "url_attribute", "event_handler")
URL_ATTRIBUTES = frozenset({"href", "src", "action", "formaction", "poster", "xlink:href"})
MAX_TEMPLATES_PER_FILE = 256
MAX_INTERPOLATIONS_PER_FILE = 512
MAX_INTERPOLATION_DEPTH = 16
MAX_EXPRESSION_BYTES = 16 * 1024

@dataclass(frozen=True)
class NestedOutputObservation:
    context: str
    declaration_line: int
    declaration_symbol: str
    source_line: int
    source_symbol: str
    operation_line: int
    control_lines: tuple[int, ...]
    reason_codes: tuple[str, ...]
```

Implement one deterministic scan that distinguishes executable code, comments, quoted strings, template raw text, and balanced `${...}` expressions. Handle escaped backticks, escaped interpolation markers, nested braces, strings, comments, regex-like literals, and nested templates inside an interpolation. On an unfinished or over-limit template, discard that unfinished observation and continue or terminate deterministically without emitting a partial hint.

Classify context only from static raw text around the interpolation. Skip dynamic tag names, dynamic attribute names, unquoted attributes, ambiguous quotes, and interpolation-created boundaries.

In `semantic_guidance.py`, accept `operation_family="output-context"` only when schema version is 3, `hint_kind` is `nested-output-context`, and `output_context` is valid. Map every observed outer sanitizer control line to the fixed location symbol `outer-html-sanitizer`; never copy a call expression into the row.

- [ ] **Step 4: Run context tests and confirm GREEN**

Run the focused context test, then the full semantic-guidance test module. Expected: all existing call-route tests remain green.

- [ ] **Step 5: Write RED provenance tests**

Add parameter, parameter-property, configuration, sanitizer-return, and one-hop alias fixtures. Assert stable literal reason codes.

```python
def test_nested_output_records_bounded_observed_provenance(self) -> None:
    source = (
        "export function render(options) {\n"
        "  const selected = options.theme;\n"
        "  const cleaned = sanitizeHtml(selected);\n"
        "  return `<style>.card { color: ${cleaned}; }</style>`;\n"
        "}\n"
    )
    result = self._build(
        "nested-provenance",
        {"src/render.ts": source},
        guidance_schema_version=3,
    )
    row = next(json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line)
    self.assertIn("one_hop_alias_provenance", row["reason_codes"])
    self.assertIn("sanitizer_return_provenance", row["reason_codes"])
    self.assertIn("outer_html_sanitizer_context_mismatch", row["reason_codes"])
    self.assertNotIn("options.theme", json.dumps(row))
```

Unknown calls, a second alias hop, dynamic property names, and ambiguous assignments must not invent supported provenance.

- [ ] **Step 6: Implement bounded local provenance and context-mismatch reasons**

Parse only the containing JavaScript/TypeScript declaration. Recognize formal and destructured parameters, member reads rooted in a parameter, exact configuration roots, direct sanitizer-like return values, and one local alias hop. Store only canonical identifiers and fixed reason codes, never raw expressions.

Use fixed provenance codes: `parameter_provenance`, `property_provenance`, `config_provenance`, `sanitizer_return_provenance`, and `one_hop_alias_provenance`. Add `nested_output_context` plus exactly one context code from `embedded_script`, `embedded_style`, `url_attribute_context`, or `event_handler_context`. Add `outer_html_sanitizer_context_mismatch` only when local syntax establishes the outer sanitizer.

- [ ] **Step 7: Write RED conservative-suppression and lexical-decoy tests**

Add table-driven negative fixtures for:

- `encodeURIComponent(request.query.q)` inside a fixed relative URL path or query position.
- An import-qualified audited sanitizer call with a literal policy that excludes the relevant tag or attribute.
- Static markup with no interpolation.
- Comments, ordinary strings, escaped `${`, and type-only text containing fake markup.
- A helper merely named `escape`, an unknown sanitizer, a retained active container, or a generic HTML escape, which must not suppress.
- Nested braces, escaped backticks, nested templates, malformed templates, expression byte overflow, template count overflow, interpolation count overflow, and depth overflow.

Each negative expectation is a literal empty list of nested-output rows; do not derive it through scanner helpers.

- [ ] **Step 8: Implement the narrow transform and policy suppressions**

Recognize URL-component suppression only when the full interpolation expression is wrapped by `encodeURIComponent` and static text fixes a relative path or query boundary before it. Start script, style, and event-handler contexts with no name-based encoder suppression.

Recognize a sanitizer policy only through the initial exact map entry `sanitize-html` default import with literal `allowedTags` and `allowedAttributes` options at the same call site. A script or style hint is suppressed only when its tag is absent from literal `allowedTags`. A URL or event-handler attribute hint is suppressed only when the exact static tag's literal attribute policy excludes that exact attribute. A helper name, nearby object, wildcard, default policy, omitted option, or unknown option never suppresses.

- [ ] **Step 9: Run all nested-output and semantic tests and confirm GREEN**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_semantic_guidance -v
```

Expected: all context, provenance, suppression, decoy, limit, and existing route tests pass.

- [ ] **Step 10: Self-review and commit Task 2**

Check that schema 1 and 2 never import or call the new scanner path, that observations contain no raw snippets, and that all limits are enforced before an observation is emitted.

```powershell
rtk git commit -m "feat: detect nested output contexts"
```

---

### Task 3: Fair Strong-Edge and Family/Component Row Allocation

**Files:**
- Modify: `benchmarks/hermesbench/semantic_guidance.py:220-280,706-865,1000-1065`
- Modify: `benchmarks/hermesbench/tests/test_semantic_guidance.py`

**Interfaces:**
- Produces: `_allocate_schema_three_references(declarations, limit) -> tuple[_Declaration, ...]`.
- Produces: `_allocate_schema_three_edges(resolved_by_declaration, limit) -> dict[identity, tuple[edge, ...]]` with strong tiers before name-only.
- Produces: `_schema_three_row_order(routes, components_by_path) -> tuple[_Route, ...]` using family then component rounds.
- Consumes: existing profile limits unchanged. Schema 1 and 2 continue through their exact current first-seen selection.

- [ ] **Step 0: Extend the test-only limits helper without changing its legacy default**

Use the real builder and keep schema 1 as the default for every existing limits regression.

```python
def _build_with_limits(
    self,
    name: str,
    files: dict[str, str | bytes],
    limits: GuidanceLimits,
    *,
    guidance_schema_version: int = 1,
    components: dict[str, str] | None = None,
) -> SemanticGuidance:
    with mock.patch.dict(PROFILE_LIMITS, {"test-limits": limits}):
        return self._build(
            name,
            files,
            "test-limits",
            guidance_schema_version=guidance_schema_version,
            components=components,
        )
```

- [ ] **Step 1: Write a RED late-strong-edge test**

Create an early declaration with several ambiguous name-only calls and a later explicit import-linked source-to-operation route. Patch `GuidanceLimits.edge_count` so only one resolved edge can survive. Assert the later import-linked route exists and no name-only route consumes the only edge.

```python
def test_schema_three_strong_edge_survives_earlier_name_only_fanout(self) -> None:
    result = self._build_with_limits(
        "fair-strong-edge",
        {
            "early.ts": "export function noise(value) { alpha(value); beta(value); gamma(value); }\n",
            "api.ts": "import { run } from './sink'; export function handle(request) { return run(request.query.q); }\n",
            "sink.ts": "export function run(value) { return child_process.exec(value); }\n",
        },
        GuidanceLimits(4096, 20, 1, 20, 20, 4096, 4),
        guidance_schema_version=3,
    )
    rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
    self.assertTrue(any(row["strength"] == "import-linked" for row in rows))
```

- [ ] **Step 2: Run the edge test and confirm RED**

Expected: the current first-seen truncation spends or discards the budget before the later strong route.

- [ ] **Step 3: Implement schema-3-only reference and resolved-edge rounds**

After source scanning, allocate one retained reference per declaration per round. During resolution, split every declaration's stable resolved sequence into strong (`direct` or `import-linked`) and weak (`name-only`) queues. Allocate one strong edge per declaration per round until exhausted or capped, then repeat for weak edges. Deduplicate exact target/strength pairs without changing canonical declaration order.

Do not alter the legacy `_scan_files` truncation or legacy `_build_routes` path. Direct same-declaration routes do not consume a resolved edge.

- [ ] **Step 4: Add and implement the optional exact import-linked caller companion**

Write a RED fixture where an imported render helper contains a local nested-output observation and one exact caller passes a parameter-derived value. Assert exactly one caller is present in the nested row trace. Add a second exact caller and assert canonical sorting still retains one. Add an ambiguous name-only caller and assert it is never attached.

Use the already allocated strong incoming edges. With a companion, the source-to-operation trace is exactly `(caller, containing_declaration)`; without one it is exactly `(containing_declaration,)`. The companion may extend an existing hint but may not create a hint without local nested-output criteria.

- [ ] **Step 5: Write RED family/component row-round tests**

Patch a two-row limit. Create several command routes in one component plus one output-context or file-family row in another component. Assert two different families appear before a repeated command row. In a same-family fixture, assert two different components appear before a repeated component.

```python
self.assertEqual(
    [(row["hint_kind"], row["operation_family"]) for row in rows],
    [("call-route", "command"), ("nested-output-context", "output-context")],
)
```

Use literal expected tuples derived from the fixture, not the allocator's sort key.

- [ ] **Step 6: Run row tests and confirm RED**

Expected: current global `_route_sort_key` ordering repeats the dominant family or component.

- [ ] **Step 7: Implement strong-tier nested family/component round-robin**

For schema 3, partition nested-output, direct, and import-linked routes into the strong tier and name-only routes into the weak tier. Within each tier, maintain queues by `(hint_kind, operation_family)`, then component subqueues. Select one row from each family before repeating a family and one component within a family before repeating that component. Use canonical keys and current route ordering only as tie-breakers.

Encode each candidate row once. If one row exceeds the remaining byte budget, skip it and continue to later queues. Never emit a partial row. Schema 1 and 2 retain the current sort-and-break behavior exactly.

- [ ] **Step 8: Add RED/GREEN byte-skip and determinism tests**

Use a patched output-byte budget where the first canonical schema-3 row cannot fit but a later shorter row can. Confirm RED under current `break`, implement `continue`, and confirm the later row is emitted. Build identical fixtures in two roots and assert exact canonical bytes and SHA-256 equality.

- [ ] **Step 9: Run Task 3 tests and the full semantic module**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_semantic_guidance -v
```

Expected: fair allocation tests pass; all schema-1/schema-2 exact and bound tests remain green.

- [ ] **Step 10: Self-review and commit Task 3**

Inspect both `_scan_files` and `_build_routes` for remaining schema-3 first-seen truncation. Confirm no profile number changed.

```powershell
rtk git commit -m "perf: allocate Hunt semantic guidance fairly"
```

---

### Task 4: Blind Protocol-v4 Hunt Verification Projection

**Files:**
- Modify: `benchmarks/hermesbench/hunt_evidence.py:31-37`
- Modify: `benchmarks/hermesbench/phase_runner.py:175-210,940-975`
- Modify: `benchmarks/hermesbench/adapters/codex_exec.py:195-230,454-525`
- Modify: `benchmarks/hermesbench/tests/test_codex_exec_adapter.py:301-350,627-670`
- Modify: `benchmarks/hermesbench/tests/test_phase_runner.py:695-805`
- Modify: `benchmarks/hermesbench/tests/test_cli.py:145-210`

**Interfaces:**
- Produces: `CanonicalCandidate.to_verification_projection() -> dict[str, object]` with exactly four top-level fields.
- Consumes: the adapter's recorded `hunt_evidence_protocol_version` and workflow. Only `workflow == "hunt"` and version 4 use the projection.
- Preserves: `CanonicalCandidate.to_json()`, `_candidate_row`, candidate-transfer bytes, attestation, terminal-decision validation, and public projection.

- [ ] **Step 1: Write a RED prompt-level blind projection test**

Construct one rich Hunt candidate with unique sentinels in every excluded field and invoke the real adapter prompt builder through `for_verification`.

```python
def test_protocol_four_hunt_verifier_receives_only_candidate_identity_and_locations(self) -> None:
    runtime = _Runtime(_stream(), final_message=_HUNT_VERIFICATION_RESPONSE)
    candidate = CanonicalCandidate(
        candidate_id="candidate-1",
        entry_point=Location("source.py", 1, 1),
        critical_operation=Location("source.py", 3, 3),
        trace=(Location("source.py", 2, 2),),
        confidence=0.81,
        vulnerability_family="family-sentinel",
        search_pass="guard",
        hypothesis="hypothesis-sentinel",
        evidence="evidence-sentinel",
        counterevidence="counterevidence-sentinel",
        expected_control="control-sentinel",
    )
    with tempfile.TemporaryDirectory() as directory:
        self._adapter(
            "hunt",
            "hunt-balanced",
            runtime,
            hunt_evidence_protocol_version=4,
        ).for_verification({"task-001": (candidate,)})(_request(), Path(directory), 60)
    prompt = runtime.calls[0]["command_argv"][-1]
    self.assertIn('"candidate_id":"candidate-1"', prompt)
    for sentinel in ("0.81", "family-sentinel", "guard", "hypothesis-sentinel", "evidence-sentinel", "counterevidence-sentinel", "control-sentinel"):
        self.assertNotIn(sentinel, prompt)
    self.assertIn("inspect the immutable source independently", prompt)
```

- [ ] **Step 2: Run the blind test and confirm RED**

Expected: current `candidate.to_json()` leaks the discovery confidence and prose into the verifier prompt.

- [ ] **Step 3: Implement the deterministic projection and v4 prompt branch**

Add this method without changing `to_json()`.

```python
def to_verification_projection(self) -> dict[str, object]:
    return {
        "candidate_id": self.candidate_id,
        "entry_point": _location_json(self.entry_point),
        "critical_operation": _location_json(self.critical_operation),
        "trace": [_location_json(location) for location in self.trace],
    }
```

In `_prompt`, serialize this projection only for v4 Hunt verification. Standard and Hunt v1-v3 continue to serialize `to_json()`. Add independent inspection language requiring the verifier to reconstruct attacker control, reachability, impact, guard failure, evidence, counterevidence, and proof gaps from source.

- [ ] **Step 4: Promote protocol 4 to the live default and pass exact legacy/default golden prompt tests**

Set `HUNT_EVIDENCE_PROTOCOL_VERSION = NESTED_OUTPUT_HUNT_EVIDENCE_PROTOCOL_VERSION` only after the blind projection is green. Freeze explicit Hunt verification hashes for versions 1, 2, and 3 at the current rich-prompt digest. Add a separate literal digest for v4. Keep Standard discovery and Standard verification hashes unchanged. Assert the default Hunt adapter and CLI propagation now equal explicit protocol 4.

- [ ] **Step 5: Prove rich candidate-transfer preservation**

Add a real `run_workflow` test with a rich discovery candidate. Read the private candidate-transfer JSONL and assert its candidate still contains confidence, family, pass, hypothesis, evidence, counterevidence, and expected control. Assert the verification executor receives the same canonical locations and terminal decision completeness remains mandatory.

- [ ] **Step 6: Run adapter and phase tests and confirm GREEN**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_codex_exec_adapter benchmarks.hermesbench.tests.test_phase_runner -v
```

Expected: blind v4 prompt, rich transfer, exact legacy prompts, exact locations, and terminal decisions all pass.

- [ ] **Step 7: Self-review and commit Task 4**

Search every verification prompt serialization and ensure no alternate v4 path uses `to_json()`. Search every candidate-transfer serialization and ensure none uses the blind projection.

```powershell
rtk git commit -m "feat: blind Hunt protocol v4 verification"
```

---

### Task 5: Documentation, Full No-Model Verification, and Offline Diagnostic Gate

**Files:**
- Modify: `benchmarks/hermesbench/README.md:118-225`
- Modify: `sdk/typescript/_bundled_plugin/skills/hunt-security-scan/references/hunt-contract.md`
- Modify: `checklist.md`
- Modify: `context-notes.md`
- Create untracked: `benchmarks/hermesbench/private/v4-build-gate.py`
- Create untracked: `benchmarks/hermesbench/private/v4-evaluate-gate.py`

**Interfaces:**
- Documents: protocol `1/2/3/4`, semantic schemas `none/1/2/3`, nested-output investigation semantics, fair unchanged caps, and blind v4 verification.
- Build gate consumes only `HERMESBENCH_V4_MANIFEST`, `HERMESBENCH_V4_SNAPSHOTS`, and `HERMESBENCH_V4_GATE_ROOT`.
- Evaluate gate consumes only `HERMESBENCH_V4_GATE_ROOT` and `HERMESBENCH_V4_ORACLES`; it does not receive the source snapshot.
- Produces only private canonical artifacts plus a path-free aggregate gate result. Neither script is tracked.

- [ ] **Step 1: Update human and bundled Hunt contracts after behavior is green**

Document that v4 schema-3 rows add `hint_kind`, `output_context`, and component, that nested-output guidance remains investigation-only, and that v4 Hunt verification receives only identity and locations. State that profiles retain their current numeric caps and model call count.

Do not name private tasks, snapshots, oracle paths, raw findings, retained run roots, or credentials.

- [ ] **Step 2: Run focused compatibility and static checks**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_semantic_guidance benchmarks.hermesbench.tests.test_hunt_evidence benchmarks.hermesbench.tests.test_codex_exec_adapter benchmarks.hermesbench.tests.test_phase_runner benchmarks.hermesbench.tests.test_cli -v
rtk python -m compileall -q benchmarks/hermesbench
rtk git diff --check
```

Expected: all focused tests pass with no compile or diff error.

- [ ] **Step 3: Run the complete Python and Bun suites**

Run:

```powershell
rtk python -m unittest discover -s benchmarks/hermesbench/tests -p "test_*.py"
```

In `sdk/typescript`, run:

```powershell
rtk bun test --timeout 90000 tests-ts/hermesbench.test.ts
```

Expected: no failure. Platform skips remain explicit and do not conceal a new Protocol-v4 failure.

- [ ] **Step 4: Create the ignored oracle-independent build gate with `apply_patch`**

The untracked build script must fail if `HERMESBENCH_V4_ORACLES` is present. It loads the immutable manifest, iterates every manifest snapshot, and calls:

```python
prepare_hunt_artifacts(
    snapshot_path,
    task_scratch,
    "hunt-balanced",
    evidence_protocol_version=4,
)
```

It writes a private index containing task ID, semantic artifact relative path, SHA-256, row count, edge count, scanned count, skipped count, and preparation fingerprint. It never imports `load_oracles`, `score_run`, or private ledger code.

- [ ] **Step 5: Run the build process with no oracle environment**

Set the three build variables to the retained immutable Canary inputs and a new private gate root, then run exactly:

```powershell
rtk python benchmarks/hermesbench/private/v4-build-gate.py
```

Expected: every task produces a deterministic schema-3 artifact and private index. Repeat only the no-model build into a second fresh gate root and require identical artifact hashes and aggregate counts.

- [ ] **Step 6: Create and run the separate private evaluator**

The evaluator imports `load_oracles`, reads only the completed artifact index and semantic JSONL, and requires at least one `nested-output-context` row whose source, operation, or trace overlaps a held-out vulnerable gold location within the scorer's fixed line tolerance. It also reports aggregate nested row count, vulnerable-task coverage count, and guarded/decoy synthetic status. It writes no paths or task IDs to its result.

Run in a fresh process with only gate root and oracle variables.

```powershell
rtk python benchmarks/hermesbench/private/v4-evaluate-gate.py
```

Expected: pass. If it fails, do not run the model; return to the smallest failing RED fixture or allocation test.

- [ ] **Step 7: Audit the public/private boundary and working tree**

Confirm both gate scripts and all generated artifacts are ignored, no private marker exists in tracked changes, no source snapshot changed, and no container is running. Use `rtk git status --short`, `rtk git check-ignore`, snapshot hashes, and the existing container cleanup check.

- [ ] **Step 8: Independent review and one batched fix cycle if required**

Provide the complete branch diff, plan, spec, and test evidence to a fresh reviewer. Apply all confirmed Critical or Important findings in one batch through the original implementer, rerun covering tests, and perform at most one scoped re-review unless a correctness or security issue remains unresolved.

- [ ] **Step 9: Commit Task 5 documentation and evidence notes**

Commit only tracked public-safe documentation, checklist, and context changes. Do not add the private gate scripts.

```powershell
rtk git commit -m "docs: document Hunt protocol v4 boundaries"
```

---

### Task 6: Single Same-Variable Paid Canary and Evidence Classification

**Files:**
- Modify after validated evidence only: `checklist.md`
- Modify after validated evidence only: `context-notes.md`
- Create private only: fresh immutable run output under the existing private benchmark root

**Interfaces:**
- Consumes: the retained Canary manifest, snapshots, oracles, authentication input, execution policy, and frozen controls from the latest completed comparable run.
- Produces: one protocol-v4 workflow receipt, discovery and verification phase receipts, canonical candidate transfer, private verifier decisions, public prediction projection, identity-free score artifact, and post-run audit evidence.
- Preserves: exact model, effort, profile, timeout, image digest, policy, manifest, snapshot hashes, grader, candidate caps, and two-call topology. Only Protocol v4 changes.

- [ ] **Step 1: Preflight frozen controls and the fresh output root**

Load the retained controls and assert equality for every frozen field. Verify `HUNT_EVIDENCE_PROTOCOL_VERSION == 4`, the new output root does not exist, the auth input is outside every snapshot/output mount, the snapshots match retained hashes, and no container is running.

- [ ] **Step 2: Run exactly one paid Hunt Canary**

Invoke the existing standalone command once with the retained private paths and a fresh run ID.

```powershell
rtk python -m benchmarks.hermesbench.cli run --manifest $env:HERMESBENCH_CANARY_MANIFEST --snapshots-root $env:HERMESBENCH_CANARY_SNAPSHOTS --output-root $env:HERMESBENCH_V4_OUTPUT --run-id $env:HERMESBENCH_V4_RUN_ID --workflow hunt --profile hunt-balanced --controls $env:HERMESBENCH_CANARY_CONTROLS --execution-policy $env:HERMESBENCH_CANARY_POLICY --auth $env:HERMESBENCH_AUTH --oracles $env:HERMESBENCH_CANARY_ORACLES
```

Do not execute this command a second time. If it is incomplete or fails, preserve the bounded receipt and classify it without retrying.

- [ ] **Step 3: Revalidate and audit independently**

Use `validate_workflow_receipt` against the immutable manifest, snapshots, controls, and policy. Recompute the identity-free score from private oracles and public predictions. Re-run snapshot hashes, regular-file/reparse checks, retained-artifact secret and host-path scans, public-artifact scans, and container cleanup checks.

- [ ] **Step 4: Compare accuracy and cost without overclaiming**

Record discovery and verification elapsed seconds separately. Record cached input, uncached input, and output tokens separately for each phase and aggregate. Record candidate count, verifier disposition counts, public finding count, endpoint/trace TP-FP-FN, specificity, and composite score.

Call it an accuracy gain only if target-localized true-positive discovery improves. Completion, confidence, specificity, or unrelated accepted findings are not a recall gain. Use `candidate`, `reproduced`, `verified`, and `reportable` evidence levels.

- [ ] **Step 5: Decide the next benchmark stage**

If v4 localizes and verifies the reviewed vulnerability with clean integrity evidence, evaluate whether Canary is sufficient to promote to Mini. If it remains inconclusive or reaches the final stage later, use the full HermesBench suite as already required. If v4 still misses, stop and return to architecture review; independent discovery lanes require separate approval and are not authorized by this run.

- [ ] **Step 6: Record public-safe evidence and commit**

Update only aggregate, path-free checklist and context facts. Keep task identities, paths, raw predictions, raw findings, oracle labels, private roots, and credentials out of Git.

```powershell
rtk git commit -m "docs: record protocol v4 Canary evidence"
```

- [ ] **Step 7: Final verification before completion claim**

Run the complete Python suite, Bun bridge, `compileall`, `git diff --check`, tracked sensitive-marker scan, worktree status, upstream divergence check, and final whole-branch review. Do not push unless the user explicitly requests a push for this new work.
