# Frontier Pass Annotations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic frontier-derived pass eligibility to new Hunt semantic guidance so discovery can select an attestable `search_pass` without weakening fail-closed host validation.

**Architecture:** Hunt evidence protocol version 3 supplies semantic-guidance schema version 2, whose rows add one canonical `eligible_search_passes` array derived only from the route's source, trace, and operation frontier rows. Protocols 1 and 2 retain exact legacy artifact and prompt reconstruction, while the protocol-v3 discovery prompt tells the model to copy a supported pass or perform an exact-path frontier lookup. Candidate parsing, location linkage, pass attestation, verification, scoring, sandboxing, and the two-call workflow remain authoritative and unchanged.

**Tech Stack:** Python 3 standard library, `unittest`, existing HermesBench host contracts, bundled Python frontier helper, Bun TypeScript compatibility test, existing Docker no-model boundary smoke, Git.

**Spec:** `docs/superpowers/specs/2026-08-28-frontier-pass-annotations-design.md`

## Global Constraints

- Perform defensive local-source discovery only. Do not generate exploits, proof-of-concept payloads, crash inputs, remote traffic, or credential access.
- New live Hunt runs use evidence protocol version 3. Protocol versions 1 and 2 must reproduce their current artifact, prompt, evidence, and receipt bytes by recorded version.
- Evidence protocol 1 has no semantic artifact. Protocol 2 uses semantic row schema 1. Protocol 3 uses semantic row schema 2.
- Canonical pass order is exactly `forward`, `backward`, `guard`, `parser`, `state`, `general`.
- `eligible_search_passes` is the exact non-empty union from source, trace, and operation frontier paths. Never infer a pass, use neighboring rows, include controls merely because they are nearby, or add `general` as a fallback.
- The host never rewrites or repairs a model-selected `search_pass`. A mismatch continues to fail with `hunt_evidence_candidate_search_pass`.
- Keep exactly two independent model invocations, at most 12 discovery candidates, at most five public findings, and a 480-second per-phase timeout.
- Keep complete frontier eligibility, coverage debt, candidate location linkage, verifier decisions, scoring, response schemas, pinned image controls, command policy, authentication isolation, and network isolation unchanged.
- Add no public CLI flag, model setting, candidate field, receipt field, scorer field, dependency, parser, SAST service, or network service.
- Persist only path-free hashes and aggregate counts. Do not publish private snapshot paths, task identities, hidden labels, raw predictions, findings, authentication values, or host paths.
- Write all new or modified code comments and docstrings in English.
- Use `apply_patch` for source edits, prefix every executed command with `rtk`, run tests before each completion claim, and make one semantic commit per completed task.

## File Structure

- Modify `benchmarks/hermesbench/hunt_protocol.py` to expose the canonical ordered pass vocabulary while preserving the existing membership set.
- Modify `benchmarks/hermesbench/semantic_guidance.py` to accept ordered path/pass rows, preserve schema-1 bytes, and emit schema-2 eligibility annotations.
- Modify `benchmarks/hermesbench/hunt_evidence.py` to support evidence protocols 1, 2, and 3 with explicit semantic-version helpers.
- Modify `benchmarks/hermesbench/adapters/codex_exec.py` to preserve exact v1/v2 prompt bytes and add only the v3 pass-selection instructions.
- Modify `benchmarks/hermesbench/tests/test_hunt_candidate_protocol.py` for the shared pass-order contract.
- Modify `benchmarks/hermesbench/tests/test_semantic_guidance.py` for schema versioning, eligibility derivation, canonical bytes, and fail-closed input tests.
- Modify `benchmarks/hermesbench/tests/test_hunt_evidence.py` for exact v1/v2 reconstruction, v3 preparation, v3 attestation, and strict parsing.
- Modify `benchmarks/hermesbench/tests/test_codex_exec_adapter.py` for exact prompt hashes and v2/v3 read behavior.
- Modify `benchmarks/hermesbench/tests/test_phase_runner.py`, `test_runner.py`, and `test_cli.py` only for supported-version and end-to-end propagation assertions. Do not edit their production modules unless a focused RED test exposes a direct hard-coded assumption.
- Modify `benchmarks/hermesbench/README.md` and `sdk/typescript/_bundled_plugin/skills/hunt-security-scan/references/hunt-contract.md` after behavior is verified.
- Update `checklist.md` and `context-notes.md` only with evidence actually produced.

---

### Task 1: Canonical Pass Vocabulary and Semantic Row Schema 2

**Files:**
- Modify: `benchmarks/hermesbench/hunt_protocol.py:14-16`
- Modify: `benchmarks/hermesbench/semantic_guidance.py:14,153-168,939-1017`
- Modify: `benchmarks/hermesbench/tests/test_hunt_candidate_protocol.py:1-85`
- Modify: `benchmarks/hermesbench/tests/test_semantic_guidance.py:1-95,540-730`
- Read-only contract: `sdk/typescript/_bundled_plugin/scripts/hunt_workflow.py:48,528-532`

**Interfaces:**
- Consumes: immutable `snapshot_path: Path`, frontier-priority-ordered `frontier_passes: tuple[tuple[str, tuple[str, ...]], ...]`, `profile: str`, and explicit `guidance_schema_version: int`.
- Produces: `HUNT_SEARCH_PASS_ORDER: tuple[str, ...]` and the existing `HUNT_SEARCH_PASSES: frozenset[str]` derived from it.
- Produces: `build_semantic_guidance(snapshot_path: Path, frontier_passes: tuple[tuple[str, tuple[str, ...]], ...], profile: str, *, guidance_schema_version: int) -> SemanticGuidance`.
- Produces: exact schema-1 bytes for protocol 2 and schema-2 rows with `eligible_search_passes` for protocol 3.

- [ ] **Step 1: Add RED tests for the shared pass vocabulary**

Add these imports and assertions to `test_hunt_candidate_protocol.py`.

```python
from benchmarks.hermesbench.hunt_protocol import (
    HUNT_SEARCH_PASS_ORDER,
    HUNT_SEARCH_PASSES,
)
from sdk.typescript._bundled_plugin.scripts.hunt_workflow import FRONTIER_PASSES


def test_host_and_frontier_generator_share_exact_pass_order(self) -> None:
    self.assertEqual(HUNT_SEARCH_PASS_ORDER, FRONTIER_PASSES)
    self.assertEqual(HUNT_SEARCH_PASSES, frozenset(HUNT_SEARCH_PASS_ORDER))
    self.assertEqual(
        HUNT_SEARCH_PASS_ORDER,
        ("forward", "backward", "guard", "parser", "state", "general"),
    )
```

- [ ] **Step 2: Add RED schema-1 compatibility and schema-2 eligibility tests**

Change the semantic test helper to provide a valid frontier tuple and explicit schema version. Keep schema 1 as the helper default so every existing extraction, containment, bound, and exact-byte regression remains a legacy compatibility test.

```python
def _frontier_passes(
    files: dict[str, str | bytes],
    overrides: dict[str, tuple[str, ...]] | None = None,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    selected = overrides or {}
    return tuple((path, selected.get(path, ("forward",))) for path in files)


def _build(
    self,
    name: str,
    files: dict[str, str | bytes],
    profile: str = "hunt-balanced",
    *,
    guidance_schema_version: int = 1,
    passes: dict[str, tuple[str, ...]] | None = None,
) -> SemanticGuidance:
    snapshot = self._root / name
    snapshot.mkdir()
    for relative, value in files.items():
        path = snapshot / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode("utf-8"))
    return build_semantic_guidance(
        snapshot,
        _frontier_passes(files, passes),
        profile,
        guidance_schema_version=guidance_schema_version,
    )
```

Retain the current exact schema-1 golden bytes beginning with `{"controls":[],"hint_id":"f51a8b5b354cdafd"` and add these concrete schema-2 cases.

```python
def test_schema_two_adds_canonical_route_pass_union_without_changing_hint_id(self) -> None:
    source = semantic_guidance._Location("entry.py", 2, "handle")
    operation = semantic_guidance._Location("sink.py", 3, "subprocess.run")
    control = semantic_guidance._Location("control.py", 1, "validate")
    route = semantic_guidance._Route(
        "import-linked",
        "command",
        source,
        operation,
        (source, operation),
        (control,),
        ("source_anchor", "operation_anchor"),
    )
    passes = {
        "entry.py": ("state", "forward"),
        "sink.py": ("guard", "backward"),
        "control.py": ("parser",),
    }
    legacy = semantic_guidance._canonical_row(route, 1, passes)
    annotated = semantic_guidance._canonical_row(route, 2, passes)
    self.assertEqual(annotated["eligible_search_passes"], ["forward", "backward", "guard", "state"])
    self.assertNotIn("parser", annotated["eligible_search_passes"])
    self.assertEqual(legacy["hint_id"], annotated["hint_id"])
    self.assertNotIn("eligible_search_passes", legacy)


def test_schema_two_includes_general_only_from_an_exact_route_location(self) -> None:
    files = {
        "app.py": "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
    }
    without_general = self._build(
        "without-general",
        files,
        guidance_schema_version=2,
        passes={"app.py": ("forward",)},
    )
    with_general = self._build(
        "with-general",
        files,
        guidance_schema_version=2,
        passes={"app.py": ("general", "forward")},
    )
    self.assertEqual(json.loads(without_general.canonical_bytes)["eligible_search_passes"], ["forward"])
    self.assertEqual(json.loads(with_general.canonical_bytes)["eligible_search_passes"], ["forward", "general"])
```

- [ ] **Step 3: Add RED fail-closed frontier-pass input tests**

Add table-driven tests for an empty pass tuple, duplicate pass, unknown pass, missing route path, unsupported schema, and boolean schema value. Exact equivalent paths with identical canonical pass sets may retain the existing deduplication behavior; conflicting pass sets for the same canonical path must fail.

```python
def test_frontier_pass_inputs_fail_closed_before_source_scanning(self) -> None:
    snapshot = self._root / "invalid-passes"
    snapshot.mkdir()
    (snapshot / "app.py").write_text("value = 1\n", encoding="utf-8")
    invalid = (
        (("app.py", ()),),
        (("app.py", ("forward", "forward")),),
        (("app.py", ("invented",)),),
    )
    for frontier_passes in invalid:
        with self.subTest(frontier_passes=frontier_passes):
            with self.assertRaises(semantic_guidance.SemanticGuidanceError):
                build_semantic_guidance(
                    snapshot,
                    frontier_passes,
                    "hunt-balanced",
                    guidance_schema_version=2,
                )


def test_schema_two_rejects_a_route_path_missing_from_frontier_passes(self) -> None:
    source = semantic_guidance._Location("entry.py", 1, "handle")
    operation = semantic_guidance._Location("sink.py", 1, "run")
    route = semantic_guidance._Route(
        "import-linked", "command", source, operation, (source, operation), (), ("source_anchor",)
    )
    with self.assertRaises(semantic_guidance.SemanticGuidanceError):
        semantic_guidance._canonical_row(route, 2, {"entry.py": ("forward",)})
```

- [ ] **Step 4: Run Task 1 tests and confirm RED**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_hunt_candidate_protocol benchmarks.hermesbench.tests.test_semantic_guidance -v
```

Expected: missing `HUNT_SEARCH_PASS_ORDER`, the old builder signature rejecting `guidance_schema_version`, and `_canonical_row` rejecting the new arguments. Existing tests must not be weakened to obtain RED.

- [ ] **Step 5: Implement the canonical vocabulary and validated builder input**

Replace the unordered literal in `hunt_protocol.py` with one ordered source of truth.

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

In `semantic_guidance.py`, import the tuple and define explicit row-schema constants.

```python
from benchmarks.hermesbench.hunt_protocol import HUNT_SEARCH_PASS_ORDER

LEGACY_SEMANTIC_GUIDANCE_SCHEMA_VERSION = 1
SEMANTIC_GUIDANCE_SCHEMA_VERSION = 2
SUPPORTED_SEMANTIC_GUIDANCE_SCHEMA_VERSIONS = frozenset({1, 2})
```

Add `_normalize_frontier_passes`. It must canonicalize relative paths with the existing `_canonical_relative_path`, preserve first-seen frontier order, allow repeated equivalent paths only when their canonical pass sets agree, reject an empty or malformed tuple, reject duplicates and unknown values, and reorder each set by `HUNT_SEARCH_PASS_ORDER`.

```python
def _normalize_frontier_passes(
    frontier_passes: tuple[tuple[str, tuple[str, ...]], ...],
) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    paths: list[str] = []
    by_path: dict[str, tuple[str, ...]] = {}
    for item in frontier_passes:
        if not isinstance(item, tuple) or len(item) != 2:
            raise SemanticGuidanceError("semantic guidance frontier passes are invalid")
        raw_path, raw_passes = item
        if not isinstance(raw_path, str) or not isinstance(raw_passes, tuple) or not raw_passes:
            raise SemanticGuidanceError("semantic guidance frontier passes are invalid")
        if any(
            not isinstance(value, str) or value not in HUNT_SEARCH_PASS_ORDER
            for value in raw_passes
        ) or len(raw_passes) != len(set(raw_passes)):
            raise SemanticGuidanceError("semantic guidance frontier passes are invalid")
        path = _canonical_relative_path(raw_path)
        ordered = tuple(value for value in HUNT_SEARCH_PASS_ORDER if value in raw_passes)
        if path in by_path:
            if by_path[path] != ordered:
                raise SemanticGuidanceError("semantic guidance frontier passes conflict")
            continue
        paths.append(path)
        by_path[path] = ordered
    return tuple(paths), by_path
```

Update `build_semantic_guidance` to reject boolean or unsupported schema values, normalize the frontier input before `_safe_snapshot`, scan only the normalized ordered paths, and pass the mapping plus schema version into canonical serialization.

- [ ] **Step 6: Implement schema-aware canonical rows**

Thread `guidance_schema_version` and `frontier_passes_by_path` through `_canonical_guidance` and `_canonical_row`. Keep the current hint identity expression unchanged.

```python
def _eligible_search_passes(
    route: _Route,
    frontier_passes_by_path: dict[str, tuple[str, ...]],
) -> list[str]:
    route_paths = {route.source.path, route.operation.path}
    route_paths.update(location.path for location in route.trace)
    try:
        selected = {
            value
            for path in route_paths
            for value in frontier_passes_by_path[path]
        }
    except KeyError as error:
        raise SemanticGuidanceError("semantic guidance route is absent from frontier passes") from error
    ordered = [value for value in HUNT_SEARCH_PASS_ORDER if value in selected]
    if not ordered:
        raise SemanticGuidanceError("semantic guidance route has no eligible search pass")
    return ordered


def _canonical_row(
    route: _Route,
    guidance_schema_version: int,
    frontier_passes_by_path: dict[str, tuple[str, ...]],
) -> dict[str, object]:
    identity = "\x1f".join(
        [route.strength, route.operation_family]
        + [
            f"{item.path}:{item.line}:{item.symbol}"
            for item in (route.source, route.operation, *route.trace)
        ]
    )
    row = {
        "schema_version": guidance_schema_version,
        "hint_id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
        "strength": route.strength,
        "operation_family": route.operation_family,
        "source": route.source.as_dict(),
        "operation": route.operation.as_dict(),
        "trace": [item.as_dict() for item in route.trace],
        "controls": [item.as_dict() for item in route.controls],
        "reason_codes": list(route.reason_codes),
        "proof_status": "investigation_only",
    }
    if guidance_schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION:
        row["eligible_search_passes"] = _eligible_search_passes(route, frontier_passes_by_path)
    return row
```

Do not change the shown identity inputs or digest truncation. `_validate_row` must compute the exact field set by schema, keep every current schema-1 validation, and for schema 2 require a non-empty unique list equal to its own canonical projection through `HUNT_SEARCH_PASS_ORDER`.

- [ ] **Step 7: Update every direct builder call without weakening containment tests**

Replace path-only calls in the replacement, link, duplicate, equivalent-path, and limit tests with paired frontier inputs plus `guidance_schema_version=1`. Preserve every current expected scan count, skip count, exact byte string, link-permission skip, source identity check, and route bound.

- [ ] **Step 8: Run GREEN verification and commit Task 1**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_hunt_candidate_protocol benchmarks.hermesbench.tests.test_semantic_guidance -v
rtk python -m compileall -q benchmarks\hermesbench\hunt_protocol.py benchmarks\hermesbench\semantic_guidance.py benchmarks\hermesbench\tests\test_hunt_candidate_protocol.py benchmarks\hermesbench\tests\test_semantic_guidance.py
rtk git diff --check
rtk git add -- benchmarks/hermesbench/hunt_protocol.py benchmarks/hermesbench/semantic_guidance.py benchmarks/hermesbench/tests/test_hunt_candidate_protocol.py benchmarks/hermesbench/tests/test_semantic_guidance.py
rtk git commit -m "feat: annotate semantic guidance with frontier passes"
```

Expected: every existing schema-1 extraction and safety regression passes, the exact schema-1 golden remains byte-identical, and all schema-2 eligibility tests pass.

---

### Task 2: Hunt Evidence Protocol Version 3

**Files:**
- Modify: `benchmarks/hermesbench/hunt_evidence.py:17-57,143-219,222-375,563-577`
- Modify: `benchmarks/hermesbench/tests/test_hunt_evidence.py:1-214,330-580`
- Modify: `benchmarks/hermesbench/tests/test_phase_runner.py:253-390`
- Modify: `benchmarks/hermesbench/tests/test_runner.py:90-195`
- Modify: `benchmarks/hermesbench/tests/test_cli.py:152-210`
- Test compatibility: `benchmarks/hermesbench/tests/test_codex_exec_adapter.py`

**Interfaces:**
- Consumes: Task 1's explicit semantic schema constants, canonical pass tuple, and new builder signature.
- Produces: `HUNT_EVIDENCE_PROTOCOL_VERSION = 3` and `SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS = frozenset({1, 2, 3})`.
- Produces: protocol-aware helpers that identify semantic protocols `{2, 3}` and map evidence protocol 2 to guidance schema 1 and evidence protocol 3 to guidance schema 2.
- Preserves: the exact v1 five-artifact contract, exact v2 six-artifact contract, existing path-free semantic evidence fields, read cardinality, read order, and candidate attestation meaning.

- [ ] **Step 1: Add RED exact-version preparation tests**

Add a one-file synthetic snapshot helper with this exact source.

```python
def _semantic_snapshot(self, root: Path) -> Path:
    snapshot = root / "semantic-snapshot"
    snapshot.mkdir()
    (snapshot / "app.py").write_text(
        "import subprocess\ndef handle(request):\n    return subprocess.run(request.args.get(\"q\"))\n",
        encoding="utf-8",
    )
    return snapshot
```

Freeze the currently measured protocol-v2 values so the version bump cannot silently rewrite v2.

```python
def test_protocol_two_semantic_bytes_and_preparation_fingerprint_remain_exact(self) -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        prepared = prepare_hunt_artifacts(
            self._semantic_snapshot(root),
            root / "scratch",
            "hunt-balanced",
            evidence_protocol_version=2,
        )
    self.assertEqual(prepared.preparation_fingerprint, "c6d4283ef55b841fd423400a6fa229e18637e5afc7b0506fb333b0905b75fe7f")
    self.assertEqual(prepared.semantic_guidance.sha256, "c7521cf55318dc1cc393c12e39c643fbabdd003d02329160f92861c257549a37")
    self.assertEqual(prepared.semantic_guidance_row_count, 1)
    self.assertEqual(prepared.semantic_guidance.byte_count, 394)
```

Add a v3 repetition test that parses its only row and requires schema 2 plus `eligible_search_passes == ["forward"]`. Assert repeated v3 semantic hashes and preparation fingerprints are identical and differ from v2.

- [ ] **Step 2: Add RED v1/v2/v3 evidence parser and attestation tests**

Change `_evidence_payload` so versions 2 and 3 receive the existing five semantic hash/count fields. Add literal parser cases for `(1, 2, 3)`, change unsupported versions to `(0, 4)`, and assert an explicit expected version must match the row's `schema_version`.

Generalize the semantic prepared helper.

```python
def _prepared_prediction_semantic(self, root: Path, version: int):
    snapshot = self._snapshot(root)
    prepared = prepare_hunt_artifacts(
        snapshot,
        root / "scratch",
        "hunt-balanced",
        evidence_protocol_version=version,
    )
    return prepared, self._prediction()
```

For both versions 2 and 3, assert exactly one semantic read after the priority read succeeds; missing, duplicate, or reversed reads retain their current fixed categories. Use protocol 3 for one valid `forward` candidate and one invalid `state` candidate, proving the invalid case still returns `hunt_evidence_candidate_search_pass` and no host correction occurs.

- [ ] **Step 3: Add RED workflow and runner propagation tests**

In `test_phase_runner.py`, change every supported-version loop from `(1, 2)` to `(1, 2, 3)` and every unsupported set from `(0, 3)` to `(0, 4)`. Reconstruct complete and incomplete synthetic workflows under all three recorded versions.

In `test_runner.py`, make `hunt_evidence(version: int = 1)` add semantic fields for versions 2 and 3, then require strict parsing of matching v3 evidence and rejection of v1/v2/v3 mismatches. In `test_cli.py`, assert the imported current constant is literally 3 in addition to verifying that both live Hunt command paths pass it explicitly.

- [ ] **Step 4: Run Task 2 tests and confirm RED**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_hunt_evidence benchmarks.hermesbench.tests.test_phase_runner benchmarks.hermesbench.tests.test_runner benchmarks.hermesbench.tests.test_cli -v
```

Expected: protocol 3 is unsupported, v3 semantic preparation is absent, and old unsupported-version assertions disagree. The new v2 exact-byte test should already pass before implementation.

- [ ] **Step 5: Implement explicit evidence-version helpers**

Import the two semantic schema constants and the pass membership set. Replace current-version equality checks with explicit helpers.

```python
LEGACY_HUNT_EVIDENCE_PROTOCOL_VERSION = 1
SEMANTIC_GUIDANCE_HUNT_EVIDENCE_PROTOCOL_VERSION = 2
HUNT_EVIDENCE_PROTOCOL_VERSION = 3
SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS = frozenset({1, 2, 3})
_SEMANTIC_HUNT_EVIDENCE_PROTOCOL_VERSIONS = frozenset({2, 3})

HUNT_EVIDENCE_FIELDS_V3 = HUNT_EVIDENCE_FIELDS_V2
HUNT_EVIDENCE_FIELDS = HUNT_EVIDENCE_FIELDS_V3


def _uses_semantic_guidance(version: int) -> bool:
    return version in _SEMANTIC_HUNT_EVIDENCE_PROTOCOL_VERSIONS


def _semantic_guidance_schema_version(version: int) -> int:
    if version == SEMANTIC_GUIDANCE_HUNT_EVIDENCE_PROTOCOL_VERSION:
        return LEGACY_SEMANTIC_GUIDANCE_SCHEMA_VERSION
    if version == HUNT_EVIDENCE_PROTOCOL_VERSION:
        return SEMANTIC_GUIDANCE_SCHEMA_VERSION
    raise HuntEvidenceError("Hunt evidence protocol has no semantic guidance")
```

Use `_uses_semantic_guidance` in `HuntEvidence.to_json`, `parse_hunt_evidence`, `prepare_hunt_artifacts`, `attest_hunt_discovery`, and `reproduce_hunt_evidence`. Protocol 1 continues to select only `HUNT_EVIDENCE_FIELDS_V1`; both semantic versions select the exact same v2/v3 field set.

- [ ] **Step 6: Bind validated frontier passes into semantic preparation**

Strengthen `_validate_frontier_rows` only at the demonstrated pass boundary: require non-empty unique strings drawn from `HUNT_SEARCH_PASSES`. Do not require incoming order because schema-2 output canonicalizes it.

After validation, project the exact frontier order.

```python
frontier_passes = tuple(
    (
        str(row["path"]),
        tuple(str(value) for value in row["passes"]),
    )
    for row in frontier_rows
)
```

For versions 2 and 3, call the Task 1 builder as follows.

```python
guidance = build_semantic_guidance(
    snapshot,
    frontier_passes,
    profile,
    guidance_schema_version=_semantic_guidance_schema_version(evidence_protocol_version),
)
```

Keep artifact names, maximum bytes, preparation fingerprint shape, path-free counts, immutable-file verification, semantic read cardinality, and priority-before-semantic ordering unchanged.

- [ ] **Step 7: Run GREEN compatibility verification and commit Task 2**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_semantic_guidance benchmarks.hermesbench.tests.test_hunt_evidence benchmarks.hermesbench.tests.test_phase_runner benchmarks.hermesbench.tests.test_runner benchmarks.hermesbench.tests.test_cli benchmarks.hermesbench.tests.test_codex_exec_adapter -v
rtk python -m compileall -q benchmarks\hermesbench\hunt_evidence.py benchmarks\hermesbench\tests\test_hunt_evidence.py benchmarks\hermesbench\tests\test_phase_runner.py benchmarks\hermesbench\tests\test_runner.py benchmarks\hermesbench\tests\test_cli.py
rtk git diff --check
rtk git add -- benchmarks/hermesbench/hunt_evidence.py benchmarks/hermesbench/tests/test_hunt_evidence.py benchmarks/hermesbench/tests/test_phase_runner.py benchmarks/hermesbench/tests/test_runner.py benchmarks/hermesbench/tests/test_cli.py
rtk git commit -m "feat: add Hunt evidence protocol v3"
```

If a focused RED test proves a production hard-coded assumption in `phase_runner.py`, `runner.py`, or `cli.py`, make the minimum direct correction, rerun the same suite, and include only the proven file in this commit. Do not edit those modules merely because they import the shared current-version constant.

---

### Task 3: Protocol-v3 Discovery Prompt Contract

**Files:**
- Modify: `benchmarks/hermesbench/adapters/codex_exec.py:454-492`
- Modify: `benchmarks/hermesbench/tests/test_codex_exec_adapter.py:146-248`
- Compatibility test: `benchmarks/hermesbench/tests/test_hunt_evidence.py`
- Compatibility test: `benchmarks/hermesbench/tests/test_runner.py`

**Interfaces:**
- Consumes: Task 2's supported protocol set and default protocol 3.
- Produces: exact explicit discovery branches for protocols 1, 2, and 3.
- Preserves: protocol-v1 SHA-256 `4713cf562c5efa5bf504b909bac0bf8f18673aca5991fd00b5e89b211d5f2c47` and protocol-v2 SHA-256 `8563f2276a113797a5896f1b500198afe519bf5cb497a98a526abbdbcef01dca` for the existing synthetic request.
- Produces: protocol-v3 SHA-256 `98906c398f5e15319266983ce30d1b18cf4a45b100f4123956220a2eb447b006` for the exact suffix below.

- [ ] **Step 1: Add RED prompt hash and instruction tests**

Replace the current default-equals-v2 assertion with an exact three-version test. Build prompts through the adapter's existing synthetic request and hash the final command argument.

```python
def test_hunt_discovery_prompt_bytes_are_explicit_for_all_evidence_protocols(self) -> None:
    expected = {
        1: "4713cf562c5efa5bf504b909bac0bf8f18673aca5991fd00b5e89b211d5f2c47",
        2: "8563f2276a113797a5896f1b500198afe519bf5cb497a98a526abbdbcef01dca",
        3: "98906c398f5e15319266983ce30d1b18cf4a45b100f4123956220a2eb447b006",
    }
    for version, digest in expected.items():
        with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
            runtime = _Runtime(_hunt_stream())
            self._adapter(
                "hunt",
                "hunt-balanced",
                runtime,
                hunt_evidence_protocol_version=version,
            )(_request(), Path(directory), 60)
            prompt = runtime.calls[0]["command_argv"][-1]
            self.assertEqual(hashlib.sha256(prompt.encode("utf-8")).hexdigest(), digest)
```

Add an assertion that the default prompt equals explicit protocol 3, not protocol 2. For v3 require the literal strings `eligible_search_passes`, `frontier.jsonl`, `exact submitted path`, and `Never invent, generalize, substitute, or default a search pass`. Assert all four are absent from v2.

- [ ] **Step 2: Preserve unrelated prompt goldens and semantic-read behavior**

Keep the existing Standard discovery, Standard verification, and Hunt verification hashes unchanged. Run the exact semantic read-cardinality and reverse-order tests once under version 2 and once under version 3. Version 1 must still omit the semantic artifact and read.

- [ ] **Step 3: Run Task 3 tests and confirm RED**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_codex_exec_adapter -v
```

Expected: protocol 3 currently hashes exactly like protocol 2 and lacks every pass-selection instruction. The v1/v2 and unrelated prompt hashes must already pass.

- [ ] **Step 4: Implement the exact v3-only suffix**

Keep the current protocol-1 return text byte-for-byte. Assign the current protocol-2 return value to a local `semantic_prompt`, return it unchanged for version 2, and append exactly this text only for version 3.

```python
pass_instructions = (
    " For a semantic-guidance candidate, copy one `eligible_search_passes` value that is supported by at least one submitted entry point, critical operation, or trace location. "
    "Preserve the route source, operation, and relevant trace locations when they support the hypothesis. "
    "If submitted locations differ from the guidance row, or the candidate is outside semantic guidance or the priority packet, query /workspace/scratch/hermesbench-hunt/frontier.jsonl by exact submitted path with one allowed simple command and copy one listed pass that occurs on at least one submitted location. "
    "Never invent, generalize, substitute, or default a search pass."
)
return semantic_prompt + pass_instructions
```

Do not refactor the shared prompt prefix, verification branch, command allowlist, response schema, candidate parser, or attestation to make this change.

- [ ] **Step 5: Run GREEN verification and commit Task 3**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_codex_exec_adapter benchmarks.hermesbench.tests.test_hunt_evidence benchmarks.hermesbench.tests.test_runner -v
rtk python -m compileall -q benchmarks\hermesbench\adapters\codex_exec.py benchmarks\hermesbench\tests\test_codex_exec_adapter.py
rtk git diff --check
rtk git add -- benchmarks/hermesbench/adapters/codex_exec.py benchmarks/hermesbench/tests/test_codex_exec_adapter.py
rtk git commit -m "feat: guide Hunt pass selection"
```

Expected: all three Hunt discovery hashes match, every unrelated prompt hash stays exact, and invalid pass attestation still fails without correction.

---

### Task 4: Public Documentation, Full Verification, and No-Model Boundaries

**Files:**
- Modify: `benchmarks/hermesbench/README.md:173-211`
- Modify: `sdk/typescript/_bundled_plugin/skills/hunt-security-scan/references/hunt-contract.md:49-77`
- Modify: `checklist.md`
- Modify: `context-notes.md`
- Test: all files under `benchmarks/hermesbench/tests/`
- Test: `sdk/typescript/tests-ts/hermesbench.test.ts`

**Interfaces:**
- Consumes: the complete Task 1-3 implementation and their commit hashes.
- Produces: public v1/v2/v3 documentation, complete local verification evidence, deterministic fixed-snapshot preparation evidence, and a clean implementation range ready for the paid diagnostic.

- [ ] **Step 1: Update public protocol documentation**

Document these exact distinctions in both public documents.

- Version 1 has the five legacy artifacts and priority-only discovery prompt.
- Version 2 retains semantic row schema 1 and the existing semantic discovery prompt.
- Version 3 uses semantic row schema 2 and adds `eligible_search_passes` derived from exact source, trace, and operation frontier paths.
- Eligible passes guide selection but never prove a vulnerability or bypass candidate-to-frontier attestation.
- Exact-path frontier lookup is required when submitted locations differ or a candidate falls outside guidance.
- The host never defaults to `general` and never repairs the model response.
- All versions reconstruct by the receipt's recorded version; workflow receipt schema remains 3 and frozen controls schema remains 2.
- The two-call ceiling, 480-second timeout, resource bounds, full frontier, coverage debt, independent verifier, scorer, sandbox, and public-data boundaries remain unchanged.

- [ ] **Step 2: Run the complete public test and compile gates**

Run from the repository root.

```powershell
rtk python -m unittest discover -s benchmarks\hermesbench\tests -p "test_*.py" -v
rtk python -m compileall -q benchmarks\hermesbench
rtk git diff --check
```

Run the bundled compatibility test from `sdk/typescript`.

```powershell
rtk bun test --timeout 90000 tests-ts/hermesbench.test.ts
```

Expected: all tests pass with only explicitly reported platform or opt-in skips. Do not report the older 318-test count after adding new tests; report the fresh count from this run.

- [ ] **Step 3: Run deterministic public large-artifact and authentication tests**

Run the opt-in synthetic large preparation twice through its existing test.

```powershell
rtk powershell -NoProfile -Command '$env:HERMESBENCH_LARGE_ARTIFACT_SMOKE="1"; python -m unittest benchmarks.hermesbench.tests.test_hunt_evidence.HuntEvidenceLargeSmokeTests -v'
rtk python -m unittest benchmarks.hermesbench.tests.test_codex_auth_runtime -v
```

Run the existing named-permission no-model test only against the already reviewed local runtime image and only if the expected immutable image/tag preflight succeeds.

```powershell
rtk powershell -NoProfile -Command '$env:HERMESBENCH_RUN_DOCKER_SMOKE="1"; python -m unittest benchmarks.hermesbench.tests.test_container_runtime.DockerIsolationSmokeTests.test_named_permission_profile_denies_auth_source_writes_and_network -v'
```

Do not run a model, make a remote request, rebuild an unrelated image, or expose authentication input while performing these checks.

- [ ] **Step 4: Reproduce retained protocols and fixed-snapshot preparation without a model**

The main agent performs the existing locally retained receipt and fixed-snapshot procedure. Keep private roots and identities out of the public plan and documentation. Record only these path-free results.

- The retained completed protocol-1 receipt revalidates with its original two invocations and separated usage.
- The retained incomplete protocol-2 receipt revalidates with its empty completed discovery subset and one invocation.
- Protocol-2 preparation runs twice with exact matching non-time fields and the previously recorded semantic hash and counts.
- Protocol-3 preparation runs twice with exact matching non-time fields, schema-2 rows, canonical eligible-pass order, and the same inventory, frontier, pass, priority, edge, scan, and skip bounds as protocol 2.
- All three response schemas in the pinned image match host SHA-256 bytes at mode `0444`.
- All eight Canary snapshots have zero audit violations, hash mismatches, and reparse entries.
- Retained outputs contain zero bounded authentication values, host paths, forbidden raw model output, or private benchmark identity.
- No named or pinned HermesBench container remains.

If v2 hashes change, stop before any paid run and repair compatibility. If v3 produces a missing, empty, duplicate, unknown, or non-canonical pass annotation, stop before runtime and repair the host builder.

- [ ] **Step 5: Self-review the implementation range against the spec**

Review every changed line from the Task 1 base through Task 3 HEAD. Confirm exact schema fields, version helper use at every former current-version equality, all callers of `build_semantic_guidance`, prompt hashes, pass derivation paths, artifact bounds, public output fields, and unchanged candidate attestation.

Because a read-only Sol advisor already resolved the security/public-contract design choice, do not add a routine second advisor. Use one read-only Terra high reviewer only if the self-review finds an unresolved Critical issue, a focused test exposes a cross-boundary ambiguity, or two materially different fixes fail.

- [ ] **Step 6: Commit verified public documentation and tracking**

Update `checklist.md` and `context-notes.md` with fresh test counts, skips, deterministic preparation results, retained receipt status, security checks, commit range, and any bounded residual. Do not record private paths, raw predictions, hidden labels, or task identities.

Run and commit.

```powershell
rtk git diff --check
rtk git add -- benchmarks/hermesbench/README.md sdk/typescript/_bundled_plugin/skills/hunt-security-scan/references/hunt-contract.md checklist.md context-notes.md
rtk git commit -m "docs: document Hunt evidence protocol v3"
rtk git status --short
```

Expected: the worktree is clean and the complete public implementation is ready for one fixed paid diagnostic.

---

### Task 5: Fixed Protocol-v3 Diagnostic and Escalation Decision

**Files:**
- Private ignored output: one new immutable single-task diagnostic root owned by the main agent
- Modify after verification: `checklist.md`
- Modify after verification: `context-notes.md`
- Preserve: `.superpowers/sdd/2026-08-28-semantic-guidance/progress.md` until the final benchmark phase is closed

**Interfaces:**
- Consumes: the reviewed Task 1-4 implementation, the same fixed diagnostic snapshot and manifest, model, high effort, `hunt-balanced` profile, 480-second task timeout, pinned image, execution policy, candidate protocol, scorer, and two-call workflow used for the protocol-v2 diagnostic.
- Produces: one independently revalidated protocol-v3 workflow result with separated cost, timing, candidate, decision, score, failure, and integrity evidence.

- [ ] **Step 1: Freeze and compare the run configuration before execution**

Create a new exact empty non-reparse output directory. Compare the new request against the retained protocol-v2 diagnostic and require equality for manifest hash, snapshot-set hash, task-order hash, model, reasoning effort, profile, timeout, image digest, frozen-controls hash, execution-policy hash, candidate protocol, scorer, and two-call ceiling. The only allowed differences are a new run identifier, a new output root, evidence protocol 3, schema-2 pass annotations, and the v3 discovery instructions.

Stop before invocation if any other field differs.

- [ ] **Step 2: Run exactly one paid protocol-v3 diagnostic**

The main agent runs the existing local command with the frozen configuration and a single top-level discovery attempt. Do not retry automatically. Do not inspect raw private prediction text or hidden oracle labels.

During the run, report only fresh verified stage, elapsed time, invocation count, and whether discovery, attestation, verification, and scoring have completed. Do not call a partial candidate a vulnerability.

- [ ] **Step 3: Parse only the approved path-free result fields**

Record workflow and phase status, elapsed time, top-level invocation count, cached input, uncached input, output tokens, semantic row/edge/scan/skip/byte counts, candidate count, pass distribution, terminal disposition counts, public finding count, public score components, and fixed failure code.

If failure publication occurs, confirm candidate transfer, predictions, commands, and evidence are empty. Treat a pre-publication failure as measurement-blocking, not a zero score.

- [ ] **Step 4: Independently revalidate and repeat integrity checks**

Revalidate the workflow receipt by its recorded protocol version. Audit all eight snapshots, compare exact manifest hashes, scan retained outputs for bounded authentication values and host paths, reject reparse entries, verify no raw prediction or hidden label was published, and confirm no residual named or pinned container remains.

- [ ] **Step 5: Apply the benchmark escalation gate**

- If discovery fails before valid publication, do not assign a score and do not run Mini. Diagnose the fixed boundary code before another material change.
- If the workflow completes but advisory recall, pair-localization F1, and trace-node F1 remain zero, record the bounded negative and change only one evidence-backed variable before another paid run.
- If at least one discovery-quality metric becomes positive without a fixed-snapshot false positive, run `hunt-balanced` and `hunt-max` on all eight Canary tasks while holding every other variable fixed.
- Run HermesBench Mini only after Canary identifies a measurable positive profile.
- Run full HermesBench when Mini is inconclusive and before the final performance claim.

- [ ] **Step 6: Record evidence and make the diagnostic documentation commit**

Update only public-safe aggregate facts in `checklist.md` and `context-notes.md`. Run:

```powershell
rtk git diff --check
rtk git add -- checklist.md context-notes.md
rtk git commit -m "docs: record protocol v3 diagnostic evidence"
rtk git status --short
```

If the diagnostic creates no verified public-safe update, do not create an empty commit. Do not push the branch unless the user explicitly asks.

---

## Final Acceptance Checklist

- [ ] Protocol-v3 guidance rows contain exactly one new non-empty canonical `eligible_search_passes` field.
- [ ] Every eligible value comes only from the exact source, trace, or operation frontier rows.
- [ ] Empty, duplicate, unknown, conflicting, or missing pass evidence fails before model runtime.
- [ ] `general` appears only when an exact route-location frontier row contains it.
- [ ] Protocol-v1 and protocol-v2 artifact, prompt, evidence, and receipt reconstruction remain exact.
- [ ] Protocol-v3 is explicit through CLI, workflow, runner, adapter, preparation, parsing, attestation, and receipt validation.
- [ ] Invalid model passes still fail with `hunt_evidence_candidate_search_pass`; no host correction exists.
- [ ] Standard prompts, Hunt verification prompt, response schemas, scoring, frontier, coverage debt, verifier, timeout, sandbox, and two-call ceiling remain unchanged.
- [ ] Focused tests, complete Python tests, Bun compatibility, compileall, diff checks, retained receipt reconstruction, fixed-snapshot repetition, auth boundary, image schema, snapshot audit, output scan, and container cleanup all provide fresh evidence.
- [ ] The fixed paid diagnostic is independently revalidated before any performance or escalation claim.
