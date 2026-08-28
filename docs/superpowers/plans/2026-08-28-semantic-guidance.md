# Deterministic Semantic Guidance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic, bounded source-to-sensitive-operation guidance to Hunt discovery while preserving the two-call workflow, Standard behavior, and protocol-v1 receipt reconstruction.

**Architecture:** A new host-only lexical graph module emits canonical investigation-only guidance from immutable snapshot bytes. Hunt evidence protocol version 2 binds that artifact and audits one additional read, while version-aware reconstruction retains the exact protocol-v1 artifact and evidence contract. The discovery prompt changes only for Hunt discovery; verification, Standard, scoring, and candidate acceptance remain unchanged.

**Tech Stack:** Python 3 standard library, `unittest`, existing HermesBench contracts and receipt code, Bun TypeScript compatibility tests, Docker only for existing opt-in boundary smokes, Git.

**Spec:** `docs/superpowers/specs/2026-08-28-semantic-guidance-design.md`

## Global Constraints

- Perform defensive local-source discovery only. Do not generate exploits, proof-of-concept payloads, crash inputs, or remote traffic.
- Add no parser, SAST, language-server, network, or model dependency.
- Keep exactly two top-level model invocations per completed Hunt task.
- Keep the complete frontier, coverage debt, candidate location linkage, verification rules, scorer, and public prediction schema unchanged.
- Keep Standard prompt bytes and Hunt verification prompt bytes unchanged.
- Protocol version 1 must reproduce its current artifact and evidence bytes; new live Hunt runs use protocol version 2.
- Each source file is bounded to 1 MiB. `hunt-balanced` scans 64 MiB with depth 4 and emits at most 256 rows or 512 KiB. `hunt-max` scans 128 MiB with depth 6 and emits at most 512 rows or 1 MiB.
- Persistent evidence contains hashes and counts only. Relative paths exist only in the immutable scratch guidance artifact.
- New and modified code comments and docstrings are English.
- Use `apply_patch` for edits, prefix every executed command with `rtk`, and make one semantic commit per completed task.

## File Structure

- Create `benchmarks/hermesbench/semantic_guidance.py` for lexical extraction, graph construction, resource bounds, route projection, and canonical bytes.
- Create `benchmarks/hermesbench/tests/test_semantic_guidance.py` for language, determinism, ambiguity, and bound tests.
- Modify `benchmarks/hermesbench/hunt_evidence.py` to coordinate protocol-specific artifacts and path-free evidence.
- Modify `benchmarks/hermesbench/adapters/codex_exec.py` to change only the Hunt discovery prompt and audit the new read.
- Modify `benchmarks/hermesbench/phase_runner.py` to load and reconstruct evidence according to the receipt's protocol version.
- Modify `benchmarks/hermesbench/runner.py` to require the workflow-selected evidence protocol and allowlist the two fixed semantic-read failure codes.
- Modify `benchmarks/hermesbench/cli.py` to select the latest protocol explicitly for live Hunt workflows.
- Modify focused tests in `test_hunt_evidence.py`, `test_codex_exec_adapter.py`, `test_runner.py`, and `test_phase_runner.py`.
- Modify `benchmarks/hermesbench/README.md` and the existing bundled Hunt contract to describe protocol version 2 without adding a new skill or command prefix.

---

### Task 1: Deterministic Lexical Guidance Builder

**Files:**
- Create: `benchmarks/hermesbench/semantic_guidance.py`
- Create: `benchmarks/hermesbench/tests/test_semantic_guidance.py`

**Interfaces:**
- Consumes: immutable `snapshot_path: Path`, frontier-ordered `paths: tuple[str, ...]`, and `profile: str`.
- Produces: `build_semantic_guidance(snapshot_path: Path, paths: tuple[str, ...], profile: str) -> SemanticGuidance`.
- Produces: frozen `SemanticGuidance(canonical_bytes, row_count, edge_count, scanned_file_count, skipped_file_count)`.
- Later tasks persist `canonical_bytes` unchanged and bind the four counts.

- [ ] **Step 1: Write RED tests for exact schemas, deterministic bytes, and direct routes**

Create `test_semantic_guidance.py` with synthetic Python, Go, and TypeScript snapshots. Assert the same bytes under two root directories and assert only the exact row fields.

```python
class SemanticGuidanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self._root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _build(
        self,
        name: str,
        files: dict[str, str | bytes],
        profile: str = "hunt-balanced",
    ) -> SemanticGuidance:
        snapshot = self._root / name
        snapshot.mkdir()
        for relative, value in files.items():
            path = snapshot / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, bytes):
                path.write_bytes(value)
            else:
                path.write_text(value, encoding="utf-8")
        return build_semantic_guidance(snapshot, tuple(files), profile)

    def _rows(self, files: dict[str, str | bytes]) -> list[dict[str, object]]:
        result = self._build(f"case-{len(tuple(self._root.iterdir()))}", files)
        return [json.loads(line) for line in result.canonical_bytes.decode("utf-8").splitlines()]

    def _single_row(self, files: dict[str, str | bytes]) -> dict[str, object]:
        rows = self._rows(files)
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_same_source_bytes_produce_identical_guidance(self) -> None:
        first = self._build("first", {"app.py": "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n"})
        second = self._build("second", {"app.py": "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n"})
        self.assertEqual(first.canonical_bytes, second.canonical_bytes)
        self.assertEqual(first.row_count, 1)
        row = json.loads(first.canonical_bytes.decode("utf-8").splitlines()[0])
        self.assertEqual(
            set(row),
            {"schema_version", "hint_id", "strength", "operation_family", "source", "operation", "trace", "controls", "reason_codes", "proof_status"},
        )
        self.assertEqual(row["proof_status"], "investigation_only")

    def test_python_go_and_typescript_direct_routes(self) -> None:
        fixtures = {
            "python": ("app.py", "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n"),
            "go": ("app.go", "func Handle(r *http.Request) { exec.Command(r.URL.Query().Get(\"q\")) }\n"),
            "typescript": ("app.ts", "export function handle(request: Request) { return child_process.exec(request.query.q); }\n"),
        }
        for language, (path, source) in fixtures.items():
            with self.subTest(language=language):
                row = self._single_row({path: source})
                self.assertEqual(row["strength"], "direct")
                self.assertEqual(row["proof_status"], "investigation_only")
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_semantic_guidance -v
```

Expected: import failure for `benchmarks.hermesbench.semantic_guidance`.

- [ ] **Step 3: Implement the public builder types, limits, and canonical row validation**

Create these public types and constants.

```python
SEMANTIC_GUIDANCE_SCHEMA_VERSION = 1
MAX_FILE_BYTES = 1024 * 1024

@dataclass(frozen=True)
class GuidanceLimits:
    total_source_bytes: int
    declaration_count: int
    edge_count: int
    route_count: int
    row_count: int
    output_bytes: int
    graph_depth: int

PROFILE_LIMITS = {
    "hunt-balanced": GuidanceLimits(64 * 1024 * 1024, 50_000, 200_000, 1_024, 256, 512 * 1024, 4),
    "hunt-max": GuidanceLimits(128 * 1024 * 1024, 100_000, 400_000, 2_048, 512, 1024 * 1024, 6),
}

@dataclass(frozen=True)
class SemanticGuidance:
    canonical_bytes: bytes
    row_count: int
    edge_count: int
    scanned_file_count: int
    skipped_file_count: int

def build_semantic_guidance(
    snapshot_path: Path,
    paths: tuple[str, ...],
    profile: str,
) -> SemanticGuidance:
    try:
        limits = PROFILE_LIMITS[profile]
    except KeyError as error:
        raise SemanticGuidanceError("semantic guidance profile is unsupported") from error
    snapshot = _safe_snapshot(snapshot_path)
    declarations, scan = _scan_files(snapshot, paths, limits)
    routes, edge_count = _build_routes(declarations, limits)
    canonical_bytes, row_count = _canonical_guidance(routes, limits)
    return SemanticGuidance(
        canonical_bytes,
        row_count,
        edge_count,
        scan.scanned_file_count,
        scan.skipped_file_count,
    )
```

Define `SemanticGuidanceError`, `_ScanStats`, `_Declaration`, `_Route`, `_safe_snapshot`, `_scan_files`, `_build_routes`, and `_canonical_guidance` in the same module. Implement relative-path validation with `PurePosixPath` and `PureWindowsPath`, deterministic frontier-order scanning, a one-link regular-file check, UTF-8 decoding, stable canonical JSON using `sort_keys=True` and compact separators, and exact row validation before bytes are returned.

- [ ] **Step 4: Implement family scanners and direct route projection**

Use fixed token vocabularies and language-shaped declaration recognition. Keep anchors defensive and generic.

```python
SOURCE_ANCHORS = {
    "request", "body", "query", "params", "headers", "cookie", "argv", "stdin", "environment", "input"
}
CONTROL_ANCHORS = {
    "allowlist", "authorize", "escape", "guard", "permission", "policy", "sanitize", "validate"
}
OPERATION_ANCHORS = {
    "command": {"exec", "eval", "system", "subprocess.run", "subprocess.popen", "child_process.exec", "child_process.spawn", "exec.command", "os/exec.command"},
    "query": {"query", "rawquery", "executesql", "cursor.execute", "db.raw"},
    "file": {"open", "os.open", "readfile", "writefile", "remove", "unlink"},
    "template": {"renderstring", "template.execute", "executetemplate"},
    "deserialize": {"pickle.load", "pickle.loads", "yaml.load", "unmarshal", "unserialize", "objectinputstream"},
    "network": {"fetch", "urlopen", "http.get", "client.do", "dial"},
    "state": {"delete", "destroy", "save", "update", "transition"},
}
```

For Python, Go, and TypeScript/JavaScript, track the current declaration by indentation or brace depth and preserve at most the final two qualified callee segments for anchor matching. For the generic fallback, emit only `name-only` rows. A source and operation in one declaration emits one `direct` route. Do not include source snippets in the row.

- [ ] **Step 5: Run direct-route tests and confirm GREEN**

Run the focused module again. Expected: all Task 1 tests written so far pass.

- [ ] **Step 6: Write RED tests for cross-file edges, ambiguity, cycles, and bounds**

Add explicit module-linked fixtures and ambiguous duplicates.

```python
def test_explicit_import_produces_import_linked_route(self) -> None:
    result = self._build(
        "linked",
        {
            "api.py": "from store import run\ndef handle(request):\n    return run(request.args['q'])\n",
            "store.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
        },
    )
    row = json.loads(result.canonical_bytes.decode("utf-8").splitlines()[0])
    self.assertEqual(row["strength"], "import-linked")
    self.assertEqual([item["path"] for item in row["trace"]], ["api.py", "store.py"])

def test_ambiguous_name_never_becomes_a_strong_route(self) -> None:
    rows = self._rows(
        {
            "api.py": "def handle(request):\n    return run(request.args['q'])\n",
            "one.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            "two.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
        }
    )
    self.assertTrue(all(row["strength"] == "name-only" for row in rows))
```

Add a cyclic two-file fixture, an oversized file, invalid UTF-8, duplicate endpoints, and a patched tiny `GuidanceLimits` case. Assert maximum 12 trace locations, 8 controls, exact output bytes, stable skip counts, and no repeated trace node.

- [ ] **Step 7: Run the expanded tests and confirm RED**

Expected: cross-file and bound assertions fail because only direct projection exists.

- [ ] **Step 8: Implement unique import resolution, bounded graph traversal, deduplication, and output truncation**

Represent declarations by stable `(path, line, symbol)` identity. Resolve same-file calls first, explicit module imports second, and ambiguous global names last. Use breadth-first traversal with the profile depth, stop cycles by node identity, and retain the strongest shortest route for each endpoint pair.

Sort output by this exact tuple.

```python
(
    {"direct": 0, "import-linked": 1, "name-only": 2}[route.strength],
    len(route.trace),
    route.operation_family,
    route.source.path,
    route.source.line,
    route.operation.path,
    route.operation.line,
    tuple((item.path, item.line, item.symbol) for item in route.trace),
)
```

Stop before adding a canonical row that would exceed the row or byte limit. Skipped files and truncated graph work affect counts only, never the frontier.

- [ ] **Step 9: Run Task 1 tests and commit**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_semantic_guidance -v
rtk python -m compileall -q benchmarks\hermesbench\semantic_guidance.py benchmarks\hermesbench\tests\test_semantic_guidance.py
rtk git diff --check
rtk git add -- benchmarks/hermesbench/semantic_guidance.py benchmarks/hermesbench/tests/test_semantic_guidance.py
rtk git commit -m "Add deterministic semantic guidance builder"
```

Expected: all focused tests and compile checks pass.

---

### Task 2: Hunt Evidence Protocol Version 2

**Files:**
- Modify: `benchmarks/hermesbench/hunt_evidence.py:18-258`
- Modify: `benchmarks/hermesbench/tests/test_hunt_evidence.py`

**Interfaces:**
- Consumes: `build_semantic_guidance` from Task 1.
- Produces: `prepare_hunt_artifacts(snapshot_path: Path, scratch_path: Path, profile: str, *, evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION) -> PreparedHuntArtifacts`.
- Produces: `parse_hunt_evidence(value: object, profile: str | None = None, *, evidence_protocol_version: int | None = None) -> dict[str, object]`.
- Produces: `reproduce_hunt_evidence(snapshot_path: Path, profile: str, prediction: object, *, evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION) -> HuntEvidence`.
- Produces: version-aware `PreparedHuntArtifacts` and `HuntEvidence` values used by the adapter and phase runner.

- [ ] **Step 1: Write RED protocol-version and immutable-artifact tests**

Import `hashlib` and `json`, then add these expectations before changing implementation. The golden values come from the current public synthetic `_snapshot` fixture at commit `c7ee977`.

```python
def test_protocol_one_preserves_legacy_artifact_set_and_evidence_fields(self) -> None:
    prepared = prepare_hunt_artifacts(snapshot, scratch, "hunt-balanced", evidence_protocol_version=1)
    self.assertIsNone(prepared.semantic_guidance)
    self.assertEqual(prepared.preparation_fingerprint, "ebd0afda04ac4dc2b9d72294aff32eb0616f003a66eac892365b58b6c1cebbf5")
    self.assertEqual(
        {
            "inventory": prepared.inventory.sha256,
            "rank_input": prepared.rank_input.sha256,
            "frontier": prepared.frontier.sha256,
            "frontier_receipt": prepared.frontier_receipt.sha256,
            "priority_packet": prepared.priority_packet.sha256,
        },
        {
            "inventory": "d974ee18bc2f3c6438d61cbe6925dc76a7f51d5ee7d2f75e23d2ad37f2047863",
            "rank_input": "89f7777170042fa6979b6d6f33b593d736a933e2374d89d585123b5fd1a29b93",
            "frontier": "a3e2464114f68c620072e327b91628ddfaa99d7655bbe478eaff25eb3c3ed7c8",
            "frontier_receipt": "1dae429f9c27156a8fce5ab7d3e8593f24a76d17135564f996da4ab7f858a850",
            "priority_packet": "cb047ea29da1af0dc9961a531acf4b518a25770c2daf1cd50f771c7154af6d6a",
        },
    )
    evidence = attest_hunt_discovery(prepared, prediction, (self._PACKET_READ,))
    self.assertEqual(evidence.to_json()["schema_version"], 1)
    self.assertEqual(set(evidence.to_json()), HUNT_EVIDENCE_FIELDS_V1)
    canonical = (json.dumps(evidence.to_json(), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    self.assertEqual(hashlib.sha256(canonical).hexdigest(), "0771c4297ed1ef8455dc90fa9e9bcdabedbe3be3b44b3ada9a43a4b434ee1ab2")

def test_protocol_two_records_deterministic_semantic_guidance(self) -> None:
    first = prepare_hunt_artifacts(snapshot, first_scratch, "hunt-balanced", evidence_protocol_version=2)
    second = prepare_hunt_artifacts(snapshot, second_scratch, "hunt-balanced", evidence_protocol_version=2)
    self.assertEqual(first.semantic_guidance.sha256, second.semantic_guidance.sha256)
    self.assertEqual(first.preparation_fingerprint, second.preparation_fingerprint)
```

Assert v1 plan-directory entries are exactly the five current files and v2 adds only `semantic-guidance.jsonl`.

- [ ] **Step 2: Run focused evidence tests and confirm RED**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_hunt_evidence -v
```

Expected: unexpected `evidence_protocol_version` argument and missing semantic fields.

- [ ] **Step 3: Implement version constants, version-aware data classes, and preparation**

Replace the single-version assumption with these constants.

```python
LEGACY_HUNT_EVIDENCE_PROTOCOL_VERSION = 1
HUNT_EVIDENCE_PROTOCOL_VERSION = 2
SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS = frozenset({1, 2})
SEMANTIC_GUIDANCE_NAME = "semantic-guidance.jsonl"
_REQUIRED_SEMANTIC_READ = ("cat", "/workspace/scratch/hermesbench-hunt/semantic-guidance.jsonl")
```

Add `evidence_protocol_version`, optional semantic `_Artifact`, and semantic counts to `PreparedHuntArtifacts`. Add `protocol_version` and optional semantic evidence fields to `HuntEvidence`. `to_json()` emits the exact v1 field set for version 1 and the five additional fields for version 2.

Keep the current five v1 preparation operations in the same order. For v2 only, call Task 1 with frontier-ordered paths, write its canonical bytes once, record the file, and include its hash in `preparation_fingerprint`.

- [ ] **Step 4: Implement exact versioned parsing and reproduction**

Define `HUNT_EVIDENCE_FIELDS_V1` and `HUNT_EVIDENCE_FIELDS_V2`. `parse_hunt_evidence` first validates `schema_version`, optionally enforces the receipt-supplied version, and then validates only that version's exact field set.

```python
def reproduce_hunt_evidence(
    snapshot_path: Path,
    profile: str,
    prediction: object,
    evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION,
) -> HuntEvidence:
    with tempfile.TemporaryDirectory(prefix="hermesbench-hunt-evidence-") as directory:
        prepared = prepare_hunt_artifacts(
            snapshot_path,
            Path(directory),
            profile,
            evidence_protocol_version=evidence_protocol_version,
        )
        observed = (_REQUIRED_PACKET_READ,)
        if evidence_protocol_version == 2:
            observed += (_REQUIRED_SEMANTIC_READ,)
        return attest_hunt_discovery(prepared, prediction, observed)
```

- [ ] **Step 5: Write RED semantic-read and mutation tests**

Add v2 tests for one valid semantic read, missing read, duplicate read, byte mutation, oversized replacement, symbolic link, hard link, and low-level replacement. Assert missing and duplicate categories exactly.

```python
with self.assertRaises(HuntEvidenceError) as caught:
    attest_hunt_discovery(prepared_v2, prediction, (self._PACKET_READ,))
self.assertEqual(caught.exception.category, "hunt_semantic_guidance_missing")
```

Also assert a v1 attestation never requires the semantic read.

- [ ] **Step 6: Implement v2 read cardinality and artifact attestation**

Require the semantic command exactly once only when `prepared.evidence_protocol_version == 2`. Reuse `_verify_record` and `_read_pinned_bytes` for identity, mode, link, size, and hash checks. Map semantic mutation to `hunt_evidence_artifact_integrity`; do not add source paths or exception text to persisted evidence.

- [ ] **Step 7: Run Task 2 tests and commit**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_semantic_guidance benchmarks.hermesbench.tests.test_hunt_evidence -v
rtk python -m compileall -q benchmarks\hermesbench\hunt_evidence.py benchmarks\hermesbench\tests\test_hunt_evidence.py
rtk git diff --check
rtk git add -- benchmarks/hermesbench/hunt_evidence.py benchmarks/hermesbench/tests/test_hunt_evidence.py
rtk git commit -m "Bind semantic guidance in Hunt evidence v2"
```

Expected: all builder and evidence tests pass, including explicit protocol-v1 cases.

---

### Task 3: Discovery Prompt and Public Failure Boundary

**Files:**
- Modify: `benchmarks/hermesbench/adapters/codex_exec.py:18-285,443-490`
- Modify: `benchmarks/hermesbench/runner.py:20-88`
- Modify: `benchmarks/hermesbench/tests/test_codex_exec_adapter.py`
- Modify: `benchmarks/hermesbench/tests/test_runner.py`

**Interfaces:**
- Consumes: latest v2 preparation and attestation from Task 2.
- Produces: a Hunt-discovery-only prompt with both fixed read commands.
- Produces: public codes `hunt_semantic_guidance_missing` and `hunt_semantic_guidance_duplicate`.

- [ ] **Step 1: Write RED adapter tests for the two required reads and investigation-only wording**

Add a helper that emits two separate command events followed by the terminal response. Do not join commands with a shell operator.

```python
def _hunt_stream() -> bytes:
    encode = lambda row: json.dumps(row).encode("utf-8") + b"\n"
    priority = {"type": "item.completed", "item": {"type": "command_execution", "command": "cat /workspace/scratch/hermesbench-hunt/priority-packet.jsonl"}}
    semantic = {"type": "item.completed", "item": {"type": "command_execution", "command": "cat /workspace/scratch/hermesbench-hunt/semantic-guidance.jsonl"}}
    return encode(priority) + _stream(command=semantic["item"]["command"])
```

Assert valid discovery observes both commands, missing semantic read yields `hunt_semantic_guidance_missing`, duplicate semantic reads yield `hunt_semantic_guidance_duplicate`, and prompt text contains all of these requirements.

```python
self.assertIn("investigation guidance only, never proof", prompt)
self.assertIn("Open the actual source", prompt)
self.assertIn("Do not raise candidate confidence from guidance strength", prompt)
```

- [ ] **Step 2: Add RED golden-hash tests for unchanged prompts**

Construct the existing `task-001` request and assert these UTF-8 prompt hashes.

```python
expected = {
    "standard_discovery": "6388f631fd0fc680e63bab85e8acfd800486c3b2932fca71829eca9608edb246",
    "standard_verification": "716beedcd9c73cf349c6181233d93897ecf8bd04fa2b9496d793506d8ff74127",
    "hunt_verification": "17695d043651ee5c387170ad7e239512ef6242c4bd6136fc45d6cef974739286",
}
```

Expected: these tests already pass before implementation and must remain green throughout Task 3. The new Hunt discovery assertions fail.

- [ ] **Step 3: Add RED runner tests for canonical failure evidence**

Extend the public-code loop in `test_runner.py` with the two semantic categories. For each, assert the task directory contains only `request.json` and canonical `failure.json`, success aggregates remain empty, and workflow receipt reconstruction can later consume the fixed code.

- [ ] **Step 4: Implement the Hunt-discovery-only prompt and allowlist codes**

Append the exact semantic read after the existing priority read sentence. State that guidance is an investigation queue, actual source inspection is mandatory, controls and counterevidence must be checked, and strength never raises confidence.

Add the two codes to `HUNT_EVIDENCE_FAILURE_CODES` and `_PUBLIC_FAILURE_CODES`. Do not change command parsing, execution-policy prefixes, Standard text, verification text, schemas, or candidate limits.

- [ ] **Step 5: Run Task 3 tests and commit**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_codex_exec_adapter benchmarks.hermesbench.tests.test_runner -v
rtk python -m compileall -q benchmarks\hermesbench\adapters\codex_exec.py benchmarks\hermesbench\runner.py
rtk git diff --check
rtk git add -- benchmarks/hermesbench/adapters/codex_exec.py benchmarks/hermesbench/runner.py benchmarks/hermesbench/tests/test_codex_exec_adapter.py benchmarks/hermesbench/tests/test_runner.py
rtk git commit -m "Require semantic guidance in Hunt discovery"
```

Expected: all focused tests pass and all three non-discovery prompt hashes remain unchanged.

---

### Task 4: Version-Aware Workflow Receipt Reconstruction

**Files:**
- Modify: `benchmarks/hermesbench/phase_runner.py:13-334,412-752`
- Modify: `benchmarks/hermesbench/runner.py:147-228,283-415`
- Modify: `benchmarks/hermesbench/cli.py:145-204`
- Modify: `benchmarks/hermesbench/tests/test_phase_runner.py`
- Modify: `benchmarks/hermesbench/tests/test_runner.py`
- Modify: `benchmarks/hermesbench/tests/test_cli.py`

**Interfaces:**
- Consumes: supported protocol versions and version-aware parse/reproduce functions from Task 2.
- Produces: schema-3 `WorkflowReceipt` values that accept Hunt evidence protocol 1 or 2 and reject every other value.
- Produces: explicit `hunt_evidence_protocol_version` selection through `run_workflow` and `run_paired`, with strict runner parsing and no evidence-driven downgrade.

- [ ] **Step 1: Write RED receipt-constructor tests**

Add unit cases proving a Hunt schema-3 receipt accepts versions 1 and 2, rejects 0 and 3, and Standard still rejects any Hunt evidence fields.

```python
for version in (1, 2):
    with self.subTest(version=version):
        self.assertEqual(WorkflowReceipt.from_json(hunt_receipt(version)).hunt_evidence_protocol_version, version)
```

- [ ] **Step 2: Write RED end-to-end v1 and v2 reconstruction tests**

Extend the fake Hunt result helper with the exact signature below, then run one synthetic v1 workflow and one v2 workflow with the same explicit workflow argument. Assert `_workflow_receipt` records the selected version and `validate_workflow_receipt` reproduces each version from snapshot bytes.

```python
def _hunt_result(
    request: object,
    count: int = 1,
    evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION,
) -> ExecutorResult:
    response = _hunt_discovery(request.task_id, count)
    prediction = parse_hunt_discovery_prediction(response["prediction"], request.task_id)
    evidence = reproduce_hunt_evidence(
        Path(request.snapshot_path),
        "hunt-balanced",
        prediction,
        evidence_protocol_version=evidence_protocol_version,
    ).to_json()
    return ExecutorResult(response, ({"event": "done"},), (), evidence)
```

```python
for version in (1, 2):
    result = run_workflow(
        manifest,
        snapshots,
        outputs,
        f"protocol-{version}",
        "hunt",
        "hunt-balanced",
        controls,
        policy,
        lambda request, *_: _hunt_result(request, evidence_protocol_version=version),
        verification_factory,
        hunt_evidence_protocol_version=version,
    )
    self.assertEqual(result.receipt.hunt_evidence_protocol_version, version)
    validated = validate_workflow_receipt(
        manifest,
        snapshots,
        outputs,
        outputs / f"protocol-{version}-workflow-receipt.json",
        controls,
        policy,
    )
    self.assertEqual(validated.hunt_evidence_protocol_version, version)
```

Add an incomplete v1 discovery case with a completed-task subset and two failure cases with no evidence rows selected explicitly as v1 and v2. Assert both receipts retain the selected version. Add a mismatch case where a v1 executor result is supplied to a v2 workflow and assert runner rejection before a success artifact is committed.

- [ ] **Step 3: Run focused phase tests and confirm RED**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_phase_runner -v
```

Expected: version 1 is rejected by the current single-version receipt check, or the runner accepts an evidence row that disagrees with the selected workflow protocol.

- [ ] **Step 4: Implement supported-version receipt validation and explicit live versioning**

Change `WorkflowReceipt.__post_init__` to require membership in `SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS`. Thread an explicit protocol through these signatures.

```text
run_suite(
    manifest: BenchmarkManifest,
    snapshots_root: Path,
    output_root: Path,
    run_id: str,
    workflow: str,
    profile: str,
    config: RunConfig,
    execution_policy: ExecutionPolicy,
    executor: Executor,
    response_kind: str = "standard",
    evidence_protocol_version: int | None = None,
) -> RunReceipt

run_workflow(
    manifest: BenchmarkManifest,
    snapshots_root: Path,
    output_root: Path,
    run_id: str,
    workflow: str,
    profile: str,
    controls: FrozenControls,
    execution_policy: ExecutionPolicy,
    discovery_executor: Executor,
    verification_executor_factory: VerificationExecutorFactory,
    score_callback: HostScoreCallback | None = None,
    *,
    hunt_evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION,
) -> WorkflowResult

run_paired(
    manifest: BenchmarkManifest,
    snapshots_root: Path,
    output_root: Path,
    run_id: str,
    controls: FrozenControls,
    execution_policy: ExecutionPolicy,
    discovery_executors: Mapping[str, Executor],
    verification_executor_factories: Mapping[str, VerificationExecutorFactory],
    profiles: Mapping[str, str],
    score_callbacks: Mapping[str, HostScoreCallback] | None = None,
    *,
    hunt_evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION,
) -> PairedRunResult
```

The code block shows the complete public signatures. Keep each existing function body in place and make the narrow changes described here. `run_suite` requires a supported version only for `hunt-discovery`, passes it to `_run_task`, and calls `parse_hunt_evidence(task_evidence, profile, evidence_protocol_version=selected_version)`. Other response kinds require `None`. `run_workflow` passes the selected version to discovery and `_workflow_receipt`; it never infers a version from evidence rows. `run_paired` passes the selected version only to Hunt. The CLI explicitly passes `HUNT_EVIDENCE_PROTOCOL_VERSION` for new live Hunt runs.

In `validate_workflow_receipt`, pass `receipt.hunt_evidence_protocol_version` to both `parse_hunt_evidence` and `reproduce_hunt_evidence`. Do not infer reconstruction version from current code, controls, or evidence content. Add the selected Hunt protocol as comparison JSON metadata without comparing it to Standard's `None` value.

- [ ] **Step 5: Add RED field-mixing and tamper tests**

Rewrite a v1 row with one v2 field, a v2 row without one semantic field, and a receipt protocol that disagrees with its evidence row. Rehash only the immediately enclosing artifact as each existing tamper test does. Assert all three fail before acceptance.

- [ ] **Step 6: Run Task 4 tests and commit**

Run:

```powershell
rtk python -m unittest benchmarks.hermesbench.tests.test_phase_runner benchmarks.hermesbench.tests.test_hunt_evidence -v
rtk python -m compileall -q benchmarks\hermesbench\phase_runner.py benchmarks\hermesbench\tests\test_phase_runner.py
rtk git diff --check
rtk git add -- benchmarks/hermesbench/phase_runner.py benchmarks/hermesbench/tests/test_phase_runner.py
rtk git commit -m "Revalidate Hunt evidence by protocol version"
```

Expected: v1 and v2 complete and incomplete synthetic receipts revalidate; mixed or unsupported evidence fails closed.

---

### Task 5: Documentation, Full Verification, Review, and Fixed Diagnostic

**Files:**
- Modify: `benchmarks/hermesbench/README.md`
- Modify: `sdk/typescript/_bundled_plugin/skills/hunt-security-scan/references/hunt-contract.md`
- Modify: `checklist.md`
- Modify: `context-notes.md`
- Test: all HermesBench Python and TypeScript tests
- Private ignored output: one new immutable fixed diagnostic root selected by the main agent

**Interfaces:**
- Consumes: Tasks 1-4 as a single protocol-v2 strategy.
- Produces: reviewed code, no-model boundary evidence, and one scored paid diagnostic with separated token classes.

- [ ] **Step 1: Update public protocol documentation**

Document the two immutable packets, investigation-only semantics, exact v1/v2 reconstruction rule, fixed resource bounds, and the unchanged two-call workflow. Do not include private paths, corpus identities, hidden labels, or paid-output details.

- [ ] **Step 2: Run the complete public test suite**

Run:

```powershell
rtk python -m unittest discover -s benchmarks\hermesbench\tests -v
rtk bun test --timeout 90000 tests-ts/hermesbench.test.ts
rtk python -m compileall -q benchmarks\hermesbench
rtk git diff --check
```

Run the Bun command from `sdk/typescript`. Expected: all Python and Bun tests pass with only documented platform skips.

- [ ] **Step 3: Run deterministic and boundary smokes without a model**

Run version-1 and version-2 preparation twice over the fixed diagnostic snapshot without reading private source output. Record only counts, hashes, elapsed time, and byte limits. Then run the existing named-permission and regular-auth smokes because the adapter preparation boundary changed.

Verify all of these conditions.

- Protocol-v1 reproduction still validates a retained v12c receipt.
- Protocol-v2 guidance hashes and counts reproduce exactly.
- All three response schemas in the pinned image match host bytes and remain mode `0444`.
- Snapshot audits report zero violations and exact hashes for all eight Canary snapshots.
- No output contains a bounded authentication value or host path.
- No reparse entry or residual container remains.

- [ ] **Step 4: Request two-stage review and apply at most one correction batch**

Use one specification-compliance reviewer and one code-quality/security reviewer. Review only the Task 1-4 commit range. Critical, Important, and Minor findings must cite exact files and lines. Return valid findings to the responsible implementer in one batch, rerun focused tests, and allow one re-review unless unresolved correctness or safety evidence requires another.

- [ ] **Step 5: Commit documentation and verified checklist state**

Run `rtk git diff --check`, then commit only documentation and tracking changes.

```powershell
rtk git add -- benchmarks/hermesbench/README.md sdk/typescript/_bundled_plugin/skills/hunt-security-scan/references/hunt-contract.md checklist.md context-notes.md
rtk git commit -m "docs: document Hunt semantic guidance v2"
```

- [ ] **Step 6: Run one fixed paid protocol-v2 diagnostic**

The main agent creates a new exact empty non-reparse output directory and runs the same single diagnostic, model, high effort, 480-second task timeout, image digest, execution policy, candidate protocol, scorer, and two-call Hunt workflow used by v12c. Only semantic guidance and its evidence protocol may differ.

Do not read raw private predictions or hidden labels. Parse only workflow status, phase times, separated token classes, guidance counts, candidate count, search-pass distribution, verifier dispositions, public finding count, and public score fields.

- [ ] **Step 7: Revalidate and decide escalation**

Revalidate the workflow receipt independently, audit all eight snapshots, scan retained artifacts for authentication values and host paths, and confirm no container remains.

Compare v10, v11, v12c, and the protocol-v2 run. Count improvement only if advisory recall, pair-localization F1, or trace-node F1 becomes positive without a fixed-snapshot false positive.

- If every discovery metric remains zero, do not run Mini. Record the bounded negative and select one lexical graph variable for the next plan.
- If a discovery metric becomes positive, run `hunt-balanced` and `hunt-max` on all eight Canary snapshots while holding every other variable fixed.
- Run HermesBench Mini only after Canary identifies a positive profile. Run HermesBench Full before any final performance claim.

- [ ] **Step 8: Final verification and milestone commit**

Rerun the complete Python and Bun suites, compileall, diff check, `git status --short`, and the no-residual-container check. Update `checklist.md` and `context-notes.md` with exact evidence and make one final semantic documentation commit if tracking changed.

Do not push the branch unless the user explicitly asks.
