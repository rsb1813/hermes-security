# HermesBench Foundation

HermesBench measures defensive source-code vulnerability discovery. It scores
whether a workflow localizes an entry point and critical operation, preserves
the ordered evidence trace, avoids repeating a retired finding on a paired
fixed snapshot, and finds at least one valid path per advisory group.

The foundation is intentionally separate from the public Codex Security CLI
and SDK. It does not generate exploits, proof-of-concept payloads, crash
inputs, or remote attack traffic.

## Safety boundary

- Prepare tasks from a pinned local checkout of a public dataset.
- Audit every agent-visible bundle before evaluation.
- Run evaluation offline with an explicit local command allowlist.
- Keep anonymization keys, hidden oracles, generated work, and repository
  snapshots outside Git.
- Treat unmatched findings as provisional until a human review decides whether
  they are false positives or previously unknown vulnerabilities.
- The host runner, executor wrapper, and the local user session that starts
  them are trusted. The untrusted model must receive only the Docker task
  scratch directory, never the final artifact root.
- Preflight and post-run path checks are defense in depth. They do not claim
  atomic protection from a hostile process running as the same host user.
- The Task 4 live Docker validation must prove that the final artifact root is
  absent from container mounts, argv, environment variables, and the working
  directory, while only the scratch directory is writable.

The repository `.gitignore` excludes the conventional `keys/`, `private/`,
`snapshots/`, and `work/` directories under this package. A path outside the
repository is still preferred for hidden evaluation material.

## Run the tests

From the repository root, run the Python suite.

```powershell
python -m unittest discover -s benchmarks/hermesbench/tests -v
```

The TypeScript package also contains a Bun integration test that invokes the
same suite and the real CLI entry point.

```powershell
cd sdk/typescript
bun test --timeout 30000 tests-ts/hermesbench.test.ts
```

## Import reviewed VulnGym labels

Use a pinned local VulnGym checkout and a private random key file. The private
output retains source and advisory identities for corpus preparation. The
summary contains aggregate counts only.

```powershell
python -m benchmarks.hermesbench import-vulngym `
  --entries C:\path\to\VulnGym\data\entries.jsonl `
  --reports C:\path\to\VulnGym\data\reports.jsonl `
  --dataset-revision <40-character-revision> `
  --key-file C:\private\hermesbench.key `
  --private-out C:\private\candidates.json `
  --summary-out C:\private\summary.json
```

Only entries whose `verify` value is the integer `1` become candidates. The
importer validates report membership, repository URL, vulnerable commit, and
all labeled source locations before deriving a keyed anonymous task ID.
When `--private-out` points inside this repository, it must remain under
`benchmarks/hermesbench/private/`; paths outside the repository remain allowed.
The in-repository private root must be a real directory, not a symbolic link or
junction.

## Audit an agent-visible bundle

```powershell
python -m benchmarks.hermesbench audit-bundle --bundle C:\prepared\hb-task
```

Exit code `0` means no known contamination was found. Exit code `2` means the
bundle contains a forbidden advisory or VulnGym source identifier,
version-control metadata, a symbolic link, or another invalid input. Auditing
is read-only and never redacts source bytes.

## Score predictions

```powershell
python -m benchmarks.hermesbench score `
  --oracles C:\private\oracles.jsonl `
  --predictions C:\runs\predictions.jsonl `
  --out C:\runs\score.json
```

Predictions are capped at five findings per task. The score reports pair
localization F1, advisory recall, ordered trace-node F1, fixed-snapshot
specificity, their published weighted composite, and provisional findings.
It also reports the same aggregate metrics for each deterministically ordered
split, so held-out performance remains available when the host public score
excludes task-level details.

## Compare controlled runs

```powershell
python -m benchmarks.hermesbench compare `
  --standard-receipt C:\runs\standard.json `
  --hunt-receipt C:\runs\hunt.json `
  --evidence C:\runs\mini-evidence.json `
  --out C:\runs\comparison.json
```

The command rejects comparisons whose manifest, task order, grader, model,
reasoning effort, seed policy, tool versions, time limit, or finding limit
differs. Cached input, uncached input, and output tokens remain separate in run
receipts.

## Run an audited workflow

`run` executes fresh discovery and verification phases. Each phase is a complete
independent `codex exec` invocation with its own task receipts, event stream,
predictions, and token usage. The verification phase receives only the bounded,
canonical candidate JSONL produced from discovery. The final predictions path
always points to verification output.

The controls document has one exact versioned shape. Its image must be an
immutable lowercase digest, and its invocation budget is exactly two per task.

```json
{
  "schema_version": 2,
  "model": "gpt-5.6-terra",
  "reasoning_effort": "high",
  "seed_supported": false,
  "seed": null,
  "image_digest": "sha256:<64-lowercase-hex-characters>",
  "tool_versions": [["codex", "0.150.0-alpha.8"]],
  "time_limit_seconds": 300,
  "max_findings": 5,
  "grader_version": "2",
  "phase_protocol_version": 1,
  "hunt_candidate_protocol_version": 1,
  "invocations_per_task": 2
}
```

Controls schema `2` remains the exact legacy sequential contract and implies
`max_parallel_tasks = 1` without adding a JSON field. Controls schema `3`
requires `max_parallel_tasks` and accepts only `1` or `2`. A value of `2` runs
at most two tasks concurrently inside one phase while preserving the discovery
to verification barrier.

```json
{
  "schema_version": 3,
  "max_parallel_tasks": 2
}
```

The abbreviated schema-3 example changes only those two fields from the full
schema-2 document above. The worker limit is projected into each phase
`RunConfig`, frozen by the aggregate controls hash, and compared between runs.
All snapshots complete preflight before any worker starts. Each worker retains
its own scratch directory, authentication runtime, and container, while task
receipts, predictions, commands, and evidence are published in manifest order.
Receipt `elapsed_seconds` remains aggregate task time for compatibility; measure
end-to-end wall time around the CLI when evaluating the parallel speedup.

The execution-policy document contains only a frozen command-prefix list.

```json
{"allowed_command_prefixes":[["python","-m","unittest"]]}
```

```powershell
python -m benchmarks.hermesbench run `
  --manifest C:\private\manifest.json `
  --snapshots-root C:\private\snapshots `
  --output-root C:\private\work `
  --run-id standard-canary `
  --workflow standard `
  --profile baseline `
  --controls C:\private\controls.json `
  --execution-policy C:\private\execution-policy.json `
  --auth C:\private\auth.json `
  --oracles C:\private\oracles.jsonl
```

The machine-readable result manifest lists only public artifact paths. The
aggregate workflow receipt binds the controls, snapshot set, phase receipt
bytes, candidate-transfer bytes, invocation count, elapsed time, and separate
token classes. Private scorer inputs remain host-side and are not command
arguments, requests, prompts, container mounts, or result-manifest fields.
When `--oracles` is provided, the public result manifest also names the
identity-free score artifact produced after verification.

## Hunt artifact evidence

Hunt discovery prepares a host-side inventory, rank input, full frontier, and
bounded priority packet before the container starts. Evidence protocol version
`1` has the legacy five-artifact contract and its priority-only discovery
prompt. Version `2` adds the immutable `semantic-guidance.jsonl` packet from
snapshot bytes while retaining semantic guidance row schema `1` and the
existing semantic discovery prompt. Version `3` uses semantic guidance row
schema `2`, which adds `eligible_search_passes` derived only from the exact
source, trace, and operation frontier paths of that row. Version `4` uses
semantic guidance row schema `3`, which adds component-aware call routes,
bounded nested-output contexts, and compact `operation-index` rows in one
canonical packet. An operation-index entry uses `p` for a frontier path, `q`
for eligible-pass codes, and `s` for structural source sites encoded as a line
number followed by `a` for assignment, `c` for call, or `m` for mutation. The
`q` codes `f/b/g/p/s/x` mean `forward/backward/guard/parser/state/general`.
Versions `2`, `3`, and `4` read the priority packet exactly once, then read
semantic guidance exactly once.

Semantic guidance is an investigation queue only. Its strength and eligible
passes order investigation; neither proves attacker control, reachability,
impact, or a missing guard, and neither changes candidate-to-frontier
attestation. Discovery must inspect the actual source plus reachable controls
and counterevidence before producing a candidate. For a version-3 guidance
candidate, choose an eligible pass supported by a submitted entry point,
critical operation, or trace location. If submitted locations differ from the
guidance row, or a candidate falls outside guidance or the priority packet,
look up `frontier.jsonl` by each exact submitted path and use only a pass listed
for a submitted location. There is no `general` fallback: the host never
invents, generalizes, substitutes, defaults, or repairs a model response.

Schema-3 nested-output rows identify only statically observed `script`,
`style`, `url_attribute`, or `event_handler` contexts and bounded local
provenance. They remain `investigation_only`: an output-context hint is not a
finding and does not establish exploitability or sanitizer failure. Protocol
`4` discovery applies the same pass-attestation rules as protocol `3`.
Schema-3 operation indexes are also `investigation_only`. They identify a
source-inspection starting point, not an attacker-controlled entry point or a
finding, and discovery must trace backward before proposing a candidate. When
ordinary semantic routes are present, direct, import-linked, and nested-output
rows are retained first. Index rows can replace only selected name-only rows
inside the route-only row and byte footprint. A structural-only packet is
separately capped at 32 rows and 64 KiB.

The index reuses the existing edge cap for retained structural sites, limits
each canonical row to 2 KiB, and rotates rows across components. Signatures
reused two through seven times are scheduled before one-off or more common
signatures. Inside that band, parameter-linked and generic rows use a 2:1
schedule, calls precede assignments and mutations, and first occurrences rotate
across signatures before later occurrences. Calls with at least three distinct
argument identifiers are inspected first within their lane. These priorities
allocate inspection bytes; they are not evidence.

Semantic preparation is deterministic and bounded. Every source file is
limited to 1 MiB. `hunt-balanced` scans at most 64 MiB, retains at most 50,000
declarations, 200,000 call/import references, 200,000 resolved edges, and 1,024
route work items or candidates at graph depth `4`, then emits at most 256 rows
or 512 KiB. `hunt-max` scans at most 128 MiB, retains at most 100,000
declarations, 400,000 references, 400,000 resolved edges, and 2,048 route work
items or candidates at graph depth `6`, then emits at most 512 rows or 1 MiB.
An empty guidance packet is valid. Truncation, skipped files, priority order, or
guidance strength never make a frontier path ineligible and never count as
reviewed closure. Schema `3` changes allocation order, not these caps: strong
direct, import-linked, and nested-output evidence is allocated before weak
name-only evidence, with deterministic family and component rounds. Name-only
targets are resolved lazily only inside the remaining edge budget.

Each successful Hunt discovery task stores path-free `evidence.json`, and the
phase stores ordered `evidence.jsonl` rows. Protocol versions `2`, `3`, and `4` add
only the semantic packet hash and row, edge, scanned-file, and skipped-file
counts to the existing inventory, rank-input, frontier, priority-packet,
candidate-link, and coverage-debt evidence. Relative paths remain inside the
immutable scratch packet; persistent evidence contains hashes and counts rather
than source paths, previews, candidate prose, or work IDs.

Standard workflow receipts remain schema version `2` with their unchanged
field set. Hunt receipts remain schema version `3` and explicitly bind evidence
protocol version `1`, `2`, `3`, or `4`. Every receipt reconstructs using its recorded
protocol, including incomplete discovery, rather than current defaults or
evidence rows. The Hunt workflow receipt schema remains `3`. Frozen controls
schema `2` remains sequential and byte-compatible, while schema `3` adds only
the bounded phase-local worker limit. The two-call ceiling, 480-second phase timeout, resource bounds,
complete frontier, coverage debt, independent verifier, scorer, sandbox,
authentication boundary, network isolation, and public-data boundary are
unchanged. Discovery preparation remains inside the task budget, and the
container receives only the positive whole-second remainder.

Protocol `4` Hunt verification receives only each candidate ID, entry point,
critical operation, and trace. The verifier independently reconstructs control,
reachability, impact, guard failure, evidence, counterevidence, and proof gaps
from immutable source. The private discovery-to-verification transfer remains
the complete canonical candidate for host attestation and terminal-decision
validation. Protocols `1` through `3` retain their rich verification prompt
bytes, and Standard verification is unchanged. Protocol `4` adds no model call.

## Run paired repeats

```powershell
python -m benchmarks.hermesbench run-paired `
  --manifest C:\private\manifest.json `
  --snapshots-root C:\private\snapshots `
  --output-root C:\private\work `
  --run-id paired-canary `
  --controls C:\private\controls.json `
  --execution-policy C:\private\execution-policy.json `
  --auth C:\private\auth.json `
  --oracles C:\private\oracles.jsonl `
  --hunt-profile hunt-balanced
```

When the backend has no seed support, the realized workflow schedule is exactly
Standard/Hunt, Hunt/Standard, Standard/Hunt. A comparison is eligible only when
both aggregate receipts are complete and all frozen controls, manifest and task
order hashes, execution policy, snapshot set, phase protocol, and invocation
count match. The command never retries a top-level phase automatically.
The comparison artifact includes the exact public artifact paths for both arms
of every repeat, including a score path when host-side scoring was requested.

## Build a reviewed corpus

`corpus_builder.py` is a library-only preparation boundary. It takes a private,
reviewed JSONL ledger plus pinned local Git repositories; it has no network
code and invokes Git only with argument vectors to read object metadata, trees,
and blobs. It never checks out a target revision or executes target repository
code, tests, package managers, or hooks.

A selected ledger row has an exact versioned shape. It binds one imported
candidate identity, vulnerable and independently reviewed fixed commits, primary
evidence, license identifier, safe repository-relative `license_path`, and blob
hash, both tree IDs, language, anonymous
group input, split, suites, time limit, explicit fixed retired-path locations,
fixed-only comment redactions, and symmetric quarantine paths. The vulnerable
gold path remains the single source of truth in the imported `CorpusCandidate`;
the ledger does not duplicate it. An excluded row has only its version, terminal
state, dataset revision, entry ID, and a concrete exclusion reason.

Fixed comment redactions bind the fixed tree, complete original blob SHA-256,
exact line or line range, and SHA-256 of the original selected line bytes. The
builder accepts only language-appropriate comment-only lines, preserves line
count and newline style with a fixed comment marker, and rejects overlaps with
fixed-tree retired entry, root, or trace locations. `quarantine_paths` must be
present in at least one pinned tree and cannot contain a gold or root source
file or the reviewed `license_path`. They are excluded symmetrically before
snapshot auditing. An exact quarantine path may also name a mode `120000` blob
symlink, which remains unmaterialized and unread in either snapshot; every
other non-regular Git entry is rejected. Files with `.patch` or `.diff` metadata
extensions must be explicitly quarantined or the build fails.

For every selected row, the builder requires exact local commit objects, exact
tree IDs, the expected vulnerable-tree license blob hash, a strict
vulnerable-to-fixed ancestry relationship, and a changed critical root file. It
materializes only regular Git blobs into a builder-owned temporary directory,
validates every tree path before any quarantine skip, rejects unsafe paths,
case-fold collisions, unsupported entries, source or advisory contamination,
then publishes by same-parent atomic rename. Existing output roots are never
overwritten.

The resulting directory contains anonymous snapshot directories, an
identity-free manifest and summary, and private oracle and provenance files.
Keep the ledger, keys, built corpora, private oracles, provenance receipts, and
run outputs outside Git. The repository ignore rules cover conventional paths
under `benchmarks/hermesbench/`, but an external private storage location is
still preferred. When an output root is inside this repository, it must be a
child of `benchmarks/hermesbench/corpora/`, be actually ignored by Git, and have
no symbolic-link, junction, or reparse-point ancestor. Existing output roots
are never overwritten.

On Windows, use a short external output parent for real corpora outside
this repository. The builder stages each publication under the exact output
parent with a short `.hb-` directory prefix so materialized repository paths
retain more of the platform path-length budget.

## Current limits

The builder intentionally does not infer fixed commits, clone repositories, or
perform network access. It also does not reuse blobs with hard links: snapshots
remain independent until a private materializer can add that optimization with
equivalent audit and publication guarantees. Git reads clear inherited `GIT_*`
repository-routing state, disable replace-object behavior, and read each tree's
regular blobs through one checked `cat-file --batch` response. The builder uses
only the provided local repository object store. It forces Git lazy fetching
off, so a partial clone with missing objects fails closed instead of contacting
a promisor remote. Operators must prepare a fully hydrated object store or full
clone before corpus preparation.

HermesBench Mini is optimization evidence, not final proof. A final, release,
or public performance claim always requires the full HermesBench. The first
full edition is not ready until it contains at least 144 reviewed vulnerable
tasks and adds previously absent cases on at least three diversity axes.
