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
  "schema_version": 1,
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
