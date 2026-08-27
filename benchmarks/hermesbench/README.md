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
  "grader_version": "1",
  "phase_protocol_version": 1,
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

## Current limits

This foundation does not infer fixed commits, clone repositories, or materialize
snapshots. Those corpus-preparation steps remain separate so fixed revisions
can be reviewed rather than guessed.

HermesBench Mini is optimization evidence, not final proof. A final, release,
or public performance claim always requires the full HermesBench. The first
full edition is not ready until it contains at least 144 reviewed vulnerable
tasks and adds previously absent cases on at least three diversity axes.
