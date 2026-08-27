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

## Current limits

This foundation imports vulnerable labels but does not infer fixed commits,
clone repositories, materialize snapshots, or run Standard or Hunt. Those
steps require a separate corpus-preparation and runner layer so fixed revisions
can be reviewed rather than guessed.

HermesBench Mini is optimization evidence, not final proof. A final, release,
or public performance claim always requires the full HermesBench. The first
full edition is not ready until it contains at least 144 reviewed vulnerable
tasks and adds previously absent cases on at least three diversity axes.
