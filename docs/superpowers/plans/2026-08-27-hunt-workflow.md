# Experimental Hunt Workflow Implementation Plan

Status: Approved architecture, implementation-ready plan  
Branch: `hermes/benchmark-foundation`  
Depends on: `docs/superpowers/specs/2026-08-27-hermes-security-design.md`

## Goal

Add an explicitly invoked bundled `hunt-security-scan` skill that improves
repository-wide vulnerability discovery through deterministic full-inventory
coverage, bidirectional review passes, independent safe validation, exact
root-cause deduplication, and accepted-only draft reporting. Preserve the
existing Standard scan, `ScanMode`, CLI, API, and SDK behavior.

## Non-negotiable boundaries

- Ranking changes review order, never file eligibility.
- Hunt runs only on the authorized local repository and uses no network during
  evaluation.
- Validation permits static tracing, existing tests, builds, type checking,
  and non-triggering invariant checks. It rejects exploit, PoC, crash, and
  remote-attack validation methods.
- A verifier identity must differ from the discovery identity.
- Every frontier item and every candidate receives a terminal disposition or
  explicit coverage debt entry.
- Only accepted, exactly deduplicated root causes enter the draft report.
- `hunt-balanced` saves cost through cached mapping, risk-ordered batches, and
  targeted passes. `hunt-max` performs forward and backward review for every
  eligible file and is the final performance profile.

## Task 1. Deterministic full-coverage frontier

Files.

- Create `sdk/typescript/_bundled_plugin/scripts/hunt_workflow.py`.
- Create `sdk/typescript/tests-ts/hunt-workflow.test.ts`.

Tests first.

1. Build rank input and rank output fixtures with two components, one
   `include: false` low-score file, entry-point signals, sink signals, and an
   ordinary file.
2. Run `make-frontier` and assert every authoritative input path appears
   exactly once.
3. Assert the first coverage round includes each component before a component
   receives a second item.
4. Assert `hunt-max` assigns both `forward` and `backward` passes to every row.
5. Assert repeated invocation over identical inputs produces byte-identical
   JSONL and a receipt with the same cache key.

Implementation contract.

```text
hunt_workflow.py make-frontier
  --rank-input <rank_input.jsonl>
  [--rank-output <rank_output.jsonl>]
  --profile hunt-balanced|hunt-max
  --out <frontier.jsonl>
  --receipt <frontier-receipt.json>
```

The command validates the same `{path, area, preview}` and
`{path, area, score, include, reason}` contracts as
`generate_rank_input.py`. Rank output must cover the authoritative input
one-to-one. It derives deterministic component and signal buckets, then orders
rows with a component round-robin and stable risk tie breakers. `include` is
retained as evidence but never removes a row.

`hunt-balanced` assigns targeted passes from entry, sink, control, parser, and
state-transition signals, with a general review fallback. `hunt-max` always
assigns both directional passes plus applicable specialist passes.

Verification command.

```powershell
bun test --timeout 30000 tests-ts/hunt-workflow.test.ts
```

Commit message.

```text
feat: build the Hunt full-coverage frontier
```

## Task 2. Coverage closure and debt accounting

Files.

- Modify `sdk/typescript/_bundled_plugin/scripts/hunt_workflow.py`.
- Modify `sdk/typescript/tests-ts/hunt-workflow.test.ts`.

Tests first.

1. Supply one closure per frontier item and verify a zero-debt receipt.
2. Omit one closure and verify the command exits `2` with the exact missing
   work ID.
3. Mark one item `deferred` and verify the receipt records one coverage debt
   item without pretending it was reviewed.
4. Reject duplicate, unknown, or non-terminal closure rows.

Implementation contract.

```text
hunt_workflow.py close-frontier
  --frontier <frontier.jsonl>
  --closures <closures.jsonl>
  --out <coverage-receipt.json>
```

Closure status is `reviewed`, `no_candidate`, or `deferred`. Every row records
notes and candidate IDs. The output records component, signal, pass, and total
coverage plus explicit deferred work.

Commit message.

```text
feat: account for every Hunt review item
```

## Task 3. Blinded independent validation

Files.

- Modify `sdk/typescript/_bundled_plugin/scripts/hunt_workflow.py`.
- Modify `sdk/typescript/tests-ts/hunt-workflow.test.ts`.

Tests first.

1. Use normalized discovery candidates compatible with
   `normalize_candidates.py`.
2. Run `prepare-validation` and verify the output labels each claim as a
   hypothesis and omits discovery confidence or terminal conclusions.
3. Reject validation when `verifier_actor == discovery_actor`.
4. Reject `accepted` unless attacker control, reachability, impact, and guard
   failure are all `proven`, required source/root-control/sink locations are
   present, and concrete evidence and remediation exist.
5. Reject unsafe methods such as `poc`, `crash`, or remote interaction.
6. Require counterevidence for `rejected` and proof gaps for `inconclusive`.
7. Require exactly one validation row for every candidate.

Implementation contracts.

```text
hunt_workflow.py prepare-validation
  --candidates <normalized-candidates.jsonl>
  --out <validation-input.jsonl>

hunt_workflow.py validate-decisions
  --candidates <normalized-candidates.jsonl>
  --validations <validations.jsonl>
  --discovery-actor <actor-id>
  --out <validated-candidates.jsonl>
```

Allowed methods are `static_trace`, `existing_test`, `build`, `type_check`,
and `safe_invariant`. Each validated row contains the derived state history
`discovered -> evidence_built -> challenged -> accepted|rejected|inconclusive`.

Commit message.

```text
feat: enforce independent Hunt validation
```

## Task 4. Exact-root deduplication and accepted-only drafts

Files.

- Modify `sdk/typescript/_bundled_plugin/scripts/hunt_workflow.py`.
- Modify `sdk/typescript/tests-ts/hunt-workflow.test.ts`.

Tests first.

1. Give two accepted candidates the same CWE, root-control location, and sink
   location but different entry instances. Assert one finding retains both
   instances and candidate IDs.
2. Give two candidates different root-control or sink locations and assert
   they remain separate.
3. Include rejected and inconclusive candidates and assert neither appears in
   structured findings or Markdown.
4. Verify the draft includes title, affected locations, preconditions,
   source-to-operation trace, impact, validation evidence, confidence,
   remediation, and uncertainty, with no exploit or PoC section.

Implementation contract.

```text
hunt_workflow.py finalize
  --validated <validated-candidates.jsonl>
  --findings-out <accepted-findings.json>
  --report-out <draft-report.md>
  --receipt <finalization-receipt.json>
```

Deduplication uses only the normalized tuple of CWE IDs, root-control
locations, and sink locations. It never merges independently rooted or
independently sunk findings merely because their prose or family is similar.

Commit message.

```text
feat: finalize validated Hunt findings
```

## Task 5. Bundled skill integration

Files.

- Create `sdk/typescript/_bundled_plugin/skills/hunt-security-scan/SKILL.md`.
- Create
  `sdk/typescript/_bundled_plugin/skills/hunt-security-scan/agents/openai.yaml`.
- Create
  `sdk/typescript/_bundled_plugin/skills/hunt-security-scan/references/hunt-contract.md`.
- Modify `sdk/typescript/plugin-files.json`.
- Modify `sdk/typescript/tests-ts/hunt-workflow.test.ts`.

The skill must be explicit and experimental. It uses
`generate_rank_input.py make-repo-rank-input`, deterministic rank shards and
pool validation when ranking workers are available, and
`merge-rank-outputs`. It must never use `select-deep-review-input`; all rank
input rows flow into the Hunt frontier.

The coordinator maps the repository once, processes component batches, runs
forward and backward discovery as directed by the frontier, normalizes raw
candidates with `normalize_candidates.py`, closes every frontier row, delegates
the blinded validation input to a fresh independent verifier, validates every
decision, and finalizes accepted findings. The target source remains
unmodified; artifacts live in the requested Hunt work directory.

Tests assert every new bundled path appears in `plugin-files.json`, the skill
names both profiles, and the skill contains the safety and full-coverage rules.

Commit message.

```text
feat: bundle the experimental Hunt scan skill
```

## Task 6. Verification and compatibility review

Run these checks from `sdk/typescript`.

```powershell
bun test --timeout 30000 tests-ts/hunt-workflow.test.ts tests-ts/hermesbench.test.ts
corepack pnpm run types
corepack pnpm run format
corepack pnpm run check:package
```

Run the HermesBench Python suite from the repository root.

```powershell
python -m unittest discover -s benchmarks/hermesbench/tests -v
```

Then inspect the complete branch diff and search all new shipped files for
credentials, hidden labels, exploit or PoC instructions, debug output, file
eligibility drops, and accidental changes to `ScanMode`, public CLI options,
API routes, or SDK signatures.

The known pre-change Windows full-suite baseline is 1,800 passing, 63 skipped,
and 79 failing tests. Re-run the full fixed-seed suite and compare its failure
set to that baseline; do not claim a clean repository-wide run unless the
environmental ACL, symlink, and timeout failures are actually gone.

Commit any verification-only tracking update as a separate documentation
unit. Do not push the branch until the user requests publication.
