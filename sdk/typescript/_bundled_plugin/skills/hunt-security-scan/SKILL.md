---
name: hunt-security-scan
description: Use when the user explicitly requests the experimental Hunt repository-wide vulnerability discovery workflow for an authorized local repository, especially for full coverage, bidirectional review, independent validation, or HermesBench comparison.
---

# Hunt Security Scan

Hunt is an experimental artifact-driven scan sibling. Standard remains unchanged.

Read [references/hunt-contract.md](references/hunt-contract.md) completely before creating Hunt artifacts.

## Invariants

- Ranking controls order, not eligibility. Preserve every authoritative inventory path, including `include: false` rows.
- Do not run `select-deep-review-input`. It is allowed to discard rows.
- Keep the target source unmodified. Write only to the requested Hunt work directory and do not use the network during evaluation.
- Do not generate exploits, proof-of-concept payloads, crash inputs, or remote attacks. Validate only with the safe methods in the contract.
- Give every frontier item and candidate exactly one terminal record. Deferred work remains visible coverage debt.
- Use a fresh verifier context whose actor identity differs from the discovery actor. Only accepted, exact-root-deduplicated findings enter the draft report.

## Profiles

| Profile | Use | Coverage rule |
| --- | --- | --- |
| `hunt-balanced` | Cost-efficient iteration | Cache the map and evidence; run signal-directed passes for every file. |
| `hunt-max` | Maximum discovery and final evidence | Run forward and backward for every file, plus applicable specialist passes. |

Use `hunt-max` when maximum discovery is requested. Cost controls may change batching, caching, and order; they never lower the coverage floor.

## Workflow

1. Resolve the repository, scope, target identity, plugin root, work directory, profile, and discovery actor. Generate `in-scope-files.txt` with `generate_in_scope_files.py` and authoritative `rank-input.jsonl` with `generate_rank_input.py make-repo-rank-input`.
2. If ranking workers are available, run `make-rank-shards`, `make-rank-pool-plan`, worker ranking, `validate-rank-worker`, `validate-rank-pool`, and `merge-rank-outputs`. Otherwise omit rank output and use the deterministic signal fallback.
3. Pass the resolved `--work-dir` and `--repository` to every `hunt_workflow.py` command. The directories must be disjoint and every helper input and output must remain inside the work directory. Run `make-frontier`, map once, and review priority batches. Join entry points, controls, and sinks across files; cache reusable maps and bounded evidence. Process every pass and write one closure per item.
4. Write raw discovery candidates using the contract, then run `normalize_candidates.py`. Run `hunt_workflow.py close-frontier`; missing, duplicate, or unknown work must fail closed.
5. Run `prepare-validation`. Give its blinded hypotheses and required source files to a fresh verifier. The verifier emits one safe decision per candidate; run `validate-decisions` to enforce proof and transitions.
6. Run `finalize` to produce accepted findings, the defensive draft report, and the finalization receipt. Do not add rejected or inconclusive prose manually.

If any validator fails, correct the rejected artifact and rerun that gate. Never bypass a gate, silently drop a row, or substitute self-validation.

## Common Mistakes

| Mistake | Required correction |
| --- | --- |
| Reusing a deep-review selection | Rebuild from the complete rank input. |
| Treating `deferred` as reviewed | Keep it as explicit coverage debt. |
| Using the discovery agent as verifier | Start a fresh actor and regenerate decisions. |
| Drafting before validation | Finalize only the validated terminal artifact. |
