# Protocol 5 Paired-Flow Seeds Design

Date: 2026-08-30

## Goal

Increase Hunt discovery localization without adding a model call. Protocol 5 replaces the model-visible full semantic packet with a compact, deterministic set of investigation seeds that explicitly pair a plausible external entry with an exact critical structural site. The host still builds and hash-binds the full semantic graph, the model still inspects immutable source, and the verifier still independently validates every candidate.

This design optimizes the failed boundary measured by the Protocol 4 Canary. The host packet contained every retained vulnerable critical operation, but discovery localized none of the vulnerable entry points or critical operations. Aggregate diagnostics showed that candidates usually stayed near semantic locations while choosing the wrong entry-to-critical combination. The next unit therefore changes semantic presentation and attestation, not the parser family, model count, verifier independence, or scorer.

## Non-goals

- Do not generate exploits, payloads, persistence instructions, or unauthorized network activity.
- Do not add an adaptive scout, automatic retry, third model call, or paid benchmark run.
- Do not alter Protocol 1 through Protocol 4 prompt bytes, semantic bytes, evidence fields, or receipt reconstruction.
- Do not change Standard behavior, public finding schemas, scoring, candidate caps, final finding caps, sandbox policy, network policy, or authentication policy.
- Do not claim end-to-end recall or billed-cost improvement from host-only tests.
- Do not weaken rejection of unquoted shell operators. Command-compliance accounting is a separate bounded unit.

## Evidence and diagnosis

The completed Protocol 4 Canary produced 32 discovery candidates and zero exact entry, critical-operation, pair, or trace true positives. A private aggregate-only localization probe found the following properties without exposing task identities, paths, labels, or source text.

- All four vulnerable critical operations existed in the selected host semantic material.
- None of the four vulnerable entry sources existed in the selected semantic routes.
- Candidate locations were usually in the same files and often near semantic locations, but exact pair selection failed.
- The raw declaration scanner found exact entry declarations for only two of four vulnerable cases.

The failure is therefore two-part. Semantic presentation does not make the correct entry-to-critical relationship salient, and entry extraction is incomplete for cases where no defensible source anchor exists. Protocol 5 addresses both with paired seeds plus bounded sink-only and whole-frontier fallbacks.

## Alternatives

### A. Protocol 5 paired-flow seeds

Build a compact artifact from the existing single-pass scan. Each seed either binds a defensible entry to an exact critical site or preserves an unresolved critical site as a sink-only investigation root. Seed identity and endpoints are host-attested.

Benefits are explicit flow localization, substantially smaller model-visible guidance, strict measurement of seed use, and no extra model call. Costs are a new protocol version, artifact contract, and mutation tests.

This is the selected design.

### B. Tighten Protocol 4 prompts and semantic linkage

Require candidates to match current semantic rows exactly.

This is smaller in code, but it would change Protocol 4 bytes and mostly reject bad candidates. It cannot create missing entry recall or make the correct pair more salient.

### C. Add an adaptive discovery scout

Run a second independent discovery actor when the first actor is uncertain.

This can diversify hypotheses, but it raises the ceiling from two calls to three, increases cost and wall time, and gives another actor the same ambiguous semantic packet. It remains a later option only if a paired two-call architecture still fails a controlled benchmark.

## Protocol boundary

Protocol 5 is a separate evidence protocol. Protocols 1 through 4 remain reconstructable from their explicit version and retain their exact artifacts and prompts.

Protocol 5 keeps building `semantic-guidance.jsonl` with schema 3 because the full semantic hash remains part of trusted preparation evidence. The model does not read that file. Instead, discovery reads these two files exactly once and in order.

1. `/workspace/scratch/hermesbench-hunt/priority-packet.jsonl`
2. `/workspace/scratch/hermesbench-hunt/paired-flow-seeds.jsonl`

The full semantic artifact is host-only under Protocol 5. This reduces model-visible guidance while preserving an independently reproducible derivation chain.

## Seed artifact

The canonical file is `paired-flow-seeds.jsonl`. It contains UTF-8 JSON Lines with sorted keys, compact separators, LF line endings, and one terminal LF. Each row has exactly these fields.

```json
{
  "component": "component-id",
  "critical": {"family": "call", "line": 42, "path": "src/example.ts", "symbol": "write"},
  "eligible_search_passes": ["forward", "backward"],
  "entry": {"line": 7, "path": "src/example.ts", "symbol": "handle"},
  "proof_status": "investigation_only",
  "reason_codes": ["declaration-source", "parameter-flow"],
  "schema_version": 1,
  "seed_id": "seed-0123456789abcdef0123456789abcdef",
  "seed_kind": "paired-flow",
  "trace": [{"line": 12, "path": "src/example.ts", "symbol": "transform"}]
}
```

For `sink-only`, `entry` is `null`. `critical.family` is one of `call`, `assignment`, `mutation`, or an existing semantic operation family. Paths are canonical inventory paths. Lines are positive integers. Symbols are normalized, bounded investigation labels and never source instructions. `trace` contains at most four canonical locations. `reason_codes` contains only fixed public codes. `proof_status` is always `investigation_only`.

`seed_id` is `seed-` plus the first 32 lowercase hexadecimal characters of SHA-256 over the canonical logical row without `seed_id`. Preparation fails on any truncated-ID collision.

## Oracle-blind derivation

The builder receives only the pinned snapshot, full frontier contexts, profile, and the existing semantic scan result. It must not receive a manifest, task ID, advisory label, oracle path, expected finding, or prior model output.

Candidate seed pools are derived in this order.

1. Existing semantic routes with a source and operation become paired-flow seeds.
2. A declaration source and a structural site inside that same declaration become paired-flow seeds.
3. A parameter-flow structural site with no stronger source uses its enclosing declaration location as an investigation entry and becomes a paired-flow seed.
4. Remaining exact structural sites become sink-only seeds.

No pair may be created merely because two locations share a component, path neighborhood, risk token, or lexical similarity. A pair requires an existing route, same-declaration source relationship, or explicit parameter flow. This prevents the artifact from presenting proximity as data flow.

The implementation reuses the existing file scan and retains the declaration owner on structural sites. It must not rescan source files for Protocol 5.

## Deterministic selection and bounds

Seed construction deduplicates by kind, entry endpoint, and critical endpoint. Rows are assigned to four fixed lanes matching the derivation order. Each lane is ordered by canonical component, endpoint path, line, family, symbol, and seed ID. Selection performs deterministic component round-robin within the repeating lane schedule `paired-route`, `paired-source`, `paired-parameter`, `sink-only`.

The profile bounds are fixed.

| Profile | Maximum rows | Maximum bytes | Maximum row bytes |
| --- | ---: | ---: | ---: |
| `hunt-balanced` | 128 | 65,536 | 1,024 |
| `hunt-max` | 256 | 131,072 | 1,024 |

The selector skips a row that cannot fit the remaining byte budget and continues deterministically. It stops when no lane can contribute. These are output bounds, not targets. Empty seed output is valid when the scanner has no defensible route or structural site.

Sink-only rows remain in the fixed lane schedule so weak entry recall cannot erase exact critical roots. The normal priority packet and a bounded unseeded candidate allowance preserve whole-frontier exploration.

## Discovery contract

The Hunt discovery response schema remains unchanged. Protocol 5 interprets `finding_id` as follows.

- A seed-derived candidate copies one `seed_id` exactly into `finding_id`.
- A paired-flow candidate copies the exact one-line entry and critical endpoints from that same seed.
- A sink-only candidate copies the exact one-line critical endpoint from that seed and may supply any frontier-valid entry after source inspection.
- An unseeded fallback candidate uses a non-seed identifier and the existing frontier and search-pass rules.

If a non-empty seed artifact exists and discovery returns any candidates, at least one candidate must be seed-derived. At most four candidates may be unseeded fallbacks. The global maximum remains 12 candidates and the final maximum remains five findings.

For a seeded candidate, `search_pass` must be one of that seed's `eligible_search_passes`. Cross-seed endpoint combinations, unknown seed IDs, changed endpoint ranges, duplicate seed IDs, and seed-shaped fallback IDs fail closed. Trace, hypothesis, evidence, controls, and counterevidence still come from actual source inspection and do not become true merely because a seed exists.

## Attestation and evidence

`PreparedHuntArtifacts` records the seed artifact identity, SHA-256, byte count, row count, paired count, and sink-only count. Its preparation fingerprint includes the full semantic and seed artifact hashes.

Protocol 5 evidence adds exactly these fields to the Protocol 4 evidence fields.

- `paired_flow_seed_sha256`
- `paired_flow_seed_count`
- `paired_flow_candidate_count`
- `sink_only_candidate_count`
- `fallback_candidate_count`
- `seed_links_sha256`

`seed_links_sha256` commits a canonical path-free list of candidate ID, seed ID, seed kind, endpoint role, start line, end line, frontier work ID, and matching-pass work ID. It does not persist source paths, symbols, hypotheses, or findings.

New fixed public failure codes are limited to read and linkage failures.

- `hunt_paired_flow_seed_missing`
- `hunt_paired_flow_seed_duplicate`
- `hunt_paired_flow_candidate_mismatch`

Artifact mutation remains `hunt_evidence_artifact_integrity`. Ordinary frontier and search-pass violations retain existing public codes.

## Adapter and phase behavior

Protocol 5 selects the existing host-managed Hunt skill. The discovery prompt describes paired-flow, sink-only, and fallback rules; requires exact seed IDs and endpoints; and reiterates that guidance is not proof. It does not expose the full semantic file.

Verification receives the unchanged bounded projection of candidate identity and exact locations. It does not receive seed reason codes, discovery prose, semantic rows, or confidence. This preserves independent source validation.

Protocol 5 receives the same partial-phase recovery behavior as Protocol 4. Recoverable task failure becomes an empty result, zero-candidate verification remains local, retries remain zero, and all manifest tasks remain scored. The shell scanner continues to reject unquoted operators and substitutions.

## Compatibility

- Protocol 1 through Protocol 4 supported-version sets, serializers, parsers, prompts, managed-skill selection, semantic bytes, and receipts remain valid.
- Protocol 5 becomes the default only after every focused and full test passes.
- Controls with an explicit older protocol continue to select that protocol.
- The discovery and verification JSON schemas do not change.
- Standard does not prepare Hunt artifacts and does not select a Hunt skill.

## Verification gates

Implementation is acceptable only when all of the following pass.

1. A public RED test proves Protocol 5 is initially unsupported.
2. Canonical seed bytes are identical across repeated builds and frontier input order.
3. Mutating an unrelated oracle-like file outside the frontier cannot change seed bytes.
4. Synthetic route, source-linked structural, parameter-flow, sink-only, multi-component, disconnected, and empty fixtures behave as specified.
5. Row, byte, trace, symbol, and seed-count bounds fail closed or truncate deterministically.
6. Missing reads, duplicate reads, unknown IDs, endpoint mutation, cross-seed combinations, pass mismatch, too many fallbacks, and artifact mutation are rejected with fixed public codes.
7. Protocol 1 through Protocol 4 golden semantic bytes, prompt hashes, receipts, and failure behavior remain unchanged.
8. Protocol 5 discovery uses the managed skill, two packet reads, one discovery call, at most one verification call, 12 candidate slots, and five final finding slots.
9. Partial discovery, zero-candidate verification, partial verification, and complete workflow receipts remain deterministic.
10. The full no-model Python and TypeScript suites, compilation, formatting, snapshot integrity, and independent Critical/Important review pass.

After these gates, an aggregate-only private build may compare Protocol 4 and Protocol 5 entry, critical, pair, and trace seed coverage without a model. A paid Canary still requires fresh explicit authorization. Mini and Full remain blocked until a same-variable Canary shows positive discovery signal.
