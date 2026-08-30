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

The first explicit-row Protocol 5 selector did not pass the host gate. Under the balanced 64-KiB packet, exact critical, entry, and pair coverage were all zero even though the complete 60.6-MiB oracle-blind pool contained three exact critical tasks. Selector-only, readable bundle, dictionary-only, confidence-first, and frontier-priority variants also failed to retain an exact pair.

The selected amendment factors repeated data into path and component dictionaries, an entry bank, a critical bank, and bounded entry-to-critical adjacency. The balanced hybrid packet keeps 64 graph entries, retains the largest semantic-operation-ordered critical prefix that fits, and admits original Protocol 5 critical roots as standalone criticals. On the same held-out host gate it retained two exact critical tasks, increased exact entry tasks from zero to two, increased exact pairs from zero to one, and reduced aggregate model-visible bytes from the Protocol 4 control's 324,248 to 262,050. These are host input-coverage results, not model recall.

The product implementation initially reproduced the critical floor but lost one entry and the exact pair. A four-way aggregate A/B diagnostic isolated the loss to an approximate graph-entry representative, not adjacency ordering. Reusing the complete canonical graph-entry order solely as the internal representative key restored the diagnostic floor. The corrected product gate retained two exact critical tasks, two exact entry tasks, one exact pair, and four exact trace nodes in 262,028 aggregate model-visible bytes with exact snapshot and packet-hash integrity. End-to-end model recall remains unmeasured.

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

The canonical file remains `paired-flow-seeds.jsonl`, but Protocol 5 now uses factorized packet schema 2. It contains UTF-8 JSON Lines with sorted keys, compact separators, LF line endings, and one terminal LF. Rows have one of three exact shapes.

```json
{"c":[[1,"component-id"]],"p":[[1,"src/example.ts"]],"t":"d","v":2}
{"e":[[1,1,7,"handle"]],"t":"e","v":2}
{"t":"x","v":2,"x":[[1,1,42,"write","c",1,"fb",[[1,"f"]]]]}
```

`d` rows define consecutive path and component IDs. `e` rows define consecutive entry IDs as `[entry_id,path_id,line,symbol]`. `x` rows define consecutive critical IDs as `[critical_id,path_id,line,symbol,family_code,component_id,critical_pass_codes,adjacency]`. Each adjacency item is `[entry_id,pass_codes]`, and one critical has at most four adjacent entries. Empty adjacency is valid and represents a standalone critical investigation root.

Pass codes are ordered subsets of `f/b/g/p/s/x` for `forward/backward/guard/parser/state/general`. Fixed family codes cover structural `a/c/m` and semantic `command/query/file/template/deserialize/network/state/output-context`. Paths are canonical inventory paths, lines are positive integers, and symbols are normalized bounded investigation labels. The packet contains no source snippets, confidence, proof claim, oracle label, prior model output, or task identity.

## Oracle-blind derivation

The builder receives only the pinned snapshot, full frontier contexts, profile, and the existing schema-3 scan result. It must not receive a manifest, task ID, advisory label, oracle path, expected finding, or prior model output.

The existing route, declaration-source, parameter-flow, and sink-only candidate pool supplies critical roots and their eligible passes. The same scan's declaration graph supplies entry-to-critical adjacency as follows.

1. Declarations with a lexical source anchor become graph roots. The canonical declaration location is the investigation entry, while the minimum canonical source remains internal derivation evidence.
2. Existing resolved call edges are reversed into deterministic caller-to-target edges. Duplicate caller-target edges retain the strongest existing `direct`, `import-linked`, or `name-only` class.
3. Breadth-first propagation retains the shortest deterministic path, at most four roots per declaration, the existing profile graph-depth bound, and a fixed work ceiling.
4. Structural sites owned by a reached declaration become adjacent criticals. The edge is investigation guidance only and never proof of attacker control, reachability, or impact.
5. Original Protocol 5 criticals that have no retained graph entry remain standalone criticals rather than being discarded.

No pair may be created merely because locations share a component, path neighborhood, risk token, priority score, confidence class, or lexical similarity. The implementation reuses the existing scan, declarations, structural sites, and resolved edges and must not rescan source files.

## Deterministic selection and bounds

Entry endpoints are deduplicated and ordered by deterministic component round-robin. `hunt-balanced` retains at most 64 entries and `hunt-max` at most 128. Critical endpoints are deduplicated by canonical endpoint and fixed family, merge graph adjacency with original critical-root pass eligibility, and are ordered by selected semantic operation rank followed by canonical key. Each critical retains at most four adjacent selected entries ordered by shortest graph trace and canonical row.

The profile bounds are fixed.

| Profile | Maximum entries | Maximum rows | Maximum bytes | Maximum row bytes |
| --- | ---: | ---: | ---: | ---: |
| `hunt-balanced` | 64 | 128 | 65,536 | 1,024 |
| `hunt-max` | 128 | 256 | 131,072 | 1,024 |

After dictionaries and the complete bounded entry bank are fixed, a deterministic binary search retains the largest prefix of semantic-ordered criticals whose canonical packet satisfies every bound. Generation and later parsing both reject noncanonical rows, duplicate or nonconsecutive IDs, unknown dictionary references, invalid codes, duplicate adjacency, more than four adjacent entries, and any bound violation.

## Discovery contract

The Hunt discovery response schema remains unchanged. Protocol 5 interprets `finding_id` as follows.

- `join-e<entry_id>-c<critical_id>` selects one exact retained adjacency and must copy that entry and critical as one-line endpoints.
- `sink-c<critical_id>` selects one exact critical and may supply any frontier-valid entry after source inspection.
- Any other non-reserved identifier is an unseeded fallback under the existing frontier and search-pass rules.

A joined candidate uses the adjacency pass codes. A sink candidate uses the critical pass codes. Unknown IDs, nonadjacent entry-critical combinations, changed endpoint ranges, pass mismatch, duplicate reserved IDs, and reserved-shaped fallbacks fail closed. If the packet exposes any addressable seeds and discovery returns candidates, at least one candidate must use a retained join or sink ID. At most four candidates may be unseeded fallbacks. The global maximum remains 12 candidates and the final maximum remains five findings.

Trace, hypothesis, evidence, controls, and counterevidence still come from actual source inspection. Dictionary membership, a standalone critical, or graph adjacency is guidance, never proof.

## Attestation and evidence

`PreparedHuntArtifacts` records the packet identity, SHA-256, byte count, physical row count, adjacency count, and critical count. Its preparation fingerprint includes the full host-only semantic hash and the factorized packet hash. Existing `paired_flow_*` field names remain the Protocol 5 public evidence vocabulary, while `paired_flow_seed_count` counts addressable join plus sink IDs rather than physical JSONL rows.

Protocol 5 evidence continues to add these fields to the Protocol 4 evidence fields.

- `paired_flow_seed_sha256`
- `paired_flow_seed_count`
- `paired_flow_candidate_count`
- `sink_only_candidate_count`
- `fallback_candidate_count`
- `seed_links_sha256`

`seed_links_sha256` commits a canonical path-free list of candidate ID, retained join or sink ID, seed kind, endpoint role, start line, end line, frontier work ID, and matching-pass work ID. It does not persist source paths, symbols, hypotheses, or findings.

The existing fixed public failure codes remain unchanged.

- `hunt_paired_flow_seed_missing`
- `hunt_paired_flow_seed_duplicate`
- `hunt_paired_flow_candidate_mismatch`

Artifact mutation remains `hunt_evidence_artifact_integrity`. Ordinary frontier and search-pass violations retain existing public codes.

## Adapter and phase behavior

Protocol 5 selects the existing host-managed Hunt skill. The discovery prompt describes dictionary, entry, critical, adjacency, sink, and fallback rules; requires exact retained IDs and endpoints; and reiterates that guidance is not proof. It does not expose the full semantic file.

Verification receives the unchanged bounded projection of candidate identity and exact locations. It does not receive seed reason codes, discovery prose, semantic rows, or confidence. This preserves independent source validation.

Protocol 5 receives the same partial-phase recovery behavior as Protocol 4. Recoverable task failure becomes an empty result, zero-candidate verification remains local, retries remain zero, and all manifest tasks remain scored. The shell scanner continues to reject unquoted operators and substitutions.

## Compatibility

- Protocol 1 through Protocol 4 supported-version sets, serializers, parsers, prompts, managed-skill selection, semantic bytes, and receipts remain valid.
- The pre-factor Protocol 5 packet schema is superseded before any paid Protocol 5 benchmark. No Protocol 1 through Protocol 4 receipt or explicit control is reinterpreted.
- Protocol 5 remains the default only after every amended focused and full test passes.
- Controls with an explicit older protocol continue to select that protocol.
- The discovery and verification JSON schemas do not change.
- Standard does not prepare Hunt artifacts and does not select a Hunt skill.

## Verification gates

Implementation is acceptable only when all of the following pass.

1. Canonical factorized bytes are identical across repeated builds, frontier order, and equivalent declaration order.
2. Mutating an unrelated oracle-like file outside the frontier cannot change packet bytes.
3. Synthetic direct, import-linked, name-only, multi-root, standalone-critical, disconnected, and empty fixtures behave as specified without a second source scan.
4. Entry, adjacency, graph-depth, graph-work, row, byte, row-byte, symbol, family, pass, dictionary, and reference bounds fail closed or truncate deterministically.
5. Missing reads, duplicate reads, unknown IDs, nonadjacent joins, endpoint mutation, pass mismatch, too many fallbacks, reserved-shaped fallbacks, and artifact mutation are rejected with fixed public codes.
6. Protocol 1 through Protocol 4 golden semantic bytes, prompt hashes, evidence, receipts, and failure behavior remain unchanged.
7. Protocol 5 discovery uses the managed skill, two packet reads, one discovery call, at most one verification call, 12 candidate slots, and five final finding slots.
8. Partial discovery, zero-candidate verification, partial verification, complete workflow receipts, and factorized evidence reproduction remain deterministic.
9. The balanced host gate retains at least two exact critical tasks, increases exact entry and pair coverage over both the current Protocol 5 selector and Protocol 4 control, and remains smaller than the Protocol 4 model-visible guidance bytes.
10. The full no-model Python and TypeScript suites, compilation, formatting, snapshot integrity, and independent Critical/Important review pass.

After these gates, an aggregate-only private build may compare Protocol 4 and Protocol 5 entry, critical, pair, and trace seed coverage without a model. A paid Canary still requires fresh explicit authorization. Mini and Full remain blocked until a same-variable Canary shows positive discovery signal.
