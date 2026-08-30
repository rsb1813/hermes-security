"""Host-side deterministic artifacts and path-free evidence for Hunt discovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from benchmarks.hermesbench.hunt_protocol import HUNT_SEARCH_PASSES
from benchmarks.hermesbench.semantic_guidance import (
    LEGACY_SEMANTIC_GUIDANCE_SCHEMA_VERSION,
    PASS_ANNOTATED_SEMANTIC_GUIDANCE_SCHEMA_VERSION,
    SEMANTIC_GUIDANCE_SCHEMA_VERSION,
    build_semantic_guidance,
)


PLAN_DIRECTORY = "hermesbench-hunt"
INVENTORY_NAME = "in-scope-files.txt"
RANK_INPUT_NAME = "rank-input.jsonl"
FRONTIER_NAME = "frontier.jsonl"
FRONTIER_RECEIPT_NAME = "frontier-receipt.json"
PRIORITY_PACKET_NAME = "priority-packet.jsonl"
SEMANTIC_GUIDANCE_NAME = "semantic-guidance.jsonl"
PAIRED_FLOW_SEEDS_NAME = "paired-flow-seeds.jsonl"
LEGACY_HUNT_EVIDENCE_PROTOCOL_VERSION = 1
SEMANTIC_GUIDANCE_HUNT_EVIDENCE_PROTOCOL_VERSION = 2
PASS_ANNOTATED_HUNT_EVIDENCE_PROTOCOL_VERSION = 3
NESTED_OUTPUT_HUNT_EVIDENCE_PROTOCOL_VERSION = 4
PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION = 5
HUNT_EVIDENCE_PROTOCOL_VERSION = NESTED_OUTPUT_HUNT_EVIDENCE_PROTOCOL_VERSION
SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS = frozenset({1, 2, 3, 4})
_PREPARATION_HUNT_EVIDENCE_PROTOCOL_VERSIONS = SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS | frozenset({PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION})
_ATTESTATION_HUNT_EVIDENCE_PROTOCOL_VERSIONS = _PREPARATION_HUNT_EVIDENCE_PROTOCOL_VERSIONS
_SEMANTIC_HUNT_EVIDENCE_PROTOCOL_VERSIONS = frozenset({2, 3, 4, 5})
MAX_INVENTORY_ROWS = 100_000
MAX_INVENTORY_BYTES = 8 * 1024 * 1024
MAX_RANK_INPUT_BYTES = 32 * 1024 * 1024
MAX_FRONTIER_ROWS = 100_000
MAX_FRONTIER_BYTES = 32 * 1024 * 1024
MAX_FRONTIER_RECEIPT_BYTES = 64 * 1024
MAX_PRIORITY_PACKET_BYTES = 1024 * 1024
MAX_SEMANTIC_GUIDANCE_BYTES = 1024 * 1024
MAX_PAIRED_FLOW_SEEDS_BYTES = 128 * 1024
MAX_PAIRED_FLOW_SEED_ROWS = 256
PRIORITY_ROW_LIMITS = {"hunt-balanced": 512, "hunt-max": 1024}
PRIORITY_PREVIEW_BYTES = 384
_REQUIRED_PACKET_READ = ("cat", "/workspace/scratch/hermesbench-hunt/priority-packet.jsonl")
_REQUIRED_SEMANTIC_READ = ("cat", "/workspace/scratch/hermesbench-hunt/semantic-guidance.jsonl")
_REQUIRED_PAIRED_FLOW_SEEDS_READ = ("cat", "/workspace/scratch/hermesbench-hunt/paired-flow-seeds.jsonl")
_PLUGIN_SCRIPTS = Path(__file__).resolve().parents[2] / "sdk" / "typescript" / "_bundled_plugin" / "scripts"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PAIRED_FLOW_SEED_ID = re.compile(r"seed-[0-9a-f]{32}\Z")
HUNT_EVIDENCE_FIELDS_V1 = frozenset({
    "schema_version", "profile", "inventory_sha256", "inventory_count", "rank_input_sha256",
    "frontier_sha256", "frontier_count", "frontier_pass_count", "priority_packet_sha256",
    "priority_packet_count", "candidate_links_sha256", "candidate_count", "linked_location_count",
    "coverage_debt_sha256", "coverage_debt_count", "validated_closure_count",
})
HUNT_EVIDENCE_FIELDS_V2 = HUNT_EVIDENCE_FIELDS_V1 | frozenset({
    "semantic_guidance_sha256",
    "semantic_guidance_count",
    "semantic_guidance_edge_count",
    "semantic_guidance_scanned_file_count",
    "semantic_guidance_skipped_file_count",
})
HUNT_EVIDENCE_FIELDS_V3 = HUNT_EVIDENCE_FIELDS_V2
HUNT_EVIDENCE_FIELDS_V4 = HUNT_EVIDENCE_FIELDS_V3
HUNT_EVIDENCE_FIELDS_V5 = HUNT_EVIDENCE_FIELDS_V4 | frozenset({
    "paired_flow_seed_sha256",
    "paired_flow_seed_count",
    "paired_flow_candidate_count",
    "sink_only_candidate_count",
    "fallback_candidate_count",
    "seed_links_sha256",
})
HUNT_EVIDENCE_FIELDS = HUNT_EVIDENCE_FIELDS_V3
HUNT_EVIDENCE_FAILURE_CODES = frozenset({
    "hunt_evidence_packet_missing",
    "hunt_evidence_packet_duplicate",
    "hunt_evidence_artifact_integrity",
    "hunt_evidence_candidate_location",
    "hunt_evidence_candidate_search_pass",
    "hunt_semantic_guidance_missing",
    "hunt_semantic_guidance_duplicate",
    "hunt_paired_flow_seed_missing",
    "hunt_paired_flow_seed_duplicate",
    "hunt_paired_flow_candidate_mismatch",
})


class HuntEvidenceError(ValueError):
    """Signals a Hunt artifact or attestation contract failure."""

    def __init__(self, message: str, *, category: str | None = None) -> None:
        if category is not None and category not in HUNT_EVIDENCE_FAILURE_CODES:
            raise ValueError("Hunt evidence failure category is unsupported")
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class _Artifact:
    path: Path
    identity: tuple[int, int, int, int]
    sha256: str
    byte_count: int


@dataclass(frozen=True)
class PreparedHuntArtifacts:
    """Binds the trusted preparation files to one future Hunt container execution."""

    plan_directory: Path
    profile: str
    evidence_protocol_version: int
    inventory: _Artifact
    rank_input: _Artifact
    frontier: _Artifact
    frontier_receipt: _Artifact
    priority_packet: _Artifact
    semantic_guidance: _Artifact | None
    paired_flow_seeds: _Artifact | None
    inventory_count: int
    frontier_count: int
    frontier_pass_count: int
    priority_count: int
    priority_bytes: int
    semantic_guidance_row_count: int | None
    semantic_guidance_edge_count: int | None
    semantic_guidance_scanned_file_count: int | None
    semantic_guidance_skipped_file_count: int | None
    paired_flow_seeds_row_count: int | None
    paired_flow_seeds_paired_count: int | None
    paired_flow_seeds_sink_only_count: int | None
    preparation_fingerprint: str
    preparation_seconds: float
    container_priority_packet_path: str = "/workspace/scratch/hermesbench-hunt/priority-packet.jsonl"


@dataclass(frozen=True)
class HuntEvidence:
    """Provides only path-free persistent evidence for one discovery prediction."""

    protocol_version: int
    profile: str
    inventory_sha256: str
    inventory_count: int
    rank_input_sha256: str
    frontier_sha256: str
    frontier_count: int
    frontier_pass_count: int
    priority_packet_sha256: str
    priority_packet_count: int
    candidate_links_sha256: str
    candidate_count: int
    linked_location_count: int
    coverage_debt_sha256: str
    coverage_debt_count: int
    semantic_guidance_sha256: str | None
    semantic_guidance_count: int | None
    semantic_guidance_edge_count: int | None
    semantic_guidance_scanned_file_count: int | None
    semantic_guidance_skipped_file_count: int | None
    paired_flow_seed_sha256: str | None
    paired_flow_seed_count: int | None
    paired_flow_candidate_count: int | None
    sink_only_candidate_count: int | None
    fallback_candidate_count: int | None
    seed_links_sha256: str | None

    @property
    def validated_closure_count(self) -> int:
        return 0

    def to_json(self) -> dict[str, object]:
        value = {
            "schema_version": self.protocol_version,
            "profile": self.profile,
            "inventory_sha256": self.inventory_sha256,
            "inventory_count": self.inventory_count,
            "rank_input_sha256": self.rank_input_sha256,
            "frontier_sha256": self.frontier_sha256,
            "frontier_count": self.frontier_count,
            "frontier_pass_count": self.frontier_pass_count,
            "priority_packet_sha256": self.priority_packet_sha256,
            "priority_packet_count": self.priority_packet_count,
            "candidate_links_sha256": self.candidate_links_sha256,
            "candidate_count": self.candidate_count,
            "linked_location_count": self.linked_location_count,
            "coverage_debt_sha256": self.coverage_debt_sha256,
            "coverage_debt_count": self.coverage_debt_count,
            "validated_closure_count": 0,
        }
        if _uses_semantic_guidance(self.protocol_version):
            value |= {
                "semantic_guidance_sha256": self.semantic_guidance_sha256,
                "semantic_guidance_count": self.semantic_guidance_count,
                "semantic_guidance_edge_count": self.semantic_guidance_edge_count,
                "semantic_guidance_scanned_file_count": self.semantic_guidance_scanned_file_count,
                "semantic_guidance_skipped_file_count": self.semantic_guidance_skipped_file_count,
            }
        if self.protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
            value |= {
                "paired_flow_seed_sha256": self.paired_flow_seed_sha256,
                "paired_flow_seed_count": self.paired_flow_seed_count,
                "paired_flow_candidate_count": self.paired_flow_candidate_count,
                "sink_only_candidate_count": self.sink_only_candidate_count,
                "fallback_candidate_count": self.fallback_candidate_count,
                "seed_links_sha256": self.seed_links_sha256,
            }
        return value


def parse_hunt_evidence(
    value: object,
    profile: str | None = None,
    *,
    evidence_protocol_version: int | None = None,
) -> dict[str, object]:
    """Validates the exact path-free evidence serialization before persistence."""
    if not isinstance(value, dict):
        raise HuntEvidenceError("Hunt evidence fields are invalid")
    version = value.get("schema_version")
    if not _supported_attestation_protocol_version(version):
        raise HuntEvidenceError("Hunt evidence schema version is invalid")
    if evidence_protocol_version is not None and (
        not _supported_attestation_protocol_version(evidence_protocol_version) or version != evidence_protocol_version
    ):
        raise HuntEvidenceError("Hunt evidence schema version is invalid")
    fields = _evidence_fields(version)
    if set(value) != fields:
        raise HuntEvidenceError("Hunt evidence fields are invalid")
    if value["profile"] not in PRIORITY_ROW_LIMITS or (profile is not None and value["profile"] != profile):
        raise HuntEvidenceError("Hunt evidence profile is invalid")
    hashes = (
        "inventory_sha256", "rank_input_sha256", "frontier_sha256", "priority_packet_sha256",
        "candidate_links_sha256", "coverage_debt_sha256",
    )
    if _uses_semantic_guidance(version):
        hashes += ("semantic_guidance_sha256",)
    if version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
        hashes += ("paired_flow_seed_sha256", "seed_links_sha256")
    for field in hashes:
        if not isinstance(value[field], str) or _SHA256.fullmatch(value[field]) is None:
            raise HuntEvidenceError("Hunt evidence hash is invalid")
    counts = (
        "inventory_count", "frontier_count", "frontier_pass_count", "priority_packet_count",
        "candidate_count", "linked_location_count", "coverage_debt_count", "validated_closure_count",
    )
    if _uses_semantic_guidance(version):
        counts += (
            "semantic_guidance_count",
            "semantic_guidance_edge_count",
            "semantic_guidance_scanned_file_count",
            "semantic_guidance_skipped_file_count",
        )
    if version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
        counts += (
            "paired_flow_seed_count",
            "paired_flow_candidate_count",
            "sink_only_candidate_count",
            "fallback_candidate_count",
        )
    for field in counts:
        if isinstance(value[field], bool) or not isinstance(value[field], int) or value[field] < 0:
            raise HuntEvidenceError("Hunt evidence count is invalid")
    if value["validated_closure_count"] != 0 or value["linked_location_count"] < value["candidate_count"]:
        raise HuntEvidenceError("Hunt evidence closure state is invalid")
    if version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION and (
        value["paired_flow_candidate_count"] + value["sink_only_candidate_count"] + value["fallback_candidate_count"] != value["candidate_count"]
        or value["paired_flow_candidate_count"] + value["sink_only_candidate_count"] > value["paired_flow_seed_count"]
        or value["fallback_candidate_count"] > 4
    ):
        raise HuntEvidenceError("Hunt evidence seed counts are invalid")
    return dict(value)


def prepare_hunt_artifacts(
    snapshot_path: Path,
    scratch_path: Path,
    profile: str,
    *,
    evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION,
) -> PreparedHuntArtifacts:
    """Creates and records the complete immutable Hunt plan using bundled helpers."""
    if profile not in PRIORITY_ROW_LIMITS or not _supported_preparation_protocol_version(evidence_protocol_version):
        raise HuntEvidenceError("Hunt profile is unsupported")
    snapshot = _safe_directory(snapshot_path, "snapshot")
    scratch = _safe_directory(scratch_path, "scratch", create=True)
    plan = scratch / PLAN_DIRECTORY
    if plan.exists() or plan.is_symlink():
        raise HuntEvidenceError("Hunt plan directory already exists")
    plan.mkdir()
    started = time.monotonic()
    inventory = plan / INVENTORY_NAME
    rank_input = plan / RANK_INPUT_NAME
    frontier = plan / FRONTIER_NAME
    receipt = plan / FRONTIER_RECEIPT_NAME
    priority_packet = plan / PRIORITY_PACKET_NAME
    semantic_guidance_path = plan / SEMANTIC_GUIDANCE_NAME
    paired_flow_seeds_path = plan / PAIRED_FLOW_SEEDS_NAME
    _run_helper("generate_in_scope_files.py", ("--repo", str(snapshot), "--scope", ".", "--out", str(inventory)))
    _run_helper("generate_rank_input.py", ("make-repo-rank-input", "--repo", str(snapshot), "--scope", ".", "--out", str(rank_input)))
    _normalize_lf(inventory, "inventory")
    _normalize_lf(rank_input, "rank input")
    _run_helper("hunt_workflow.py", ("make-frontier", "--work-dir", str(plan), "--repository", str(snapshot), "--rank-input", str(rank_input), "--profile", profile, "--out", str(frontier), "--receipt", str(receipt)))
    _normalize_lf(frontier, "frontier")
    inventory_paths = _inventory_paths(inventory)
    rank_rows = _jsonl_rows(rank_input, "rank input", MAX_RANK_INPUT_BYTES, None)
    frontier_rows = _jsonl_rows(frontier, "frontier", MAX_FRONTIER_BYTES, MAX_FRONTIER_ROWS)
    rank_by_path = _validate_rank_rows(rank_rows, inventory_paths)
    _validate_frontier_rows(frontier_rows, set(rank_by_path))
    frontier_contexts = tuple(
        (
            str(row["path"]),
            str(row["component"]),
            tuple(str(value) for value in row["passes"]),
        )
        for row in frontier_rows
    )
    priority_rows = _priority_rows(frontier_rows, rank_by_path, PRIORITY_ROW_LIMITS[profile])
    _write_jsonl(priority_packet, priority_rows)
    artifacts = {
        "inventory": _record(inventory, "inventory"),
        "rank_input": _record(rank_input, "rank input"),
        "frontier": _record(frontier, "frontier"),
        "frontier_receipt": _record(receipt, "frontier receipt"),
        "priority_packet": _record(priority_packet, "priority packet"),
    }
    semantic_guidance = None
    semantic_counts = (None, None, None, None)
    paired_flow_seeds = None
    paired_flow_seed_counts = (None, None, None)
    if _uses_semantic_guidance(evidence_protocol_version):
        guidance = build_semantic_guidance(
            snapshot,
            frontier_contexts,
            profile,
            guidance_schema_version=_semantic_guidance_schema_version(evidence_protocol_version),
            include_paired_flow_seeds=evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION,
        )
        semantic_guidance_path.write_bytes(guidance.canonical_bytes)
        semantic_guidance = _record(semantic_guidance_path, "semantic guidance")
        artifacts["semantic_guidance"] = semantic_guidance
        semantic_counts = (
            guidance.row_count,
            guidance.edge_count,
            guidance.scanned_file_count,
            guidance.skipped_file_count,
        )
        if evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
            if guidance.paired_flow_seeds is None:
                raise HuntEvidenceError("paired flow seeds are unavailable")
            paired_flow_seeds_path.write_bytes(guidance.paired_flow_seeds.canonical_bytes)
            paired_flow_seeds = _record(paired_flow_seeds_path, "paired flow seeds")
            artifacts["paired_flow_seeds"] = paired_flow_seeds
            paired_flow_seed_counts = (
                guidance.paired_flow_seeds.row_count,
                guidance.paired_flow_seeds.paired_count,
                guidance.paired_flow_seeds.sink_only_count,
            )
    passes = {(str(row["work_id"]), value) for row in frontier_rows for value in row["passes"]}
    fingerprint = _canonical_sha256({name: artifact.sha256 for name, artifact in artifacts.items()} | {"profile": profile})
    return PreparedHuntArtifacts(
        plan_directory=plan,
        profile=profile,
        evidence_protocol_version=evidence_protocol_version,
        inventory=artifacts["inventory"],
        rank_input=artifacts["rank_input"],
        frontier=artifacts["frontier"],
        frontier_receipt=artifacts["frontier_receipt"],
        priority_packet=artifacts["priority_packet"],
        semantic_guidance=semantic_guidance,
        paired_flow_seeds=paired_flow_seeds,
        inventory_count=len(inventory_paths),
        frontier_count=len(frontier_rows),
        frontier_pass_count=len(passes),
        priority_count=len(priority_rows),
        priority_bytes=artifacts["priority_packet"].byte_count,
        semantic_guidance_row_count=semantic_counts[0],
        semantic_guidance_edge_count=semantic_counts[1],
        semantic_guidance_scanned_file_count=semantic_counts[2],
        semantic_guidance_skipped_file_count=semantic_counts[3],
        paired_flow_seeds_row_count=paired_flow_seed_counts[0],
        paired_flow_seeds_paired_count=paired_flow_seed_counts[1],
        paired_flow_seeds_sink_only_count=paired_flow_seed_counts[2],
        preparation_fingerprint=fingerprint,
        preparation_seconds=time.monotonic() - started,
    )


def attest_hunt_discovery(prepared: PreparedHuntArtifacts, prediction: object, observed_argv: tuple[tuple[str, ...], ...]) -> HuntEvidence:
    """Checks prepared bytes and binds a valid discovery result without source paths."""
    if not isinstance(prepared, PreparedHuntArtifacts):
        raise HuntEvidenceError("prepared Hunt artifacts are invalid")
    if not isinstance(observed_argv, tuple) or observed_argv.count(_REQUIRED_PACKET_READ) == 0:
        raise HuntEvidenceError("priority packet was not read", category="hunt_evidence_packet_missing")
    if observed_argv.count(_REQUIRED_PACKET_READ) != 1:
        raise HuntEvidenceError("priority packet was read more than once", category="hunt_evidence_packet_duplicate")
    if prepared.evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
        if observed_argv.count(_REQUIRED_PAIRED_FLOW_SEEDS_READ) == 0:
            raise HuntEvidenceError("paired flow seeds were not read", category="hunt_paired_flow_seed_missing")
        if observed_argv.count(_REQUIRED_PAIRED_FLOW_SEEDS_READ) != 1:
            raise HuntEvidenceError("paired flow seeds were read more than once", category="hunt_paired_flow_seed_duplicate")
        if observed_argv.index(_REQUIRED_PACKET_READ) > observed_argv.index(_REQUIRED_PAIRED_FLOW_SEEDS_READ):
            raise HuntEvidenceError("Hunt packet reads are out of order")
    elif _uses_semantic_guidance(prepared.evidence_protocol_version):
        if observed_argv.count(_REQUIRED_SEMANTIC_READ) == 0:
            raise HuntEvidenceError("semantic guidance was not read", category="hunt_semantic_guidance_missing")
        if observed_argv.count(_REQUIRED_SEMANTIC_READ) != 1:
            raise HuntEvidenceError("semantic guidance was read more than once", category="hunt_semantic_guidance_duplicate")
        if observed_argv.index(_REQUIRED_PACKET_READ) > observed_argv.index(_REQUIRED_SEMANTIC_READ):
            raise HuntEvidenceError("Hunt packet reads are out of order")
    try:
        for artifact, label in ((prepared.inventory, "inventory"), (prepared.rank_input, "rank input"), (prepared.frontier, "frontier"), (prepared.frontier_receipt, "frontier receipt"), (prepared.priority_packet, "priority packet")):
            _verify_record(artifact, label)
        inventory_paths = _inventory_paths_value(_read_pinned_bytes(prepared.inventory, "inventory", MAX_INVENTORY_BYTES))
        rank_rows = _jsonl_rows_value(_read_pinned_bytes(prepared.rank_input, "rank input", MAX_RANK_INPUT_BYTES), "rank input", None)
        frontier_rows = _jsonl_rows_value(_read_pinned_bytes(prepared.frontier, "frontier", MAX_FRONTIER_BYTES), "frontier", MAX_FRONTIER_ROWS)
        rank_by_path = _validate_rank_rows(rank_rows, inventory_paths)
        frontier_by_path = _validate_frontier_rows(frontier_rows, set(rank_by_path))
        _validate_frontier_receipt(_read_pinned_bytes(prepared.frontier_receipt, "frontier receipt", MAX_FRONTIER_RECEIPT_BYTES), prepared.profile, prepared.rank_input.sha256, len(frontier_rows))
        paired_flow_seeds_by_id: dict[str, dict[str, object]] = {}
        if _uses_semantic_guidance(prepared.evidence_protocol_version):
            if prepared.semantic_guidance is None or any(value is None for value in (
                prepared.semantic_guidance_row_count,
                prepared.semantic_guidance_edge_count,
                prepared.semantic_guidance_scanned_file_count,
                prepared.semantic_guidance_skipped_file_count,
            )):
                raise HuntEvidenceError("semantic guidance is unavailable")
            _verify_record(prepared.semantic_guidance, "semantic guidance")
            _read_pinned_bytes(prepared.semantic_guidance, "semantic guidance", MAX_SEMANTIC_GUIDANCE_BYTES)
        if prepared.evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
            if prepared.paired_flow_seeds is None or any(value is None for value in (
                prepared.paired_flow_seeds_row_count,
                prepared.paired_flow_seeds_paired_count,
                prepared.paired_flow_seeds_sink_only_count,
            )):
                raise HuntEvidenceError("paired flow seeds are unavailable")
            _verify_record(prepared.paired_flow_seeds, "paired flow seeds")
            paired_flow_seeds_by_id = _paired_flow_seed_rows(
                _read_pinned_bytes(prepared.paired_flow_seeds, "paired flow seeds", MAX_PAIRED_FLOW_SEEDS_BYTES)
            )
            if (
                len(paired_flow_seeds_by_id) != prepared.paired_flow_seeds_row_count
                or sum(row["seed_kind"] == "paired-flow" for row in paired_flow_seeds_by_id.values()) != prepared.paired_flow_seeds_paired_count
                or sum(row["seed_kind"] == "sink-only" for row in paired_flow_seeds_by_id.values()) != prepared.paired_flow_seeds_sink_only_count
            ):
                raise HuntEvidenceError("paired flow seed counts are invalid")
    except HuntEvidenceError as error:
        raise HuntEvidenceError("prepared Hunt artifacts are invalid", category="hunt_evidence_artifact_integrity") from error
    candidates = getattr(prediction, "candidates", None)
    if not isinstance(candidates, tuple):
        raise HuntEvidenceError("Hunt discovery prediction is invalid")
    links: list[dict[str, object]] = []
    seed_links: list[dict[str, object]] = []
    paired_flow_candidate_count = 0
    sink_only_candidate_count = 0
    fallback_candidate_count = 0
    for candidate in candidates:
        candidate_id = getattr(candidate, "finding_id", None)
        search_pass = getattr(candidate, "search_pass", None)
        locations = (("entry_point", 0, getattr(candidate, "entry_point", None)), ("critical_operation", 0, getattr(candidate, "critical_operation", None)))
        trace = tuple(("trace", index, location) for index, location in enumerate(getattr(candidate, "trace", ())))
        seed = None
        if prepared.evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
            seed = paired_flow_seeds_by_id.get(candidate_id) if isinstance(candidate_id, str) else None
            if seed is None:
                if not isinstance(candidate_id, str) or candidate_id.startswith("seed-"):
                    _paired_flow_candidate_mismatch()
                fallback_candidate_count += 1
            elif seed["seed_kind"] == "paired-flow":
                if not _seed_endpoint_matches(getattr(candidate, "entry_point", None), seed["entry"]) or not _seed_endpoint_matches(getattr(candidate, "critical_operation", None), seed["critical"]) or search_pass not in seed["eligible_search_passes"]:
                    _paired_flow_candidate_mismatch()
                paired_flow_candidate_count += 1
            else:
                if not _seed_endpoint_matches(getattr(candidate, "critical_operation", None), seed["critical"]) or search_pass not in seed["eligible_search_passes"]:
                    _paired_flow_candidate_mismatch()
                sink_only_candidate_count += 1
        matching_pass = False
        for role, trace_index, location in (*locations, *trace):
            path = getattr(location, "path", None)
            start_line = getattr(location, "start_line", None)
            end_line = getattr(location, "end_line", None)
            if not isinstance(candidate_id, str) or not isinstance(path, str) or path not in inventory_paths or path not in frontier_by_path:
                raise HuntEvidenceError("candidate location is outside the complete frontier", category="hunt_evidence_candidate_location")
            row = frontier_by_path[path]
            if search_pass in row["passes"]:
                matching_pass = True
            links.append({"candidate_id": candidate_id, "role": role, "trace_index": trace_index, "start_line": start_line, "end_line": end_line, "work_id": row["work_id"], "matching_pass_work_id": row["work_id"] if search_pass in row["passes"] else None})
            if seed is not None and role in {"entry_point", "critical_operation"}:
                endpoint = seed["entry"] if role == "entry_point" else seed["critical"]
                if endpoint is not None:
                    seed_links.append({"candidate_id": candidate_id, "seed_id": seed["seed_id"], "seed_kind": seed["seed_kind"], "endpoint_role": role, "start_line": start_line, "end_line": end_line, "work_id": row["work_id"], "matching_pass_work_id": row["work_id"] if search_pass in row["passes"] else None})
        if not matching_pass:
            raise HuntEvidenceError("candidate search pass is absent from linked frontier rows", category="hunt_evidence_candidate_search_pass")
    if prepared.evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
        if fallback_candidate_count > 4 or (paired_flow_seeds_by_id and candidates and paired_flow_candidate_count + sink_only_candidate_count == 0):
            _paired_flow_candidate_mismatch()
    debt = [{"work_id": row["work_id"], "pass": review_pass} for row in frontier_rows for review_pass in row["passes"]]
    return HuntEvidence(
        prepared.evidence_protocol_version, prepared.profile, prepared.inventory.sha256, prepared.inventory_count, prepared.rank_input.sha256,
        prepared.frontier.sha256, prepared.frontier_count, prepared.frontier_pass_count, prepared.priority_packet.sha256,
        prepared.priority_count, _canonical_sha256(links), len(candidates), len(links), _canonical_sha256(debt), len(debt),
        prepared.semantic_guidance.sha256 if prepared.semantic_guidance is not None else None,
        prepared.semantic_guidance_row_count, prepared.semantic_guidance_edge_count,
        prepared.semantic_guidance_scanned_file_count, prepared.semantic_guidance_skipped_file_count,
        prepared.paired_flow_seeds.sha256 if prepared.paired_flow_seeds is not None else None,
        prepared.paired_flow_seeds_row_count,
        paired_flow_candidate_count if prepared.evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION else None,
        sink_only_candidate_count if prepared.evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION else None,
        fallback_candidate_count if prepared.evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION else None,
        _canonical_sha256(seed_links) if prepared.evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION else None,
    )


def reproduce_hunt_evidence(
    snapshot_path: Path,
    profile: str,
    prediction: object,
    *,
    evidence_protocol_version: int = HUNT_EVIDENCE_PROTOCOL_VERSION,
) -> HuntEvidence:
    """Rebuilds canonical Hunt evidence without invoking a model runtime."""
    with tempfile.TemporaryDirectory(prefix="hermesbench-hunt-evidence-") as directory:
        prepared = prepare_hunt_artifacts(
            snapshot_path,
            Path(directory),
            profile,
            evidence_protocol_version=evidence_protocol_version,
        )
        observed = (_REQUIRED_PACKET_READ,)
        if evidence_protocol_version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
            observed += (_REQUIRED_PAIRED_FLOW_SEEDS_READ,)
        elif _uses_semantic_guidance(evidence_protocol_version):
            observed += (_REQUIRED_SEMANTIC_READ,)
        return attest_hunt_discovery(prepared, prediction, observed)


def _supported_protocol_version(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value in SUPPORTED_HUNT_EVIDENCE_PROTOCOL_VERSIONS


def _supported_preparation_protocol_version(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value in _PREPARATION_HUNT_EVIDENCE_PROTOCOL_VERSIONS


def _supported_attestation_protocol_version(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value in _ATTESTATION_HUNT_EVIDENCE_PROTOCOL_VERSIONS


def _uses_semantic_guidance(version: int) -> bool:
    return version in _SEMANTIC_HUNT_EVIDENCE_PROTOCOL_VERSIONS


def _semantic_guidance_schema_version(version: int) -> int:
    if version == SEMANTIC_GUIDANCE_HUNT_EVIDENCE_PROTOCOL_VERSION:
        return LEGACY_SEMANTIC_GUIDANCE_SCHEMA_VERSION
    if version == PASS_ANNOTATED_HUNT_EVIDENCE_PROTOCOL_VERSION:
        return PASS_ANNOTATED_SEMANTIC_GUIDANCE_SCHEMA_VERSION
    if version == NESTED_OUTPUT_HUNT_EVIDENCE_PROTOCOL_VERSION:
        return SEMANTIC_GUIDANCE_SCHEMA_VERSION
    if version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
        return SEMANTIC_GUIDANCE_SCHEMA_VERSION
    raise HuntEvidenceError("Hunt evidence protocol has no semantic guidance")


def _evidence_fields(version: int) -> frozenset[str]:
    if version == LEGACY_HUNT_EVIDENCE_PROTOCOL_VERSION:
        return HUNT_EVIDENCE_FIELDS_V1
    if version == SEMANTIC_GUIDANCE_HUNT_EVIDENCE_PROTOCOL_VERSION:
        return HUNT_EVIDENCE_FIELDS_V2
    if version == PASS_ANNOTATED_HUNT_EVIDENCE_PROTOCOL_VERSION:
        return HUNT_EVIDENCE_FIELDS_V3
    if version == NESTED_OUTPUT_HUNT_EVIDENCE_PROTOCOL_VERSION:
        return HUNT_EVIDENCE_FIELDS_V4
    if version == PAIRED_FLOW_HUNT_EVIDENCE_PROTOCOL_VERSION:
        return HUNT_EVIDENCE_FIELDS_V5
    raise HuntEvidenceError("Hunt evidence protocol is unsupported")


def _run_helper(script_name: str, arguments: tuple[str, ...]) -> None:
    script = _PLUGIN_SCRIPTS / script_name
    result = subprocess.run((sys.executable, str(script), *arguments), shell=False, capture_output=True, check=False)
    if result.returncode != 0:
        raise HuntEvidenceError("trusted Hunt preparation helper failed")


def _normalize_lf(path: Path, label: str) -> None:
    """Converts trusted helper text output to the cross-platform canonical newline form."""
    _regular_stat(path, label)
    try:
        value = path.read_bytes()
    except OSError as error:
        raise HuntEvidenceError(f"{label} cannot be normalized") from error
    normalized = value.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise HuntEvidenceError(f"{label} contains unsupported carriage returns")
    if normalized != value:
        path.write_bytes(normalized)


def _safe_directory(path: Path, label: str, *, create: bool = False) -> Path:
    candidate = Path(path)
    if create:
        candidate.mkdir(parents=True, exist_ok=True)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise HuntEvidenceError(f"{label} directory is unavailable") from error
    if not resolved.is_dir() or resolved.is_symlink():
        raise HuntEvidenceError(f"{label} must be a directory")
    return resolved


def _regular_stat(path: Path, label: str) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError as error:
        raise HuntEvidenceError(f"{label} is unavailable") from error
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or bool(value.st_file_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)):
        raise HuntEvidenceError(f"{label} must be one regular unlinked file")
    return value


def _record(path: Path, label: str) -> _Artifact:
    value = _regular_stat(path, label)
    digest, size = _read_sha256(path, label, (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns))
    return _Artifact(path, (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns), digest, size)


def _verify_record(artifact: _Artifact, label: str) -> None:
    value = _regular_stat(artifact.path, label)
    if (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns) != artifact.identity:
        raise HuntEvidenceError(f"{label} identity changed")
    digest, size = _read_sha256(artifact.path, label, artifact.identity)
    if digest != artifact.sha256 or size != artifact.byte_count:
        raise HuntEvidenceError(f"{label} bytes changed")


def _read_sha256(path: Path, label: str, identity: tuple[int, int, int, int]) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HuntEvidenceError(f"{label} cannot be opened") from error
    try:
        opened = os.fstat(descriptor)
        opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened_identity != identity:
            raise HuntEvidenceError(f"{label} identity changed before read")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    after = _regular_stat(path, label)
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity:
        raise HuntEvidenceError(f"{label} identity changed after read")
    return digest.hexdigest(), total


def _read_pinned_bytes(artifact: _Artifact, label: str, maximum: int) -> bytes:
    """Reads one recorded regular file once while preserving its exact identity."""
    value = _regular_stat(artifact.path, label)
    if (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns) != artifact.identity:
        raise HuntEvidenceError(f"{label} identity changed")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(artifact.path, flags)
    except OSError as error:
        raise HuntEvidenceError(f"{label} cannot be opened") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != artifact.identity:
            raise HuntEvidenceError(f"{label} identity changed before read")
        chunks: list[bytes] = []
        size = 0
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            digest.update(chunk)
            if size > maximum:
                raise HuntEvidenceError(f"{label} exceeds its byte limit")
    finally:
        os.close(descriptor)
    after = _regular_stat(artifact.path, label)
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != artifact.identity or digest.hexdigest() != artifact.sha256:
        raise HuntEvidenceError(f"{label} identity changed after read")
    return b"".join(chunks)


def _inventory_paths(path: Path) -> set[str]:
    value = _read_bounded(path, "inventory", MAX_INVENTORY_BYTES)
    return _inventory_paths_value(value)


def _paired_flow_seed_rows(value: bytes) -> dict[str, dict[str, object]]:
    rows = _jsonl_rows_value(value, "paired flow seeds", MAX_PAIRED_FLOW_SEED_ROWS)
    if value != b"".join(_canonical_json(row) for row in rows):
        raise HuntEvidenceError("paired flow seeds are not canonical")
    result: dict[str, dict[str, object]] = {}
    for row in rows:
        _validate_paired_flow_seed_row(row)
        seed_id = str(row["seed_id"])
        if seed_id in result:
            raise HuntEvidenceError("paired flow seed IDs are duplicated")
        result[seed_id] = row
    return result


def _validate_paired_flow_seed_row(row: dict[str, object]) -> None:
    expected = {
        "component", "critical", "eligible_search_passes", "entry", "proof_status",
        "reason_codes", "schema_version", "seed_id", "seed_kind", "trace",
    }
    if set(row) != expected or row["schema_version"] != 1 or row["proof_status"] != "investigation_only":
        raise HuntEvidenceError("paired flow seed row is invalid")
    if not isinstance(row["component"], str) or not row["component"] or not isinstance(row["seed_id"], str) or _PAIRED_FLOW_SEED_ID.fullmatch(row["seed_id"]) is None:
        raise HuntEvidenceError("paired flow seed row is invalid")
    kind = row["seed_kind"]
    if kind not in {"paired-flow", "sink-only"}:
        raise HuntEvidenceError("paired flow seed row is invalid")
    _validate_seed_location(row["critical"], critical=True)
    entry = row["entry"]
    if (kind == "paired-flow" and entry is None) or (kind == "sink-only" and entry is not None):
        raise HuntEvidenceError("paired flow seed row is invalid")
    if entry is not None:
        _validate_seed_location(entry, critical=False)
    eligible = row["eligible_search_passes"]
    if not isinstance(eligible, list) or not eligible or any(not isinstance(item, str) or item not in HUNT_SEARCH_PASSES for item in eligible) or len(eligible) != len(set(eligible)):
        raise HuntEvidenceError("paired flow seed row is invalid")
    trace = row["trace"]
    if not isinstance(trace, list) or len(trace) > 4:
        raise HuntEvidenceError("paired flow seed row is invalid")
    for location in trace:
        _validate_seed_location(location, critical=False)
    if not isinstance(row["reason_codes"], list) or any(not isinstance(code, str) or not code for code in row["reason_codes"]):
        raise HuntEvidenceError("paired flow seed row is invalid")


def _validate_seed_location(value: object, *, critical: bool) -> None:
    expected = {"path", "line", "symbol"} | ({"family"} if critical else set())
    if not isinstance(value, dict) or set(value) != expected or not _relative_path(value.get("path")) or isinstance(value.get("line"), bool) or not isinstance(value.get("line"), int) or value["line"] <= 0 or not isinstance(value.get("symbol"), str):
        raise HuntEvidenceError("paired flow seed endpoint is invalid")
    if critical and (not isinstance(value.get("family"), str) or not value["family"]):
        raise HuntEvidenceError("paired flow seed endpoint is invalid")


def _seed_endpoint_matches(location: object, endpoint: object) -> bool:
    return (
        isinstance(endpoint, dict)
        and getattr(location, "path", None) == endpoint.get("path")
        and getattr(location, "start_line", None) == endpoint.get("line")
        and getattr(location, "end_line", None) == endpoint.get("line")
    )


def _paired_flow_candidate_mismatch() -> None:
    raise HuntEvidenceError("paired flow candidate does not match its seed", category="hunt_paired_flow_candidate_mismatch")


def _inventory_paths_value(value: bytes) -> set[str]:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HuntEvidenceError("inventory is not UTF-8") from error
    if not text.endswith("\n") or "\r" in text:
        raise HuntEvidenceError("inventory is not LF canonical")
    paths = [item.removeprefix("./") for item in text.splitlines()]
    if len(paths) > MAX_INVENTORY_ROWS or len(paths) != len(set(paths)) or any(not _relative_path(path) for path in paths):
        raise HuntEvidenceError("inventory is invalid")
    return set(paths)


def _jsonl_rows(path: Path, label: str, maximum_bytes: int, maximum_rows: int | None) -> list[dict[str, object]]:
    value = _read_bounded(path, label, maximum_bytes)
    return _jsonl_rows_value(value, label, maximum_rows)


def _jsonl_rows_value(value: bytes, label: str, maximum_rows: int | None) -> list[dict[str, object]]:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HuntEvidenceError(f"{label} is not UTF-8") from error
    if (value and not text.endswith("\n")) or "\r" in text:
        raise HuntEvidenceError(f"{label} is not canonical JSONL")
    rows: list[dict[str, object]] = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise HuntEvidenceError(f"{label} is invalid JSONL") from error
        if not isinstance(row, dict) or any(not isinstance(key, str) for key in row):
            raise HuntEvidenceError(f"{label} row is invalid")
        rows.append(row)
    if maximum_rows is not None and len(rows) > maximum_rows:
        raise HuntEvidenceError(f"{label} has too many rows")
    return rows


def _validate_frontier_receipt(value: bytes, profile: str, rank_input_sha256: str, frontier_count: int) -> None:
    try:
        decoded = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HuntEvidenceError("frontier receipt is invalid") from error
    expected = {"schema_version", "profile", "cache_key", "rank_input_sha256", "rank_output_sha256", "total_files", "components", "rank_excluded_but_retained", "signal_counts", "coverage_strategy", "eligibility_dropped"}
    if not isinstance(decoded, dict) or set(decoded) != expected or decoded["schema_version"] != 1 or decoded["profile"] != profile or decoded["rank_input_sha256"] != rank_input_sha256 or decoded["total_files"] != frontier_count:
        raise HuntEvidenceError("frontier receipt is invalid")


def _validate_rank_rows(rows: list[dict[str, object]], inventory_paths: set[str]) -> dict[str, dict[str, object]]:
    expected = {"path", "area", "preview"}
    result: dict[str, dict[str, object]] = {}
    for row in rows:
        if set(row) != expected or not _relative_path(row.get("path")) or not isinstance(row["area"], str) or not isinstance(row["preview"], str):
            raise HuntEvidenceError("rank input row is invalid")
        path = str(row["path"])
        if path in result or path not in inventory_paths:
            raise HuntEvidenceError("rank input paths are invalid")
        result[path] = row
    return result


def _validate_frontier_rows(rows: list[dict[str, object]], rank_paths: set[str]) -> dict[str, dict[str, object]]:
    expected = {"work_id", "path", "area", "component", "risk_score", "rank_include", "rank_reason", "signals", "passes", "priority"}
    result: dict[str, dict[str, object]] = {}
    work_ids: set[str] = set()
    for priority, row in enumerate(rows, 1):
        if set(row) != expected or not _relative_path(row.get("path")) or not isinstance(row["work_id"], str) or not isinstance(row["component"], str) or isinstance(row["risk_score"], bool) or not isinstance(row["risk_score"], int) or not isinstance(row["signals"], list) or not isinstance(row["passes"], list) or row["priority"] != priority:
            raise HuntEvidenceError("frontier row is invalid")
        path = str(row["path"])
        if path in result or row["work_id"] in work_ids or path not in rank_paths or not row["passes"] or any(not isinstance(item, str) or not item or item not in HUNT_SEARCH_PASSES for item in row["passes"]) or len(row["passes"]) != len(set(row["passes"])):
            raise HuntEvidenceError("frontier paths are invalid")
        result[path] = row
        work_ids.add(row["work_id"])
    if set(result) != rank_paths:
        raise HuntEvidenceError("frontier must cover rank input exactly")
    return result


def _priority_rows(frontier: list[dict[str, object]], rank_by_path: dict[str, dict[str, object]], limit: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for row in frontier:
        preview = _truncate_utf8(str(rank_by_path[str(row["path"])]["preview"]), PRIORITY_PREVIEW_BYTES)
        projected = {key: row[key] for key in ("work_id", "path", "component", "risk_score", "signals", "passes")} | {"preview": preview}
        candidate = _canonical_json(projected)
        current = sum(len(_canonical_json(item)) for item in rows)
        if len(rows) >= limit or current + len(candidate) > MAX_PRIORITY_PACKET_BYTES:
            break
        rows.append(projected)
    if frontier and not rows:
        raise HuntEvidenceError("priority packet cannot represent the frontier")
    return rows


def _truncate_utf8(value: str, maximum: int) -> str:
    encoded = value.encode("utf-8")[:maximum]
    while True:
        try:
            return encoded.decode("utf-8")
        except UnicodeDecodeError:
            encoded = encoded[:-1]


def _read_bounded(path: Path, label: str, maximum: int) -> bytes:
    _regular_stat(path, label)
    try:
        value = path.read_bytes()
    except OSError as error:
        raise HuntEvidenceError(f"{label} cannot be read") from error
    if len(value) > maximum:
        raise HuntEvidenceError(f"{label} exceeds its byte limit")
    return value


def _relative_path(value: object) -> bool:
    return isinstance(value, str) and bool(value) and "\\" not in value and "\x00" not in value and not value.startswith("/") and ".." not in value.split("/")


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_bytes(b"".join(_canonical_json(row) for row in rows))


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()
