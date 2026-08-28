"""Host-side deterministic artifacts and path-free evidence for Hunt discovery."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


PLAN_DIRECTORY = "hermesbench-hunt"
INVENTORY_NAME = "in-scope-files.txt"
RANK_INPUT_NAME = "rank-input.jsonl"
FRONTIER_NAME = "frontier.jsonl"
FRONTIER_RECEIPT_NAME = "frontier-receipt.json"
PRIORITY_PACKET_NAME = "priority-packet.jsonl"
HUNT_EVIDENCE_PROTOCOL_VERSION = 1
MAX_INVENTORY_ROWS = 100_000
MAX_INVENTORY_BYTES = 8 * 1024 * 1024
MAX_RANK_INPUT_BYTES = 32 * 1024 * 1024
MAX_FRONTIER_ROWS = 100_000
MAX_FRONTIER_BYTES = 32 * 1024 * 1024
MAX_PRIORITY_PACKET_BYTES = 1024 * 1024
PRIORITY_ROW_LIMITS = {"hunt-balanced": 512, "hunt-max": 1024}
PRIORITY_PREVIEW_BYTES = 384
_REQUIRED_PACKET_READ = ("cat", "/workspace/scratch/hermesbench-hunt/priority-packet.jsonl")
_PLUGIN_SCRIPTS = Path(__file__).resolve().parents[2] / "sdk" / "typescript" / "_bundled_plugin" / "scripts"


class HuntEvidenceError(ValueError):
    """Signals a Hunt artifact or attestation contract failure."""


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
    inventory: _Artifact
    rank_input: _Artifact
    frontier: _Artifact
    frontier_receipt: _Artifact
    priority_packet: _Artifact
    inventory_count: int
    frontier_count: int
    frontier_pass_count: int
    priority_count: int
    priority_bytes: int
    preparation_fingerprint: str
    preparation_seconds: float
    container_priority_packet_path: str = "/workspace/scratch/hermesbench-hunt/priority-packet.jsonl"


@dataclass(frozen=True)
class HuntEvidence:
    """Provides only path-free persistent evidence for one discovery prediction."""

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

    @property
    def validated_closure_count(self) -> int:
        return 0

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": HUNT_EVIDENCE_PROTOCOL_VERSION,
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


def prepare_hunt_artifacts(snapshot_path: Path, scratch_path: Path, profile: str) -> PreparedHuntArtifacts:
    """Creates and records the complete immutable Hunt plan using bundled helpers."""
    if profile not in PRIORITY_ROW_LIMITS:
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
    _run_helper("generate_in_scope_files.py", ("--repo", str(snapshot), "--scope", ".", "--out", str(inventory)))
    _run_helper("generate_rank_input.py", ("make-repo-rank-input", "--repo", str(snapshot), "--scope", ".", "--out", str(rank_input)))
    _run_helper("hunt_workflow.py", ("make-frontier", "--work-dir", str(plan), "--repository", str(snapshot), "--rank-input", str(rank_input), "--profile", profile, "--out", str(frontier), "--receipt", str(receipt)))
    _normalize_lf(inventory, "inventory")
    _normalize_lf(rank_input, "rank input")
    _normalize_lf(frontier, "frontier")
    inventory_paths = _inventory_paths(inventory)
    rank_rows = _jsonl_rows(rank_input, "rank input", MAX_RANK_INPUT_BYTES, None)
    frontier_rows = _jsonl_rows(frontier, "frontier", MAX_FRONTIER_BYTES, MAX_FRONTIER_ROWS)
    rank_by_path = _validate_rank_rows(rank_rows, inventory_paths)
    _validate_frontier_rows(frontier_rows, set(rank_by_path))
    priority_rows = _priority_rows(frontier_rows, rank_by_path, PRIORITY_ROW_LIMITS[profile])
    _write_jsonl(priority_packet, priority_rows)
    artifacts = {
        "inventory": _record(inventory, "inventory"),
        "rank_input": _record(rank_input, "rank input"),
        "frontier": _record(frontier, "frontier"),
        "frontier_receipt": _record(receipt, "frontier receipt"),
        "priority_packet": _record(priority_packet, "priority packet"),
    }
    passes = {(str(row["work_id"]), value) for row in frontier_rows for value in row["passes"]}
    fingerprint = _canonical_sha256({name: artifact.sha256 for name, artifact in artifacts.items()} | {"profile": profile})
    return PreparedHuntArtifacts(
        plan, profile, artifacts["inventory"], artifacts["rank_input"], artifacts["frontier"], artifacts["frontier_receipt"], artifacts["priority_packet"],
        len(inventory_paths), len(frontier_rows), len(passes), len(priority_rows), artifacts["priority_packet"].byte_count,
        fingerprint, time.monotonic() - started,
    )


def attest_hunt_discovery(prepared: PreparedHuntArtifacts, prediction: object, observed_argv: tuple[tuple[str, ...], ...]) -> HuntEvidence:
    """Checks prepared bytes and binds a valid discovery result without source paths."""
    if not isinstance(prepared, PreparedHuntArtifacts):
        raise HuntEvidenceError("prepared Hunt artifacts are invalid")
    if not isinstance(observed_argv, tuple) or _REQUIRED_PACKET_READ not in observed_argv:
        raise HuntEvidenceError("priority packet was not read exactly as required")
    for artifact, label in ((prepared.inventory, "inventory"), (prepared.rank_input, "rank input"), (prepared.frontier, "frontier"), (prepared.frontier_receipt, "frontier receipt"), (prepared.priority_packet, "priority packet")):
        _verify_record(artifact, label)
    inventory_paths = _inventory_paths(prepared.inventory.path)
    rank_rows = _jsonl_rows(prepared.rank_input.path, "rank input", MAX_RANK_INPUT_BYTES, None)
    frontier_rows = _jsonl_rows(prepared.frontier.path, "frontier", MAX_FRONTIER_BYTES, MAX_FRONTIER_ROWS)
    rank_by_path = _validate_rank_rows(rank_rows, inventory_paths)
    frontier_by_path = _validate_frontier_rows(frontier_rows, set(rank_by_path))
    candidates = getattr(prediction, "candidates", None)
    if not isinstance(candidates, tuple):
        raise HuntEvidenceError("Hunt discovery prediction is invalid")
    links: list[dict[str, object]] = []
    for candidate in candidates:
        candidate_id = getattr(candidate, "finding_id", None)
        search_pass = getattr(candidate, "search_pass", None)
        locations = (("entry_point", 0, getattr(candidate, "entry_point", None)), ("critical_operation", 0, getattr(candidate, "critical_operation", None)))
        trace = tuple(("trace", index, location) for index, location in enumerate(getattr(candidate, "trace", ())))
        matching_pass = False
        for role, trace_index, location in (*locations, *trace):
            path = getattr(location, "path", None)
            start_line = getattr(location, "start_line", None)
            end_line = getattr(location, "end_line", None)
            if not isinstance(candidate_id, str) or not isinstance(path, str) or path not in inventory_paths or path not in frontier_by_path:
                raise HuntEvidenceError("candidate location is outside the complete frontier")
            row = frontier_by_path[path]
            if search_pass in row["passes"]:
                matching_pass = True
            links.append({"candidate_id": candidate_id, "role": role, "trace_index": trace_index, "start_line": start_line, "end_line": end_line, "work_id": row["work_id"], "matching_pass_work_id": row["work_id"] if search_pass in row["passes"] else None})
        if not matching_pass:
            raise HuntEvidenceError("candidate search pass is absent from linked frontier rows")
    debt = [{"work_id": row["work_id"], "pass": review_pass} for row in frontier_rows for review_pass in row["passes"]]
    return HuntEvidence(
        prepared.profile, prepared.inventory.sha256, prepared.inventory_count, prepared.rank_input.sha256,
        prepared.frontier.sha256, prepared.frontier_count, prepared.frontier_pass_count, prepared.priority_packet.sha256,
        prepared.priority_count, _canonical_sha256(links), len(candidates), len(links), _canonical_sha256(debt), len(debt),
    )


def reproduce_hunt_evidence(snapshot_path: Path, profile: str, prediction: object) -> HuntEvidence:
    """Rebuilds canonical Hunt evidence without invoking a model runtime."""
    with tempfile.TemporaryDirectory(prefix="hermesbench-hunt-evidence-") as directory:
        prepared = prepare_hunt_artifacts(snapshot_path, Path(directory), profile)
        return attest_hunt_discovery(prepared, prediction, (_REQUIRED_PACKET_READ,))


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


def _inventory_paths(path: Path) -> set[str]:
    value = _read_bounded(path, "inventory", MAX_INVENTORY_BYTES)
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
        if path in result or row["work_id"] in work_ids or path not in rank_paths or not row["passes"] or any(not isinstance(item, str) for item in row["passes"]):
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
