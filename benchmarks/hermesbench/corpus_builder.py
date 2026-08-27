# Builds anonymous HermesBench corpora from reviewed local Git objects.

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal, Mapping

from .contracts import ContractError, GoldPath, Location, SCHEMA_VERSION, parse_oracle
from .corpus import CorpusCandidate
from .sanitize import BundleAuditError, audit_bundle, tree_sha256

_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_SPLITS = frozenset({"public_dev", "hidden_test", "rotating_audit", "full_holdout"})
_SUITES = frozenset({"canary", "mini", "full"})
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$", *(f"COM{number}" for number in range(1, 10)), *(f"LPT{number}" for number in range(1, 10))}
)
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class CorpusBuildError(ValueError):
    """Signals a corpus-preparation boundary failure."""


@dataclass(frozen=True)
class CommentRedaction:
    tree: str
    path: str
    blob_sha256: str
    start_line: int
    end_line: int
    expected_line_sha256: str


@dataclass(frozen=True)
class SelectedLedgerRow:
    candidate_task_id: str
    dataset_revision: str
    entry_id: str
    report_identity: str
    repository_identity: str
    vulnerable_commit: str
    fixed_commit: str
    primary_evidence: str
    license_identifier: str
    license_path: str
    license_sha256: str
    vulnerable_tree: str
    fixed_tree: str
    language: str
    group_input: str
    split: str
    suites: tuple[str, ...]
    time_limit_seconds: int
    fixed_locations: tuple[GoldPath, ...]
    comment_redactions: tuple[CommentRedaction, ...]
    quarantine_paths: tuple[str, ...]
    state: Literal["selected"] = "selected"


@dataclass(frozen=True)
class ExcludedLedgerRow:
    dataset_revision: str
    entry_id: str
    exclusion_reason: str
    state: Literal["excluded"] = "excluded"


LedgerRow = SelectedLedgerRow | ExcludedLedgerRow


@dataclass(frozen=True)
class CorpusBuildResult:
    snapshots_root: Path
    snapshot_paths: tuple[Path, ...]
    manifest_path: Path
    oracle_path: Path
    provenance_path: Path
    summary_path: Path
    manifest_sha256: str
    oracle_sha256: str


@dataclass(frozen=True)
class TreeReadResult:
    files: dict[str, bytes]
    quarantined_symlink_paths: frozenset[str]


def derive_anonymous_id(
    key: bytes,
    domain: Literal["vulnerable", "fixed", "group"],
    dataset_revision: str,
    entry_id: str,
) -> str:
    """Returns a keyed, domain-separated anonymous corpus identifier."""

    if not isinstance(key, bytes) or not key:
        raise CorpusBuildError("anonymization key must be non-empty bytes")
    if domain not in {"vulnerable", "fixed", "group"}:
        raise CorpusBuildError("anonymous ID domain is unsupported")
    revision = _require_commit(dataset_revision, "dataset_revision")
    source_entry = _require_non_empty_string(entry_id, "entry_id")
    digest = hmac.new(
        key,
        f"hermesbench\x00{domain}\x00{revision}\x00{source_entry}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:20]
    prefixes = {"vulnerable": "hb-v", "fixed": "hb-f", "group": "hb-g"}
    return f"{prefixes[domain]}-{digest}"


def parse_reviewed_ledger(path: Path) -> tuple[LedgerRow, ...]:
    """Parses exact reviewed-ledger rows without materializing any source."""

    rows: list[LedgerRow] = []
    seen_entries: set[tuple[str, str]] = set()
    seen_candidates: set[str] = set()
    try:
        stream = path.open("r", encoding="utf-8", newline="")
    except OSError as error:
        raise CorpusBuildError(f"cannot read reviewed ledger: {path}") from error
    with stream:
        for line_number, raw_line in enumerate(stream, start=1):
            if not raw_line.strip():
                raise CorpusBuildError(f"{path}: line {line_number}: blank rows are not allowed")
            try:
                value = json.loads(raw_line)
            except json.JSONDecodeError as error:
                raise CorpusBuildError(f"{path}: line {line_number}: invalid JSON") from error
            row = _parse_ledger_row(value, path, line_number)
            entry_key = (row.dataset_revision, row.entry_id)
            if entry_key in seen_entries:
                raise CorpusBuildError(f"{path}: line {line_number}: duplicate ledger entry")
            seen_entries.add(entry_key)
            if isinstance(row, SelectedLedgerRow):
                if row.candidate_task_id in seen_candidates:
                    raise CorpusBuildError(f"{path}: line {line_number}: duplicate selected candidate")
                seen_candidates.add(row.candidate_task_id)
            rows.append(row)
    if not rows:
        raise CorpusBuildError("reviewed ledger must not be empty")
    return tuple(rows)


def build_reviewed_corpus(
    ledger_path: Path,
    candidates: Mapping[str, CorpusCandidate],
    repositories: Mapping[str, Path],
    output_root: Path,
    anonymization_key: bytes,
    *,
    suite: Literal["canary", "mini", "full"],
) -> CorpusBuildResult:
    """Verifies reviewed records and atomically builds one anonymous suite."""

    if suite not in _SUITES:
        raise CorpusBuildError("unsupported corpus suite")
    _validate_output_root(output_root)
    parent = output_root.parent
    derive_anonymous_id(anonymization_key, "group", "0" * 40, "key-check")

    ledger_rows = parse_reviewed_ledger(ledger_path)
    _verify_group_splits(ledger_rows)
    selected_rows = tuple(
        row
        for row in ledger_rows
        if isinstance(row, SelectedLedgerRow) and suite in row.suites
    )
    if not selected_rows:
        raise CorpusBuildError("reviewed ledger has no selected rows for suite")

    stage = Path(tempfile.mkdtemp(prefix=".hb-", dir=parent))
    try:
        built = _build_stage(
            stage,
            ledger_path,
            selected_rows,
            ledger_rows,
            candidates,
            repositories,
            anonymization_key,
            suite,
        )
        _validate_output_root(output_root)
        os.replace(stage, output_root)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise

    return CorpusBuildResult(
        snapshots_root=output_root / "snapshots",
        snapshot_paths=tuple(output_root / "snapshots" / path.name for path in built.snapshot_paths),
        manifest_path=output_root / built.manifest_path.relative_to(stage),
        oracle_path=output_root / built.oracle_path.relative_to(stage),
        provenance_path=output_root / built.provenance_path.relative_to(stage),
        summary_path=output_root / built.summary_path.relative_to(stage),
        manifest_sha256=built.manifest_sha256,
        oracle_sha256=built.oracle_sha256,
    )


def _build_stage(
    stage: Path,
    ledger_path: Path,
    selected_rows: tuple[SelectedLedgerRow, ...],
    all_rows: tuple[LedgerRow, ...],
    candidates: Mapping[str, CorpusCandidate],
    repositories: Mapping[str, Path],
    key: bytes,
    suite: str,
) -> CorpusBuildResult:
    snapshots_root = stage / "snapshots"
    private_root = stage / "private"
    snapshots_root.mkdir()
    private_root.mkdir()
    tasks: list[dict[str, object]] = []
    oracle_rows: list[dict[str, object]] = []
    receipt_rows: list[dict[str, object]] = []
    snapshot_paths: list[Path] = []

    for row in sorted(selected_rows, key=lambda item: (item.dataset_revision, item.entry_id)):
        candidate = candidates.get(row.candidate_task_id)
        repository = repositories.get(row.candidate_task_id)
        if candidate is None or repository is None:
            raise CorpusBuildError("selected ledger row lacks a reviewed candidate or local repository")
        _verify_candidate(row, candidate)
        vulnerable_result, fixed_result = _verify_git_revisions(repository, row)
        vulnerable_tree = vulnerable_result.files
        fixed_tree = fixed_result.files
        _verify_quarantine_paths(
            candidate.gold_path,
            row.fixed_locations,
            row.license_path,
            row.quarantine_paths,
            vulnerable_result,
            fixed_result,
        )
        _verify_gold_locations(candidate.gold_path, vulnerable_tree, "vulnerable gold")
        _verify_fixed_locations(candidate.gold_path, row.fixed_locations, fixed_tree)
        _verify_root_changed(candidate.gold_path, vulnerable_tree, fixed_tree)
        _verify_disclosure_metadata_is_quarantined(row.quarantine_paths, vulnerable_tree, fixed_tree)
        redacted_fixed_tree = _apply_comment_redactions(row, fixed_tree)
        materialized_vulnerable_tree = _without_quarantine(vulnerable_tree, row.quarantine_paths)
        materialized_fixed_tree = _without_quarantine(redacted_fixed_tree, row.quarantine_paths)

        group_id = derive_anonymous_id(key, "group", row.dataset_revision, row.group_input)
        vulnerable_id = derive_anonymous_id(key, "vulnerable", row.dataset_revision, row.entry_id)
        fixed_id = derive_anonymous_id(key, "fixed", row.dataset_revision, row.entry_id)
        for task_id, kind, paths, retired_paths, tree in (
            (vulnerable_id, "vulnerable", (candidate.gold_path,), (), materialized_vulnerable_tree),
            (fixed_id, "fixed", (), row.fixed_locations, materialized_fixed_tree),
        ):
            snapshot = snapshots_root / task_id
            _materialize_tree(tree, snapshot)
            _audit_snapshot(snapshot)
            snapshot_hash = tree_sha256(snapshot)
            snapshot_paths.append(snapshot)
            tasks.append(
                {
                    "task_id": task_id,
                    "snapshot_sha256": snapshot_hash,
                    "language": row.language,
                    "allowed_commands": [],
                    "time_limit_seconds": row.time_limit_seconds,
                }
            )
            oracle = {
                "schema_version": SCHEMA_VERSION,
                "task_id": task_id,
                "kind": kind,
                "group_id": group_id,
                "split": row.split,
                "category": candidate.category_l2,
                "language": row.language,
                "paths": [_gold_path_json(path) for path in paths],
                "retired_paths": [_gold_path_json(path) for path in retired_paths],
            }
            try:
                parse_oracle(oracle)
            except ContractError as error:
                raise CorpusBuildError("reviewed oracle cannot satisfy frozen contract") from error
            oracle_rows.append(oracle)
            receipt_rows.append(
                {
                    "task_id": task_id,
                    "kind": kind,
                    "dataset_revision": row.dataset_revision,
                    "entry_id": row.entry_id,
                    "vulnerable_commit": row.vulnerable_commit,
                    "fixed_commit": row.fixed_commit,
                    "vulnerable_tree": row.vulnerable_tree,
                    "fixed_tree": row.fixed_tree,
                    "license_sha256": row.license_sha256,
                    "license_path": row.license_path,
                    "snapshot_sha256": snapshot_hash,
                }
            )

    tasks.sort(key=lambda item: str(item["task_id"]))
    oracle_rows.sort(key=lambda item: str(item["task_id"]))
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "suite": suite,
        "manifest_id": f"hb-{suite}-{_sha256_json(tasks)[:20]}",
        "tasks": tasks,
    }
    manifest_path = stage / f"manifest-{suite}.json"
    _write_json(manifest_path, manifest)
    oracle_path = private_root / f"oracles-{suite}.jsonl"
    _write_jsonl(oracle_path, oracle_rows)
    manifest_hash = _sha256_bytes(manifest_path.read_bytes())
    oracle_hash = _sha256_bytes(oracle_path.read_bytes())
    summary_path = stage / f"summary-{suite}.json"
    _write_json(
        summary_path,
        {
            "schema_version": SCHEMA_VERSION,
            "suite": suite,
            "manifest_sha256": manifest_hash,
            "vulnerable_count": len(tasks) // 2,
            "fixed_count": len(tasks) // 2,
            "excluded_count": sum(isinstance(row, ExcludedLedgerRow) for row in all_rows),
            "language_counts": _language_counts(selected_rows),
            "snapshot_size_buckets": _snapshot_size_buckets(snapshot_paths),
        },
    )
    provenance_path = private_root / f"provenance-{suite}.json"
    _write_json(
        provenance_path,
        {
            "schema_version": SCHEMA_VERSION,
            "suite": suite,
            "ledger_sha256": _sha256_bytes(ledger_path.read_bytes()),
            "manifest_sha256": manifest_hash,
            "oracle_sha256": oracle_hash,
            "quarantine_policy": "reject-unsupported-or-contaminated",
            "unsupported_git_entries": "reject-except-explicit-quarantined-symlink",
            "tasks": receipt_rows,
            "selected_count": len(selected_rows),
            "excluded_count": sum(isinstance(row, ExcludedLedgerRow) for row in all_rows),
        },
    )
    return CorpusBuildResult(
        snapshots_root=snapshots_root,
        snapshot_paths=tuple(snapshot_paths),
        manifest_path=manifest_path,
        oracle_path=oracle_path,
        provenance_path=provenance_path,
        summary_path=summary_path,
        manifest_sha256=manifest_hash,
        oracle_sha256=oracle_hash,
    )


def _parse_ledger_row(value: object, path: Path, line_number: int) -> LedgerRow:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CorpusBuildError(f"{path}: line {line_number}: ledger row must be an object")
    state = value.get("state")
    if state == "selected":
        expected = {
            "schema_version", "state", "candidate_task_id", "dataset_revision", "entry_id",
            "report_identity", "repository_identity", "vulnerable_commit", "fixed_commit",
            "primary_evidence", "license_identifier", "license_path", "license_sha256", "vulnerable_tree",
            "fixed_tree", "language", "group_input", "split", "suites", "time_limit_seconds",
            "excluded", "fixed_locations", "comment_redactions", "quarantine_paths",
        }
        _require_exact_fields(value, expected, "selected ledger row")
        _require_schema(value["schema_version"])
        if value["excluded"] is not False:
            raise CorpusBuildError("selected ledger row must be exclusion-free")
        split = _require_non_empty_string(value["split"], "split")
        if split not in _SPLITS:
            raise CorpusBuildError("selected ledger row has an unknown split")
        suites = _parse_suites(value["suites"])
        time_limit = value["time_limit_seconds"]
        if isinstance(time_limit, bool) or not isinstance(time_limit, int) or time_limit < 1:
            raise CorpusBuildError("time_limit_seconds must be a positive integer")
        fixed_locations = _parse_gold_paths(value["fixed_locations"], "fixed_locations")
        if not fixed_locations:
            raise CorpusBuildError("selected ledger row requires fixed_locations")
        return SelectedLedgerRow(
            candidate_task_id=_require_non_empty_string(value["candidate_task_id"], "candidate_task_id"),
            dataset_revision=_require_commit(value["dataset_revision"], "dataset_revision"),
            entry_id=_require_non_empty_string(value["entry_id"], "entry_id"),
            report_identity=_require_non_empty_string(value["report_identity"], "report_identity"),
            repository_identity=_require_non_empty_string(value["repository_identity"], "repository_identity"),
            vulnerable_commit=_require_commit(value["vulnerable_commit"], "vulnerable_commit"),
            fixed_commit=_require_commit(value["fixed_commit"], "fixed_commit"),
            primary_evidence=_require_non_empty_string(value["primary_evidence"], "primary_evidence"),
            license_identifier=_require_non_empty_string(value["license_identifier"], "license_identifier"),
            license_path=_require_git_path(value["license_path"], "license_path"),
            license_sha256=_require_sha256(value["license_sha256"], "license_sha256"),
            vulnerable_tree=_require_commit(value["vulnerable_tree"], "vulnerable_tree"),
            fixed_tree=_require_commit(value["fixed_tree"], "fixed_tree"),
            language=_require_non_empty_string(value["language"], "language"),
            group_input=_require_non_empty_string(value["group_input"], "group_input"),
            split=split,
            suites=suites,
            time_limit_seconds=time_limit,
            fixed_locations=fixed_locations,
            comment_redactions=_parse_comment_redactions(value["comment_redactions"]),
            quarantine_paths=_parse_quarantine_paths(value["quarantine_paths"]),
        )
    if state == "excluded":
        expected = {"schema_version", "state", "dataset_revision", "entry_id", "exclusion_reason"}
        _require_exact_fields(value, expected, "excluded ledger row")
        _require_schema(value["schema_version"])
        return ExcludedLedgerRow(
            dataset_revision=_require_commit(value["dataset_revision"], "dataset_revision"),
            entry_id=_require_non_empty_string(value["entry_id"], "entry_id"),
            exclusion_reason=_require_non_empty_string(value["exclusion_reason"], "exclusion_reason"),
        )
    raise CorpusBuildError("ledger row state must be selected or excluded")


def _verify_candidate(row: SelectedLedgerRow, candidate: CorpusCandidate) -> None:
    expected = (
        (candidate.dataset_revision, row.dataset_revision),
        (candidate.entry_id, row.entry_id),
        (candidate.report_id, row.report_identity),
        (candidate.repo_url, row.repository_identity),
        (candidate.vulnerable_commit, row.vulnerable_commit),
    )
    if any(left != right for left, right in expected):
        raise CorpusBuildError("reviewed ledger source metadata disagrees with candidate")


def _verify_group_splits(rows: tuple[LedgerRow, ...]) -> None:
    splits: dict[tuple[str, str], str] = {}
    for row in rows:
        if not isinstance(row, SelectedLedgerRow):
            continue
        key = (row.dataset_revision, row.group_input)
        existing = splits.setdefault(key, row.split)
        if existing != row.split:
            raise CorpusBuildError("reviewed group must remain in one split")


def _verify_git_revisions(
    repository: Path, row: SelectedLedgerRow
) -> tuple[TreeReadResult, TreeReadResult]:
    if not repository.is_dir() or repository.is_symlink():
        raise CorpusBuildError("local Git repository must be a real directory")
    _git(repository, "rev-parse", "--git-dir")
    for commit in (row.vulnerable_commit, row.fixed_commit):
        if _git(repository, "cat-file", "-t", commit) != "commit":
            raise CorpusBuildError("pinned Git object is not a commit")
    if row.vulnerable_commit == row.fixed_commit or not _git_success(repository, "merge-base", "--is-ancestor", row.vulnerable_commit, row.fixed_commit):
        raise CorpusBuildError("fixed commit must be a strict descendant of vulnerable commit")
    if _git(repository, "rev-parse", f"{row.vulnerable_commit}^{{tree}}") != row.vulnerable_tree:
        raise CorpusBuildError("vulnerable tree does not match reviewed commit")
    if _git(repository, "rev-parse", f"{row.fixed_commit}^{{tree}}") != row.fixed_tree:
        raise CorpusBuildError("fixed tree does not match reviewed commit")
    vulnerable_result = _read_tree(repository, row.vulnerable_tree, row.quarantine_paths)
    fixed_result = _read_tree(repository, row.fixed_tree, row.quarantine_paths)
    vulnerable_license = vulnerable_result.files.get(row.license_path)
    fixed_license = fixed_result.files.get(row.license_path)
    if (
        vulnerable_license is None
        or fixed_license is None
        or hashlib.sha256(vulnerable_license).hexdigest() != row.license_sha256
        or hashlib.sha256(fixed_license).hexdigest() != row.license_sha256
    ):
        raise CorpusBuildError("license blob does not match reviewed license hash")
    return vulnerable_result, fixed_result


def _read_tree(
    repository: Path, tree: str, quarantine_paths: tuple[str, ...] = ()
) -> TreeReadResult:
    raw = _git_bytes(repository, "ls-tree", "-r", "-z", tree)
    paths: list[tuple[str, str]] = []
    quarantined_symlink_paths: set[str] = set()
    quarantined = set(quarantine_paths)
    folded: set[str] = set()
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            metadata, raw_path = entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise CorpusBuildError("Git tree entry is malformed or not UTF-8") from error
        _validate_git_path(path)
        if path.casefold() in folded:
            raise CorpusBuildError("Git tree contains case-fold-colliding paths")
        folded.add(path.casefold())
        if _COMMIT_PATTERN.fullmatch(object_id) is None:
            raise CorpusBuildError("Git tree entry has an invalid object ID")
        if mode == "120000" and object_type == "blob" and path in quarantined:
            quarantined_symlink_paths.add(path)
            continue
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise CorpusBuildError("Git tree contains an unsupported entry")
        paths.append((path, object_id))
    if not paths:
        raise CorpusBuildError("Git tree must contain regular files")
    object_ids = tuple(dict.fromkeys(object_id for _, object_id in paths))
    contents = _read_batch_blobs(repository, object_ids)
    return TreeReadResult(
        files={path: contents[object_id] for path, object_id in paths},
        quarantined_symlink_paths=frozenset(quarantined_symlink_paths),
    )


def _read_batch_blobs(
    repository: Path, object_ids: tuple[str, ...]
) -> dict[str, bytes]:
    request = b"".join(object_id.encode("ascii") + b"\n" for object_id in object_ids)
    raw = _git_bytes(repository, "cat-file", "--batch", input_bytes=request)
    cursor = 0
    contents: dict[str, bytes] = {}
    for object_id in object_ids:
        header_end = raw.find(b"\n", cursor)
        if header_end < 0:
            raise CorpusBuildError("Git batch output is malformed")
        header = raw[cursor:header_end].split(b" ")
        cursor = header_end + 1
        if (
            len(header) != 3
            or header[0] != object_id.encode("ascii")
            or header[1] != b"blob"
            or not header[2].isdigit()
        ):
            raise CorpusBuildError("Git batch output is malformed")
        try:
            size = int(header[2])
        except ValueError as error:
            raise CorpusBuildError("Git batch output is malformed") from error
        payload_end = cursor + size
        if payload_end >= len(raw) or raw[payload_end : payload_end + 1] != b"\n":
            raise CorpusBuildError("Git batch output is malformed")
        contents[object_id] = raw[cursor:payload_end]
        cursor = payload_end + 1
    if cursor != len(raw):
        raise CorpusBuildError("Git batch output is malformed")
    return contents


def _verify_gold_locations(path: GoldPath, tree: Mapping[str, bytes], name: str) -> None:
    for location in (path.entry_point, path.critical_operation, *path.trace):
        _verify_location(location, tree, name)


def _verify_fixed_locations(vulnerable: GoldPath, fixed: tuple[GoldPath, ...], tree: Mapping[str, bytes]) -> None:
    if len(fixed) != 1 or fixed[0].path_id != vulnerable.path_id or len(fixed[0].trace) != len(vulnerable.trace):
        raise CorpusBuildError("fixed locations must correspond exactly to the candidate path")
    _verify_gold_locations(fixed[0], tree, "fixed retired path")


def _verify_root_changed(path: GoldPath, vulnerable: Mapping[str, bytes], fixed: Mapping[str, bytes]) -> None:
    root = path.critical_operation.path
    if root not in vulnerable or root not in fixed or vulnerable[root] == fixed[root]:
        raise CorpusBuildError("selected critical root file must change in the fixed revision")


def _verify_quarantine_paths(
    vulnerable: GoldPath,
    fixed: tuple[GoldPath, ...],
    license_path: str,
    quarantine_paths: tuple[str, ...],
    vulnerable_tree: TreeReadResult,
    fixed_tree: TreeReadResult,
) -> None:
    protected = {location.path for path in (vulnerable, *fixed) for location in _all_locations(path)}
    available = (
        set(vulnerable_tree.files)
        | set(fixed_tree.files)
        | set(vulnerable_tree.quarantined_symlink_paths)
        | set(fixed_tree.quarantined_symlink_paths)
    )
    for path in quarantine_paths:
        if path in protected:
            raise CorpusBuildError("quarantine path cannot contain a gold or root source file")
        if path == license_path:
            raise CorpusBuildError("quarantine path cannot contain the reviewed license path")
        if path not in available:
            raise CorpusBuildError("quarantine path must exist in at least one pinned tree")


def _verify_disclosure_metadata_is_quarantined(
    quarantine_paths: tuple[str, ...],
    vulnerable_tree: Mapping[str, bytes],
    fixed_tree: Mapping[str, bytes],
) -> None:
    quarantined = set(quarantine_paths)
    for path in set(vulnerable_tree) | set(fixed_tree):
        if Path(path).suffix.lower() in {".patch", ".diff"} and path not in quarantined:
            raise CorpusBuildError("patch metadata requires an explicit quarantine path")


def _apply_comment_redactions(
    row: SelectedLedgerRow,
    fixed_tree: Mapping[str, bytes],
) -> dict[str, bytes]:
    redacted = dict(fixed_tree)
    protected = {
        (location.path, line)
        for path in row.fixed_locations
        for location in _all_locations(path)
        for line in range(location.start_line, location.end_line + 1)
    }
    seen_lines: set[tuple[str, int]] = set()
    for redaction in row.comment_redactions:
        if redaction.tree != row.fixed_tree:
            raise CorpusBuildError("comment redaction tree does not bind the fixed tree")
        contents = fixed_tree.get(redaction.path)
        if contents is None:
            raise CorpusBuildError("comment redaction path is absent from fixed tree")
        if hashlib.sha256(contents).hexdigest() != redaction.blob_sha256:
            raise CorpusBuildError("comment redaction blob does not match fixed tree")
        lines = contents.splitlines(keepends=True)
        if redaction.end_line > len(lines):
            raise CorpusBuildError("comment redaction line is outside fixed blob")
        selected_lines = lines[redaction.start_line - 1 : redaction.end_line]
        if hashlib.sha256(b"".join(selected_lines)).hexdigest() != redaction.expected_line_sha256:
            raise CorpusBuildError("comment redaction expected line hash does not match")
        for index in range(redaction.start_line, redaction.end_line + 1):
            if (redaction.path, index) in protected:
                raise CorpusBuildError("comment redaction cannot modify a gold or root location")
            if (redaction.path, index) in seen_lines:
                raise CorpusBuildError("comment redaction ranges must not overlap")
            seen_lines.add((redaction.path, index))
            lines[index - 1] = _redaction_marker(lines[index - 1], row.language)
        redacted[redaction.path] = b"".join(lines)
    return redacted


def _all_locations(path: GoldPath) -> tuple[Location, ...]:
    return (path.entry_point, path.critical_operation, *path.trace)


def _without_quarantine(tree: Mapping[str, bytes], quarantine_paths: tuple[str, ...]) -> dict[str, bytes]:
    excluded = set(quarantine_paths)
    return {path: contents for path, contents in tree.items() if path not in excluded}


def _redaction_marker(line: bytes, language: str) -> bytes:
    body = line.rstrip(b"\r\n")
    newline = b"\r\n" if line.endswith(b"\r\n") else b"\n" if line.endswith(b"\n") else b""
    stripped = body.lstrip()
    indent = body[: len(body) - len(stripped)]
    if language in {"python", "shell", "ruby", "yaml"} and stripped.startswith(b"#"):
        return indent + b"# [redacted]" + newline
    if language in {"go", "javascript", "typescript", "java", "c", "cpp", "csharp", "rust"} and stripped.startswith(b"//"):
        return indent + b"// [redacted]" + newline
    if language in {"javascript", "typescript", "java", "c", "cpp", "csharp", "rust"} and stripped.startswith(b"/*") and stripped.endswith(b"*/"):
        return indent + b"/* [redacted] */" + newline
    raise CorpusBuildError("comment redaction must target a language-appropriate comment-only line")


def _verify_location(location: Location, tree: Mapping[str, bytes], name: str) -> None:
    contents = tree.get(location.path)
    if contents is None:
        raise CorpusBuildError(f"{name} location is absent from pinned tree")
    if location.end_line > len(contents.splitlines()):
        raise CorpusBuildError(f"{name} location line is outside pinned blob")


def _materialize_tree(tree: Mapping[str, bytes], destination: Path) -> None:
    destination.mkdir()
    for path, contents in sorted(tree.items()):
        target = destination.joinpath(*PurePosixPath(path).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)


def _audit_snapshot(snapshot: Path) -> None:
    try:
        violations = audit_bundle(snapshot)
    except BundleAuditError as error:
        raise CorpusBuildError("snapshot audit could not inspect materialized tree") from error
    if violations:
        raise CorpusBuildError("snapshot contamination or unsafe metadata was detected")


def _validate_git_path(path: str) -> None:
    pure = PurePosixPath(path)
    windows = PureWindowsPath(path)
    if not path or "\\" in path or "\x00" in path or pure.is_absolute() or windows.is_absolute() or ".." in pure.parts:
        raise CorpusBuildError("Git tree contains an unsafe path")
    for part in pure.parts:
        stem = part.split(".", 1)[0].upper()
        if part.endswith((".", " ")) or any(character in part for character in '<>:"|?*') or stem in _WINDOWS_RESERVED_NAMES:
            raise CorpusBuildError("Git tree contains a Windows-unsafe path")


def _require_git_path(value: object, name: str) -> str:
    path = _require_non_empty_string(value, name)
    _validate_git_path(path)
    return path


def _validate_output_root(output_root: Path) -> None:
    if output_root.exists() or _is_link_or_reparse(output_root):
        raise CorpusBuildError("corpus output root must not exist")
    parent = output_root.parent
    if not parent.is_dir() or _is_link_or_reparse(parent):
        raise CorpusBuildError("corpus output parent must be a real directory")
    repository_root = _REPOSITORY_ROOT.resolve(strict=True)
    absolute_output = Path(os.path.abspath(output_root))
    if not _is_within(absolute_output, repository_root):
        return
    allowed_root = repository_root / "benchmarks" / "hermesbench" / "corpora"
    if not _is_within(absolute_output, allowed_root) or absolute_output == allowed_root:
        raise CorpusBuildError("repository output root must be below the ignored corpus root")
    _reject_linked_ancestors(absolute_output.parent, repository_root)
    if not _git_ignored(repository_root, absolute_output):
        raise CorpusBuildError("repository output root must be ignored by Git")


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _reject_linked_ancestors(path: Path, stop: Path) -> None:
    current = path
    while True:
        if _is_link_or_reparse(current):
            raise CorpusBuildError("repository output path must not traverse a link or reparse point")
        if current == stop:
            return
        current = current.parent


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def _git_ignored(repository_root: Path, output_root: Path) -> bool:
    completed = _git_completed(
        repository_root,
        "check-ignore",
        "--no-index",
        "--quiet",
        "--",
        os.fspath(output_root),
        check=False,
    )
    if completed.returncode not in {0, 1}:
        raise CorpusBuildError("could not verify repository output ignore rule")
    return completed.returncode == 0


def _git(repository: Path, *arguments: str) -> str:
    return _git_bytes(repository, *arguments).decode("utf-8", errors="strict").strip()


def _git_bytes(
    repository: Path, *arguments: str, input_bytes: bytes | None = None
) -> bytes:
    completed = _git_completed(
        repository, *arguments, check=True, input_bytes=input_bytes
    )
    return completed.stdout


def _git_success(repository: Path, *arguments: str) -> bool:
    return _git_completed(repository, *arguments, check=False).returncode == 0


def _git_completed(
    repository: Path, *arguments: str, check: bool, input_bytes: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", "-C", os.fspath(repository), *arguments],
            check=check,
            shell=False,
            capture_output=True,
            env=_git_environment(),
            input=input_bytes,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise CorpusBuildError("pinned local Git verification failed") from error
    return completed


def _git_environment() -> dict[str, str]:
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    return environment


def _parse_suites(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise CorpusBuildError("suites must be a non-empty array")
    suites = tuple(_require_non_empty_string(item, "suite") for item in value)
    if len(suites) != len(set(suites)) or any(suite not in _SUITES for suite in suites):
        raise CorpusBuildError("suites must contain distinct known suite names")
    return suites


def _parse_comment_redactions(value: object) -> tuple[CommentRedaction, ...]:
    if not isinstance(value, list):
        raise CorpusBuildError("comment_redactions must be an array")
    redactions: list[CommentRedaction] = []
    for item in value:
        if not isinstance(item, dict):
            raise CorpusBuildError("comment redaction must be an object")
        _require_exact_fields(
            item,
            {"tree", "path", "blob_sha256", "line", "expected_line_sha256"},
            "comment redaction",
        )
        path = _require_non_empty_string(item["path"], "comment redaction path")
        _validate_git_path(path)
        start_line, end_line = _parse_line_range(item["line"], "comment redaction line")
        redactions.append(
            CommentRedaction(
                tree=_require_commit(item["tree"], "comment redaction tree"),
                path=path,
                blob_sha256=_require_sha256(item["blob_sha256"], "comment redaction blob_sha256"),
                start_line=start_line,
                end_line=end_line,
                expected_line_sha256=_require_sha256(item["expected_line_sha256"], "comment redaction expected_line_sha256"),
            )
        )
    return tuple(redactions)


def _parse_quarantine_paths(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise CorpusBuildError("quarantine_paths must be an array")
    paths = tuple(_require_non_empty_string(item, "quarantine path") for item in value)
    for path in paths:
        _validate_git_path(path)
    if len(paths) != len(set(paths)):
        raise CorpusBuildError("quarantine paths must be distinct")
    return paths


def _parse_line_range(value: object, name: str) -> tuple[int, int]:
    if isinstance(value, bool):
        raise CorpusBuildError(f"{name} must be an integer or range")
    if isinstance(value, int):
        start = end = value
    elif isinstance(value, str) and value.count("-") == 1:
        left, right = value.split("-", 1)
        if not left.isdigit() or not right.isdigit():
            raise CorpusBuildError(f"{name} must be an integer or range")
        start, end = int(left), int(right)
    else:
        raise CorpusBuildError(f"{name} must be an integer or range")
    if start < 1 or end < start:
        raise CorpusBuildError(f"{name} must be positive and ordered")
    return start, end


def _parse_gold_paths(value: object, name: str) -> tuple[GoldPath, ...]:
    if not isinstance(value, list):
        raise CorpusBuildError(f"{name} must be an array")
    paths: list[GoldPath] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"path_id", "entry_point", "critical_operation", "trace"}:
            raise CorpusBuildError(f"{name} must contain exact gold path objects")
        try:
            path = GoldPath(
                path_id=_require_non_empty_string(item["path_id"], "path_id"),
                entry_point=Location.from_json(item["entry_point"]),
                critical_operation=Location.from_json(item["critical_operation"]),
                trace=tuple(Location.from_json(location) for location in _require_list(item["trace"], "trace")),
            )
        except ContractError as error:
            raise CorpusBuildError(f"{name} has an invalid location") from error
        paths.append(path)
    if len({path.path_id for path in paths}) != len(paths):
        raise CorpusBuildError(f"{name} contains duplicate path IDs")
    return tuple(paths)


def _gold_path_json(path: GoldPath) -> dict[str, object]:
    return {
        "path_id": path.path_id,
        "entry_point": _location_json(path.entry_point),
        "critical_operation": _location_json(path.critical_operation),
        "trace": [_location_json(location) for location in path.trace],
    }


def _location_json(location: Location) -> dict[str, object]:
    line: int | str = location.start_line if location.start_line == location.end_line else f"{location.start_line}-{location.end_line}"
    return {"file": location.path, "line": line}


def _language_counts(rows: tuple[SelectedLedgerRow, ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.language] = counts.get(row.language, 0) + 2
    return dict(sorted(counts.items()))


def _snapshot_size_buckets(snapshots: list[Path]) -> dict[str, int]:
    buckets = {"0-4KiB": 0, "4-64KiB": 0, "64KiB+": 0}
    for snapshot in snapshots:
        size = sum(path.stat().st_size for path in snapshot.rglob("*") if path.is_file())
        if size < 4 * 1024:
            buckets["0-4KiB"] += 1
        elif size < 64 * 1024:
            buckets["4-64KiB"] += 1
        else:
            buckets["64KiB+"] += 1
    return buckets


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical_json(value) + b"\n")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_bytes(b"".join(_canonical_json(row) + b"\n" for row in rows))


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256_json(value: object) -> str:
    return _sha256_bytes(_canonical_json(value))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_exact_fields(value: dict[str, object], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise CorpusBuildError(f"{name} must contain exactly the required fields")


def _require_schema(value: object) -> None:
    if isinstance(value, bool) or value != SCHEMA_VERSION:
        raise CorpusBuildError(f"schema_version must be {SCHEMA_VERSION}")


def _require_commit(value: object, name: str) -> str:
    commit = _require_non_empty_string(value, name)
    if _COMMIT_PATTERN.fullmatch(commit) is None:
        raise CorpusBuildError(f"{name} must be a lowercase 40-character Git object ID")
    return commit


def _require_sha256(value: object, name: str) -> str:
    digest = _require_non_empty_string(value, name)
    if _SHA256_PATTERN.fullmatch(digest) is None:
        raise CorpusBuildError(f"{name} must be a lowercase SHA-256 digest")
    return digest


def _require_non_empty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CorpusBuildError(f"{name} must be a non-empty string")
    return value


def _require_list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise CorpusBuildError(f"{name} must be an array")
    return value
