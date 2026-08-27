# Imports reviewed VulnGym labels into private benchmark records.

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .contracts import GoldPath, Location

_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
_ENTRY_ID_PATTERN = re.compile(r"entry-\d{5}\Z")


@dataclass(frozen=True)
class CorpusCandidate:
    task_id: str
    dataset_revision: str
    entry_id: str
    report_id: str
    repo_url: str
    vulnerable_commit: str
    category_l1: str
    category_l2: str
    gold_path: GoldPath

    def to_private_json(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "dataset_revision": self.dataset_revision,
            "source": {
                "entry_id": self.entry_id,
                "report_id": self.report_id,
                "repo_url": self.repo_url,
                "vulnerable_commit": self.vulnerable_commit,
            },
            "category_l1": self.category_l1,
            "category_l2": self.category_l2,
            "gold_path": _gold_path_to_json(self.gold_path),
        }


@dataclass(frozen=True)
class CorpusSummary:
    dataset_revision: str
    total_reports: int
    total_entries: int
    verified_entries: int
    unverified_entries: int
    candidate_reports: int

    def to_json(self) -> dict[str, object]:
        return {
            "dataset_revision": self.dataset_revision,
            "total_reports": self.total_reports,
            "total_entries": self.total_entries,
            "verified_entries": self.verified_entries,
            "unverified_entries": self.unverified_entries,
            "candidate_reports": self.candidate_reports,
        }


@dataclass(frozen=True)
class _Report:
    report_id: str
    repo_url: str
    commit: str
    entry_ids: tuple[str, ...]


def anonymous_task_id(key: bytes, dataset_revision: str, entry_id: str) -> str:
    if not isinstance(key, bytes) or not key:
        raise ValueError("anonymization key must be non-empty bytes")
    revision = _require_non_empty_string(dataset_revision, "dataset_revision")
    source_entry_id = _require_non_empty_string(entry_id, "entry_id")
    message = f"{revision}\x00{source_entry_id}".encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()[:20]
    return f"hb-{digest}"


def load_vulngym_candidates(
    entries_path: Path,
    reports_path: Path,
    *,
    dataset_revision: str,
    anonymization_key: bytes,
) -> tuple[tuple[CorpusCandidate, ...], CorpusSummary]:
    _require_commit(dataset_revision, "dataset_revision")
    anonymous_task_id(anonymization_key, dataset_revision, "key-check")

    report_rows = _load_jsonl(reports_path)
    reports: dict[str, _Report] = {}
    for line_number, row in report_rows:
        report = _parse_report(row, reports_path, line_number)
        if report.report_id in reports:
            raise ValueError(
                f"{reports_path}: line {line_number}: duplicate report_id {report.report_id}"
            )
        reports[report.report_id] = report

    entry_rows = _load_jsonl(entries_path)
    seen_entry_ids: set[str] = set()
    joined_entry_ids: dict[str, set[str]] = {report_id: set() for report_id in reports}
    candidates: list[CorpusCandidate] = []
    unverified_entries = 0

    for line_number, row in entry_rows:
        entry_id = _require_entry_id(
            _required(row, "entry_id", entries_path, line_number), "entry_id"
        )
        if entry_id in seen_entry_ids:
            raise ValueError(
                f"{entries_path}: line {line_number}: duplicate entry_id {entry_id}"
            )
        seen_entry_ids.add(entry_id)

        report_id = _require_non_empty_string(
            _required(row, "report_id", entries_path, line_number), "report_id"
        )
        report = reports.get(report_id)
        if report is None:
            raise ValueError(
                f"{entries_path}: line {line_number}: missing report {report_id}"
            )
        if entry_id not in report.entry_ids:
            raise ValueError(
                f"{entries_path}: line {line_number}: entry_id absent from report entry_ids"
            )
        joined_entry_ids[report_id].add(entry_id)

        repo_url = _require_github_repo(
            _required(row, "repo_url", entries_path, line_number), "repo_url"
        )
        commit = _require_commit(
            _required(row, "commit", entries_path, line_number), "commit"
        )
        if repo_url != report.repo_url:
            raise ValueError(
                f"{entries_path}: line {line_number}: repo_url does not match report"
            )
        if commit != report.commit:
            raise ValueError(
                f"{entries_path}: line {line_number}: commit does not match report"
            )

        verify = _required(row, "verify", entries_path, line_number)
        if isinstance(verify, bool) or not isinstance(verify, int) or verify not in (0, 1):
            raise ValueError(
                f"{entries_path}: line {line_number}: verify must be integer 0 or 1"
            )
        category_l1 = _require_non_empty_string(
            _required(row, "vuln_category_l1", entries_path, line_number),
            "vuln_category_l1",
        )
        category_l2 = _require_non_empty_string(
            _required(row, "vuln_category_l2", entries_path, line_number),
            "vuln_category_l2",
        )
        entry_point = _parse_label_location(
            _required(row, "entry_point", entries_path, line_number), "entry_point"
        )
        critical_operation = _parse_label_location(
            _required(row, "critical_operation", entries_path, line_number),
            "critical_operation",
        )
        raw_trace = _required(row, "trace", entries_path, line_number)
        if not isinstance(raw_trace, list):
            raise ValueError(f"{entries_path}: line {line_number}: trace must be an array")
        trace = tuple(
            _parse_label_location(item, f"trace[{index}]")
            for index, item in enumerate(raw_trace)
        )

        if verify == 0:
            unverified_entries += 1
            continue
        task_id = anonymous_task_id(anonymization_key, dataset_revision, entry_id)
        candidates.append(
            CorpusCandidate(
                task_id=task_id,
                dataset_revision=dataset_revision,
                entry_id=entry_id,
                report_id=report_id,
                repo_url=repo_url,
                vulnerable_commit=commit,
                category_l1=category_l1,
                category_l2=category_l2,
                gold_path=GoldPath(
                    path_id=f"{task_id}-path-1",
                    entry_point=entry_point,
                    critical_operation=critical_operation,
                    trace=trace,
                ),
            )
        )

    for report_id, report in reports.items():
        if joined_entry_ids[report_id] != set(report.entry_ids):
            raise ValueError(
                f"{reports_path}: report {report_id} entry_ids do not match entries.jsonl"
            )

    ordered = tuple(sorted(candidates, key=lambda candidate: candidate.task_id))
    summary = CorpusSummary(
        dataset_revision=dataset_revision,
        total_reports=len(reports),
        total_entries=len(entry_rows),
        verified_entries=len(ordered),
        unverified_entries=unverified_entries,
        candidate_reports=len({candidate.report_id for candidate in ordered}),
    )
    return ordered, summary


def _parse_report(row: dict[str, object], path: Path, line_number: int) -> _Report:
    report_id = _require_non_empty_string(
        _required(row, "report_id", path, line_number), "report_id"
    )
    repo_url = _require_github_repo(
        _required(row, "repo_url", path, line_number), "repo_url"
    )
    commit = _require_commit(_required(row, "commit", path, line_number), "commit")
    raw_entry_ids = _required(row, "entry_ids", path, line_number)
    if not isinstance(raw_entry_ids, list) or not raw_entry_ids:
        raise ValueError(f"{path}: line {line_number}: entry_ids must be a non-empty array")
    entry_ids = tuple(_require_entry_id(item, "entry_ids item") for item in raw_entry_ids)
    if len(entry_ids) != len(set(entry_ids)):
        raise ValueError(f"{path}: line {line_number}: duplicate report entry_ids")
    return _Report(
        report_id=report_id,
        repo_url=repo_url,
        commit=commit,
        entry_ids=entry_ids,
    )


def _parse_label_location(value: object, name: str) -> Location:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    for field in ("file", "line", "code"):
        if field not in value:
            raise ValueError(f"{name} is missing {field}")
    if not isinstance(value["code"], str):
        raise ValueError(f"{name} code must be a string")
    if "desc" in value and not isinstance(value["desc"], str):
        raise ValueError(f"{name} desc must be a string")
    return Location.from_json({"file": value["file"], "line": value["line"]})


def _load_jsonl(path: Path) -> list[tuple[int, dict[str, object]]]:
    rows: list[tuple[int, dict[str, object]]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            if not raw_line.strip():
                continue
            try:
                value = json.loads(raw_line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}: line {line_number}: invalid JSON") from error
            if not isinstance(value, dict) or not all(
                isinstance(key, str) for key in value
            ):
                raise ValueError(f"{path}: line {line_number}: row must be an object")
            rows.append((line_number, value))
    return rows


def _required(
    row: dict[str, object], field: str, path: Path, line_number: int
) -> object:
    if field not in row:
        raise ValueError(f"{path}: line {line_number}: missing field {field}")
    return row[field]


def _require_entry_id(value: object, name: str) -> str:
    entry_id = _require_non_empty_string(value, name)
    if _ENTRY_ID_PATTERN.fullmatch(entry_id) is None:
        raise ValueError(f"{name} must use entry-00000 format")
    return entry_id


def _require_commit(value: object, name: str) -> str:
    commit = _require_non_empty_string(value, name)
    if _COMMIT_PATTERN.fullmatch(commit) is None:
        raise ValueError(f"{name} must be a 40-character lowercase commit")
    return commit


def _require_github_repo(value: object, name: str) -> str:
    repo_url = _require_non_empty_string(value, name)
    parsed = urlsplit(repo_url)
    parts = tuple(part for part in parsed.path.split("/") if part)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or len(parts) != 2
    ):
        raise ValueError(f"{name} must be a canonical HTTPS GitHub repository URL")
    return repo_url


def _require_non_empty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _gold_path_to_json(path: GoldPath) -> dict[str, object]:
    return {
        "path_id": path.path_id,
        "entry_point": _location_to_json(path.entry_point),
        "critical_operation": _location_to_json(path.critical_operation),
        "trace": [_location_to_json(location) for location in path.trace],
    }


def _location_to_json(location: Location) -> dict[str, object]:
    line: int | str
    if location.start_line == location.end_line:
        line = location.start_line
    else:
        line = f"{location.start_line}-{location.end_line}"
    return {"file": location.path, "line": line}
