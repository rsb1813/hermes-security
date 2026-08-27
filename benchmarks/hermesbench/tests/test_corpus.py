# Verifies reviewed VulnGym import and anonymization.

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.hermesbench.corpus import anonymous_task_id, load_vulngym_candidates

DATASET_REVISION = "cd69f7e163e08485ab5496115ae03439cda6e27e"
REPORT = {
    "report_id": "GHSA-2345-6789-cfgh",
    "repo_url": "https://github.com/example/project",
    "commit": "1" * 40,
    "entry_ids": ["entry-00001", "entry-00002"],
}
VERIFIED_ENTRY = {
    "entry_id": "entry-00001",
    "report_id": REPORT["report_id"],
    "repo_url": REPORT["repo_url"],
    "commit": REPORT["commit"],
    "vuln_category_l1": "Authorization",
    "vuln_category_l2": "Missing authorization",
    "entry_point": {
        "file": "src/api.py",
        "line": 10,
        "code": "handle(request)",
        "desc": "reachable input",
    },
    "critical_operation": {
        "file": "src/db.py",
        "line": 20,
        "code": "save(record)",
    },
    "trace": [
        {"file": "src/policy.py", "line": 15, "code": "allow = True"}
    ],
    "verify": 1,
}
UNVERIFIED_ENTRY = VERIFIED_ENTRY | {"entry_id": "entry-00002", "verify": 0}


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def load_fixture(
    entries: list[dict[str, object]], reports: list[dict[str, object]]
):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_jsonl(root / "entries.jsonl", entries)
        write_jsonl(root / "reports.jsonl", reports)
        return load_vulngym_candidates(
            root / "entries.jsonl",
            root / "reports.jsonl",
            dataset_revision=DATASET_REVISION,
            anonymization_key=b"fixture-key",
        )


class CorpusTests(unittest.TestCase):
    def test_importer_keeps_only_human_reviewed_entries(self) -> None:
        candidates, summary = load_fixture(
            [VERIFIED_ENTRY, UNVERIFIED_ENTRY], [REPORT]
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(summary.total_entries, 2)
        self.assertEqual(summary.verified_entries, 1)
        self.assertEqual(summary.unverified_entries, 1)
        self.assertTrue(candidates[0].task_id.startswith("hb-"))

    def test_anonymous_id_is_keyed_and_deterministic(self) -> None:
        first = anonymous_task_id(b"key-a", "revision", "entry-00001")
        self.assertEqual(
            first, anonymous_task_id(b"key-a", "revision", "entry-00001")
        )
        self.assertNotEqual(
            first, anonymous_task_id(b"key-b", "revision", "entry-00001")
        )
        self.assertNotIn("00001", first)

    def test_anonymous_id_rejects_an_empty_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "key"):
            anonymous_task_id(b"", "revision", "entry-00001")

    def test_missing_report_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing report"):
            load_fixture(entries=[VERIFIED_ENTRY], reports=[])

    def test_malformed_commit_is_rejected(self) -> None:
        bad_report = REPORT | {"commit": "not-a-commit"}
        bad_entry = VERIFIED_ENTRY | {"commit": "not-a-commit"}
        with self.assertRaisesRegex(ValueError, "commit"):
            load_fixture(entries=[bad_entry], reports=[bad_report])

    def test_report_and_entry_source_must_match(self) -> None:
        entry = VERIFIED_ENTRY | {
            "repo_url": "https://github.com/example/other-project"
        }
        with self.assertRaisesRegex(ValueError, "repo_url"):
            load_fixture(entries=[entry], reports=[REPORT | {"entry_ids": ["entry-00001"]}])

    def test_report_entry_membership_is_validated(self) -> None:
        report = REPORT | {"entry_ids": ["entry-99999"]}
        with self.assertRaisesRegex(ValueError, "entry_ids"):
            load_fixture(entries=[VERIFIED_ENTRY], reports=[report])

    def test_range_lines_survive_import(self) -> None:
        entry = VERIFIED_ENTRY | {
            "entry_point": VERIFIED_ENTRY["entry_point"] | {"line": "10-12"}
        }
        report = REPORT | {"entry_ids": ["entry-00001"]}
        candidate = load_fixture(entries=[entry], reports=[report])[0][0]
        self.assertEqual(candidate.gold_path.entry_point.start_line, 10)
        self.assertEqual(candidate.gold_path.entry_point.end_line, 12)

    def test_public_summary_contains_no_advisory_or_source_identity(self) -> None:
        _, summary = load_fixture(
            [VERIFIED_ENTRY], [REPORT | {"entry_ids": ["entry-00001"]}]
        )
        encoded = json.dumps(summary.to_json(), sort_keys=True)
        self.assertNotIn("GHSA", encoded)
        self.assertNotIn("github.com", encoded)
        self.assertNotIn("entry-00001", encoded)

    def test_verify_must_be_the_integer_zero_or_one(self) -> None:
        entry = VERIFIED_ENTRY | {"verify": True}
        report = REPORT | {"entry_ids": ["entry-00001"]}
        with self.assertRaisesRegex(ValueError, "verify"):
            load_fixture(entries=[entry], reports=[report])


if __name__ == "__main__":
    unittest.main()
