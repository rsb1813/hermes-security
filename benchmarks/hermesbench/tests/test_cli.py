# Verifies the standalone HermesBench CLI.

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from benchmarks.hermesbench.receipts import (
    RunConfig,
    RunReceipt,
    TokenUsage,
    write_receipt,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "benchmarks.hermesbench", *arguments],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def location(path: str, line: int) -> dict[str, object]:
    return {"file": path, "line": line}


GOLD_PATH = {
    "path_id": "path-1",
    "entry_point": location("src/api.py", 10),
    "critical_operation": location("src/db.py", 20),
    "trace": [location("src/policy.py", 15)],
}
ORACLES = [
    {
        "schema_version": 1,
        "task_id": "hb-vulnerable",
        "kind": "vulnerable",
        "group_id": "group-a",
        "split": "hidden_test",
        "category": "authorization",
        "language": "python",
        "paths": [GOLD_PATH],
        "retired_paths": [],
    },
    {
        "schema_version": 1,
        "task_id": "hb-fixed",
        "kind": "fixed",
        "group_id": "group-a",
        "split": "hidden_test",
        "category": "authorization",
        "language": "python",
        "paths": [],
        "retired_paths": [GOLD_PATH],
    },
]
PREDICTIONS = [
    {
        "schema_version": 1,
        "task_id": "hb-vulnerable",
        "findings": [
            {
                "finding_id": "f-1",
                "entry_point": location("src/api.py", 10),
                "critical_operation": location("src/db.py", 20),
                "trace": [location("src/policy.py", 15)],
                "confidence": 0.9,
            }
        ],
    },
    {"schema_version": 1, "task_id": "hb-fixed", "findings": []},
]


def config() -> RunConfig:
    return RunConfig(
        manifest_sha256="a" * 64,
        task_order_sha256="b" * 64,
        grader_version="0.1.0",
        model="gpt-test",
        reasoning_effort="medium",
        seed="12345",
        seed_supported=True,
        tool_versions=(("python", "3.14.6"),),
        time_limit_seconds=300,
    )


def receipt(workflow: str, run_config: RunConfig) -> RunReceipt:
    return RunReceipt(
        schema_version=1,
        run_id=f"run-{workflow}",
        workflow=workflow,
        profile="baseline" if workflow == "standard" else "hunt-max",
        config=run_config,
        elapsed_seconds=10.0,
        status="completed",
        token_usage=TokenUsage(10, 20, 5),
    )


EVIDENCE = {
    "ci_low": 0.01,
    "ci_high": 0.08,
    "hidden_additional_localized": 2,
    "repeat_winners": ["hunt", "hunt", "hunt"],
    "category_recall_deltas": [["python", 0.0]],
    "comparison_semantics_changed": False,
    "final_stage": False,
    "release_candidate": False,
    "public_performance_claim": False,
}


class AuditCommandTests(unittest.TestCase):
    def test_audit_bundle_returns_nonzero_for_contamination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "source.py").write_text(
                "# GHSA-2345-6789-cfgh\n", encoding="utf-8"
            )
            result = run_cli("audit-bundle", "--bundle", str(bundle))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["violations"][0]["code"],
            "advisory_identifier",
        )

    def test_audit_bundle_returns_zero_for_clean_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "source.py").write_text("value = 1\n", encoding="utf-8")
            result = run_cli("audit-bundle", "--bundle", str(bundle))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"violations": []})


class ScoreCommandTests(unittest.TestCase):
    def test_score_writes_the_machine_readable_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracles = root / "oracles.jsonl"
            predictions = root / "predictions.jsonl"
            output = root / "score.json"
            write_jsonl(oracles, ORACLES)
            write_jsonl(predictions, PREDICTIONS)
            result = run_cli(
                "score",
                "--oracles",
                str(oracles),
                "--predictions",
                str(predictions),
                "--out",
                str(output),
            )
            score = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(score["composite_score"], 1.0)

    def test_score_returns_json_error_for_an_invalid_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracles = root / "oracles.jsonl"
            predictions = root / "predictions.jsonl"
            output = root / "score.json"
            write_jsonl(oracles, [{}])
            write_jsonl(predictions, [])
            result = run_cli(
                "score",
                "--oracles",
                str(oracles),
                "--predictions",
                str(predictions),
                "--out",
                str(output),
            )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["error_type"], "ContractError")


class CompareCommandTests(unittest.TestCase):
    def test_compare_rejects_changed_controls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            standard_path = root / "standard.json"
            hunt_path = root / "hunt.json"
            evidence_path = root / "evidence.json"
            output = root / "comparison.json"
            write_receipt(standard_path, receipt("standard", config()))
            write_receipt(
                hunt_path,
                receipt("hunt", config().replace(reasoning_effort="high")),
            )
            write_json(evidence_path, EVIDENCE)
            result = run_cli(
                "compare",
                "--standard-receipt",
                str(standard_path),
                "--hunt-receipt",
                str(hunt_path),
                "--evidence",
                str(evidence_path),
                "--out",
                str(output),
            )
            comparison = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(comparison["mismatches"], ["reasoning_effort"])

    def test_final_stage_requires_full_for_a_comparable_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            standard_path = root / "standard.json"
            hunt_path = root / "hunt.json"
            evidence_path = root / "evidence.json"
            output = root / "comparison.json"
            shared_config = config()
            write_receipt(standard_path, receipt("standard", shared_config))
            write_receipt(hunt_path, receipt("hunt", shared_config))
            write_json(evidence_path, EVIDENCE | {"final_stage": True})
            result = run_cli(
                "compare",
                "--standard-receipt",
                str(standard_path),
                "--hunt-receipt",
                str(hunt_path),
                "--evidence",
                str(evidence_path),
                "--out",
                str(output),
            )
            comparison = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(comparison["full_required"])
        self.assertIn("final_stage", comparison["reasons"])


class ImportCommandTests(unittest.TestCase):
    def test_import_writes_private_candidates_and_identity_free_summary(self) -> None:
        report = {
            "report_id": "GHSA-2345-6789-cfgh",
            "repo_url": "https://github.com/example/project",
            "commit": "1" * 40,
            "entry_ids": ["entry-00001"],
        }
        entry = {
            "entry_id": "entry-00001",
            "report_id": report["report_id"],
            "repo_url": report["repo_url"],
            "commit": report["commit"],
            "vuln_category_l1": "Authorization",
            "vuln_category_l2": "Missing authorization",
            "entry_point": location("src/api.py", 10) | {"code": "entry()"},
            "critical_operation": location("src/db.py", 20) | {"code": "save()"},
            "trace": [],
            "verify": 1,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = root / "entries.jsonl"
            reports = root / "reports.jsonl"
            key = root / "key.bin"
            private_output = root / "private.json"
            summary_output = root / "summary.json"
            write_jsonl(entries, [entry])
            write_jsonl(reports, [report])
            key.write_bytes(b"private-test-key")
            result = run_cli(
                "import-vulngym",
                "--entries",
                str(entries),
                "--reports",
                str(reports),
                "--dataset-revision",
                "c" * 40,
                "--key-file",
                str(key),
                "--private-out",
                str(private_output),
                "--summary-out",
                str(summary_output),
            )
            private_data = json.loads(private_output.read_text(encoding="utf-8"))
            summary_text = summary_output.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(private_data["candidates"]), 1)
        self.assertNotIn("GHSA", summary_text)
        self.assertNotIn("github.com", summary_text)
        self.assertNotIn("private-test-key", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
