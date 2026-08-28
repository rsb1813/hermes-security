import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from benchmarks.hermesbench.semantic_guidance import (
    MAX_FILE_BYTES,
    GuidanceLimits,
    PROFILE_LIMITS,
    SemanticGuidance,
    build_semantic_guidance,
)


class SemanticGuidanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self._root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _build(
        self,
        name: str,
        files: dict[str, str | bytes],
        profile: str = "hunt-balanced",
    ) -> SemanticGuidance:
        snapshot = self._root / name
        snapshot.mkdir()
        for relative, value in files.items():
            path = snapshot / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, bytes):
                path.write_bytes(value)
            else:
                path.write_text(value, encoding="utf-8")
        return build_semantic_guidance(snapshot, tuple(files), profile)

    def _rows(self, files: dict[str, str | bytes]) -> list[dict[str, object]]:
        result = self._build(f"case-{len(tuple(self._root.iterdir()))}", files)
        return [json.loads(line) for line in result.canonical_bytes.decode("utf-8").splitlines()]

    def _single_row(self, files: dict[str, str | bytes]) -> dict[str, object]:
        rows = self._rows(files)
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_same_source_bytes_produce_identical_guidance(self) -> None:
        first = self._build(
            "first",
            {"app.py": "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n"},
        )
        second = self._build(
            "second",
            {"app.py": "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n"},
        )
        self.assertEqual(first.canonical_bytes, second.canonical_bytes)
        self.assertEqual(first.row_count, 1)
        row = json.loads(first.canonical_bytes.decode("utf-8").splitlines()[0])
        self.assertEqual(
            set(row),
            {
                "schema_version",
                "hint_id",
                "strength",
                "operation_family",
                "source",
                "operation",
                "trace",
                "controls",
                "reason_codes",
                "proof_status",
            },
        )
        self.assertEqual(row["proof_status"], "investigation_only")

    def test_python_go_and_typescript_direct_routes(self) -> None:
        fixtures = {
            "python": ("app.py", "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n"),
            "go": ("app.go", "func Handle(r *http.Request) { exec.Command(r.URL.Query().Get(\"q\")) }\n"),
            "typescript": ("app.ts", "export function handle(request: Request) { return child_process.exec(request.query.q); }\n"),
        }
        for language, (path, source) in fixtures.items():
            with self.subTest(language=language):
                row = self._single_row({path: source})
                self.assertEqual(row["strength"], "direct")
                self.assertEqual(row["proof_status"], "investigation_only")

    def test_explicit_import_produces_import_linked_route(self) -> None:
        result = self._build(
            "linked",
            {
                "api.py": "from store import run\ndef handle(request):\n    return run(request.args['q'])\n",
                "store.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            },
        )
        row = json.loads(result.canonical_bytes.decode("utf-8").splitlines()[0])
        self.assertEqual(row["strength"], "import-linked")
        self.assertEqual([item["path"] for item in row["trace"]], ["api.py", "store.py"])

    def test_ambiguous_name_never_becomes_a_strong_route(self) -> None:
        rows = self._rows(
            {
                "api.py": "def handle(request):\n    return run(request.args['q'])\n",
                "one.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
                "two.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            }
        )
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["strength"] == "name-only" for row in rows))

    def test_generic_source_is_name_only(self) -> None:
        row = self._single_row({"handler.txt": "request = input\nexec(request)\n"})
        self.assertEqual(row["strength"], "name-only")

    def test_cycle_has_no_repeated_trace_node(self) -> None:
        rows = self._rows(
            {
                "api.py": "from store import run\ndef handle(request):\n    return run(request.args['q'])\n",
                "store.py": "from api import handle\nimport subprocess\ndef run(value):\n    handle(value)\n    return subprocess.run(value)\n",
            }
        )
        self.assertEqual(len(rows), 1)
        trace = rows[0]["trace"]
        self.assertLessEqual(len(trace), 12)
        self.assertEqual(
            len(trace),
            len({(item["path"], item["line"], item["symbol"]) for item in trace}),
        )

    def test_invalid_and_oversized_files_are_skipped(self) -> None:
        result = self._build(
            "skips",
            {
                "app.py": "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
                "large.py": b"x" * (MAX_FILE_BYTES + 1),
                "invalid.py": b"\xff",
            },
        )
        self.assertEqual(result.scanned_file_count, 1)
        self.assertEqual(result.skipped_file_count, 2)
        self.assertEqual(result.row_count, 1)

    def test_duplicate_frontier_path_does_not_duplicate_endpoint(self) -> None:
        snapshot = self._root / "duplicate"
        snapshot.mkdir()
        (snapshot / "app.py").write_text(
            "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
            encoding="utf-8",
        )
        result = build_semantic_guidance(snapshot, ("app.py", "app.py"), "hunt-balanced")
        self.assertEqual(result.scanned_file_count, 1)
        self.assertEqual(result.row_count, 1)

    def test_tiny_limits_truncate_output_before_partial_row(self) -> None:
        limits = GuidanceLimits(1024, 10, 10, 10, 10, 1, 1)
        with mock.patch.dict(PROFILE_LIMITS, {"test-tiny": limits}):
            result = self._build(
                "tiny",
                {"app.py": "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n"},
                "test-tiny",
            )
        self.assertEqual(result.canonical_bytes, b"")
        self.assertEqual(result.row_count, 0)

    def test_controls_are_bounded_to_eight(self) -> None:
        controls = "\n".join("    validate(request)" for _ in range(9))
        row = self._single_row(
            {
                "app.py": (
                    "import subprocess\ndef handle(request):\n"
                    f"{controls}\n"
                    "    return subprocess.run(request.args['q'])\n"
                )
            }
        )
        self.assertEqual(len(row["controls"]), 8)
