import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from benchmarks.hermesbench import semantic_guidance
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

    def _build_with_limits(
        self,
        name: str,
        files: dict[str, str | bytes],
        limits: GuidanceLimits,
    ) -> SemanticGuidance:
        with mock.patch.dict(PROFILE_LIMITS, {"test-limits": limits}):
            return self._build(name, files, "test-limits")

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
        self.assertEqual(
            first.canonical_bytes,
            b'{"controls":[],"hint_id":"f51a8b5b354cdafd","operation":{"line":3,"path":"app.py","symbol":"subprocess.run"},"operation_family":"command","proof_status":"investigation_only","reason_codes":["source_anchor","operation_anchor","same_declaration"],"schema_version":1,"source":{"line":2,"path":"app.py","symbol":"handle"},"strength":"direct","trace":[{"line":2,"path":"app.py","symbol":"handle"}]}\n',
        )
        self.assertTrue(first.canonical_bytes)
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

    def test_unique_same_file_call_produces_direct_route(self) -> None:
        row = self._single_row(
            {
                "app.py": (
                    "import subprocess\n"
                    "def handle(request):\n"
                    "    return run(request.args['q'])\n"
                    "def run(value):\n"
                    "    return subprocess.run(value)\n"
                )
            }
        )
        self.assertEqual(row["strength"], "direct")
        self.assertEqual([item["symbol"] for item in row["trace"]], ["handle", "run"])

    def test_language_methods_and_assigned_callables_produce_direct_routes(self) -> None:
        fixtures = {
            "python": (
                "app.py",
                "import subprocess\n"
                "class Handler:\n"
                "    def handle(self, request):\n"
                "        return self.run(request.args['q'])\n"
                "    def run(self, value):\n"
                "        return subprocess.run(value)\n",
            ),
            "go": (
                "app.go",
                "type Handler struct{}\n"
                "func (handler Handler) Handle(request *http.Request) { handler.Run(request.URL.Query().Get(\"q\")) }\n"
                "func (handler Handler) Run(value string) { exec.Command(value) }\n",
            ),
            "typescript": (
                "app.ts",
                "class Handler {\n"
                "  handle(request: Request) { return this.run(request.query.q); }\n"
                "  run(value: string) { return child_process.exec(value); }\n"
                "}\n",
            ),
            "javascript": (
                "app.js",
                "const run = (value) => child_process.exec(value);\n"
                "const handle = function (request) { return run(request.query.q); };\n",
            ),
        }
        for language, (path, source) in fixtures.items():
            with self.subTest(language=language):
                row = self._single_row({path: source})
                self.assertEqual(row["strength"], "direct")

    def test_python_go_and_typescript_assigned_callables_produce_direct_routes(self) -> None:
        fixtures = {
            "python": (
                "app.py",
                "import subprocess\n"
                "run = lambda value: subprocess.run(value)\n"
                "handle = lambda request: run(request.args['q'])\n",
            ),
            "go": (
                "app.go",
                "var run = func(value string) { exec.Command(value) }\n"
                "var handle = func(request *http.Request) { run(request.URL.Query().Get(\"q\")) }\n",
            ),
            "typescript": (
                "app.ts",
                "class Handler {\n"
                "  run: (value: string) => void = (value) => child_process.exec(value);\n"
                "  handle: (request: Request) => void = (request) => this.run(request.query.q);\n"
                "}\n",
            ),
        }
        for language, (path, source) in fixtures.items():
            with self.subTest(language=language):
                row = self._single_row({path: source})
                self.assertEqual(row["strength"], "direct")

    def test_class_declarations_are_facts_without_distorting_method_routes(self) -> None:
        fixtures = {
            "python": (
                "app.py",
                "import subprocess\n"
                "class Handler:\n"
                "    def handle(self, request):\n"
                "        return self.run(request.args['q'])\n"
                "    def run(self, value):\n"
                "        return subprocess.run(value)\n",
            ),
            "go": (
                "app.go",
                "type Handler struct{}\n"
                "func (handler Handler) handle(request *http.Request) { handler.run(request.URL.Query().Get(\"q\")) }\n"
                "func (handler Handler) run(value string) { exec.Command(value) }\n",
            ),
            "typescript": (
                "app.ts",
                "class Handler {\n"
                "  handle(request: Request) { return this.run(request.query.q); }\n"
                "  run(value: string) { return child_process.exec(value); }\n"
                "}\n",
            ),
            "javascript": (
                "app.js",
                "class Handler {\n"
                "  handle(request) { return this.run(request.query.q); }\n"
                "  run(value) { return child_process.exec(value); }\n"
                "}\n",
            ),
        }
        for language, (path, source) in fixtures.items():
            with self.subTest(language=language):
                declarations = semantic_guidance._extract_declarations(path, source, 20)
                self.assertIn("Handler", [item.location.symbol for item in declarations])
                row = self._single_row({path: source})
                self.assertEqual([item["symbol"] for item in row["trace"]], ["handle", "run"])

    def test_import_scanner_ignores_fake_imports_inside_non_code(self) -> None:
        fixtures = {
            "python": {
                "api.py": "\"\"\"\nfrom pkg.store import run\n\"\"\"\ndef handle(request):\n    return run(request.args['q'])\n",
                "pkg/store.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            },
            "go": {
                "api.go": "var note = `\n\"pkg/store\"\n`\nfunc handle(request *http.Request) { store.Run(request.URL.Query().Get(\"q\")) }\n",
                "pkg/store.go": "func Run(value string) { exec.Command(value) }\n",
            },
            "typescript": {
                "src/api.ts": "/*\nimport { run } from './store';\n*/\nconst note = `\nimport { run } from './store';\n`;\nexport function handle(request: Request) { return run(request.query.q); }\n",
                "src/store.ts": "export function run(value: string) { return child_process.exec(value); }\n",
            },
            "javascript": {
                "src/api.js": "/*\nimport { run } from './store';\n*/\nconst note = `\nimport { run } from './store';\n`;\nexport function handle(request) { return run(request.query.q); }\n",
                "src/store.js": "export function run(value) { return child_process.exec(value); }\n",
            },
        }
        for language, files in fixtures.items():
            with self.subTest(language=language):
                rows = self._rows(files)
                self.assertFalse(any(row["strength"] == "import-linked" for row in rows))

    def test_package_and_index_modules_remain_exact_import_links(self) -> None:
        fixtures = {
            "python": {
                "api.py": "from pkg import run\ndef handle(request):\n    return run(request.args['q'])\n",
                "pkg/__init__.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            },
            "go": {
                "api.go": "import \"pkg/store\"\nfunc handle(request *http.Request) { store.Run(request.URL.Query().Get(\"q\")) }\n",
                "pkg/store/impl.go": "func Run(value string) { exec.Command(value) }\n",
            },
            "typescript": {
                "src/api.ts": "import { run } from './store';\nexport function handle(request: Request) { return run(request.query.q); }\n",
                "src/store/index.ts": "export function run(value: string) { return child_process.exec(value); }\n",
            },
            "javascript": {
                "src/api.js": "import { run } from './store';\nexport function handle(request) { return run(request.query.q); }\n",
                "src/store/index.js": "export function run(value) { return child_process.exec(value); }\n",
            },
        }
        for language, files in fixtures.items():
            with self.subTest(language=language):
                row = self._single_row(files)
                self.assertEqual(row["strength"], "import-linked")

    def test_go_import_block_ignores_comment_literals_and_keeps_adjacent_import(self) -> None:
        rows = self._rows(
            {
                "api.go": (
                    "import (\n"
                    "  /* \"fake/path\" */\n"
                    "  /*\n"
                    "  \"fake/path\"\n"
                    "  */\n"
                    "  // \"fake/path\"\n"
                    "  \"pkg/store\"\n"
                    ")\n"
                    "func handle(request *http.Request) { path.Run(request.URL.Query().Get(\"q\")); store.Run(request.URL.Query().Get(\"q\")) }\n"
                ),
                "fake/path.go": "func Run(value string) { exec.Command(value) }\n",
                "pkg/store/impl.go": "func Run(value string) { exec.Command(value) }\n",
            }
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["strength"], "import-linked")
        self.assertEqual(rows[0]["operation"]["path"], "pkg/store/impl.go")

    def test_import_links_never_cross_language_families(self) -> None:
        fixtures = {
            "python-to-typescript": {
                "pkg/api.py": "from .store import run\ndef handle(request):\n    return run(request.args['q'])\n",
                "pkg/store/index.ts": "export function run(value: string) { return child_process.exec(value); }\n",
            },
            "typescript-to-python": {
                "src/api.ts": "import { run } from './pkg';\nexport function handle(request: Request) { return run(request.query.q); }\n",
                "src/pkg/__init__.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            },
        }
        for direction, files in fixtures.items():
            with self.subTest(direction=direction):
                rows = self._rows(files)
                self.assertFalse(any(row["strength"] == "import-linked" for row in rows))

    def test_relative_python_package_import_requires_one_exact_target(self) -> None:
        unique = self._single_row(
            {
                "pkg/api.py": "from . import run\ndef handle(request):\n    return run(request.args['q'])\n",
                "pkg/run.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            }
        )
        self.assertEqual(unique["strength"], "import-linked")

        ambiguous = self._rows(
            {
                "pkg/api.py": "from . import run\ndef handle(request):\n    return run(request.args['q'])\n",
                "pkg/__init__.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
                "pkg/run.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            }
        )
        self.assertFalse(any(row["strength"] == "import-linked" for row in ambiguous))

    def test_go_import_targets_only_exact_same_language_package_directory(self) -> None:
        rows = self._rows(
            {
                "api.go": "import \"pkg/store\"\nfunc handle(request *http.Request) { store.Run(request.URL.Query().Get(\"q\")) }\n",
                "pkg/store/impl.go": "func Run(value string) { exec.Command(value) }\n",
                "pkg/store.go": "func Run(value string) { exec.Command(value) }\n",
                "pkg/store/nested/impl.go": "func Run(value string) { exec.Command(value) }\n",
                "pkg/store.ts": "export function Run(value: string) { return child_process.exec(value); }\n",
            }
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["strength"], "import-linked")
        self.assertEqual(rows[0]["operation"]["path"], "pkg/store/impl.go")

        ambiguous = self._rows(
            {
                "api.go": "import \"pkg/store\"\nfunc handle(request *http.Request) { store.Run(request.URL.Query().Get(\"q\")) }\n",
                "pkg/store/first.go": "func Run(value string) { exec.Command(value) }\n",
                "pkg/store/second.go": "func Run(value string) { exec.Command(value) }\n",
            }
        )
        self.assertFalse(any(row["strength"] == "import-linked" for row in ambiguous))

    def test_parent_typescript_relative_module_remains_exact(self) -> None:
        row = self._single_row(
            {
                "src/nested/api.ts": "import { run } from '../store';\nexport function handle(request: Request) { return run(request.query.q); }\n",
                "src/store.ts": "export function run(value: string) { return child_process.exec(value); }\n",
            }
        )
        self.assertEqual(row["strength"], "import-linked")
        self.assertEqual(row["operation"]["path"], "src/store.ts")

    def test_route_direction_quotas_preserve_profile_and_single_route_bounds(self) -> None:
        self.assertEqual(semantic_guidance._route_direction_quotas(PROFILE_LIMITS["hunt-balanced"].route_count), (512, 512))
        self.assertEqual(semantic_guidance._route_direction_quotas(PROFILE_LIMITS["hunt-max"].route_count), (1024, 1024))
        limits = GuidanceLimits(4096, 10, 10, 1, 10, 4096, 4)
        original_reverse = semantic_guidance._traverse_reverse_routes
        with mock.patch.object(
            semantic_guidance,
            "_traverse_reverse_routes",
            wraps=original_reverse,
        ) as reverse:
            result = self._build_with_limits(
                "single-route",
                {
                    "app.py": (
                        "import subprocess\n"
                        "def first(request):\n"
                        "    return subprocess.run(request.args['q'])\n"
                        "def second(request):\n"
                        "    return open(request.args['path'])\n"
                    )
                },
                limits,
            )
        self.assertLessEqual(result.row_count, 1)
        self.assertEqual(reverse.call_count, 0)

    def test_source_scanner_ignores_comments_and_strings_without_losing_call_name(self) -> None:
        row = self._single_row(
            {
                "app.ts": (
                    "// function fake(request) { child_process.exec(request.query.q); }\n"
                    "const note = \"child_process.exec(request.query.q)\";\n"
                    "const run = (value) => child_process.exec(value, \"safe\");\n"
                    "const handle = (request) => run(request.query.q);\n"
                )
            }
        )
        self.assertEqual(row["strength"], "direct")
        self.assertEqual(row["operation"]["symbol"], "child_process.exec")
        self.assertEqual([item["symbol"] for item in row["trace"]], ["handle", "run"])

    def test_language_scanners_ignore_multiline_string_anchors(self) -> None:
        fixtures = {
            "python": (
                "app.py",
                "\"\"\"\ndef fake(request):\n    subprocess.run(request.args['q'])\n\"\"\"\n"
                "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
            ),
            "go": (
                "app.go",
                "var note = `func fake(request *http.Request) { exec.Command(request.URL.Query().Get(\"q\")) }`\n"
                "func handle(request *http.Request) { exec.Command(request.URL.Query().Get(\"q\")) }\n",
            ),
            "typescript": (
                "app.ts",
                "const note = `function fake(request) { child_process.exec(request.query.q); }`;\n"
                "const handle = (request: Request) => child_process.exec(request.query.q);\n",
            ),
            "javascript": (
                "app.js",
                "const note = `function fake(request) { child_process.exec(request.query.q); }`;\n"
                "const handle = (request) => child_process.exec(request.query.q);\n",
            ),
        }
        for language, (path, source) in fixtures.items():
            with self.subTest(language=language):
                row = self._single_row({path: source})
                self.assertEqual(row["source"]["symbol"], "handle")

    def test_import_link_requires_exact_module_path_and_unique_declaration(self) -> None:
        rows = self._rows(
            {
                "api.py": "from pkg.store import run\ndef handle(request):\n    return run(request.args['q'])\n",
                "other/store.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            }
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["strength"], "name-only")

    def test_relative_python_and_typescript_modules_remain_import_linked(self) -> None:
        fixtures = {
            "python": {
                "api.py": "from .services.store import run\ndef handle(request):\n    return run(request.args['q'])\n",
                "services/store.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            },
            "typescript": {
                "src/api.ts": "import { run } from './services/store';\nexport function handle(request: Request) { return run(request.query.q); }\n",
                "src/services/store.ts": "export function run(value: string) { return child_process.exec(value); }\n",
            },
        }
        for language, files in fixtures.items():
            with self.subTest(language=language):
                row = self._single_row(files)
                self.assertEqual(row["strength"], "import-linked")

    def test_reverse_route_search_preserves_the_strongest_shortest_route(self) -> None:
        row = self._single_row(
            {
                "app.py": (
                    "import subprocess\n"
                    "def handle(request):\n"
                    "    return relay(request.args['q'])\n"
                    "def relay(value):\n"
                    "    return run(value)\n"
                    "def run(value):\n"
                    "    return subprocess.run(value)\n"
                )
            }
        )
        self.assertEqual(row["strength"], "direct")
        self.assertEqual([item["symbol"] for item in row["trace"]], ["handle", "relay", "run"])

    def test_small_route_limit_still_schedules_reverse_traversal(self) -> None:
        limits = GuidanceLimits(4096, 10, 10, 2, 10, 4096, 4)
        reverse_entry_counts: list[int] = []
        original_reverse = semantic_guidance._traverse_reverse_routes

        def observe_reverse(*args: object) -> None:
            reverse_entry_counts.append(len(args[-2]))
            original_reverse(*args)

        with mock.patch.object(
            semantic_guidance,
            "_traverse_reverse_routes",
            side_effect=observe_reverse,
        ) as reverse:
            result = self._build_with_limits(
                "reverse-schedule",
                {
                    "app.py": (
                        "import subprocess\n"
                        "def first(request):\n"
                        "    return subprocess.run(request.args['q'])\n"
                        "def second(request):\n"
                        "    return open(request.args['path'])\n"
                    )
                },
                limits,
            )
        self.assertEqual(result.row_count, 2)
        self.assertGreater(reverse.call_count, 0)
        self.assertTrue(any(count < limits.route_count for count in reverse_entry_counts))

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

    def test_equivalent_frontier_paths_are_canonicalized_before_deduplication(self) -> None:
        snapshot = self._root / "canonical"
        snapshot.mkdir()
        (snapshot / "app.py").write_text(
            "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
            encoding="utf-8",
        )
        result = build_semantic_guidance(snapshot, ("./app.py", "app.py"), "hunt-balanced")
        self.assertEqual(result.scanned_file_count, 1)
        self.assertEqual(result.skipped_file_count, 0)
        self.assertEqual(result.row_count, 1)

    def test_intermediate_directory_link_is_skipped(self) -> None:
        snapshot = self._root / "snapshot"
        snapshot.mkdir()
        outside = self._root / "outside"
        outside.mkdir()
        (outside / "external.py").write_text(
            "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
            encoding="utf-8",
        )
        link = snapshot / "linked"
        try:
            os.symlink(outside, link, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"directory links are unavailable: {error}")
        result = build_semantic_guidance(snapshot, ("linked/external.py",), "hunt-balanced")
        self.assertEqual(result.scanned_file_count, 0)
        self.assertEqual(result.skipped_file_count, 1)
        self.assertEqual(result.canonical_bytes, b"")

    def test_multiple_operation_families_produce_multiple_direct_routes(self) -> None:
        result = self._build(
            "multiple-operations",
            {
                "app.py": (
                    "import subprocess\ndef handle(request):\n"
                    "    subprocess.run(request.args['q'])\n"
                    "    return open(request.args['path'])\n"
                )
            },
        )
        rows = [json.loads(line) for line in result.canonical_bytes.decode("utf-8").splitlines()]
        self.assertEqual(result.row_count, 2)
        self.assertEqual([row["operation_family"] for row in rows], ["command", "file"])
        self.assertTrue(all(row["strength"] == "direct" for row in rows))

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

    def test_patched_limits_bound_declarations_edges_routes_rows_and_total_bytes(self) -> None:
        source = "import subprocess\ndef first(request):\n    return subprocess.run(request.args['q'])\ndef second(request):\n    return subprocess.run(request.args['q'])\n"
        declaration_result = self._build_with_limits(
            "declarations",
            {"app.py": source},
            GuidanceLimits(4096, 1, 10, 10, 10, 4096, 4),
        )
        self.assertEqual(declaration_result.row_count, 1)
        self.assertEqual([row["source"]["symbol"] for row in [json.loads(line) for line in declaration_result.canonical_bytes.splitlines()]], ["first"])

        edge_result = self._build_with_limits(
            "edges",
            {
                "api.py": "from store import run\ndef handle(request):\n    return run(request.args['q'])\n",
                "store.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            },
            GuidanceLimits(4096, 10, 0, 10, 10, 4096, 4),
        )
        self.assertEqual(edge_result.edge_count, 0)
        self.assertEqual(edge_result.canonical_bytes, b"")

        route_result = self._build_with_limits(
            "routes",
            {
                "app.py": (
                    "import subprocess\ndef handle(request):\n"
                    "    subprocess.run(request.args['q'])\n"
                    "    return open(request.args['path'])\n"
                )
            },
            GuidanceLimits(4096, 10, 10, 1, 10, 4096, 4),
        )
        self.assertEqual(route_result.row_count, 1)

        row_result = self._build_with_limits(
            "rows",
            {"app.py": source},
            GuidanceLimits(4096, 10, 10, 10, 1, 4096, 4),
        )
        self.assertEqual(row_result.row_count, 1)

        first_file = b"import subprocess\ndef first(request):\n    return subprocess.run(request.args['q'])\n"
        total_bytes_result = self._build_with_limits(
            "total-bytes",
            {"first.py": first_file, "second.py": first_file},
            GuidanceLimits(len(first_file), 10, 10, 10, 10, 4096, 4),
        )
        self.assertEqual(total_bytes_result.scanned_file_count, 1)
        self.assertEqual(total_bytes_result.skipped_file_count, 1)

    def test_patched_graph_depth_stops_before_distant_operation(self) -> None:
        result = self._build_with_limits(
            "depth",
            {
                "api.py": "from middle import relay\ndef handle(request):\n    return relay(request.args['q'])\n",
                "middle.py": "from store import run\ndef relay(value):\n    return run(value)\n",
                "store.py": "import subprocess\ndef run(value):\n    return subprocess.run(value)\n",
            },
            GuidanceLimits(4096, 10, 10, 10, 10, 4096, 1),
        )
        self.assertEqual(result.edge_count, 2)
        self.assertEqual(result.canonical_bytes, b"")
