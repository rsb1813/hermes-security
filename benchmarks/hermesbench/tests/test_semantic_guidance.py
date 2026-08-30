import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from benchmarks.hermesbench import nested_output_guidance, semantic_guidance
from benchmarks.hermesbench.semantic_guidance import (
    MAX_FILE_BYTES,
    GuidanceLimits,
    PROFILE_LIMITS,
    SemanticGuidance,
    build_semantic_guidance,
)


def _frontier_contexts(
    files: dict[str, str | bytes],
    passes: dict[str, tuple[str, ...]] | None = None,
    components: dict[str, str] | None = None,
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    selected_passes = passes or {}
    selected_components = components or {}
    return tuple(
        (
            path,
            selected_components.get(path, "component-default"),
            selected_passes.get(path, ("forward",)),
        )
        for path in files
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
        *,
        guidance_schema_version: int = 1,
        passes: dict[str, tuple[str, ...]] | None = None,
        components: dict[str, str] | None = None,
    ) -> SemanticGuidance:
        snapshot = self._root / name
        snapshot.mkdir()
        for relative, value in files.items():
            path = snapshot / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value if isinstance(value, bytes) else value.encode("utf-8"))
        return build_semantic_guidance(
            snapshot,
            _frontier_contexts(files, passes, components),
            profile,
            guidance_schema_version=guidance_schema_version,
        )

    def _rows(self, files: dict[str, str | bytes]) -> list[dict[str, object]]:
        result = self._build(f"case-{len(tuple(self._root.iterdir()))}", files)
        return [json.loads(line) for line in result.canonical_bytes.decode("utf-8").splitlines()]

    def _build_with_limits(
        self,
        name: str,
        files: dict[str, str | bytes],
        limits: GuidanceLimits,
        *,
        guidance_schema_version: int = 1,
        components: dict[str, str] | None = None,
    ) -> SemanticGuidance:
        with mock.patch.dict(PROFILE_LIMITS, {"test-limits": limits}):
            return self._build(
                name,
                files,
                "test-limits",
                guidance_schema_version=guidance_schema_version,
                components=components,
            )

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

    def test_schema_two_adds_canonical_route_pass_union_without_changing_hint_id(self) -> None:
        source = semantic_guidance._Location("entry.py", 2, "handle")
        operation = semantic_guidance._Location("sink.py", 3, "subprocess.run")
        control = semantic_guidance._Location("control.py", 1, "validate")
        route = semantic_guidance._Route(
            "import-linked",
            "command",
            source,
            operation,
            (source, operation),
            (control,),
            ("source_anchor", "operation_anchor"),
        )
        passes = {
            "entry.py": ("state", "forward"),
            "sink.py": ("guard", "backward"),
            "control.py": ("parser",),
        }
        legacy = semantic_guidance._canonical_row(route, 1, passes)
        annotated = semantic_guidance._canonical_row(route, 2, passes)
        self.assertEqual(annotated["eligible_search_passes"], ["forward", "backward", "guard", "state"])
        self.assertNotIn("parser", annotated["eligible_search_passes"])
        self.assertEqual(legacy["hint_id"], annotated["hint_id"])
        self.assertNotIn("eligible_search_passes", legacy)

    def test_schema_three_classifies_call_routes_and_exact_operation_component(self) -> None:
        result = self._build(
            "schema-three-call",
            {"src/app.ts": "export function handle(request: Request) { return child_process.exec(request.query.q); }\n"},
            guidance_schema_version=3,
            components={"src/app.ts": "component-api"},
        )
        row = json.loads(result.canonical_bytes)
        self.assertEqual(row["schema_version"], 3)
        self.assertEqual(row["hint_kind"], "call-route")
        self.assertIsNone(row["output_context"])
        self.assertEqual(row["component"], "component-api")
        self.assertEqual(row["eligible_search_passes"], ["forward"])
        self.assertEqual(row["proof_status"], "investigation_only")

    def test_schema_three_emits_compact_sink_first_index_for_structural_operations(self) -> None:
        result = self._build(
            "schema-three-operation-index",
            {
                "src/state.ts": (
                    "export function apply(target, value) {\n"
                    "  target.custom(value);\n"
                    "  target.setting = value;\n"
                    "}\n"
                )
            },
            guidance_schema_version=3,
            components={"src/state.ts": "component-state"},
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        structural = [row for row in rows if row["hint_kind"] == "operation-index"]
        self.assertEqual(len(structural), 1)
        self.assertEqual(structural[0]["component"], "component-state")
        self.assertEqual(structural[0]["proof_status"], "investigation_only")
        self.assertEqual(structural[0]["reason_codes"], ["operation_context", "structural_index"])
        self.assertEqual(
            structural[0]["entries"],
            [
                {
                    "p": "src/state.ts",
                    "q": "f",
                    "s": ["2c", "3m"],
                }
            ],
        )

    def test_schema_three_operation_index_is_byte_deterministic(self) -> None:
        files = {
            "src/state.ts": (
                "export function apply(target, value) {\n"
                "  target.custom(value);\n"
                "  target.setting = value;\n"
                "}\n"
            )
        }
        first = self._build(
            "schema-three-operation-index-deterministic-first",
            files,
            guidance_schema_version=3,
        )
        second = self._build(
            "schema-three-operation-index-deterministic-second",
            files,
            guidance_schema_version=3,
        )
        self.assertEqual(first.canonical_bytes, second.canonical_bytes)

    def test_schema_three_emits_local_assignment_context_without_duplicate_mutation(self) -> None:
        result = self._build(
            "schema-three-assignment-context",
            {
                "src/state.ts": (
                    "export function apply(target, value) {\n"
                    "  let next = value;\n"
                    "  target.setting = next;\n"
                    "}\n"
                )
            },
            guidance_schema_version=3,
            components={"src/state.ts": "component-state"},
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        structural = [row for row in rows if row["hint_kind"] == "operation-index"]
        self.assertEqual(
            structural[0]["entries"][0]["s"],
            ["2a", "3m"],
        )

    def test_member_mutation_scanner_keeps_multiple_updates_on_one_line(self) -> None:
        mutations = semantic_guidance._member_mutations(
            ["target.first = value; target.second = value;"],
            1,
        )
        self.assertEqual(
            [(mutation.line, mutation.signature) for mutation in mutations],
            [(1, "first"), (1, "second")],
        )

    def test_structural_scanners_mark_only_parameter_linked_operations(self) -> None:
        calls = semantic_guidance._calls(
            ["client.use(value); client.idle(constant);"],
            1,
            frozenset({"value"}),
        )
        mutations = semantic_guidance._member_mutations(
            ["target.first = constant; other.second = value; plain.third = constant;"],
            1,
            frozenset({"target", "value"}),
        )
        self.assertEqual([call.parameter_flow for call in calls], [True, False])
        self.assertEqual(
            [mutation.parameter_flow for mutation in mutations],
            [True, True, False],
        )

    def test_call_scanner_counts_unique_argument_identifiers(self) -> None:
        calls = semantic_guidance._calls(
            ["client.use(first, second, first, third);"],
            1,
        )
        self.assertEqual(calls[0].argument_identifier_count, 3)

        nested = semantic_guidance._calls(
            ["client.use(first, helper(second, third), fourth);"],
            1,
        )
        outer = next(call for call in nested if call.name == "use")
        self.assertEqual(outer.argument_identifier_count, 5)

    def test_parameter_parser_does_not_treat_python_body_calls_as_parameters(self) -> None:
        parameters = semantic_guidance._declaration_parameters(
            [
                "def handle(request):",
                "    client.use(value)",
                "    return request",
            ],
            "python",
        )
        self.assertEqual(parameters, frozenset({"request"}))

    def test_structural_flow_priority_tracks_one_local_assignment_hop(self) -> None:
        declaration = semantic_guidance._declaration_from_block(
            "src/state.ts",
            "typescript",
            "apply",
            1,
            [
                "export function apply(value) {",
                "  let next = value;",
                "  client.use(next);",
                "}",
            ],
        )
        call = next(call for call in declaration.calls if call.name == "use")
        self.assertTrue(call.parameter_flow)

    def test_assignment_context_requires_parameter_flow_on_the_assignment_side(self) -> None:
        result = self._build(
            "schema-three-assignment-side-flow",
            {
                "src/state.ts": (
                    "export function apply(value) { let unrelated = 0; client.use(value); }\n"
                )
            },
            guidance_schema_version=3,
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        structural = [row for row in rows if row["hint_kind"] == "operation-index"]
        self.assertEqual(structural[0]["entries"][0]["s"], ["1c"])

    def test_structural_sites_keep_distinct_operations_on_a_known_sink_line(self) -> None:
        path = "src/state.ts"
        location = semantic_guidance._Location(path, 1, "apply")
        declaration = semantic_guidance._Declaration(
            location,
            "typescript",
            None,
            (),
            (("command", semantic_guidance._Location(path, 2, "child_process.exec")),),
            (),
            (),
            (semantic_guidance._Call("custom", "client", 2),),
            (semantic_guidance._Mutation(2, "flag"),),
        )
        sites = semantic_guidance._structural_sites(
            (declaration,),
            {path: "component"},
        )
        self.assertEqual(
            {(site.family, site.signature) for site in sites},
            {("call", "custom"), ("mutation", "flag")},
        )

    def test_schema_three_assignment_context_ignores_comparisons_arrows_and_object_properties(self) -> None:
        result = self._build(
            "schema-three-assignment-context-decoys",
            {
                "src/compare.ts": (
                    "export function compare(left, right) {\n"
                    "  if (left === right || left <= right || left >= right) return true;\n"
                    "  const constant = 42;\n"
                    "  const mapper = (value) => ({ value });\n"
                    "  return { left, right, mapper };\n"
                    "}\n"
                )
            },
            guidance_schema_version=3,
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        structural = [row for row in rows if row["hint_kind"] == "operation-index"]
        self.assertEqual(
            structural[0]["entries"][0]["s"],
            ["4a"],
        )

    def test_schema_three_operation_context_ignores_strings_comments_and_object_literals(self) -> None:
        result = self._build(
            "schema-three-operation-context-decoys",
            {
                "src/format.ts": (
                    "export function format(value) {\n"
                    "  // target.other(value); target.flag = value;\n"
                    "  return { setting: value, text: 'target.custom(value); target.setting = value' };\n"
                    "}\n"
                )
            },
            guidance_schema_version=3,
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        self.assertFalse(any(row["hint_kind"] == "operation-index" for row in rows))

    def test_operation_index_is_schema_three_only(self) -> None:
        files = {"state.ts": "export function apply(target, value) { target.custom(value); target.setting = value; }\n"}
        legacy = self._build("operation-context-v1", files, guidance_schema_version=1)
        annotated = self._build("operation-context-v2", files, guidance_schema_version=2)
        structural = self._build("operation-context-v3", files, guidance_schema_version=3)
        self.assertEqual(legacy.canonical_bytes, b"")
        self.assertEqual(annotated.canonical_bytes, b"")
        self.assertTrue(structural.canonical_bytes)

    def test_schema_three_operation_index_rotates_components_within_the_row_cap(self) -> None:
        files = {
            "a/first.ts": "export function first(target, value) { target.alpha(value); }\n",
            "a/second.ts": "export function second(target, value) { target.beta(value); }\n",
            "b/third.ts": "export function third(target, value) { target.gamma(value); }\n",
        }
        result = self._build_with_limits(
            "operation-context-component-fairness",
            files,
            GuidanceLimits(4096, 20, 20, 20, 2, 4096, 4),
            guidance_schema_version=3,
            components={
                "a/first.ts": "component-a",
                "a/second.ts": "component-a",
                "b/third.ts": "component-b",
            },
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["component"] for row in rows}, {"component-a", "component-b"})
        self.assertTrue(all(row["hint_kind"] == "operation-index" for row in rows))

    def test_schema_three_operation_index_prioritizes_dense_rows_with_bounded_lookahead(self) -> None:
        sites = tuple(
            semantic_guidance._StructuralSite(
                f"component-{component_index:02}",
                f"src/file-{component_index:02}.ts",
                line,
                "call",
                f"signature-{component_index}-{line}",
            )
            for component_index in range(17)
            for line in range(
                1,
                33
                if component_index == 16
                else 25
                if component_index == 15
                else 2,
            )
        )
        rows = semantic_guidance._operation_index_rows(
            sites,
            {site.path: ("forward",) for site in sites},
            GuidanceLimits(128 * 1024, 800, 800, 800, 200, 128 * 1024, 4),
        )
        self.assertEqual(
            [row["component"] for row in rows[:3]],
            ["component-15", "component-16", "component-00"],
        )

    def test_schema_three_operation_index_prefers_reused_signatures_before_singletons(self) -> None:
        self.assertEqual(
            semantic_guidance._operation_index_signature_priority(2)[0],
            semantic_guidance._operation_index_signature_priority(7)[0],
        )
        self.assertLess(
            semantic_guidance._operation_index_signature_priority(7)[0],
            semantic_guidance._operation_index_signature_priority(8)[0],
        )
        self.assertLess(
            semantic_guidance._operation_index_signature_priority(1)[0],
            semantic_guidance._operation_index_signature_priority(8)[0],
        )
        sites = (
            semantic_guidance._StructuralSite("component", "a/one.ts", 1, "call", "unique-one"),
            semantic_guidance._StructuralSite("component", "a/two.ts", 1, "call", "unique-two"),
            semantic_guidance._StructuralSite("component", "z/first.ts", 1, "call", "shared"),
            semantic_guidance._StructuralSite("component", "z/second.ts", 1, "call", "shared"),
        )
        rows = semantic_guidance._operation_index_rows(
            sites,
            {site.path: ("forward",) for site in sites},
            GuidanceLimits(4096, 20, 20, 20, 20, 4096, 4),
        )
        self.assertEqual(
            [entry["p"] for entry in rows[0]["entries"][:2]],
            ["z/first.ts", "z/second.ts"],
        )

    def test_schema_three_operation_index_prefers_calls_within_a_reuse_lane(self) -> None:
        sites = (
            semantic_guidance._StructuralSite(
                "component", "a/assignment-first.ts", 1, "assignment", "shared"
            ),
            semantic_guidance._StructuralSite(
                "component", "a/assignment-second.ts", 1, "assignment", "shared"
            ),
            semantic_guidance._StructuralSite(
                "component", "z/call-first.ts", 1, "call", "shared"
            ),
            semantic_guidance._StructuralSite(
                "component", "z/call-second.ts", 1, "call", "shared"
            ),
        )
        rows = semantic_guidance._operation_index_rows(
            sites,
            {site.path: ("forward",) for site in sites},
            GuidanceLimits(4096, 20, 20, 20, 20, 4096, 4),
        )
        self.assertEqual(
            [entry["p"] for row in rows for entry in row["entries"]],
            [
                "z/call-first.ts",
                "z/call-second.ts",
                "a/assignment-first.ts",
                "a/assignment-second.ts",
            ],
        )

    def test_schema_three_operation_index_prefers_complex_calls_within_a_lane(self) -> None:
        sites = (
            semantic_guidance._StructuralSite(
                "component", "a/simple-first.ts", 1, "call", "shared"
            ),
            semantic_guidance._StructuralSite(
                "component", "b/simple-second.ts", 1, "call", "shared"
            ),
            semantic_guidance._StructuralSite(
                "component",
                "z/complex-first.ts",
                1,
                "call",
                "shared",
                argument_identifier_count=3,
            ),
            semantic_guidance._StructuralSite(
                "component",
                "z/complex-second.ts",
                1,
                "call",
                "shared",
                argument_identifier_count=4,
            ),
        )
        rows = semantic_guidance._operation_index_rows(
            sites,
            {site.path: ("forward",) for site in sites},
            GuidanceLimits(4096, 20, 20, 20, 20, 4096, 4),
        )
        self.assertEqual(
            [entry["p"] for row in rows for entry in row["entries"]],
            [
                "z/complex-first.ts",
                "z/complex-second.ts",
                "a/simple-first.ts",
                "b/simple-second.ts",
            ],
        )

    def test_schema_three_operation_index_rotates_reused_signature_occurrences(self) -> None:
        sites = (
            semantic_guidance._StructuralSite(
                "component", "a/alpha-first.ts", 1, "call", "alpha"
            ),
            semantic_guidance._StructuralSite(
                "component", "b/alpha-second.ts", 1, "call", "alpha"
            ),
            semantic_guidance._StructuralSite(
                "component", "c/beta-first.ts", 1, "call", "beta"
            ),
            semantic_guidance._StructuralSite(
                "component", "d/beta-second.ts", 1, "call", "beta"
            ),
        )
        rows = semantic_guidance._operation_index_rows(
            sites,
            {site.path: ("forward",) for site in sites},
            GuidanceLimits(4096, 20, 20, 20, 20, 4096, 4),
        )
        self.assertEqual(
            [entry["p"] for row in rows for entry in row["entries"]],
            [
                "a/alpha-first.ts",
                "c/beta-first.ts",
                "b/alpha-second.ts",
                "d/beta-second.ts",
            ],
        )

    def test_schema_three_operation_index_balances_parameter_flow_and_reuse(self) -> None:
        sites = (
            semantic_guidance._StructuralSite(
                "component",
                "a/singleton.ts",
                1,
                "call",
                "unique",
                parameter_flow=True,
            ),
            semantic_guidance._StructuralSite(
                "component",
                "z/linked.ts",
                1,
                "call",
                "shared",
                parameter_flow=True,
            ),
            semantic_guidance._StructuralSite(
                "component",
                "z/generic.ts",
                1,
                "call",
                "shared",
            ),
        )
        rows = semantic_guidance._operation_index_rows(
            sites,
            {site.path: ("forward",) for site in sites},
            GuidanceLimits(4096, 20, 20, 20, 20, 4096, 4),
        )
        self.assertEqual(
            [entry["p"] for row in rows for entry in row["entries"]],
            ["z/linked.ts", "z/generic.ts", "a/singleton.ts"],
        )

    def test_schema_three_operation_index_interleaves_flow_and_generic_reuse_rows(self) -> None:
        flow_sites = tuple(
            semantic_guidance._StructuralSite(
                "component",
                path,
                index + 1,
                "call",
                f"flow-{index}",
                parameter_flow=True,
            )
            for path in ("z/flow-first.ts", "z/flow-second.ts")
            for index in range(300)
        )
        generic_sites = (
            semantic_guidance._StructuralSite(
                "component", "a/generic-first.ts", 1, "call", "generic"
            ),
            semantic_guidance._StructuralSite(
                "component", "a/generic-second.ts", 1, "call", "generic"
            ),
        )
        sites = (*flow_sites, *generic_sites)
        rows = semantic_guidance._operation_index_rows(
            sites,
            {site.path: ("forward",) for site in sites},
            GuidanceLimits(128 * 1024, 800, 800, 800, 200, 128 * 1024, 4),
        )
        entry_paths = [entry["p"] for row in rows for entry in row["entries"]]
        lanes = [
            "flow" if row["entries"][0]["p"].startswith("z/flow-") else "generic"
            for row in rows[:3]
        ]
        self.assertEqual(lanes, ["flow", "flow", "generic"])
        self.assertLess(
            entry_paths.index("a/generic-first.ts"),
            max(
                index
                for index, path in enumerate(entry_paths)
                if path in {"z/flow-first.ts", "z/flow-second.ts"}
            ),
        )

    def test_schema_three_operation_index_finishes_reused_chunks_before_singletons(self) -> None:
        reused = tuple(
            semantic_guidance._StructuralSite(
                "component",
                path,
                index + 1,
                "call",
                f"shared-{index}",
            )
            for path in ("z/first.ts", "z/second.ts")
            for index in range(130)
        )
        singleton = semantic_guidance._StructuralSite(
            "component",
            "a/singleton.ts",
            1,
            "call",
            "unique",
        )
        sites = (*reused, singleton)
        rows = semantic_guidance._operation_index_rows(
            sites,
            {site.path: ("forward",) for site in sites},
            GuidanceLimits(64 * 1024, 400, 400, 400, 100, 64 * 1024, 4),
        )
        entry_paths = [entry["p"] for row in rows for entry in row["entries"]]
        self.assertGreater(
            entry_paths.index("a/singleton.ts"),
            max(
                index
                for index, path in enumerate(entry_paths)
                if path in {"z/first.ts", "z/second.ts"}
            ),
        )

    def test_schema_three_operation_index_finishes_reused_component_rows_before_singletons(self) -> None:
        reused = tuple(
            semantic_guidance._StructuralSite(
                "component-reused",
                path,
                index + 1,
                "call",
                f"shared-{index}",
            )
            for path in ("z/first.ts", "z/second.ts")
            for index in range(300)
        )
        singleton = semantic_guidance._StructuralSite(
            "component-singleton",
            "a/singleton.ts",
            1,
            "call",
            "unique",
        )
        sites = (*reused, singleton)
        rows = semantic_guidance._operation_index_rows(
            sites,
            {site.path: ("forward",) for site in sites},
            GuidanceLimits(128 * 1024, 800, 800, 800, 200, 128 * 1024, 4),
        )
        components = [row["component"] for row in rows]
        self.assertGreater(
            components.index("component-singleton"),
            max(
                index
                for index, component in enumerate(components)
                if component == "component-reused"
            ),
        )

    def test_schema_three_structural_site_retention_uses_the_existing_edge_cap(self) -> None:
        limits = GuidanceLimits(4096, 20, 2, 20, 20, 4096, 4)
        with mock.patch.object(
            semantic_guidance,
            "_operation_index_rows",
            wraps=semantic_guidance._operation_index_rows,
        ) as indexer:
            self._build_with_limits(
                "operation-index-site-cap",
                {
                    "src/state.ts": (
                        "export function apply(value) {\n"
                        "  client.first(value);\n"
                        "  client.second(value);\n"
                        "  target.first = value;\n"
                        "  target.second = value;\n"
                        "  let third = value;\n"
                        "  let fourth = value;\n"
                        "}\n"
                    )
                },
                limits,
                guidance_schema_version=3,
            )
        self.assertLessEqual(len(indexer.call_args.args[0]), limits.edge_count)

    def test_schema_three_operation_index_skips_a_site_that_cannot_fit_one_row(self) -> None:
        path = f"src/{'nested-' * 300}file.ts"
        rows = semantic_guidance._operation_index_rows(
            (semantic_guidance._StructuralSite("component", path, 1, "call", "shared"),),
            {path: ("forward",)},
            GuidanceLimits(4096, 20, 20, 20, 20, 4096, 4),
        )
        self.assertEqual(rows, ())

    def test_schema_three_operation_index_packs_more_sites_than_the_row_cap(self) -> None:
        files = {
            f"src/file-{index}.ts": (
                f"export function item{index}(client, value) {{ client.action{index}(value); }}\n"
            )
            for index in range(12)
        }
        result = self._build_with_limits(
            "operation-index-packing",
            files,
            GuidanceLimits(16 * 1024, 100, 100, 100, 1, 4096, 4),
            guidance_schema_version=3,
            components={path: "component-one" for path in files},
        )
        row = json.loads(result.canonical_bytes)
        self.assertEqual(row["hint_kind"], "operation-index")
        self.assertEqual(len(row["entries"]), 12)
        self.assertEqual(sum(len(entry["s"]) for entry in row["entries"]), 12)

    def test_schema_three_operation_index_keeps_late_mutations_in_large_declarations(self) -> None:
        mutations = "\n".join(
            f"  target.field{index} = value;" for index in range(10)
        )
        result = self._build(
            "operation-index-late-mutation",
            {
                "src/state.ts": (
                    "export function apply(target, value) {\n"
                    f"{mutations}\n"
                    "}\n"
                )
            },
            guidance_schema_version=3,
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        sites = [
            site
            for row in rows
            if row["hint_kind"] == "operation-index"
            for entry in row["entries"]
            for site in entry["s"]
        ]
        self.assertIn("11m", sites)

    def test_schema_three_operation_index_never_displaces_the_only_high_signal_route(self) -> None:
        files = {
            "src/known.ts": (
                "export function known(request) { return child_process.exec(request.query.q); }\n"
            ),
            "src/unknown.ts": (
                "export function unknown(client, value) { client.custom(value); }\n"
            ),
        }
        result = self._build_with_limits(
            "operation-index-route-reserve",
            files,
            GuidanceLimits(4096, 20, 20, 20, 2, 4096, 4),
            guidance_schema_version=3,
            components={
                "src/known.ts": "component-known",
                "src/unknown.ts": "component-unknown",
            },
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        self.assertEqual([row["hint_kind"] for row in rows], ["call-route"])
        self.assertEqual(rows[0]["strength"], "direct")

    def test_schema_three_operation_index_replaces_weak_routes_within_route_only_budget(self) -> None:
        files = {
            "src/known.ts": (
                "export function known(request) { return child_process.exec(request.query.q); }\n"
            ),
            "src/entry.py": "def handle(request):\n    return run(request.args['q'])\n",
            "src/sink.py": (
                "import subprocess\ndef run(value):\n    return subprocess.run(value)\n"
            ),
            "src/unknown.ts": (
                "export function unknown(client, value) { client.custom(value); }\n"
            ),
        }
        limits = GuidanceLimits(16 * 1024, 40, 40, 40, 4, 16 * 1024, 4)
        with mock.patch.object(semantic_guidance, "_operation_index_rows", return_value=()):
            route_only = self._build_with_limits(
                "operation-index-route-only-budget-baseline",
                files,
                limits,
                guidance_schema_version=3,
            )
        result = self._build_with_limits(
            "operation-index-route-only-budget",
            files,
            limits,
            guidance_schema_version=3,
        )
        baseline_rows = [json.loads(line) for line in route_only.canonical_bytes.splitlines()]
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        self.assertLessEqual(len(result.canonical_bytes), len(route_only.canonical_bytes))
        self.assertEqual(
            [
                line
                for line in result.canonical_bytes.splitlines(keepends=True)
                if json.loads(line).get("strength") != "name-only"
                and json.loads(line)["hint_kind"] != "operation-index"
            ],
            [
                line
                for line in route_only.canonical_bytes.splitlines(keepends=True)
                if json.loads(line).get("strength") != "name-only"
            ],
        )
        self.assertTrue(any(row.get("strength") == "direct" for row in rows))
        self.assertTrue(any(row["hint_kind"] == "operation-index" for row in rows))
        self.assertLess(
            sum(row.get("strength") == "name-only" for row in rows),
            sum(row.get("strength") == "name-only" for row in baseline_rows),
        )

    def test_schema_three_operation_index_does_not_repeat_a_preserved_nested_location(self) -> None:
        result = self._build(
            "operation-index-nested-deduplication",
            {
                "src/render.ts": (
                    "export function render(request, client) {\n"
                    "  return `<script>${client.custom(request.query.q)}</script>`;\n"
                    "}\n"
                )
            },
            guidance_schema_version=3,
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        nested = [row for row in rows if row["hint_kind"] == "nested-output-context"]
        self.assertEqual(len(nested), 1)
        repeated = [
            site
            for row in rows
            if row["hint_kind"] == "operation-index"
            for entry in row["entries"]
            if entry["p"] == nested[0]["operation"]["path"]
            for site in entry["s"]
            if site.startswith(f'{nested[0]["operation"]["line"]}')
        ]
        self.assertEqual(repeated, [])

    def test_schema_three_structural_only_output_has_a_separate_small_cap(self) -> None:
        index_rows = tuple(
            semantic_guidance._canonical_operation_index_row(
                f"component-{index}",
                [
                    {
                        "p": f"src/file-{index}.ts",
                        "q": "f",
                        "s": ["1c"],
                    }
                ],
            )
            for index in range(40)
        )
        canonical, row_count = semantic_guidance._canonical_guidance(
            (),
            GuidanceLimits(1024, 1, 1, 1, 100, 1024 * 1024, 1),
            3,
            {},
            {},
            index_rows,
        )
        self.assertEqual(row_count, 32)
        self.assertLessEqual(len(canonical), 64 * 1024)

    def test_nested_output_scanner_skips_sources_without_template_interpolation_markers(self) -> None:
        with mock.patch.object(
            nested_output_guidance,
            "_TemplateScanner",
            side_effect=AssertionError("template scanner should not run"),
        ), mock.patch.object(
            nested_output_guidance,
            "_javascript_declarations",
            side_effect=AssertionError("declaration scanner should not run"),
        ):
            self.assertEqual(nested_output_guidance.scan_nested_output_contexts("const value = request.query.q;\n"), ())
            self.assertEqual(nested_output_guidance.scan_nested_output_contexts("const value = `static`;\n"), ())
            self.assertEqual(nested_output_guidance.scan_nested_output_contexts("const value = '${request.query.q}';\n"), ())

    def test_nested_output_scanner_skips_declaration_scan_without_supported_context(self) -> None:
        source = "export function render(request) { return `value: ${request.query.q}`; }\n"
        with mock.patch.object(
            nested_output_guidance,
            "_javascript_declarations",
            side_effect=AssertionError("declaration scanner should not run"),
        ):
            self.assertEqual(nested_output_guidance.scan_nested_output_contexts(source), ())

    def test_nested_output_reuses_controls_for_supported_interpolations_in_one_declaration(self) -> None:
        source = (
            "export function render(request) {\n"
            "  return `<script>${request.query.first}${request.query.second}</script>`;\n"
            "}\n"
        )
        with mock.patch.object(
            nested_output_guidance,
            "_outer_sanitizer_lines",
            wraps=nested_output_guidance._outer_sanitizer_lines,
        ) as controls:
            observations = nested_output_guidance.scan_nested_output_contexts(source)
        self.assertEqual(
            observations,
            (
                nested_output_guidance.NestedOutputObservation(
                    "script",
                    1,
                    "render",
                    2,
                    "request",
                    2,
                    (),
                    ("nested_output_context", "embedded_script", "property_provenance"),
                ),
                nested_output_guidance.NestedOutputObservation(
                    "script",
                    1,
                    "render",
                    2,
                    "request",
                    2,
                    (),
                    ("nested_output_context", "embedded_script", "property_provenance"),
                ),
            ),
        )
        self.assertEqual(controls.call_count, 1)

    def test_schema_three_does_not_resolve_each_candidate_before_pinned_read(self) -> None:
        snapshot = self._root / "schema-three-no-candidate-resolve"
        snapshot.mkdir()
        (snapshot / "render.ts").write_text(
            "export function render(request) { return `<script>${request.query.q}</script>`; }\n",
            encoding="utf-8",
        )
        with mock.patch.object(
            semantic_guidance,
            "_safe_snapshot",
            return_value=snapshot,
        ), mock.patch.object(
            Path,
            "resolve",
            side_effect=AssertionError("candidate paths should not resolve before pinned read"),
        ):
            result = build_semantic_guidance(
                snapshot,
                (("render.ts", "component-default", ("forward",)),),
                "hunt-balanced",
                guidance_schema_version=3,
            )
        self.assertEqual(result.scanned_file_count, 1)

    def test_schema_three_emits_each_nested_output_context(self) -> None:
        fixtures = {
            "script": "export function render(request) { return `<script>const value = '${request.query.value}'</script>`; }\n",
            "style": "export function render(options) { return `<style>.card { color: ${options.color}; }</style>`; }\n",
            "url_attribute": "export function render(config) { return `<a href=\"/go?next=${config.next}\">go</a>`; }\n",
            "event_handler": "export function render(params) { return `<button onclick=\"show('${params.name}')\">go</button>`; }\n",
        }
        for context, source in fixtures.items():
            with self.subTest(context=context):
                result = self._build(
                    f"nested-{context}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
                nested = [row for row in rows if row["hint_kind"] == "nested-output-context"]
                self.assertEqual(len(nested), 1)
                self.assertEqual(nested[0]["output_context"], context)
                self.assertEqual(nested[0]["operation_family"], "output-context")
                self.assertEqual(nested[0]["proof_status"], "investigation_only")

    def test_schema_three_strong_edge_survives_earlier_name_only_fanout(self) -> None:
        result = self._build_with_limits(
            "fair-strong-edge",
            {
                "early.ts": "export function noise(value) { alpha(value); beta(value); gamma(value); }\n",
                "alpha.ts": "export function alpha(value) { return value; }\n",
                "beta.ts": "export function beta(value) { return value; }\n",
                "gamma.ts": "export function gamma(value) { return value; }\n",
                "api.ts": "import { run } from './sink'; export function handle(request) { return run(request.query.q); }\n",
                "sink.ts": "export function run(value) { return child_process.exec(value); }\n",
            },
            GuidanceLimits(4096, 20, 1, 20, 20, 4096, 4),
            guidance_schema_version=3,
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        self.assertEqual(result.edge_count, 1)
        self.assertTrue(any(row["strength"] == "import-linked" for row in rows))
        self.assertFalse(any(row["strength"] == "name-only" for row in rows))

    def test_schema_three_import_resolution_uses_prebuilt_module_index(self) -> None:
        with mock.patch.object(
            semantic_guidance,
            "_module_matches",
            side_effect=AssertionError("schema three should not scan module candidates"),
        ):
            result = self._build_with_limits(
                "indexed-import-resolution",
                {
                    "api.ts": "import { run } from './sink'; export function handle(request) { return run(request.query.q); }\n",
                    "sink.ts": "export function run(value) { return child_process.exec(value); }\n",
                },
                GuidanceLimits(4096, 20, 20, 20, 20, 4096, 4),
                guidance_schema_version=3,
            )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        self.assertTrue(any(row["strength"] == "import-linked" for row in rows))

    def test_schema_three_reference_budget_matches_the_edge_cap(self) -> None:
        limits = GuidanceLimits(4096, 20, 1, 20, 20, 4096, 4)
        original = semantic_guidance._allocate_schema_three_references
        with mock.patch.object(
            semantic_guidance,
            "_allocate_schema_three_references",
            wraps=original,
        ) as allocator:
            self._build_with_limits(
                "reference-budget",
                {
                    "api.ts": "export function handle(request) { alpha(request.query.q); beta(request.query.q); gamma(request.query.q); }\n",
                    "alpha.ts": "export function alpha(value) { return value; }\n",
                    "beta.ts": "export function beta(value) { return value; }\n",
                    "gamma.ts": "export function gamma(value) { return value; }\n",
                },
                limits,
                guidance_schema_version=3,
            )
        self.assertEqual(allocator.call_args.args[1], limits.edge_count)

    def test_schema_three_zero_edge_budget_keeps_same_declaration_direct_routes(self) -> None:
        result = self._build_with_limits(
            "zero-edge-direct",
            {"app.ts": "export function handle(request) { return child_process.exec(request.query.q); }\n"},
            GuidanceLimits(4096, 20, 0, 20, 20, 4096, 4),
            guidance_schema_version=3,
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        self.assertEqual(result.edge_count, 0)
        self.assertEqual([row["strength"] for row in rows], ["direct"])

    def test_schema_three_weak_target_iteration_stops_at_the_edge_budget(self) -> None:
        class _ExplodingTargets:
            def __init__(self, target: object) -> None:
                self._target = target
                self.count = 0

            def __iter__(self) -> object:
                return self

            def __next__(self) -> object:
                self.count += 1
                if self.count > 1:
                    raise AssertionError("weak target iterator exceeded the edge budget")
                return self._target

        caller_location = semantic_guidance._Location("caller.ts", 1, "caller")
        target_location = semantic_guidance._Location("target.ts", 1, "target")
        caller = semantic_guidance._Declaration(
            caller_location,
            "typescript",
            None,
            (),
            (),
            (),
            (),
            (semantic_guidance._Call("target", None, 1),),
        )
        target = semantic_guidance._Declaration(
            target_location,
            "typescript",
            None,
            (),
            (),
            (),
            (),
            (),
        )
        targets = _ExplodingTargets(target)
        outgoing = semantic_guidance._allocate_schema_three_edges(
            {},
            {semantic_guidance._location_identity(caller_location): caller.calls},
            {semantic_guidance._location_identity(caller_location): caller},
            {("typescript", "target"): targets},
            1,
        )
        self.assertEqual(
            outgoing,
            {
                semantic_guidance._location_identity(caller_location): (
                    (semantic_guidance._location_identity(target_location), "name-only"),
                )
            },
        )
        self.assertEqual(targets.count, 1)

    def test_schema_three_reference_cap_does_not_prefetch_after_exact_terminal_edge(self) -> None:
        location = semantic_guidance._Location("caller.ts", 1, "caller")
        declaration = semantic_guidance._Declaration(
            location,
            "typescript",
            None,
            (),
            (),
            (),
            (),
            (semantic_guidance._Call("exact", None, 1),)
            + tuple(semantic_guidance._Call(f"later{index}", None, 1) for index in range(1000)),
        )

        def resolve_exact(
            item: semantic_guidance._Declaration,
            call: semantic_guidance._Call,
            by_file: object,
            by_language: object,
        ) -> tuple[tuple[str, int, str], str] | None:
            if call.name == "exact":
                return (("target.ts", 1, "target"), "direct")
            return None

        with mock.patch.object(
            semantic_guidance,
            "_resolve_exact_call",
            side_effect=resolve_exact,
        ) as resolver:
            selected, strong, weak = semantic_guidance._allocate_schema_three_references(
                (declaration,),
                1,
                {},
                {},
            )
        identity = semantic_guidance._location_identity(location)
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(selected[0].calls, (semantic_guidance._Call("exact", None, 1),))
        self.assertEqual(strong, {identity: ((("target.ts", 1, "target"), "direct"),)})
        self.assertEqual(weak, {})

    def test_schema_three_duplicate_weak_calls_reuse_exact_resolution(self) -> None:
        location = semantic_guidance._Location("caller.ts", 1, "caller")
        call = semantic_guidance._Call("target", None, 1)
        declaration = semantic_guidance._Declaration(
            location,
            "typescript",
            None,
            (),
            (),
            (),
            (),
            (call,) * 1001,
        )
        with mock.patch.object(
            semantic_guidance,
            "_resolve_exact_call",
            return_value=None,
        ) as resolver:
            selected, strong, weak = semantic_guidance._allocate_schema_three_references(
                (declaration,),
                1,
                {},
                {},
            )
        identity = semantic_guidance._location_identity(location)
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(selected[0].calls, (call,))
        self.assertEqual(strong, {})
        self.assertEqual(weak, {identity: (call,)})

    def test_schema_three_zero_reference_cap_does_not_prefetch_candidates(self) -> None:
        declaration = semantic_guidance._Declaration(
            semantic_guidance._Location("caller.ts", 1, "caller"),
            "typescript",
            None,
            (),
            (),
            (),
            (),
            (semantic_guidance._Call("exact", None, 1),),
        )
        with mock.patch.object(semantic_guidance, "_resolve_exact_call") as resolver:
            selected, strong, weak = semantic_guidance._allocate_schema_three_references(
                (declaration,),
                0,
                {},
                {},
            )
        self.assertEqual(resolver.call_count, 0)
        self.assertEqual(selected[0].calls, ())
        self.assertEqual(strong, {})
        self.assertEqual(weak, {})

    def test_schema_three_reference_rounds_do_not_rescan_sparse_declarations(self) -> None:
        target = semantic_guidance._Location("target.ts", 1, "target")
        empty = tuple(
            semantic_guidance._Declaration(
                semantic_guidance._Location(f"empty-{index}.ts", 1, f"empty{index}"),
                "typescript",
                None,
                (),
                (),
                (),
                (),
                (),
            )
            for index in range(32)
        )
        active = semantic_guidance._Declaration(
            semantic_guidance._Location("active.ts", 1, "active"),
            "typescript",
            None,
            (),
            (),
            (),
            (),
            tuple(semantic_guidance._Call(f"call{index}", None, 1) for index in range(8)),
        )
        declarations = (*empty, active)
        original_identity = semantic_guidance._location_identity
        with mock.patch.object(
            semantic_guidance,
            "_resolve_exact_call",
            side_effect=lambda declaration, call, by_file, by_language: (
                (target.path, int(call.name.removeprefix("call")) + 1, target.symbol),
                "direct",
            ),
        ), mock.patch.object(
            semantic_guidance,
            "_location_identity",
            side_effect=original_identity,
        ) as location_identity:
            selected, strong, weak = semantic_guidance._allocate_schema_three_references(
                declarations,
                8,
                {},
                {},
            )
        self.assertEqual(sum(len(item.calls) for item in selected), 8)
        self.assertEqual(sum(len(edges) for edges in strong.values()), 8)
        self.assertEqual(weak, {})
        self.assertLessEqual(location_identity.call_count, len(declarations) + 8 * 3)

    def test_schema_three_edge_dedupe_uses_hashed_membership(self) -> None:
        class _CountingIdentity:
            comparisons = 0

            def __init__(self, value: tuple[str, int, str]) -> None:
                self.value = value

            def __hash__(self) -> int:
                return hash(self.value)

            def __eq__(self, other: object) -> bool:
                type(self).comparisons += 1
                return isinstance(other, _CountingIdentity) and self.value == other.value

        caller_location = semantic_guidance._Location("caller.ts", 1, "caller")
        caller_identity = semantic_guidance._location_identity(caller_location)
        caller = semantic_guidance._Declaration(
            caller_location,
            "typescript",
            None,
            (),
            (),
            (),
            (),
            (semantic_guidance._Call("target", None, 1),),
        )
        targets = tuple(
            semantic_guidance._Declaration(
                semantic_guidance._Location(f"target-{index}.ts", 1, "target"),
                "typescript",
                None,
                (),
                (),
                (),
                (),
                (),
            )
            for index in range(16)
        )
        original_identity = semantic_guidance._location_identity

        def counting_identity(location: semantic_guidance._Location) -> object:
            identity = original_identity(location)
            if location.path.startswith("target-"):
                return _CountingIdentity(identity)
            return identity

        with mock.patch.object(semantic_guidance, "_location_identity", side_effect=counting_identity):
            outgoing = semantic_guidance._allocate_schema_three_edges(
                {},
                {caller_identity: caller.calls},
                {caller_identity: caller},
                {("typescript", "target"): targets},
                len(targets),
            )
        self.assertEqual(len(outgoing[caller_identity]), len(targets))
        self.assertLessEqual(_CountingIdentity.comparisons, len(targets) * 2)

    def test_schema_three_sparse_fanout_keeps_the_edge_cap_and_late_strong_route(self) -> None:
        result = self._build_with_limits(
            "sparse-fanout",
            {
                "early.ts": "export function noise(value) { target(value); target(value); target(value); target(value); }\n",
                "one.ts": "export function target(value) { return value; }\n",
                "two.ts": "export function target(value) { return value; }\n",
                "api.ts": "import { run } from './sink'; export function handle(request) { return run(request.query.q); }\n",
                "sink.ts": "export function run(value) { return child_process.exec(value); }\n",
            },
            GuidanceLimits(4096, 20, 2, 20, 20, 4096, 4),
            guidance_schema_version=3,
        )
        rows = [json.loads(line) for line in result.canonical_bytes.splitlines()]
        self.assertEqual(result.edge_count, 2)
        self.assertTrue(any(row["strength"] == "import-linked" for row in rows))

    def test_schema_three_nested_output_adds_one_exact_import_linked_companion(self) -> None:
        result = self._build_with_limits(
            "nested-companion",
            {
                "caller-z.ts": "import { render } from './render'; export function later(request) { return render(request.query.value); }\n",
                "caller-a.ts": "import { render } from './render'; export function earlier(request) { return render(request.query.value); }\n",
                "ambiguous.ts": "export function maybe(request) { return render(request.query.value); }\n",
                "render.ts": "export function render(value) { return `<script>${value}</script>`; }\n",
            },
            GuidanceLimits(4096, 20, 20, 20, 20, 4096, 4),
            guidance_schema_version=3,
        )
        nested = next(
            json.loads(line)
            for line in result.canonical_bytes.splitlines()
            if b"nested-output-context" in line
        )
        self.assertEqual(
            [(item["path"], item["symbol"]) for item in nested["trace"]],
            [("caller-a.ts", "earlier"), ("render.ts", "render")],
        )
        self.assertIn("explicit_import", nested["reason_codes"])

    def test_schema_three_companion_requires_a_source_derived_call_argument(self) -> None:
        result = self._build_with_limits(
            "nested-companion-static-argument",
            {
                "caller.ts": "import { render } from './render'; export function handle(request) { audit(request.query.value); return render('static'); }\n",
                "render.ts": "export function render(value) { return `<script>${value}</script>`; }\n",
            },
            GuidanceLimits(4096, 20, 20, 20, 20, 4096, 4),
            guidance_schema_version=3,
        )
        nested = next(
            json.loads(line)
            for line in result.canonical_bytes.splitlines()
            if b"nested-output-context" in line
        )
        self.assertEqual(
            [(item["path"], item["symbol"]) for item in nested["trace"]],
            [("render.ts", "render")],
        )
        self.assertNotIn("explicit_import", nested["reason_codes"])

    def test_schema_three_companion_does_not_create_a_nested_output_hint(self) -> None:
        result = self._build_with_limits(
            "nested-companion-no-local-hint",
            {
                "caller.ts": "import { render } from './render'; export function handle(request) { return render(request.query.value); }\n",
                "render.ts": "export function render(value) { return value; }\n",
            },
            GuidanceLimits(4096, 20, 20, 20, 20, 4096, 4),
            guidance_schema_version=3,
        )
        self.assertFalse(
            any(b"nested-output-context" in line for line in result.canonical_bytes.splitlines())
        )

    def test_schema_three_row_rounds_preserve_strong_families_and_components(self) -> None:
        family_result = self._build_with_limits(
            "family-rounds",
            {
                "api.ts": (
                    "export function first(request) { return child_process.exec(request.query.q); }\n"
                    "export function second(request) { return child_process.exec(request.query.q); }\n"
                ),
                "render.ts": "export function render(value) { return `<script>${value}</script>`; }\n",
            },
            GuidanceLimits(4096, 20, 20, 20, 2, 4096, 4),
            guidance_schema_version=3,
            components={"api.ts": "component-api", "render.ts": "component-render"},
        )
        family_rows = [json.loads(line) for line in family_result.canonical_bytes.splitlines()]
        self.assertEqual(
            [(row["hint_kind"], row["operation_family"]) for row in family_rows],
            [("call-route", "command"), ("nested-output-context", "output-context")],
        )

        component_result = self._build_with_limits(
            "component-rounds",
            {
                "api.ts": (
                    "export function first(request) { return child_process.exec(request.query.q); }\n"
                    "export function second(request) { return child_process.exec(request.query.q); }\n"
                ),
                "worker.ts": "export function execute(request) { return child_process.exec(request.query.q); }\n",
            },
            GuidanceLimits(4096, 20, 20, 20, 2, 4096, 4),
            guidance_schema_version=3,
            components={"api.ts": "component-api", "worker.ts": "component-worker"},
        )
        component_rows = [json.loads(line) for line in component_result.canonical_bytes.splitlines()]
        self.assertEqual(
            [row["component"] for row in component_rows],
            ["component-api", "component-worker"],
        )

    def test_schema_three_skips_oversized_row_and_remains_deterministic(self) -> None:
        long_path = "a.ts"
        files = {
            long_path: "export function oversized(request) { return child_process.exec(request.query.q); }\n",
            "z.ts": "export function short(request) { return child_process.exec(request.query.q); }\n",
        }
        limits = GuidanceLimits(4096, 20, 20, 20, 20, 700, 4)
        components = {long_path: "x" * 500, "z.ts": "component-short"}
        first = self._build_with_limits(
            "byte-skip-one",
            files,
            limits,
            guidance_schema_version=3,
            components=components,
        )
        second = self._build_with_limits(
            "byte-skip-two",
            files,
            limits,
            guidance_schema_version=3,
            components=components,
        )
        self.assertEqual(first.canonical_bytes, second.canonical_bytes)
        self.assertEqual(
            hashlib.sha256(first.canonical_bytes).hexdigest(),
            hashlib.sha256(second.canonical_bytes).hexdigest(),
        )
        rows = [json.loads(line) for line in first.canonical_bytes.splitlines()]
        self.assertEqual([row["operation"]["path"] for row in rows], ["z.ts"])

    def test_nested_output_records_bounded_observed_provenance(self) -> None:
        source = (
            "export function render(options) {\n"
            "  const selected = options.theme;\n"
            "  const cleaned = sanitizeHtml(selected);\n"
            "  return `<style>.card { color: ${cleaned}; }</style>`;\n"
            "}\n"
        )
        result = self._build(
            "nested-provenance",
            {"src/render.ts": source},
            guidance_schema_version=3,
        )
        row = next(json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line)
        self.assertIn("one_hop_alias_provenance", row["reason_codes"])
        self.assertIn("sanitizer_return_provenance", row["reason_codes"])
        self.assertIn("outer_html_sanitizer_context_mismatch", row["reason_codes"])
        self.assertNotIn("options.theme", json.dumps(row))

    def test_nested_output_records_parameter_property_and_configuration_provenance(self) -> None:
        fixtures = {
            "parameter_provenance": "export function render(request) { return `<script>${request}</script>`; }\n",
            "property_provenance": "export function render(request) { return `<style>${request.theme}</style>`; }\n",
            "config_provenance": "export function render() { return `<style>${process.env.THEME}</style>`; }\n",
        }
        for expected, source in fixtures.items():
            with self.subTest(expected=expected):
                result = self._build(
                    f"nested-provenance-{expected}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(len(nested), 1)
                row = nested[0]
                self.assertIn(expected, row["reason_codes"])

    def test_nested_output_suppresses_only_established_transforms_and_policies(self) -> None:
        fixtures = {
            "url_component": "export function render(request) { return `<a href=\"/go?next=${encodeURIComponent(request.query.q)}\">go</a>`; }\n",
            "script_policy": "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.query.q, { allowedTags: ['p'] })}</script>`; }\n",
            "url_policy": "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<a href=\"/go?next=${sanitizeHtml(request.query.q, { allowedTags: ['a'], allowedAttributes: { a: ['title'] } })}\">go</a>`; }\n",
        }
        for name, source in fixtures.items():
            with self.subTest(name=name):
                result = self._build(
                    f"nested-suppression-{name}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(nested, [])

    def test_nested_output_does_not_suppress_wildcard_or_dynamic_policies(self) -> None:
        fixtures = {
            "wildcard_tag": "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.query.q, { allowedTags: ['*'] })}</script>`; }\n",
            "wildcard_attribute": "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<a href=\"/go?next=${sanitizeHtml(request.query.q, { allowedTags: ['a'], allowedAttributes: { a: ['*'] } })}\">go</a>`; }\n",
            "dynamic_tag": "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.query.q, { allowedTags: tags })}</script>`; }\n",
            "dynamic_attribute": "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<a href=\"/go?next=${sanitizeHtml(request.query.q, { allowedTags: ['a'], allowedAttributes: { a: attrs } })}\">go</a>`; }\n",
        }
        for name, source in fixtures.items():
            with self.subTest(name=name):
                result = self._build(
                    f"nested-policy-open-{name}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(len(nested), 1)

    def test_nested_output_does_not_parse_policy_fields_inside_strings_or_comments(self) -> None:
        fixtures = {
            "string": "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.q, { note: \"allowedTags: ['safe']\" })}</script>`; }\n",
            "comment": "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.q, { /* allowedTags: ['safe'] */ note: 'safe' })}</script>`; }\n",
        }
        for name, source in fixtures.items():
            with self.subTest(name=name):
                result = self._build(
                    f"nested-policy-lexical-{name}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(len(nested), 1)

    def test_nested_output_policy_keys_require_exact_static_tokens(self) -> None:
        fixtures = {
            "unquoted_tag": (
                "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.q, { allowedTags: ['p'] })}</script>`; }\n",
                0,
            ),
            "quoted_attribute": (
                "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<a href=\"/go?next=${sanitizeHtml(request.q, { allowedTags: ['a'], allowedAttributes: { 'a': ['title'] } })}\">go</a>`; }\n",
                0,
            ),
            "wildcard": (
                "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.q, { allowedTags: ['*'] })}</script>`; }\n",
                1,
            ),
            "dynamic": (
                "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.q, { allowedTags: configured })}</script>`; }\n",
                1,
            ),
            "computed": (
                "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.q, { ['allowedTags']: ['p'] })}</script>`; }\n",
                1,
            ),
            "escaped": (
                "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.q, { \"allowed\\u0054ags\": ['p'] })}</script>`; }\n",
                1,
            ),
            "duplicate": (
                "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.q, { allowedTags: ['p'], allowedTags: ['script'] })}</script>`; }\n",
                1,
            ),
            "malformed": (
                "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.q, { allowedTags: ['p'], malformed: })}</script>`; }\n",
                1,
            ),
        }
        for name, (source, expected) in fixtures.items():
            with self.subTest(name=name):
                result = self._build(
                    f"nested-policy-token-{name}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(len(nested), expected)

    def test_nested_output_lexical_goal_distinguishes_division_and_regex(self) -> None:
        division = {
            "identifier": "export function render(request, total) { const n = total / 2; return `<style>${request.q}</style>`; }\n",
            "numeric": "export function render(request) { const n = 42 / 2; return `<style>${request.q}</style>`; }\n",
            "closing": "export function render(request, total) { const n = (total) / 2; return `<style>${request.q}</style>`; }\n",
            "postfix": "export function render(request, total) { const n = total++ / 2; return `<style>${request.q}</style>`; }\n",
            "interpolation": "export function render(request) { return `<style>${request.q++ / 2}${request.q}</style>`; }\n",
        }
        regex = {
            "expression_start": "export function render(request) { /`<script>${request.q}</script>`/.test('safe'); return 'safe'; }\n",
            "return": "export function render(request) { return /`<script>${request.q}</script>`/.test('safe'); }\n",
            "control_header": "export function render(request) { if (true) /`<script>${request.q}</script>`/.test('safe'); return 'safe'; }\n",
            "block": "export function render(request) { if (true) {} /`<script>${request.q}</script>`/.test('safe'); return 'safe'; }\n",
        }
        for name, source in division.items():
            with self.subTest(kind="division", name=name):
                result = self._build(f"nested-goal-division-{name}", {"src/render.ts": source}, guidance_schema_version=3)
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(len(nested), 2 if name == "interpolation" else 1)
        for name, source in regex.items():
            with self.subTest(kind="regex", name=name):
                result = self._build(f"nested-goal-regex-{name}", {"src/render.ts": source}, guidance_schema_version=3)
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(nested, [])

    def test_nested_output_lexical_goal_tracks_block_kinds_before_regex(self) -> None:
        regex = {
            "general_block": "export function render(request) { {} /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "function_body": "export function render(request) { function helper() {} /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "arrow_body": "export function render(request) { const helper = () => {} /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "try_body": "export function render(request) { try {} /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "finally_body": "export function render(request) { try {} finally {} /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
        }
        division = "export function render(request) { const value = ({ total: 2 } / 2); return `<style>${request.q}</style>`; }\n"
        for name, source in regex.items():
            with self.subTest(kind="regex", name=name):
                result = self._build(f"nested-goal-block-{name}", {"src/render.ts": source}, guidance_schema_version=3)
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(nested, [])
        result = self._build("nested-goal-object-division", {"src/render.ts": division}, guidance_schema_version=3)
        nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
        self.assertEqual(len(nested), 1)

    def test_nested_output_lexical_goal_tracks_class_body_kinds(self) -> None:
        regex = {
            "method": "export function render(request) { class C { method() {} } /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "extends_static": "export function render(request) { class C extends Base { static {} method() {} } /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
        }
        division = "export function render(request) { const value = (class C extends Base { static {} method() {} } / 2); return `<style>${request.q}</style>`; }\n"
        for name, source in regex.items():
            with self.subTest(kind="regex", name=name):
                result = self._build(f"nested-goal-class-{name}", {"src/render.ts": source}, guidance_schema_version=3)
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(nested, [])
        result = self._build("nested-goal-class-division", {"src/render.ts": division}, guidance_schema_version=3)
        nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
        self.assertEqual(len(nested), 1)

    def test_nested_output_lexical_goal_defers_class_header_confirmation(self) -> None:
        decoys = {
            "destructuring_key": "export function render(config, request) { const { class: alias } = config; {} /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "object_property": "export function render(config, request) { const value = { class: config.value }; {} /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "member_access": "export function render(config, request) { const value = config.class; {} /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "object_method": "export function render(config, request) { const value = { class() {} }; {} /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "string_and_computed_keys": "export function render(config, request) { const value = { 'class': config.value, ['class']: config.value }; {} /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
        }
        class_headers = {
            "declaration": "export function render(request) { class Widget { static {} method() {} } /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "export_default": "export default class Widget { static {} method() {} } /`<style>${request.q}</style>`/.test('safe'); export function render(request) { return 'safe'; }\n",
            "named_expression": "export function render(request) { const Widget = class Widget extends mixin(Base) { static {} method() {} }; /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "anonymous_expression": "export function render(request) { const Widget = class extends mixin(Base) { static {} method() {} }; /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
        }
        for name, source in {**decoys, **class_headers}.items():
            with self.subTest(kind="regex", name=name):
                result = self._build(f"nested-goal-deferred-class-{name}", {"src/render.ts": source}, guidance_schema_version=3)
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(nested, [])
        division = "export function render(config, request) { const value = config.class / 2; return `<style>${request.q}</style>`; }\n"
        result = self._build("nested-goal-deferred-class-division", {"src/render.ts": division}, guidance_schema_version=3)
        nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
        self.assertEqual(len(nested), 1)

    def test_nested_output_lexical_goal_fails_closed_for_invalid_class_headers(self) -> None:
        over_limit_header = ".".join(["Root", *("member" for _ in range(17))])
        fixtures = {
            "computed_key": "export function render(config, request) { const value = class [config.kind] {}; /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "malformed_extends": "export function render(request) { const value = class Widget extends mixin(Base); /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "over_limit": f"export function render(request) {{ const value = class Widget extends {over_limit_header} {{}}; /`<style>${{request.q}}</style>`/.test('safe'); return 'safe'; }}\n",
        }
        for name, source in fixtures.items():
            with self.subTest(name=name):
                first = self._build(f"nested-goal-invalid-class-{name}-first", {"src/render.ts": source}, guidance_schema_version=3)
                second = self._build(f"nested-goal-invalid-class-{name}-second", {"src/render.ts": source}, guidance_schema_version=3)
                self.assertNotIn(b"nested-output-context", first.canonical_bytes)
                self.assertNotIn(b"nested-output-context", second.canonical_bytes)
                self.assertEqual(first.canonical_bytes, second.canonical_bytes)

    def test_nested_output_lexical_goal_accepts_balanced_typescript_class_headers(self) -> None:
        headers = {
            "named_generic": "export function render(request) { class Widget<T> { static {} method() {} } /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "anonymous_generic": "export function render(request) { const Widget = class<T extends string> { static {} method() {} }; /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
            "nested_generic_extends_implements": "export function render(request) { class Widget<T extends Record<string, Array<number>>> extends mixin(Base) implements A, B { static {} method() {} } /`<style>${request.q}</style>`/.test('safe'); return 'safe'; }\n",
        }
        for name, source in headers.items():
            with self.subTest(name=name):
                result = self._build(f"nested-goal-typescript-class-{name}", {"src/render.ts": source}, guidance_schema_version=3)
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(nested, [])

    def test_nested_output_lexical_goal_bounds_class_header_source_span(self) -> None:
        prefix = "export function render(request) { const Widget = class"
        suffix = " { static {} /`<style>${request.q}<\\/style>`/.test('safe'); }; return `<style>${request.q}</style>`; }\n"
        fillers = {
            "whitespace": lambda size: " " * (size - len("class {".encode("utf-8"))),
            "line_comment": lambda size: "//" + (" " * (size - len("class//\n {".encode("utf-8")))) + "\n",
            "block_comment": lambda size: "/*" + (" " * (size - len("class/**/ {".encode("utf-8")))) + "*/",
        }
        for name, filler in fillers.items():
            for size, expected in ((16 * 1024, 1), ((16 * 1024) + 1, 0)):
                with self.subTest(name=name, size=size):
                    source = prefix + filler(size) + suffix
                    class_start = source.index("class")
                    body_start = source.index("{", class_start)
                    self.assertEqual(len(source[class_start:body_start + 1].encode("utf-8")), size)
                    first = self._build(f"nested-goal-class-span-{name}-{size}-first", {"src/render.ts": source}, guidance_schema_version=3)
                    second = self._build(f"nested-goal-class-span-{name}-{size}-second", {"src/render.ts": source}, guidance_schema_version=3)
                    nested = [json.loads(line) for line in first.canonical_bytes.splitlines() if b"nested-output-context" in line]
                    self.assertEqual(len(nested), expected)
                    self.assertEqual(first.canonical_bytes, second.canonical_bytes)

    def test_nested_output_depth_budget_counts_nested_template_levels(self) -> None:
        fixtures = {}
        for depth in (9, 16, 17):
            nested_template = "'safe'"
            for _ in range(depth):
                nested_template = "`${" + nested_template + "}`"
            source = (
                "export function render(request) { const decoy = `${"
                + nested_template
                + "}`; return `<style>${request.q}</style>`; }\n"
            )
            fixtures[depth] = source
        for depth, source in fixtures.items():
            with self.subTest(depth=depth):
                result = self._build(f"nested-depth-level-{depth}", {"src/render.ts": source}, guidance_schema_version=3)
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(len(nested), 0 if depth == 17 else 1)

    def test_nested_output_depth_budget_bounds_declaration_template_skipping(self) -> None:
        nested_template = "request.q"
        for _ in range(600):
            nested_template = "`${" + nested_template + "}`"
        source = "export function render(request) { return `<style>${" + nested_template + "}</style>`; }\n"
        first = self._build("nested-depth-budget-first", {"src/render.ts": source}, guidance_schema_version=3)
        second = self._build("nested-depth-budget-second", {"src/render.ts": source}, guidance_schema_version=3)
        self.assertEqual(first.canonical_bytes, b"")
        self.assertEqual(second.canonical_bytes, b"")
        self.assertEqual(first.canonical_bytes, second.canonical_bytes)

    def test_nested_output_remains_deterministic_for_malformed_and_overflow_inputs(self) -> None:
        fixtures = {
            "malformed": "export function render(request) { const safe = `<style>${request.q}</style>`; return `<script>${request.q}</script>; }\n",
            "overflow": "export function render(request) { const safe = `<style>${request.q}</style>`; return `<script>${request.q + '" + ("x" * 16385) + "'}</script>`; }\n",
        }
        for name, source in fixtures.items():
            with self.subTest(name=name):
                first = self._build(f"nested-token-bound-{name}-first", {"src/render.ts": source}, guidance_schema_version=3)
                second = self._build(f"nested-token-bound-{name}-second", {"src/render.ts": source}, guidance_schema_version=3)
                self.assertEqual(first.canonical_bytes, second.canonical_bytes)
                self.assertNotIn(b"nested-output-context", first.canonical_bytes)

    def test_nested_output_keeps_templates_after_division_expressions(self) -> None:
        fixtures = {
            "statement": (
                "export function render(request, total) { const n = total / 2; return `<style>${request.q}</style>`; }\n",
                1,
            ),
            "interpolation": (
                "export function render(request) { return `<style>${request.q / 2}${request.q}</style>`; }\n",
                2,
            ),
        }
        for name, (source, expected) in fixtures.items():
            with self.subTest(name=name):
                result = self._build(
                    f"nested-division-{name}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(len(nested), expected)

    def test_nested_output_lexer_ignores_regex_decoys_and_keeps_later_interpolation(self) -> None:
        decoy = "export function render(request) { const pattern = /`<script>${request.query.q}</script>`/; return 'safe'; }\n"
        actual = "export function render(request) { return `<script>${/}/.test('}') ? `${'safe'}` : 'safe'}${request.query.q}</script>`; }\n"
        for name, source, expected in (("regex-decoy", decoy, 0), ("regex-nested-later", actual, 1)):
            with self.subTest(name=name):
                result = self._build(
                    f"nested-lexer-{name}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(len(nested), expected)

    def test_nested_output_skips_ambiguous_unclosed_html_attribute_quotes(self) -> None:
        result = self._build(
            "nested-ambiguous-quote",
            {"src/render.ts": "export function render(request) { return `<style data-x=\">${request.query.q}</style>`; }\n"},
            guidance_schema_version=3,
        )
        nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
        self.assertEqual(nested, [])

    def test_nested_output_controls_ignore_strings_and_remain_bounded(self) -> None:
        string_decoy = "export function render(request) { const note = 'sanitizeFake('; return `<style>${request.query.q}</style>`; }\n"
        controls = "\n".join(f"  sanitizeControl{index}();" for index in range(9))
        bounded = f"export function render(request) {{\n{controls}\n  return `<style>${{request.query.q}}</style>`;\n}}\n"
        for name, source, expected_controls in (("string-decoy", string_decoy, 0), ("nine-controls", bounded, 8)):
            with self.subTest(name=name):
                result = self._build(
                    f"nested-controls-{name}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                row = next(json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line)
                self.assertEqual(len(row["controls"]), expected_controls)
                self.assertEqual(
                    "outer_html_sanitizer_context_mismatch" in row["reason_codes"],
                    bool(expected_controls),
                )

    def test_nested_output_does_not_infer_two_hop_alias_provenance(self) -> None:
        source = (
            "export function render(request) {\n"
            "  const first = request.q;\n"
            "  const second = first;\n"
            "  return `<style>${second}</style>`;\n"
            "}\n"
        )
        result = self._build(
            "nested-two-hop-alias",
            {"src/render.ts": source},
            guidance_schema_version=3,
        )
        nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
        self.assertEqual(nested, [])

    def test_nested_output_ignores_lexical_decoys_and_limit_overflows(self) -> None:
        templates = "".join("`static`;" for _ in range(256))
        interpolations = "".join('${"safe"}' for _ in range(512))
        nested_templates = "request.query.q"
        for _ in range(17):
            nested_templates = "`$" + "{" + nested_templates + "}`"
        fixtures = {
            "static_markup": "export function render(request) { return `<script>const value = 'safe'</script>`; }\n",
            "comment": "// `<script>${request.query.q}</script>`\nexport function render(request) { return 'safe'; }\n",
            "ordinary_string": "export function render(request) { return \"<style>${request.query.q}</style>\"; }\n",
            "escaped_interpolation": "export function render(request) { return `<script>\\${request.query.q}</script>`; }\n",
            "type_only": "type Rendered = \"<button onclick=\\\"${request.query.q}\\\">\";\n",
            "nested_braces": "export function render(request) { return `<script>${({ value: 'safe' }).value}</script>`; }\n",
            "escaped_backtick": "export function render(request) { return `\\` ${'safe'}`; }\n",
            "nested_template": "export function render(request) { return `<script>${`<style>${'safe'}</style>`}</script>`; }\n",
            "malformed": "export function render(request) { return `<script>${`<style>${request.query.q}</style>`}</script>; }\n",
            "expression_overflow": "export function render(request) { return `<style>${request.query.q + '" + ("a" * 16385) + "'}</style>`; }\n",
            "template_overflow": "export function render(request) { " + templates + " return `<script>${request.query.q}</script>`; }\n",
            "interpolation_overflow": "export function render(request) { return `<style>" + interpolations + "${request.query.q}</style>`; }\n",
            "depth_overflow": "export function render(request) { return `<script>${" + nested_templates + "}</script>`; }\n",
        }
        for name, source in fixtures.items():
            with self.subTest(name=name):
                result = self._build(
                    f"nested-decoy-{name}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(nested, [])

    def test_nested_output_does_not_suppress_unknown_or_retained_context_helpers(self) -> None:
        fixtures = {
            "escape": "export function render(request) { return `<script>${escape(request.query.q)}</script>`; }\n",
            "unknown_sanitizer": "export function render(request) { return `<style>${unknownSanitizer(request.query.q)}</style>`; }\n",
            "generic_html_escape": "export function render(request) { return `<button onclick=\"show('${escapeHtml(request.query.q)}')\">go</button>`; }\n",
            "retained_container": "import sanitizeHtml from 'sanitize-html'; export function render(request) { return `<script>${sanitizeHtml(request.query.q, { allowedTags: ['script'] })}</script>`; }\n",
            "commented_import": "/* import sanitizeHtml from 'sanitize-html'; */ export function render(request) { return `<script>${sanitizeHtml(request.query.q, { allowedTags: ['p'] })}</script>`; }\n",
        }
        for name, source in fixtures.items():
            with self.subTest(name=name):
                result = self._build(
                    f"nested-no-suppression-{name}",
                    {"src/render.ts": source},
                    guidance_schema_version=3,
                )
                nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
                self.assertEqual(len(nested), 1)

    def test_legacy_schemas_do_not_call_the_nested_output_scanner(self) -> None:
        source = "export function render(request) { return `<script>${request.query.q}</script>`; }\n"
        with mock.patch(
            "benchmarks.hermesbench.nested_output_guidance.scan_nested_output_contexts",
            side_effect=AssertionError("legacy schema called nested scanner"),
        ):
            for schema_version in (1, 2):
                with self.subTest(schema_version=schema_version):
                    result = self._build(
                        f"legacy-no-nested-{schema_version}",
                        {"src/render.ts": source},
                        guidance_schema_version=schema_version,
                    )
                    self.assertEqual(result.canonical_bytes, b"")

    def test_schema_three_limits_nested_output_scanning_to_javascript_and_typescript_extensions(self) -> None:
        source = "export function render(request) { return `<script>${request.query.q}</script>`; }\n"
        result = self._build(
            "nested-non-javascript",
            {"src/render.txt": source},
            guidance_schema_version=3,
        )
        nested = [json.loads(line) for line in result.canonical_bytes.splitlines() if b"nested-output-context" in line]
        self.assertEqual(nested, [])

    def test_schema_two_includes_general_only_from_an_exact_route_location(self) -> None:
        files = {
            "app.py": "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
        }
        without_general = self._build(
            "without-general",
            files,
            guidance_schema_version=2,
            passes={"app.py": ("forward",)},
        )
        with_general = self._build(
            "with-general",
            files,
            guidance_schema_version=2,
            passes={"app.py": ("general", "forward")},
        )
        self.assertEqual(json.loads(without_general.canonical_bytes)["eligible_search_passes"], ["forward"])
        self.assertEqual(json.loads(with_general.canonical_bytes)["eligible_search_passes"], ["forward", "general"])

    def test_frontier_pass_inputs_fail_closed_before_source_scanning(self) -> None:
        snapshot = self._root / "invalid-passes"
        snapshot.mkdir()
        (snapshot / "app.py").write_text("value = 1\n", encoding="utf-8")
        invalid = (
            (),
            [("app.py", ("forward",))],
            (("app.py", ()),),
            (("app.py", ("forward", "forward")),),
            (("app.py", ("invented",)),),
            (("./app.py", ("forward",)), ("app.py", ("guard",))),
        )
        for frontier_passes in invalid:
            with self.subTest(frontier_passes=frontier_passes):
                with self.assertRaises(semantic_guidance.SemanticGuidanceError):
                    build_semantic_guidance(
                        snapshot,
                        frontier_passes,
                        "hunt-balanced",
                        guidance_schema_version=2,
                    )

    def test_frontier_schema_inputs_fail_closed_before_source_scanning(self) -> None:
        snapshot = self._root / "invalid-schema"
        snapshot.mkdir()
        (snapshot / "app.py").write_text("value = 1\n", encoding="utf-8")
        for guidance_schema_version in (0, 4, True):
            with self.subTest(guidance_schema_version=guidance_schema_version):
                with self.assertRaises(semantic_guidance.SemanticGuidanceError):
                    build_semantic_guidance(
                        snapshot,
                        (("app.py", ("forward",)),),
                        "hunt-balanced",
                        guidance_schema_version=guidance_schema_version,
                    )

    def test_schema_two_rejects_a_route_path_missing_from_frontier_passes(self) -> None:
        source = semantic_guidance._Location("entry.py", 1, "handle")
        operation = semantic_guidance._Location("sink.py", 1, "run")
        route = semantic_guidance._Route(
            "import-linked", "command", source, operation, (source, operation), (), ("source_anchor",)
        )
        with self.assertRaises(semantic_guidance.SemanticGuidanceError):
            semantic_guidance._canonical_row(route, 2, {"entry.py": ("forward",)})

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

    def test_replaced_source_after_lstat_is_skipped_without_reading_replacement(self) -> None:
        snapshot = self._root / "replacement"
        snapshot.mkdir()
        target = snapshot / "app.py"
        target.write_text("import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n", encoding="utf-8")
        replacement = snapshot / "replacement.py"
        replacement.write_text("import subprocess\ndef replaced(request):\n    return subprocess.run(request.args['q'])\n", encoding="utf-8")
        original_open = semantic_guidance.os.open

        def replace_before_open(path: object, flags: int) -> int:
            if Path(path) == target:
                os.replace(replacement, target)
            return original_open(path, flags)

        with mock.patch.object(semantic_guidance.os, "open", side_effect=replace_before_open):
            result = build_semantic_guidance(
                snapshot,
                (("app.py", ("forward",)),),
                "hunt-balanced",
                guidance_schema_version=1,
            )
        self.assertEqual(result.scanned_file_count, 0)
        self.assertEqual(result.skipped_file_count, 1)
        self.assertEqual(result.canonical_bytes, b"")

    def test_replaced_intermediate_directory_is_skipped_before_external_source_read(self) -> None:
        snapshot = self._root / "snapshot-replacement"
        nested = snapshot / "sub"
        nested.mkdir(parents=True)
        target = nested / "app.py"
        target.write_text("import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n", encoding="utf-8")
        outside = self._root / "outside-replacement"
        outside.mkdir()
        original_open = semantic_guidance.os.open

        def replace_parent_before_open(path: object, flags: int) -> int:
            if Path(path) == target:
                os.replace(target, outside / "app.py")
                nested.rmdir()
                try:
                    os.symlink(outside, nested, target_is_directory=True)
                except OSError as error:
                    self.skipTest(f"directory links are unavailable: {error}")
            return original_open(path, flags)

        with mock.patch.object(semantic_guidance.os, "open", side_effect=replace_parent_before_open):
            result = build_semantic_guidance(
                snapshot,
                (("sub/app.py", ("forward",)),),
                "hunt-balanced",
                guidance_schema_version=1,
            )
        self.assertEqual(result.scanned_file_count, 0)
        self.assertEqual(result.skipped_file_count, 1)
        self.assertEqual(result.canonical_bytes, b"")

    def test_replaced_snapshot_root_is_skipped_before_external_source_read(self) -> None:
        snapshot = self._root / "root-replacement"
        snapshot.mkdir()
        target = snapshot / "app.py"
        target.write_text("import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n", encoding="utf-8")
        outside = self._root / "outside-root"
        outside.mkdir()
        original_open = semantic_guidance.os.open

        def replace_root_before_open(path: object, flags: int) -> int:
            if Path(path) == target:
                os.replace(snapshot, outside / "snapshot")
                try:
                    os.symlink(outside / "snapshot", snapshot, target_is_directory=True)
                except OSError as error:
                    self.skipTest(f"directory links are unavailable: {error}")
            return original_open(path, flags)

        with mock.patch.object(semantic_guidance.os, "open", side_effect=replace_root_before_open):
            result = build_semantic_guidance(
                snapshot,
                (("app.py", ("forward",)),),
                "hunt-balanced",
                guidance_schema_version=1,
            )
        self.assertEqual(result.scanned_file_count, 0)
        self.assertEqual(result.skipped_file_count, 1)
        self.assertEqual(result.canonical_bytes, b"")

    def test_python_declaration_stops_before_sibling_class_method(self) -> None:
        rows = self._rows(
            {
                "app.py": (
                    "def handle(request):\n"
                    "    return request.args['q']\n"
                    "class Worker:\n"
                    "    def run(self, value):\n"
                    "        return subprocess.run(value)\n"
                )
            }
        )
        self.assertFalse(any(row["source"]["symbol"] == "handle" for row in rows))

    def test_multiline_python_header_keeps_its_indented_body(self) -> None:
        row = self._single_row(
            {
                "app.py": (
                    "import subprocess\n"
                    "def handle(\n"
                    "    request,\n"
                    "):\n"
                    "    return subprocess.run(request.args['q'])\n"
                    "class Worker:\n"
                    "    def run(self, value):\n"
                    "        return subprocess.run(value)\n"
                )
            }
        )
        self.assertEqual(row["source"]["symbol"], "handle")
        self.assertEqual(row["strength"], "direct")

    def test_escaped_single_quotes_do_not_create_fake_operations(self) -> None:
        fixtures = {
            "app.py": "def handle(request):\n    note = 'escaped \\\' subprocess.run(request.args[\\\'q\\\'])'\n    return request.args['q']\n",
            "app.js": "function handle(request) { const note = 'escaped \\\' child_process.exec(request.query.q)'; return request.query.q; }\n",
        }
        for path, source in fixtures.items():
            with self.subTest(path=path):
                self.assertEqual(self._rows({path: source}), [])

    def test_duplicate_frontier_path_does_not_duplicate_endpoint(self) -> None:
        snapshot = self._root / "duplicate"
        snapshot.mkdir()
        (snapshot / "app.py").write_text(
            "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
            encoding="utf-8",
        )
        result = build_semantic_guidance(
            snapshot,
            (("app.py", ("forward",)), ("app.py", ("forward",))),
            "hunt-balanced",
            guidance_schema_version=1,
        )
        self.assertEqual(result.scanned_file_count, 1)
        self.assertEqual(result.row_count, 1)

    def test_legacy_schemas_ignore_component_conflicts_for_exact_duplicate_frontier_paths(self) -> None:
        snapshot = self._root / "duplicate-components"
        snapshot.mkdir()
        (snapshot / "app.py").write_text(
            "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
            encoding="utf-8",
        )
        for guidance_schema_version in (1, 2):
            with self.subTest(guidance_schema_version=guidance_schema_version):
                result = build_semantic_guidance(
                    snapshot,
                    (
                        ("app.py", "component-first", ("forward",)),
                        ("app.py", "component-conflict", ("forward",)),
                    ),
                    "hunt-balanced",
                    guidance_schema_version=guidance_schema_version,
                )
                row = json.loads(result.canonical_bytes)
                self.assertEqual(row["schema_version"], guidance_schema_version)
                self.assertNotIn("component", row)
                if guidance_schema_version == 1:
                    self.assertEqual(
                        result.canonical_bytes,
                        b'{"controls":[],"hint_id":"f51a8b5b354cdafd","operation":{"line":3,"path":"app.py","symbol":"subprocess.run"},"operation_family":"command","proof_status":"investigation_only","reason_codes":["source_anchor","operation_anchor","same_declaration"],"schema_version":1,"source":{"line":2,"path":"app.py","symbol":"handle"},"strength":"direct","trace":[{"line":2,"path":"app.py","symbol":"handle"}]}\n',
                    )
                else:
                    self.assertEqual(row["eligible_search_passes"], ["forward"])

    def test_schema_three_rejects_component_conflicts_for_exact_duplicate_frontier_paths(self) -> None:
        snapshot = self._root / "duplicate-schema-three-components"
        snapshot.mkdir()
        (snapshot / "app.py").write_text(
            "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
            encoding="utf-8",
        )
        with self.assertRaises(semantic_guidance.SemanticGuidanceError):
            build_semantic_guidance(
                snapshot,
                (
                    ("app.py", "component-first", ("forward",)),
                    ("app.py", "component-conflict", ("forward",)),
                ),
                "hunt-balanced",
                guidance_schema_version=3,
            )

    def test_schema_two_component_contexts_preserve_legacy_canonical_bytes(self) -> None:
        snapshot = self._root / "schema-two-component-contexts"
        snapshot.mkdir()
        (snapshot / "app.py").write_text(
            "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
            encoding="utf-8",
        )
        baseline = build_semantic_guidance(
            snapshot,
            (("app.py", ("forward",)),),
            "hunt-balanced",
            guidance_schema_version=2,
        )
        component_contexts = build_semantic_guidance(
            snapshot,
            (
                ("app.py", "component-first", ("forward",)),
                ("app.py", "component-conflict", ("forward",)),
            ),
            "hunt-balanced",
            guidance_schema_version=2,
        )
        self.assertEqual(component_contexts.canonical_bytes, baseline.canonical_bytes)

    def test_equivalent_frontier_paths_are_canonicalized_before_deduplication(self) -> None:
        snapshot = self._root / "canonical"
        snapshot.mkdir()
        (snapshot / "app.py").write_text(
            "import subprocess\ndef handle(request):\n    return subprocess.run(request.args['q'])\n",
            encoding="utf-8",
        )
        result = build_semantic_guidance(
            snapshot,
            (("./app.py", ("forward",)), ("app.py", ("forward",))),
            "hunt-balanced",
            guidance_schema_version=1,
        )
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
        result = build_semantic_guidance(
            snapshot,
            (("linked/external.py", ("forward",)),),
            "hunt-balanced",
            guidance_schema_version=1,
        )
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
