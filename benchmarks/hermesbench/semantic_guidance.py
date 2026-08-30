from __future__ import annotations

from dataclasses import dataclass, replace
from collections import Counter, deque
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import posixpath
import re
import stat
from typing import Callable

from benchmarks.hermesbench.hunt_protocol import HUNT_SEARCH_PASS_ORDER

LEGACY_SEMANTIC_GUIDANCE_SCHEMA_VERSION = 1
PASS_ANNOTATED_SEMANTIC_GUIDANCE_SCHEMA_VERSION = 2
SEMANTIC_GUIDANCE_SCHEMA_VERSION = 3
SUPPORTED_SEMANTIC_GUIDANCE_SCHEMA_VERSIONS = frozenset({1, 2, 3})
OPERATION_INDEX_FAMILY_CODES = {
    "assignment": "a",
    "call": "c",
    "mutation": "m",
}
OPERATION_INDEX_FAMILY_PRIORITY = {
    "call": 0,
    "assignment": 1,
    "mutation": 2,
}
OPERATION_INDEX_PASS_CODES = {
    "forward": "f",
    "backward": "b",
    "guard": "g",
    "parser": "p",
    "state": "s",
    "general": "x",
}
MAX_OPERATION_INDEX_SITES_PER_ENTRY = 128
MAX_OPERATION_INDEX_ROW_BYTES = 2 * 1024
MAX_OPERATION_INDEX_ONLY_ROWS = 32
MAX_OPERATION_INDEX_ONLY_BYTES = 64 * 1024
MAX_OPERATION_INDEX_PREFERRED_REUSED_SIGNATURE_FREQUENCY = 7
MAX_OPERATION_INDEX_REUSED_SIGNATURE_FREQUENCY = 16
MIN_OPERATION_INDEX_COMPLEX_CALL_IDENTIFIERS = 3
OPERATION_INDEX_PARAMETER_FLOW_WEIGHT = 2
OPERATION_INDEX_DENSITY_LOOKAHEAD = 16
PAIRED_FLOW_SEED_SCHEMA_VERSION = 1
PAIRED_FLOW_SEED_LIMITS = {
    "hunt-balanced": (128, 64 * 1024, 1024),
    "hunt-max": (256, 128 * 1024, 1024),
}
MAX_PAIRED_FLOW_SEED_TRACE = 4
MAX_PAIRED_FLOW_SEED_SYMBOL_BYTES = 256
MAX_FILE_BYTES = 1024 * 1024
_CODE = "C"
_STRING = "S"
_COMMENT = "M"

SOURCE_ANCHORS = {
    "request",
    "body",
    "query",
    "params",
    "headers",
    "cookie",
    "argv",
    "stdin",
    "environment",
    "input",
}
CONTROL_ANCHORS = {
    "allowlist",
    "authorize",
    "escape",
    "guard",
    "permission",
    "policy",
    "sanitize",
    "validate",
}
OPERATION_ANCHORS = {
    "command": {
        "exec",
        "eval",
        "system",
        "subprocess.run",
        "subprocess.popen",
        "child_process.exec",
        "child_process.spawn",
        "exec.command",
        "os/exec.command",
    },
    "query": {"query", "rawquery", "executesql", "cursor.execute", "db.raw"},
    "file": {"open", "os.open", "readfile", "writefile", "remove", "unlink"},
    "template": {"renderstring", "template.execute", "executetemplate"},
    "deserialize": {
        "pickle.load",
        "pickle.loads",
        "yaml.load",
        "unmarshal",
        "unserialize",
        "objectinputstream",
    },
    "network": {"fetch", "urlopen", "http.get", "client.do", "dial"},
    "state": {"delete", "destroy", "save", "update", "transition"},
}


class SemanticGuidanceError(ValueError):
    pass


@dataclass(frozen=True)
class GuidanceLimits:
    total_source_bytes: int
    declaration_count: int
    edge_count: int
    route_count: int
    row_count: int
    output_bytes: int
    graph_depth: int


PROFILE_LIMITS = {
    "hunt-balanced": GuidanceLimits(64 * 1024 * 1024, 50_000, 200_000, 1_024, 256, 512 * 1024, 4),
    "hunt-max": GuidanceLimits(128 * 1024 * 1024, 100_000, 400_000, 2_048, 512, 1024 * 1024, 6),
}


@dataclass(frozen=True)
class SemanticGuidance:
    canonical_bytes: bytes
    row_count: int
    edge_count: int
    scanned_file_count: int
    skipped_file_count: int
    paired_flow_seeds: PairedFlowSeeds | None = None


@dataclass(frozen=True)
class PairedFlowSeeds:
    canonical_bytes: bytes
    row_count: int
    paired_count: int
    sink_only_count: int


@dataclass(frozen=True)
class _Location:
    path: str
    line: int
    symbol: str

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "line": self.line, "symbol": self.symbol}


@dataclass(frozen=True)
class _Declaration:
    location: _Location
    language: str
    receiver: str | None
    sources: tuple[_Location, ...]
    operations: tuple[tuple[str, _Location], ...]
    controls: tuple[_Location, ...]
    imports: tuple[_Import, ...]
    calls: tuple[_Call, ...]
    mutations: tuple[_Mutation, ...] = ()
    assignments: tuple[_Assignment, ...] = ()


@dataclass(frozen=True)
class _Import:
    local_name: str
    module: str
    symbol: str | None


@dataclass(frozen=True)
class _Call:
    name: str
    qualifier: str | None
    line: int
    arguments: str = ""
    parameter_flow: bool = False
    argument_identifier_count: int = 0


@dataclass(frozen=True)
class _Mutation:
    line: int
    signature: str
    parameter_flow: bool = False


@dataclass(frozen=True)
class _Assignment:
    line: int
    signature: str
    parameter_flow: bool


@dataclass(frozen=True)
class _StructuralSite:
    component: str
    path: str
    line: int
    family: str
    signature: str
    parameter_flow: bool = False
    argument_identifier_count: int = 0
    owner: _Location | None = None
    owner_sources: tuple[_Location, ...] = ()


_ModuleTargetIndex = dict[tuple[str, str, str], tuple[_Declaration, ...]]


@dataclass(frozen=True)
class _Route:
    strength: str
    operation_family: str
    source: _Location
    operation: _Location
    trace: tuple[_Location, ...]
    controls: tuple[_Location, ...]
    reason_codes: tuple[str, ...]
    hint_kind: str = "call-route"
    output_context: str | None = None


@dataclass(frozen=True)
class _ScanStats:
    scanned_file_count: int
    skipped_file_count: int


def build_semantic_guidance(
    snapshot_path: Path,
    frontier_contexts: tuple[tuple[str, str, tuple[str, ...]], ...],
    profile: str,
    *,
    guidance_schema_version: int,
    include_paired_flow_seeds: bool = False,
) -> SemanticGuidance:
    try:
        limits = PROFILE_LIMITS[profile]
    except KeyError as error:
        raise SemanticGuidanceError("semantic guidance profile is unsupported") from error
    if (
        isinstance(guidance_schema_version, bool)
        or not isinstance(guidance_schema_version, int)
        or guidance_schema_version not in SUPPORTED_SEMANTIC_GUIDANCE_SCHEMA_VERSIONS
    ):
        raise SemanticGuidanceError("semantic guidance schema version is unsupported")
    if not isinstance(include_paired_flow_seeds, bool):
        raise SemanticGuidanceError("paired flow seed selection is invalid")
    paths, frontier_passes_by_path, frontier_components_by_path = _normalize_frontier_contexts(
        frontier_contexts,
        guidance_schema_version,
    )
    snapshot = _safe_snapshot(snapshot_path)
    nested_scanner = None
    nested_extensions = frozenset()
    if guidance_schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION:
        from benchmarks.hermesbench.nested_output_guidance import (
            JAVASCRIPT_TYPESCRIPT_EXTENSIONS,
            scan_nested_output_contexts,
        )

        nested_scanner = scan_nested_output_contexts
        nested_extensions = JAVASCRIPT_TYPESCRIPT_EXTENSIONS
    declarations, scan, nested_observations = _scan_files(
        snapshot,
        paths,
        limits,
        nested_scanner,
        nested_extensions,
        guidance_schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION,
    )
    if guidance_schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION:
        routes, edge_count, incoming, by_identity = _build_schema_three_routes(declarations, limits)
        structural_sites = _structural_sites(
            declarations,
            frontier_components_by_path,
            limits.edge_count,
        )
        operation_index_rows = _operation_index_rows(
            structural_sites,
            frontier_passes_by_path,
            limits,
        )
        routes = (
            *routes,
            *_nested_output_routes(nested_observations, incoming, by_identity),
        )
        paired_flow_seeds = (
            _paired_flow_seeds(
                routes,
                structural_sites,
                frontier_passes_by_path,
                frontier_components_by_path,
                profile,
            )
            if include_paired_flow_seeds
            else None
        )
    else:
        routes, edge_count = _build_routes(declarations, limits)
        operation_index_rows = ()
        paired_flow_seeds = None
    canonical_bytes, row_count = _canonical_guidance(
        routes,
        limits,
        guidance_schema_version,
        frontier_passes_by_path,
        frontier_components_by_path,
        operation_index_rows,
    )
    return SemanticGuidance(
        canonical_bytes,
        row_count,
        edge_count,
        scan.scanned_file_count,
        scan.skipped_file_count,
        paired_flow_seeds,
    )


def _normalize_frontier_contexts(
    frontier_contexts: tuple[tuple[str, str, tuple[str, ...]], ...],
    guidance_schema_version: int,
) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]], dict[str, str]]:
    if not isinstance(frontier_contexts, tuple) or not frontier_contexts:
        raise SemanticGuidanceError("semantic guidance frontier passes are invalid")
    paths: list[str] = []
    by_path: dict[str, tuple[str, ...]] = {}
    components_by_path: dict[str, str] = {}
    for item in frontier_contexts:
        if not isinstance(item, tuple) or len(item) not in {2, 3}:
            raise SemanticGuidanceError("semantic guidance frontier passes are invalid")
        if len(item) == 2:
            raw_path, raw_passes = item
            raw_component = None
        else:
            raw_path, raw_component, raw_passes = item
        if not isinstance(raw_path, str) or not isinstance(raw_passes, tuple) or not raw_passes:
            raise SemanticGuidanceError("semantic guidance frontier passes are invalid")
        if guidance_schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION and (
            not isinstance(raw_component, str) or not raw_component or "\x00" in raw_component
        ):
            raise SemanticGuidanceError("semantic guidance frontier component is invalid")
        if any(
            not isinstance(value, str) or value not in HUNT_SEARCH_PASS_ORDER
            for value in raw_passes
        ) or len(raw_passes) != len(set(raw_passes)):
            raise SemanticGuidanceError("semantic guidance frontier passes are invalid")
        path = _canonical_relative_path(raw_path)
        ordered = tuple(value for value in HUNT_SEARCH_PASS_ORDER if value in raw_passes)
        if path in by_path:
            if by_path[path] != ordered or (
                guidance_schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION
                and isinstance(raw_component, str)
                and path in components_by_path
                and components_by_path[path] != raw_component
            ):
                raise SemanticGuidanceError("semantic guidance frontier passes conflict")
            continue
        paths.append(path)
        by_path[path] = ordered
        if guidance_schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION and isinstance(raw_component, str):
            components_by_path[path] = raw_component
    return tuple(paths), by_path, components_by_path


def _safe_snapshot(snapshot_path: Path) -> Path:
    snapshot = snapshot_path.resolve(strict=True)
    if not snapshot.is_dir():
        raise SemanticGuidanceError("semantic guidance snapshot is not a directory")
    return snapshot


def _scan_files(
    snapshot: Path,
    paths: tuple[str, ...],
    limits: GuidanceLimits,
    nested_scanner: Callable[[str], tuple[object, ...]] | None = None,
    nested_extensions: frozenset[str] = frozenset(),
    retain_all_references: bool = False,
) -> tuple[tuple[_Declaration, ...], _ScanStats, tuple[tuple[str, object], ...]]:
    declarations: list[_Declaration] = []
    scanned = 0
    skipped = 0
    total_bytes = 0
    retained_references = 0
    retained_structural_sites = 0
    seen_paths: set[str] = set()
    nested_observations: list[tuple[str, object]] = []
    for raw_path in paths:
        relative_path = _canonical_relative_path(raw_path)
        if relative_path in seen_paths:
            continue
        seen_paths.add(relative_path)
        candidate = snapshot / Path(relative_path)
        try:
            encoded, source_size = _read_pinned_source(snapshot, candidate)
            if total_bytes + source_size > limits.total_source_bytes:
                raise ValueError("source budget exceeded")
            source = encoded.decode("utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            skipped += 1
            continue
        total_bytes += source_size
        scanned += 1
        if nested_scanner is not None and PurePosixPath(relative_path).suffix.lower() in nested_extensions:
            nested_observations.extend((relative_path, item) for item in nested_scanner(source))
        if len(declarations) >= limits.declaration_count:
            continue
        extracted = _extract_declarations(relative_path, source, limits.declaration_count - len(declarations))
        for declaration in extracted:
            remaining_structural_sites = max(
                0,
                limits.edge_count - retained_structural_sites,
            )
            mutations = declaration.mutations[:remaining_structural_sites]
            remaining_structural_sites -= len(mutations)
            assignments = declaration.assignments[:remaining_structural_sites]
            retained_structural_sites += len(mutations) + len(assignments)
            bounded_declaration = replace(
                declaration,
                mutations=mutations,
                assignments=assignments,
            )
            if retain_all_references:
                declarations.append(bounded_declaration)
                continue
            remaining_references = max(0, limits.edge_count - retained_references)
            calls = declaration.calls[:remaining_references]
            remaining_references -= len(calls)
            imports = declaration.imports[:remaining_references]
            retained_references += len(calls) + len(imports)
            declarations.append(
                replace(
                    bounded_declaration,
                    calls=calls,
                    imports=imports,
                )
            )
    return tuple(declarations), _ScanStats(scanned, skipped), tuple(nested_observations)


def _read_pinned_source(snapshot: Path, path: Path) -> tuple[bytes, int]:
    parent_identities = _source_parent_identities(snapshot, path)
    before = path.lstat()
    _validate_source_metadata(before)
    identity = _source_identity(before)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _validate_source_metadata(opened)
        if _source_identity(opened) != identity:
            raise ValueError("source identity changed before open")
        if _source_parent_identities(snapshot, path) != parent_identities:
            raise ValueError("source parent changed before read")
        encoded = bytearray()
        while True:
            chunk = os.read(descriptor, min(16 * 1024, MAX_FILE_BYTES + 1 - len(encoded)))
            if not chunk:
                break
            encoded.extend(chunk)
            if len(encoded) > MAX_FILE_BYTES:
                raise ValueError("source exceeds maximum size")
    finally:
        os.close(descriptor)
    after = path.lstat()
    _validate_source_metadata(after)
    if _source_identity(after) != identity:
        raise ValueError("source identity changed after read")
    return bytes(encoded), len(encoded)


def _source_parent_identities(snapshot: Path, path: Path) -> tuple[tuple[int, int], ...]:
    relative_parent = path.parent.relative_to(snapshot)
    current = snapshot
    identities: list[tuple[int, int]] = []
    for part in (None, *relative_parent.parts):
        if part is not None:
            current /= part
        metadata = current.lstat()
        mode = getattr(metadata, "st_mode", None)
        attributes = getattr(metadata, "st_file_attributes", None)
        if not isinstance(mode, int) or isinstance(mode, bool) or not stat.S_ISDIR(mode):
            raise ValueError("source parent is invalid")
        if attributes is not None and (not isinstance(attributes, int) or isinstance(attributes, bool) or attributes & 0x400):
            raise ValueError("source parent is invalid")
        device = getattr(metadata, "st_dev", None)
        inode = getattr(metadata, "st_ino", None)
        if not isinstance(device, int) or isinstance(device, bool) or not isinstance(inode, int) or isinstance(inode, bool):
            raise ValueError("source parent identity is unavailable")
        identities.append((device, inode))
    return tuple(identities)


def _validate_source_metadata(metadata: object) -> None:
    mode = getattr(metadata, "st_mode", None)
    links = getattr(metadata, "st_nlink", None)
    size = getattr(metadata, "st_size", None)
    attributes = getattr(metadata, "st_file_attributes", None)
    if not isinstance(mode, int) or isinstance(mode, bool) or not stat.S_ISREG(mode):
        raise ValueError("source is not regular")
    if not isinstance(links, int) or isinstance(links, bool) or links != 1:
        raise ValueError("source link count is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > MAX_FILE_BYTES:
        raise ValueError("source size is invalid")
    if attributes is not None and (not isinstance(attributes, int) or isinstance(attributes, bool) or attributes & 0x400):
        raise ValueError("source attributes are invalid")


def _source_identity(metadata: object) -> tuple[int, int, int, int]:
    values = (getattr(metadata, "st_dev", None), getattr(metadata, "st_ino", None), getattr(metadata, "st_size", None), getattr(metadata, "st_mtime_ns", None))
    if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
        raise ValueError("source identity is unavailable")
    return values  # type: ignore[return-value]


def _canonical_relative_path(raw_path: str) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise SemanticGuidanceError("semantic guidance path is invalid")
    posix_path = PurePosixPath(raw_path)
    windows_path = PureWindowsPath(raw_path)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or any(part == ".." for part in posix_path.parts)
        or any(part == ".." for part in windows_path.parts)
    ):
        raise SemanticGuidanceError("semantic guidance path is not relative")
    normalized = raw_path.replace("\\", "/")
    canonical = PurePosixPath(normalized)
    if canonical.is_absolute() or normalized in {"", "."} or normalized.startswith("/"):
        raise SemanticGuidanceError("semantic guidance path is invalid")
    return canonical.as_posix()


def _extract_declarations(path: str, source: str, remaining: int) -> tuple[_Declaration, ...]:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".py":
        states = _lexical_state_map(source, "python")
        masked = _mask_non_code(source, states)
        classes = _class_declarations(
            path,
            "python",
            masked,
            r"(?m)^\s*class\s+(?P<name>[A-Za-z_]\w*)\b",
            remaining,
        )
        matches = list(re.finditer(
            r"(?m)^(?P<indent>[ \t]*)(?:(?:async[ \t]+)?def[ \t]+(?P<name>[A-Za-z_]\w*)\s*\(|(?P<assigned>[A-Za-z_]\w*)\s*=\s*(?:async[ \t]+)?lambda\b)",
            masked,
        ))
        declarations = _python_declarations(path, masked, matches, remaining - len(classes))
        imports = _scan_imports(source, states, "python")
    elif suffix == ".go":
        states = _lexical_state_map(source, "go")
        masked = _mask_non_code(source, states)
        classes = _class_declarations(
            path,
            "go",
            masked,
            r"(?m)^\s*type\s+(?P<name>[A-Za-z_]\w*)\s+struct\b",
            remaining,
        )
        matches = list(re.finditer(
            r"\bfunc\s+(?:\((?P<receiver>[A-Za-z_]\w*)\s+[^\n)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\(|\b(?P<assigned>[A-Za-z_]\w*)\s*(?::=|=)\s*func\s*\(",
            masked,
        ))
        declarations = _brace_declarations(path, masked, matches, remaining - len(classes), "go")
        imports = _scan_imports(source, states, "go")
    elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
        states = _lexical_state_map(source, "typescript")
        masked = _mask_non_code(source, states)
        classes = _class_declarations(
            path,
            "typescript",
            masked,
            r"\bclass\s+(?P<name>[A-Za-z_$][\w$]*)\b",
            remaining,
        )
        matches = list(re.finditer(
            r"(?m)\b(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(|"
            r"^[ \t]*(?!(?:if|for|while|switch|catch)\b)(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*(?P<method>[A-Za-z_$][\w$]*)\s*\(|"
            r"(?:\b(?:const|let|var)\s+|^[ \t]*(?:public\s+|private\s+|protected\s+|static\s+)*)?(?P<assigned>[A-Za-z_$][\w$]*)(?:\s*:(?:(?!\s=\s)[^\n])*)?\s*=\s*(?:async\s+)?(?:function\s*)?(?:\([^\n)]*\)|[A-Za-z_$][\w$]*)\s*(?:=>|\{)",
            masked,
        ))
        declarations = _brace_declarations(path, masked, matches, remaining - len(classes), "typescript")
        imports = _scan_imports(source, states, "typescript")
    else:
        classes = ()
        states = _lexical_state_map(source, "generic")
        declarations = _generic_declarations(path, _mask_non_code(source, states), remaining)
        imports = ()
    return tuple(replace(declaration, imports=imports) for declaration in (*classes, *declarations))


def _class_declarations(
    path: str,
    language: str,
    source: str,
    pattern: str,
    remaining: int,
) -> tuple[_Declaration, ...]:
    declarations: list[_Declaration] = []
    for match in re.finditer(pattern, source):
        if len(declarations) >= remaining:
            break
        line = source.count("\n", 0, match.start()) + 1
        declarations.append(_Declaration(_Location(path, line, match.group("name")), language, None, (), (), (), (), ()))
    return tuple(declarations)


def _python_declarations(path: str, source: str, matches: list[re.Match[str]], remaining: int) -> tuple[_Declaration, ...]:
    declarations: list[_Declaration] = []
    lines = source.splitlines()
    for index, match in enumerate(matches[:remaining]):
        start_line = source.count("\n", 0, match.start()) + 1
        if match.group("assigned"):
            declarations.append(
                _declaration_from_block(
                    path,
                    "python",
                    match.group("assigned"),
                    start_line,
                    [lines[start_line - 1]],
                )
            )
            continue
        indent = len(match.group("indent").expandtabs(8))
        header_end = start_line - 1
        parentheses = 0
        for line_number in range(start_line - 1, len(lines)):
            header = lines[line_number]
            parentheses += header.count("(") - header.count(")")
            if parentheses <= 0 and ":" in header:
                header_end = line_number
                break
        end_line = len(lines)
        for line_number in range(header_end + 1, len(lines)):
            line = lines[line_number]
            if line.strip() and len(line) - len(line.lstrip(" \t")) <= indent:
                end_line = line_number
                break
        declarations.append(_declaration_from_block(path, "python", match.group("name"), start_line, lines[start_line - 1 : end_line]))
    return tuple(declarations)


def _brace_declarations(
    path: str,
    source: str,
    matches: list[re.Match[str]],
    remaining: int,
    language: str,
) -> tuple[_Declaration, ...]:
    declarations: list[_Declaration] = []
    for match in matches[:remaining]:
        start_line = source.count("\n", 0, match.start()) + 1
        opening = source.find("{", match.end())
        line_end = source.find("\n", match.end())
        if line_end < 0:
            line_end = len(source)
        closing = _matching_brace(source, opening) if 0 <= opening <= line_end else None
        block_end = line_end if closing is None else closing + 1
        block = source[match.start() : block_end].splitlines()
        groups = match.groupdict()
        symbol = groups.get("name") or groups.get("method") or groups.get("assigned")
        declarations.append(
            _declaration_from_block(
                path,
                language,
                symbol,
                start_line,
                block,
                match.groupdict().get("receiver"),
            )
        )
    return tuple(declarations)


def _matching_brace(source: str, opening: int) -> int | None:
    if opening < 0:
        return None
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _generic_declarations(path: str, source: str, remaining: int) -> tuple[_Declaration, ...]:
    if not source or remaining == 0:
        return ()
    return (_declaration_from_block(path, "generic", "file", 1, source.splitlines()),)


def _declaration_from_block(
    path: str,
    language: str,
    symbol: str,
    line: int,
    lines: list[str],
    receiver: str | None = None,
) -> _Declaration:
    location = _Location(path, line, symbol)
    parameters = _declaration_parameters(lines, language)
    assignments = _assignments(lines, line, parameters)
    flow_names = parameters | frozenset(
        assignment.signature
        for assignment in assignments
        if assignment.parameter_flow
    )
    source_locations = _anchor_locations(path, symbol, line, lines, SOURCE_ANCHORS)[:1]
    controls = _anchor_locations(path, symbol, line, lines, CONTROL_ANCHORS)
    operations: list[tuple[str, _Location]] = []
    for family, anchors in OPERATION_ANCHORS.items():
        for offset, line_text in enumerate(lines):
            for callee in _operation_callees(line_text, anchors):
                operations.append((family, _Location(path, line + offset, callee)))
    return _Declaration(
        location,
        language,
        receiver.lower() if receiver else None,
        source_locations,
        tuple(operations),
        controls,
        (),
        _calls(lines, line, flow_names),
        _member_mutations(lines, line, flow_names),
        assignments,
    )


def _lexical_state_map(source: str, language: str) -> str:
    states = [_CODE] * len(source)
    quote: str | None = None
    triple_quote = False
    index = 0
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if quote is not None:
            if triple_quote and source.startswith(quote * 3, index):
                states[index : index + 3] = [_STRING, _STRING, _STRING]
                quote = None
                triple_quote = False
                index += 3
                continue
            if character == "\\" and not triple_quote and index + 1 < len(source):
                states[index] = _STRING
                index += 1
                states[index] = _STRING
            elif character == quote and not triple_quote:
                states[index] = _STRING
                quote = None
            else:
                states[index] = _STRING
            index += 1
            continue
        if language == "python" and character == "#":
            while index < len(source) and source[index] != "\n":
                states[index] = _COMMENT
                index += 1
            continue
        if language != "python" and character == "/" and following == "/":
            while index < len(source) and source[index] != "\n":
                states[index] = _COMMENT
                index += 1
            continue
        if language != "python" and character == "/" and following == "*":
            states[index] = states[index + 1] = _COMMENT
            index += 2
            while index < len(source) and not (source[index] == "*" and index + 1 < len(source) and source[index + 1] == "/"):
                states[index] = _COMMENT
                index += 1
            if index + 1 < len(source):
                states[index] = states[index + 1] = _COMMENT
                index += 2
            continue
        if language == "python" and character in {"'", '"'} and source.startswith(character * 3, index):
            quote = character
            triple_quote = True
            states[index : index + 3] = [_STRING, _STRING, _STRING]
            index += 3
            continue
        if character in {"'", '"'} or (language != "python" and character == "`"):
            quote = character
            states[index] = _STRING
        index += 1
    return "".join(states)


def _mask_non_code(source: str, states: str) -> str:
    return "".join(character if state == _CODE else "\n" if character == "\n" else " " for character, state in zip(source, states, strict=True))


def _scan_imports(source: str, states: str, language: str) -> tuple[_Import, ...]:
    imports: list[_Import] = []
    if language == "python":
        pattern = r"(?m)^\s*(from)\s+(\.+(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)?|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+(import)\s+([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?"
        for match in re.finditer(pattern, source):
            if _state_is(states, match.start(1), match.end(1), _CODE) and _state_is(states, match.start(2), match.end(2), _CODE) and _state_is(states, match.start(3), match.end(3), _CODE):
                imports.append(_Import(match.group(5) or match.group(4), match.group(2), match.group(4)))
        for match in re.finditer(r"(?m)^\s*(import)\s+([A-Za-z_][\w.]*)(?:\s+as\s+([A-Za-z_]\w*))?", source):
            if _state_is(states, match.start(1), match.end(1), _CODE) and _state_is(states, match.start(2), match.end(2), _CODE):
                module = match.group(2)
                imports.append(_Import(match.group(3) or module.rsplit(".", 1)[-1], module, None))
    elif language == "go":
        scalar = r'(?m)^\s*(import)\s+(?:([A-Za-z_]\w*)\s+)?(?P<literal>"[^"\n]+")'
        for match in re.finditer(scalar, source):
            if _state_is(states, match.start(1), match.end(1), _CODE) and _state_is(states, match.start("literal"), match.end("literal"), _STRING):
                module = match.group("literal")[1:-1]
                imports.append(_Import(match.group(2) or module.rsplit("/", 1)[-1], module, None))
        for block in re.finditer(r"(?ms)^\s*(import)\s*\((?P<body>.*?)^\s*\)", source):
            if not _state_is(states, block.start(1), block.end(1), _CODE):
                continue
            body_start = block.start("body")
            for match in re.finditer(r'(?m)^\s*(?:([A-Za-z_]\w*)\s+)?(?P<literal>"[^"\n]+")', block.group("body")):
                start = body_start + match.start("literal")
                end = body_start + match.end("literal")
                if _state_is(states, start, end, _STRING):
                    module = match.group("literal")[1:-1]
                    imports.append(_Import(match.group(1) or module.rsplit("/", 1)[-1], module, None))
    elif language == "typescript":
        named = r'(?m)^\s*(import)\s*{([^}]+)}\s*(from)\s*(?P<literal>["\'][^"\']+["\'])'
        for match in re.finditer(named, source):
            if _state_is(states, match.start(1), match.end(1), _CODE) and _state_is(states, match.start(3), match.end(3), _CODE) and _state_is(states, match.start("literal"), match.end("literal"), _STRING):
                module = match.group("literal")[1:-1]
                for part in match.group(2).split(","):
                    names = re.match(r"\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?", part)
                    if names:
                        imports.append(_Import(names.group(2) or names.group(1), module, names.group(1)))
        default = r'(?m)^\s*(import)\s+([A-Za-z_$][\w$]*)\s+(from)\s*(?P<literal>["\'][^"\']+["\'])'
        for match in re.finditer(default, source):
            if _state_is(states, match.start(1), match.end(1), _CODE) and _state_is(states, match.start(3), match.end(3), _CODE) and _state_is(states, match.start("literal"), match.end("literal"), _STRING):
                imports.append(_Import(match.group(2), match.group("literal")[1:-1], None))
    return tuple(imports)


def _state_is(states: str, start: int, end: int, state: str) -> bool:
    return start < end and end <= len(states) and all(value == state for value in states[start:end])


def _calls(
    lines: list[str],
    start_line: int,
    parameters: frozenset[str] = frozenset(),
) -> tuple[_Call, ...]:
    calls: list[_Call] = []
    for offset, line in enumerate(lines):
        if "(" not in line:
            continue
        opening_stack: list[int] = []
        closing_by_opening: dict[int, int] = {}
        for index, character in enumerate(line):
            if character == "(":
                opening_stack.append(index)
            elif character == ")" and opening_stack:
                closing_by_opening[opening_stack.pop()] = index
        for match in re.finditer(r"\b((?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*)\s*\(", line):
            declaration_prefix = line[: match.start()].rstrip()
            if re.search(r"(?:^|\s)(?:def|func|function)\s*$", declaration_prefix):
                continue
            parts = [part.strip().lower() for part in match.group(1).split(".")]
            if parts[-1] in {"def", "func", "function", "if", "for", "while", "switch", "catch"}:
                continue
            opening = match.end() - 1
            closing = closing_by_opening.get(opening, len(line))
            arguments = line[match.end() : closing]
            qualifier = parts[-2] if len(parts) > 1 else None
            identifiers = frozenset(
                value.lower()
                for value in re.findall(r"\b[A-Za-z_$][\w$]*\b", arguments)
            )
            calls.append(
                _Call(
                    parts[-1],
                    qualifier,
                    start_line + offset,
                    arguments,
                    bool(parameters & identifiers)
                    or bool(parameters.intersection(parts[:-1])),
                    len(identifiers),
                )
            )
    return tuple(calls)


def _member_mutations(
    lines: list[str],
    start_line: int,
    parameters: frozenset[str] = frozenset(),
) -> tuple[_Mutation, ...]:
    pattern = re.compile(
        r"(?P<target>\b[A-Za-z_$][\w$]*(?:(?:\s*\.\s*[A-Za-z_$][\w$]*)|(?:\s*\[[^\]\n]{1,256}\]))+)"
        r"\s*(?:\?\?=|\|\|=|&&=|<<=|>>=|\*\*=|[+\-*/%&|^]?=(?!=|>))"
    )
    mutations: list[_Mutation] = []
    for offset, line in enumerate(lines):
        for match in pattern.finditer(line):
            members = re.findall(r"\.\s*([A-Za-z_$][\w$]*)", match.group("target"))
            signature = members[-1].lower() if members else "computed-member"
            target_root = re.match(r"[A-Za-z_$][\w$]*", match.group("target"))
            right_hand_side = line[match.end() :].split(";", 1)[0]
            identifiers = frozenset(
                value.lower()
                for value in re.findall(r"\b[A-Za-z_$][\w$]*\b", right_hand_side)
            )
            parameter_flow = bool(parameters & identifiers) or (
                target_root is not None
                and target_root.group(0).lower() in parameters
            )
            mutations.append(
                _Mutation(start_line + offset, signature, parameter_flow)
            )
    return tuple(mutations)


def _assignments(
    lines: list[str],
    start_line: int,
    parameters: frozenset[str],
) -> tuple[_Assignment, ...]:
    pattern = re.compile(
        r"(?:^|[;{}])\s*(?:(?:const|let|var)\s+)?"
        r"(?P<target>[A-Za-z_$][\w$]*)"
        r"(?:\s*:[^=;\n]{1,128})?\s*"
        r"(?P<operator>\?\?=|\|\|=|&&=|<<=|>>=|\*\*=|:=|[+\-*/%&|^]?=(?!=|>))"
    )
    assignments: list[_Assignment] = []
    for offset, line in enumerate(lines):
        for match in pattern.finditer(line):
            target = match.group("target").lower()
            right_hand_side = line[match.end() :].split(";", 1)[0]
            identifiers = frozenset(
                value.lower()
                for value in re.findall(r"\b[A-Za-z_$][\w$]*\b", right_hand_side)
            )
            parameter_flow = bool(parameters & identifiers)
            if match.group("operator") not in {"=", ":="} and target in parameters:
                parameter_flow = True
            assignments.append(
                _Assignment(
                    start_line + offset,
                    target,
                    parameter_flow,
                )
            )
    return tuple(assignments)


def _declaration_parameters(
    lines: list[str],
    language: str,
) -> frozenset[str]:
    if language == "generic":
        return frozenset()
    header = "\n".join(lines[:8])
    noise = {
        "any",
        "async",
        "bool",
        "boolean",
        "const",
        "def",
        "export",
        "float",
        "func",
        "function",
        "int",
        "interface",
        "let",
        "number",
        "object",
        "private",
        "protected",
        "public",
        "self",
        "static",
        "str",
        "string",
        "this",
        "var",
        "void",
    }
    groups: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(header):
        if depth == 0 and character == "{":
            break
        if depth == 0 and character == ":" and groups:
            break
        if character == "(":
            if depth == 0:
                start = index + 1
            depth += 1
        elif character == ")" and depth:
            depth -= 1
            if depth == 0:
                groups.append(header[start:index])
    if language == "python" and not groups:
        match = re.search(r"\blambda\s+([^:\n]+):", header)
        if match:
            groups.append(match.group(1))
    parameters: set[str] = set()
    for group in groups:
        for segment in group.split(","):
            identifiers = [
                value.lower()
                for value in re.findall(r"\b[A-Za-z_$][\w$]*\b", segment)
                if value.lower() not in noise
            ]
            if not identifiers:
                continue
            if segment.lstrip().startswith(("{", "[")):
                parameters.update(identifiers)
            else:
                parameters.add(identifiers[0])
    return frozenset(parameters)


def _anchor_locations(
    path: str,
    symbol: str,
    start_line: int,
    lines: list[str],
    anchors: set[str],
) -> tuple[_Location, ...]:
    locations: list[_Location] = []
    pattern = re.compile(r"\b(" + "|".join(sorted(map(re.escape, anchors))) + r")\b", re.IGNORECASE)
    for offset, line in enumerate(lines):
        match = pattern.search(line)
        if match:
            locations.append(_Location(path, start_line + offset, symbol))
    return tuple(locations)


def _operation_callees(line: str, anchors: set[str]) -> tuple[str, ...]:
    callees: list[str] = []
    for candidate in re.finditer(r"(?:[A-Za-z_$][\w$]*(?:\s*/\s*[A-Za-z_$][\w$]*)?\s*\.\s*)*[A-Za-z_$][\w$]*", line):
        normalized = re.sub(r"\s+", "", candidate.group()).lower()
        segments = normalized.replace("/", ".").split(".")
        preserved = ".".join(segments[-2:])
        if normalized in anchors or preserved in anchors:
            callees.append(preserved)
    return tuple(dict.fromkeys(callees))


def _resolve_exact_call(
    declaration: _Declaration,
    call: _Call,
    by_file_symbol: dict[tuple[str, str], list[_Declaration]],
    by_language_symbol: dict[tuple[str, str], list[_Declaration]],
    module_targets: _ModuleTargetIndex | None = None,
) -> tuple[tuple[str, int, str], str] | None:
    direct = _unique_same_file_call_target(declaration, call, by_file_symbol)
    if direct is not None:
        return (_location_identity(direct.location), "direct")
    imported = _unique_import_call_target(declaration, call, by_language_symbol, module_targets)
    if imported is not None:
        return (_location_identity(imported.location), "import-linked")
    return None


def _unique_same_file_call_target(
    declaration: _Declaration,
    call: _Call,
    by_file_symbol: dict[tuple[str, str], list[_Declaration]],
) -> _Declaration | None:
    selected: _Declaration | None = None
    for candidate in by_file_symbol.get((declaration.location.path, call.name), ()):
        if not _same_file_call_target(declaration, call, candidate):
            continue
        if selected is not None and selected != candidate:
            return None
        selected = candidate
    return selected


def _unique_import_call_target(
    declaration: _Declaration,
    call: _Call,
    by_language_symbol: dict[tuple[str, str], list[_Declaration]],
    module_targets: _ModuleTargetIndex | None = None,
) -> _Declaration | None:
    selected: _Declaration | None = None
    seen_imports: set[tuple[str, str | None]] = set()
    for imported in declaration.imports:
        if not (
            call.qualifier == imported.local_name.lower()
            or (call.qualifier is None and call.name == imported.local_name.lower())
        ):
            continue
        import_key = (imported.module, imported.symbol)
        if import_key in seen_imports:
            continue
        seen_imports.add(import_key)
        symbol = imported.symbol or call.name
        if module_targets is not None:
            candidates = (
                candidate
                for module_key in _module_lookup_keys(
                    declaration.location.path,
                    imported.module,
                    declaration.language,
                    imported.symbol,
                )
                for candidate in module_targets.get((declaration.language, symbol, module_key), ())
            )
        else:
            candidates = by_language_symbol.get((declaration.language, symbol), ())
        for candidate in candidates:
            if module_targets is None and not _module_matches(
                declaration.location.path,
                imported.module,
                candidate.location.path,
                declaration.language,
                imported.symbol,
            ):
                continue
            if selected is not None and selected != candidate:
                return None
            selected = candidate
    return selected


def _allocate_schema_three_references(
    declarations: tuple[_Declaration, ...],
    limit: int,
    by_file_symbol: dict[tuple[str, str], list[_Declaration]],
    by_language_symbol: dict[tuple[str, str], list[_Declaration]],
    module_targets: _ModuleTargetIndex | None = None,
) -> tuple[
    tuple[_Declaration, ...],
    dict[tuple[str, int, str], tuple[tuple[tuple[str, int, str], str], ...]],
    dict[tuple[str, int, str], tuple[_Call, ...]],
]:
    retained = [deque() for _ in declarations]
    strong: dict[tuple[str, int, str], list[tuple[tuple[str, int, str], str]]] = {}
    weak: dict[tuple[str, int, str], list[_Call]] = {}
    remaining = max(0, limit)
    strong_positions = [0] * len(declarations)
    seen_strong = [set() for _ in declarations]
    resolution_cache: list[
        dict[tuple[str, str | None], tuple[tuple[str, int, str], str] | None] | None
    ] = [None] * len(declarations)

    def resolve(index: int, call: _Call) -> tuple[tuple[str, int, str], str] | None:
        cache = resolution_cache[index]
        if cache is None:
            cache = {}
            resolution_cache[index] = cache
        key = (call.name, call.qualifier)
        if key not in cache:
            if module_targets is None:
                cache[key] = _resolve_exact_call(
                    declarations[index], call, by_file_symbol, by_language_symbol
                )
            else:
                cache[key] = _resolve_exact_call(
                    declarations[index], call, by_file_symbol, by_language_symbol, module_targets
                )
        return cache[key]

    def next_strong(index: int) -> tuple[_Call, tuple[tuple[str, int, str], str]] | None:
        declaration = declarations[index]
        while strong_positions[index] < len(declaration.calls):
            call = declaration.calls[strong_positions[index]]
            strong_positions[index] += 1
            edge = resolve(index, call)
            if edge is not None and edge not in seen_strong[index]:
                return call, edge
        return None

    strong_active = deque()
    if remaining:
        strong_active.extend(
            (index, candidate)
            for index in range(len(declarations))
            if (candidate := next_strong(index)) is not None
        )
    while remaining and strong_active:
        index, (call, edge) = strong_active.popleft()
        identity = _location_identity(declarations[index].location)
        seen_strong[index].add(edge)
        retained[index].append(call)
        strong.setdefault(identity, []).append(edge)
        remaining -= 1
        if remaining:
            candidate = next_strong(index)
            if candidate is not None:
                strong_active.append((index, candidate))

    weak_positions = [0] * len(declarations)
    seen_weak = [set() for _ in declarations]

    def next_weak(index: int) -> _Call | None:
        declaration = declarations[index]
        while weak_positions[index] < len(declaration.calls):
            call = declaration.calls[weak_positions[index]]
            weak_positions[index] += 1
            if (
                call.qualifier is not None
                or resolve(index, call) is not None
            ):
                continue
            key = (declaration.language, call.name)
            if key not in seen_weak[index]:
                return call
        return None

    weak_active = deque()
    if remaining:
        weak_active.extend(
            (index, call)
            for index in range(len(declarations))
            if (call := next_weak(index)) is not None
        )
    while remaining and weak_active:
        index, call = weak_active.popleft()
        declaration = declarations[index]
        identity = _location_identity(declaration.location)
        seen_weak[index].add((declaration.language, call.name))
        retained[index].append(call)
        weak.setdefault(identity, []).append(call)
        remaining -= 1
        if remaining:
            next_call = next_weak(index)
            if next_call is not None:
                weak_active.append((index, next_call))
    selected_declarations = tuple(
        replace(declaration, calls=tuple(retained[index]))
        for index, declaration in enumerate(declarations)
    )
    return (
        selected_declarations,
        {identity: tuple(edges) for identity, edges in strong.items()},
        {identity: tuple(calls) for identity, calls in weak.items()},
    )


def _allocate_schema_three_edges(
    strong_by_declaration: dict[
        tuple[str, int, str], tuple[tuple[tuple[str, int, str], str], ...]
    ],
    weak_by_declaration: dict[tuple[str, int, str], tuple[_Call, ...]],
    declarations: dict[tuple[str, int, str], _Declaration],
    by_language_symbol: dict[tuple[str, str], list[_Declaration]],
    limit: int,
) -> dict[tuple[str, int, str], tuple[tuple[tuple[str, int, str], str], ...]]:
    allocated: dict[tuple[str, int, str], list[tuple[tuple[str, int, str], str]]] = {}
    allocated_edges: dict[tuple[str, int, str], set[tuple[tuple[str, int, str], str]]] = {}
    remaining = max(0, limit)
    strong_active = deque(
        (identity, deque(edges))
        for identity, edges in strong_by_declaration.items()
        if edges
    )
    while remaining and strong_active:
        identity, queue = strong_active.popleft()
        edge = queue.popleft()
        seen = allocated_edges.setdefault(identity, set())
        if edge not in seen:
            seen.add(edge)
            allocated.setdefault(identity, []).append(edge)
            remaining -= 1
        if queue:
            strong_active.append((identity, queue))
    weak_active = deque(
        (identity, deque(calls), None)
        for identity, calls in weak_by_declaration.items()
        if calls
    )
    target_checks = remaining
    while remaining and target_checks and weak_active:
        identity, queue, iterator = weak_active.popleft()
        while target_checks:
            if iterator is None:
                if not queue:
                    break
                call = queue.popleft()
                iterator = iter(by_language_symbol.get((declarations[identity].language, call.name), ()))
            try:
                target = next(iterator)
            except StopIteration:
                iterator = None
                continue
            target_checks -= 1
            edge = (_location_identity(target.location), "name-only")
            seen = allocated_edges.setdefault(identity, set())
            if edge not in seen:
                seen.add(edge)
                allocated.setdefault(identity, []).append(edge)
                remaining -= 1
            weak_active.append((identity, queue, iterator))
            break
    return {
        identity: tuple(edges)
        for identity, edges in allocated.items()
        if edges
    }


def _build_schema_three_routes(
    declarations: tuple[_Declaration, ...],
    limits: GuidanceLimits,
) -> tuple[
    tuple[_Route, ...],
    int,
    dict[tuple[str, int, str], list[tuple[tuple[str, int, str], str]]],
    dict[tuple[str, int, str], _Declaration],
]:
    by_identity = {_location_identity(item.location): item for item in declarations}
    by_file_symbol: dict[tuple[str, str], list[_Declaration]] = {}
    by_language_symbol: dict[tuple[str, str], list[_Declaration]] = {}
    module_targets: dict[tuple[str, str, str], list[_Declaration]] = {}
    for item in declarations:
        by_file_symbol.setdefault((item.location.path, item.location.symbol.lower()), []).append(item)
        by_language_symbol.setdefault((item.language, item.location.symbol.lower()), []).append(item)
        module_targets.setdefault(
            (
                item.language,
                item.location.symbol.lower(),
                _module_target_key(item.location.path, item.language),
            ),
            [],
        ).append(item)
    selected_declarations, strong_by_declaration, weak_by_declaration = _allocate_schema_three_references(
        declarations,
        limits.edge_count,
        by_file_symbol,
        by_language_symbol,
        {key: tuple(values) for key, values in module_targets.items()},
    )
    selected_by_identity = {
        _location_identity(item.location): item for item in selected_declarations
    }
    outgoing = _allocate_schema_three_edges(
        strong_by_declaration,
        weak_by_declaration,
        selected_by_identity,
        by_language_symbol,
        limits.edge_count,
    )
    edge_count = sum(len(edges) for edges in outgoing.values())
    incoming: dict[tuple[str, int, str], list[tuple[tuple[str, int, str], str]]] = {
        identity: [] for identity in by_identity
    }
    for caller, edges in outgoing.items():
        for target, strength in edges:
            incoming[target].append((caller, strength))
    retained: dict[tuple[_Location, _Location], _Route] = {}
    forward_limit, reverse_quota = _route_direction_quotas(limits.route_count)
    forward_work = [forward_limit]
    for declaration in declarations:
        if not declaration.sources:
            continue
        identity = _location_identity(declaration.location)
        for source in declaration.sources:
            _traverse_routes(source, identity, by_identity, outgoing, limits, retained, forward_limit, forward_work)
            if len(retained) >= forward_limit:
                break
        if len(retained) >= forward_limit:
            break
    if reverse_quota:
        reverse_work = [reverse_quota]
        for declaration in declarations:
            identity = _location_identity(declaration.location)
            for family, operation in declaration.operations:
                if declaration.sources and all((source, operation) in retained for source in declaration.sources):
                    continue
                _traverse_reverse_routes(
                    family,
                    operation,
                    identity,
                    by_identity,
                    incoming,
                    reverse_work,
                    limits,
                    retained,
                    limits.route_count,
                )
                if len(retained) >= limits.route_count:
                    break
            if len(retained) >= limits.route_count:
                break
    return tuple(retained.values()), edge_count, incoming, selected_by_identity


def _build_routes(declarations: tuple[_Declaration, ...], limits: GuidanceLimits) -> tuple[tuple[_Route, ...], int]:
    by_identity = {(item.location.path, item.location.line, item.location.symbol): item for item in declarations}
    by_file_symbol: dict[tuple[str, str], list[_Declaration]] = {}
    by_language_symbol: dict[tuple[str, str], list[_Declaration]] = {}
    for item in declarations:
        by_file_symbol.setdefault((item.location.path, item.location.symbol.lower()), []).append(item)
        by_language_symbol.setdefault((item.language, item.location.symbol.lower()), []).append(item)
    outgoing: dict[tuple[str, int, str], tuple[tuple[tuple[str, int, str], str], ...]] = {}
    edge_count = 0
    for identity, declaration in by_identity.items():
        if edge_count >= limits.edge_count:
            break
        resolved = _resolve_calls(declaration, by_file_symbol, by_language_symbol)
        retained_edges = resolved[: max(0, limits.edge_count - edge_count)]
        outgoing[identity] = retained_edges
        edge_count += len(retained_edges)
    incoming: dict[tuple[str, int, str], list[tuple[tuple[str, int, str], str]]] = {
        identity: [] for identity in by_identity
    }
    for caller, edges in outgoing.items():
        for target, strength in edges:
            incoming[target].append((caller, strength))
    retained: dict[tuple[_Location, _Location], _Route] = {}
    forward_limit, reverse_quota = _route_direction_quotas(limits.route_count)
    forward_work = [forward_limit]
    for declaration in declarations:
        if not declaration.sources:
            continue
        identity = _location_identity(declaration.location)
        for source in declaration.sources:
            _traverse_routes(source, identity, by_identity, outgoing, limits, retained, forward_limit, forward_work)
            if len(retained) >= forward_limit:
                break
        if len(retained) >= forward_limit:
            break
    if reverse_quota:
        reverse_work = [reverse_quota]
        for declaration in declarations:
            identity = _location_identity(declaration.location)
            for family, operation in declaration.operations:
                if declaration.sources and all((source, operation) in retained for source in declaration.sources):
                    continue
                _traverse_reverse_routes(
                    family,
                    operation,
                    identity,
                    by_identity,
                    incoming,
                    reverse_work,
                    limits,
                    retained,
                    limits.route_count,
                )
                if len(retained) >= limits.route_count:
                    break
            if len(retained) >= limits.route_count:
                break
    return tuple(retained.values()), edge_count


def _structural_sites(
    declarations: tuple[_Declaration, ...],
    components_by_path: dict[str, str],
    site_limit: int | None = None,
) -> tuple[_StructuralSite, ...]:
    retained: dict[tuple[str, int, str, str], _StructuralSite] = {}

    def retain(site: _StructuralSite) -> None:
        identity = (site.path, site.line, site.family, site.signature)
        if identity in retained:
            return
        if site_limit is None or len(retained) < site_limit:
            retained[identity] = site

    for declaration in declarations:
        try:
            component = components_by_path[declaration.location.path]
        except KeyError as error:
            raise SemanticGuidanceError(
                "operation index has no component"
            ) from error
        recognized = {
            (operation.line, operation.symbol.rsplit(".", 1)[-1].lower())
            for _, operation in declaration.operations
        }
        for call in declaration.calls:
            if call.qualifier is None or (call.line, call.name.lower()) in recognized:
                continue
            site = _StructuralSite(
                component,
                declaration.location.path,
                call.line,
                "call",
                call.name.lower(),
                call.parameter_flow,
                call.argument_identifier_count,
                declaration.location,
                declaration.sources,
            )
            retain(site)
        for mutation in declaration.mutations:
            if (mutation.line, mutation.signature) in recognized:
                continue
            site = _StructuralSite(
                component,
                declaration.location.path,
                mutation.line,
                "mutation",
                mutation.signature,
                mutation.parameter_flow,
                0,
                declaration.location,
                declaration.sources,
            )
            retain(site)
        for assignment in declaration.assignments:
            if (
                (assignment.line, assignment.signature) in recognized
                or not assignment.parameter_flow
            ):
                continue
            site = _StructuralSite(
                component,
                declaration.location.path,
                assignment.line,
                "assignment",
                assignment.signature,
                True,
                0,
                declaration.location,
                declaration.sources,
            )
            retain(site)
    return tuple(
        sorted(
            retained.values(),
            key=lambda site: (
                site.component,
                site.path,
                site.line,
                site.family,
                site.signature,
            ),
        )
    )


def _operation_index_rows(
    sites: tuple[_StructuralSite, ...],
    passes_by_path: dict[str, tuple[str, ...]],
    limits: GuidanceLimits,
) -> tuple[dict[str, object], ...]:
    if not sites:
        return ()
    frequencies = Counter((site.family, site.signature) for site in sites)
    frontier_order = {path: index for index, path in enumerate(passes_by_path)}
    signature_occurrences: dict[
        tuple[str, str, bool],
        list[_StructuralSite],
    ] = {}
    for site in sites:
        signature_occurrences.setdefault(
            (site.family, site.signature, site.parameter_flow),
            [],
        ).append(site)
    occurrence_by_site: dict[tuple[str, str, int, str, str, bool], int] = {}
    for occurrences in signature_occurrences.values():
        for index, site in enumerate(
            sorted(
                occurrences,
                key=lambda item: (
                    frontier_order.get(item.path, len(frontier_order)),
                    item.component,
                    item.path,
                    item.line,
                ),
            )
        ):
            occurrence_by_site[
                (
                    site.component,
                    site.path,
                    site.line,
                    site.family,
                    site.signature,
                    site.parameter_flow,
                )
            ] = index
    grouped: dict[str, dict[str, list[_StructuralSite]]] = {}
    for site in sites:
        grouped.setdefault(site.component, {}).setdefault(site.path, []).append(site)
    rows_by_component: dict[
        str,
        deque[tuple[tuple[int, int, int, int, int, int], dict[str, object]]],
    ] = {}
    maximum_row_bytes = min(MAX_OPERATION_INDEX_ROW_BYTES, limits.output_bytes)
    for component, paths in grouped.items():
        prioritized_entries: list[
            tuple[tuple[int, int, int, int, int, int], int, int, int, str, int, dict[str, object]]
        ] = []
        for path, path_sites in paths.items():
            try:
                eligible = "".join(
                    OPERATION_INDEX_PASS_CODES[value]
                    for value in passes_by_path[path]
                )
            except KeyError as error:
                raise SemanticGuidanceError(
                    "operation index is absent from frontier passes"
                ) from error
            sites_by_line: dict[int, set[str]] = {}
            priority_by_line: dict[int, tuple[int, int, int, int, int, int]] = {}
            for site in path_sites:
                sites_by_line.setdefault(site.line, set()).add(
                    OPERATION_INDEX_FAMILY_CODES[site.family]
                )
                signature_priority = _operation_index_signature_priority(
                    frequencies[(site.family, site.signature)]
                )
                priority = (
                    signature_priority[0],
                    0 if site.parameter_flow else 1,
                    0
                    if site.family == "call"
                    and site.argument_identifier_count
                    >= MIN_OPERATION_INDEX_COMPLEX_CALL_IDENTIFIERS
                    else 1,
                    OPERATION_INDEX_FAMILY_PRIORITY[site.family],
                    occurrence_by_site[
                        (
                            site.component,
                            site.path,
                            site.line,
                            site.family,
                            site.signature,
                            site.parameter_flow,
                        )
                    ],
                    signature_priority[1],
                )
                priority_by_line[site.line] = min(
                    priority,
                    priority_by_line.get(site.line, priority),
                )
            lines_by_priority_tier: dict[tuple[int, int], list[int]] = {}
            for line, priority in priority_by_line.items():
                lines_by_priority_tier.setdefault(priority[:2], []).append(line)

            def entry_for(lines: list[int]) -> dict[str, object]:
                return {
                    "p": path,
                    "q": eligible,
                    "s": [
                        f"{line}{''.join(sorted(sites_by_line[line]))}"
                        for line in sorted(lines)
                    ],
                }

            def bounded_entries(lines: list[int]) -> list[dict[str, object]]:
                entry = entry_for(lines)
                if len(
                    _encode_canonical_row(
                        _canonical_operation_index_row(component, [entry])
                    )
                ) <= maximum_row_bytes:
                    return [entry]
                if len(lines) == 1:
                    return []
                midpoint = len(lines) // 2
                return [
                    *bounded_entries(lines[:midpoint]),
                    *bounded_entries(lines[midpoint:]),
                ]

            for priority_tier in sorted(lines_by_priority_tier):
                prioritized = sorted(
                    lines_by_priority_tier[priority_tier],
                    key=lambda line: (priority_by_line[line], line),
                )
                for offset in range(
                    0,
                    len(prioritized),
                    MAX_OPERATION_INDEX_SITES_PER_ENTRY,
                ):
                    chunk_index = offset // MAX_OPERATION_INDEX_SITES_PER_ENTRY
                    entries = bounded_entries(
                        prioritized[offset : offset + MAX_OPERATION_INDEX_SITES_PER_ENTRY]
                    )
                    for split_index, entry in enumerate(entries):
                        priority = min(
                            priority_by_line[line]
                            for line in prioritized[
                                offset : offset + MAX_OPERATION_INDEX_SITES_PER_ENTRY
                            ]
                        )
                        prioritized_entries.append(
                            (
                                priority,
                                chunk_index,
                                len(sites_by_line),
                                frontier_order[path],
                                path,
                                split_index,
                                entry,
                            )
                        )
        ordered_entries = [
            (item[0], item[-1])
            for item in sorted(prioritized_entries, key=lambda item: item[:-1])
        ]
        component_rows: deque[
            tuple[tuple[int, int, int, int, int, int], dict[str, object]]
        ] = deque()
        current: list[
            tuple[tuple[int, int, int, int, int, int], dict[str, object]]
        ] = []
        for priority, entry in ordered_entries:
            if current and priority[:2] != current[0][0][:2]:
                component_rows.append(
                    (
                        current[0][0],
                        _canonical_operation_index_row(
                            component,
                            [item[1] for item in current],
                        ),
                    )
                )
                current = [(priority, entry)]
                continue
            candidate = _canonical_operation_index_row(
                component,
                [item[1] for item in current] + [entry],
            )
            encoded = _encode_canonical_row(candidate)
            if current and len(encoded) > maximum_row_bytes:
                component_rows.append(
                    (
                        current[0][0],
                        _canonical_operation_index_row(
                            component,
                            [item[1] for item in current],
                        ),
                    )
                )
                current = [(priority, entry)]
            else:
                current.append((priority, entry))
        if current:
            component_rows.append(
                (
                    current[0][0],
                    _canonical_operation_index_row(
                        component,
                        [item[1] for item in current],
                    ),
                )
            )
        rows_by_component[component] = component_rows
    ordered_rows: list[
        tuple[int, int, int, int, int, int, int, str, dict[str, object]]
    ] = []
    for component, queue in rows_by_component.items():
        lane_positions: dict[tuple[int, int], int] = {}
        for priority, row in queue:
            lane = priority[:2]
            lane_position = lane_positions.get(lane, 0)
            lane_positions[lane] = lane_position + 1
            cycle_size = OPERATION_INDEX_PARAMETER_FLOW_WEIGHT + 1
            if priority[1] == 0:
                scheduled_position = (
                    lane_position // OPERATION_INDEX_PARAMETER_FLOW_WEIGHT
                ) * cycle_size + lane_position % OPERATION_INDEX_PARAMETER_FLOW_WEIGHT
            else:
                scheduled_position = lane_position * cycle_size + OPERATION_INDEX_PARAMETER_FLOW_WEIGHT
            ordered_rows.append(
                (
                    priority[0],
                    scheduled_position,
                    priority[1],
                    priority[2],
                    priority[3],
                    priority[4],
                    priority[5],
                    component,
                    row,
                )
            )
    priority_order = tuple(
        (item[:7], item[-1])
        for item in sorted(ordered_rows, key=lambda item: item[:-1])
    )
    return _operation_index_density_order(priority_order)


def _operation_index_density_order(
    prioritized_rows: tuple[
        tuple[tuple[int, int, int, int, int, int, int], dict[str, object]],
        ...,
    ],
) -> tuple[dict[str, object], ...]:
    def density(row: dict[str, object]) -> Fraction:
        site_count = sum(
            len(entry["s"])
            for entry in row["entries"]
            if isinstance(entry, dict) and isinstance(entry.get("s"), list)
        )
        return Fraction(site_count, len(_encode_canonical_row(row)))

    slot_lanes: list[tuple[int, int, int, int, int, int]] = []
    rows_by_lane: dict[
        tuple[int, int, int, int, int, int],
        list[tuple[Fraction, dict[str, object]]],
    ] = {}
    for priority, row in prioritized_rows:
        lane = (priority[0], *priority[2:])
        slot_lanes.append(lane)
        rows_by_lane.setdefault(lane, []).append((density(row), row))

    ordered_by_lane: dict[
        tuple[int, int, int, int, int, int],
        deque[dict[str, object]],
    ] = {}
    for lane, lane_rows in rows_by_lane.items():
        pending = iter(lane_rows)
        window = list(
            item
            for _, item in zip(range(OPERATION_INDEX_DENSITY_LOOKAHEAD), pending)
        )
        ordered: deque[dict[str, object]] = deque()
        while window:
            selected_index = max(
                range(len(window)),
                key=lambda index: (window[index][0], -index),
            )
            _, row = window.pop(selected_index)
            ordered.append(row)
            next_row = next(pending, None)
            if next_row is not None:
                window.append(next_row)
        ordered_by_lane[lane] = ordered
    return tuple(ordered_by_lane[lane].popleft() for lane in slot_lanes)


def _operation_index_signature_priority(frequency: int) -> tuple[int, int]:
    if 2 <= frequency <= MAX_OPERATION_INDEX_PREFERRED_REUSED_SIGNATURE_FREQUENCY:
        return (0, 0)
    if frequency == 1:
        return (1, 0)
    if frequency <= MAX_OPERATION_INDEX_REUSED_SIGNATURE_FREQUENCY:
        return (2, frequency)
    return (3, frequency)


def _canonical_operation_index_row(
    component: str,
    entries: list[dict[str, object]],
) -> dict[str, object]:
    identity = json.dumps(
        [component, entries],
        sort_keys=True,
        separators=(",", ":"),
    )
    row: dict[str, object] = {
        "schema_version": SEMANTIC_GUIDANCE_SCHEMA_VERSION,
        "hint_id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
        "hint_kind": "operation-index",
        "component": component,
        "entries": entries,
        "reason_codes": ["operation_context", "structural_index"],
        "proof_status": "investigation_only",
    }
    _validate_operation_index_row(row)
    return row


def _encode_canonical_row(row: dict[str, object]) -> bytes:
    return json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _validate_operation_index_row(row: dict[str, object]) -> None:
    if (
        set(row)
        != {
            "schema_version",
            "hint_id",
            "hint_kind",
            "component",
            "entries",
            "reason_codes",
            "proof_status",
        }
        or row.get("schema_version") != SEMANTIC_GUIDANCE_SCHEMA_VERSION
        or not isinstance(row.get("hint_id"), str)
        or not re.fullmatch(r"[0-9a-f]{16}", row["hint_id"])
        or row.get("hint_kind") != "operation-index"
        or not isinstance(row.get("component"), str)
        or not row["component"]
        or "\x00" in row["component"]
        or row.get("reason_codes") != ["operation_context", "structural_index"]
        or row.get("proof_status") != "investigation_only"
        or not isinstance(row.get("entries"), list)
        or not row["entries"]
    ):
        raise SemanticGuidanceError("semantic guidance operation index is invalid")
    for entry in row["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"p", "q", "s"}:
            raise SemanticGuidanceError("semantic guidance operation index is invalid")
        path = entry["p"]
        eligible = entry["q"]
        sites = entry["s"]
        if (
            not isinstance(path, str)
            or _canonical_relative_path(path) != path
            or not isinstance(eligible, str)
            or not eligible
            or eligible
            != "".join(
                code
                for code in OPERATION_INDEX_PASS_CODES.values()
                if code in eligible
            )
            or len(eligible) != len(set(eligible))
            or not isinstance(sites, list)
            or not 1 <= len(sites) <= MAX_OPERATION_INDEX_SITES_PER_ENTRY
        ):
            raise SemanticGuidanceError("semantic guidance operation index is invalid")
        identities: list[tuple[int, str]] = []
        for site in sites:
            if not isinstance(site, str) or not re.fullmatch(r"[1-9]\d*[acm]{1,3}", site):
                raise SemanticGuidanceError("semantic guidance operation index is invalid")
            match = re.fullmatch(r"([1-9]\d*)([acm]{1,3})", site)
            if match is None or match.group(2) != "".join(sorted(set(match.group(2)))):
                raise SemanticGuidanceError("semantic guidance operation index is invalid")
            identities.append((int(match.group(1)), match.group(2)))
        if identities != sorted(identities) or len(identities) != len(set(identities)):
            raise SemanticGuidanceError("semantic guidance operation index is invalid")


def _nested_output_routes(
    observations: tuple[tuple[str, object], ...],
    incoming: dict[tuple[str, int, str], list[tuple[tuple[str, int, str], str]]] | None = None,
    declarations: dict[tuple[str, int, str], _Declaration] | None = None,
) -> tuple[_Route, ...]:
    routes: list[_Route] = []
    for path, observation in observations:
        declaration_line = getattr(observation, "declaration_line")
        declaration_symbol = getattr(observation, "declaration_symbol")
        source_line = getattr(observation, "source_line")
        source_symbol = getattr(observation, "source_symbol")
        operation_line = getattr(observation, "operation_line")
        control_lines = getattr(observation, "control_lines")
        reason_codes = getattr(observation, "reason_codes")
        context = getattr(observation, "context")
        declaration = _Location(path, declaration_line, declaration_symbol)
        trace = (declaration,)
        if incoming is not None and declarations is not None:
            candidates = [
                declarations[caller]
                for caller, strength in incoming.get(_location_identity(declaration), ())
                if strength == "import-linked"
                and _caller_passes_source_derived_argument(declarations[caller], declaration)
            ]
            if candidates:
                caller = min(candidates, key=lambda item: _location_identity(item.location))
                trace = (caller.location, declaration)
                reason_codes = tuple(dict.fromkeys((*reason_codes, "explicit_import")))
        routes.append(
            _Route(
                "direct",
                "output-context",
                _Location(path, source_line, source_symbol),
                _Location(path, operation_line, "nested-output-context"),
                trace,
                tuple(_Location(path, line, "outer-html-sanitizer") for line in control_lines),
                reason_codes,
                "nested-output-context",
                context,
            )
        )
    return tuple(routes)


def _caller_passes_source_derived_argument(caller: _Declaration, target: _Location) -> bool:
    pattern = re.compile(r"\b(?:" + "|".join(sorted(map(re.escape, SOURCE_ANCHORS))) + r")\b", re.IGNORECASE)
    return any(
        call.name == target.symbol.lower() and pattern.search(call.arguments)
        for call in caller.calls
    )


def _route_direction_quotas(route_count: int) -> tuple[int, int]:
    return ((route_count + 1) // 2, route_count // 2)


def _traverse_routes(
    source: _Location,
    root_identity: tuple[str, int, str],
    declarations: dict[tuple[str, int, str], _Declaration],
    outgoing: dict[tuple[str, int, str], tuple[tuple[tuple[str, int, str], str], ...]],
    limits: GuidanceLimits,
    retained: dict[tuple[_Location, _Location], _Route],
    route_limit: int,
    work_budget: list[int],
) -> None:
    queue = deque([
        (root_identity, (declarations[root_identity].location,), "direct", 0)
    ])
    while queue and len(retained) < route_limit and work_budget[0] > 0:
        identity, trace, strength, depth = queue.popleft()
        work_budget[0] -= 1
        declaration = declarations[identity]
        for family, operation in declaration.operations:
            route_strength = "name-only" if declaration.language == "generic" else strength
            candidate = _Route(
                route_strength,
                family,
                source,
                operation,
                trace,
                _trace_controls(trace, declarations),
                _reason_codes(route_strength, len(trace)),
            )
            endpoint = (source, operation)
            current = retained.get(endpoint)
            if current is None or _route_sort_key(candidate) < _route_sort_key(current):
                retained[endpoint] = candidate
            if len(retained) >= route_limit:
                break
        if len(retained) >= route_limit:
            continue
        if depth >= limits.graph_depth or len(trace) >= 12:
            continue
        for target_identity, edge_strength in outgoing.get(identity, ()):
            if work_budget[0] <= len(queue):
                break
            target = declarations[target_identity]
            if target.location in trace:
                continue
            next_strength = _combined_strength(strength, edge_strength)
            queue.append((target_identity, (*trace, target.location), next_strength, depth + 1))


def _traverse_reverse_routes(
    family: str,
    operation: _Location,
    root_identity: tuple[str, int, str],
    declarations: dict[tuple[str, int, str], _Declaration],
    incoming: dict[tuple[str, int, str], list[tuple[tuple[str, int, str], str]]],
    work_budget: list[int],
    limits: GuidanceLimits,
    retained: dict[tuple[_Location, _Location], _Route],
    route_limit: int,
) -> None:
    queue = deque([
        (root_identity, (declarations[root_identity].location,), "direct", 0)
    ])
    while queue and len(retained) < route_limit and work_budget[0] > 0:
        identity, reverse_trace, strength, depth = queue.popleft()
        work_budget[0] -= 1
        declaration = declarations[identity]
        trace = tuple(reversed(reverse_trace))
        for source in declaration.sources:
            route_strength = "name-only" if declaration.language == "generic" else strength
            candidate = _Route(
                route_strength,
                family,
                source,
                operation,
                trace,
                _trace_controls(trace, declarations),
                _reason_codes(route_strength, len(trace)),
            )
            endpoint = (source, operation)
            current = retained.get(endpoint)
            if current is None or _route_sort_key(candidate) < _route_sort_key(current):
                retained[endpoint] = candidate
        if depth >= limits.graph_depth or len(reverse_trace) >= 12:
            continue
        for caller_identity, edge_strength in incoming[identity]:
            if work_budget[0] <= len(queue):
                break
            caller = declarations[caller_identity]
            if caller.location in reverse_trace:
                continue
            queue.append(
                (
                    caller_identity,
                    (*reverse_trace, caller.location),
                    _combined_strength(strength, edge_strength),
                    depth + 1,
                )
            )


def _resolve_calls(
    declaration: _Declaration,
    by_file_symbol: dict[tuple[str, str], list[_Declaration]],
    by_language_symbol: dict[tuple[str, str], list[_Declaration]],
) -> tuple[tuple[tuple[str, int, str], str], ...]:
    resolved: list[tuple[tuple[str, int, str], str]] = []
    for call in declaration.calls:
        same_file = [item for item in by_file_symbol.get((declaration.location.path, call.name), ()) if _same_file_call_target(declaration, call, item)]
        if len(same_file) == 1:
            resolved.append((_location_identity(same_file[0].location), "direct"))
            continue
        imports = [
            item
            for item in declaration.imports
            if (call.qualifier == item.local_name.lower()) or (call.qualifier is None and call.name == item.local_name.lower())
        ]
        imported = _resolve_import_targets(declaration, call, imports, by_language_symbol)
        if len(imported) == 1:
            resolved.append((_location_identity(imported[0].location), "import-linked"))
            continue
        global_matches = by_language_symbol.get((declaration.language, call.name), ()) if call.qualifier is None else ()
        for target in global_matches:
            resolved.append((_location_identity(target.location), "name-only"))
    return tuple(dict.fromkeys(resolved))


def _same_file_call_target(caller: _Declaration, call: _Call, target: _Declaration) -> bool:
    if call.qualifier is None or call.qualifier in {"self", "this"}:
        return True
    return caller.language == "go" and target.language == "go" and target.receiver == call.qualifier


def _resolve_import_targets(
    declaration: _Declaration,
    call: _Call,
    imports: list[_Import],
    by_language_symbol: dict[tuple[str, str], list[_Declaration]],
) -> list[_Declaration]:
    targets: list[_Declaration] = []
    for imported in imports:
        symbol = imported.symbol or call.name
        targets.extend(
            item
            for item in by_language_symbol.get((declaration.language, symbol), ())
            if _module_matches(declaration.location.path, imported.module, item.location.path, declaration.language, imported.symbol)
        )
    return list(dict.fromkeys(targets))


def _module_matches(caller_path: str, module: str, target_path: str, language: str, imported_symbol: str | None) -> bool:
    return _module_target_key(target_path, language) in _module_lookup_keys(
        caller_path,
        module,
        language,
        imported_symbol,
    )


def _module_lookup_keys(
    caller_path: str,
    module: str,
    language: str,
    imported_symbol: str | None,
) -> tuple[str, ...]:
    caller_parent = PurePosixPath(caller_path).parent
    normalized = module.replace("\\", "/")
    if language == "python":
        leading_dots = len(normalized) - len(normalized.lstrip("."))
        if leading_dots:
            base = caller_parent
            for _ in range(leading_dots - 1):
                base = base.parent
            remainder = normalized[leading_dots:]
            normalized = (base / remainder.replace(".", "/")).as_posix()
        else:
            normalized = normalized.replace(".", "/")
    elif normalized.startswith("."):
        normalized = posixpath.normpath(f"{caller_parent.as_posix()}/{normalized}")
    if language == "python":
        candidates = [normalized, f"{normalized}/__init__"]
        if imported_symbol is not None:
            candidates.append(f"{normalized}/{imported_symbol}")
        return tuple(dict.fromkeys(candidates))
    if language == "typescript":
        return tuple(dict.fromkeys((normalized, f"{normalized}/index")))
    return (normalized,)


def _module_target_key(target_path: str, language: str) -> str:
    if language == "go":
        return PurePosixPath(target_path).parent.as_posix()
    target = PurePosixPath(target_path).as_posix()
    if target.endswith(".d.ts"):
        target = target[: -len(".d.ts")]
    else:
        target = PurePosixPath(target).with_suffix("").as_posix()
    return target


def _trace_controls(
    trace: tuple[_Location, ...],
    declarations: dict[tuple[str, int, str], _Declaration],
) -> tuple[_Location, ...]:
    controls: list[_Location] = []
    for location in trace:
        for control in declarations[_location_identity(location)].controls:
            if control not in controls:
                controls.append(control)
            if len(controls) == 8:
                return tuple(controls)
    return tuple(controls)


def _reason_codes(strength: str, trace_length: int) -> tuple[str, ...]:
    if strength == "direct":
        return ("source_anchor", "operation_anchor", "same_declaration")
    if strength == "import-linked":
        return ("source_anchor", "operation_anchor", "explicit_import")
    if trace_length == 1:
        return ("source_anchor", "operation_anchor", "generic_fallback")
    return ("source_anchor", "operation_anchor", "name_resolution")


def _combined_strength(current: str, edge: str) -> str:
    if current == "name-only" or edge == "name-only":
        return "name-only"
    return edge


def _location_identity(location: _Location) -> tuple[str, int, str]:
    return (location.path, location.line, location.symbol)


def _paired_flow_seeds(
    routes: tuple[_Route, ...],
    sites: tuple[_StructuralSite, ...],
    frontier_passes_by_path: dict[str, tuple[str, ...]],
    frontier_components_by_path: dict[str, str],
    profile: str,
) -> PairedFlowSeeds:
    row_limit, byte_limit, row_byte_limit = PAIRED_FLOW_SEED_LIMITS.get(
        profile,
        PAIRED_FLOW_SEED_LIMITS["hunt-balanced"],
    )
    lanes: dict[str, list[dict[str, object]]] = {
        "paired-route": [],
        "paired-source": [],
        "paired-parameter": [],
        "sink-only": [],
    }
    covered_sites: set[tuple[str, int, str, str]] = set()
    for route in routes:
        try:
            component = frontier_components_by_path[route.operation.path]
        except KeyError as error:
            raise SemanticGuidanceError("paired flow seed route has no component") from error
        row = _paired_flow_seed_row(
            "paired-flow",
            route.source,
            route.operation,
            route.operation_family,
            route.trace,
            ("semantic-route",),
            frontier_passes_by_path,
            component,
        )
        if row is not None:
            lanes["paired-route"].append(row)
    for site in sites:
        if _site_identity(site) in covered_sites or site.owner is None or _route_covers_site(routes, site):
            continue
        for source in site.owner_sources:
            row = _paired_flow_seed_row(
                "paired-flow",
                source,
                _site_location(site),
                site.family,
                (),
                ("declaration-source",),
                frontier_passes_by_path,
                site.component,
            )
            if row is not None:
                lanes["paired-source"].append(row)
                covered_sites.add(_site_identity(site))
                break
    for site in sites:
        if _site_identity(site) in covered_sites or _route_covers_site(routes, site) or not site.parameter_flow or site.owner is None:
            continue
        row = _paired_flow_seed_row(
            "paired-flow",
            site.owner,
            _site_location(site),
            site.family,
            (),
            ("parameter-flow",),
            frontier_passes_by_path,
            site.component,
        )
        if row is not None:
            lanes["paired-parameter"].append(row)
            covered_sites.add(_site_identity(site))
    for site in sites:
        if _site_identity(site) in covered_sites or _route_covers_site(routes, site):
            continue
        row = _paired_flow_seed_row(
            "sink-only",
            None,
            _site_location(site),
            site.family,
            (),
            ("sink-only",),
            frontier_passes_by_path,
            site.component,
        )
        if row is not None:
            lanes["sink-only"].append(row)
    lanes = _deduplicate_paired_flow_seed_rows(lanes)
    selected: list[bytes] = []
    used_bytes = 0
    queues = {
        lane: deque(_component_round_robin_rows(rows))
        for lane, rows in lanes.items()
    }
    while any(queues.values()) and len(selected) < row_limit:
        contributed = False
        for lane in ("paired-route", "paired-source", "paired-parameter", "sink-only"):
            queue = queues[lane]
            if not queue or len(selected) >= row_limit:
                continue
            encoded = _encode_canonical_row(queue.popleft())
            if len(encoded) > row_byte_limit or used_bytes + len(encoded) > byte_limit:
                continue
            selected.append(encoded)
            used_bytes += len(encoded)
            contributed = True
        if not contributed and not any(queues.values()):
            break
    rows = [json.loads(encoded) for encoded in selected]
    return PairedFlowSeeds(
        b"".join(selected),
        len(selected),
        sum(row["seed_kind"] == "paired-flow" for row in rows),
        sum(row["seed_kind"] == "sink-only" for row in rows),
    )


def _component_round_robin_rows(rows: list[dict[str, object]]) -> tuple[dict[str, object], ...]:
    grouped: dict[str, deque[dict[str, object]]] = {}
    for row in rows:
        component = row["component"]
        if not isinstance(component, str):
            raise SemanticGuidanceError("paired flow seed component is invalid")
        grouped.setdefault(component, deque()).append(row)
    for component, queue in tuple(grouped.items()):
        grouped[component] = deque(sorted(queue, key=_paired_flow_seed_sort_key))
    ordered: list[dict[str, object]] = []
    while True:
        contributed = False
        for component in sorted(grouped):
            queue = grouped[component]
            if queue:
                ordered.append(queue.popleft())
                contributed = True
        if not contributed:
            return tuple(ordered)


def _paired_flow_seed_sort_key(row: dict[str, object]) -> tuple[object, ...]:
    critical = row["critical"]
    if not isinstance(critical, dict):
        raise SemanticGuidanceError("paired flow seed critical location is invalid")
    return (
        row["component"],
        critical["path"],
        critical["line"],
        critical["family"],
        critical["symbol"],
        row["seed_id"],
    )


def _deduplicate_paired_flow_seed_rows(
    lanes: dict[str, list[dict[str, object]]],
) -> dict[str, list[dict[str, object]]]:
    retained: dict[tuple[object, ...], dict[str, object]] = {}
    seed_ids: dict[str, dict[str, object]] = {}
    result = {lane: [] for lane in lanes}
    for lane, rows in lanes.items():
        for row in rows:
            key = (row["seed_kind"], _seed_endpoint_key(row["entry"]), _seed_endpoint_key(row["critical"]))
            if key in retained:
                continue
            seed_id = row["seed_id"]
            if not isinstance(seed_id, str):
                raise SemanticGuidanceError("paired flow seed ID is invalid")
            previous = seed_ids.get(seed_id)
            if previous is not None and previous != row:
                raise SemanticGuidanceError("paired flow seed ID collision")
            retained[key] = row
            seed_ids[seed_id] = row
            result[lane].append(row)
    return result


def _seed_endpoint_key(value: object) -> tuple[object, ...] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise SemanticGuidanceError("paired flow seed endpoint is invalid")
    return tuple(sorted(value.items()))


def _paired_flow_seed_row(
    seed_kind: str,
    entry: _Location | None,
    critical: _Location,
    family: str,
    trace: tuple[_Location, ...],
    reason_codes: tuple[str, ...],
    frontier_passes_by_path: dict[str, tuple[str, ...]],
    component: str,
) -> dict[str, object] | None:
    entry_value = _seed_location(entry) if entry is not None else None
    critical_value = _seed_critical_location(critical, family)
    trace_value = [
        value
        for location in trace
        if location not in {entry, critical}
        if (value := _seed_location(location)) is not None
    ][:MAX_PAIRED_FLOW_SEED_TRACE]
    if (entry is not None and entry_value is None) or critical_value is None:
        return None
    paths = {critical.path}
    if entry is not None:
        paths.add(entry.path)
    paths.update(location.path for location in trace)
    try:
        eligible = [
            value
            for value in HUNT_SEARCH_PASS_ORDER
            if any(value in frontier_passes_by_path[path] for path in paths)
        ]
    except KeyError as error:
        raise SemanticGuidanceError("paired flow seed is absent from frontier passes") from error
    if not eligible or not isinstance(component, str) or not component or "\x00" in component:
        return None
    logical: dict[str, object] = {
        "component": component,
        "critical": critical_value,
        "eligible_search_passes": eligible,
        "entry": entry_value,
        "proof_status": "investigation_only",
        "reason_codes": list(reason_codes),
        "schema_version": PAIRED_FLOW_SEED_SCHEMA_VERSION,
        "seed_kind": seed_kind,
        "trace": trace_value,
    }
    seed_id = _paired_flow_seed_id(logical)
    return {**logical, "seed_id": seed_id}


def _paired_flow_seed_id(logical_row: dict[str, object]) -> str:
    canonical = json.dumps(logical_row, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "seed-" + hashlib.sha256(canonical).hexdigest()[:32]


def _seed_location(location: _Location) -> dict[str, object] | None:
    if len(location.symbol.encode("utf-8")) > MAX_PAIRED_FLOW_SEED_SYMBOL_BYTES:
        return None
    return location.as_dict()


def _seed_critical_location(location: _Location, family: str) -> dict[str, object] | None:
    value = _seed_location(location)
    if value is None or not isinstance(family, str) or not family:
        return None
    return {"family": family, **value}


def _site_location(site: _StructuralSite) -> _Location:
    return _Location(site.path, site.line, site.signature)


def _site_identity(site: _StructuralSite) -> tuple[str, int, str, str]:
    return (site.path, site.line, site.family, site.signature)


def _route_covers_site(routes: tuple[_Route, ...], site: _StructuralSite) -> bool:
    return any(
        route.operation.path == site.path
        and route.operation.line == site.line
        and route.operation.symbol.rsplit(".", 1)[-1].lower() == site.signature
        for route in routes
    )


def _canonical_guidance(
    routes: tuple[_Route, ...],
    limits: GuidanceLimits,
    guidance_schema_version: int,
    frontier_passes_by_path: dict[str, tuple[str, ...]],
    frontier_components_by_path: dict[str, str],
    operation_index_rows: tuple[dict[str, object], ...] = (),
) -> tuple[bytes, int]:
    if guidance_schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION:
        ordered = _schema_three_row_order(routes, frontier_components_by_path)
        route_rows: list[tuple[_Route, bytes]] = []
        for route in ordered:
            row = _canonical_row(
                route,
                guidance_schema_version,
                frontier_passes_by_path,
                frontier_components_by_path,
            )
            _validate_row(row)
            route_rows.append((route, _encode_canonical_row(row)))
        index_lines = []
        for row in operation_index_rows:
            _validate_operation_index_row(row)
            index_lines.append(_encode_canonical_row(row))
        if not route_rows:
            lines, _ = _select_encoded_rows(
                index_lines,
                min(limits.row_count, MAX_OPERATION_INDEX_ONLY_ROWS),
                min(limits.output_bytes, MAX_OPERATION_INDEX_ONLY_BYTES),
            )
            return b"".join(lines), len(lines)
        route_only: list[tuple[_Route, bytes]] = []
        route_only_bytes = 0
        for route, encoded in route_rows:
            if (
                len(route_only) < limits.row_count
                and route_only_bytes + len(encoded) <= limits.output_bytes
            ):
                route_only.append((route, encoded))
                route_only_bytes += len(encoded)
        if not route_only:
            return b"", 0
        strong_lines = [
            encoded
            for route, encoded in route_only
            if route.strength != "name-only"
        ]
        weak_lines = [
            encoded
            for route, encoded in route_only
            if route.strength == "name-only"
        ]
        remaining_rows = len(route_only) - len(strong_lines)
        remaining_bytes = route_only_bytes - sum(map(len, strong_lines))
        index_selected, _ = _select_encoded_rows(
            index_lines,
            remaining_rows,
            remaining_bytes,
        )
        remaining_rows -= len(index_selected)
        remaining_bytes -= sum(map(len, index_selected))
        weak_selected, _ = _select_encoded_rows(
            weak_lines,
            remaining_rows,
            remaining_bytes,
        )
        lines = [*strong_lines, *index_selected, *weak_selected]
        return b"".join(lines), len(lines)
    ordered = sorted(routes, key=_route_sort_key)
    lines: list[bytes] = []
    for route in ordered:
        row = _canonical_row(
            route,
            guidance_schema_version,
            frontier_passes_by_path,
            frontier_components_by_path,
        )
        _validate_row(row)
        encoded = _encode_canonical_row(row)
        if len(lines) >= limits.row_count or sum(map(len, lines)) + len(encoded) > limits.output_bytes:
            break
        lines.append(encoded)
    return b"".join(lines), len(lines)


def _select_encoded_rows(
    lines: list[bytes],
    row_limit: int,
    byte_limit: int,
) -> tuple[list[bytes], list[bytes]]:
    selected: list[bytes] = []
    remaining: list[bytes] = []
    used_bytes = 0
    for line in lines:
        if len(selected) < row_limit and used_bytes + len(line) <= byte_limit:
            selected.append(line)
            used_bytes += len(line)
        else:
            remaining.append(line)
    return selected, remaining


def _schema_three_row_order(
    routes: tuple[_Route, ...],
    components_by_path: dict[str, str],
) -> tuple[_Route, ...]:
    ordered: list[_Route] = []
    for strong in (True, False):
        families: dict[tuple[str, str], dict[str, list[_Route]]] = {}
        for route in routes:
            if (route.strength != "name-only") != strong:
                continue
            try:
                component = components_by_path[route.operation.path]
            except KeyError as error:
                raise SemanticGuidanceError("semantic guidance route has no component") from error
            families.setdefault((route.hint_kind, route.operation_family), {}).setdefault(component, []).append(route)
        family_queues: dict[tuple[str, str], deque[_Route]] = {}
        for family, components in families.items():
            component_queues = {
                component: deque(sorted(component_routes, key=_route_sort_key))
                for component, component_routes in components.items()
            }
            family_queue: deque[_Route] = deque()
            while True:
                selected = False
                for component in sorted(component_queues):
                    queue = component_queues[component]
                    if not queue:
                        continue
                    family_queue.append(queue.popleft())
                    selected = True
                if not selected:
                    break
            family_queues[family] = family_queue
        while True:
            selected = False
            for family in sorted(family_queues):
                queue = family_queues[family]
                if not queue:
                    continue
                ordered.append(queue.popleft())
                selected = True
            if not selected:
                break
    return tuple(ordered)


def _route_sort_key(route: _Route) -> tuple[object, ...]:
    return (
        {"direct": 0, "import-linked": 1, "name-only": 2}[route.strength],
        len(route.trace),
        route.operation_family,
        route.source.path,
        route.source.line,
        route.operation.path,
        route.operation.line,
        tuple((item.path, item.line, item.symbol) for item in route.trace),
    )


def _eligible_search_passes(
    route: _Route,
    frontier_passes_by_path: dict[str, tuple[str, ...]],
) -> list[str]:
    route_paths = {route.source.path, route.operation.path}
    route_paths.update(location.path for location in route.trace)
    try:
        selected = {
            value
            for path in route_paths
            for value in frontier_passes_by_path[path]
        }
    except KeyError as error:
        raise SemanticGuidanceError("semantic guidance route is absent from frontier passes") from error
    ordered = [value for value in HUNT_SEARCH_PASS_ORDER if value in selected]
    if not ordered:
        raise SemanticGuidanceError("semantic guidance route has no eligible search pass")
    return ordered


def _canonical_row(
    route: _Route,
    guidance_schema_version: int,
    frontier_passes_by_path: dict[str, tuple[str, ...]],
    frontier_components_by_path: dict[str, str] | None = None,
) -> dict[str, object]:
    identity_values = (
        [route.strength, route.operation_family]
        + [f"{item.path}:{item.line}:{item.symbol}" for item in (route.source, route.operation, *route.trace)]
    )
    if guidance_schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION:
        identity_values.extend((route.hint_kind, route.output_context or ""))
    identity = "\x1f".join(identity_values)
    row: dict[str, object] = {
        "schema_version": guidance_schema_version,
        "hint_id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
        "strength": route.strength,
        "operation_family": route.operation_family,
        "source": route.source.as_dict(),
        "operation": route.operation.as_dict(),
        "trace": [item.as_dict() for item in route.trace],
        "controls": [item.as_dict() for item in route.controls],
        "reason_codes": list(route.reason_codes),
        "proof_status": "investigation_only",
    }
    if guidance_schema_version in {
        PASS_ANNOTATED_SEMANTIC_GUIDANCE_SCHEMA_VERSION,
        SEMANTIC_GUIDANCE_SCHEMA_VERSION,
    }:
        row["eligible_search_passes"] = _eligible_search_passes(route, frontier_passes_by_path)
    if guidance_schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION:
        if frontier_components_by_path is None or route.operation.path not in frontier_components_by_path:
            raise SemanticGuidanceError("semantic guidance route has no component")
        row["hint_kind"] = route.hint_kind
        row["output_context"] = route.output_context
        row["component"] = frontier_components_by_path[route.operation.path]
    return row


def _validate_row(row: dict[str, object]) -> None:
    required_keys = {
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
    }
    schema_version = row.get("schema_version")
    if schema_version in {
        PASS_ANNOTATED_SEMANTIC_GUIDANCE_SCHEMA_VERSION,
        SEMANTIC_GUIDANCE_SCHEMA_VERSION,
    }:
        required_keys.add("eligible_search_passes")
    if schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION:
        required_keys.update(("hint_kind", "output_context", "component"))
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version not in SUPPORTED_SEMANTIC_GUIDANCE_SCHEMA_VERSIONS
        or set(row) != required_keys
        or not isinstance(row["hint_id"], str)
        or not re.fullmatch(r"[0-9a-f]{16}", row["hint_id"])
        or row["strength"] not in {"direct", "import-linked", "name-only"}
        or (
            row["operation_family"] not in OPERATION_ANCHORS
            and not (
                schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION
                and row["operation_family"] == "output-context"
            )
        )
        or row["proof_status"] != "investigation_only"
        or not _valid_location(row["source"])
        or not _valid_location(row["operation"])
        or not isinstance(row["trace"], list)
        or not 1 <= len(row["trace"]) <= 12
        or not all(_valid_location(item) for item in row["trace"])
        or len({(item["path"], item["line"], item["symbol"]) for item in row["trace"]}) != len(row["trace"])
        or not isinstance(row["controls"], list)
        or len(row["controls"]) > 8
        or not all(_valid_location(item) for item in row["controls"])
        or not isinstance(row["reason_codes"], list)
        or not all(isinstance(item, str) and item for item in row["reason_codes"])
    ):
        raise SemanticGuidanceError("semantic guidance row is invalid")
    if schema_version in {
        PASS_ANNOTATED_SEMANTIC_GUIDANCE_SCHEMA_VERSION,
        SEMANTIC_GUIDANCE_SCHEMA_VERSION,
    }:
        eligible = row["eligible_search_passes"]
        if (
            not isinstance(eligible, list)
            or not eligible
            or not all(isinstance(value, str) for value in eligible)
            or len(eligible) != len(set(eligible))
            or eligible != [value for value in HUNT_SEARCH_PASS_ORDER if value in eligible]
        ):
            raise SemanticGuidanceError("semantic guidance row is invalid")
    if schema_version == SEMANTIC_GUIDANCE_SCHEMA_VERSION:
        nested = row["hint_kind"] == "nested-output-context"
        if (
            row["hint_kind"]
            not in {"call-route", "nested-output-context"}
            or (nested and (row["operation_family"] != "output-context" or row["output_context"] not in {"script", "style", "url_attribute", "event_handler"}))
            or (
                not nested
                and (
                    row["operation_family"] not in OPERATION_ANCHORS
                    or row["output_context"] is not None
                )
            )
            or not isinstance(row["component"], str)
            or not row["component"]
            or "\x00" in row["component"]
        ):
            raise SemanticGuidanceError("semantic guidance row is invalid")


def _valid_location(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"path", "line", "symbol"}:
        return False
    path = value["path"]
    line = value["line"]
    symbol = value["symbol"]
    if not isinstance(path, str) or not isinstance(line, int) or line < 1 or not isinstance(symbol, str) or not symbol:
        return False
    try:
        return _canonical_relative_path(path) == path
    except SemanticGuidanceError:
        return False
