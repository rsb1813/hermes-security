from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat


SEMANTIC_GUIDANCE_SCHEMA_VERSION = 1
MAX_FILE_BYTES = 1024 * 1024

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
    sources: tuple[_Location, ...]
    operations: tuple[tuple[str, _Location], ...]
    controls: tuple[_Location, ...]
    imports: tuple[_Import, ...]
    calls: tuple[_Call, ...]


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


@dataclass(frozen=True)
class _Route:
    strength: str
    operation_family: str
    source: _Location
    operation: _Location
    trace: tuple[_Location, ...]
    controls: tuple[_Location, ...]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class _ScanStats:
    scanned_file_count: int
    skipped_file_count: int


def build_semantic_guidance(
    snapshot_path: Path,
    paths: tuple[str, ...],
    profile: str,
) -> SemanticGuidance:
    try:
        limits = PROFILE_LIMITS[profile]
    except KeyError as error:
        raise SemanticGuidanceError("semantic guidance profile is unsupported") from error
    snapshot = _safe_snapshot(snapshot_path)
    declarations, scan = _scan_files(snapshot, paths, limits)
    routes, edge_count = _build_routes(declarations, limits)
    canonical_bytes, row_count = _canonical_guidance(routes, limits)
    return SemanticGuidance(
        canonical_bytes,
        row_count,
        edge_count,
        scan.scanned_file_count,
        scan.skipped_file_count,
    )


def _safe_snapshot(snapshot_path: Path) -> Path:
    snapshot = snapshot_path.resolve(strict=True)
    if not snapshot.is_dir():
        raise SemanticGuidanceError("semantic guidance snapshot is not a directory")
    return snapshot


def _scan_files(
    snapshot: Path,
    paths: tuple[str, ...],
    limits: GuidanceLimits,
) -> tuple[tuple[_Declaration, ...], _ScanStats]:
    declarations: list[_Declaration] = []
    scanned = 0
    skipped = 0
    total_bytes = 0
    seen_paths: set[str] = set()
    for raw_path in paths:
        relative_path = _canonical_relative_path(raw_path)
        if relative_path in seen_paths:
            continue
        seen_paths.add(relative_path)
        candidate = snapshot / Path(relative_path)
        try:
            file_stat = candidate.lstat()
        except OSError:
            skipped += 1
            continue
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
            skipped += 1
            continue
        if file_stat.st_size > MAX_FILE_BYTES or total_bytes + file_stat.st_size > limits.total_source_bytes:
            skipped += 1
            continue
        try:
            source = candidate.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            skipped += 1
            continue
        total_bytes += file_stat.st_size
        scanned += 1
        if len(declarations) >= limits.declaration_count:
            continue
        declarations.extend(_extract_declarations(relative_path, source, limits.declaration_count - len(declarations)))
    return tuple(declarations), _ScanStats(scanned, skipped)


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
    if normalized in {"", "."} or normalized.startswith("/"):
        raise SemanticGuidanceError("semantic guidance path is invalid")
    return normalized


def _extract_declarations(path: str, source: str, remaining: int) -> tuple[_Declaration, ...]:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".py":
        matches = list(re.finditer(r"(?m)^(?P<indent>[ \t]*)(?:async[ \t]+)?def[ \t]+(?P<name>[A-Za-z_]\w*)\s*\(", source))
        declarations = _python_declarations(path, source, matches, remaining)
        imports = _python_imports(source)
    elif suffix == ".go":
        matches = list(re.finditer(r"\bfunc\s+(?:\([^\n)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\(", source))
        declarations = _brace_declarations(path, source, matches, remaining, "go")
        imports = _go_imports(source)
    elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
        matches = list(re.finditer(r"\b(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(", source))
        declarations = _brace_declarations(path, source, matches, remaining, "typescript")
        imports = _typescript_imports(source)
    else:
        declarations = _generic_declarations(path, source, remaining)
        imports = ()
    return tuple(replace(declaration, imports=imports) for declaration in declarations)


def _python_declarations(path: str, source: str, matches: list[re.Match[str]], remaining: int) -> tuple[_Declaration, ...]:
    declarations: list[_Declaration] = []
    lines = source.splitlines()
    for index, match in enumerate(matches[:remaining]):
        start_line = source.count("\n", 0, match.start()) + 1
        indent = len(match.group("indent").expandtabs(8))
        end_line = len(lines)
        for line_number in range(start_line, len(lines)):
            line = lines[line_number]
            if line.strip() and len(line) - len(line.lstrip(" \t")) <= indent and re.match(r"(?:async\s+)?def\s+", line.lstrip()):
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
        closing = _matching_brace(source, opening)
        block_end = len(source) if closing is None else closing + 1
        block = source[match.start() : block_end].splitlines()
        declarations.append(_declaration_from_block(path, language, match.group("name"), start_line, block))
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


def _declaration_from_block(path: str, language: str, symbol: str, line: int, lines: list[str]) -> _Declaration:
    location = _Location(path, line, symbol)
    source_locations = _anchor_locations(path, symbol, line, lines, SOURCE_ANCHORS)[:1]
    controls = _anchor_locations(path, symbol, line, lines, CONTROL_ANCHORS)
    operations: list[tuple[str, _Location]] = []
    for family, anchors in OPERATION_ANCHORS.items():
        for offset, line_text in enumerate(lines):
            callee = _operation_callee(line_text, anchors)
            if callee is not None:
                operations.append((family, _Location(path, line + offset, callee)))
                break
        if operations:
            break
    return _Declaration(location, language, source_locations, tuple(operations), controls, (), _calls(lines, line))


def _python_imports(source: str) -> tuple[_Import, ...]:
    imports: list[_Import] = []
    for match in re.finditer(r"(?m)^\s*from\s+(\.*[A-Za-z_][\w.]*)\s+import\s+([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?", source):
        imports.append(_Import(match.group(3) or match.group(2), match.group(1), match.group(2)))
    for match in re.finditer(r"(?m)^\s*import\s+([A-Za-z_][\w.]*)(?:\s+as\s+([A-Za-z_]\w*))?", source):
        module = match.group(1)
        imports.append(_Import(match.group(2) or module.rsplit(".", 1)[-1], module, None))
    return tuple(imports)


def _go_imports(source: str) -> tuple[_Import, ...]:
    imports: list[_Import] = []
    for match in re.finditer(r'(?m)^\s*(?:([A-Za-z_]\w*)\s+)?"([^"\n]+)"', source):
        module = match.group(2)
        imports.append(_Import(match.group(1) or module.rsplit("/", 1)[-1], module, None))
    return tuple(imports)


def _typescript_imports(source: str) -> tuple[_Import, ...]:
    imports: list[_Import] = []
    for match in re.finditer(r'(?m)^\s*import\s*{([^}]+)}\s*from\s*["\']([^"\']+)["\']', source):
        for part in match.group(1).split(","):
            names = re.match(r"\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?", part)
            if names:
                imports.append(_Import(names.group(2) or names.group(1), match.group(2), names.group(1)))
    for match in re.finditer(r'(?m)^\s*import\s+([A-Za-z_$][\w$]*)\s+from\s*["\']([^"\']+)["\']', source):
        imports.append(_Import(match.group(1), match.group(2), None))
    return tuple(imports)


def _calls(lines: list[str], start_line: int) -> tuple[_Call, ...]:
    calls: list[_Call] = []
    for offset, line in enumerate(lines):
        for match in re.finditer(r"\b((?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*)\s*\(", line):
            parts = [part.strip().lower() for part in match.group(1).split(".")]
            if parts[-1] in {"def", "func", "function", "if", "for", "while", "switch", "catch"}:
                continue
            calls.append(_Call(parts[-1], parts[-2] if len(parts) > 1 else None, start_line + offset))
    return tuple(calls)


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


def _operation_callee(line: str, anchors: set[str]) -> str | None:
    for candidate in re.finditer(r"(?:[A-Za-z_$][\w$]*(?:\s*/\s*[A-Za-z_$][\w$]*)?\s*\.\s*)*[A-Za-z_$][\w$]*", line):
        normalized = re.sub(r"\s+", "", candidate.group()).lower()
        segments = normalized.replace("/", ".").split(".")
        preserved = ".".join(segments[-2:])
        if normalized in anchors or preserved in anchors or segments[-1] in anchors:
            return preserved
    return None


def _build_routes(declarations: tuple[_Declaration, ...], limits: GuidanceLimits) -> tuple[tuple[_Route, ...], int]:
    by_identity = {(item.location.path, item.location.line, item.location.symbol): item for item in declarations}
    outgoing: dict[tuple[str, int, str], tuple[tuple[tuple[str, int, str], str], ...]] = {}
    edge_count = 0
    for identity, declaration in by_identity.items():
        resolved = _resolve_calls(declaration, declarations)
        retained_edges = resolved[: max(0, limits.edge_count - edge_count)]
        outgoing[identity] = retained_edges
        edge_count += len(retained_edges)
    retained: dict[tuple[_Location, _Location], _Route] = {}
    for declaration in declarations:
        if not declaration.sources:
            continue
        identity = _location_identity(declaration.location)
        for source in declaration.sources:
            _traverse_routes(source, identity, by_identity, outgoing, limits, retained)
            if len(retained) >= limits.route_count:
                break
        if len(retained) >= limits.route_count:
            break
    return tuple(retained.values()), edge_count


def _traverse_routes(
    source: _Location,
    root_identity: tuple[str, int, str],
    declarations: dict[tuple[str, int, str], _Declaration],
    outgoing: dict[tuple[str, int, str], tuple[tuple[tuple[str, int, str], str], ...]],
    limits: GuidanceLimits,
    retained: dict[tuple[_Location, _Location], _Route],
) -> None:
    queue: list[tuple[tuple[str, int, str], tuple[_Location, ...], str, int]] = [
        (root_identity, (declarations[root_identity].location,), "direct", 0)
    ]
    while queue and len(retained) < limits.route_count:
        identity, trace, strength, depth = queue.pop(0)
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
        if depth >= limits.graph_depth or len(trace) >= 12:
            continue
        for target_identity, edge_strength in outgoing[identity]:
            target = declarations[target_identity]
            if target.location in trace:
                continue
            next_strength = _combined_strength(strength, edge_strength)
            queue.append((target_identity, (*trace, target.location), next_strength, depth + 1))


def _resolve_calls(
    declaration: _Declaration,
    declarations: tuple[_Declaration, ...],
) -> tuple[tuple[tuple[str, int, str], str], ...]:
    resolved: list[tuple[tuple[str, int, str], str]] = []
    for call in declaration.calls:
        same_file = [item for item in declarations if item.location.path == declaration.location.path and item.location.symbol.lower() == call.name]
        if len(same_file) == 1:
            resolved.append((_location_identity(same_file[0].location), "name-only"))
            continue
        imports = [
            item
            for item in declaration.imports
            if (call.qualifier == item.local_name.lower()) or (call.qualifier is None and call.name == item.local_name.lower())
        ]
        imported = _resolve_import_targets(declaration, call, imports, declarations)
        if len(imported) == 1:
            resolved.append((_location_identity(imported[0].location), "import-linked"))
            continue
        global_matches = [item for item in declarations if item.location.symbol.lower() == call.name]
        for target in global_matches:
            resolved.append((_location_identity(target.location), "name-only"))
    return tuple(dict.fromkeys(resolved))


def _resolve_import_targets(
    declaration: _Declaration,
    call: _Call,
    imports: list[_Import],
    declarations: tuple[_Declaration, ...],
) -> list[_Declaration]:
    targets: list[_Declaration] = []
    for imported in imports:
        symbol = imported.symbol or call.name
        targets.extend(
            item
            for item in declarations
            if item.location.symbol.lower() == symbol and _module_matches(declaration.location.path, imported.module, item.location.path)
        )
    return targets


def _module_matches(caller_path: str, module: str, target_path: str) -> bool:
    caller_parent = PurePosixPath(caller_path).parent
    normalized_module = module.lstrip(".")
    if module.startswith("."):
        normalized_module = str((caller_parent / normalized_module).as_posix())
    module_stem = normalized_module.rsplit("/", 1)[-1].rsplit(".", 1)[-1]
    target = PurePosixPath(target_path)
    return target.stem == module_stem or target.with_suffix("").as_posix().replace("/", ".") == normalized_module


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


def _canonical_guidance(routes: tuple[_Route, ...], limits: GuidanceLimits) -> tuple[bytes, int]:
    ordered = sorted(routes, key=_route_sort_key)
    lines: list[bytes] = []
    for route in ordered:
        row = _canonical_row(route)
        _validate_row(row)
        encoded = json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(lines) >= limits.row_count or sum(map(len, lines)) + len(encoded) > limits.output_bytes:
            break
        lines.append(encoded)
    return b"".join(lines), len(lines)


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


def _canonical_row(route: _Route) -> dict[str, object]:
    identity = "\x1f".join(
        [route.strength, route.operation_family]
        + [f"{item.path}:{item.line}:{item.symbol}" for item in (route.source, route.operation, *route.trace)]
    )
    return {
        "schema_version": SEMANTIC_GUIDANCE_SCHEMA_VERSION,
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
    if (
        set(row) != required_keys
        or row["schema_version"] != SEMANTIC_GUIDANCE_SCHEMA_VERSION
        or not isinstance(row["hint_id"], str)
        or not re.fullmatch(r"[0-9a-f]{16}", row["hint_id"])
        or row["strength"] not in {"direct", "import-linked", "name-only"}
        or row["operation_family"] not in OPERATION_ANCHORS
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
