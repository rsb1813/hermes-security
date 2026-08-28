from __future__ import annotations

from dataclasses import dataclass, replace
from collections import deque
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import posixpath
import re
import stat


SEMANTIC_GUIDANCE_SCHEMA_VERSION = 1
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
    retained_references = 0
    seen_paths: set[str] = set()
    for raw_path in paths:
        relative_path = _canonical_relative_path(raw_path)
        if relative_path in seen_paths:
            continue
        seen_paths.add(relative_path)
        candidate = snapshot / Path(relative_path)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(snapshot)
            candidate.lstat()
        except OSError:
            skipped += 1
            continue
        except ValueError:
            skipped += 1
            continue
        try:
            encoded, source_size = _read_pinned_source(candidate)
            if total_bytes + source_size > limits.total_source_bytes:
                raise ValueError("source budget exceeded")
            source = encoded.decode("utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            skipped += 1
            continue
        total_bytes += source_size
        scanned += 1
        if len(declarations) >= limits.declaration_count:
            continue
        extracted = _extract_declarations(relative_path, source, limits.declaration_count - len(declarations))
        for declaration in extracted:
            remaining_references = max(0, limits.edge_count - retained_references)
            calls = declaration.calls[:remaining_references]
            remaining_references -= len(calls)
            imports = declaration.imports[:remaining_references]
            retained_references += len(calls) + len(imports)
            declarations.append(replace(declaration, calls=calls, imports=imports))
    return tuple(declarations), _ScanStats(scanned, skipped)


def _read_pinned_source(path: Path) -> tuple[bytes, int]:
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
        end_line = len(lines)
        for line_number in range(start_line, len(lines)):
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
    source_locations = _anchor_locations(path, symbol, line, lines, SOURCE_ANCHORS)[:1]
    controls = _anchor_locations(path, symbol, line, lines, CONTROL_ANCHORS)
    operations: list[tuple[str, _Location]] = []
    for family, anchors in OPERATION_ANCHORS.items():
        for offset, line_text in enumerate(lines):
            for callee in _operation_callees(line_text, anchors):
                operations.append((family, _Location(path, line + offset, callee)))
    return _Declaration(location, language, receiver.lower() if receiver else None, source_locations, tuple(operations), controls, (), _calls(lines, line))


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


def _calls(lines: list[str], start_line: int) -> tuple[_Call, ...]:
    calls: list[_Call] = []
    for offset, line in enumerate(lines):
        for match in re.finditer(r"\b((?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*)\s*\(", line):
            declaration_prefix = line[: match.start()].rstrip()
            if re.search(r"(?:^|\s)(?:def|func|function)\s*$", declaration_prefix):
                continue
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


def _operation_callees(line: str, anchors: set[str]) -> tuple[str, ...]:
    callees: list[str] = []
    for candidate in re.finditer(r"(?:[A-Za-z_$][\w$]*(?:\s*/\s*[A-Za-z_$][\w$]*)?\s*\.\s*)*[A-Za-z_$][\w$]*", line):
        normalized = re.sub(r"\s+", "", candidate.group()).lower()
        segments = normalized.replace("/", ".").split(".")
        preserved = ".".join(segments[-2:])
        if normalized in anchors or preserved in anchors:
            callees.append(preserved)
    return tuple(dict.fromkeys(callees))


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
    target = PurePosixPath(target_path).as_posix()
    if target.endswith(".d.ts"):
        target = target[: -len(".d.ts")]
    else:
        target = PurePosixPath(target).with_suffix("").as_posix()
    if language == "python":
        candidates = {normalized, f"{normalized}/__init__"}
        if imported_symbol is not None:
            candidates.add(f"{normalized}/{imported_symbol}")
        return target in candidates
    if language == "typescript":
        return target == normalized or target == f"{normalized}/index"
    if language == "go":
        return PurePosixPath(target_path).parent.as_posix() == normalized
    return target == normalized


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
