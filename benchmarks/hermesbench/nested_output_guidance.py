"""Detects bounded JavaScript and TypeScript nested output contexts."""

from __future__ import annotations

from dataclasses import dataclass
import re


JAVASCRIPT_TYPESCRIPT_EXTENSIONS = frozenset({
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"
})
OUTPUT_CONTEXT_ORDER = ("script", "style", "url_attribute", "event_handler")
URL_ATTRIBUTES = frozenset({"href", "src", "action", "formaction", "poster", "xlink:href"})
MAX_TEMPLATES_PER_FILE = 256
MAX_INTERPOLATIONS_PER_FILE = 512
MAX_INTERPOLATION_DEPTH = 16
MAX_EXPRESSION_BYTES = 16 * 1024

_IDENTIFIER = r"[A-Za-z_$][\w$]*"
_CONFIGURATION_ROOTS = frozenset({"config", "configuration", "environment", "options", "settings"})
_CONTEXT_REASON_CODES = {
    "script": "embedded_script",
    "style": "embedded_style",
    "url_attribute": "url_attribute_context",
    "event_handler": "event_handler_context",
}


@dataclass(frozen=True)
class NestedOutputObservation:
    context: str
    declaration_line: int
    declaration_symbol: str
    source_line: int
    source_symbol: str
    operation_line: int
    control_lines: tuple[int, ...]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class _Declaration:
    start: int
    end: int
    line: int
    symbol: str
    parameters: frozenset[str]


@dataclass(frozen=True)
class _Interpolation:
    expression_start: int
    expression_end: int
    raw_before: str
    raw_after: str


@dataclass(frozen=True)
class _Origin:
    line: int
    symbol: str
    reason_codes: tuple[str, ...]


class _ScanLimit(ValueError):
    pass


class _TemplateScanner:
    def __init__(self, source: str) -> None:
        self.source = source
        self.template_count = 0
        self.interpolation_count = 0
        self.observations: list[_Interpolation] = []

    def scan(self) -> tuple[_Interpolation, ...]:
        index = 0
        while index < len(self.source):
            if self.source.startswith("//", index):
                newline = self.source.find("\n", index + 2)
                index = len(self.source) if newline < 0 else newline + 1
                continue
            if self.source.startswith("/*", index):
                closing = self.source.find("*/", index + 2)
                index = len(self.source) if closing < 0 else closing + 2
                continue
            character = self.source[index]
            if character in {"'", '"'}:
                index = _skip_quoted(self.source, index)
                continue
            if character == "/" and _looks_like_regex(self.source, index):
                index = _skip_regex(self.source, index)
                continue
            if character == "`":
                try:
                    index = self._template(index, 0)
                except _ScanLimit:
                    return tuple(self.observations)
                continue
            index += 1
        return tuple(self.observations)

    def _template(self, opening: int, depth: int) -> int:
        checkpoint = len(self.observations)
        try:
            return self._scan_template(opening, depth)
        except _ScanLimit:
            del self.observations[checkpoint:]
            raise

    def _scan_template(self, opening: int, depth: int) -> int:
        self.template_count += 1
        if self.template_count > MAX_TEMPLATES_PER_FILE or depth > MAX_INTERPOLATION_DEPTH:
            raise _ScanLimit()
        index = opening + 1
        raw_start = index
        chunks: list[str] = []
        entries: list[tuple[int, int]] = []
        while index < len(self.source):
            character = self.source[index]
            if character == "\\":
                index += 2
                continue
            if character == "`":
                chunks.append(self.source[raw_start:index])
                for position, (expression_start, expression_end) in enumerate(entries):
                    self.observations.append(
                        _Interpolation(
                            expression_start,
                            expression_end,
                            "\x00".join(chunks[: position + 1]),
                            "\x00".join(chunks[position + 1:]),
                        )
                    )
                return index + 1
            if self.source.startswith("${", index):
                self.interpolation_count += 1
                if self.interpolation_count > MAX_INTERPOLATIONS_PER_FILE:
                    raise _ScanLimit()
                chunks.append(self.source[raw_start:index])
                expression_start = index + 2
                expression_end = self._expression(expression_start, depth + 1)
                if len(self.source[expression_start:expression_end].encode("utf-8")) > MAX_EXPRESSION_BYTES:
                    raise _ScanLimit()
                entries.append((expression_start, expression_end))
                index = expression_end + 1
                raw_start = index
                continue
            index += 1
        raise _ScanLimit()

    def _expression(self, start: int, depth: int) -> int:
        braces = 1
        index = start
        while index < len(self.source):
            if self.source.startswith("//", index):
                newline = self.source.find("\n", index + 2)
                index = len(self.source) if newline < 0 else newline + 1
                continue
            if self.source.startswith("/*", index):
                closing = self.source.find("*/", index + 2)
                if closing < 0:
                    raise _ScanLimit()
                index = closing + 2
                continue
            character = self.source[index]
            if character in {"'", '"'}:
                index = _skip_quoted(self.source, index)
                continue
            if character == "`":
                index = self._template(index, depth)
                continue
            if character == "/" and _looks_like_regex(self.source, index):
                index = _skip_regex(self.source, index)
                continue
            if character == "{":
                braces += 1
            elif character == "}":
                braces -= 1
                if braces == 0:
                    return index
            index += 1
        raise _ScanLimit()


def scan_nested_output_contexts(source: str) -> tuple[NestedOutputObservation, ...]:
    scanner = _TemplateScanner(source)
    declarations = _javascript_declarations(source)
    observations: list[NestedOutputObservation] = []
    for interpolation in scanner.scan():
        declaration = _containing_declaration(declarations, interpolation.expression_start)
        if declaration is None:
            continue
        context = _classify_context(interpolation.raw_before, interpolation.raw_after)
        if context is None:
            continue
        expression = source[interpolation.expression_start:interpolation.expression_end]
        origin = _origin_for_expression(source, declaration, interpolation.expression_start, expression)
        if origin is None or _is_suppressed(source, expression, context, interpolation.raw_before, interpolation.raw_after):
            continue
        reasons = (
            "nested_output_context",
            _CONTEXT_REASON_CODES[context],
            *origin.reason_codes,
        )
        controls = _outer_sanitizer_lines(source, declaration)
        if controls:
            reasons = (*reasons, "outer_html_sanitizer_context_mismatch")
        observations.append(
            NestedOutputObservation(
                context,
                declaration.line,
                declaration.symbol,
                origin.line,
                origin.symbol,
                _line_number(source, interpolation.expression_start),
                controls,
                tuple(dict.fromkeys(reasons)),
            )
        )
    return tuple(observations)


def _classify_context(raw_before: str, raw_after: str) -> str | None:
    if _active_static_element(raw_before, "script") and _static_closing_element(raw_after, "script"):
        return "script"
    if _active_static_element(raw_before, "style") and _static_closing_element(raw_after, "style"):
        return "style"
    attribute = re.search(
        rf"<({_IDENTIFIER}(?:\s+[^<>]*)?)\s+({_IDENTIFIER}(?::{_IDENTIFIER})?)\s*=\s*(['\"])[^<>]*$",
        raw_before,
        re.IGNORECASE,
    )
    if attribute and attribute.group(3) in raw_after.split("<", 1)[0]:
        name = attribute.group(2).lower()
        if name in URL_ATTRIBUTES:
            return "url_attribute"
        if name.startswith("on") and len(name) > 2:
            return "event_handler"
    return None


def _active_static_element(raw_before: str, name: str) -> bool:
    for segment in raw_before.split("\x00"):
        matches = list(re.finditer(rf"<{re.escape(name)}\b", segment, re.IGNORECASE))
        if not matches:
            continue
        end = _static_tag_end(segment, matches[-1].start() + 1)
        if end is not None and "<" not in segment[end + 1:] and ">" not in segment[end + 1:]:
            return True
    return False


def _static_closing_element(raw_after: str, name: str) -> bool:
    return any(
        re.match(rf"[^<>]*</{re.escape(name)}\s*>", segment, re.IGNORECASE)
        for segment in raw_after.split("\x00")
    )


def _static_tag_end(raw: str, start: int) -> int | None:
    quote: str | None = None
    index = start
    while index < len(raw):
        character = raw[index]
        if quote is not None:
            if character == "\\":
                index += 2
                continue
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == ">":
            return index
        elif character == "<":
            return None
        index += 1
    return None


def _javascript_declarations(source: str) -> tuple[_Declaration, ...]:
    patterns = (
        re.compile(rf"\b(?:export\s+)?(?:async\s+)?function\s+({_IDENTIFIER})\s*\(([^)]*)\)\s*\{{"),
        re.compile(rf"\b(?:const|let|var)\s+({_IDENTIFIER})[^=\n]*=\s*(?:async\s+)?\(([^)]*)\)\s*=>\s*\{{"),
        re.compile(rf"\b(?:const|let|var)\s+({_IDENTIFIER})[^=\n]*=\s*(?:async\s+)?({_IDENTIFIER})\s*=>\s*\{{"),
        re.compile(rf"(?m)^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*({_IDENTIFIER})\s*\(([^)]*)\)\s*\{{"),
    )
    declarations: list[_Declaration] = []
    for pattern in patterns:
        for match in pattern.finditer(source):
            closing = _matching_code_brace(source, match.end() - 1)
            if closing is None:
                continue
            parameters = _parameter_names(match.group(2))
            declarations.append(
                _Declaration(match.start(), closing + 1, _line_number(source, match.start()), match.group(1), parameters)
            )
    return tuple(sorted({(item.start, item.end, item.symbol): item for item in declarations}.values(), key=lambda item: (item.start, item.end, item.symbol)))


def _parameter_names(raw: str) -> frozenset[str]:
    return frozenset(re.findall(_IDENTIFIER, raw))


def _containing_declaration(declarations: tuple[_Declaration, ...], position: int) -> _Declaration | None:
    candidates = [item for item in declarations if item.start <= position < item.end]
    return max(candidates, key=lambda item: item.start, default=None)


def _origin_for_expression(source: str, declaration: _Declaration, position: int, expression: str) -> _Origin | None:
    normalized = expression.strip()
    direct = _direct_origin(source, declaration, position, normalized)
    if direct is not None:
        return direct
    member = re.search(rf"\b({_IDENTIFIER})\.({_IDENTIFIER})\b", normalized)
    if member and member.group(1) in declaration.parameters:
        return _Origin(
            _line_number(source, position + member.start(1)),
            member.group(1),
            ("property_provenance",),
        )
    return None


def _direct_origin(source: str, declaration: _Declaration, position: int, expression: str) -> _Origin | None:
    if re.fullmatch(rf"(?:process\.)?env\.{_IDENTIFIER}", expression):
        return _Origin(_line_number(source, position), "environment", ("config_provenance",))
    identifier = re.fullmatch(_IDENTIFIER, expression)
    if identifier:
        name = identifier.group()
        if name in declaration.parameters:
            return _Origin(declaration.line, name, ("parameter_provenance",))
        assignment = _local_assignment(source, declaration, name, position)
        if assignment is not None:
            line, value = assignment
            nested = _direct_origin(source, declaration, position, value)
            if nested is not None and "one_hop_alias_provenance" not in nested.reason_codes:
                return _Origin(line, name, (*nested.reason_codes, "one_hop_alias_provenance"))
            sanitizer = _sanitizer_call(value)
            if sanitizer is not None:
                return _Origin(line, name, ("sanitizer_return_provenance", "one_hop_alias_provenance"))
        if name.lower() in _CONFIGURATION_ROOTS:
            return _Origin(declaration.line, name, ("config_provenance",))
    member = re.fullmatch(rf"({_IDENTIFIER})\.({_IDENTIFIER})", expression)
    if member:
        root = member.group(1)
        if root in declaration.parameters:
            return _Origin(declaration.line, root, ("property_provenance",))
        if root.lower() in _CONFIGURATION_ROOTS:
            return _Origin(declaration.line, root, ("config_provenance", "property_provenance"))
    sanitizer = _sanitizer_call(expression)
    if sanitizer is not None:
        return _Origin(_line_number(source, position), sanitizer, ("sanitizer_return_provenance",))
    return None


def _local_assignment(source: str, declaration: _Declaration, name: str, position: int) -> tuple[int, str] | None:
    block = source[declaration.start:position]
    pattern = re.compile(rf"\b(?:const|let)\s+{re.escape(name)}\s*=\s*([^;\n]+)\s*;")
    matches = list(pattern.finditer(block))
    if len(matches) != 1:
        return None
    match = matches[0]
    return (_line_number(source, declaration.start + match.start()), match.group(1).strip())


def _sanitizer_call(expression: str) -> str | None:
    match = re.fullmatch(rf"({_IDENTIFIER})\s*\([^()]*\)", expression)
    if match and match.group(1).lower().startswith("sanitize"):
        return match.group(1)
    return None


def _outer_sanitizer_lines(source: str, declaration: _Declaration) -> tuple[int, ...]:
    block = source[declaration.start:declaration.end]
    lines: list[int] = []
    for match in re.finditer(rf"\b{_IDENTIFIER}\s*\(", block):
        if not _is_code_position(block, match.start()):
            continue
        if match.group().split("(", 1)[0].strip().lower().startswith("sanitize"):
            line = _line_number(source, declaration.start + match.start())
            if line not in lines:
                lines.append(line)
            if len(lines) == 8:
                break
    return tuple(lines)


def _is_suppressed(source: str, expression: str, context: str, raw_before: str, raw_after: str) -> bool:
    if context == "url_attribute" and re.fullmatch(r"encodeURIComponent\s*\(.+\)", expression.strip(), re.DOTALL):
        return bool(re.search(r"(?:[?&][^=<>]*=|/[A-Za-z0-9._~/-]*)[^<>]*$", raw_before))
    return _policy_excludes_context(source, expression, context, raw_before)


def _policy_excludes_context(source: str, expression: str, context: str, raw_before: str) -> bool:
    imported = _audited_sanitizer_import(source)
    if imported is None:
        return False
    call = re.fullmatch(rf"{re.escape(imported.group(1))}\s*\([^,]+,\s*\{{(.+)\}}\s*\)", expression.strip(), re.DOTALL)
    if call is None:
        return False
    policy = _top_level_object_fields(call.group(1))
    if policy is None:
        return False
    allowed_tags = _literal_array_values(policy.get("allowedTags"))
    if allowed_tags is None:
        return False
    tag = _static_tag(raw_before)
    if tag is None:
        return False
    if context in {"script", "style"}:
        return tag not in allowed_tags
    attribute = _static_attribute(raw_before)
    allowed_attributes = _object_field_array(policy.get("allowedAttributes"), tag)
    if attribute is None or allowed_attributes is None:
        return False
    return attribute not in allowed_attributes


def _top_level_object_fields(raw: str) -> dict[str, str] | None:
    fields: dict[str, str] = {}
    index = 0
    while True:
        index = _skip_space_and_comments(raw, index)
        if index >= len(raw):
            return fields
        key_match = re.match(rf"{_IDENTIFIER}", raw[index:])
        if key_match is None:
            return None
        key = key_match.group()
        index += len(key)
        index = _skip_space_and_comments(raw, index)
        if index >= len(raw) or raw[index] != ":":
            return None
        value_start = index = _skip_space_and_comments(raw, index + 1)
        value_end = _top_level_value_end(raw, index)
        if value_end is None:
            return None
        if key in fields:
            return None
        fields[key] = raw[value_start:value_end].strip()
        index = _skip_space_and_comments(raw, value_end)
        if index >= len(raw):
            return fields
        if raw[index] != ",":
            return None
        index += 1


def _top_level_value_end(raw: str, start: int) -> int | None:
    index = start
    depth = 0
    while index < len(raw):
        if raw.startswith("//", index):
            newline = raw.find("\n", index + 2)
            index = len(raw) if newline < 0 else newline + 1
            continue
        if raw.startswith("/*", index):
            closing = raw.find("*/", index + 2)
            if closing < 0:
                return None
            index = closing + 2
            continue
        if raw[index] in {"'", '"'}:
            index = _skip_quoted(raw, index)
            continue
        if raw[index] == "`":
            index = _skip_template_literal(raw, index)
            continue
        if raw[index] in "[{(":
            depth += 1
        elif raw[index] in "]})":
            if depth == 0:
                return None
            depth -= 1
        elif raw[index] == "," and depth == 0:
            return index
        index += 1
    return len(raw) if depth == 0 else None


def _skip_space_and_comments(raw: str, index: int) -> int:
    while index < len(raw):
        if raw[index].isspace():
            index += 1
            continue
        if raw.startswith("//", index):
            newline = raw.find("\n", index + 2)
            index = len(raw) if newline < 0 else newline + 1
            continue
        if raw.startswith("/*", index):
            closing = raw.find("*/", index + 2)
            if closing < 0:
                return len(raw)
            index = closing + 2
            continue
        return index
    return index


def _literal_array_values(value: str | None) -> frozenset[str] | None:
    if value is None:
        return None
    array = re.fullmatch(r"\[([\s\S]*)\]", value)
    return _literal_policy_values(array.group(1)) if array else None


def _object_field_array(value: str | None, key: str) -> frozenset[str] | None:
    if value is None:
        return None
    object_match = re.fullmatch(r"\{([\s\S]*)\}", value)
    if object_match is None:
        return None
    fields = _top_level_object_fields(object_match.group(1))
    return _literal_array_values(fields.get(key)) if fields is not None else None


def _literal_policy_values(raw: str) -> frozenset[str] | None:
    if not re.fullmatch(r"\s*(?:['\"][A-Za-z0-9:-]+['\"]\s*(?:,\s*['\"][A-Za-z0-9:-]+['\"]\s*)*)?", raw):
        return None
    values = frozenset(re.findall(r"['\"]([A-Za-z0-9:-]+)['\"]", raw))
    return None if "*" in raw or "*" in values else values


def _audited_sanitizer_import(source: str) -> re.Match[str] | None:
    pattern = re.compile(rf"(?m)^\s*import\s+({_IDENTIFIER})\s+from\s+['\"]sanitize-html['\"]\s*;")
    for match in pattern.finditer(source):
        if _is_code_position(source, match.start()):
            return match
    return None


def _is_code_position(source: str, position: int) -> bool:
    index = 0
    while index < position:
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            closing = source.find("*/", index + 2)
            index = len(source) if closing < 0 else closing + 2
            continue
        if source[index] in {"'", '"'}:
            index = _skip_quoted(source, index)
            continue
        if source[index] == "`":
            index = _skip_template_literal(source, index)
            continue
        if source[index] == "/" and _looks_like_regex(source, index):
            index = _skip_regex(source, index)
            continue
        index += 1
    return index == position


def _static_tag(raw_before: str) -> str | None:
    match = re.search(rf"<({_IDENTIFIER})\b(?:\s+[^<>]*)?>?[^<>]*$", raw_before, re.IGNORECASE)
    return match.group(1).lower() if match else None


def _static_attribute(raw_before: str) -> str | None:
    match = re.search(rf"<({_IDENTIFIER})(?:\s+[^<>]*)?\s+({_IDENTIFIER}(?::{_IDENTIFIER})?)\s*=\s*['\"][^<>]*$", raw_before, re.IGNORECASE)
    return match.group(2).lower() if match else None


def _matching_code_brace(source: str, opening: int) -> int | None:
    depth = 0
    index = opening
    while index < len(source):
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            closing = source.find("*/", index + 2)
            if closing < 0:
                return None
            index = closing + 2
            continue
        if source[index] in {"'", '"'}:
            index = _skip_quoted(source, index)
            continue
        if source[index] == "`":
            index = _skip_template_literal(source, index)
            continue
        if source[index] == "/" and _looks_like_regex(source, index):
            index = _skip_regex(source, index)
            continue
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _skip_template_literal(source: str, opening: int) -> int:
    index = opening + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == "`":
            return index + 1
        if source.startswith("${", index):
            end = _skip_template_expression(source, index + 2)
            if end is None:
                return len(source)
            index = end + 1
            continue
        index += 1
    return len(source)


def _skip_template_expression(source: str, start: int) -> int | None:
    depth = 1
    index = start
    while index < len(source):
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            closing = source.find("*/", index + 2)
            if closing < 0:
                return None
            index = closing + 2
            continue
        if source[index] in {"'", '"'}:
            index = _skip_quoted(source, index)
            continue
        if source[index] == "`":
            index = _skip_template_literal(source, index)
            continue
        if source[index] == "/" and _looks_like_regex(source, index):
            index = _skip_regex(source, index)
            continue
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _skip_quoted(source: str, opening: int) -> int:
    quote = source[opening]
    index = opening + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == quote:
            return index + 1
        index += 1
    return len(source)


def _looks_like_regex(source: str, index: int) -> bool:
    previous = index - 1
    while previous >= 0 and source[previous].isspace():
        previous -= 1
    if previous < 0:
        return True
    character = source[previous]
    if character.isidentifier():
        start = previous
        while start > 0 and source[start - 1].isidentifier():
            start -= 1
        return source[start:previous + 1] in {"case", "delete", "do", "else", "return", "throw", "typeof", "void", "yield"}
    if character.isdigit() or character in ")]}`'\"":
        return False
    return True


def _skip_regex(source: str, opening: int) -> int:
    index = opening + 1
    in_class = False
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == "[":
            in_class = True
        elif source[index] == "]":
            in_class = False
        elif source[index] == "/" and not in_class:
            index += 1
            while index < len(source) and source[index].isalpha():
                index += 1
            return index
        index += 1
    return len(source)


def _line_number(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1
