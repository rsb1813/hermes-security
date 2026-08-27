# Audits agent-visible benchmark bundles for label leakage.

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

ADVISORY_PATTERN = re.compile(
    rb"(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2})",
    re.IGNORECASE,
)
ADVISORY_URL = b"github.com/advisories/"
_VCS_DIRECTORIES = frozenset({".git", ".hg", ".svn"})
_SCAN_CHUNK_SIZE = 1024 * 1024
_SCAN_OVERLAP = 128


class BundleAuditError(ValueError):
    """Signals a bundle that cannot be inspected safely."""


@dataclass(frozen=True, order=True)
class BundleViolation:
    code: str
    path: str


def audit_bundle(root: Path) -> tuple[BundleViolation, ...]:
    resolved = _resolve_bundle_root(root)
    violations: set[BundleViolation] = set()
    for path in _sorted_tree(resolved):
        relative_path = path.relative_to(resolved)
        relative = relative_path.as_posix()
        relative_bytes = relative.encode("utf-8", errors="surrogatepass")
        if _contains_advisory(relative_bytes):
            violations.add(BundleViolation("advisory_identifier", relative))
        if path.is_symlink():
            violations.add(BundleViolation("symbolic_link", relative))
            continue
        if any(part in _VCS_DIRECTORIES for part in relative_path.parts):
            if path.name == ".git":
                code = "git_metadata"
            elif path.name in _VCS_DIRECTORIES:
                code = "vcs_metadata"
            else:
                continue
            violations.add(BundleViolation(code, relative))
            continue
        if path.is_file() and _file_contains_advisory(path):
            violations.add(BundleViolation("advisory_identifier", relative))
    return tuple(sorted(violations))


def tree_sha256(root: Path) -> str:
    resolved = _resolve_bundle_root(root)
    digest = hashlib.sha256()
    for path in _sorted_tree(resolved):
        relative = path.relative_to(resolved).as_posix()
        if path.is_symlink():
            raise BundleAuditError(f"bundle contains a symbolic link: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise BundleAuditError(f"bundle contains a non-regular file: {relative}")
        digest.update(relative.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\x00")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(_SCAN_CHUNK_SIZE), b""):
                digest.update(chunk)
        digest.update(b"\x00")
    return digest.hexdigest()


def _resolve_bundle_root(root: Path) -> Path:
    if root.is_symlink():
        raise BundleAuditError(f"bundle root must not be a symbolic link: {root}")
    try:
        resolved = root.resolve(strict=True)
    except FileNotFoundError as error:
        raise BundleAuditError(f"bundle root must be an existing directory: {root}") from error
    if not resolved.is_dir():
        raise BundleAuditError(f"bundle root must be an existing directory: {root}")
    return resolved


def _sorted_tree(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix()))


def _file_contains_advisory(path: Path) -> bool:
    overlap = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_SCAN_CHUNK_SIZE), b""):
            window = overlap + chunk
            if _contains_advisory(window):
                return True
            overlap = window[-_SCAN_OVERLAP:]
    return False


def _contains_advisory(value: bytes) -> bool:
    return ADVISORY_PATTERN.search(value) is not None or ADVISORY_URL in value.lower()
