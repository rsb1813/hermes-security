#!/usr/bin/env python3
# Runs pinned Codex with a private tmpfs-backed external authentication runtime.

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from pathlib import Path


MAX_AUTH_BYTES = 16 * 1024
MAX_CHILD_STDERR_BYTES = 16 * 1024
_CHILD_FAILURE_PREFIX = "hermesbench-child-category:"
_SETUP_FAILURE_PREFIX = "hermesbench-setup-stage:"
_CHILD_STDERR_CATEGORIES = (
    ("auth_unauthorized", (b"401", b"unauthorized")),
    ("auth_token_unavailable", (b"token data unavailable",)),
    ("auth_refresh", (b"refresh token",)),
    ("auth_not_logged_in", (b"not logged in", b"login required")),
    ("auth_account", (b"account mismatch",)),
    ("auth_other", (b"authentication failed", b"authentication error", b"failed to authenticate")),
    ("network", (b"network", b"connection", b"dns", b"socket", b"proxy", b"tls")),
    ("sandbox", (b"sandbox", b"landlock", b"seccomp")),
    ("filesystem", (b"filesystem", b"file not found", b"no such file", b"read-only file system", b"not a directory", b"permission denied")),
    ("configuration_cloud_auth_init", (b"failed to initialize cloud configuration authentication",)),
    ("configuration_cloud_auth_resolve", (b"failed to resolve cloud configuration authentication",)),
    ("configuration_bootstrap_load", (b"failed to load bootstrap configuration",)),
    ("configuration_load", (b"failed to load configuration",)),
    ("configuration_schema", (b"schema",)),
    ("configuration_cli_args", (b"invalid argument", b"unknown option")),
    ("configuration_other", (b"configuration", b"config", b"bootstrap")),
    ("resource", (b"memory", b"resource", b"quota", b"rate limit", b"timeout")),
    ("cli", (b"command not found", b"usage:", b"unknown command")),
    ("internal", (b"internal", b"panic", b"traceback", b"exception")),
)


class BoundedStderrDrainer:
    """Drains child stderr while retaining only a bounded prefix for classification."""

    def __init__(self, stream: object) -> None:
        self._stream = stream
        self._prefix = bytearray()
        self._thread = threading.Thread(target=self._drain, daemon=True)

    @property
    def prefix(self) -> bytes:
        """Returns the private bounded prefix without writing it to wrapper output."""
        return bytes(self._prefix)

    def start(self) -> None:
        """Starts the dedicated child stderr drain."""
        self._thread.start()

    def join(self) -> None:
        """Waits for the stderr drain after the child closes its stream."""
        self._thread.join()

    def category(self) -> str:
        """Classifies the retained prefix with the fixed ASCII category priority."""
        lowered = self.prefix.lower()
        for category, keywords in _CHILD_STDERR_CATEGORIES:
            if any(keyword in lowered for keyword in keywords):
                return category
        return "unknown"

    def _drain(self) -> None:
        reader = getattr(self._stream, "read", None)
        if not callable(reader):
            return
        try:
            while True:
                chunk = reader(4096)
                if not isinstance(chunk, bytes) or not chunk:
                    return
                remaining = MAX_CHILD_STDERR_BYTES - len(self._prefix)
                if remaining > 0:
                    self._prefix.extend(chunk[:remaining])
        except OSError:
            return


def validate_auth_payload(payload: bytes) -> bytes:
    """Validates the pinned minimal external-auth payload without retaining its fields."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_AUTH_BYTES:
        raise ValueError("authentication payload is invalid")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("authentication payload is invalid") from error
    if not isinstance(value, dict) or set(value) != {"auth_mode", "tokens", "last_refresh"}:
        raise ValueError("authentication payload is invalid")
    tokens = value.get("tokens")
    if value.get("auth_mode") != "chatgptAuthTokens" or not isinstance(tokens, dict):
        raise ValueError("authentication payload is invalid")
    if set(tokens) != {"id_token", "access_token", "refresh_token", "account_id"}:
        raise ValueError("authentication payload is invalid")
    if tokens.get("refresh_token") != "" or tokens.get("id_token") != tokens.get("access_token") or not all(
        isinstance(tokens.get(name), str) and tokens[name]
        for name in ("id_token", "access_token", "account_id")
    ):
        raise ValueError("authentication payload is invalid")
    if not isinstance(value.get("last_refresh"), str) or not value["last_refresh"]:
        raise ValueError("authentication payload is invalid")
    return payload


def validate_auth_envelope(payload: bytes) -> tuple[bytes, str]:
    """Validates the bounded auth envelope and returns compact auth bytes and identity."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_AUTH_BYTES:
        raise ValueError("authentication payload is invalid")
    try:
        envelope = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("authentication payload is invalid") from error
    if not isinstance(envelope, dict) or set(envelope) != {"auth", "installation_id"}:
        raise ValueError("authentication payload is invalid")
    try:
        installation_id = _canonical_installation_id(envelope["installation_id"])
        compact_auth = json.dumps(envelope["auth"], separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("authentication payload is invalid") from error
    return validate_auth_payload(compact_auth), installation_id


def start_auth_runtime(parent: Path, payload: bytes, installation_id: str) -> tuple[Path, Path]:
    """Creates a mode-0700 runtime with exclusive mode-0600 auth and identity files."""
    validated = validate_auth_payload(payload)
    identity = _canonical_installation_id(installation_id)
    directory = Path(tempfile.mkdtemp(prefix="hb-runtime-", dir=parent))
    try:
        os.chmod(directory, 0o700)
        auth_path = _write_private_file(directory, "auth.json", validated)
        _write_private_file(directory, "installation_id", identity.encode("ascii"))
        return directory, auth_path
    except (OSError, ValueError):
        remove_auth_runtime(directory)
        raise


def remove_auth_runtime(directory: Path) -> None:
    """Removes one wrapper-created private runtime after child completion."""
    shutil.rmtree(directory, ignore_errors=True)


def _write_private_file(directory: Path, name: str, value: bytes) -> Path:
    if not isinstance(value, bytes) or not value:
        raise ValueError("authentication payload is invalid")
    path = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                raise OSError("private file write failed")
            offset += written
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)
    return path


def _canonical_installation_id(value: object) -> str:
    """Accepts only the lowercase canonical UUID form used by Codex installations."""
    if not isinstance(value, str):
        raise ValueError("authentication payload is invalid")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as error:
        raise ValueError("authentication payload is invalid") from error
    if str(parsed) != value:
        raise ValueError("authentication payload is invalid")
    return value


def main(argv: list[str]) -> int:
    """Runs one Codex child after writing auth only inside the private tmpfs runtime."""
    if len(argv) < 2 or argv[0] != "--":
        sys.stderr.write(_setup_failure_token("setup_invalid_args"))
        return 2
    command = argv[1:]
    try:
        payload, installation_id = validate_auth_envelope(sys.stdin.buffer.read(MAX_AUTH_BYTES + 1))
    except ValueError:
        sys.stderr.write(_setup_failure_token("setup_invalid_payload"))
        return 2
    except OSError:
        sys.stderr.write(_setup_failure_token("setup_wrapper_os_error"))
        return 2
    directory: Path | None = None
    try:
        directory, _auth_path = start_auth_runtime(Path("/tmp"), payload, installation_id)
    except (OSError, ValueError):
        sys.stderr.write(_setup_failure_token("setup_auth_runtime"))
        return 2
    try:
        child_environment = dict(os.environ)
        child_environment["CODEX_HOME"] = str(directory)
        try:
            child = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=None,
                stderr=subprocess.PIPE,
                env=child_environment,
                shell=False,
            )
        except OSError:
            sys.stderr.write(_setup_failure_token("setup_child_start"))
            return 2
        drainer = BoundedStderrDrainer(child.stderr)
        drainer.start()
        try:
            child.wait()
        finally:
            drainer.join()
        if child.returncode != 0:
            sys.stderr.write(_child_failure_token(drainer.category()))
        return child.returncode
    except (OSError, subprocess.SubprocessError):
        sys.stderr.write(_setup_failure_token("setup_wrapper_os_error"))
        return 2
    finally:
        if directory is not None:
            remove_auth_runtime(directory)


def _child_failure_token(category: str) -> str:
    """Builds one fixed public wrapper token from a finite failure category."""
    return f"{_CHILD_FAILURE_PREFIX}{category}\n"


def _setup_failure_token(stage: str) -> str:
    """Builds one fixed public wrapper setup token."""
    return f"{_SETUP_FAILURE_PREFIX}{stage}\n"


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
