#!/usr/bin/env python3
# Feeds the pinned Codex external-auth payload through an unlinked private FIFO.

from __future__ import annotations

import argparse
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path


MAX_AUTH_BYTES = 16 * 1024
MAX_CHILD_STDERR_BYTES = 16 * 1024
_RETRY_SECONDS = 0.01
_READER_DEADLINE_SECONDS = 60.0
_CHILD_POLL_INTERVAL_SECONDS = 0.1
_CHILD_FAILURE_PREFIX = "hermesbench-child-category:"
_SETUP_FAILURE_PREFIX = "hermesbench-setup-stage:"
_READER_RECEIPT_PREFIX = "hermesbench-auth-readers:"
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
    """Drains child stderr while retaining only the bounded prefix used for classification."""

    def __init__(self, stream: object) -> None:
        self._stream = stream
        self._prefix = bytearray()
        self._thread = threading.Thread(target=self._drain, daemon=True)

    @property
    def prefix(self) -> bytes:
        """Returns the retained bounded stderr prefix without exposing it to wrapper output."""
        return bytes(self._prefix)

    def start(self) -> None:
        """Starts the dedicated stderr drain before the parent waits for the child."""
        self._thread.start()

    def join(self) -> None:
        """Waits for the stderr reader after the child closes its stream."""
        self._thread.join()

    def category(self) -> str:
        """Classifies the retained prefix using the fixed ASCII keyword priority."""
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


class AuthFifoFeeder:
    """Writes one payload per bounded Codex auth reader before removing the private FIFO."""

    def __init__(self, fifo_path: Path, payload: bytes, readers: int = 1) -> None:
        self._fifo_path = fifo_path
        self._payload = payload
        self._readers = _require_auth_readers(readers)
        self._cancelled = threading.Event()
        self._reader_condition = threading.Condition()
        self._readers_served = 0
        self._failed = False
        self._deadline = time.monotonic() + _READER_DEADLINE_SECONDS
        self._thread = threading.Thread(target=self._feed, daemon=True)
        self._thread.start()

    def wait_for_reader(self, timeout_seconds: float = 2.0) -> bool:
        """Returns whether a FIFO reader accepted the writer within the bounded wait."""
        return self.wait_for_readers(1, timeout_seconds)

    def wait_for_readers(self, count: int, timeout_seconds: float = _READER_DEADLINE_SECONDS) -> bool:
        """Returns whether exactly the requested bounded reader count received payloads."""
        if not isinstance(count, int) or count < 1 or count > self._readers:
            return False
        deadline = time.monotonic() + timeout_seconds
        with self._reader_condition:
            while self._readers_served < count and not self._failed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._reader_condition.wait(remaining)
            return self._readers_served >= count and not self._failed

    @property
    def failed(self) -> bool:
        """Reports a cancelled, deadline, or feeder error state without exposing payload data."""
        with self._reader_condition:
            return self._failed

    def cancel(self) -> None:
        """Stops the feeder and waits briefly for its private thread."""
        self._cancelled.set()
        self._thread.join(timeout=1)

    def _feed(self) -> None:
        try:
            writer_flags = os.O_WRONLY | os.O_NONBLOCK
        except AttributeError:
            self._mark_failed()
            return
        for reader_index in range(1, self._readers + 1):
            descriptor: int | None = None
            try:
                while not self._cancelled.is_set():
                    if time.monotonic() >= self._deadline:
                        self._mark_failed()
                        return
                    try:
                        descriptor = os.open(self._fifo_path, writer_flags)
                    except OSError as error:
                        if error.errno != errno.ENXIO:
                            self._mark_failed()
                            return
                        time.sleep(_RETRY_SECONDS)
                        continue
                    break
                if descriptor is None:
                    self._mark_failed()
                    return
                if reader_index == self._readers:
                    try:
                        self._fifo_path.unlink()
                    except FileNotFoundError:
                        self._mark_failed()
                        return
                if not _write_all(descriptor, self._payload, self._cancelled):
                    self._mark_failed()
                    return
                with self._reader_condition:
                    self._readers_served += 1
                    self._reader_condition.notify_all()
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        if self._readers_served != self._readers:
            self._mark_failed()

    def _mark_failed(self) -> None:
        with self._reader_condition:
            self._failed = True
            self._reader_condition.notify_all()


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
    """Validates the bounded identity envelope and returns only compact FIFO auth bytes."""
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


def write_installation_id(directory: Path, installation_id: str) -> None:
    """Writes one canonical installation identity into the private runtime directory."""
    value = _canonical_installation_id(installation_id).encode("ascii")
    descriptor = os.open(directory / "installation_id", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                raise OSError("installation identity write failed")
            offset += written
    finally:
        os.close(descriptor)
    os.chmod(directory / "installation_id", 0o600)


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


def start_auth_fifo(parent: Path, payload: bytes, readers: int = 1) -> tuple[Path, Path, AuthFifoFeeder]:
    """Creates a private FIFO under parent and starts one cancellable feeder."""
    validated = validate_auth_payload(payload)
    bounded_readers = _require_auth_readers(readers)
    directory = Path(tempfile.mkdtemp(prefix="hb-runtime-", dir=parent))
    os.chmod(directory, 0o700)
    fifo_path = directory / "auth.json"
    os.mkfifo(fifo_path, 0o600)
    os.chmod(fifo_path, 0o600)
    return directory, fifo_path, AuthFifoFeeder(fifo_path, validated, bounded_readers)


def main(argv: list[str]) -> int:
    """Runs one Codex child with standard input detached from the credential feeder."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--auth-readers")
    parser.add_argument("--reader-receipt", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    if arguments.auth_readers not in {"1", "2"}:
        sys.stderr.write(_setup_failure_token("setup_invalid_args"))
        return 2
    readers = int(arguments.auth_readers)
    command = arguments.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        sys.stderr.write(_setup_failure_token("setup_invalid_args"))
        return 2
    try:
        payload, installation_id = validate_auth_envelope(sys.stdin.buffer.read(MAX_AUTH_BYTES + 1))
    except ValueError:
        sys.stderr.write(_setup_failure_token("setup_invalid_payload"))
        return 2
    except OSError:
        sys.stderr.write(_setup_failure_token("setup_wrapper_os_error"))
        return 2
    directory: Path | None = None
    feeder: AuthFifoFeeder | None = None
    try:
        directory, _fifo_path, feeder = start_auth_fifo(Path("/tmp"), payload, readers)
        write_installation_id(directory, installation_id)
    except (OSError, ValueError):
        if feeder is not None:
            feeder.cancel()
        if directory is not None:
            shutil.rmtree(directory, ignore_errors=True)
        sys.stderr.write(_setup_failure_token("setup_fifo"))
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
        early_exit: int | None = None
        feeder_failed = False
        try:
            while not feeder.wait_for_readers(readers, timeout_seconds=_CHILD_POLL_INTERVAL_SECONDS):
                exit_code = child.poll()
                if exit_code is not None:
                    child.wait()
                    early_exit = exit_code
                    break
                if feeder.failed:
                    child.terminate()
                    child.wait()
                    feeder_failed = True
                    break
            if early_exit is None and not feeder_failed and arguments.reader_receipt:
                sys.stderr.write(_reader_receipt(readers))
            if early_exit is None and not feeder_failed:
                child.wait()
        finally:
            drainer.join()
            feeder.cancel()
        if early_exit is not None:
            if early_exit != 0:
                sys.stderr.write(
                    _child_failure_token(
                        _auth_replay_failure_category(
                            drainer.category(), replay_completed=False
                        )
                    )
                )
                return early_exit
            sys.stderr.write(_setup_failure_token("setup_child_zero_before_readers"))
            return 2
        if feeder_failed:
            sys.stderr.write(_setup_failure_token("setup_feeder"))
            return 2
        if child.returncode != 0:
            sys.stderr.write(
                _child_failure_token(
                    _auth_replay_failure_category(
                        drainer.category(), replay_completed=readers == 2
                    )
                )
            )
        return child.returncode
    except (OSError, subprocess.SubprocessError):
        sys.stderr.write(_setup_failure_token("setup_wrapper_os_error"))
        return 2
    finally:
        if feeder is not None:
            feeder.cancel()
        if directory is not None:
            shutil.rmtree(directory, ignore_errors=True)


def _write_all(descriptor: int, payload: bytes, cancelled: threading.Event) -> bool:
    offset = 0
    while offset < len(payload) and not cancelled.is_set():
        try:
            offset += os.write(descriptor, payload[offset:])
        except BlockingIOError:
            time.sleep(_RETRY_SECONDS)
        except OSError:
            return False
    return offset == len(payload)


def _child_failure_token(category: str) -> str:
    """Builds the fixed public wrapper token from one finite category."""
    return f"{_CHILD_FAILURE_PREFIX}{category}\n"


def _auth_replay_failure_category(category: str, replay_completed: bool) -> str:
    """Splits only unauthorized failures by the bounded second auth read."""
    if category != "auth_unauthorized":
        return category
    suffix = "after_replay" if replay_completed else "before_replay"
    return f"auth_unauthorized_{suffix}"


def _setup_failure_token(stage: str) -> str:
    """Builds the fixed public wrapper token for one setup failure stage."""
    return f"{_SETUP_FAILURE_PREFIX}{stage}\n"


def _require_auth_readers(value: object) -> int:
    """Accepts only the pinned auth loader counts supported by the wrapper."""
    if isinstance(value, bool) or not isinstance(value, int) or value not in {1, 2}:
        raise ValueError("auth readers are invalid")
    return value


def _reader_receipt(readers: int) -> str:
    """Builds the fixed diagnostic receipt after every requested reader received a payload."""
    return f"{_READER_RECEIPT_PREFIX}{readers}\n"


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
