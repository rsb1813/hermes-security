# Runs one HermesBench adapter command inside a constrained Docker container.

from __future__ import annotations

import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_DOCKER_CLI_TIMEOUT_SECONDS = 15
MAX_CONFIDENTIAL_STDIN_BYTES = 16 * 1024


class ContainerRuntimeError(RuntimeError):
    """Signals a Docker runtime boundary failure without exposing process output."""


class ContainerTimeoutError(TimeoutError):
    """Signals that the exact created container was stopped for timeout."""


class ContainerCleanupError(ContainerRuntimeError):
    """Signals that exact-container cleanup could not be confirmed."""


@dataclass(frozen=True)
class ContainerResult:
    """Contains adapter process bytes and the immutable image used for execution."""

    stdout: bytes
    stderr: bytes
    exit_code: int
    resolved_image_id: str


class ContainerRuntime:
    """Creates and removes one isolated Docker container for an adapter command."""

    def __init__(self, image_ref: str, docker_binary: str = "docker") -> None:
        self._image_ref = _require_text(image_ref, "image_ref")
        self._docker_binary = _require_text(docker_binary, "docker_binary")

    def execute(
        self,
        snapshot_path: Path,
        scratch_path: Path,
        plugin_path: Path | None,
        command_argv: Sequence[str],
        timeout_seconds: int,
        confidential_stdin: bytes | None = None,
    ) -> ContainerResult:
        """Runs command_argv with only read-only inputs and writable task scratch."""
        snapshot = _resolve_mount_source(snapshot_path, "snapshot path")
        scratch = _resolve_mount_source(scratch_path, "scratch path")
        plugin = (
            _resolve_mount_source(plugin_path, "plugin path") if plugin_path is not None else None
        )
        _assert_disjoint_mount_sources(snapshot, scratch, plugin)
        command = _require_command(command_argv)
        timeout = _require_timeout(timeout_seconds)
        confidential = _require_confidential_stdin(confidential_stdin)
        image_id = self._resolve_image_id()
        container_id = self._create(
            image_id,
            snapshot,
            scratch,
            plugin,
            command,
            interactive=confidential is not None,
        )
        process: subprocess.Popen[bytes] | None = None
        try:
            start_argv = [self._docker_binary, "start", "--attach"]
            if confidential is not None:
                start_argv.append("--interactive")
            start_argv.append(container_id)
            process = subprocess.Popen(
                start_argv,
                stdin=subprocess.PIPE if confidential is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except OSError as exc:
            cleanup_error = self._cleanup_container(container_id, None, stop_container=False)
            if cleanup_error is not None:
                raise cleanup_error from exc
            raise ContainerRuntimeError("Docker container start failed") from exc
        try:
            stdout, stderr = process.communicate(input=confidential, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            cleanup_error = self._cleanup_container(container_id, process, stop_container=True)
            if cleanup_error is not None:
                raise cleanup_error from exc
            raise ContainerTimeoutError("container execution timed out") from exc
        except KeyboardInterrupt as exc:
            cleanup_error = self._cleanup_container(container_id, process, stop_container=True)
            if cleanup_error is not None:
                raise cleanup_error from exc
            raise
        except Exception as exc:
            cleanup_error = self._cleanup_container(container_id, process, stop_container=True)
            if cleanup_error is not None:
                raise cleanup_error from exc
            raise ContainerRuntimeError("Docker container attach failed") from exc
        cleanup_error = self._cleanup_container(container_id, process, stop_container=False)
        if cleanup_error is not None:
            raise cleanup_error
        return ContainerResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=process.returncode,
            resolved_image_id=image_id,
        )

    def _resolve_image_id(self) -> str:
        completed = _run_docker(
            [self._docker_binary, "image", "inspect", "--format", "{{.Id}}", self._image_ref]
        )
        if completed.returncode != 0:
            raise ContainerRuntimeError("Docker image inspection failed")
        image_id = _decode_stdout(completed.stdout)
        if not _IMAGE_ID.fullmatch(image_id):
            raise ContainerRuntimeError("Docker image inspection did not return an immutable image ID")
        return image_id

    def _create(
        self,
        image_id: str,
        snapshot: Path,
        scratch: Path,
        plugin: Path | None,
        command: tuple[str, ...],
        interactive: bool = False,
    ) -> str:
        argv = [
            self._docker_binary,
            "create",
            "--read-only",
            "--user",
            "10001:10001",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--ipc",
            "private",
            "--cgroupns",
            "private",
            "--pids-limit",
            "128",
            "--memory",
            "512m",
            "--cpus",
            "1.0",
            "--shm-size",
            "64m",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
            "--init",
            "--network",
            "bridge",
            "--mount",
            _readonly_mount(snapshot, "/workspace/snapshot"),
        ]
        if interactive:
            argv.append("--interactive")
        if plugin is not None:
            argv.extend(["--mount", _readonly_mount(plugin, "/workspace/plugin")])
        argv.extend(
            [
                "--mount",
                _writable_mount(scratch, "/workspace/scratch"),
                "--workdir",
                "/workspace/scratch",
                image_id,
                *command,
            ]
        )
        completed = _run_docker(argv)
        if completed.returncode != 0:
            raise ContainerRuntimeError("Docker create failed")
        container_id = _decode_stdout(completed.stdout)
        if not _CONTAINER_ID.fullmatch(container_id):
            raise ContainerRuntimeError("Docker create did not return an exact container ID")
        return container_id

    def _kill_exact(self, container_id: str) -> None:
        completed = _run_docker([self._docker_binary, "kill", container_id])
        if completed.returncode != 0:
            raise ContainerCleanupError("Docker exact-container kill failed")

    def _remove_exact(self, container_id: str) -> None:
        completed = _run_docker([self._docker_binary, "rm", "--force", container_id])
        if completed.returncode != 0:
            raise ContainerCleanupError("Docker exact-container remove failed")

    def _cleanup_container(
        self,
        container_id: str,
        process: subprocess.Popen[bytes] | None,
        stop_container: bool,
    ) -> ContainerCleanupError | None:
        failures: list[str] = []
        if stop_container:
            _attempt_cleanup("kill", lambda: self._kill_exact(container_id), failures)
        if process is not None and stop_container:
            _attempt_cleanup("attach", lambda: _terminate_attach(process), failures)
        _attempt_cleanup("remove", lambda: self._remove_exact(container_id), failures)
        if failures:
            return ContainerCleanupError(f"Docker exact-container cleanup failed: {', '.join(failures)}")
        return None


def _run_docker(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            check=False,
            shell=False,
            timeout=_DOCKER_CLI_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise ContainerRuntimeError("Docker CLI command timed out") from exc


def _decode_stdout(value: bytes | str | None) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise ContainerRuntimeError("Docker returned invalid UTF-8") from exc
    if isinstance(value, str):
        return value.strip()
    return ""


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{name} must be a non-empty single-line string")
    return value


def _require_command(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not value:
        raise ValueError("command_argv must be a non-empty string sequence")
    return tuple(_require_text(token, "command argument") for token in value)


def _require_timeout(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("timeout_seconds must be a positive integer")
    return value


def _require_confidential_stdin(value: object) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, bytes) or not value or len(value) > MAX_CONFIDENTIAL_STDIN_BYTES:
        raise ValueError("confidential_stdin must be non-empty bytes when provided")
    return value


def _resolve_mount_source(value: Path, name: str) -> Path:
    if not isinstance(value, Path):
        raise ValueError(f"{name} must be a Path")
    try:
        original = value.absolute()
    except OSError as exc:
        raise ContainerRuntimeError(f"{name} cannot be inspected") from exc
    _assert_safe_path_components(original, name)
    try:
        resolved = value.resolve(strict=True)
    except OSError as exc:
        raise ContainerRuntimeError(f"{name} cannot be resolved") from exc
    if not resolved.is_dir():
        raise ContainerRuntimeError(f"{name} must be a directory")
    _assert_safe_path_components(resolved, name)
    if "," in str(resolved):
        raise ContainerRuntimeError(f"{name} cannot contain a comma")
    return resolved


def _assert_disjoint_mount_sources(snapshot: Path, scratch: Path, plugin: Path | None) -> None:
    sources = [("snapshot", snapshot), ("scratch", scratch)]
    if plugin is not None:
        sources.append(("plugin", plugin))
    for index, (left_name, left_path) in enumerate(sources):
        for right_name, right_path in sources[index + 1 :]:
            if _paths_overlap(left_path, right_path):
                raise ContainerRuntimeError(
                    f"container mount sources overlap: {left_name} and {right_name}"
                )


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _assert_safe_path_components(path: Path, name: str) -> None:
    for component in (path, *path.parents):
        try:
            metadata = os.lstat(component)
        except OSError as exc:
            raise ContainerRuntimeError(f"{name} cannot be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise ContainerRuntimeError(f"{name} contains a link or junction")


def _readonly_mount(source: Path, target: str) -> str:
    return f"type=bind,src={source},dst={target},readonly"


def _writable_mount(source: Path, target: str) -> str:
    return f"type=bind,src={source},dst={target}"


def _terminate_attach(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _attempt_cleanup(label: str, action: Callable[[], None], failures: list[str]) -> None:
    try:
        action()
    except KeyboardInterrupt:
        failures.append(label)
    except Exception:
        failures.append(label)
