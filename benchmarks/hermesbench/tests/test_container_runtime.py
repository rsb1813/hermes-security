# Verifies the hardened Docker boundary used by HermesBench adapters.

from __future__ import annotations

import json
import hashlib
import os
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import benchmarks.hermesbench.container_runtime as container_runtime
from benchmarks.hermesbench.container_runtime import (
    ContainerRuntime,
    ContainerRuntimeError,
    ContainerTimeoutError,
)


IMAGE_ID = "sha256:" + "a" * 64
CONTAINER_ID = "b" * 64


class _AttachProcess:
    def __init__(self, outcome: object = (b"stdout", b"stderr")) -> None:
        self.outcome = outcome
        self.terminated = False
        self.returncode = 0

    def communicate(self, input: bytes | None = None, timeout: int | None = None) -> tuple[bytes, bytes]:
        self.stdin_bytes = input
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome  # type: ignore[return-value]

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: int) -> None:
        return None


class _InterruptingAttachProcess(_AttachProcess):
    def terminate(self) -> None:
        self.terminated = True
        raise KeyboardInterrupt()


def _completed(argv: list[str], stdout: bytes = b"", returncode: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=b"")


_DOCKER_BUILD_TIMEOUT_SECONDS = 180
_DOCKER_CONTROL_TIMEOUT_SECONDS = 30


def _run_live_docker(
    argv: list[str], *, timeout_seconds: int, operation: str
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            check=False,
            shell=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"Docker {operation} timed out") from exc
    if completed.returncode != 0:
        raise AssertionError(f"Docker {operation} failed")
    return completed


def _require_new_receipt_target(receipt_path: Path) -> None:
    absolute_target = receipt_path.absolute()
    for component in (absolute_target.parent, *absolute_target.parent.parents):
        try:
            metadata = os.lstat(component)
        except OSError as exc:
            raise AssertionError("Docker smoke receipt directory cannot be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode) or (
            getattr(metadata, "st_file_attributes", 0) & container_runtime._FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise AssertionError("Docker smoke receipt directory contains a link or junction")
    try:
        os.lstat(absolute_target)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AssertionError("Docker smoke receipt target cannot be inspected") from exc
    raise AssertionError("Docker smoke receipt target already exists")


def _publish_receipt(receipt_path: Path, receipt: dict[str, object], forbidden_values: tuple[str, ...]) -> None:
    _require_new_receipt_target(receipt_path)
    serialized = (json.dumps(receipt, sort_keys=True) + "\n").encode("utf-8")
    for forbidden_value in forbidden_values:
        if forbidden_value and forbidden_value.encode("utf-8") in serialized:
            raise AssertionError("Docker smoke receipt contains forbidden data")
    temporary_path = receipt_path.parent / f".{receipt_path.name}.{uuid.uuid4().hex}.tmp"
    try:
        with temporary_path.open("xb") as temporary_file:
            temporary_file.write(serialized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        _require_new_receipt_target(receipt_path)
        os.replace(temporary_path, receipt_path)
    except (Exception, KeyboardInterrupt):
        temporary_path.unlink(missing_ok=True)
        raise


class ContainerRuntimeTests(unittest.TestCase):
    def _paths(self, root: Path) -> tuple[Path, Path, Path]:
        snapshot = root / "snapshot"
        plugin = root / "plugin"
        scratch = root / "scratch"
        snapshot.mkdir()
        plugin.mkdir()
        scratch.mkdir()
        return snapshot, plugin, scratch

    def _docker_run(self, calls: list[tuple[list[str], dict[str, object]]]):
        def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            calls.append((argv, kwargs))
            if argv[1:4] == ["image", "inspect", "--format"]:
                return _completed(argv, (IMAGE_ID + "\n").encode("ascii"))
            if argv[1] == "create":
                return _completed(argv, (CONTAINER_ID + "\n").encode("ascii"))
            return _completed(argv)

        return fake_run

    def test_creates_a_hardened_container_with_only_task_mounts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []
            attach = _AttachProcess()
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=self._docker_run(calls)), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=attach
            ) as popen:
                result = ContainerRuntime("runtime:mutable").execute(
                    snapshot, scratch, plugin, ("python3", "-V"), 17
                )

            resolved_snapshot = str(snapshot.resolve())
            resolved_plugin = str(plugin.resolve())
            resolved_scratch = str(scratch.resolve())
            expected_create = [
                "docker", "create", "--read-only", "--user", "10001:10001", "--cap-drop", "ALL",
                "--security-opt", f"seccomp={container_runtime._SECCOMP_PROFILE_PATH.resolve()}",
                "--security-opt", "no-new-privileges:true", "--ipc", "private",
                "--cgroupns", "private", "--pids-limit", "128", "--memory", "512m", "--cpus", "1.0",
                "--shm-size", "64m", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
                "--init", "--network", "bridge",
                "--mount", f"type=bind,src={resolved_snapshot},dst=/workspace/snapshot,readonly",
                "--mount", f"type=bind,src={resolved_plugin},dst=/workspace/plugin,readonly",
                "--mount", f"type=bind,src={resolved_scratch},dst=/workspace/scratch",
                "--workdir", "/workspace/scratch", IMAGE_ID, "python3", "-V",
            ]
            self.assertEqual(calls[1][0], expected_create)
            self.assertNotIn("--pid", calls[1][0])
            self.assertEqual(calls[0][0], ["docker", "image", "inspect", "--format", "{{.Id}}", "runtime:mutable"])
            self.assertEqual(popen.call_args.args[0], ["docker", "start", "--attach", CONTAINER_ID])
            self.assertEqual(result.resolved_image_id, IMAGE_ID)
            self.assertEqual(result.stdout, b"stdout")
            self.assertEqual(result.stderr, b"stderr")
            self.assertEqual(calls[2][0], ["docker", "rm", "--force", CONTAINER_ID])
            for _argv, kwargs in calls:
                self.assertIs(kwargs["shell"], False)
            self.assertIs(popen.call_args.kwargs["shell"], False)

    def test_rejects_missing_tampered_or_linked_seccomp_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "seccomp.json"
            with patch.object(container_runtime, "_SECCOMP_PROFILE_PATH", profile):
                with self.assertRaisesRegex(ContainerRuntimeError, "cannot be inspected"):
                    container_runtime._resolve_seccomp_profile()
            profile.write_text('{"defaultAction":"SCMP_ACT_ERRNO"}', encoding="utf-8")
            expected_sha256 = hashlib.sha256(profile.read_bytes()).hexdigest()
            with patch.object(container_runtime, "_SECCOMP_PROFILE_PATH", profile), patch.object(
                container_runtime, "_SECCOMP_PROFILE_SHA256", expected_sha256
            ):
                self.assertEqual(container_runtime._resolve_seccomp_profile(), profile.resolve())

            profile.write_text('{"defaultAction":"SCMP_ACT_ALLOW"}', encoding="utf-8")
            with patch.object(container_runtime, "_SECCOMP_PROFILE_PATH", profile), patch.object(
                container_runtime, "_SECCOMP_PROFILE_SHA256", expected_sha256
            ):
                with self.assertRaisesRegex(ContainerRuntimeError, "seccomp profile is invalid"):
                    container_runtime._resolve_seccomp_profile()

            linked = root / "linked-seccomp.json"
            try:
                linked.symlink_to(profile)
            except OSError:
                self.skipTest("symbolic links are unavailable on this platform")
            with patch.object(container_runtime, "_SECCOMP_PROFILE_PATH", linked), patch.object(
                container_runtime, "_SECCOMP_PROFILE_SHA256", hashlib.sha256(profile.read_bytes()).hexdigest()
            ):
                with self.assertRaisesRegex(ContainerRuntimeError, "link or junction"):
                    container_runtime._resolve_seccomp_profile()

    def test_confidential_stdin_is_limited_to_interactive_attach(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []
            attach = _AttachProcess()
            secret = b'{"access_token":"secret-value","account_id":"account"}'
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=self._docker_run(calls)), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=attach
            ) as popen:
                result = ContainerRuntime("runtime:mutable").execute(
                    snapshot,
                    scratch,
                    plugin,
                    ("true",),
                    17,
                    confidential_stdin=secret,
                )

            self.assertEqual(popen.call_args.args[0], ["docker", "start", "--attach", "--interactive", CONTAINER_ID])
            self.assertIs(popen.call_args.kwargs["stdin"], subprocess.PIPE)
            self.assertEqual(attach.stdin_bytes, secret)
            self.assertEqual(result.stdout, b"stdout")
            self.assertIn("--interactive", calls[1][0])
            public_values = " ".join(token for argv, _kwargs in calls for token in argv)
            self.assertNotIn("secret-value", public_values)
            self.assertNotIn("secret-value", str(popen.call_args))

    def test_rejects_oversized_confidential_stdin_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run") as docker_run:
                with self.assertRaisesRegex(ValueError, "confidential_stdin"):
                    ContainerRuntime("runtime:mutable").execute(
                        snapshot,
                        scratch,
                        plugin,
                        ("true",),
                        17,
                        confidential_stdin=b"x" * (container_runtime.MAX_CONFIDENTIAL_STDIN_BYTES + 1),
                    )
            docker_run.assert_not_called()

    def test_confidential_stdin_never_enters_start_failure_or_cleanup_argv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []
            secret = b'{"access_token":"secret-value","account_id":"account"}'
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=self._docker_run(calls)), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", side_effect=OSError("attach failed")
            ) as popen:
                with self.assertRaisesRegex(ContainerRuntimeError, "start failed") as error:
                    ContainerRuntime("runtime:mutable").execute(
                        snapshot, scratch, plugin, ("true",), 17, confidential_stdin=secret
                    )
            self.assertNotIn("secret-value", str(error.exception))
            self.assertEqual(popen.call_args.args[0], ["docker", "start", "--attach", "--interactive", CONTAINER_ID])
            self.assertNotIn("secret-value", " ".join(token for argv, _kwargs in calls for token in argv))

    def test_does_not_expose_final_artifact_path_to_docker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []
            final_artifact_sentinel = "C:\\private\\final-artifact-oracle"
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=self._docker_run(calls)), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=_AttachProcess()
            ) as popen:
                ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)

            all_tokens = [token for argv, _kwargs in calls for token in argv]
            all_tokens.extend(popen.call_args.args[0])
            self.assertNotIn(final_artifact_sentinel, all_tokens)
            self.assertNotIn(final_artifact_sentinel, str(popen.call_args.kwargs.get("cwd")))
            self.assertNotIn(final_artifact_sentinel, str(popen.call_args.kwargs.get("env")))

    def test_rejects_every_resolved_mount_overlap_before_docker_invocation(self) -> None:
        cases = (
            ("scratch equals snapshot", "snapshot", "plugin", "snapshot"),
            ("scratch is below snapshot", "snapshot", "plugin", "snapshot/scratch"),
            ("scratch contains snapshot", "scratch/snapshot", "plugin", "scratch"),
            ("plugin equals snapshot", "snapshot", "snapshot", "scratch"),
            ("plugin is below snapshot", "snapshot", "snapshot/plugin", "scratch"),
            ("plugin contains snapshot", "plugin/snapshot", "plugin", "scratch"),
            ("scratch equals plugin", "snapshot", "plugin", "plugin"),
            ("scratch is below plugin", "snapshot", "plugin", "plugin/scratch"),
            ("scratch contains plugin", "snapshot", "scratch/plugin", "scratch"),
        )
        for label, snapshot_name, plugin_name, scratch_name in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                snapshot = root / snapshot_name
                plugin = root / plugin_name
                scratch = root / scratch_name
                snapshot.mkdir(parents=True, exist_ok=True)
                plugin.mkdir(parents=True, exist_ok=True)
                scratch.mkdir(parents=True, exist_ok=True)
                with patch("benchmarks.hermesbench.container_runtime.subprocess.run") as docker_run:
                    with self.assertRaisesRegex(ContainerRuntimeError, "overlap"):
                        ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)
                docker_run.assert_not_called()

    def test_rejects_linked_original_mount_source_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            linked_source = root / "linked-source"
            plugin = root / "plugin"
            scratch = root / "scratch"
            target.mkdir()
            plugin.mkdir()
            scratch.mkdir()
            real_resolve = Path.resolve
            real_lstat = os.lstat

            def resolved_path(path: Path, strict: bool = False) -> Path:
                if path == linked_source:
                    return target
                return real_resolve(path, strict=strict)

            def linked_lstat(path: Path) -> os.stat_result:
                if path == linked_source.absolute():
                    return os.stat_result((stat.S_IFLNK,) + (0,) * 9)
                return real_lstat(path)

            with patch.object(Path, "resolve", autospec=True, side_effect=resolved_path), patch.object(
                container_runtime.os, "lstat", side_effect=linked_lstat
            ), patch("benchmarks.hermesbench.container_runtime.subprocess.run") as docker_run:
                with self.assertRaisesRegex(ContainerRuntimeError, "link or junction"):
                    ContainerRuntime("runtime:mutable").execute(linked_source, scratch, plugin, ("true",), 17)
            docker_run.assert_not_called()

    def test_rejects_original_mount_inspection_error_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            unresolved_source = root / "unresolved-source"
            plugin = root / "plugin"
            scratch = root / "scratch"
            target.mkdir()
            plugin.mkdir()
            scratch.mkdir()
            real_resolve = Path.resolve
            real_lstat = os.lstat

            def resolved_path(path: Path, strict: bool = False) -> Path:
                if path == unresolved_source:
                    return target
                return real_resolve(path, strict=strict)

            def denied_lstat(path: Path) -> os.stat_result:
                if path == unresolved_source.absolute():
                    raise OSError("denied")
                return real_lstat(path)

            with patch.object(Path, "resolve", autospec=True, side_effect=resolved_path), patch.object(
                container_runtime.os, "lstat", side_effect=denied_lstat
            ), patch("benchmarks.hermesbench.container_runtime.subprocess.run") as docker_run:
                with self.assertRaisesRegex(ContainerRuntimeError, "cannot be inspected"):
                    ContainerRuntime("runtime:mutable").execute(unresolved_source, scratch, plugin, ("true",), 17)
            docker_run.assert_not_called()

    def test_rejects_unresolved_or_malicious_ids_without_starting_a_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            with patch(
                "benchmarks.hermesbench.container_runtime.subprocess.run",
                return_value=_completed(["docker"], b"sha256:" + b"a" * 63 + b"\n"),
            ), patch("benchmarks.hermesbench.container_runtime.subprocess.Popen") as popen:
                with self.assertRaisesRegex(ContainerRuntimeError, "immutable"):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)
            popen.assert_not_called()

            calls: list[tuple[list[str], dict[str, object]]] = []
            def malformed_create(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                calls.append((argv, kwargs))
                if argv[1:4] == ["image", "inspect", "--format"]:
                    return _completed(argv, (IMAGE_ID + "\n").encode("ascii"))
                return _completed(argv, (CONTAINER_ID + "\nextra").encode("ascii"))

            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=malformed_create), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen"
            ) as popen:
                with self.assertRaisesRegex(ContainerRuntimeError, "container ID"):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)
            popen.assert_not_called()
            self.assertEqual(len(calls), 2)

    def test_rejects_image_inspect_failure_and_newline_input_before_container_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            with patch(
                "benchmarks.hermesbench.container_runtime.subprocess.run",
                return_value=_completed(["docker"], returncode=1),
            ), patch("benchmarks.hermesbench.container_runtime.subprocess.Popen") as popen:
                with self.assertRaisesRegex(ContainerRuntimeError, "inspection"):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)
            popen.assert_not_called()
            with self.assertRaisesRegex(ValueError, "single-line"):
                ContainerRuntime("runtime:mutable\nother")

    def test_nonzero_container_exit_still_removes_the_exact_created_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []
            attach = _AttachProcess()
            attach.returncode = 23
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=self._docker_run(calls)), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=attach
            ):
                result = ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("false",), 17)

            self.assertEqual(result.exit_code, 23)
            self.assertEqual(calls[2][0], ["docker", "rm", "--force", CONTAINER_ID])

    def test_timeout_kills_terminates_and_removes_only_the_created_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []
            attach = _AttachProcess(subprocess.TimeoutExpired(["docker"], 17))
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=self._docker_run(calls)), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=attach
            ):
                with self.assertRaises(ContainerTimeoutError):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)

            self.assertTrue(attach.terminated)
            self.assertEqual(calls[2][0], ["docker", "kill", CONTAINER_ID])
            self.assertEqual(calls[3][0], ["docker", "rm", "--force", CONTAINER_ID])

    def test_keyboard_interrupt_kills_and_removes_only_the_created_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []
            attach = _AttachProcess(KeyboardInterrupt())
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=self._docker_run(calls)), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=attach
            ):
                with self.assertRaises(KeyboardInterrupt):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)

            self.assertTrue(attach.terminated)
            self.assertEqual(calls[2][0], ["docker", "kill", CONTAINER_ID])
            self.assertEqual(calls[3][0], ["docker", "rm", "--force", CONTAINER_ID])

    def test_create_and_start_failures_remove_only_a_valid_created_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            create_calls: list[tuple[list[str], dict[str, object]]] = []
            def create_failure(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                create_calls.append((argv, kwargs))
                if argv[1:4] == ["image", "inspect", "--format"]:
                    return _completed(argv, (IMAGE_ID + "\n").encode("ascii"))
                return _completed(argv, b"", returncode=1)

            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=create_failure), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen"
            ):
                with self.assertRaisesRegex(ContainerRuntimeError, "create"):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)
            self.assertEqual(len(create_calls), 2)

            start_calls: list[tuple[list[str], dict[str, object]]] = []
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=self._docker_run(start_calls)), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", side_effect=OSError("cannot attach")
            ):
                with self.assertRaisesRegex(ContainerRuntimeError, "start"):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)
            self.assertEqual(start_calls[2][0], ["docker", "rm", "--force", CONTAINER_ID])

    def test_docker_lifecycle_calls_use_a_bounded_cli_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=self._docker_run(calls)), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=_AttachProcess()
            ):
                ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)

            for _argv, kwargs in calls:
                self.assertGreater(kwargs["timeout"], 0)
                self.assertLessEqual(kwargs["timeout"], 30)

    def test_normal_result_is_not_returned_when_exact_remove_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []

            def remove_failure(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                calls.append((argv, kwargs))
                if argv[1] == "rm":
                    return _completed(argv, returncode=1)
                return self._docker_run([])(argv, **kwargs)

            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=remove_failure), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=_AttachProcess()
            ):
                with self.assertRaises(container_runtime.ContainerCleanupError):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)
            self.assertEqual(calls[-1][0], ["docker", "rm", "--force", CONTAINER_ID])

    def test_timeout_attempts_remove_after_kill_failure_and_reports_cleanup_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []

            def kill_failure(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                calls.append((argv, kwargs))
                if argv[1] == "kill":
                    return _completed(argv, returncode=1)
                return self._docker_run([])(argv, **kwargs)

            attach = _AttachProcess(subprocess.TimeoutExpired(["docker"], 17))
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=kill_failure), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=attach
            ):
                with self.assertRaises(container_runtime.ContainerCleanupError):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)
            self.assertTrue(attach.terminated)
            self.assertEqual(calls[-2][0], ["docker", "kill", CONTAINER_ID])
            self.assertEqual(calls[-1][0], ["docker", "rm", "--force", CONTAINER_ID])

    def test_cleanup_cli_timeout_is_not_reported_as_a_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)

            def remove_timeout(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                if argv[1] == "rm":
                    raise subprocess.TimeoutExpired(argv, 10)
                return self._docker_run([])(argv, **kwargs)

            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=remove_timeout), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=_AttachProcess()
            ):
                with self.assertRaises(container_runtime.ContainerCleanupError):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)

    def test_interrupt_during_kill_still_terminates_attach_and_removes_exact_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []

            def kill_interrupt(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                calls.append((argv, kwargs))
                if argv[1] == "kill":
                    raise KeyboardInterrupt()
                return self._docker_run([])(argv, **kwargs)

            attach = _AttachProcess(KeyboardInterrupt())
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=kill_interrupt), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=attach
            ):
                with self.assertRaises(container_runtime.ContainerCleanupError):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)

            self.assertTrue(attach.terminated)
            self.assertEqual(calls[-2][0], ["docker", "kill", CONTAINER_ID])
            self.assertEqual(calls[-1][0], ["docker", "rm", "--force", CONTAINER_ID])

    def test_interrupt_during_attach_termination_still_removes_exact_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)
            calls: list[tuple[list[str], dict[str, object]]] = []
            attach = _InterruptingAttachProcess(KeyboardInterrupt())
            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=self._docker_run(calls)), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=attach
            ):
                with self.assertRaises(container_runtime.ContainerCleanupError):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)

            self.assertTrue(attach.terminated)
            self.assertEqual(calls[-2][0], ["docker", "kill", CONTAINER_ID])
            self.assertEqual(calls[-1][0], ["docker", "rm", "--force", CONTAINER_ID])

    def test_interrupt_during_normal_remove_is_not_reported_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, plugin, scratch = self._paths(root)

            def remove_interrupt(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                if argv[1] == "rm":
                    raise KeyboardInterrupt()
                return self._docker_run([])(argv, **kwargs)

            with patch("benchmarks.hermesbench.container_runtime.subprocess.run", side_effect=remove_interrupt), patch(
                "benchmarks.hermesbench.container_runtime.subprocess.Popen", return_value=_AttachProcess()
            ):
                with self.assertRaises(container_runtime.ContainerCleanupError):
                    ContainerRuntime("runtime:mutable").execute(snapshot, scratch, plugin, ("true",), 17)

    def test_cleanup_does_not_swallow_system_exit(self) -> None:
        failures: list[str] = []

        def exit_action() -> None:
            raise SystemExit()

        with self.assertRaises(SystemExit):
            container_runtime._attempt_cleanup("remove", exit_action, failures)
        self.assertEqual(failures, [])


class LiveSmokeReceiptTests(unittest.TestCase):
    def test_existing_receipt_target_is_rejected_without_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipt.json"
            receipt_path.write_text("stale", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "already exists"):
                _require_new_receipt_target(receipt_path)
            self.assertEqual(receipt_path.read_text(encoding="utf-8"), "stale")

    def test_dangling_receipt_link_is_rejected_by_lstat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipt.json"
            real_lstat = os.lstat

            def dangling_link(path: os.PathLike[str] | str) -> os.stat_result:
                if Path(path) == receipt_path.absolute():
                    return os.stat_result((stat.S_IFLNK,) + (0,) * 9)
                return real_lstat(path)

            with patch(__name__ + ".os.lstat", side_effect=dangling_link):
                with self.assertRaisesRegex(AssertionError, "already exists"):
                    _require_new_receipt_target(receipt_path)

    def test_existing_dangling_receipt_symlink_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipt.json"
            try:
                receipt_path.symlink_to(Path(directory) / "missing-target")
            except OSError:
                self.skipTest("the platform does not permit symlink creation")
            with self.assertRaisesRegex(AssertionError, "already exists"):
                _require_new_receipt_target(receipt_path)

    def test_receipt_parent_reparse_and_target_inspection_errors_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipt.json"
            real_lstat = os.lstat

            class _ReparseMetadata:
                st_mode = stat.S_IFDIR
                st_file_attributes = container_runtime._FILE_ATTRIBUTE_REPARSE_POINT

            def reparse_parent(path: os.PathLike[str] | str) -> os.stat_result | _ReparseMetadata:
                if Path(path) == receipt_path.parent.absolute():
                    return _ReparseMetadata()
                return real_lstat(path)

            with patch(__name__ + ".os.lstat", side_effect=reparse_parent):
                with self.assertRaisesRegex(AssertionError, "link or junction"):
                    _require_new_receipt_target(receipt_path)

            def denied_target(path: os.PathLike[str] | str) -> os.stat_result:
                if Path(path) == receipt_path.absolute():
                    raise OSError("denied")
                return real_lstat(path)

            with patch(__name__ + ".os.lstat", side_effect=denied_target):
                with self.assertRaisesRegex(AssertionError, "cannot be inspected"):
                    _require_new_receipt_target(receipt_path)

    def test_receipt_publish_checks_forbidden_data_and_writes_a_complete_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipt.json"
            receipt = {"schema_version": 1, "status": "passed"}
            _publish_receipt(receipt_path, receipt, ("/host/mount", "container-id", "private"))
            self.assertEqual(json.loads(receipt_path.read_text(encoding="utf-8")), receipt)
            self.assertFalse(list(Path(directory).glob("*.tmp")))
            with self.assertRaisesRegex(AssertionError, "forbidden"):
                _publish_receipt(Path(directory) / "bad.json", {"path": "/host/mount"}, ("/host/mount",))

    def test_receipt_publish_rechecks_the_target_before_atomic_replace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipt.json"
            with patch(
                __name__ + "._require_new_receipt_target",
                side_effect=(None, AssertionError("Docker smoke receipt target already exists")),
            ) as require_target:
                with self.assertRaisesRegex(AssertionError, "already exists"):
                    _publish_receipt(receipt_path, {"schema_version": 1}, ())
            self.assertEqual(require_target.call_count, 2)
            self.assertFalse(receipt_path.exists())

    def test_live_docker_call_fails_for_nonzero_and_timeout(self) -> None:
        with patch(__name__ + ".subprocess.run", return_value=_completed(["docker"], returncode=1)):
            with self.assertRaisesRegex(AssertionError, "failed"):
                _run_live_docker(["docker", "version"], timeout_seconds=1, operation="version")
        with patch(__name__ + ".subprocess.run", side_effect=subprocess.TimeoutExpired(["docker"], 1)):
            with self.assertRaisesRegex(AssertionError, "timed out"):
                _run_live_docker(["docker", "version"], timeout_seconds=1, operation="version")

    def test_live_docker_call_uses_argv_shell_false_and_the_requested_timeout(self) -> None:
        with patch(__name__ + ".subprocess.run", return_value=_completed(["docker", "version"])) as docker_run:
            _run_live_docker(["docker", "version"], timeout_seconds=7, operation="version")
        self.assertEqual(docker_run.call_args.args[0], ["docker", "version"])
        self.assertIs(docker_run.call_args.kwargs["shell"], False)
        self.assertEqual(docker_run.call_args.kwargs["timeout"], 7)


@unittest.skipUnless(
    os.environ.get("HERMESBENCH_RUN_DOCKER_SMOKE") == "1",
    "set HERMESBENCH_RUN_DOCKER_SMOKE=1 to run the Docker isolation smoke",
)
class DockerIsolationSmokeTests(unittest.TestCase):
    def test_runtime_image_enforces_the_live_boundary(self) -> None:
        runtime_directory = Path(__file__).parents[1] / "containers"
        image_ref = f"hermesbench-runtime-task4-smoke:{os.getpid()}"
        receipt_path_value = os.environ.get("HERMESBENCH_DOCKER_RECEIPT_PATH")
        if not receipt_path_value:
            self.fail("HERMESBENCH_DOCKER_RECEIPT_PATH is required for the Docker isolation smoke")
        receipt_path = Path(receipt_path_value)
        _require_new_receipt_target(receipt_path)
        build_succeeded = False
        resolved_image_id: str | None = None
        docker_server: str | None = None
        receipt_forbidden_values: tuple[str, ...] | None = None
        try:
            _run_live_docker(
                ["docker", "build", "-f", str(runtime_directory / "Dockerfile"), "-t", image_ref, str(runtime_directory.parent)],
                timeout_seconds=_DOCKER_BUILD_TIMEOUT_SECONDS,
                operation="runtime image build",
            )
            build_succeeded = True
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                snapshot, plugin, scratch = ContainerRuntimeTests()._paths(root)
                (snapshot / "source.py").write_text("value = 1\n", encoding="utf-8")
                (plugin / "plugin.txt").write_text("plugin\n", encoding="utf-8")
                final_artifact_root = root / "final-artifact-oracle"
                final_artifact_root.mkdir()
                runtime = ContainerRuntime(image_ref)

                self.assertNotEqual(
                    runtime.execute(snapshot, scratch, plugin, ("python3", "-c", "from pathlib import Path; Path('/workspace/snapshot/new').write_text('x')"), 20).exit_code,
                    0,
                )
                self.assertNotEqual(
                    runtime.execute(snapshot, scratch, plugin, ("python3", "-c", "from pathlib import Path; Path('/workspace/plugin/new').write_text('x')"), 20).exit_code,
                    0,
                )
                self.assertNotEqual(
                    runtime.execute(snapshot, scratch, plugin, ("python3", "-c", "from pathlib import Path; Path('/rootfs-write').write_text('x')"), 20).exit_code,
                    0,
                )
                self.assertEqual(
                    runtime.execute(snapshot, scratch, plugin, ("python3", "-c", "from pathlib import Path; Path('/workspace/scratch/wrote').write_text('ok')"), 20).exit_code,
                    0,
                )
                self.assertEqual((scratch / "wrote").read_text(encoding="utf-8"), "ok")
                self.assertEqual(
                    runtime.execute(snapshot, scratch, plugin, ("python3", "-c", "from pathlib import Path; raise SystemExit(Path('/var/run/docker.sock').exists())"), 20).exit_code,
                    0,
                )

                with _local_sentinel() as (host, port, connected):
                    direct = runtime.execute(
                        snapshot,
                        scratch,
                        plugin,
                        ("python3", "-c", f"import socket; socket.create_connection(({host!r}, {port}), timeout=3).close()"),
                        20,
                    )
                    self.assertEqual(direct.exit_code, 0)
                    self.assertTrue(connected.wait(3), "outer container could not reach the host sentinel")

                sandbox_state = json.dumps(
                    {
                        "permissionProfile": {
                            "type": "managed",
                            "file_system": {"type": "unrestricted"},
                            "network": "restricted",
                        },
                        "codexLinuxSandboxExe": None,
                        "sandboxCwd": "file:///workspace/scratch",
                        "useLegacyLandlock": False,
                    },
                    separators=(",", ":"),
                )
                with _local_sentinel() as (host, port, connected):
                    started_marker = scratch / "sandbox-child-started"
                    blocked_marker = scratch / "sandbox-network-blocked"
                    unexpected_marker = scratch / "sandbox-network-unexpected"
                    sandbox_program = "\n".join(
                        (
                            "from pathlib import Path",
                            "import socket",
                            "scratch = Path('/workspace/scratch')",
                            "(scratch / 'sandbox-child-started').write_text('started')",
                            "try:",
                            f"    socket.create_connection(({host!r}, {port}), timeout=3).close()",
                            "except OSError:",
                            "    (scratch / 'sandbox-network-blocked').write_text('blocked')",
                            "    raise SystemExit(0)",
                            "(scratch / 'sandbox-network-unexpected').write_text('connected')",
                            "raise SystemExit(71)",
                        )
                    )
                    sandbox_payload = f"exec({sandbox_program!r})"
                    sandboxed = runtime.execute(
                        snapshot,
                        scratch,
                        plugin,
                        (
                            "codex", "sandbox", "--sandbox-state-json", sandbox_state,
                            "--sandbox-state-disable-network", "--", "python3", "-c",
                            sandbox_payload,
                        ),
                        20,
                    )
                    self.assertEqual(sandboxed.exit_code, 0)
                    self.assertEqual(started_marker.read_text(encoding="utf-8"), "started")
                    self.assertEqual(blocked_marker.read_text(encoding="utf-8"), "blocked")
                    self.assertFalse(unexpected_marker.exists())
                    self.assertFalse(connected.wait(1), "sandboxed child reached the host sentinel")

                image_id = runtime._resolve_image_id()
                container_id = runtime._create(
                    image_id,
                    snapshot.resolve(),
                    scratch.resolve(),
                    plugin.resolve(),
                    ("sleep", "10"),
                )
                try:
                    inspection = _run_live_docker(
                        ["docker", "inspect", container_id],
                        timeout_seconds=_DOCKER_CONTROL_TIMEOUT_SECONDS,
                        operation="exact-ID container inspection",
                    )
                    inspected = json.loads(inspection.stdout)[0]
                    self.assertNotEqual(inspected["HostConfig"]["NetworkMode"], "none")
                    self.assertTrue(inspected["HostConfig"]["ReadonlyRootfs"])
                    self.assertEqual(inspected["Config"]["User"], "10001:10001")
                    self.assertIn("ALL", inspected["HostConfig"]["CapDrop"])
                    self.assertIn("no-new-privileges:true", inspected["HostConfig"]["SecurityOpt"])
                    self.assertEqual(inspected["HostConfig"]["IpcMode"], "private")
                    self.assertEqual(inspected["HostConfig"]["CgroupnsMode"], "private")
                    self.assertNotEqual(inspected["HostConfig"]["PidMode"], "host")
                    self.assertEqual(inspected["HostConfig"]["PidsLimit"], 128)
                    self.assertFalse(inspected["HostConfig"]["Privileged"])
                    mounts = {mount["Destination"]: mount for mount in inspected["Mounts"]}
                    self.assertFalse(mounts["/workspace/snapshot"]["RW"])
                    self.assertFalse(mounts["/workspace/plugin"]["RW"])
                    self.assertTrue(mounts["/workspace/scratch"]["RW"])
                    self.assertNotIn(final_artifact_root.name, json.dumps(inspected))
                    self.assertNotIn("/var/run/docker.sock", json.dumps(inspected))
                    docker_version = _run_live_docker(
                        ["docker", "version", "--format", "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}"],
                        timeout_seconds=_DOCKER_CONTROL_TIMEOUT_SECONDS,
                        operation="server version inspection",
                    )
                    resolved_image_id = image_id
                    docker_server = docker_version.stdout.decode("utf-8", errors="strict").strip()
                    receipt_forbidden_values = (
                        str(root.resolve()),
                        str(snapshot.resolve()),
                        str(plugin.resolve()),
                        str(scratch.resolve()),
                        str(final_artifact_root.resolve()),
                        final_artifact_root.name,
                        container_id,
                        "oracle",
                        "private",
                    )
                finally:
                    _run_live_docker(
                        ["docker", "rm", "--force", container_id],
                        timeout_seconds=_DOCKER_CONTROL_TIMEOUT_SECONDS,
                        operation="exact-ID container removal",
                    )
        finally:
            if build_succeeded:
                _run_live_docker(
                    ["docker", "image", "rm", "--force", image_ref],
                    timeout_seconds=_DOCKER_CONTROL_TIMEOUT_SECONDS,
                    operation="smoke image removal",
                )
        if resolved_image_id is None or docker_server is None or receipt_forbidden_values is None:
            raise AssertionError("Docker smoke did not collect complete receipt evidence")
        receipt = {
            "schema_version": 1,
            "task": "HermesBench Task 4 Docker isolation smoke",
            "image_ref": image_ref,
            "resolved_image_id": resolved_image_id,
            "docker_server": docker_server,
            "observations": {
                "snapshot_write_rejected": True,
                "plugin_write_rejected": True,
                "root_filesystem_write_rejected": True,
                "scratch_write_succeeded": True,
                "docker_socket_absent": True,
                "outer_network_mode_is_not_none": True,
                "outer_container_reached_host_local_sentinel": True,
                "codex_sandbox_child_started": True,
                "codex_sandbox_child_host_local_sentinel_rejected": True,
                "host_pid_namespace_absent": True,
                "inspect_has_only_snapshot_plugin_and_scratch_mounts": True,
                "snapshot_and_plugin_mounts_read_only": True,
                "scratch_mount_writable": True,
                "final_artifact_root_absent": True,
            },
        }
        _publish_receipt(
            receipt_path,
            receipt,
            receipt_forbidden_values,
        )

    def test_named_permission_profile_denies_auth_source_writes_and_network(self) -> None:
        image_ref = "hermesbench-runtime-task5-local:latest"
        with tempfile.TemporaryDirectory() as directory, _local_sentinel() as (host, port, connected):
            root = Path(directory)
            snapshot, plugin, scratch = ContainerRuntimeTests()._paths(root)
            (snapshot / "source.py").write_text("value = 1\n", encoding="utf-8")
            (scratch / "mount-target").mkdir()
            child = plugin / "assert_named_permissions.py"
            child.write_text(
                "\n".join(
                    (
                        "import socket",
                        "from pathlib import Path",
                        "scratch = Path('/workspace/scratch')",
                        "Path('/workspace/snapshot/source.py').read_text(encoding='utf-8')",
                        "Path('/workspace/plugin/launch-sandbox.sh').read_text(encoding='utf-8')",
                        "(scratch / 'named-profile-scratch-write').write_text('ok', encoding='utf-8')",
                        "def denied(marker, operation):",
                        "    try:",
                        "        operation()",
                        "    except OSError:",
                        "        (scratch / marker).write_text('denied', encoding='utf-8')",
                        "        return",
                        "    raise SystemExit(marker)",
                        "denied('named-profile-snapshot-write-denied', lambda: Path('/workspace/snapshot/new').write_text('x'))",
                        "denied('named-profile-plugin-write-denied', lambda: Path('/workspace/plugin/new').write_text('x'))",
                        "denied('named-profile-root-write-denied', lambda: Path('/usr/local/bin/hb-root-write').write_text('x'))",
                        "denied('named-profile-auth-direct-denied', lambda: Path('/tmp/hb-runtime-sentinel/auth.json').read_text())",
                        "denied('named-profile-auth-dotdot-denied', lambda: Path('/tmp/hb-runtime-sentinel/../hb-runtime-sentinel/auth.json').read_text())",
                        f"denied('named-profile-network-denied', lambda: socket.create_connection(({host!r}, {port}), timeout=2).close())",
                    )
                ) + "\n",
                encoding="utf-8",
            )
            launcher = plugin / "launch-sandbox.sh"
            launcher.write_bytes(
                "\n".join(
                    (
                        "#!/bin/sh",
                        "set -eu",
                        "mkdir -p /tmp/hb-runtime-sentinel",
                        "printf sentinel > /tmp/hb-runtime-sentinel/auth.json",
                        "exec codex sandbox -c 'permissions.hermesbench={filesystem={\":minimal\"=\"read\",\"/workspace/snapshot\"=\"read\",\"/workspace/plugin\"=\"read\",\"/workspace/scratch\"=\"write\",\"/tmp/hb-runtime-*\"=\"deny\"},network={enabled=false}}' -c 'default_permissions=\"hermesbench\"' -P hermesbench -C /workspace/scratch -- python3 /workspace/plugin/assert_named_permissions.py",
                    )
                ).encode("utf-8") + b"\n",
            )
            runtime = ContainerRuntime(image_ref)
            self.assertEqual(
                runtime.execute(snapshot, scratch, plugin, ("unshare", "--user", "--map-root-user", "/bin/true"), 20).exit_code,
                0,
            )
            self.assertNotEqual(
                runtime.execute(snapshot, scratch, plugin, ("unshare", "--mount", "/bin/true"), 20).exit_code,
                0,
            )
            self.assertNotEqual(
                runtime.execute(snapshot, scratch, plugin, ("unshare", "--user", "--map-root-user", "--mount", "/bin/true"), 20).exit_code,
                0,
            )
            self.assertNotEqual(
                runtime.execute(snapshot, scratch, plugin, ("mount", "-t", "tmpfs", "tmpfs", "/workspace/scratch/mount-target"), 20).exit_code,
                0,
            )
            result = runtime.execute(
                snapshot, scratch, plugin, ("sh", "/workspace/plugin/launch-sandbox.sh"), 30
            )
            self.assertEqual(result.exit_code, 0, result.stderr.decode("utf-8", errors="replace"))
            for marker in (
                "named-profile-scratch-write",
                "named-profile-snapshot-write-denied",
                "named-profile-plugin-write-denied",
                "named-profile-root-write-denied",
                "named-profile-auth-direct-denied",
                "named-profile-auth-dotdot-denied",
                "named-profile-network-denied",
            ):
                self.assertTrue((scratch / marker).is_file(), marker)
            self.assertFalse(connected.wait(1), "named sandbox child reached the host sentinel")


class _local_sentinel:
    def __enter__(self) -> tuple[str, int, threading.Event]:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("0.0.0.0", 0))
        self._socket.listen(1)
        self._socket.settimeout(4)
        self.connected = threading.Event()
        self._thread = threading.Thread(target=self._accept_once, daemon=True)
        self._thread.start()
        return "host.docker.internal", self._socket.getsockname()[1], self.connected

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self._socket.close()
        self._thread.join(timeout=1)

    def _accept_once(self) -> None:
        try:
            connection, _address = self._socket.accept()
        except OSError:
            return
        with connection:
            self.connected.set()
