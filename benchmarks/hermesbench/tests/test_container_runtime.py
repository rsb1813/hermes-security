# Verifies the hardened Docker boundary used by HermesBench adapters.

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
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

    def communicate(self, timeout: int) -> tuple[bytes, bytes]:
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome  # type: ignore[return-value]

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: int) -> None:
        return None


def _completed(argv: list[str], stdout: bytes = b"", returncode: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=b"")


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
        build = subprocess.run(
            ["docker", "build", "-f", str(runtime_directory / "Dockerfile"), "-t", image_ref, str(runtime_directory)],
            capture_output=True,
            check=False,
            shell=False,
        )
        if build.returncode != 0:
            self.fail("Docker runtime image build failed")

        try:
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
                    inspection = subprocess.run(
                        ["docker", "inspect", container_id], capture_output=True, check=False, shell=False
                    )
                    self.assertEqual(inspection.returncode, 0)
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
                    docker_version = subprocess.run(
                        ["docker", "version", "--format", "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}"],
                        capture_output=True,
                        check=False,
                        shell=False,
                    )
                    self.assertEqual(docker_version.returncode, 0)
                    receipt = {
                        "schema_version": 1,
                        "task": "HermesBench Task 4 Docker isolation smoke",
                        "image_ref": image_ref,
                        "resolved_image_id": image_id,
                        "docker_server": docker_version.stdout.decode("utf-8", errors="strict").strip(),
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
                    receipt_path.parent.mkdir(parents=True, exist_ok=True)
                    receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
                    recorded = json.loads(receipt_path.read_text(encoding="utf-8"))
                    self.assertEqual(recorded, receipt)
                    self.assertNotIn(str(root), json.dumps(recorded))
                    self.assertNotIn(final_artifact_root.name, json.dumps(recorded))
                finally:
                    subprocess.run(
                        ["docker", "rm", "--force", container_id],
                        capture_output=True,
                        check=False,
                        shell=False,
                    )
        finally:
            subprocess.run(
                ["docker", "image", "rm", "--force", image_ref],
                capture_output=True,
                check=False,
                shell=False,
            )


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
