# Verifies the hardened Docker boundary used by HermesBench adapters.

from __future__ import annotations

import os
import json
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

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


@unittest.skipUnless(
    os.environ.get("HERMESBENCH_RUN_DOCKER_SMOKE") == "1",
    "set HERMESBENCH_RUN_DOCKER_SMOKE=1 to run the Docker isolation smoke",
)
class DockerIsolationSmokeTests(unittest.TestCase):
    def test_runtime_image_enforces_the_live_boundary(self) -> None:
        runtime_directory = Path(__file__).parents[1] / "containers"
        image_ref = f"hermesbench-runtime-task4-smoke:{os.getpid()}"
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
                    sandboxed = runtime.execute(
                        snapshot,
                        scratch,
                        plugin,
                        (
                            "codex", "sandbox", "--sandbox-state-json", sandbox_state,
                            "--sandbox-state-disable-network", "--", "python3", "-c",
                            f"import socket; socket.create_connection(({host!r}, {port}), timeout=3).close()",
                        ),
                        20,
                    )
                    self.assertNotEqual(sandboxed.exit_code, 0)
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
                    self.assertEqual(inspected["HostConfig"]["PidsLimit"], 128)
                    self.assertFalse(inspected["HostConfig"]["Privileged"])
                    mounts = {mount["Destination"]: mount for mount in inspected["Mounts"]}
                    self.assertFalse(mounts["/workspace/snapshot"]["RW"])
                    self.assertFalse(mounts["/workspace/plugin"]["RW"])
                    self.assertTrue(mounts["/workspace/scratch"]["RW"])
                    self.assertNotIn(final_artifact_root.name, json.dumps(inspected))
                    self.assertNotIn("/var/run/docker.sock", json.dumps(inspected))
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
