# Verifies the bounded in-container Codex authentication FIFO wrapper.

from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


_WRAPPER_PATH = Path(__file__).parents[1] / "containers" / "codex_auth_fifo.py"


def _load_wrapper() -> object:
    spec = importlib.util.spec_from_file_location("codex_auth_fifo", _WRAPPER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("FIFO wrapper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _auth_envelope(auth_payload: bytes) -> bytes:
    return json.dumps(
        {
            "auth": json.loads(auth_payload),
            "installation_id": "123e4567-e89b-12d3-a456-426614174000",
        }
    ).encode("utf-8")


class CodexAuthFifoTests(unittest.TestCase):
    def test_payload_accepts_only_bounded_external_chatgpt_auth_shape(self) -> None:
        wrapper = _load_wrapper()
        payload = json.dumps(
            {
                "auth_mode": "chatgptAuthTokens",
                "tokens": {
                    "id_token": "header.payload.signature",
                    "access_token": "header.payload.signature",
                    "refresh_token": "",
                    "account_id": "account",
                },
                "last_refresh": "2026-08-27T00:00:00Z",
            }
        ).encode("utf-8")

        self.assertEqual(wrapper.validate_auth_payload(payload), payload)
        with self.assertRaisesRegex(ValueError, "payload"):
            wrapper.validate_auth_payload(payload + b"x" * wrapper.MAX_AUTH_BYTES)
        with self.assertRaisesRegex(ValueError, "payload"):
            wrapper.validate_auth_payload(b'{"auth_mode":"chatgptAuthTokens","tokens":{}}')
        mismatched = json.loads(payload)
        mismatched["tokens"]["id_token"] = "different.token.value"
        with self.assertRaisesRegex(ValueError, "payload"):
            wrapper.validate_auth_payload(json.dumps(mismatched).encode("utf-8"))

    def test_envelope_requires_canonical_installation_id_and_writes_private_runtime_file(self) -> None:
        wrapper = _load_wrapper()
        auth = {
            "auth_mode": "chatgptAuthTokens",
            "tokens": {
                "id_token": "header.payload.signature",
                "access_token": "header.payload.signature",
                "refresh_token": "",
                "account_id": "account",
            },
            "last_refresh": "2026-08-27T00:00:00Z",
        }
        envelope = {
            "auth": auth,
            "installation_id": "123e4567-e89b-12d3-a456-426614174000",
        }
        compact_auth, installation_id = wrapper.validate_auth_envelope(json.dumps(envelope).encode("utf-8"))
        self.assertEqual(json.loads(compact_auth), auth)
        self.assertEqual(installation_id, envelope["installation_id"])
        for invalid in (None, "not-a-uuid", "123E4567-E89B-12D3-A456-426614174000"):
            candidate = dict(envelope)
            if invalid is None:
                candidate.pop("installation_id")
            else:
                candidate["installation_id"] = invalid
            with self.subTest(installation_id=invalid):
                with self.assertRaisesRegex(ValueError, "payload"):
                    wrapper.validate_auth_envelope(json.dumps(candidate).encode("utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir(mode=0o700)
            wrapper.write_installation_id(runtime, installation_id)
            identity_file = runtime / "installation_id"
            if os.name != "nt":
                self.assertEqual(oct(identity_file.stat().st_mode & 0o777), "0o600")
            self.assertEqual(identity_file.read_text(encoding="ascii"), installation_id)

    def test_main_keeps_installation_id_out_of_fifo_child_environment_and_public_output(self) -> None:
        wrapper = _load_wrapper()
        installation_id = "123e4567-e89b-12d3-a456-426614174000"
        auth = {
            "auth_mode": "chatgptAuthTokens",
            "tokens": {
                "id_token": "header.payload.signature",
                "access_token": "header.payload.signature",
                "refresh_token": "",
                "account_id": "account",
            },
            "last_refresh": "2026-08-27T00:00:00Z",
        }
        envelope = json.dumps({"auth": auth, "installation_id": installation_id}).encode("utf-8")
        captured: dict[str, object] = {}

        class _Feeder:
            failed = False

            def wait_for_readers(self, count: int, timeout_seconds: float = 0.0) -> bool:
                return count == 2

            def cancel(self) -> None:
                return None

        class _Child:
            returncode = 0
            stderr = io.BytesIO()

            def wait(self) -> None:
                return None

        def start_fifo(parent: Path, payload: bytes, readers: int) -> tuple[Path, Path, _Feeder]:
            runtime = Path(tempfile.mkdtemp())
            captured["payload"] = payload
            return runtime, runtime / "auth.json", _Feeder()

        def start_child(argv: list[str], **kwargs: object) -> _Child:
            captured["argv"] = argv
            captured["env"] = kwargs["env"]
            return _Child()

        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(envelope), encoding="utf-8")
        with patch.object(wrapper, "start_auth_fifo", side_effect=start_fifo), patch.object(wrapper.subprocess, "Popen", side_effect=start_child), patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
            self.assertEqual(wrapper.main(["--auth-readers", "2", "--", "codex", "exec"]), 0)

        self.assertEqual(json.loads(captured["payload"]), auth)
        self.assertNotIn(installation_id.encode("ascii"), captured["payload"])
        self.assertNotIn(installation_id, captured["argv"])
        self.assertNotIn(installation_id, captured["env"].values())
        self.assertEqual(stderr.getvalue(), "")

    def test_child_stderr_is_bounded_and_emits_only_fixed_category(self) -> None:
        wrapper = _load_wrapper()
        payload = json.dumps(
            {
                "auth_mode": "chatgptAuthTokens",
                "tokens": {
                    "id_token": "header.payload.signature",
                    "access_token": "header.payload.signature",
                    "refresh_token": "",
                    "account_id": "account",
                },
                "last_refresh": "2026-08-27T00:00:00Z",
            }
        ).encode("utf-8")

        class _Child:
            returncode = 7
            stderr = io.BytesIO(
                b"authentication failed credential-sentinel account-123 header.payload.signature /private/path "
                + b"x" * (wrapper.MAX_CHILD_STDERR_BYTES * 2)
            )

            def wait(self) -> None:
                return None

            def poll(self) -> int:
                return self.returncode

        class _Feeder:
            def wait_for_readers(self, count: int, timeout_seconds: float = 0.0) -> bool:
                return count == 1

            failed = False

            def cancel(self) -> None:
                return None

        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(_auth_envelope(payload)), encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            auth_directory = Path(directory) / "auth"
            auth_directory.mkdir()
            with patch.object(wrapper, "start_auth_fifo", return_value=(auth_directory, auth_directory / "auth.json", _Feeder())), patch.object(
                wrapper.subprocess, "Popen", return_value=_Child()
            ), patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
                self.assertEqual(wrapper.main(["--auth-readers", "1", "--", "codex", "login", "status"]), 7)
        self.assertEqual(stderr.getvalue(), "hermesbench-child-category:auth_other\n")
        for forbidden in ("credential-sentinel", "account-123", "header.payload.signature", "/private/path"):
            self.assertNotIn(forbidden, stderr.getvalue())

    def test_early_child_exit_wins_over_unfinished_second_reader(self) -> None:
        wrapper = _load_wrapper()
        payload = json.dumps(
            {
                "auth_mode": "chatgptAuthTokens",
                "tokens": {
                    "id_token": "header.payload.signature",
                    "access_token": "header.payload.signature",
                    "refresh_token": "",
                    "account_id": "account",
                },
                "last_refresh": "2026-08-27T00:00:00Z",
            }
        ).encode("utf-8")

        class _Child:
            returncode = 7
            stderr = io.BytesIO(b"401 unauthorized credential-sentinel")

            def poll(self) -> int:
                return self.returncode

            def wait(self) -> None:
                return None

        class _Feeder:
            failed = False

            def wait_for_readers(self, count: int, timeout_seconds: float) -> bool:
                return False

            def cancel(self) -> None:
                return None

        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(_auth_envelope(payload)), encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            auth_directory = Path(directory) / "auth"
            auth_directory.mkdir()
            with patch.object(wrapper, "start_auth_fifo", return_value=(auth_directory, auth_directory / "auth.json", _Feeder())), patch.object(
                wrapper.subprocess, "Popen", return_value=_Child()
            ), patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
                self.assertEqual(wrapper.main(["--auth-readers", "2", "--", "codex", "exec"]), 7)
        self.assertEqual(
            stderr.getvalue(),
            "hermesbench-child-category:auth_unauthorized_before_replay\n",
        )

    def test_completed_auth_replay_is_reflected_in_fixed_unauthorized_category(self) -> None:
        wrapper = _load_wrapper()
        payload = json.dumps(
            {
                "auth_mode": "chatgptAuthTokens",
                "tokens": {
                    "id_token": "header.payload.signature",
                    "access_token": "header.payload.signature",
                    "refresh_token": "",
                    "account_id": "account",
                },
                "last_refresh": "2026-08-27T00:00:00Z",
            }
        ).encode("utf-8")

        class _Child:
            returncode = 7
            stderr = io.BytesIO(b"401 unauthorized credential-sentinel")

            def poll(self) -> int:
                return self.returncode

            def wait(self) -> None:
                return None

        class _Feeder:
            failed = False

            def wait_for_readers(self, count: int, timeout_seconds: float) -> bool:
                return count == 2

            def cancel(self) -> None:
                return None

        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(_auth_envelope(payload)), encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            auth_directory = Path(directory) / "auth"
            auth_directory.mkdir()
            with patch.object(
                wrapper,
                "start_auth_fifo",
                return_value=(
                    auth_directory,
                    auth_directory / "auth.json",
                    _Feeder(),
                ),
            ), patch.object(
                wrapper.subprocess, "Popen", return_value=_Child()
            ), patch.object(
                wrapper.sys, "stdin", stdin
            ), patch.object(
                wrapper.sys, "stderr", stderr
            ):
                self.assertEqual(
                    wrapper.main(["--auth-readers", "2", "--", "codex", "exec"]),
                    7,
                )
        self.assertEqual(
            stderr.getvalue(),
            "hermesbench-child-category:auth_unauthorized_after_replay\n",
        )
        self.assertNotIn("credential-sentinel", stderr.getvalue())

    def test_setup_failures_emit_only_fixed_stage_tokens(self) -> None:
        wrapper = _load_wrapper()
        payload = json.dumps(
            {
                "auth_mode": "chatgptAuthTokens",
                "tokens": {
                    "id_token": "header.payload.signature",
                    "access_token": "header.payload.signature",
                    "refresh_token": "",
                    "account_id": "account",
                },
                "last_refresh": "2026-08-27T00:00:00Z",
            }
        ).encode("utf-8")
        payload = _auth_envelope(payload)

        class _Feeder:
            def __init__(self, completed: bool, failed: bool = False) -> None:
                self.completed = completed
                self.failed = failed

            def wait_for_readers(self, count: int, timeout_seconds: float) -> bool:
                return self.completed

            def cancel(self) -> None:
                return None

        class _Child:
            stderr = io.BytesIO()

            def __init__(self, poll_result: int | None = None, wait_error: bool = False) -> None:
                self.returncode = poll_result
                self._wait_error = wait_error

            def poll(self) -> int | None:
                return self.returncode

            def wait(self) -> None:
                if self._wait_error:
                    raise wrapper.subprocess.SubprocessError("credential-sentinel /private/path")

            def terminate(self) -> None:
                self.returncode = 1

        def run_main(argv: list[str], stdin_bytes: bytes, start_return: object | None = None, start_error: BaseException | None = None, popen_return: object | None = None, popen_error: BaseException | None = None) -> tuple[int, str]:
            stderr = io.StringIO()
            stdin = io.TextIOWrapper(io.BytesIO(stdin_bytes), encoding="utf-8")
            with patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
                with patch.object(wrapper, "start_auth_fifo", return_value=start_return, side_effect=start_error):
                    with patch.object(wrapper, "write_installation_id"):
                        with patch.object(wrapper.subprocess, "Popen", return_value=popen_return, side_effect=popen_error):
                            return wrapper.main(argv), stderr.getvalue()

        with self.subTest(stage="setup_invalid_args"):
            exit_code, output = run_main([], payload)
            self.assertEqual(exit_code, 2)
            self.assertEqual(output, "hermesbench-setup-stage:setup_invalid_args\n")

        with self.subTest(stage="setup_invalid_payload"):
            exit_code, output = run_main(["--auth-readers", "1", "--", "codex", "exec"], b"not-json")
            self.assertEqual(exit_code, 2)
            self.assertEqual(output, "hermesbench-setup-stage:setup_invalid_payload\n")

        with self.subTest(stage="setup_fifo"):
            exit_code, output = run_main(
                ["--auth-readers", "1", "--", "codex", "exec"],
                payload,
                start_error=OSError("credential-sentinel /private/path"),
            )
            self.assertEqual(exit_code, 2)
            self.assertEqual(output, "hermesbench-setup-stage:setup_fifo\n")

        with tempfile.TemporaryDirectory() as directory:
            auth_directory = Path(directory) / "auth"
            auth_directory.mkdir()
            start_return = (auth_directory, auth_directory / "auth.json", _Feeder(completed=True))
            with self.subTest(stage="setup_child_start"):
                exit_code, output = run_main(
                    ["--auth-readers", "1", "--", "codex", "exec"],
                    payload,
                    start_return=start_return,
                    popen_error=OSError("credential-sentinel /private/path"),
                )
                self.assertEqual(exit_code, 2)
                self.assertEqual(output, "hermesbench-setup-stage:setup_child_start\n")

            with self.subTest(stage="setup_feeder"):
                exit_code, output = run_main(
                    ["--auth-readers", "1", "--", "codex", "exec"],
                    payload,
                    start_return=(auth_directory, auth_directory / "auth.json", _Feeder(completed=False, failed=True)),
                    popen_return=_Child(),
                )
                self.assertEqual(exit_code, 2)
                self.assertEqual(output, "hermesbench-setup-stage:setup_feeder\n")

            with self.subTest(stage="setup_child_zero_before_readers"):
                exit_code, output = run_main(
                    ["--auth-readers", "1", "--", "codex", "exec"],
                    payload,
                    start_return=(auth_directory, auth_directory / "auth.json", _Feeder(completed=False)),
                    popen_return=_Child(poll_result=0),
                )
                self.assertEqual(exit_code, 2)
                self.assertEqual(output, "hermesbench-setup-stage:setup_child_zero_before_readers\n")

            with self.subTest(stage="setup_wrapper_os_error"):
                exit_code, output = run_main(
                    ["--auth-readers", "1", "--", "codex", "exec"],
                    payload,
                    start_return=(auth_directory, auth_directory / "auth.json", _Feeder(completed=True)),
                    popen_return=_Child(wait_error=True),
                )
                self.assertEqual(exit_code, 2)
                self.assertEqual(output, "hermesbench-setup-stage:setup_wrapper_os_error\n")

        self.assertNotIn("credential-sentinel", output)
        self.assertNotIn("/private/path", output)

    def test_child_stderr_drainer_retains_at_most_one_prefix(self) -> None:
        wrapper = _load_wrapper()
        drainer = wrapper.BoundedStderrDrainer(
            io.BytesIO(b"x" * (wrapper.MAX_CHILD_STDERR_BYTES * 2))
        )
        drainer.start()
        drainer.join()

        self.assertEqual(len(drainer.prefix), wrapper.MAX_CHILD_STDERR_BYTES)
        self.assertEqual(drainer.category(), "unknown")

    def test_auth_categories_use_fixed_ascii_phrase_priority(self) -> None:
        wrapper = _load_wrapper()
        cases = (
            (b"refresh token then 401 unauthorized", "auth_unauthorized"),
            (b"token data unavailable and refresh token", "auth_token_unavailable"),
            (b"refresh token cannot be used", "auth_refresh"),
            (b"not logged in and login required", "auth_not_logged_in"),
            (b"account mismatch detected", "auth_account"),
            (b"authentication failed credential-sentinel header.payload.signature /private/path", "auth_other"),
        )
        for stderr_bytes, expected in cases:
            with self.subTest(expected=expected):
                drainer = wrapper.BoundedStderrDrainer(io.BytesIO(stderr_bytes))
                drainer.start()
                drainer.join()
                self.assertEqual(drainer.category(), expected)

    def test_benign_paths_and_non_auth_failures_do_not_contaminate_auth_category(self) -> None:
        wrapper = _load_wrapper()
        cases = (
            (b"warning: PATH alias /tmp/hermesbench-auth-private", "unknown"),
            (b"permission denied", "filesystem"),
            (b"bootstrap warning", "configuration_other"),
            (b"usage: codex exec", "cli"),
        )
        for stderr_bytes, expected in cases:
            with self.subTest(expected=expected):
                drainer = wrapper.BoundedStderrDrainer(io.BytesIO(stderr_bytes))
                drainer.start()
                drainer.join()
                self.assertEqual(drainer.category(), expected)

    def test_configuration_categories_use_fixed_phrase_priority(self) -> None:
        wrapper = _load_wrapper()
        cases = (
            (b"failed to initialize cloud configuration authentication", "configuration_cloud_auth_init"),
            (b"failed to resolve cloud configuration authentication", "configuration_cloud_auth_resolve"),
            (b"failed to load bootstrap configuration", "configuration_bootstrap_load"),
            (b"failed to load configuration", "configuration_load"),
            (b"schema validation failed", "configuration_schema"),
            (b"unknown option supplied", "configuration_cli_args"),
            (b"configuration warning", "configuration_other"),
        )
        for stderr_bytes, expected in cases:
            with self.subTest(expected=expected):
                drainer = wrapper.BoundedStderrDrainer(io.BytesIO(stderr_bytes))
                drainer.start()
                drainer.join()
                self.assertEqual(drainer.category(), expected)

    def test_feeder_swallows_closed_reader_without_thread_traceback(self) -> None:
        wrapper = _load_wrapper()
        cancelled = wrapper.threading.Event()
        with patch.object(wrapper.os, "write", side_effect=BrokenPipeError):
            self.assertFalse(wrapper._write_all(9, b"payload", cancelled))

    def test_private_fifo_is_unlinked_after_reader_handshake(self) -> None:
        if os.name == "nt":
            self.skipTest("FIFO behavior is exercised in the Linux runtime image")
        wrapper = _load_wrapper()
        payload = json.dumps(
            {
                "auth_mode": "chatgptAuthTokens",
                "tokens": {
                    "id_token": "header.payload.signature",
                    "access_token": "header.payload.signature",
                    "refresh_token": "",
                    "account_id": "account",
                },
                "last_refresh": "2026-08-27T00:00:00Z",
            }
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            auth_directory, fifo_path, feeder = wrapper.start_auth_fifo(Path(directory), payload)
            self.assertEqual(oct(auth_directory.stat().st_mode & 0o777), "0o700")
            descriptor = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
            try:
                self.assertTrue(feeder.wait_for_reader())
                self.assertFalse(fifo_path.exists())
                self.assertEqual(os.read(descriptor, len(payload)), payload)
            finally:
                os.close(descriptor)
                feeder.cancel()

    def test_two_readers_receive_one_payload_each_before_fifo_unlinks(self) -> None:
        if os.name == "nt":
            self.skipTest("FIFO behavior is exercised in the Linux runtime image")
        wrapper = _load_wrapper()
        payload = json.dumps(
            {
                "auth_mode": "chatgptAuthTokens",
                "tokens": {
                    "id_token": "header.payload.signature",
                    "access_token": "header.payload.signature",
                    "refresh_token": "",
                    "account_id": "account",
                },
                "last_refresh": "2026-08-27T00:00:00Z",
            }
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            auth_directory, fifo_path, feeder = wrapper.start_auth_fifo(
                Path(directory), payload, readers=2
            )
            first = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
            try:
                self.assertTrue(feeder.wait_for_readers(1))
                self.assertTrue(fifo_path.exists())
                self.assertEqual(os.read(first, len(payload)), payload)
            finally:
                os.close(first)
            second = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
            try:
                self.assertTrue(feeder.wait_for_readers(2))
                self.assertFalse(fifo_path.exists())
                self.assertEqual(os.read(second, len(payload)), payload)
                with self.assertRaises(FileNotFoundError):
                    os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
            finally:
                os.close(second)
                feeder.cancel()
            self.assertEqual(auth_directory.parent, Path(directory))

    def test_rejects_reader_counts_outside_the_pinned_auth_contract(self) -> None:
        wrapper = _load_wrapper()
        payload = json.dumps(
            {
                "auth_mode": "chatgptAuthTokens",
                "tokens": {
                    "id_token": "header.payload.signature",
                    "access_token": "header.payload.signature",
                    "refresh_token": "",
                    "account_id": "account",
                },
                "last_refresh": "2026-08-27T00:00:00Z",
            }
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "readers"):
                wrapper.start_auth_fifo(Path(directory), payload, readers=3)

    def test_handshake_deadline_is_bounded_and_missing_reader_fails_closed(self) -> None:
        wrapper = _load_wrapper()
        self.assertEqual(wrapper._READER_DEADLINE_SECONDS, 60.0)
        with tempfile.TemporaryDirectory() as directory:
            feeder = wrapper.AuthFifoFeeder(Path(directory) / "missing-auth-reader", b"payload")
            try:
                self.assertFalse(feeder.wait_for_readers(1, timeout_seconds=0.1))
            finally:
                feeder.cancel()

    def test_diagnostic_reader_receipt_exposes_only_completed_count(self) -> None:
        wrapper = _load_wrapper()
        payload = json.dumps(
            {
                "auth_mode": "chatgptAuthTokens",
                "tokens": {
                    "id_token": "header.payload.signature",
                    "access_token": "header.payload.signature",
                    "refresh_token": "",
                    "account_id": "account",
                },
                "last_refresh": "2026-08-27T00:00:00Z",
            }
        ).encode("utf-8")

        class _Child:
            returncode = 0
            stderr = io.BytesIO()

            def wait(self) -> None:
                return None

        class _Feeder:
            def wait_for_readers(self, count: int, timeout_seconds: float = 0.0) -> bool:
                return count == 2

            failed = False

            def cancel(self) -> None:
                return None

        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(_auth_envelope(payload)), encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            auth_directory = Path(directory) / "auth"
            auth_directory.mkdir()
            with patch.object(wrapper, "start_auth_fifo", return_value=(auth_directory, auth_directory / "auth.json", _Feeder())), patch.object(
                wrapper.subprocess, "Popen", return_value=_Child()
            ), patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
                self.assertEqual(
                    wrapper.main(["--auth-readers", "2", "--reader-receipt", "--", "codex", "exec"]),
                    0,
                )
        self.assertEqual(stderr.getvalue(), "hermesbench-auth-readers:2\n")
