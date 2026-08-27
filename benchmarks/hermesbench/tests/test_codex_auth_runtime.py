# Verifies the bounded in-container Codex authentication runtime wrapper.

from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


_WRAPPER_PATH = Path(__file__).parents[1] / "containers" / "codex_auth_runtime.py"
_INSTALLATION_ID = "123e4567-e89b-12d3-a456-426614174000"


def _load_wrapper() -> object:
    spec = importlib.util.spec_from_file_location("codex_auth_runtime", _WRAPPER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("authentication runtime wrapper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _auth() -> dict[str, object]:
    return {
        "auth_mode": "chatgptAuthTokens",
        "tokens": {
            "id_token": "header.payload.signature",
            "access_token": "header.payload.signature",
            "refresh_token": "",
            "account_id": "account",
        },
        "last_refresh": "2026-08-27T00:00:00Z",
    }


def _auth_envelope(auth: dict[str, object] | None = None, installation_id: str = _INSTALLATION_ID) -> bytes:
    return json.dumps({"auth": auth or _auth(), "installation_id": installation_id}).encode("utf-8")


class CodexAuthRuntimeTests(unittest.TestCase):
    def test_runtime_writes_replayable_regular_auth_and_cleans_up(self) -> None:
        wrapper = _load_wrapper()
        payload = json.dumps(_auth(), separators=(",", ":")).encode("utf-8")

        with tempfile.TemporaryDirectory() as directory:
            runtime, auth_path = wrapper.start_auth_runtime(Path(directory), payload, _INSTALLATION_ID)
            try:
                self.assertEqual(runtime.parent, Path(directory))
                self.assertEqual(auth_path, runtime / "auth.json")
                self.assertTrue(auth_path.is_file())
                self.assertFalse(auth_path.is_symlink())
                with auth_path.open("rb") as first, auth_path.open("rb") as second:
                    self.assertEqual(first.read(), payload)
                    self.assertEqual(second.read(), payload)
                self.assertEqual((runtime / "installation_id").read_text(encoding="ascii"), _INSTALLATION_ID)
                if os.name != "nt":
                    self.assertEqual(oct(runtime.stat().st_mode & 0o777), "0o700")
                    self.assertEqual(oct(auth_path.stat().st_mode & 0o777), "0o600")
                    self.assertEqual(oct((runtime / "installation_id").stat().st_mode & 0o777), "0o600")
            finally:
                wrapper.remove_auth_runtime(runtime)
            self.assertFalse(runtime.exists())

    def test_validation_rejects_oversized_or_incomplete_external_auth(self) -> None:
        wrapper = _load_wrapper()
        payload = json.dumps(_auth(), separators=(",", ":")).encode("utf-8")
        self.assertEqual(wrapper.validate_auth_payload(payload), payload)
        invalid_auth = []
        invalid_auth.append(payload + b"x" * wrapper.MAX_AUTH_BYTES)
        mismatched = _auth()
        mismatched["tokens"] = dict(mismatched["tokens"], id_token="different.token.value")
        invalid_auth.append(json.dumps(mismatched).encode("utf-8"))
        refresh = _auth()
        refresh["tokens"] = dict(refresh["tokens"], refresh_token="must-not-cross")
        invalid_auth.append(json.dumps(refresh).encode("utf-8"))
        for candidate in invalid_auth:
            with self.subTest(candidate=candidate[:20]):
                with self.assertRaisesRegex(ValueError, "payload"):
                    wrapper.validate_auth_payload(candidate)

        for installation_id in ("not-a-uuid", "123E4567-E89B-12D3-A456-426614174000"):
            with self.subTest(installation_id=installation_id):
                with self.assertRaisesRegex(ValueError, "payload"):
                    wrapper.validate_auth_envelope(_auth_envelope(installation_id=installation_id))
        for envelope in (
            {"auth": _auth()},
            {"auth": _auth(), "installation_id": _INSTALLATION_ID, "unexpected": "field"},
        ):
            with self.subTest(envelope=envelope):
                with self.assertRaisesRegex(ValueError, "payload"):
                    wrapper.validate_auth_envelope(json.dumps(envelope).encode("utf-8"))
        with self.assertRaisesRegex(ValueError, "payload"):
            wrapper.validate_auth_envelope(b"x" * (wrapper.MAX_AUTH_BYTES + 1))

    def test_main_exposes_only_codex_home_and_scrubs_child_failures(self) -> None:
        wrapper = _load_wrapper()
        original_start = wrapper.start_auth_runtime
        cases = (
            (0, b"", ""),
            (7, b"401 unauthorized credential-sentinel /private/path", "hermesbench-child-category:auth_unauthorized\n"),
        )
        for returncode, child_stderr, expected_stderr in cases:
            with self.subTest(returncode=returncode):
                captured: dict[str, object] = {}

                class _Child:
                    stderr = io.BytesIO(child_stderr)

                    def __init__(self) -> None:
                        self.returncode = returncode

                    def wait(self) -> None:
                        return None

                def start_child(argv: list[str], **kwargs: object) -> _Child:
                    captured["argv"] = argv
                    captured["env"] = kwargs["env"]
                    captured["stdin"] = kwargs["stdin"]
                    return _Child()

                stderr = io.StringIO()
                stdin = io.TextIOWrapper(io.BytesIO(_auth_envelope()), encoding="utf-8")
                with tempfile.TemporaryDirectory() as directory:
                    def start_runtime(_parent: Path, payload: bytes, installation_id: str) -> tuple[Path, Path]:
                        return original_start(Path(directory), payload, installation_id)

                    with patch.object(wrapper, "start_auth_runtime", side_effect=start_runtime), patch.object(wrapper.subprocess, "Popen", side_effect=start_child), patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
                        self.assertEqual(wrapper.main(["--", "codex", "exec"]), returncode)

                self.assertEqual(captured["argv"], ["codex", "exec"])
                self.assertIs(captured["stdin"], wrapper.subprocess.DEVNULL)
                environment = captured["env"]
                self.assertIn("CODEX_HOME", environment)
                self.assertNotIn(_INSTALLATION_ID, environment.values())
                self.assertNotIn("header.payload.signature", environment.values())
                self.assertEqual(stderr.getvalue(), expected_stderr)
                self.assertNotIn("credential-sentinel", stderr.getvalue())
                self.assertNotIn("/private/path", stderr.getvalue())

    def test_main_setup_failures_emit_fixed_tokens_and_remove_runtime(self) -> None:
        wrapper = _load_wrapper()
        cases = (
            ([], _auth_envelope(), "hermesbench-setup-stage:setup_invalid_args\n"),
            (["--", "codex", "exec"], b"not-json", "hermesbench-setup-stage:setup_invalid_payload\n"),
        )
        for argv, payload, expected in cases:
            with self.subTest(argv=argv):
                stderr = io.StringIO()
                stdin = io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8")
                with patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
                    self.assertEqual(wrapper.main(argv), 2)
                self.assertEqual(stderr.getvalue(), expected)

        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(_auth_envelope()), encoding="utf-8")
        with patch.object(wrapper, "start_auth_runtime", side_effect=OSError("credential-sentinel /private/path")), patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
            self.assertEqual(wrapper.main(["--", "codex", "exec"]), 2)
        self.assertEqual(stderr.getvalue(), "hermesbench-setup-stage:setup_auth_runtime\n")

        original_start = wrapper.start_auth_runtime
        captured_runtime: list[Path] = []
        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(_auth_envelope()), encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            def start_runtime(_parent: Path, payload: bytes, installation_id: str) -> tuple[Path, Path]:
                runtime = original_start(Path(directory), payload, installation_id)
                captured_runtime.append(runtime[0])
                return runtime

            with patch.object(wrapper, "start_auth_runtime", side_effect=start_runtime), patch.object(wrapper.subprocess, "Popen", side_effect=OSError("credential-sentinel /private/path")), patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
                self.assertEqual(wrapper.main(["--", "codex", "exec"]), 2)
            self.assertEqual(stderr.getvalue(), "hermesbench-setup-stage:setup_child_start\n")
            self.assertEqual(len(captured_runtime), 1)
            self.assertFalse(captured_runtime[0].exists())
        self.assertNotIn("credential-sentinel", stderr.getvalue())
        self.assertNotIn("/private/path", stderr.getvalue())

    def test_stderr_categories_keep_priority_and_benign_messages_out_of_auth(self) -> None:
        wrapper = _load_wrapper()
        cases = (
            (b"refresh token then 401 unauthorized", "auth_unauthorized"),
            (b"token data unavailable and refresh token", "auth_token_unavailable"),
            (b"refresh token cannot be used", "auth_refresh"),
            (b"authentication failed credential-sentinel", "auth_other"),
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

        bounded = wrapper.BoundedStderrDrainer(io.BytesIO(b"x" * (wrapper.MAX_CHILD_STDERR_BYTES * 2)))
        bounded.start()
        bounded.join()
        self.assertEqual(len(bounded.prefix), wrapper.MAX_CHILD_STDERR_BYTES)


if __name__ == "__main__":
    unittest.main()
