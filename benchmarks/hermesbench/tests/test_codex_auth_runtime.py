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


def _auth_envelope() -> bytes:
    return json.dumps({"auth": _auth(), "installation_id": _INSTALLATION_ID}).encode("utf-8")


class CodexAuthRuntimeTests(unittest.TestCase):
    def test_private_runtime_writes_regular_auth_and_installation_files(self) -> None:
        wrapper = _load_wrapper()
        payload = json.dumps(_auth(), separators=(",", ":")).encode("utf-8")

        with tempfile.TemporaryDirectory() as directory:
            runtime, auth_path = wrapper.start_auth_runtime(Path(directory), payload, _INSTALLATION_ID)
            try:
                self.assertEqual(runtime.parent, Path(directory))
                self.assertEqual(auth_path, runtime / "auth.json")
                self.assertTrue(auth_path.is_file())
                self.assertFalse(auth_path.is_symlink())
                self.assertEqual(json.loads(auth_path.read_bytes()), _auth())
                self.assertEqual((runtime / "installation_id").read_text(encoding="ascii"), _INSTALLATION_ID)
                if os.name != "nt":
                    self.assertEqual(oct(runtime.stat().st_mode & 0o777), "0o700")
                    self.assertEqual(oct(auth_path.stat().st_mode & 0o777), "0o600")
                    self.assertEqual(oct((runtime / "installation_id").stat().st_mode & 0o777), "0o600")
            finally:
                wrapper.remove_auth_runtime(runtime)
            self.assertFalse(runtime.exists())

    def test_main_exposes_only_codex_home_and_regular_runtime_to_child(self) -> None:
        wrapper = _load_wrapper()
        captured: dict[str, object] = {}

        class _Child:
            returncode = 0
            stderr = io.BytesIO()

            def wait(self) -> None:
                return None

        def start_child(argv: list[str], **kwargs: object) -> _Child:
            captured["argv"] = argv
            captured["env"] = kwargs["env"]
            captured["stdin"] = kwargs["stdin"]
            return _Child()

        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(_auth_envelope()), encoding="utf-8")
        original_start = wrapper.start_auth_runtime
        with tempfile.TemporaryDirectory() as directory:
            def start_runtime(_parent: Path, payload: bytes, installation_id: str) -> tuple[Path, Path]:
                return original_start(Path(directory), payload, installation_id)

            with patch.object(wrapper, "start_auth_runtime", side_effect=start_runtime), patch.object(wrapper.subprocess, "Popen", side_effect=start_child), patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
                self.assertEqual(wrapper.main(["--", "codex", "exec"]), 0)

        self.assertEqual(captured["argv"], ["codex", "exec"])
        self.assertIs(captured["stdin"], wrapper.subprocess.DEVNULL)
        environment = captured["env"]
        self.assertIn("CODEX_HOME", environment)
        self.assertNotIn(_INSTALLATION_ID, environment.values())
        self.assertNotIn("header.payload.signature", environment.values())
        self.assertEqual(stderr.getvalue(), "")

    def test_unauthorized_child_emits_the_unsplit_fixed_category(self) -> None:
        wrapper = _load_wrapper()

        class _Child:
            returncode = 7
            stderr = io.BytesIO(b"401 unauthorized credential-sentinel /private/path")

            def wait(self) -> None:
                return None

        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(_auth_envelope()), encoding="utf-8")
        original_start = wrapper.start_auth_runtime
        with tempfile.TemporaryDirectory() as directory:
            def start_runtime(_parent: Path, payload: bytes, installation_id: str) -> tuple[Path, Path]:
                return original_start(Path(directory), payload, installation_id)

            with patch.object(wrapper, "start_auth_runtime", side_effect=start_runtime), patch.object(wrapper.subprocess, "Popen", return_value=_Child()), patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
                self.assertEqual(wrapper.main(["--", "codex", "exec"]), 7)

        self.assertEqual(stderr.getvalue(), "hermesbench-child-category:auth_unauthorized\n")
        self.assertNotIn("credential-sentinel", stderr.getvalue())
        self.assertNotIn("/private/path", stderr.getvalue())

    def test_invalid_envelope_and_runtime_setup_failures_emit_only_fixed_tokens(self) -> None:
        wrapper = _load_wrapper()
        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(b"not-json"), encoding="utf-8")
        with patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
            self.assertEqual(wrapper.main(["--", "codex", "exec"]), 2)
        self.assertEqual(stderr.getvalue(), "hermesbench-setup-stage:setup_invalid_payload\n")

        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(_auth_envelope()), encoding="utf-8")
        with patch.object(wrapper, "start_auth_runtime", side_effect=OSError("credential-sentinel /private/path")), patch.object(wrapper.sys, "stdin", stdin), patch.object(wrapper.sys, "stderr", stderr):
            self.assertEqual(wrapper.main(["--", "codex", "exec"]), 2)
        self.assertEqual(stderr.getvalue(), "hermesbench-setup-stage:setup_auth_runtime\n")
        self.assertNotIn("credential-sentinel", stderr.getvalue())

    def test_bounded_stderr_classification_retains_only_fixed_categories(self) -> None:
        wrapper = _load_wrapper()
        drainer = wrapper.BoundedStderrDrainer(
            io.BytesIO(b"authentication failed credential-sentinel" + b"x" * (wrapper.MAX_CHILD_STDERR_BYTES * 2))
        )
        drainer.start()
        drainer.join()

        self.assertEqual(len(drainer.prefix), wrapper.MAX_CHILD_STDERR_BYTES)
        self.assertEqual(drainer.category(), "auth_other")


if __name__ == "__main__":
    unittest.main()
