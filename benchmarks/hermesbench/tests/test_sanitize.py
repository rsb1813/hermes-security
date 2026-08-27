# Verifies benchmark bundle contamination detection.

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks.hermesbench.sanitize import BundleAuditError, audit_bundle, tree_sha256


class SanitizeTests(unittest.TestCase):
    def test_git_history_and_advisory_ids_contaminate_a_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            (root / "src").mkdir()
            (root / "src" / "handler.py").write_text(
                "# Fixed in CVE-2026-12345\n", encoding="utf-8"
            )
            codes = {violation.code for violation in audit_bundle(root)}
            self.assertEqual(codes, {"git_metadata", "advisory_identifier"})

    def test_advisory_identifiers_in_paths_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "GHSA-2345-6789-cfgh.patch").write_bytes(b"clean contents\n")
            self.assertEqual(
                audit_bundle(root)[0].code,
                "advisory_identifier",
            )

    def test_advisory_urls_are_detected_case_insensitively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "notes.txt").write_text(
                "HTTPS://GITHUB.COM/ADVISORIES/example\n", encoding="utf-8"
            )
            self.assertEqual(
                {violation.code for violation in audit_bundle(root)},
                {"advisory_identifier"},
            )

    def test_vulngym_source_identifiers_contaminate_a_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "private-record.json").write_text(
                '{"entry_id":"entry-00001","origin":"VulnGym"}\n',
                encoding="utf-8",
            )
            self.assertEqual(
                {violation.code for violation in audit_bundle(root)},
                {"source_identifier"},
            )

    def test_clean_source_is_not_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "handler.py"
            source.write_bytes(b"def handle(value):\n    return value\n")
            before = source.read_bytes()
            self.assertEqual(audit_bundle(root), ())
            self.assertEqual(source.read_bytes(), before)


class TreeHashTests(unittest.TestCase):
    def test_tree_hash_changes_when_source_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "a.py"
            source.write_text("value = 1\n", encoding="utf-8")
            first = tree_sha256(Path(directory))
            source.write_text("value = 2\n", encoding="utf-8")
            self.assertNotEqual(tree_sha256(Path(directory)), first)

    def test_tree_hash_is_independent_of_file_creation_order(self) -> None:
        with tempfile.TemporaryDirectory() as left_directory, tempfile.TemporaryDirectory() as right_directory:
            left = Path(left_directory)
            right = Path(right_directory)
            (left / "a.txt").write_bytes(b"a")
            (left / "b.txt").write_bytes(b"b")
            (right / "b.txt").write_bytes(b"b")
            (right / "a.txt").write_bytes(b"a")
            self.assertEqual(tree_sha256(left), tree_sha256(right))

    def test_tree_hash_rejects_symbolic_links_without_following_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            linked = root / "linked.py"
            linked.write_bytes(b"not actually linked")
            original = Path.is_symlink

            def simulated_symlink(path: Path) -> bool:
                return path == linked or original(path)

            with patch.object(Path, "is_symlink", simulated_symlink):
                with self.assertRaisesRegex(BundleAuditError, "symbolic link"):
                    tree_sha256(root)

    def test_missing_bundle_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with self.assertRaisesRegex(BundleAuditError, "directory"):
                audit_bundle(missing)


if __name__ == "__main__":
    unittest.main()
