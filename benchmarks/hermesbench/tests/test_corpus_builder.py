# Verifies deterministic reviewed-corpus materialization with synthetic Git data.

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from benchmarks.hermesbench.adapters.fake import FakeAdapter
from benchmarks.hermesbench.contracts import GoldPath, Location, load_manifest, load_oracles
from benchmarks.hermesbench.corpus import CorpusCandidate
from benchmarks.hermesbench.corpus_builder import (
    CorpusBuildError,
    build_reviewed_corpus,
    derive_anonymous_id,
    parse_reviewed_ledger,
)
from benchmarks.hermesbench import corpus_builder
from benchmarks.hermesbench.receipts import RunConfig
from benchmarks.hermesbench.runner import ExecutionPolicy, execution_policy_sha256, manifest_sha256, run_suite, task_order_sha256


DATASET_REVISION = "a" * 40
VULNERABLE_SOURCE = (
    "def process(request):\n"
    "    untrusted_value = request[\"value\"]\n"
    "    execute(untrusted_value)\n"
)
FIXED_SOURCE = (
    "def process(request):\n"
    "    cleaned_value = sanitize(request[\"value\"])\n"
    "    execute(cleaned_value)\n"
)


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        shell=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "--all")
    return _commit_index(repository, message)


def _commit_index(repository: Path, message: str) -> str:
    _git(repository, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _tree(repository: Path, commit: str) -> str:
    return _git(repository, "rev-parse", f"{commit}^{{tree}}")


def _license_hash(repository: Path, commit: str, path: str = "LICENSE") -> str:
    contents = subprocess.run(
        ["git", "-C", str(repository), "show", f"{commit}:{path}"],
        check=True,
        shell=False,
        capture_output=True,
    ).stdout
    return hashlib.sha256(contents).hexdigest()


def _blob_hash(repository: Path, commit: str, path: str) -> str:
    contents = subprocess.run(
        ["git", "-C", str(repository), "show", f"{commit}:{path}"],
        check=True,
        shell=False,
        capture_output=True,
    ).stdout
    return hashlib.sha256(contents).hexdigest()


def _synthetic_pair(
    root: Path, *, change_source: bool = True, quarantined_path: str | None = None
) -> tuple[Path, str, str]:
    repository = root / "repository"
    repository.mkdir(parents=True)
    _git(repository, "init", "--quiet")
    (repository / "LICENSE").write_text("Synthetic license\n", encoding="utf-8")
    (repository / "module.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")
    if quarantined_path is not None:
        (repository / quarantined_path).write_text("review notes\n", encoding="utf-8")
    vulnerable = _commit(repository, "vulnerable")
    if change_source:
        (repository / "module.py").write_text(FIXED_SOURCE, encoding="utf-8")
    else:
        (repository / "README").write_text("changed\n", encoding="utf-8")
    fixed = _commit(repository, "fixed")
    return repository, vulnerable, fixed


def _synthetic_blob_tree(root: Path, payloads: dict[str, bytes]) -> tuple[Path, str]:
    repository = root / "blob-repository"
    repository.mkdir(parents=True)
    _git(repository, "init", "--quiet")
    for path, contents in payloads.items():
        target = repository.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)
    return repository, _commit(repository, "binary blobs")


def _index_synthetic_symlink(repository: Path, path: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), "hash-object", "-w", "--stdin"],
        check=True,
        shell=False,
        capture_output=True,
        input=b"synthetic-link-target",
    )
    object_id = completed.stdout.decode("ascii").strip()
    _git(repository, "update-index", "--add", "--cacheinfo", f"120000,{object_id},{path}")
    return object_id


def _synthetic_pair_with_symlink(
    root: Path, *, vulnerable_link: bool, fixed_link: bool
) -> tuple[Path, str, str, str]:
    repository = root / "symlink-repository"
    repository.mkdir(parents=True)
    _git(repository, "init", "--quiet")
    (repository / "LICENSE").write_text("Synthetic license\n", encoding="utf-8")
    (repository / "module.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")
    _git(repository, "add", "LICENSE", "module.py")
    link_path = "quarantined-link"
    if vulnerable_link:
        _index_synthetic_symlink(repository, link_path)
    vulnerable = _commit_index(repository, "vulnerable")
    (repository / "module.py").write_text(FIXED_SOURCE, encoding="utf-8")
    _git(repository, "add", "module.py")
    if fixed_link and not vulnerable_link:
        _index_synthetic_symlink(repository, link_path)
    if not fixed_link and vulnerable_link:
        _git(repository, "update-index", "--force-remove", link_path)
    fixed = _commit_index(repository, "fixed")
    return repository, vulnerable, fixed, link_path


def _ignored_workspace(root: Path) -> Path:
    workspace = root / "workspace"
    workspace.mkdir()
    _git(workspace, "init", "--quiet")
    (workspace / ".gitignore").write_text(
        "/benchmarks/hermesbench/corpora/\n", encoding="utf-8"
    )
    return workspace


def _gold(path_id: str = "path-1", line: int = 2) -> GoldPath:
    location = Location("module.py", line, line)
    return GoldPath(path_id, location, Location("module.py", 3, 3), (location,))


def _candidate(vulnerable_commit: str) -> CorpusCandidate:
    return CorpusCandidate(
        task_id="source-candidate-1",
        dataset_revision=DATASET_REVISION,
        entry_id="entry-00001",
        report_id="synthetic-report",
        repo_url="synthetic-repository",
        vulnerable_commit=vulnerable_commit,
        category_l1="Synthetic",
        category_l2="Synthetic category",
        gold_path=_gold(),
    )


def _selected_row(
    repository: Path,
    vulnerable: str,
    fixed: str,
    *,
    license_path: str = "LICENSE",
) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": 1,
        "state": "selected",
        "candidate_task_id": "source-candidate-1",
        "dataset_revision": DATASET_REVISION,
        "entry_id": "entry-00001",
        "report_identity": "synthetic-report",
        "repository_identity": "synthetic-repository",
        "vulnerable_commit": vulnerable,
        "fixed_commit": fixed,
        "primary_evidence": "review://synthetic-primary",
        "license_identifier": "Synthetic-1.0",
        "license_path": license_path,
        "license_sha256": _license_hash(repository, vulnerable, license_path),
        "vulnerable_tree": _tree(repository, vulnerable),
        "fixed_tree": _tree(repository, fixed),
        "language": "python",
        "group_input": "synthetic-group-1",
        "split": "public_dev",
        "suites": ["canary", "mini"],
        "time_limit_seconds": 19,
        "excluded": False,
        "fixed_locations": [_gold_to_json(_gold())],
        "comment_redactions": [],
        "quarantine_paths": [],
    }
    return row


def _excluded_row() -> dict[str, object]:
    return {
        "schema_version": 1,
        "state": "excluded",
        "dataset_revision": DATASET_REVISION,
        "entry_id": "entry-00002",
        "exclusion_reason": "synthetic exclusion",
    }


def _gold_to_json(path: GoldPath) -> dict[str, object]:
    def location(value: Location) -> dict[str, object]:
        return {"file": value.path, "line": value.start_line}

    return {
        "path_id": path.path_id,
        "entry_point": location(path.entry_point),
        "critical_operation": location(path.critical_operation),
        "trace": [location(item) for item in path.trace],
    }


def _write_ledger(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
        newline="\n",
    )


def _run_config(manifest) -> RunConfig:
    policy = ExecutionPolicy((('python',),))
    return RunConfig(
        manifest_sha256=manifest_sha256(manifest),
        task_order_sha256=task_order_sha256(manifest),
        execution_policy_sha256=execution_policy_sha256(policy),
        grader_version="synthetic",
        model="fake",
        reasoning_effort="fixed",
        seed="synthetic-seed",
        seed_supported=True,
        tool_versions=(("fake", "1"),),
        time_limit_seconds=19,
    )


class CorpusBuilderTests(unittest.TestCase):
    def test_ledger_requires_exact_terminal_row_shapes_and_distinct_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            selected = _selected_row(repository, vulnerable, fixed)
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [selected, _excluded_row()])
            rows = parse_reviewed_ledger(ledger)
            self.assertEqual([row.state for row in rows], ["selected", "excluded"])
            self.assertNotEqual(
                derive_anonymous_id(b"synthetic-key", "vulnerable", DATASET_REVISION, "entry-00001"),
                derive_anonymous_id(b"synthetic-key", "fixed", DATASET_REVISION, "entry-00001"),
            )
            malformed = selected | {"unexpected": "field"}
            _write_ledger(ledger, [malformed])
            with self.assertRaisesRegex(CorpusBuildError, "exactly"):
                parse_reviewed_ledger(ledger)
            duplicate = _excluded_row() | {"entry_id": "entry-00001"}
            _write_ledger(ledger, [selected, duplicate])
            with self.assertRaisesRegex(CorpusBuildError, "duplicate"):
                parse_reviewed_ledger(ledger)

    def test_builder_rejects_candidate_mismatch_and_unverified_fixed_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            ledger = root / "ledger.jsonl"
            selected = _selected_row(repository, vulnerable, fixed)
            _write_ledger(ledger, [selected])
            with self.assertRaisesRegex(CorpusBuildError, "candidate"):
                build_reviewed_corpus(
                    ledger,
                    {"source-candidate-1": _candidate("f" * 40)},
                    {"source-candidate-1": repository},
                    root / "output",
                    b"synthetic-key",
                    suite="canary",
                )
            selected["fixed_commit"] = vulnerable
            _write_ledger(ledger, [selected])
            with self.assertRaisesRegex(CorpusBuildError, "strict descendant"):
                build_reviewed_corpus(
                    ledger,
                    {"source-candidate-1": _candidate(vulnerable)},
                    {"source-candidate-1": repository},
                    root / "output",
                    b"synthetic-key",
                    suite="canary",
                )

    def test_builder_rejects_unchanged_roots_bad_lines_and_wrong_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root, change_source=False)
            ledger = root / "ledger.jsonl"
            selected = _selected_row(repository, vulnerable, fixed)
            _write_ledger(ledger, [selected])
            arguments = (ledger, {"source-candidate-1": _candidate(vulnerable)}, {"source-candidate-1": repository}, root / "output", b"synthetic-key")
            with self.assertRaisesRegex(CorpusBuildError, "change"):
                build_reviewed_corpus(*arguments, suite="canary")
            repository, vulnerable, fixed = _synthetic_pair(root / "second")
            selected = _selected_row(repository, vulnerable, fixed)
            selected["fixed_locations"] = [_gold_to_json(_gold(line=99))]
            _write_ledger(ledger, [selected])
            with self.assertRaisesRegex(CorpusBuildError, "line"):
                build_reviewed_corpus(ledger, {"source-candidate-1": _candidate(vulnerable)}, {"source-candidate-1": repository}, root / "output-two", b"synthetic-key", suite="canary")
            selected = _selected_row(repository, vulnerable, fixed)
            selected["fixed_tree"] = "0" * 40
            _write_ledger(ledger, [selected])
            with self.assertRaisesRegex(CorpusBuildError, "tree"):
                build_reviewed_corpus(ledger, {"source-candidate-1": _candidate(vulnerable)}, {"source-candidate-1": repository}, root / "output-three", b"synthetic-key", suite="canary")

    def test_builder_publishes_deterministic_anonymous_manifest_oracles_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [_selected_row(repository, vulnerable, fixed), _excluded_row()])
            result = build_reviewed_corpus(
                ledger,
                {"source-candidate-1": _candidate(vulnerable)},
                {"source-candidate-1": repository},
                root / "output",
                b"synthetic-key",
                suite="canary",
            )
            manifest = load_manifest(result.manifest_path)
            oracles = load_oracles(result.oracle_path)
            self.assertEqual(len(manifest.tasks), 2)
            self.assertEqual({oracle.kind for oracle in oracles.values()}, {"vulnerable", "fixed"})
            self.assertEqual(len({oracle.group_id for oracle in oracles.values()}), 1)
            self.assertTrue(all(task.task_id.startswith("hb-") for task in manifest.tasks))
            self.assertFalse(any("synthetic-repository" in path.as_posix() for path in result.snapshot_paths))
            public_bytes = result.manifest_path.read_bytes() + result.summary_path.read_bytes()
            self.assertNotIn(b"synthetic-report", public_bytes)
            self.assertNotIn(b"synthetic-repository", public_bytes)
            self.assertNotIn(vulnerable.encode(), public_bytes)
            repeat = build_reviewed_corpus(
                ledger,
                {"source-candidate-1": _candidate(vulnerable)},
                {"source-candidate-1": repository},
                root / "repeat",
                b"synthetic-key",
                suite="canary",
            )
            self.assertEqual(result.manifest_path.read_bytes(), repeat.manifest_path.read_bytes())
            self.assertEqual(result.oracle_path.read_bytes(), repeat.oracle_path.read_bytes())
            self.assertEqual(result.summary_path.read_bytes(), repeat.summary_path.read_bytes())

    def test_builder_uses_reviewed_group_input_for_paired_group_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            first = _selected_row(repository, vulnerable, fixed)
            second = first | {
                "candidate_task_id": "source-candidate-2",
                "entry_id": "entry-00002",
            }
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [first, second])
            first_candidate = _candidate(vulnerable)
            second_candidate = replace(first_candidate, task_id="source-candidate-2", entry_id="entry-00002")
            result = build_reviewed_corpus(
                ledger,
                {first_candidate.task_id: first_candidate, second_candidate.task_id: second_candidate},
                {first_candidate.task_id: repository, second_candidate.task_id: repository},
                root / "output",
                b"synthetic-key",
                suite="canary",
            )
            self.assertEqual(len({oracle.group_id for oracle in load_oracles(result.oracle_path).values()}), 1)

    def test_builder_rejects_a_group_that_crosses_splits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            first = _selected_row(repository, vulnerable, fixed)
            second = first | {
                "candidate_task_id": "source-candidate-2",
                "entry_id": "entry-00002",
                "split": "hidden_test",
            }
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [first, second])
            first_candidate = _candidate(vulnerable)
            second_candidate = replace(first_candidate, task_id="source-candidate-2", entry_id="entry-00002")
            with self.assertRaisesRegex(CorpusBuildError, "group.*split"):
                build_reviewed_corpus(
                    ledger,
                    {first_candidate.task_id: first_candidate, second_candidate.task_id: second_candidate},
                    {first_candidate.task_id: repository, second_candidate.task_id: repository},
                    root / "output",
                    b"synthetic-key",
                    suite="canary",
                )

    def test_builder_rejects_tracked_repository_output_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [_selected_row(repository, vulnerable, fixed)])
            workspace = _ignored_workspace(root)
            output = workspace / "benchmarks" / "hermesbench" / "tracked-output"
            output.parent.mkdir(parents=True)
            with patch.object(corpus_builder, "_REPOSITORY_ROOT", workspace, create=True):
                try:
                    with self.assertRaisesRegex(CorpusBuildError, "ignored"):
                        build_reviewed_corpus(
                            ledger,
                            {"source-candidate-1": _candidate(vulnerable)},
                            {"source-candidate-1": repository},
                            output,
                            b"synthetic-key",
                            suite="canary",
                        )
                finally:
                    shutil.rmtree(output, ignore_errors=True)

    def test_builder_accepts_an_actually_ignored_repository_corpus_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [_selected_row(repository, vulnerable, fixed)])
            workspace = _ignored_workspace(root)
            output = workspace / "benchmarks" / "hermesbench" / "corpora" / "nested" / "synthetic"
            output.parent.mkdir(parents=True)
            with patch.object(corpus_builder, "_REPOSITORY_ROOT", workspace, create=True):
                result = build_reviewed_corpus(
                    ledger,
                    {"source-candidate-1": _candidate(vulnerable)},
                    {"source-candidate-1": repository},
                    output,
                    b"synthetic-key",
                    suite="canary",
                )
            self.assertTrue(result.manifest_path.exists())

    def test_builder_rejects_a_linked_internal_output_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [_selected_row(repository, vulnerable, fixed)])
            workspace = _ignored_workspace(root)
            output = workspace / "benchmarks" / "hermesbench" / "corpora" / "nested" / "synthetic"
            output.parent.mkdir(parents=True)
            original = corpus_builder._is_link_or_reparse
            with (
                patch.object(corpus_builder, "_REPOSITORY_ROOT", workspace, create=True),
                patch.object(
                    corpus_builder,
                    "_is_link_or_reparse",
                    side_effect=lambda path: path == output.parents[1] or original(path),
                ),
            ):
                with self.assertRaisesRegex(CorpusBuildError, "link or reparse"):
                    build_reviewed_corpus(
                        ledger,
                        {"source-candidate-1": _candidate(vulnerable)},
                        {"source-candidate-1": repository},
                        output,
                        b"synthetic-key",
                        suite="canary",
                    )

    def test_builder_quarantines_fixed_only_files_from_both_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, _ = _synthetic_pair(root)
            (repository / "fixed-only.patch").write_text("metadata\n", encoding="utf-8")
            fixed = _commit(repository, "fixed metadata")
            selected = _selected_row(repository, vulnerable, fixed)
            selected["quarantine_paths"] = ["fixed-only.patch"]
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [selected])
            result = build_reviewed_corpus(
                ledger,
                {"source-candidate-1": _candidate(vulnerable)},
                {"source-candidate-1": repository},
                root / "output",
                b"synthetic-key",
                suite="canary",
            )
            self.assertFalse(any(path.name == "fixed-only.patch" for path in result.snapshots_root.rglob("*")))

    def test_tree_reader_rejects_clock_device_alias(self) -> None:
        raw = b"100644 blob " + b"1" * 40 + b"\tCLOCK$\0"
        with patch.object(corpus_builder, "_git_bytes", side_effect=(raw, b"contents")):
            with self.assertRaisesRegex(CorpusBuildError, "Windows-unsafe"):
                corpus_builder._read_tree(Path("synthetic"), "2" * 40)

    def test_tree_reader_batches_many_binary_blobs_in_two_git_processes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payloads = {
                "binary/embedded-nul.bin": b"\0prefix\nbody\0suffix\n",
                "binary/empty.bin": b"",
                "binary/newlines.bin": b"\n\n",
                "binary/no-final-newline.bin": b"last line",
            }
            payloads.update(
                {
                    f"many/blob-{index:03d}.bin": f"payload {index}\n".encode("ascii")
                    for index in range(64)
                }
            )
            repository, commit = _synthetic_blob_tree(root, payloads)
            tree = _tree(repository, commit)
            with patch.object(
                corpus_builder,
                "_git_completed",
                wraps=corpus_builder._git_completed,
            ) as git_completed:
                loaded = corpus_builder._read_tree(repository, tree)
            self.assertEqual(loaded.files, payloads)
            commands = [call.args[1:] for call in git_completed.call_args_list]
            self.assertEqual(commands[0], ("ls-tree", "-r", "-z", tree))
            self.assertEqual(commands[1], ("cat-file", "--batch"))
            self.assertEqual(
                git_completed.call_args_list[1].kwargs["input_bytes"].count(b"\n"),
                len(payloads),
            )
            self.assertLessEqual(git_completed.call_count, 2)

    def test_tree_reader_rejects_malformed_batch_framing(self) -> None:
        object_id = b"1" * 40
        tree = b"100644 blob " + object_id + b"\tblob.bin\0"
        malformed = (
            b"0" * 40 + b" blob 1\nx\n",
            object_id + b" blob 1\nx",
            object_id + b" blob 1\nx\ntrailing",
            object_id + b" missing\n",
            object_id + b" tree 1\nx\n",
            object_id + b" blob no-size\nx\n",
            object_id + b" blob 2\nx\n",
        )
        for output in malformed:
            with self.subTest(output=output), patch.object(
                corpus_builder,
                "_git_bytes",
                side_effect=(tree, output),
            ):
                with self.assertRaisesRegex(CorpusBuildError, "batch output"):
                    corpus_builder._read_tree(Path("synthetic"), "2" * 40)

    def test_tree_reader_rejects_out_of_order_batch_headers(self) -> None:
        first = b"1" * 40
        second = b"2" * 40
        tree = (
            b"100644 blob " + first + b"\tfirst.bin\0"
            b"100644 blob " + second + b"\tsecond.bin\0"
        )
        reversed_output = second + b" blob 1\nb\n" + first + b" blob 1\na\n"
        with patch.object(
            corpus_builder,
            "_git_bytes",
            side_effect=(tree, reversed_output),
        ):
            with self.assertRaisesRegex(CorpusBuildError, "batch output"):
                corpus_builder._read_tree(Path("synthetic"), "3" * 40)

    def test_builder_skips_exact_quarantined_symlinks_from_both_snapshots(self) -> None:
        for vulnerable_link, fixed_link in ((True, True), (True, False), (False, True)):
            with self.subTest(vulnerable_link=vulnerable_link, fixed_link=fixed_link), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repository, vulnerable, fixed, link_path = _synthetic_pair_with_symlink(
                    root,
                    vulnerable_link=vulnerable_link,
                    fixed_link=fixed_link,
                )
                selected = _selected_row(repository, vulnerable, fixed)
                selected["quarantine_paths"] = [link_path]
                ledger = root / "ledger.jsonl"
                _write_ledger(ledger, [selected])
                result = build_reviewed_corpus(
                    ledger,
                    {"source-candidate-1": _candidate(vulnerable)},
                    {"source-candidate-1": repository},
                    root / "output",
                    b"synthetic-key",
                    suite="canary",
                )
                self.assertFalse(any(path.name == link_path for path in result.snapshots_root.rglob("*")))

    def test_tree_reader_skips_quarantined_symlink_without_batch_reading_its_blob(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, _, link_path = _synthetic_pair_with_symlink(
                root,
                vulnerable_link=True,
                fixed_link=True,
            )
            tree = _tree(repository, vulnerable)
            symlink_entry = _git(repository, "ls-tree", tree, "--", link_path)
            symlink_object_id = symlink_entry.split()[2]
            with patch.object(
                corpus_builder,
                "_git_completed",
                wraps=corpus_builder._git_completed,
            ) as git_completed:
                result = corpus_builder._read_tree(repository, tree, (link_path,))
            self.assertNotIn(link_path, result.files)
            self.assertEqual(result.quarantined_symlink_paths, frozenset({link_path}))
            batch = next(
                call
                for call in git_completed.call_args_list
                if call.args[1:] == ("cat-file", "--batch")
            )
            self.assertNotIn(
                symlink_object_id.encode("ascii") + b"\n",
                batch.kwargs["input_bytes"],
            )
            self.assertLessEqual(git_completed.call_count, 2)

    def test_builder_rejects_unquarantined_symlinks_and_other_special_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed, _ = _synthetic_pair_with_symlink(
                root,
                vulnerable_link=True,
                fixed_link=True,
            )
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [_selected_row(repository, vulnerable, fixed)])
            with self.assertRaisesRegex(CorpusBuildError, "unsupported entry"):
                build_reviewed_corpus(
                    ledger,
                    {"source-candidate-1": _candidate(vulnerable)},
                    {"source-candidate-1": repository},
                    root / "output",
                    b"synthetic-key",
                    suite="canary",
                )
        submodule = b"160000 commit " + b"1" * 40 + b"\tthird-party\0"
        with patch.object(corpus_builder, "_git_bytes", return_value=submodule):
            with self.assertRaisesRegex(CorpusBuildError, "unsupported entry"):
                corpus_builder._read_tree(Path("synthetic"), "2" * 40)

    def test_builder_rejects_quarantining_the_reviewed_license_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            selected = _selected_row(repository, vulnerable, fixed)
            selected["quarantine_paths"] = ["LICENSE"]
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [selected])
            with self.assertRaisesRegex(CorpusBuildError, "license"):
                build_reviewed_corpus(
                    ledger,
                    {"source-candidate-1": _candidate(vulnerable)},
                    {"source-candidate-1": repository},
                    root / "output",
                    b"synthetic-key",
                    suite="canary",
                )

    def test_tree_reader_validates_quarantined_symlink_paths_before_skipping(self) -> None:
        object_id = b"1" * 40
        unsafe = b"120000 blob " + object_id + b"\t../escape\0"
        with patch.object(corpus_builder, "_git_bytes", return_value=unsafe):
            with self.assertRaisesRegex(CorpusBuildError, "unsafe path"):
                corpus_builder._read_tree(Path("synthetic"), "2" * 40, ("../escape",))
        collision = (
            b"120000 blob " + object_id + b"\tReadme\0"
            b"100644 blob " + object_id + b"\tREADME\0"
        )
        with patch.object(corpus_builder, "_git_bytes", return_value=collision):
            with self.assertRaisesRegex(CorpusBuildError, "case-fold"):
                corpus_builder._read_tree(Path("synthetic"), "2" * 40, ("Readme",))

    def test_builder_ignores_inherited_git_repository_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [_selected_row(repository, vulnerable, fixed)])
            poisoned = {
                "GIT_DIR": str(root / "missing-git-dir"),
                "GIT_WORK_TREE": str(root / "missing-work-tree"),
                "GIT_OBJECT_DIRECTORY": str(root / "missing-objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(root / "missing-alternates"),
                "GIT_INDEX_FILE": str(root / "missing-index"),
                "GIT_COMMON_DIR": str(root / "missing-common"),
                "GIT_NAMESPACE": "synthetic-namespace",
                "GIT_REPLACE_REF_BASE": "refs/replace/",
                "GIT_NO_REPLACE_OBJECTS": "0",
            }
            with patch.dict(os.environ, poisoned, clear=False):
                result = build_reviewed_corpus(
                    ledger,
                    {"source-candidate-1": _candidate(vulnerable)},
                    {"source-candidate-1": repository},
                    root / "output",
                    b"synthetic-key",
                    suite="canary",
                )
            self.assertTrue(result.manifest_path.exists())

    def test_builder_binds_selected_license_path_in_both_trees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            _git(repository, "init", "--quiet")
            (repository / "LICENSE.md").write_text("Synthetic license\n", encoding="utf-8")
            (repository / "module.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")
            vulnerable = _commit(repository, "vulnerable")
            (repository / "module.py").write_text(FIXED_SOURCE, encoding="utf-8")
            fixed = _commit(repository, "fixed")
            selected = _selected_row(
                repository,
                vulnerable,
                fixed,
                license_path="LICENSE.md",
            )
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [selected])
            result = build_reviewed_corpus(
                ledger,
                {"source-candidate-1": _candidate(vulnerable)},
                {"source-candidate-1": repository},
                root / "output",
                b"synthetic-key",
                suite="canary",
            )
            self.assertTrue(result.manifest_path.exists())
            (repository / "LICENSE.md").write_text("Changed license\n", encoding="utf-8")
            changed_fixed = _commit(repository, "changed license")
            changed = _selected_row(
                repository,
                vulnerable,
                changed_fixed,
                license_path="LICENSE.md",
            )
            ledger = root / "changed-ledger.jsonl"
            _write_ledger(ledger, [changed])
            with self.assertRaisesRegex(CorpusBuildError, "license blob"):
                build_reviewed_corpus(
                    ledger,
                    {"source-candidate-1": _candidate(vulnerable)},
                    {"source-candidate-1": repository},
                    root / "rejected",
                    b"synthetic-key",
                    suite="canary",
                )

    def test_builder_refuses_existing_outputs_and_contaminated_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [_selected_row(repository, vulnerable, fixed)])
            output = root / "output"
            output.mkdir()
            with self.assertRaisesRegex(CorpusBuildError, "must not exist"):
                build_reviewed_corpus(ledger, {"source-candidate-1": _candidate(vulnerable)}, {"source-candidate-1": repository}, output, b"synthetic-key", suite="canary")
            repository, vulnerable, fixed = _synthetic_pair(root / "contaminated")
            (repository / "notes.txt").write_text("CVE-9999-9999\n", encoding="utf-8")
            fixed = _commit(repository, "contaminate")
            selected = _selected_row(repository, vulnerable, fixed)
            _write_ledger(ledger, [selected])
            with self.assertRaisesRegex(CorpusBuildError, "contamination"):
                build_reviewed_corpus(ledger, {"source-candidate-1": _candidate(vulnerable)}, {"source-candidate-1": repository}, root / "contaminated-output", b"synthetic-key", suite="canary")
            self.assertFalse((root / "contaminated-output").exists())

    def test_builder_redacts_only_reviewed_fixed_comment_lines_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, _ = _synthetic_pair(root)
            fixed_source = FIXED_SOURCE + "# SECURITY FIX CVE-9999-9999\n"
            (repository / "module.py").write_text(fixed_source, encoding="utf-8")
            fixed = _commit(repository, "fixed comment")
            selected = _selected_row(repository, vulnerable, fixed)
            comment = "# SECURITY FIX CVE-9999-9999\n".encode("utf-8")
            selected["comment_redactions"] = [
                {
                    "tree": _tree(repository, fixed),
                    "path": "module.py",
                    "blob_sha256": _blob_hash(repository, fixed, "module.py"),
                    "line": 4,
                    "expected_line_sha256": hashlib.sha256(comment).hexdigest(),
                }
            ]
            selected["quarantine_paths"] = []
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [selected])
            result = build_reviewed_corpus(
                ledger,
                {"source-candidate-1": _candidate(vulnerable)},
                {"source-candidate-1": repository},
                root / "output",
                b"synthetic-key",
                suite="canary",
            )
            fixed_task = next(task.task_id for task in load_manifest(result.manifest_path).tasks if (result.snapshots_root / task.task_id / "module.py").read_text(encoding="utf-8") != VULNERABLE_SOURCE)
            fixed_bytes = (result.snapshots_root / fixed_task / "module.py").read_bytes()
            self.assertNotIn(b"CVE-9999-9999", fixed_bytes)
            self.assertIn(b"# [redacted]\n", fixed_bytes)
            self.assertEqual(fixed_bytes.count(b"\n"), FIXED_SOURCE.encode().count(b"\n") + 1)
            selected["comment_redactions"][0]["expected_line_sha256"] = "0" * 64
            _write_ledger(ledger, [selected])
            with self.assertRaisesRegex(CorpusBuildError, "redaction"):
                build_reviewed_corpus(
                    ledger,
                    {"source-candidate-1": _candidate(vulnerable)},
                    {"source-candidate-1": repository},
                    root / "rejected",
                    b"synthetic-key",
                    suite="canary",
                )
            self.assertFalse((root / "rejected").exists())

    def test_builder_symmetrically_quarantines_only_non_gold_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root, quarantined_path="notes.patch")
            selected = _selected_row(repository, vulnerable, fixed)
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [selected])
            with self.assertRaisesRegex(CorpusBuildError, "quarantine"):
                build_reviewed_corpus(ledger, {"source-candidate-1": _candidate(vulnerable)}, {"source-candidate-1": repository}, root / "unquarantined", b"synthetic-key", suite="canary")
            selected["quarantine_paths"] = ["notes.patch"]
            _write_ledger(ledger, [selected])
            result = build_reviewed_corpus(ledger, {"source-candidate-1": _candidate(vulnerable)}, {"source-candidate-1": repository}, root / "output", b"synthetic-key", suite="canary")
            self.assertFalse(any(path.name == "notes.patch" for path in result.snapshots_root.rglob("*")))
            selected["quarantine_paths"] = ["module.py"]
            _write_ledger(ledger, [selected])
            with self.assertRaisesRegex(CorpusBuildError, "gold or root"):
                build_reviewed_corpus(ledger, {"source-candidate-1": _candidate(vulnerable)}, {"source-candidate-1": repository}, root / "rejected", b"synthetic-key", suite="canary")

    def test_tree_reader_rejects_unsafe_names_collisions_and_non_regular_entries(self) -> None:
        object_id = b"1" * 40
        tree_id = "2" * 40
        cases = (
            b"100644 blob " + object_id + b"\t../escape.py\0",
            b"100644 blob " + object_id + b"\tsafe\\escape.py\0",
            b"100644 blob " + object_id + b"\tCON.txt\0",
            b"120000 blob " + object_id + b"\tlinked.py\0",
        )
        for raw in cases:
            with self.subTest(raw=raw), patch.object(corpus_builder, "_git_bytes", return_value=raw):
                with self.assertRaises(CorpusBuildError):
                    corpus_builder._read_tree(Path("synthetic"), tree_id)
        collision = (
            b"100644 blob " + object_id + b"\tReadme\0"
            b"100644 blob " + object_id + b"\tREADME\0"
        )
        with patch.object(corpus_builder, "_git_bytes", side_effect=(collision, b"first")):
            with self.assertRaisesRegex(CorpusBuildError, "case-fold"):
                corpus_builder._read_tree(Path("synthetic"), tree_id)

    def test_built_synthetic_corpus_runs_without_model_or_auth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, vulnerable, fixed = _synthetic_pair(root)
            ledger = root / "ledger.jsonl"
            _write_ledger(ledger, [_selected_row(repository, vulnerable, fixed)])
            result = build_reviewed_corpus(ledger, {"source-candidate-1": _candidate(vulnerable)}, {"source-candidate-1": repository}, root / "output", b"synthetic-key", suite="canary")
            manifest = load_manifest(result.manifest_path)
            work = root / "work"
            work.mkdir()
            policy = ExecutionPolicy((('python',),))
            receipt = run_suite(manifest, result.snapshots_root, work, "synthetic-run", "standard", "baseline", _run_config(manifest), policy, FakeAdapter())
            self.assertEqual(receipt.status, "completed")
            self.assertTrue((work / "synthetic-run" / "predictions.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
