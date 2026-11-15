#!/usr/bin/env python3
"""Pure contracts for the frozen legacy135 producer preparation helper.

No Git client, Cargo, rustc, artifact-store write or network operation runs.
The tests exercise source-format refusal, path/role separation, Cargo-event
selection and the static error boundary.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import prepare_legacy135_producer as prep  # noqa: E402


def make_source(root, format_value=11, schema=135):
    root = Path(root)
    (root / "src" / "backup").mkdir(parents=True)
    (root / "migrations").mkdir()
    migrations = [(2, "002_reliability.sql"),
                  (schema, "%03d_migration.sql" % schema)]
    for version, name in migrations:
        (root / "migrations" / name).write_text("-- migration\n")
    pairs = "".join(
        '    (%d, include_str!("../migrations/%s")),\n' % pair for pair in migrations)
    versions = ", ".join(str(version) for version in [1] + [
        version for version, _ in migrations])
    (root / "src" / "db.rs").write_text(
        "pub const SCHEMA_VERSIONS: &[i32] = &[" + versions + "];\n"
        "const MIGRATIONS: &[(i32, &str)] = &[\n" + pairs + "];\n")
    (root / "src" / "backup" / "catalog.rs").write_text(
        "pub(super) const FORMAT: u32 = %d;\n" % format_value)
    return root


def args_for(root, candidate):
    return argparse.Namespace(
        source_commit=prep.FROZEN_SOURCE_COMMIT,
        source_dir=str(Path(root) / "source"),
        candidate_source_root=str(candidate),
        cargo_target_dir=str(Path(root) / "target"),
        artifact_store=str(Path(root) / "store"),
        output_dir=str(Path(root) / "output"),
    )


class FrozenSourceTest(unittest.TestCase):
    def test_exact_format11_schema135_source_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_source(Path(temporary) / "source")
            result = prep.frozen_source_contract(root)
            self.assertEqual(result["format"], 11)
            self.assertEqual(result["schema"], 135)
            self.assertTrue(result["schema136_absent"])

    def test_schema136_or_other_format_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = make_source(Path(temporary) / "a")
            (root / "migrations" / "136_next.sql").write_text("-- next\n")
            with self.assertRaises(prep.PreparationError) as caught:
                prep.frozen_source_contract(root)
            self.assertEqual(caught.exception.code, "frozen_schema136_migration_present")
        with tempfile.TemporaryDirectory() as temporary:
            root = make_source(Path(temporary) / "b", format_value=12)
            with self.assertRaises(prep.PreparationError) as caught:
                prep.frozen_source_contract(root)
            self.assertEqual(caught.exception.code, "frozen_format_not_11")


class PathSeparationTest(unittest.TestCase):
    def test_source_target_and_store_must_be_outside_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            args = args_for(root, candidate)
            paths = prep.validate_paths(args)
            self.assertEqual(paths["source_dir"], (root / "source").resolve())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            args = args_for(root, candidate)
            args.source_dir = str(candidate / "nested-source")
            with self.assertRaises(prep.PreparationError) as caught:
                prep.validate_paths(args)
            self.assertEqual(caught.exception.code, "source_inside_candidate_checkout")

    def test_output_and_store_must_not_be_inside_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            args = args_for(root, candidate)
            args.output_dir = str(root / "source" / "output")
            with self.assertRaises(prep.PreparationError) as caught:
                prep.validate_paths(args)
            self.assertEqual(caught.exception.code, "output_inside_source_checkout")

    def test_wrong_frozen_commit_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            args = args_for(root, candidate)
            args.source_commit = "0" * 40
            with self.assertRaises(prep.PreparationError) as caught:
                prep.validate_paths(args)
            self.assertEqual(caught.exception.code, "source_commit_not_frozen_560")


class BuildContractTest(unittest.TestCase):
    def test_build_command_is_locked_pando_lab_json_without_clean(self):
        command = prep.build_command({"cargo_args": ["--jobs", "2"]})
        self.assertEqual(command[:4], ["cargo", "build", "--locked", "--message-format=json"])
        self.assertIn("pando-lab", command)
        self.assertIn("--jobs", command)
        self.assertNotIn("clean", command)

    def test_cargo_failure_has_a_static_code_and_no_secret(self):
        secret = "compiler-stderr-secret"
        completed = SimpleNamespace(returncode=1, stdout="", stderr=secret)
        with mock.patch.object(prep.subprocess, "run", return_value=completed):
            with self.assertRaises(prep.PreparationError) as caught:
                prep.run_cargo_build(Path("/tmp/source"), Path("/tmp/target"),
                                    {"environment": {}, "cargo_args": []}, 60)
        self.assertEqual(caught.exception.code, "cargo_build_failed")
        self.assertNotIn(secret, str(caught.exception))

    def test_selects_exactly_one_rootyard_bin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "src" / "main.rs"
            source.parent.mkdir(parents=True)
            source.write_text("fn main() {}\n")
            executable = root / "rootyard"
            executable.write_bytes(b"binary")
            event = {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": {"name": "rootyard", "kind": ["bin"],
                           "src_path": str(source)},
                "fresh": False,
                "profile": {"opt_level": "0", "debuginfo": 2,
                            "debug_assertions": True, "overflow_checks": True,
                            "test": False},
                "executable": str(executable),
            }
            row = prep.select_rootyard_bin([event], root)
            self.assertEqual(row["kind"], "bin")
            self.assertEqual(row["target"], "rootyard")
            with self.assertRaises(prep.PreparationError) as caught:
                prep.select_rootyard_bin([event, event], root)
            self.assertEqual(caught.exception.code,
                             "cargo_binary_artifact_count_invalid")

    def test_unexpected_error_is_static_and_secret_free(self):
        secret = "unexpected-secret"
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            args = argparse.Namespace(
                source_commit=prep.FROZEN_SOURCE_COMMIT,
                source_dir=str(Path(temporary) / "source"),
                candidate_source_root=str(Path(temporary) / "candidate"),
                cargo_target_dir=str(Path(temporary) / "target"),
                artifact_store=str(Path(temporary) / "store"),
                output_dir=str(Path(temporary) / "output"),
                report=str(report),
                remote="https://example.invalid/rootyard.git",
                build_timeout=60,
            )
            with mock.patch.object(prep, "prepare", side_effect=RuntimeError(secret)), \
                    mock.patch.object(sys, "stderr", new_callable=lambda: __import__("io").StringIO()) as stderr:
                self.assertEqual(prep.main([
                    "--source-dir", args.source_dir,
                    "--candidate-source-root", args.candidate_source_root,
                    "--cargo-target-dir", args.cargo_target_dir,
                    "--artifact-store", args.artifact_store,
                    "--output-dir", args.output_dir,
                    "--report", args.report,
                ]), 1)
                self.assertNotIn(secret, stderr.getvalue())
                self.assertIn("unexpected_error", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
