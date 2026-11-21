#!/usr/bin/env python3
"""Hermetic regression tests for pack-evaluation binary receipt verification.

The fixture is a temporary Git repository and a temporary executable.  It uses
the canonical receipt builder and reader; it never invokes Cargo, rustc,
network services or the production PostgreSQL/S3 fixtures.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import native_build_receipt as receipts  # noqa: E402
from pack_compression_eval import telemetry  # noqa: E402

TARGET_TRIPLE = "x86_64-unknown-linux-gnu"


class BinaryReceiptVerificationFixture(unittest.TestCase):
    """A clean temporary source commit, executable, and canonical v2 receipt."""

    def setUp(self) -> None:
        self.tempdir = Path(tempfile.mkdtemp(prefix="pack-eval-receipt-")).resolve()
        self.addCleanup(shutil.rmtree, self.tempdir, ignore_errors=True)
        self.repo = self.tempdir / "repo"
        self.repo.mkdir()
        self._git("init", "--quiet")
        self._git("config", "user.name", "Pack Eval Receipt Test")
        self._git("config", "user.email", "pack-eval-receipt@example.invalid")
        self._git("config", "commit.gpgsign", "false")
        self.write("Cargo.toml", '[package]\nname = "rootyard"\nversion = "0.1.0"\n')
        self.write("Cargo.lock", "version = 3\n")
        self.write("src/main.rs", "fn main() { println!(\"fixture\"); }\n")
        self.write("experimental/pando/schema.sql", "create table pando_session();\n")
        self._git("add", "Cargo.toml", "Cargo.lock", "src/main.rs", "experimental/pando/schema.sql")
        self._git("commit", "--quiet", "-m", "fixture source")
        self.environ = {"HOME": str(self.tempdir / "home")}
        self.bound = receipts.capture_bound_inputs(self.repo, environ=self.environ)
        self.binary = self.write_external("bin/rootyard", b"canonical-rootyard-binary")
        self.binary.chmod(0o755)
        self.receipt_path = self.binary.with_name(self.binary.name + ".build.json")
        self.payload = self.make_receipt()
        self.write_receipt(self.payload)

    @staticmethod
    def _put(path: Path, content: str | bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def write(self, relative: str, content: str | bytes) -> Path:
        return self._put(self.repo / relative, content)

    def write_external(self, relative: str, content: str | bytes) -> Path:
        return self._put(self.tempdir / relative, content)

    def _git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout

    def state(self) -> dict:
        return receipts.git_state(self.repo)

    def toolchain(self) -> dict:
        def identity(name: str, commit_hash: str) -> dict:
            executable = self.write_external(f"toolchain/{name}", f"fake-{name}".encode())
            return {
                "executable": str(executable),
                "executable_sha256": receipts.sha256_file(executable),
                "version": f"{name} 1.0.0 (fixture)",
                "release": "1.0.0",
                "commit_hash": commit_hash,
                "host": TARGET_TRIPLE,
            }

        return {
            "cargo": identity("cargo", "a" * 40),
            "rustc": identity("rustc", "b" * 40),
            "target_triple": TARGET_TRIPLE,
        }

    def artifact(self) -> dict:
        return receipts.cargo_artifact_record(
            {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": {
                    "name": "rootyard",
                    "kind": ["bin"],
                    "src_path": str(self.repo / "src/main.rs"),
                },
                "profile": {
                    "opt_level": "3",
                    "debuginfo": 0,
                    "debug_assertions": False,
                    "overflow_checks": False,
                    "test": False,
                },
                "fresh": True,
                "executable": str(self.binary),
            },
            self.repo,
        )

    def make_receipt(self) -> dict:
        state = self.state()
        return receipts.make_receipt_v2(
            binary_path=self.binary,
            command=["cargo", "build", "--locked", "--bin", "rootyard"],
            profile="release",
            artifacts=[self.artifact()],
            toolchain=self.toolchain(),
            bound_inputs=self.bound,
            workspace_commit=state["commit"],
            target_dir=self.tempdir / "target",
            target_triple=TARGET_TRIPLE,
            features=[],
            git_head=state["head"],
            working_tree={"tree": state["tree"], "status": state["status"]},
        )

    def write_receipt(self, payload: dict) -> None:
        self.receipt_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def verify(self) -> dict:
        return telemetry.verify_binary_receipt(self.binary, True, source_root=self.repo)

    def assert_rejected(self, expected: str) -> RuntimeError:
        with self.assertRaises(RuntimeError) as caught:
            self.verify()
        self.assertIn(expected, str(caught.exception))
        return caught.exception


class ValidReceiptTest(BinaryReceiptVerificationFixture):
    def test_clean_canonical_receipt_is_verified_and_reported(self) -> None:
        info = self.verify()

        self.assertTrue(info["receipt_verified"])
        self.assertEqual(info["path"], str(self.binary.resolve()))
        self.assertEqual(info["sha256"], receipts.sha256_file(self.binary))
        self.assertEqual(info["size_bytes"], self.binary.stat().st_size)
        self.assertEqual(info["receipt_sha256"], receipts.sha256_file(self.receipt_path))
        self.assertEqual(info["workspace_commit"], self.state()["commit"])
        self.assertEqual(info["config_digest"], self.payload["config_digest"])
        self.assertEqual(info["source_inputs_sha256"], self.payload["source_inputs_sha256"])
        self.assertEqual(info["receipt_schema"], receipts.RECEIPT_SCHEMA_V2)

    def test_symlink_input_returns_resolved_verified_path(self) -> None:
        links = self.tempdir / "links"
        links.mkdir()
        link = links / "rootyard-link"
        link.symlink_to(self.binary)

        info = telemetry.verify_binary_receipt(link, True, source_root=self.repo)

        self.assertTrue(info["receipt_verified"])
        self.assertEqual(info["path"], str(self.binary.resolve()))
        self.assertEqual(info["sha256"], receipts.sha256_file(self.binary))
        self.assertEqual(info["size_bytes"], self.binary.stat().st_size)

    def test_receipt_is_optional_only_when_absent_and_not_required(self) -> None:
        self.receipt_path.unlink()

        with self.assertRaises(RuntimeError) as caught:
            self.verify()
        self.assertIn("missing binary build receipt", str(caught.exception))

        info = telemetry.verify_binary_receipt(self.binary, False, source_root=self.repo)
        self.assertFalse(info["receipt_verified"])
        self.assertEqual(info["sha256"], receipts.sha256_file(self.binary))


class FailClosedReceiptTest(BinaryReceiptVerificationFixture):
    def test_first_digest_is_passed_to_canonical_validator(self) -> None:
        real_validator = receipts.validate_receipt
        seen: dict = {}

        def capture(receipt, **kwargs):
            seen.update(kwargs)
            return real_validator(receipt, **kwargs)

        with mock.patch.object(telemetry.build_receipt_mod, "validate_receipt", capture):
            info = self.verify()

        self.assertTrue(info["receipt_verified"])
        self.assertEqual(seen["expected_binary_sha256"], info["sha256"])
        self.assertEqual(seen["binary_path"], self.binary.resolve())

    def test_mutation_between_first_digest_and_validator_is_rejected(self) -> None:
        real_validator = receipts.validate_receipt

        def mutate_then_validate(receipt, **kwargs):
            self.binary.write_bytes(b"replacement-binary-after-first-digest")
            self.binary.chmod(0o755)
            return real_validator(receipt, **kwargs)

        with mock.patch.object(telemetry.build_receipt_mod, "validate_receipt", mutate_then_validate):
            self.assert_rejected("binary digest")

    def test_missing_canonical_validator_is_rejected(self) -> None:
        with mock.patch.object(telemetry, "build_receipt_mod", None):
            self.assert_rejected("canonical build-receipt validator is unavailable")

        with mock.patch.object(telemetry.build_receipt_mod, "validate_receipt", None):
            self.assert_rejected("canonical build-receipt validator is unavailable")

    def test_malformed_json_is_rejected(self) -> None:
        self.receipt_path.write_text("{not-json\n", encoding="utf-8")
        self.assert_rejected("malformed binary build receipt")

        self.receipt_path.write_text("[]\n", encoding="utf-8")
        self.assert_rejected("expected a JSON object")

    def test_tampered_receipt_field_is_rejected(self) -> None:
        tampered = copy.deepcopy(self.payload)
        tampered["source_inputs_sha256"] = "0" * 64
        self.write_receipt(tampered)
        self.assert_rejected("source_inputs_sha256")

    def test_tampered_binary_is_rejected(self) -> None:
        self.binary.write_bytes(self.binary.read_bytes() + b"-tampered")
        self.binary.chmod(0o755)
        self.assert_rejected("binary_sha256")

    def test_dirty_source_tree_is_rejected(self) -> None:
        (self.repo / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        self.assert_rejected("not clean")

    def test_committed_source_change_is_rejected_by_expected_head(self) -> None:
        (self.repo / "src" / "main.rs").write_text("fn main() { println!(\"changed\"); }\n", encoding="utf-8")
        self._git("add", "src/main.rs")
        self._git("commit", "--quiet", "-m", "changed source")
        self.assert_rejected("workspace_commit")

    def test_changed_source_bytes_are_rejected_even_when_status_is_clean(self) -> None:
        (self.repo / "src" / "main.rs").write_text("fn main() { println!(\"hidden\"); }\n", encoding="utf-8")
        self._git("update-index", "--assume-unchanged", "src/main.rs")
        self.assertEqual(self.state()["status"], "")
        self.assert_rejected("bound input inventory differs")

    def test_receipt_git_binding_must_match_current_source(self) -> None:
        tampered = copy.deepcopy(self.payload)
        tampered["git_head"] = "0" * 40
        self.write_receipt(tampered)
        self.assert_rejected("git_head")

        tampered = copy.deepcopy(self.payload)
        tampered["working_tree"]["tree"] = "0" * 40
        self.write_receipt(tampered)
        self.assert_rejected("working_tree.tree")

        tampered = copy.deepcopy(self.payload)
        tampered["working_tree"]["status"] = " M src/main.rs\n"
        self.write_receipt(tampered)
        self.assert_rejected("dirty working tree")


if __name__ == "__main__":
    unittest.main()
