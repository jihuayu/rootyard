"""Pure provenance-policy tests for the Issue #85 acceptance runner.

The canonical receipt reader is the real existing
``scripts/native_build_receipt.py`` implementation.  Temporary source trees and
an injectable validator are used only because a real native build receipt
cannot be produced without a compiler; no Rootyard service, PostgreSQL, Git
network, LFS network, Docker, compiler or Cargo execution occurs.
"""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

import repository_lifecycle_acceptance_support as support

ROOT = Path(__file__).resolve().parents[1]


class AcceptanceProvenanceTest(unittest.TestCase):
    def test_bind_build_receipt_real_api_good_v1_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "rootyard"
            binary.write_bytes(b"pure-temp-binary")
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "Cargo.toml").write_text("[package]\nname = \"fixture\"\n")
            (source_root / "Cargo.lock").write_text("# fixture lock\n")
            receipts = support._receipt_module(ROOT)
            commit = "a" * 40
            receipt = {
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "source_inputs_sha256": receipts.source_digest(source_root),
                "workspace_commit": commit,
                "rustc": "rustc test",
                "command": ["cargo", "build"],
            }
            receipt_path = root / "rootyard.build.json"
            receipt_path.write_text(json.dumps(receipt))
            result = support.bind_build_receipt(
                binary,
                receipt_path,
                commit,
                source_root,
                module_root=ROOT,
                helper_files=[],
            )
            self.assertTrue(result["bound"], result)
            self.assertTrue(result["source_root_verified"])
            self.assertTrue(result["receipt_byte_stable"])
            self.assertEqual(
                result["receipt_sha256"],
                hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            )

    def test_bind_build_receipt_real_api_rejects_wrong_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "rootyard"
            binary.write_bytes(b"pure-temp-binary")
            source_root = root / "source"
            (source_root / "src").mkdir(parents=True)
            (source_root / "Cargo.toml").write_text("[package]\nname = \"fixture\"\n")
            (source_root / "Cargo.lock").write_text("# fixture lock\n")
            receipts = support._receipt_module(ROOT)
            commit = "a" * 40
            receipt = {
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "source_inputs_sha256": receipts.source_digest(source_root),
                "workspace_commit": commit,
                "rustc": "rustc test",
                "command": ["cargo", "build"],
            }
            (source_root / "src" / "changed.rs").write_text("// changed\n")
            receipt_path = root / "rootyard.build.json"
            receipt_path.write_text(json.dumps(receipt))
            result = support.bind_build_receipt(
                binary,
                receipt_path,
                commit,
                source_root,
                module_root=ROOT,
                helper_files=[],
            )
            self.assertFalse(result["bound"])
            self.assertEqual(result["error_class"], "build_receipt_invalid")

    def test_bind_build_receipt_rejects_tampered_parsed_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "rootyard"
            binary.write_bytes(b"pure-temp-binary")
            source_root = root / "source"
            source_root.mkdir()
            receipt_path = root / "rootyard.build.json"
            receipt_path.write_text(json.dumps({"binary_sha256": "x"}))
            commit = "a" * 40

            def mutate_and_validate(payload, **kwargs):
                Path(kwargs["receipt_path"]).write_text(json.dumps({"tampered": True}))
                return SimpleNamespace(
                    schema="v1",
                    receipt_sha256=kwargs["receipt_sha256"],
                    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    workspace_commit=commit,
                    source_inputs_sha256="b" * 64,
                    config_digest=None,
                )

            validator = SimpleNamespace(validate_receipt=mutate_and_validate)
            result = support.bind_build_receipt(
                binary,
                receipt_path,
                commit,
                source_root,
                module_root=ROOT,
                validator=validator,
                helper_files=[],
            )
            self.assertFalse(result["bound"])
            self.assertEqual(result["error_class"], "build_receipt_invalid")

    def test_bind_build_receipt_requires_matching_external_receipt_anchor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "rootyard"
            binary.write_bytes(b"pure-temp-binary")
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "Cargo.toml").write_text("[package]\nname = \"fixture\"\n")
            (source_root / "Cargo.lock").write_text("# fixture lock\n")
            receipts = support._receipt_module(ROOT)
            commit = "a" * 40
            receipt = {
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "source_inputs_sha256": receipts.source_digest(source_root),
                "workspace_commit": commit,
                "rustc": "rustc test",
                "command": ["cargo", "build"],
            }
            receipt_path = root / "rootyard.build.json"
            receipt_path.write_text(json.dumps(receipt))
            actual = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            good = support.bind_build_receipt(
                binary,
                receipt_path,
                commit,
                source_root,
                module_root=ROOT,
                helper_files=[],
                expected_receipt_sha256=actual,
            )
            self.assertTrue(good["bound"], good)
            self.assertTrue(good["receipt_anchor_matches"])
            bad = support.bind_build_receipt(
                binary,
                receipt_path,
                commit,
                source_root,
                module_root=ROOT,
                helper_files=[],
                expected_receipt_sha256="0" * 64,
            )
            self.assertFalse(bad["bound"])
            self.assertEqual(bad["error_class"], "build_receipt_anchor_mismatch")


if __name__ == "__main__":
    unittest.main()
