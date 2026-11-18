#!/usr/bin/env python3
"""Offline structural, policy, eval, and CI workflow contracts for Issue #122."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import unittest

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
RUST_FILES = [
    ROOT / "src" / "storage_lifecycle" / "safe_gc.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "anti_aba.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "compaction.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "domain.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "executor.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "git_ops.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "model.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "proof.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "proof_digest.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "store.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "store_barrier.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "tests.rs",
    ROOT / "src" / "storage_lifecycle" / "safe_gc" / "tests_concurrency.rs",
    ROOT / "tests" / "storage_safe_gc.rs",
]
WORKFLOW = ROOT / ".github" / "workflows" / "storage-safe-gc.yml"
DOC = ROOT / "docs" / "storage-safe-gc.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_storage_safe_gc.py"


class StorageSafeGcContractsTest(unittest.TestCase):
    def test_rust_hygiene_default_off_and_serde_guards(self) -> None:
        facade = (ROOT / "src" / "storage_lifecycle.rs").read_text(encoding="utf-8")
        self.assertIn("pub mod safe_gc;", facade)
        self.assertLess(len(facade.splitlines()), 110)
        self.assertFalse(list((ROOT / "src" / "storage_lifecycle").rglob("mod.rs")))

        for path in RUST_FILES:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                raw = path.read_bytes()
                self.assertNotIn(b"\r\n", raw, "CRLF detected")
                text = raw.decode("utf-8")
                lines = text.splitlines()
                self.assertLess(len(lines), 500, f"{path.name} has {len(lines)} lines (>= 500)")
                self.assertNotIn("#[allow(", text, f"lint suppression forbidden in {path.name}")

        for name in ("model.rs", "proof.rs", "anti_aba.rs", "store.rs", "domain.rs"):
            src = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / name).read_text(encoding="utf-8")
            for m in re.finditer(r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:#\[[^\]]+\]\s*)*pub struct (\w+)", src):
                self.assertIn("deny_unknown_fields", m.group(0), f"{name}:{m.group(1)} missing deny_unknown_fields")

        model = (ROOT / "src" / "storage_lifecycle" / "safe_gc" / "model.rs").read_text(encoding="utf-8")
        self.assertIn("pub const SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT: bool = false;", model)

    def test_workflow_and_doc_contracts(self) -> None:
        wf_raw = WORKFLOW.read_bytes()
        self.assertNotIn(b"\r\n", wf_raw)
        wf_text = wf_raw.decode("utf-8")
        self.assertTrue(wf_text.startswith("name: "))
        self.assertNotIn("\t", wf_text)
        if yaml is not None:
            doc = yaml.safe_load(wf_text)
            on_cfg = doc.get("on") if "on" in doc else doc.get(True)
            self.assertIn("pull_request", on_cfg)
            self.assertIn("workflow_dispatch", on_cfg)
            self.assertNotIn("push", on_cfg)
            paths = on_cfg["pull_request"]["paths"]
            for req in (
                "src/storage_lifecycle.rs",
                "src/storage_lifecycle/safe_gc.rs",
                "src/storage_lifecycle/safe_gc/**",
                "tests/storage_safe_gc.rs",
                "scripts/eval_storage_safe_gc.py",
                "docs/storage-safe-gc.md",
            ):
                self.assertIn(req, paths)

        for token in (
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "cargo test --locked --no-default-features --lib storage_lifecycle::safe_gc",
            "cargo test --locked --no-default-features --test storage_safe_gc",
            "scripts/eval_storage_safe_gc.py",
        ):
            self.assertIn(token, wf_text)

        doc_text = DOC.read_text(encoding="utf-8")
        self.assertIn("SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT = false", doc_text)
        self.assertIn("#151", doc_text)
        self.assertIn("#153", doc_text)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", doc_text):
            clean = target.split("#", 1)[0]
            if not clean or "://" in clean:
                continue
            self.assertTrue((DOC.parent / clean).resolve().exists(), f"missing doc link: {target}")

    def test_eval_script_smoke_sha1_and_sha256(self) -> None:
        spec = importlib.util.spec_from_file_location("eval_storage_safe_gc", EVAL_SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.run_benchmark(["small"], ["sha1", "sha256"])
        self.assertEqual(report["issue"], 122)
        self.assertTrue(report["delete_disabled_by_default"])
        self.assertEqual(len(report["runs"]), 2)
        for run in report["runs"]:
            self.assertEqual(run["git_fsck_parity"], "pass")
            self.assertEqual(run["aba_key_collisions"], 0)
            self.assertEqual(run["false_deletions"], 0)
            self.assertGreater(run["reclaimed_orphan_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
