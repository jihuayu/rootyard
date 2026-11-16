#!/usr/bin/env python3
"""Offline structural, policy, benchmark, and CI workflow contracts for Issue #165."""
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
    ROOT / "src" / "blob_store" / "read_accel.rs",
    ROOT / "src" / "blob_store" / "read_accel" / "manifest.rs",
    ROOT / "src" / "blob_store" / "read_accel" / "builder.rs",
    ROOT / "src" / "blob_store" / "read_accel" / "reader.rs",
    ROOT / "tests" / "blob_read_accel.rs",
]
WORKFLOW = ROOT / ".github" / "workflows" / "rubicon-read-accel.yml"
DOC = ROOT / "docs" / "rubicon-read-accel.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_blob_read_accel.py"


class ReadAccelContractsTest(unittest.TestCase):
    def test_rust_modules_respect_line_budget_mod_rs_allow_and_serde_guards(self) -> None:
        self.assertIn("pub mod read_accel;", (ROOT / "src" / "blob_store.rs").read_text(encoding="utf-8"))
        self.assertFalse(list((ROOT / "src" / "blob_store").rglob("mod.rs")))
        for path in RUST_FILES:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                raw = path.read_bytes()
                self.assertNotIn(b"\r\n", raw, "CRLF detected")
                text = raw.decode("utf-8")
                lines = text.splitlines()
                self.assertLess(len(lines), 500, f"{path.name} reached {len(lines)} lines (must stay < 500)")
                self.assertNotIn("#[allow(", text, f"lint suppression forbidden in {path.name}")

        manifest_src = (ROOT / "src" / "blob_store" / "read_accel" / "manifest.rs").read_text(encoding="utf-8")
        deserialize_structs = list(re.finditer(r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:#\[[^\]]+\]\s*)*pub struct (\w+)", manifest_src))
        self.assertGreaterEqual(len(deserialize_structs), 5)
        for match in deserialize_structs:
            block = match.group(0)
            self.assertIn("deny_unknown_fields", block, f"{match.group(1)} missing #[serde(deny_unknown_fields)]")

        accel_src = (ROOT / "src" / "blob_store" / "read_accel.rs").read_text(encoding="utf-8")
        self.assertIn("pub const ENABLE_BY_DEFAULT: bool = false;", accel_src)
        self.assertIn('tenant_id', manifest_src)
        self.assertIn('repo_id', manifest_src)
        self.assertIn('history_id', manifest_src)
        self.assertIn('object_format', manifest_src)
        self.assertIn('membership_generation', manifest_src)
        self.assertIn('sorted_pack_digests', manifest_src)

    def test_workflow_contract_and_doc_links(self) -> None:
        wf_text = WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(wf_text.startswith("name: "))
        self.assertNotIn("\t", wf_text)
        if yaml is not None:
            doc = yaml.safe_load(wf_text)
            on_cfg = doc.get("on") if "on" in doc else doc.get(True)
            self.assertIsInstance(on_cfg, dict)
            self.assertIn("pull_request", on_cfg)
            self.assertIn("workflow_dispatch", on_cfg)
            self.assertNotIn("push", on_cfg)
            paths = on_cfg["pull_request"]["paths"]
            for required in (
                "src/blob_store/read_accel.rs",
                "src/blob_store/read_accel/**",
                "tests/blob_read_accel.rs",
                "scripts/eval_blob_read_accel.py",
                "docs/rubicon-read-accel.md",
            ):
                self.assertIn(required, paths)

        for token in (
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "cargo test --locked --no-default-features --lib blob_store::read_accel",
            "cargo test --locked --no-default-features --test blob_read_accel",
            "scripts/eval_blob_read_accel.py",
        ):
            self.assertIn(token, wf_text)

        doc_text = DOC.read_text(encoding="utf-8")
        self.assertIn("ENABLE_BY_DEFAULT = false", doc_text)
        self.assertIn("#179", doc_text)
        self.assertIn("#163", doc_text)
        self.assertIn("#164", doc_text)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", doc_text):
            clean = target.split("#", 1)[0]
            if not clean or "://" in clean:
                continue
            self.assertTrue((DOC.parent / clean).resolve().exists(), f"missing doc link: {target}")

    def test_eval_script_smoke_execution_separates_costs_and_verifies_parity(self) -> None:
        spec = importlib.util.spec_from_file_location("eval_blob_read_accel", EVAL_SCRIPT)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.run_benchmark(["small"], ["sha1"])
        self.assertEqual(report["issue"], 165)
        self.assertFalse(report["default_enabled_policy"])
        self.assertEqual(len(report["results"]), 1)
        row = report["results"][0]
        self.assertTrue(row["parity_verified"])
        self.assertGreater(row["authoritative_pack_bytes"], 0)
        self.assertGreater(row["sidecar_bytes"], 0)
        self.assertGreater(row["sidecar_get_count"], 0)
        self.assertEqual(row["authoritative_pack_gets"], row["authoritative_pack_count"] * 2)


if __name__ == "__main__":
    unittest.main()
