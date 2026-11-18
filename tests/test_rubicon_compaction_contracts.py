#!/usr/bin/env python3
"""Offline structural, policy, benchmark, and CI workflow contracts for Issue #162."""
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
    ROOT / "src" / "storage_lifecycle" / "rubicon_compaction.rs",
    ROOT / "src" / "storage_lifecycle" / "rubicon_compaction" / "budget.rs",
    ROOT / "src" / "storage_lifecycle" / "rubicon_compaction" / "executor.rs",
    ROOT / "src" / "storage_lifecycle" / "rubicon_compaction" / "git_ops.rs",
    ROOT / "src" / "storage_lifecycle" / "rubicon_compaction" / "lease.rs",
    ROOT / "src" / "storage_lifecycle" / "rubicon_compaction" / "segment.rs",
    ROOT / "src" / "storage_lifecycle" / "rubicon_compaction" / "sharding.rs",
    ROOT / "src" / "storage_lifecycle" / "rubicon_compaction" / "store.rs",
    ROOT / "src" / "storage_lifecycle" / "rubicon_compaction" / "store_cas.rs",
    ROOT / "src" / "storage_lifecycle" / "rubicon_compaction" / "unit_tests.rs",
    ROOT / "tests" / "rubicon_compaction.rs",
]
WORKFLOW = ROOT / ".github" / "workflows" / "rubicon-compaction.yml"
DOC = ROOT / "docs" / "rubicon-compaction.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_rubicon_compaction.py"


class RubiconCompactionContractsTest(unittest.TestCase):
    def test_rust_modules_respect_line_budget_mod_rs_allow_and_serde_guards(self) -> None:
        facade = (ROOT / "src" / "storage_lifecycle.rs").read_text(encoding="utf-8")
        self.assertIn("pub mod rubicon_compaction;", facade)
        self.assertLess(len(facade.splitlines()), 105)
        self.assertFalse(list((ROOT / "src" / "storage_lifecycle").rglob("mod.rs")))

        for path in RUST_FILES:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                raw = path.read_bytes()
                self.assertNotIn(b"\r\n", raw, "CRLF detected")
                text = raw.decode("utf-8")
                lines = text.splitlines()
                self.assertLess(len(lines), 500, f"{path.name} reached {len(lines)} lines (must stay < 500)")
                self.assertNotIn("#[allow(", text, f"lint suppression forbidden in {path.name}")

        for src_name in ("sharding.rs", "segment.rs", "lease.rs"):
            src = (ROOT / "src" / "storage_lifecycle" / "rubicon_compaction" / src_name).read_text(encoding="utf-8")
            structs = list(
                re.finditer(
                    r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:#\[[^\]]+\]\s*)*pub struct (\w+)",
                    src,
                )
            )
            for match in structs:
                self.assertIn(
                    "deny_unknown_fields",
                    match.group(0),
                    f"{src_name}:{match.group(1)} missing #[serde(deny_unknown_fields)]",
                )

        root_mod = (ROOT / "src" / "storage_lifecycle" / "rubicon_compaction.rs").read_text(encoding="utf-8")
        self.assertIn("pub const DELETE_OLD_PACKS_BY_DEFAULT: bool = false;", root_mod)

    def test_workflow_contract_and_doc_links(self) -> None:
        wf_raw = WORKFLOW.read_bytes()
        self.assertNotIn(b"\r\n", wf_raw, "CRLF in workflow")
        wf_text = wf_raw.decode("utf-8")
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
                "src/storage_lifecycle.rs",
                "src/storage_lifecycle/rubicon_compaction.rs",
                "src/storage_lifecycle/rubicon_compaction/**",
                "tests/rubicon_compaction.rs",
                "scripts/eval_rubicon_compaction.py",
                "docs/rubicon-compaction.md",
            ):
                self.assertIn(required, paths)

        for token in (
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "cargo test --locked --no-default-features --lib storage_lifecycle::rubicon_compaction",
            "cargo test --locked --no-default-features --test rubicon_compaction",
            "scripts/eval_rubicon_compaction.py",
        ):
            self.assertIn(token, wf_text)

        doc_text = DOC.read_text(encoding="utf-8")
        self.assertIn("DELETE_OLD_PACKS_BY_DEFAULT = false", doc_text)
        self.assertIn("#122", doc_text)
        self.assertIn("#184", doc_text)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", doc_text):
            clean = target.split("#", 1)[0]
            if not clean or "://" in clean:
                continue
            self.assertTrue((DOC.parent / clean).resolve().exists(), f"missing doc link: {target}")

    def test_eval_script_smoke_execution_verifies_equivalence_and_split_accounting(self) -> None:
        spec = importlib.util.spec_from_file_location("eval_rubicon_compaction", EVAL_SCRIPT)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.run_benchmark(["small"], ["sha1"], [1, 2])
        self.assertEqual(report["issue"], 162)
        self.assertTrue(report["delete_disabled"])
        self.assertEqual(len(report["results"]), 2)
        for row in report["results"]:
            self.assertTrue(row["delete_disabled"])
            self.assertEqual(row["physical_bytes_deleted"], 0)
            self.assertFalse(row["claims_physical_savings"])
            self.assertGreater(row["retained_old_pack_bytes"], 0)
            self.assertEqual(
                row["total_physical_blob_bytes"],
                row["serving_pack_bytes"] + row["retained_old_pack_bytes"],
            )
            self.assertLess(row["compacted_serving_pack_count"], row["uncompacted_serving_pack_count"])
            self.assertEqual(row["final_mergeable_backlog_segments"], 0)
            self.assertTrue(row["equivalence"]["fsck_and_clone_verified"])


if __name__ == "__main__":
    unittest.main()
