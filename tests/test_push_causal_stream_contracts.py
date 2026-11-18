#!/usr/bin/env python3
"""Offline structural, protocol, benchmark, and CI workflow contracts for Issue #183."""
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
    ROOT / "src" / "namespace_service" / "push_causal_stream.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "types.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "receipt.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "protocol.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "quarantine.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "git_proc.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "lfs_verify.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "git_verify.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "closure_prove.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "commit_gate.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "sm_commands.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "sm_executor.rs",
    ROOT / "src" / "namespace_service" / "push_causal_stream" / "unit_tests.rs",
    ROOT / "tests" / "push_causal_stream.rs",
    ROOT / "tests" / "push_causal_stream" / "support.rs",
]
WORKFLOW = ROOT / ".github" / "workflows" / "push-causal-stream.yml"
DOC = ROOT / "docs" / "push-causal-stream.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_push_causal_stream.py"


class PushCausalStreamContractsTest(unittest.TestCase):
    def test_rust_modules_respect_line_budget_mod_rs_allow_and_serde_guards(self) -> None:
        facade = (ROOT / "src" / "namespace_service.rs").read_text(encoding="utf-8")
        self.assertIn("pub mod push_causal_stream;", facade)
        self.assertLess(len(facade.splitlines()), 100)
        self.assertFalse(list((ROOT / "src" / "namespace_service").rglob("mod.rs")))

        for path in RUST_FILES:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                raw = path.read_bytes()
                self.assertNotIn(b"\r\n", raw, "CRLF detected")
                text = raw.decode("utf-8")
                lines = text.splitlines()
                self.assertLess(len(lines), 500, f"{path.name} reached {len(lines)} lines (must stay < 500)")
                self.assertNotIn("#[allow(", text, f"lint suppression forbidden in {path.name}")

        for src_name in ("types.rs", "receipt.rs", "protocol.rs", "quarantine.rs"):
            src = (ROOT / "src" / "namespace_service" / "push_causal_stream" / src_name).read_text(encoding="utf-8")
            structs = list(
                re.finditer(
                    r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:#\[[^\]]+\]\s*)*pub struct (\w+)",
                    src,
                )
            )
            self.assertTrue(structs, f"expected public Deserialize struct(s) in {src_name}")
            for match in structs:
                self.assertIn(
                    "deny_unknown_fields",
                    match.group(0),
                    f"{src_name}:{match.group(1)} missing #[serde(deny_unknown_fields)]",
                )

    def test_workflow_and_design_doc_contracts(self) -> None:
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
                "src/namespace_service.rs",
                "src/namespace_service/push_causal_stream.rs",
                "src/namespace_service/push_causal_stream/**",
                "tests/push_causal_stream.rs",
                "scripts/eval_push_causal_stream.py",
                "docs/push-causal-stream.md",
            ):
                self.assertIn(required, paths)

        for token in (
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "cargo test --locked --no-default-features --lib namespace_service::push_causal_stream",
            "cargo test --locked --no-default-features --test push_causal_stream",
            "scripts/eval_push_causal_stream.py",
        ):
            self.assertIn(token, wf_text)

        doc_text = DOC.read_text(encoding="utf-8")
        for expected in ("Refs #183", "CausalPushProofReceipt", "OverlappedPipeline", "#164", "SHA-256"):
            self.assertIn(expected, doc_text)
        self.assertLess(len(doc_text.splitlines()), 500)

    def test_eval_script_runs_and_reports_overlap_vs_naive_repack(self) -> None:
        spec = importlib.util.spec_from_file_location("eval_push_causal_stream", EVAL_SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.run_benchmark(formats=["sha1"], pushes=2, base_commits=3, payload_kb=8, build_receipt=None)
        sha1 = report["formats"]["sha1"]
        self.assertLess(sha1["overlapped_stream"]["blob_put_bytes"], sha1["naive_full_repack"]["blob_put_bytes"])
        self.assertEqual(sha1["overlapped_stream"]["duplicate_materialized_bytes"], 0)
        self.assertGreater(sha1["naive_full_repack"]["duplicate_materialized_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
