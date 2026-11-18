#!/usr/bin/env python3
"""Offline structural, security, benchmark, and CI workflow contracts for Issue #163."""
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
REPLICA_DIR = ROOT / "src" / "cache_wake" / "replica_cache"
RUST_FILES = [
    ROOT / "src" / "cache_wake" / "replica_cache.rs",
    *sorted(REPLICA_DIR.glob("*.rs")),
    ROOT / "tests" / "rubicon_replica_cache.rs",
]
WORKFLOW = ROOT / ".github" / "workflows" / "rubicon-replica-cache.yml"
DOC = ROOT / "docs" / "rubicon-replica-cache.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_rubicon_replica_cache.py"


class ReplicaCacheContractsTest(unittest.TestCase):
    def test_rust_modules_line_budget_mod_rs_allow_and_serde_guards(self) -> None:
        cache_wake = ROOT / "src" / "cache_wake.rs"
        cw_raw = cache_wake.read_bytes()
        self.assertNotIn(b"\r\n", cw_raw, "CRLF in cache_wake.rs")
        cw_text = cw_raw.decode("utf-8")
        self.assertIn("pub mod replica_cache;", cw_text)
        self.assertLess(len(cw_text.splitlines()), 100)
        self.assertFalse(list((ROOT / "src" / "cache_wake").rglob("mod.rs")))

        total_deserialize = 0
        for path in RUST_FILES:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                raw = path.read_bytes()
                self.assertNotIn(b"\r\n", raw, f"CRLF detected in {path.name}")
                text = raw.decode("utf-8")
                lines = text.splitlines()
                self.assertLess(len(lines), 500, f"{path.name} has {len(lines)} lines (limit < 500)")
                self.assertNotIn("#[allow(", text, f"lint suppression forbidden in {path.name}")
                self.assertIsNone(
                    re.search(r"DisposableViewRoot::open\(\s*(?:&\s*)?\w+\.path\(\s*\)", text),
                    f"must use clean 0o700 subdir instead of direct TempDir::path() in {path.name}",
                )
                for match in re.finditer(
                    r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:#\[[^\]]+\]\s*)*pub struct (\w+)",
                    text,
                ):
                    total_deserialize += 1
                    self.assertIn("deny_unknown_fields", match.group(0), f"{match.group(1)} lacks deny_unknown_fields")

        self.assertGreaterEqual(total_deserialize, 1)
        types_src = (REPLICA_DIR / "types.rs").read_text(encoding="utf-8")
        for field in (
            "tenant_id",
            "repo_id",
            "history_id",
            "cluster_incarnation",
            "backend_identity",
            "authority_epoch",
            "gate_revision",
            "membership_digest",
        ):
            self.assertIn(field, types_src)

    def test_workflow_contract_and_doc_links(self) -> None:
        wf_raw = WORKFLOW.read_bytes()
        self.assertNotIn(b"\r\n", wf_raw)
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
                ".github/workflows/rubicon-replica-cache.yml",
                "src/cache_wake.rs",
                "src/cache_wake/replica_cache.rs",
                "src/cache_wake/replica_cache/**",
                "tests/rubicon_replica_cache.rs",
                "tests/test_rubicon_replica_cache_contracts.py",
                "scripts/eval_rubicon_replica_cache.py",
                "docs/rubicon-replica-cache.md",
            ):
                self.assertIn(required, paths)

        for token in (
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "cargo clippy --locked --no-default-features --lib --test rubicon_replica_cache -- -D warnings",
            "RUSTFLAGS=\"-D warnings\" cargo test --locked --no-default-features --lib cache_wake::replica_cache",
            "RUSTFLAGS=\"-D warnings\" cargo test --locked --no-default-features --test rubicon_replica_cache",
            "scripts/eval_rubicon_replica_cache.py",
        ):
            self.assertIn(token, wf_text)

        doc_raw = DOC.read_bytes()
        self.assertNotIn(b"\r\n", doc_raw)
        doc_text = doc_raw.decode("utf-8")
        for token in ("#163", "#164", "#165", "#174", "DisposableViewRoot", "DurablePinHold", "ServingCache"):
            self.assertIn(token, doc_text)
        for token in ("python_reference_model_with_stock_git", "drr_thread_simulation"):
            self.assertIn(token, doc_text)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", doc_text):
            clean = target.split("#", 1)[0]
            if not clean or "://" in clean:
                continue
            self.assertTrue((DOC.parent / clean).resolve().exists(), f"missing doc link: {target}")

    def test_eval_script_smoke_execution_verifies_cache_failover_and_fairness(self) -> None:
        spec = importlib.util.spec_from_file_location("eval_rubicon_replica_cache", EVAL_SCRIPT)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.run_benchmark(["small"], ["sha1"])
        self.assertEqual(report["issue"], 163)
        self.assertEqual(report["benchmark_kind"], "python_reference_model_with_stock_git")
        self.assertIs(report["covers_rust_runtime_acceptance"], False)
        self.assertGreater(report["peak_rss_bytes"], 0)
        fair = report["drr_thread_simulation"]
        self.assertEqual(fair["normal_rejected"], 0)
        self.assertGreater(fair["noisy_rejected"], 0)
        self.assertEqual(len(report["results"]), 1)
        row = report["results"][0]
        self.assertTrue(row["parity_verified"])
        self.assertEqual(row["warm"]["blob_get_count"], 0)
        self.assertEqual(row["warm"]["replicated_bytes"], 0)
        self.assertGreaterEqual(row["incremental_pack_reuse"]["base_packs_reused"], 1)
        failover = row["model_failover_two_process"]
        self.assertTrue(failover["hot_node_killed"])
        self.assertNotEqual(failover["hot_worker_exit_code"], 0)
        self.assertIn(failover["hot_worker_terminated_via"], ("SIGKILL", "TerminateProcess"))
        self.assertGreater(failover["cold_blob_get_count"], 0)
        self.assertTrue(row["push_scratch"]["view_isolated"])
        self.assertEqual(row["push_scratch"]["scratch_residual_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
