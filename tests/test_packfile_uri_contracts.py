#!/usr/bin/env python3
"""Offline structural, security, benchmark, and CI workflow contracts for Issue #185."""
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
MOD_DIR = ROOT / "src" / "browse" / "packfile_uri"
SUPPORT_DIR = ROOT / "tests" / "packfile_uri_support"
OWNED_RUST_FILES = [
    ROOT / "src" / "browse" / "packfile_uri.rs",
    *sorted(MOD_DIR.glob("*.rs")),
    ROOT / "tests" / "packfile_uri_delivery.rs",
    *sorted(SUPPORT_DIR.glob("*.rs")),
]
GATEWAY_WIRING_FILES = [
    ROOT / "src" / "blob_git_gateway" / "state.rs",
    ROOT / "src" / "blob_git_gateway" / "smart_http.rs",
]
WORKFLOW = ROOT / ".github" / "workflows" / "packfile-uri-delivery.yml"
DOC = ROOT / "docs" / "packfile-uri-delivery.md"
EVAL_SCRIPT = ROOT / "scripts" / "eval_packfile_uri_delivery.py"


class PackfileUriContractsTest(unittest.TestCase):
    def test_rust_modules_line_budget_no_mod_rs_allow_and_serde_guards(self) -> None:
        browse_rs = ROOT / "src" / "browse.rs"
        browse_raw = browse_rs.read_bytes()
        self.assertNotIn(b"\r\n", browse_raw, "CRLF in src/browse.rs")
        browse_txt = browse_raw.decode("utf-8")
        self.assertIn("pub mod packfile_uri;", browse_txt)
        self.assertLess(len(browse_txt.splitlines()), 100)
        self.assertLess(len((ROOT / "src" / "browse" / "packfile_uri.rs").read_text("utf-8").splitlines()), 100)
        self.assertFalse(list((ROOT / "src" / "browse").rglob("mod.rs")))

        total_deserialize = 0
        for path in OWNED_RUST_FILES:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                raw = path.read_bytes()
                self.assertNotIn(b"\r\n", raw, f"CRLF detected in {path.name}")
                text = raw.decode("utf-8")
                lines = text.splitlines()
                self.assertLess(len(lines), 500, f"{path.name} has {len(lines)} lines (limit < 500)")
                self.assertNotIn("#[allow(", text, f"#[allow( forbidden in {path.name}")
                self.assertNotIn("#[expect(", text, f"#[expect( forbidden in {path.name}")
                for match in re.finditer(
                    r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:#\[[^\]]+\]\s*)*pub struct (\w+)",
                    text,
                ):
                    total_deserialize += 1
                    self.assertIn("deny_unknown_fields", match.group(0), f"{match.group(1)} lacks deny_unknown_fields")
        self.assertGreaterEqual(total_deserialize, 4)

        for gw_path in GATEWAY_WIRING_FILES:
            raw = gw_path.read_bytes()
            self.assertNotIn(b"\r\n", raw, f"CRLF detected in {gw_path.name}")
            text = raw.decode("utf-8")
            self.assertLess(len(text.splitlines()), 500, f"{gw_path.name} exceeds 500 lines")
        smart_txt = (ROOT / "src" / "blob_git_gateway" / "smart_http.rs").read_text("utf-8")
        self.assertNotIn("#[allow(", smart_txt)
        self.assertIn("inject_packfile_uris_into_v2_advertisement", smart_txt)
        self.assertIn("try_serve_upload_pack_v2", smart_txt)

    def test_security_and_closure_proof_contracts(self) -> None:
        types_txt = (MOD_DIR / "types.rs").read_text("utf-8")
        self.assertIn("Self::disabled()", types_txt)
        self.assertIn("DownloadSubjectContext", types_txt)
        ssrf_txt = (MOD_DIR / "ssrf_guard.rs").read_text("utf-8")
        self.assertIn("pinned_addrs", ssrf_txt)
        dl_txt = (MOD_DIR / "downloader.rs").read_text("utf-8")
        self.assertIn("resolve_to_addrs", dl_txt)
        self.assertIn(".chunk()", dl_txt)
        planner_txt = (MOD_DIR / "planner.rs").read_text("utf-8")
        self.assertIn("VerifiedFetchPlanProof", planner_txt)
        self.assertIn("binds_live_auth", planner_txt)
        delivery_txt = (MOD_DIR / "delivery.rs").read_text("utf-8")
        self.assertIn("Body::from_stream", delivery_txt)

    def test_workflow_contract_and_required_triggers(self) -> None:
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
                ".github/workflows/packfile-uri-delivery.yml",
                "src/browse.rs",
                "src/browse/packfile_uri.rs",
                "src/browse/packfile_uri/**",
                "src/blob_git_gateway/state.rs",
                "src/blob_git_gateway/smart_http.rs",
                "tests/packfile_uri_delivery.rs",
                "tests/packfile_uri_support/**",
                "tests/test_packfile_uri_contracts.py",
                "scripts/eval_packfile_uri_delivery.py",
                "docs/packfile-uri-delivery.md",
            ):
                self.assertIn(required, paths)

        for token in (
            "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            "1.99.1",
            'RUSTFLAGS="-D warnings"',
            "postgres:17",
        ):
            self.assertIn(token, wf_text)

    def test_doc_and_eval_script_contracts(self) -> None:
        doc_raw = DOC.read_bytes()
        self.assertNotIn(b"\r\n", doc_raw)
        doc_txt = doc_raw.decode("utf-8")
        self.assertLess(len(doc_txt.splitlines()), 500)
        self.assertIn("Refs #185", doc_txt)
        self.assertNotIn("Closes #185", doc_txt)

        eval_raw = EVAL_SCRIPT.read_bytes()
        self.assertNotIn(b"\r\n", eval_raw)
        self.assertLess(len(eval_raw.splitlines()), 500)
        spec = importlib.util.spec_from_file_location("eval_packfile_uri_delivery", EVAL_SCRIPT)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        report = mod.run_benchmark(["small"], ["sha1"])
        self.assertEqual(report["issue"], 185)
        self.assertIn("Does not claim cross-region", report["scope_note"])
        entry = report["results"]["small"]["sha1"]
        self.assertGreater(entry["origin_egress_reduction_ratio"], 0.5)
        self.assertGreater(entry["packfile_uris_offload_185"]["cdn_cache_hits"], 0)


if __name__ == "__main__":
    unittest.main()
