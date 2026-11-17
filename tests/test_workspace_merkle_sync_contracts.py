"""Offline contract checks for Issue #181 Merkle directory manifest & incremental sync."""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_eval_module():
    path = REPO_ROOT / "scripts" / "eval_workspace_merkle_sync.py"
    spec = importlib.util.spec_from_file_location("eval_workspace_merkle_sync", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class WorkspaceMerkleSyncContractsTest(unittest.TestCase):
    def test_file_boundaries_line_caps_lf_and_no_allows(self) -> None:
        ws_lab = REPO_ROOT / "src" / "workspace_lab.rs"
        ws_text = ws_lab.read_text(encoding="utf-8")
        self.assertLess(len(ws_text.splitlines()), 148)
        self.assertIn('#[path = "workspace_lab/merkle_sync.rs"]', ws_text)
        self.assertIn("pub mod merkle_sync;", ws_text)

        mod_rs = list((REPO_ROOT / "src" / "workspace_lab").rglob("mod.rs"))
        self.assertEqual(mod_rs, [], f"unexpected mod.rs under src/workspace_lab: {mod_rs}")

        new_files = [
            REPO_ROOT / "src" / "workspace_lab" / "merkle_sync.rs",
            *sorted((REPO_ROOT / "src" / "workspace_lab" / "merkle_sync").glob("*.rs")),
            REPO_ROOT / "tests" / "workspace_merkle_sync.rs",
            REPO_ROOT / "scripts" / "eval_workspace_merkle_sync.py",
            REPO_ROOT / "tests" / "test_workspace_merkle_sync_contracts.py",
            REPO_ROOT / "docs" / "workspace-merkle-sync.md",
            REPO_ROOT / ".github" / "workflows" / "workspace-merkle-sync.yml",
        ]
        self.assertGreaterEqual(len(new_files), 15)
        for p in new_files:
            self.assertTrue(p.is_file(), f"missing deliverable: {p}")
            raw = p.read_bytes()
            self.assertNotIn(b"\r", raw, f"CRLF detected in {p}")
            text = raw.decode("utf-8")
            self.assertLess(len(text.splitlines()), 500, f"{p} exceeds 500-line budget")
            if p.suffix == ".rs":
                self.assertNotIn("#[allow(", text, f"disallowed #[allow( in {p}")

    def test_serde_deserialize_structs_deny_unknown_fields(self) -> None:
        rs_files = [
            REPO_ROOT / "src" / "workspace_lab" / "merkle_sync.rs",
            *sorted((REPO_ROOT / "src" / "workspace_lab" / "merkle_sync").glob("*.rs")),
        ]
        pat = re.compile(r"#\[derive\([^)]*Deserialize[^)]*\)\]\s*(?:\n\s*#\[[^\]]+\]\s*)*\npub struct (\w+)")
        for p in rs_files:
            text = p.read_text(encoding="utf-8")
            for match in pat.finditer(text):
                window = text[max(0, match.start() - 120) : match.end()]
                self.assertIn(
                    "deny_unknown_fields",
                    window,
                    f"{p.name}::{match.group(1)} missing #[serde(deny_unknown_fields)]",
                )

    def test_workflow_structure_and_pins(self) -> None:
        wf_path = REPO_ROOT / ".github" / "workflows" / "workspace-merkle-sync.yml"
        raw = wf_path.read_text(encoding="utf-8")
        self.assertTrue(raw.startswith("name: "))
        self.assertNotIn("\t", raw)
        parsed = yaml.safe_load(raw)
        on_cfg = parsed.get("on") or parsed.get(True)
        self.assertIn("workflow_dispatch", on_cfg)
        self.assertIn("pull_request", on_cfg)
        self.assertTrue(on_cfg["pull_request"]["paths"])
        self.assertIn("1.99.1", raw)
        self.assertIn("64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b", raw)
        self.assertIn("-D warnings", raw)
        self.assertIn("eval_workspace_merkle_sync.py", raw)

    def test_design_doc_references(self) -> None:
        doc = REPO_ROOT / "docs" / "workspace-merkle-sync.md"
        text = doc.read_text(encoding="utf-8")
        self.assertIn("eval_workspace_merkle_sync.py", text)
        self.assertIn("workspace_merkle_sync.rs", text)
        for target in re.findall(r"\[[^\]]+\]\(([^)#]+)", text):
            if target.startswith(("http://", "https://")):
                continue
            resolved = (doc.parent / target).resolve()
            self.assertTrue(resolved.exists(), f"broken relative link {target!r} in {doc}")

    def test_eval_benchmark_smoke_small_sha1(self) -> None:
        mod = _load_eval_module()
        report = mod.run_benchmark(["small"], ["sha1"])
        self.assertEqual(report["issue"], 181)
        self.assertTrue(report["source_git_rev"])
        self.assertEqual(len(report["results"]), 1)
        row = report["results"][0]
        full = row["full"]
        inc = row["incremental"]
        rest = row["restore_fork"]
        for metric in (
            "scanned_bytes",
            "hashed_bytes",
            "recomputed_nodes",
            "reused_nodes",
            "uploaded_downloaded_bytes",
            "p95_ms",
            "p99_ms",
            "cpu_ms",
            "peak_rss_kib",
            "temp_disk_bytes",
        ):
            self.assertIn(metric, full)
            self.assertIn(metric, inc)
        self.assertGreater(inc["reused_nodes"], 0)
        self.assertLess(inc["hashed_bytes"], full["hashed_bytes"])
        self.assertLess(inc["uploaded_downloaded_bytes"], full["uploaded_downloaded_bytes"])
        self.assertTrue(rest["git_fsck_ok"])


if __name__ == "__main__":
    unittest.main()
