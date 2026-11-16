#!/usr/bin/env python3
"""Offline structural and contract tests for Issue #31 online Namespace & Git Views."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NamespaceOnlineContractsTest(unittest.TestCase):
    def test_router_and_modularity_contracts(self):
        entry = ROOT / "src/namespace_service.rs"
        self.assertTrue(entry.is_file())
        self.assertFalse((ROOT / "src/namespace_service/mod.rs").exists())
        entry_text = entry.read_text(encoding="utf-8")
        self.assertLess(len(entry_text.splitlines()), 100)

        for route in (
            "/api/namespaces",
            "/api/namespaces/{id}",
            "/api/namespaces/{id}/views",
            "/api/views/{id}",
            "/api/views/{id}/bundle",
            "/api/views/{id}/history",
            "/api/namespaces/{id}/changesets",
            "/api/changesets/{id}",
            "/api/changesets/{id}/review",
            "/api/changesets/{id}/integrate",
            "/api/changesets/{id}/recover",
            "/api/views/{id}/changesets",
            "/git/views/{view_git}/info/refs",
            "/git/views/{view_git}/git-upload-pack",
            "/git/views/{view_git}/git-receive-pack",
        ):
            self.assertIn(route, entry_text, f"Missing route {route}")

        submodules = (
            "handlers.rs",
            "views.rs",
            "view_git_http.rs",
            "changesets.rs",
            "reverse.rs",
            "reverse_git.rs",
        )
        for sub in submodules:
            path = ROOT / "src/namespace_service" / sub
            self.assertTrue(path.is_file(), f"Missing submodule {sub}")
            text = path.read_text(encoding="utf-8")
            self.assertLess(len(text.splitlines()), 500, f"{sub} exceeds 500 lines")
            self.assertNotIn("#[allow(", text, f"Forbidden #[allow( in {sub}")

    def test_deserialize_structs_deny_unknown_fields_and_use_fine_grained_scopes(self):
        for rel in (
            "src/namespace_service.rs",
            "src/namespace_service/handlers.rs",
            "src/namespace_service/views.rs",
            "src/namespace_service/view_git_http.rs",
            "src/namespace_service/changesets.rs",
            "src/namespace_service/reverse.rs",
        ):
            text = (ROOT / rel).read_text(encoding="utf-8")
            for match in re.finditer(r"#\[derive\([^\]]*Deserialize[^\]]*\)\]\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+", text):
                window = text[max(0, match.start() - 120) : match.end() + 40]
                self.assertIn("deny_unknown_fields", window, f"Missing deny_unknown_fields in {rel}")

        handlers_txt = (ROOT / "src/namespace_service/handlers.rs").read_text(encoding="utf-8")
        views_txt = (ROOT / "src/namespace_service/views.rs").read_text(encoding="utf-8")
        git_http_txt = (ROOT / "src/namespace_service/view_git_http.rs").read_text(encoding="utf-8")
        changesets_txt = (ROOT / "src/namespace_service/changesets.rs").read_text(encoding="utf-8")
        reverse_txt = (ROOT / "src/namespace_service/reverse.rs").read_text(encoding="utf-8")

        self.assertIn("RepoAction::ContentsRead", handlers_txt)
        self.assertIn("RepoAction::ContentsRead", views_txt)
        self.assertIn("RepoAction::ContentsRead", git_http_txt)
        self.assertIn("verify_active", git_http_txt)
        self.assertIn("service=git-receive-pack", git_http_txt)
        self.assertIn("StatusCode::FORBIDDEN", git_http_txt)
        self.assertIn("RepoAction::ContentsWrite", changesets_txt)
        self.assertIn("verify_active", changesets_txt)
        self.assertIn("RepoAction::ContentsWrite", reverse_txt)
        self.assertIn("verify_active", reverse_txt)

    def test_docs_workflow_and_e2e_harness_align(self):
        doc_txt = (ROOT / "docs/namespace-views.md").read_text(encoding="utf-8")
        for token in (
            "/git/views/{id}.git/info/refs",
            "/git/views/{id}.git/git-upload-pack",
            "/api/views/{id}/history",
            "RepoAction::ContentsRead",
            "RepoAction::ContentsWrite",
            "ROOTYARD_CHANGESET_KILL_AFTER_STEP",
            "partial",
        ):
            self.assertIn(token, doc_txt, f"Missing doc reference {token}")

        wf_path = ROOT / ".github/workflows/namespace-online.yml"
        self.assertTrue(wf_path.is_file())
        wf_raw = wf_path.read_bytes()
        self.assertNotIn(b"\r\n", wf_raw, "Workflow file must use LF line endings")
        self.assertNotIn(b"\t", wf_raw, "Workflow YAML must not contain literal tabs")
        job_text = wf_raw.decode("utf-8")
        lines = job_text.splitlines()
        self.assertTrue(any(line == "jobs:" for line in lines), "Workflow missing top-level jobs:")
        self.assertTrue(any(line == "  namespace-online:" for line in lines), "Workflow missing namespace-online job")
        self.assertIn("runs-on: ubuntu-22.04", job_text)
        self.assertIn("rootyard-view-lab", job_text)
        self.assertIn("tests.test_namespace_service", job_text)
        self.assertIn("tests/namespace_online_workflows.py", job_text)
        self.assertIn("clippy", job_text)

        e2e_txt = (ROOT / "tests/namespace_online_workflows.py").read_text(encoding="utf-8")
        self.assertIn("ROOTYARD_CHANGESET_KILL_AFTER_STEP", e2e_txt)
        self.assertIn("/git/views/", e2e_txt)


if __name__ == "__main__":
    unittest.main()
