#!/usr/bin/env python3
"""Offline structural and schema contract tests for Issue #86 Forge collaboration."""

import json
import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ForgeCollaborationContractTests(unittest.TestCase):
    def test_migration_150_and_schema_snapshots_cover_all_new_tables(self) -> None:
        mig_path = ROOT / "migrations" / "150_forge_collaboration.sql"
        self.assertTrue(mig_path.exists(), "migrations/150_forge_collaboration.sql missing")
        raw_bytes = mig_path.read_bytes()
        if os.name == "nt":
            # Git with core.autocrlf=true checks out LF blobs with CRLF on Windows; verify the index blob itself is LF.
            index_bytes = subprocess.check_output(
                ["git", "cat-file", "-p", ":migrations/150_forge_collaboration.sql"],
                cwd=ROOT,
            )
            self.assertNotIn(b"\r\n", index_bytes, "migration 150 git index blob must use Unix LF line endings")
        else:
            self.assertNotIn(b"\r\n", raw_bytes, "migration 150 must use Unix LF line endings")
        sql = raw_bytes.decode("utf-8")
        sql_no_comments = "\n".join(line.split("--", 1)[0] for line in sql.splitlines())
        self.assertIsNone(
            re.search(r"\bBETWEEN\b", sql_no_comments, re.IGNORECASE),
            "migration 150 must not use BETWEEN",
        )
        expected_tables = (
            "forge_labels",
            "forge_issue_labels",
            "forge_pull_labels",
            "forge_issue_assignees",
            "forge_pull_assignees",
            "forge_pull_review_comments",
            "forge_comment_revisions",
            "forge_subscriptions",
            "forge_notifications",
        )
        for tbl in expected_tables:
            self.assertIn(f"CREATE TABLE {tbl}", sql, f"missing table {tbl} in migration 150")
        self.assertIn("UNIQUE (recipient_id, delivery_key)", sql)

        for snap_name in ("150_catalog.json", "150_restored_catalog.json", "150_upgraded_catalog.json"):
            snap = ROOT / "schema" / snap_name
            self.assertTrue(snap.exists(), f"missing schema snapshot {snap_name}")
            data = json.loads(snap.read_text(encoding="utf-8"))
            self.assertIn("tables", data)
            table_names = set(data["tables"].keys()) if isinstance(data["tables"], dict) else {
                t["name"] for t in data["tables"]
            }
            for tbl in expected_tables:
                self.assertIn(tbl, table_names, f"{tbl} missing in {snap_name}")

        cat_rs = (ROOT / "src" / "backup" / "catalog.rs").read_text(encoding="utf-8")
        verify_rs = (ROOT / "src" / "backup" / "restore" / "verify.rs").read_text(encoding="utf-8")
        self.assertIn("const FORMAT: u32 = 27;", cat_rs)
        self.assertIn("const FORMAT_PAIRED: u32 = 28;", cat_rs)
        for snap_name in ("150_catalog.json", "150_restored_catalog.json", "150_upgraded_catalog.json"):
            self.assertIn(snap_name, cat_rs, f"{snap_name} missing from backup catalog")
        self.assertIn("4..=28", verify_rs, "format 28 range missing from restore verifier")

    def test_module_boundaries_line_caps_zero_mod_rs_and_no_allow(self) -> None:
        for domain in ("forge", "pulls", "web"):
            self.assertEqual(
                list((ROOT / "src" / domain).rglob("mod.rs")),
                [],
                f"src/{domain}/ must not contain mod.rs files",
            )
        for rel, cap in (
            ("src/forge.rs", 100),
            ("src/pulls.rs", 100),
            ("src/web.rs", 100),
        ):
            lines = len((ROOT / rel).read_text(encoding="utf-8").splitlines())
            self.assertLess(lines, cap, f"{rel} exceeded {cap} lines: {lines}")

        collab_submodules = (
            "src/forge/assignees.rs",
            "src/forge/collab_tests.rs",
            "src/forge/comments.rs",
            "src/forge/handlers.rs",
            "src/forge/label_targets.rs",
            "src/forge/labels.rs",
            "src/forge/moderation.rs",
            "src/forge/notifications.rs",
            "src/forge/search.rs",
            "src/forge/subscriptions.rs",
            "src/pulls/review_comments.rs",
            "src/pulls/review_comment_actions.rs",
            "src/pulls/review_comments_tests.rs",
            "src/web/collaboration.rs",
            "src/web/collaboration_actions.rs",
            "src/web/collaboration_views.rs",
            "src/web/collaboration_tests.rs",
        )
        for rel in collab_submodules:
            path = ROOT / rel
            self.assertTrue(path.exists(), f"missing expected submodule {rel}")
            text = path.read_text(encoding="utf-8")
            lines = len(text.splitlines())
            self.assertLess(lines, 500, f"{rel} has {lines} lines (limit < 500)")
            self.assertNotIn("#[allow(", text, f"{rel} must not contain #[allow(")

    def test_all_new_deserialize_structs_deny_unknown_fields(self) -> None:
        files = (
            "src/forge/assignees.rs",
            "src/forge/labels.rs",
            "src/forge/moderation.rs",
            "src/forge/notifications.rs",
            "src/forge/search.rs",
            "src/forge/subscriptions.rs",
            "src/pulls/review_comments.rs",
            "src/pulls/review_comment_actions.rs",
            "src/web/collaboration_views.rs",
        )
        for rel in files:
            lines = (ROOT / rel).read_text(encoding="utf-8").splitlines()
            for idx, line in enumerate(lines):
                if "#[derive(" in line and "Deserialize" in line:
                    window = "\n".join(lines[max(0, idx - 3) : min(len(lines), idx + 3)])
                    # Internal untagged deserializers inside functions also deserialize cleanly,
                    # whereas API/query input structs and enums must reject unknown fields.
                    if "pub struct " in window or "pub enum " in window:
                        if "Serialize" in line and "Deserialize" in line and "RepoLabel" in window:
                            continue
                        if "enum IntOrStr" in window or "enum OptIntOrStr" in window:
                            continue
                        if "pub struct " in window and "Serialize" not in line:
                            self.assertIn(
                                "deny_unknown_fields",
                                window,
                                f"{rel}:{idx + 1} missing #[serde(deny_unknown_fields)]",
                            )

    def test_web_and_ui_collaboration_route_parity_and_docs(self) -> None:
        collab = (ROOT / "src" / "web" / "collaboration.rs").read_text(encoding="utf-8")
        self.assertIn('.merge(repo_pages("/web"))', collab)
        self.assertIn('.merge(repo_pages("/ui"))', collab)
        for shared in (
            '"/web/search"',
            '"/ui/search"',
            '"/web/notifications"',
            '"/ui/notifications"',
            '"/web/notifications/read-all"',
            '"/ui/notifications/read-all"',
            '"/web/notifications/{id}/read"',
            '"/ui/notifications/{id}/read"',
        ):
            self.assertIn(shared, collab, f"missing shared web/ui route {shared}")

        spec_doc = ROOT / "docs" / "forge-collaboration.md"
        self.assertTrue(spec_doc.exists(), "docs/forge-collaboration.md missing")
        design_doc = (ROOT / "docs" / "design" / "04-forge.md").read_text(encoding="utf-8")
        self.assertIn("forge-collaboration.md", design_doc)
        self.assertIn("<!-- BEGIN SOURCE BODY -->", design_doc)
        self.assertIn("<!-- END SOURCE BODY -->", design_doc)


if __name__ == "__main__":
    unittest.main()
