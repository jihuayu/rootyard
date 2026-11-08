#!/usr/bin/env python3
"""Unit tests for parallel development boundaries, router composition, and schema baseline sync."""
import json
import re
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema_baseline  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class ParallelBoundariesTest(unittest.TestCase):
    def test_schema_baseline_matches_rust_migrations_and_sql_files(self):
        db_rs = (ROOT / "src/db.rs").read_text()
        const_match = re.search(
            r"pub const SCHEMA_VERSIONS:\s*&\[i32\]\s*=\s*&\[([0-9,\s]+)\];",
            db_rs,
        )
        self.assertIsNotNone(const_match, "SCHEMA_VERSIONS missing in src/db.rs")
        rust_versions = [
            int(token.strip())
            for token in const_match.group(1).split(",")
            if token.strip()
        ]
        self.assertEqual(rust_versions, schema_baseline.SCHEMA_VERSIONS)

        migration_pairs = re.findall(
            r'\((\d+),\s*include_str!\("../migrations/([^"]+)"\)\)',
            db_rs,
        )
        self.assertEqual(
            [1] + [int(version) for version, _ in migration_pairs],
            schema_baseline.SCHEMA_VERSIONS,
        )
        sql_files = sorted(p.name for p in (ROOT / "migrations").glob("*.sql"))
        self.assertEqual(
            ["001_initial.sql"] + [name for _, name in migration_pairs],
            sql_files,
        )

    def test_backup_tables_match_schema_baseline(self):
        # The backup now consumes the frozen catalog directly. Native schema
        # and backup suites check it against PostgreSQL; this is a wiring guard.
        catalog_rs = (ROOT / "src/backup/catalog.rs").read_text()
        self.assertIn('schema/' + schema_baseline.CATALOG_JSON_PATH.name, catalog_rs)
        for name in ('catalog', 'restored_catalog', 'upgraded_catalog'):
            value = json.loads((ROOT / 'schema' / f'{schema_baseline.LATEST_PREFIX}_{name}.json').read_text())
            tables = {item['name'] for item in value['tables'] if item['kind'] == 'r'}
            self.assertEqual(tables, schema_baseline.EXPECTED_TABLES)
        self.assertIn('catalog::relations(FORMAT, true)', (ROOT / 'src/backup/snapshot.rs').read_text())

    def test_catalog_fixtures_exist(self):
        for path in (
            schema_baseline.CATALOG_SQL_PATH,
            schema_baseline.CATALOG_JSON_PATH,
            schema_baseline.RESTORED_CATALOG_JSON_PATH,
            schema_baseline.UPGRADED_CATALOG_JSON_PATH,
        ):
            self.assertTrue(path.is_file(), f"Missing schema fixture: {path}")

    def test_domain_routers_are_self_contained_and_merged_in_lib_rs(self):
        lib_rs = (ROOT / "src/lib.rs").read_text()
        domain_modules = (
            "browse",
            "ci_pins",
            "ci_checkouts",
            "reliability",
            "forge",
            "pulls",
            "lfs",
            "webhooks",
            "members",
            "web",
            "sharding",
        )
        for mod_name in domain_modules:
            mod_path = ROOT / "src" / f"{mod_name}.rs"
            self.assertTrue(mod_path.is_file(), f"Missing domain module {mod_path}")
            mod_source = mod_path.read_text()
            self.assertRegex(
                mod_source,
                r"pub fn routes\((?:state: Arc<AppState>)?\) -> Router<Arc<AppState>>",
                f"{mod_name}.rs must expose its domain router",
            )
            self.assertRegex(
                lib_rs,
                rf"\.merge\({mod_name}::routes\((?:state\.clone\(\))?\)\)",
                f"src/lib.rs must merge {mod_name}::routes()",
            )

    def test_shared_auth_and_event_contracts_exist(self):
        auth_rs = (ROOT / "src/auth.rs").read_text()
        for signature in (
            "pub fn idempotency_key(",
            "pub async fn authorize_repo_with_role(",
            "pub async fn authorize_repo_action_by_id(",
            "pub async fn verify_token(",
            "pub async fn finish_tx(",
        ):
            self.assertIn(signature, auth_rs)

        # Repository authorization must carry the explicit PAT action; the
        # former untyped convenience wrapper was removed by scope hardening.
        self.assertNotIn("pub async fn authorize_repo(", auth_rs)
        self.assertRegex(auth_rs, r"pub async fn authorize_repo_with_role\([^)]*action: crate::token_scopes::RepoAction")

        events_rs = (ROOT / "src/events.rs").read_text()
        dispatch_rs = (ROOT / "src/dispatch.rs").read_text()
        self.assertIn("pub const CONSUMERS: &[&str]", events_rs)
        self.assertIn("events::CONSUMERS", dispatch_rs)

        pulls_handlers = (ROOT / "src/pulls/handlers.rs").read_text()
        self.assertIn("crate::webhooks::delivery::on_pull_synchronized", pulls_handlers)

    def test_tier2_modularity_and_staged_schemas_exist(self):
        for dom in ("webhooks", "members"):
            root_rs = ROOT / "src" / f"{dom}.rs"
            self.assertTrue(root_rs.is_file())
            self.assertFalse((ROOT / "src" / dom / "mod.rs").exists())
            self.assertLess(len(root_rs.read_text().splitlines()), 100)

        for sql_rel in ("src/webhooks/040_webhooks.sql", "src/members/050_members_rbac.sql"):
            sql_path = ROOT / sql_rel
            self.assertTrue(sql_path.is_file(), f"Missing staged schema {sql_rel}")
            self.assertIsNone(re.search(r"\bBETWEEN\b", sql_path.read_text(), re.IGNORECASE))

        for p_sub in ("migration.rs", "rollback.rs"):
            p_path = ROOT / "src/pando_lab" / p_sub
            self.assertTrue(p_path.is_file())
            self.assertLess(len(p_path.read_text().splitlines()), 850)

        for w_sub in ("remote.rs", "namespace.rs"):
            w_path = ROOT / "src/workspace_lab" / w_sub
            self.assertTrue(w_path.is_file())
            self.assertLess(len(w_path.read_text().splitlines()), 600)

    def test_tier3_modularity_and_staged_schemas_exist(self):
        for dom in ("web", "sharding"):
            root_rs = ROOT / "src" / f"{dom}.rs"
            self.assertTrue(root_rs.is_file())
            self.assertFalse((ROOT / "src" / dom / "mod.rs").exists())
            self.assertLess(len(root_rs.read_text().splitlines()), 100)

        sql_path = ROOT / "src/sharding/060_sharding_fencing.sql"
        self.assertTrue(sql_path.is_file(), "Missing staged schema src/sharding/060_sharding_fencing.sql")
        self.assertIsNone(re.search(r"\bBETWEEN\b", sql_path.read_text(), re.IGNORECASE))

        for p_sub in ("object_store.rs", "repack.rs"):
            p_path = ROOT / "src/pando_lab" / p_sub
            self.assertTrue(p_path.is_file())
            self.assertLess(len(p_path.read_text().splitlines()), 850)

        w_path = ROOT / "src/workspace_lab/vfs.rs"
        self.assertTrue(w_path.is_file())
        self.assertLess(len(w_path.read_text().splitlines()), 600)

    def test_tier4_modularity_exists(self):
        for rel, cap in (
            ("src/mirror/auto_origin.rs", 450),
            ("src/pando_lab/lifecycle.rs", 450),
            ("src/workspace_lab/writable_view.rs", 500),
            ("src/sharding/rebalance.rs", 500),
        ):
            p = ROOT / rel
            self.assertTrue(p.is_file(), f"Missing Tier-4 submodule {rel}")
            self.assertLess(len(p.read_text().splitlines()), cap)

    def test_tier5_modularity_exists(self):
        view_lab_rs = ROOT / "src/view_lab.rs"
        self.assertTrue(view_lab_rs.is_file(), "Missing src/view_lab.rs")
        self.assertFalse((ROOT / "src/view_lab/mod.rs").exists(), "Forbidden src/view_lab/mod.rs")
        self.assertLess(len(view_lab_rs.read_text().splitlines()), 120)

        for sub in ("models.rs", "namespace.rs", "projection.rs", "changeset.rs"):
            sub_path = ROOT / "src/view_lab" / sub
            self.assertTrue(sub_path.is_file(), f"Missing view_lab submodule {sub}")
            self.assertLess(len(sub_path.read_text().splitlines()), 500)

        for rel, cap in (
            ("src/browse/object_format.rs", 480),
            ("src/pando_lab/object_format.rs", 480),
            ("src/sharding/benchmark.rs", 480),
            ("src/workspace_lab/crash_recovery.rs", 500),
        ):
            p = ROOT / rel
            self.assertTrue(p.is_file(), f"Missing Tier-5 submodule {rel}")
            self.assertLess(len(p.read_text().splitlines()), cap)

        gitignore_txt = (ROOT / ".gitignore").read_text()
        self.assertTrue(
            "/ORIGINAL_REQUEST.md" in gitignore_txt or "ORIGINAL_REQUEST.md" in gitignore_txt,
            "Missing /ORIGINAL_REQUEST.md in .gitignore",
        )


if __name__ == "__main__":
    unittest.main()
