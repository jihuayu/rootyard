#!/usr/bin/env python3
"""Phase 2 Tier-5 White-Box Adversarial Test Suite (Milestone M5 / F19).

Probes cross-track integration boundaries, router parameter & method non-collision,
schema baseline 030 catalog & FK topological invariants, anti-monolith Rust 2024
module architecture, and white-box adversarial boundary inputs across Tracks 1-4.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import e2e_tiers  # noqa: E402
import schema_baseline  # noqa: E402
from workspace import WorkspaceHarness  # noqa: E402


def _extract_route_registrations(rs_path: Path) -> list[tuple[str, list[str]]]:
    """Extracts (route_path, [http_methods]) from .route("...", <method_chain>) calls in a Rust file."""
    text = rs_path.read_text(encoding="utf-8")
    results: list[tuple[str, list[str]]] = []
    idx = 0
    while True:
        pos = text.find(".route(", idx)
        if pos == -1:
            break
        depth = 0
        end = pos + len(".route")
        in_str = False
        escape = False
        for i in range(end, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if not in_str:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        call_body = text[end + 1 : i]
                        idx = i + 1
                        break
        else:
            break

        m_path = re.search(r'"([^"]+)"', call_body)
        if not m_path:
            continue
        route_path = m_path.group(1)
        remainder = call_body[m_path.end() :]
        methods = [m.upper() for m in re.findall(r"\b(get|post|put|patch|delete)\s*\(", remainder)]
        results.append((route_path, methods))
    return results


def _normalize_route_pattern(route_path: str) -> str:
    """Replaces {param} with {} and {*wildcard} with {*} for collision detection."""
    segments = []
    for seg in route_path.strip("/").split("/"):
        if seg.startswith("{*") and seg.endswith("}"):
            segments.append("{*}")
        elif seg.startswith("{") and seg.endswith("}"):
            segments.append("{}")
        else:
            segments.append(seg)
    return "/" + "/".join(segments)


class TestTier5RouterAndParameterNonCollision(unittest.TestCase):
    """Class 1: Cross-track router, method, and Axum 0.8 matchit parameter non-collision."""

    PRIMARY_ROUTER_FILES = (
        "src/lib.rs",
        "src/browse.rs",
        "src/ci_pins.rs",
        "src/ci_checkouts.rs",
        "src/reliability.rs",
        "src/forge.rs",
        "src/pulls.rs",
        "src/lfs.rs",
        "src/members.rs",
        "src/web.rs",
        "src/sharding.rs",
    )
    ALL_PRIMARY_ROUTER_FILES = (
        *PRIMARY_ROUTER_FILES,
        "src/webhooks.rs",
    )

    def test_all_seven_domain_routers_and_lib_rs_have_zero_method_path_collisions(self) -> None:
        lib_text = (ROOT / "src/lib.rs").read_text(encoding="utf-8")
        for domain in (
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
        ):
            self.assertIn(f".merge({domain}::routes())", lib_text)

        seen_bindings: dict[tuple[str, str], tuple[str, str]] = {}
        total_bindings = 0
        for rel in self.ALL_PRIMARY_ROUTER_FILES:
            regs = _extract_route_registrations(ROOT / rel)
            self.assertGreater(len(regs), 0, f"No routes found in {rel}")
            for raw_path, methods in regs:
                self.assertGreater(len(methods), 0, f"No HTTP methods extracted for {raw_path} in {rel}")
                norm = _normalize_route_pattern(raw_path)
                for method in methods:
                    key = (norm, method)
                    self.assertNotIn(
                        key,
                        seen_bindings,
                        f"Route/method collision on {key}: {rel} ({raw_path}) vs {seen_bindings.get(key)}",
                    )
                    seen_bindings[key] = (rel, raw_path)
                    total_bindings += 1

        self.assertGreaterEqual(total_bindings, 80)

    def test_axum_08_matchit_parameter_names_are_consistent_at_all_shared_prefixes(self) -> None:
        # Build prefix tree across primary + mirror routers and verify parameter names match at every shared node
        param_by_prefix: dict[tuple[str, ...], tuple[str, str, str]] = {}
        all_files = (*self.ALL_PRIMARY_ROUTER_FILES, "src/mirror.rs")
        for rel in all_files:
            for raw_path, _ in _extract_route_registrations(ROOT / rel):
                segments = [s for s in raw_path.strip("/").split("/") if s]
                norm_prefix: list[str] = []
                for seg in segments:
                    if seg.startswith("{") and seg.endswith("}"):
                        key = tuple(norm_prefix)
                        if key in param_by_prefix:
                            prev_seg, prev_file, prev_path = param_by_prefix[key]
                            self.assertEqual(
                                seg,
                                prev_seg,
                                f"Axum 0.8 matchit parameter conflict under prefix /{'/'.join(norm_prefix)}: "
                                f"{seg} in {rel} ({raw_path}) vs {prev_seg} in {prev_file} ({prev_path})",
                            )
                        else:
                            param_by_prefix[key] = (seg, rel, raw_path)
                        norm_prefix.append("{*}" if seg.startswith("{*") else "{}")
                    else:
                        norm_prefix.append(seg)

        # Explicitly verify cross-track shared prefix parameter names
        self.assertEqual(param_by_prefix[("api", "repos")][0], "{owner}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}")][0], "{name}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "commits")][0], "{oid}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "pulls")][0], "{number}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "issues")][0], "{number}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "ci-pins")][0], "{job}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "ci-checkouts")][0], "{job}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "webhooks")][0], "{hook_id}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "webhooks", "{}", "deliveries")][0], "{delivery_id}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "integrations")][0], "{hook_id}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "collaborators")][0], "{username}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "teams")][0], "{team_slug}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "teams", "{}", "members")][0], "{username}")
        self.assertEqual(param_by_prefix[("api", "repos", "{}", "{}", "permissions")][0], "{username}")

    def test_no_legacy_axum_07_colon_or_star_route_syntax_and_valid_wildcard_placement(self) -> None:
        wildcard_routes: list[tuple[str, str]] = []
        for rs_file in sorted((ROOT / "src").rglob("*.rs")):
            rel = rs_file.relative_to(ROOT).as_posix()
            for raw_path, _ in _extract_route_registrations(rs_file):
                self.assertTrue(raw_path.startswith("/"), f"Route must start with '/': {raw_path} in {rel}")
                self.assertNotIn("/:", raw_path, f"Legacy Axum 0.7 ':param' syntax forbidden in {rel}: {raw_path}")
                self.assertNotIn("/*", raw_path, f"Legacy Axum 0.7 '*wildcard' syntax forbidden in {rel}: {raw_path}")
                segments = [s for s in raw_path.strip("/").split("/") if s]
                for i, seg in enumerate(segments):
                    if seg.startswith("{*"):
                        self.assertEqual(
                            i,
                            len(segments) - 1,
                            f"Catch-all wildcard {seg} must be final segment in {raw_path} ({rel})",
                        )
                        wildcard_routes.append((rel, raw_path))

        self.assertEqual(wildcard_routes, [("src/pulls.rs", "/api/repos/{owner}/{name}/branch-rules/{*branch}")])

    def test_lfs_upload_routes_disable_default_body_limit_while_api_router_caps_at_16kib(self) -> None:
        lfs_src = (ROOT / "src/lfs.rs").read_text(encoding="utf-8")
        lib_src = (ROOT / "src/lib.rs").read_text(encoding="utf-8")
        mirror_src = (ROOT / "src/mirror.rs").read_text(encoding="utf-8")

        self.assertIn("DefaultBodyLimit::disable()", lfs_src)
        self.assertIn(".merge(upload_routes)", lfs_src)
        self.assertIn("DefaultBodyLimit::max(16 * 1024)", lib_src)
        self.assertIn("DefaultBodyLimit::max(16 * 1024)", mirror_src)

        # Ensure only PUT object routes are inside upload_routes before .layer(DefaultBodyLimit::disable())
        upload_block = lfs_src.split("DefaultBodyLimit::disable()", 1)[0]
        self.assertEqual(upload_block.count("put(handlers::upload_object"), 8)
        self.assertNotIn("post(handlers::batch)", upload_block)

    def test_mirror_router_isolation_and_route_table_completeness(self) -> None:
        mirror_regs = _extract_route_registrations(ROOT / "src/mirror.rs")
        route_map = {path: methods for path, methods in mirror_regs}
        expected = {
            "/health/live": ["GET"],
            "/health/ready": ["GET"],
            "/api/repos/{owner}/{name}/mirror-sync": ["POST"],
            "/api/repos/{owner}/{name}/mirror-prepare": ["POST"],
            "/api/repos/{owner}/{name}/mirror-evict": ["POST"],
            "/api/repos/{owner}/{name}/mirror-prune": ["POST"],
            "/api/repos/{owner}/{name}/mirror-status": ["GET"],
            "/api/repos/{owner}/{name}/mirror-auto-fetch": ["POST"],
            "/api/repos/{owner}/{name}/mirror-runners": ["GET", "POST"],
            "/metrics": ["GET"],
        }
        self.assertEqual(route_map, expected)


class TestTier5Schema030AndBackupCatalogAdversarial(unittest.TestCase):
    """Class 2: Schema baseline 060, FK topological DAG, backup lock ordering, and relational CHECK constraints."""

    def test_migrations_001_to_030_exact_version_sequence_and_staged_sql_byte_parity(self) -> None:
        self.assertEqual(schema_baseline.SCHEMA_VERSIONS, [1, 2, 3, 6, 7, 8, 9, 20, 30, 40, 50, 60])
        self.assertEqual(schema_baseline.LATEST_VERSION, 60)
        self.assertEqual(schema_baseline.LATEST_PREFIX, "060")
        self.assertEqual(schema_baseline.TABLE_COUNT, 34)

        info = e2e_tiers.SchemaBoundaryIntegrationFixture.verify_db_rs_and_migrations()
        self.assertEqual(info["versions"], schema_baseline.SCHEMA_VERSIONS)

        staged_pairs = [
            ("migrations/009_forge_pulls.sql", "src/pulls/009_forge_pulls.sql", 9),
            ("migrations/020_lfs_objects.sql", "src/lfs/020_lfs_objects.sql", 20),
            ("migrations/030_ci_mirror.sql", "src/mirror/030_ci_mirror.sql", 30),
            ("migrations/040_webhooks.sql", "src/webhooks/040_webhooks.sql", 40),
            ("migrations/050_members_rbac.sql", "src/members/050_members_rbac.sql", 50),
            ("migrations/060_sharding_fencing.sql", "src/sharding/060_sharding_fencing.sql", 60),
        ]
        for mig_rel, staged_rel, ver in staged_pairs:
            mig_bytes = (ROOT / mig_rel).read_bytes()
            staged_bytes = (ROOT / staged_rel).read_bytes()
            self.assertEqual(mig_bytes, staged_bytes, f"{mig_rel} must match {staged_rel} byte-for-byte")
            self.assertRegex(
                mig_bytes.decode("utf-8").strip(),
                rf"INSERT INTO schema_migrations \(version\) VALUES \({ver}\)(?:\s+ON CONFLICT(?:\s*\(version\))?\s+DO NOTHING)?;$",
            )

    def test_zero_between_clauses_in_new_migrations_and_030_catalog_constraints(self) -> None:
        for mig_name in (
            "009_forge_pulls.sql",
            "020_lfs_objects.sql",
            "030_ci_mirror.sql",
            "040_webhooks.sql",
            "050_members_rbac.sql",
            "060_sharding_fencing.sql",
        ):
            sql_text = (ROOT / "migrations" / mig_name).read_text(encoding="utf-8")
            e2e_tiers.SchemaBoundaryIntegrationFixture.validate_sql_no_between(sql_text)

        new_tables = {
            "ci_mirror_evictions",
            "forge_branch_rules",
            "forge_check_runs",
            "forge_pull_counters",
            "forge_pull_reviews",
            "forge_pulls",
            "forge_webhook_callbacks",
            "forge_webhook_deliveries",
            "forge_webhooks",
            "lfs_objects",
            "repository_audit_log",
            "repository_collaborators",
            "repository_shard_routes",
            "repository_team_members",
            "repository_teams",
            "shard_failover_operations",
            "shard_nodes",
            "shard_virtual_buckets",
        }
        for cat_path in (
            schema_baseline.CATALOG_JSON_PATH,
            schema_baseline.RESTORED_CATALOG_JSON_PATH,
            schema_baseline.UPGRADED_CATALOG_JSON_PATH,
        ):
            data = json.loads(cat_path.read_text(encoding="utf-8"))
            for con in data["constraints"]:
                if con["table"] in new_tables:
                    self.assertNotIn(
                        "BETWEEN",
                        con["definition"].upper(),
                        f"Forbidden BETWEEN in {cat_path.name} constraint {con['name']}",
                    )

    def test_foreign_key_topological_dag_and_composite_tenant_isolation_across_all_23_tables(self) -> None:
        created_order: list[str] = []
        fk_edges: list[tuple[str, str]] = []
        composite_tenant_tables: set[str] = set()

        for sql_path in sorted((ROOT / "migrations").glob("*.sql")):
            sql_text = "\n".join(
                line.split("--", 1)[0] for line in sql_path.read_text(encoding="utf-8").splitlines()
            )
            for m_tbl in re.finditer(
                r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z0-9_]+)\s*\((.*?)\);",
                sql_text,
                re.IGNORECASE | re.DOTALL,
            ):
                tbl_name = m_tbl.group(1)
                body = m_tbl.group(2)
                created_order.append(tbl_name)
                for m_ref in re.finditer(r"REFERENCES\s+(?:public\.)?([a-z0-9_]+)\s*\(", body, re.IGNORECASE):
                    parent_tbl = m_ref.group(1)
                    self.assertIn(
                        parent_tbl,
                        created_order,
                        f"Child table {tbl_name} in {sql_path.name} references {parent_tbl} before it is created",
                    )
                    fk_edges.append((parent_tbl, tbl_name))
                if re.search(
                    r"FOREIGN\s+KEY\s*\(\s*repository_id\s*,\s*(?:tenant_id|owner_id|actor_id)\s*\)\s*REFERENCES\s+repositories\s*\(\s*id\s*,\s*owner_id\s*\)",
                    body,
                    re.IGNORECASE,
                ):
                    composite_tenant_tables.add(tbl_name)

        self.assertEqual(len(created_order), schema_baseline.TABLE_COUNT)
        self.assertEqual(set(created_order), schema_baseline.EXPECTED_TABLES)
        expected_composite = {
            "ci_checkout_jobs",
            "forge_branch_rules",
            "forge_check_runs",
            "forge_creation_requests",
            "forge_issue_counters",
            "forge_issues",
            "forge_pull_counters",
            "forge_pulls",
            "forge_webhook_callbacks",
            "forge_webhook_deliveries",
            "forge_webhooks",
            "git_operations",
            "lfs_objects",
            "repository_audit_log",
            "repository_collaborators",
            "repository_shard_routes",
            "repository_teams",
            "shard_failover_operations",
        }
        self.assertEqual(composite_tenant_tables, expected_composite)

    def test_backup_tables_lexicographical_lock_ordering_and_advisory_lock_barrier(self) -> None:
        info = e2e_tiers.SchemaBoundaryIntegrationFixture.verify_backup_tables_parity()
        self.assertEqual(info["count"], schema_baseline.TABLE_COUNT)
        self.assertEqual(info["tables"], sorted(schema_baseline.EXPECTED_TABLES))

        backup_src = (ROOT / "src/backup.rs").read_text(encoding="utf-8")
        adv_pos = backup_src.find("pg_advisory_lock(738390103)")
        lock_pos = backup_src.find("LOCK TABLE {list} IN SHARE MODE")
        self.assertGreater(adv_pos, 0)
        self.assertGreater(lock_pos, adv_pos, "pg_advisory_lock must precede LOCK TABLE in src/backup.rs")
        self.assertIn(f'include_str!("../schema/{schema_baseline.LATEST_PREFIX}_catalog.sql")', backup_src)
        self.assertIn(f'include_str!("../schema/{schema_baseline.LATEST_PREFIX}_catalog.json")', backup_src)
        self.assertIn(f'include_str!("../schema/{schema_baseline.LATEST_PREFIX}_restored_catalog.json")', backup_src)
        self.assertIn(f'include_str!("../schema/{schema_baseline.LATEST_PREFIX}_upgraded_catalog.json")', backup_src)
        for tbl in (
            "forge_webhook_callbacks",
            "forge_webhook_deliveries",
            "forge_webhooks",
            "repository_audit_log",
            "repository_collaborators",
            "repository_shard_routes",
            "repository_team_members",
            "repository_teams",
            "shard_failover_operations",
            "shard_nodes",
            "shard_virtual_buckets",
        ):
            self.assertIn(f'"{tbl}"', backup_src)

    def test_schema_030_catalog_json_structural_invariants_and_contract_digest(self) -> None:
        self.assertEqual(
            (ROOT / f"schema/{schema_baseline.LATEST_PREFIX}_catalog.sql").read_bytes(),
            (ROOT / "schema/008_catalog.sql").read_bytes(),
        )
        catalogs = [
            json.loads(p.read_text(encoding="utf-8"))
            for p in (
                schema_baseline.CATALOG_JSON_PATH,
                schema_baseline.RESTORED_CATALOG_JSON_PATH,
                schema_baseline.UPGRADED_CATALOG_JSON_PATH,
            )
        ]
        for cat in catalogs:
            self.assertEqual(len(cat["tables"]), schema_baseline.TABLE_COUNT)
            self.assertGreaterEqual(len(cat["columns"]), 314)
            self.assertGreaterEqual(len(cat["constraints"]), 254)
            self.assertGreaterEqual(len(cat["indexes"]), 70)
            self.assertEqual(cat["internal_disabled_triggers"], 0)
            self.assertEqual(cat["rules"], 0)
            self.assertEqual(cat["policies"], 0)
            self.assertEqual(cat["event_triggers"], 0)
            self.assertEqual(
                [t["name"] for t in cat["tables"]],
                sorted(t["name"] for t in cat["tables"]),
            )

        # Post-008 tables must have identical constraints across all 3 catalog fixtures
        new_tables = {
            "ci_mirror_evictions",
            "forge_branch_rules",
            "forge_check_runs",
            "forge_pull_counters",
            "forge_pull_reviews",
            "forge_pulls",
            "forge_webhook_callbacks",
            "forge_webhook_deliveries",
            "forge_webhooks",
            "lfs_objects",
            "repository_audit_log",
            "repository_collaborators",
            "repository_shard_routes",
            "repository_team_members",
            "repository_teams",
            "shard_failover_operations",
            "shard_nodes",
            "shard_virtual_buckets",
        }
        c0 = [c for c in catalogs[0]["constraints"] if c["table"] in new_tables]
        c1 = [c for c in catalogs[1]["constraints"] if c["table"] in new_tables]
        c2 = [c for c in catalogs[2]["constraints"] if c["table"] in new_tables]
        self.assertEqual(c0, c1)
        self.assertEqual(c1, c2)
        self.assertEqual(len(c0), 158)

    def test_sqlite_relational_constraint_adversarial_rejection_on_009_020_030_tables(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rootyard-tier5-sql-") as tmp:
            tmp_path = Path(tmp)
            git_fix = e2e_tiers.GitRepoFixture(tmp_path / "repo.git", init_seeded=True)
            pulls = e2e_tiers.Track1PullsEngine(git_fix)
            lfs = e2e_tiers.Track2LfsEngine(tmp_path / "lfs_data")
            mirror = e2e_tiers.MirrorPinCheckoutFixture(tmp_path / "mirror_data")

            c_main = git_fix.commits["c2"]
            c_ff = git_fix.commits["c3"]

            # 1. forge_pulls: state='merged' with NULL merge_commit_oid -> IntegrityError
            with self.assertRaises(sqlite3.IntegrityError):
                pulls.conn.execute(
                    """
                    INSERT INTO forge_pulls (
                        tenant_id, repository_id, number, author_id, title, body, state,
                        head_ref, base_ref, head_oid, base_oid, merge_commit_oid, merged_storage_generation
                    ) VALUES (?, ?, 99, ?, 'Bad merge', '', 'merged', 'refs/heads/feature', 'refs/heads/main', ?, ?, NULL, 1)
                    """,
                    (e2e_tiers.ALICE_ID, e2e_tiers.DEFAULT_REPO_ID, e2e_tiers.ALICE_ID, c_ff, c_main),
                )

            # 2. forge_pulls: cross-tenant author_id != tenant_id -> IntegrityError
            with self.assertRaises(sqlite3.IntegrityError):
                pulls.conn.execute(
                    """
                    INSERT INTO forge_pulls (
                        tenant_id, repository_id, number, author_id, title, body, state,
                        head_ref, base_ref, head_oid, base_oid
                    ) VALUES (?, ?, 99, ?, 'Cross tenant', '', 'open', 'refs/heads/feature', 'refs/heads/main', ?, ?)
                    """,
                    (e2e_tiers.ALICE_ID, e2e_tiers.DEFAULT_REPO_ID, e2e_tiers.BOB_ID, c_ff, c_main),
                )

            # 3. forge_check_runs: completed with NULL conclusion OR queued with non-null conclusion -> IntegrityError
            with self.assertRaises(sqlite3.IntegrityError):
                pulls.conn.execute(
                    """
                    INSERT INTO forge_check_runs (tenant_id, repository_id, commit_oid, context, status, conclusion, attempt, sequence)
                    VALUES (?, ?, ?, 'ci/build', 'completed', NULL, 1, 1)
                    """,
                    (e2e_tiers.ALICE_ID, e2e_tiers.DEFAULT_REPO_ID, c_ff),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                pulls.conn.execute(
                    """
                    INSERT INTO forge_check_runs (tenant_id, repository_id, commit_oid, context, status, conclusion, attempt, sequence)
                    VALUES (?, ?, ?, 'ci/build', 'queued', 'success', 1, 1)
                    """,
                    (e2e_tiers.ALICE_ID, e2e_tiers.DEFAULT_REPO_ID, c_ff),
                )

            # 4. forge_branch_rules: required_approvals > 100 or < 0 -> IntegrityError
            with self.assertRaises(sqlite3.IntegrityError):
                pulls.conn.execute(
                    """
                    INSERT INTO forge_branch_rules (tenant_id, repository_id, branch_ref, required_approvals)
                    VALUES (?, ?, 'refs/heads/main', 101)
                    """,
                    (e2e_tiers.ALICE_ID, e2e_tiers.DEFAULT_REPO_ID),
                )

            # 5. lfs_objects: uppercase OID or negative size -> IntegrityError
            with self.assertRaises(sqlite3.IntegrityError):
                lfs.conn.execute(
                    "INSERT INTO lfs_objects (tenant_id, repository_id, oid, size, state) VALUES (?, ?, ?, 10, 'pending')",
                    (e2e_tiers.ALICE_ID, e2e_tiers.DEFAULT_REPO_ID, "A" * 64),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                lfs.conn.execute(
                    "INSERT INTO lfs_objects (tenant_id, repository_id, oid, size, state) VALUES (?, ?, ?, -1, 'pending')",
                    (e2e_tiers.ALICE_ID, e2e_tiers.DEFAULT_REPO_ID, "a" * 64),
                )

            # 6. ci_mirror_evictions: storage_generation <= 0 or negative reclaimed_bytes -> IntegrityError
            with self.assertRaises(sqlite3.IntegrityError):
                mirror.conn.execute(
                    """
                    INSERT INTO ci_mirror_evictions (
                        repository_id, eviction_id, storage_generation, evicted_pins, evicted_job_views, evicted_snapshots, reclaimed_bytes
                    ) VALUES (?, 'ev-bad-1', 0, 0, 0, 0, 0)
                    """,
                    (e2e_tiers.DEFAULT_REPO_ID,),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                mirror.conn.execute(
                    """
                    INSERT INTO ci_mirror_evictions (
                        repository_id, eviction_id, storage_generation, evicted_pins, evicted_job_views, evicted_snapshots, reclaimed_bytes
                    ) VALUES (?, 'ev-bad-2', 1, 0, 0, 0, -5)
                    """,
                    (e2e_tiers.DEFAULT_REPO_ID,),
                )


class TestTier5AntiMonolithAndRust2024Architecture(unittest.TestCase):
    """Class 3: Anti-monolith enforcement & Rust 2024 module architecture invariants."""

    def test_all_domain_roots_are_regular_files_without_mod_rs_and_within_line_caps(self) -> None:
        e2e_tiers.SchemaBoundaryIntegrationFixture.verify_domain_routers_and_modularity()

        entry_caps = {
            "pulls": 100,
            "browse": 100,
            "lfs": 100,
            "webhooks": 100,
            "members": 100,
            "web": 100,
            "sharding": 100,
            "view_lab": 120,
            "mirror": 150,
            "workspace_lab": 150,
        }
        for mod_name, max_lines in entry_caps.items():
            root_rs = ROOT / "src" / f"{mod_name}.rs"
            mod_rs = ROOT / "src" / mod_name / "mod.rs"
            self.assertTrue(root_rs.is_file(), f"Missing module entry file {root_rs}")
            self.assertFalse(mod_rs.exists(), f"Forbidden mod.rs alongside {root_rs}: {mod_rs}")
            line_count = len(root_rs.read_text(encoding="utf-8").splitlines())
            self.assertLess(line_count, max_lines, f"{root_rs.name} has {line_count} lines (cap {max_lines})")

    def test_all_track_submodules_exist_and_satisfy_single_responsibility_line_bounds(self) -> None:
        expected_submodules = {
            "pulls": (["models.rs", "handlers.rs", "checks.rs", "rules.rs", "merge.rs"], 600),
            "browse": (["models.rs", "git_read.rs", "handlers.rs", "transactions.rs", "object_format.rs"], 550),
            "lfs": (["models.rs", "storage.rs", "handlers.rs"], 550),
            "webhooks": (["models.rs", "signing.rs", "delivery.rs", "handlers.rs"], 550),
            "members": (["models.rs", "rbac.rs", "audit.rs"], 550),
            "web": (["models.rs", "sanitize.rs", "templates.rs", "handlers.rs"], 600),
            "sharding": (["models.rs", "router.rs", "fencing.rs", "failover.rs", "rebalance.rs", "benchmark.rs"], 600),
            "view_lab": (["models.rs", "namespace.rs", "projection.rs", "changeset.rs"], 500),
            "mirror": (["auto_origin.rs", "eviction.rs", "limiter.rs", "observability.rs", "sync.rs", "views.rs"], 700),
            "pando_lab": (
                [
                    "mod.rs",
                    "delta.rs",
                    "graph.rs",
                    "export.rs",
                    "store.rs",
                    "http.rs",
                    "hook.rs",
                    "migration.rs",
                    "rollback.rs",
                    "object_store.rs",
                    "repack.rs",
                    "lifecycle.rs",
                    "object_format.rs",
                ],
                850,
            ),
            "workspace_lab": (
                [
                    "core.rs",
                    "manifest.rs",
                    "ignore.rs",
                    "sync.rs",
                    "view.rs",
                    "remote.rs",
                    "namespace.rs",
                    "vfs.rs",
                    "writable_view.rs",
                    "crash_recovery.rs",
                ],
                1150,
            ),
        }
        for domain, (files, cap) in expected_submodules.items():
            for fname in files:
                fpath = ROOT / "src" / domain / fname
                self.assertTrue(fpath.is_file(), f"Missing required submodule {fpath}")
                lines = len(fpath.read_text(encoding="utf-8").splitlines())
                self.assertGreaterEqual(lines, 35, f"Submodule {fpath} looks like a stub ({lines} lines)")
                self.assertLess(lines, cap, f"Submodule {fpath} exceeds {cap}-line anti-monolith bound ({lines} lines)")

    def test_thin_router_entry_files_delegate_all_sql_and_git_execution_to_submodules(self) -> None:
        for entry_rel in (
            "src/pulls.rs",
            "src/browse.rs",
            "src/lfs.rs",
            "src/webhooks.rs",
            "src/members.rs",
            "src/web.rs",
            "src/sharding.rs",
            "src/view_lab.rs",
        ):
            src = (ROOT / entry_rel).read_text(encoding="utf-8")
            for sql_kw in ("SELECT ", "INSERT ", "UPDATE ", "DELETE "):
                self.assertNotIn(sql_kw, src, f"Router entry {entry_rel} must not embed inline SQL ({sql_kw})")
            self.assertNotIn("Command::new", src, f"Router entry {entry_rel} must not spawn subprocesses directly")

    def test_serde_deny_unknown_fields_and_shared_auth_fencing_across_tracks(self) -> None:
        model_files = (
            "src/pulls/models.rs",
            "src/browse/models.rs",
            "src/browse/object_format.rs",
            "src/lfs/models.rs",
            "src/webhooks/models.rs",
            "src/members/models.rs",
            "src/web/models.rs",
            "src/sharding/models.rs",
            "src/sharding/rebalance.rs",
            "src/sharding/benchmark.rs",
            "src/view_lab/models.rs",
            "src/mirror/eviction.rs",
            "src/mirror/auto_origin.rs",
            "src/pando_lab/lifecycle.rs",
            "src/pando_lab/object_format.rs",
            "src/workspace_lab/manifest.rs",
            "src/workspace_lab/remote.rs",
            "src/workspace_lab/namespace.rs",
            "src/workspace_lab/vfs.rs",
            "src/workspace_lab/writable_view.rs",
            "src/workspace_lab/crash_recovery.rs",
        )
        for rel in model_files:
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertIn("#[serde(deny_unknown_fields)]", text, f"Missing #[serde(deny_unknown_fields)] in {rel}")

        # Verify shared auth::authenticate, authorize_repo, finish_tx, and tokio::spawn disconnect safety
        merge_src = (ROOT / "src/pulls/merge.rs").read_text(encoding="utf-8")
        tx_src = (ROOT / "src/browse/transactions.rs").read_text(encoding="utf-8")
        lfs_src = (ROOT / "src/lfs/handlers.rs").read_text(encoding="utf-8")
        wh_src = (ROOT / "src/webhooks/handlers.rs").read_text(encoding="utf-8")
        self.assertIn("tokio::spawn", merge_src)
        self.assertIn("finish_tx", merge_src)
        self.assertIn("tokio::spawn", tx_src)
        self.assertIn("finish_tx", tx_src)
        self.assertIn("tokio::spawn", lfs_src)
        self.assertIn("auth::authenticate", lfs_src)
        self.assertIn("tokio::spawn", wh_src)


class TestTier5Track1AndTrack2AdversarialBoundaries(e2e_tiers.BaseRootyardTestCase):
    """Class 4: White-box adversarial boundary cases for Track 1 (Pulls/Checks/Merge) and Track 2 (Browse/LFS)."""

    def test_track1_review_changes_requested_supercession_and_head_oid_invalidation_matrix(self) -> None:
        git_fix = self.clone_git_fixture("t5_track1_reviews.git")
        engine = e2e_tiers.Track1PullsEngine(git_fix)
        c_ff = git_fix.commits["c3"]
        c_main = git_fix.commits["c2"]

        code, pr = engine.create_pull(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            "Feature PR",
            "refs/heads/feature",
            "refs/heads/main",
        )
        self.assertEqual(code, 201)
        pr_num = pr["number"]

        engine.upsert_branch_rule(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            "refs/heads/main",
            required_approvals=1,
            required_checks=["ci/test"],
        )
        engine.report_check(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            c_ff,
            "ci/test",
            "completed",
            conclusion="success",
        )

        # Reviewer requests changes -> blocks merge
        engine.create_review(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, pr_num, "changes_requested", c_ff, "Fix bug")
        self.assertTrue(engine.has_blocking_changes_requested(pr_num, c_ff))
        m_code, _ = engine.merge_pull(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, pr_num, 1, c_ff, c_main)
        self.assertEqual(m_code, 409)

        # A 'commented' review does NOT supersede 'changes_requested'
        engine.create_review(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, pr_num, "commented", c_ff, "Still blocked")
        self.assertTrue(engine.has_blocking_changes_requested(pr_num, c_ff))
        self.assertEqual(engine.count_valid_approvals(pr_num, c_ff), 0)

        # An 'approved' review from the same author supersedes their prior 'changes_requested'
        engine.create_review(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, pr_num, "approved", c_ff, "LGTM now")
        self.assertFalse(engine.has_blocking_changes_requested(pr_num, c_ff))
        self.assertEqual(engine.count_valid_approvals(pr_num, c_ff), 1)

        # Verify SQL query in src/pulls/rules.rs enforces review supercession
        rules_rs = (ROOT / "src/pulls/rules.rs").read_text(encoding="utf-8")
        self.assertIn("state='changes_requested'", rules_rs)
        self.assertIn("state='approved'", rules_rs)

    def test_track1_check_run_monotonic_attempt_sequence_and_status_conclusion_matrix(self) -> None:
        git_fix = self.clone_git_fixture("t5_track1_checks.git")
        engine = e2e_tiers.Track1PullsEngine(git_fix)
        c_ff = git_fix.commits["c3"]

        # Initial report (attempt=2, sequence=3)
        c1, _ = engine.report_check(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            c_ff,
            "ci/lint",
            "in_progress",
            attempt=2,
            sequence=3,
            output="step 1",
        )
        self.assertEqual(c1, 201)

        # Idempotent retry of exact same (attempt=2, sequence=3) and payload -> 200
        c_idem, _ = engine.report_check(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            c_ff,
            "ci/lint",
            "in_progress",
            attempt=2,
            sequence=3,
            output="step 1",
        )
        self.assertEqual(c_idem, 200)

        # Conflicting payload on same (attempt=2, sequence=3) -> 409
        c_conflict, _ = engine.report_check(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            c_ff,
            "ci/lint",
            "completed",
            conclusion="failure",
            attempt=2,
            sequence=3,
            output="step 1",
        )
        self.assertEqual(c_conflict, 409)

        # Stale sequence (attempt=2, sequence=2) and stale attempt (attempt=1, sequence=99) -> 409
        self.assertEqual(
            engine.report_check(
                e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, c_ff, "ci/lint", "completed", conclusion="success", attempt=2, sequence=2
            )[0],
            409,
        )
        self.assertEqual(
            engine.report_check(
                e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, c_ff, "ci/lint", "completed", conclusion="success", attempt=1, sequence=99
            )[0],
            409,
        )

        # Complete on (attempt=2, sequence=4) with failure, then re-run on (attempt=3, sequence=1) as queued -> completed(success)
        self.assertEqual(
            engine.report_check(
                e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, c_ff, "ci/lint", "completed", conclusion="failure", attempt=2, sequence=4
            )[0],
            200,
        )
        self.assertEqual(
            engine.report_check(
                e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, c_ff, "ci/lint", "queued", conclusion=None, attempt=3, sequence=1
            )[0],
            200,
        )
        self.assertEqual(
            engine.report_check(
                e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, c_ff, "ci/lint", "completed", conclusion="success", attempt=3, sequence=2
            )[0],
            200,
        )

    def test_track1_atomic_merge_live_ref_race_and_connection_drop_before_outbox_publish(self) -> None:
        git_fix = self.clone_git_fixture("t5_track1_merge_race.git")
        engine = e2e_tiers.Track1PullsEngine(git_fix)
        c_main = git_fix.commits["c2"]
        c_ff = git_fix.commits["c3"]
        c_div1 = git_fix.commits["c_div1"]

        _, pr = engine.create_pull(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            "Race PR",
            "refs/heads/feature",
            "refs/heads/main",
        )
        # Simulate concurrent push moving refs/heads/main to c_div1 behind PR's back
        git_fix.update_ref("refs/heads/main", c_div1)
        code, body = engine.merge_pull(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            pr["number"],
            expected_version=1,
            expected_head_oid=c_ff,
            expected_base_oid=c_main,
        )
        self.assertEqual(code, 409)
        self.assertIn("base_ref moved", body["error"])
        self.assertEqual(git_fix.resolve_ref("refs/heads/main"), c_div1)
        outbox_cnt = engine.conn.execute("SELECT count(*) FROM outbox_events").fetchone()[0]
        self.assertEqual(outbox_cnt, 0)

        # Verify src/pulls/merge.rs drops pooled DB client before events::publish
        merge_rs = (ROOT / "src/pulls/merge.rs").read_text(encoding="utf-8")
        drop_pos = merge_rs.find("drop(client)")
        pub_pos = merge_rs.find("events::publish(")
        self.assertGreater(drop_pos, 0)
        self.assertGreater(pub_pos, drop_pos, "src/pulls/merge.rs must drop(client) before events::publish")

    def test_track2a_browse_path_revision_injection_and_multi_ref_cas_partial_failure_rollback(self) -> None:
        git_fix = self.clone_git_fixture("t5_track2_browse.git")
        pulls = e2e_tiers.Track1PullsEngine(git_fix)
        browse = e2e_tiers.Track2BrowseEngine(git_fix, pulls)
        c_main = git_fix.commits["c2"]
        c_ff = git_fix.commits["c3"]
        blob_oid = git_fix.blobs["readme_v1"]

        # Flag injection & path traversal on browse endpoints
        self.assertEqual(browse.get_commits(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, oid="--all")[0], 400)
        self.assertEqual(browse.get_tree(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, c_main, path="../etc/passwd")[0], 400)
        self.assertEqual(browse.get_blob(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, c_main, path="a/\x00b")[0], 400)
        self.assertEqual(browse.get_refs(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, prefix="refs/rootyard-ci/jobs")[0], 400)

        # Pointing refs/heads/* at a blob OID -> 422
        code_blob, _ = browse.post_ref_transaction(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            storage_generation=1,
            updates=[{"ref_name": "refs/heads/bad-branch", "old_oid": e2e_tiers.ZERO_OID, "new_oid": blob_oid}],
        )
        self.assertEqual(code_blob, 422)

        # Deleting default symbolic HEAD branch -> 409
        code_del_head, _ = browse.post_ref_transaction(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            storage_generation=1,
            updates=[{"ref_name": "refs/heads/main", "old_oid": c_main, "new_oid": e2e_tiers.ZERO_OID}],
        )
        self.assertEqual(code_del_head, 409)

        # Multi-ref batch where second ref has wrong old_oid -> entire batch rolls back atomically (409)
        code_batch, _ = browse.post_ref_transaction(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            storage_generation=1,
            updates=[
                {"ref_name": "refs/heads/atomic-new", "old_oid": e2e_tiers.ZERO_OID, "new_oid": c_ff},
                {"ref_name": "refs/heads/main", "old_oid": c_ff, "new_oid": c_ff},  # wrong old_oid (actual is c_main)
            ],
        )
        self.assertEqual(code_batch, 409)
        self.assertIsNone(git_fix.resolve_ref("refs/heads/atomic-new"))
        self.assertEqual(git_fix.resolve_ref("refs/heads/main"), c_main)

    def test_track2b_lfs_streaming_staging_cleanup_and_on_disk_corruption_detection(self) -> None:
        lfs = e2e_tiers.Track2LfsEngine(self.tmp_path / "lfs_adv")
        payload = b"deterministic-tier5-lfs-payload-bytes"
        oid = hashlib.sha256(payload).hexdigest()
        size = len(payload)

        # Reserve via Batch API
        b_code, _, _ = lfs.post_batch(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            "upload",
            [{"oid": oid, "size": size}],
        )
        self.assertEqual(b_code, 200)

        # 1. Stream digest mismatch -> 422 and zero leftover .tmp-* files
        bad_code, _ = lfs.put_object(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            oid,
            size,
            [b"X" + payload[1:]],
        )
        self.assertEqual(bad_code, 422)
        self.assertEqual(list(lfs.repo_dir.glob(".tmp-*")), [])

        # 2. Quota exceeded -> 507 Insufficient Storage
        q_code, _ = lfs.put_object(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            oid,
            size,
            [payload],
            quota_bytes=size - 1,
        )
        self.assertEqual(q_code, 507)

        # 3. Valid streaming upload -> 200 and paired backup passes
        ok_code, _ = lfs.put_object(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            oid,
            size,
            [payload[:10], payload[10:]],
        )
        self.assertEqual(ok_code, 200)
        self.assertEqual(lfs.verify_paired_backup()["ready_count"], 1)

        # 4. Corrupt 1 byte on disk -> download fails closed (503) and paired backup raises RuntimeError
        obj_file = lfs.repo_dir / oid
        os.chmod(obj_file, 0o600)
        obj_file.write_bytes(b"Z" + payload[1:])
        dl_code, _, _ = lfs.get_object(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, oid)
        self.assertEqual(dl_code, 503)
        with self.assertRaises(RuntimeError):
            lfs.verify_paired_backup()


class TestTier5Track3CiMirrorEvictionAndLeaseAdversarial(e2e_tiers.BaseRootyardTestCase):
    """Class 5: White-box adversarial tests for Track 3 (CI Pins, Checkout Leases, Mirror Eviction & Limiter)."""

    def test_ci_checkout_lease_expiry_exact_second_boundary_and_pin_release_fencing(self) -> None:
        mirror = e2e_tiers.MirrorPinCheckoutFixture(self.tmp_path / "m_lease")
        c_main = mirror.git.commits["c2"]

        code, _ = mirror.create_source_pin("job-boundary", c_main)
        self.assertEqual(code, 201)
        l_code, lease = mirror.issue_checkout_lease("job-boundary", ttl_seconds=60, now_unix=1000)
        self.assertEqual(l_code, 201)
        self.assertEqual(lease["expires_unix"], 1060)

        # At now_unix=1059 (1 second before expiry), lease is active -> release blocked with 409
        r_active, _ = mirror.release_source_pin("job-boundary", now_unix=1059)
        self.assertEqual(r_active, 409)

        # At exact boundary now_unix=1060 (expires_unix == now_unix), lease is expired -> release succeeds (200)
        r_expired, body = mirror.release_source_pin("job-boundary", now_unix=1060)
        self.assertEqual(r_expired, 200)
        self.assertEqual(body["state"], "released")

        # Repeat release is idempotent (200)
        r_idem, _ = mirror.release_source_pin("job-boundary", now_unix=1061)
        self.assertEqual(r_idem, 200)

    def test_mirror_eviction_never_evicts_current_snapshot_or_pin_referenced_snapshots(self) -> None:
        mirror = e2e_tiers.MirrorPinCheckoutFixture(self.tmp_path / "m_snap_protect")
        c_main = mirror.git.commits["c2"]
        c_ff = mirror.git.commits["c3"]

        # Create snap-1 and materialize a pin protected by an active checkout lease
        mirror.sync_mirror_snapshot("snap-1", mtime=100.0)
        mirror.create_source_pin("job-pinned", c_main)
        mirror.issue_checkout_lease("job-pinned", ttl_seconds=600, now_unix=1000)
        mirror.materialize_mirror_pin_and_job_view("snap-1", c_main, mtime=100.0)

        # Create unreferenced snap-2, then current snap-3
        mirror.sync_mirror_snapshot("snap-2", mtime=200.0)
        mirror.sync_mirror_snapshot("snap-3", mtime=300.0)
        mirror.materialize_mirror_pin_and_job_view("snap-3", c_ff, mtime=300.0)

        # Evict with aggressive max_bytes=1:
        # - snap-3 (current) and snap-1 (referenced by protected pin c_main) MUST survive
        # - snap-2 (unreferenced) and unprotected pin c_ff are evicted
        ev_code, receipt = mirror.evict_mirror(max_bytes=1, now_unix=1100)
        self.assertEqual(ev_code, 200)
        self.assertGreaterEqual(receipt["evicted_snapshots"], 1)
        self.assertTrue((mirror.mirror_repo_dir / "snap-1").is_dir())
        self.assertFalse((mirror.mirror_repo_dir / "snap-2").exists())
        self.assertTrue((mirror.mirror_repo_dir / "snap-3").is_dir())

    def test_mirror_eviction_protects_active_leases_and_primary_ci_roots_against_explicit_evict_oids(self) -> None:
        mirror = e2e_tiers.MirrorPinCheckoutFixture(self.tmp_path / "m_oid_protect")
        c_main = mirror.git.commits["c2"]
        c_ff = mirror.git.commits["c3"]
        c_div1 = mirror.git.commits["c_div1"]

        mirror.sync_mirror_snapshot("snap-cur", mtime=100.0)
        # c_main protected by active primary source pin ref; c_ff protected by active checkout lease; c_div1 unprotected
        mirror.create_source_pin("job-pin-only", c_main)
        mirror.create_source_pin("job-lease", c_ff)
        mirror.issue_checkout_lease("job-lease", ttl_seconds=300, now_unix=2000)
        # Release primary ref on job-lease is blocked, so simulate lease-only protection by inserting a lease row for c_ff
        mirror.materialize_mirror_pin_and_job_view("snap-cur", c_main, mtime=100.0)
        mirror.materialize_mirror_pin_and_job_view("snap-cur", c_ff, mtime=110.0)
        mirror.materialize_mirror_pin_and_job_view("snap-cur", c_div1, mtime=120.0)

        ev_code, receipt = mirror.evict_mirror(max_bytes=1, now_unix=2100)
        self.assertEqual(ev_code, 200)
        self.assertEqual(receipt["evicted_pins"], 1)
        self.assertEqual(receipt["evicted_job_views"], 1)
        self.assertTrue((mirror.mirror_repo_dir / f"pin-1-{c_main}.json").is_file())
        self.assertTrue((mirror.mirror_repo_dir / f"pin-1-{c_ff}.json").is_file())
        self.assertFalse((mirror.mirror_repo_dir / f"pin-1-{c_div1}.json").exists())

        # Verify Rust source in src/mirror/eviction.rs queries active leases & primary CI refs
        ev_rs = (ROOT / "src/mirror/eviction.rs").read_text(encoding="utf-8")
        self.assertIn("ci_checkout_jobs", ev_rs)
        self.assertIn("ci_mirror_evictions", ev_rs)

    def test_mirror_limiter_per_repo_contention_global_saturation_and_cooldown_window(self) -> None:
        limiter = e2e_tiers.SyncRateLimiter(max_concurrent=2)
        with limiter.acquire("repo-1") as (c1, _):
            self.assertEqual(c1, 200)
            # Same-repo concurrent sync -> 429
            with limiter.acquire("repo-1") as (c_dup, _):
                self.assertEqual(c_dup, 429)
            with limiter.acquire("repo-2") as (c2, _):
                self.assertEqual(c2, 200)
                # Global concurrency cap (2) reached -> repo-3 gets 429
                with limiter.acquire("repo-3") as (c3, _):
                    self.assertEqual(c3, 429)

        self.assertEqual(limiter.in_flight, 0)
        self.assertEqual(limiter.sync_total, 2)
        self.assertEqual(limiter.rate_limited_total, 2)

        limiter_rs = (ROOT / "src/mirror/limiter.rs").read_text(encoding="utf-8")
        self.assertIn("ROOTYARD_MIRROR_MAX_CONCURRENT_SYNCS", limiter_rs)
        self.assertIn("ROOTYARD_MIRROR_SYNC_COOLDOWN_MS", limiter_rs)
        self.assertIn("StatusCode::TOO_MANY_REQUESTS", limiter_rs)

    def test_mirror_prometheus_metrics_fixed_cardinality_and_no_store_headers(self) -> None:
        mirror = e2e_tiers.MirrorPinCheckoutFixture(self.tmp_path / "m_prom")
        mirror.sync_mirror_snapshot("snap-prom")
        mirror.evict_mirror(max_bytes=10**9)

        code, body, headers = mirror.render_prometheus_metrics()
        self.assertEqual(code, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Content-Type"], "text/plain; version=0.0.4; charset=utf-8")
        self.assertNotIn(e2e_tiers.DEFAULT_REPO_ID, body)
        for metric_name in (
            "rootyard_mirror_sync_in_flight",
            "rootyard_mirror_sync_limit",
            "rootyard_mirror_sync_total",
            "rootyard_mirror_sync_failed_total",
            "rootyard_mirror_sync_rate_limited_total",
            "rootyard_mirror_evictions_total",
            "rootyard_mirror_reclaimed_bytes_total",
            "rootyard_mirror_disk_bytes",
        ):
            self.assertIn(metric_name, body)


class TestTier5Track4PandoAndWorkspaceLabAdversarial(e2e_tiers.BaseRootyardTestCase):
    """Class 6: White-box adversarial tests for Track 4A (Pando Lab) and Track 4B (Workspace Lab)."""

    def test_pando_pack_corrupt_magic_trailer_varint_ofs_cycle_ref_cycle_and_depth_65(self) -> None:
        pando = e2e_tiers.PandoDeltaGraphExportFixture(self.tmp_path / "pando_adv")
        base_payload = b"hello pando adversarial pack world\n"
        base_oid_hex = pando.git_oid("blob", base_payload)

        # 1. Corrupt magic & unsupported version 3 & corrupt trailer
        valid_pack = pando.build_pack_from_entries([(3, base_payload, None, None)])
        with self.assertRaisesRegex(ValueError, "magic"):
            pando.parse_and_resolve_pack(b"NOPE" + valid_pack[4:])
        bad_ver = bytearray(valid_pack)
        struct.pack_into(">I", bad_ver, 4, 3)
        bad_ver[-20:] = hashlib.sha1(bytes(bad_ver[:-20])).digest()
        with self.assertRaisesRegex(ValueError, "version"):
            pando.parse_and_resolve_pack(bytes(bad_ver))
        with self.assertRaisesRegex(ValueError, "checksum"):
            pando.parse_and_resolve_pack(valid_pack[:-1] + bytes([valid_pack[-1] ^ 0xFF]))

        # 2. Self-referencing OBJ_OFS_DELTA (neg_ofs = 0) -> cycle / missing base offset
        delta_nop = bytes([len(base_payload), len(base_payload), 0x90, len(base_payload)])
        ofs_self_pack = pando.build_pack_from_entries([(6, delta_nop, 0, None)])
        with self.assertRaises(ValueError):
            pando.parse_and_resolve_pack(ofs_self_pack)

        # 3. Missing OBJ_REF_DELTA base OID -> rejected
        ref_missing_pack = pando.build_pack_from_entries([(7, delta_nop, None, b"\xaa" * 20)])
        with self.assertRaisesRegex(ValueError, "missing delta base"):
            pando.parse_and_resolve_pack(ref_missing_pack)

        # 4. Reserved delta opcode 0x00 and out-of-bounds copy -> rejected
        with self.assertRaisesRegex(ValueError, "opcode 0"):
            pando.apply_git_delta(base_payload, bytes([len(base_payload), len(base_payload), 0x00]))
        with self.assertRaisesRegex(ValueError, "out of bounds"):
            pando.apply_git_delta(base_payload, bytes([len(base_payload), len(base_payload), 0x91, 5, len(base_payload)]))

        # 5. Chain depth 64 succeeds; chain depth 65 fails closed
        def build_chain(depth: int) -> bytes:
            out = bytearray(b"PACK")
            out.extend(struct.pack(">II", 2, depth + 1))
            offsets: list[int] = []
            # Base entry
            offsets.append(len(out))
            b_size = len(base_payload)
            first_b = (3 << 4) | (b_size & 0x0F)
            rem_b = b_size >> 4
            if rem_b > 0:
                first_b |= 0x80
            out.append(first_b)
            while rem_b > 0:
                b_byte = rem_b & 0x7F
                rem_b >>= 7
                if rem_b > 0:
                    b_byte |= 0x80
                out.append(b_byte)
            out.extend(zlib.compress(base_payload))
            for _ in range(depth):
                cur_off = len(out)
                neg_ofs = cur_off - offsets[-1]
                offsets.append(cur_off)
                d_stream = bytes([len(base_payload), len(base_payload), 0x90, len(base_payload)])
                d_size = len(d_stream)
                out.append((6 << 4) | (d_size & 0x0F))
                vals = [neg_ofs & 0x7F]
                rem = neg_ofs >> 7
                while rem > 0:
                    rem -= 1
                    vals.append(0x80 | (rem & 0x7F))
                    rem >>= 7
                out.extend(reversed(vals))
                out.extend(zlib.compress(d_stream))
            out.extend(hashlib.sha1(bytes(out)).digest())
            return bytes(out)

        res64 = pando.parse_and_resolve_pack(build_chain(64), max_depth=64)
        self.assertTrue(res64["verified"])
        with self.assertRaisesRegex(ValueError, "depth"):
            pando.parse_and_resolve_pack(build_chain(65), max_depth=64)

    def test_pando_graph_malformed_commit_tree_tag_and_gitlink_submodule_exclusion(self) -> None:
        graph_rs = (ROOT / "src/pando_lab/graph.rs").read_text(encoding="utf-8")
        self.assertIn("160000", graph_rs)
        self.assertIn("Gitlink", graph_rs)
        self.assertIn("commit missing tree header", graph_rs)
        self.assertIn("commit contains multiple tree headers", graph_rs)
        self.assertIn("invalid tree entry filename", graph_rs)

        # Differential export parity on real Git repo with OFS/REF deltas
        git_fix = self.clone_git_fixture("t5_pando_diff.git")
        pando = e2e_tiers.PandoDeltaGraphExportFixture(self.tmp_path / "pando_diff")
        c_main = git_fix.commits["c2"]
        c_ff = git_fix.commits["c3"]
        pack_res = subprocess.run(
            ["git", f"--git-dir={git_fix.bare_dir}", "pack-objects", "--stdout", "--revs", "--delta-base-offset"],
            input=f"{c_ff}\n".encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=e2e_tiers.GIT_ENV,
            check=True,
        )
        pack_path, _ = pando.register_manifest_pack("pack-t5", pack_res.stdout)
        diff = pando.diff_export_dual_operator(git_fix.bare_dir, [pack_path], want_oids=[c_ff], have_oids=(c_main,))
        self.assertTrue(diff["parity"])
        self.assertGreater(diff["pando_object_count"], 0)

    def test_pando_loopback_dsn_enforcement_and_synthetic_only_env_guard(self) -> None:
        pando_mod = (ROOT / "src/pando_lab/mod.rs").read_text(encoding="utf-8")
        self.assertIn("PANDO_SYNTHETIC_ONLY", pando_mod)
        self.assertIn("validate_database_address", pando_mod)
        self.assertIn("is_loopback", pando_mod)
        self.assertIn("hostaddr", pando_mod)

        pando_bin = ROOT / "target/debug/rootyard-pando-lab"
        if pando_bin.is_file() and os.access(pando_bin, os.X_OK):
            # Missing PANDO_SYNTHETIC_ONLY=1 -> must fail closed before opening any socket/store
            env_missing = {k: v for k, v in os.environ.items() if k != "PANDO_SYNTHETIC_ONLY"}
            res1 = subprocess.run([str(pando_bin), "gc"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env_missing)
            self.assertNotEqual(res1.returncode, 0)

            # Remote non-loopback PANDO_DATABASE_URL -> must fail closed in Config::load()
            env_remote = {
                **os.environ,
                "PANDO_SYNTHETIC_ONLY": "1",
                "PANDO_DATABASE_URL": "postgres://postgres:postgres@198.51.100.10:5432/pando",
                "PANDO_STORE_ROOT": str(self.tmp_path / "pando_store"),
                "PANDO_HOOK_SIGNING_SECRET": "a" * 64,
            }
            res2 = subprocess.run([str(pando_bin), "gc"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env_remote)
            self.assertNotEqual(res2.returncode, 0)

    def test_workspace_lab_quiescent_guard_overlap_rejection_and_symlink_escape_boundaries(self) -> None:
        ws_fix = e2e_tiers.WorkspaceManifestIgnoreViewFixture(self.tmp_path / "ws_store")
        ws_repo = ws_fix.init_workspace("ws-adv")

        # 1. Overlapping source and store paths -> ValueError
        with self.assertRaisesRegex(ValueError, "overlap"):
            ws_fix.check_non_overlapping(ws_repo, ws_repo / "sub")
        with self.assertRaisesRegex(ValueError, "overlap"):
            ws_fix.check_non_overlapping(self.tmp_path, self.tmp_path / "ws_store")

        # 2. Absolute symlink, ../../ escape symlink, .git target symlink, and >40-hop symlink loop -> rejected
        abs_link = ws_repo / "abs_link"
        os.symlink("/etc/passwd", abs_link)
        with self.assertRaisesRegex(ValueError, "absolute symlink"):
            ws_fix.validate_symlink(ws_repo, abs_link)
        abs_link.unlink()

        esc_link = ws_repo / "esc_link"
        os.symlink("../../outside.txt", esc_link)
        with self.assertRaisesRegex(ValueError, "escapes workspace root"):
            ws_fix.validate_symlink(ws_repo, esc_link)
        esc_link.unlink()

        git_link = ws_repo / "git_link"
        os.symlink(".git/config", git_link)
        with self.assertRaisesRegex(ValueError, "targeting .git"):
            ws_fix.validate_symlink(ws_repo, git_link)
        git_link.unlink()

        loop_a = ws_repo / "loop_a"
        loop_b = ws_repo / "loop_b"
        os.symlink("loop_b", loop_a)
        os.symlink("loop_a", loop_b)
        with self.assertRaisesRegex(ValueError, "loop"):
            ws_fix.validate_symlink(ws_repo, loop_a)
        loop_a.unlink()
        loop_b.unlink()

        # 3. Missing --quiescent flag on apply_changeset -> rejected
        ckpt_base = ws_fix.create_checkpoint("ws-adv", "ckpt-1")
        (ws_repo / "plain.txt").write_bytes(b"updated\n")
        ckpt_src = ws_fix.create_checkpoint("ws-adv", "ckpt-2")
        cs_id = ws_fix.create_changeset(ckpt_base, ckpt_src, "cs-1")
        with self.assertRaisesRegex(ValueError, "--quiescent"):
            ws_fix.apply_changeset("ws-adv", cs_id, quiescent=False)

    def test_workspace_lab_three_way_apply_conflict_atomicity_and_readonly_view_tamper_detection(self) -> None:
        ws_fix = e2e_tiers.WorkspaceManifestIgnoreViewFixture(self.tmp_path / "ws_tamper")
        ws_repo = ws_fix.init_workspace("ws-1")
        # Tracked file matching .rootyardignore must STILL be managed
        (ws_repo / ".rootyardignore").write_text("plain.txt\n*.ignored\n", encoding="utf-8")
        (ws_repo / "scratch.ignored").write_bytes(b"ignore me\n")
        st = ws_fix.workspace_status("ws-1")
        self.assertIn("plain.txt", st["managed_entries"])
        self.assertNotIn("scratch.ignored", st["managed_entries"])

        ckpt_base = ws_fix.create_checkpoint("ws-1", "c-base")
        (ws_repo / "plain.txt").write_bytes(b"source change\n")
        (ws_repo / "added.txt").write_bytes(b"brand new file\n")
        ckpt_src = ws_fix.create_checkpoint("ws-1", "c-src")
        cs_id = ws_fix.create_changeset(ckpt_base, ckpt_src, "cs-atomic")

        # Restore target workspace from base and introduce a conflicting edit on plain.txt
        target_repo = ws_fix.restore_workspace(ckpt_base, "ws-target")
        (target_repo / "plain.txt").write_bytes(b"conflicting target edit\n")
        before_snapshot = {
            p.relative_to(target_repo).as_posix(): p.read_bytes()
            for p in target_repo.rglob("*")
            if p.is_file() and ".git" not in p.parts
        }
        with self.assertRaisesRegex(ValueError, "3-way apply conflict"):
            ws_fix.apply_changeset("ws-target", cs_id, quiescent=True)
        after_snapshot = {
            p.relative_to(target_repo).as_posix(): p.read_bytes()
            for p in target_repo.rglob("*")
            if p.is_file() and ".git" not in p.parts
        }
        self.assertEqual(before_snapshot, after_snapshot)
        self.assertFalse((target_repo / "added.txt").exists())

        # Project read-only view and verify tamper detection (writable mode, content tamper, rogue file, missing file)
        view_dir = ws_fix.project_readonly_view(ckpt_src)
        self.assertTrue(ws_fix.verify_readonly_view(ckpt_src, view_dir)["valid"])

        ro_file = view_dir / "plain.txt"
        os.chmod(ro_file, 0o644)
        with self.assertRaisesRegex(ValueError, "writable mode drift"):
            ws_fix.verify_readonly_view(ckpt_src, view_dir)

        ro_file.write_bytes(b"tampered bytes\n")
        os.chmod(ro_file, 0o444)
        with self.assertRaisesRegex(ValueError, "sha256 tamper"):
            ws_fix.verify_readonly_view(ckpt_src, view_dir)


class TestTier5Phase2CrossTrackAdversarial(e2e_tiers.BaseRootyardTestCase):
    """Class 7: White-box adversarial tests for Phase 2 Tracks A, B, C, and D (F22-F31)."""

    def test_track_a_webhooks_ssrf_hmac_backoff_dead_letter_and_pr_sync_hook(self) -> None:
        git_fix = self.clone_git_fixture("t5_track_a_wh.git")
        mfx = e2e_tiers.MirrorPinCheckoutFixture(self.tmp_path / "t5_track_a_mirror")
        pulls = e2e_tiers.Track1PullsEngine(git_fix)
        webhooks = e2e_tiers.TrackAWebhooksEngine(pulls, mirror_fx=mfx)

        for bad_url in (
            "ftp://example.com/hook",
            "http://example.com/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/internal",
            "https://user:pass@example.com/hook",
            "http://127.0.0.1:8080/hook with space",
        ):
            self.assertEqual(
                webhooks.create_webhook(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, bad_url, "valid-secret-key")[0],
                422,
            )

        secret = "tier5-webhook-hmac-secret"
        with e2e_tiers.LoopbackWebhookReceiver(response_codes=[502, 503, 200], secret=secret) as rx:
            st_wh, hk = webhooks.create_webhook(
                e2e_tiers.ALICE,
                e2e_tiers.DEFAULT_REPO_ID,
                rx.url,
                secret,
                events=["pull_request"],
                ci_contexts=["ci/tier5"],
                max_attempts=2,
            )
            self.assertEqual(st_wh, 201)
            _, pr = pulls.create_pull(
                e2e_tiers.ALICE,
                e2e_tiers.DEFAULT_REPO_ID,
                "Tier5 WH PR",
                "refs/heads/feature",
                "refs/heads/main",
            )
            orch = webhooks.on_pull_synchronized(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, pr)
            self.assertIn("ci/tier5", orch["seeded_checks"])
            deliv_id = webhooks.list_deliveries(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, hk["id"])[1]["items"][0]["id"]
            webhooks.conn.execute("UPDATE forge_webhook_deliveries SET max_attempts=2 WHERE id=?", (deliv_id,))
            # Attempt 1 -> 502 (failed), Attempt 2 -> 503 (dead_letter)
            webhooks.dispatch_due_deliveries(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, now_unix=1000, base_backoff_sec=2)
            d_dead = webhooks.dispatch_due_deliveries(
                e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, now_unix=1002, base_backoff_sec=2
            )[1]["items"][0]
            self.assertEqual(d_dead["state"], "dead_letter")
            # Manual retry -> 200 (delivered)
            webhooks.retry_delivery(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, hk["id"], d_dead["id"], now_unix=1010)
            d_ok = webhooks.dispatch_due_deliveries(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, now_unix=1010)[1]["items"][0]
            self.assertEqual(d_ok["state"], "delivered")
            self.assertTrue(rx.received[-1]["signature_valid"])

            # Callback with tampered signature rejected (401); valid callback succeeds (200); conflicting event_id rejected (409)
            cb_p = {
                "commit_oid": pr["head_oid"],
                "context": "ci/tier5",
                "status": "completed",
                "conclusion": "success",
                "attempt": 1,
                "sequence": 2,
            }
            cb_raw = json.dumps(cb_p, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.assertEqual(webhooks.post_ci_callback(hk["id"], "cb-t5", "sha256=" + ("0" * 64), cb_p)[0], 401)
            self.assertEqual(
                webhooks.post_ci_callback(hk["id"], "cb-t5", webhooks.signature_header(secret, cb_raw), cb_p)[0],
                200,
            )
            cb_conflict = {**cb_p, "conclusion": "failure"}
            cb_conflict_raw = json.dumps(cb_conflict, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.assertEqual(
                webhooks.post_ci_callback(
                    hk["id"], "cb-t5", webhooks.signature_header(secret, cb_conflict_raw), cb_conflict
                )[0],
                409,
            )

        pulls_handlers = (ROOT / "src/pulls/handlers.rs").read_text(encoding="utf-8")
        self.assertIn("crate::webhooks::delivery::on_pull_synchronized", pulls_handlers)

    def test_track_b_members_5_role_rbac_self_approval_demotion_and_audit_log(self) -> None:
        git_fix = self.clone_git_fixture("t5_track_b_rbac.git")
        pulls = e2e_tiers.Track1PullsEngine(git_fix)
        rbac = e2e_tiers.TrackBMembersRbacAuditEngine(pulls)

        self.assertEqual(rbac.upsert_collaborator(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, "alice", "admin")[0], 409)
        rbac.upsert_collaborator(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, "bob", "write")
        rbac.upsert_collaborator(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, "charlie", "write")
        rbac.upsert_branch_rule(
            e2e_tiers.ALICE,
            e2e_tiers.DEFAULT_REPO_ID,
            "main",
            required_approvals=1,
            prevent_self_approval=True,
        )

        _, pr = rbac.create_pull(
            e2e_tiers.BOB,
            e2e_tiers.DEFAULT_REPO_ID,
            "RBAC Tier5 PR",
            "refs/heads/feature",
            "refs/heads/main",
        )
        # Self-approval rejected with 403
        self.assertEqual(
            rbac.create_review(e2e_tiers.BOB, e2e_tiers.DEFAULT_REPO_ID, pr["number"], "approved", pr["head_oid"])[0],
            403,
        )
        # Charlie approves, then gets demoted to triage before merge -> approval invalidated at merge time (409)
        rbac.create_review(e2e_tiers.CHARLIE, e2e_tiers.DEFAULT_REPO_ID, pr["number"], "approved", pr["head_oid"])
        rbac.upsert_collaborator(
            e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, "charlie", "triage", expected_version=1
        )
        self.assertEqual(
            rbac.merge_pull(
                e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, pr["number"], 1, pr["head_oid"], pr["base_oid"]
            )[0],
            409,
        )
        # Owner ALICE approves and merges -> audit log records pull.merged
        rbac.create_review(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, pr["number"], "approved", pr["head_oid"])
        self.assertEqual(
            rbac.merge_pull(
                e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, pr["number"], 1, pr["head_oid"], pr["base_oid"]
            )[0],
            200,
        )
        st_aud, aud = rbac.list_audit_log(e2e_tiers.ALICE, e2e_tiers.DEFAULT_REPO_ID, filter_action="pull.merged")
        self.assertEqual((st_aud, len(aud["items"])), (200, 1))

    def test_track_c_pando_five_step_online_migration_write_fence_and_rollback_with_new_commits(self) -> None:
        git_fix = self.clone_git_fixture("t5_track_c_pando.git")
        pando = e2e_tiers.PandoDeltaGraphExportFixture(self.tmp_path / "t5_track_c_store")

        with self.assertRaises(ValueError):
            pando.migrate_step(git_fix.bare_dir, "switchover")

        for step in ("copy", "verify", "drain", "fence", "switchover"):
            pando.migrate_step(git_fix.bare_dir, step)
        self.assertEqual((pando.storage_backend, pando.storage_generation), ("pando", 2))
        self.assertEqual(
            pando.gitfs_push_commit(git_fix.bare_dir, "refs/heads/main", git_fix.commits["c2"], git_fix.commits["c3"])[0],
            409,
        )
        self.assertEqual(
            pando.pando_receive_pack(
                "alice",
                [("refs/heads/main", git_fix.commits["c2"], git_fix.commits["c3"])],
                expected_storage_gen=1,
            )[0],
            409,
        )
        self.assertEqual(
            pando.pando_receive_pack(
                "alice",
                [("refs/heads/main", git_fix.commits["c2"], git_fix.commits["c3"])],
                expected_storage_gen=2,
            )[0],
            200,
        )
        rb = pando.rollback_to_gitfs(git_fix.bare_dir)
        self.assertEqual((rb["state"], rb["new_storage_generation"]), ("ROLLED_BACK", 3))
        self.assertEqual(git_fix.resolve_ref("refs/heads/main"), git_fix.commits["c3"])

    def test_track_d_workspace_remote_cas_tamper_guards_and_virtual_namespace_git_view(self) -> None:
        node_a = e2e_tiers.WorkspaceManifestIgnoreViewFixture(self.tmp_path / "t5_td_a")
        node_b = e2e_tiers.WorkspaceManifestIgnoreViewFixture(self.tmp_path / "t5_td_b")
        remote_cas = self.tmp_path / "t5_td_cas"

        node_a.init_workspace("ws_a", {"svc.rs": b"pub fn run() {}\n"})
        pushed = node_a.push_remote("ws_a", remote_cas, quiescent=True)
        node_b.pull_remote(remote_cas, pushed["checkpoint_id"], "ws_b")

        with self.assertRaisesRegex(ValueError, "overlapping namespace mount paths"):
            node_b.namespace_mount("ns-bad", [("pkg", pushed["checkpoint_id"]), ("pkg/sub", pushed["checkpoint_id"])])

        ns = node_b.namespace_mount("ns-ok", {"services/svc": pushed["checkpoint_id"]}, revision=1)
        self.assertTrue(node_b.verify_namespace("ns-ok")["verified"])
        gv = node_b.namespace_git_view("ns-ok")
        self.assertTrue(gv["fsck_passed"])
        self.assertEqual((Path(gv["view_repo_path"]) / "services/svc/svc.rs").read_bytes(), b"pub fn run() {}\n")


class TestTier5Phase5TracksAdversarial(e2e_tiers.BaseRootyardTestCase):
    """Class 8: White-box adversarial tests for Phase 5 Tracks 1, 2, 3, and 4 (F43-F51)."""

    def test_tier5_f43_f44_f45_view_lab_history_projection_and_provenance_signature_tamper(self) -> None:
        vfx = e2e_tiers.Tier5ViewLabHistoryAndSignatureFixture(self.tmp_path / "t5_view_lab_adv")
        mod_report = vfx.verify_view_lab_modularity()
        self.assertFalse(mod_report["mod_rs_exists"])
        self.assertLess(mod_report["root_lines"], 120)
        self.assertTrue(mod_report["gitignore_has_original_request"])

        vfx.register_repo("repo-core", {"pkg/core/lib.rs": b"pub fn v1() {}\n"})
        vfx.create_signed_source_commit("repo-core", {"pkg/core/lib.rs": b"pub fn v2() {}\n"}, sig_type="gpg_pgp")
        vfx.create_namespace(
            "ns-core",
            "rev-1",
            [{"repo_id": "repo-core", "subpath": "pkg/core", "mount_path": "core"}],
        )

        # Epoch 1 deterministic_history projection + incremental Epoch 2 reuse
        ep1 = vfx.project_history("view-hist", "ns-core", "rev-1", strategy="deterministic_history", view_epoch=1)
        self.assertGreaterEqual(ep1["newly_projected_commits"], 2)
        self.assertTrue(vfx.verify_view("view-hist")["verified"])

        vfx.create_signed_source_commit("repo-core", {"pkg/core/lib.rs": b"pub fn v3() {}\n"}, sig_type="ssh_sig")
        vfx.create_namespace(
            "ns-core",
            "rev-2",
            [{"repo_id": "repo-core", "subpath": "pkg/core", "mount_path": "core"}],
        )
        ep2 = vfx.project_history(
            "view-hist",
            "ns-core",
            "rev-2",
            strategy="deterministic_history",
            view_epoch=2,
            previous_epoch_map=ep1["history_map"],
        )
        self.assertGreaterEqual(ep2["reused_commits"], 2)
        self.assertEqual(ep2["newly_projected_commits"], 1)

        # Wrong HMAC secret key -> provenance signature verification fails closed
        with self.assertRaisesRegex(ValueError, "HMAC signature verification failed"):
            vfx.verify_view("view-hist", secret_key="wrong-adversarial-secret-key")

        # Require signed source commits rejects initial unsigned root commit in history
        with self.assertRaisesRegex(ValueError, "Unsigned source commit"):
            vfx.project_history(
                "view-strict-sig",
                "ns-core",
                "rev-2",
                strategy="deterministic_history",
                view_epoch=1,
                require_signed_source=True,
            )

        # Malformed source commit signature rejected during projection
        vfx.create_signed_source_commit("repo-core", {"pkg/core/lib.rs": b"pub fn bad() {}\n"}, sig_type="malformed")
        vfx.create_namespace(
            "ns-core",
            "rev-bad",
            [{"repo_id": "repo-core", "subpath": "pkg/core", "mount_path": "core"}],
        )
        with self.assertRaisesRegex(ValueError, "Malformed source commit signature"):
            vfx.project_history("view-bad-sig", "ns-core", "rev-bad", strategy="task_snapshot", view_epoch=1)

    def test_tier5_f46_f47_dual_hash_sha256_pack_trailer_and_smart_http_negotiation(self) -> None:
        dfx = e2e_tiers.Tier5DualHashObjectFormatFixture(self.tmp_path / "t5_dual_hash_adv")
        r1 = dfx.init_repo("repo-sha1", object_format="sha1")
        r256 = dfx.init_repo("repo-sha256", object_format="sha256")
        self.assertEqual((len(r1["head_oid"]), len(r256["head_oid"])), (40, 64))

        # Packv2 trailer verification: 20-byte SHA-1 vs 32-byte SHA-256, and corrupt trailer rejection
        p1 = dfx.verify_pack_trailer("repo-sha1", expected_format="sha1")
        p256 = dfx.verify_pack_trailer("repo-sha256", expected_format="sha256")
        self.assertEqual((p1["trailer_bytes"], p256["trailer_bytes"]), (20, 32))
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            dfx.verify_pack_trailer("repo-sha256", corrupt_last_byte=True)
        with self.assertRaisesRegex(ValueError, "Object format mismatch"):
            dfx.verify_pack_trailer("repo-sha256", expected_format="sha1")

        # Cross-format negotiation rejected with 409; wrong OID length rejected with 422
        st_mis, err_mis = dfx.negotiate_object_format(
            "repo-sha256", protocol_version="v2", client_object_format="sha1", operation="push"
        )
        self.assertEqual((st_mis, err_mis["error"]), (409, "object_format_mismatch"))
        st_len, _ = dfx.negotiate_object_format(
            "repo-sha256",
            protocol_version="v2",
            client_object_format="sha256",
            operation="fetch",
            client_oid=r1["head_oid"],
        )
        self.assertEqual(st_len, 422)

        # Full 4-combination Smart HTTP v1/v2 x SHA-1/SHA-256 + LFS compatibility matrix drill
        matrix = dfx.run_compat_matrix_drill()
        self.assertTrue(matrix["matrix_passed"])
        self.assertEqual(matrix["combinations_tested"], 4)
        self.assertEqual(matrix["cross_format_rejections_verified"], 4)

    def test_tier5_f48_f49_multinode_sharding_benchmark_pinned_roots_and_proc_telemetry(self) -> None:
        bfx = e2e_tiers.Tier5MultiNodeShardingBenchmarkFixture(self.tmp_path / "t5_bench_adv")

        # Auth and parameter validation guards
        self.assertEqual(bfx.http_post_benchmark(e2e_tiers.UNAUTH)[0], 401)
        self.assertEqual(bfx.http_post_benchmark(e2e_tiers.ALICE_RO)[0], 403)
        self.assertEqual(bfx.http_post_benchmark(e2e_tiers.ALICE, node_counts=(3,))[0], 400)

        # Execute 1/2/4-node scaling benchmark with failover, GC, and pinned-root reachability verification
        st_ok, rep = bfx.http_post_benchmark(
            e2e_tiers.ALICE, node_counts=(1, 2, 4), worker_threads=2, ops_per_worker=4
        )
        self.assertEqual(st_ok, 200)
        self.assertTrue(rep["all_pinned_roots_verified"])
        self.assertTrue(rep["zero_split_brain"])
        for tier_key in ("1_node", "2_node", "4_node"):
            tier = rep["runs"][tier_key]
            self.assertLessEqual(tier["p50_ms"], tier["p95_ms"])
            self.assertLessEqual(tier["p95_ms"], tier["p99_ms"])
            self.assertGreater(tier["telemetry"]["rss_kb"], 0)
            self.assertEqual(tier["pinned_roots_verified"], tier["pinned_roots_total"])

        st_md, md_doc = bfx.http_get_benchmark_report(e2e_tiers.ALICE, fmt="markdown")
        self.assertEqual(st_md, 200)
        self.assertIn("Rootyard Sharding Concurrency & Latency Benchmark Report", md_doc["markdown"])

    def test_tier5_f50_f51_workspace_cow_overlay_sandbox_and_wal_power_loss_crash_recovery(self) -> None:
        ofx = e2e_tiers.Tier5WorkspaceOverlayAndCrashRecoveryFixture(self.tmp_path / "t5_overlay_crash_adv")
        ofx.init_lower_checkpoint(
            "ckpt-base",
            {
                "src/lib.rs": b"pub fn base() {}\n",
                "src/old_dir/mod.rs": b"pub mod sub;\n",
                ".gitignore": b"*.log\nbuild/\n",
            },
        )
        ofx.overlay_mount("ov-agent-1", "ckpt-base", agent_id="agent-alpha")

        # Cross-agent access denied with PermissionError
        with self.assertRaisesRegex(PermissionError, "isolation violation"):
            ofx.overlay_write("ov-agent-1", "src/lib.rs", b"hacked\n", caller_agent_id="agent-beta")

        # Cross-layer directory rename places whiteout tombstone on lower path while keeping lower 0o444 intact
        ofx.overlay_rename("ov-agent-1", "src/old_dir", "src/new_dir", caller_agent_id="agent-alpha")
        ofx.overlay_chmod("ov-agent-1", "src/lib.rs", 0o755, caller_agent_id="agent-alpha")
        ofx.overlay_write("ov-agent-1", "debug.log", b"trace log\n", caller_agent_id="agent-alpha")
        st_before_f = ofx.overlay_status("ov-agent-1", caller_agent_id="agent-alpha")
        self.assertTrue(st_before_f["lower_intact"])
        self.assertIn("src/old_dir/mod.rs", st_before_f["whiteouts"])
        self.assertIn("debug.log", st_before_f["ignored"])

        # git add -f synchronously promotes ignored file into tracked upper_added
        st_after_f = ofx.overlay_git_add_f("ov-agent-1", "debug.log", caller_agent_id="agent-alpha")
        self.assertIn("debug.log", st_after_f["force_added"])
        self.assertIn("debug.log", st_after_f["upper_added"])
        self.assertNotIn("debug.log", st_after_f["ignored"])

        # Power-loss crash windows: before_wal_fsync, after_wal_before_publish, after_publish_before_ack, index_update_interrupted
        for idx, win in enumerate(ofx.VALID_CRASH_WINDOWS):
            ws_id = f"ws-crash-{idx}"
            ofx.init_crash_workspace(ws_id, {"app.rs": b"fn v0() {}\n"})
            ofx.crash_drill(ws_id, "app.rs", f"fn recovered_{win}() {{}}\n".encode("utf-8"), window=win)
            rec = ofx.crash_recover(ws_id)
            self.assertTrue(rec["recovered"])
            self.assertTrue(rec["fsck_passed"])
            self.assertFalse(rec["index_lock_exists"])
            self.assertEqual(rec["leftover_tmp_files"], 0)
            app_bytes = (Path(ofx.crash_workspaces[ws_id]["repo_dir"]) / "app.rs").read_bytes()
            if win == "before_wal_fsync":
                self.assertEqual(app_bytes, b"fn v0() {}\n")
            else:
                self.assertEqual(app_bytes, f"fn recovered_{win}() {{}}\n".encode("utf-8"))

        # Corrupt WAL journal sha256 fails closed during crash_recover
        ofx.init_crash_workspace("ws-corrupt-wal", {"app.rs": b"fn v0() {}\n"})
        ofx.crash_drill("ws-corrupt-wal", "app.rs", b"fn v1() {}\n", window="after_wal_before_publish")
        (Path(ofx.crash_workspaces["ws-corrupt-wal"]["wal_dir"]) / "journal.sha256").write_text(
            "0" * 64 + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "checksum corruption"):
            ofx.crash_recover("ws-corrupt-wal")


if __name__ == "__main__":
    unittest.main(verbosity=2)
