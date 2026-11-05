#!/usr/bin/env python3
"""Offline unit, static contract, and deterministic reference tests for Track 4
(F39 Multi-Node Consistent Shard Routing & Lease/Epoch Storage Fencing +
F40 Automated 4-Stage Failover & Read-Only Degradation Drills).
"""
import ast
from pathlib import Path
import re
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sharding  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class ShardingTrack4ContractTest(unittest.TestCase):
    def test_sharding_module_layout_and_anti_monolith_bounds(self):
        sharding_rs = ROOT / "src/sharding.rs"
        self.assertTrue(sharding_rs.is_file(), "src/sharding.rs must be a regular file")
        self.assertFalse(
            (ROOT / "src/sharding/mod.rs").exists(),
            "src/sharding/mod.rs must never exist (Rust 2024 module layout)",
        )
        sharding_src = sharding_rs.read_text(encoding="utf-8")
        sharding_lines = sharding_src.splitlines()
        self.assertLess(
            len(sharding_lines),
            100,
            f"src/sharding.rs must remain < 100 lines, got {len(sharding_lines)}",
        )
        self.assertIn("pub const MIGRATION_060_SQL: &str", sharding_src)
        self.assertIn("pub fn routes() -> Router<Arc<AppState>>", sharding_src)

        for sql_kw in ("SELECT ", "INSERT ", "UPDATE ", "DELETE "):
            self.assertNotIn(
                sql_kw,
                sharding_src,
                f"src/sharding.rs must not embed inline SQL ({sql_kw})",
            )
        self.assertNotIn("Command::new", sharding_src)
        self.assertNotIn("/:", sharding_src)
        self.assertNotIn("{*", sharding_src)

        for sub in ("models", "router", "fencing", "failover"):
            self.assertIn(f"pub mod {sub};", sharding_src)
            sub_path = ROOT / "src/sharding" / f"{sub}.rs"
            self.assertTrue(sub_path.is_file(), f"Missing submodule {sub_path}")
            sub_text = sub_path.read_text(encoding="utf-8")
            sub_lines = sub_text.splitlines()
            self.assertGreaterEqual(
                len(sub_lines),
                50,
                f"{sub}.rs is unexpectedly small ({len(sub_lines)} lines)",
            )
            self.assertLess(
                len(sub_lines),
                550,
                f"{sub}.rs exceeds 550-line anti-monolith bound ({len(sub_lines)} lines)",
            )
            self.assertIn("#[cfg(test)]", sub_text, f"{sub}.rs must include #[cfg(test)] unit tests")

        expected_routes = (
            "/api/shards/nodes",
            "/api/shards/nodes/{node_id}",
            "/api/shards/nodes/{node_id}/lease",
            "/api/shards/buckets",
            "/api/repos/{owner}/{name}/shard-route",
            "/api/repos/{owner}/{name}/shard-route/resolve",
            "/api/repos/{owner}/{name}/shard-fence",
            "/api/repos/{owner}/{name}/shard-failover",
            "/api/repos/{owner}/{name}/shard-degrade",
        )
        for route in expected_routes:
            self.assertIn(route, sharding_src, f"Route {route} missing from src/sharding.rs")

        models_src = (ROOT / "src/sharding/models.rs").read_text(encoding="utf-8")
        router_src = (ROOT / "src/sharding/router.rs").read_text(encoding="utf-8")
        fencing_src = (ROOT / "src/sharding/fencing.rs").read_text(encoding="utf-8")
        failover_src = (ROOT / "src/sharding/failover.rs").read_text(encoding="utf-8")

        self.assertGreaterEqual(models_src.count("#[serde(deny_unknown_fields)]"), 8)
        self.assertIn("pub fn deterministic_bucket_id(", models_src)
        self.assertIn("VOLUME_FENCE_MARKER_FILE", models_src)
        self.assertIn("pub fn select_route_target(", router_src)
        self.assertIn("pub fn evaluate_write_barrier(", fencing_src)
        self.assertIn("pub async fn check_before_push(", fencing_src)
        self.assertIn("pub fn validate_failover_candidate(", failover_src)

    def test_migration_060_sql_contract_and_pg_dump_invariance(self):
        sql_path = sharding.migration_060_path()
        self.assertTrue(sql_path.is_file(), f"Missing SQL migration at {sql_path}")
        sql = sql_path.read_text(encoding="utf-8")

        self.assertIsNone(
            re.search(r"\bBETWEEN\b", sql, flags=re.IGNORECASE),
            "060_sharding_fencing.sql must not use BETWEEN (use >=, <=, and < for pg_dump invariance)",
        )
        self.assertIsNone(
            re.search(r"\b(?:BIGSERIAL|SMALLSERIAL|SERIAL)\b", sql, flags=re.IGNORECASE),
            "060_sharding_fencing.sql must not use SERIAL/BIGSERIAL sequences",
        )

        tables = (
            "shard_nodes",
            "shard_virtual_buckets",
            "repository_shard_routes",
            "shard_failover_operations",
        )
        positions = {}
        for table in tables:
            match = re.search(rf"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+{table}\s*\(", sql)
            self.assertIsNotNone(match, f"Missing CREATE TABLE IF NOT EXISTS {table}")
            positions[table] = match.start()

        self.assertLess(positions["shard_nodes"], positions["shard_virtual_buckets"])
        self.assertLess(positions["shard_virtual_buckets"], positions["repository_shard_routes"])
        self.assertLess(positions["repository_shard_routes"], positions["shard_failover_operations"])

        # Verify no semicolons appear inside any CREATE TABLE (...) body before the closing ');'
        for match in re.finditer(r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+\w+\s*\((.*?)\n\);", sql, flags=re.DOTALL):
            body = match.group(1)
            self.assertNotIn(";", body, "CREATE TABLE body must not contain internal semicolons")

        self.assertEqual(
            sql.count("FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE"),
            2,
        )
        self.assertRegex(
            sql.strip(),
            r"INSERT INTO schema_migrations \(version\) VALUES \(60\)(?:\s+ON CONFLICT(?:\s*\(version\))?\s+DO NOTHING)?;$",
        )

    def test_virtual_bucket_deterministic_mapping_and_explicit_overrides(self):
        # Verify deterministic SHA-256 bucket mapping bounds and stability
        b_nil = sharding.deterministic_bucket_id(uuid.UUID(int=0))
        b_one = sharding.deterministic_bucket_id("00000000-0000-0000-0000-000000000001")
        b_sample = sharding.deterministic_bucket_id("550e8400-e29b-41d4-a716-446655440000")
        for b in (b_nil, b_one, b_sample):
            self.assertGreaterEqual(b, 0)
            self.assertLess(b, sharding.VIRTUAL_BUCKET_COUNT)
        self.assertEqual(b_nil, sharding.deterministic_bucket_id(uuid.UUID(int=0)))
        self.assertNotEqual(b_nil, b_one)

        eng = sharding.ShardingReferenceEngine()
        self.addCleanup(eng.close)
        alice = eng.create_user("alice")
        r1 = eng.create_repo(alice, "repo1")
        r2 = eng.create_repo(alice, "repo2")

        eng.upsert_node(alice, "node-a", "http://node-a:8080", role="primary", status="healthy")
        eng.upsert_node(alice, "node-b", "http://node-b:8080", role="primary", status="healthy")
        eng.upsert_node(alice, "node-rep", "http://node-rep:8080", role="replica", status="healthy")

        b1 = sharding.deterministic_bucket_id(r1["id"])
        self.assertEqual(eng.upsert_bucket(alice, b1, "node-a", ["node-rep"])[0], 201)

        _, rt1 = eng.get_repo_route(alice, "alice", "repo1")
        self.assertEqual(rt1["primary_node_id"], "node-a")
        self.assertEqual(rt1["read_replica_nodes"], ["node-rep"])
        self.assertFalse(rt1["explicit_override"])

        # Explicit override on repo2 pins it to node-b even if its bucket is reassigned
        b2 = sharding.deterministic_bucket_id(r2["id"])
        eng.upsert_bucket(alice, b2, "node-a")
        _, rt2_ov = eng.configure_repo_route(
            alice, "alice", "repo2", primary_node_id="node-b", explicit_override=True
        )
        self.assertTrue(rt2_ov["explicit_override"])
        self.assertEqual(rt2_ov["primary_node_id"], "node-b")

        # Updating bucket b2 does not overwrite explicit override on repo2, but updates non-overridden bucket b1
        eng.upsert_bucket(alice, b2, "node-a", ["node-rep"])
        _, rt2_after = eng.get_repo_route(alice, "alice", "repo2")
        self.assertEqual(rt2_after["primary_node_id"], "node-b")

        eng.upsert_bucket(alice, b1, "node-b", ["node-rep"])
        _, rt1_after = eng.get_repo_route(alice, "alice", "repo1")
        self.assertEqual(rt1_after["primary_node_id"], "node-b")

    def test_primary_node_lease_acquisition_renewal_and_expiry_fencing(self):
        eng = sharding.ShardingReferenceEngine()
        self.addCleanup(eng.close)
        alice = eng.create_user("alice")
        eng.create_repo(alice, "lease-repo")
        eng.upsert_node(
            alice, "node-a", "http://node-a:8080", role="primary", status="healthy", lease_ttl_seconds=60, now_unix=1000
        )
        eng.configure_repo_route(alice, "alice", "lease-repo", primary_node_id="node-a")

        # Valid lease renewal increments lease_epoch and extends expiry
        st, n1 = eng.renew_node_lease(
            alice, "node-a", lease_ttl_seconds=60, expected_lease_epoch=1, now_unix=1020
        )
        self.assertEqual(st, 200)
        self.assertEqual((n1["lease_epoch"], n1["lease_expires_unix"]), (2, 1080))

        # Stale expected_lease_epoch -> 409 Conflict
        self.assertEqual(
            eng.renew_node_lease(alice, "node-a", lease_ttl_seconds=60, expected_lease_epoch=1, now_unix=1030)[0],
            409,
        )

        # Write route resolution succeeds before lease expiry (now_unix=1050 <= 1080)
        self.assertEqual(
            eng.resolve_repo_route(alice, "alice", "lease-repo", op="write", now_unix=1050)[0],
            200,
        )

        # Write route resolution and barrier check fail after lease expiry (now_unix=1100 > 1080) -> 409
        self.assertEqual(
            eng.resolve_repo_route(alice, "alice", "lease-repo", op="write", now_unix=1100)[0],
            409,
        )
        self.assertEqual(
            eng.apply_or_verify_fence(alice, "alice", "lease-repo", action="verify", now_unix=1100)[0],
            409,
        )

    def test_dual_layer_epoch_and_generation_write_barriers(self):
        eng = sharding.ShardingReferenceEngine()
        self.addCleanup(eng.close)
        alice = eng.create_user("alice")
        repo = eng.create_repo(alice, "fence-repo", storage_generation=2)
        eng.upsert_node(alice, "node-a", "http://node-a:8080", role="primary", status="healthy")
        eng.configure_repo_route(alice, "alice", "fence-repo", primary_node_id="node-a")

        # Fence repository at epoch 2, generation 3 -> writes volume fence marker on disk
        st_f, fenced = eng.apply_or_verify_fence(
            alice, "alice", "fence-repo", action="fence", fenced_epoch=2, storage_generation=3, now_unix=2000
        )
        self.assertEqual(st_f, 200)
        self.assertFalse(fenced["write_admitted"])
        self.assertTrue(eng.marker_path(repo["id"]).is_file())
        self.assertEqual(fenced["volume_marker"]["fenced_epoch"], 2)
        self.assertEqual(fenced["volume_marker"]["storage_generation"], 3)

        # Any write attempt while fenced is rejected with 409
        self.assertEqual(
            eng.apply_or_verify_fence(alice, "alice", "fence-repo", action="verify", now_unix=2005)[0],
            409,
        )

        # Unfence advances route_epoch to 3 and fencing_token to 4
        st_u, unfenced = eng.apply_or_verify_fence(
            alice, "alice", "fence-repo", action="unfence", storage_generation=3, now_unix=2010
        )
        self.assertEqual(st_u, 200)
        self.assertTrue(unfenced["write_admitted"])
        self.assertEqual((unfenced["route_epoch"], unfenced["fencing_token"]), (3, 4))

        # Stale writer probes (epoch=2, token=3, generation=2, or wrong node) are rejected with 409
        self.assertEqual(
            eng.apply_or_verify_fence(
                alice, "alice", "fence-repo", action="verify", writer_route_epoch=2, now_unix=2015
            )[0],
            409,
        )
        self.assertEqual(
            eng.apply_or_verify_fence(
                alice, "alice", "fence-repo", action="verify", writer_fencing_token=3, now_unix=2015
            )[0],
            409,
        )
        self.assertEqual(
            eng.apply_or_verify_fence(
                alice, "alice", "fence-repo", action="verify", writer_storage_generation=2, now_unix=2015
            )[0],
            409,
        )
        self.assertEqual(
            eng.apply_or_verify_fence(
                alice, "alice", "fence-repo", action="verify", writer_node_id="node-stale", now_unix=2015
            )[0],
            409,
        )

        # Matching current epoch=3, token=4, generation=3 succeeds with 200
        self.assertEqual(
            eng.apply_or_verify_fence(
                alice,
                "alice",
                "fence-repo",
                action="verify",
                writer_node_id="node-a",
                writer_route_epoch=3,
                writer_fencing_token=4,
                writer_storage_generation=3,
                now_unix=2015,
            )[0],
            200,
        )

    def test_read_write_watermark_routing_and_replica_fallback(self):
        eng = sharding.ShardingReferenceEngine()
        self.addCleanup(eng.close)
        alice = eng.create_user("alice")
        eng.create_repo(alice, "rw-repo", storage_generation=2)
        eng.upsert_node(alice, "node-a", "http://node-a:8080", role="primary", status="healthy")
        eng.upsert_node(alice, "node-b", "http://node-b:8080", role="replica", status="healthy")
        eng.upsert_node(alice, "node-c", "http://node-c:8080", role="replica", status="healthy")

        eng.configure_repo_route(
            alice,
            "alice",
            "rw-repo",
            primary_node_id="node-a",
            read_replica_nodes=["node-b", "node-c"],
            replica_watermarks={
                "node-b": {"storage_generation": 2, "op_sequence": 8, "verified": True, "updated_unix": 100},
                "node-c": {"storage_generation": 2, "op_sequence": 15, "verified": True, "updated_unix": 100},
            },
            required_generation=2,
            required_op_sequence=10,
        )

        # Read skips lagging node-b (op_sequence=8 < 10) and selects caught-up node-c (op_sequence=15 >= 10)
        st_r, res_r = eng.resolve_repo_route(alice, "alice", "rw-repo", op="read")
        self.assertEqual(st_r, 200)
        self.assertEqual((res_r["target_node_id"], res_r["target_role"], res_r["fallback_to_primary"]), ("node-c", "replica", False))

        # Write and merge_check always target primary node-a when healthy
        _, res_w = eng.resolve_repo_route(alice, "alice", "rw-repo", op="write")
        self.assertEqual((res_w["target_node_id"], res_w["target_role"]), ("node-a", "primary"))
        _, res_m = eng.resolve_repo_route(alice, "alice", "rw-repo", op="merge_check")
        self.assertEqual((res_m["target_node_id"], res_m["target_role"]), ("node-a", "primary"))

        # Read with min_op_sequence=50 (above all replicas) falls back to primary node-a
        _, res_fb = eng.resolve_repo_route(alice, "alice", "rw-repo", op="read", min_op_sequence=50)
        self.assertEqual((res_fb["target_node_id"], res_fb["fallback_to_primary"]), ("node-a", True))

        # Mismatched client_route_epoch -> 409 Conflict
        self.assertEqual(
            eng.resolve_repo_route(alice, "alice", "rw-repo", op="read", client_route_epoch=999)[0],
            409,
        )

    def test_automated_four_stage_failover_and_split_brain_prevention(self):
        eng = sharding.ShardingReferenceEngine()
        self.addCleanup(eng.close)
        alice = eng.create_user("alice")
        repo = eng.create_repo(alice, "fo-repo", storage_generation=2)
        eng.upsert_node(alice, "node-a", "http://node-a:8080", role="primary", status="healthy")
        eng.upsert_node(alice, "node-b", "http://node-b:8080", role="replica", status="healthy")
        eng.upsert_node(alice, "node-c", "http://node-c:8080", role="replica", status="healthy")

        eng.configure_repo_route(
            alice,
            "alice",
            "fo-repo",
            primary_node_id="node-a",
            read_replica_nodes=["node-b", "node-c"],
            replica_watermarks={
                "node-b": {"storage_generation": 2, "op_sequence": 3, "verified": True, "updated_unix": 100},
                "node-c": {"storage_generation": 2, "op_sequence": 20, "verified": True, "updated_unix": 100},
            },
            required_generation=2,
            required_op_sequence=10,
            in_flight_writes=1,
        )

        # Active in-flight writes without force_drain rejects failover at Stage 1 (draining) -> 409
        self.assertEqual(
            eng.execute_failover(alice, "alice", "fo-repo", new_primary_node_id="node-c")[0],
            409,
        )
        eng.configure_repo_route(alice, "alice", "fo-repo", in_flight_writes=0)

        # Git lock file on disk rejects failover -> 409
        lock_file = eng.repo_path(repo["id"]) / "HEAD.lock"
        lock_file.write_text("locked", encoding="utf-8")
        self.assertEqual(
            eng.execute_failover(alice, "alice", "fo-repo", new_primary_node_id="node-c")[0],
            409,
        )
        lock_file.unlink()

        # Lagging replica node-b rejected at Stage 3 (verified) -> 409
        self.assertEqual(
            eng.execute_failover(alice, "alice", "fo-repo", new_primary_node_id="node-b")[0],
            409,
        )

        # Caught-up replica node-c promotes through draining -> fenced -> verified -> promoted
        st, fo = eng.execute_failover(
            alice, "alice", "fo-repo", new_primary_node_id="node-c", reason="Planned switchover", bump_generation=True
        )
        self.assertEqual(st, 200)
        self.assertEqual(fo["state"], "promoted")
        self.assertEqual((fo["old_primary_node_id"], fo["new_primary_node_id"]), ("node-a", "node-c"))
        self.assertEqual(fo["new_route_epoch"], fo["old_route_epoch"] + 1)
        self.assertEqual(fo["storage_generation"], 3)
        self.assertEqual(fo["snapshot"]["stages"], ["draining", "fenced", "verified", "promoted"])

        # Split-brain write from old primary node-a is rejected with 409
        self.assertEqual(
            eng.apply_or_verify_fence(alice, "alice", "fo-repo", action="verify", writer_node_id="node-a")[0],
            409,
        )
        # New primary node-c is admitted for writes
        self.assertEqual(
            eng.apply_or_verify_fence(alice, "alice", "fo-repo", action="verify", writer_node_id="node-c")[0],
            200,
        )

    def test_read_only_degradation_drill_and_recovery(self):
        eng = sharding.ShardingReferenceEngine()
        self.addCleanup(eng.close)
        alice = eng.create_user("alice")
        eng.create_repo(alice, "deg-repo", storage_generation=1)
        eng.upsert_node(alice, "node-a", "http://node-a:8080", role="primary", status="healthy")
        eng.upsert_node(alice, "node-b", "http://node-b:8080", role="replica", status="healthy")
        eng.configure_repo_route(
            alice,
            "alice",
            "deg-repo",
            primary_node_id="node-a",
            read_replica_nodes=["node-b"],
            replica_watermarks={
                "node-b": {"storage_generation": 1, "op_sequence": 10, "verified": True, "updated_unix": 100}
            },
            required_generation=1,
            required_op_sequence=5,
        )

        # Enter read-only degradation drill
        st_d, deg = eng.degrade_or_recover_repo(
            alice, "alice", "deg-repo", mode="degrade", reason="Chaos drill"
        )
        self.assertEqual(st_d, 200)
        self.assertTrue(deg["read_only_degraded"])
        self.assertFalse(deg["write_admitted"])
        self.assertTrue(deg["volume_marker"]["read_only_degraded"])

        # Writes and write barriers rejected with 409 during drill
        self.assertEqual(eng.resolve_repo_route(alice, "alice", "deg-repo", op="write")[0], 409)
        self.assertEqual(eng.apply_or_verify_fence(alice, "alice", "deg-repo", action="verify")[0], 409)

        # Reads and merge_check continue via watermark-qualified replica node-b
        st_r, res_r = eng.resolve_repo_route(alice, "alice", "deg-repo", op="read")
        self.assertEqual(st_r, 200)
        self.assertEqual((res_r["target_node_id"], res_r["read_only_degraded"]), ("node-b", True))

        # Recover from degradation drill restores writable primary and bumps route_epoch + fencing_token
        st_rec, rec = eng.degrade_or_recover_repo(alice, "alice", "deg-repo", mode="recover")
        self.assertEqual(st_rec, 200)
        self.assertFalse(rec["read_only_degraded"])
        self.assertTrue(rec["write_admitted"])
        self.assertEqual(eng.resolve_repo_route(alice, "alice", "deg-repo", op="write")[0], 200)

    def test_access_boundaries_and_e2e_harness_contract(self):
        eng = sharding.ShardingReferenceEngine()
        self.addCleanup(eng.close)
        alice = eng.create_user("alice")
        bob_write = eng.create_user("bob")
        carol_read = eng.create_user("carol")
        outsider = eng.create_user("outsider")
        alice_ro = {**alice, "read_only": True}
        eng.create_repo(alice, "sec-repo")
        eng.add_collaborator(alice, "sec-repo", bob_write, "write")
        eng.add_collaborator(alice, "sec-repo", carol_read, "read")

        # 401 unauthenticated
        self.assertEqual(eng.get_repo_route(None, "alice", "sec-repo")[0], 401)
        self.assertEqual(eng.list_nodes(None)[0], 401)

        # 404 non-member on private repo
        self.assertEqual(eng.get_repo_route(outsider, "alice", "sec-repo")[0], 404)
        self.assertEqual(eng.get_fence_status(outsider, "alice", "sec-repo")[0], 404)

        # Read member can view route & fence status (200), but Write member cannot mutate shard config/fence/failover (403)
        self.assertEqual(eng.get_repo_route(carol_read, "alice", "sec-repo")[0], 200)
        self.assertEqual(eng.get_fence_status(carol_read, "alice", "sec-repo")[0], 200)
        self.assertEqual(eng.configure_repo_route(bob_write, "alice", "sec-repo", required_op_sequence=1)[0], 403)
        self.assertEqual(eng.apply_or_verify_fence(bob_write, "alice", "sec-repo", action="fence")[0], 403)
        self.assertEqual(eng.execute_failover(bob_write, "alice", "sec-repo", "node-b")[0], 403)
        self.assertEqual(eng.degrade_or_recover_repo(bob_write, "alice", "sec-repo", mode="degrade")[0], 403)

        # Read-only token on Admin actor rejected with 403 on mutations
        self.assertEqual(eng.upsert_node(alice_ro, "node-ro", "http://ro:8080")[0], 403)
        self.assertEqual(eng.degrade_or_recover_repo(alice_ro, "alice", "sec-repo", mode="degrade")[0], 403)

        # Unknown fields / invalid values rejected with 400
        self.assertEqual(
            eng.upsert_node(alice, "node-x", "http://x:8080", extra_fields={"unexpected": 1})[0],
            400,
        )

        # Verify E2E script AST and required case methods
        sharding_py = ROOT / "tests/sharding.py"
        src = sharding_py.read_text(encoding="utf-8")
        ast.parse(src)
        for case_name in (
            "setup",
            "migration",
            "virtual_bucket_routing_and_explicit_overrides",
            "primary_node_lease_renewal_and_expiry_fencing",
            "dual_layer_epoch_and_generation_write_barriers",
            "read_write_watermark_routing_and_replica_fallback",
            "automated_four_stage_failover_state_machine",
            "read_only_degradation_drill_and_recovery",
            "access_and_boundaries",
            "run_all",
        ):
            self.assertIn(f"def {case_name}(", src)


if __name__ == "__main__":
    unittest.main()
