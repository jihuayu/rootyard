#!/usr/bin/env python3
"""Unit, structural, SQL contract, and behavioral tests for Track 3 (M3: F13, F14, F15)."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
from unittest import mock
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_mirror  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class CiMirrorTrack3Test(unittest.TestCase):
    def test_mirror_modular_architecture_and_line_bounds(self):
        mirror_rs = ROOT / "src" / "mirror.rs"
        self.assertTrue(mirror_rs.is_file(), "src/mirror.rs must remain a regular file")
        self.assertFalse(
            (ROOT / "src" / "mirror" / "mod.rs").exists(),
            "src/mirror/mod.rs must not exist; src/mirror.rs is the module root",
        )
        lines = mirror_rs.read_text().splitlines()
        self.assertLess(
            len(lines),
            150,
            f"src/mirror.rs must stay under 150 lines (got {len(lines)})",
        )
        source = mirror_rs.read_text()
        for decl in (
            "pub mod eviction;",
            "pub mod limiter;",
            "pub mod observability;",
            "pub mod sync;",
            "pub mod views;",
            "pub fn routes() -> Router<Arc<AppState>>",
            "pub fn router(state: Arc<AppState>) -> Router",
            "pub async fn open(config: Config, pool: Pool) -> Result<Arc<AppState>>",
        ):
            self.assertIn(decl, source, f"Missing declaration in src/mirror.rs: {decl}")

        for submod in ("eviction.rs", "limiter.rs", "observability.rs", "sync.rs", "views.rs"):
            sub_path = ROOT / "src" / "mirror" / submod
            self.assertTrue(sub_path.is_file(), f"Missing submodule {sub_path}")
            sub_lines = len(sub_path.read_text().splitlines())
            self.assertGreaterEqual(sub_lines, 40, f"{submod} is unexpectedly tiny ({sub_lines} lines)")
            self.assertLessEqual(sub_lines, 700, f"{submod} exceeds modular size bound ({sub_lines} lines)")

    def test_staged_migration_030_ci_mirror_sql_contract(self):
        sql_path = ROOT / "src" / "mirror" / "030_ci_mirror.sql"
        if not sql_path.is_file():
            sql_path = ROOT / "migrations" / "030_ci_mirror.sql"
        self.assertTrue(sql_path.is_file(), "Missing 030_ci_mirror.sql")
        sql = sql_path.read_text()

        for snippet in (
            "CREATE TABLE ci_mirror_evictions",
            "repository_id UUID NOT NULL REFERENCES repositories(id)",
            "eviction_id UUID NOT NULL",
            "storage_generation BIGINT NOT NULL CHECK (storage_generation > 0)",
            "evicted_pins BIGINT NOT NULL CHECK (evicted_pins >= 0)",
            "evicted_job_views BIGINT NOT NULL CHECK (evicted_job_views >= 0)",
            "evicted_snapshots BIGINT NOT NULL CHECK (evicted_snapshots >= 0)",
            "reclaimed_bytes BIGINT NOT NULL CHECK (reclaimed_bytes >= 0)",
            "created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()",
            "PRIMARY KEY (repository_id, eviction_id)",
            "CREATE INDEX ci_mirror_evictions_repo_created_idx",
            "INSERT INTO schema_migrations (version) VALUES (30);",
        ):
            self.assertIn(snippet, sql, f"Missing SQL contract snippet in 030_ci_mirror.sql: {snippet}")

        self.assertIsNone(
            re.search(r"\bBETWEEN\b", sql, re.IGNORECASE),
            "030_ci_mirror.sql must not use BETWEEN in CHECK constraints",
        )

    def test_f13_eviction_routes_and_safety_guards_in_source(self):
        mirror_rs = (ROOT / "src" / "mirror.rs").read_text()
        eviction_rs = (ROOT / "src" / "mirror" / "eviction.rs").read_text()

        self.assertIn('"/api/repos/{owner}/{name}/mirror-evict"', mirror_rs)
        self.assertIn('"/api/repos/{owner}/{name}/mirror-prune"', mirror_rs)

        for guard in (
            "current.json",
            "crate::ci_checkouts::active_leases",
            "crate::ci_pins::active_pinned_oids",
            "INSERT INTO ci_mirror_evictions",
            "pub struct EvictRequest",
            "pub struct EvictionReport",
            "pub(crate) fn evict_repo_directory",
            "pub(crate) async fn enforce_watermark_locked",
        ):
            self.assertIn(guard, eviction_rs, f"Missing F13 eviction guard in eviction.rs: {guard}")

    def test_f14_ci_pins_release_and_lease_coordination_in_source(self):
        ci_pins_rs = (ROOT / "src" / "ci_pins.rs").read_text()
        ci_checkouts_rs = (ROOT / "src" / "ci_checkouts.rs").read_text()

        self.assertIn("pub fn routes() -> Router<Arc<AppState>>", ci_pins_rs)
        self.assertIn('"/api/repos/{owner}/{name}/ci-pins"', ci_pins_rs)
        self.assertIn('"/api/repos/{owner}/{name}/ci-pins/{job}"', ci_pins_rs)
        self.assertIn('"/api/repos/{owner}/{name}/ci-pins/{job}/release"', ci_pins_rs)

        for fn_sig in (
            "pub fn is_lease_active(",
            "pub async fn has_active_lease_on(",
            "pub async fn active_leases(",
            "pub async fn active_job_ids(",
            "pub async fn active_pinned_oids(",
        ):
            self.assertIn(fn_sig, ci_checkouts_rs, f"Missing helper in src/ci_checkouts.rs: {fn_sig}")

        for pin_contract in (
            "crate::ci_checkouts::has_active_lease_on(&tx, repo.id, job)",
            "active checkout lease exists for job",
            "StatusCode::CONFLICT",
            "update-ref",
            "-d",
            "--no-deref",
            "observed_immutable_ci_root",
            '"released"',
            "pub async fn active_pinned_oids(",
        ):
            self.assertIn(pin_contract, ci_pins_rs, f"Missing F14 contract in src/ci_pins.rs: {pin_contract}")

    def test_f15_limiter_and_observability_in_source(self):
        mirror_rs = (ROOT / "src" / "mirror.rs").read_text()
        limiter_rs = (ROOT / "src" / "mirror" / "limiter.rs").read_text()
        observability_rs = (ROOT / "src" / "mirror" / "observability.rs").read_text()

        self.assertIn('"/api/repos/{owner}/{name}/mirror-status"', mirror_rs)
        self.assertIn('"/metrics"', mirror_rs)

        for limiter_contract in (
            "ROOTYARD_MIRROR_MAX_CONCURRENT_SYNCS",
            "ROOTYARD_MIRROR_MAX_CONCURRENT_CLOSURES",
            "ROOTYARD_MIRROR_SYNC_COOLDOWN_MS",
            "StatusCode::TOO_MANY_REQUESTS",
            "pub struct MirrorLimiter",
            "pub struct SyncPermit",
            "try_acquire_sync",
            "try_acquire_closure",
        ):
            self.assertIn(limiter_contract, limiter_rs, f"Missing F15 contract in limiter.rs: {limiter_contract}")

        for obs_contract in (
            "pub struct MirrorCounters",
            "pub struct MirrorRepoStatus",
            "rootyard_mirror_sync_in_flight",
            "rootyard_mirror_sync_limit",
            "rootyard_mirror_sync_total",
            "rootyard_mirror_sync_rate_limited_total",
            "rootyard_mirror_evictions_total",
            "rootyard_mirror_reclaimed_bytes_total",
            "rootyard_mirror_disk_bytes",
            '"no-store"',
        ):
            self.assertIn(obs_contract, observability_rs, f"Missing F15 contract in observability.rs: {obs_contract}")

    def test_mirror_harness_f13_f14_f15_methods_offline(self):
        harness = object.__new__(ci_mirror.MirrorHarness)
        harness.root = Path("/tmp/fake-mirror-root")
        harness.bare = Path("/tmp/fake-primary-bare")
        harness.repo = {"id": str(uuid.uuid4())}
        harness.alice = {"username": "alice", "token": "ryt_alice_secret"}
        harness.bob = {"username": "bob", "token": "ryt_bob_secret"}
        harness.reader = {"username": "alice", "token": "ryt_reader_secret"}
        harness.first = "1" * 40
        harness.second = "2" * 40
        harness.third = "3" * 40

        sql_queries = []
        active_pins = {}

        def fake_sql(query):
            sql_queries.append(query)
            if "to_regclass('ci_mirror_evictions')" in query:
                return "f"
            if "SELECT count(*) FROM ci_mirror_evictions" in query:
                return "1"
            return ""

        def fake_expect(path, codes, token=None, method="GET", body=None):
            if path == "/api/repos/alice/demo/ci-pins" and method == "POST":
                rec = {
                    "version": 1,
                    "job_id": body["job_id"],
                    "owner_id": str(uuid.uuid4()),
                    "repository_id": harness.repo["id"],
                    "storage_generation": body["storage_generation"],
                    "object_format": "sha1",
                    "target_oid": body["target_oid"],
                    "retention_ref": f"refs/rootyard-ci/jobs/{body['job_id']}",
                    "state": "pinned",
                }
                active_pins[body["job_id"]] = rec
                return json.dumps(rec).encode()
            if path == "/api/repos/alice/demo/ci-pins" and method == "GET":
                if codes != 200:
                    return b"denied"
                return json.dumps(list(active_pins.values())).encode()
            if "/ci-checkouts/" in path and path.endswith("/revoke"):
                return json.dumps({"state": "revoked"}).encode()
            if "/ci-pins/" in path and method in ("DELETE", "POST"):
                if codes != 200:
                    return b"conflict_or_forbidden"
                parts = path.rstrip("/").split("/")
                job_id = parts[-2] if parts[-1] == "release" else parts[-1]
                rec = active_pins.pop(job_id, {"job_id": job_id, "target_oid": harness.first})
                rec = dict(rec, state="released", released=True)
                return json.dumps(rec).encode()
            return b"{}"

        def fake_mirror_expect(path, codes, token=None, method="GET", body=None):
            if codes != 200:
                return b"denied"
            if path.endswith("/mirror-evict") or path.endswith("/mirror-prune"):
                retained = 0 if path.endswith("/mirror-prune") else 1
                return json.dumps(
                    {
                        "eviction_id": str(uuid.uuid4()),
                        "repository_id": harness.repo["id"],
                        "storage_generation": 1,
                        "evicted_pins": 1,
                        "evicted_job_views": 1,
                        "evicted_snapshots": 1,
                        "reclaimed_bytes": 4096,
                        "disk_bytes": 8192,
                        "retained_pins": retained,
                        "protected_oids": [harness.first],
                    }
                ).encode()
            if path.endswith("/mirror-status"):
                return json.dumps(
                    {
                        "repository_id": harness.repo["id"],
                        "storage_generation": 1,
                        "current_snapshot": str(uuid.uuid4()),
                        "snapshot_count": 2,
                        "pin_count": 1,
                        "job_view_count": 1,
                        "active_lease_count": 0,
                        "sync_in_flight": 0,
                        "sync_limit": 4,
                        "evictions_total": 1,
                        "reclaimed_bytes_total": 4096,
                        "disk_bytes": 8192,
                    }
                ).encode()
            if path.endswith("/mirror-sync"):
                return json.dumps(
                    {
                        "repository_id": harness.repo["id"],
                        "storage_generation": 1,
                        "snapshot": str(uuid.uuid4()),
                    }
                ).encode()
            return b"{}"

        def fake_mirror_http(path, method="GET", **kwargs):
            metrics_body = (
                "rootyard_mirror_sync_in_flight 0\n"
                "rootyard_mirror_sync_limit 4\n"
                "rootyard_mirror_sync_total 2\n"
                "rootyard_mirror_sync_rate_limited_total 0\n"
                "rootyard_mirror_evictions_total 1\n"
                "rootyard_mirror_reclaimed_bytes_total 4096\n"
                "rootyard_mirror_disk_bytes 8192\n"
            ).encode()
            return 200, metrics_body, {"Cache-Control": "no-store"}

        def fake_git(*args, **kwargs):
            if "--verify" in args:
                return subprocess.CompletedProcess(args, 1, b"", b"")
            return subprocess.CompletedProcess(args, 0, (harness.first + "\n").encode(), b"")

        harness.sql = fake_sql
        harness.expect = fake_expect
        harness.mirror_expect = fake_mirror_expect
        harness.mirror_http = fake_mirror_http
        harness.git = fake_git
        harness.clone_at = mock.MagicMock(return_value=Path("/tmp/cloned"))

        res_f14 = harness.pin_listing_and_lease_coordinated_release()
        self.assertTrue(res_f14["active_lease_blocks_release_409"])
        self.assertTrue(res_f14["released_after_revoke"])

        res_f13 = harness.watermark_and_lru_eviction_safety()
        self.assertTrue(res_f13["protected_pin_preserved"])
        self.assertTrue(res_f13["sql_audit_recorded"])
        self.assertTrue(any("CREATE TABLE ci_mirror_evictions" in q for q in sql_queries))

        res_f15 = harness.sync_rate_limiting_and_observability()
        self.assertTrue(res_f15["status_endpoint_verified"])
        self.assertTrue(res_f15["prometheus_metrics_verified"])

    def test_docs_ci_mirror_fences_and_links(self):
        doc_path = ROOT / "docs" / "ci-mirror.md"
        self.assertTrue(doc_path.is_file())
        text = doc_path.read_text()
        fence_lines = [
            line for line in text.splitlines() if line.lstrip().startswith(("```", "~~~"))
        ]
        self.assertEqual(
            len(fence_lines) % 2,
            0,
            f"Unbalanced code fences in docs/ci-mirror.md ({len(fence_lines)} fence markers)",
        )
        for section in (
            "## Source pin listing and lease-coordinated release",
            "## Disk watermarks and safe LRU eviction",
            "## Concurrent sync rate limiting and mirror observability",
        ):
            self.assertIn(section, text, f"Missing section in docs/ci-mirror.md: {section}")

    def test_optional_cargo_when_available(self):
        search_path = os.environ.get("PATH", "")
        for extra in ("/root/.cargo/bin", str(Path.home() / ".cargo" / "bin"), "/usr/local/cargo/bin"):
            if extra not in search_path:
                search_path = f"{extra}:{search_path}"
        cargo = shutil.which("cargo", path=search_path)
        if not cargo:
            return
        env = os.environ.copy()
        env["PATH"] = search_path
        for target in ("mirror", "ci_pins", "ci_checkouts"):
            proc = subprocess.run(
                [cargo, "test", "--lib", target],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
