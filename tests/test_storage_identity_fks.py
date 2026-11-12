#!/usr/bin/env python3
"""Per-PR live PostgreSQL regression for schema134 repository/tenant FKs (#90).

Runs under ``python3 -m unittest discover -s tests -p 'test_*.py'``. In CI
(``GITHUB_ACTIONS=true``) ``ROOTYARD_TEST_DATABASE_URL`` is required and missing
configuration fails hard rather than skipping. Locally, if unset, an ephemeral
PostgreSQL cluster starts under ``tempfile`` (honoring ``TMPDIR``) and stops on
class teardown. Each test owns a random SQL schema dropped with ``CASCADE``.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema_baseline  # noqa: E402

MIGRATION_134 = schema_baseline.MIGRATIONS_DIR / "134_storage_identity_fks.sql"
MANIFEST_UNIQUE = "pando_pack_manifests_id_repository_tenant_key"
MANIFEST_IDENTITY_FK = "pando_manifest_artifacts_manifest_identity_fkey"
ARTIFACT_AUTHORITY_FK = "pando_manifest_artifacts_authority_id_tenant_id_namespace__fkey"
REPO_STATE_OWNER_FK = "storage_maintenance_repo_state_repository_owner_fkey"
JOBS_OWNER_FK = "storage_maintenance_jobs_repository_owner_fkey"
TOMBSTONES_OWNER_FK = "storage_maintenance_tombstones_repository_owner_fkey"
REPO_OWNER_PAIR = ("FOREIGN KEY (repository_id, tenant_id)", "REFERENCES repositories(id, owner_id)")
COMPOSITE_FKS = {
    MANIFEST_IDENTITY_FK: (
        "FOREIGN KEY (manifest_id, repository_id, tenant_id)",
        "REFERENCES pando_pack_manifests(id, repository_id, tenant_id)",
    ),
    REPO_STATE_OWNER_FK: REPO_OWNER_PAIR,
    JOBS_OWNER_FK: REPO_OWNER_PAIR,
    TOMBSTONES_OWNER_FK: REPO_OWNER_PAIR,
}
REMOVED_SINGLE_COL_FKS = (
    "pando_manifest_artifacts_manifest_id_fkey",
    "storage_maintenance_repo_state_repository_id_fkey",
    "storage_maintenance_jobs_repository_id_fkey",
    "storage_maintenance_tombstones_repository_id_fkey",
)


def resolve_database_url(environ, start_local):
    url = (environ.get("ROOTYARD_TEST_DATABASE_URL") or "").strip()
    if url:
        return url
    if environ.get("GITHUB_ACTIONS") == "true":
        raise RuntimeError(
            "ROOTYARD_TEST_DATABASE_URL is required when GITHUB_ACTIONS=true; "
            "refusing to silently skip live PostgreSQL regression in CI"
        )
    return start_local()


def refusal_message(links, repo_state, jobs, tombstones):
    return (
        f"schema134 refuses to upgrade: {links} manifest link row(s), "
        f"{repo_state} repository state row(s), {jobs} maintenance job(s) and "
        f"{tombstones} tombstone(s) disagree with their repository identity; no row was modified"
    )


def psql_exec(db_url, args=(), stdin_sql=None, check=True):
    proc = subprocess.run(
        ["psql", "--dbname", db_url, "-X", "-qAt", "-v", "ON_ERROR_STOP=1", *args],
        cwd=schema_baseline.ROOT, input=stdin_sql, capture_output=True, text=True, timeout=60,
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"psql failed (rc={proc.returncode}): {proc.stderr[-3000:]}")
    return proc


def sql_scalar(db_url, query):
    return psql_exec(db_url, ("-c", query)).stdout.strip()


def start_ephemeral_pg(add_cleanup, prefix="rootyard-fk90-pg-"):
    for tool in ("initdb", "pg_ctl"):
        if not shutil.which(tool):
            raise RuntimeError(f"ROOTYARD_TEST_DATABASE_URL is unset and {tool} is missing")
    root = Path(tempfile.mkdtemp(prefix=prefix))
    add_cleanup(shutil.rmtree, root, True)
    pgdata = root / "pgdata"
    init_cmd = ["initdb", "--no-instructions", "-A", "trust", "-U", "rootyard",
                "--no-locale", "--encoding=UTF8", "-D", str(pgdata)]
    if os.environ.get("PG_SHARE"):
        init_cmd.extend(["-L", os.environ["PG_SHARE"]])
    subprocess.run(init_cmd, check=True, capture_output=True, text=True, timeout=60)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    add_cleanup(subprocess.run, ["pg_ctl", "-D", str(pgdata), "-m", "immediate", "-w", "stop"],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    subprocess.run(["pg_ctl", "-D", str(pgdata), "-l", str(root / "pg.log"),
                    "-o", f"-h 127.0.0.1 -p {port} -k ''", "-w", "start"],
                   check=True, capture_output=True, text=True, timeout=60)
    sql_scalar(f"postgresql://rootyard@127.0.0.1:{port}/postgres", "CREATE DATABASE rootyard_test TEMPLATE template0")
    return f"postgresql://rootyard@127.0.0.1:{port}/rootyard_test"


class StorageIdentityFksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("psql"):
            raise RuntimeError("psql is required for live PostgreSQL FK regression")
        cls.base_db = resolve_database_url(os.environ, lambda: start_ephemeral_pg(cls.addClassCleanup))
        if cls._sql(cls.base_db, "SELECT 1") != "1":
            raise RuntimeError("PostgreSQL connectivity check failed")

    _psql = staticmethod(psql_exec)
    _sql = staticmethod(sql_scalar)

    def _isolated_schema(self):
        schema = "rootyard_fk90_" + uuid.uuid4().hex
        parts = urllib.parse.urlsplit(self.base_db)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if any(key == "options" for key, _ in query):
            raise RuntimeError("ROOTYARD_TEST_DATABASE_URL must not preset options")
        query.append(("options", f"-csearch_path={schema}"))
        schema_db = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
        self.addCleanup(self._sql, self.base_db, f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        self._sql(self.base_db, f'CREATE SCHEMA "{schema}"')
        return schema, schema_db

    def _migrate(self, db_url, min_ver=1, max_ver=schema_baseline.LATEST_VERSION):
        args = ["--single-transaction", "-c", "SELECT pg_advisory_xact_lock(738390103)"]
        for path in sorted(schema_baseline.MIGRATIONS_DIR.glob("*.sql")):
            if min_ver <= int(path.name.split("_", 1)[0]) <= max_ver:
                args.extend(["-f", str(path)])
        self._psql(db_url, args)

    def _constraints(self, db_url, schema):
        raw = self._sql(
            db_url,
            "SELECT COALESCE(json_object_agg(k.conname, json_build_array("
            "k.contype::text, k.convalidated, k.confdeltype::text, pg_get_constraintdef(k.oid)"
            f")), '{{}}'::json)::text FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid "
            f"JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '{schema}' AND k.contype IN ('f', 'u')",
        )
        return {
            name: (ct, val, dt, dfn.replace(f"{schema}.", ""))
            for name, (ct, val, dt, dfn) in json.loads(raw).items()
        }

    def _assert_schema134_constraints(self, db_url, schema):
        defs = self._constraints(db_url, schema)
        for name, (cols, target) in COMPOSITE_FKS.items():
            self.assertIn(name, defs)
            contype, validated, deltype, definition = defs[name]
            self.assertEqual((contype, validated, deltype), ("f", True, "c"))
            self.assertIn(cols, definition)
            self.assertIn(target, definition)
            self.assertIn("ON DELETE CASCADE", definition)
        self.assertIn(MANIFEST_UNIQUE, defs)
        u_type, u_valid, _, u_def = defs[MANIFEST_UNIQUE]
        self.assertEqual((u_type, u_valid), ("u", True))
        self.assertIn("UNIQUE (id, repository_id, tenant_id)", u_def)
        self.assertIn(ARTIFACT_AUTHORITY_FK, defs)
        for removed in REMOVED_SINGLE_COL_FKS:
            self.assertNotIn(removed, defs)

    def _assert_fk_rejected(self, db_url, insert_sql, expected_constraint):
        probe = (
            "BEGIN;\nCREATE TEMP TABLE fk90_probe(st text, cn text) ON COMMIT DROP;\n"
            f"DO $$ DECLARE s text; c text; BEGIN BEGIN {insert_sql}; EXCEPTION WHEN OTHERS THEN "
            "GET STACKED DIAGNOSTICS s = RETURNED_SQLSTATE, c = CONSTRAINT_NAME; "
            "INSERT INTO fk90_probe VALUES (s, c); END; END $$;\n"
            "SELECT COALESCE(st, '') || '|' || COALESCE(cn, '') FROM fk90_probe;\nCOMMIT;\n"
        )
        observed = self._psql(db_url, stdin_sql=probe).stdout.strip()
        self.assertTrue(observed, f"Expected 23503/{expected_constraint}, statement succeeded")
        sqlstate, constraint = observed.split("|", 1)
        self.assertEqual((sqlstate, constraint), ("23503", expected_constraint))

    def _seed_two_tenants(self, db_url):
        ids = {k: str(uuid.uuid4()) for k in ("owner_a", "owner_b", "repo_a", "repo_a_free", "repo_b", "manifest_a", "manifest_b")}
        ids["sha_a"] = uuid.uuid4().hex + uuid.uuid4().hex
        ids["sha_b"] = uuid.uuid4().hex + uuid.uuid4().hex
        ids["authority"] = self._sql(db_url, "SELECT authority_id::text FROM pando_storage_authorities")
        self._psql(db_url, stdin_sql=(
            f"INSERT INTO users(id, username) VALUES ('{ids['owner_a']}', 'alice-secret-90'), ('{ids['owner_b']}', 'bob-secret-90');\n"
            f"INSERT INTO repositories(id, owner_id, name, state, storage_backend) VALUES "
            f"('{ids['repo_a']}', '{ids['owner_a']}', 'repo-alpha-90', 'ready', 'pando'), "
            f"('{ids['repo_a_free']}', '{ids['owner_a']}', 'repo-alpha-free-90', 'ready', 'gitfs'), "
            f"('{ids['repo_b']}', '{ids['owner_b']}', 'repo-beta-90', 'ready', 'pando');\n"
            f"INSERT INTO pando_remote_artifacts(authority_id, tenant_id, namespace, sha256, size, object_generation, remote_path, state) VALUES "
            f"('{ids['authority']}', '{ids['owner_a']}', 'pando-cipher', '{ids['sha_a']}', 64, 1, 'pando/{ids['authority']}/{ids['owner_a']}/{ids['sha_a']}', 'active'), "
            f"('{ids['authority']}', '{ids['owner_b']}', 'pando-cipher', '{ids['sha_b']}', 64, 1, 'pando/{ids['authority']}/{ids['owner_b']}/{ids['sha_b']}', 'active');\n"
            f"INSERT INTO pando_pack_manifests(id, repository_id, tenant_id, storage_generation, object_format, manifest) VALUES "
            f"('{ids['manifest_a']}', '{ids['repo_a']}', '{ids['owner_a']}', 1, 'sha1', '{{\"marker\":\"manifest-secret-90\"}}'::jsonb), "
            f"('{ids['manifest_b']}', '{ids['repo_b']}', '{ids['owner_b']}', 1, 'sha1', '{{}}'::jsonb);\n"
        ))
        return ids

    def test_ci_requires_explicit_database_url(self):
        with self.assertRaisesRegex(RuntimeError, "GITHUB_ACTIONS=true"):
            resolve_database_url({"GITHUB_ACTIONS": "true"}, lambda: self.fail("started local PG in CI"))
        self.assertEqual(
            resolve_database_url({"GITHUB_ACTIONS": "true", "ROOTYARD_TEST_DATABASE_URL": "postgresql://h/d"}, lambda: ""),
            "postgresql://h/d",
        )

    def test_latest_schema_composite_fks_and_exact_23503_refusals(self):
        self.assertGreaterEqual(schema_baseline.LATEST_VERSION, 147)
        schema, db_url = self._isolated_schema()
        self._migrate(db_url, 1, schema_baseline.LATEST_VERSION)
        installed = [int(v) for v in self._sql(db_url, "SELECT version FROM schema_migrations ORDER BY version").splitlines()]
        self.assertEqual(installed, schema_baseline.SCHEMA_VERSIONS)
        self._assert_schema134_constraints(db_url, schema)

        ids = self._seed_two_tenants(db_url)
        ok_job, ok_oid, bad_oid = str(uuid.uuid4()), uuid.uuid4().hex + "0" * 8, uuid.uuid4().hex + "f" * 8
        self._psql(db_url, stdin_sql=(
            f"INSERT INTO pando_manifest_artifacts VALUES "
            f"('{ids['manifest_a']}', '{ids['repo_a']}', '{ids['authority']}', '{ids['owner_a']}', 'pando-cipher', '{ids['sha_a']}', 'index-cipher'), "
            f"('{ids['manifest_b']}', '{ids['repo_b']}', '{ids['authority']}', '{ids['owner_b']}', 'pando-cipher', '{ids['sha_b']}', 'index-cipher');\n"
            f"INSERT INTO storage_maintenance_repo_state(repository_id, tenant_id) VALUES ('{ids['repo_a']}', '{ids['owner_a']}');\n"
            f"INSERT INTO storage_maintenance_jobs(id, repository_id, tenant_id, kind, state, repository_generation, completed_at) "
            f"VALUES ('{ok_job}', '{ids['repo_a']}', '{ids['owner_a']}', 'gitfs_stage_cleanup', 'failed', 1, clock_timestamp());\n"
            f"INSERT INTO storage_maintenance_tombstones(repository_id, tenant_id, oid, object_kind, repository_generation, delete_after, state) "
            f"VALUES ('{ids['repo_a']}', '{ids['owner_a']}', '{ok_oid}', 'blob', 1, clock_timestamp(), 'retained');\n"
        ))

        self._assert_fk_rejected(
            db_url,
            f"INSERT INTO pando_manifest_artifacts VALUES ('{ids['manifest_a']}', '{ids['repo_a']}', "
            f"'{ids['authority']}', '{ids['owner_b']}', 'pando-cipher', '{ids['sha_b']}', 'pack-cipher')",
            MANIFEST_IDENTITY_FK,
        )
        self._assert_fk_rejected(
            db_url,
            f"INSERT INTO pando_manifest_artifacts VALUES ('{ids['manifest_a']}', '{ids['repo_b']}', "
            f"'{ids['authority']}', '{ids['owner_a']}', 'pando-cipher', '{ids['sha_a']}', 'pack-cipher')",
            MANIFEST_IDENTITY_FK,
        )
        self._assert_fk_rejected(
            db_url,
            f"INSERT INTO pando_manifest_artifacts VALUES ('{ids['manifest_b']}', '{ids['repo_b']}', "
            f"'{ids['authority']}', '{ids['owner_b']}', 'pando-cipher', '{ids['sha_a']}', 'pack-cipher')",
            ARTIFACT_AUTHORITY_FK,
        )
        self._assert_fk_rejected(
            db_url,
            f"INSERT INTO storage_maintenance_repo_state(repository_id, tenant_id) VALUES ('{ids['repo_a_free']}', '{ids['owner_b']}')",
            REPO_STATE_OWNER_FK,
        )
        self._assert_fk_rejected(
            db_url,
            f"INSERT INTO storage_maintenance_jobs(id, repository_id, tenant_id, kind, repository_generation) "
            f"VALUES ('{uuid.uuid4()}', '{ids['repo_a']}', '{ids['owner_b']}', 'gitfs_repack', 1)",
            JOBS_OWNER_FK,
        )
        self._assert_fk_rejected(
            db_url,
            f"INSERT INTO storage_maintenance_tombstones(repository_id, tenant_id, oid, object_kind, repository_generation, delete_after) "
            f"VALUES ('{ids['repo_a']}', '{ids['owner_b']}', '{bad_oid}', 'blob', 1, clock_timestamp())",
            TOMBSTONES_OWNER_FK,
        )

    def test_dirty_schema133_preflight_refusal_rollback_and_clean_upgrade(self):
        schema, db_url = self._isolated_schema()
        self._migrate(db_url, 1, 133)
        self.assertEqual(self._sql(db_url, "SELECT max(version) FROM schema_migrations"), "133")

        ids = self._seed_two_tenants(db_url)
        legal_job, bad_job = str(uuid.uuid4()), str(uuid.uuid4())
        legal_oid, bad_oid = uuid.uuid4().hex + "1" * 8, uuid.uuid4().hex + "2" * 8
        self._psql(db_url, stdin_sql=(
            f"INSERT INTO pando_manifest_artifacts VALUES ('{ids['manifest_a']}', '{ids['repo_a']}', "
            f"'{ids['authority']}', '{ids['owner_a']}', 'pando-cipher', '{ids['sha_a']}', 'index-cipher');\n"
            f"INSERT INTO storage_maintenance_repo_state(repository_id, tenant_id) VALUES ('{ids['repo_b']}', '{ids['owner_b']}');\n"
            f"INSERT INTO storage_maintenance_jobs(id, repository_id, tenant_id, kind, state, repository_generation, completed_at) "
            f"VALUES ('{legal_job}', '{ids['repo_b']}', '{ids['owner_b']}', 'gitfs_stage_cleanup', 'failed', 1, clock_timestamp());\n"
            f"INSERT INTO storage_maintenance_tombstones(repository_id, tenant_id, oid, object_kind, repository_generation, delete_after, state) "
            f"VALUES ('{ids['repo_b']}', '{ids['owner_b']}', '{legal_oid}', 'blob', 1, clock_timestamp(), 'retained');\n"
        ))
        forbidden = (
            *ids.values(), legal_job, bad_job, legal_oid, bad_oid,
            "alice-secret-90", "bob-secret-90", "repo-alpha-90", "repo-beta-90",
            "pando-cipher", "manifest-secret-90", "job-secret-90", "tombstone-secret-90",
        )
        migration_tx = "BEGIN;\n" + MIGRATION_134.read_text() + "\nCOMMIT;\n"
        dirty_cases = (
            ((1, 0, 0, 0),
             f"INSERT INTO pando_manifest_artifacts VALUES ('{ids['manifest_a']}', '{ids['repo_a']}', '{ids['authority']}', '{ids['owner_b']}', 'pando-cipher', '{ids['sha_b']}', 'pack-cipher')",
             f"SELECT count(*) FROM pando_manifest_artifacts WHERE manifest_id='{ids['manifest_a']}' AND artifact_role='pack-cipher'",
             f"DELETE FROM pando_manifest_artifacts WHERE manifest_id='{ids['manifest_a']}' AND artifact_role='pack-cipher'"),
            ((1, 0, 0, 0),
             f"INSERT INTO pando_manifest_artifacts VALUES ('{ids['manifest_a']}', '{ids['repo_b']}', '{ids['authority']}', '{ids['owner_a']}', 'pando-cipher', '{ids['sha_a']}', 'pack-cipher')",
             f"SELECT count(*) FROM pando_manifest_artifacts WHERE manifest_id='{ids['manifest_a']}' AND artifact_role='pack-cipher'",
             f"DELETE FROM pando_manifest_artifacts WHERE manifest_id='{ids['manifest_a']}' AND artifact_role='pack-cipher'"),
            ((0, 1, 0, 0),
             f"INSERT INTO storage_maintenance_repo_state(repository_id, tenant_id) VALUES ('{ids['repo_a']}', '{ids['owner_b']}')",
             f"SELECT count(*) FROM storage_maintenance_repo_state WHERE repository_id='{ids['repo_a']}' AND tenant_id='{ids['owner_b']}'",
             f"DELETE FROM storage_maintenance_repo_state WHERE repository_id='{ids['repo_a']}'"),
            ((0, 0, 1, 0),
             f"INSERT INTO storage_maintenance_jobs(id, repository_id, tenant_id, kind, state, repository_generation, last_error, completed_at) VALUES ('{bad_job}', '{ids['repo_a']}', '{ids['owner_b']}', 'gitfs_repack', 'failed', 1, 'job-secret-90', clock_timestamp())",
             f"SELECT count(*) FROM storage_maintenance_jobs WHERE id='{bad_job}' AND tenant_id='{ids['owner_b']}'",
             f"DELETE FROM storage_maintenance_jobs WHERE id='{bad_job}'"),
            ((0, 0, 0, 1),
             f"INSERT INTO storage_maintenance_tombstones(repository_id, tenant_id, oid, object_kind, repository_generation, delete_after, state, last_error) VALUES ('{ids['repo_a']}', '{ids['owner_b']}', '{bad_oid}', 'blob', 1, clock_timestamp(), 'retained', 'tombstone-secret-90')",
             f"SELECT count(*) FROM storage_maintenance_tombstones WHERE repository_id='{ids['repo_a']}' AND oid='{bad_oid}'",
             f"DELETE FROM storage_maintenance_tombstones WHERE repository_id='{ids['repo_a']}' AND oid='{bad_oid}'"),
        )
        def assert_dirty_refused(expected_counts, verify_queries):
            proc = self._psql(db_url, stdin_sql=migration_tx, check=False)
            self.assertNotEqual(proc.returncode, 0)
            combined = proc.stdout + "\n" + proc.stderr
            self.assertIn(refusal_message(*expected_counts), combined)
            for marker in forbidden:
                self.assertNotIn(marker, combined)
            self.assertEqual(self._sql(db_url, "SELECT max(version) FROM schema_migrations"), "133")
            self.assertEqual(self._sql(db_url, "SELECT count(*) FROM schema_migrations WHERE version = 134"), "0")
            defs = self._constraints(db_url, schema)
            for fk in (*COMPOSITE_FKS, MANIFEST_UNIQUE):
                self.assertNotIn(fk, defs)
            for old_fk in REMOVED_SINGLE_COL_FKS:
                self.assertIn(old_fk, defs)
            for query in verify_queries:
                self.assertEqual(self._sql(db_url, query), "1")

        legal_queries = (
            f"SELECT count(*) FROM pando_manifest_artifacts WHERE manifest_id='{ids['manifest_a']}' AND artifact_role='index-cipher'",
            f"SELECT count(*) FROM storage_maintenance_repo_state WHERE repository_id='{ids['repo_b']}' AND tenant_id='{ids['owner_b']}'",
            f"SELECT count(*) FROM storage_maintenance_jobs WHERE id='{legal_job}' AND tenant_id='{ids['owner_b']}'",
            f"SELECT count(*) FROM storage_maintenance_tombstones WHERE repository_id='{ids['repo_b']}' AND oid='{legal_oid}'",
        )
        for counts, seed_sql, verify_sql, cleanup_sql in dirty_cases:
            self._sql(db_url, seed_sql)
            assert_dirty_refused(counts, (verify_sql, *legal_queries))
            self._sql(db_url, cleanup_sql)

        all_dirty = ";\n".join(seed_sql for _, seed_sql, _, _ in dirty_cases[1:])
        self._psql(db_url, stdin_sql=all_dirty)
        assert_dirty_refused(
            (1, 1, 1, 1),
            (*(verify_sql for _, _, verify_sql, _ in dirty_cases[1:]), *legal_queries),
        )
        self._psql(db_url, stdin_sql=";\n".join(cleanup_sql for _, _, _, cleanup_sql in dirty_cases[1:]))

        self._psql(db_url, stdin_sql=migration_tx)
        self.assertEqual(self._sql(db_url, "SELECT max(version) FROM schema_migrations"), "134")
        self._assert_schema134_constraints(db_url, schema)
        self._migrate(db_url, 135, schema_baseline.LATEST_VERSION)
        installed = [int(v) for v in self._sql(db_url, "SELECT version FROM schema_migrations ORDER BY version").splitlines()]
        self.assertEqual(installed, schema_baseline.SCHEMA_VERSIONS)
        self.assertEqual(self._sql(db_url, f"SELECT count(*) FROM pando_manifest_artifacts WHERE manifest_id='{ids['manifest_a']}' AND artifact_role='index-cipher'"), "1")
        self.assertEqual(self._sql(db_url, f"SELECT count(*) FROM storage_maintenance_repo_state WHERE repository_id='{ids['repo_b']}'"), "1")
        self.assertEqual(self._sql(db_url, f"SELECT count(*) FROM storage_maintenance_jobs WHERE id='{legal_job}'"), "1")
        self.assertEqual(self._sql(db_url, f"SELECT count(*) FROM storage_maintenance_tombstones WHERE oid='{legal_oid}'"), "1")


if __name__ == "__main__":
    unittest.main()
