#!/usr/bin/env python3
"""Pure ownership tests for the owned local PostgreSQL fixture.

No PostgreSQL, psql, Git, Cargo, Vault, Docker or real child process is used.
The approved helpers run against an in-memory SQL transition probe and a
temporary private root only.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import pando_producer_pg.process as process  # noqa: E402
import pando_producer_pg.resources as resources  # noqa: E402
from pando_vault_rotation_fixture import FixtureError  # noqa: E402


class FakeRootRemover:
    """Hermetic stand-in for the bounded child root remover."""

    def __init__(self):
        self.calls = []

    def remove(self, root, deadline):
        self.calls.append((root, deadline))
        root.remove()
        return {
            "removed": bool(root.removed),
            "absent": bool(root.removed),
            "verified": bool(root.removed),
            "code": None,
            "within_deadline": True,
        }


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class PgFake:
    def __init__(self, database, create_mode="ok", validate_fail=False):
        self.database = database
        self.create_mode = create_mode
        self.validate_fail = validate_fail
        self.exists = False
        self.identity = {"oid": "16384", "datdba": "10", "database": database}
        self.calls = []
        self.drop_sqls = []
        self.schema_ok = True

    def run(self, argv, **kwargs):
        sql = (kwargs.get("input") or b"").decode(errors="replace")
        self.calls.append(([str(item) for item in argv], dict(kwargs), sql))
        if "SHOW server_version_num" in sql:
            if self.validate_fail:
                return Result(1, b"")
            return Result(0, b"170004\n")
        if "oid::text" in sql and "FROM pg_database" in sql:
            if not self.exists:
                return Result(0, b"")
            value = self.identity
            return Result(0, ("%s|%s|%s|10\n" % (
                value["oid"], value["datdba"], value["database"])).encode())
        if "FROM pg_database" in sql:
            return Result(0, (("1" if self.exists else "") + "\n").encode())
        if sql.startswith("CREATE DATABASE"):
            if self.create_mode == "ok":
                self.exists = True
                return Result(0, b"")
            if self.create_mode == "unknown":
                raise FixtureError("process_failed")
            if self.create_mode == "group_unverified":
                raise process.RunnerError(
                    "setup",
                    "process_group_unverified",
                    primary_code="process_timeout",
                )
            self.exists = True
            self.identity = {"oid": "999", "datdba": "10", "database": self.database}
            return Result(1, b"")
        if sql.startswith("DROP DATABASE"):
            self.drop_sqls.append(sql)
            self.exists = False
            return Result(0, b"")
        if sql.startswith("CREATE SCHEMA") and not self.schema_ok:
            return Result(1, b"")
        return Result(0, b"")


class PgFactory:
    def __init__(
        self, create_mode="ok", schema_ok=True, validate_fail=False, bounded=False
    ):
        self.create_mode = create_mode
        self.schema_ok = schema_ok
        self.validate_fail = validate_fail
        self.bounded = bounded
        self.pg = None
        self.fake = None

    def __call__(self, dsn, nonce, runner):
        factory = (
            resources.BoundedOwnedPostgres
            if self.bounded
            else resources.OwnedPostgres
        )
        pg = factory(dsn, nonce=nonce, runner=runner)
        fake = PgFake(pg.database, self.create_mode, self.validate_fail)
        fake.schema_ok = self.schema_ok
        pg.runner = fake
        self.pg = pg
        self.fake = fake
        return pg


BOOTSTRAP = "postgresql://user:password@127.0.0.1:55432/bootstrap"


class OwnedFixtureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        schema = self.root / resources.SCHEMA_REL
        schema.parent.mkdir(parents=True)
        self.schema = b"CREATE SCHEMA IF NOT EXISTS pando_lab;\n"
        schema.write_bytes(self.schema)
        self.sha = hashlib.sha256(self.schema).hexdigest()
        self.base = Path(self.tmp.name) / "owned"
        self.base.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def fixture(self, factory=None):
        return resources.OwnedFixture(
            self.root,
            BOOTSTRAP,
            {},
            process.ProcessRunner(popen=lambda *a, **k: None),
            schema_sha256=self.sha,
            postgres_factory=factory or PgFactory(),
            root_factory=lambda: resources.OwnedRoot(base=self.base),
            root_remover=FakeRootRemover(),
        )

    def test_schema_goes_to_owned_database_only(self):
        factory = PgFactory()
        fixture = self.fixture(factory)
        fixture.start(deadline=1e18)
        pg = factory.pg
        self.assertEqual(pg.environment["PGDATABASE"], "bootstrap")
        schema_calls = [call for call in factory.fake.calls if call[2].startswith("CREATE SCHEMA")]
        self.assertEqual(len(schema_calls), 1)
        argv, kwargs, sql = schema_calls[0]
        self.assertEqual(argv[0], "psql")
        self.assertIn("-f", argv)
        self.assertEqual(kwargs["input"], self.schema)
        self.assertEqual(kwargs["env"]["PGDATABASE"], pg.database)
        self.assertNotIn("bootstrap", " ".join(argv))
        child = fixture.child_environment
        self.assertEqual(child["ROOTYARD_TEST_DATABASE_URL"], pg.child_dsn())
        self.assertEqual(child["TMPDIR"], str(fixture.root_path))
        for name in resources.ESCAPE_VARIABLES:
            self.assertNotIn(name, child)
        cleanup = fixture.cleanup(1e18)
        self.assertTrue(cleanup["cleanup_ok"])
        self.assertEqual(len(factory.fake.drop_sqls), 1)
        self.assertFalse(Path(fixture.root_path).exists())
        self.assertTrue(cleanup["postgres"]["dropped"])
        self.assertTrue(cleanup["root"]["removed"])
        self.assertTrue(cleanup["postgres_cleanup_verified"])
        self.assertTrue(cleanup["root_cleanup_verified"])
        self.assertTrue(cleanup["cleanup_verified"])

    def test_escape_variable_presence_fails_before_effects(self):
        factory = PgFactory()
        fixture = resources.OwnedFixture(
            self.root, BOOTSTRAP, {"PANDO_KMS_PROVIDER": ""},
            process.ProcessRunner(popen=lambda *a, **k: None),
            schema_sha256=self.sha, postgres_factory=factory,
            root_factory=lambda: resources.OwnedRoot(base=self.base),
        )
        with self.assertRaises(process.RunnerError) as caught:
            fixture.start(deadline=1e18)
        self.assertEqual(caught.exception.code, "escape_variable_present")
        self.assertIsNone(factory.pg)
        self.assertIsNone(fixture.root)

    def test_partial_schema_startup_remains_cleanable(self):
        factory = PgFactory(schema_ok=False)
        fixture = self.fixture(factory)
        with self.assertRaises(process.RunnerError) as caught:
            fixture.start(deadline=1e18)
        self.assertEqual(caught.exception.code, "schema_init_failed")
        self.assertTrue(factory.pg.created)
        cleanup = fixture.cleanup(1e18)
        self.assertTrue(cleanup["cleanup_ok"])
        self.assertEqual(len(factory.fake.drop_sqls), 1)
        self.assertFalse(Path(fixture.root_path).exists())
        self.assertTrue(cleanup["postgres"]["dropped"])
        self.assertTrue(cleanup["root"]["removed"])
        self.assertTrue(cleanup["postgres_cleanup_verified"])
        self.assertTrue(cleanup["root_cleanup_verified"])
        self.assertTrue(cleanup["cleanup_verified"])

    def test_unknown_create_outcome_never_drops(self):
        factory = PgFactory("unknown")
        fixture = self.fixture(factory)
        with self.assertRaises(process.RunnerError) as caught:
            fixture.start(deadline=1e18)
        self.assertEqual(caught.exception.code, "postgres_create_unknown")
        cleanup = fixture.cleanup(1e18)
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertEqual(cleanup["error_code"], "postgres_create_outcome_unknown")
        self.assertEqual(factory.fake.drop_sqls, [])
        self.assertTrue(cleanup["root_removed"])
        self.assertFalse(cleanup["postgres"]["dropped"])
        self.assertTrue(cleanup["root"]["removed"])
        self.assertFalse(cleanup["postgres_cleanup_verified"])
        self.assertTrue(cleanup["root_cleanup_verified"])

    def test_group_unverified_create_is_unknown_and_never_drops(self):
        factory = PgFactory("group_unverified", bounded=True)
        fixture = self.fixture(factory)
        with self.assertRaises(process.RunnerError) as caught:
            fixture.start(deadline=1e18)
        self.assertEqual(caught.exception.code, "postgres_create_unknown")
        self.assertEqual(fixture.postgres.creation_outcome, "unknown")
        cleanup = fixture.cleanup(1e18)
        self.assertFalse(cleanup["database_absent"])
        self.assertFalse(cleanup["postgres_dropped"])
        self.assertEqual(
            cleanup["error_code"], "postgres_create_outcome_unknown"
        )
        self.assertEqual(factory.fake.drop_sqls, [])

    def test_rejected_create_race_never_claims_absent_or_drops(self):
        factory = PgFactory("reject")
        fixture = self.fixture(factory)
        with self.assertRaises(process.RunnerError) as caught:
            fixture.start(deadline=1e18)
        self.assertEqual(caught.exception.code, "postgres_create_failed")
        cleanup = fixture.cleanup(1e18)
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertFalse(cleanup["database_absent"])
        self.assertEqual(cleanup["error_code"], "cleanup_unresolved")
        self.assertEqual(factory.fake.drop_sqls, [])
        self.assertTrue(cleanup["root_removed"])
        self.assertFalse(cleanup["postgres"]["dropped"])
        self.assertTrue(cleanup["root"]["removed"])

    def test_completed_absence_precheck_can_claim_absence(self):
        fixture = self.fixture()
        fixture.root = resources.OwnedRoot(base=self.base)
        fixture.root.create()
        pg = resources.OwnedPostgres(
            BOOTSTRAP,
            nonce=fixture.root.nonce,
            runner=process.ProcessRunner(popen=lambda *a, **k: None),
        )
        pg.major = 17
        pg.prechecked_absent = True
        fixture.postgres = pg
        cleanup = fixture.cleanup(1e18)
        self.assertFalse(cleanup["postgres_dropped"])
        self.assertTrue(cleanup["database_absent"])
        self.assertTrue(cleanup["postgres_cleanup_verified"])
        self.assertTrue(cleanup["root"]["removed"])
        self.assertFalse(cleanup["postgres"]["dropped"])
        self.assertTrue(cleanup["cleanup_ok"])
        self.assertNotIn("error_code", cleanup)

    def test_nested_record_refresh_failure_is_unresolved(self):
        factory = PgFactory()
        fixture = self.fixture(factory)
        fixture.start(deadline=1e18)
        with mock.patch.object(
            fixture.postgres,
            "safe_record",
            side_effect=RuntimeError("secret /tmp/path"),
        ):
            cleanup = fixture.cleanup(1e18)
        self.assertFalse(cleanup["cleanup_verified"])
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertEqual(cleanup["error_code"], "cleanup_unresolved")
        self.assertEqual(cleanup["postgres"], {})
        self.assertNotIn("secret", str(cleanup))

    def test_validation_failure_before_precheck_is_not_absence(self):
        factory = PgFactory(validate_fail=True)
        fixture = self.fixture(factory)
        with self.assertRaises(process.RunnerError) as caught:
            fixture.start(deadline=1e18)
        self.assertEqual(caught.exception.code, "postgres_validate_failed")
        self.assertIsNone(factory.pg.major)
        self.assertFalse(factory.pg.prechecked_absent)
        cleanup = fixture.cleanup(1e18)
        self.assertFalse(cleanup["postgres_dropped"])
        self.assertFalse(cleanup["database_absent"])
        self.assertFalse(cleanup["postgres_cleanup_verified"])
        self.assertFalse(cleanup["cleanup_verified"])
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertEqual(cleanup["error_code"], "cleanup_unresolved")
        self.assertFalse(cleanup["postgres"]["dropped"])
        self.assertTrue(cleanup["root"]["removed"])
        self.assertTrue(cleanup["root_removed"])

    def test_changed_database_identity_is_unresolved(self):
        factory = PgFactory()
        fixture = self.fixture(factory)
        fixture.start(deadline=1e18)
        factory.fake.identity = {"oid": "999", "datdba": "10",
                                 "database": factory.pg.database}
        cleanup = fixture.cleanup(1e18)
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertEqual(cleanup["error_code"], "postgres_drop_unverified")
        self.assertEqual(factory.fake.drop_sqls, [])
        self.assertTrue(cleanup["root_removed"])

    def test_cleanup_deadline_never_claims_success(self):
        factory = PgFactory()
        fixture = self.fixture(factory)
        fixture.start(deadline=1e18)
        cleanup = fixture.cleanup(deadline=-1)
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertEqual(cleanup["error_code"], "cleanup_deadline_exceeded")
        self.assertEqual(factory.fake.drop_sqls, [])
        self.assertTrue(Path(fixture.root_path).exists())
        self.assertFalse(cleanup["postgres"]["dropped"])
        self.assertFalse(cleanup["root"]["removed"])
        fixture.cleanup(1e18)

    def test_unresolved_root_removal_fails_cleanup(self):
        factory = PgFactory()
        fixture = self.fixture(factory)
        fixture.start(deadline=1e18)
        with mock.patch.object(
            fixture.root, "remove", side_effect=FixtureError("root_identity_mismatch")
        ):
            cleanup = fixture.cleanup(1e18)
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertEqual(cleanup["error_code"], "root_remove_failed")
        self.assertFalse(cleanup["root_removed"])

    def test_child_environment_is_filtered_without_global_mutation(self):
        base = {
            "KEEP": "1",
            "PANDO_OBJECT_STORE_ROOT": "x",
            "PANDO_KMS_KEYRING_DIR": "x",
            "PANDO_KMS_PROVIDER": "x",
            "ROOTYARD_OBJECT_STORE_ENDPOINT": "x",
        }
        pg = SimpleNamespace(child_dsn=lambda: "postgresql://owned@127.0.0.1/db")
        child = resources.build_child_environment(base, pg, self.base)
        self.assertEqual(base["PANDO_KMS_PROVIDER"], "x")
        self.assertEqual(child["KEEP"], "1")
        self.assertEqual(child["TMPDIR"], str(self.base.resolve()))
        for name in resources.ESCAPE_VARIABLES:
            self.assertNotIn(name, child)
        self.assertNotIn("password", child["ROOTYARD_TEST_DATABASE_URL"])

    def test_failure_text_does_not_expose_bootstrap_dsn(self):
        factory = PgFactory("unknown")
        fixture = self.fixture(factory)
        with self.assertRaises(process.RunnerError) as caught:
            fixture.start(deadline=1e18)
        self.assertNotIn("password", str(caught.exception))
        self.assertNotIn(BOOTSTRAP, str(caught.exception))
        fixture.cleanup(1e18)


if __name__ == "__main__":
    unittest.main()
