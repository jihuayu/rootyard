#!/usr/bin/env python3
"""Pure ownership counterexamples for PG, private root and stock Git.

These tests use injected runners and temporary filesystem objects only.  They
start no PostgreSQL, Docker, Vault, HTTP, Git or other subprocess and perform no
SQL.  The PostgreSQL fake models preflight/ack/identity/foreign-race outcomes;
the root tests use real mkdtemp/chmod/stat on a private temporary base; the Git
tests inspect the filtered environment passed to a fake runner.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from pando_vault_rotation_fixture import FixtureError  # noqa: E402
import pando_vault_rotation_fixture_resources as resources  # noqa: E402


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def database_from_sql(sql):
    marker = "datname='"
    if marker in sql:
        return sql.split(marker, 1)[1].split("'", 1)[0]
    marker = 'CREATE DATABASE "'
    if marker in sql:
        return sql.split(marker, 1)[1].split('"', 1)[0]
    return None


class PgFake:
    """No SQL is executed; each branch models one ownership transition."""

    def __init__(self, database, create_mode="ok"):
        self.database = database
        self.create_mode = create_mode
        self.exists = False
        self.identity = {"oid": "16384", "datdba": "10",
                         "database": database}
        self.calls = []
        self.drop_sqls = []

    def run(self, argv, **kwargs):
        sql = (kwargs.get("input") or b"").decode()
        self.calls.append(([str(item) for item in argv], kwargs, sql))
        if "SHOW server_version_num" in sql:
            return Result(0, b"170004\n")
        if "oid::text" in sql and "FROM pg_database" in sql:
            if not self.exists or self.identity is None:
                return Result(0, b"")
            value = self.identity
            return Result(0, ("%s|%s|%s|10\n" % (
                value["oid"], value["datdba"], value["database"])).encode())
        if "FROM pg_database" in sql:
            return Result(0, (("1" if self.exists else "") + "\n").encode())
        if sql.startswith('CREATE DATABASE'):
            if self.create_mode == "ok":
                self.exists = True
                self.identity = {"oid": "16384", "datdba": "10",
                                 "database": self.database}
                return Result(0, b"")
            if self.create_mode == "reject":
                # A foreign actor won the race after the absence preflight.
                self.exists = True
                self.identity = {"oid": "999", "datdba": "10",
                                 "database": self.database}
                return Result(1, b"")
            if self.create_mode == "timeout":
                raise FixtureError("process_failed")
        if sql.startswith('DROP DATABASE'):
            self.drop_sqls.append(sql)
            self.exists = False
            return Result(0, b"")
        return Result(0, b"")


def make_pg(create_mode="ok"):
    pg = resources.OwnedPostgres(
        "postgresql://user:password@127.0.0.1:55432/admin",
        nonce="a" * 12)
    fake = PgFake(pg.database, create_mode=create_mode)
    pg.runner = fake
    return pg, fake


class PostgresOwnershipStateTest(unittest.TestCase):
    def test_preflight_absent_alone_never_authorizes_drop(self):
        pg, fake = make_pg()
        pg.prechecked_absent = True
        with self.assertRaises(FixtureError) as caught:
            pg.drop()
        self.assertEqual(caught.exception.code, "pg_drop_not_owned")
        self.assertEqual(fake.drop_sqls, [])

    def test_foreign_race_after_preflight_never_drops_foreign_database(self):
        pg, fake = make_pg("reject")
        with self.assertRaises(FixtureError) as caught:
            pg.create()
        self.assertEqual(caught.exception.code, "pg_command_failed")
        self.assertFalse(pg.owned)
        self.assertFalse(pg.create_acknowledged)
        self.assertEqual(pg.creation_outcome, "rejected")
        self.assertTrue(pg.prechecked_absent)
        with self.assertRaises(FixtureError) as caught:
            pg.drop()
        self.assertEqual(caught.exception.code, "pg_drop_not_owned")
        self.assertEqual(fake.drop_sqls, [])
        self.assertTrue(fake.exists)

    def test_unknown_create_outcome_is_unresolved_without_blind_drop(self):
        pg, fake = make_pg("timeout")
        with self.assertRaises(FixtureError) as caught:
            pg.create()
        self.assertEqual(caught.exception.code, "process_failed")
        self.assertEqual(pg.creation_outcome, "unknown")
        self.assertFalse(pg.owned)
        with self.assertRaises(FixtureError) as caught:
            pg.drop()
        self.assertEqual(caught.exception.code, "pg_create_outcome_unknown")
        self.assertEqual(fake.drop_sqls, [])

    def test_created_then_post_setup_failure_retains_owned_cleanup(self):
        pg, fake = make_pg()
        with mock.patch.object(
                pg, "_post_create_setup",
                side_effect=FixtureError("pg_post_create_failed")):
            with self.assertRaises(FixtureError) as caught:
                pg.create()
        self.assertEqual(caught.exception.code, "pg_post_create_failed")
        self.assertTrue(pg.create_acknowledged)
        self.assertTrue(pg.owned)
        self.assertIsNotNone(pg.identity)
        self.assertFalse(pg.created)
        self.assertTrue(pg.drop())
        self.assertEqual(len(fake.drop_sqls), 1)
        self.assertIn(pg.database, fake.drop_sqls[0])
        self.assertFalse(fake.exists)

    def test_create_ack_without_identity_is_unresolved_without_drop(self):
        pg, fake = make_pg()
        with mock.patch.object(
                pg, "_capture_identity",
                side_effect=FixtureError("pg_database_identity_unreadable")):
            with self.assertRaises(FixtureError):
                pg.create()
        self.assertTrue(pg.create_acknowledged)
        self.assertTrue(pg.owned)
        self.assertIsNone(pg.identity)
        with self.assertRaises(FixtureError) as caught:
            pg.drop()
        self.assertEqual(caught.exception.code, "pg_cleanup_identity_unresolved")
        self.assertEqual(fake.drop_sqls, [])

    def test_identity_replacement_blocks_drop(self):
        pg, fake = make_pg()
        pg.create()
        fake.identity["oid"] = "999"
        with self.assertRaises(FixtureError) as caught:
            pg.drop()
        self.assertEqual(caught.exception.code, "pg_drop_identity_mismatch")
        self.assertEqual(fake.drop_sqls, [])

    def test_normal_create_captures_identity_and_drops_exact_database(self):
        pg, fake = make_pg()
        dsn = pg.create()
        self.assertIn(pg.database, dsn)
        self.assertTrue(pg.created)
        self.assertEqual(pg.identity["oid"], "16384")
        self.assertTrue(pg.drop())
        self.assertEqual(len(fake.drop_sqls), 1)
        self.assertIn(pg.database, fake.drop_sqls[0])
        self.assertIn("WITH (FORCE)", fake.drop_sqls[0])
        self.assertFalse(fake.exists)


if __name__ == "__main__":
    unittest.main()


class RootCreationOwnershipTest(unittest.TestCase):
    def test_chmod_failure_registers_exact_root_and_cleanup_removes_it(self):
        with tempfile.TemporaryDirectory() as base:
            root = resources.OwnedRoot(nonce="b" * 12, base=base)
            with mock.patch.object(Path, "chmod", side_effect=OSError("denied")):
                with self.assertRaises(FixtureError) as caught:
                    root.create()
            self.assertEqual(caught.exception.code, "root_post_create_failed")
            self.assertTrue(root.created)
            self.assertTrue(root.ownership_verified)
            self.assertIsNotNone(root.creation_proof)
            self.assertTrue(root.path.exists())
            self.assertTrue(root.remove())
            self.assertFalse(root.path.exists())
            self.assertTrue(root.safe_record()["removed"])

    def test_stat_failure_retains_path_and_cleanup_does_not_pretend_absent(self):
        with tempfile.TemporaryDirectory() as base:
            root = resources.OwnedRoot(nonce="c" * 12, base=base)
            with mock.patch.object(Path, "stat", side_effect=OSError("denied")):
                with self.assertRaises(FixtureError) as caught:
                    root.create()
            self.assertEqual(caught.exception.code, "root_ownership_unverified")
            self.assertTrue(root.created)
            self.assertFalse(root.ownership_verified)
            self.assertTrue(root.path.exists())
            self.assertFalse(root.safe_record()["removed"])
            self.assertTrue(root.remove())
            self.assertFalse(root.path.exists())

    def test_permission_verification_failure_keeps_registered_root(self):
        with tempfile.TemporaryDirectory() as base:
            root = resources.OwnedRoot(nonce="d" * 12, base=base)
            with mock.patch.object(resources.stat, "S_IMODE", return_value=0o755):
                with self.assertRaises(FixtureError) as caught:
                    root.create()
            self.assertEqual(caught.exception.code, "root_permissions_invalid")
            self.assertTrue(root.created)
            self.assertFalse(root.private_permissions)
            self.assertTrue(root.path.exists())
            self.assertTrue(root.remove())
            self.assertFalse(root.path.exists())

    def test_mkdtemp_without_ack_never_pretends_owned(self):
        with tempfile.TemporaryDirectory() as base:
            root = resources.OwnedRoot(nonce="e" * 12, base=base)
            with mock.patch.object(
                    resources.tempfile, "mkdtemp",
                    side_effect=OSError("unavailable")):
                with self.assertRaises(FixtureError) as caught:
                    root.create()
            self.assertEqual(caught.exception.code, "root_create_failed")
            self.assertFalse(root.created)
            self.assertIsNone(root.path)
            self.assertTrue(root.remove())
            self.assertTrue(root.removed)

    def test_inode_replacement_is_refused_not_deleted(self):
        with tempfile.TemporaryDirectory() as base:
            root = resources.OwnedRoot(nonce="f" * 12, base=base)
            path = root.create()
            backup = Path(base) / "owned-backup"
            path.rename(backup)
            replacement = Path(path)
            replacement.mkdir()
            with self.assertRaises(FixtureError) as caught:
                root.remove()
            self.assertEqual(caught.exception.code, "root_identity_mismatch")
            self.assertTrue(replacement.exists())
            shutil.rmtree(replacement)
            backup.rename(path)
            self.assertTrue(root.remove())
            self.assertFalse(path.exists())

    def test_private_mode_owner_and_creation_proof_are_recorded(self):
        with tempfile.TemporaryDirectory() as base:
            root = resources.OwnedRoot(nonce="a" * 12, base=base)
            path = root.create()
            self.assertEqual(stat_mode(path), 0o700)
            self.assertEqual(root.creation_proof["st_uid"], os.getuid())
            self.assertIn("st_dev", root.creation_proof)
            self.assertIn("st_ino", root.creation_proof)
            self.assertTrue(root.safe_record()["creation_proof_recorded"])
            self.assertTrue(root.safe_record()["private_permissions"])
            self.assertTrue(root.remove())


def stat_mode(path):
    return Path(path).stat().st_mode & 0o777
