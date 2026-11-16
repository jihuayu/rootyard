#!/usr/bin/env python3
"""Offline regressions for #107 commit-unknown blocker database ownership.

These tests exercise the real ``CheckpointHarness._register_owned_blocker`` and
``_register_owned_blocker_or_reap`` methods without starting PostgreSQL, the
service, psql, or any network path. SQL answers are synthesized on a minimal
harness; reaping uses only short, locally owned Python children.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from blob_commit_unknown_service import CheckpointHarness  # noqa: E402

APPLICATION_NAME = "rootyard-commit-gate-offline"
PID = 4242
BACKEND_START = "2026-11-16 00:00:00+00"

# Synthetic complete DSNs only: no real credentials or passwords. Every DSN
# carries a search_path query, so self.db is never a bare database name.
DSN_DEFAULT = (
    "postgresql://fixture@127.0.0.1:1/rootyard_test"
    "?options=-csearch_path%3Drootyard_fixture"
)
DSN_ESCAPED = (
    "postgresql://fixture@127.0.0.1:1/rootyard%2Fescaped"
    "?options=-csearch_path%3Drootyard_fixture"
)
DSN_QUERY_OVERRIDE = (
    "postgresql://fixture@127.0.0.1:1/url_path_db"
    "?dbname=actual_query_db&options=-csearch_path%3Drootyard_fixture"
)


class FakeSQL:
    """Only the two queries the ownership helper is allowed to issue."""

    def __init__(self, rows, current_database):
        self.rows = rows
        self.current_database = current_database
        self.calls = []

    def __call__(self, query, isolated=True):
        self.calls.append(query)
        if query == "SELECT current_database()":
            return self.current_database
        if "FROM pg_stat_activity" in query and "jsonb_agg" in query:
            return json.dumps(self.rows)
        raise AssertionError("offline ownership test issued an unexpected SQL query")


class LiveProcess:
    """Minimal live process stand-in for the positive registration path."""

    def __init__(self):
        self._rootyard_blocker_identity = None

    def poll(self):
        return None


class ExitedProcess:
    def poll(self):
        return 1


class ReapedProcess:
    """Already-exited local child stand-in for the release path."""

    def __init__(self, identity):
        self._rootyard_blocker_identity = identity
        self.stdout = None
        self.stderr = None
        self.communicated = False

    def poll(self):
        return -15

    def communicate(self, timeout=None):
        self.communicated = True
        return b"", b""


class ReleaseFakeSQL:
    """Synthetic answers for the release path; no PG connection is opened."""

    def __init__(self, before_rows, after_rows=None, lock_count="0", termination="1"):
        self.before_rows = before_rows
        self.after_rows = [] if after_rows is None else after_rows
        self.lock_count = lock_count
        self.termination = termination
        self.owned_calls = 0
        self.lock_calls = 0
        self.terminations = []
        self.queries = []

    def __call__(self, query, isolated=True):
        self.queries.append(query)
        if "pg_terminate_backend" in query:
            self.terminations.append(query)
            return self.termination
        if "FROM pg_locks" in query:
            self.lock_calls += 1
            return self.lock_count
        if "jsonb_agg" in query:
            self.owned_calls += 1
            return json.dumps(self.before_rows if self.owned_calls == 1 else self.after_rows)
        raise AssertionError("offline release test issued an unexpected SQL query")


def release_identity(application_name=APPLICATION_NAME, database="owned_db",
                     pid=PID, backend_start=BACKEND_START):
    return {
        "application_name": application_name,
        "database": database,
        "pid": pid,
        "backend_start": backend_start,
    }


def row(database, pid=PID, backend_start=BACKEND_START):
    return {"pid": pid, "database": database, "backend_start": backend_start}


def harness(db, rows, current_database):
    fixture = object.__new__(CheckpointHarness)
    fixture.db = db
    fixture.sql = FakeSQL(rows, current_database)
    return fixture


def spawn_sleeper():
    """A real, short, locally owned Python child; never a psql or PG client."""
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def stop_child(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
    for stream in (child.stdout, child.stderr):
        if stream is not None:
            stream.close()


class BlockerDatabaseIdentityTest(unittest.TestCase):
    def test_complete_dsns_accept_the_connection_current_database_name(self):
        cases = (
            (DSN_DEFAULT, "rootyard_test"),
            (DSN_ESCAPED, "rootyard/escaped"),
            (DSN_QUERY_OVERRIDE, "actual_query_db"),
        )
        for dsn, current_database in cases:
            with self.subTest(current_database=current_database):
                fixture = harness(dsn, [row(current_database)], current_database)
                process = LiveProcess()
                identity = fixture._register_owned_blocker(process, APPLICATION_NAME)
                self.assertEqual(identity["database"], current_database)
                self.assertNotEqual(identity["database"], fixture.db)
                self.assertEqual(identity["application_name"], APPLICATION_NAME)
                self.assertEqual(identity["pid"], PID)
                self.assertEqual(identity["backend_start"], BACKEND_START)
                self.assertEqual(process._rootyard_blocker_identity, identity)
                self.assertIn("SELECT current_database()", fixture.sql.calls)

    def test_foreign_database_is_refused_and_only_the_owned_child_is_reaped(self):
        owned = spawn_sleeper()
        foreign = spawn_sleeper()
        try:
            fixture = harness(DSN_QUERY_OVERRIDE, [row("foreign_db")], "actual_query_db")
            with self.assertRaisesRegex(
                    AssertionError, "fixture blocker backend database is not owned"):
                fixture._register_owned_blocker_or_reap(owned, APPLICATION_NAME)
            self.assertIsNotNone(owned.poll(), "the rejected owned blocker child was not reaped")
            self.assertIsNone(foreign.poll(), "an unrelated child was reaped on registration failure")
            self.assertIsNone(getattr(owned, "_rootyard_blocker_identity", None))
        finally:
            stop_child(owned)
            stop_child(foreign)

    def test_remaining_identity_checks_still_reject_bad_rows(self):
        cases = (
            ("rootyard-commit-gate-bad!", [row("owned_db")],
             "application_name has unsafe characters"),
            (APPLICATION_NAME, [row("owned_db", pid=0)], "backend pid is invalid"),
            (APPLICATION_NAME, [row("owned_db", backend_start="")], "backend_start is missing"),
            (APPLICATION_NAME, [row("owned_db", backend_start="x';DROP")],
             "backend_start is not SQL-safe"),
            (APPLICATION_NAME, [row("owned_db"), row("owned_db")], "not a single backend"),
        )
        for application_name, rows, message in cases:
            with self.subTest(message=message):
                fixture = harness(DSN_ESCAPED, rows, "owned_db")
                with self.assertRaisesRegex(AssertionError, message):
                    fixture._register_owned_blocker(LiveProcess(), application_name)

        fixture = harness(DSN_ESCAPED, [row("owned_db")], "owned_db")
        with self.assertRaisesRegex(AssertionError, "child exited before ownership registration"):
            fixture._register_owned_blocker(ExitedProcess(), APPLICATION_NAME)


class BlockerReleaseTest(unittest.TestCase):
    def test_exact_owned_backend_is_terminated_only_after_identity_accept(self):
        identity = release_identity()
        sql = ReleaseFakeSQL([row(identity["database"])], after_rows=[], lock_count="0")
        fixture = object.__new__(CheckpointHarness)
        fixture.sql = sql
        process = ReapedProcess(identity)

        self.assertIsNone(fixture._release_blocker(process))
        self.assertTrue(process.communicated)
        self.assertEqual(len(sql.terminations), 1)
        query = sql.terminations[0]
        self.assertEqual(sql.queries.index(query), 1)
        self.assertTrue(query.startswith("WITH owned AS MATERIALIZED ("))
        for predicate in (
                "a.application_name='" + identity["application_name"] + "'",
                "a.datname=current_database()",
                "a.pid=" + str(identity["pid"]),
                "a.backend_start::text='" + identity["backend_start"] + "'",
                "a.pid<>pg_backend_pid()",
        ):
            self.assertIn(predicate, query)
        self.assertIn("SELECT count(*) FROM owned WHERE pg_terminate_backend(owned.pid)", query)
        self.assertEqual(sql.owned_calls, 2)
        self.assertEqual(sql.lock_calls, 1)
        self.assertFalse(any("pg_terminate_backend" in item for item in sql.queries[2:]))

    def test_foreign_identity_fields_refuse_without_termination(self):
        cases = (
            ("database", release_identity(database="foreign_db"), [row("owned_db")]),
            ("backend_start", release_identity(), [row("owned_db", backend_start="other")]),
            ("pid", release_identity(), [row("owned_db", pid=PID + 1)]),
        )
        for field, identity, rows in cases:
            with self.subTest(field=field):
                sql = ReleaseFakeSQL(rows)
                fixture = object.__new__(CheckpointHarness)
                fixture.sql = sql
                with self.assertRaisesRegex(AssertionError, "refusing foreign termination"):
                    fixture._release_blocker(ReapedProcess(identity))
                self.assertEqual(sql.terminations, [])
                self.assertEqual(sql.owned_calls, 1)
                self.assertEqual(sql.lock_calls, 0)

    def test_foreign_application_name_and_absent_backend_probe_lock_without_termination(self):
        cases = (
            ("foreign_application_name",
             release_identity(application_name="rootyard-commit-gate-foreign"), []),
            ("absent_backend", release_identity(), []),
        )
        for label, identity, rows in cases:
            with self.subTest(case=label):
                sql = ReleaseFakeSQL(rows, lock_count="0")
                fixture = object.__new__(CheckpointHarness)
                fixture.sql = sql
                self.assertIsNone(fixture._release_blocker(ReapedProcess(identity)))
                self.assertEqual(sql.terminations, [])
                self.assertEqual(sql.owned_calls, 1)
                self.assertEqual(sql.lock_calls, 1)
                self.assertIn("a.application_name='" + identity["application_name"] + "'",
                              sql.queries[0])


if __name__ == "__main__":
    unittest.main()
