#!/usr/bin/env python3
"""Pure deadline and resource-truth regressions for the producer PG runner.

No PostgreSQL, psql, Cargo, compiler, Git, Vault, Docker, network or real child
process is used.  Time is a fake monotonic clock, psql is an in-memory SQL probe
and the bounded root remover runs against a temporary private directory only.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import pando_producer_pg.cases as cases  # noqa: E402
import pando_producer_pg.process as process  # noqa: E402
import pando_producer_pg.resources as resources  # noqa: E402
import pando_producer_pg.root_cleanup as root_cleanup  # noqa: E402
import run_pando_producer_pg as runner  # noqa: E402
from pando_producer_pg.errors import RunnerError  # noqa: E402
from pando_producer_pg.process import Completed  # noqa: E402
from test_pando_producer_pg_process import (  # noqa: E402
    FakeThread,
    GroupKiller,
    StreamingPopen,
)

BOOTSTRAP = "postgresql://user:password@127.0.0.1:55432/bootstrap"
BINARY = "/tmp/owned/target/debug/deps/rootyard_pando_lab-abc"


class FakeClock:
    def __init__(self, now=0.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)

    def set(self, value):
        self.now = float(value)


class StepClock:
    def __init__(self, step=10.0):
        self.now = 0.0
        self.step = float(step)

    def __call__(self):
        self.now += self.step
        return self.now


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class ClockProbe:
    """psql probe that can consume exactly the timeout it was given."""

    def __init__(self, database, clock, create_mode="ok"):
        self.database = database
        self.clock = clock
        self.create_mode = create_mode
        self.advance = False
        self.exists = False
        self.identity = {"oid": "16384", "datdba": "10", "database": database}
        self.calls = []
        self.drop_sqls = []

    def run(self, argv, **kwargs):
        timeout = kwargs.get("timeout")
        sql = (kwargs.get("input") or b"").decode(errors="replace")
        self.calls.append({
            "argv": [str(item) for item in argv],
            "timeout": timeout,
            "sql": sql,
        })
        if self.advance and isinstance(timeout, (int, float)):
            self.clock.advance(timeout)
        if "SHOW server_version_num" in sql:
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
            if self.create_mode == "runner_timeout":
                raise RunnerError("setup", "process_timeout")
            self.exists = True
            return Result(0, b"")
        if sql.startswith("DROP DATABASE"):
            self.drop_sqls.append(sql)
            self.exists = False
            return Result(0, b"")
        return Result(0, b"")


class ClockPgFactory:
    def __init__(self, clock, create_mode="ok"):
        self.clock = clock
        self.create_mode = create_mode
        self.pg = None
        self.probe = None

    def __call__(self, dsn, nonce, runner):
        pg = resources.BoundedOwnedPostgres(
            dsn, nonce=nonce, runner=runner, clock=self.clock
        )
        probe = ClockProbe(pg.database, self.clock, self.create_mode)
        pg.runner = probe
        self.pg = pg
        self.probe = probe
        return pg


class InProcessRootRemover:
    def remove(self, root, deadline):
        root.remove()
        return {
            "removed": bool(root.removed),
            "absent": bool(root.removed),
            "verified": bool(root.removed),
            "code": None,
            "within_deadline": True,
        }


class TimeoutRootRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        raise RunnerError("cleanup", "root_remove_timeout")


class RemovingRootRunner:
    def run(self, argv, **kwargs):
        shutil.rmtree(Path(argv[2]))
        return Completed(argv, 0, b"", b"")


class OwnedFixtureDeadlineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        schema = self.root / resources.SCHEMA_REL
        schema.parent.mkdir(parents=True)
        self.schema = b"CREATE SCHEMA IF NOT EXISTS pando_lab;\n"
        schema.write_bytes(self.schema)
        self.sha = hashlib.sha256(self.schema).hexdigest()
        self.base = self.root / "owned"
        self.base.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def fixture(self, clock, create_mode="ok", root_remover=None):
        factory = ClockPgFactory(clock, create_mode)
        fixture = resources.OwnedFixture(
            self.root,
            BOOTSTRAP,
            {},
            object(),
            schema_sha256=self.sha,
            postgres_factory=factory,
            root_factory=lambda: resources.OwnedRoot(base=self.base),
            root_remover=root_remover or InProcessRootRemover(),
            clock=clock,
        )
        return fixture, factory

    def test_multiple_teardown_caps_respect_the_absolute_deadline(self):
        clock = FakeClock(0)
        remover = root_cleanup.BoundedRootRemover(
            clock=clock, process_runner=TimeoutRootRunner()
        )
        fixture, factory = self.fixture(clock, root_remover=remover)
        fixture.start(deadline=1e18)
        clock.set(0)
        factory.probe.calls.clear()
        factory.probe.advance = True
        cleanup = fixture.cleanup(deadline=90)
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertFalse(cleanup["cleanup_verified"])
        self.assertFalse(cleanup["postgres_dropped"])
        self.assertFalse(cleanup["database_absent"])
        self.assertFalse(cleanup["root_removed"])
        self.assertFalse(cleanup["root_absent"])
        self.assertEqual(cleanup["error_code"], "cleanup_deadline_exceeded")
        self.assertLessEqual(clock(), 90)
        self.assertEqual(len(factory.probe.drop_sqls), 1)
        timeouts = [
            call["timeout"] for call in factory.probe.calls
            if isinstance(call["timeout"], (int, float))
        ]
        self.assertTrue(all(item <= 60 for item in timeouts))
        self.assertTrue(any(0 < item < 30 for item in timeouts))

    def test_expired_deadline_never_inherits_absent_or_removed_defaults(self):
        clock = FakeClock(0)
        fixture, factory = self.fixture(clock)
        fixture.start(deadline=1e18)
        calls = len(factory.probe.calls)
        cleanup = fixture.cleanup(deadline=0)
        self.assertTrue(fixture.postgres.created)
        self.assertTrue(fixture.root.created)
        self.assertTrue(Path(fixture.root_path).exists())
        self.assertTrue(cleanup["postgres_owned"])
        self.assertTrue(cleanup["postgres_created"])
        self.assertTrue(cleanup["root_owned"])
        self.assertTrue(cleanup["root_created"])
        self.assertFalse(cleanup["postgres_dropped"])
        self.assertFalse(cleanup["database_absent"])
        self.assertFalse(cleanup["root_removed"])
        self.assertFalse(cleanup["root_absent"])
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertFalse(cleanup["cleanup_within_deadline"])
        self.assertFalse(cleanup["postgres_cleanup_verified"])
        self.assertFalse(cleanup["root_cleanup_verified"])
        self.assertFalse(cleanup["cleanup_verified"])
        self.assertEqual(cleanup["error_code"], "cleanup_deadline_exceeded")
        self.assertEqual(len(factory.probe.calls), calls)
        self.assertEqual(factory.probe.drop_sqls, [])

    def test_unverified_child_absence_is_not_marked_removed(self):
        clock = FakeClock(0)
        remover = root_cleanup.BoundedRootRemover(
            clock=clock, process_runner=AbsentThenTimeoutRunner()
        )
        fixture, factory = self.fixture(clock, root_remover=remover)
        fixture.start(deadline=1e18)
        cleanup = fixture.cleanup(deadline=100)
        self.assertFalse(Path(fixture.root_path).exists())
        self.assertFalse(cleanup["root_removed"])
        self.assertFalse(cleanup["root_absent"])
        self.assertFalse(cleanup["root"]["removed"])
        self.assertFalse(cleanup["root_cleanup_verified"])
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertEqual(cleanup["error_code"], "cleanup_deadline_exceeded")
        self.assertTrue(cleanup["postgres_dropped"])
        self.assertTrue(cleanup["postgres"]["dropped"])
        self.assertFalse(fixture.root.removed)

    def test_root_group_unverified_primary_reaches_cleanup(self):
        clock = FakeClock(0)
        remover = root_cleanup.BoundedRootRemover(
            clock=clock,
            process_runner=GroupUnverifiedRootRunner(),
        )
        fixture, factory = self.fixture(clock, root_remover=remover)
        fixture.start(deadline=1e18)
        cleanup = fixture.cleanup(deadline=100)
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertFalse(cleanup["root_removed"])
        self.assertEqual(cleanup["error_code"], "root_remove_failed")
        self.assertEqual(cleanup["primary_code"], "root_remove_timeout")

    def test_unknown_runner_timeout_create_never_drops_or_claims_absence(self):
        clock = FakeClock(0)
        fixture, factory = self.fixture(clock, create_mode="runner_timeout")
        with self.assertRaises(RunnerError) as caught:
            fixture.start(deadline=1e18)
        self.assertEqual(caught.exception.code, "postgres_create_unknown")
        self.assertEqual(fixture.postgres.creation_outcome, "unknown")
        cleanup = fixture.cleanup(deadline=1000)
        self.assertFalse(cleanup["cleanup_ok"])
        self.assertFalse(cleanup["database_absent"])
        self.assertFalse(cleanup["postgres_dropped"])
        self.assertEqual(cleanup["error_code"], "postgres_create_outcome_unknown")
        self.assertEqual(factory.probe.drop_sqls, [])


class AbsentThenTimeoutRunner:
    """Child proves absence by deleting, then fails before reporting success."""

    def __init__(self):
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        shutil.rmtree(Path(argv[2]))
        raise RunnerError("cleanup", "root_remove_timeout")


class GroupUnverifiedRootRunner:
    def run(self, argv, **kwargs):
        raise RunnerError(
            "cleanup",
            "process_group_unverified",
            primary_code="root_remove_timeout",
        )


class BoundedRootRemovalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def owned_root(self):
        root = resources.OwnedRoot(base=self.base)
        root.create()
        (root.path / "child").mkdir()
        (root.path / "child/data.bin").write_bytes(b"x")
        return root

    def test_child_timeout_is_unresolved_and_reaped(self):
        root = self.owned_root()
        runner_obj = TimeoutRootRunner()
        remover = root_cleanup.BoundedRootRemover(
            clock=lambda: 0.0, process_runner=runner_obj
        )
        result = remover.remove(root, deadline=100)
        self.assertFalse(result["removed"])
        self.assertFalse(result["absent"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["code"], "root_cleanup_deadline_exceeded")
        self.assertTrue(root.path.exists())
        self.assertEqual(len(runner_obj.calls), 1)
        self.assertLessEqual(runner_obj.calls[0][1]["timeout"], 98)

    def test_owned_child_timeout_kills_and_polls_to_reaped(self):
        root = self.owned_root()
        fake = StreamingPopen(block=True)
        clock = StepClock()
        process_runner = process.ProcessRunner(
            clock=clock,
            popen=lambda *a, **k: fake,
            thread_factory=FakeThread,
            killpg=GroupKiller(),
        )
        remover = root_cleanup.BoundedRootRemover(
            clock=clock, process_runner=process_runner
        )
        result = remover.remove(root, deadline=100)
        self.assertFalse(result["removed"])
        self.assertEqual(result["code"], "root_cleanup_deadline_exceeded")
        self.assertTrue(fake.killed)
        self.assertIsNotNone(fake.poll())
        self.assertTrue(root.path.exists())

    def test_group_unverified_child_is_root_remove_unverified(self):
        root = self.owned_root()
        remover = root_cleanup.BoundedRootRemover(
            clock=lambda: 0.0,
            process_runner=GroupUnverifiedRootRunner(),
        )
        result = remover.remove(root, deadline=100)
        self.assertFalse(result["removed"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["code"], "root_remove_unverified")
        self.assertEqual(result["primary_code"], "root_remove_timeout")
        self.assertTrue(root.path.exists())

    def test_verified_child_absence_is_required_for_success(self):
        root = self.owned_root()
        remover = root_cleanup.BoundedRootRemover(
            clock=lambda: 0.0, process_runner=RemovingRootRunner()
        )
        result = remover.remove(root, deadline=100)
        self.assertTrue(result["removed"])
        self.assertTrue(result["absent"])
        self.assertTrue(result["verified"])
        self.assertFalse(root.path.exists())


if __name__ == "__main__":
    unittest.main()
