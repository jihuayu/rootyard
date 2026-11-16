"""Owned local PostgreSQL fixture for the ignored producer cases.

The approved ``OwnedPostgres``/``OwnedRoot`` helpers own one acknowledged random
database and one private temporary root.  No Vault fixture is constructed.  The
actual ``experimental/pando/schema.sql`` is applied to the owned database with
SQL on psql stdin; the bootstrap database is never initialized.  The child
environment is a fresh copy with all four fixture-escape variables absent
(presence, not value, is rejected) and with the owned database/root selected.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from pando_vault_rotation_fixture import FixtureError  # noqa: E402
from pando_vault_rotation_fixture_resources import (  # noqa: E402
    OwnedPostgres,
    OwnedRoot,
)

from .errors import RunnerError, require  # noqa: E402

ESCAPE_VARIABLES = (
    "PANDO_OBJECT_STORE_ROOT",
    "PANDO_KMS_KEYRING_DIR",
    "PANDO_KMS_PROVIDER",
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
)
SCHEMA_REL = "experimental/pando/schema.sql"
PSQL_COMMAND = ("psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-f", "-")


def require_escape_absent(environ=None):
    env = os.environ if environ is None else environ
    for name in ESCAPE_VARIABLES:
        if name in env:
            raise RunnerError("setup", "escape_variable_present")
    return True


def build_child_environment(base, postgres, root_path):
    """Fresh filtered child environment; the caller's mapping is not mutated."""
    env = dict(base)
    for name in ESCAPE_VARIABLES:
        env.pop(name, None)
    for name in (
        "ROOTYARD_TEST_DATABASE_URL",
        "ROOTYARD_RESTORE_TEST_DATABASE_URL",
        "DATABASE_URL",
    ):
        env.pop(name, None)
    env["ROOTYARD_TEST_DATABASE_URL"] = postgres.child_dsn()
    env["TMPDIR"] = str(Path(root_path).resolve())
    env["LC_ALL"] = "C"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    require_escape_absent(env)
    return env


def empty_cleanup():
    return {
        "cleanup_ok": True,
        "postgres_owned": False,
        "postgres_created": False,
        "postgres_dropped": True,
        "database_absent": True,
        "root_owned": False,
        "root_created": False,
        "root_removed": True,
        "root_absent": True,
        "cleanup_within_deadline": True,
        "no_global_cleanup": True,
        "postgres": {},
        "root": {},
    }


def _cleanup_code(code):
    if code == "pg_create_outcome_unknown":
        return "postgres_create_outcome_unknown"
    if code in (
        "pg_drop_identity_mismatch",
        "pg_cleanup_identity_unresolved",
        "pg_database_identity_unreadable",
        "pg_database_drop_unverified",
    ):
        return "postgres_drop_unverified"
    if code.startswith("pg_"):
        return "postgres_drop_failed"
    if code.startswith("root_"):
        return "root_remove_failed"
    return "cleanup_unresolved"


class OwnedFixture:
    """One root and one acknowledged owned database for this nonce."""

    def __init__(
        self,
        source_root,
        bootstrap_dsn,
        base_environment,
        runner,
        *,
        schema_sha256,
        postgres_factory=OwnedPostgres,
        root_factory=OwnedRoot,
        clock=None,
    ):
        import time

        self.source_root = Path(source_root).resolve()
        self.bootstrap_dsn = bootstrap_dsn
        self.base_environment = dict(base_environment)
        self.runner = runner
        self.schema_sha256 = schema_sha256
        self.postgres_factory = postgres_factory
        self.root_factory = root_factory
        self.clock = clock or time.monotonic
        self.root = None
        self.root_path = None
        self.postgres = None
        self.child_environment = None
        self.schema_initialized = False

    def _check(self, deadline):
        if self.clock() >= deadline:
            raise RunnerError("setup", "setup_deadline_exceeded")

    def start(self, deadline):
        require_escape_absent(self.base_environment)
        self._check(deadline)
        self.root = self.root_factory()
        try:
            self.root_path = self.root.create()
        except FixtureError:
            raise RunnerError("setup", "root_create_failed") from None
        self._check(deadline)
        self.postgres = self.postgres_factory(
            self.bootstrap_dsn, nonce=self.root.nonce, runner=self.runner
        )
        try:
            self.postgres.validate()
        except FixtureError:
            raise RunnerError("setup", "postgres_validate_failed") from None
        self._check(deadline)
        try:
            self.postgres.create()
        except FixtureError as error:
            code = (
                "postgres_create_unknown"
                if getattr(error, "code", "") in ("process_failed", "pg_command_timeout")
                else "postgres_create_failed"
            )
            raise RunnerError("setup", code) from None
        self._check(deadline)
        self._install_schema(deadline)
        try:
            self.child_environment = build_child_environment(
                self.base_environment, self.postgres, self.root_path
            )
        except (TypeError, ValueError, OSError):
            raise RunnerError("setup", "child_environment_failed") from None
        return self

    def _install_schema(self, deadline):
        path = self.source_root / SCHEMA_REL
        try:
            raw = path.read_bytes()
        except OSError:
            raise RunnerError("setup", "schema_read_failed") from None
        import hashlib

        if hashlib.sha256(raw).hexdigest() != self.schema_sha256:
            raise RunnerError("setup", "schema_hash_mismatch")
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise RunnerError("setup", "setup_deadline_exceeded")
        schema_environment = dict(self.postgres.environment)
        schema_environment["PGDATABASE"] = self.postgres.database
        try:
            result = self.postgres.runner.run(
                list(PSQL_COMMAND),
                env=schema_environment,
                input=raw,
                timeout=remaining,
                stage="setup",
                timeout_code="schema_init_timeout",
                spawn_code="schema_init_failed",
            )
        except RunnerError:
            raise
        except (OSError, ValueError):
            raise RunnerError("setup", "schema_init_failed") from None
        if result.returncode != 0:
            raise RunnerError("setup", "schema_init_failed")
        self.schema_initialized = True

    def _safe_records(self):
        postgres = {}
        root = {}
        try:
            if self.postgres is not None:
                postgres = self.postgres.safe_record()
        except Exception:
            postgres = {}
        try:
            if self.root is not None:
                root = self.root.safe_record()
        except Exception:
            root = {}
        return postgres, root

    def cleanup(self, deadline):
        facts = empty_cleanup()
        postgres, root = self._safe_records()
        facts["postgres"] = postgres
        facts["root"] = root
        if self.clock() >= deadline:
            facts.update(
                {
                    "cleanup_ok": False,
                    "cleanup_within_deadline": False,
                    "error_code": "cleanup_deadline_exceeded",
                }
            )
            return facts
        facts["cleanup_within_deadline"] = True
        failure = None
        if self.postgres is not None:
            facts["postgres_owned"] = bool(self.postgres.owned)
            facts["postgres_created"] = bool(self.postgres.created)
            outcome = getattr(self.postgres, "creation_outcome", "not_attempted")
            if self.postgres.create_acknowledged or self.postgres.owned:
                try:
                    self.postgres.drop()
                except FixtureError as error:
                    failure = _cleanup_code(getattr(error, "code", ""))
                except Exception:
                    failure = "cleanup_unresolved"
                facts["postgres_dropped"] = bool(self.postgres.dropped)
                facts["database_absent"] = bool(self.postgres.dropped)
            elif outcome == "unknown":
                failure = "postgres_create_outcome_unknown"
                facts["postgres_dropped"] = False
                facts["database_absent"] = False
            elif outcome == "not_attempted" and (
                self.postgres.major is None or self.postgres.prechecked_absent
            ):
                # No CREATE was issued by this process, so no owned database
                # exists.  A failed preflight that found a foreign database is
                # handled by the final branch and never treated as ours.
                facts["postgres_dropped"] = True
                facts["database_absent"] = True
            else:
                # CREATE was attempted without an ownership acknowledgment
                # (rejected/raced), or the absence preflight found a foreign
                # database.  Absence is unresolved and no DROP is authorized.
                failure = "postgres_create_outcome_unknown" if outcome == "unknown" else "cleanup_unresolved"
                facts["postgres_dropped"] = False
                facts["database_absent"] = False
        if self.root is not None:
            facts["root_owned"] = bool(self.root.created)
            facts["root_created"] = bool(self.root.created)
            try:
                self.root.remove()
            except FixtureError as error:
                if failure is None:
                    failure = _cleanup_code(getattr(error, "code", ""))
            except Exception:
                if failure is None:
                    failure = "cleanup_unresolved"
            facts["root_removed"] = bool(self.root.removed)
            facts["root_absent"] = bool(self.root.removed)
        if failure is not None:
            facts["error_code"] = failure
        facts["cleanup_ok"] = bool(
            facts["postgres_dropped"]
            and facts["database_absent"]
            and facts["root_removed"]
            and facts["root_absent"]
            and failure is None
        )
        facts["cleanup_within_deadline"] = self.clock() <= deadline
        return facts
