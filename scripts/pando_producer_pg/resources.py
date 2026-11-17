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
import time

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
from .root_cleanup import REAP_RESERVE_SECONDS, BoundedRootRemover  # noqa: E402

ESCAPE_VARIABLES = (
    "PANDO_OBJECT_STORE_ROOT",
    "PANDO_KMS_KEYRING_DIR",
    "PANDO_KMS_PROVIDER",
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
)
SCHEMA_REL = "experimental/pando/schema.sql"
PSQL_COMMAND = ("psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-f", "-")
TIMEOUT_CODES = ("process_timeout", "process_unreaped", "pg_command_timeout")


class BoundedOwnedPostgres(OwnedPostgres):
    """OwnedPostgres whose every psql child is capped by one absolute deadline.

    ``arm(deadline)`` stores the remaining overall budget.  Every existence,
    identity, CREATE, DROP and post-DROP verification subprocess gets at most
    ``min(requested, remaining - reap_reserve)`` seconds, so a fixed 30/60/30
    sequence can never ignore the caller's deadline.  A process timeout/spawn
    failure is translated into a fixed fixture code so CREATE outcomes remain
    unknown rather than looking absent.
    """

    def __init__(self, *args, clock=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.clock = clock or time.monotonic
        self._deadline = None

    def set_clock(self, clock):
        self.clock = clock
        return self

    def arm(self, deadline):
        self._deadline = float(deadline)
        return self

    def _psql(self, sql, timeout=30):
        if self._deadline is not None:
            remaining = self._deadline - self.clock()
            if remaining <= REAP_RESERVE_SECONDS:
                raise FixtureError("pg_cleanup_deadline_exceeded")
            timeout = min(float(timeout), remaining - REAP_RESERVE_SECONDS)
        try:
            return super()._psql(sql, timeout=timeout)
        except RunnerError as error:
            code = (
                "pg_command_timeout"
                if error.code in TIMEOUT_CODES or "timeout" in error.code
                else "process_failed"
            )
            raise FixtureError(code) from None



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
        "postgres_cleanup_verified": True,
        "root_cleanup_verified": True,
        "cleanup_verified": True,
        "postgres": {},
        "root": {},
    }


def unresolved_cleanup(code="cleanup_unresolved"):
    """Conservative fallback when cleanup itself cannot be observed."""
    facts = empty_cleanup()
    facts.update(
        {
            "cleanup_ok": False,
            "postgres_dropped": False,
            "database_absent": False,
            "root_removed": False,
            "root_absent": False,
            "cleanup_within_deadline": False,
            "postgres_cleanup_verified": False,
            "root_cleanup_verified": False,
            "cleanup_verified": False,
            "error_code": code,
        }
    )
    return facts


def _cleanup_code(code):
    if code in (
        "pg_cleanup_deadline_exceeded",
        "root_cleanup_deadline_exceeded",
        "root_remove_timeout",
    ):
        return "cleanup_deadline_exceeded"
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
        postgres_factory=None,
        root_factory=None,
        root_remover=None,
        clock=None,
    ):
        import time

        self.source_root = Path(source_root).resolve()
        self.bootstrap_dsn = bootstrap_dsn
        self.base_environment = dict(base_environment)
        self.runner = runner
        self.schema_sha256 = schema_sha256
        self.postgres_factory = postgres_factory or BoundedOwnedPostgres
        self.root_factory = root_factory or OwnedRoot
        self.clock = clock or time.monotonic
        self.root_remover = root_remover or BoundedRootRemover(clock=self.clock)
        self.root = None
        self.root_path = None
        self.postgres = None
        self.child_environment = None
        self.schema_initialized = False

    def _arm_postgres(self, deadline):
        arm = getattr(self.postgres, "arm", None)
        if callable(arm):
            arm(deadline)

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
        set_clock = getattr(self.postgres, "set_clock", None)
        if callable(set_clock):
            set_clock(self.clock)
        self._arm_postgres(deadline)
        try:
            self.postgres.validate()
        except FixtureError:
            raise RunnerError("setup", "postgres_validate_failed") from None
        self._check(deadline)
        self._arm_postgres(deadline)
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

    def _truth_base(self, postgres, root):
        """Build cleanup facts from observations, never from success defaults.

        A resource is only reported absent/dropped/removed when this fixture can
        actually prove it never created it or already removed it.  Owned,
        acknowledged, unknown or identity-unresolved resources stay false.
        """
        created = bool(postgres.get("created"))
        owned = bool(postgres.get("owned"))
        acknowledged = bool(postgres.get("create_acknowledged"))
        outcome = postgres.get("creation_outcome", "not_attempted")
        no_create = (
            outcome == "not_attempted"
            and not created
            and not owned
            and not acknowledged
        )
        proven_absent = self.postgres is None or (
            no_create
            and (
                postgres.get("pg_major") is None
                or postgres.get("prechecked_absent") is True
            )
        )
        postgres_absent = bool(proven_absent or postgres.get("dropped"))
        root_created = bool(root.get("created"))
        root_absent = bool(
            self.root is None or not root_created or root.get("removed")
        )
        return {
            "cleanup_ok": False,
            "postgres_owned": owned,
            "postgres_created": created,
            "postgres_dropped": postgres_absent,
            "database_absent": postgres_absent,
            "root_owned": root_created,
            "root_created": root_created,
            "root_removed": root_absent,
            "root_absent": root_absent,
            "cleanup_within_deadline": False,
            "no_global_cleanup": True,
            "postgres": postgres,
            "root": root,
        }

    def _finish_cleanup(self, facts, failure, deadline):
        within = self.clock() < deadline
        postgres_verified = bool(
            facts["postgres_dropped"] and facts["database_absent"]
        )
        root_verified = bool(facts["root_removed"] and facts["root_absent"])
        facts["postgres_cleanup_verified"] = postgres_verified
        facts["root_cleanup_verified"] = root_verified
        facts["cleanup_verified"] = bool(
            postgres_verified and root_verified and failure is None
        )
        facts["cleanup_within_deadline"] = within
        facts["cleanup_ok"] = bool(facts["cleanup_verified"] and within)
        if failure is not None:
            facts["error_code"] = failure
        elif not within:
            facts["error_code"] = "cleanup_deadline_exceeded"
        return facts

    def cleanup(self, deadline):
        postgres, root = self._safe_records()
        facts = self._truth_base(postgres, root)
        failure = None
        if self.clock() >= deadline:
            return self._finish_cleanup(
                facts, "cleanup_deadline_exceeded", deadline
            )
        if self.postgres is not None:
            self._arm_postgres(deadline)
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
                dropped = bool(getattr(self.postgres, "dropped", False))
                facts["postgres_dropped"] = dropped
                facts["database_absent"] = dropped
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
                failure = (
                    "postgres_create_outcome_unknown"
                    if outcome == "unknown"
                    else "cleanup_unresolved"
                )
                facts["postgres_dropped"] = False
                facts["database_absent"] = False
        if self.root is not None:
            facts["root_owned"] = bool(self.root.created)
            facts["root_created"] = bool(self.root.created)
            try:
                removal = self.root_remover.remove(self.root, deadline)
            except FixtureError as error:
                removal = {
                    "removed": False,
                    "absent": False,
                    "verified": False,
                    "code": getattr(error, "code", "root_remove_failed"),
                }
            except Exception:
                removal = {
                    "removed": False,
                    "absent": False,
                    "verified": False,
                    "code": "root_remove_failed",
                }
            if not isinstance(removal, dict):
                removal = {
                    "removed": False,
                    "absent": False,
                    "verified": False,
                    "code": "root_remove_failed",
                }
            facts["root_removed"] = bool(removal.get("removed"))
            facts["root_absent"] = bool(removal.get("absent"))
            if not removal.get("verified") or removal.get("code"):
                if failure is None:
                    failure = _cleanup_code(
                        removal.get("code") or "root_remove_unverified"
                    )
        return self._finish_cleanup(facts, failure, deadline)

