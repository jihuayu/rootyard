#!/usr/bin/env python3
"""Owned PostgreSQL database and disposable PANDO_ROOT for issue #21.

The fixture never inherits a developer ``DATABASE_URL`` as the target.  It
takes an explicit bootstrap DSN from ``ROOTYARD_TEST_DATABASE_URL`` (or a
caller-supplied string), proves it is a literal loopback PostgreSQL 17 server,
creates one random nonce-derived database, and drops only that exact database.
Connection values are passed to ``psql`` through its process environment and
SQL arrives on stdin, so neither the DSN nor a password appears in argv,
stdout, a report or an exception string.

The root is one private absolute temporary directory.  Cleanup verifies the
exact parent/name prefix and removes only that directory; there is no global
temporary-file, PostgreSQL or Docker cleanup path.
"""
from __future__ import annotations

from pathlib import Path
import os
import re
import secrets
import shutil
import stat
import tempfile
import urllib.parse

from pando_vault_rotation_fixture import FixtureError, ProcessRunner

PG_BOOTSTRAP_ENV = "ROOTYARD_TEST_DATABASE_URL"
PG_MAJOR = 17
DB_PREFIX = "pando_rotation_"
ROOT_PREFIX = "rootyard-pando-vault-rotation-"
DB_NAME_RE = re.compile(r"^pando_rotation_[0-9a-f]{12}$")
NONCE_RE = re.compile(r"^[0-9a-f]{12}$")


def _require(condition, code):
    if not condition:
        raise FixtureError(code)


def parse_bootstrap_dsn(dsn):
    """Return a fixed host/port/user/database projection, never the raw DSN."""
    _require(isinstance(dsn, str) and bool(dsn.strip()), "pg_dsn_missing")
    try:
        value = urllib.parse.urlsplit(dsn)
    except ValueError:
        raise FixtureError("pg_dsn_invalid") from None
    _require(value.scheme in ("postgres", "postgresql"), "pg_dsn_scheme_invalid")
    host = value.hostname
    _require(host in ("127.0.0.1", "::1"), "pg_dsn_not_loopback")
    try:
        port = value.port or 5432
    except ValueError:
        raise FixtureError("pg_dsn_port_invalid") from None
    _require(1 <= port <= 65535, "pg_dsn_port_invalid")
    user = urllib.parse.unquote(value.username or "")
    password = urllib.parse.unquote(value.password or "")
    database = urllib.parse.unquote(value.path.lstrip("/"))
    _require(bool(user), "pg_dsn_user_missing")
    _require(bool(database), "pg_dsn_database_missing")
    query = dict(urllib.parse.parse_qsl(value.query, keep_blank_values=True))
    _require(set(query) <= {"sslmode"}, "pg_dsn_query_unsupported")
    sslmode = query.get("sslmode")
    _require(sslmode is None or sslmode in ("disable", "prefer", "require"),
             "pg_dsn_sslmode_unsupported")
    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "database": database,
        "sslmode": sslmode,
    }


class OwnedPostgres:
    """One random database owned by this process for this nonce only."""

    def __init__(self, bootstrap_dsn, nonce=None, runner=None):
        self.nonce = nonce or secrets.token_hex(6)
        _require(NONCE_RE.fullmatch(self.nonce) is not None, "pg_nonce_invalid")
        self.database = DB_PREFIX + self.nonce
        _require(DB_NAME_RE.fullmatch(self.database) is not None, "pg_database_name_invalid")
        self.parts = parse_bootstrap_dsn(bootstrap_dsn)
        self.runner = runner or ProcessRunner()
        self.environment = self._environment(self.parts["database"])
        self.major = None
        self.prechecked_absent = False
        self.create_acknowledged = False
        self.owned = False
        self.identity = None
        self.creation_outcome = "not_attempted"
        self.created = False
        self.dropped = False

    def _environment(self, database):
        env = {
            "PGHOST": self.parts["host"],
            "PGPORT": str(self.parts["port"]),
            "PGUSER": self.parts["user"],
            "PGDATABASE": database,
            "PGCONNECT_TIMEOUT": "10",
        }
        if self.parts["password"]:
            env["PGPASSWORD"] = self.parts["password"]
        if self.parts["sslmode"]:
            env["PGSSLMODE"] = self.parts["sslmode"]
        return env

    def child_dsn(self):
        """URI used only in child environments, never in argv or a report."""
        user = urllib.parse.quote(self.parts["user"], safe="")
        credentials = user
        if self.parts["password"]:
            credentials += ":" + urllib.parse.quote(self.parts["password"], safe="")
        host = self.parts["host"]
        if ":" in host:
            host = "[" + host + "]"
        query = ""
        if self.parts["sslmode"]:
            query = "?sslmode=" + urllib.parse.quote(self.parts["sslmode"], safe="")
        return "postgresql://%s@%s:%d/%s%s" % (
            credentials, host, self.parts["port"],
            urllib.parse.quote(self.database, safe=""), query,
        )

    def child_environment(self):
        return {"PANDO_DATABASE_URL": self.child_dsn()}

    def _psql(self, sql, timeout=30):
        result = self.runner.run(
            ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
            env=self.environment,
            input=sql.encode(),
            timeout=timeout,
        )
        if result.returncode != 0:
            raise FixtureError("pg_command_failed")
        return result.stdout.decode(errors="replace").strip()

    def validate(self):
        _require(self.major is None, "pg_already_validated")
        raw = self._psql("SHOW server_version_num;\n")
        try:
            version = int(raw.splitlines()[-1])
        except (IndexError, ValueError):
            raise FixtureError("pg_version_unreadable") from None
        major = version // 10000
        _require(major == PG_MAJOR, "pg_major_not_17")
        self.major = major
        return major

    def _exists(self):
        raw = self._psql(
            "SELECT 1 FROM pg_database WHERE datname='%s';\n" % self.database)
        return raw.splitlines()[-1:] == ["1"]

    def _database_identity(self):
        """Read the exact name/OID/owner identity of the nonce database."""
        raw = self._psql(
            "SELECT oid::text, datdba::text, datname, "
            "(SELECT oid::text FROM pg_roles WHERE rolname=current_user) "
            "FROM pg_database WHERE datname='%s';\n" % self.database)
        rows = [line for line in raw.splitlines() if line.strip()]
        _require(len(rows) == 1, "pg_database_identity_unreadable")
        parts = rows[0].split("|")
        _require(len(parts) == 4, "pg_database_identity_unreadable")
        oid, datdba, database, current_oid = parts
        _require(database == self.database, "pg_database_identity_mismatch")
        _require(oid.isdigit() and int(oid) > 0, "pg_database_oid_invalid")
        _require(datdba.isdigit() and current_oid.isdigit()
                 and datdba == current_oid, "pg_database_owner_mismatch")
        return {"oid": oid, "datdba": datdba, "database": database}

    def _capture_identity(self):
        self.identity = self._database_identity()
        return self.identity

    def _post_create_setup(self):
        """Fresh identity proof after CREATE; failure keeps ownership."""
        current = self._database_identity()
        _require(self.identity is not None, "pg_identity_missing")
        _require(current["oid"] == self.identity["oid"]
                 and current["datdba"] == self.identity["datdba"]
                 and current["database"] == self.identity["database"],
                 "pg_database_identity_changed")

    def create(self):
        if self.major is None:
            self.validate()
        _require(not self.owned and not self.created, "pg_already_created")
        _require(not self._exists(), "pg_database_already_exists")
        self.prechecked_absent = True
        try:
            self._psql('CREATE DATABASE "%s";\n' % self.database)
        except FixtureError as error:
            # A nonzero CREATE is a rejection.  A timed-out/lost process is
            # unknown: it never authorizes cleanup to drop anything by name.
            self.creation_outcome = (
                "unknown" if error.code in ("process_failed", "pg_command_timeout")
                else "rejected")
            raise
        # The successful CREATE acknowledgement is the ownership boundary.
        self.create_acknowledged = True
        self.owned = True
        self.creation_outcome = "created_ack"
        self._capture_identity()
        self._post_create_setup()
        self.created = True
        return self.child_dsn()

    def drop(self):
        if not self.create_acknowledged:
            if self.creation_outcome == "unknown":
                raise FixtureError("pg_create_outcome_unknown")
            raise FixtureError("pg_drop_not_owned")
        _require(self.owned, "pg_drop_not_owned")
        _require(self.identity is not None, "pg_cleanup_identity_unresolved")
        if not self._exists():
            # The exact database is already absent; no DROP is issued.
            self.dropped = True
            return True
        current = self._database_identity()
        _require(current["oid"] == self.identity["oid"]
                 and current["datdba"] == self.identity["datdba"]
                 and current["database"] == self.identity["database"],
                 "pg_drop_identity_mismatch")
        self._psql('DROP DATABASE IF EXISTS "%s" WITH (FORCE);\n' % self.database,
                   timeout=60)
        _require(not self._exists(), "pg_database_drop_unverified")
        self.dropped = True
        return True

    def safe_record(self):
        return {
            "owned": self.owned,
            "prechecked_absent": self.prechecked_absent,
            "create_acknowledged": self.create_acknowledged,
            "creation_outcome": self.creation_outcome,
            "identity_oid": self.identity["oid"] if self.identity else None,
            "identity_verified": self.identity is not None,
            "created": self.created,
            "dropped": self.dropped,
            "pg_major": self.major,
            "loopback": True,
        }


class OwnedRoot:
    """One absolute private temporary PANDO_ROOT owned by this nonce."""

    def __init__(self, nonce=None, base=None):
        self.nonce = nonce or secrets.token_hex(6)
        _require(NONCE_RE.fullmatch(self.nonce) is not None, "root_nonce_invalid")
        self.base = Path(base or tempfile.gettempdir()).resolve()
        self.prefix = ROOT_PREFIX + self.nonce + "-"
        self.path = None
        self.creation_proof = None
        self.created = False
        self.ownership_verified = False
        self.private_permissions = False
        self.removed = False

    def create(self):
        _require(not self.created, "root_already_created")
        try:
            path = Path(tempfile.mkdtemp(prefix=self.prefix, dir=str(self.base)))
        except OSError:
            raise FixtureError("root_create_failed") from None
        # Register the exact mkdtemp result before chmod/stat verification can
        # fail.  A post-create failure must remain visible to cleanup.
        self.path = path
        self.created = True
        self.creation_proof = {
            "base": str(self.base),
            "name": path.name,
            "prefix": self.prefix,
            "nonce": self.nonce,
        }
        try:
            current = path.stat()
            self.creation_proof.update({
                "st_dev": current.st_dev,
                "st_ino": current.st_ino,
                "st_uid": current.st_uid,
            })
            _require(current.st_uid == os.getuid(), "root_ownership_unverified")
            self.ownership_verified = True
        except OSError:
            raise FixtureError("root_ownership_unverified") from None
        try:
            path.chmod(0o700)
            mode = stat.S_IMODE(path.stat().st_mode)
            _require(mode == 0o700, "root_permissions_invalid")
            self.private_permissions = True
            return path.resolve()
        except FixtureError:
            raise
        except OSError:
            raise FixtureError("root_post_create_failed") from None

    def remove(self):
        if not self.created:
            self.removed = True
            return True
        _require(self.path is not None, "root_path_missing")
        _require(self.creation_proof is not None, "root_creation_proof_missing")
        try:
            resolved = self.path.resolve()
        except OSError:
            raise FixtureError("root_path_unresolved") from None
        _require(resolved.parent == self.base, "root_path_parent_mismatch")
        _require(resolved.name == self.creation_proof["name"]
                 and resolved.name.startswith(self.prefix),
                 "root_path_prefix_mismatch")
        if not resolved.exists():
            self.removed = True
            return True
        proof_dev = self.creation_proof.get("st_dev")
        proof_ino = self.creation_proof.get("st_ino")
        if proof_dev is not None and proof_ino is not None:
            try:
                current = resolved.stat()
            except OSError:
                raise FixtureError("root_identity_unreadable") from None
            _require(current.st_dev == proof_dev and current.st_ino == proof_ino,
                     "root_identity_mismatch")
        shutil.rmtree(resolved)
        _require(not resolved.exists(), "root_remove_unverified")
        self.removed = True
        return True

    def safe_record(self):
        return {
            "owned": self.created,
            "absolute_private_root": bool(
                self.created and self.path is not None and self.path.is_absolute()),
            "ownership_verified": self.ownership_verified,
            "creation_proof_recorded": self.creation_proof is not None,
            "private_permissions": self.private_permissions,
            "created": self.created,
            "removed": self.removed,
        }
