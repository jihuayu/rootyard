#!/usr/bin/env python3
"""Shared real legacy-archive restore drill (format8/schema132 entry point).

A trusted pre-schema135 binary creates genuine repositories, pushes real Git
history through the stock server, and performs real CLI cutovers to Pando-backed
repository authority.  The legacy binary writes an offline archive.  The
candidate must reject that archive unless its explicit legacy schema opt-in is
given, restore into a brand-new database/data directory under one newly minted
Pando authority, apply the reviewed current migrations, and serve stock Git
fetch/clone for both repositories.  Every frozen predecessor source contract
here keeps its own format/schema verification and then upgrades to the same
current reviewed target: format18/schema142.

``backup_legacy133_identity.py`` through ``backup_legacy141_packs.py`` reuse this
harness with the format9/schema133 through format17/schema141 contracts and
assert the same Pando/session/Git boundaries, the frozen source contract and the
reviewed current migration target.  A genuine format8 through format17 archive
carries no RefStore core rows for this fixture, so the schema139 core tables are
verified to exist, be correctly constrained and stay empty; this harness never
claims a core-row roundtrip and does not assert the schema140 snapshot tables
that migration 140 introduces.  It also verifies that the schema141 global
artifact-hold tables exist and stay empty except for an exact fixed global shard
seed if the settled migration SQL inserts one, and that the schema142 pack
registration/membership/history/usage tables exist and stay empty; no hold or
pack row is fabricated.

Only random task-owned databases and temporary storage are used.  Secrets, DSNs,
raw HTTP logs and Garage/Vault credentials are never printed; recorded failures
are redacted.  The shared PostgreSQL/Garage/Vault services are never stopped.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.parse

from dataclasses import dataclass, replace

from backup import BackupHarness

REQUIRED_ENV = (
    "ROOTYARD_TEST_DATABASE_URL",
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
    "ROOTYARD_OBJECT_STORE_BUCKET",
    "ROOTYARD_OBJECT_STORE_REGION",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_KMS_VAULT_URL",
    "ROOTYARD_KMS_VAULT_TOKEN",
    "ROOTYARD_KMS_VAULT_KEY",
)
INDEXES = (
    "git_operations_token_actor_idx",
    "git_ref_admissions_token_actor_idx",
    "ci_checkout_jobs_issuer_token_idx",
    "ci_checkout_delegations_issuer_token_idx",
    "web_sessions_expiry_token_idx",
    "tokens_browser_expiry_idx",
)
# schema135 adds the partial covering metrics index to the six GC indexes every
# reviewed restore target must contain; schema136 adds the two token-scope
# reference indexes plus the PAT column/table contract checked below.
TARGET_INDEXES = INDEXES + ("storage_maintenance_metrics",)
SCHEMA136_INDEXES = TARGET_INDEXES + (
    "token_repository_scopes_repository_idx",
    "token_namespace_scopes_organization_idx",
)
# schema139 adds the minimal RefStore core: one initialized gate per repository,
# the current ref CAS rows it owns and immutable terminal/event receipts.
SCHEMA139_INDEXES = SCHEMA136_INDEXES + ("ref_store_core_refs_prefix",)
SCHEMA139_CORE_TABLES = ("ref_store_core_gates", "ref_store_core_refs",
                         "ref_store_core_events")
SCHEMA139_CORE_TRIGGER = "ref_store_core_event_immutable"
SCHEMA139_CORE_TRIGGER_FUNCTION = "rootyard_ref_store_core_event_immutable"
# schema142 adds the one-way metadata_only -> pack_verified gate fence. A
# genuine historical producer keeps its frozen source schema, but the
# current reviewed restore target is schema142 and legitimately carries
# both the immutable-event trigger and this mode fence.
SCHEMA142_CORE_TRIGGER = "ref_store_core_gate_pack_mode_fence"
SCHEMA142_CORE_TRIGGER_FUNCTION = "rootyard_ref_store_core_gate_pack_mode_fence"

SCHEMA134_FOREIGN_KEYS = (
    "pando_manifest_artifacts_manifest_identity_fkey",
    "storage_maintenance_repo_state_repository_owner_fkey",
    "storage_maintenance_jobs_repository_owner_fkey",
    "storage_maintenance_tombstones_repository_owner_fkey",
)
SCHEMA134_UNIQUE = ("pando_pack_manifests_id_repository_tenant_key",)
SCHEMA134_REMOVED_FOREIGN_KEY = "pando_manifest_artifacts_manifest_id_fkey"
ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ArchiveContract:
    """The frozen source format plus the reviewed target schema it upgrades to."""
    format: int
    schema: int
    flag: str
    source_label: str
    target_schema: int = 142
    target_format: int = 18
    indexes: tuple = SCHEMA139_INDEXES
    foreign_keys: tuple = SCHEMA134_FOREIGN_KEYS
    unique_constraints: tuple = SCHEMA134_UNIQUE
    removed_foreign_key: str = SCHEMA134_REMOVED_FOREIGN_KEY


LEGACY132 = ArchiveContract(format=8, schema=132, flag="--allow-legacy-schema132",
                            source_label="schema132", target_schema=142,
                            indexes=SCHEMA139_INDEXES)
LEGACY133 = ArchiveContract(format=9, schema=133, flag="--allow-legacy-schema133",
                            source_label="schema133", target_schema=142,
                            indexes=SCHEMA139_INDEXES)
# Format10/schema134 is an older frozen contract.  Its archive upgrades through
# the same reviewed path to the current schema142/format18 target.
LEGACY134 = replace(LEGACY132, format=10, schema=134,
                    flag="--allow-legacy-schema134", source_label="schema134")
# Format11/schema135 carries the frozen schema135 catalog and no schema136
# tables; it upgrades through migrations 136 through 139.
LEGACY135 = replace(LEGACY134, format=11, schema=135,
                    flag="--allow-legacy-schema135", source_label="schema135")
# Format12/schema136 upgrades through the terminal-admission projection (137),
# the operation registry (138) and the minimal RefStore core (139).
LEGACY136 = replace(LEGACY135, format=12, schema=136,
                    flag="--allow-legacy-schema136", source_label="schema136")
# Genuine predecessor format13 archive; migrations 138 and 139 add durable
# operation identity and then the minimal RefStore core.
LEGACY137 = replace(LEGACY136, format=13, schema=137,
                    flag="--allow-legacy-schema137", source_label="schema137")
# Genuine format14/schema138 archive: the immediate predecessor of the frozen
# format15/schema139 contract.  Its archive may carry the schema138 operation
# registry but never the schema139 core rows, so every restored target is
# checked for the schema139 core schema.
LEGACY138 = replace(LEGACY137, format=14, schema=138,
                    flag="--allow-legacy-schema138", source_label="schema138")
# Genuine format15/schema139 archive: the immediate predecessor of the frozen
# format16/schema140 contract.  It is produced by a trusted schema139 binary and
# is verified against its frozen schema139 catalogs before the reviewed
# migrations to schema142; earlier core rows stay empty on this fixture and no
# schema140 snapshot-table assertion is made here.
LEGACY139 = replace(LEGACY138, format=15, schema=139,
                    flag="--allow-legacy-schema139", source_label="schema139")
# Genuine format16/schema140 archive: the immediate predecessor of this
# format17/schema141 target.  Root supplies the real retained old producer and
# archive; this harness never manufactures, edits or relabels one.  The source
# has no schema141 hold rows, so the migrated ledger is inspected against the
# current catalog instead of being populated by a fake fixture.
LEGACY140 = replace(LEGACY139, format=16, schema=140,
                    flag="--allow-legacy-schema140", source_label="schema140")
# Genuine format17/schema141 archive: the immediate predecessor of this
# format18/schema142 target.  Root supplies the real retained old producer and
# archive (the native raw producer binary is retained outside this worktree);
# this harness never manufactures, edits or relabels one.  The source has no
# schema142 pack ledger rows, so the migrated tables are inspected empty against
# the current catalog instead of being populated by a fake fixture.
LEGACY141 = replace(LEGACY140, format=17, schema=141,
                    flag="--allow-legacy-schema141", source_label="schema141")

# Every legacy opt-in this shared harness knows about, oldest first.  The
# adjacent entry is used for the mixed-flag and mismatched-opt-in rejections.
LEGACY_FLAGS = (
    "--allow-legacy-schema132", "--allow-legacy-schema133",
    "--allow-legacy-schema134", "--allow-legacy-schema135",
    "--allow-legacy-schema136", "--allow-legacy-schema137",
    "--allow-legacy-schema138", "--allow-legacy-schema139",
    "--allow-legacy-schema140", "--allow-legacy-schema141",
)


def neighbour_legacy_flag(flag):
    index = LEGACY_FLAGS.index(flag)
    return (LEGACY_FLAGS[index + 1]
            if index + 1 < len(LEGACY_FLAGS) else LEGACY_FLAGS[index - 1])


def catalog_tables(version):
    """Regular public tables in one generated catalog, never a guessed list."""
    path = ROOT / "schema" / (f"{version:03d}_catalog.json")
    try:
        catalog = json.loads(path.read_text())
    except OSError as error:
        raise AssertionError(
            "catalog " + str(path) + " is unavailable; the root runner must "
            "generate it from settled PostgreSQL: " + str(error))
    tables = catalog.get("tables")
    assert isinstance(tables, list), str(path) + " has no tables list"
    return {entry["name"] for entry in tables if entry.get("kind") == "r"}


def migration_seed_counts(version):
    """Exact fixed row counts one settled migration SQL file itself seeds."""
    matches = sorted((ROOT / "migrations").glob(f"{version:03d}_*.sql"))
    if len(matches) != 1:
        raise AssertionError(
            "expected exactly one settled migration" + str(version) +
            " SQL file, found " + repr([str(path) for path in matches]))
    path = matches[0]
    try:
        sql = path.read_text()
    except OSError as error:
        raise AssertionError("settled migration" + str(version) +
                             " SQL is unavailable: " + str(error))
    pattern = re.compile(
        r"INSERT\s+INTO\s+([a-z_][a-z0-9_]*)\s*\([^;]*?\)\s*SELECT\s+"
        r"generate_series\(\s*(\d+)\s*,\s*(\d+)\s*\)", re.I | re.S)
    seeds = {}
    for table, first, last in pattern.findall(sql):
        first, last = int(first), int(last)
        assert last >= first, ("migration" + str(version) +
                               " seed range is descending for " + table)
        seeds[table] = seeds.get(table, 0) + (last - first + 1)
    return seeds


def schema141_seed_counts():
    return migration_seed_counts(141)


class LegacyArchiveHarness(BackupHarness):
    def __init__(self, args, contract):
        super().__init__(args)
        self.contract = contract
        # Parent created a disposable restore target; use it only for the
        # no-opt-in rejection.  The real restore gets another untouched pair.
        self.reject_db = self.target_db
        self.reject_data = self.target
        self.restore_db = self.new_database(self.restore_admin)
        self.restore_data = self.root / "candidate-data"
        self.source_data = self.root / "legacy-source-data"
        self.legacy_backup = self.root / ("legacy-" + str(contract.schema) + "-backup")
        self.legacy_env = self.env.copy()
        self.legacy_env.update(DATABASE_URL=self.source_db,
                               ROOTYARD_DATA_DIR=str(self.source_data))
        self.use_legacy()
        self.candidate_binary = args.binary
        self.repos = []
        self.web_cookies = None
        self.source_authority = None
        self.source_paths_digest = None
        self.source_paths_count = None
        self.source_path_list = None

    def use_legacy(self):
        self.env = self.legacy_env.copy()
        self.db = self.source_db

    def use_candidate(self, db, data):
        self.env = self.legacy_env.copy()
        self.env.update(DATABASE_URL=db, ROOTYARD_DATA_DIR=str(data))
        self.db = db

    def http_raw(self, path, method="GET", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read(), response.getheaders()
        finally:
            conn.close()

    @staticmethod
    def response_header(headers, name):
        for key, value in headers:
            if key.lower() == name.lower():
                return value
        return None

    @staticmethod
    def split_cookies(headers):
        cookies = {}
        for key, value in headers:
            if key.lower() == "set-cookie":
                name, first = value.split(";", 1)[0].split("=", 1)
                cookies[name] = first
        return cookies

    @staticmethod
    def cookie_header(cookies):
        return "; ".join(f"{key}={value}" for key, value in cookies.items())

    def create_web_session(self):
        fields = urllib.parse.urlencode({"username": "alice",
                                         "token": self.alice["token"]})
        status, _, headers = self.http_raw(
            "/web/login", "POST", fields,
            {"Content-Type": "application/x-www-form-urlencoded",
             "Origin": self.base})
        assert status == 303, f"web login status {status}"
        cookies = self.split_cookies(headers)
        assert cookies.get("rootyard_session", "").startswith("ryt_")
        assert cookies.get("rootyard_csrf")
        self.secrets.extend(cookies.values())
        self.web_cookies = cookies
        assert self.sql("SELECT count(*) FROM web_sessions WHERE NOT revoked") == "1"
        assert self.sql("SELECT count(*) FROM tokens WHERE kind='browser'") == "1"
        return dict(web_session_created=True, browser_token_created=True)

    def repo_setup(self, name):
        repo = json.loads(self.expect("/api/repos", 201, token=self.alice,
                                      method="POST", body={"name": name}))
        remote = self.base + repo["clone_path"]
        work = self.root / (name + "-work")
        self.git("init", "--initial-branch=main", str(work))
        self.git("config", "user.name", "Legacy " + self.contract.source_label, cwd=work)
        self.git("config", "user.email", "legacy" + str(self.contract.schema) + "@example.invalid", cwd=work)
        self.git("remote", "add", "origin", remote, cwd=work)
        content = self.contract.source_label + " pando source for " + name + "\n"
        (work / (name + ".txt")).write_text(content)
        self.git("add", name + ".txt", cwd=work)
        self.git("commit", "-m", self.contract.source_label + " " + name, cwd=work)
        head = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work,
                 token=self.alice)
        refs = self.parse_heads(self.git(
            "ls-remote", "--heads", remote, token=self.alice).stdout)
        assert refs == {"refs/heads/main": head}
        return dict(name=name, id=repo["id"], clone_path=repo["clone_path"],
                    remote=remote, work=work, head=head, refs=refs,
                    content=content)

    @staticmethod
    def parse_heads(output):
        refs = {}
        for line in output.decode().splitlines():
            oid, ref = line.split("\t", 1)
            refs[ref] = oid
        return refs

    def pando_closure(self, db, label):
        authority = self.query(
            db, "SELECT authority_id FROM pando_storage_authorities WHERE singleton")
        paths = self.query(
            db, "SELECT remote_path FROM pando_remote_artifacts "
                "WHERE state <> 'deleted' ORDER BY remote_path")
        path_list = paths.splitlines() if paths else []
        result = dict(
            label=label,
            authority_id=authority,
            remote_paths_count=len(path_list),
            remote_paths_sha256=hashlib.sha256(
                "\n".join(path_list).encode()).hexdigest(),
            manifests=int(self.query(
                db, "SELECT count(*) FROM pando_pack_manifests")),
        )
        return result, path_list

    def assert_source_closure(self):
        self.use_legacy()
        manifest, paths = self.pando_closure(self.source_db, "source")
        assert manifest["manifests"] == len(self.repos), manifest
        assert manifest["remote_paths_count"] >= 4 * len(self.repos), manifest
        for repo in self.repos:
            condition = "repository_id='" + repo["id"] + "'"
            assert self.query(
                self.source_db,
                "SELECT r.storage_backend || '/' || cardinality(s.pack_ids)::text "
                "|| '/' || s.head_ref FROM pando_repository_states s "
                "JOIN repositories r ON r.id=s.repository_id WHERE s." +
                condition) == "pando/1/refs/heads/main"
            refs = {}
            rows = self.query(
                self.source_db,
                "SELECT ref_name || '\t' || oid::text FROM pando_refs WHERE " +
                condition + " ORDER BY ref_name")
            for row in rows.splitlines():
                name, oid = row.split("\t", 1)
                refs[name] = oid
            assert refs == repo["refs"], (repo["name"], refs)
            assert self.query(
                self.source_db,
                "SELECT count(*) FROM pando_manifest_artifacts WHERE " +
                condition) == "4"
        self.source_authority = manifest["authority_id"]
        self.source_paths_digest = manifest["remote_paths_sha256"]
        self.source_paths_count = manifest["remote_paths_count"]
        self.source_path_list = paths
        return manifest, paths

    def create_real_source(self):
        self.use_legacy()
        self.args.binary = self.args.legacy_binary
        self.cli("migrate")
        self.alice = self.account("create-user", "alice")
        self.reader = self.account("create-token", "alice", "--read-only")
        self.start()
        for name in ("alpha", "beta"):
            self.repos.append(self.repo_setup(name))
        session = self.create_web_session()
        self.stop()
        cutovers = {}
        for repo in self.repos:
            report = json.loads(self.cli(
                "pando-transition", "cutover", "--repository", repo["id"]))
            assert report["direction"] == "gitfs_to_pando", report
            assert report["new_storage_backend"] == "pando", report
            cutovers[repo["name"]] = dict(
                refs=int(report["refs"]), packs=int(report["packs"]),
                objects_verified=int(report["objects_verified"]))
        manifest, _ = self.assert_source_closure()
        return dict(
            source_heads={repo["name"]: repo["head"] for repo in self.repos},
            source_refs={repo["name"]: repo["refs"] for repo in self.repos},
            source_authority_id=self.source_authority,
            source_remote_paths_count=self.source_paths_count,
            source_remote_paths_sha256=self.source_paths_digest,
            cutovers=cutovers, **session)

    def legacy_archive(self):
        self.use_legacy()
        self.args.binary = self.args.legacy_binary
        self.stop()
        result = json.loads(self.run(
            [self.args.legacy_binary, "backup", str(self.legacy_backup),
             "--offline"], env=self.env).stdout)
        manifest = json.loads(
            (self.legacy_backup / "manifest.json").read_text())
        legacy_sha = hashlib.sha256(
            Path(self.args.legacy_binary).read_bytes()).hexdigest()
        assert manifest["format"] == self.contract.format, manifest["format"]
        assert manifest["schema_versions"][-1] == self.contract.schema, manifest["schema_versions"]
        assert self.contract.schema + 1 not in manifest["schema_versions"]
        assert manifest["binary_sha256"] == legacy_sha
        assert result["complete"] is True
        self.run([self.args.legacy_binary, "backup-verify",
                  str(self.legacy_backup)], env=self.env)
        self.assert_source_closure()
        return dict(format=manifest["format"],
                    schema_last=manifest["schema_versions"][-1],
                    schema_contains_next=False,
                    repository_count=len(manifest["repositories"]),
                    legacy_binary_sha256=legacy_sha,
                    backup_verified=True)

    def candidate_cli_usage_errors(self):
        self.use_candidate(self.reject_db, self.reject_data)
        self.args.binary = self.candidate_binary
        missing = self.run([self.candidate_binary, "restore"],
                           env=self.env, check=False)
        assert missing.returncode != 0
        assert b"usage:" in missing.stderr, missing.stderr[-400:]
        no_archive_flags = self.run(
            [self.candidate_binary, "restore", str(self.legacy_backup)],
            env=self.env, check=False)
        assert no_archive_flags.returncode != 0
        assert b"usage:" in no_archive_flags.stderr, no_archive_flags.stderr[-400:]
        other = neighbour_legacy_flag(self.contract.flag)
        # The candidate's own usage line must document this contract's opt-in
        # (and its adjacent one), so the drill cannot pass against a binary that
        # silently lacks the flag.
        assert self.contract.flag.encode() in missing.stderr, missing.stderr[-1200:]
        assert other.encode() in missing.stderr, missing.stderr[-1200:]
        mixed = self.run(
            [self.candidate_binary, "restore", str(self.legacy_backup),
             "--isolated", "--trust-backup", self.contract.flag, other],
            env=self.env, check=False)
        assert mixed.returncode != 0
        assert b"usage:" in mixed.stderr, mixed.stderr[-400:]
        assert not self.reject_data.exists()
        return dict(missing_arguments_usage=True, missing_flags_usage=True,
                    mixed_legacy_flags_usage=True,
                    documented_opt_in=self.contract.flag,
                    documented_neighbour_opt_in=other)

    def candidate_rejects_without_opt_in(self):
        self.use_candidate(self.reject_db, self.reject_data)
        self.args.binary = self.candidate_binary
        result = self.run(
            [self.candidate_binary, "restore", str(self.legacy_backup),
             "--isolated", "--trust-backup"], env=self.env, check=False)
        assert result.returncode != 0
        wrong = neighbour_legacy_flag(self.contract.flag)
        mismatched = self.run(
            [self.candidate_binary, "restore", str(self.legacy_backup),
             "--isolated", "--trust-backup", wrong], env=self.env, check=False)
        assert mismatched.returncode != 0
        assert b"usage:" not in mismatched.stderr, mismatched.stderr[-400:]
        assert not self.reject_data.exists()
        guard = self.reject_data.parent / (
            "." + self.reject_data.name + ".rootyard-restoring")
        assert not guard.exists()
        objects = self.query(
            self.reject_db,
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n "
            "ON n.oid=c.relnamespace WHERE n.nspname NOT IN "
            "('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'")
        assert objects == "0", objects
        return dict(explicit_schema_opt_in_required=True,
                    mismatched_legacy_opt_in_rejected=True,
                    target_data_published=False, target_database_empty=True)

    def assert_core_schema(self):
        """The migrated target must carry the complete schema139 core schema.

        Every genuine format8 through format15 source has no RefStore core rows
        (and older sources have no core tables at all), so migration139 must
        create the gates/refs/events tables, the current-ref CAS key, the
        operation FK and the immutable-event trigger while leaving every core
        table empty.  This fixture does not assert the schema140 snapshot
        tables added by migration 140 or the schema141 artifact-hold ledger; a
        populated current-schema backrestore qualification is separate.
        """
        tables = self.query(
            self.restore_db,
            "SELECT string_agg(tablename, ',' ORDER BY tablename) FROM pg_tables "
            "WHERE schemaname='public' AND tablename IN ('" +
            "','".join(SCHEMA139_CORE_TABLES) + "')")
        assert tables == ",".join(sorted(SCHEMA139_CORE_TABLES)), tables
        refs_key = self.query(
            self.restore_db,
            "SELECT string_agg(a.attname, ',' ORDER BY a.attnum) FROM pg_constraint k "
            "JOIN pg_class c ON c.oid=k.conrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum = ANY(k.conkey) "
            "WHERE n.nspname='public' AND c.relname='ref_store_core_refs' "
            "AND k.contype='p' AND k.convalidated")
        assert refs_key == "repository_id,ref_name", refs_key
        event_fk = self.query(
            self.restore_db,
            "SELECT count(*) FROM pg_constraint k "
            "JOIN pg_class c ON c.oid=k.conrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='public' AND c.relname='ref_store_core_events' "
            "AND k.contype='f' AND k.convalidated "
            "AND k.confrelid = 'ref_store_operations'::regclass")
        assert event_fk == "1", event_fk
        triggers = self.query(
            self.restore_db,
            "SELECT string_agg(t.tgname || ':' || c.relname || ':' || "
            "t.tgtype::text || ':' || CASE WHEN (t.tgtype & 2) <> 0 THEN 'before' "
            "WHEN (t.tgtype & 64) <> 0 THEN 'instead' ELSE 'after' END || ':' || "
            "p.proname, ',' ORDER BY t.tgname) FROM pg_trigger t "
            "JOIN pg_class c ON c.oid=t.tgrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_proc p ON p.oid=t.tgfoid WHERE n.nspname='public' "
            "AND NOT t.tgisinternal AND c.relname IN ('" +
            "','".join(SCHEMA139_CORE_TABLES) + "')")
        mode_fence = self.contract.target_schema >= 142
        expected_trigger = (SCHEMA139_CORE_TRIGGER +
                            ":ref_store_core_events:19:before:" +
                            SCHEMA139_CORE_TRIGGER_FUNCTION)
        if mode_fence:
            # Only the current schema142 target adds this guard; it is part of
            # the exact expected set, so any other extra trigger still fails.
            expected_trigger += ("," + SCHEMA142_CORE_TRIGGER +
                                 ":ref_store_core_gates:19:before:" +
                                 SCHEMA142_CORE_TRIGGER_FUNCTION)
        assert triggers == expected_trigger, triggers
        mode_fence_enabled = self.query(
            self.restore_db,
            "SELECT count(*) FROM pg_trigger WHERE tgname='" +
            SCHEMA142_CORE_TRIGGER + "' AND tgenabled='O'")
        assert mode_fence_enabled == ("1" if mode_fence else "0"), mode_fence_enabled
        rows = self.query(
            self.restore_db,
            "SELECT (SELECT count(*) FROM ref_store_core_gates)::text || '/' || "
            "(SELECT count(*) FROM ref_store_core_refs)::text || '/' || "
            "(SELECT count(*) FROM ref_store_core_events)::text")
        assert rows == "0/0/0", rows
        return dict(schema139_core_tables=len(SCHEMA139_CORE_TABLES),
                    schema139_core_refs_key=refs_key,
                    schema139_core_event_operation_fkey=True,
                    schema139_core_event_immutable_trigger=True,
                    schema142_core_gate_pack_mode_fence=mode_fence,
                    schema142_core_gate_pack_mode_fence_enabled=mode_fence_enabled == "1",
                    schema139_core_rows=rows,
                    genuine_legacy_source_had_core_rows=False)

    def assert_holds_schema(self):
        """Verify the schema141 ledger from current catalogs and settled SQL.

        A genuine format8 through format16 source carries no new hold rows.
        The table names come from the generated current-vs-schema140 catalog
        difference, never a guessed list.  Any row count is taken from a fixed
        seed in the settled migration141 SQL itself; the fixture inserts no
        hold, request or consumption row and invents no quota value.
        """
        assert self.contract.target_schema >= 141, self.contract.target_schema
        # The schema141 hold ledger is exactly the 141-vs-140 catalog delta,
        # independent of whatever newer schema the current target carries.
        current = catalog_tables(141)
        prior = catalog_tables(140)
        new_tables = current - prior
        assert new_tables, ("the current catalog adds no schema141 table; root "
                            "must regenerate it from settled PostgreSQL")
        for name in new_tables:
            assert re.fullmatch(r"[a-z_][a-z0-9_]*", name), name
        categories = {
            "hold_requests": sorted(n for n in new_tables if "request" in n),
            "holds": sorted(n for n in new_tables
                            if "hold" in n and not any(
                                key in n for key in ("request", "consume",
                                                     "receipt", "shard",
                                                     "usage"))),
            "consumption": sorted(n for n in new_tables
                                  if "consume" in n or "receipt" in n),
            "quota": sorted(n for n in new_tables
                            if "quota" in n or "usage" in n or "shard" in n),
        }
        assert categories["hold_requests"], new_tables
        assert categories["holds"], new_tables
        assert categories["consumption"], new_tables
        present = self.query(
            self.restore_db,
            "SELECT COALESCE(string_agg(tablename, ',' ORDER BY tablename), '')"
            " FROM pg_tables WHERE schemaname='public' AND tablename IN ('" +
            "','".join(sorted(new_tables)) + "')")
        assert set(filter(None, present.split(","))) == new_tables, present
        seeds = schema141_seed_counts()
        assert set(seeds) <= new_tables, (seeds, new_tables)
        counts = {
            name: int(self.query(
                self.restore_db,
                'SELECT count(*) FROM public."' + name + '"'))
            for name in sorted(new_tables)
        }
        expected = {name: seeds.get(name, 0) for name in new_tables}
        assert counts == expected, (counts, expected)
        return dict(
            schema141_new_tables=sorted(new_tables),
            schema141_hold_request_tables=categories["hold_requests"],
            schema141_hold_tables=categories["holds"],
            schema141_consumption_tables=categories["consumption"],
            schema141_seeded_rows={name: counts[name] for name in sorted(seeds)},
            schema141_new_tables_empty_except_migration_seed=True,
            schema141_hold_rows_fabricated=False)

    def assert_pack_ledger_schema(self):
        """Verify the schema142 pack ledger without fabricating a pack row.

        A genuine format8 through format17 source carries no A4 pack
        registration, artifact, membership, history or usage row.  The table
        names come from the generated 142-vs-141 catalog difference, never a
        guessed list.  Any row count is taken from a fixed seed in the settled
        migration142 SQL itself; normally there is none, so every pack table
        must be empty.  The schema141 shard seed and counters must be unchanged.
        """
        assert self.contract.target_schema >= 142, self.contract.target_schema
        new_tables = catalog_tables(142) - catalog_tables(141)
        assert new_tables, ("the current catalog adds no schema142 table; root "
                            "must regenerate it from settled PostgreSQL")
        for name in new_tables:
            assert re.fullmatch(r"[a-z_][a-z0-9_]*", name), name
        categories = {
            "registration": sorted(n for n in new_tables
                                   if "publication" in n or "artifact" in n),
            "membership": sorted(n for n in new_tables if "membership" in n),
            "history": sorted(n for n in new_tables if "history" in n),
            "usage": sorted(n for n in new_tables if "usage" in n),
        }
        for category, names in categories.items():
            assert names, (category, new_tables)
        present = self.query(
            self.restore_db,
            "SELECT COALESCE(string_agg(tablename, ',' ORDER BY tablename), '')"
            " FROM pg_tables WHERE schemaname='public' AND tablename IN ('" +
            "','".join(sorted(new_tables)) + "')")
        assert set(filter(None, present.split(","))) == new_tables, present
        seeds = migration_seed_counts(142)
        assert set(seeds) <= new_tables, (seeds, new_tables)
        counts = {
            name: int(self.query(
                self.restore_db,
                'SELECT count(*) FROM public."' + name + '"'))
            for name in sorted(new_tables)
        }
        expected = {name: seeds.get(name, 0) for name in new_tables}
        assert counts == expected, (counts, expected)
        assert all(value == 0 for value in counts.values()), counts
        pack_mode = self.query(
            self.restore_db,
            "SELECT string_agg(column_name || ':' || data_type || ':' || "
            "is_nullable || ':' || coalesce(column_default,''), ',' ORDER BY "
            "column_name) FROM information_schema.columns WHERE "
            "table_schema='public' AND table_name='ref_store_core_gates' "
            "AND column_name='pack_mode'")
        assert pack_mode == "pack_mode:text:NO:'metadata_only'::text", pack_mode
        gate_modes = self.query(
            self.restore_db,
            "SELECT string_agg(DISTINCT pack_mode, ',' ORDER BY pack_mode) "
            "FROM ref_store_core_gates")
        # Genuine CLI producers have no unserved RefStore gates. The column
        # contract above proves the new default even when this aggregate is
        # empty; do not fabricate a gate to exercise an otherwise empty ledger.
        if not gate_modes:
            assert self.query(self.restore_db, "SELECT count(*) FROM ref_store_core_gates") == "0"
        else:
            assert gate_modes == "metadata_only", gate_modes
        shards = self.query(
            self.restore_db,
            "SELECT count(*) FROM artifact_hold_shards WHERE shard_id BETWEEN "
            "0 AND 63 AND hold_count=0 AND declared_bytes=0 AND "
            "logical_bytes=0 AND receipt_count=0")
        assert shards == "64", shards
        return dict(
            schema142_new_tables=sorted(new_tables),
            schema142_registration_tables=categories["registration"],
            schema142_membership_tables=categories["membership"],
            schema142_history_tables=categories["history"],
            schema142_usage_tables=categories["usage"],
            schema142_new_tables_empty_except_migration_seed=not seeds,
            schema142_gate_pack_mode_default="metadata_only",
            schema142_active_pack_membership_fabricated=False,
            schema141_shard_seed_unchanged=True)

    def candidate_restores_and_rotates_authority(self):
        self.use_candidate(self.restore_db, self.restore_data)
        self.args.binary = self.candidate_binary
        self.run([self.candidate_binary, "restore",
                  str(self.legacy_backup), "--isolated", "--trust-backup",
                  self.contract.flag], env=self.env)
        last = self.query(
            self.restore_db, "SELECT max(version) FROM schema_migrations")
        assert last == str(self.contract.target_schema), last
        if self.contract.target_schema >= 138:
            registry_tables = self.query(
                self.restore_db,
                "SELECT count(*) FROM pg_tables WHERE schemaname='public' "
                "AND tablename IN ('ref_store_operations','ref_store_cancellations','ref_store_issuer_lanes')")
            assert registry_tables == "3", registry_tables
        core = {}
        if self.contract.target_schema >= 139:
            core = self.assert_core_schema()
        holds = {}
        if self.contract.target_schema >= 141:
            holds = self.assert_holds_schema()
        packs = {}
        if self.contract.target_schema >= 142:
            packs = self.assert_pack_ledger_schema()
        names = self.query(
            self.restore_db,
            "SELECT string_agg(indexname, ',' ORDER BY indexname) FROM pg_indexes "
            "WHERE schemaname='public' AND indexname IN ('" +
            "','".join(self.contract.indexes) + "')")
        assert names and sorted(names.split(",")) == sorted(
            self.contract.indexes), names
        constraints = self.query(
            self.restore_db,
            "SELECT string_agg(conname::text || ':' || contype::text || ':' || "
            "convalidated::text, ',' ORDER BY conname) FROM pg_constraint k "
            "JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n "
            "ON n.oid=c.relnamespace WHERE n.nspname='public' AND conname IN ('" +
            "','".join(self.contract.foreign_keys + self.contract.unique_constraints) + "')")
        expected_constraints = sorted(
            [name + ":f:true" for name in self.contract.foreign_keys] +
            [name + ":u:true" for name in self.contract.unique_constraints])
        assert constraints and sorted(constraints.split(",")) == expected_constraints, constraints
        removed = self.query(
            self.restore_db,
            "SELECT count(*) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' "
            "AND conname='" + self.contract.removed_foreign_key + "'")
        assert removed == "0", removed
        token_columns = self.query(
            self.restore_db,
            "SELECT string_agg(column_name || ':' || data_type || ':' || "
            "is_nullable || ':' || coalesce(column_default,''), ',' ORDER BY "
            "column_name) FROM information_schema.columns WHERE "
            "table_schema='public' AND table_name='tokens' AND column_name IN "
            "('is_restricted','scope_version','display_name')")
        expected_token_columns = ('display_name:text:YES:,'
                                  'is_restricted:boolean:NO:false,'
                                  'scope_version:bigint:NO:1')
        assert token_columns == expected_token_columns, token_columns
        scope_tables = self.query(
            self.restore_db,
            "SELECT string_agg(table_name, ',' ORDER BY table_name) FROM "
            "information_schema.tables WHERE table_schema='public' AND "
            "table_name IN ('token_repository_scopes',"
            "'token_namespace_scopes')")
        assert scope_tables == ('token_namespace_scopes,'
                                'token_repository_scopes'), scope_tables
        assert self.query(
            self.restore_db,
            "SELECT count(*) FROM tokens WHERE is_restricted") == "0"
        authority = self.query(
            self.restore_db,
            "SELECT authority_id FROM pando_storage_authorities WHERE singleton")
        assert authority != self.source_authority, (authority, self.source_authority)
        assert self.query(
            self.restore_db, "SELECT count(*) FROM pando_storage_authorities") == "1"
        links = int(self.query(
            self.restore_db, "SELECT count(*) FROM pando_manifest_artifacts"))
        assert links == 4 * len(self.repos), links
        assert self.query(
            self.restore_db,
            "SELECT count(DISTINCT authority_id) FROM pando_manifest_artifacts") == "1"
        assert self.query(
            self.restore_db,
            "SELECT count(*) FROM pando_manifest_artifacts WHERE authority_id <> "
            "(SELECT authority_id FROM pando_storage_authorities WHERE singleton)") == "0"
        assert self.query(
            self.restore_db,
            "SELECT count(DISTINCT authority_id) FROM pando_remote_artifacts") == "1"
        assert self.query(
            self.restore_db,
            "SELECT count(*) FROM pando_remote_artifacts WHERE authority_id <> "
            "(SELECT authority_id FROM pando_storage_authorities WHERE singleton)") == "0"
        target, target_paths = self.pando_closure(self.restore_db, "target")
        assert target["authority_id"] == authority
        assert target["manifests"] == len(self.repos), target
        assert target["remote_paths_count"] >= 4 * len(self.repos), target
        assert set(target_paths).isdisjoint(self.source_path_list)
        for repo in self.repos:
            condition = "repository_id='" + repo["id"] + "'"
            assert self.query(
                self.restore_db,
                "SELECT head_ref FROM pando_repository_states WHERE " +
                condition) == "refs/heads/main"
            assert self.query(
                self.restore_db,
                "SELECT count(*) FROM pando_manifest_artifacts WHERE " +
                condition) == "4"
        revoked_sessions = self.query(
            self.restore_db, "SELECT count(*) FROM web_sessions WHERE revoked")
        revoked_browser = self.query(
            self.restore_db,
            "SELECT count(*) FROM tokens WHERE kind='browser' AND revoked")
        assert revoked_sessions == "1", revoked_sessions
        assert revoked_browser == "1", revoked_browser
        return dict(**core, **holds, **packs, schema_version=int(last),
                    target_format=self.contract.target_format,
                    indexes=len(self.contract.indexes),
                    schema134_identity_constraints=True,
                    schema135_metrics_index=True,
                    schema136_token_scope_schema=True,
                    schema138_operation_registry=True,
                    legacy_tokens_default_unrestricted=True,
                    target_authority_id=authority,
                    target_authority_differs_from_source=True,
                    target_manifest_artifacts=links,
                    target_authority_singleton_unique=True,
                    target_remote_paths_count=target["remote_paths_count"],
                    source_and_target_remote_paths_disjoint=True,
                    browser_session_revoked=True, browser_token_revoked=True)

    def restored_service_and_git(self):
        self.use_candidate(self.restore_db, self.restore_data)
        self.args.binary = self.candidate_binary
        self.start()
        repos = json.loads(self.expect("/api/repos", 200, token=self.alice))
        assert sorted(repo["name"] for repo in repos) == sorted(
            repo["name"] for repo in self.repos)
        # The API credential survives; the pre-backup browser cookie does not.
        assert self.web_cookies
        cookie = self.cookie_header(self.web_cookies)
        status, _, headers = self.http_raw(
            "/web/repos", headers={"Cookie": cookie})
        assert status in (303, 401), status
        if status == 303:
            location = self.response_header(headers, "Location") or ""
            assert location.startswith("/web/login"), location
        status, _, _ = self.http_raw(
            "/api/repos", headers={
                "Authorization": "Bearer " + self.web_cookies["rootyard_session"]})
        assert status == 401, status
        clones = []
        for repo in self.repos:
            clone = self.root / ("restored-" + repo["name"])
            self.git("clone", self.base + repo["clone_path"], str(clone),
                     token=self.alice)
            assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == repo["head"]
            assert (clone / (repo["name"] + ".txt")).read_text() == repo["content"]
            self.git("fsck", "--full", "--strict", cwd=clone)
            clones.append(clone)
        # The second repository shares the one new authority.  Fetching the
        # first again after both restores/clones proves it was not reset.
        self.git("fetch", "origin", cwd=clones[0], token=self.alice)
        assert self.git("rev-parse", "HEAD", cwd=clones[0]).stdout.decode().strip() == self.repos[0]["head"]
        self.git("fsck", "--full", "--strict", cwd=clones[0])
        authority = self.query(
            self.restore_db,
            "SELECT authority_id FROM pando_storage_authorities WHERE singleton")
        assert self.query(
            self.restore_db,
            "SELECT count(DISTINCT authority_id) FROM pando_manifest_artifacts") == "1"
        assert self.query(
            self.restore_db,
            "SELECT count(*) FROM pando_manifest_artifacts WHERE authority_id='" +
            authority + "'") == str(4 * len(self.repos))
        self.stop()
        return dict(api_token_readable=True, old_browser_cookie_rejected=True,
                    old_browser_bearer_rejected=True,
                    git_clones=len(clones), clone_heads_exact=True,
                    clone_contents_exact=True, fsck_clean=True,
                    first_repo_refetch_after_second_ok=True,
                    sole_target_authority_unchanged=True)

    def source_remains_available(self):
        self.use_legacy()
        self.args.binary = self.args.legacy_binary
        manifest, _ = self.pando_closure(self.source_db, "source_after_restore")
        assert manifest["authority_id"] == self.source_authority
        assert manifest["remote_paths_count"] == self.source_paths_count
        assert manifest["remote_paths_sha256"] == self.source_paths_digest
        # Re-open the original legacy deployment and clone the source itself,
        # proving the source authority's remote objects are still readable.
        self.start()
        for repo in self.repos:
            clone = self.root / ("source-recheck-" + repo["name"])
            self.git("clone", repo["remote"], str(clone), token=self.alice)
            assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == repo["head"]
            assert (clone / (repo["name"] + ".txt")).read_text() == repo["content"]
            self.git("fsck", "--full", "--strict", cwd=clone)
        self.stop()
        after, _ = self.pando_closure(self.source_db, "source_after_recheck")
        assert after["authority_id"] == self.source_authority
        assert after["remote_paths_count"] >= self.source_paths_count, after
        return dict(source_authority_unchanged=True,
                    source_remote_paths_unchanged=True,
                    source_remote_paths_count=self.source_paths_count,
                    source_remote_paths_sha256=self.source_paths_digest,
                    source_clone_heads_exact=True, source_clone_contents_exact=True,
                    source_git_fsck_clean=True)

    def cleanup(self):
        self.stop()
        for admin, name in reversed(self.created):
            self.query(admin, 'DROP DATABASE "' + name + '" WITH (FORCE)')
        self.created = []
        if not self.args.keep:
            shutil.rmtree(self.root, ignore_errors=True)


def harness_git_head():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parent.parent,
            stderr=subprocess.DEVNULL, text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def run_main(contract=None, argv=None):
    contract = contract or LEGACY132
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--legacy-binary", required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args(argv)
    candidate = str(Path(args.binary).resolve())
    legacy = str(Path(args.legacy_binary).resolve())
    if not Path(candidate).is_file():
        parser.error("candidate --binary is not a file")
    if not Path(legacy).is_file():
        parser.error("--legacy-binary is not a file")
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        parser.error("missing required environment names: " + ", ".join(missing))
    args.binary = candidate
    args.legacy_binary = legacy
    harness = LegacyArchiveHarness(args, contract)
    success = False
    try:
        harness.case("create_real_" + contract.source_label + "_pando_source",
                     harness.create_real_source)
        harness.case("legacy_binary_writes_format" + str(contract.format) +
                     "_schema" + str(contract.schema) + "_archive",
                     harness.legacy_archive)
        harness.case("candidate_cli_usage_and_mixed_legacy_flags",
                     harness.candidate_cli_usage_errors)
        harness.case("candidate_rejects_without_schema" + str(contract.schema) +
                     "_opt_in", harness.candidate_rejects_without_opt_in)
        harness.case("candidate_restores_schema" + str(contract.target_schema) +
                     "_one_new_authority",
                     harness.candidate_restores_and_rotates_authority)
        harness.case("restored_service_git_and_session_boundaries",
                     harness.restored_service_and_git)
        harness.case("source_authority_and_remote_objects_remain_available",
                     harness.source_remains_available)
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(dict(name="cleanup", status="failed",
                                        error=harness.redact(error)))
            success = False
        report = dict(
            passed=success, cases=harness.results,
            reviewed_target_schema=contract.target_schema,
            reviewed_target_format=contract.target_format,
            binary_sha256=hashlib.sha256(Path(candidate).read_bytes()).hexdigest(),
            legacy_binary_sha256=hashlib.sha256(Path(legacy).read_bytes()).hexdigest(),
            harness_git_head=harness_git_head(),
            limitations=[
                "Loopback functional drill; no production RPO/RTO or power-loss claim.",
                "The legacy archive is produced by the trusted format" + str(contract.format) + " binary and is never edited.",
                "source_head values are repository heads, not binary build provenance.",
                "Genuine format" + str(contract.format) + "/schema" +
                str(contract.schema) + " sources carry no ref-store core rows; the "
                "migrated schema139 core tables are verified present, constrained "
                "and empty, not round-tripped.",
                "No schema140 snapshot/pin table or row assertion is made; that "
                "populated current-format qualification follows the primary "
                "migration-140 SQL.",
                "The schema141 ledger tables are derived from the generated "
                "current-vs-140 catalogs and are verified present with only the "
                "exact fixed rows seeded by the settled migration141 SQL; this "
                "fixture inserts no hold, request or consumption row.",
                "The schema142 pack-registration/membership/history/usage "
                "tables are derived from the generated 142-vs-141 catalogs and "
                "must stay empty on a genuine pre-142 source; this fixture "
                "inserts no pack row and claims no pack-verified gate.",
                "A format16 drill requires root to supply the genuine retained "
                "old schema140 producer and its archive; a format17 drill "
                "requires the genuine retained schema141 producer; this "
                "harness never fabricates or relabels one.",
            ])
        if args.keep:
            report["retained_directory"] = str(harness.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


def main():
    return run_main(LEGACY132)


if __name__ == "__main__":
    sys.exit(main())
