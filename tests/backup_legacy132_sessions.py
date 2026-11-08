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
current reviewed target: format19/schema143.

``backup_legacy133_identity.py`` through ``backup_legacy142_pack_snapshots.py`` reuse this
harness with the format9/schema133 through format18/schema142 contracts and
assert the same Pando/session/Git boundaries, the frozen source contract and the
reviewed current migration target.  A genuine format8 through format18 archive
carries no RefStore core rows for this fixture, so the schema139 core tables are
verified to exist, be correctly constrained and stay empty; this harness never
claims a core-row roundtrip and does not assert the schema140 snapshot tables
that migration 140 introduces.  It also verifies that the schema141 global
artifact-hold tables exist and stay empty except for an exact fixed global shard
seed if the settled migration SQL inserts one, that the schema142 pack registration/membership/history/usage tables exist, and
that the schema143 pack-snapshot binding/history/permanent-usage tables exist
and stay empty; no hold, pack or A5 snapshot-pin row is fabricated.

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
# genuine historical producer keeps its frozen source schema, but the current
# reviewed restore target is schema143 and legitimately carries both the
# immutable-event trigger and this mode fence.
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


def _uuid_text(value):
    """Canonical text form of a UUID, rejecting anything else."""
    import uuid
    return str(uuid.UUID(str(value)))


@dataclass(frozen=True)
class ArchiveContract:
    """The frozen source format plus the reviewed target schema it upgrades to."""
    format: int
    schema: int
    flag: str
    source_label: str
    target_schema: int = 143
    target_format: int = 19
    indexes: tuple = SCHEMA139_INDEXES
    foreign_keys: tuple = SCHEMA134_FOREIGN_KEYS
    unique_constraints: tuple = SCHEMA134_UNIQUE
    removed_foreign_key: str = SCHEMA134_REMOVED_FOREIGN_KEY


LEGACY132 = ArchiveContract(format=8, schema=132, flag="--allow-legacy-schema132",
                            source_label="schema132", target_schema=143,
                            indexes=SCHEMA139_INDEXES)
LEGACY133 = ArchiveContract(format=9, schema=133, flag="--allow-legacy-schema133",
                            source_label="schema133", target_schema=143,
                            indexes=SCHEMA139_INDEXES)
# Format10/schema134 is an older frozen contract.  Its archive upgrades through
# the same reviewed path to the current schema143/format19 target.
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
# migrations to schema143; earlier core rows stay empty on this fixture and no
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
# format19/schema143 target.  Root supplies the real retained old producer and
# archive (the native raw producer binary is retained outside this worktree);
# this harness never manufactures, edits or relabels one.  The source has no
# schema142 pack ledger rows, so the migrated tables are inspected empty against
# the current catalog instead of being populated by a fake fixture.
LEGACY141 = replace(LEGACY140, format=17, schema=141,
                    flag="--allow-legacy-schema141", source_label="schema141")
# Genuine format18/schema142 archive: the immediate predecessor of this
# format19/schema143 target.  Root supplies the real retained A4 producer and
# archive (the binary is retained outside this worktree); this harness never
# manufactures, edits or relabels one.  The source has no schema143 pack
# snapshot binding/history/permanent-usage row, so migration 143 must add the
# four new tables empty and leave every old A2 snapshot row at the default
# metadata-only/unavailable shape while preserving the complete schema142
# pack/A3 ledger rows and all schema142 columns exactly.
LEGACY142 = replace(LEGACY141, format=18, schema=142,
                    flag="--allow-legacy-schema142", source_label="schema142")

# Every legacy opt-in this shared harness knows about, oldest first.  The
# adjacent entry is used for the mixed-flag and mismatched-opt-in rejections.
LEGACY_FLAGS = (
    "--allow-legacy-schema132", "--allow-legacy-schema133",
    "--allow-legacy-schema134", "--allow-legacy-schema135",
    "--allow-legacy-schema136", "--allow-legacy-schema137",
    "--allow-legacy-schema138", "--allow-legacy-schema139",
    "--allow-legacy-schema140", "--allow-legacy-schema141",
    "--allow-legacy-schema142",
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


def schema_delta(version):
    """Exact catalog delta introduced by one settled migration."""
    return tuple(sorted(catalog_tables(version) - catalog_tables(version - 1)))


def schema143_pack_snapshot_tables():
    """A5a binding/history/permanent-usage tables; never a guessed list."""
    tables = schema_delta(143)
    assert tables, ("the 143 catalog adds no A5 pack-snapshot table; root "
                    "must regenerate it from settled PostgreSQL")
    return tables


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
        # Exact pre-upgrade rows of every older RefStore ledger that the source
        # schema actually carries.  None means the source predates that ledger,
        # so the migration must create it empty (except a settled migration seed).
        self.source_core_rows = None
        self.source_snapshot_rows = None
        self.source_hold_rows = None
        self.source_pack_rows = None
        # OPTIONAL retained-A4 fixture hook.  It stays None for every legacy
        # entrypoint older than schema142 (and for a format18 drill without the
        # selected old helper), so existing genuine17/16/15 drills are unchanged
        # and remain no-op.
        self.legacy_fixture_binary = getattr(args, "legacy_fixture_binary", None)
        self.legacy_fixture_receipt = getattr(args, "legacy_fixture_receipt", None)
        self.legacy_pack_helper = None
        self.legacy_pack_marker = None

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

    A5_SNAPSHOT_COLUMNS = ("pack_mode", "pack_count", "membership_digest",
                           "snapshot_digest")

    def table_rows(self, db, tables, drop=()):
        """Exact immutable ledger rows, optionally without added A5 columns."""
        rows = {}
        for name in sorted(tables):
            expression = "to_jsonb(t)"
            for column in drop:
                expression += " - '" + column + "'"
            output = self.query(
                db,
                "SELECT COALESCE(json_agg(" + expression + " ORDER BY " +
                expression + "::text), '[]'::json) FROM public." + '"' + name + '"' + " t")
            rows[name] = json.loads(output)
        return rows

    def capture_source_ledgers(self):
        """Record the genuine pre-upgrade rows this source schema carries.

        A source older than a ledger is left as None so the migrated tables
        must be empty except for an exact seed in the settled migration SQL.
        A genuine format18 source carries the complete schema142 pack/A3
        ledger; those rows are compared exactly before and after migration143.
        """
        schema = self.contract.schema
        if schema >= 139:
            self.source_core_rows = self.table_rows(self.source_db,
                                                    schema_delta(139))
        if schema >= 140:
            self.source_snapshot_rows = self.table_rows(
                self.source_db, schema_delta(140), self.A5_SNAPSHOT_COLUMNS)
        if schema >= 141:
            self.source_hold_rows = self.table_rows(self.source_db,
                                                    schema_delta(141))
        if schema >= 142:
            self.source_pack_rows = self.table_rows(self.source_db,
                                                    schema_delta(142))

    # -- OPTIONAL retained schema142 A4 fixture (format18 drill only) -------------------
    LEGACY_PACK_MARKER = "ROOTYARD-REF-STORE-PACKS-FIXTURE-METADATA"
    LEGACY_PACK_KIND = "rootyard/ref-store-core-packs-backup-fixture"
    LEGACY_PACK_TEST = "ref_store_pack_backup_metadata_fixture"
    LEGACY_PACK_TARGET = "ref_store_packs_backup_fixture"
    # Root's retained old producer receipt for the schema142 A4 helper.  The
    # complete digest stays in the receipt; only its documented prefix is pinned
    # here so the entrypoint cannot bind an arbitrary new build.
    LEGACY_PACK_SOURCE_INPUTS_PREFIX = "46ff"
    LEGACY_PACK_SOURCE = ROOT / "tests" / "ref_store_packs_backup_fixture.rs"

    @staticmethod
    def _file_sha256(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def validate_legacy_pack_fixture(self):
        """Bind the selected retained old A4 helper to its genuine build receipt."""
        helper = Path(self.legacy_fixture_binary)
        assert helper.is_file(), "retained schema142 A4 helper is missing: " + str(helper)
        receipt_path = (Path(self.legacy_fixture_receipt) if self.legacy_fixture_receipt
                        else Path(str(helper) + ".build.json"))
        assert receipt_path.is_file(), (
            "retained schema142 A4 helper receipt is missing: " + str(receipt_path))
        receipt = json.loads(receipt_path.read_text())
        assert isinstance(receipt, dict), "retained A4 helper receipt is not an object"
        actual = self._file_sha256(helper)
        recorded = (receipt.get("binary_sha256") or receipt.get("artifact_sha256") or
                    receipt.get("sha256"))
        assert recorded == actual, "retained A4 helper does not match its build receipt"
        assert receipt.get("kind") == "rust-integration-test", (
            "retained A4 helper receipt kind is " + repr(receipt.get("kind")))
        assert receipt.get("package_rebuilt") is True, "retained A4 helper was not rebuilt"
        entries = receipt.get("fresh_false_artifacts")
        assert isinstance(entries, list) and len(entries) == 1, (
            "retained A4 helper receipt must record exactly one fresh=False artifact")
        entry = entries[0]
        assert isinstance(entry, dict), "retained A4 helper fresh=False entry is not an object"
        assert str(entry.get("target")) == self.LEGACY_PACK_TARGET, (
            "retained A4 helper receipt target is " + repr(entry.get("target")))
        assert entry.get("fresh") is False and str(entry.get("kind")) == "test"
        assert (entry.get("profile") or {}).get("test") is True
        executable = entry.get("executable")
        assert executable and Path(str(executable)).name.startswith(self.LEGACY_PACK_TARGET)
        assert receipt.get("relocated_artifact") is True
        source_sha = receipt.get("integration_test_source_sha256")
        assert source_sha == self._file_sha256(self.LEGACY_PACK_SOURCE), (
            "the retained A4 helper was produced from different integration-test source")
        source_inputs = receipt.get("source_inputs_sha256") or receipt.get("source_inputs")
        assert isinstance(source_inputs, str) and len(source_inputs) == 64, (
            "retained A4 helper receipt has no source-input digest")
        assert source_inputs.startswith(self.LEGACY_PACK_SOURCE_INPUTS_PREFIX), (
            "retained A4 helper source inputs do not match the old producer receipt " +
            self.LEGACY_PACK_SOURCE_INPUTS_PREFIX)
        self.legacy_pack_helper = {
            "binary": str(helper),
            "binary_sha256": actual,
            "build_receipt": str(receipt_path),
            "build_receipt_sha256": self._file_sha256(receipt_path),
            "kind": "rust-integration-test",
            "fresh": False,
            "retained_binding_stages": [],
            "integration_test_source_sha256": source_sha,
            "integration_test_source_matches_source_file": True,
            "source_inputs_sha256": source_inputs,
            "source_inputs_match_old_producer_receipt_prefix": True,
            "verify_mode_run_against_schema143": False,
        }
        return self.legacy_pack_helper

    def seed_legacy_pack_fixture(self):
        """OPTIONAL hook: seed the genuine A4 S3/native-Git ledger in the old DB.

        Called from ``legacy_archive`` after the old CLI setup and BEFORE the
        source ``core``/A3/A4 row capture and the old offline backup, and only
        when the entrypoint selected the retained old helper.  Every older
        legacy entrypoint has no helper and therefore takes the no-op path.
        The old helper is only ever run in ``seed`` mode against the frozen
        schema142 database; its ``verify`` mode is never run against schema143.
        """
        if self.legacy_fixture_binary is None:
            assert self.contract.schema < 142, (
                "a schema142 entrypoint must supply the retained old A4 helper")
            return None
        assert self.contract.schema == 142, (
            "the retained old A4 helper is only valid for the format18/schema142 entrypoint")
        binding = self.validate_legacy_pack_fixture()
        assert self.query(
            self.source_db,
            "SELECT to_regclass('public.ref_store_core_snapshot_packs') IS NULL") == "t", (
                "the frozen schema142 source already carries migration-143 tables")
        assert self.query(
            self.source_db, "SELECT max(version) FROM schema_migrations") == str(
                self.contract.schema), "the source schema moved before the A4 fixture seed"
        output = self.root / "legacy-pack-fixture-manifest.json"
        env = self.legacy_env.copy()
        env.update(ROOTYARD_TEST_DATABASE_URL=self.source_db,
                   ROOTYARD_PACKS_FIXTURE_MODE="seed",
                   ROOTYARD_PACKS_FIXTURE_OUTPUT=str(output))
        process = self.run(
            [str(self.legacy_fixture_binary), "--ignored", "--exact",
             self.LEGACY_PACK_TEST, "--format=terse", "--nocapture",
             "--test-threads=1"], env=env)
        stdout = process.stdout.decode()
        summaries = [line for line in stdout.splitlines()
                     if line.startswith("test result:")]
        assert summaries, "the retained A4 helper reported no test result at all"
        summary = summaries[-1]
        assert "1 passed" in summary and "0 failed" in summary and "0 ignored" in summary, summary
        lines = [line for line in stdout.splitlines()
                 if line.startswith(self.LEGACY_PACK_MARKER + " ")]
        assert len(lines) == 1, "the retained A4 helper must print exactly one marker line"
        text = lines[0]
        assert self.redact(text) == text, "the retained A4 helper marker leaked a credential or database URL"
        marker = json.loads(text[len(self.LEGACY_PACK_MARKER) + 1:])
        assert marker["kind"] == self.LEGACY_PACK_KIND
        assert marker["mode"] == "seed"
        assert marker["provider_io_attempted"] is True
        assert marker["protected_upload_attempted"] is True
        assert marker["held_remote_objects_deleted"] is False
        assert marker["restored_blob_bytes_backed_up"] is False
        assert json.loads(output.read_text()) == marker, (
            "the private old A4 manifest differs from the public marker")
        assert self.query(
            self.source_db,
            "SELECT to_regclass('public.ref_store_core_snapshot_packs') IS NULL") == "t", (
                "the old A4 fixture fabricated a migration-143 table")
        assert self.query(
            self.source_db, "SELECT max(version) FROM schema_migrations") == str(
                self.contract.schema), "the old A4 fixture moved the frozen source schema"
        counts = marker["counts"]["pack"]
        assert counts == {"ref_store_core_pack_publications": 1,
                          "ref_store_core_pack_artifacts": 2,
                          "ref_store_core_pack_memberships": 1,
                          "ref_store_core_pack_history": 2,
                          "ref_store_core_pack_repo_usage": 1,
                          "ref_store_core_pack_tenant_usage": 1}, counts
        holds = marker["counts"]["holds"]
        assert holds["artifact_hold_requests"] == 1 and holds["artifact_holds"] == 2
        assert holds["artifact_hold_consume_receipts"] == 2 and holds["artifact_hold_shards"] == 64
        repo = _uuid_text(marker["scope"]["repository_id"])
        gate = self.query(
            self.source_db,
            "SELECT pack_mode || ':' || revision FROM ref_store_core_gates "
            "WHERE repository_id='" + repo + "'")
        assert gate == "pack_verified:2", gate
        self.legacy_pack_marker = marker
        binding["retained_binding_stages"].append("seed")
        binding["helper_binary_sha256_after_run"] = self._file_sha256(self.legacy_fixture_binary)
        binding["binaries_unchanged_after_run"] = (
            binding["helper_binary_sha256_after_run"] == binding["binary_sha256"])
        assert binding["binaries_unchanged_after_run"]
        return {"helper": binding,
                "pack_rows": marker["counts"]["pack"],
                "hold_rows": marker["counts"]["holds"],
                "gate": gate}

    def scoped_rows(self, db, tables, owners, scope):
        """Exact rows of one table family scoped to the fixture repository/tenant."""
        rows = {}
        repo = _uuid_text(scope["repository_id"])
        tenant = _uuid_text(scope["tenant_id"])
        for name in sorted(tables):
            owner = owners.get(name, "repository_id")
            expression = "to_jsonb(t)"
            if owner is None:
                where = ""
            else:
                value = tenant if owner == "tenant_id" else repo
                where = " WHERE t." + owner + "='" + value + "'"
            output = self.query(
                db,
                "SELECT COALESCE(json_agg(" + expression + " ORDER BY " +
                expression + "::text), '[]'::json) FROM public." + '"' + name + '"' + " t" + where)
            rows[name] = json.loads(output)
        return rows

    def assert_legacy_pack_fixture_preserved(self):
        """The genuine format18 A4 ledger survives migration143 exactly.

        Requires the old helper's own typed marker rows to equal the restored
        rows, so a genuine non-empty schema142 pack/A3 ledger is proven across
        the upgrade instead of only empty CLI tables.  No schema143 A5 snapshot,
        pin or history row exists in the old archive.
        """
        marker = self.legacy_pack_marker
        assert marker is not None, "the retained A4 fixture hook did not run"
        assert self.contract.schema == 142 and self.contract.format == 18
        scope = marker["scope"]
        pack_tables = catalog_tables(142) - catalog_tables(141)
        hold_tables = catalog_tables(141) - catalog_tables(140)
        core_tables = catalog_tables(139) - catalog_tables(138)
        pack = self.scoped_rows(
            self.restore_db, pack_tables,
            {name: ("tenant_id" if name.endswith("_tenant_usage") else "repository_id")
             for name in pack_tables}, scope)
        holds = self.scoped_rows(
            self.restore_db, hold_tables,
            {name: ("tenant_id" if name == "artifact_hold_tenant_usage" else
                    (None if name == "artifact_hold_shards" else "repository_id"))
             for name in hold_tables}, scope)
        core = self.scoped_rows(
            self.restore_db, core_tables, {name: "repository_id" for name in core_tables}, scope)
        assert pack == marker["rows"]["pack"], (
            "the retained schema142 A4 ledger rows were not restored exactly")
        assert holds == marker["rows"]["holds"], (
            "the retained schema141 A3 hold ledger rows were not restored exactly")
        assert core == marker["rows"]["core"], (
            "the retained schema139 core rows were not restored exactly")
        repo = _uuid_text(scope["repository_id"])
        gate = json.loads(self.query(
            self.restore_db,
            "SELECT to_jsonb(g) FROM public.ref_store_core_gates g WHERE g.repository_id='" +
            repo + "'"))
        assert gate["pack_mode"] == marker["gate"]["committed"]["pack_mode"] == "pack_verified"
        assert gate["revision"] == marker["gate"]["committed"]["revision"] == 2
        assert gate["head_ref"] == marker["gate"]["committed"]["head_ref"]
        assert json.loads(pack["ref_store_core_pack_publications"][0]["ack_body"]) == (
            marker["registration"]["ack"])
        assert self.query(
            self.restore_db,
            "SELECT count(*) FROM ref_store_core_snapshots WHERE pack_mode='pack_verified'") == "0", (
                "the old archive fabricated a pack-aware A5 snapshot")
        for table in schema143_pack_snapshot_tables():
            assert self.query(
                self.restore_db,
                'SELECT count(*) FROM public."' + table + '"') == "0", (
                    "the old archive fabricated an A5 row in " + table)
        return {
            "legacy_a4_pack_ledger_nonempty": {name: len(rows) for name, rows in pack.items()},
            "legacy_a3_hold_ledger_nonempty": {name: len(rows) for name, rows in holds.items()},
            "legacy_core_rows_nonempty": {name: len(rows) for name, rows in core.items()},
            "legacy_a4_pack_ledger_restored_exactly": True,
            "legacy_a3_hold_ledger_restored_exactly": True,
            "legacy_core_rows_restored_exactly": True,
            "legacy_a4_gate_pack_verified_retained": True,
            "legacy_a4_ack_body_matches_typed_registration": True,
            "legacy_format18_archive_has_no_schema143_rows": True,
            "legacy_a5_pack_snapshot_fabricated": False,
            "legacy_old_helper_verify_mode_run_against_143": False,
            "legacy_old_helper_seed_only": True,
        }

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
        # OPTIONAL retained-A4 hook: real S3/native-Git seeding in the frozen
        # schema142 source, run BEFORE the source row capture and the old
        # offline backup.  Default no-op for every older legacy entrypoint.
        legacy_fixture = self.seed_legacy_pack_fixture()
        self.capture_source_ledgers()
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
        if self.legacy_pack_marker is not None:
            assert self.contract.schema == 142
            assert 143 not in manifest["schema_versions"], (
                "the frozen format18 archive relabelled the schema143 migration set")
            assert manifest["schema_versions"][-1] == 142
        self.run([self.args.legacy_binary, "backup-verify",
                  str(self.legacy_backup)], env=self.env)
        self.assert_source_closure()
        return dict(format=manifest["format"],
                    schema_last=manifest["schema_versions"][-1],
                    schema_contains_next=False,
                    legacy_a4_fixture_seeded=self.legacy_pack_marker is not None,
                    legacy_a4_fixture_gate_pack_verified=(
                        self.legacy_pack_marker["gate"]["committed"]["pack_mode"]
                        if self.legacy_pack_marker is not None else None),
                    schema143_absent_from_old_archive=True,
                    old_helper_verify_mode_run_against_143=False,
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
            # Only the schema142+ target adds this guard; it is part of the
            # exact expected set, so any other extra trigger still fails.
            expected_trigger += ("," + SCHEMA142_CORE_TRIGGER +
                                 ":ref_store_core_gates:19:before:" +
                                 SCHEMA142_CORE_TRIGGER_FUNCTION)
        assert triggers == expected_trigger, triggers
        mode_fence_enabled = self.query(
            self.restore_db,
            "SELECT count(*) FROM pg_trigger WHERE tgname='" +
            SCHEMA142_CORE_TRIGGER + "' AND tgenabled='O'")
        assert mode_fence_enabled == ("1" if mode_fence else "0"), mode_fence_enabled
        restored_core = self.table_rows(self.restore_db, schema_delta(139))
        if self.source_core_rows is None:
            assert all(not value for value in restored_core.values()), restored_core
        else:
            assert restored_core == self.source_core_rows, (
                "the migrated schema139 core rows differ from the genuine source")
        rows = "/".join(str(len(restored_core[name])) for name in sorted(restored_core))
        return dict(schema139_core_tables=len(SCHEMA139_CORE_TABLES),
                    schema139_core_refs_key=refs_key,
                    schema139_core_event_operation_fkey=True,
                    schema139_core_event_immutable_trigger=True,
                    schema142_core_gate_pack_mode_fence=mode_fence,
                    schema142_core_gate_pack_mode_fence_enabled=mode_fence_enabled == "1",
                    schema139_core_rows=rows,
                    preserved_genuine_source_core_rows=self.source_core_rows is not None)

    def assert_holds_schema(self):
        """Verify the schema141 ledger from current catalogs and settled SQL.

        A genuine source older than schema141 carries no new hold rows, so the
        migrated ledger must be empty except for a fixed seed in the settled
        migration141 SQL.  A genuine format16/17/18 source that already carries
        the hold ledger must preserve its rows exactly.  The table names come
        from the generated current-vs-schema140 catalog difference, never a
        guessed list; this fixture inserts no hold, request or consumption row
        and invents no quota value.
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
        restored_rows = self.table_rows(self.restore_db, new_tables)
        counts = {name: len(restored_rows[name]) for name in sorted(new_tables)}
        if self.source_hold_rows is None:
            expected = {name: seeds.get(name, 0) for name in sorted(new_tables)}
            assert counts == expected, (counts, expected)
        else:
            assert restored_rows == self.source_hold_rows, (
                "the migrated schema141 hold ledger differs from the genuine source")
        return dict(
            schema141_new_tables=sorted(new_tables),
            schema141_hold_request_tables=categories["hold_requests"],
            schema141_hold_tables=categories["holds"],
            schema141_consumption_tables=categories["consumption"],
            schema141_seeded_rows={name: counts[name] for name in sorted(seeds)},
            schema141_new_tables_empty_except_migration_seed=self.source_hold_rows is None,
            schema141_hold_rows_preserved_from_genuine_source=self.source_hold_rows is not None,
            schema141_hold_rows_fabricated=False)

    def assert_pack_ledger_schema(self):
        """Verify the schema142 pack ledger without fabricating a pack row.

        A genuine source older than schema142 carries no A4 pack registration,
        artifact, membership, history or usage row, so the migrated tables must
        be empty except for a fixed seed in the settled migration142 SQL.  A
        genuine format18 source carries the complete schema142 pack/A3 ledger;
        migration143 must preserve every row and the gate mode exactly.  The
        table names come from the generated 142-vs-141 catalog difference,
        never a guessed list.
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
        restored_rows = self.table_rows(self.restore_db, new_tables)
        counts = {name: len(restored_rows[name]) for name in sorted(new_tables)}
        if self.source_pack_rows is None:
            expected = {name: seeds.get(name, 0) for name in sorted(new_tables)}
            assert counts == expected, (counts, expected)
            gates = (self.source_core_rows or {}).get("ref_store_core_gates", [])
            expected_gate_modes = ",".join(sorted({
                row.get("pack_mode", "metadata_only") for row in gates}))
        else:
            assert restored_rows == self.source_pack_rows, (
                "the migrated schema142 pack ledger differs from the genuine source")
            gates = (self.source_core_rows or {}).get("ref_store_core_gates", [])
            expected_gate_modes = ",".join(sorted({row["pack_mode"] for row in gates}))
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
        assert gate_modes == expected_gate_modes, (gate_modes, expected_gate_modes)
        if self.source_hold_rows is None:
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
            schema142_new_tables_empty_except_migration_seed=self.source_pack_rows is None,
            schema142_pack_rows_preserved_from_genuine_source=self.source_pack_rows is not None,
            schema142_gate_pack_mode=gate_modes,
            schema142_active_pack_membership_fabricated=False,
            schema141_shard_seed_unchanged=self.source_hold_rows is None)

    def assert_a5_pack_snapshot_schema(self):
        """Migration 143 adds only empty A5 tables and defaulted metadata gaps.

        A genuine pre-A5 source has no snapshot-pack binding, pack-snapshot
        history or permanent pack-snapshot usage row, and no pack-mode A2
        snapshot: the four generated 143-vs-142 tables must be empty and every
        existing schema140 snapshot must keep the ``metadata_only`` /
        ``unavailable`` / zero-pack / null-digest shape.  A genuine format18
        source's own snapshot rows are compared exactly (without the four new
        columns) so migration143 cannot rewrite historical metadata.
        """
        assert self.contract.target_schema >= 143, self.contract.target_schema
        new_tables = schema143_pack_snapshot_tables()
        for name in new_tables:
            assert re.fullmatch(r"[a-z_][a-z0-9_]*", name), name
        categories = {
            "bindings": sorted(n for n in new_tables if "snapshot_packs" in n),
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
        assert set(filter(None, present.split(","))) == set(new_tables), present
        seeds = migration_seed_counts(143)
        assert set(seeds) <= set(new_tables), (seeds, new_tables)
        counts = {
            name: int(self.query(
                self.restore_db,
                'SELECT count(*) FROM public."' + name + '"'))
            for name in sorted(new_tables)
        }
        expected = {name: seeds.get(name, 0) for name in sorted(new_tables)}
        assert counts == expected, (counts, expected)
        columns = self.query(
            self.restore_db,
            "SELECT string_agg(column_name || ':' || data_type || ':' || "
            "is_nullable || ':' || coalesce(column_default,''), ',' ORDER BY "
            "column_name) FROM information_schema.columns WHERE "
            "table_schema='public' AND table_name='ref_store_core_snapshots' "
            "AND column_name IN ('pack_mode','pack_count','membership_digest',"
            "'snapshot_digest')")
        assert columns == ("membership_digest:text:YES:,pack_count:integer:NO:0,"
                           "pack_mode:text:NO:'metadata_only'::text,"
                           "snapshot_digest:text:YES:"), columns
        nondefault = self.query(
            self.restore_db,
            "SELECT count(*) FROM ref_store_core_snapshots WHERE "
            "pack_mode<>'metadata_only' OR pack_count<>0 OR "
            "membership_digest IS NOT NULL OR snapshot_digest IS NOT NULL OR "
            "pack_membership_state<>'unavailable'")
        assert nondefault == "0", nondefault
        preserved = False
        if self.source_snapshot_rows is None:
            assert self.query(
                self.restore_db,
                "SELECT count(*) FROM ref_store_core_snapshots") == "0", (
                    "a pre-schema140 source must not gain a fabricated A2 snapshot")
        else:
            restored = self.table_rows(self.restore_db, schema_delta(140),
                                       self.A5_SNAPSHOT_COLUMNS)
            assert restored == self.source_snapshot_rows, (
                "migration143 rewrote historical schema140 snapshot rows")
            preserved = True
        return dict(
            schema143_pack_snapshot_tables=sorted(new_tables),
            schema143_binding_tables=categories["bindings"],
            schema143_history_tables=categories["history"],
            schema143_usage_tables=categories["usage"],
            schema143_new_tables_empty_except_migration_seed=not seeds,
            schema143_old_snapshot_rows_metadata_only=True,
            schema143_old_snapshot_rows_preserved_from_genuine_source=preserved,
            schema143_pack_pin_or_history_fabricated=False,
            complete_git_read_snapshot_claimed=False)

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
        a5 = {}
        if self.contract.target_schema >= 143:
            a5 = self.assert_a5_pack_snapshot_schema()
        legacy_fixture = {}
        if self.legacy_pack_marker is not None:
            legacy_fixture = self.assert_legacy_pack_fixture_preserved()
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
        return dict(**core, **holds, **packs, **a5, **legacy_fixture,
                    schema_version=int(last),
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
    parser.add_argument("--legacy-fixture-binary",
                        help="retained schema142 A4 integration-test helper "
                             "(required by the format18/schema142 entrypoint only)")
    parser.add_argument("--legacy-fixture-receipt", type=Path,
                        help="build receipt for the retained A4 helper "
                             "(defaults to <helper>.build.json)")
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
    if contract.schema >= 142:
        if not args.legacy_fixture_binary:
            parser.error("the format18/schema142 entrypoint requires "
                         "--legacy-fixture-binary (the retained old A4 helper)")
        if not args.legacy_fixture_receipt:
            parser.error("the format18/schema142 entrypoint requires "
                         "--legacy-fixture-receipt")
        args.legacy_fixture_binary = str(Path(args.legacy_fixture_binary).resolve())
        if not Path(args.legacy_fixture_binary).is_file():
            parser.error("--legacy-fixture-binary is not a file")
        args.legacy_fixture_receipt = Path(args.legacy_fixture_receipt).resolve()
        if not args.legacy_fixture_receipt.is_file():
            parser.error("--legacy-fixture-receipt is not a file")
    else:
        args.legacy_fixture_binary = None
        args.legacy_fixture_receipt = None
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
            legacy_pack_fixture_helper=harness.legacy_pack_helper,
            harness_git_head=harness_git_head(),
            limitations=[
                "Loopback functional drill; no production RPO/RTO or power-loss claim.",
                "The legacy archive is produced by the trusted format" + str(contract.format) + " binary and is never edited.",
                "source_head values are repository heads, not binary build provenance.",
                "A source older than a ledger schema gains that ledger empty "
                "(except an exact settled-migration seed); a genuine source that "
                "already carries schema139/140/141/142 rows has the exact rows "
                "preserved across migration143, never fabricated.",
                "A genuine pre-schema140 source gains an empty migration-140 "
                "snapshot/pin schema; a genuine source that carries it has its "
                "exact rows preserved and every old snapshot left metadata-only.",
                "The schema141 ledger tables are derived from the generated "
                "140-vs-139 catalogs; a source older than schema141 must leave "
                "them at the exact settled seed, while a genuine format16/17/18 "
                "source's rows are compared exactly. This fixture inserts no "
                "hold, request or consumption row.",
                "The schema142 pack-registration/membership/history/usage "
                "tables are derived from the generated 142-vs-141 catalogs and "
                "must stay empty on a genuine pre-142 source, while a genuine "
                "format18 A4 source's rows and gate mode are preserved exactly. "
                "This fixture inserts no pack row and claims no pack-verified gate.",
                "The schema143 pack-snapshot binding/history/permanent-usage "
                "tables are derived from the generated 143-vs-142 catalogs and "
                "must stay empty; no A5 pack snapshot, pin or history row is "
                "fabricated and no complete Git-read snapshot is claimed.",
                "The format18/schema142 drill seeds its genuine A4 S3/native-Git "
                "pack/A3 ledger with the retained old A4 helper (seed mode only) "
                "before the old archive is written; that helper's verify mode is "
                "never run against the schema143 target.",
                "A format16 drill requires root to supply the genuine retained "
                "old schema140 producer and its archive; format17/18 drills "
                "require the genuine retained schema141/schema142 producers "
                "(the format18 producer is the retained A4 app); this harness "
                "never fabricates or relabels one.",
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
