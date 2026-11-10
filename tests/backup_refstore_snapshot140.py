#!/usr/bin/env python3
"""Current-format backup roundtrip of **populated** schema140 RefStore metadata.

The archive is current format19/schema143.  The six schema140 tables remain the
only new rows this A2 fixture populates; it makes no claim about the schema141
global artifact-hold ledger or the schema142 pack-registration/membership
ledger and is not a hold-row, pack-row or Blob-byte backup drill.  The dynamic
dump is still inspected for every A4 pack table derived from the generated
142-vs-141 catalogs and for the A5 pack-snapshot tables derived from the
generated 143-vs-142 catalogs; both sets must restore empty, the old snapshots
keep the default ``metadata_only``/``unavailable`` shape, and the gate stays at
the default ``metadata_only`` mode.

This is the acceptance drill for #107-A2.  It subclasses the inherited
``tests/backup_refstore_core139.py`` harness, so its seven cases are exactly the
seven real backup cases (synthetic source, offline barrier/snapshot, corrupt
inputs, barrier failure, interrupted restore, post-backup write exclusion and a
fresh authenticated restore/clone/fsck into a new database, directory and
service).  Everything the parent proves about the migration-139 core tables
stays asserted and must keep holding: the A2 adapter never mutates the
migration-138 operation registry, the migration-139 gate/ref/event rows or the
unserved repository row.

What is new here is that the migration-140 tables are **populated by the real
typed PostgreSQL adapter**, not by hand-written SQL.  The parent SQL fixture
still seeds only the gate/refs/lane/operation rows (plainly a metadata fixture,
never an adapter or protocol acknowledgement, never a Git `ACK`).  Then the Rust
integration-test companion ``tests/ref_store_snapshot_backup_fixture.rs`` is
invoked against that same disposable database (``ROOTYARD_TEST_DATABASE_URL``,
never the outer admin URL, never a second database or schema, no migration) in
``seed`` mode.  It builds one trusted ``MetadataSnapshotScope`` with purpose
``backup`` from the actual core gate version and drives three pin lifecycles:

* an **active** pin renewed for real (TTL 3600 s), final generation 2;
* a **released** pin ended by an exact release at generation 1;
* an **expired** pin created with a 1 s TTL and left to expire through a bounded
  wait on the real PostgreSQL clock (no SQL lease overwrite, no fake clock).

The helper also validates pages and receipt lookups, and prints exactly one
public marker line (ids, digests, scopes, request ids, receipt bodies - never an
env value, DSN or token).  The parent keeps the fixture manifest itself in this
run's private temporary directory.

After the real offline backup and the fresh restore, this harness compares the
exact global JSON rows of all six migration-140 tables, then invokes the same
helper in ``verify`` mode.  Verify rebuilds the identical typed
create/renew/release requests from the manifest through the public constructors
and replays them: every replay must return the original receipt and must not
write, refund, re-extend or revive a row, a counter or a timestamp.  The active
pin still pages (through a real keyset cursor), the released pin denies as
``MetadataPinReleased`` and the expired pin denies as ``MetadataPinExpired``.

The helper executable is only trusted when a matching ``.build.json`` receipt
binds its SHA-256, records a ``rust-integration-test`` build with
``package_rebuilt=True`` and one test artifact with ``fresh=False``, and shares the candidate
application receipt's ``source_inputs_sha256``.  A missing binary, missing
receipt, digest mismatch or a helper run that does not report exactly one
passing test fails the whole drill: there is no skip and no zero-test pass.

Limits: metadata rows only.  No Git object, pack membership, physical GC,
object protection or serving claim is made, and the drill repository stays
``provisioning``/``gitfs`` with no bare directory, no Pando authority and no
legacy ref projection.  Requires a dedicated synthetic
``ROOTYARD_TEST_DATABASE_URL`` with CREATEDB.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

from backup_refstore_core139 import BackupRefStoreCore139Harness, uuid_literal
from schema_baseline import A5_PACK_SNAPSHOT_TABLES, CURRENT_BACKUP_FORMAT, SCHEMA_VERSIONS

#: The six tables migration 140 adds.  Every one of them must be non-empty.
NEW_TABLES = (
    "ref_store_core_snapshots",
    "ref_store_core_snapshot_refs",
    "ref_store_core_pins",
    "ref_store_core_receipts",
    "ref_store_core_repo_usage",
    "ref_store_core_tenant_usage",
)
#: Tenant-wide table: its fixture row is keyed by the tenant, not the repository.
TENANT_SCOPED_TABLES = ("ref_store_core_tenant_usage",)
MARKER = "ROOTYARD-SNAPSHOT-FIXTURE-METADATA"
FIXTURE_KIND = "rootyard/ref-store-snapshot-backup-fixture"
HELPER_TEST = "snapshot_backup_metadata_fixture"
HELPER_TARGET = "ref_store_snapshot_backup_fixture"
ROOT = Path(__file__).resolve().parents[1]
HELPER_SOURCE = ROOT / "tests" / "ref_store_snapshot_backup_fixture.rs"


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


def schema142_pack_tables():
    """The exact current-vs-141 catalog delta; no fabricated names."""
    tables = catalog_tables(142) - catalog_tables(141)
    assert tables, ("the 142 catalog adds no pack table; root must regenerate "
                    "it from settled PostgreSQL")
    return sorted(tables)


def sha256_file(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def receipt_field(receipt, names, label):
    """Return the first present field of a build receipt under any accepted name."""
    for name in names:
        if name in receipt:
            return receipt[name]
    raise AssertionError("build receipt has no " + label + " (accepted keys: " + ", ".join(names) + ")")


def receipt_flag(receipt, names, label):
    value = receipt_field(receipt, names, label)
    assert isinstance(value, bool), "build receipt " + label + " must be a boolean"
    return value

def fresh_false_entry(receipt, label, target):
    """Return the single fresh=False artifact entry a real builder records."""
    entries = receipt.get("fresh_false_artifacts")
    assert isinstance(entries, list), label + " has no fresh_false_artifacts list"
    assert len(entries) == 1, label + " must record exactly one fresh=False artifact, got " + str(len(entries))
    entry = entries[0]
    assert isinstance(entry, dict), label + " fresh_false_artifacts entry is not an object"
    assert str(entry.get("target")) == target, (
        label + " fresh=False artifact target is " + repr(entry.get("target")) + ", expected " + target)
    assert entry.get("fresh") is False, label + " artifact is not marked fresh=False"
    return entry


def load_receipt(path, label):
    path = Path(path)
    assert path.is_file(), label + " is missing: " + str(path)
    value = json.loads(path.read_text())
    assert isinstance(value, dict), label + " is not a JSON object"
    return value


def candidate_receipt(path):
    """Locate the .build.json receipt that belongs to one built executable."""
    path = Path(path)
    for option in (Path(str(path) + ".build.json"), path.with_suffix(".build.json")):
        if option.is_file():
            return option
    raise AssertionError("no build receipt next to " + str(path) + " (expected " + str(path) + ".build.json)")


def validate_snapshot_fixture_binary(helper, app_binary, helper_receipt=None, app_receipt=None):
    """Bind the helper executable to the real integration-test build that made it.

    The real builder (build-state-integration-test.py / build_native_test.py)
    compiles the actual rootyard package (package_rebuilt=True) and records exactly
    one fresh_false_artifacts entry for the requested test target with fresh=False
    and a test profile.  The receipt therefore proves this is the integration-test
    executable of an unmodified package build, not a stub: its SHA-256 must equal
    the receipt digest, the target name must be exact, the recorded
    integration-test source digest must equal this source file, and the candidate
    application binary must match its own real build receipt and share the same
    compiled source inputs.
    """
    helper = Path(helper)
    assert helper.is_file(), "snapshot fixture binary is missing: " + str(helper)
    receipt_path = Path(helper_receipt) if helper_receipt else candidate_receipt(helper)
    receipt = load_receipt(receipt_path, "snapshot fixture build receipt")
    actual = sha256_file(helper)
    recorded = receipt_field(receipt, ("binary_sha256", "artifact_sha256", "sha256"), "binary sha256")
    assert recorded == actual, (
        "snapshot fixture binary does not match its build receipt: " + actual + " != " + str(recorded))
    kind = receipt_field(receipt, ("kind", "target_kind"), "build kind")
    assert kind == "rust-integration-test", "snapshot fixture receipt kind is " + repr(kind)
    assert receipt_flag(receipt, ("package_rebuilt",), "package_rebuilt") is True, (
        "the real builder compiles the rootyard package; package_rebuilt must be true")
    entry = fresh_false_entry(receipt, "snapshot fixture receipt", HELPER_TARGET)
    assert str(entry.get("kind")) == "test", "snapshot fixture artifact kind is not test"
    profile = entry.get("profile") or {}
    assert isinstance(profile, dict) and profile.get("test") is True, (
        "snapshot fixture artifact was not built with a test profile")
    executable = entry.get("executable")
    assert executable, "snapshot fixture artifact records no executable"
    # The builder relocates the artifact outside CARGO_TARGET_DIR, so the entry
    # names the freshly compiled target artifact (target-<hash>); the binding to
    # the helper itself is the receipt's binary_sha256 checked above.
    assert Path(str(executable)).name.startswith(HELPER_TARGET), (
        "snapshot fixture receipt artifact does not name the " + HELPER_TARGET + " target")
    if "relocated_artifact" in receipt:
        assert receipt["relocated_artifact"] is True, (
            "snapshot fixture receipt must record the relocated integration-test artifact")
    source_sha = receipt_field(receipt, ("integration_test_source_sha256",), "integration_test_source_sha256")
    assert source_sha == sha256_file(HELPER_SOURCE), (
        "the helper receipt was produced from different integration-test source")
    source_inputs = receipt_field(receipt, ("source_inputs_sha256", "source_inputs"), "source_inputs_sha256")
    assert isinstance(source_inputs, str) and len(source_inputs) == 64, (
        "snapshot fixture receipt has no source-input digest")
    app_receipt_path = Path(app_receipt) if app_receipt else candidate_receipt(Path(app_binary))
    app = load_receipt(app_receipt_path, "candidate application build receipt")
    app_actual = sha256_file(Path(app_binary))
    app_recorded = receipt_field(app, ("binary_sha256", "artifact_sha256", "sha256"), "candidate binary sha256")
    assert app_recorded == app_actual, (
        "the candidate application binary does not match its own build receipt")
    assert receipt_flag(app, ("package_rebuilt",), "candidate package_rebuilt") is True, (
        "the candidate application receipt must come from the real package build")
    app_entries = app.get("fresh_false_artifacts")
    assert isinstance(app_entries, list) and app_entries, (
        "the candidate application receipt records no fresh=False artifact")
    assert all(isinstance(item, dict) and item.get("fresh") is False for item in app_entries), (
        "the candidate application receipt has an artifact that is not fresh=False")
    app_source = receipt_field(app, ("source_inputs_sha256", "source_inputs"), "candidate source_inputs_sha256")
    assert app_source == source_inputs, (
        "the snapshot fixture helper and the candidate application were built from different source inputs")
    return {
        "binary": str(helper),
        "binary_sha256": actual,
        "build_receipt": str(receipt_path),
        "build_receipt_sha256": sha256_file(receipt_path),
        "build_kind": "rust-integration-test",
        "package_rebuilt": True,
        "fresh": False,
        "fresh_false_artifact": {key: entry.get(key) for key in ("target", "kind", "fresh")},
        "test_profile": True,
        "integration_test_source_sha256": source_sha,
        "integration_test_source_matches_source_file": True,
        "source_inputs_sha256": source_inputs,
        "candidate_application_receipt": str(app_receipt_path),
        "candidate_application_sha256": app_actual,
        "candidate_application_package_rebuilt": True,
        "source_inputs_match_candidate_application": True,
    }

class BackupRefStoreSnapshot140Harness(BackupRefStoreCore139Harness):
    """Populate all six schema140 tables through the real adapter, then restore."""

    def __init__(self, args):
        super().__init__(args)
        self.snapshot_fixture_binary = Path(args.snapshot_fixture_binary)
        # The fixture manifest stays inside this run's 0700 temporary directory.
        self.snapshot_manifest = self.root / "snapshot-fixture-manifest.json"
        self.snapshot_helper = None

    # ------------------------------------------------------------------ helper
    def fixture_env(self, mode, db):
        """Env for the Rust companion: this fixture's database, never the admin URL."""
        env = self.env.copy()
        env.update(
            ROOTYARD_TEST_DATABASE_URL=db,
            ROOTYARD_SNAPSHOT_FIXTURE_MODE=mode,
            ROOTYARD_SNAPSHOT_FIXTURE_REPOSITORY=self.core_repo["id"],
            ROOTYARD_SNAPSHOT_FIXTURE_TENANT=self.core_repo["tenant_id"],
            ROOTYARD_SNAPSHOT_FIXTURE_OWNER=self.core_repo["tenant_id"],
            ROOTYARD_SNAPSHOT_FIXTURE_OUTPUT=str(self.snapshot_manifest),
        )
        return env

    def run_snapshot_fixture(self, mode, db=None):
        """Run one mandatory helper mode and return its single public marker."""
        assert self.snapshot_helper is not None, "helper binary was not validated"
        assert mode in ("seed", "verify")
        process = self.run(
            [str(self.snapshot_fixture_binary), "--ignored", "--exact", HELPER_TEST,
             "--format=terse", "--nocapture", "--test-threads=1"],
            env=self.fixture_env(mode, db or self.db))
        stdout = process.stdout.decode()
        summaries = [line for line in stdout.splitlines() if line.startswith("test result:")]
        assert summaries, "the snapshot fixture helper reported no test result at all"
        summary = summaries[-1]
        # Exactly one test ran, it passed, and nothing was ignored/filtered away.
        assert "1 passed" in summary, "the snapshot fixture helper did not run exactly one test: " + summary
        assert "0 failed" in summary, "the snapshot fixture helper failed: " + summary
        assert "0 ignored" in summary, "the snapshot fixture helper skipped its test: " + summary
        lines = [line for line in stdout.splitlines() if line.startswith(MARKER + " ")]
        assert len(lines) == 1, "the snapshot fixture helper must print exactly one marker line"
        text = lines[0]
        assert self.redact(text) == text, "the snapshot fixture marker leaked a credential or database URL"
        marker = json.loads(text[len(MARKER) + 1:])
        assert marker["kind"] == FIXTURE_KIND, "the snapshot fixture marker has an unexpected kind"
        assert marker["mode"] == mode, "the snapshot fixture marker reports an unexpected mode"
        assert marker["pack_membership_state"] == "unavailable"
        assert marker["serving_claim"] is False
        counts = marker.get("counts") or {}
        assert sorted(counts) == sorted(NEW_TABLES), "the snapshot fixture marker does not count all six tables"
        assert all(value > 0 for value in counts.values()), "the snapshot fixture left a migration-140 table empty"
        return marker


    def assert_binary_binding(self, stage):
        """Re-check both built executables after the helper ran (swap guard)."""
        assert self.snapshot_helper is not None, "helper binary was not validated"
        helper = sha256_file(self.snapshot_fixture_binary)
        app = sha256_file(Path(self.args.binary))
        assert helper == self.snapshot_helper["binary_sha256"], (
            "the helper binary changed after validation (" + stage + ")")
        assert app == self.snapshot_helper["candidate_application_sha256"], (
            "the application binary changed after validation (" + stage + ")")
        self.snapshot_helper["retained_binding_stages"] = self.snapshot_helper.get("retained_binding_stages", []) + [stage]
        self.snapshot_helper["helper_binary_sha256_after_run"] = helper
        self.snapshot_helper["candidate_application_sha256_after_run"] = app
        self.snapshot_helper["binaries_unchanged_after_run"] = True
        return {"stage": stage, "helper_binary_sha256": helper,
                "application_binary_sha256": app, "unchanged": True}

    # ------------------------------------------------------------- SQL helpers
    def new_rows(self, db=None):
        """Exact global JSON rows of all six migration-140 tables."""
        rows = {}
        for table in NEW_TABLES:
            value = self.metadata_psql(
                "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text), '[]'::json) FROM public." +
                table + " t", db=db).stdout.decode().strip()
            rows[table] = json.loads(value)
        return rows

    def new_scoped_rows(self, db=None, repository=None):
        """Rows of the six migration-140 tables that belong to this fixture scope."""
        repository = uuid_literal(repository or self.core_repo["id"])
        tenant = uuid_literal(self.core_repo["tenant_id"])
        rows = {}
        for table in NEW_TABLES:
            if table in TENANT_SCOPED_TABLES:
                where = "t.tenant_id='" + tenant + "'"
            elif table == "ref_store_core_snapshot_refs":
                where = ("t.snapshot_id IN (SELECT snapshot_id FROM public.ref_store_core_snapshots "
                         "WHERE repository_id='" + repository + "')")
            else:
                where = "t.repository_id='" + repository + "'"
            value = self.metadata_psql(
                "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text), '[]'::json) FROM public." +
                table + " t WHERE " + where, db=db).stdout.decode().strip()
            rows[table] = json.loads(value)
        return rows

    def core_gate_row(self, db=None):
        return json.loads(self.metadata_psql(
            "SELECT to_jsonb(g) FROM public.ref_store_core_gates g WHERE g.repository_id='" +
            uuid_literal(self.core_repo["id"]) + "'", db=db).stdout.decode().strip())

    def assert_new_tables_populated(self, scoped, marker):
        """Assert every new table is non-empty, coherent and matches the marker."""
        per_snapshot_refs = len(marker["captured_refs"])
        expected = {
            "ref_store_core_snapshots": 3,
            "ref_store_core_snapshot_refs": 3 * per_snapshot_refs,
            "ref_store_core_pins": 3,
            "ref_store_core_receipts": 5,
            "ref_store_core_repo_usage": 1,
            "ref_store_core_tenant_usage": 1,
        }
        for table, count in expected.items():
            assert len(scoped[table]) == count, table + " rows are not populated exactly: " + str(len(scoped[table]))
        assert marker["counts"] == expected, "the helper counts differ from the SQL row counts"
        lifecycles = {entry["kind"]: entry for entry in marker["lifecycles"]}
        assert sorted(lifecycles) == ["active", "expired", "released"]
        pins = {row["pin_id"]: row for row in scoped["ref_store_core_pins"]}
        snapshots = {row["snapshot_id"]: row for row in scoped["ref_store_core_snapshots"]}
        for kind, entry in lifecycles.items():
            pin = pins[entry["pin_id"]]
            snapshot = snapshots[entry["snapshot_id"]]
            assert pin["state"] == entry["final_state"], kind + " pin state differs from the marker"
            assert pin["generation"] == entry["final_generation"], kind + " pin generation differs from the marker"
            assert uuid_literal(pin["snapshot_id"]) == entry["snapshot_id"]
            assert snapshot["ref_count"] == per_snapshot_refs
            assert snapshot["purpose"] == "backup"
            assert snapshot["tenant_id"] == uuid_literal(self.core_repo["tenant_id"])
            assert snapshot["owner_id"] == uuid_literal(self.core_repo["tenant_id"])
            assert snapshot["gate_revision"] == marker["scope"]["gate_revision"]
            assert snapshot["gate_digest"] == marker["scope"]["gate_digest"]
            assert snapshot["pack_membership_state"] == "unavailable"
            assert snapshot["logical_bytes"] > 0
            assert snapshot["head_ref"] == marker["scope"]["head_ref"]
            refs = [row for row in scoped["ref_store_core_snapshot_refs"]
                    if row["snapshot_id"] == entry["snapshot_id"]]
            assert len(refs) == per_snapshot_refs
            assert [row["ref_name"] for row in refs] == [row["name"] for row in marker["captured_refs"]]
        active = pins[lifecycles["active"]["pin_id"]]
        assert active["state"] == "active" and active["generation"] == 2 and active["renewed_at"] is not None
        assert active["released_at"] is None and active["release_reason"] is None
        released = pins[lifecycles["released"]["pin_id"]]
        assert released["state"] == "released" and released["generation"] == 1
        assert released["released_at"] is not None and released["release_reason"] == "client_done"
        assert released["release_request_id"] == lifecycles["released"]["release"]["request_id"]
        expired = pins[lifecycles["expired"]["pin_id"]]
        assert expired["state"] == "active" and expired["renewed_at"] is None
        # Expiry is the database clock, never a rewritten lease column.
        assert self.sql(
            "SELECT count(*) FROM ref_store_core_pins WHERE repository_id='" +
            uuid_literal(self.core_repo["id"]) + "' AND pin_id='" + expired["pin_id"] +
            "' AND expires_at <= clock_timestamp()") == "1"
        receipts = scoped["ref_store_core_receipts"]
        assert sorted(row["action"] for row in receipts) == ["create", "create", "create", "release", "renew"]
        for row in receipts:
            assert len(row["request_digest"]) == 64 and all(c in "0123456789abcdef" for c in row["request_digest"])
            assert 0 < len(row["body"]) <= 4096
            body = json.loads(row["body"])
            assert body["request_id"] == row["request_id"]
            assert body["snapshot_id"] == row["snapshot_id"]
            assert body["pin_id"] == row["pin_id"]
            assert body["pin_generation"] == row["pin_generation"]
            assert body["tenant_id"] == row["tenant_id"] and body["purpose"] == "backup"
            if row["action"] != "create":
                assert body["action"] == row["action"]
        repo_usage = scoped["ref_store_core_repo_usage"][0]
        tenant_usage = scoped["ref_store_core_tenant_usage"][0]
        for counter in ("snapshot_count", "snapshot_ref_count", "logical_bytes", "receipt_count"):
            assert repo_usage[counter] == tenant_usage[counter], "retained " + counter + " differs between scopes"
            assert repo_usage[counter] > 0
        assert repo_usage["snapshot_count"] == 3 and repo_usage["receipt_count"] == 5
        assert repo_usage["snapshot_ref_count"] == 3 * per_snapshot_refs

    # ------------------------------------------------------------------- seed
    def seed_core_fixture(self):
        # Validate both built executables before the drill executes anything: a
        # missing binary/receipt, a stub build, a digest mismatch or a helper
        # built from different source inputs fails before any database or
        # backup work starts.
        self.snapshot_helper = validate_snapshot_fixture_binary(
            self.args.snapshot_fixture_binary, self.args.binary,
            getattr(self.args, "snapshot_fixture_receipt", None),
            getattr(self.args, "candidate_receipt", None))
        result = super().seed_core_fixture()
        repository = uuid_literal(self.core_repo["id"])
        marker = self.run_snapshot_fixture("seed")
        self.assert_binary_binding("seed")
        self.snapshot_marker = marker
        assert json.loads(self.snapshot_manifest.read_text()) == marker, (
            "the private fixture manifest differs from the public marker")
        gate = self.core_gate_row()
        scope = marker["scope"]
        assert scope["repository_id"] == repository
        assert scope["tenant_id"] == uuid_literal(self.core_repo["tenant_id"])
        assert scope["owner_id"] == uuid_literal(self.core_repo["tenant_id"])
        assert scope["purpose"] == "backup"
        assert scope["object_format"] == gate["object_format"]
        assert scope["history_incarnation"] == gate["history_incarnation"]
        assert scope["authority_epoch"] == gate["authority_epoch"]
        assert scope["group_epoch"] == gate["group_epoch"]
        assert scope["gate_revision"] == gate["revision"]
        assert gate["revision"] == 2, "the seeded core gate revision must stay the SQL fixture revision"
        assert scope["head_ref"] == gate["head_ref"]
        assert marker["captured_refs"] and all(row["name"].startswith("refs/") for row in marker["captured_refs"])
        assert scope["head_ref"] in [row["name"] for row in marker["captured_refs"]]
        self.source_new_rows = self.new_rows()
        self.source_new_scoped_rows = self.new_scoped_rows()
        assert self.source_new_scoped_rows == marker["tables"], (
            "the adapter-seeded rows differ from the SQL capture of the same rows")
        self.assert_new_tables_populated(self.source_new_scoped_rows, marker)
        # A2 never rewrites the inherited migration-139/138 rows or the repository.
        assert self.core_rows() == self.source_core_rows, "A2 seeding mutated migration-139 rows"
        assert self.core_repository_row() == self.source_core_repo
        for table, rows in self.source_fixture_rows.items():
            assert self.core_fixture_rows(table) == rows, table + " changed during A2 seeding"
        request_ids = {entry["create_request_id"] for entry in marker["lifecycles"]}
        for entry in marker["lifecycles"]:
            for key in ("renew", "release"):
                if entry[key]:
                    request_ids.add(entry[key]["request_id"])
        operations = self.core_fixture_rows("ref_store_operations")
        assert len(operations) == 2, "the migration-138 operation registry gained or lost rows"
        assert not request_ids & {row["operation_id"] for row in operations}, (
            "a metadata snapshot/pin request was recorded as a ref operation")
        result.update({
            "adapter_seeded_schema140_tables": {table: len(rows) for table, rows in self.source_new_scoped_rows.items()},
            "snapshot_pin_lifecycles": {entry["kind"]: {
                "final_state": entry["final_state"],
                "final_generation": entry["final_generation"],
                "create_request_id": entry["create_request_id"],
                "pin_id": entry["pin_id"],
                "snapshot_id": entry["snapshot_id"],
            } for entry in marker["lifecycles"]},
            "trusted_metadata_scope_purpose": marker["scope"]["purpose"],
            "metadata_rows_came_from_real_adapter": True,
            "core_gate_version_confirmed_by_adapter": True,
            "schema140_core_and_139_rows_unchanged": True,
            "expired_pin_waited_on_database_clock_not_sql_lease_overwrite": True,
        })
        return result

    # -------------------------------------------------------------- backup 16
    def lock_and_snapshot(self):
        result = super().lock_and_snapshot()
        manifest = json.loads((self.backup / "manifest.json").read_text())
        assert manifest["format"] == CURRENT_BACKUP_FORMAT, (
            "the drill did not produce the current-format archive")
        assert manifest["schema_versions"] == SCHEMA_VERSIONS, (
            "the archive does not record exactly the current migration set")
        listing = self.run(["pg_restore", "--list", str(self.backup / "metadata.dump")]).stdout.decode()
        pack_tables = schema142_pack_tables()
        for table in pack_tables:
            assert ("TABLE DATA public " + table in listing) or (
                'TABLE DATA public "' + table + '"' in listing), (
                "parent snapshot dump silently excluded schema142 table " + table)
            assert self.sql(
                'SELECT count(*) FROM public."' + table + '"') == "0", (
                    "A2 fixture fabricated a schema142 pack row in " + table)
        assert self.sql(
            "SELECT string_agg(DISTINCT pack_mode, ',' ORDER BY pack_mode) "
            "FROM ref_store_core_gates") == "metadata_only"
        for table in A5_PACK_SNAPSHOT_TABLES:
            assert ("TABLE DATA public " + table in listing) or (
                'TABLE DATA public "' + table + '"' in listing), (
                "parent snapshot dump silently excluded schema143 table " + table)
            assert self.sql(
                'SELECT count(*) FROM public."' + table + '"') == "0", (
                    "A2 fixture fabricated an A5 snapshot-pack row in " + table)
        assert self.sql(
            "SELECT count(*) FROM ref_store_core_snapshots WHERE "
            "pack_mode<>'metadata_only' OR pack_count<>0 OR "
            "membership_digest IS NOT NULL OR snapshot_digest IS NOT NULL OR "
            "pack_membership_state<>'unavailable'") == "0"
        result.update({"backup_format": manifest["format"],
                       "schema143_pack_snapshot_tables": list(A5_PACK_SNAPSHOT_TABLES),
                       "schema142_pack_ledger_tables": pack_tables,
                       "schema142_pack_tables_empty_and_not_fabricated": True,
                       "gate_pack_mode_default_metadata_only": True,
                       "archive_contains_schema_versions": SCHEMA_VERSIONS[-6:]})
        return result

    # ------------------------------------------------------------- restore 140
    def reject_metadata(self, sql, message):
        self.reject_sql(sql, message)

    def restore_and_clone(self):
        """Restore for real, then prove every new row survived and is immutable."""
        result = super().restore_and_clone()
        repository = uuid_literal(self.core_repo["id"])
        tenant = uuid_literal(self.core_repo["tenant_id"])
        restored_rows = self.new_rows()
        assert restored_rows == self.source_new_rows, (
            "restored migration-140 rows differ: " + ", ".join(
                table for table in NEW_TABLES if restored_rows[table] != self.source_new_rows[table]))
        restored_scoped = self.new_scoped_rows()
        assert restored_scoped == self.source_new_scoped_rows, "restored fixture rows differ"
        self.assert_new_tables_populated(restored_scoped, self.snapshot_marker)
        restored_gate = self.core_gate_row()
        assert restored_gate["revision"] == 2
        assert restored_gate["revision"] == self.snapshot_marker["scope"]["gate_revision"]
        assert restored_gate["history_incarnation"] == self.snapshot_marker["scope"]["history_incarnation"]
        assert self.core_rows() == self.source_core_rows, "restored migration-139 rows differ"
        assert self.sql("SELECT max(version) FROM schema_migrations") == str(SCHEMA_VERSIONS[-1])
        assert self.sql("SELECT count(*) FROM schema_migrations WHERE version BETWEEN 138 AND " +
                        str(SCHEMA_VERSIONS[-1])) == str(
                            len([v for v in SCHEMA_VERSIONS if v >= 138]))
        for table in schema142_pack_tables() + list(A5_PACK_SNAPSHOT_TABLES):
            assert self.sql(
                'SELECT count(*) FROM public."' + table + '"') == "0", (
                    "restore fabricated a pack/snapshot row in " + table)
        assert self.sql(
            "SELECT count(*) FROM ref_store_core_snapshots WHERE "
            "pack_mode<>'metadata_only' OR pack_count<>0 OR "
            "membership_digest IS NOT NULL OR snapshot_digest IS NOT NULL OR "
            "pack_membership_state<>'unavailable'") == "0"
        assert restored_gate["pack_mode"] == "metadata_only", restored_gate
        restored_repo = self.core_repository_row()
        assert restored_repo == self.source_core_repo
        assert restored_repo["state"] == "provisioning"
        assert restored_repo["storage_backend"] == "gitfs"
        assert restored_repo["transition_state"] == "stable"
        assert restored_repo["provision_attempts"] == 0
        assert not (self.target / "repos" / (restored_repo["id"] + ".git")).exists()
        assert self.sql("SELECT count(*) FROM pando_repository_states WHERE repository_id='" + repository + "'") == "0"
        assert self.sql("SELECT count(*) FROM repository_ref_projection WHERE repository_id='" + repository + "'") == "0"
        # The verify helper rebuilds the identical typed requests from the
        # private manifest and replays them exactly.  Rows are captured before
        # and after so an accidental write, refund or revival cannot hide.
        before_replay = self.new_rows()
        verify = self.run_snapshot_fixture("verify", db=self.db)
        self.assert_binary_binding("verify")
        after_replay = self.new_rows()
        assert before_replay == after_replay, "the verify replay mutated restored metadata rows"
        assert verify["scope"] == self.snapshot_marker["scope"], "the restored gate scope differs from the seed scope"
        assert verify["restored_rows_equal_pre_backup_rows"] is True
        assert verify["exact_replay_returned_original_receipts"] is True
        assert verify["replay_mutated_rows_counters_or_timestamps"] is False
        typed = {entry["kind"]: entry["typed_state"] for entry in verify["lifecycles"]}
        assert typed == {"active": "live", "released": "released", "expired": "expired"}, typed
        assert self.new_rows() == self.source_new_rows
        lifecycles = {entry["kind"]: entry for entry in self.snapshot_marker["lifecycles"]}
        active = lifecycles["active"]
        released = lifecycles["released"]
        # The migration-140 triggers stay enabled: no test disables them.
        triggers = int(self.sql("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'ref_store_core_%'"))
        assert triggers >= 12, "the migration-140 guards are missing"
        assert self.sql("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'ref_store_core_%' "
                        "AND tgenabled <> 'O'") == "0", "a migration-140 guard was disabled"
        self.reject_metadata(
            "UPDATE public.ref_store_core_snapshots SET logical_bytes=logical_bytes+1 WHERE snapshot_id='" +
            active["snapshot_id"] + "'", "ref-store core metadata snapshot is immutable")
        self.reject_metadata(
            "UPDATE public.ref_store_core_snapshot_refs SET oid='" + "f" * 40 + "' WHERE snapshot_id='" +
            active["snapshot_id"] + "'", "ref-store core metadata snapshot is immutable")
        self.reject_metadata(
            "UPDATE public.ref_store_core_receipts SET body='{}' WHERE request_id='" +
            active["create_request_id"] + "'", "ref-store core mutation receipt is immutable")
        self.reject_metadata(
            "UPDATE public.ref_store_core_pins SET expires_at=clock_timestamp()+interval '1 hour' "
            "WHERE pin_id='" + active["pin_id"] + "'",
            "ref-store core pin active update is not a valid renewal")
        self.reject_metadata(
            "UPDATE public.ref_store_core_pins SET state='active',released_at=NULL "
            "WHERE pin_id='" + released["pin_id"] + "'", "is released and terminal")
        for table, key, value, message in (
                ("ref_store_core_pins", "pin_id", active["pin_id"],
                 "ref-store core pin cannot be deleted while its repository exists"),
                ("ref_store_core_snapshots", "snapshot_id", active["snapshot_id"],
                 "ref-store core snapshot cannot be deleted while its repository exists"),
                ("ref_store_core_snapshot_refs", "snapshot_id", active["snapshot_id"],
                 "ref-store core snapshot refs cannot be deleted"),
                ("ref_store_core_receipts", "request_id", active["create_request_id"],
                 "ref-store core receipt cannot be deleted"),
                ("ref_store_core_repo_usage", "repository_id", repository,
                 "ref-store core repository usage cannot be deleted"),
                ("ref_store_core_tenant_usage", "tenant_id", tenant,
                 "ref-store core tenant usage cannot be deleted")):
            self.reject_metadata("DELETE FROM public." + table + " WHERE " + key + "='" + value + "'", message)
        self.reject_metadata(
            "UPDATE public.ref_store_core_repo_usage SET receipt_count=0 WHERE repository_id='" +
            repository + "'", "ref-store core retained repository usage cannot decrease")
        self.reject_metadata(
            "UPDATE public.ref_store_core_tenant_usage SET tenant_id='" + str(uuid.uuid4()) +
            "' WHERE tenant_id='" + tenant + "'", "ref-store core tenant usage identity is immutable")
        assert self.new_rows() == self.source_new_rows, (
            "a rejected direct mutation changed restored migration-140 rows")
        assert self.core_rows() == self.source_core_rows
        assert self.core_repository_row() == self.source_core_repo
        (self.root / "restored-refstore-snapshot-rows.json").write_text(
            json.dumps({"scope": self.snapshot_marker["scope"],
                        "lifecycles": self.snapshot_marker["lifecycles"],
                        "fixture_rows_by_table": {table: len(rows) for table, rows in restored_scoped.items()}},
                       indent=2) + "\n")
        result.update({
            "all_six_schema140_tables_restored_exactly": True,
            "snapshot_pins_receipts_usage_nonempty_after_restore": True,
            "active_released_expired_states_present": True,
            "typed_replay_verify_helper_ran": True,
            "exact_replay_returned_old_receipts_without_writes": True,
            "direct_updates_deletes_refused_with_rows_unchanged": True,
            "triggers_enabled_not_disabled_by_the_drill": True,
            "snapshot_pins_are_not_physical_git_object_protection": True,
            "core_repository_stays_provisioning_gitfs_unserved": True,
            "schema142_pack_ledger_tables_empty_after_current_restore": True,
            "schema142_gate_pack_mode_metadata_only": True,
            "schema142_pack_registration_fabricated": False,
        })
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--snapshot-fixture-binary", required=True,
                        help="selected Rust integration-test executable for ref_store_snapshot_backup_fixture")
    parser.add_argument("--snapshot-fixture-receipt", type=Path,
                        help="build receipt for the helper (defaults to <helper>.build.json)")
    parser.add_argument("--candidate-receipt", type=Path,
                        help="candidate application build receipt (defaults to <binary>.build.json)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    args.snapshot_fixture_binary = str(Path(args.snapshot_fixture_binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("dedicated synthetic ROOTYARD_TEST_DATABASE_URL required")
    harness = BackupRefStoreSnapshot140Harness(args)
    success = False
    try:
        for name, function in [
            ("synthetic_source_with_seeded_refstore_core", harness.seed_core_fixture),
            ("offline_barriers_and_snapshot", harness.lock_and_snapshot),
            ("unsafe_or_corrupt_inputs", harness.invalid_inputs),
            ("backup_barrier_failures", harness.backup_barrier_failures),
            ("interrupted_restore_guard", harness.interrupted_restore),
            ("post_backup_write_not_in_snapshot", harness.write_after_backup),
            ("new_environment_restore_schema140_rows_clone_fsck", harness.restore_and_clone),
        ]:
            harness.case(name, function)
        assert len(harness.results) == 7, "the drill must run all seven backup cases"
        success = all(case["status"] == "passed" for case in harness.results)
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            print(harness.redact(error), file=sys.stderr)
            success = False
        report = dict(
            passed=success,
            cases=harness.results,
            binary=args.binary,
            binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            backup_format=CURRENT_BACKUP_FORMAT,
            snapshot_fixture_helper=harness.snapshot_helper,
            limitations=[
                "The migration-139 gate/refs/lane/operation rows are still a direct SQL metadata fixture; they are not an adapter or Git ACK.",
                "The migration-140 snapshot, ref, pin, receipt and usage rows are produced by the real typed PgRefStoreCore adapter and replayed through the public typed requests.",
                "A metadata pin is not protective of Git objects: pack membership stays 'unavailable', there is no physical GC or serving claim, and the drill repository is never served.",
                "Synthetic loopback drill, no host/disk power-loss or production RPO/RTO promise.",
                "This A2 fixture does not populate or assert the schema141 global artifact-hold ledger; hold-row roundtrip and Blob byte-closure qualification remain separate.",
                "Only three pin lifecycles (active renewed, exactly released, database-clock expired) are covered here; concurrency, quotas and ABA races are covered by the Rust suites.",
            ],
        )
        if args.keep:
            report["retained_directory"] = str(harness.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
