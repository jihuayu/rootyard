#!/usr/bin/env python3
"""Current-format19/schema143 backup roundtrip of a populated A5a pack-snapshot ledger.

This is the #105/#107 A5a drill. It subclasses the inherited
``tests/backup_refstore_core139.py`` seven-case harness, so the seven real
offline backup cases (synthetic source, barrier/snapshot, corrupt inputs,
barrier failure, interrupted restore, post-backup write exclusion and a fresh
authenticated restore/clone/fsck) stay mandatory with zero skips.

The four schema143 A5 tables *and* the complete migration-140 A2, migration-141
A3 and migration-142 A4 ledgers are populated by the real typed pipeline in
``tests/ref_store_pack_snapshots_backup_fixture.rs``: a fresh random unserved
repository gets a typed gate, one genuine A2 metadata-only snapshot is created
before activation, mature Git writes a real ``.pack``/``.idx`` for a synthetic
native commit, A3 acquires+consumes two holds and the protected uploader uploads
the exact bytes to the configured real S3 store, A4 registers the publication,
captures the closure context, runs the real native ``PackVerifier`` and performs
the verified PG commit. Only then are four A5 snapshots/pins created under a
separate producer identity B (publisher A stays the A4 owner): active (long TTL),
renewed (generation 2), released, and — created last with a 1s lease — expired by
a bounded database-clock poll. Nothing is faked with SQL: there is no SQL ACK, no
SQL proof and no SQL registration.

After the actual ``pg_dump``/restore the helper runs in verify mode against the
restored database and replays only typed read-only paths: ``PgPackSnapshot::read``
(full registered pack metadata, ``complete_git_read_snapshot()==false``),
``query_receipt`` (historical create -> ``Found``, renew/release -> ``FoundPin``,
no live lease) and the A2 page reader for the old metadata-only snapshot. It
mints no proof, grant or authority, charges no quota and needs no source-only
tempfiles; the external S3 originals are re-read and hashed. This drill compares
every schema143/142/141/140 table and the 139 core rows globally and scoped,
checks actual dump table inclusion, and requires the ``pack_verified`` gate to be
retained. The exact permanent counters are recomputed from the typed receipt
logical bytes plus the implementation's own fixed row overheads recorded in the
marker — never from an arbitrary estimate.

No Blob byte backup is claimed: the S3 originals are external, unchanged and
never deleted. No DSN/token/credential is written to the report.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

from backup_refstore_core139 import CORE_TABLES, BackupRefStoreCore139Harness, uuid_literal
from backup_refstore_holds141 import (
    candidate_receipt,
    load_receipt,
    receipt_field,
    receipt_flag,
    schema142_pack_tables,
    sha256_file,
)
from schema_baseline import A5_PACK_SNAPSHOT_TABLES, CURRENT_BACKUP_FORMAT, SCHEMA_VERSIONS

MARKER = "ROOTYARD-REF-STORE-PACK-SNAPSHOTS-FIXTURE-METADATA"
FIXTURE_KIND = "rootyard/ref-store-core-pack-snapshots-backup-fixture"
HELPER_TEST = "ref_store_pack_snapshot_backup_metadata_fixture"
HELPER_TARGET = "ref_store_pack_snapshots_backup_fixture"
ROOT = Path(__file__).resolve().parents[1]
HELPER_SOURCE = ROOT / "tests" / "ref_store_pack_snapshots_backup_fixture.rs"

HOLD_TABLES = (
    "artifact_hold_requests",
    "artifact_holds",
    "artifact_hold_consume_receipts",
    "artifact_hold_shards",
    "artifact_hold_repo_usage",
    "artifact_hold_tenant_usage",
)
TENANT_SCOPED_HOLDS = ("artifact_hold_tenant_usage",)
A2_TABLES = (
    "ref_store_core_snapshots",
    "ref_store_core_snapshot_refs",
    "ref_store_core_pins",
    "ref_store_core_receipts",
    "ref_store_core_repo_usage",
    "ref_store_core_tenant_usage",
)
A2_TENANT_TABLES = ("ref_store_core_tenant_usage",)

# Expected fixture cardinalities. Table *names* always come from the generated
# 143-vs-142 / 142-vs-141 / 141-vs-140 / 140-vs-139 catalogs; these dicts only
# pin the documented drill shape (one verified pack + four A5 scenarios).
SNAPSHOT_COUNTS = {
    "ref_store_core_snapshot_packs": 4,
    "ref_store_core_pack_snapshot_history": 6,
    "ref_store_core_pack_snapshot_repo_usage": 1,
    "ref_store_core_pack_snapshot_tenant_usage": 1,
}
A2_COUNTS = {
    "ref_store_core_snapshots": 5,
    "ref_store_core_snapshot_refs": 5,
    "ref_store_core_pins": 5,
    "ref_store_core_receipts": 7,
    "ref_store_core_repo_usage": 1,
    "ref_store_core_tenant_usage": 1,
}
PACK_COUNTS = {
    "ref_store_core_pack_publications": 1,
    "ref_store_core_pack_artifacts": 2,
    "ref_store_core_pack_memberships": 1,
    "ref_store_core_pack_history": 2,
    "ref_store_core_pack_repo_usage": 1,
    "ref_store_core_pack_tenant_usage": 1,
}
HOLD_COUNTS = {
    "artifact_hold_requests": 1,
    "artifact_holds": 2,
    "artifact_hold_consume_receipts": 2,
    "artifact_hold_shards": 64,
    "artifact_hold_repo_usage": 1,
    "artifact_hold_tenant_usage": 1,
}
CORE_COUNTS = {
    "ref_store_issuer_lanes": 1,
    "ref_store_operations": 1,
    "ref_store_cancellations": 0,
    "ref_store_core_gates": 1,
    "ref_store_core_refs": 1,
    "ref_store_core_events": 1,
}


def validate_snapshot_fixture_binary(helper, app_binary, helper_receipt=None, app_receipt=None):
    """Bind the selected helper executable to its real integration-test build."""
    helper = Path(helper)
    assert helper.is_file(), "pack-snapshot fixture binary is missing: " + str(helper)
    receipt_path = Path(helper_receipt) if helper_receipt else candidate_receipt(helper)
    receipt = load_receipt(receipt_path, "pack-snapshot fixture build receipt")
    actual = sha256_file(helper)
    recorded = receipt_field(receipt, ("binary_sha256", "artifact_sha256", "sha256"), "binary sha256")
    assert recorded == actual, "pack-snapshot fixture binary does not match its build receipt"
    kind = receipt_field(receipt, ("kind", "target_kind"), "build kind")
    assert kind == "rust-integration-test", "pack-snapshot fixture receipt kind is " + repr(kind)
    assert receipt_flag(receipt, ("package_rebuilt",), "package_rebuilt") is True
    entries = receipt.get("fresh_false_artifacts")
    assert isinstance(entries, list) and len(entries) == 1, (
        "pack-snapshot fixture receipt must record exactly one fresh=False artifact")
    entry = entries[0]
    assert isinstance(entry, dict), "pack-snapshot fixture fresh=False entry is not an object"
    assert str(entry.get("target")) == HELPER_TARGET, (
        "pack-snapshot fixture receipt target is " + repr(entry.get("target")) + ", expected " + HELPER_TARGET)
    assert entry.get("fresh") is False, "pack-snapshot fixture artifact is not marked fresh=False"
    assert str(entry.get("kind")) == "test", "pack-snapshot fixture artifact kind is not test"
    profile = entry.get("profile") or {}
    assert isinstance(profile, dict) and profile.get("test") is True, (
        "pack-snapshot fixture artifact was not built with a test profile")
    executable = entry.get("executable")
    assert executable, "pack-snapshot fixture artifact records no executable"
    assert Path(str(executable)).name.startswith(HELPER_TARGET), (
        "pack-snapshot fixture receipt artifact does not name the " + HELPER_TARGET + " target")
    assert receipt.get("relocated_artifact") is True, (
        "pack-snapshot fixture receipt must record the relocated integration-test artifact")
    source_sha = receipt_field(receipt, ("integration_test_source_sha256",), "integration_test_source_sha256")
    assert source_sha == sha256_file(HELPER_SOURCE), (
        "the pack-snapshot fixture receipt was produced from different integration-test source")
    source_inputs = receipt_field(receipt, ("source_inputs_sha256", "source_inputs"), "source_inputs_sha256")
    assert isinstance(source_inputs, str) and len(source_inputs) == 64, (
        "pack-snapshot fixture receipt has no source-input digest")
    app_receipt_path = Path(app_receipt) if app_receipt else candidate_receipt(Path(app_binary))
    app = load_receipt(app_receipt_path, "candidate application build receipt")
    app_actual = sha256_file(Path(app_binary))
    app_recorded = receipt_field(app, ("binary_sha256", "artifact_sha256", "sha256"), "candidate binary sha256")
    assert app_recorded == app_actual, "candidate application binary does not match its build receipt"
    assert receipt_flag(app, ("package_rebuilt",), "candidate package_rebuilt") is True
    app_entries = app.get("fresh_false_artifacts")
    assert isinstance(app_entries, list) and app_entries, "candidate has no fresh=False artifacts"
    assert all(isinstance(item, dict) and item.get("fresh") is False for item in app_entries)
    app_source = receipt_field(app, ("source_inputs_sha256", "source_inputs"), "candidate source_inputs_sha256")
    assert app_source == source_inputs, "helper and candidate application were built from different source inputs"
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


class BackupRefStorePackSnapshots143Harness(BackupRefStoreCore139Harness):
    """Populate the schema143 A5 ledger through the real typed pipeline, then restore."""

    def __init__(self, args):
        super().__init__(args)
        self.snapshot_fixture_binary = Path(args.pack_snapshot_fixture_binary)
        self.snapshot_manifest = self.root / "pack-snapshots-fixture-manifest.json"
        self.snapshot_helper = None
        self.snapshot_marker = None
        self.snapshot_scope = None
        self.snapshot_verify = None

    # -- helper process -----------------------------------------------------------------
    def fixture_env(self, mode, db):
        env = self.env.copy()
        env.update(
            ROOTYARD_TEST_DATABASE_URL=db,
            ROOTYARD_PACK_SNAPSHOTS_FIXTURE_MODE=mode,
            ROOTYARD_PACK_SNAPSHOTS_FIXTURE_OUTPUT=str(self.snapshot_manifest),
        )
        return env

    def run_snapshot_fixture(self, mode, db=None):
        assert self.snapshot_helper is not None, "helper binary was not validated"
        assert mode in ("seed", "verify")
        process = self.run(
            [str(self.snapshot_fixture_binary), "--ignored", "--exact", HELPER_TEST,
             "--format=terse", "--nocapture", "--test-threads=1"],
            env=self.fixture_env(mode, db or self.db))
        stdout = process.stdout.decode()
        summaries = [line for line in stdout.splitlines() if line.startswith("test result:")]
        assert summaries, "the pack-snapshot fixture reported no test result at all"
        summary = summaries[-1]
        assert "1 passed" in summary, "the pack-snapshot fixture did not run exactly one test: " + summary
        assert "0 failed" in summary, "the pack-snapshot fixture failed: " + summary
        assert "0 ignored" in summary, "the pack-snapshot fixture skipped its test: " + summary
        lines = [line for line in stdout.splitlines() if line.startswith(MARKER + " ")]
        assert len(lines) == 1, "the pack-snapshot fixture must print exactly one marker line"
        text = lines[0]
        assert self.redact(text) == text, "the pack-snapshot fixture marker leaked a credential or database URL"
        marker = json.loads(text[len(MARKER) + 1:])
        assert marker["kind"] == FIXTURE_KIND, "pack-snapshot fixture marker has an unexpected kind"
        assert marker["mode"] == mode, "pack-snapshot fixture marker reports an unexpected mode"
        assert marker["held_remote_objects_deleted"] is False, "the drill must not delete held remote objects"
        assert marker["restored_blob_bytes_backed_up"] is False
        assert marker["physical_blob_backup_closure"] is False
        assert marker["complete_git_read_snapshot_claimed"] is False
        assert marker["provider_io_attempted"] is True, "the provider IO of this drill is not optional"
        if mode == "seed":
            assert marker["protected_upload_attempted"] is True
            assert marker["s3_original_bytes_read_back_after_upload"] is True
            self.assert_counts(marker)
        else:
            assert marker["protected_upload_attempted"] is False, "restored verification must not upload"
            checks = marker["checks"]
            assert isinstance(checks, dict) and checks
            for key, value in checks.items():
                assert isinstance(value, bool), "verify check " + key + " is not boolean"
            for key in (
                    "restored_rows_equal_pre_backup_rows",
                    "historical_create_lookup_found",
                    "historical_renew_release_lookup_found_pin",
                    "active_and_renewed_read_complete_registered_membership",
                    "complete_git_read_snapshot_false",
                    "released_and_expired_read_refused",
                    "old_a2_metadata_snapshot_still_readable",
                    "permanent_and_transient_counters_unchanged",
                    "no_new_authority_charge_or_grant",
                    "s3_original_bytes_read_back_unchanged"):
                assert checks[key] is True, "verify check " + key + " did not hold"
            assert checks["source_only_tempfiles_required"] is False
            assert checks["quota_charged_by_replay"] is False
            self.assert_counts(marker)
        return marker

    def assert_binary_binding(self, stage):
        assert self.snapshot_helper is not None, "helper binary was not validated"
        helper = sha256_file(self.snapshot_fixture_binary)
        app = sha256_file(Path(self.args.binary))
        assert helper == self.snapshot_helper["binary_sha256"], (
            "helper binary changed after validation (" + stage + ")")
        assert app == self.snapshot_helper["candidate_application_sha256"], (
            "application binary changed after validation (" + stage + ")")
        self.snapshot_helper["retained_binding_stages"] = (
            self.snapshot_helper.get("retained_binding_stages", []) + [stage])
        self.snapshot_helper["helper_binary_sha256_after_run"] = helper
        self.snapshot_helper["candidate_application_sha256_after_run"] = app
        self.snapshot_helper["binaries_unchanged_after_run"] = True
        return {"stage": stage, "helper_binary_sha256": helper,
                "application_binary_sha256": app, "unchanged": True}

    # -- SQL observations (never an ACK) ------------------------------------------------
    def snapshot_tables(self):
        tables = A5_PACK_SNAPSHOT_TABLES
        assert sorted(tables) == sorted(SNAPSHOT_COUNTS), (
            "the generated 143-vs-142 catalog delta is " + repr(tables))
        return tables

    def pack_tables(self):
        tables = schema142_pack_tables()
        assert sorted(tables) == sorted(PACK_COUNTS), (
            "the generated 142-vs-141 catalog delta is " + repr(tables))
        return tables

    def _json_rows(self, table, where, db=None):
        sql = ("SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text), '[]'::json) "
               "FROM public." + table + " t")
        if where:
            sql += " WHERE " + where
        return json.loads(self.metadata_psql(sql, db=db).stdout.decode().strip())

    def _scoped_where(self, table, owner, scope):
        repo = uuid_literal(scope["repository_id"])
        tenant = uuid_literal(scope["tenant_id"])
        if owner == "tenant":
            return "t.tenant_id='" + tenant + "'"
        if owner == "all":
            return None
        if table == "ref_store_core_snapshot_refs":
            return ("t.snapshot_id IN (SELECT snapshot_id FROM public.ref_store_core_snapshots "
                    "WHERE repository_id='" + repo + "')")
        return "t.repository_id='" + repo + "'"

    def snapshot_rows(self, db=None, scoped=True):
        return {table: self._json_rows(
            table, self._scoped_where(table, "tenant", self.snapshot_scope) if scoped else None, db=db)
            for table in self.snapshot_tables()}

    def a2_rows(self, db=None, scoped=True):
        rows = {}
        for table in A2_TABLES:
            owner = "tenant" if table in A2_TENANT_TABLES else "repo"
            where = self._scoped_where(table, owner, self.snapshot_scope) if scoped else None
            rows[table] = self._json_rows(table, where, db=db)
        return rows

    def pack_rows(self, db=None, scoped=True):
        return {table: self._json_rows(
            table, self._scoped_where(table, "tenant", self.snapshot_scope) if scoped else None, db=db)
            for table in self.pack_tables()}

    def hold_rows(self, db=None, scoped=True):
        rows = {}
        for table in HOLD_TABLES:
            where = None
            if scoped and table != "artifact_hold_shards":
                owner = "tenant" if table in TENANT_SCOPED_HOLDS else "repo"
                where = self._scoped_where(table, owner, self.snapshot_scope)
            rows[table] = self._json_rows(table, where, db=db)
        return rows

    def pack_core_rows(self, db=None):
        repo = uuid_literal(self.snapshot_scope["repository_id"])
        return {table: self._json_rows(table, "t.repository_id='" + repo + "'", db=db)
                for table in CORE_TABLES}

    def pack_gate_row(self, db=None):
        return json.loads(self.metadata_psql(
            "SELECT to_jsonb(g) FROM public.ref_store_core_gates g WHERE g.repository_id='" +
            uuid_literal(self.snapshot_scope["repository_id"]) + "'", db=db).stdout.decode().strip())

    def a2_usage_row(self, db=None):
        return json.loads(self.metadata_psql(
            "SELECT to_jsonb(u) FROM public.ref_store_core_repo_usage u WHERE u.repository_id='" +
            uuid_literal(self.snapshot_scope["repository_id"]) + "'", db=db).stdout.decode().strip())

    def assert_counts(self, marker):
        counts = marker.get("counts") or {}
        assert sorted(counts["snapshot_packs"]) == sorted(self.snapshot_tables()), (
            "marker does not count all four 143 tables")
        assert counts["snapshot_packs"] == SNAPSHOT_COUNTS, "marker 143 row counts differ from the drill shape"
        assert sorted(counts["a2"]) == sorted(A2_TABLES), "marker does not count all six 140 tables"
        assert counts["a2"] == A2_COUNTS, "marker 140 row counts differ from the drill shape"
        assert sorted(counts["pack"]) == sorted(self.pack_tables()), "marker does not count all six 142 tables"
        assert counts["pack"] == PACK_COUNTS, "marker 142 row counts differ from the drill shape"
        assert sorted(counts["holds"]) == sorted(HOLD_TABLES), "marker does not count all six 141 tables"
        assert counts["holds"] == HOLD_COUNTS, "marker 141 row counts differ from the complete hold ledger"
        assert sorted(counts["core"]) == sorted(CORE_TABLES), "marker does not count all six 139 tables"
        assert all(value >= 0 for value in counts["core"].values())

    # -- semantic assertions -------------------------------------------------------------
    def assert_snapshot_ledger_populated(self, marker, rows, a2_rows, pack_rows, hold_rows, core_rows):
        counts = marker["counts"]
        assert counts["snapshot_packs"] == SNAPSHOT_COUNTS, "helper 143 counts differ from SQL row counts"
        for table, expected in SNAPSHOT_COUNTS.items():
            assert len(rows[table]) == expected, table + " rows are not populated exactly"
        for table, expected in A2_COUNTS.items():
            assert len(a2_rows[table]) == expected, table + " rows are not populated exactly"
        for table, expected in PACK_COUNTS.items():
            assert len(pack_rows[table]) == expected, table + " rows are not populated exactly"
        for table, expected in HOLD_COUNTS.items():
            assert len(hold_rows[table]) == expected, table + " rows are not populated exactly"
        for table, expected in CORE_COUNTS.items():
            assert len(core_rows[table]) == expected, table + " pack-repository rows are not populated exactly"

        scope = marker["scope"]
        plan = marker["plan"]
        ack = marker["registration"]["ack"]
        producer = scope["owner_id"]
        publisher = scope["publisher_owner_id"]
        assert producer != publisher, "the A5 producer must differ from the A4 publisher"
        assert producer != scope["tenant_id"], "the A5 producer must differ from the repository tenant"
        snapshots = marker["snapshots"]
        assert [entry["state"] for entry in snapshots] == ["active", "renewed", "released", "expired"]
        assert [entry["label"] for entry in snapshots] == ["active", "renewed", "released", "expired"]
        create_logical = []
        for entry in snapshots:
            assert entry["receipt"]["pack_mode"] == "pack_verified"
            assert entry["receipt"]["pack_count"] == 1 and entry["receipt"]["ref_count"] == 1
            assert entry["receipt"]["gate_revision"] == marker["gate"]["committed"]["revision"] == 2
            assert entry["receipt"]["owner_id"] == producer
            assert len(entry["request_digest"]) == 64 and len(entry["receipt"]["snapshot_digest"]) == 64
            assert entry["receipt"]["complete_git_read_snapshot"] is False
            assert entry["receipt"]["complete_registered_pack_membership"] is False
            create_logical.append(entry["receipt"]["logical_bytes"])
            if entry["state"] == "renewed":
                assert entry["renew"]["receipt"]["history_kind"] == "renewed"
                assert entry["renew"]["receipt"]["pin_generation"] == 2
                assert entry["renew"]["receipt"]["grants_live_lease"] is False
                assert entry["pin_generation"] == 2
            if entry["state"] == "released":
                assert entry["release"]["receipt"]["history_kind"] == "released"
                assert entry["release"]["receipt"]["released_at_unix_micros"] is not None
                assert entry["release"]["receipt"]["release_reason"] == "client_done"
            if entry["state"] == "expired":
                assert entry["lease_seconds"] == 1
                assert entry["request_id"] == snapshots[-1]["request_id"]
        assert snapshots[-1]["state"] == "expired", "the short-expiry scenario must be created LAST"

        old = marker["old_a2"]
        snapshots_by_id = {row["snapshot_id"]: row for row in a2_rows["ref_store_core_snapshots"]}
        expected_snapshot_ids = sorted([old["snapshot_id"]] +
                                       [entry["snapshot_id"] for entry in snapshots])
        assert sorted(snapshots_by_id) == expected_snapshot_ids, (
            "the SQL snapshot headers do not match the old A2 create plus four A5 receipts")
        assert old["snapshot_id"] in snapshots_by_id
        for entry in snapshots:
            row = snapshots_by_id[entry["snapshot_id"]]
            assert row["pack_mode"] == "pack_verified" and row["pack_count"] == 1
            assert row["pack_membership_state"] == "complete"
            assert row["membership_digest"] == entry["receipt"]["membership_digest"]
            assert row["snapshot_digest"] == entry["receipt"]["snapshot_digest"]
            assert row["refs_digest"] == entry["receipt"]["refs_digest"]
            assert row["gate_revision"] == entry["receipt"]["gate_revision"] == 2
            assert row["owner_id"] == producer and row["purpose"] == "verification"
            assert row["repository_id"] == scope["repository_id"] == ack["repository_id"]
            assert row["head_ref"] == "refs/heads/main"
            assert row["head_oid"] == marker["source"]["commit_oid"]
            assert row["ref_count"] == 1
            assert row["logical_bytes"] == entry["receipt"]["logical_bytes"] > 0
        old_row = snapshots_by_id[old["snapshot_id"]]
        assert old_row["pack_mode"] == "metadata_only" and old_row["pack_count"] == 0
        assert old_row["pack_membership_state"] == "unavailable"
        assert old_row["membership_digest"] is None and old_row["snapshot_digest"] is None
        assert old_row["gate_revision"] == 1 and old_row["owner_id"] == scope["tenant_id"]

        bindings = rows["ref_store_core_snapshot_packs"]
        a5_snapshot_ids = sorted(entry["snapshot_id"] for entry in snapshots)
        assert sorted({row["snapshot_id"] for row in bindings}) == a5_snapshot_ids, (
            "pack bindings do not cover exactly the four pack-aware snapshots")
        assert old["snapshot_id"] not in a5_snapshot_ids, (
            "the old metadata-only A2 snapshot must not have a pack binding")
        pack = plan["packs"][0]
        for binding in bindings:
            assert binding["repository_id"] == scope["repository_id"]
            assert binding["pack_id"] == ack["pack_id"] == pack["pack_id"]
            assert binding["registration_id"] == ack["registration_id"] == pack["registration_id"]
            assert binding["artifact_set_digest"] == ack["artifact_set_digest"]
            assert binding["joined_revision"] == 2

        history = rows["ref_store_core_pack_snapshot_history"]
        kinds = [row["kind"] for row in history]
        assert kinds.count("created") == 4 and kinds.count("renewed") == 1 and kinds.count("released") == 1
        request_ids = {}
        for entry in snapshots:
            request_ids[entry["request_id"]] = ("created", entry)
            for action in ("renew", "release"):
                if action in entry:
                    request_ids[entry[action]["request_id"]] = (entry[action]["receipt"]["history_kind"], entry)
        assert sorted(row["request_id"] for row in history) == sorted(request_ids), (
            "permanent history does not cover every typed request id")
        for row in history:
            kind, entry = request_ids[row["request_id"]]
            assert row["kind"] == kind
            assert row["repository_id"] == scope["repository_id"]
            assert row["tenant_id"] == scope["tenant_id"]
            assert row["owner_id"] == producer
            assert row["snapshot_id"] == entry["snapshot_id"] and row["pin_id"] == entry["pin_id"]
            assert row["gate_revision"] == 2 and row["pack_mode"] == "pack_verified"
            assert row["membership_digest"] == entry["receipt"]["membership_digest"]
            assert row["snapshot_digest"] == entry["receipt"]["snapshot_digest"]
            assert row["refs_digest"] == entry["receipt"]["refs_digest"]
            assert row["pack_count"] == 1 and row["ref_count"] == 1
            assert row["logical_bytes"] == entry["receipt"]["logical_bytes"]
            if "original_request_digest" in row:
                assert row["original_request_digest"] == entry["request_digest"], (
                    "the permanent history lost the original create request digest")
            assert 0 < len(row["body"].encode("utf-8")) <= 4096
            assert json.loads(row["body"])["snapshot_id"] == entry["snapshot_id"]

        pins = {row["pin_id"]: row for row in a2_rows["ref_store_core_pins"]}
        receipts = {row["request_id"]: row for row in a2_rows["ref_store_core_receipts"]}
        a2_request_ids = set(request_ids) | {old["request_id"]}
        assert sorted(receipts) == sorted(a2_request_ids), (
            "A2 receipts must cover the old A2 create plus all six A5 request ids")
        old_receipt = receipts[old["request_id"]]
        assert old_receipt["action"] == "create"
        assert old_receipt["snapshot_id"] == old["snapshot_id"]
        assert old_receipt["pin_id"] == old["pin_id"]
        assert old_receipt["request_digest"] == old["request_digest"]
        assert pins[old["pin_id"]]["state"] == "active"
        for entry in snapshots:
            pin = pins[entry["pin_id"]]
            assert pin["snapshot_id"] == entry["snapshot_id"]
            assert pin["generation"] == entry["pin_generation"]
            assert pin["purpose"] == "verification" and pin["owner_id"] == producer
            if entry["state"] == "released":
                assert pin["state"] == "released"
                assert pin["released_at"] is not None and pin["release_reason"] == "client_done"
            else:
                assert pin["state"] == "active" and pin["released_at"] is None
            receipt = receipts[entry["request_id"]]
            assert receipt["action"] == "create" and receipt["pin_id"] == entry["pin_id"]
            assert receipt["snapshot_id"] == entry["snapshot_id"]
            assert receipt["request_digest"] == entry["request_digest"]
            for action in ("renew", "release"):
                if action not in entry:
                    continue
                mutation = receipts[entry[action]["request_id"]]
                assert mutation["action"] == action
                assert mutation["request_digest"] == entry[action]["request_digest"]
                assert mutation["pin_id"] == entry["pin_id"]
                body = json.loads(mutation["body"])
                assert body["pin_id"] == entry["pin_id"]
        assert len(receipts) == 7, "A2 receipts must be one old create plus six A5 mutations"

        a5_usage = rows["ref_store_core_pack_snapshot_repo_usage"][0]
        tenant_usage = rows["ref_store_core_pack_snapshot_tenant_usage"][0]
        counters = ("snapshot_count", "snapshot_ref_count", "binding_count", "pin_count",
                    "history_count", "receipt_count", "logical_bytes")
        assert [a5_usage[name] for name in counters] == marker["usage"]
        assert [tenant_usage[name] for name in counters] == marker["tenant_usage"] == marker["usage"]
        assert a5_usage["repository_id"] == ack["repository_id"] and a5_usage["tenant_id"] == ack["tenant_id"]
        assert tenant_usage["tenant_id"] == ack["tenant_id"]
        assert [a5_usage[name] for name in counters[:6]] == [4, 4, 4, 4, 6, 6]
        accounting = marker["logical_accounting"]
        assert accounting["create_receipt_logical_bytes"] == create_logical
        # Both fixed components are measured from actual typed operations by the
        # helper, so this harness never guesses an implementation constant.
        assert accounting["a2_fixed_charge_bytes"] > 0
        assert accounting["lifecycle_charge_bytes"] > 0
        assert accounting["create_fixed_charge_bytes"] == (
            accounting["a2_fixed_charge_bytes"] + accounting["lifecycle_charge_bytes"])
        expected_logical = (sum(create_logical) + 4 * accounting["create_fixed_charge_bytes"] +
                            2 * accounting["lifecycle_charge_bytes"])
        assert accounting["expected_logical_bytes"] == expected_logical, "typed accounting is inconsistent"
        assert a5_usage["logical_bytes"] == expected_logical, "the SQL counter differs from the typed charge"

        a2_usage = self.a2_usage_row() if self.snapshot_scope else None
        assert a2_usage is not None
        assert [a2_usage[name] for name in
                ("snapshot_count", "snapshot_ref_count", "logical_bytes", "receipt_count")] == marker["a2_usage"]
        assert a2_usage["snapshot_count"] == 5 and a2_usage["snapshot_ref_count"] == 5
        assert a2_usage["receipt_count"] == 7 and a2_usage["logical_bytes"] > 0

        gate = core_rows["ref_store_core_gates"][0]
        assert gate["pack_mode"] == "pack_verified" and gate["revision"] == 2
        assert gate["head_ref"] == "refs/heads/main" and gate["tenant_id"] == ack["tenant_id"]
        publication = pack_rows["ref_store_core_pack_publications"][0]
        assert publication["registration_id"] == ack["registration_id"]
        assert publication["pack_id"] == ack["pack_id"]
        assert publication["owner_id"] == publisher, "the A4 publication owner is not publisher A"
        assert publication["gate_revision"] == 1 and publication["pack_mode"] == "metadata_only"
        assert json.loads(publication["ack_body"]) == ack
        membership = pack_rows["ref_store_core_pack_memberships"][0]
        assert membership["pack_id"] == ack["pack_id"] and membership["joined_revision"] == 2
        assert membership["artifact_set_digest"] == ack["artifact_set_digest"]
        artifacts = {row["role"]: row for row in pack_rows["ref_store_core_pack_artifacts"]}
        assert sorted(artifacts) == ["idx", "pack"]
        assert artifacts["pack"]["sha256"] == plan["packs"][0]["pack_sha256"]
        assert artifacts["idx"]["sha256"] == plan["packs"][0]["idx_sha256"]
        assert sorted(row["hold_id"] for row in pack_rows["ref_store_core_pack_artifacts"]) == sorted(ack["hold_ids"])
        history142 = pack_rows["ref_store_core_pack_history"]
        assert sorted(row["kind"] for row in history142) == ["committed", "registered"]
        assert [row["revision"] for row in history142 if row["kind"] == "registered"] == [1]
        assert [row["revision"] for row in history142 if row["kind"] == "committed"] == [2]
        holds = hold_rows["artifact_holds"]
        assert len(holds) == 2 and all(row["state"] == "active" for row in holds)
        refs = core_rows["ref_store_core_refs"]
        assert len(refs) == 1 and refs[0]["oid"] == marker["source"]["commit_oid"]

    # -- the inherited seven-case hooks -------------------------------------------------
    def seed_core_fixture(self):
        self.snapshot_helper = validate_snapshot_fixture_binary(
            self.args.pack_snapshot_fixture_binary, self.args.binary,
            getattr(self.args, "pack_snapshot_fixture_receipt", None),
            getattr(self.args, "candidate_receipt", None))
        result = super().seed_core_fixture()
        marker = self.run_snapshot_fixture("seed")
        self.assert_binary_binding("seed")
        self.snapshot_marker = marker
        assert json.loads(self.snapshot_manifest.read_text()) == marker, (
            "the private pack-snapshot fixture manifest differs from the public marker")
        self.snapshot_scope = marker["scope"]
        assert self.snapshot_scope["repository_id"] != self.core_repo["id"], (
            "the typed native gate must not reuse the inherited plain-SQL 139 gate repository")
        gate = self.pack_gate_row()
        assert gate["pack_mode"] == marker["gate"]["committed"]["pack_mode"] == "pack_verified"
        assert gate["revision"] == marker["gate"]["committed"]["revision"] == 2
        self.source_snapshot_rows = self.snapshot_rows()
        self.source_snapshot_rows_global = self.snapshot_rows(scoped=False)
        self.source_a2_rows = self.a2_rows()
        self.source_a2_rows_global = self.a2_rows(scoped=False)
        self.source_pack_rows = self.pack_rows()
        self.source_pack_rows_global = self.pack_rows(scoped=False)
        self.source_hold_rows = self.hold_rows()
        self.source_hold_rows_global = self.hold_rows(scoped=False)
        self.source_pack_core_rows = self.pack_core_rows()
        assert self.source_snapshot_rows == marker["rows"]["snapshot_packs"], (
            "typed A5 rows differ from the helper's SQL capture of the same rows")
        assert self.source_a2_rows == marker["rows"]["a2"], (
            "typed A2 rows differ from the helper's SQL capture of the same rows")
        assert self.source_pack_rows == marker["rows"]["pack"], (
            "typed A4 pack rows differ from the helper's SQL capture of the same rows")
        assert self.source_hold_rows == marker["rows"]["holds"], (
            "typed A3 hold rows differ from the helper's SQL capture of the same rows")
        assert self.source_pack_core_rows == marker["rows"]["core"], (
            "typed pack-repository core rows differ from the helper's SQL capture")
        self.assert_snapshot_ledger_populated(marker, self.source_snapshot_rows, self.source_a2_rows,
                                              self.source_pack_rows, self.source_hold_rows,
                                              self.source_pack_core_rows)
        self._adopt_typed_fixture(marker)
        (self.root / "source-refstore-pack-snapshots-rows.json").write_text(
            json.dumps({"scope": marker["scope"], "gate": marker["gate"], "plan": marker["plan"],
                        "source": marker["source"], "old_a2": marker["old_a2"],
                        "snapshots": marker["snapshots"], "usage": marker["usage"],
                        "a2_usage": marker["a2_usage"],
                        "logical_accounting": marker["logical_accounting"],
                        "snapshot_rows_by_table": {table: len(rows)
                                                   for table, rows in self.source_snapshot_rows.items()},
                        "a2_rows_by_table": {table: len(rows)
                                             for table, rows in self.source_a2_rows.items()},
                        "pack_rows_by_table": {table: len(rows)
                                               for table, rows in self.source_pack_rows.items()},
                        "hold_rows_by_table": {table: len(rows)
                                               for table, rows in self.source_hold_rows.items()}},
                       indent=2) + "\n")
        result.update({
            "adapter_seeded_schema143_pack_snapshot_tables": {
                table: len(rows) for table, rows in self.source_snapshot_rows.items()},
            "adapter_seeded_schema140_a2_tables": {
                table: len(rows) for table, rows in self.source_a2_rows.items()},
            "adapter_seeded_schema142_pack_tables": {
                table: len(rows) for table, rows in self.source_pack_rows.items()},
            "adapter_seeded_complete_schema141_hold_tables": {
                table: len(rows) for table, rows in self.source_hold_rows.items()},
            "typed_native_pack_commit_registered_and_verified": True,
            "native_pack_verifier_proof_minted_by_real_verifier": True,
            "sql_faked_ack_or_registration": False,
            "pack_snapshot_producer_differs_from_a4_publisher": True,
            "pack_snapshot_scenarios": [entry["state"] for entry in marker["snapshots"]],
            "pack_snapshot_history_kinds": ["created", "created", "created", "created", "renewed", "released"],
            "pack_snapshot_db_clock_expired_last": True,
            "pack_gate_pack_mode": gate["pack_mode"],
            "pack_gate_revision": gate["revision"],
            "restored_blob_bytes_backed_up": False,
            "held_remote_objects_deleted": False,
        })
        return result

    def _adopt_typed_fixture(self, marker):
        """The typed fixture adds rows only for its own new repository."""
        repo = uuid_literal(marker["scope"]["repository_id"])
        before = self.source_core_rows
        after = self.core_rows()
        for table in CORE_TABLES:
            before_other = [row for row in before[table] if row.get("repository_id") != repo]
            after_other = [row for row in after[table] if row.get("repository_id") != repo]
            assert after_other == before_other, table + " inherited rows changed during typed seeding"
            added = [row for row in after[table] if row.get("repository_id") == repo]
            assert len(added) == CORE_COUNTS[table], table + " pack-repository row count differs"
            assert not [row for row in before[table] if row.get("repository_id") == repo], (
                table + " already held pack-repository rows before seeding")
        for table in self.core_expected_counts:
            assert self.core_fixture_rows(table) == self.source_fixture_rows[table], (
                table + " inherited fixture rows changed during typed seeding")
        assert self.core_repository_row() == self.source_core_repo, "the inherited repository row changed"
        self.source_core_rows = after

    def lock_and_snapshot(self):
        result = super().lock_and_snapshot()
        manifest = json.loads((self.backup / "manifest.json").read_text())
        assert manifest["format"] == CURRENT_BACKUP_FORMAT, "drill did not produce the current backup format"
        assert manifest["schema_versions"] == SCHEMA_VERSIONS, "the archive schema versions differ"
        assert SCHEMA_VERSIONS[-1] == 143, "the current schema is not migration 143"
        assert "metadata.dump" in manifest["files"], "the parent snapshot has no metadata dump"
        listing = self.run(["pg_restore", "--list", str(self.backup / "metadata.dump")]).stdout.decode()
        expected = list(self.snapshot_tables()) + list(A2_TABLES) + self.pack_tables() + list(HOLD_TABLES)
        for table in expected:
            assert (("TABLE DATA public " + table in listing) or
                    ('TABLE DATA public "' + table + '"' in listing)), (
                "parent snapshot dump silently excluded table " + table)
            assert int(self.sql('SELECT count(*) FROM public."' + table + '"')) > 0, (
                "the drill left table " + table + " empty")
        for table, expected_count in SNAPSHOT_COUNTS.items():
            assert self.sql('SELECT count(*) FROM public."' + table + '"') == str(expected_count), (
                table + " row count differs before the backup")
        assert self.sql("SELECT count(*) FROM ref_store_core_pack_snapshot_history "
                        "WHERE kind='created'") == "4", "created history rows are not four"
        assert self.sql("SELECT count(*) FROM ref_store_core_pack_snapshot_history "
                        "WHERE kind IN ('renewed','released')") == "2", "lifecycle history rows are not two"
        assert self.sql("SELECT count(*) FROM ref_store_core_snapshots WHERE pack_mode='pack_verified'") == "4", (
            "the snapshot does not carry exactly four pack-verified snapshots")
        assert self.sql("SELECT count(*) FROM ref_store_core_snapshots WHERE pack_mode='metadata_only' "
                        "AND pack_membership_state<>'unavailable'") == "0", (
            "an old metadata-only snapshot was rewritten")
        assert self.sql("SELECT count(*) FROM ref_store_core_gates WHERE pack_mode='pack_verified'") == "1", (
            "the snapshot does not carry exactly one activated pack gate")
        assert self.pack_gate_row()["pack_mode"] == "pack_verified"
        result.update({
            "backup_format": manifest["format"],
            "schema143_is_current_base": True,
            "schema143_pack_snapshot_tables": list(self.snapshot_tables()),
            "schema143_pack_snapshot_tables_nonempty": True,
            "schema140_a2_tables_nonempty": True,
            "schema142_pack_ledger_tables": self.pack_tables(),
            "schema142_pack_ledger_nonempty": True,
            "schema141_hold_ledger_complete": {table: len(rows)
                                               for table, rows in self.source_hold_rows.items()},
            "parent_snapshot_inspected_dynamic_schema143_tables": list(self.snapshot_tables()),
            "gate_pack_mode_pack_verified": True,
        })
        return result

    def reject_guard(self, sql, message):
        self.reject_sql(sql, message)

    def restore_and_clone(self):
        result = super().restore_and_clone()
        marker = self.snapshot_marker
        restored = {
            "snapshot_packs": self.snapshot_rows(),
            "a2": self.a2_rows(),
            "pack": self.pack_rows(),
            "holds": self.hold_rows(),
            "core": self.pack_core_rows(),
        }
        source = {
            "snapshot_packs": self.source_snapshot_rows,
            "a2": self.source_a2_rows,
            "pack": self.source_pack_rows,
            "holds": self.source_hold_rows,
            "core": self.source_pack_core_rows,
        }
        for family, label in (("snapshot_packs", "schema143 A5"),
                              ("a2", "schema140 A2"),
                              ("pack", "schema142 A4"),
                              ("holds", "schema141 A3"),
                              ("core", "schema139 core")):
            assert restored[family] == source[family], (
                "restored " + label + " rows differ: " + ", ".join(
                    table for table in source[family]
                    if restored[family].get(table) != source[family][table]))
            assert self._global(family) == self._global_seed(family), (
                "restored global " + label + " rows differ")
        self.assert_snapshot_ledger_populated(marker, restored["snapshot_packs"], restored["a2"],
                                              restored["pack"], restored["holds"], restored["core"])
        gate = self.pack_gate_row()
        assert gate["pack_mode"] == "pack_verified" and gate["revision"] == 2
        assert self.sql("SELECT max(version) FROM schema_migrations") == str(SCHEMA_VERSIONS[-1])
        assert self.sql("SELECT count(*) FROM schema_migrations WHERE version BETWEEN 138 AND " +
                        str(SCHEMA_VERSIONS[-1])) == str(
                            len([v for v in SCHEMA_VERSIONS if v >= 138]))

        # Read-only typed replay against the restored database.
        before = {
            "snapshot_packs": self.snapshot_rows(scoped=False),
            "a2": self.a2_rows(scoped=False),
            "pack": self.pack_rows(scoped=False),
            "holds": self.hold_rows(scoped=False),
            "core": self.core_rows(),
        }
        verify = self.run_snapshot_fixture("verify", db=self.db)
        self.snapshot_verify = verify
        self.assert_binary_binding("verify")
        after = {
            "snapshot_packs": self.snapshot_rows(scoped=False),
            "a2": self.a2_rows(scoped=False),
            "pack": self.pack_rows(scoped=False),
            "holds": self.hold_rows(scoped=False),
            "core": self.core_rows(),
        }
        assert before == after, "the read-only restored verification mutated rows, counters or timestamps"
        assert json.loads(self.snapshot_manifest.read_text()) == verify, (
            "the verify manifest differs from the public verify marker")
        assert verify["scope"] == marker["scope"], "restored typed scope differs from seed"
        assert verify["plan"] == marker["plan"], "the restored rebuilt plan differs from seed"
        assert verify["gate"] == marker["gate"], "the restored gate differs from seed"
        assert verify["snapshots"] == marker["snapshots"], "the restored typed snapshots differ from seed"
        assert verify["old_a2"] == marker["old_a2"], "the restored old A2 evidence differs from seed"
        assert verify["usage"] == marker["usage"], "the restored permanent counters differ"
        assert verify["a2_usage"] == marker["a2_usage"], "the restored A2 counters differ"
        assert verify["snapshot_counts"] == marker["snapshot_counts"]
        assert verify["a3_ack"] == marker["a3"]["ack"]
        assert verify["a3_receipts"] == marker["a3"]["receipts"]
        assert verify["registration_ack"] == marker["registration"]["ack"]
        assert verify["terminal"] == marker["terminal"]
        assert verify["counts"] == marker["counts"]

        # Immutable ledger, monotone counters and the one-way pack-mode fence.
        rows = restored["snapshot_packs"]
        history = rows["ref_store_core_pack_snapshot_history"]
        a5_usage = rows["ref_store_core_pack_snapshot_repo_usage"][0]
        tenant_usage = rows["ref_store_core_pack_snapshot_tenant_usage"][0]
        binding = rows["ref_store_core_snapshot_packs"][0]
        repo = uuid_literal(marker["scope"]["repository_id"])
        tenant = uuid_literal(marker["scope"]["tenant_id"])
        immutable = "ref-store core pack snapshot"
        monotone = "pack snapshot usage counters are monotone and cannot be refunded"
        self.reject_guard("UPDATE public.ref_store_core_pack_snapshot_history SET body='{}' "
                          "WHERE history_id='" + history[0]["history_id"] + "'", immutable)
        self.reject_guard("DELETE FROM public.ref_store_core_pack_snapshot_history "
                          "WHERE history_id='" + history[0]["history_id"] + "'", immutable)
        self.reject_guard("UPDATE public.ref_store_core_snapshot_packs SET joined_revision=1 "
                          "WHERE snapshot_id='" + binding["snapshot_id"] + "'", immutable)
        self.reject_guard("DELETE FROM public.ref_store_core_snapshot_packs "
                          "WHERE snapshot_id='" + binding["snapshot_id"] + "'", immutable)
        self.reject_guard("UPDATE public.ref_store_core_pack_snapshot_repo_usage "
                          "SET history_count=history_count-1 WHERE repository_id='" + repo + "'", monotone)
        self.reject_guard("UPDATE public.ref_store_core_pack_snapshot_tenant_usage "
                          "SET receipt_count=receipt_count-1 WHERE tenant_id='" + tenant + "'", monotone)
        self.reject_guard("UPDATE public.ref_store_core_pack_snapshot_repo_usage "
                          "SET repository_id=gen_random_uuid() WHERE repository_id='" + repo + "'",
                          "pack snapshot usage row identity is immutable")
        self.reject_guard("DELETE FROM public.ref_store_core_pack_snapshot_repo_usage "
                          "WHERE repository_id='" + repo + "'", immutable)
        self.reject_guard("UPDATE public.ref_store_core_gates SET pack_mode='metadata_only' "
                          "WHERE repository_id='" + repo + "'",
                          "ref-store core pack mode is one-way and cannot be downgraded")
        triggers = int(self.sql("SELECT count(*) FROM pg_trigger WHERE tgname LIKE "
                                "'ref_store_core_pack_snapshot%'"))
        assert triggers >= 10, "the migration-143 history/usage/binding guards are missing"
        assert self.sql("SELECT count(*) FROM pg_trigger WHERE tgname LIKE "
                        "'ref_store_core_pack_snapshot%' AND tgenabled <> 'O'") == "0", (
            "a migration-143 guard was disabled")
        assert self.snapshot_rows() == self.source_snapshot_rows
        assert self.snapshot_rows(scoped=False) == self.source_snapshot_rows_global
        assert self.a2_rows() == self.source_a2_rows
        assert self.a2_rows(scoped=False) == self.source_a2_rows_global
        assert self.pack_rows() == self.source_pack_rows
        assert self.hold_rows() == self.source_hold_rows
        assert self.pack_core_rows() == self.source_pack_core_rows
        assert self.pack_gate_row()["pack_mode"] == "pack_verified"
        (self.root / "restored-refstore-pack-snapshots-rows.json").write_text(
            json.dumps({"scope": marker["scope"], "gate": marker["gate"], "plan": marker["plan"],
                        "source": marker["source"], "old_a2": marker["old_a2"],
                        "snapshots": marker["snapshots"], "usage": marker["usage"],
                        "a2_usage": marker["a2_usage"], "terminal": marker["terminal"],
                        "snapshot_rows_by_table": {table: len(value)
                                                   for table, value in restored["snapshot_packs"].items()},
                        "a2_rows_by_table": {table: len(value)
                                             for table, value in restored["a2"].items()}},
                       indent=2) + "\n")
        result.update({
            "all_four_schema143_tables_restored_exactly": True,
            "all_six_schema140_a2_tables_restored_exactly": True,
            "schema142_pack_ledger_restored_exactly": True,
            "complete_schema141_hold_ledger_restored_exactly": True,
            "schema143_active_renewed_released_expired_rows_restored_exactly": True,
            "schema143_pack_verified_gate_retained": True,
            "typed_read_back_complete_registered_membership": True,
            "typed_read_back_complete_git_read_snapshot_false": True,
            "historical_create_and_pin_lookups_resolved": True,
            "released_and_expired_pins_refused_by_the_restored_reader": True,
            "old_a2_metadata_only_snapshot_still_readable": True,
            "restored_counters_not_charged_by_replay": True,
            "direct_updates_deletes_refused_with_rows_unchanged": True,
            "pack_mode_downgrade_refused": True,
            "triggers_enabled_not_disabled_by_the_drill": True,
            "s3_original_bytes_external_and_unchanged_after_restore": True,
            "s3_originals_read_back_and_hashed": True,
            "byte_backup_or_physical_protection_closure_claimed": False,
            "held_remote_objects_deleted": False,
        })
        return result

    def _global(self, family):
        if family == "snapshot_packs":
            return self.snapshot_rows(scoped=False)
        if family == "a2":
            return self.a2_rows(scoped=False)
        if family == "pack":
            return self.pack_rows(scoped=False)
        if family == "holds":
            return self.hold_rows(scoped=False)
        return self.core_rows()

    def _global_seed(self, family):
        return {
            "snapshot_packs": self.source_snapshot_rows_global,
            "a2": self.source_a2_rows_global,
            "pack": self.source_pack_rows_global,
            "holds": self.source_hold_rows_global,
            "core": self.source_core_rows,
        }[family]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--pack-snapshot-fixture-binary", required=True,
                        help="selected Rust integration-test executable for "
                             "ref_store_pack_snapshots_backup_fixture")
    parser.add_argument("--pack-snapshot-fixture-receipt", type=Path,
                        help="build receipt for the helper (defaults to <helper>.build.json)")
    parser.add_argument("--candidate-receipt", type=Path,
                        help="candidate application build receipt (defaults to <binary>.build.json)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    args.pack_snapshot_fixture_binary = str(Path(args.pack_snapshot_fixture_binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("dedicated synthetic ROOTYARD_TEST_DATABASE_URL required")
    harness = BackupRefStorePackSnapshots143Harness(args)
    success = False
    try:
        for name, function in [
            ("synthetic_source_with_typed_native_pack_snapshot_ledger", harness.seed_core_fixture),
            ("offline_barriers_and_snapshot", harness.lock_and_snapshot),
            ("unsafe_or_corrupt_inputs", harness.invalid_inputs),
            ("backup_barrier_failures", harness.backup_barrier_failures),
            ("interrupted_restore_guard", harness.interrupted_restore),
            ("post_backup_write_not_in_snapshot", harness.write_after_backup),
            ("new_environment_restore_schema143_pack_snapshots_clone_fsck", harness.restore_and_clone),
        ]:
            harness.case(name, function)
        assert len(harness.results) == 7, "the drill must run all seven real backup cases"
        assert all(case["status"] == "passed" for case in harness.results), "a backup case did not pass"
        success = True
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
            skips=0,
            binary=args.binary,
            binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            backup_format=CURRENT_BACKUP_FORMAT,
            schema_version=SCHEMA_VERSIONS[-1],
            pack_snapshot_fixture_helper=harness.snapshot_helper,
            limitations=[
                "The typed A5/A4/A3 ledger is seeded by the real adapter and native PackVerifier; no SQL ACK, proof, receipt or registration is fabricated.",
                "The inherited migration-139 metadata gate/ref fixture is plain SQL and is never used for the native proof; the drill uses its own typed gate.",
                "The random pack repository stays provisioning/gitfs/unserved for the whole drill.",
                "The DB-clock-expired scenario uses a 1s lease and a bounded clock_timestamp() poll, created last; it is not a TTL unit test.",
                "complete_git_read_snapshot() is false everywhere: this drill claims registered pack membership metadata only, never verified Blob bytes or native Git object closure.",
                "Blob byte backup is not claimed: the S3 originals are external, re-read read-only and never deleted; only PostgreSQL metadata is restored.",
                "The read-only restored replay mints no proof, grant or authority and charges no quota.",
                "Synthetic loopback drill, no host/disk power-loss or production RPO/RTO promise.",
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
