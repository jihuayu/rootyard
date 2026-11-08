#!/usr/bin/env python3
"""Current-format18/schema142 backup roundtrip of a populated A4a pack ledger.

This is the #107 A4a drill. It subclasses the inherited
``tests/backup_refstore_core139.py`` seven-case harness, so the seven real
offline backup cases (synthetic source, barrier/snapshot, corrupt inputs,
barrier failure, interrupted restore, post-backup write exclusion and a fresh
authenticated restore/clone/fsck) stay mandatory with zero skips.

The six schema142 pack-ledger tables are populated by the real typed pipeline in
``tests/ref_store_packs_backup_fixture.rs``: a fresh random unserved repository
gets a typed core gate, mature Git writes a real ``.pack``/``.idx`` for a
synthetic native commit, A3 acquires+consumes two holds and the protected
uploader uploads the exact bytes to the configured real S3 store, A4 registers
the publication, captures the closure context, runs the real native
``PackVerifier`` and performs the verified PG commit. Nothing is faked with SQL:
there is no SQL ACK, no SQL proof and no SQL registration. The inherited
migration-139 metadata gate/ref fixture is a plain-SQL fixture whose
``refs/heads/main`` names no real Git object, so the native proof deliberately
uses its own separate typed gate/repository (the internal producer identity and
its tenant are reported, never required to equal the inherited fixture).

After the actual ``pg_dump``/restore the helper runs in verify mode against the
restored database and replays only typed read-only paths: immutable
``query_registration``, the A3 acquire/consume receipt lookups and the
migration-138 operation terminal lookup. It mints no proof, grant or authority,
charges no quota and needs no source-only tempfiles; the external S3 originals
are re-read and hashed. This drill compares every schema142 table plus the
complete old migration-141 hold ledger and the pack repository's 139 rows
globally and scoped, checks actual dump table inclusion and requires the
``pack_verified`` gate to be retained.

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
from schema_baseline import CURRENT_BACKUP_FORMAT, SCHEMA_VERSIONS

MARKER = "ROOTYARD-REF-STORE-PACKS-FIXTURE-METADATA"
FIXTURE_KIND = "rootyard/ref-store-core-packs-backup-fixture"
HELPER_TEST = "ref_store_pack_backup_metadata_fixture"
HELPER_TARGET = "ref_store_packs_backup_fixture"
ROOT = Path(__file__).resolve().parents[1]
HELPER_SOURCE = ROOT / "tests" / "ref_store_packs_backup_fixture.rs"

HOLD_TABLES = (
    "artifact_hold_requests",
    "artifact_holds",
    "artifact_hold_consume_receipts",
    "artifact_hold_shards",
    "artifact_hold_repo_usage",
    "artifact_hold_tenant_usage",
)
TENANT_SCOPED_HOLDS = ("artifact_hold_tenant_usage",)

# Expected fixture cardinalities of the six current-format pack tables. The
# table *names* are always taken from the generated 142-vs-141 catalogs; this
# dict only pins the documented single-pack drill shape.
PACK_LEDGER_COUNTS = {
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


def validate_pack_fixture_binary(helper, app_binary, helper_receipt=None, app_receipt=None):
    """Bind the selected helper executable to its real integration-test build."""
    helper = Path(helper)
    assert helper.is_file(), "pack fixture binary is missing: " + str(helper)
    receipt_path = Path(helper_receipt) if helper_receipt else candidate_receipt(helper)
    receipt = load_receipt(receipt_path, "pack fixture build receipt")
    actual = sha256_file(helper)
    recorded = receipt_field(receipt, ("binary_sha256", "artifact_sha256", "sha256"), "binary sha256")
    assert recorded == actual, "pack fixture binary does not match its build receipt"
    kind = receipt_field(receipt, ("kind", "target_kind"), "build kind")
    assert kind == "rust-integration-test", "pack fixture receipt kind is " + repr(kind)
    assert receipt_flag(receipt, ("package_rebuilt",), "package_rebuilt") is True
    entries = receipt.get("fresh_false_artifacts")
    assert isinstance(entries, list) and len(entries) == 1, (
        "pack fixture receipt must record exactly one fresh=False artifact")
    entry = entries[0]
    assert isinstance(entry, dict), "pack fixture fresh=False entry is not an object"
    assert str(entry.get("target")) == HELPER_TARGET, (
        "pack fixture receipt target is " + repr(entry.get("target")) + ", expected " + HELPER_TARGET)
    assert entry.get("fresh") is False, "pack fixture artifact is not marked fresh=False"
    assert str(entry.get("kind")) == "test", "pack fixture artifact kind is not test"
    profile = entry.get("profile") or {}
    assert isinstance(profile, dict) and profile.get("test") is True, (
        "pack fixture artifact was not built with a test profile")
    executable = entry.get("executable")
    assert executable, "pack fixture artifact records no executable"
    assert Path(str(executable)).name.startswith(HELPER_TARGET), (
        "pack fixture receipt artifact does not name the " + HELPER_TARGET + " target")
    assert receipt.get("relocated_artifact") is True, (
        "pack fixture receipt must record the relocated integration-test artifact")
    source_sha = receipt_field(receipt, ("integration_test_source_sha256",), "integration_test_source_sha256")
    assert source_sha == sha256_file(HELPER_SOURCE), (
        "the pack fixture receipt was produced from different integration-test source")
    source_inputs = receipt_field(receipt, ("source_inputs_sha256", "source_inputs"), "source_inputs_sha256")
    assert isinstance(source_inputs, str) and len(source_inputs) == 64, (
        "pack fixture receipt has no source-input digest")
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


class BackupRefStorePacks142Harness(BackupRefStoreCore139Harness):
    """Populate the schema142 pack ledger through the real typed pipeline, then restore."""

    def __init__(self, args):
        super().__init__(args)
        self.pack_fixture_binary = Path(args.pack_fixture_binary)
        self.pack_manifest = self.root / "packs-fixture-manifest.json"
        self.pack_helper = None
        self.pack_marker = None
        self.pack_scope = None

    # -- helper process -----------------------------------------------------------------
    def fixture_env(self, mode, db):
        env = self.env.copy()
        env.update(
            ROOTYARD_TEST_DATABASE_URL=db,
            ROOTYARD_PACKS_FIXTURE_MODE=mode,
            ROOTYARD_PACKS_FIXTURE_OUTPUT=str(self.pack_manifest),
        )
        return env

    def run_pack_fixture(self, mode, db=None):
        assert self.pack_helper is not None, "helper binary was not validated"
        assert mode in ("seed", "verify")
        process = self.run(
            [str(self.pack_fixture_binary), "--ignored", "--exact", HELPER_TEST,
             "--format=terse", "--nocapture", "--test-threads=1"],
            env=self.fixture_env(mode, db or self.db))
        stdout = process.stdout.decode()
        summaries = [line for line in stdout.splitlines() if line.startswith("test result:")]
        assert summaries, "the pack fixture reported no test result at all"
        summary = summaries[-1]
        assert "1 passed" in summary, "the pack fixture did not run exactly one test: " + summary
        assert "0 failed" in summary, "the pack fixture failed: " + summary
        assert "0 ignored" in summary, "the pack fixture skipped its test: " + summary
        lines = [line for line in stdout.splitlines() if line.startswith(MARKER + " ")]
        assert len(lines) == 1, "the pack fixture must print exactly one marker line"
        text = lines[0]
        assert self.redact(text) == text, "the pack fixture marker leaked a credential or database URL"
        marker = json.loads(text[len(MARKER) + 1:])
        assert marker["kind"] == FIXTURE_KIND, "pack fixture marker has an unexpected kind"
        assert marker["mode"] == mode, "pack fixture marker reports an unexpected mode"
        assert marker["held_remote_objects_deleted"] is False, "the drill must not delete held remote objects"
        assert marker["restored_blob_bytes_backed_up"] is False
        assert marker["restored_blob_bytes_qualified"] is False
        assert marker["physical_blob_backup_closure"] is False
        assert marker["provider_io_attempted"] is True, "the provider IO of this drill is not optional"
        if mode == "seed":
            assert marker["protected_upload_attempted"] is True
            assert marker["s3_original_bytes_read_back_after_upload"] is True
            self.assert_counts(marker)
        else:
            assert marker["protected_upload_attempted"] is False, "restored verification must not upload"
            for key, value in marker["checks"].items():
                assert value is True or value is False, "verify check " + key + " is not boolean"
            assert marker["checks"]["restored_rows_equal_pre_backup_rows"] is True
            assert marker["checks"]["immutable_registration_replayed_without_grant"] is True
            assert marker["checks"]["a3_acquire_and_consume_receipts_match"] is True
            assert marker["checks"]["operation_terminal_replay_without_proof_or_authority"] is True
            assert marker["checks"]["retained_pack_counters_unchanged"] is True
            assert marker["checks"]["physical_locators_and_backend_identity_match"] is True
            assert marker["checks"]["known_refs_head_mode_revision_history_event_match"] is True
            assert marker["checks"]["s3_original_bytes_read_back_unchanged"] is True
            assert marker["checks"]["source_only_tempfiles_required"] is False
            assert marker["checks"]["quota_charged_by_replay"] is False
            self.assert_counts(marker)
        return marker

    def assert_binary_binding(self, stage):
        assert self.pack_helper is not None, "helper binary was not validated"
        helper = sha256_file(self.pack_fixture_binary)
        app = sha256_file(Path(self.args.binary))
        assert helper == self.pack_helper["binary_sha256"], "helper binary changed after validation (" + stage + ")"
        assert app == self.pack_helper["candidate_application_sha256"], (
            "application binary changed after validation (" + stage + ")")
        self.pack_helper["retained_binding_stages"] = self.pack_helper.get("retained_binding_stages", []) + [stage]
        self.pack_helper["helper_binary_sha256_after_run"] = helper
        self.pack_helper["candidate_application_sha256_after_run"] = app
        self.pack_helper["binaries_unchanged_after_run"] = True
        return {"stage": stage, "helper_binary_sha256": helper,
                "application_binary_sha256": app, "unchanged": True}

    # -- SQL observations (never an ACK) ------------------------------------------------
    def pack_tables(self):
        tables = schema142_pack_tables()
        assert sorted(tables) == sorted(PACK_LEDGER_COUNTS), (
            "the generated 142-vs-141 catalog delta is " + repr(tables))
        return tables

    def _json_rows(self, table, where, db=None):
        sql = ("SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text), '[]'::json) "
               "FROM public." + table + " t")
        if where:
            sql += " WHERE " + where
        return json.loads(self.metadata_psql(sql, db=db).stdout.decode().strip())

    def pack_rows(self, db=None, scoped=True):
        repo = uuid_literal(self.pack_scope["repository_id"])
        tenant = uuid_literal(self.pack_scope["tenant_id"])
        rows = {}
        for table in self.pack_tables():
            where = None
            if scoped:
                where = ("t.tenant_id='" + tenant + "'" if table.endswith("_tenant_usage")
                         else "t.repository_id='" + repo + "'")
            rows[table] = self._json_rows(table, where, db=db)
        return rows

    def hold_rows(self, db=None, scoped=True):
        repo = uuid_literal(self.pack_scope["repository_id"])
        tenant = uuid_literal(self.pack_scope["tenant_id"])
        rows = {}
        for table in HOLD_TABLES:
            where = None
            if scoped:
                if table == "artifact_hold_shards":
                    where = None
                elif table in TENANT_SCOPED_HOLDS:
                    where = "t.tenant_id='" + tenant + "'"
                else:
                    where = "t.repository_id='" + repo + "'"
            rows[table] = self._json_rows(table, where, db=db)
        return rows

    def pack_core_rows(self, db=None):
        repo = uuid_literal(self.pack_scope["repository_id"])
        return {table: self._json_rows(table, "t.repository_id='" + repo + "'", db=db) for table in CORE_TABLES}

    def pack_gate_row(self, db=None):
        return json.loads(self.metadata_psql(
            "SELECT to_jsonb(g) FROM public.ref_store_core_gates g WHERE g.repository_id='" +
            uuid_literal(self.pack_scope["repository_id"]) + "'", db=db).stdout.decode().strip())

    def assert_counts(self, marker):
        counts = marker.get("counts") or {}
        assert sorted(counts["pack"]) == sorted(self.pack_tables()), "marker does not count all six 142 tables"
        assert counts["pack"] == PACK_LEDGER_COUNTS, "marker 142 row counts differ from the drill shape"
        assert sorted(counts["holds"]) == sorted(HOLD_TABLES), "marker does not count all six 141 tables"
        assert counts["holds"] == HOLD_COUNTS, "marker 141 row counts differ from the complete hold ledger"
        assert sorted(counts["core"]) == sorted(CORE_TABLES), "marker does not count all six 139 tables"
        assert all(value >= 0 for value in counts["core"].values())

    # -- semantic assertions -------------------------------------------------------------
    def assert_pack_ledger_populated(self, marker, pack_rows, hold_rows, core_rows):
        counts = marker["counts"]
        assert counts["pack"] == PACK_LEDGER_COUNTS, "helper pack counts differ from SQL row counts"
        for table, expected in PACK_LEDGER_COUNTS.items():
            assert len(pack_rows[table]) == expected, table + " rows are not populated exactly"
        for table, expected in HOLD_COUNTS.items():
            assert len(hold_rows[table]) == expected, table + " rows are not populated exactly"
        for table, expected in CORE_COUNTS.items():
            assert len(core_rows[table]) == expected, table + " pack-repository rows are not populated exactly"

        scope = marker["scope"]
        plan = marker["plan"]
        ack = marker["registration"]["ack"]
        a3 = marker["a3"]["ack"]
        publication = pack_rows["ref_store_core_pack_publications"][0]
        assert publication["registration_id"] == ack["registration_id"] == plan["packs"][0]["registration_id"]
        assert publication["pack_id"] == ack["pack_id"] == plan["packs"][0]["pack_id"]
        assert publication["repository_id"] == scope["repository_id"] == ack["repository_id"]
        assert publication["tenant_id"] == scope["tenant_id"] == ack["tenant_id"]
        assert publication["owner_id"] == scope["owner_id"] == ack["owner_id"]
        assert publication["purpose"] == scope["purpose"] == "ref_publication"
        assert publication["object_format"] == scope["object_format"] == ack["object_format"]
        assert publication["history_incarnation"] == scope["history_incarnation"] == ack["history_incarnation"]
        assert publication["authority_epoch"] == scope["authority_epoch"] == ack["authority_epoch"]
        assert publication["group_epoch"] == scope["group_epoch"] == ack["group_epoch"]
        assert publication["parent_digest"] == plan["parent_digest"] == ack["parent_digest"]
        assert publication["plan_operation_id"] == plan["operation"]["operation_id"]
        assert publication["planned_pack_sha256"] == plan["packs"][0]["pack_sha256"] == ack["planned_pack_sha256"]
        assert publication["planned_pack_length"] == plan["packs"][0]["pack_length"] == ack["planned_pack_length"]
        assert publication["planned_idx_sha256"] == plan["packs"][0]["idx_sha256"] == ack["planned_idx_sha256"]
        assert publication["planned_idx_length"] == plan["packs"][0]["idx_length"] == ack["planned_idx_length"]
        assert publication["artifact_set_digest"] == ack["artifact_set_digest"]
        assert publication["acquire_request_id"] == marker["acquire_request_id"] == ack["acquire_request_id"]
        assert publication["acquire_request_id"] == a3["request_id"]
        assert publication["consume_request_id"] == marker["consume_request_id"] == ack["consume_request_id"]
        assert publication["consume_request_id"] == a3["consume_request_id"]
        assert publication["backend_identity"] == marker["backend_identity"] == ack["backend_identity"]
        assert publication["gate_revision"] == plan["expected_gate_revision"] == 1
        assert publication["gate_digest"] == plan["expected_gate_digest"]
        assert publication["pack_mode"] == plan["expected_mode"] == "metadata_only"
        assert publication["logical_bytes"] == ack["logical_bytes"] > 0
        assert publication["declared_bytes"] == (plan["packs"][0]["pack_length"] + plan["packs"][0]["idx_length"])
        assert 0 < len(publication["ack_body"].encode("utf-8")) <= 65536
        assert json.loads(publication["ack_body"]) == ack, "the stored ACK body is not the typed registration ACK"

        artifacts = {row["role"]: row for row in pack_rows["ref_store_core_pack_artifacts"]}
        assert sorted(artifacts) == ["idx", "pack"], "the pack pair roles changed"
        a3_artifacts = {hold["slot"]: hold for hold in a3["artifacts"]}
        for role, slot, key in (("pack", 0, "pack"), ("idx", 1, "idx")):
            row = artifacts[role]
            assert row["slot"] == slot == a3_artifacts[slot]["slot"]
            assert row["hold_id"] == a3_artifacts[slot]["hold_id"]
            assert row["hold_id"] in ack["hold_ids"]
            assert row["acquire_request_id"] == ack["acquire_request_id"]
            assert row["consume_request_id"] == ack["consume_request_id"]
            assert row["pack_id"] == ack["pack_id"]
            assert row["repository_id"] == ack["repository_id"]
            assert row["tenant_id"] == ack["tenant_id"]
            assert row["provider"] == a3_artifacts[slot]["artifact"]["provider"]
            assert row["backend_identity"] == ack["backend_identity"] == a3_artifacts[slot]["artifact"]["backend_identity"]
            assert row["namespace"] == a3_artifacts[slot]["artifact"]["namespace"]
            assert row["sha256"] == plan["packs"][0][key + "_sha256"] == a3_artifacts[slot]["artifact"]["sha256"]
            assert row["content_length"] == plan["packs"][0][key + "_length"] > 0
            assert row["content_length"] == a3_artifacts[slot]["artifact"]["length"]
            assert row["declared_bytes"] == row["content_length"]
            assert row["logical_bytes"] > 0
        assert sorted(artifacts[role]["hold_id"] for role in artifacts) == sorted(ack["hold_ids"])

        membership = pack_rows["ref_store_core_pack_memberships"][0]
        assert membership["pack_id"] == ack["pack_id"]
        assert membership["registration_id"] == ack["registration_id"]
        assert membership["artifact_set_digest"] == ack["artifact_set_digest"]
        assert membership["joined_revision"] == marker["gate"]["committed"]["revision"] == 2
        assert membership["repository_id"] == ack["repository_id"]
        assert publication["gate_revision"] + 1 == membership["joined_revision"]

        history = pack_rows["ref_store_core_pack_history"]
        assert sorted(row["kind"] for row in history) == ["committed", "registered"]
        registered = next(row for row in history if row["kind"] == "registered")
        committed = next(row for row in history if row["kind"] == "committed")
        for row in history:
            assert row["repository_id"] == ack["repository_id"] and row["tenant_id"] == ack["tenant_id"]
            assert row["registration_id"] == ack["registration_id"] and row["pack_id"] == ack["pack_id"]
            assert row["parent_digest"] == ack["parent_digest"]
            assert row["operation_id"] == plan["operation"]["operation_id"]
            assert row["artifact_set_digest"] == ack["artifact_set_digest"]
            assert 0 < len(row["body"].encode("utf-8")) <= 65536
        assert registered["revision"] == publication["gate_revision"] == 1
        assert registered["body"] == publication["ack_body"]
        assert committed["revision"] == membership["joined_revision"] == 2
        assert committed["body"] == marker["context_digest"]

        repo_usage = pack_rows["ref_store_core_pack_repo_usage"][0]
        tenant_usage = pack_rows["ref_store_core_pack_tenant_usage"][0]
        counters = ("registration_count", "artifact_count", "membership_count", "logical_bytes", "receipt_count")
        assert [repo_usage[name] for name in counters] == marker["usage"] == [tenant_usage[name] for name in counters]
        assert repo_usage["registration_count"] == 1 and repo_usage["artifact_count"] == 2
        assert repo_usage["membership_count"] == 1 and repo_usage["receipt_count"] == 4
        assert repo_usage["logical_bytes"] == marker["logical_accounting"]["expected_logical_bytes"] > 0
        assert repo_usage["repository_id"] == ack["repository_id"] and repo_usage["tenant_id"] == ack["tenant_id"]
        assert tenant_usage["tenant_id"] == ack["tenant_id"]

        requests = hold_rows["artifact_hold_requests"]
        holds = hold_rows["artifact_holds"]
        receipts = hold_rows["artifact_hold_consume_receipts"]
        request = requests[0]
        assert request["request_id"] == a3["request_id"] == publication["acquire_request_id"]
        assert request["request_digest"] == a3["request_digest"]
        assert request["repository_id"] == ack["repository_id"] and request["tenant_id"] == ack["tenant_id"]
        assert request["owner_id"] == ack["owner_id"]
        assert request["purpose"] == "ref_publication"
        assert request["artifact_count"] == 2
        assert request["consume_request_id"] == ack["consume_request_id"]
        assert request["gate_revision"] == publication["gate_revision"]
        assert request["gate_digest"] == publication["gate_digest"]
        body = json.loads(request["ack_body"])
        assert body["request_id"] == request["request_id"]
        assert body["consume_request_id"] == request["consume_request_id"]
        assert body["artifacts"] == a3["artifacts"]
        assert sorted(hold["hold_id"] for hold in holds) == sorted(ack["hold_ids"])
        for hold in holds:
            assert hold["state"] == "active" and hold["generation"] == 1
            assert hold["request_id"] == request["request_id"]
            assert hold["repository_id"] == request["repository_id"]
            assert hold["operation_id"] == request["operation_id"]
        expected_receipts = {row["hold_id"]: row for row in marker["a3"]["receipts"]}
        assert len(receipts) == len(expected_receipts) == 2
        for receipt in receipts:
            assert receipt["request_id"] == request["request_id"]
            assert receipt["consume_request_id"] == request["consume_request_id"]
            assert receipt["hold_id"] in expected_receipts
            assert receipt["consume_digest"] == expected_receipts[receipt["hold_id"]]["consume_digest"]
            receipt_body = json.loads(receipt["body"])
            assert receipt_body["hold_id"] == receipt["hold_id"]
            assert receipt_body["consume_request_id"] == receipt["consume_request_id"]
        shards = {row["shard_id"]: row for row in hold_rows["artifact_hold_shards"]}
        assert sorted(shards) == list(range(64)), "the fixed 64 shard rows changed"
        used = shards[a3["shard"]]
        assert used["hold_count"] >= 2 and used["receipt_count"] >= 3
        hold_usage = hold_rows["artifact_hold_repo_usage"][0]
        hold_tenant = hold_rows["artifact_hold_tenant_usage"][0]
        for name in ("hold_count", "declared_bytes", "logical_bytes", "receipt_count"):
            assert hold_usage[name] == hold_tenant[name] > 0
        assert hold_usage["hold_count"] == 2 and hold_usage["receipt_count"] == 3

        gate = core_rows["ref_store_core_gates"][0]
        assert gate["pack_mode"] == marker["gate"]["committed"]["pack_mode"] == "pack_verified"
        assert gate["revision"] == marker["gate"]["committed"]["revision"] == 2
        assert gate["head_ref"] == marker["gate"]["committed"]["head_ref"] == "refs/heads/main"
        assert gate["tenant_id"] == ack["tenant_id"]
        assert gate["object_format"] == scope["object_format"]
        assert gate["history_incarnation"] == scope["history_incarnation"]
        assert gate["authority_epoch"] == scope["authority_epoch"]
        assert gate["group_epoch"] == scope["group_epoch"]
        operations = core_rows["ref_store_operations"]
        operation = operations[0]
        assert operation["operation_id"] == plan["operation"]["operation_id"]
        assert operation["state"] == "committed" and operation["terminal_at"] is not None
        assert operation["request_digest"] == plan["operation"]["operation_digest"]
        assert operation["terminal_result"] == marker["terminal"]
        refs = core_rows["ref_store_core_refs"]
        assert len(refs) == 1 and refs[0]["ref_name"] == "refs/heads/main"
        assert refs[0]["oid"] == marker["source"]["commit_oid"] == marker["gate"]["committed"]["ref_oid"]
        assert refs[0]["revision"] == gate["revision"] == 2
        events = core_rows["ref_store_core_events"]
        assert len(events) == 1 and events[0]["outcome"] == "committed"
        assert events[0]["payload"] == marker["terminal"]
        assert events[0]["revision"] == gate["revision"] == 2
        assert events[0]["operation_id"] == operation["operation_id"]
        assert core_rows["ref_store_cancellations"] == []
        lanes = core_rows["ref_store_issuer_lanes"]
        assert len(lanes) == 1 and lanes[0]["lane"] == plan["operation"]["lane"]
        assert lanes[0]["last_reserved_sequence"] >= plan["operation"]["sequence"]

    # -- the inherited seven-case hooks -------------------------------------------------
    def seed_core_fixture(self):
        self.pack_helper = validate_pack_fixture_binary(
            self.args.pack_fixture_binary, self.args.binary,
            getattr(self.args, "pack_fixture_receipt", None),
            getattr(self.args, "candidate_receipt", None))
        result = super().seed_core_fixture()
        marker = self.run_pack_fixture("seed")
        self.assert_binary_binding("seed")
        self.pack_marker = marker
        assert json.loads(self.pack_manifest.read_text()) == marker, (
            "the private pack fixture manifest differs from the public marker")
        self.pack_scope = marker["scope"]
        assert self.pack_scope["repository_id"] != self.core_repo["id"], (
            "the typed native gate must not reuse the inherited plain-SQL 139 gate repository")
        gate = self.pack_gate_row()
        assert gate["pack_mode"] == marker["gate"]["committed"]["pack_mode"]
        assert gate["revision"] == marker["gate"]["committed"]["revision"]
        self.source_pack_rows = self.pack_rows()
        self.source_pack_rows_global = self.pack_rows(scoped=False)
        self.source_hold_rows = self.hold_rows()
        self.source_hold_rows_global = self.hold_rows(scoped=False)
        self.source_pack_core_rows = self.pack_core_rows()
        assert self.source_pack_rows == marker["rows"]["pack"], (
            "typed pack rows differ from the helper's SQL capture of the same rows")
        assert self.source_hold_rows == marker["rows"]["holds"], (
            "typed A3 hold rows differ from the helper's SQL capture of the same rows")
        assert self.source_pack_core_rows == marker["rows"]["core"], (
            "typed pack-repository core rows differ from the helper's SQL capture")
        self.assert_pack_ledger_populated(marker, self.source_pack_rows, self.source_hold_rows,
                                          self.source_pack_core_rows)
        self._adopt_typed_pack_fixture(marker)
        (self.root / "source-refstore-packs-rows.json").write_text(
            json.dumps({"scope": marker["scope"], "gate": marker["gate"], "plan": marker["plan"],
                        "source": marker["source"], "context_digest": marker["context_digest"],
                        "registration_ack": marker["registration"]["ack"], "terminal": marker["terminal"],
                        "usage": marker["usage"], "logical_accounting": marker["logical_accounting"],
                        "fixture_rows_by_table": {table: len(rows) for table, rows in self.source_pack_rows.items()},
                        "hold_rows_by_table": {table: len(rows) for table, rows in self.source_hold_rows.items()}},
                       indent=2) + "\n")
        result.update({
            "adapter_seeded_schema142_pack_tables": {table: len(rows) for table, rows in self.source_pack_rows.items()},
            "adapter_seeded_complete_schema141_hold_tables": {table: len(rows) for table, rows in self.source_hold_rows.items()},
            "typed_native_pack_commit_registered_and_verified": True,
            "native_pack_verifier_proof_minted_by_real_verifier": True,
            "sql_faked_ack_or_registration": False,
            "inherited_plain_sql_139_gate_reused_for_native_proof": False,
            "pack_repository_tenant_equals_inherited_fixture_tenant": (
                marker["scope"]["tenant_id"] == self.core_repo["tenant_id"]),
            "pack_gate_pack_mode": gate["pack_mode"],
            "pack_gate_revision": gate["revision"],
            "pack_verified_gate_activated_by_the_commit": True,
            "restored_blob_bytes_backed_up": False,
            "held_remote_objects_deleted": False,
        })
        return result

    def _adopt_typed_pack_fixture(self, marker):
        """The typed pack fixture adds rows only for its own new repository."""
        repo = uuid_literal(marker["scope"]["repository_id"])
        before = self.source_core_rows
        after = self.core_rows()
        for table in CORE_TABLES:
            before_other = [row for row in before[table] if row.get("repository_id") != repo]
            after_other = [row for row in after[table] if row.get("repository_id") != repo]
            assert after_other == before_other, table + " inherited rows changed during typed pack seeding"
            added = [row for row in after[table] if row.get("repository_id") == repo]
            assert len(added) == CORE_COUNTS[table], table + " pack-repository row count differs"
            assert not [row for row in before[table] if row.get("repository_id") == repo], (
                table + " already held pack-repository rows before seeding")
        for table in self.core_expected_counts:
            assert self.core_fixture_rows(table) == self.source_fixture_rows[table], (
                table + " inherited fixture rows changed during typed pack seeding")
        assert self.core_repository_row() == self.source_core_repo, "the inherited repository row changed"
        # The inherited restore assertions compare the global 139 capture, so it
        # must now include the typed pack rows that the snapshot will carry.
        self.source_core_rows = after

    def lock_and_snapshot(self):
        result = super().lock_and_snapshot()
        manifest = json.loads((self.backup / "manifest.json").read_text())
        assert manifest["format"] == CURRENT_BACKUP_FORMAT, "drill did not produce the current backup format"
        assert CURRENT_BACKUP_FORMAT == 18, "the current backup format is not the expected 18"
        assert manifest["schema_versions"] == SCHEMA_VERSIONS, "the archive schema versions differ"
        assert SCHEMA_VERSIONS[-1] == 142, "the current schema is not 142"
        assert "metadata.dump" in manifest["files"], "the parent snapshot has no metadata dump"
        listing = self.run(["pg_restore", "--list", str(self.backup / "metadata.dump")]).stdout.decode()
        for table in self.pack_tables() + list(HOLD_TABLES):
            assert ("TABLE DATA public " + table in listing) or ('TABLE DATA public "' + table + '"' in listing), (
                "parent snapshot dump silently excluded table " + table)
            assert int(self.sql('SELECT count(*) FROM public."' + table + '"')) > 0, (
                "the drill left table " + table + " empty")
        for table, expected in PACK_LEDGER_COUNTS.items():
            assert self.sql('SELECT count(*) FROM public."' + table + '"') == str(expected), (
                table + " row count differs before the backup")
        gate = self.pack_gate_row()
        assert gate["pack_mode"] == "pack_verified" and gate["revision"] == 2, "the pack gate is not activated"
        assert self.sql("SELECT count(*) FROM ref_store_core_gates WHERE pack_mode='pack_verified'") == "1", (
            "the snapshot does not carry exactly one activated pack gate")
        result.update({"backup_format": manifest["format"],
                       "schema142_is_current": SCHEMA_VERSIONS[-1] == 142,
                       "schema142_pack_ledger_tables": self.pack_tables(),
                       "schema142_pack_ledger_nonempty": True,
                       "schema141_hold_ledger_complete": {table: len(rows) for table, rows in self.source_hold_rows.items()},
                       "parent_snapshot_inspected_dynamic_schema142_tables": self.pack_tables(),
                       "gate_pack_mode_pack_verified": True})
        return result

    def reject_pack(self, sql, message):
        self.reject_sql(sql, message)

    def restore_and_clone(self):
        result = super().restore_and_clone()
        marker = self.pack_marker
        restored_pack = self.pack_rows()
        restored_pack_global = self.pack_rows(scoped=False)
        restored_holds = self.hold_rows()
        restored_holds_global = self.hold_rows(scoped=False)
        restored_core = self.pack_core_rows()
        assert restored_pack == self.source_pack_rows, "restored schema142 rows differ: " + ", ".join(
            table for table in self.pack_tables() if restored_pack[table] != self.source_pack_rows[table])
        assert restored_pack_global == self.source_pack_rows_global, "restored global schema142 rows differ"
        assert restored_holds == self.source_hold_rows, "restored schema141 hold rows differ"
        assert restored_holds_global == self.source_hold_rows_global, "restored global schema141 rows differ"
        assert restored_core == self.source_pack_core_rows, "restored pack-repository 139 rows differ"
        self.assert_pack_ledger_populated(marker, restored_pack, restored_holds, restored_core)
        gate = self.pack_gate_row()
        assert gate["pack_mode"] == "pack_verified", "the restored gate lost pack_verified mode"
        assert gate["revision"] == marker["gate"]["committed"]["revision"] == 2
        assert self.sql("SELECT max(version) FROM schema_migrations") == "142"
        assert self.sql("SELECT count(*) FROM schema_migrations WHERE version BETWEEN 138 AND 142") == "5"
        triggers = int(self.sql("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'ref_store_core_pack%'"))
        assert triggers >= 14, "the migration-142 ledger/fence guards are missing"
        assert self.sql("SELECT count(*) FROM pg_trigger WHERE tgname='ref_store_core_gate_pack_mode_fence'") == "1", (
            "the one-way pack-mode gate fence is missing")
        assert self.sql("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'ref_store_core_pack%' "
                        "AND tgenabled <> 'O'") == "0", "a migration-142 guard was disabled"

        # Read-only typed replay against the restored database.
        before = {"pack": self.pack_rows(scoped=False), "holds": self.hold_rows(scoped=False),
                  "core": self.core_rows()}
        verify = self.run_pack_fixture("verify", db=self.db)
        self.assert_binary_binding("verify")
        after = {"pack": self.pack_rows(scoped=False), "holds": self.hold_rows(scoped=False),
                 "core": self.core_rows()}
        assert before == after, "the read-only restored verification mutated rows, counters or timestamps"
        assert verify["scope"] == marker["scope"], "restored typed scope differs from seed"
        assert verify["plan"] == marker["plan"], "the restored rebuilt plan differs from seed"
        assert verify["terminal"] == marker["terminal"], "the replayed terminal differs from the commit"
        assert verify["registration_ack"] == marker["registration"]["ack"], "the restored registration ACK differs"
        assert verify["a3_ack"] == marker["a3"]["ack"], "the restored A3 acquire ACK differs"
        assert verify["a3_receipts"] == marker["a3"]["receipts"], "the restored A3 consume receipts differ"
        assert verify["usage"] == marker["usage"], "the restored pack counters differ"
        assert verify["gate"]["committed"]["digest"] == marker["gate"]["committed"]["digest"], (
            "the restored committed gate digest differs")
        assert verify["gate"]["committed"]["membership_digest"] == (
            marker["gate"]["committed"]["membership_digest"]), "the restored membership digest differs"
        assert self.pack_rows() == self.source_pack_rows

        # Immutable ledger, monotone counters and the one-way pack-mode fence.
        publication = restored_pack["ref_store_core_pack_publications"][0]
        artifacts = {row["role"]: row for row in restored_pack["ref_store_core_pack_artifacts"]}
        membership = restored_pack["ref_store_core_pack_memberships"][0]
        history = restored_pack["ref_store_core_pack_history"]
        repo = uuid_literal(marker["scope"]["repository_id"])
        tenant = uuid_literal(marker["scope"]["tenant_id"])
        immutable = "ref-store core pack ledger is immutable"
        monotone = "pack usage counters are monotone and cannot be refunded"
        fence = "ref-store core pack mode is one-way and cannot be downgraded"
        self.reject_pack("UPDATE public.ref_store_core_pack_publications SET ack_body='{}' "
                         "WHERE registration_id='" + publication["registration_id"] + "'", immutable)
        self.reject_pack("UPDATE public.ref_store_core_pack_artifacts SET sha256='" + "f" * 64 + "' "
                         "WHERE registration_id='" + publication["registration_id"] + "' AND role='pack'", immutable)
        self.reject_pack("UPDATE public.ref_store_core_pack_memberships SET joined_revision=1 "
                         "WHERE repository_id='" + repo + "'", immutable)
        self.reject_pack("UPDATE public.ref_store_core_pack_history SET body='{}' "
                         "WHERE history_id='" + history[0]["history_id"] + "'", immutable)
        self.reject_pack("UPDATE public.ref_store_core_pack_repo_usage SET registration_count=registration_count-1 "
                         "WHERE repository_id='" + repo + "'", monotone)
        self.reject_pack("UPDATE public.ref_store_core_pack_tenant_usage SET receipt_count=receipt_count-1 "
                         "WHERE tenant_id='" + tenant + "'", monotone)
        self.reject_pack("UPDATE public.ref_store_core_gates SET pack_mode='metadata_only' "
                         "WHERE repository_id='" + repo + "'", fence)
        for table, key, value in (
                ("ref_store_core_pack_publications", "registration_id", publication["registration_id"]),
                ("ref_store_core_pack_artifacts", "hold_id", artifacts["pack"]["hold_id"]),
                ("ref_store_core_pack_memberships", "pack_id", membership["pack_id"]),
                ("ref_store_core_pack_history", "history_id", history[0]["history_id"]),
                ("ref_store_core_pack_repo_usage", "repository_id", repo),
                ("ref_store_core_pack_tenant_usage", "tenant_id", tenant)):
            self.reject_pack("DELETE FROM public." + table + " WHERE " + key + "='" + value + "'", immutable)
        self.reject_pack("TRUNCATE public.ref_store_core_pack_publications CASCADE", immutable)
        assert self.pack_rows() == self.source_pack_rows, "a rejected direct mutation changed restored pack rows"
        assert self.pack_rows(scoped=False) == self.source_pack_rows_global
        assert self.hold_rows() == self.source_hold_rows
        assert self.hold_rows(scoped=False) == self.source_hold_rows_global
        assert self.core_rows() == self.source_core_rows
        assert self.pack_gate_row()["pack_mode"] == "pack_verified", "the fence attempt downgraded the gate"
        (self.root / "restored-refstore-packs-rows.json").write_text(
            json.dumps({"scope": marker["scope"], "gate": marker["gate"], "plan": marker["plan"],
                        "source": marker["source"], "terminal": marker["terminal"],
                        "registration_ack": marker["registration"]["ack"], "usage": marker["usage"],
                        "fixture_rows_by_table": {table: len(rows) for table, rows in restored_pack.items()},
                        "hold_rows_by_table": {table: len(rows) for table, rows in restored_holds.items()}},
                       indent=2) + "\n")
        result.update({
            "all_six_schema142_tables_restored_exactly": True,
            "pack_publications_artifacts_memberships_history_usage_nonempty_after_restore": True,
            "complete_schema141_hold_ledger_restored_exactly": True,
            "schema142_pack_mode_pack_verified_retained": True,
            "typed_replay_verify_helper_ran_on_restored_database": True,
            "immutable_registration_replayed_without_proof_or_grant": True,
            "restored_pack_counters_not_charged_by_replay": True,
            "physical_locators_and_backend_identity_compared": True,
            "known_refs_head_mode_revision_history_event_compared": True,
            "direct_updates_deletes_truncate_refused_with_rows_unchanged": True,
            "pack_mode_downgrade_refused": True,
            "triggers_enabled_not_disabled_by_the_drill": True,
            "s3_original_bytes_external_and_unchanged_after_restore": True,
            "restored_blob_bytes_backed_up": False,
            "byte_backup_or_physical_protection_closure_claimed": False,
            "held_remote_objects_deleted": False,
        })
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--pack-fixture-binary", required=True,
                        help="selected Rust integration-test executable for ref_store_packs_backup_fixture")
    parser.add_argument("--pack-fixture-receipt", type=Path,
                        help="build receipt for the helper (defaults to <helper>.build.json)")
    parser.add_argument("--candidate-receipt", type=Path,
                        help="candidate application build receipt (defaults to <binary>.build.json)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    args.pack_fixture_binary = str(Path(args.pack_fixture_binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("dedicated synthetic ROOTYARD_TEST_DATABASE_URL required")
    harness = BackupRefStorePacks142Harness(args)
    success = False
    try:
        for name, function in [
            ("synthetic_source_with_typed_native_pack_commit", harness.seed_core_fixture),
            ("offline_barriers_and_snapshot", harness.lock_and_snapshot),
            ("unsafe_or_corrupt_inputs", harness.invalid_inputs),
            ("backup_barrier_failures", harness.backup_barrier_failures),
            ("interrupted_restore_guard", harness.interrupted_restore),
            ("post_backup_write_not_in_snapshot", harness.write_after_backup),
            ("new_environment_restore_schema142_pack_ledger_clone_fsck", harness.restore_and_clone),
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
            pack_fixture_helper=harness.pack_helper,
            limitations=[
                "The typed pack ledger is seeded by the real A3/A4 pipeline and native PackVerifier; no SQL ACK, proof or registration is fabricated.",
                "The inherited migration-139 metadata gate/ref fixture is plain SQL and is never used for the native proof; the drill uses its own typed gate.",
                "The random pack repository stays provisioning/gitfs/unserved for the whole drill.",
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
