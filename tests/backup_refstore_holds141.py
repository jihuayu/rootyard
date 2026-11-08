#!/usr/bin/env python3
"""Current-format19/schema143 backup roundtrip of populated artifact holds.

This is the #107/#105 A3 drill. It subclasses the inherited
``tests/backup_refstore_core139.py`` seven-case harness, so the seven real
offline backup cases (synthetic source, barrier/snapshot, corrupt inputs,
barrier failure, interrupted restore, post-backup write exclusion and a fresh
authenticated restore/clone/fsck) are mandatory with zero skips.

The schema141 artifact-hold tables remain populated by the real typed
``PgArtifactHoldStore`` in ``tests/ref_store_holds_backup_fixture.rs``:
one acquired batch is consumed (durable receipts), and a second acquired batch
is deliberately dropped without consuming its grant. Replaying that second
request must return the old immutable ACK and never mint another grant. The
helper first adds one plain-SQL pending migration-138 parent operation/lane
against the inherited migration-139 gate; that row is explicitly a metadata
fixture, not an adapter or Git ACK. Every request/hold/consume ACK is produced
by the typed adapter, never by hand SQL.

Blob metadata uses a fixed non-secret synthetic S3 identity only. No provider
IO, raw upload or read-back is attempted; restored Blob bytes are not qualified
and no physical backup/protection closure is claimed. The dump is inspected to
show the dynamic schema-141 tables are present; the restored rows are compared
globally and exactly, including all 64 fixed shard rows and monotone quota
counters. The current archive is format19/schema143, so the drill also derives
the six new schema142 pack-ledger tables from the generated 142-vs-141
catalogs, proves the dynamic dump carries no silent table exclusion, and
requires those tables to stay empty with the gate at the default
``metadata_only`` mode.  The four schema143 A5 pack-snapshot tables derived from
the generated 143-vs-142 catalogs must also restore empty, every old A2 snapshot
must keep the default metadata-only shape, and no pack pin or history row is
fabricated.  This A3 fixture copies no Blob pack bytes. No
DSN/token is written to the public report.
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

NEW_TABLES = (
    "artifact_hold_requests",
    "artifact_holds",
    "artifact_hold_consume_receipts",
    "artifact_hold_shards",
    "artifact_hold_repo_usage",
    "artifact_hold_tenant_usage",
)
TENANT_SCOPED_TABLES = ("artifact_hold_tenant_usage",)
MARKER = "ROOTYARD-ARTIFACT-HOLD-FIXTURE-METADATA"
FIXTURE_KIND = "rootyard/ref-store-artifact-holds-backup-fixture"
HELPER_TEST = "artifact_hold_backup_metadata_fixture"
HELPER_TARGET = "ref_store_holds_backup_fixture"
ROOT = Path(__file__).resolve().parents[1]
HELPER_SOURCE = ROOT / "tests" / "ref_store_holds_backup_fixture.rs"


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
    for name in names:
        if name in receipt:
            return receipt[name]
    raise AssertionError("build receipt has no " + label + " (accepted keys: " + ", ".join(names) + ")")


def receipt_flag(receipt, names, label):
    value = receipt_field(receipt, names, label)
    assert isinstance(value, bool), "build receipt " + label + " must be a boolean"
    return value


def load_receipt(path, label):
    path = Path(path)
    assert path.is_file(), label + " is missing: " + str(path)
    value = json.loads(path.read_text())
    assert isinstance(value, dict), label + " is not a JSON object"
    return value


def candidate_receipt(path):
    path = Path(path)
    for option in (Path(str(path) + ".build.json"), path.with_suffix(".build.json")):
        if option.is_file():
            return option
    raise AssertionError("no build receipt next to " + str(path) + " (expected " + str(path) + ".build.json)")

def validate_holds_fixture_binary(helper, app_binary, helper_receipt=None, app_receipt=None):
    """Bind the selected helper executable to its real integration-test build."""
    helper = Path(helper)
    assert helper.is_file(), "artifact-hold fixture binary is missing: " + str(helper)
    receipt_path = Path(helper_receipt) if helper_receipt else candidate_receipt(helper)
    receipt = load_receipt(receipt_path, "artifact-hold fixture build receipt")
    actual = sha256_file(helper)
    recorded = receipt_field(receipt, ("binary_sha256", "artifact_sha256", "sha256"), "binary sha256")
    assert recorded == actual, "artifact-hold fixture binary does not match its build receipt"
    kind = receipt_field(receipt, ("kind", "target_kind"), "build kind")
    assert kind == "rust-integration-test", "artifact-hold fixture receipt kind is " + repr(kind)
    assert receipt_flag(receipt, ("package_rebuilt",), "package_rebuilt") is True
    entries = receipt.get("fresh_false_artifacts")
    assert isinstance(entries, list) and len(entries) == 1, (
        "artifact-hold receipt must record exactly one fresh=False artifact")
    entry = entries[0]
    assert isinstance(entry, dict), "artifact-hold fresh=False entry is not an object"
    assert str(entry.get("target")) == HELPER_TARGET, (
        "artifact-hold receipt target is " + repr(entry.get("target")) + ", expected " + HELPER_TARGET)
    assert entry.get("fresh") is False, "artifact-hold artifact is not marked fresh=False"
    assert str(entry.get("kind")) == "test", "artifact-hold artifact kind is not test"
    profile = entry.get("profile") or {}
    assert isinstance(profile, dict) and profile.get("test") is True, (
        "artifact-hold artifact was not built with a test profile")
    executable = entry.get("executable")
    assert executable, "artifact-hold artifact records no executable"
    assert Path(str(executable)).name.startswith(HELPER_TARGET), (
        "artifact-hold receipt artifact does not name the " + HELPER_TARGET + " target")
    assert receipt.get("relocated_artifact") is True, (
        "artifact-hold receipt must record the relocated integration-test artifact")
    source_sha = receipt_field(receipt, ("integration_test_source_sha256",), "integration_test_source_sha256")
    assert source_sha == sha256_file(HELPER_SOURCE), (
        "the helper receipt was produced from different integration-test source")
    source_inputs = receipt_field(receipt, ("source_inputs_sha256", "source_inputs"), "source_inputs_sha256")
    assert isinstance(source_inputs, str) and len(source_inputs) == 64, (
        "artifact-hold fixture receipt has no source-input digest")
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

class BackupRefStoreHolds141Harness(BackupRefStoreCore139Harness):
    """Populate migration-141 artifact holds through the real adapter, then restore."""

    def __init__(self, args):
        super().__init__(args)
        self.holds_fixture_binary = Path(args.holds_fixture_binary)
        self.holds_manifest = self.root / "holds-fixture-manifest.json"
        self.holds_helper = None
        self.expected_new_counts = {
            "artifact_hold_requests": 2,
            "artifact_holds": 3,
            "artifact_hold_consume_receipts": 2,
            "artifact_hold_shards": 64,
            "artifact_hold_repo_usage": 1,
            "artifact_hold_tenant_usage": 1,
        }

    def fixture_env(self, mode, db):
        env = self.env.copy()
        env.update(
            ROOTYARD_TEST_DATABASE_URL=db,
            ROOTYARD_HOLDS_FIXTURE_MODE=mode,
            ROOTYARD_HOLDS_FIXTURE_REPOSITORY=self.core_repo["id"],
            ROOTYARD_HOLDS_FIXTURE_TENANT=self.core_repo["tenant_id"],
            ROOTYARD_HOLDS_FIXTURE_OWNER=self.core_repo["tenant_id"],
            ROOTYARD_HOLDS_FIXTURE_OUTPUT=str(self.holds_manifest),
        )
        return env

    def run_holds_fixture(self, mode, db=None):
        assert self.holds_helper is not None, "helper binary was not validated"
        assert mode in ("seed", "verify")
        process = self.run(
            [str(self.holds_fixture_binary), "--ignored", "--exact", HELPER_TEST,
             "--format=terse", "--nocapture", "--test-threads=1"],
            env=self.fixture_env(mode, db or self.db))
        stdout = process.stdout.decode()
        summaries = [line for line in stdout.splitlines() if line.startswith("test result:")]
        assert summaries, "the artifact-hold fixture reported no test result at all"
        summary = summaries[-1]
        assert "1 passed" in summary, "the artifact-hold fixture did not run exactly one test: " + summary
        assert "0 failed" in summary, "the artifact-hold fixture failed: " + summary
        assert "0 ignored" in summary, "the artifact-hold fixture skipped its test: " + summary
        lines = [line for line in stdout.splitlines() if line.startswith(MARKER + " ")]
        assert len(lines) == 1, "the artifact-hold fixture must print exactly one marker line"
        text = lines[0]
        assert self.redact(text) == text, "the artifact-hold marker leaked a credential or database URL"
        marker = json.loads(text[len(MARKER) + 1:])
        assert marker["kind"] == FIXTURE_KIND, "artifact-hold marker has an unexpected kind"
        assert marker["mode"] == mode, "artifact-hold marker reports an unexpected mode"
        assert marker["provider_io_attempted"] is False
        assert marker["raw_upload_attempted"] is False
        assert marker["restored_blob_bytes_qualified"] is False
        assert marker["restored_blob_bytes_denied"] is True
        assert marker["physical_backup_closure"] is False
        counts = marker.get("counts") or {}
        assert sorted(counts) == sorted(NEW_TABLES), "marker does not count all six migration-141 tables"
        assert all(value > 0 for value in counts.values()), "marker left a migration-141 table empty"
        return marker

    def assert_binary_binding(self, stage):
        assert self.holds_helper is not None, "helper binary was not validated"
        helper = sha256_file(self.holds_fixture_binary)
        app = sha256_file(Path(self.args.binary))
        assert helper == self.holds_helper["binary_sha256"], "helper binary changed after validation (" + stage + ")"
        assert app == self.holds_helper["candidate_application_sha256"], (
            "application binary changed after validation (" + stage + ")")
        self.holds_helper["retained_binding_stages"] = self.holds_helper.get("retained_binding_stages", []) + [stage]
        self.holds_helper["helper_binary_sha256_after_run"] = helper
        self.holds_helper["candidate_application_sha256_after_run"] = app
        self.holds_helper["binaries_unchanged_after_run"] = True
        return {"stage": stage, "helper_binary_sha256": helper,
                "application_binary_sha256": app, "unchanged": True}

    def new_rows(self, db=None):
        rows = {}
        for table in NEW_TABLES:
            value = self.metadata_psql(
                "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text), '[]'::json) FROM public." +
                table + " t", db=db).stdout.decode().strip()
            rows[table] = json.loads(value)
        return rows

    def new_scoped_rows(self, db=None):
        repository = uuid_literal(self.core_repo["id"])
        tenant = uuid_literal(self.core_repo["tenant_id"])
        rows = {}
        for table in NEW_TABLES:
            if table == "artifact_hold_shards":
                where = "TRUE"
            elif table in TENANT_SCOPED_TABLES:
                where = "t.tenant_id='" + tenant + "'"
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
        for table, count in self.expected_new_counts.items():
            assert len(scoped[table]) == count, table + " rows are not populated exactly"
        assert marker["counts"] == self.expected_new_counts, "helper counts differ from SQL row counts"
        requests = {row["request_id"]: row for row in scoped["artifact_hold_requests"]}
        holds_by_request = {}
        for row in scoped["artifact_holds"]:
            holds_by_request.setdefault(row["request_id"], []).append(row)
        receipts_by_request = {}
        for row in scoped["artifact_hold_consume_receipts"]:
            receipts_by_request.setdefault(row["request_id"], []).append(row)
        acquires = {entry["label"]: entry for entry in marker["acquires"]}
        assert sorted(acquires) == ["consumed", "dropped-grant"], "unexpected fixture acquire labels"
        for entry in marker["acquires"]:
            request = requests[entry["request_id"]]
            ack = entry["ack"]
            assert request["request_id"] == ack["request_id"] == entry["request_id"]
            assert request["request_digest"] == ack["request_digest"]
            assert request["shard_id"] == ack["shard"]
            assert request["artifact_count"] == len(ack["artifacts"])
            assert request["tenant_id"] == uuid_literal(self.core_repo["tenant_id"])
            assert request["repository_id"] == uuid_literal(self.core_repo["id"])
            assert request["consume_request_id"] == ack["consume_request_id"]
            assert request["gate_digest"] == marker["scope"]["gate_digest"]
            body = json.loads(request["ack_body"])
            assert body["request_id"] == request["request_id"]
            assert body["consume_request_id"] == request["consume_request_id"]
            assert body["artifacts"] == ack["artifacts"]
            holds = holds_by_request.get(entry["request_id"], [])
            assert len(holds) == request["artifact_count"]
            for hold in holds:
                assert hold["state"] == "active" and hold["generation"] == 1
                assert hold["repository_id"] == request["repository_id"]
                assert hold["operation_id"] == request["operation_id"]
            if entry["consumed"] is not None:
                receipts = receipts_by_request[entry["request_id"]]
                assert len(receipts) == len(entry["consumed"]["receipts"])
                assert entry["consumed"]["consume_request_id"] == ack["consume_request_id"]
                expected_receipts = {row["hold_id"]: row for row in entry["consumed"]["receipts"]}
                for receipt in receipts:
                    assert receipt["consume_request_id"] == ack["consume_request_id"]
                    assert receipt["request_id"] == entry["request_id"]
                    assert receipt["consume_digest"] == expected_receipts[receipt["hold_id"]]["consume_digest"]
                    receipt_body = json.loads(receipt["body"])
                    assert receipt_body["hold_id"] == receipt["hold_id"]
                    assert receipt_body["consume_request_id"] == receipt["consume_request_id"]
            else:
                assert entry["request_id"] not in receipts_by_request
                assert entry["grant_dropped"] is True and entry["replay_after_drop"] is True
        shards = {row["shard_id"]: row for row in scoped["artifact_hold_shards"]}
        assert sorted(shards) == list(range(64)), "the fixed 64 shard rows changed"
        expected = {shard: [0, 0, 0, 0] for shard in range(64)}
        for row in scoped["artifact_holds"]:
            shard = requests[row["request_id"]]["shard_id"]
            expected[shard][0] += 1
            expected[shard][1] += row["declared_bytes"]
            expected[shard][2] += row["logical_bytes"]
        for row in scoped["artifact_hold_requests"]:
            shard = row["shard_id"]
            expected[shard][2] += len(row["ack_body"].encode("utf-8")) + 128
            expected[shard][3] += 1
        for row in scoped["artifact_hold_consume_receipts"]:
            shard = requests[row["request_id"]]["shard_id"]
            expected[shard][2] += len(row["body"].encode("utf-8")) + 128
            expected[shard][3] += 1
        for shard, counters in expected.items():
            row = shards[shard]
            actual = [row["hold_count"], row["declared_bytes"], row["logical_bytes"], row["receipt_count"]]
            assert actual == counters, "shard " + str(shard) + " counters differ from retained rows"
            assert all(value >= 0 for value in actual)
        repo_usage = scoped["artifact_hold_repo_usage"][0]
        tenant_usage = scoped["artifact_hold_tenant_usage"][0]
        total_logical = sum(row["logical_bytes"] for row in scoped["artifact_holds"])
        total_logical += sum(len(row["ack_body"].encode("utf-8")) + 128
                             for row in scoped["artifact_hold_requests"])
        total_logical += sum(len(row["body"].encode("utf-8")) + 128
                             for row in scoped["artifact_hold_consume_receipts"])
        total_receipts = len(scoped["artifact_hold_requests"]) + len(scoped["artifact_hold_consume_receipts"])
        for counter in ("hold_count", "declared_bytes", "logical_bytes", "receipt_count"):
            assert repo_usage[counter] == tenant_usage[counter], "retained " + counter + " differs between scopes"
            assert repo_usage[counter] > 0
        assert repo_usage["logical_bytes"] == total_logical
        assert repo_usage["hold_count"] == 3 and repo_usage["receipt_count"] == total_receipts == 4
        snapshot_gate = marker["scope"]
        gate = self.core_gate_row()
        assert gate["revision"] == snapshot_gate["gate_revision"] == 2
        assert gate["history_incarnation"] == snapshot_gate["history_incarnation"]
        assert gate["object_format"] == snapshot_gate["object_format"]
        parent = marker["parent_operation"]
        assert parent["adapter_or_git_ack"] is False
        assert parent["seeded_by"] == "direct_sql_metadata_fixture"

    def _adopt_pending_parent_fixture(self, marker):
        """The helper adds exactly one plain-SQL lane and pending parent row."""
        before_lanes = {(row["repository_id"], row["issuer_id"], row["lane"]): row
                        for row in self.source_fixture_rows["ref_store_issuer_lanes"]}
        before_ops = {row["operation_id"]: row for row in self.source_fixture_rows["ref_store_operations"]}
        after_lanes = {(row["repository_id"], row["issuer_id"], row["lane"]): row
                       for row in self.core_fixture_rows("ref_store_issuer_lanes")}
        after_ops = {row["operation_id"]: row for row in self.core_fixture_rows("ref_store_operations")}
        parent = marker["parent_operation"]
        parent_key = (uuid_literal(self.core_repo["id"]), parent["issuer_id"], parent["lane"])
        assert set(after_lanes) == set(before_lanes) | {parent_key}, "the helper added unexpected issuer lanes"
        assert set(after_ops) == set(before_ops) | {parent["operation_id"]}, "the helper added unexpected operations"
        for key, row in before_lanes.items():
            assert after_lanes[key] == row, "an inherited issuer lane changed during A3 seeding"
        for operation_id, row in before_ops.items():
            assert after_ops[operation_id] == row, "an inherited operation changed during A3 seeding"
        pending = after_ops[parent["operation_id"]]
        assert pending["state"] == "pending" and pending["terminal_at"] is None
        assert pending["request_digest"] == parent["operation_digest"]
        assert pending["issuer_id"] == parent["issuer_id"] and pending["lane"] == parent["lane"]
        assert after_lanes[parent_key]["last_reserved_sequence"] >= parent["sequence"]
        for table in ("ref_store_cancellations", "ref_store_core_gates", "ref_store_core_refs", "ref_store_core_events"):
            assert self.core_fixture_rows(table) == self.source_fixture_rows[table], table + " changed during A3 seeding"
        assert self.core_repository_row() == self.source_core_repo
        self.core_expected_counts["ref_store_issuer_lanes"] += 1
        self.core_expected_counts["ref_store_operations"] += 1
        self.source_fixture_rows = {table: self.core_fixture_rows(table) for table in self.core_expected_counts}
        self.source_core_rows = self.core_rows()

    def seed_core_fixture(self):
        self.holds_helper = validate_holds_fixture_binary(
            self.args.holds_fixture_binary, self.args.binary,
            getattr(self.args, "holds_fixture_receipt", None),
            getattr(self.args, "candidate_receipt", None))
        result = super().seed_core_fixture()
        marker = self.run_holds_fixture("seed")
        self.assert_binary_binding("seed")
        self.holds_marker = marker
        assert json.loads(self.holds_manifest.read_text()) == marker, (
            "the private artifact-hold manifest differs from the public marker")
        gate = self.core_gate_row()
        scope = marker["scope"]
        assert scope["repository_id"] == uuid_literal(self.core_repo["id"])
        assert scope["tenant_id"] == uuid_literal(self.core_repo["tenant_id"])
        assert scope["owner_id"] == uuid_literal(self.core_repo["tenant_id"])
        assert scope["purpose"] == "ref_publication"
        assert scope["object_format"] == gate["object_format"]
        assert scope["history_incarnation"] == gate["history_incarnation"]
        assert scope["authority_epoch"] == gate["authority_epoch"]
        assert scope["group_epoch"] == gate["group_epoch"]
        assert scope["gate_revision"] == gate["revision"] == 2
        assert scope["head_ref"] == gate["head_ref"]
        self.source_new_rows = self.new_rows()
        self.source_new_scoped_rows = self.new_scoped_rows()
        assert self.source_new_scoped_rows == marker["tables"], (
            "adapter-seeded artifact-hold rows differ from the SQL capture of the same rows")
        self.assert_new_tables_populated(self.source_new_scoped_rows, marker)
        self._adopt_pending_parent_fixture(marker)
        request_ids = {entry["request_id"] for entry in marker["acquires"]}
        operations = self.core_fixture_rows("ref_store_operations")
        assert not request_ids & {row["operation_id"] for row in operations}, (
            "an artifact-hold request was recorded as a ref operation")
        result.update({
            "adapter_seeded_schema141_tables": {table: len(rows) for table, rows in self.source_new_scoped_rows.items()},
            "artifact_hold_acquire_labels": [entry["label"] for entry in marker["acquires"]],
            "stable_consume_ids_captured": True,
            "dropped_grant_replay_returned_old_ack_without_remint": True,
            "parent_operation_direct_sql_not_adapter_ack": True,
            "full_parent_operation_tuple_bound_in_ack": True,
            "all_64_shard_rows_present": True,
            "restored_blob_bytes_qualified": False,
        })
        return result

    def lock_and_snapshot(self):
        result = super().lock_and_snapshot()
        manifest = json.loads((self.backup / "manifest.json").read_text())
        assert manifest["format"] == CURRENT_BACKUP_FORMAT
        assert manifest["schema_versions"] == SCHEMA_VERSIONS
        assert "metadata.dump" in manifest["files"]
        listing = self.run(["pg_restore", "--list", str(self.backup / "metadata.dump")]).stdout.decode()
        for table in NEW_TABLES:
            assert ("TABLE DATA public " + table in listing) or (
                'TABLE DATA public "' + table + '"' in listing), (
                "parent snapshot dump does not contain migration-141 table " + table)
        pack_tables = schema142_pack_tables()
        for table in pack_tables:
            assert ("TABLE DATA public " + table in listing) or (
                'TABLE DATA public "' + table + '"' in listing), (
                "parent snapshot dump silently excluded schema142 table " + table)
            assert self.sql(
                'SELECT count(*) FROM public."' + table + '"') == "0", (
                    "A3 fixture fabricated a schema142 pack row in " + table)
        for table in A5_PACK_SNAPSHOT_TABLES:
            assert ("TABLE DATA public " + table in listing) or (
                'TABLE DATA public "' + table + '"' in listing), (
                "parent snapshot dump silently excluded schema143 table " + table)
            assert self.sql(
                'SELECT count(*) FROM public."' + table + '"') == "0", (
                    "A3 fixture fabricated an A5 snapshot-pack row in " + table)
        gate_modes = self.sql(
            "SELECT string_agg(DISTINCT pack_mode, ',' ORDER BY pack_mode) "
            "FROM ref_store_core_gates")
        assert gate_modes == "metadata_only", gate_modes
        result.update({"backup_format": manifest["format"],
                       "schema141_retained_in_current_schema": SCHEMA_VERSIONS[-1] >= 141,
                       "schema142_is_current_base": SCHEMA_VERSIONS[-1] >= 142,
                       "schema143_pack_snapshot_tables": list(A5_PACK_SNAPSHOT_TABLES),
                       "schema142_pack_ledger_tables": pack_tables,
                       "schema142_pack_tables_empty_and_not_fabricated": True,
                       "gate_pack_mode_default_metadata_only": True,
                       "parent_snapshot_inspected_dynamic_schema141_tables": list(NEW_TABLES)})
        return result

    def reject_metadata(self, sql, message):
        self.reject_sql(sql, message)

    def restore_and_clone(self):
        result = super().restore_and_clone()
        repository = uuid_literal(self.core_repo["id"])
        tenant = uuid_literal(self.core_repo["tenant_id"])
        restored_rows = self.new_rows()
        assert restored_rows == self.source_new_rows, "restored migration-141 rows differ: " + ", ".join(
            table for table in NEW_TABLES if restored_rows[table] != self.source_new_rows[table])
        restored_scoped = self.new_scoped_rows()
        assert restored_scoped == self.source_new_scoped_rows, "restored fixture rows differ"
        self.assert_new_tables_populated(restored_scoped, self.holds_marker)
        gate = self.core_gate_row()
        assert gate["revision"] == 2 == self.holds_marker["scope"]["gate_revision"]
        assert gate["history_incarnation"] == self.holds_marker["scope"]["history_incarnation"]
        pack_tables = schema142_pack_tables()
        for table in pack_tables:
            assert self.sql(
                'SELECT count(*) FROM public."' + table + '"') == "0", (
                    "restore fabricated a schema142 pack row in " + table)
        assert gate["pack_mode"] == "metadata_only", gate
        assert self.sql("SELECT max(version) FROM schema_migrations") == str(SCHEMA_VERSIONS[-1])
        assert self.sql("SELECT count(*) FROM schema_migrations WHERE version BETWEEN 138 AND " +
                        str(SCHEMA_VERSIONS[-1])) == str(
                            len([v for v in SCHEMA_VERSIONS if v >= 138]))
        for table in A5_PACK_SNAPSHOT_TABLES:
            assert self.sql(
                'SELECT count(*) FROM public."' + table + '"') == "0", (
                    "restore fabricated an A5 snapshot-pack row in " + table)
        assert self.sql(
            "SELECT count(*) FROM ref_store_core_snapshots WHERE "
            "pack_mode<>'metadata_only' OR pack_count<>0 OR "
            "membership_digest IS NOT NULL OR snapshot_digest IS NOT NULL OR "
            "pack_membership_state<>'unavailable'") == "0"
        assert self.sql("SELECT count(*) FROM pg_trigger WHERE tgname LIKE "
                        "'ref_store_core_pack_%' AND tgenabled <> 'O'") == "0", (
                            "a migration-142 guard was disabled")
        before_replay = self.new_rows()
        verify = self.run_holds_fixture("verify", db=self.db)
        self.assert_binary_binding("verify")
        after_replay = self.new_rows()
        assert before_replay == after_replay, "verify replay mutated restored metadata rows"
        assert verify["scope"] == self.holds_marker["scope"], "restored gate scope differs from seed"
        assert verify["restored_rows_equal_pre_backup_rows"] is True
        assert verify["exact_replay_returned_original_ack_without_grant"] is True
        assert verify["exact_replay_returned_original_consume_receipts"] is True
        assert verify["replay_mutated_rows_counters_or_timestamps"] is False
        assert verify["unconsumed_consume_lookup"] == "unknown"
        assert verify["scope_mismatch_denied"] is True
        assert self.new_rows() == self.source_new_rows
        request_ids = {entry["request_id"] for entry in self.holds_marker["acquires"]}
        assert all(any(row["request_id"] == rid for row in restored_rows["artifact_hold_requests"])
                   for rid in request_ids)
        triggers = int(self.sql("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'artifact_hold_%'"))
        assert triggers >= 15, "the migration-141 ledger guards are missing"
        assert self.sql("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'artifact_hold_%' "
                        "AND tgenabled <> 'O'") == "0", "a migration-141 guard was disabled"
        active = next(entry for entry in self.holds_marker["acquires"] if entry["label"] == "consumed")
        request_id = active["request_id"]
        hold_id = active["ack"]["artifacts"][0]["hold_id"]
        receipt_id = active["consumed"]["receipts"][0]["hold_id"]
        used_shard = str(active["ack"]["shard"])
        self.reject_metadata(
            "UPDATE public.artifact_hold_requests SET ack_body='{}' WHERE request_id='" + request_id + "'",
            "artifact hold ledger row is immutable")
        self.reject_metadata(
            "UPDATE public.artifact_holds SET state='released' WHERE hold_id='" + hold_id + "'",
            "artifact hold ledger row is immutable")
        self.reject_metadata(
            "UPDATE public.artifact_hold_consume_receipts SET body='{}' WHERE hold_id='" + receipt_id + "'",
            "artifact hold ledger row is immutable")
        self.reject_metadata(
            "UPDATE public.artifact_hold_repo_usage SET hold_count=hold_count-1 WHERE repository_id='" + repository + "'",
            "artifact hold retained admission counters cannot decrease")
        self.reject_metadata(
            "UPDATE public.artifact_hold_shards SET hold_count=hold_count-1 WHERE shard_id=" + used_shard,
            "artifact hold retained admission counters cannot decrease")
        for table, key, value in (
                ("artifact_hold_requests", "request_id", request_id),
                ("artifact_holds", "hold_id", hold_id),
                ("artifact_hold_consume_receipts", "hold_id", receipt_id),
                ("artifact_hold_repo_usage", "repository_id", repository),
                ("artifact_hold_tenant_usage", "tenant_id", tenant),
                ("artifact_hold_shards", "shard_id", used_shard)):
            field = key if key != "shard_id" else "shard_id"
            literal = "'" + value + "'" if field != "shard_id" else value
            self.reject_metadata(
                "DELETE FROM public." + table + " WHERE " + field + "=" + literal,
                "artifact hold ledger rows are permanent and cannot be deleted")
        self.reject_metadata(
            "TRUNCATE public.artifact_hold_requests CASCADE",
            "artifact hold ledger and quota rows are permanent and cannot be truncated")
        assert self.new_rows() == self.source_new_rows, "a rejected direct mutation changed restored rows"
        assert self.core_rows() == self.source_core_rows
        (self.root / "restored-refstore-holds-rows.json").write_text(
            json.dumps({"scope": self.holds_marker["scope"],
                        "parent_operation": self.holds_marker["parent_operation"],
                        "acquires": self.holds_marker["acquires"],
                        "fixture_rows_by_table": {table: len(rows) for table, rows in restored_scoped.items()}},
                       indent=2) + "\n")
        result.update({
            "all_six_schema141_tables_restored_exactly": True,
            "hold_requests_holds_receipts_usage_nonempty_after_restore": True,
            "all_64_shard_rows_and_monotone_quota_counters_restored": True,
            "schema142_pack_ledger_tables_empty_after_current_restore": True,
            "schema142_gate_pack_mode_metadata_only": True,
            "schema142_pack_registration_fabricated": False,
            "typed_replay_verify_helper_ran": True,
            "exact_replay_returned_old_acks_and_receipts_without_writes": True,
            "dropped_grant_replay_cannot_remint": True,
            "unconsumed_consume_lookup_remains_unknown": True,
            "scope_mismatch_denied_on_restored_ledger": True,
            "direct_updates_deletes_truncate_refused_with_rows_unchanged": True,
            "triggers_enabled_not_disabled_by_the_drill": True,
            "restored_blob_bytes_explicitly_unqualified_and_denied": True,
            "physical_backup_or_byte_protection_closure_claimed": False,
        })
        return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--holds-fixture-binary", required=True,
                        help="selected Rust integration-test executable for ref_store_holds_backup_fixture")
    parser.add_argument("--holds-fixture-receipt", type=Path,
                        help="build receipt for the helper (defaults to <helper>.build.json)")
    parser.add_argument("--candidate-receipt", type=Path,
                        help="candidate application build receipt (defaults to <binary>.build.json)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    args.holds_fixture_binary = str(Path(args.holds_fixture_binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("dedicated synthetic ROOTYARD_TEST_DATABASE_URL required")
    harness = BackupRefStoreHolds141Harness(args)
    success = False
    try:
        for name, function in [
            ("synthetic_source_with_seeded_artifact_holds", harness.seed_core_fixture),
            ("offline_barriers_and_snapshot", harness.lock_and_snapshot),
            ("unsafe_or_corrupt_inputs", harness.invalid_inputs),
            ("backup_barrier_failures", harness.backup_barrier_failures),
            ("interrupted_restore_guard", harness.interrupted_restore),
            ("post_backup_write_not_in_snapshot", harness.write_after_backup),
            ("new_environment_restore_schema141_holds_clone_fsck", harness.restore_and_clone),
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
            holds_fixture_helper=harness.holds_helper,
            limitations=[
                "The pending migration-138 parent operation/lane is a direct-SQL metadata fixture, not an adapter or Git ACK.",
                "All migration-141 request/hold/consume ACK rows are produced by the real typed PgArtifactHoldStore.",
                "Only a fixed non-secret synthetic S3 identity is used; there is no provider IO, raw upload or read-back.",
                "Restored Blob bytes are explicitly unqualified/denied; no byte protection or physical backup closure is claimed.",
                "The drill repository remains provisioning/gitfs/unserved; artifact holds are metadata rows only.",
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
