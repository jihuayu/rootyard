#!/usr/bin/env python3
"""Current-format20/schema144 offline backup drill for retention roots + decisions.

This is the #105/#107 roots/decisions drill. It subclasses the inherited
``tests/backup_refstore_core139.py`` seven-case harness, so the seven real
offline backup cases (synthetic source, barrier/snapshot, corrupt inputs,
barrier failure, interrupted restore, post-backup write exclusion and a fresh
authenticated restore/clone/fsck) stay mandatory with zero skips.

The schema144 root tables (10) *and* the publication-decision tables (7) plus
the complete migration-139/140/141/142/143 ledgers are populated by the real
typed pipeline in ``tests/ref_store_roots_decisions_backup_fixture.rs``: a fresh
random unserved repository gets a typed gate, two genuine A4 verified pack
commits are made (gate revision 2 -> 3), one A5 pack-verified snapshot/pin is
created, three retention roots are registered (active, released, and a
release-before-register tombstone whose delayed register is refused), the A5
source pin is released and the active root is materialized from the retained
rows, and the real staged authorized-decision facade is exercised:

* one ``AcceptedSubset`` decision with one accepted and one stale-pre-image ref
  (all per-ref verdicts persisted) reaches ``CONSUMED`` and writes the selected
  ref in the same transaction;
* one ``Atomic`` decision is installed and then cancelled (``CANCELLED``);
* one operation is cancelled before any install (decision-less tombstone).

Nothing is faked with SQL: there is no SQL ACK, proof, registration, decision
row or capability.

After the actual ``pg_dump``/restore the helper runs in verify mode against the
restored database and replays only typed read-only paths:
``PgRetentionRoots::get``/``query_receipt``/``materialize`` (retained roots and
pack locators, external S3 originals re-read), ``PgDecisionProtocol::read``
(one-way fence retained) and the historical decision rows. It mints no proof,
grant or authority, charges no quota and needs no source-only tempfile. This
drill compares **every** table of the 144 schema by canonical row-set digest
(count + SHA-256 + byte length) before the backup, after the restore and after
the read-only replay, and requires the whole ``schema_delta(144)`` table set
(from the generated 144-vs-143 catalog) to be present and non-empty.

No Blob byte backup is claimed: the S3 originals are external, unchanged and
never deleted. No DSN/token/credential/token_digest is written to the report.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from backup_refstore_core139 import BackupRefStoreCore139Harness, uuid_literal
from backup_refstore_holds141 import candidate_receipt, load_receipt, receipt_field, receipt_flag, sha256_file
from schema_baseline import CURRENT_BACKUP_FORMAT, CURRENT_SCHEMA_VERSION, SCHEMA_VERSIONS, schema_delta

MARKER = "ROOTYARD-REF-STORE-ROOTS-DECISIONS-FIXTURE-METADATA"
FIXTURE_KIND = "rootyard/ref-store-core-roots-decisions-backup-fixture"
HELPER_TEST = "ref_store_roots_decisions_backup_metadata_fixture"
HELPER_TARGET = "ref_store_roots_decisions_backup_fixture"
ROOT = Path(__file__).resolve().parents[1]
HELPER_SOURCE = ROOT / "tests" / "ref_store_roots_decisions_backup_fixture.rs"

ROOT_TABLES = (
    "ref_store_core_root_heads",
    "ref_store_core_roots",
    "ref_store_core_root_refs",
    "ref_store_core_root_oids",
    "ref_store_core_root_packs",
    "ref_store_core_root_tombstones",
    "ref_store_core_root_receipts",
    "ref_store_core_root_repo_usage",
    "ref_store_core_root_tenant_usage",
    "ref_store_core_protocol_repos",
)
DECISION_TABLES = (
    "ref_store_decision_scopes",
    "ref_store_publication_decisions",
    "ref_store_decision_dependencies",
    "ref_store_decision_refs",
    "ref_store_decision_cancellations",
    "ref_store_decision_repo_usage",
    "ref_store_decision_tenant_usage",
)

# Only the documented drill shape is pinned here; the *table names* always come
# from the generated 144-vs-143 catalog (asserted in ``schema_tables``).
EXPECTED_ROOT_COUNTS = {
    "ref_store_core_root_heads": 3,
    "ref_store_core_roots": 2,
    "ref_store_core_root_refs": 2,
    "ref_store_core_root_oids": 2,
    "ref_store_core_root_packs": 4,

    "ref_store_core_root_tombstones": 2,
    "ref_store_core_root_receipts": 4,
    "ref_store_core_root_repo_usage": 1,
    "ref_store_core_root_tenant_usage": 1,
    "ref_store_core_protocol_repos": 1,
}
EXPECTED_DECISION_COUNTS = {
    "ref_store_decision_scopes": None,
    "ref_store_publication_decisions": 2,
    "ref_store_decision_dependencies": None,
    "ref_store_decision_refs": 3,
    "ref_store_decision_cancellations": 2,
    "ref_store_decision_repo_usage": 1,
    "ref_store_decision_tenant_usage": 1,
}

DIGEST_EXPRESSION = (
    "SELECT count(*)::bigint, "
    "coalesce(encode(sha256(convert_to(coalesce(string_agg(to_jsonb(t)::text, E'\\n' "
    "ORDER BY to_jsonb(t)::text), ''), 'UTF8')), 'hex'), ''), "
    "coalesce(octet_length(convert_to(coalesce(string_agg(to_jsonb(t)::text, E'\\n' "
    "ORDER BY to_jsonb(t)::text), ''), 'UTF8')), 0) "
    'FROM public."{table}" t')


def digest_sql(table):
    assert table.replace("_", "").isalnum(), table
    return DIGEST_EXPRESSION.format(table=table)


def validate_roots_decision_fixture_binary(helper, app_binary, helper_receipt=None, app_receipt=None):
    """Bind the selected helper executable to its real integration-test build."""
    helper = Path(helper)
    assert helper.is_file(), "roots/decisions fixture binary is missing: " + str(helper)
    receipt_path = Path(helper_receipt) if helper_receipt else candidate_receipt(helper)
    receipt = load_receipt(receipt_path, "roots/decisions fixture build receipt")
    actual = sha256_file(helper)
    recorded = receipt_field(receipt, ("binary_sha256", "artifact_sha256", "sha256"), "binary sha256")
    assert recorded == actual, "roots/decisions fixture binary does not match its build receipt"
    kind = receipt_field(receipt, ("kind", "target_kind"), "build kind")
    assert kind == "rust-integration-test", "roots/decisions fixture receipt kind is " + repr(kind)
    assert receipt_flag(receipt, ("package_rebuilt",), "package_rebuilt") is True
    entries = receipt.get("fresh_false_artifacts")
    assert isinstance(entries, list) and len(entries) == 1, (
        "roots/decisions fixture receipt must record exactly one fresh=False artifact")
    entry = entries[0]
    assert isinstance(entry, dict), "roots/decisions fixture fresh=False entry is not an object"
    assert str(entry.get("target")) == HELPER_TARGET, (
        "roots/decisions fixture receipt target is " + repr(entry.get("target")) + ", expected " + HELPER_TARGET)
    assert entry.get("fresh") is False, "roots/decisions fixture artifact is not marked fresh=False"
    assert str(entry.get("kind")) == "test", "roots/decisions fixture artifact kind is not test"
    profile = entry.get("profile") or {}
    assert isinstance(profile, dict) and profile.get("test") is True, (
        "roots/decisions fixture artifact was not built with a test profile")
    executable = entry.get("executable")
    assert executable, "roots/decisions fixture artifact records no executable"
    assert Path(str(executable)).name.startswith(HELPER_TARGET), (
        "roots/decisions fixture receipt artifact does not name the " + HELPER_TARGET + " target")
    assert receipt.get("relocated_artifact") is True, (
        "roots/decisions fixture receipt must record the relocated integration-test artifact")
    source_sha = receipt_field(receipt, ("integration_test_source_sha256",), "integration_test_source_sha256")
    assert source_sha == sha256_file(HELPER_SOURCE), (
        "the roots/decisions fixture receipt was produced from different integration-test source")
    source_inputs = receipt_field(receipt, ("source_inputs_sha256", "source_inputs"), "source_inputs_sha256")
    assert isinstance(source_inputs, str) and len(source_inputs) == 64, (
        "roots/decisions fixture receipt has no source-input digest")
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


class BackupRefStoreRootsDecisions144Harness(BackupRefStoreCore139Harness):
    """Populate the schema144 roots + decisions ledgers through the typed pipeline."""

    def __init__(self, args):
        super().__init__(args)
        self.fixture_binary = Path(args.roots_decisions_fixture_binary)
        self.seed_manifest = self.root / "roots-decisions-seed-marker.json"
        self.verify_manifest = self.root / "roots-decisions-verify-marker.json"
        self.fixture_helper = None
        self.marker = None
        self.verify_marker = None
        self.scope = None

    # -- helper process -----------------------------------------------------------------
    def fixture_env(self, mode, db, output):
        env = self.env.copy()
        env.update(
            ROOTYARD_TEST_DATABASE_URL=db,
            ROOTYARD_ROOTS_DECISIONS_FIXTURE_MODE=mode,
            ROOTYARD_ROOTS_DECISIONS_FIXTURE_OUTPUT=str(output),
        )
        if mode == "verify":
            env["ROOTYARD_ROOTS_DECISIONS_FIXTURE_SEED"] = str(self.seed_manifest)
        return env

    def run_fixture(self, mode, db=None, output=None):
        assert self.fixture_helper is not None, "fixture binary was not validated"
        assert mode in ("seed", "verify"), mode
        output = output or (self.seed_manifest if mode == "seed" else self.verify_manifest)
        process = self.run(
            [str(self.fixture_binary), "--ignored", "--exact", HELPER_TEST,
             "--format=terse", "--nocapture", "--test-threads=1"],
            env=self.fixture_env(mode, db or self.db, output))
        stdout = process.stdout.decode()
        summaries = [line for line in stdout.splitlines() if line.startswith("test result:")]
        assert summaries, "the roots/decisions fixture reported no test result at all"
        summary = summaries[-1]
        assert "1 passed" in summary, "the roots/decisions fixture did not run exactly one test: " + summary
        assert "0 failed" in summary, "the roots/decisions fixture failed: " + summary
        assert "0 ignored" in summary, "the roots/decisions fixture skipped its test: " + summary
        lines = [line for line in stdout.splitlines() if line.startswith(MARKER + " ")]
        assert len(lines) == 1, "the roots/decisions fixture must print exactly one marker line"
        text = lines[0]
        assert self.redact(text) == text, "the roots/decisions marker leaked a credential or database URL"
        marker = json.loads(text[len(MARKER) + 1:])
        assert marker["kind"] == FIXTURE_KIND, "roots/decisions marker has an unexpected kind"
        assert marker["mode"] == mode, "roots/decisions marker reports an unexpected mode"
        claims = marker["claims"]
        assert claims["restored_blob_bytes_backed_up"] is False
        assert claims["physical_blob_backup_closure"] is False
        assert claims["complete_git_read_snapshot_claimed"] is False
        assert claims["decision_consumed_via_authorized_facade"] is True
        assert claims["decision_or_receipt_fabricated_by_sql"] is False
        assert claims["sql_faked_ack_or_proof_or_registration"] is False
        assert claims["held_remote_objects_deleted"] is False
        assert claims["read_only_replay_charges_quota"] is False
        assert claims["marker_contains_credential_or_token_digest"] is False
        assert json.loads(output.read_text()) == marker, (
            "the private roots/decisions manifest differs from the public marker")
        return marker

    def assert_binary_binding(self, stage):
        assert self.fixture_helper is not None, "fixture binary was not validated"
        helper = sha256_file(self.fixture_binary)
        app = sha256_file(Path(self.args.binary))
        assert helper == self.fixture_helper["binary_sha256"], (
            "fixture binary changed after validation (" + stage + ")")
        assert app == self.fixture_helper["candidate_application_sha256"], (
            "application binary changed after validation (" + stage + ")")
        self.fixture_helper["retained_binding_stages"] = (
            self.fixture_helper.get("retained_binding_stages", []) + [stage])
        self.fixture_helper["binaries_unchanged_after_run"] = True
        return {"stage": stage, "helper_binary_sha256": helper, "application_binary_sha256": app, "unchanged": True}

    # -- canonical whole-schema capture (identical SQL in the Rust helper) --------------
    def schema_tables(self):
        delta = list(schema_delta(CURRENT_SCHEMA_VERSION))
        assert sorted(delta) == sorted(ROOT_TABLES + DECISION_TABLES), (
            "the generated 144-vs-143 catalog delta is " + repr(delta))
        return tuple(delta)

    def table_digests(self, db=None, refstore_only=True):
        db = db or self.db
        tables = self.metadata_psql(
            "SELECT string_agg(tablename, ',' ORDER BY tablename) FROM pg_tables "
            "WHERE schemaname='public'", db=db).stdout.decode().strip()
        assert tables, "the drilled database has no public tables"
        digests = {}
        for table in tables.split(","):
            if not table or (refstore_only and not table.startswith("ref_store_")):
                continue
            row = self.metadata_psql(digest_sql(table), db=db).stdout.decode().strip()
            count, sha256, length = row.split("|")
            digests[table] = {"rows": int(count), "sha256": sha256, "bytes": int(length)}
        return digests

    def family_counts(self, tables, db=None):
        return {table: int(self.metadata_psql(
            'SELECT count(*) FROM public."' + table + '"', db=db or self.db).stdout.decode().strip())
            for table in tables}

    # -- case 1: seed ------------------------------------------------------------------
    def seed_core_fixture(self):
        self.fixture_helper = validate_roots_decision_fixture_binary(
            self.args.roots_decisions_fixture_binary, self.args.binary,
            getattr(self.args, "roots_decisions_fixture_receipt", None),
            getattr(self.args, "candidate_receipt", None))
        result = super().seed_core_fixture()
        marker = self.run_fixture("seed")
        self.assert_binary_binding("seed")
        self.marker = marker
        self.scope = marker["scope"]
        assert self.scope["repository_id"] != self.core_repo["id"], (
            "the typed roots/decisions gate must not reuse the inherited plain-SQL 139 repository")
        self.schema_tables()
        self.assert_root_and_decision_scenarios(marker)
        families = set(ROOT_TABLES) | set(DECISION_TABLES)
        for table in families:
            assert int(self.metadata_psql('SELECT count(*) FROM public."' + table + '"').stdout.decode().strip()) > 0, (
                "the drill left migration-144 table " + table + " empty")
        seeded_digests = self.table_digests()
        assert marker["tables"] == seeded_digests, (
            "the helper's Rust table digests differ from the harness psql capture")
        assert marker["root_family_counts"] == self.family_counts(ROOT_TABLES)
        assert marker["decision_family_counts"] == self.family_counts(DECISION_TABLES)
        result.update({
            "adapter_seeded_schema144_root_tables": marker["root_family_counts"],
            "adapter_seeded_schema144_decision_tables": marker["decision_family_counts"],
            "schema144_table_names_from_generated_catalog": list(self.schema_tables()),
            "typed_native_pack_commit_registered_and_verified": True,
            "pack_verified_a5_snapshot_source": True,
            "retention_roots": [entry["label"] for entry in marker["roots"]],
            "root_release_before_register_tombstone": True,
            "decision_consumed_via_authorized_facade": True,
            "decision_installed_then_cancelled": True,
            "decision_cancelled_before_install": True,
            "sql_faked_ack_proof_registration_or_decision": False,
            "marker_contains_credential_or_token_digest": False,
        })
        return result

    def assert_root_and_decision_scenarios(self, marker):
        roots = marker["roots"]
        assert [entry["label"] for entry in roots] == ["active", "released", "tombstone"]
        active, released, tombstone = roots
        assert active["state"] == "active" and released["state"] == "released"
        assert active["ref_count"] == 1 and active["oid_count"] == 1
        assert active["pack_count"] == 2 and len(active["packs"]) == 2
        assert len(active["binding_digest"]) == 64 and len(active["register_digest"]) == 64
        assert released["receipts"]["release"]["state"] == "released"
        assert tombstone["record"] is None, "the release-before-register tombstone gained a capture"
        assert "register" not in tombstone["receipts"], "a refused register produced a receipt"
        materialized = marker["materialized"]
        assert materialized["root_id"] == active["root_id"]
        assert materialized["verified_pairs"] == 2 and materialized["verified_bytes"] > 0
        assert materialized["readback_pairs"] == 2
        assert materialized["readback_bytes"] == materialized["verified_bytes"]
        assert marker["source"]["source_pin_released"] is True
        quota = marker["quota"]
        assert quota["repo"]["roots"] >= 2 and quota["tenant"]["roots"] == quota["repo"]["roots"]
        assert quota["repo"]["receipts"] == 4 and quota["tenant"]["receipts"] == 4
        assert quota["repo"]["pack_bindings"] == 4
        assert quota["roots_revision"] is not None
        # Both ordinary release and release-before-register retain a tombstone.
        assert marker["root_counts"]["tombstones"] == 2, marker["root_counts"]
        counts = marker["root_family_counts"]
        variable = ("ref_store_core_root_refs", "ref_store_core_root_oids", "ref_store_core_root_packs")
        for table, expected in EXPECTED_ROOT_COUNTS.items():
            if table in variable:
                assert counts[table] >= expected, table + " rows are below the documented drill shape"
            else:
                assert counts[table] == expected, table + " rows differ from the documented drill shape"
        decision_counts = marker["decision_family_counts"]
        for table, expected in EXPECTED_DECISION_COUNTS.items():
            if expected is not None:
                assert decision_counts[table] == expected, table + " rows differ from the drill shape"
        decisions = marker["decisions"]
        assert decisions["installed"] == 2 and decisions["consumed"] == 1
        assert decisions["cancelled"] == 1 and decisions["cancel_before_install_count"] == 1
        rows = {row["decision_id"]: row for row in decisions["rows"]}
        consumed = rows[decisions["consumed_decision"]["decision_id"]]
        assert consumed["state"] == "CONSUMED", "the accepted-subset decision is not CONSUMED"
        assert consumed["action"] in ("push", "merge"), consumed["action"]
        verdicts = consumed["verdicts"]
        assert len(verdicts) == 2, "the consumed decision did not persist both per-ref verdicts"
        accepted = [v for v in verdicts if v["reject_code"] is None]
        rejected = [v for v in verdicts if v["reject_code"] is not None]
        assert len(accepted) == 1 and len(rejected) == 1, verdicts
        assert accepted[0]["ref_name"] == "refs/heads/release"
        assert rejected[0]["ref_name"] == "refs/heads/main"
        cancelled = rows[decisions["cancelled_decision"]["decision_id"]]
        assert cancelled["state"] == "CANCELLED", "the post-install cancel did not close the decision"
        assert decisions["cancel_before_install"]["decision_id"] is None
        assert decisions["cancel_before_install"]["cancellation"]["decision_id"] is None
        assert decisions["prepared"]["planned_refs"] == 2
        assert marker["protocol"]["decision_required"] is True, "the one-way decision fence was not enabled"

    # -- case 2: offline barrier + snapshot --------------------------------------------
    def lock_and_snapshot(self):
        result = super().lock_and_snapshot()
        manifest = json.loads((self.backup / "manifest.json").read_text())
        assert manifest["format"] == CURRENT_BACKUP_FORMAT, "drill did not produce the current backup format"
        assert manifest["schema_versions"] == SCHEMA_VERSIONS, "the archive schema versions differ"
        assert SCHEMA_VERSIONS[-1] == 144, "the current schema is not migration 144"
        assert "metadata.dump" in manifest["files"], "the parent snapshot has no metadata dump"
        listing = self.run(["pg_restore", "--list", str(self.backup / "metadata.dump")]).stdout.decode()
        for table in self.schema_tables():
            assert (("TABLE DATA public " + table in listing) or
                    ('TABLE DATA public "' + table + '"' in listing)), (
                "parent snapshot dump silently excluded table " + table)
            assert int(self.metadata_psql('SELECT count(*) FROM public."' + table + '"').stdout.decode().strip()) > 0, (
                "the drill left migration-144 table " + table + " empty before the backup")
        assert self.metadata_psql("SELECT count(*) FROM ref_store_publication_decisions "
                                  "WHERE state='CONSUMED'").stdout.decode().strip() == "1"
        assert self.metadata_psql("SELECT count(*) FROM ref_store_publication_decisions "
                                  "WHERE state='CANCELLED'").stdout.decode().strip() == "1"
        assert self.metadata_psql("SELECT count(*) FROM ref_store_decision_cancellations "
                                  "WHERE decision_id IS NULL").stdout.decode().strip() == "1"
        self.backup_digests = self.table_digests()
        assert self.backup_digests["ref_store_publication_decisions"] == (
            self.marker["tables"]["ref_store_publication_decisions"]), (
            "the offline snapshot changed the decision rows after seeding")
        result.update({
            "backup_format": manifest["format"],
            "schema144_is_current_base": True,
            "schema144_tables": list(self.schema_tables()),
            "schema144_tables_nonempty": True,
            "parent_snapshot_inspected_dynamic_schema144_tables": list(self.schema_tables()),
            "decision_consumed_row_in_snapshot": True,
            "decision_cancelled_row_in_snapshot": True,
            "decision_less_tombstone_in_snapshot": True,
        })
        return result

    def reject_guard(self, sql, message):
        self.reject_sql(sql, message)

    # -- case 7: fresh environment restore + clone + fsck ------------------------------
    def restore_and_clone(self):
        result = json.loads(self.restore_command().stdout)
        # Typed read-only replay against the restored database BEFORE any service
        # process can touch an auth/session row.
        restored_before = self.table_digests(self.target_db)
        assert restored_before == self.backup_digests, (
            "restored table digests differ: " + ", ".join(
                table for table in self.backup_digests
                if restored_before.get(table) != self.backup_digests[table]))
        # Cluster authority deliberately rotates on restore. Compare every
        # retained RefStore ledger exactly, then all schema tables independently
        # around the read-only verification to detect any new mutation.
        readonly_before = self.table_digests(self.target_db, refstore_only=False)
        verify = self.run_fixture("verify", db=self.target_db)
        self.verify_marker = verify
        self.assert_binary_binding("verify")
        restored_after = self.table_digests(self.target_db)
        assert restored_after == restored_before, (
            "the read-only restored verification mutated canonical rows, counters or timestamps: " + ", ".join(
                table for table in restored_before
                if restored_after.get(table) != restored_before[table]))
        readonly_after = self.table_digests(self.target_db, refstore_only=False)
        assert readonly_after == readonly_before, "typed verification mutated a table outside the RefStore cohort"
        for key in ("scope", "source", "gate", "roots", "materialized", "root_counts", "quota",
                    "tables", "root_family_counts", "decision_family_counts", "protocol"):
            assert verify[key] == self.marker[key], "restored typed evidence differs for " + key
        self.assert_root_and_decision_scenarios(verify)
        assert self.metadata_psql("SELECT max(version) FROM schema_migrations",
                                  db=self.target_db).stdout.decode().strip() == "144"

        # The restored database keeps the one-way decision fence and immutable rows.
        scope = self.scope
        repo = uuid_literal(scope["repository_id"])
        decision_id = self.marker["decisions"]["consumed_decision"]["decision_id"]
        self.reject_guard("UPDATE ref_store_publication_decisions SET state='OPEN' "
                          "WHERE decision_id='" + decision_id + "'", "publication decision terminal state is immutable")
        self.reject_guard("DELETE FROM ref_store_publication_decisions "
                          "WHERE decision_id='" + decision_id + "'", "publication decision history is never deleted or truncated")
        self.reject_guard("UPDATE ref_store_core_root_receipts SET body='{}' "
                          "WHERE repository_id='" + repo + "'", "retained roots row is immutable")
        self.reject_guard("DELETE FROM ref_store_core_root_receipts "
                          "WHERE repository_id='" + repo + "'", "retained roots row is immutable")
        self.reject_guard("UPDATE ref_store_core_protocol_repos SET decision_required=FALSE "
                          "WHERE repository_id='" + repo + "'", "decision_required is a one-way fence")
        self.reject_guard("UPDATE ref_store_core_root_tenant_usage SET roots=roots-1 "
                          "WHERE tenant_id='" + uuid_literal(scope["tenant_id"]) + "'",
                          "roots quota counters are monotone")

        # Inherited fresh authenticated clone/fsck/auth-boundary proof.
        self.env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        self.db = self.target_db
        self.start()
        assert self.git("ls-remote", self.remote, token=self.alice).stdout == self.before_refs
        clone = self.root / "restored-clone"
        self.git("clone", self.remote, str(clone), token=self.reader)
        self.git("fsck", "--full", "--strict", cwd=clone)
        assert (clone / "hello.txt").read_text() == "second\n"
        assert not (clone / "after-backup.txt").exists()
        assert self.git("cat-file", "-e", self.post_backup_oid, cwd=clone, check=False).returncode != 0
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == self.second
        self.expect("/api/repos", 401, token=self.revoked)
        self.expect(self.repo["clone_path"] + "/info/refs?service=git-receive-pack", 403, token=self.reader)
        unknown = json.loads(self.expect("/api/repos/alice/unknown", 200, token=self.alice))
        assert unknown["state"] == "recovering"
        self.expect(self.unknown_repo["clone_path"] + "/info/refs?service=git-upload-pack", 503, token=self.alice)
        self.stop()
        result.update({
            "all_refstore_schema144_and_legacy_ledgers_restored_exactly": True,
            "all_schema_tables_unchanged_by_readonly_verification": True,
            "schema144_root_tables_restored_exactly": True,
            "schema144_decision_tables_restored_exactly": True,
            "typed_root_get_query_and_materialize_after_restore": True,
            "retained_root_pack_locators_read_back_from_external_s3": True,
            "historical_decision_rows_data_only": True,
            "decision_one_way_fence_retained": True,
            "restored_read_only_replay_not_charged_and_not_mutating": True,
            "direct_updates_deletes_refused_with_rows_unchanged": True,
            "fresh_authenticated_clone_and_fsck": True,
            "byte_backup_or_physical_protection_closure_claimed": False,
            "held_remote_objects_deleted": False,
            "separate_pg_server": self.admin != self.restore_admin,
        })
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--roots-decisions-fixture-binary", required=True,
                        help="selected Rust integration-test executable for "
                             "ref_store_roots_decisions_backup_fixture")
    parser.add_argument("--roots-decisions-fixture-receipt", type=Path,
                        help="build receipt for the helper (defaults to <helper>.build.json)")
    parser.add_argument("--candidate-receipt", type=Path,
                        help="candidate application build receipt (defaults to <binary>.build.json)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    args.roots_decisions_fixture_binary = str(Path(args.roots_decisions_fixture_binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("dedicated synthetic ROOTYARD_TEST_DATABASE_URL required")
    harness = BackupRefStoreRootsDecisions144Harness(args)
    success = False
    try:
        for name, function in [
            ("synthetic_source_with_typed_roots_and_decision_ledger", harness.seed_core_fixture),
            ("offline_barriers_and_snapshot", harness.lock_and_snapshot),
            ("unsafe_or_corrupt_inputs", harness.invalid_inputs),
            ("backup_barrier_failures", harness.backup_barrier_failures),
            ("interrupted_restore_guard", harness.interrupted_restore),
            ("post_backup_write_not_in_snapshot", harness.write_after_backup),
            ("new_environment_restore_schema144_roots_decisions_clone_fsck", harness.restore_and_clone),
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
            roots_decisions_fixture_helper=harness.fixture_helper,
            schema144_tables=list(harness.schema_tables()),
            limitations=[
                "The typed A3/A4/A5, root and decision ledger is seeded by the real adapters and the real staged authorized pipeline; no SQL ACK, proof, receipt, registration or decision row is fabricated.",
                "The inherited migration-139 metadata gate/ref fixture is plain SQL and is never used for the native proof; the drill uses its own typed gate.",
                "The random roots repository stays provisioning/gitfs/unserved for the whole drill.",
                "Only the AcceptedSubset decision consumes refs; the Atomic decision is cancelled before commit and the third operation is cancelled before install.",
                "complete_git_read_snapshot() is false everywhere: this drill claims registered pack membership metadata only, never verified Blob bytes or native Git object closure.",
                "Blob byte backup is not claimed: the S3 originals are external, re-read read-only and never deleted; only PostgreSQL metadata is restored.",
                "The read-only restored replay mints no proof, grant or authority and charges no quota.",
                "Decision rows are represented in the marker/report only by canonical per-table digests, counts and non-secret verdict codes; no credential or token_digest is written anywhere.",
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
