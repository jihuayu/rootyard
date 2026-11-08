#!/usr/bin/env python3
"""Format15/schema139 backup roundtrip with populated RefStore core metadata.

This is a native, offline ``rootyard backup --offline`` drill on disposable
PostgreSQL databases and volume directories.  It reuses the shared
``BackupHarness`` (association barriers, snapshot, corrupt-input rejection,
interrupted restore guard, post-backup write exclusion and a fresh authenticated
clone/fsck) and adds one task-owned repository that is deliberately unserved:
``state='provisioning'``, ``storage_backend='gitfs'``,
``transition_state='stable'``, no Pando state row, no legacy ref projection and
no bare Git directory.  Its next provisioning retry is far in the future so a
service restart during the drill cannot provision or serve it.

The rows in ``ref_store_issuer_lanes``, ``ref_store_operations``,
``ref_store_cancellations`` and the migration-139 gate/ref/event tables are
inserted directly as a SQL metadata fixture.  They are NOT evidence of an
adapter or protocol acknowledgement; ``tests/ref_store_operations.rs`` and
``tests/ref_store_core.rs`` own that proof.  The JSON terminal/event values use
the real persisted shapes from the Rust RefStore implementation.

Requires a dedicated synthetic ROOTYARD_TEST_DATABASE_URL with CREATEDB.  An
optional separate ROOTYARD_RESTORE_TEST_DATABASE_URL is honoured by the shared
harness.  Never use production credentials or a production server.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.parse
import uuid

from backup import BackupHarness


CORE_TABLES = (
    "ref_store_issuer_lanes",
    "ref_store_operations",
    "ref_store_cancellations",
    "ref_store_core_gates",
    "ref_store_core_refs",
    "ref_store_core_events",
)


def uuid_literal(value):
    """Return the canonical text form of a UUID, rejecting anything else."""
    return str(uuid.UUID(str(value)))


def digest_literal(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class BackupRefStoreCore139Harness(BackupHarness):
    """Populate the schema139 core on an unserved repository, then restore it."""

    def metadata_psql(self, sql, db=None, check=True):
        """Run psql with PG* env; pin UTC so timestamptz JSON is comparable."""
        env = self.env.copy()
        parts = urllib.parse.urlsplit(db or self.db)
        env.update(PGHOST=parts.hostname or "", PGPORT=str(parts.port or 5432),
                   PGDATABASE=parts.path.lstrip("/"), PGUSER=parts.username or "",
                   PGPASSWORD=parts.password or "", PGTZ="UTC")
        options = env.get("PGOPTIONS", "").strip()
        env["PGOPTIONS"] = (options + " -c timezone=UTC").strip()
        return self.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql],
                        env=env, check=check)

    def seed_core_fixture(self):
        super().setup()
        tenant = uuid_literal(self.query(self.db, "SELECT id FROM users WHERE username='alice'"))
        repo = uuid_literal(uuid.uuid4())
        name = "core-backup-" + uuid.uuid4().hex[:12]
        gate_incarnation = uuid_literal(uuid.uuid4())
        issuer = uuid_literal(uuid.uuid4())
        committed_op = uuid_literal(uuid.uuid4())
        cancelled_op = uuid_literal(uuid.uuid4())
        event_id = uuid_literal(uuid.uuid4())
        lane = "offline-backup-drill"
        oid = hashlib.sha1(b"rootyard-refstore-core139-backup").hexdigest()
        committed_digest = digest_literal("committed refs/heads/main")
        cancelled_digest = digest_literal("cancelled before registration")
        # Exact CommitTerminal shape persisted by src/ref_store/core/terminal.rs.
        committed_terminal = {
            "kind": "committed",
            "repository_id": repo,
            "revision": 2,
            "head_ref": "refs/heads/main",
            "refs": [{
                "outcome": "applied",
                "name": "refs/heads/main",
                "old_oid": None,
                "new_oid": oid,
            }],
            "rejection": None,
        }
        # Exact cancellation terminal shape persisted by src/ref_store/pg.rs.
        cancelled_terminal = {"state": "cancelled", "reason": "cancel_requested"}
        created = "2025-01-02 03:04:05.123456+00"
        terminal = "2025-01-02 03:04:06.654321+00"
        sql = "\n".join([
            "BEGIN;",
            "INSERT INTO public.repositories(id,owner_id,name,state,storage_backend,"
            "storage_generation,next_retry_at,provision_attempts,created_at,object_format) "
            "VALUES ('" + repo + "','" + tenant + "','" + name + "','provisioning','gitfs',1,"
            "clock_timestamp()+interval '100 years',0,'" + created + "','sha1');",
            "INSERT INTO public.ref_store_issuer_lanes(repository_id,issuer_id,lane,"
            "last_reserved_sequence,created_at,updated_at) VALUES ('" + repo + "','" + issuer +
            "','" + lane + "',2,'" + created + "','" + created + "');",
            "INSERT INTO public.ref_store_operations(repository_id,issuer_id,lane,sequence,"
            "operation_id,request_digest,state,terminal_result,created_at,terminal_at) VALUES "
            "('" + repo + "','" + issuer + "','" + lane + "',1,'" + committed_op + "','" +
            committed_digest + "','committed','" + json.dumps(committed_terminal) + "','" +
            created + "','" + terminal + "'),"
            "('" + repo + "','" + issuer + "','" + lane + "',2,'" + cancelled_op + "','" +
            cancelled_digest + "','cancelled','" + json.dumps(cancelled_terminal) + "','" +
            created + "','" + terminal + "');",
            "INSERT INTO public.ref_store_cancellations(repository_id,issuer_id,lane,sequence,"
            "operation_id,request_digest,created_at) VALUES ('" + repo + "','" + issuer + "','" +
            lane + "',2,'" + cancelled_op + "','" + cancelled_digest + "','" + terminal + "');",
            "INSERT INTO public.ref_store_core_gates(repository_id,tenant_id,object_format,"
            "history_incarnation,authority_epoch,group_epoch,head_ref,revision,created_at,updated_at) "
            "VALUES ('" + repo + "','" + tenant + "','sha1','" + gate_incarnation + "',7,11,"
            "'refs/heads/main',2,'" + created + "','" + terminal + "');",
            "INSERT INTO public.ref_store_core_refs(repository_id,ref_name,oid,revision,updated_at) "
            "VALUES ('" + repo + "','refs/heads/main','" + oid + "',2,'" + terminal + "');",
            "INSERT INTO public.ref_store_core_events(event_id,repository_id,revision,operation_id,"
            "outcome,payload,created_at) VALUES ('" + event_id + "','" + repo + "',2,'" +
            committed_op + "','committed','" + json.dumps(committed_terminal) + "','" + terminal + "');",
            "COMMIT;",
        ])
        self.query(self.db, sql)
        self.core_repo = {
            "id": repo,
            "name": name,
            "tenant_id": tenant,
            "issuer_id": issuer,
            "lane": lane,
            "committed_operation_id": committed_op,
            "cancelled_operation_id": cancelled_op,
            "event_id": event_id,
            "oid": oid,
            "committed_digest": committed_digest,
            "cancelled_digest": cancelled_digest,
        }
        # The bootstrap contract requires an empty unserved GitFS repository:
        # no native bare directory, no Pando authority and no legacy projection.
        assert not (Path(self.env["ROOTYARD_DATA_DIR"]) / "repos" / (repo + ".git")).exists()
        assert self.query(self.db, "SELECT count(*) FROM pando_repository_states WHERE repository_id='" + repo + "'") == "0"
        assert self.query(self.db, "SELECT count(*) FROM repository_ref_projection WHERE repository_id='" + repo + "'") == "0"
        # The inherited setup performs real pushes, so the six registry tables
        # may already contain unrelated real rows.  Count only this fixture's
        # repository, and keep the separate global row capture below for the
        # full-preservation restore comparison.
        expected_counts = {
            "ref_store_issuer_lanes": 1,
            "ref_store_operations": 2,
            "ref_store_cancellations": 1,
            "ref_store_core_gates": 1,
            "ref_store_core_refs": 1,
            "ref_store_core_events": 1,
        }
        self.core_expected_counts = expected_counts
        self.source_fixture_rows = {}
        for table, count in expected_counts.items():
            rows = self.core_fixture_rows(table)
            scoped = int(self.sql(
                "SELECT count(*) FROM public." + table + " WHERE repository_id='" + repo + "'"))
            assert len(rows) == scoped == count, table + " fixture is not populated exactly"
            self.source_fixture_rows[table] = rows
        self.source_core_rows = self.core_rows()
        self.source_core_repo = self.core_repository_row()
        # The fixture must be internally coherent with the real persisted
        # receipt relationships, not just satisfy column checks.
        committed = next(row for row in self.source_fixture_rows["ref_store_operations"]
                         if row["operation_id"] == committed_op)
        cancelled = next(row for row in self.source_fixture_rows["ref_store_operations"]
                         if row["operation_id"] == cancelled_op)
        cancellation = self.source_fixture_rows["ref_store_cancellations"][0]
        event = self.source_fixture_rows["ref_store_core_events"][0]
        gate = self.source_fixture_rows["ref_store_core_gates"][0]
        assert committed["state"] == "committed" and committed["terminal_at"] is not None
        assert committed["terminal_result"] == committed_terminal
        assert committed["request_digest"] == committed_digest
        assert cancelled["state"] == "cancelled" and cancelled["terminal_at"] is not None
        assert cancelled["terminal_result"] == cancelled_terminal
        assert cancelled["request_digest"] == cancellation["request_digest"] == cancelled_digest
        assert cancellation["operation_id"] == cancelled_op
        assert event["operation_id"] == committed_op and event["outcome"] == "committed"
        assert event["payload"] == committed["terminal_result"]
        assert event["revision"] == committed["terminal_result"]["revision"] == gate["revision"] == 2
        assert gate["head_ref"] == committed["terminal_result"]["head_ref"] == "refs/heads/main"
        assert self.source_fixture_rows["ref_store_core_refs"][0]["oid"] == oid
        assert self.source_fixture_rows["ref_store_issuer_lanes"][0]["last_reserved_sequence"] == 2
        assert self.source_core_repo["state"] == "provisioning"
        assert self.source_core_repo["storage_backend"] == "gitfs"
        assert self.source_core_repo["transition_state"] == "stable"
        assert self.source_core_repo["object_format"] == "sha1"
        (self.root / "source-refstore-core-rows.json").write_text(
            json.dumps({"repository": self.source_core_repo,
                        "fixture_rows_by_table": self.source_fixture_rows,
                        "tables": self.source_core_rows}, indent=2) + "\n")
        return {
            "fresh_databases": 2,
            "live_server_backup_rejected": True,
            "unknown_and_unfinished_journal": True,
            "direct_sql_core_fixture_repository": repo,
            "core_fixture_is_adapter_or_protocol_acknowledgement": False,
            "populated_fixture_rows_by_table": expected_counts,
        }

    def core_rows(self):
        """Capture all rows in the six registry/core tables globally."""
        rows = {}
        for table in CORE_TABLES:
            value = self.metadata_psql(
                "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text), '[]'::json) "
                "FROM public." + table + " t").stdout.decode().strip()
            rows[table] = json.loads(value)
        return rows

    def core_fixture_rows(self, table):
        """Capture only this fixture repository's rows for its explicit count."""
        assert table in CORE_TABLES
        repo = uuid_literal(self.core_repo["id"])
        value = self.metadata_psql(
            "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text), '[]'::json) "
            "FROM public." + table + " t WHERE t.repository_id='" + repo + "'").stdout.decode().strip()
        return json.loads(value)

    def core_repository_row(self):
        return json.loads(self.metadata_psql(
            "SELECT to_jsonb(r) FROM public.repositories r WHERE id='" +
            uuid_literal(self.core_repo["id"]) + "'").stdout.decode().strip())

    def reject_sql(self, sql, message):
        process = self.metadata_psql(sql, check=False)
        assert process.returncode != 0, "metadata mutation unexpectedly succeeded"
        stderr = self.redact(process.stderr.decode())
        assert message in stderr, stderr[-2000:]

    def lock_and_snapshot(self):
        result = super().lock_and_snapshot()
        manifest = json.loads((self.backup / "manifest.json").read_text())
        assert manifest["format"] == 15, "drill did not produce a format15 archive"
        assert 138 in manifest["schema_versions"] and 139 in manifest["schema_versions"]
        result.update({"backup_format": manifest["format"],
                       "archive_contains_schema_versions": [138, 139]})
        return result

    def restore_and_clone(self):
        # The inherited case restores into a fresh database/directory, starts
        # the real service, performs an authenticated clone/fsck and proves the
        # post-backup acknowledged commit is absent.  It also sets the target
        # DATABASE_URL/ROOTYARD_DATA_DIR used by the checks below.
        result = super().restore_and_clone()
        restored_rows = self.core_rows()
        restored_repo = self.core_repository_row()
        assert restored_rows == self.source_core_rows, (
            "restored schema139 core rows differ: " + ", ".join(sorted(
                table for table in CORE_TABLES
                if restored_rows.get(table) != self.source_core_rows.get(table))))
        restored_fixture_rows = {table: self.core_fixture_rows(table) for table in CORE_TABLES}
        assert restored_fixture_rows == self.source_fixture_rows
        for table, count in self.core_expected_counts.items():
            assert len(restored_fixture_rows[table]) == count
        assert restored_repo == self.source_core_repo, "restored unserved repository row differs"
        assert self.sql("SELECT count(*) FROM schema_migrations WHERE version IN (138,139)") == "2"
        assert restored_repo["state"] == "provisioning"
        assert restored_repo["storage_backend"] == "gitfs"
        assert restored_repo["transition_state"] == "stable"
        assert restored_repo["provision_attempts"] == 0
        assert not (self.target / "repos" / (restored_repo["id"] + ".git")).exists()
        assert self.sql("SELECT count(*) FROM pando_repository_states WHERE repository_id='" + restored_repo["id"] + "'") == "0"
        assert self.sql("SELECT count(*) FROM repository_ref_projection WHERE repository_id='" + restored_repo["id"] + "'") == "0"
        # Terminal operation/event/cancellation rows are immutable in the
        # restored database.  Each rejected UPDATE must leave every seeded row
        # byte-for-byte (JSON text) identical.
        before = self.core_rows()
        where = "repository_id='" + restored_repo["id"] + "' AND operation_id='"
        self.reject_sql(
            "UPDATE public.ref_store_operations SET terminal_result='{\"forged\":true}'::jsonb WHERE " +
            where + self.core_repo["committed_operation_id"] + "'",
            "ref-store terminal operation result is immutable")
        self.reject_sql(
            "UPDATE public.ref_store_operations SET state='rejected' WHERE " +
            where + self.core_repo["committed_operation_id"] + "'",
            "ref-store terminal operation result is immutable")
        self.reject_sql(
            "UPDATE public.ref_store_operations SET terminal_result='{\"forged\":true}'::jsonb WHERE " +
            where + self.core_repo["cancelled_operation_id"] + "'",
            "ref-store terminal operation result is immutable")
        self.reject_sql(
            "UPDATE public.ref_store_core_events SET outcome='rejected',payload='{\"forged\":true}'::jsonb "
            "WHERE event_id='" + self.core_repo["event_id"] + "'",
            "ref-store core event is immutable")
        self.reject_sql(
            "UPDATE public.ref_store_cancellations SET request_digest='" + "f" * 64 +
            "' WHERE repository_id='" + restored_repo["id"] + "' AND operation_id='" +
            self.core_repo["cancelled_operation_id"] + "'",
            "ref-store cancellation tombstone is immutable")
        assert self.core_rows() == before, "rejected terminal/event updates changed restored rows"
        assert self.core_repository_row() == self.source_core_repo
        (self.root / "restored-refstore-core-rows.json").write_text(
            json.dumps({"repository": restored_repo,
                        "fixture_rows_by_table": restored_fixture_rows,
                        "tables": restored_rows}, indent=2) + "\n")
        result.update({
            "populated_core_rows_restored_exactly": True,
            "gates_refs_events_operations_cancellations_issuer_lanes_nonempty": True,
            "terminal_event_cancellation_updates_refused_without_row_changes": True,
            "core_repository_stays_provisioning_gitfs_unserved": True,
            "core_fixture_direct_sql_not_adapter_acknowledgement": True,
        })
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("dedicated synthetic ROOTYARD_TEST_DATABASE_URL required")
    harness = BackupRefStoreCore139Harness(args)
    success = False
    try:
        for name, function in [
            ("synthetic_source_with_populated_refstore_core", harness.seed_core_fixture),
            ("offline_barriers_and_snapshot", harness.lock_and_snapshot),
            ("unsafe_or_corrupt_inputs", harness.invalid_inputs),
            ("backup_barrier_failures", harness.backup_barrier_failures),
            ("interrupted_restore_guard", harness.interrupted_restore),
            ("post_backup_write_not_in_snapshot", harness.write_after_backup),
            ("new_environment_restore_core_rows_clone_fsck", harness.restore_and_clone),
        ]:
            harness.case(name, function)
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
            binary=args.binary,
            binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            limitations=[
                "RefStore core rows are direct SQL metadata fixtures, not adapter/protocol ACK evidence; Rust ref_store_* tests own that proof.",
                "The unserved provisioning repository is never served or cut over; its core gate/ref rows are not native Git ref authority.",
                "Synthetic loopback drill, no host/disk power-loss or production RPO/RTO promise.",
                "One committed operation/event and one cancelled tombstone/terminal are populated; batches, rejections and concurrency are covered by Rust tests.",
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
