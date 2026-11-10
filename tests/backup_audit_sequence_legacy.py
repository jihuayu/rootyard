#!/usr/bin/env python3
"""#7 recovery drill: audit ID sequence survives backup -> fresh restore.

The fixture is a legacy-style **format 21** source: a real GitFS storage volume
served by the stock server hooks, so the CLI backup can only write a metadata
archive (a served ``pg_refstore`` source is refused as a metadata archive and
would need the format-22 Blob path).  No Blob serving service is started.

Everything the audit assertions observe is produced through the CLI and real
HTTP/Git against run-owned databases, a temporary volume and temporary clones:

1. API collaborator writes create real audit rows ided by the migration-110
   sequence; then a real Git push lands and the stock server settles it by its
   own reconciliation (no ``worker-once``, no hand-written SQL).
2. ``backup --offline`` then ``restore --isolated`` into a brand-new database
   and data directory.
3. On the restored service real HTTP collaborator writes and a Git push audit
   again must allocate IDs strictly above every pre-backup ID, keep every
   pre-backup row unchanged and never rewind or reuse an ID.
4. Negative control in the restored **run-owned** database only: with the
   migration-110 sequence default dropped, the same concurrent audit writes no
   longer all commit with distinct ordering IDs, so the positive assertions
   cannot pass vacuously.  The control then replays migration 110 and removes
   its own rows.  It reproduces the legacy shape locally; it does not restore a
   historical binary, so it is not itself legacy-path native evidence.

Missing dependencies (PostgreSQL 17, Git >= 2.43, CREATEDB, an attested
source-bound binary) are hard failures, never skips.  This is a loopback
functional drill, not power-loss, RPO/RTO, HA or multi-tenant qualification.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_evidence  # noqa: E402
from backup import BackupHarness  # noqa: E402
from schema_baseline import CURRENT_BACKUP_FORMAT, CURRENT_SCHEMA_VERSION  # noqa: E402

CASES = (
    "setup",
    "metadata_only_format_without_blob_service",
    "offline_backup_and_fresh_database_restore",
    "restored_http_audit_sequence_continues",
    "restored_concurrent_audit_sequence_continues",
    "restored_git_push_audit_sequence_continues",
    "legacy_replay_control_loses_sequence",
)
# Concurrent writers of the restored-run positive case and the negative control.
CONTROL_WRITERS = 16
MIN_GIT_VERSION = (2, 43)
MIN_POSTGRES_VERSION = 17
REQUIRED_EXECUTABLES = ("git", "psql", "pg_dump", "pg_restore")
# Exact migration-110 DDL, replayed only in the negative control's restored
# run-owned database to show what the same writes looked like on a legacy shape.
MIGRATION_110 = Path(__file__).resolve().parents[1] / "migrations" / "110_audit_sequence.sql"


def numeric_version(text):
    """Leading ``major.minor`` of a tool banner, or ``None`` when unparseable."""
    match = re.search(r"\b(\d+)\.(\d+)(?![\d])", text or "")
    return (int(match.group(1)), int(match.group(2))) if match else None


def new_audit_ids(before_ids, after_ids, api_ids):
    """IDs the post-restore window added; rejects reuse, rewind or gaps.

    ``before_ids`` is every audit ID captured before the backup, ``after_ids``
    the full set after the post-restore writes and ``api_ids`` the IDs the
    restored HTTP responses returned.  The result is sorted and strictly above
    every pre-backup ID, and the added set is exactly the responses, so a
    duplicate, reused or rewound ID or a silently added row fails.
    """
    before, after, api = set(before_ids), set(after_ids), list(api_ids)
    assert all(isinstance(value, int) and not isinstance(value, bool)
               for value in before | after | set(api)), "audit IDs must be integers"
    assert before, "the source must own audit rows before the backup"
    assert api and len(api) == len(set(api)), "API responses must be distinct audit IDs"
    if not after >= before:
        raise AssertionError("audit rows disappeared across backup/restore: "
                             + repr(sorted(before - after)[:10]))
    added = after - before
    if added != set(api):
        raise AssertionError("audit rows added after restore " + repr(sorted(added)[:10])
                             + " differ from API-returned IDs " + repr(sorted(api)[:10]))
    low = min(added)
    if low <= max(before):
        raise AssertionError("audit sequence rewound: new ID " + repr(low)
                             + " is not above pre-backup maximum " + repr(max(before)))
    return sorted(added)


def settled_outcomes(rows):
    """Operation outcomes of one repository once its journal is fully settled."""
    outcomes = [str(row) for row in rows]
    return outcomes if outcomes and "unknown" not in outcomes else None


class AuditSequenceLegacyHarness(BackupHarness):
    """BackupHarness supplies the random source/restore databases and volumes."""

    def __init__(self, args):
        super().__init__(args)
        # serve (GitFS) only: the CLI must write a metadata archive, never pair it
        # with a Blob closure, and this drill refuses any other format.
        for key in ("ROOTYARD_BLOB_ROOT", "ROOTYARD_SERVE_BLOB", "ROOTYARD_OBJECT_STORE_BUCKET"):
            self.env.pop(key, None)
        self.audit_path = "/api/repos/alice/demo/audit"
        self.rules_path = "/api/repos/alice/demo/branch-rules"
        self.authors_path = "/api/repos/alice/demo/collaborators"

    def document(self, path, code=200, token=None, **kwargs):
        """JSON mutation/read with the no-store contract; never logs argv or creds."""
        status, body, headers = self.http(path, token=token or self.alice, **kwargs)
        assert status == code, self.redact(f"{path}: expected {code}, got {status}: {body[:300]!r}")
        assert headers.get("cache-control") == "no-store", headers
        assert "application/json" in headers.get("content-type", ""), headers
        return json.loads(body)

    def all_audit_ids(self, db):
        return [int(value) for value in
                self.query(db, "SELECT id FROM repository_audit_log ORDER BY id").splitlines()]

    def audit_rows(self, db, repo):
        """Every captured audit row of one repository as ordered JSON objects."""
        return json.loads(self.query(db, (
            "SELECT COALESCE(json_agg(json_build_object("
            "'id',id,'actor_name',actor_name,'action',action,'target_type',target_type,"
            "'target_name',target_name,'details',details,'created_unix',created_unix) ORDER BY id),'[]')"
            "  FROM repository_audit_log WHERE repository_id='" + repo + "'")))

    def wait_settled(self, db, label):
        """Wait until the stock server has settled every push journal itself.

        No worker command, no SQL settlement: the restored service reconciles
        its own journal on the normal request path.  A still-``unknown`` outcome
        is a failure, not a reason to keep waiting.
        """
        deadline = time.monotonic() + 30
        while True:
            raw = self.query(db, "SELECT outcome FROM git_operations WHERE repository_id='"
                             + self.repo["id"] + "' ORDER BY sequence")
            outcomes = settled_outcomes(raw.splitlines() if raw else [])
            if outcomes:
                return outcomes
            assert time.monotonic() < deadline, label + " was not settled within 30s: " + repr(raw)
            time.sleep(0.05)

    def create_collaborators(self, names):
        created = []
        for name in names:
            self.document(self.authors_path, (200, 201), method="POST",
                          body={"username": name, "role": "triage"})
            created.append(self.last_audit_id())
        return created

    def audit_writer(self, db):
        """Evidence that audit IDs come from the owned migration-110 sequence."""
        row = self.query(db, (
            "SELECT column_default || '|' || COALESCE((SELECT c.relkind::text FROM pg_class c "
            "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() "
            "AND c.relname='repository_audit_log_id_seq'),'missing') || '|' || "
            "COALESCE((SELECT a.attidentity::text FROM pg_attribute a WHERE a.attrelid="
            "'repository_audit_log'::regclass AND a.attname='id'),'missing') "
            "FROM information_schema.columns WHERE table_schema=current_schema() "
            "AND table_name='repository_audit_log' AND column_name='id'"))
        default, sequence_kind, identity = row.split("|")
        assert default == "nextval('repository_audit_log_id_seq'::regclass)", row
        assert sequence_kind == "S", "owned audit sequence is missing: " + row
        assert identity in ("", "missing"), "audit id must not be a legacy identity column"
        return {"default": default, "sequence_relkind": sequence_kind}

    def last_audit_id(self):
        """Newest audit ID as served by the real cursor API (descending order)."""
        status, body, _ = self.http(self.audit_path + "?limit=1", token=self.alice)
        assert status == 200, body[:300]
        return int(json.loads(body)["items"][0]["id"])

    def branch_rule_audit_ids(self, count):
        """IDs of the newest ``count`` audit rows, all ``branch_rule.upserted``."""
        page = self.document(self.audit_path + "?limit=" + str(count), token=self.alice)
        items = page["items"]
        assert len(items) == count, (count, len(items))
        assert {item["action"] for item in items} == {"branch_rule.upserted"}, items[:3]
        ids = [int(item["id"]) for item in items]
        assert ids == sorted(ids, reverse=True), "audit page is not newest-first"
        return ids

    def setup(self):
        # The inherited setup performs the real push/clone round trip of demo.
        super().setup()
        self.sequence = self.audit_writer(self.db)
        sources = self.create_collaborators(["carol", "dave"])
        self.source_api_ids = sources
        self.pre_push_ids = self.all_audit_ids(self.db)
        self.pre_push_rows = self.audit_rows(self.db, self.repo["id"])
        assert len(self.pre_push_rows) >= 2, self.pre_push_rows
        note = self.work / "audit-sequence-drill.txt"
        note.write_text("settled by the stock server reconciliation\n")
        self.git("add", note.name, cwd=self.work)
        self.git("commit", "-m", "audit sequence drill push", cwd=self.work)
        self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
        self.pushed_oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        outcomes = self.wait_settled(self.db, "source push")
        observed = self.git("--git-dir=" + str(self.bare), "rev-parse",
                            "refs/heads/main").stdout.decode().strip()
        assert observed == self.pushed_oid, (observed, self.pushed_oid)
        self.post_push_ids = self.all_audit_ids(self.db)
        self.post_push_rows = self.audit_rows(self.db, self.repo["id"])
        kept = {row["id"]: row for row in self.post_push_rows}
        assert [kept[row["id"]] for row in self.pre_push_rows] == self.pre_push_rows, \
            "pre-push audit rows changed while the push settled"
        self.sequence_before_backup = self.query(
            self.db, "SELECT last_value || '/' || is_called FROM repository_audit_log_id_seq")
        return {"audit_sequence": self.sequence,
                "source_api_audit_ids": self.source_api_ids,
                "git_operation_outcomes": outcomes,
                "push_oid": self.pushed_oid}

    def metadata_only_format_without_blob_service(self):
        self.stop()
        result = json.loads(self.backup_command().stdout)
        manifest = json.loads((self.backup / "manifest.json").read_text())
        assert manifest["format"] == CURRENT_BACKUP_FORMAT == 21, manifest["format"]
        assert manifest["schema_versions"][-1] == CURRENT_SCHEMA_VERSION
        assert manifest.get("blob_closure") is None and not manifest.get("blob_artifacts"), \
            "a paired Blob archive would bypass the legacy audit path"
        for forbidden in ("blob", "volume/blobs"):
            assert not (self.backup / forbidden).exists(), forbidden
        self.cli("backup-verify", str(self.backup))
        self.backup_result = result
        return {"backup_format": manifest["format"], "schema_version": manifest["schema_versions"][-1],
                "continuity": manifest["consistency"], "blob_closure": None}

    def offline_backup_and_fresh_database_restore(self):
        result = json.loads(self.restore_command().stdout)
        assert result["restored"] is True, result
        versions = "SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations"
        for db in (self.source_db, self.target_db):
            assert self.query(db, versions), "migrations missing in " + db
        assert self.query(self.source_db, versions) == self.query(self.target_db, versions)
        # The restored database owns the same sequence state; capture it before
        # any post-restore write so the rewind check uses restored facts only.
        self.restored_sequence_start = self.query(
            self.target_db, "SELECT last_value || '/' || is_called FROM repository_audit_log_id_seq")
        assert self.restored_sequence_start == self.sequence_before_backup, \
            (self.restored_sequence_start, self.sequence_before_backup)
        assert self.audit_writer(self.target_db) == self.sequence
        self.env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        self.db = self.target_db
        self.start()
        self.restored_rows = self.audit_rows(self.target_db, self.repo["id"])
        assert self.restored_rows == self.post_push_rows, "restored audit rows differ from the source"
        assert self.git("ls-remote", self.remote, "main", token=self.alice).stdout.decode().strip() \
            == self.pushed_oid + "\trefs/heads/main", "restored main ref differs from the pushed OID"
        return {"fresh_database": self.source_db != self.target_db,
                "restored_sequence_equals_source": True,
                "restore_seconds": result["elapsed_seconds"]}

    def restored_http_audit_sequence_continues(self):
        before = self.restored_rows
        floor = max(row["id"] for row in before)
        updated = self.document(self.authors_path, 200, method="POST",
                                body={"username": "bob", "role": "maintain", "expected_version": 1})
        assert updated["role"] == "maintain", updated
        after = self.audit_rows(self.target_db, self.repo["id"])
        # locate the new row through the real ascending cursor API from the
        # newest pre-backup ID; its position is what the sequence must extend.
        stanza = self.document(self.audit_path + "?after=" + str(floor) + "&limit=1", token=self.alice)
        assert len(stanza["items"]) == 1 and stanza["next_after"] is None, stanza
        returned = [int(stanza["items"][0]["id"])]
        assert stanza["items"][0]["action"] == "collaborator.updated", stanza
        new = new_audit_ids([row["id"] for row in before], [row["id"] for row in after], returned)
        kept = {row["id"]: row for row in after}
        assert [kept[row["id"]] for row in before] == before, "pre-backup audit rows changed after restore"
        assert new[0] > floor
        rows = [row for row in after if row["id"] in set(new)]
        assert [row["action"] for row in rows] == ["collaborator.updated"], rows
        self.http_audit_floor = new[-1]
        self.restored_after_http = after
        return {"returned_audit_ids": returned, "pre_backup_max_id": floor,
                "restored_rows_preserved": len(before)}

    def restored_concurrent_audit_sequence_continues(self):
        floor = self.http_audit_floor
        def write(index):
            return self.http(self.rules_path, token=self.alice, method="POST",
                             body={"branch_ref": f"refs/heads/restored-race-{index}"})[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONTROL_WRITERS) as executor:
            statuses = list(executor.map(write, range(2 * CONTROL_WRITERS)))
        assert statuses == [201] * (2 * CONTROL_WRITERS), statuses
        ids = self.branch_rule_audit_ids(2 * CONTROL_WRITERS)
        assert min(ids) > floor, (min(ids), floor)
        after = self.audit_rows(self.target_db, self.repo["id"])
        new = new_audit_ids([row["id"] for row in self.restored_after_http],
                            [row["id"] for row in after], ids)
        assert len(new) == 2 * CONTROL_WRITERS
        self.restored_after_race = after
        self.race_floor = max(new)
        return {"concurrent_writes": 2 * CONTROL_WRITERS, "first_new_audit_id": new[0],
                "statuses": sorted(set(statuses))}

    def restored_git_push_audit_sequence_continues(self):
        before = self.restored_after_race
        branch = self.root / "restored-push"
        self.git("clone", "--single-branch", "--branch", "main", self.remote, str(branch), token=self.alice)
        self.git("config", "user.name", "E2E", cwd=branch)
        self.git("config", "user.email", "e2e@example.invalid", cwd=branch)
        assert self.git("rev-parse", "HEAD", cwd=branch).stdout.decode().strip() == self.pushed_oid
        (branch / "after-restore.txt").write_text("pushed into the restored service\n")
        self.git("add", "after-restore.txt", cwd=branch)
        self.git("commit", "-m", "push after restore", cwd=branch)
        oid = self.git("rev-parse", "HEAD", cwd=branch).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=branch, token=self.alice)
        outcomes = self.wait_settled(self.target_db, "restored push")
        assert self.git("ls-remote", self.remote, "main", token=self.alice).stdout.decode().strip() \
            == oid + "\trefs/heads/main"
        checkout = self.root / "restored-push-check"
        self.git("clone", self.remote, str(checkout), token=self.reader)
        self.git("fsck", "--full", "--strict", cwd=checkout)
        assert (checkout / "after-restore.txt").read_text() == "pushed into the restored service\n"
        after = self.audit_rows(self.target_db, self.repo["id"])
        returned = self.branch_rule_audit_ids(1)
        ids = new_audit_ids([row["id"] for row in before], [row["id"] for row in after], returned)
        kept = {row["id"]: row for row in after}
        assert [kept[row["id"]] for row in before] == before, "restored audit rows changed during the push"
        assert ids[0] > self.race_floor
        assert ids[0] > max(row["id"] for row in before)
        return {"pushed_oid": oid, "git_operation_outcomes": outcomes,
                "first_new_audit_id": ids[0], "restored_refs_and_fsck": True}

    def audit_sequence_column(self):
        """(id default, id identity kind) of the audit table in the run database."""
        row = self.query(self.target_db, (
            "SELECT COALESCE(column_default,'') || '|' || COALESCE(attidentity::text,'') "
            "|| '|' || COALESCE((SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n "
            "ON n.oid=c.relnamespace WHERE n.nspname=current_schema() "
            "AND c.relname='repository_audit_log_id_seq'),'missing') "
            "FROM information_schema.columns, pg_attribute WHERE table_schema=current_schema() "
            "AND table_name='repository_audit_log' AND column_name='id' "
            "AND attrelid='repository_audit_log'::regclass AND attname='id'"))
        return tuple(row.split("|"))

    def legacy_replay_control_loses_sequence(self):
        """The same writes without the migration-110 sequence MUST lose ordering.

        Only the restored run-owned database is altered, and only temporarily.
        With the sequence default dropped the table is back to the legacy shape
        (no server-side ID allocation): the same concurrent audit writes no
        longer all commit, which proves the positive cases above assert a
        property the sequence provides.  Finally the exact migration-110 DDL is
        replayed, every control row is deleted and the pre-control rows are
        shown unchanged.  This is a local reproduction of the legacy shape, not
        a replay of a historical producer or its binary.
        """
        before = self.restored_rows_before_control()
        default, identity, kind = self.audit_sequence_column()
        assert default == "nextval('repository_audit_log_id_seq'::regclass)" and kind == "S", (default, kind)
        self.query(self.target_db, "ALTER TABLE repository_audit_log ALTER COLUMN id DROP DEFAULT")
        statuses = []
        try:
            assert self.audit_sequence_column()[0] == "", "control could not remove the sequence default"
            def legacy_write(index):
                target = f"refs/heads/legacy-control-{index}"
                status, _, _ = self.http(self.rules_path, token=self.alice, method="POST",
                                         body={"branch_ref": target})
                return status
            with concurrent.futures.ThreadPoolExecutor(max_workers=CONTROL_WRITERS) as executor:
                statuses = list(executor.map(legacy_write, range(2 * CONTROL_WRITERS)))
            # The control must demonstrate lost ordering (non-2xx writes), never be
            # tolerated as a vacuous pass.
            assert statuses and any(status != 201 for status in statuses), (
                "the legacy shape accepted " + str(2 * CONTROL_WRITERS) + " concurrent audit writes; "
                "the positive assertions would be vacuous: " + repr(sorted(set(statuses))))
        finally:
            self.query(self.target_db, "CREATE SEQUENCE IF NOT EXISTS repository_audit_log_id_seq AS bigint")
            self.query(self.target_db, MIGRATION_110.read_text())
            self.query(self.target_db, "DELETE FROM repository_audit_log WHERE action='branch_rule.upserted' "
                       "AND target_name LIKE 'refs/heads/legacy-control-%'")
        default, identity, kind = self.audit_sequence_column()
        assert default == "nextval('repository_audit_log_id_seq'::regclass)" and kind == "S", (default, kind)
        after = self.audit_rows(self.target_db, self.repo["id"])
        kept = {row["id"]: row for row in after}
        assert [kept[row["id"]] for row in before] == before, \
            "the control changed audit rows that the positive cases attribute to the sequence"
        remaining = [row for row in after if str(row["target_name"]).startswith("refs/heads/legacy-control-")]
        assert not remaining, "control rows were not removed: " + repr(remaining[:3])
        return {"legacy_shape_writes": 2 * CONTROL_WRITERS,
                "legacy_shape_failures": sorted({status for status in statuses if status != 201}),
                "restored_rows_unchanged": len(before)}


def preflight(args, environ=None):
    """Missing or wrong dependencies fail loudly; nothing is skipped."""
    missing = [exe for exe in REQUIRED_EXECUTABLES if not shutil.which(exe)]
    if not Path(args.binary).is_file():
        missing.append("binary " + args.binary)
    environ = os.environ if environ is None else environ
    if not environ.get("ROOTYARD_TEST_DATABASE_URL"):
        missing.append("ROOTYARD_TEST_DATABASE_URL")
    if missing:
        raise SystemExit("required dependencies missing (no skip): " + ", ".join(missing))
    git_version = numeric_version(subprocess_version(["git", "--version"]))
    if git_version is None or git_version < MIN_GIT_VERSION:
        raise SystemExit("Git >= 2.43 is required, found " + repr(git_version))
    pg_version = numeric_version(subprocess_version(["psql", "--version"]))
    if pg_version is None or pg_version[0] < MIN_POSTGRES_VERSION:
        raise SystemExit("PostgreSQL 17 client tools are required, found " + repr(pg_version))
    server = subprocess_version(["psql", environ["ROOTYARD_TEST_DATABASE_URL"], "-XAtc", "SHOW server_version_num"])
    if not server.isdigit() or int(server) // 10000 < MIN_POSTGRES_VERSION:
        raise SystemExit("a PostgreSQL 17 server is required, found " + repr(server))
    record = native_evidence.build_record(args.binary)
    if record.get("attested") is not True:
        raise SystemExit("the binary is not source-bound (no matching build receipt): "
                         + str(record.get("reason")))
    return {"git_version": ".".join(map(str, git_version)), "postgres_server_version_num": int(server)}


def subprocess_version(argv):
    try:
        completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    except OSError:
        return ""
    return completed.stdout.decode(errors="replace").strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    runtime = preflight(args)
    harness = AuditSequenceLegacyHarness(args)
    success = False
    try:
        for name in CASES:
            harness.case(name, getattr(harness, name))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            print(harness.redact(error), file=sys.stderr)
            success = False
        report = dict(passed=success, cases=harness.results, runtime=runtime,
                      binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      limitations=[
                          "Format21 metadata archive of a stock GitFS source; no Blob closure is read or written.",
                          "The HTTP/Git write->push->settle->backup->restore path is required; no SQL seeds "
                          "a positive row.",
                          "The control reproduces the legacy shape locally in the restored run-owned database "
                          "only; it is not historical-legacy-path native evidence.",
                          "Loopback functional drill only: no power-loss, RPO/RTO, HA or multi-tenant promise."])
        if args.keep:
            report["retained_directory"] = str(harness.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
