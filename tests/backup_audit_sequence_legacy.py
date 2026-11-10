#!/usr/bin/env python3
"""#7 recovery drill: the audit ID sequence survives backup -> fresh restore.

The fixture is a **format 21** source: a real GitFS volume served by the stock
candidate binary's hooks, so a CLI backup can only write the metadata archive
(a served ``pg_refstore`` source is refused as metadata and would need format
22).  No Blob serving service is started.  The archive format matches a legacy
producer, but the producer here is the current source-bound binary: this is not
a replay of a historical legacy binary.

What the audit assertions observe is produced only through the CLI and real
HTTP/Git against run-owned databases, a temporary volume and temporary clones:

1. Real Git pushes (demo and a planned repository) are settled by the stock
   server itself and kept as the Git/receipt recovery check.  Real API
   collaborator writes then create ``repository_audit_log`` rows whose ids come
   from the migration-110 sequence (``record_audit_event``).  The drill proves
   the pushes write ``git_operations``/``audit_events`` and *not*
   ``repository_audit_log``.  A REST ``POST .../issues`` is a real issue write
   (it proves Bob's triage grant) but the REST handler records no audit row:
   only the web form handler emits ``issue.created``, so the drill never counts
   a REST issue as an audit write.
2. ``backup --offline`` then ``restore --isolated`` into a brand-new database
   and data directory.
3. On the restored service the next real API audit writes (one, then 32
   concurrent) must allocate ids strictly above every pre-backup id, found
   through the ascending ``?after=<floor>`` cursor -- never the oldest page --
   and every pre-backup row (all columns, ``created_at`` included) must survive
   byte-identically.  The cursor walks are cross-checked against the SQL id
   sets, because each repository's cursor only sees its own rows.
4. Negative control, in the restored run-owned database only: dropping the
   migration-110 sequence default (the schema shape a pre-110 source has) makes
   audit writes fail with no server-side ID allocation.  It is labelled as a
   *missing-default* control; it does not reproduce the historical ``MAX(id)+1``
   algorithm or its race.  After that point the database no longer satisfies
   the service contract, so the run is resumed with a non-isolated
   ``restore`` of the same archive, which re-imports it and re-applies
   migration 110.

Missing dependencies (PostgreSQL 17 server with CREATEDB, Git >= 2.43, and a binary
bound to this checkout's production source bytes) are hard failures, never
skips.  A loopback functional drill only: no power-loss, RPO/RTO or HA claim.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ops_provenance  # noqa: E402
import source_bound_binary  # noqa: E402
from backup import BackupHarness  # noqa: E402
from schema_baseline import CURRENT_BACKUP_FORMAT, CURRENT_SCHEMA_VERSION  # noqa: E402

CASES = (
    "setup",
    "setup_repos",
    "source_audit_writes_advance_sequence",
    "metadata_only_format_without_blob_service",
    "offline_backup_and_fresh_database_restore",
    "restored_http_audit_sequence_continues",
    "restored_concurrent_audit_sequence_continues",
    "restored_git_push_and_audit_events_recovery",
    "missing_default_control_has_no_sequence",
)
CONCURRENT_WRITERS = 16
MIN_GIT_VERSION = (2, 43)
MIN_POSTGRES_VERSION = 17
REQUIRED_EXECUTABLES = ("git", "psql", "pg_dump", "pg_restore")
# Exact migration-110 DDL, replayed only in the control's restored run-owned
# database to return it to the reviewed schema after the negative control.
MIGRATION_110 = Path(__file__).resolve().parents[1] / "migrations" / "110_audit_sequence.sql"
# Every persisted repository_audit_log column (migrations/050_members_rbac.sql);
# the restore comparison must see a changed tenant, repository or actor.
AUDIT_COLUMNS = "id,tenant_id,repository_id,actor_id,actor_name,action,target_type,target_name,"
AUDIT_COLUMNS += "details,created_unix,created_at"


def numeric_version(text):
    """Leading ``major.minor`` of a tool banner, or ``None`` when unparseable."""
    match = re.search(r"\b(\d+)\.(\d+)(?![\d])", text or "")
    return (int(match.group(1)), int(match.group(2))) if match else None


def new_audit_ids(before_ids, after_ids, api_ids, expected=None):
    """IDs the post-restore window added; rejects reuse, rewind or gaps.

    ``before_ids`` is every audit ID captured before the backup, ``after_ids``
    the full set afterwards and ``api_ids`` the IDs the ``?after=`` cursor
    walk returned.  The added set is strictly above every pre-backup ID and is
    exactly the walked set, so a duplicate, reused, rewound or unobserved ID
    fails.
    """
    before, after, api = set(before_ids), set(after_ids), list(api_ids)
    assert all(isinstance(value, int) and not isinstance(value, bool)
               for value in before | after | set(api)), "audit IDs must be integers"
    assert before, "the source must own audit rows before the backup"
    assert api and len(api) == len(set(api)), "walked audit IDs must be distinct"
    if not after >= before:
        raise AssertionError("audit rows disappeared across backup/restore: "
                             + repr(sorted(before - after)[:10]))
    added = after - before
    if added != set(api):
        raise AssertionError("audit rows added after restore " + repr(sorted(added)[:10])
                             + " differ from the IDs walked after the pre-backup maximum "
                             + repr(sorted(api)[:10]))
    if expected is not None and len(added) != expected:
        raise AssertionError(repr(len(added)) + " new audit rows, expected "
                             + repr(expected))
    low = min(added)
    if low <= max(before):
        raise AssertionError("audit sequence rewound: new ID " + repr(low)
                             + " is not above pre-backup maximum " + repr(max(before)))
    return sorted(added)


def _keyed_audit_rows(rows):
    keys = [row["id"] for row in rows]
    assert len(keys) == len(set(keys)), "duplicate audit id in " + repr(keys[:10])
    return {row["id"]: row for row in rows}


def _compare_audit_rows(expected, actual):
    """Every expected id present and equal in ``actual``, as the full row."""
    changed = [key for key in sorted(expected) if expected[key] != actual[key]]
    if changed:
        key = changed[0]
        fields = sorted(name for name in set(expected[key]) | set(actual[key])
                        if expected[key].get(name) != actual[key].get(name))
        raise AssertionError("audit row " + repr(key) + " changed " + repr(fields)
                             + ": " + repr(expected[key]) + " -> " + repr(actual[key]))


def audit_rows_by_id(before, after):
    """Reject a restore that lost, added or changed any full audit row.

    Every row is keyed by its id and compared as the complete persisted row
    (tenant, repository, actor id/name, action, target, details, timestamps),
    so a row copied under another actor or tenant, a rewritten detail or a
    shifted ``created_at`` fails even when the id set is unchanged.  Both sides
    must be the same set: use this only where no write may have happened.
    """
    expected, actual = _keyed_audit_rows(before), _keyed_audit_rows(after)
    lost = sorted(set(expected) - set(actual))
    added = sorted(set(actual) - set(expected))
    assert not lost, "audit rows disappeared: " + repr(lost[:10])
    assert not added, "audit rows appeared: " + repr(added[:10])
    _compare_audit_rows(expected, actual)
    return actual


def audit_subrows_by_id(rows, after):
    """Compare only rows whose id already exists in ``rows``; return added ids.

    A legal post-restore write adds id-only rows, so a full-set comparison
    would fail for the wrong reason.  This checks every original id is still
    present, byte-identical in all persisted columns, and returns the added ids
    so the caller can bind them to the exact walked window.
    """
    expected, actual = _keyed_audit_rows(rows), _keyed_audit_rows(after)
    lost = sorted(set(expected) - set(actual))
    assert not lost, "audit rows disappeared: " + repr(lost[:10])
    _compare_audit_rows(expected, actual)
    return sorted(set(actual) - set(expected))


def settled_outcomes(rows):
    """Operation outcomes once every journal is settled; ``unknown`` is never a pass."""
    outcomes = [str(row) for row in rows]
    return outcomes if outcomes and "unknown" not in outcomes else None


class AuditSequenceLegacyHarness(BackupHarness):
    """BackupHarness supplies the random source/restore databases and volumes."""

    def __init__(self, args):
        super().__init__(args)
        # serve (GitFS) only: the CLI must write a metadata archive and this
        # drill refuses anything that carries a Blob closure.
        for key in ("ROOTYARD_SERVE_BLOB", "ROOTYARD_BLOB_ROOT"):
            self.env.pop(key, None)
        # The restore provisions its own fresh database like the source does.
        # Without the key the CLI would inherit the source database as the
        # restore server, and a CREATE after the restore would run on the
        # positive-state source rather than an empty test server.
        self.env["ROOTYARD_RESTORE_TEST_DATABASE_URL"] = self.restore_admin
        # The hook runner is the binary already executed (the re-executed copy
        # bootstraps before Config), so a later rebuild must not be mistaken for
        # this run's binary: the runner digest is recorded for the report.
        self.hook_runner = None
        self.rules_path = "/api/repos/alice/demo/branch-rules"
        self.authors_path = "/api/repos/alice/demo/collaborators"

    def hook_runner_digest(self):
        runner = Path(self.env["ROOTYARD_DATA_DIR"]) / "managed-hooks" / ".runner"
        if not runner.is_file():
            return None
        return hashlib.sha256(runner.read_bytes()).hexdigest()

    def query(self, db, sql):
        """Run SQL with an explicit host/port.

        The runner may have no local account for its uid (``--user``), and
        libpq then falls back to a unix socket that does not exist; the
        URL's host and port select the same server explicitly.
        """
        parts = urllib.parse.urlsplit(db)
        env = self.env.copy()
        env.update(PGHOST=parts.hostname or "", PGPORT=str(parts.port or 5432),
                   PGDATABASE=parts.path.lstrip("/"), PGUSER=parts.username or "",
                   PGPASSWORD=parts.password or "")
        return self.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql],
                        env=env).stdout.decode().strip()

    def repo_path(self, suffix="", repo="demo"):
        return "/api/repos/alice/" + repo + suffix

    def document(self, path, code=200, token=None, **kwargs):
        """JSON request with the no-store contract; argv and credentials stay out."""
        status, body, headers = self.http(path, token=token or self.alice, **kwargs)
        assert status == code, self.redact(f"{path}: expected {code}, got {status}: {body[:300]!r}")
        assert headers.get("cache-control") == "no-store", headers
        assert "application/json" in headers.get("content-type", ""), headers
        return json.loads(body)

    def _diagnose_case(self, name, error):
        """Keep bounded, redacted evidence when the service connection fails.

        A refused connection in ``setup`` says nothing by itself; the retained
        server log tail, the binary's exit status and a bounded wait for the
        port distinguish a crash from a slow start without secrets.
        """
        if "Connection refused" not in str(error):
            return
        base = getattr(self, "base", None)
        port = int(base.rsplit(":", 1)[1]) if base and base.rsplit(":", 1)[-1].isdigit() else None
        deadline = time.monotonic() + getattr(getattr(self, "args", None), "connection_debug", 0)
        ready = False
        while port and time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.5)
        log = Path(self.root) / "server.log"
        tail = log.read_text(errors="replace")[-3000:] if log.is_file() else ""
        print(self.redact("case " + name + ": connection refused; port " + repr(port)
                          + " ready within " + repr(getattr(self.args, "connection_debug", 0))
                          + "s: " + repr(ready) + "; server log tail: " + tail), file=sys.stderr)

    def all_audit_ids(self, db):
        return [int(value) for value in
                self.query(db, "SELECT id FROM repository_audit_log ORDER BY id").splitlines()]

    def audit_rows(self, db):
        """Every audit row of the fixture repositories with all persisted columns.

        Both signed-in repositories are included: their rows come from real
        API/Git traffic and every one of them must survive the restore.
        """
        repos = ",".join("'" + item["id"] + "'" for item in (self.repo, self.other))
        return json.loads(self.query(db, (
            "SELECT COALESCE(json_agg(json_build_object(" + ", ".join(
                f"'{name}',{name}" for name in AUDIT_COLUMNS.split(","))
            + ") ORDER BY id),'[]') FROM repository_audit_log WHERE repository_id IN (" + repos + ")")))

    def audit_writer(self, db):
        """Evidence that audit ids come from the owned migration-110 sequence."""
        row = self.query(db, (
            "SELECT COALESCE(column_default,'') || '|' || COALESCE(attidentity::text,'') || '|' || "
            "COALESCE((SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=current_schema() AND c.relname='repository_audit_log_id_seq'),'missing') "
            "FROM information_schema.columns, pg_attribute WHERE table_schema=current_schema() "
            "AND table_name='repository_audit_log' AND column_name='id' "
            "AND attrelid='repository_audit_log'::regclass AND attname='id'"))
        default, identity, kind = row.split("|")
        assert default == "nextval('repository_audit_log_id_seq'::regclass)", row
        assert identity == "" and kind == "S", "expected an owned sequence, not identity/legacy: " + row
        return {"default": default, "sequence_relkind": kind}

    def audit_page(self, after, limit, repo="demo"):
        """Real ascending cursor API: ``id > after`` ordered by id, never a DESC page."""
        page = self.document(self.repo_path("/audit", repo) + "?after=" + str(after)
                             + "&limit=" + str(limit), token=self.alice)
        return [int(item["id"]) for item in page["items"]], page["next_after"]

    def walk_audit(self, after, limit=100, repo="demo"):
        """Walk the ascending cursor of one repository past ``after``.

        The cursor is per repository (audit.rs also filters repository_id), so
        the drill compares it with the same repository's SQL rows.
        """
        ids, pages = [], 0
        while True:
            more, page_next = self.audit_page(after, limit, repo)
            pages += 1
            assert more == sorted(more) and all(value > after for value in more), (after, more)
            ids.extend(more)
            if page_next is None:
                return ids, pages
            assert page_next == more[-1], "cursor did not advance to the last item id"
            after = page_next

    def collaborator(self, name, path=None):
        for item in self.document((path or self.authors_path) + "?limit=100")["items"]:
            if item["username"] == name:
                return item
        return None

    def triage_negative(self, label):
        """Prove Bob's triage grant on the repository it was granted for.

        Bob is a triage collaborator of ``alice/demo`` only, so both writes go
        there: a real issue create (201, the REST handler's own permission) and
        a pull create refused by the role gate (403).  Distinct valid branch
        names keep the same-branch 400 from standing in for the role refusal;
        both branches exist, so a role check ordered after the ref lookup
        cannot answer 409 either.  The REST issue create writes no audit row,
        so callers still expect their audit rows to be unchanged.
        """
        self.document(self.repo_path("/issues"), 201, token=self.bob,
                      method="POST", body={"title": label + " triage issue"})
        self.document(self.repo_path("/pulls"), 403, token=self.bob, method="POST",
                      body={"title": label + " triage cannot open pulls",
                            "head_ref": "refs/heads/main", "base_ref": "refs/heads/triage-base"})

    def update_collaborator(self, name, role):
        """Real collaborator mutation: PUT the live version, expect 200 updated.

        The path carries the username and the body must not repeat it; the
        version is the row's current one, so the call fails loudly instead of
        silently creating, if the source and the restored rows disagree.
        """
        current = self.collaborator(name)
        assert current is not None, "collaborator " + name + " is missing"
        updated = self.document(self.authors_path + "/" + name, 200, method="PUT",
                                body={"role": role, "expected_version": current["version"]})
        assert updated["username"] == name and updated["role"] == role, updated
        assert updated["version"] == current["version"] + 1, (current, updated)
        return current, updated

    def review_pull(self, number, commit_oid, actor="alice", state="changes_requested"):
        """Real REST review write; the API audits it as pull_review.submitted.

        The review is a ``changes_requested`` on the open pull, so the
        publishable merge of the source window is still available later.
        """
        path = self.repo_path("/pulls/" + str(number) + "/reviews")
        return self.document(path, 201, token=getattr(self, actor), method="POST",
                             body={"state": state, "commit_oid": commit_oid,
                                   "body": "real REST review before the backup"})

    def wait_settled(self, db, label):
        """Wait until the stock server settled every push journal by itself.

        No worker command and no SQL settlement: the service reconciles its own
        journal on the normal request path.  A still-``unknown`` outcome fails.
        """
        deadline = time.monotonic() + 30
        while True:
            raw = self.query(db, "SELECT outcome FROM git_operations WHERE repository_id IN ('"
                             + self.repo["id"] + "','" + self.other["id"] + "') ORDER BY sequence")
            outcomes = settled_outcomes(raw.splitlines() if raw else [])
            if outcomes:
                assert set(outcomes) <= {"recorded", "no_ref_changes"}, outcomes
                return outcomes
            assert time.monotonic() < deadline, label + " was not settled within 30s: " + repr(raw)
            time.sleep(0.05)

    def setup(self):
        # The explicit fixture, in order: migrate, the real alice/bob accounts,
        # a read-only and a (later revoked on the source) API token, the live
        # service, its real API/Git round trip, and the volume-lock refusal of
        # an offline backup while the service holds the lock.  No SQL-seeded
        # "git outcome unknown" repository or retained operation journal: this
        # drill backs up a settled source only and recovers through a real push
        # the stock server settles itself.
        self.cli("migrate")
        self.alice = self.account("create-user", "alice")
        self.bob = self.account("create-user", "bob")
        self.reader = self.account("create-token", "alice", "--read-only")
        self.revoked = self.account("create-token", "alice")
        self.start()
        self.api()
        self.roundtrip()
        # There is a real active server and it owns the volume lock.
        assert self.backup_command(check=False).returncode != 0
        assert not self.backup.exists()
        # A settled source at the live-service point: nothing is left unsettled.
        assert self.query(self.db, "SELECT count(*) FROM git_operations "
                          "WHERE outcome='unknown'") == "0"
        self.sequence = self.audit_writer(self.db)
        assert self.query(self.db, "SELECT 1 FROM schema_migrations WHERE version=110") == "1"
        # Collaborator rows reference real accounts (rc/rbac.rs lookup_user),
        # so carol and dave exist before they are granted anything.
        for name in ("carol", "dave"):
            self.account("create-user", name)
        # Real create semantics: no expected_version means "create" (201,
        # collaborator.added); the API rejects expected_version for a new row.
        # bob, carol and dave all start as triage collaborators of alice/demo.
        for name in ("bob", "carol", "dave"):
            created = self.document(self.authors_path, 201, method="POST",
                                    body={"username": name, "role": "triage"})
            assert created["role"] == "triage" and created["version"] == 1, created
        return {"audit_sequence": self.sequence, "triage_collaborators": ["bob", "carol", "dave"],
                "live_server_backup_rejected": True}

    def setup_repos(self):
        # Every real Git push happens here, before the single post-push snapshot,
        # so nothing is written silently between the snapshot and the backup.
        # The outbox baseline precedes the first ahead/triage/Git push: the
        # background audit consumer may drain the pushes' events long before
        # the source window below reads its count.
        self.audit_events_before = int(self.query(self.db, "SELECT count(*) FROM audit_events"))
        other = self.create_repository({"name": "ahead"}, token=self.alice)
        self.other = other
        assert other["state"] == "ready" and other["id"] != self.repo["id"], other
        # share_base: the freshly provisioned repository's bare HEAD names an
        # unborn main, so before any clone the real demo working repository
        # (the one roundtrip pushed from) pushes its second commit to the new
        # main ref with stock Git.  Both clones below then see one real base.
        self.git("-C", str(self.work), "push", self.base + other["clone_path"],
                 self.second + ":refs/heads/main", token=self.alice)
        assert self.git("ls-remote", self.base + other["clone_path"], "main", token=self.alice) \
            .stdout.decode().strip() == self.second + "\trefs/heads/main"
        # The demo triage-base ref is a real Git fact too: self.first already
        # exists in this demo working repository and the server object store,
        # so it is pushed directly with stock Git.  A Git push writes Git
        # operations, never audit rows.
        self.git("-C", str(self.work), "push", self.remote,
                 self.first + ":refs/heads/triage-base", token=self.alice)
        # ls-remote exits 0 even for an absent ref; compare full stdout.
        assert self.git("ls-remote", self.remote, "refs/heads/triage-base", token=self.alice) \
            .stdout.decode().strip() == self.first + "\trefs/heads/triage-base"
        assert self.git("-C", str(self.work), "merge-base", "--is-ancestor",
                        self.first, self.second, check=False).returncode == 0
        # Bob's triage grant is observable through the real API before the
        # backup: a triage may file an issue and may not open a pull request.
        assert self.collaborator("bob")["role"] == "triage"
        before_triage = self.audit_rows(self.db)
        self.triage_negative("source")
        self.pre_push_rows = self.audit_rows(self.db)
        # The REST issue create returned 201 but recorded no audit row: only
        # the web form handler emits issue.created.  The refused pull create
        # wrote nothing, and the only audit rows are the three real creates.
        assert self.pre_push_rows == before_triage, \
            "the REST triage issue/pull writes recorded repository_audit_log rows"
        assert [row["action"] for row in self.pre_push_rows] == [
            "collaborator.added"] * 3, self.pre_push_rows
        planned = self.base + other["clone_path"]
        base = self.second
        for remote, commit in ((self.remote, "audit-then-push.txt"), (planned, "ahead-then-write.txt")):
            target = self.root / ("work-" + commit)
            self.git("clone", remote, str(target), token=self.alice)
            self.git("config", "user.name", "E2E", cwd=target)
            self.git("config", "user.email", "e2e@example.invalid", cwd=target)
            assert self.git("rev-parse", "HEAD", cwd=target).stdout.decode().strip() == base
            (target / commit).write_text("settled by the stock server reconciliation\n")
            self.git("add", commit, cwd=target)
            self.git("commit", "-m", "push " + commit, cwd=target)
            self.git("push", "origin", "main", cwd=target, token=self.alice)
        outcomes = self.wait_settled(self.db, "source pushes")
        for remote, commit in ((self.remote, "audit-then-push.txt"), (planned, "ahead-then-write.txt")):
            target = self.root / ("work-" + commit)
            assert self.git("ls-remote", remote, "main", token=self.alice).stdout.decode().strip() \
                == self.git("rev-parse", "HEAD", cwd=target).stdout.decode().strip() + "\trefs/heads/main"
        self.pre_push_ids = self.all_audit_ids(self.db)
        # The pushes are Git/receipt facts only: the audit rows are exactly the
        # pre-push snapshot (three collaborator creations, no push action).
        # The failure message is the set comparison's own.
        audit_rows_by_id(self.pre_push_rows, self.audit_rows(self.db))
        self.hook_runner = self.hook_runner_digest()
        assert self.hook_runner == self.runtime_binary_sha256, \
            "the managed hook runner is not the executed binary"
        return {"repositories": [self.repo["name"], self.other["name"]], "base_oid": base,
                "git_operation_outcomes": outcomes, "hook_runner_sha256": self.hook_runner,
                "audit_rows_before_sequence_check": len(self.pre_push_rows)}

    def action_sequence(self, db, actions):
        """Per-action audit ids of every row with the given actions, ascending."""
        wanted = ",".join("'" + action + "'" for action in actions)
        raw = self.query(db, "SELECT COALESCE(json_agg(json_build_object('action',action,'id',id)"
                          " ORDER BY id),'[]') FROM repository_audit_log WHERE action IN ("
                          + wanted + ")")
        return json.loads(raw)

    def source_audit_writes_advance_sequence(self):
        # The audit id space advances only through API audit writes; the pushes
        # are Git/receipt facts (Git operations, not repository_audit_log).
        before = self.audit_rows(self.db)
        # Every row id allocated so far proves the write below advances past it.
        self.ids_before_write = self.all_audit_ids(self.db)
        self.update_collaborator("carol", "maintain")
        after = self.audit_rows(self.db)
        rows = after[len(before):]
        assert [row["action"] for row in rows] == ["collaborator.updated"], rows
        assert [row["actor_name"] for row in rows] == ["alice"], rows
        assert rows[0]["id"] > max(self.ids_before_write), (rows, self.ids_before_write)
        walked, _ = self.walk_audit(max(row["id"] for row in before))
        assert walked == [row["id"] for row in rows]
        # Real REST forge writes of the source window: a PR create and a
        # review.  Only these API handlers are audited for forge actions (the
        # REST issue create is not), so their rows must be exactly these.
        pull = self.document(self.repo_path("/pulls"), 201, method="POST",
                             body={"title": "source pull", "head_ref": "refs/heads/main",
                                   "base_ref": "refs/heads/triage-base"})
        review = self.review_pull(pull["number"], pull["head_oid"])
        assert review["state"] == "changes_requested", review
        self.pull_number = pull["number"]
        final = self.audit_rows(self.db)
        forge_rows = final[len(after):]
        assert [(row["action"], row["target_name"], row["actor_name"]) for row in forge_rows] == [
            ("pull.created", str(pull["number"]), "alice"),
            ("pull_review.submitted", "%d:%d" % (pull["number"], review["number"]), "alice"),
        ], forge_rows
        # The saved prefix is every audited write of the source window; the
        # Git pushes above added none of these actions or rows.
        self.saved_actions = ["collaborator.added", "collaborator.updated",
                              "pull.created", "pull_review.submitted"]
        self.source_sequence = self.action_sequence(self.db, self.saved_actions)
        self.cli("worker-once")  # outbox audit-log consumer claims the push events
        self.audit_events_after = int(self.query(self.db, "SELECT count(*) FROM audit_events"))
        snapshotted = self.audit_rows(self.db)
        assert self.source_sequence == [{"action": row["action"], "id": row["id"]}
                                        for row in snapshotted
                                        if row["action"] in self.saved_actions]
        assert [row["id"] for row in rows] == [row["id"] for row in self.source_sequence[3:4]]
        assert snapshotted == final, "a Git push or the audit-log consumer wrote repository_audit_log"
        assert self.audit_events_after > self.audit_events_before, \
            "the settled pushes produced no outbox audit_events claim"
        self.snapshot_rows = snapshotted
        self.sequence_before_backup = self.query(
            self.db, "SELECT last_value || '/' || is_called FROM repository_audit_log_id_seq")
        return {"api_audit_writes": [row["action"] for row in rows + forge_rows],
                "walked_audit_ids": walked[-1:],
                "saved_audit_sequence": self.source_sequence,
                "audit_events_delta": self.audit_events_after - self.audit_events_before,
                "snapshot_rows": len(snapshotted)}

    def metadata_only_format_without_blob_service(self):
        self.stop()
        self.backup_result = json.loads(self.backup_command().stdout)
        manifest = json.loads((self.backup / "manifest.json").read_text())
        assert manifest["format"] == CURRENT_BACKUP_FORMAT == 21, manifest["format"]
        assert manifest["schema_versions"][-1] == CURRENT_SCHEMA_VERSION
        assert manifest.get("blob_closure") is None and not manifest.get("blob_artifacts"), \
            "a paired Blob archive would bypass this storage/format family"
        self.cli("backup-verify", str(self.backup))
        return {"backup_format": manifest["format"], "schema_version": manifest["schema_versions"][-1],
                "consistency": manifest["consistency"], "blob_closure": None}

    def offline_backup_and_fresh_database_restore(self):
        result = json.loads(self.restore_command().stdout)
        assert result["restored"] is True, result
        versions = "SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations"
        for db in (self.source_db, self.target_db):
            assert self.query(db, versions), "migrations missing in " + db
        assert self.query(self.source_db, versions) == self.query(self.target_db, versions)
        # Restored facts only: sequence state before any post-restore write.
        self.restored_sequence_start = self.query(
            self.target_db, "SELECT last_value || '/' || is_called FROM repository_audit_log_id_seq")
        assert self.restored_sequence_start == self.sequence_before_backup, \
            (self.restored_sequence_start, self.sequence_before_backup)
        assert self.audit_writer(self.target_db) == self.sequence
        self.env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        self.db = self.target_db
        self.start()
        assert self.hook_runner_digest() == self.runtime_binary_sha256, \
            "the restored data directory does not expose the executed binary as its hook runner"
        alice_tenant = self.query(self.target_db, "SELECT n.id FROM namespaces n WHERE n.slug='alice'")
        self.restored_rows = self.audit_rows(self.target_db)
        # Full-row comparison keyed by id, so a row re-attributed to another
        # tenant/repository/actor or with another created_at also fails.
        audit_rows_by_id(self.snapshot_rows, self.restored_rows)
        self.restored_tenants = sorted({str(row["tenant_id"]) for row in self.restored_rows})
        self.restored_actors = sorted({row["actor_name"] for row in self.restored_rows})
        # Both repositories of alice's tenant; the audited source writes are
        # alice's collaborator creates/updates only (Bob's REST issue is an
        # issue row, not an audit row), so their only actor is alice.
        assert self.restored_tenants == [alice_tenant], self.restored_tenants
        assert self.restored_actors == ["alice"], self.restored_actors
        self.restored_floor = max(row["id"] for row in self.restored_rows)
        return {"fresh_database": self.source_db != self.target_db,
                "restored_tenants": self.restored_tenants, "restored_actors": self.restored_actors,
                "restored_sequence_equals_source": True,
                "restored_rows": len(self.restored_rows),
                "restore_seconds": result["elapsed_seconds"]}

    def restored_http_audit_sequence_continues(self):
        # The collaborators restored through the archive must be the ones the
        # source created: bob (and carol's source-side update) survive with
        # their roles and versions, together with the real API-visible grants.
        assert self.collaborator("bob")["role"] == "triage", "bob's triage grant was not restored"
        assert self.collaborator("carol")["role"] == "maintain"
        # Bob's triage writes are real 201/403 outcomes, but the REST issue
        # handler records no audit row, so the audit window is the PUT alone.
        self.triage_negative("restored")
        assert self.audit_rows(self.target_db) == self.restored_rows, \
            "the restored REST triage issue/pull writes recorded audit rows"
        self.update_collaborator("bob", "maintain")
        after = self.audit_rows(self.target_db)
        assert self.collaborator("bob")["role"] == "maintain"
        rows = after[len(self.restored_rows):]
        # One real API audit write of this window: alice's PUT.  The refused
        # pull create and Bob's REST issue write nothing here.
        assert [row["action"] for row in rows] == ["collaborator.updated"], rows
        assert [row["actor_name"] for row in rows] == ["alice"], rows
        assert rows[0]["target_name"] == "bob", rows
        walked, pages = self.walk_audit(self.restored_floor, limit=100)
        assert walked == [row["id"] for row in rows], (walked, [row["id"] for row in rows])
        new = new_audit_ids([row["id"] for row in self.restored_rows],
                            [row["id"] for row in after], walked, expected=1)
        added = audit_subrows_by_id(self.restored_rows, after)
        assert added == new == [rows[0]["id"]], (added, new, rows)
        self.after_http_rows = after
        self.http_floor = new[-1]
        return {"status": 200, "actions": [row["action"] for row in rows],
                "actors": [row["actor_name"] for row in rows],
                "rest_triage_issue_audited": False,
                "walked_audit_ids": walked, "pages": pages,
                "pre_backup_max_id": self.restored_floor}

    def restored_concurrent_audit_sequence_continues(self):
        # 32 concurrent real branch-rule creates, each on its own previously
        # absent branch_ref, so every request is a genuine create (201).
        count = 2 * CONCURRENT_WRITERS
        race_prefix = "refs/heads/audit-race-" + os.urandom(4).hex() + "-"
        branches = [race_prefix + "%02d" % index for index in range(count)]
        # The prefix known before the race is every audited write of the
        # source plus the restored window's PUT (collaborator.updated): six
        # source rows plus one restored row, in id order.  The saved prefix
        # holds {"action","id"} only, so the restored window is projected the
        # same way; its full rows are already checked by audit_subrows.
        restored_window = [{"action": row["action"], "id": row["id"]}
                           for row in self.after_http_rows[len(self.restored_rows):]]
        known = self.action_sequence(self.target_db, self.saved_actions)
        expected_prefix = self.source_sequence + restored_window
        assert known == expected_prefix, (known, expected_prefix)
        assert known[:len(self.source_sequence)] == self.source_sequence
        self.prefix_sequence = known
        before_rows = self.after_http_rows

        def write(branch_ref):
            body = {"branch_ref": branch_ref, "required_approvals": 0,
                    "required_checks": [], "require_fast_forward": True,
                    "prevent_deletion": True, "prevent_force_push": True}
            status, raw, _ = self.http(self.rules_path, token=self.alice, method="POST", body=body)
            return status, branch_ref, raw[:200]

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_WRITERS) as pool:
            results = list(pool.map(write, branches))
        assert [result[0] for result in results] == [201] * count, results
        for branch_ref in branches:
            rule = self.document(self.rules_path + "/" + branch_ref, token=self.alice)
            assert rule["branch_ref"] == branch_ref and rule["version"] == 1, rule
        after = self.audit_rows(self.target_db)
        walked, pages = self.walk_audit(self.http_floor, limit=7)
        new = new_audit_ids([row["id"] for row in self.after_http_rows],
                            [row["id"] for row in after], walked, expected=count)
        # The cursor is per repository (all these writes are demo's), so the
        # SQL rows of the same repository must show the very same window.
        demo_rows = [row["id"] for row in after if row["repository_id"] == self.repo["id"]]
        assert walked == [value for value in demo_rows if value > self.http_floor], (walked, demo_rows)
        rows = sorted((row for row in after if row["id"] in set(new)), key=lambda row: row["id"])
        # Exactly one branch-rule row per request, each naming its own branch.
        # The same set is the one the cursor walk returned.
        assert [row["action"] for row in rows] == ["branch_rule.upserted"] * count, rows
        assert sorted(row["target_name"] for row in rows) == branches
        assert [row["id"] for row in rows] == list(new), (rows, new)
        # The prefix saved after restore is re-read from SQL and must be
        # byte-identical, in action and id order, to what was captured.
        assert self.action_sequence(self.target_db, self.saved_actions) == self.prefix_sequence, \
            "the saved audit prefix changed during the concurrent window"
        assert [row["id"] for row in self.prefix_sequence] \
            == [row["id"] for row in before_rows], "prefix ids changed"
        # Every pre-existing row (all columns) is unchanged; the added rows are
        # exactly the walked window.
        added = audit_subrows_by_id(before_rows, after)
        assert added == new, (added, new)
        window_ids = [row["id"] for row in rows]
        self.race_floor = max(window_ids)
        sequence = self.query(self.target_db,
                              "SELECT last_value || '/' || is_called FROM repository_audit_log_id_seq")
        assert int(sequence.split("/")[0]) >= self.race_floor, sequence
        self.after_race_rows = after
        return {"concurrent_writes": count, "statuses": sorted({result[0] for result in results}),
                "unique_branch_refs": len(set(branches)), "audit_rows_for_window": len(rows),
                "saved_prefix_len": len(known), "window_ids": window_ids, "pages": pages,
                "first_new_audit_id": new[0], "last_new_audit_id": new[-1]}

    def restored_git_push_and_audit_events_recovery(self):
        branch = self.root / "restored-push"
        self.git("clone", "--single-branch", "--branch", "main", self.remote, str(branch), token=self.alice)
        self.git("config", "user.name", "E2E", cwd=branch)
        self.git("config", "user.email", "e2e@example.invalid", cwd=branch)
        expected = self.git("ls-remote", self.remote, "main", token=self.alice).stdout.decode().split()[0]
        assert self.git("rev-parse", "HEAD", cwd=branch).stdout.decode().strip() == expected
        (branch / "after-restore.txt").write_text("pushed into the restored service\n")
        self.git("add", "after-restore.txt", cwd=branch)
        self.git("commit", "-m", "push after restore", cwd=branch)
        oid = self.git("rev-parse", "HEAD", cwd=branch).stdout.decode().strip()
        # Both baselines precede the push: the audit consumer may drain the
        # push's events before the post-clone reads, and the log count here
        # proves directly that the push itself wrote no repository_audit_log.
        logs_before = int(self.query(self.target_db, "SELECT count(*) FROM repository_audit_log"))
        events_before = int(self.query(self.target_db, "SELECT count(*) FROM audit_events"))
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=branch, token=self.alice)
        outcomes = self.wait_settled(self.target_db, "restored push")
        assert self.git("ls-remote", self.remote, "main", token=self.alice).stdout.decode().strip() \
            == oid + "\trefs/heads/main"
        checkout = self.root / "restored-push-check"
        self.git("clone", self.remote, str(checkout), token=self.reader)
        self.git("fsck", "--full", "--strict", cwd=checkout)
        assert (checkout / "after-restore.txt").read_text() == "pushed into the restored service\n"
        self.cli("worker-once")
        logs_after = int(self.query(self.target_db, "SELECT count(*) FROM repository_audit_log"))
        events_after = int(self.query(self.target_db, "SELECT count(*) FROM audit_events"))
        # Git/receipt recovery is the push; the audit id space is untouched by
        # it: the full-set row comparison is exact here (no write is allowed).
        assert logs_after == logs_before, "the restored Git push wrote repository_audit_log"
        audit_rows_by_id(self.after_race_rows, self.audit_rows(self.target_db))
        assert events_after > events_before, "the restored push produced no audit_events claim"
        return {"pushed_oid": oid, "git_operation_outcomes": outcomes,
                "audit_events": {"before": events_before, "after": events_after},
                "repository_audit_log_rows_unchanged": logs_after}

    def missing_default_control_has_no_sequence(self):
        """Missing-default control: the pre-110 schema shape has no sequence.

        Dropping the default leaves the table as a source before migration 110
        had it (no server-side id allocation), so real audit writes must fail
        instead of committing.  This does NOT replay the historical MAX(id)+1
        algorithm or its races; it shows only that the positive results depend
        on the sequence default.  Restored run-owned database only; re-applied
        migration 110 and a non-isolated restore bring it back to the contract.
        """
        assert self.audit_rows(self.target_db) == self.after_race_rows
        default, identity, kind = self.audit_sequence_column()
        assert default == "nextval('repository_audit_log_id_seq'::regclass)" and kind == "S", (default, kind)
        self.query(self.target_db, "ALTER TABLE repository_audit_log ALTER COLUMN id DROP DEFAULT")
        statuses = []
        try:
            assert self.audit_sequence_column()[0] == "", "control could not remove the sequence default"
            control = "refs/heads/missing-default-control-" + os.urandom(4).hex() + "-"
            statuses = [self.http(self.rules_path, token=self.alice, method="POST",
                                  body={"branch_ref": control + "%d" % index})[0]
                        for index in range(3)]
            assert statuses and all(status >= 500 for status in statuses), (
                "a missing ID default must fail the write, observed " + repr(statuses))
            # The failed audit insert must roll the whole request back: no rule
            # of the control's own run-owned prefix was committed.
            assert self.query(self.target_db, "SELECT count(*) FROM forge_branch_rules "
                              "WHERE branch_ref LIKE '" + control + "%'") == "0", \
                "the refused control write committed a branch rule"
        finally:
            self.query(self.target_db, "CREATE SEQUENCE IF NOT EXISTS repository_audit_log_id_seq AS bigint")
            self.query(self.target_db, MIGRATION_110.read_text())
        default, identity, kind = self.audit_sequence_column()
        assert default == "nextval('repository_audit_log_id_seq'::regclass)" and kind == "S", (default, kind)
        assert self.audit_rows(self.target_db) == self.after_race_rows, \
            "the control changed audit rows produced through the real API"
        live = self.query(self.target_db, "SELECT count(*) FROM pg_stat_activity "
                          "WHERE datname=current_database() AND pid<>pg_backend_pid() "
                          "AND application_name='rootyard-worker'")
        return {"control": "missing_sequence_default", "observed_statuses": statuses,
                "replays_legacy_max_id_algorithm": False,
                "external_rootyard_workers": int(live),
                "resume_required": "restore --isolated --trust-backup without --no-start "
                                   "(re-applies migration 110 to this database)"}

    def audit_sequence_column(self):
        row = self.query(self.target_db, (
            "SELECT COALESCE(column_default,'') || '|' || COALESCE(attidentity::text,'') || '|' || "
            "COALESCE((SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=current_schema() AND c.relname='repository_audit_log_id_seq'),'missing') "
            "FROM information_schema.columns, pg_attribute WHERE table_schema=current_schema() "
            "AND table_name='repository_audit_log' AND column_name='id' "
            "AND attrelid='repository_audit_log'::regclass AND attname='id'"))
        return tuple(row.split("|"))


def subprocess_version(argv):
    try:
        completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    except OSError:
        return ""
    return completed.stdout.decode(errors="replace").strip()


def preflight(args, environ=None):
    """Missing or wrong dependencies fail loudly; nothing is skipped."""
    environ = os.environ if environ is None else environ
    missing = [exe for exe in REQUIRED_EXECUTABLES if not shutil.which(exe)]
    if not Path(args.binary).is_file():
        missing.append("binary " + args.binary)
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
    parts = urllib.parse.urlsplit(environ["ROOTYARD_TEST_DATABASE_URL"])
    server = subprocess_version(["psql", "-X", environ["ROOTYARD_TEST_DATABASE_URL"], "-h",
                                 parts.hostname or "", "-p", str(parts.port or 5432),
                                 "-Atc", "SHOW server_version_num"])
    if not server.isdigit() or int(server) // 10000 < MIN_POSTGRES_VERSION:
        raise SystemExit("a PostgreSQL 17 server is required, found " + repr(server))
    try:
        binding = source_bound_binary.bind(args.binary, environ=environ)
    except source_bound_binary.SourceBindingError as error:
        raise SystemExit("binary is not bound to this checkout: " + str(error)) from None
    return {"git_version": ".".join(map(str, git_version)), "postgres_server_version_num": int(server),
            "source_binding": binding}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--connection-debug", type=float, default=0, metavar="SECONDS")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    runtime, failure = None, None
    try:
        runtime = preflight(args)
    except SystemExit as error:
        failure = str(error) or "preflight failed"
    harness = None
    success = False
    try:
        if failure:
            raise SystemExit(failure)
        harness = AuditSequenceLegacyHarness(args)
        harness.runtime_binary_sha256 = ops_provenance.sha256_file(args.binary)
        for name in CASES:
            try:
                harness.case(name, getattr(harness, name))
            except Exception as error:
                if name == CASES[0]:
                    harness._diagnose_case(name, error)
                raise
        success = True
    except SystemExit:
        raise
    except Exception as error:
        print(harness.redact(error) if harness else str(error), file=sys.stderr)
    finally:
        if harness is not None:
            try:
                harness.cleanup()
            except Exception as error:
                print(harness.redact(error), file=sys.stderr)
                success = False
            report = dict(passed=success, cases=harness.results, runtime=runtime,
                          binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                          limitations=[
                              "Format21 metadata archive of a stock GitFS source; no Blob closure is read or written.",
                              "A Git push is checked as a Git/audit_events fact; only API audit writes advance "
                              "repository_audit_log ids.",
                              "The control removes the migration-110 sequence default (the pre-110 shape); it does "
                              "not reproduce the historical MAX(id)+1 race.",
                              "Source binding compares production input bytes only; a test/doc-only commit may "
                              "move HEAD without invalidating the binary.",
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
