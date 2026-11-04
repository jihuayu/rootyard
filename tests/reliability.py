#!/usr/bin/env python3
"""Durable Git receipt/recovery integration tests with isolated PostgreSQL/storage.

Run after building rootyard, with ROOTYARD_TEST_DATABASE_URL set. SQL fault
injection and synthetic crash journals are deliberately distinguished from real
Git push evidence. No current ref value is used to manufacture successful events.
"""
import argparse
import base64
import http.client
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import time
import uuid

from e2e import Harness

ZERO = "0" * 40


class ReliabilityHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.env["ROOTYARD_OUTBOX_WORKER"] = "false"
        self.limits = [
            "Process restart and SQL publication faults do not emulate kernel/power loss.",
            "Prepared/repeated-evidence recovery cases use explicit synthetic crash journals, not claims of actual push success.",
            "Local transactional consumers are tested; no external exactly-once delivery is claimed.",
        ]

    def rows(self, select):
        return json.loads(self.sql("SELECT COALESCE(json_agg(t), '[]'::json) FROM (" + select + ") t"))

    def operations(self, repo=None):
        return self.rows("SELECT * FROM git_operations WHERE repository_id='" + (repo or self.repo)["id"] + "' ORDER BY sequence")

    def events(self, repo=None):
        return self.rows("SELECT * FROM outbox_events WHERE repository_id='" + (repo or self.repo)["id"] + "' ORDER BY operation_sequence,transaction_sequence,ref_name")

    def last_operation(self, outcome):
        ops = self.operations()
        assert ops and ops[-1]["outcome"] == outcome, ops
        return ops[-1]

    def ref(self, name):
        p = self.git("--git-dir=" + str(self.bare), "rev-parse", "--verify", name, check=False)
        return p.stdout.decode().strip() if p.returncode == 0 else None

    def push(self, *refs, check=True):
        return self.git("push", "origin", *refs, cwd=self.work, token=self.alice, check=check)

    def upgrade(self):
        h = Harness(self.args)
        try:
            h.sql('CREATE SCHEMA "' + h.schema + '"', isolated=False)
            h.schema_created = True
            h.sql((Path(__file__).resolve().parents[1] / "migrations/001_initial.sql").read_text())
            user, repo = str(uuid.uuid4()), str(uuid.uuid4())
            h.sql("INSERT INTO users(id,username) VALUES('" + user + "','upgradeowner'); INSERT INTO repositories(id,owner_id,name) VALUES('" + repo + "','" + user + "','preserved')")
            h.cli("migrate")
            h.cli("migrate")
            assert h.sql("SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations") == "1,2,3,6,7"
            assert h.sql("SELECT name FROM repositories WHERE id='" + repo + "'") == "preserved"
            assert h.sql("SELECT username FROM users WHERE id='" + user + "'") == "upgradeowner"
            assert h.sql("SELECT count(*) FROM git_operations") == "0"
            return {"migration_001_data_preserved": True, "repeated_migrate": True}
        finally:
            h.cleanup()

    def real_pushes(self):
        self.roundtrip()
        op = self.last_operation("recorded")
        events = self.events()
        assert len(events) == 2 and events[-1]["operation_id"] == op["id"]
        assert (events[0]["ref_name"], events[0]["old_oid"], events[0]["new_oid"]) == ("refs/heads/main", ZERO, self.first)
        assert self.events()[-1]["old_oid"] == self.first
        # A leading + sends the non-FF request to receive-pack rather than
        # allowing the client to reject it before an operation exists.
        before = len(self.operations())
        rejected = self.push("+" + self.first + ":main", check=False)
        assert rejected.returncode != 0
        assert len(self.operations()) == before + 1
        nochange = self.last_operation("no_ref_changes")
        assert not any(e["operation_id"] == nochange["id"] for e in self.events())
        assert self.ref("refs/heads/main") == self.second
        self.git("fetch", "origin", cwd=self.copy, token=self.reader)
        assert self.git("rev-parse", "origin/main", cwd=self.copy).stdout.decode().strip() == self.second
        return {"recorded": op["id"], "no_ref_changes": nochange["id"], "native_ref_verified": True}

    def partial_push(self):
        before = len(self.operations())
        result = self.push("+" + self.first + ":main", "HEAD:partial-ok", check=False)
        assert result.returncode != 0, "Mixed success push must report its rejected ref"
        assert len(self.operations()) == before + 1
        op = self.last_operation("recorded")
        subset = [e for e in self.events() if e["operation_id"] == op["id"]]
        assert [(e["ref_name"], e["old_oid"], e["new_oid"]) for e in subset] == [("refs/heads/partial-ok", ZERO, self.second)], subset
        assert self.ref("refs/heads/main") == self.second
        assert self.ref("refs/heads/partial-ok") == self.second
        return {"successful_subset_only": True, "rejected_ref": "refs/heads/main"}

    def deletions(self):
        for name, packed in [("loose-delete", False), ("packed-delete", True)]:
            self.push("HEAD:" + name)
            if packed:
                # Maintenance fixture is offline; never race the service writer.
                self.stop()
                self.git("--git-dir=" + str(self.bare), "pack-refs", "--all", "--prune")
                assert not (self.bare / "refs/heads" / name).exists()
                assert "refs/heads/" + name in (self.bare / "packed-refs").read_text()
                self.start()
            self.push(":" + name)
            op = self.last_operation("recorded")
            changes = [e for e in self.events() if e["operation_id"] == op["id"]]
            assert len(changes) == 1
            assert (changes[0]["old_oid"], changes[0]["new_oid"]) == (self.second, ZERO)
            assert self.ref("refs/heads/" + name) is None
        return {"loose_and_packed_delete_receipts": True}

    def owner_api(self):
        for suffix in ("operations", "events"):
            path = "/api/repos/alice/demo/" + suffix
            owner = json.loads(self.expect(path, 200, token=self.alice))
            reader = json.loads(self.expect(path, 200, token=self.reader))
            assert owner == reader
            assert isinstance(owner, list) and owner
            self.expect(path, 401)
            self.expect(path, (403, 404), token=self.bob)
            self.expect(path, 405, token=self.alice, method="POST", body={})
            wire = json.dumps(owner)
            assert all(secret not in wire for secret in self.secrets)
        return {"owner_and_read_only_token": True, "other_owner_denied": True}

    def publication_replay(self):
        # Fail final SQL settlement AFTER Git writes a real durable receipt.
        # This deliberately does not fault initial unknown-operation insertion.
        self.sql("CREATE FUNCTION test_fail_settle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome <> 'unknown' THEN RAISE EXCEPTION 'test settlement unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_fail_settle BEFORE INSERT OR UPDATE ON git_operations FOR EACH ROW EXECUTE FUNCTION test_fail_settle()")
        try:
            self.push("HEAD:replay-receipt", check=False)
            journal = self.root / "data/journal" / self.repo["id"]
            pending = [p for p in journal.iterdir() if p.is_dir() and not p.name.startswith(".")]
            assert len(pending) == 1, "Expected retained durable operation"
            path = pending[0]
            metadata = json.loads((path / "operation.json").read_text())
            receipt = json.loads((path / "post-receive.json").read_text())
            assert (path / "finished").exists()
            assert [(r["ref_name"], r["new_oid"]) for r in receipt] == [("refs/heads/replay-receipt", self.second)]
            assert self.ref("refs/heads/replay-receipt") == self.second
            self.stop(hard=True)
        finally:
            self.sql("DROP TRIGGER test_fail_settle ON git_operations; DROP FUNCTION test_fail_settle()")
        # Keep the real receipt, but emulate interrupted completion and an
        # already-persisted conservative unknown state before restarting.
        (path / "finished").unlink()
        self.sql("INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,storage_generation,evidence,outcome) VALUES('" + metadata["id"] + "','" + metadata["repository_id"] + "','" + metadata["actor_id"] + "','" + metadata["token_id"] + "','alice'," + str(metadata["sequence"]) + ",1,'{}','unknown')")
        self.sql("UPDATE repositories SET state='recovering',recovery_reason='push_outcome_unknown' WHERE id='" + self.repo["id"] + "'")
        self.start()
        assert self.sql("SELECT state FROM repositories WHERE id='" + self.repo["id"] + "'") == "ready"
        assert self.sql("SELECT recovery_reason IS NULL FROM repositories WHERE id='" + self.repo["id"] + "'") == "t"
        recovered = [o for o in self.operations() if o["id"] == metadata["id"]]
        assert len(recovered) == 1 and recovered[0]["outcome"] == "recorded"
        events = [e for e in self.events() if e["operation_id"] == metadata["id"]]
        assert len(events) == len(receipt) == 1
        assert not path.exists(), "SQL-committed journal should be retired"
        before = self.events()
        self.stop(hard=True)
        self.start()
        assert self.events() == before, "Restart duplicated or changed event identities"
        return {"actual_post_receive_receipt": True, "replayed_operation": metadata["id"], "restart_idempotent": True, "unknown_with_real_receipt_recovers_to_ready": True}

    def runtime_publication_retry(self):
        pid = self.proc.pid
        self.sql("CREATE FUNCTION test_fail_runtime_settle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome <> 'unknown' THEN RAISE EXCEPTION 'test transient settlement unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_fail_runtime_settle BEFORE INSERT OR UPDATE ON git_operations FOR EACH ROW EXECUTE FUNCTION test_fail_runtime_settle()")
        try:
            self.push("HEAD:runtime-replay", check=False)
            journal = self.root / "data/journal" / self.repo["id"]
            pending = [path for path in journal.iterdir() if path.is_dir() and not path.name.startswith(".")]
            assert len(pending) == 1, "Transient SQL fault did not retain its actual receipt"
            path = pending[0]
            operation = json.loads((path / "operation.json").read_text())
            receipt = json.loads((path / "post-receive.json").read_text())
            assert (path / "finished").exists()
            assert [(change["ref_name"], change["new_oid"]) for change in receipt] == [("refs/heads/runtime-replay", self.second)]
            assert self.ref("refs/heads/runtime-replay") == self.second
        finally:
            self.sql("DROP TRIGGER test_fail_runtime_settle ON git_operations; DROP FUNCTION test_fail_runtime_settle()")
        start = time.monotonic()
        deadline = start + 15
        while True:
            settled = [row for row in self.operations() if row["id"] == operation["id"]]
            if settled and settled[0]["outcome"] == "recorded" and not path.exists():
                break
            assert time.monotonic() < deadline, "Periodic ingestion did not replay the pending receipt within 15 seconds"
            time.sleep(.1)
        assert self.proc.pid == pid and self.proc.poll() is None, "Recovery must not require restarting the service"
        events = [row for row in self.events() if row["operation_id"] == operation["id"]]
        assert len(events) == 1 and events[0]["ref_name"] == "refs/heads/runtime-replay"
        self.push("HEAD:after-runtime-replay")
        self.last_operation("recorded")
        assert self.ref("refs/heads/after-runtime-replay") == self.second
        return {"actual_receipt_replayed": True, "service_restart": False,
                "background_ingestion_seconds": round(time.monotonic() - start, 3),
                "subsequent_push_recorded": True}

    def drain(self):
        deadline = time.monotonic() + 30
        while int(self.sql("SELECT count(*) FROM event_deliveries WHERE state <> 'delivered'")):
            assert time.monotonic() < deadline, "Outbox did not drain"
            self.cli("worker-once")

    def outbox(self):
        assert int(self.sql("SELECT count(*) FROM event_deliveries WHERE state='pending'")) > 0
        self.drain()
        expected = self.sql("SELECT count(*) FROM outbox_events")
        assert self.sql("SELECT count(*) FROM audit_events") == expected
        before = self.rows("SELECT * FROM repository_ref_projection ORDER BY repository_id,ref_name")
        native = self.git("ls-remote", self.remote, token=self.reader).stdout
        # Re-delivery of the same durable events must not duplicate audit effects
        # or roll a cache backwards when older events are replayed.
        self.sql("UPDATE event_deliveries SET state='pending',delivered_at=NULL,next_attempt_at=clock_timestamp()")
        self.drain()
        assert self.sql("SELECT count(*) FROM audit_events") == expected
        assert self.rows("SELECT * FROM repository_ref_projection ORDER BY repository_id,ref_name") == before
        # Destroying the rebuildable projection must not alter Git fetch/refs.
        self.sql("DELETE FROM repository_ref_projection")
        assert self.git("ls-remote", self.remote, token=self.reader).stdout == native
        self.sql("UPDATE event_deliveries SET state='pending',delivered_at=NULL,next_attempt_at=clock_timestamp() WHERE consumer='ref-index'")
        self.drain()
        assert self.sql("SELECT oid FROM repository_ref_projection WHERE repository_id='" + self.repo["id"] + "' AND ref_name='refs/heads/main'") == self.second
        assert self.sql("SELECT deleted FROM repository_ref_projection WHERE repository_id='" + self.repo["id"] + "' AND ref_name='refs/heads/packed-delete'") == "t"
        return {"idempotent_local_consumers": True, "native_refs_authoritative": True}

    def admission_and_background(self):
        self.stop()
        self.env["ROOTYARD_MAX_PENDING_DELIVERIES"] = "1"
        self.start()
        self.push("HEAD:admission-first")
        count = len(self.operations())
        denied = self.push("HEAD:admission-blocked", check=False)
        assert denied.returncode != 0
        assert self.ref("refs/heads/admission-blocked") is None
        assert len(self.operations()) == count, "Admission rejection began a Git operation"
        self.drain()
        self.push("HEAD:admission-after-drain")
        self.stop()
        self.env.pop("ROOTYARD_MAX_PENDING_DELIVERIES")
        self.env["ROOTYARD_OUTBOX_WORKER"] = "true"
        self.start()
        deadline = time.monotonic() + 30
        while int(self.sql("SELECT count(*) FROM event_deliveries WHERE state <> 'delivered'")):
            assert time.monotonic() < deadline, "Background outbox did not drain"
            time.sleep(.1)
        self.stop()
        self.env["ROOTYARD_OUTBOX_WORKER"] = "false"
        self.start()
        return {"backlog_blocks_before_git": True, "drain_restores_admission": True, "background_delivery": True}

    def unknown_evidence(self):
        details = []
        # Identical old/new values in a prior completed callback do NOT prove
        # that a later prepared transaction completed. Native current OID is
        # deliberately set to match the requested new OID in both fixtures.
        for name, phases in [("prepared-only", ["Prepared"]),
                             ("repeated-evidence", ["Prepared", "Committed", "Prepared"])]:
            repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice, body={"name": name}))
            remote = self.base + repo["clone_path"]
            self.git("push", remote, "HEAD:main", cwd=self.work, token=self.alice)
            self.stop()
            journal = self.root / "data/journal" / repo["id"]
            seq = int((journal / "sequence").read_text()) + 1
            operation_id = str(uuid.uuid4())
            operation = dict(id=operation_id, repository_id=repo["id"], actor_id=self.sql("SELECT id FROM users WHERE username='alice'"), actor_name="alice", token_id=self.alice["token_id"], sequence=seq, storage_generation=1)
            path = journal / (f"{seq:020}-" + operation_id)
            path.mkdir(mode=0o700)
            (journal / "sequence").write_text(str(seq))
            (path / "operation.json").write_text(json.dumps(operation))
            changes = [dict(ref_name="refs/heads/main", old_oid=self.first, new_oid=self.second)]
            for ordinal, phase in enumerate(phases, 1):
                (path / f"{ordinal:020}.event.json").write_text(json.dumps(dict(ordinal=ordinal, phase=phase, changes=changes)))
            # No finished marker and no successful-ref receipt, as after an
            # interrupted process. This fixture is explicitly not a real push.
            self.start()
            ops = [o for o in self.operations(repo) if o["id"] == operation_id]
            assert len(ops) == 1 and ops[0]["outcome"] == "unknown", ops
            assert not any(e["operation_id"] == operation_id for e in self.events(repo))
            assert self.sql("SELECT state FROM repositories WHERE id='" + repo["id"] + "'") == "recovering"
            denied = self.git("push", remote, "HEAD:blocked", cwd=self.work, token=self.alice, check=False)
            assert denied.returncode != 0
            bare = self.root / "data/repos" / (repo["id"] + ".git")
            assert self.git("--git-dir=" + str(bare), "rev-parse", "refs/heads/main").stdout.decode().strip() == self.second
            assert self.git("--git-dir=" + str(bare), "show-ref", "--verify", "refs/heads/blocked", check=False).returncode != 0
            details.append({"fixture": name, "outcome": "unknown", "push_blocked": True})
        return details

    def duplicate_receipt(self):
        repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice,
                                    body={"name": "duplicate-receipt"}))
        self.git("push", self.base + repo["clone_path"], "HEAD:main", cwd=self.work, token=self.alice)
        self.stop()
        journal = self.root / "data/journal" / repo["id"]
        sequence = int((journal / "sequence").read_text()) + 1
        operation_id = str(uuid.uuid4())
        operation = dict(id=operation_id, repository_id=repo["id"],
                         actor_id=self.sql("SELECT id FROM users WHERE username='alice'"),
                         actor_name="alice", token_id=self.alice["token_id"],
                         sequence=sequence, storage_generation=1)
        path = journal / (f"{sequence:020}-" + operation_id)
        path.mkdir(mode=0o700)
        (journal / "sequence").write_text(str(sequence))
        (path / "operation.json").write_text(json.dumps(operation))
        # A synthetic duplicate-ref receipt describes A -> B -> A. A receipt
        # is one successful-ref subset, not permission to invent an ordered
        # history for repeated entries of the same ref.
        receipt = [dict(ref_name="refs/heads/main", old_oid=self.second, new_oid=self.first),
                   dict(ref_name="refs/heads/main", old_oid=self.first, new_oid=self.second)]
        (path / "post-receive.json").write_text(json.dumps(receipt))
        (path / "finished").write_bytes(b"")
        self.start()
        ops = [o for o in self.operations(repo) if o["id"] == operation_id]
        assert len(ops) == 1 and ops[0]["outcome"] == "unknown", ops
        assert not any(e["operation_id"] == operation_id for e in self.events(repo))
        assert self.sql("SELECT count(*) FROM event_deliveries d JOIN outbox_events e USING(event_id) WHERE e.operation_id='" + operation_id + "'") == "0"
        self.cli("worker-once")
        assert self.sql("SELECT count(*) FROM audit_events a JOIN outbox_events e USING(event_id) WHERE e.operation_id='" + operation_id + "'") == "0"
        assert self.sql("SELECT count(*) FROM repository_ref_projection p JOIN outbox_events e USING(event_id) WHERE e.operation_id='" + operation_id + "'") == "0"
        assert self.sql("SELECT state FROM repositories WHERE id='" + repo["id"] + "'") == "recovering"
        return {"synthetic_aba_receipt": True, "outcome": "unknown", "published_events": 0,
                "deliveries": 0, "consumer_effects": 0}

    def oversized_ref(self):
        repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice,
                                    body={"name": "oversized-ref"}))
        # Each filesystem component is short, so the controlled hook's total
        # ref length bound, not NAME_MAX, is what this fixture exercises.
        ref = "refs/heads/" + "/".join(["segment" + str(i).zfill(2) + "x" * 90 for i in range(11)])
        assert 1024 < len(ref.encode()) < 2048
        self.git("check-ref-format", ref)
        result = self.git("push", self.base + repo["clone_path"], "HEAD:" + ref,
                          cwd=self.work, token=self.alice, check=False)
        assert result.returncode != 0, "Oversized ref escaped admission hook"
        assert b"pre-receive hook declined" in result.stderr, self.redact(result.stderr.decode(errors="replace")[-2000:])
        bare = self.root / "data/repos" / (repo["id"] + ".git")
        assert self.git("--git-dir=" + str(bare), "show-ref", "--verify", ref, check=False).returncode != 0
        assert not self.events(repo), "Rejected oversized ref published a successful event"
        ops = self.operations(repo)
        assert len(ops) == 1 and ops[0]["outcome"] == "no_ref_changes", ops
        assert self.sql("SELECT state FROM repositories WHERE id='" + repo["id"] + "'") == "ready"
        return {"actual_git_push": True, "ref_bytes": len(ref.encode()),
                "native_ref_absent": True, "successful_events": 0}

    def oversized_batch(self):
        repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice,
                                    body={"name": "oversized-batch"}))
        count = 4097
        refs = ["refs/heads/batch-bound/branch-" + str(i).zfill(4) for i in range(count)]
        # One local transaction creates the fixture efficiently. Every ref
        # points to an existing commit so the test stresses admission, not pack
        # volume or loose object creation.
        commands = "".join("create " + ref + " " + self.second + "\n" for ref in refs)
        self.run(["git", "update-ref", "--stdin"], cwd=self.work, data=commands.encode())
        result = self.git("push", self.base + repo["clone_path"],
                          "refs/heads/batch-bound/*:refs/heads/batch-bound/*",
                          cwd=self.work, token=self.alice, check=False)
        assert result.returncode != 0, "Oversized command batch unexpectedly succeeded"
        assert b"pre-receive hook declined" in result.stderr, self.redact(result.stderr.decode(errors="replace")[-2000:])
        bare = self.root / "data/repos" / (repo["id"] + ".git")
        assert not self.git("--git-dir=" + str(bare), "for-each-ref", "--format=%(refname)").stdout.strip(), "Non-atomic oversized batch partially changed native refs"
        assert not self.events(repo), "Rejected batch published successful-ref events"
        ops = self.operations(repo)
        assert ops and all(op["outcome"] == "no_ref_changes" for op in ops), ops
        assert self.sql("SELECT state FROM repositories WHERE id='" + repo["id"] + "'") == "ready"
        return {"actual_git_push": True, "batch_refs": count, "native_refs_created": 0,
                "successful_events": 0, "outcome": "no_ref_changes", "http_operations": len(ops)}

    def unrelated_recovery_block(self):
        repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice,
                                    body={"name": "operator-blocked"}))
        self.stop()
        self.sql("UPDATE repositories SET state='recovering',recovery_reason='operator_investigation' WHERE id='" + repo["id"] + "'")
        self.start()
        assert self.sql("SELECT state || ':' || recovery_reason FROM repositories WHERE id='" + repo["id"] + "'") == "recovering:operator_investigation"
        denied = self.git("push", self.base + repo["clone_path"], "HEAD:main", cwd=self.work,
                          token=self.alice, check=False)
        assert denied.returncode != 0
        assert not self.operations(repo) and not self.events(repo)
        return {"unrelated_recovery_reason_preserved": True, "new_push_blocked": True}

    def stale_compare_swap(self):
        repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice,
                                    body={"name": "stale-cas"}))
        self.git("push", self.base + repo["clone_path"], "HEAD:main", cwd=self.work, token=self.alice)
        bare = self.root / "data/repos" / (repo["id"] + ".git")
        endpoint = repo["clone_path"] + "/git-receive-pack"

        def request(updates):
            commands = []
            for index, (old, new, ref) in enumerate(updates):
                line = (old + " " + new + " " + ref).encode()
                if index == 0:
                    line += b"\0report-status"
                line += b"\n"
                commands.append(f"{len(line) + 4:04x}".encode() + line)
            # All objects already exist at the receiver. Native PACK v2 with
            # zero entries consists of its header and SHA-1 trailer.
            pack = b"PACK" + struct.pack(">II", 2, 0)
            body = b"".join(commands) + b"0000" + pack + hashlib.sha1(pack).digest()
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
            auth = base64.b64encode((self.alice["username"] + ":" + self.alice["token"]).encode()).decode()
            try:
                connection.request("POST", endpoint, body=body, headers={
                    "Authorization": "Basic " + auth,
                    "Content-Type": "application/x-git-receive-pack-request"})
                result = connection.getresponse()
                assert result.status == 200, result.status
                interrupted = False
                try:
                    response = result.read()
                except http.client.IncompleteRead as error:
                    # An unknown settlement can deliberately terminate HTTP
                    # after Git has already emitted its rejection report.
                    interrupted = True
                    response = error.partial
                assert not interrupted or len(updates) == 1, "Successful-subset response was truncated"
                assert b"unpack ok" in response, response
                return response
            finally:
                connection.close()

        response = request([(self.first, self.second, "refs/heads/main"),
                            (ZERO, self.second, "refs/heads/cas-good")])
        assert b"ng refs/heads/main " in response, response
        assert b"ok refs/heads/cas-good" in response, response
        assert self.git("--git-dir=" + str(bare), "rev-parse", "refs/heads/main").stdout.decode().strip() == self.second
        assert self.git("--git-dir=" + str(bare), "rev-parse", "refs/heads/cas-good").stdout.decode().strip() == self.second
        ops = self.operations(repo)
        assert ops[-1]["outcome"] == "recorded", ops
        changes = [event for event in self.events(repo) if event["operation_id"] == ops[-1]["id"]]
        assert [(event["ref_name"], event["old_oid"], event["new_oid"]) for event in changes] == [("refs/heads/cas-good", ZERO, self.second)], changes
        before = self.events(repo)
        response = request([(self.first, self.second, "refs/heads/main")])
        assert b"ng refs/heads/main " in response, response
        assert b"ok refs/heads/main" not in response, response
        assert self.events(repo) == before, "Repeated stale old/new request falsely published success"
        ops = self.operations(repo)
        assert ops[-1]["outcome"] in ("unknown", "no_ref_changes"), ops
        assert self.git("--git-dir=" + str(bare), "rev-parse", "refs/heads/main").stdout.decode().strip() == self.second
        return {"real_pkt_line_receive_pack": True, "stale_ref_rejected": True,
                "successful_subset": ["refs/heads/cas-good"],
                "repeated_stale_outcome": ops[-1]["outcome"], "current_oid_not_used_as_evidence": True}

    def deployed_hook_runner(self):
        original_binary = self.args.binary
        deployed_binary = self.root / "deployed-rootyard"
        self.stop()
        shutil.copy2(original_binary, deployed_binary)
        self.args.binary = str(deployed_binary)
        try:
            self.start()
            deployed_binary.unlink()
            # This simulates replacement/removal of an installation path,
            # without touching the shared target binary used by other tests.
            self.push("HEAD:runner-after-unlink")
            self.last_operation("recorded")
            assert self.ref("refs/heads/runner-after-unlink") == self.second
            hooks = self.root / "data/managed-hooks"
            assert (hooks / ".runner").is_file()
            (hooks / "pre-receive").unlink()
            before_ops, before_events = self.operations(), self.events()
            self.expect(self.repo["clone_path"] + "/git-receive-pack", 503,
                        token=self.alice, basic=True, method="POST", body=b"0000",
                        content_type="application/x-git-receive-pack-request")
            denied = self.push("HEAD:runner-missing-hook", check=False)
            assert denied.returncode != 0
            assert self.ref("refs/heads/runner-missing-hook") is None
            assert self.operations() == before_ops and self.events() == before_events
        finally:
            self.stop()
            self.args.binary = original_binary
            self.start()
        self.push("HEAD:runner-restored")
        self.last_operation("recorded")
        assert self.ref("refs/heads/runner-restored") == self.second
        return {"removed_deployment_binary_push_recorded": True,
                "missing_pre_receive_rejected_before_git": True,
                "startup_reinstalled_hook": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    for executable in ("git", "psql", args.binary):
        if not shutil.which(executable):
            parser.error("Required executable not found: " + executable)
    h = ReliabilityHarness(args)
    success = False
    try:
        for name, case in [
            ("fresh_migration_accounts", h.setup),
            ("upgrade_001_preserves_data", h.upgrade),
            ("repository_api", h.api),
            ("real_git_recorded_and_no_ref_changes", h.real_pushes),
            ("non_atomic_partial_success_subset", h.partial_push),
            ("loose_and_packed_deletion", h.deletions),
            ("owner_isolated_read_only_history", h.owner_api),
            ("real_receipt_sql_failure_restart_replay", h.publication_replay),
            ("transient_sql_failure_background_replay", h.runtime_publication_retry),
            ("outbox_idempotency_native_authority", h.outbox),
            ("admission_and_background_delivery", h.admission_and_background),
            ("ambiguous_evidence_never_infers_success", h.unknown_evidence),
            ("duplicate_receipt_has_no_delivery_or_effect", h.duplicate_receipt),
            ("oversized_ref_rejected_before_native_write", h.oversized_ref),
            ("oversized_batch_rejected_before_any_write", h.oversized_batch),
            ("unrelated_recovery_block_is_preserved", h.unrelated_recovery_block),
            ("real_stale_compare_swap_subset_and_repeat", h.stale_compare_swap),
            ("durable_hook_runner_and_missing_hook_guard", h.deployed_hook_runner),
        ]:
            h.case(name, case)
        success = True
    except Exception as error:
        print(h.redact(error), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as error:
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(error)))
            success = False
        report = dict(passed=success, cases=h.results, limitations=h.limits, runtime={
            "git_client": h.run(["git", "--version"]).stdout.decode().strip(),
            "git_server": h.run([h.env.get("ROOTYARD_GIT", "git"), "--version"]).stdout.decode().strip(),
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        })
        if args.keep:
            report["retained_directory"] = str(h.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
