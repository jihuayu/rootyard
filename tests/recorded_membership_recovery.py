#!/usr/bin/env python3
"""Issue #98: historical Git projection after membership withdrawal.

This native harness grants a real collaborator (or organization member) write
access through the HTTP API, performs a real Git push, and injects a SQL fault
on the *terminal* git_operations settlement only after Git has written its
durable post-receive receipt. The owner then removes the grant through the real
API. The harness retains the actual journal bytes, removes them while a
short-lived server performs the removal, marks the repository
recovering/push_outcome_unknown, restores the exact retained journal and
restarts.

Expected: the past receipt is projected as COMMITTED/recorded with its outbox
event while the repository becomes ready, without restoring access; a new push
is still denied. The retained journal is replayed a second time to require the
exact terminal-admission replay path. SQL negative cases prove a mismatched
ledger cannot authorize another actor/operation/generation and that generic
non-admitted Git/Forge publication stays strict.

Requires a built binary, PostgreSQL and Git; values are redacted in reports.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sys
import time
import uuid

from reliability import ReliabilityHarness

ZERO = "0" * 40


class MembershipRecoveryHarness(ReliabilityHarness):
    def __init__(self, args):
        super().__init__(args)
        self.limits = [
            "This harness kills the service process; it does not emulate kernel or power loss.",
            "The SQL fault is an injected BEFORE trigger on git_operations, not a disk failure.",
            "The retained journal is the real native post-receive evidence; no synthetic push claim is used.",
            "No external consumer exactly-once delivery is claimed.",
        ]

    def sql_fails(self, query, expected_sqlstate="23514"):
        env = self.env.copy()
        env["PGDATABASE"] = self.db
        result = self.run(
            ["psql", "--dbname", env["PGDATABASE"], "-X", "-v", "ON_ERROR_STOP=1",
             "-v", "VERBOSITY=verbose", "-At", "-c", query],
            env=env, check=False)
        assert result.returncode != 0, "SQL unexpectedly succeeded: " + query
        diagnostics = result.stderr.decode(errors="replace")
        assert re.search(r"ERROR:\s+" + re.escape(expected_sqlstate) + r"\b", diagnostics), (
            "expected SQLSTATE " + expected_sqlstate + ", got: " + diagnostics[-2000:])
        return diagnostics

    @staticmethod
    def journal_digest(path):
        digest = hashlib.sha256()
        for name in ("operation.json", "pre-receive.json", "post-receive.json", "finished"):
            record = path / name
            if record.exists():
                digest.update(name.encode() + b"\0" + record.read_bytes())
        for event in sorted(path.glob("*.event.json")):
            digest.update(event.name.encode() + b"\0" + event.read_bytes())
        return digest.hexdigest()

    def native_ref(self, repo, name):
        bare = self.root / "data" / "repos" / (repo["id"] + ".git")
        result = self.git("--git-dir=" + str(bare), "rev-parse", "--verify", name, check=False)
        return result.stdout.decode().strip() if result.returncode == 0 else None

    def wait_ready(self, repo, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.sql("SELECT state || ':' || COALESCE(recovery_reason,'') FROM repositories WHERE id='" +
                             repo["id"] + "'")
            if state == "ready:":
                return
            time.sleep(.1)
        raise AssertionError("repository did not recover to ready: " + state)

    def operation_count(self, repo):
        return int(self.sql("SELECT count(*) FROM git_operations WHERE repository_id='" + repo["id"] + "'"))

    def admission_count(self, repo):
        return int(self.sql("SELECT count(*) FROM git_ref_admissions WHERE repository_id='" + repo["id"] + "'"))

    def faulted_push_and_withdraw(self, repo, branch, remove_access, exact_replay=True):
        remote = self.base + repo["clone_path"]
        (self.work / "hello.txt").write_text("membership recovery " + branch + "\n")
        self.git("commit", "-am", "membership " + branch, cwd=self.work)
        pushed = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.sql(
            "CREATE FUNCTION test_fail_terminal_membership_settle() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN IF NEW.outcome <> 'unknown' THEN "
            "RAISE EXCEPTION 'test terminal membership settlement unavailable'; END IF; RETURN NEW; END $$; "
            "CREATE TRIGGER test_fail_terminal_membership_settle BEFORE INSERT OR UPDATE ON git_operations "
            "FOR EACH ROW EXECUTE FUNCTION test_fail_terminal_membership_settle()")
        path = held = None
        try:
            result = self.git("push", remote, "HEAD:" + branch, cwd=self.work, token=self.bob, check=False)
            assert result.returncode != 0, "faulted terminal push unexpectedly succeeded"
            journal = self.root / "data/journal" / repo["id"]
            pending = [item for item in journal.iterdir() if item.is_dir() and not item.name.startswith(".")]
            assert len(pending) == 1, "Expected one retained real native operation"
            path = pending[0]
            metadata = json.loads((path / "operation.json").read_text())
            receipt = json.loads((path / "post-receive.json").read_text())
            assert (path / "finished").exists()
            assert [(item["ref_name"], item["new_oid"]) for item in receipt] == [("refs/heads/" + branch, pushed)]
            assert self.native_ref(repo, "refs/heads/" + branch) == pushed
            self.stop(hard=True)
        finally:
            self.stop(hard=True)
            self.sql("DROP TRIGGER IF EXISTS test_fail_terminal_membership_settle ON git_operations; "
                     "DROP FUNCTION IF EXISTS test_fail_terminal_membership_settle()")
        assert path is not None, "Native push did not retain a journal"
        receipt_digest = hashlib.sha256((path / "post-receive.json").read_bytes()).hexdigest()
        held = self.root / ("held-journal-" + repo["id"])
        shutil.copytree(path, held)
        journal_digest = self.journal_digest(held)
        shutil.rmtree(path)
        self.sql("UPDATE repositories SET state='recovering',recovery_reason='push_outcome_unknown' WHERE id='" +
                 repo["id"] + "'")
        # A short-lived server performs the real API withdrawal while the
        # retained journal is outside the data directory, so startup cannot
        # settle the receipt before the grant is gone.
        self.start()
        remove_access()
        self.stop(hard=True)
        self.sql("UPDATE repositories SET state='recovering',recovery_reason='push_outcome_unknown' WHERE id='" +
                 repo["id"] + "'")
        target = (self.root / "data/journal" / repo["id"] / path.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(held, target)
        assert self.journal_digest(target) == journal_digest
        self.start()
        self.wait_ready(repo)
        operation = [row for row in self.operations(repo) if row["id"] == metadata["id"]]
        assert len(operation) == 1 and operation[0]["outcome"] == "recorded", operation
        events = [event for event in self.events(repo) if event["operation_id"] == metadata["id"]]
        assert len(events) == len(receipt) == 1
        assert (events[0]["old_oid"], events[0]["new_oid"]) == (ZERO, pushed)
        assert not target.exists(), "SQL-committed journal should be retired"
        assert self.sql("SELECT state FROM git_ref_admissions WHERE writer_id='" + metadata["id"] + "'") == "COMMITTED"
        assert self.native_ref(repo, "refs/heads/" + branch) == pushed
        before_ops = self.operation_count(repo)
        before_admissions = self.admission_count(repo)
        denied = self.git("push", remote, "HEAD:" + branch + "-after-withdrawal", cwd=self.work,
                          token=self.bob, check=False)
        assert denied.returncode != 0, "removed collaborator still pushed"
        assert self.operation_count(repo) == before_ops and self.admission_count(repo) == before_admissions
        assert self.native_ref(repo, "refs/heads/" + branch + "-after-withdrawal") is None
        before_events = self.events(repo)
        replay = False
        if exact_replay:
            shutil.copytree(held, target)
            assert self.journal_digest(target) == journal_digest
            self.stop(hard=True)
            self.start()
            self.wait_ready(repo)
            assert not target.exists(), "terminal replay journal should be retired"
            assert self.sql("SELECT state FROM git_ref_admissions WHERE writer_id='" + metadata["id"] + "'") == "COMMITTED"
            assert self.events(repo) == before_events, "terminal replay duplicated or changed events"
            assert self.operation_count(repo) == before_ops
            replay = True
        return dict(metadata=metadata, receipt_digest=receipt_digest,
                    journal_evidence_digest=journal_digest,
                    operation_outcome="recorded", admission_state="COMMITTED",
                    repository_ready=True, access_restored=False,
                    new_push_denied=True, exact_terminal_replay=replay,
                    replay_copy_is_actual_journal=True)

    def terminal_ledger_negatives(self, repo, operation_id):
        alice_id = self.alice["user_id"]
        alice_token = self.alice["token_id"]
        bob_id = self.bob["user_id"]
        bob_token = self.bob["token_id"]
        # Bob has already lost repository access in the caller. A different,
        # non-owner user and a second Bob token let the update cases prove the
        # immutable actor/token binding without the owner-membership shortcut.
        mallory_id = self.account("create-user", "mallory")["user_id"]
        bob_alt_token = self.account("create-token", "bob")["token_id"]
        repo_id = repo["id"]
        generation = int(self.sql("SELECT storage_generation FROM repositories WHERE id='" + repo_id + "'"))
        fake = str(uuid.uuid4())
        ledger = []

        def add_ledger(writer, actor, token, state):
            suffix = "" if state == "ADMITTED" else ",settled_at"
            value = "" if state == "ADMITTED" else ",clock_timestamp()"
            self.sql("INSERT INTO git_ref_admissions(writer_id,repository_id,shard_epoch,actor_id,token_id,"
                     "ref_names,state" + suffix + ") VALUES('" + writer + "','" + repo_id + "',1,'" + actor +
                     "','" + token + "',ARRAY['refs/heads/main'],'" + state + "'" + value + ")")
            ledger.append(writer)

        try:
            # A new non-admitted human Git operation stays strictly denied.
            self.sql_fails(
                "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,"
                "storage_generation,evidence,outcome) VALUES('" + fake + "','" + repo_id + "','" + bob_id +
                "','" + bob_token + "','bob',999,1,'{}','recorded')")
            # A terminal ledger owned by another actor/token cannot authorize Bob.
            other = str(uuid.uuid4())
            add_ledger(other, alice_id, alice_token, "COMMITTED")
            self.sql_fails(
                "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,"
                "storage_generation,evidence,outcome) VALUES('" + other + "','" + repo_id + "','" + bob_id +
                "','" + bob_token + "','bob',998,1,'{}','recorded')")
            # A matching Bob ledger cannot authorize a first projection at a
            # generation other than the current repository generation.
            bob_ledger = str(uuid.uuid4())
            add_ledger(bob_ledger, bob_id, bob_token, "COMMITTED")
            self.sql_fails(
                "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,"
                "storage_generation,evidence,outcome) VALUES('" + bob_ledger + "','" + repo_id + "','" + bob_id +
                "','" + bob_token + "','bob',997," + str(generation + 1) + ",'{}','recorded')")
            # COMMITTED does not authorize no_ref_changes. Bob remains
            # non-member, so only the terminal-ledger exemption could allow it.
            committed = str(uuid.uuid4())
            add_ledger(committed, bob_id, bob_token, "COMMITTED")
            self.sql_fails(
                "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,"
                "storage_generation,evidence,outcome) VALUES('" + committed + "','" + repo_id + "','" + bob_id +
                "','" + bob_token + "','bob',996," + str(generation) + ",'{}','no_ref_changes')")
            # ADMITTED and FENCED_ABORTED ledgers are not terminal authority.
            admitted = str(uuid.uuid4())
            add_ledger(admitted, bob_id, bob_token, "ADMITTED")
            self.sql_fails(
                "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,"
                "storage_generation,evidence,outcome) VALUES('" + admitted + "','" + repo_id + "','" + bob_id +
                "','" + bob_token + "','bob',995," + str(generation) + ",'{}','recorded')")
            fenced = str(uuid.uuid4())
            add_ledger(fenced, bob_id, bob_token, "FENCED_ABORTED")
            self.sql_fails(
                "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,"
                "storage_generation,evidence,outcome) VALUES('" + fenced + "','" + repo_id + "','" + bob_id +
                "','" + bob_token + "','bob',994," + str(generation) + ",'{}','recorded')")
            # The real terminal row is immutable in identity, generation,
            # sequence, name, token and outcome once membership is gone.
            for assignment in ("storage_generation=storage_generation+1", "sequence=sequence+1",
                               "actor_name='mallory'", "actor_id='" + mallory_id + "'",
                               "token_id='" + bob_alt_token + "'", "outcome='no_ref_changes'",
                               "evidence='{}'::jsonb", "settled_at=settled_at+interval '1 second'",
                               "created_at=created_at+interval '1 second'"):
                self.sql_fails("UPDATE git_operations SET " + assignment + " WHERE id='" + operation_id + "'")
        finally:
            for writer in ledger:
                self.sql("DELETE FROM git_ref_admissions WHERE writer_id='" + writer + "'")
        return dict(non_admitted_new_git_denied=True, foreign_actor_ledger_denied=True,
                    nonterminal_ledger_denied=True, fenced_ledger_denied=True,
                    terminal_identity_generation_sequence_name_binding=True)

    def collaborator_case(self):
        self.expect("/api/repos/alice/demo/collaborators/bob", (200, 201), method="PUT",
                    token=self.alice, body={"role": "write"})
        assert self.sql("SELECT role FROM repository_collaborators WHERE repository_id='" +
                        self.repo["id"] + "' AND user_id='" + self.bob["user_id"] + "'") == "write"

        def remove():
            self.expect("/api/repos/alice/demo/collaborators/bob", 200, method="DELETE", token=self.alice)

        result = self.faulted_push_and_withdraw(self.repo, "bob-collab", remove)
        assert self.sql("SELECT count(*) FROM repository_collaborators WHERE repository_id='" +
                        self.repo["id"] + "' AND user_id='" + self.bob["user_id"] + "'") == "0"
        self.expect("/api/repos/alice/demo", (403, 404), token=self.bob)
        self.expect("/api/repos/alice/demo/issues", (403, 404), method="POST", token=self.bob,
                    body={"title": "denied after withdrawal"})
        result["removal"] = "api_collaborator_delete"
        result["generic_forge_denied"] = True
        result.update(self.terminal_ledger_negatives(self.repo, result["metadata"]["id"]))
        return result

    def organization_member_case(self):
        slug = "membership-org"
        self.expect("/api/orgs", 201, method="POST", token=self.alice, body={"slug": slug})
        org_id = self.sql("SELECT id FROM namespaces WHERE kind='organization' AND slug='" + slug + "'")
        self.expect("/api/orgs/" + slug + "/members/bob", (200, 201), method="PUT", token=self.alice,
                    body={"role": "write"})
        repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice,
                                      body={"owner": slug, "name": "org-demo"}))
        assert repo["state"] == "ready", repo
        assert repo["clone_path"] == "/git/" + slug + "/org-demo.git"
        assert self.sql("SELECT role FROM organization_memberships WHERE organization_id='" + org_id +
                        "' AND user_id='" + self.bob["user_id"] + "'") == "write"

        def remove():
            self.expect("/api/orgs/" + slug + "/members/bob", 200, method="DELETE", token=self.alice)

        result = self.faulted_push_and_withdraw(repo, "bob-org", remove, exact_replay=False)
        assert self.sql("SELECT count(*) FROM organization_memberships WHERE organization_id='" +
                        org_id + "' AND user_id='" + self.bob["user_id"] + "'") == "0"
        self.expect("/api/repos/" + slug + "/org-demo", (403, 404), token=self.bob)
        result["removal"] = "api_organization_member_delete"
        return result


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
    h = MembershipRecoveryHarness(args)
    success = False
    try:
        h.case("fresh_migration_accounts", h.setup)
        h.case("repository_api_and_real_pushes", h.api)
        h.case("real_alice_history_fixture", h.roundtrip)
        h.case("collaborator_terminal_receipt_survives_withdrawal", h.collaborator_case)
        h.case("organization_member_terminal_receipt_survives_withdrawal",
               h.organization_member_case)
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
            "native_executed_by_implementer": False,
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
