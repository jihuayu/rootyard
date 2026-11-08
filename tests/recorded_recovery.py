#!/usr/bin/env python3
"""Issue #96: native recorded-receipt settlement after a revoked token.

Reuses ``ReliabilityHarness`` (real server, real Git, real PostgreSQL) and the
same real SQL fault setup as ``reliability.py::publication_replay``: a BEFORE
trigger rejects a terminal ``git_operations`` settlement, so native Git has
already written ``post-receive.json`` and the ``finished`` marker while the
server is stopped before SQL publication.

The difference under test: the push token is revoked *after* the real receipt
exists and the repository is left ``recovering``/``push_outcome_unknown``. The
restart must settle from the journal-proven recorded receipt (ADMITTED ->
COMMITTED plus outbox and ``git_operations``) and return the repository to
``ready`` without a new grant. The report records the matching receipt and the
journal evidence digest, and never includes the DSN, environment or token.

Native execution requires a built binary and ``ROOTYARD_TEST_DATABASE_URL``.
It is intentionally not executed by the implementation environment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

from reliability import ReliabilityHarness


class RecordedRecoveryHarness(ReliabilityHarness):
    def __init__(self, args):
        super().__init__(args)
        self.limits = [
            "This harness kills the service process; it does not emulate kernel or power loss.",
            "The SQL fault is an injected BEFORE trigger on git_operations, not a real disk failure.",
            "It proves SQL settlement from the real native post-receive receipt; it does not repeat the failed write.",
            "No external consumer exactly-once delivery is claimed.",
        ]

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

    def native_fixture(self):
        # Real server, clone and native pushes so the recorded case starts from
        # an actual receipt-producing workflow rather than a synthetic ref.
        self.api()
        self.roundtrip()
        return {"fixture_repo": self.repo["id"], "second_oid": self.second}

    def recorded_settlement_with_revoked_token(self):
        repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice,
                                      body={"name": "recorded-recovery"}))
        # A dedicated token is revoked after the push, exactly like an operator
        # or expiry revoking a PAT between native publication and restart.
        push_token = self.account("create-token", "alice")
        expected_ref = "refs/heads/recorded-recovery"
        journal = self.root / "data/journal" / repo["id"]
        path = None
        self.sql("CREATE FUNCTION test_fail_recorded_settle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                 "IF NEW.outcome <> 'unknown' THEN RAISE EXCEPTION 'test recorded settlement unavailable'; "
                 "END IF; RETURN NEW; END $$; CREATE TRIGGER test_fail_recorded_settle BEFORE INSERT OR UPDATE "
                 "ON git_operations FOR EACH ROW EXECUTE FUNCTION test_fail_recorded_settle()")
        try:
            self.git("push", self.base + repo["clone_path"], "HEAD:recorded-recovery",
                     cwd=self.work, token=push_token, check=False)
            pending = [item for item in journal.iterdir() if item.is_dir() and not item.name.startswith(".")]
            assert len(pending) == 1, "Expected one retained real native operation"
            path = pending[0]
            metadata = json.loads((path / "operation.json").read_text())
            receipt = json.loads((path / "post-receive.json").read_text())
            assert (path / "finished").exists()
            assert [(item["ref_name"], item["new_oid"]) for item in receipt] == [(expected_ref, self.second)]
            bare = self.root / "data" / "repos" / (repo["id"] + ".git")
            observed = self.git("--git-dir=" + str(bare), "rev-parse", "--verify", expected_ref)
            assert observed.stdout.decode().strip() == self.second
            self.stop(hard=True)
        finally:
            self.stop(hard=True)
            self.sql("DROP TRIGGER test_fail_recorded_settle ON git_operations; "
                     "DROP FUNCTION test_fail_recorded_settle()")
        assert path is not None, "Native push did not retain a journal"
        receipt_digest = hashlib.sha256((path / "post-receive.json").read_bytes()).hexdigest()
        evidence_digest = self.journal_digest(path)
        admitted_refs = self.sql(
            "SELECT array_to_json(ref_names) FROM git_ref_admissions WHERE writer_id='" + metadata["id"] + "'")
        assert json.loads(admitted_refs) == [expected_ref], admitted_refs
        # Emulate interrupted completion plus the conservative unknown row and
        # the temporary recovery flag that blocked the original settlement.
        (path / "finished").unlink()
        self.sql("INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,"
                 "storage_generation,evidence,outcome) VALUES('" + metadata["id"] + "','" + metadata["repository_id"] +
                 "','" + metadata["actor_id"] + "','" + metadata["token_id"] + "','alice'," +
                 str(metadata["sequence"]) + ",1,'{}','unknown')")
        self.sql("UPDATE repositories SET state='recovering',recovery_reason='push_outcome_unknown' WHERE id='" +
                 repo["id"] + "'")
        self.sql("UPDATE tokens SET revoked=true WHERE id='" + metadata["token_id"] + "'")
        self.start()
        assert self.sql("SELECT state FROM repositories WHERE id='" + repo["id"] + "'") == "ready"
        assert self.sql("SELECT recovery_reason IS NULL FROM repositories WHERE id='" + repo["id"] + "'") == "t"
        recovered = [row for row in self.operations(repo) if row["id"] == metadata["id"]]
        assert len(recovered) == 1 and recovered[0]["outcome"] == "recorded", recovered
        events = [event for event in self.events(repo) if event["operation_id"] == metadata["id"]]
        assert len(events) == len(receipt) == 1
        assert (events[0]["old_oid"], events[0]["new_oid"]) == ("0" * 40, self.second)
        assert not path.exists(), "SQL-committed journal should be retired"
        assert self.sql("SELECT state FROM git_ref_admissions WHERE writer_id='" + metadata["id"] + "'") == "COMMITTED"
        before = self.events(repo)
        self.stop(hard=True)
        self.start()
        assert self.events(repo) == before, "Restart duplicated or changed event identities"
        assert self.sql("SELECT outcome FROM git_operations WHERE id='" + metadata["id"] + "'") == "recorded"
        return {
            "actual_native_push": True,
            "required_matching_receipt": True,
            "receipt_sha256": receipt_digest,
            "journal_evidence_digest": evidence_digest,
            "admitted_refs": [expected_ref],
            "receipt_refs": [item["ref_name"] for item in receipt],
            "token_revoked_before_restart": True,
            "admission_state": "COMMITTED",
            "operation_outcome": "recorded",
            "repository_ready": True,
            "restart_idempotent": True,
        }


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
    h = RecordedRecoveryHarness(args)
    success = False
    try:
        h.case("fresh_migration_accounts", h.setup)
        h.case("native_repository_fixture", h.native_fixture)
        h.case("recorded_receipt_sets_revoked_token_operation", h.recorded_settlement_with_revoked_token)
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
