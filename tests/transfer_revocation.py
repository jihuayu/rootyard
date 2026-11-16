#!/usr/bin/env python3
"""Native slow Git upload-pack transfer revocation on primary and CI mirror."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

from ci_mirror import MirrorHarness
import transfer_revocation_git_source as revocation_git_source
import transfer_revocation_observer as revocation_observer
import transfer_revocation_timing as revocation_timing
import transfer_revocation_transport as revocation_transport


class RevocationHarness(MirrorHarness):
    def barrier_available(self):
        repo = uuid.UUID(self.repo["id"])
        output = self.sql("BEGIN; SELECT pg_try_advisory_xact_lock("
            f"hashtextextended('rootyard-data-v1:{repo}', 0)); ROLLBACK")
        return "t" in output.splitlines()

    def _wait_no_owned_children(self, service_pids, timeout=2.5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            table = revocation_observer.read_proc_table(uid=os.geteuid())
            descendants = revocation_observer.descendant_pids(table, service_pids)
            if not any(table[pid].live for pid in descendants):
                return
            time.sleep(0.05)
        raise AssertionError("owned service descendant remained live after transfer cleanup")

    def _db_clock_sample(self):
        started = time.monotonic_ns()
        raw = self.sql("SELECT extract(epoch FROM clock_timestamp())")
        ended = time.monotonic_ns()
        return revocation_timing.DbClockSample(started, ended, float(raw))

    def _set_token_natural_expiry(self, token_id, seconds=8):
        token = uuid.UUID(token_id)
        self.sql(
            "UPDATE tokens SET expires_at=to_timestamp(floor(extract(epoch FROM clock_timestamp()))"
            f" + {int(seconds)}) WHERE id='{token}'"
        )
        return float(self.sql(f"SELECT extract(epoch FROM expires_at) FROM tokens WHERE id='{token}'"))

    def _git_transfer(self, base, path, token, target, payload_bytes, *, trigger=None,
                      natural_expiry=None, service_pid=None):
        def packet(payload):
            return f"{len(payload) + 4:04x}".encode() + payload

        body = packet(f"want {target} side-band-64k\n".encode()) + b"0000" + packet(b"done\n")
        result = revocation_transport.run_timed_transfer(
            base=base,
            path=path + "/git-upload-pack",
            method="POST",
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/x-git-upload-pack-request",
            },
            body=body,
            expected_size=payload_bytes + 8 * 1024 * 1024,
            initial_bytes=4096,
            framing="chunked",
            service_pid=service_pid or self.proc.pid,
            bound_ms=1200,
            trigger=trigger,
            trigger_kind="committed_mutation",
            natural_expiry=natural_expiry,
            post_pause_ms=800,
            rcvbuf=16 * 1024,
            require_backpressure=True,
            require_group=True,
            active_barrier_check=lambda: not self.barrier_available(),
            source_witness_factory=lambda observer: revocation_git_source.GitSourceWitness(
                service_pid or self.proc.pid, observer.identities,
                arch=os.uname().machine,
            ),
            transfer_kind="git",
        )
        result["configured_bound_proven"] = bool(result["configured_bound_proven"])
        result["received_before_abort"] = result["client_stop"]["received_bytes"]
        result["abort_seconds"] = round(result["client_stop_after_lower_ms"] / 1000, 3)
        return result

    def stream_until_revoked(self, base, path, token, target, revoke, *, service_pid=None):
        return self._git_transfer(
            base, path, token, target, 32 * 1024 * 1024,
            trigger=revoke, service_pid=service_pid or self.proc.pid,
        )

    def stream_until_expiry(self, base, path, token, target, expiry_clock, *, service_pid=None):
        return self._git_transfer(
            base, path, token, target, 32 * 1024 * 1024,
            natural_expiry=expiry_clock, service_pid=service_pid or self.proc.pid,
        )

    def active_transfer_revocation(self):
        audience = str(uuid.uuid4())
        self.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = audience
        self.mirror_env["ROOTYARD_CI_MIRROR_AUDIENCE"] = audience
        self.env["ROOTYARD_TRANSFER_REVOCATION_BOUND_MS"] = "1200"
        self.mirror_env["ROOTYARD_TRANSFER_REVOCATION_BOUND_MS"] = "1200"
        self.setup_mirror()
        writer = self.account("create-token", "alice")
        expiring = self.account("create-token", "alice")
        with open(self.work / "large.bin", "wb") as output:
            for _ in range(32):
                output.write(os.urandom(1024 * 1024))
        self.git("add", "large.bin", cwd=self.work)
        self.git("commit", "-m", "large transfer", cwd=self.work)
        target = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
        self.sync()

        def revoke_human():
            self.cli("revoke-token", writer["token_id"])

        exp_epoch = self._set_token_natural_expiry(expiring["token_id"], seconds=10)
        expiry_before = self._db_clock_sample()
        expiry_before_clock = revocation_timing.reconcile_expiry([expiry_before], exp_epoch)

        human = self.stream_until_revoked(self.base, "/git/alice/demo.git",
                                          writer["token"], target, revoke_human,
                                          service_pid=self.proc.pid)
        expired = self.stream_until_expiry(self.base, "/git/alice/demo.git",
                                           expiring["token"], target, expiry_before_clock,
                                           service_pid=self.proc.pid)
        expiry_after = self._db_clock_sample()
        expired = revocation_timing.apply_natural_expiry_clock(
            expired,
            revocation_timing.reconcile_expiry([expiry_before, expiry_after], exp_epoch),
            1200,
        )
        self._wait_no_owned_children([self.proc.pid])
        self.expect("/api/repos/alice/demo/collaborators/bob", (200, 201), method="PUT",
                    token=self.alice, body={"role": "read", "username": "bob"})
        try:
            member_removed = self.stream_until_revoked(
                self.base, "/git/alice/demo.git", self.bob["token"], target,
                lambda: self.expect("/api/repos/alice/demo/collaborators/bob", 200, method="DELETE", token=self.alice))
        finally:
            self.http("/api/repos/alice/demo/collaborators/bob", method="DELETE", token=self.alice)
        self._wait_no_owned_children([self.proc.pid])

        repo_id = self.repo["id"]
        try:
            gen_changed = self.stream_until_revoked(
                self.base, "/git/alice/demo.git", self.reader["token"], target,
                lambda: self.sql(f"UPDATE repositories SET storage_generation=2 WHERE id='{repo_id}'"))
        finally:
            self.sql(f"UPDATE repositories SET storage_generation=1 WHERE id='{repo_id}'")
        self._wait_no_owned_children([self.proc.pid])

        job = str(uuid.uuid4())
        self.create_pin(oid=target, job=job)
        now = int(time.time())
        issue = json.loads(self.expect("/api/repos/alice/demo/ci-checkouts", 200,
            token=self.alice, method="POST", body={"job_id": job, "target_oid": target,
                "storage_generation": 1, "mirror_audience": audience,
                "expires_unix": now + 600}))
        credential = issue["token"]

        def cancel_job():
            self.expect(f"/api/repos/alice/demo/ci-checkouts/{job}/cancel", 200,
                        token=self.alice, method="POST", body=b"")

        mirror = self.stream_until_revoked(self.mirror_base, self.path(target),
                                           credential, target, cancel_job,
                                           service_pid=self.mirror_proc.pid)
        self._wait_no_owned_children([self.proc.pid, self.mirror_proc.pid])
        results = {
            "human_token": human,
            "expired_token": expired,
            "removed_collaborator": member_removed,
            "generation_changed": gen_changed,
            "cancelled_ci_job": mirror,
        }
        proofs = {name: bool(result["configured_bound_proven"]) for name, result in results.items()}
        unproven = sorted(name for name, proven in proofs.items() if not proven)
        assert not unproven, {"configured_bound_ms": 1200, "unproven_subcases": unproven}
        results["bound_proof_summary"] = {
            "configured_bound_ms": 1200,
            "subcases": proofs,
            "all_proven": True,
        }
        return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = RevocationHarness(args)
    success = False
    try:
        harness.case("active_transfer_revocation", harness.active_transfer_revocation)
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        harness.cleanup()
        report = {"passed": success, "cases": harness.results,
                  "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
