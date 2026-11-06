#!/usr/bin/env python3
"""Prove repository membership writes serialize before actor-role lock upgrades."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from members import MembersHarness


class PolicyLockHarness(MembersHarness):
    def reciprocal_admin_mutations(self):
        self.setup()
        for username in ("bob", "carol"):
            self.document(f"{self.collabspath}/{username}", code=201, method="PUT",
                          json_body={"role": "admin"})
        p = subprocess.Popen(["psql", "--dbname", self.db, "-X", "-qAt",
                              "-v", "ON_ERROR_STOP=1"], env=self.env,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        try:
            p.stdin.write("BEGIN; SELECT pg_advisory_xact_lock(hashtextextended('alice/forge', 7329)); SELECT pg_backend_pid();\n")
            p.stdin.flush()
            assert select.select([p.stdout], [], [], 5)[0], "fixture lock did not start"
            pid = p.stdout.readline().strip()
            if not pid:
                pid = p.stdout.readline().strip()
            blocker_pid = int(pid)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                jobs = [
                    executor.submit(self.http, f"{self.collabspath}/carol", token=self.bob,
                                    method="PUT", body={"role": "admin", "expected_version": 1}),
                    executor.submit(self.http, f"{self.collabspath}/bob", token=self.carol,
                                    method="PUT", body={"role": "admin", "expected_version": 1}),
                ]
                deadline = time.monotonic() + 5
                waiters = 0
                while time.monotonic() < deadline and not any(job.done() for job in jobs):
                    waiters = int(self.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND " + str(blocker_pid) + " = ANY(pg_blocking_pids(pid)) AND query LIKE '%pg_advisory_xact_lock%'"))
                    if waiters == 2:
                        break
                    time.sleep(.05)
                p.stdin.write("COMMIT;\n")
                p.stdin.flush()
                statuses = [job.result(timeout=10)[0] for job in jobs]
            assert waiters == 2, f"both role mutations did not queue before actor-role locks: {waiters}"
            assert statuses == [200, 200], statuses
            for username in ("bob", "carol"):
                row = self.document(f"{self.collabspath}/{username}")
                assert row["role"] == "admin" and row["version"] == 2
            return {"queued_before_role_upgrade": 2, "both_admin_mutations_committed": True}
        finally:
            if p.poll() is None:
                p.stdin.write("ROLLBACK;\\q\n")
                p.stdin.flush()
                p.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    h = PolicyLockHarness(args)
    passed = False
    try:
        h.case("reciprocal_admin_mutations", h.reciprocal_admin_mutations)
        passed = True
    except Exception:
        print(h.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        h.cleanup()
        report = {"passed": passed, "cases": h.results,
                  "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
