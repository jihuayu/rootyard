#!/usr/bin/env python3
"""Native slow Git upload-pack transfer revocation on primary and CI mirror."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import time
import urllib.parse
import uuid

from ci_mirror import MirrorHarness


def packet(payload):
    return f"{len(payload) + 4:04x}".encode() + payload


class RevocationHarness(MirrorHarness):
    def stream_until_revoked(self, base, path, token, target, revoke):
        url = urllib.parse.urlsplit(base)
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
        body = packet(f"want {target} side-band-64k\n".encode()) + b"0000" + packet(b"done\n")
        headers = {"Authorization": "Bearer " + token,
                   "Content-Type": "application/x-git-upload-pack-request"}
        try:
            connection.request("POST", path + "/git-upload-pack", body=body, headers=headers)
            response = connection.getresponse()
            assert response.status == 200, (response.status, response.read(200))
            first = response.read(4096)
            assert first, "upload-pack returned no data before revocation"
            received = len(first)
            started = time.monotonic()
            revoke()
            interrupted = False
            while time.monotonic() - started < 5:
                try:
                    chunk = response.read(64 * 1024)
                except (http.client.IncompleteRead, OSError):
                    interrupted = True
                    break
                if not chunk:
                    break
                received += len(chunk)
                time.sleep(0.02)
            elapsed = time.monotonic() - started
            assert interrupted, f"Git transfer completed or stalled after revocation ({received} bytes)"
            assert received < 32 * 1024 * 1024, "entire pack escaped after revocation"
            assert elapsed < 5, f"transfer cancellation took {elapsed:.2f}s"
            return {"received_before_abort": received, "abort_seconds": round(elapsed, 3)}
        finally:
            connection.close()

    def active_transfer_revocation(self):
        audience = str(uuid.uuid4())
        self.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = audience
        self.mirror_env["ROOTYARD_CI_MIRROR_AUDIENCE"] = audience
        self.setup_mirror()
        writer = self.account("create-token", "alice")
        with open(self.work / "large.bin", "wb") as output:
            for _ in range(32):
                output.write(os.urandom(1024 * 1024))
        self.git("add", "large.bin", cwd=self.work)
        self.git("commit", "-m", "large transfer", cwd=self.work)
        target = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
        self.sync()

        def revoke_human():
            self.sql(f"UPDATE tokens SET revoked=true WHERE id='{uuid.UUID(writer['token_id'])}'")

        human = self.stream_until_revoked(self.base, "/git/alice/demo.git",
                                          writer["token"], target, revoke_human)
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
                                           credential, target, cancel_job)
        return {"human_token": human, "cancelled_ci_job": mirror}


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
