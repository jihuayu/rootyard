"""Native bwrap sandbox lifecycle over the Rust HTTP service and PostgreSQL."""
import argparse
import base64
import json
import os
import time
import unittest
from pathlib import Path

from tests.e2e import Harness

BINARY = os.environ.get("ROOTYARD_BINARY", "target/debug/rootyard")


def harness(extra_env=None):
    h = Harness(argparse.Namespace(binary=BINARY, keep=os.environ.get("ROOTYARD_KEEP_TEST") == "1"))
    h.env["ROOTYARD_SANDBOX_MODE"] = "dev"
    h.env.update(extra_env or {})
    return h


def wait_for(predicate, timeout=20, interval=0.1, message="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("timed out waiting for " + message)


def wait_done(h, job, timeout=25):
    def terminal():
        data = json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}", 200, token=h.alice))
        return data if data["state"] not in ("queued", "preparing", "running") else None

    return wait_for(terminal, timeout=timeout, message="sandbox job terminal state")


def logs_of(h, job):
    payload = json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}/logs", 200, token=h.alice))
    return base64.b64decode(payload["stdout_base64"]), base64.b64decode(payload["stderr_base64"])


def process_alive(pid):
    return Path(f"/proc/{pid}").exists()


def no_cmdline_contains(marker):
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if marker in cmdline:
            return False
    return True


def no_process_references(path):
    needle = str(path).encode()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if needle in cmdline:
            return False
    return True


class SandboxServiceTest(unittest.TestCase):
    def test_isolated_jobs_logs_artifacts_cancel_and_timeout(self):
        h = harness()
        try:
            h.setup()
            h.api()
            h.roundtrip()
            h.stop()
            h.sql("ALTER TABLE sandbox_jobs DROP COLUMN terminal; DELETE FROM schema_migrations WHERE version=116")
            h.start()
            self.assertEqual(
                h.sql(
                    "SELECT count(*) FROM information_schema.columns "
                    "WHERE table_name='sandbox_jobs' AND column_name='terminal'"
                ),
                "1",
            )
            ws = json.loads(
                h.expect(
                    "/api/workspaces",
                    201,
                    token=h.alice,
                    method="POST",
                    body={"owner": "alice", "repository": "demo", "agent_id": "sandbox-parent", "base_oid": h.second},
                    extra_headers={"Idempotency-Key": "sandbox-parent"},
                )
            )

            def start(argv, timeout=10, terminal=False):
                return json.loads(
                    h.expect(
                        f"/api/workspaces/{ws['id']}/sandbox-jobs",
                        201,
                        token=h.alice,
                        method="POST",
                        body={"argv": argv, "timeout_seconds": timeout, "lease_epoch": 1, "terminal": terminal},
                    )
                )

            # Two real tasks. Each must see the pristine checkout, may only
            # write its own private workspace and its own /artifacts export.
            command = (
                "printf {mark} > task.txt; mkdir -p /artifacts; cp task.txt /artifacts/result.txt; "
                "ln -s ../task.txt /artifacts/escape; cat hello.txt; env | sort; "
                "test ! -e /root; test ! -e /workspace/shared/rootyard-env.sh; "
                "test ! -e /var/run/docker.sock; test -z \"$DATABASE_URL\"; "
                "test -z \"$ROOTYARD_SANDBOX_MODE\"; "
                "! grep -qs 'job-other' /workspace /tmp /home; "
                "test ! -e /workspace/job-other.txt"
            )
            jobs = [start(["/bin/sh", "-c", command.format(mark=f"job-{mark}")]) for mark in ("one", "two")]
            for mark, job in zip(("one", "two"), jobs):
                state = wait_done(h, job)["state"]
                stdout, stderr = logs_of(h, job)
                self.assertEqual(state, "succeeded", stderr)
                self.assertIn(b"second", stdout)
                self.assertIn(b"PATH=/usr/bin:/bin", stdout)
                self.assertIn(b"HOME=/home", stdout)
                self.assertIn(b"TMPDIR=/tmp", stdout)
                self.assertNotIn(b"DATABASE_URL", stdout)
                self.assertNotIn(b"ROOTYARD_", stdout)
                self.assertEqual(h.http(f"/api/sandbox-jobs/{job['id']}/logs", token=h.bob)[0], 404)
                artifact = json.loads(
                    h.expect(f"/api/sandbox-jobs/{job['id']}/artifacts?path=result.txt", 200, token=h.alice)
                )
                self.assertEqual(base64.b64decode(artifact["content_base64"]), f"job-{mark}".encode())
                self.assertEqual(h.http(f"/api/sandbox-jobs/{job['id']}/artifacts?path=result.txt", token=h.bob)[0], 404)
                self.assertEqual(h.http(f"/api/sandbox-jobs/{job['id']}/artifacts?path=escape", token=h.alice)[0], 404)
                self.assertEqual(h.http(f"/api/sandbox-jobs/{job['id']}/artifacts?path=../stdout.log", token=h.alice)[0], 400)
                # The transient writable copy is reclaimed at terminal state;
                # only bounded logs and artifacts remain for export.
                job_root = h.root / "data/sandbox-jobs" / job["id"]
                self.assertFalse((job_root / "workspace").exists(), "writable copy was not reclaimed")
                self.assertTrue((job_root / "artifacts/result.txt").is_file())
            self.assertFalse((h.root / "data/workspace-service/workspaces" / ws["id"] / "task.txt").exists())
            # Authorized cleanup removes the retained export and is idempotent.
            self.assertEqual(h.http(f"/api/sandbox-jobs/{jobs[0]['id']}/cleanup", token=h.bob, method="POST")[0], 404)
            cleaned = json.loads(
                h.expect(f"/api/sandbox-jobs/{jobs[0]['id']}/cleanup", 200, token=h.alice, method="POST")
            )
            self.assertTrue(cleaned["removed"])
            self.assertEqual(h.http(f"/api/sandbox-jobs/{jobs[0]['id']}/logs", token=h.alice)[0], 404)
            again = json.loads(
                h.expect(f"/api/sandbox-jobs/{jobs[0]['id']}/cleanup", 200, token=h.alice, method="POST")
            )
            self.assertFalse(again["removed"])

            slow = start(
                ["/bin/sh", "-c", "touch started; setsid /bin/sh -c 'sleep 271827' & sleep 271827"], timeout=10
            )
            wait_for(
                lambda: h.sql(f"SELECT state FROM sandbox_jobs WHERE id='{slow['id']}'") == "running",
                message="running sandbox",
            )
            pid = int(h.sql(f"SELECT pid FROM sandbox_jobs WHERE id='{slow['id']}'"))
            self.assertTrue(process_alive(pid))
            # Live logs are a normal product feature for running jobs.
            self.assertEqual(h.http(f"/api/sandbox-jobs/{slow['id']}/logs", token=h.alice)[0], 200)
            self.assertEqual(
                h.http(f"/api/sandbox-jobs/{slow['id']}/artifacts?path=result.txt", token=h.alice)[0], 409
            )
            self.assertEqual(
                json.loads(h.expect(f"/api/sandbox-jobs/{slow['id']}/stop", 200, token=h.alice, method="POST"))["state"],
                "cancelled",
            )
            wait_for(lambda: not process_alive(pid), message="cancelled process exit")
            cancelled_root = h.root / "data/sandbox-jobs" / slow["id"]
            wait_for(lambda: not (cancelled_root / "workspace").exists(), message="cancelled workspace reclaim")
            self.assertTrue(no_process_references(cancelled_root), "cancelled process tree survived")
            self.assertTrue(no_cmdline_contains(b"271827"), "cancelled setsid descendant survived")
            timed = start(["/bin/sh", "-c", "sleep 20"], timeout=1)
            self.assertEqual(wait_done(h, timed)["state"], "timed_out")

            interactive = start(
                [
                    "/bin/sh",
                    "-c",
                    "for fd in /proc/self/fd/*; do "
                    'case "$fd" in /proc/self/fd/[012]) ;; *) '
                    'test "$(readlink "$fd")" != /dev/ptmx || exit 88 ;; esac; done; '
                    "printf 'ready\\n'; read line; stty size; printf 'got:%s\\n' \"$line\"",
                ],
                terminal=True,
            )
            self.assertTrue(interactive["terminal"])
            url = f"/api/sandbox-jobs/{interactive['id']}/terminal"
            self.assertEqual(h.http(url + "/output", token=h.bob)[0], 404)
            self.assertEqual(h.http(f"/api/sandbox-jobs/{jobs[1]['id']}/terminal/output", token=h.alice)[0], 404)
            wait_for(
                lambda: b"ready" in base64.b64decode(
                    json.loads(h.expect(url + "/output?offset=0", 200, token=h.alice))["data_base64"]
                ),
                timeout=5,
                message="terminal prompt",
            )
            h.expect(url + "/resize", 200, token=h.alice, method="POST", body={"rows": 31, "columns": 97})
            h.expect(
                url + "/input",
                200,
                token=h.alice,
                method="POST",
                body={"data_base64": base64.b64encode(b"hello\n").decode()},
            )
            self.assertEqual(wait_done(h, interactive)["state"], "succeeded")
            data = base64.b64decode(
                json.loads(h.expect(url + "/output?offset=0", 200, token=h.alice))["data_base64"]
            )
            self.assertIn(b"31 97", data)
            self.assertIn(b"got:hello", data)
            self.assertEqual(
                h.http(
                    url + "/input",
                    token=h.alice,
                    method="POST",
                    body={"data_base64": base64.b64encode(b"later\n").decode()},
                )[0],
                409,
            )
        finally:
            h.cleanup()

    def test_quota_cancel_crash_cleanup_and_retention(self):
        h = harness(
            {
                "ROOTYARD_SANDBOX_WORKSPACE_MAX_BYTES": "8388608",
                "ROOTYARD_SANDBOX_ARTIFACTS_MAX_BYTES": "262144",
                "ROOTYARD_SANDBOX_MAX_ENTRIES": "2000",
            }
        )
        try:
            h.setup()
            h.api()
            h.roundtrip()
            ws = json.loads(
                h.expect(
                    "/api/workspaces",
                    201,
                    token=h.alice,
                    method="POST",
                    body={"owner": "alice", "repository": "demo", "agent_id": "sandbox-quota", "base_oid": h.second},
                    extra_headers={"Idempotency-Key": "sandbox-quota"},
                )
            )

            def start(argv, timeout=10):
                return json.loads(
                    h.expect(
                        f"/api/workspaces/{ws['id']}/sandbox-jobs",
                        201,
                        token=h.alice,
                        method="POST",
                        body={"argv": argv, "timeout_seconds": timeout, "lease_epoch": 1},
                    )
                )

            artifacts = start(["/bin/sh", "-c", "mkdir -p /artifacts; dd if=/dev/zero of=/artifacts/big bs=65536 count=8"])
            result = wait_done(h, artifacts)
            self.assertEqual(result["state"], "failed")
            _, stderr = logs_of(h, artifacts)
            self.assertIn(b"artifact quota exceeded", stderr)

            workspace = start(["/bin/sh", "-c", "dd if=/dev/zero of=big.bin bs=65536 count=256"])
            self.assertEqual(wait_done(h, workspace)["state"], "failed")
            _, stderr = logs_of(h, workspace)
            self.assertIn(b"workspace quota exceeded", stderr)

            crash = start(
                [
                    "/bin/sh",
                    "-c",
                    "touch alive; setsid /bin/sh -c 'sleep 271828' & "
                    "/bin/sh -c 'sleep 271828 & wait' & sleep 271828",
                ],
                timeout=60,
            )
            wait_for(
                lambda: h.sql(f"SELECT state FROM sandbox_jobs WHERE id='{crash['id']}'") == "running",
                message="crash job running",
            )
            crash_pid = int(h.sql(f"SELECT pid FROM sandbox_jobs WHERE id='{crash['id']}'"))
            self.assertTrue(process_alive(crash_pid))
            crash_root = h.root / "data/sandbox-jobs" / crash["id"]
            h.stop(hard=True)
            wait_for(lambda: not process_alive(crash_pid), message="namespace exit after service crash")
            self.assertTrue(no_process_references(crash_root), "sandbox process survived service crash")
            # setsid/new-session and double-fork descendants are still killed by
            # kernel PID-namespace teardown when the Bubblewrap leader exits.
            wait_for(lambda: no_cmdline_contains(b"271828"), message="descendant namespace teardown")
            self.assertTrue(no_cmdline_contains(b"271828"), "setsid descendant survived crash")
            h.start()
            self.assertEqual(
                h.sql(f"SELECT state||','||coalesce(pid::text,'null') FROM sandbox_jobs WHERE id='{crash['id']}'"),
                "failed,null",
            )
            wait_for(lambda: not (crash_root / "workspace").exists(), message="crashed workspace reclaim")
            stdout, _ = logs_of(h, crash)
            self.assertEqual(stdout, b"")
            h.expect(f"/api/sandbox-jobs/{crash['id']}/cleanup", 200, token=h.alice, method="POST")

            # A retained terminal root is swept on the next startup when the
            # retention window is zero; the terminal result row survives.
            h.stop()
            h.env["ROOTYARD_SANDBOX_RETENTION_SECONDS"] = "0"
            h.start()
            for job in (artifacts, workspace):
                root = h.root / "data/sandbox-jobs" / job["id"]
                wait_for(lambda root=root: not root.exists(), message="retention sweep")
                self.assertEqual(h.http(f"/api/sandbox-jobs/{job['id']}/logs", token=h.alice)[0], 404)
                self.assertEqual(
                    h.sql(f"SELECT state FROM sandbox_jobs WHERE id='{job['id']}'"), "failed"
                )
        finally:
            h.cleanup()

    def test_artifact_pool_is_bounded_and_validated(self):
        import uuid

        pool = Path("/dev/shm") / ("rootyard-runner32-pool-" + uuid.uuid4().hex)
        self.assertTrue(Path("/dev/shm").is_dir(), "bounded tmpfs pool test requires /dev/shm")
        pool.mkdir()
        os.chmod(pool, 0o700)
        h = harness(
            {
                "ROOTYARD_SANDBOX_ARTIFACTS_POOL": str(pool),
                "ROOTYARD_SANDBOX_ARTIFACTS_POOL_MAX_BYTES": str(16 * 1024**3),
            }
        )
        try:
            h.setup()
            h.api()
            h.roundtrip()
            ws = json.loads(
                h.expect(
                    "/api/workspaces",
                    201,
                    token=h.alice,
                    method="POST",
                    body={"owner": "alice", "repository": "demo", "agent_id": "sandbox-pool", "base_oid": h.second},
                    extra_headers={"Idempotency-Key": "sandbox-pool"},
                )
            )

            def start(argv):
                return h.http(
                    f"/api/workspaces/{ws['id']}/sandbox-jobs",
                    token=h.alice,
                    method="POST",
                    body={"argv": argv, "timeout_seconds": 10, "lease_epoch": 1},
                )

            status, raw, _ = start(["/bin/sh", "-c", "mkdir -p /artifacts; printf pool > /artifacts/out.txt"])
            self.assertEqual(status, 201, raw[:300])
            job = json.loads(raw)
            self.assertEqual(wait_done(h, job)["state"], "succeeded")
            artifact = json.loads(
                h.expect(f"/api/sandbox-jobs/{job['id']}/artifacts?path=out.txt", 200, token=h.alice)
            )
            self.assertEqual(base64.b64decode(artifact["content_base64"]), b"pool")
            self.assertEqual((pool / job["id"] / "out.txt").read_text(), "pool")
            h.expect(f"/api/sandbox-jobs/{job['id']}/cleanup", 200, token=h.alice, method="POST")
            self.assertFalse((pool / job["id"]).exists(), "artifact export directory was not reclaimed")

            # A normal host directory is not a kernel-bounded export store and
            # must fail closed before any job process starts.
            h.stop()
            host_pool = h.root / "data" / "host-artifacts-pool"
            host_pool.mkdir()
            os.chmod(host_pool, 0o700)
            h.env["ROOTYARD_SANDBOX_ARTIFACTS_POOL"] = str(host_pool)
            h.start()
            before = h.sql("SELECT count(*) FROM sandbox_jobs")
            status, raw, _ = start(["/bin/true"])
            self.assertEqual(status, 503, raw[:300])
            self.assertEqual(h.sql("SELECT count(*) FROM sandbox_jobs"), str(int(before) + 1))
            self.assertEqual(h.sql("SELECT count(*) FROM sandbox_jobs WHERE state='failed'"), "1")
            self.assertEqual(list(host_pool.iterdir()), [])
        finally:
            h.cleanup()
            for entry in pool.iterdir() if pool.exists() else []:
                if entry.is_dir():
                    import shutil

                    shutil.rmtree(entry, ignore_errors=True)
            if pool.exists():
                pool.rmdir()


if __name__ == "__main__":
    unittest.main()
