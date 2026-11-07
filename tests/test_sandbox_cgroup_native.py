#!/usr/bin/env python3
"""Opt-in native acceptance for the production cgroup sandbox mode.

Exit codes:
  0  all native cgroup assertions passed
  1  an executed assertion failed
  3  blocked: the environment has no delegated cgroup v2 subtree, so no
     cgroup-mode acceptance was executed (this is never reported as a pass)

The test never creates cgroups outside ``ROOTYARD_TEST_CGROUP_ROOT`` and never
runs the service in development mode.
"""
import argparse
import base64
import json
import os
import sys
import time
import unittest
import uuid
from pathlib import Path

from tests.e2e import Harness

BINARY = os.environ.get("ROOTYARD_BINARY", "target/debug/rootyard")
CGROUP_ROOT = os.environ.get("ROOTYARD_TEST_CGROUP_ROOT") or os.environ.get("ROOTYARD_SANDBOX_CGROUP_ROOT")


def preflight():
    """Return (ok, diagnostics). Diagnostics contain no credentials."""
    base = CGROUP_ROOT
    data = {"root": base}
    if not base:
        data["reason"] = "ROOTYARD_TEST_CGROUP_ROOT is not set"
        return False, data
    path = Path(base)
    data["exists"] = path.is_dir()
    if not data["exists"]:
        data["reason"] = "delegated cgroup root does not exist"
        return False, data
    data["path_prefix_ok"] = path.is_absolute() and str(path).startswith("/sys/fs/cgroup/")
    try:
        controllers = (path / "cgroup.controllers").read_text().split()
        subtree = (path / "cgroup.subtree_control").read_text().split()
    except OSError as error:
        data["reason"] = "cannot read cgroup control files: " + str(error)
        return False, data
    required = ("cpu", "memory", "pids")
    data["controllers"] = controllers
    data["subtree_control"] = subtree
    missing = [name for name in required if name not in controllers]
    if missing:
        data["reason"] = "missing controllers: " + ",".join(missing)
        return False, data
    not_delegated = [name for name in required if "+" + name not in subtree]
    if not_delegated:
        data["reason"] = "controllers are not delegated to this subtree: " + ",".join(not_delegated)
        return False, data
    probe = path / ("runner32-probe-" + uuid.uuid4().hex)
    try:
        probe.mkdir()
        for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max", "cgroup.procs", "cgroup.kill"):
            if not (probe / name).exists():
                data["reason"] = "delegated cgroup child is missing " + name
                return False, data
        for name, value in (("memory.max", "67108864"), ("pids.max", "16"), ("cpu.max", "50000 100000")):
            (probe / name).write_text(value)
            if (probe / name).read_text().strip() != value:
                data["reason"] = "delegated cgroup write did not persist for " + name
                return False, data
    except OSError as error:
        data["reason"] = "cannot write a delegated child cgroup: " + str(error)
        return False, data
    finally:
        try:
            probe.rmdir()
        except OSError:
            pass
    data["ok"] = True
    return True, data


def wait_for(predicate, timeout=30, message="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("timed out waiting for " + message)


def process_alive(pid):
    return Path(f"/proc/{pid}").exists()


class CgroupSandboxTest(unittest.TestCase):
    def test_real_kernel_enforcement_and_reclaim(self):
        pool_root = Path("/dev/shm")
        self.assertTrue(pool_root.is_dir(), "bounded tmpfs export pool requires /dev/shm")
        pool = pool_root / ("runner32-cgroup-pool-" + uuid.uuid4().hex)
        pool.mkdir()
        os.chmod(pool, 0o700)
        h = Harness(argparse.Namespace(binary=BINARY, keep=os.environ.get("ROOTYARD_KEEP_TEST") == "1"))
        h.env.update(
            {
                "ROOTYARD_SANDBOX_MODE": "cgroup",
                "ROOTYARD_SANDBOX_CGROUP_ROOT": CGROUP_ROOT,
                "ROOTYARD_SANDBOX_MEMORY_MAX": "134217728",
                "ROOTYARD_SANDBOX_PIDS_MAX": "32",
                "ROOTYARD_SANDBOX_CPU_MAX": "50000 100000",
                "ROOTYARD_SANDBOX_WORKSPACE_MAX_BYTES": "8388608",
                "ROOTYARD_SANDBOX_TMP_MAX_BYTES": "8388608",
                "ROOTYARD_SANDBOX_ARTIFACTS_MAX_BYTES": "1048576",
                "ROOTYARD_SANDBOX_ARTIFACTS_POOL": str(pool),
                "ROOTYARD_SANDBOX_ARTIFACTS_POOL_MAX_BYTES": str(16 * 1024**3),
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
                    body={"owner": "alice", "repository": "demo", "agent_id": "cgroup-parent", "base_oid": h.second},
                    extra_headers={"Idempotency-Key": "cgroup-parent"},
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

            def wait_done(job, timeout=40):
                def terminal():
                    data = json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}", 200, token=h.alice))
                    return data if data["state"] not in ("queued", "preparing", "running") else None

                return wait_for(terminal, timeout=timeout, message="cgroup job terminal")

            def logs(job):
                payload = json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}/logs", 200, token=h.alice))
                return (
                    base64.b64decode(payload["stdout_base64"]),
                    base64.b64decode(payload["stderr_base64"]),
                )

            # Observe the live cgroup controls and process attachment while a
            # job is running, then cancel it and prove the cgroup is removed.
            live = start(["/bin/sh", "-c", "touch ready; while [ -f ready ]; do sleep 0.2; done"], timeout=30)
            group = Path(CGROUP_ROOT) / live["id"]
            wait_for(lambda: (group / "cgroup.procs").is_file() and (group / "cgroup.procs").read_text().strip(),
                     message="cgroup attachment")
            self.assertEqual((group / "memory.max").read_text().strip(), "134217728")
            self.assertEqual((group / "pids.max").read_text().strip(), "32")
            self.assertEqual((group / "cpu.max").read_text().strip(), "50000 100000")
            attached = {int(pid) for pid in (group / "cgroup.procs").read_text().split()}
            self.assertTrue(attached)
            h.expect(f"/api/sandbox-jobs/{live['id']}/stop", 200, token=h.alice, method="POST")
            wait_done(live)
            wait_for(lambda: not group.exists(), message="cgroup removal after cancellation")

            # Memory exhaustion is a terminal failure, not a success.
            memory = start(
                [
                    "/bin/sh",
                    "-c",
                    "printf '#include <stdlib.h>\\n#include <string.h>\\n#include <stdio.h>\\n"
                    "int main(void){char*p=malloc(134217728);if(!p)return 3;memset(p,1,134217728);puts(\"survived\");return 0;}\\n' > m.c; "
                    "gcc m.c -o m && ./m",
                ],
                timeout=30,
            )
            result = wait_done(memory)
            self.assertEqual(result["state"], "failed")
            stdout, _ = logs(memory)
            self.assertNotIn(b"survived", stdout)
            wait_for(lambda: not (Path(CGROUP_ROOT) / memory["id"]).exists(), message="memory cgroup removal")

            # pids.max is a real kernel process limit: fork must fail well
            # before 200 children.
            pids = start(
                [
                    "/bin/sh",
                    "-c",
                    "printf '#include <unistd.h>\\n#include <stdio.h>\\n"
                    "int main(void){int n=0;for(;n<200;n++){pid_t p=fork();if(p<0)break;if(p==0){pause();return 0;}}"
                    "printf(\"forked=%d\\\\n\",n);return n<200?0:1;}\\n' > p.c; gcc p.c -o p && ./p",
                ],
                timeout=30,
            )
            result = wait_done(pids)
            self.assertEqual(result["state"], "succeeded", logs(pids))
            stdout, _ = logs(pids)
            forked = int(stdout.split(b"forked=")[1].split()[0])
            self.assertGreater(forked, 0)
            self.assertLess(forked, 32, "pids.max was not enforced")

            # cpu.max really throttles: two seconds of CPU cannot complete in
            # two seconds of wall time at a 50% quota.
            cpu = start(
                [
                    "/bin/sh",
                    "-c",
                    "printf '#include <stdio.h>\\n#include <time.h>\\n"
                    "int main(void){clock_t start=clock();volatile double x=0;while((double)(clock()-start)/CLOCKS_PER_SEC<2.0)x+=1.1;"
                    "printf(\"wall_ms=%ld\\\\n\",(long)((double)(clock()-start)/CLOCKS_PER_SEC*1000));return 0;}\\n' > c.c; "
                    "gcc c.c -o c && ./c",
                ],
                timeout=30,
            )
            self.assertEqual(wait_done(cpu)["state"], "succeeded", logs(cpu))
            stdout, _ = logs(cpu)
            cpu_ms = int(stdout.split(b"wall_ms=")[1].split()[0])
            self.assertGreaterEqual(cpu_ms, 3000, "cpu.max did not throttle 50%")

            # The workspace tmpfs is the real disk bound. dd must hit ENOSPC
            # well before the 8 MiB private workspace.
            disk = start(
                [
                    "/bin/sh",
                    "-c",
                    "mkdir -p /artifacts; "
                    "dd if=/dev/zero of=/workspace/fill bs=1M count=128 2>/tmp/dd.err || printf 'disk-full\\n'; "
                    "printf 'artifact-ok' > /artifacts/result.txt; tail -2 /tmp/dd.err",
                ],
                timeout=60,
            )
            result = wait_done(disk)
            self.assertEqual(result["state"], "succeeded", logs(disk))
            stdout, _ = logs(disk)
            self.assertIn(b"disk-full", stdout)
            self.assertIn(b"No space left on device", stdout)
            artifact = json.loads(
                h.expect(f"/api/sandbox-jobs/{disk['id']}/artifacts?path=result.txt", 200, token=h.alice)
            )
            self.assertEqual(base64.b64decode(artifact["content_base64"]), b"artifact-ok")

            # Crash recovery: the cgroup and namespace are reclaimed and the
            # durable row is terminal after restart.
            crash = start(["/bin/sh", "-c", "touch alive; sleep 60"], timeout=60)
            crash_group = Path(CGROUP_ROOT) / crash["id"]
            wait_for(lambda: (crash_group / "cgroup.procs").is_file(), message="crash cgroup")
            crash_pid = int(h.sql(f"SELECT pid FROM sandbox_jobs WHERE id='{crash['id']}'"))
            self.assertTrue(process_alive(crash_pid))
            h.stop(hard=True)
            wait_for(lambda: not process_alive(crash_pid), message="crash namespace exit")
            h.env["ROOTYARD_SANDBOX_RETENTION_SECONDS"] = "0"
            h.start()
            self.assertEqual(h.sql(f"SELECT state||','||coalesce(pid::text,'null') FROM sandbox_jobs WHERE id='{crash['id']}'"),
                             "failed,null")
            wait_for(lambda: not crash_group.exists(), message="stale cgroup reaped")
            wait_for(lambda: not (h.root / "data/sandbox-jobs" / crash["id"]).exists(), message="crash root reaped")
        finally:
            h.cleanup()
            import shutil

            shutil.rmtree(pool, ignore_errors=True)


def main():
    ok, diagnostics = preflight()
    print(json.dumps({"cgroup_preflight": diagnostics}, sort_keys=True), flush=True)
    if not ok:
        print("BLOCKED: no delegated cgroup v2 subtree; cgroup acceptance was not executed.", flush=True)
        return 3
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CgroupSandboxTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
