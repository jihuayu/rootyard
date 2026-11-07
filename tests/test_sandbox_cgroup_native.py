#!/usr/bin/env python3
"""Opt-in native acceptance for the production cgroup sandbox mode.

Exit codes:
  0  all native cgroup assertions executed and passed
  1  an executed assertion failed, or the process profile was not cgroup
  3  blocked: the environment has no delegated cgroup v2 subtree, so no
     cgroup-mode acceptance was executed (this is never reported as a pass)

The test only creates cgroups below ``ROOTYARD_TEST_CGROUP_ROOT`` and never
runs the service in development mode. A successful exit requires an explicit
machine-readable proof set collected from real kernel observations, not merely
a green unittest run: ``native_receipt`` records every executed assertion.

The bounded artifact tmpfs root defaults to ``/dev/shm`` for ad-hoc use and can
be replaced with ``ROOTYARD_TEST_TMPFS_ROOT`` on a machine where ``/dev/shm`` is
not a usable tmpfs. ``ROOTYARD_TEST_ARTIFACTS_POOL_MAX_BYTES`` is an acceptance
threshold for the mounted capacity, never a claim that a configured byte cap is
the physical tmpfs bound.
"""
import argparse
import base64
import concurrent.futures
import json
import os
import shutil
import sys
import time
import unittest
import urllib.parse
import uuid
from pathlib import Path

from tests.e2e import Harness
from tests.webhooks import WebhooksHarness

BINARY = os.environ.get("ROOTYARD_BINARY", "target/debug/rootyard")
CGROUP_ROOT = os.environ.get("ROOTYARD_TEST_CGROUP_ROOT") or os.environ.get("ROOTYARD_SANDBOX_CGROUP_ROOT")
TMPFS_ROOT = Path(os.environ.get("ROOTYARD_TEST_TMPFS_ROOT") or "/dev/shm")
# Acceptance cap for the real mounted pool size. The workflow mounts a unique
# 64 MiB tmpfs and exports its statvfs capacity here; the value is not itself a
# physical bound.
POOL_MAX_BYTES = int(os.environ.get("ROOTYARD_TEST_ARTIFACTS_POOL_MAX_BYTES") or str(16 * 1024**3))
MEMORY_MAX = 134217728
PIDS_MAX = 32
CPU_MAX = "50000 100000"

PROOF = {}
REQUIRED_PROOF = {
    "live_controls",
    "cancel_cgroup_removed",
    "timeout_terminal_reclaim",
    "memory_oom",
    "pids_enforced",
    "cpu_quota_aggregate",
    "workspace_disk_enospc",
    "isolated_concurrent_builds",
    "platform_credentials_absent",
    "logs_artifact_auth",
    "artifact_cgroup_reclaim",
    "crash_descendants_reaped",
    "fenced_attempt_new_attempt",
}


def proof(name):
    PROOF[name] = True


def tokens(path):
    """Return controller names from a cgroup control file.

    ``cgroup.controllers`` and ``cgroup.subtree_control`` use bare names when
    read (``cpu memory pids``). Only writes use the ``+cpu``/``-cpu`` form, so
    an optional leading ``+`` is tolerated but the read form is authoritative.
    """
    return [item[1:] if item.startswith("+") else item for item in path.read_text().split()]


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
    data["path_prefix_ok"] = (
        path.is_absolute() and str(path).startswith("/sys/fs/cgroup/") and str(path) != "/sys/fs/cgroup"
    )
    if not data["path_prefix_ok"]:
        data["reason"] = "delegated cgroup root must be below /sys/fs/cgroup"
        return False, data
    try:
        controllers = tokens(path / "cgroup.controllers")
        subtree = tokens(path / "cgroup.subtree_control")
        kind = (path / "cgroup.type").read_text().strip() if (path / "cgroup.type").is_file() else "domain"
        internal = (path / "cgroup.procs").read_text().split()
    except OSError as error:
        data["reason"] = "cannot read cgroup control files: " + str(error)
        return False, data
    required = ("cpu", "memory", "pids")
    data["controllers"] = controllers
    data["subtree_control"] = subtree
    data["cgroup_type"] = kind
    data["internal_pids"] = len(internal)
    missing = [name for name in required if name not in controllers]
    if missing:
        data["reason"] = "missing controllers: " + ",".join(missing)
        return False, data
    not_delegated = [name for name in required if name not in subtree]
    if not_delegated:
        data["reason"] = "controllers are not delegated to this subtree: " + ",".join(not_delegated)
        return False, data
    if kind != "domain":
        data["reason"] = "delegated cgroup is not a domain cgroup: " + kind
        return False, data
    if internal:
        # cgroup v2 requires the delegated root to have no internal processes
        # while controllers are enabled for its children. The supervisor must
        # move itself into its own leaf before this test runs.
        data["reason"] = "delegated root still contains supervisor processes; use a supervisor leaf"
        return False, data
    probe = path / ("runner32-probe-" + uuid.uuid4().hex)
    try:
        probe.mkdir()
        probe.chmod(0o700)
        for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max", "cgroup.procs", "cgroup.kill"):
            if not (probe / name).exists():
                data["reason"] = "delegated cgroup child is missing " + name
                return False, data
        for name, value in (
            ("memory.max", str(MEMORY_MAX)),
            ("pids.max", str(PIDS_MAX)),
            ("cpu.max", CPU_MAX),
        ):
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
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat.rsplit(") ", 1)[1].split()[0] not in ("Z", "X")


def no_cmdline_contains(marker):
    needle = marker if isinstance(marker, bytes) else marker.encode()
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


def sandbox_env():
    return {
        "ROOTYARD_SANDBOX_MODE": "cgroup",
        "ROOTYARD_SANDBOX_CGROUP_ROOT": CGROUP_ROOT,
        "ROOTYARD_SANDBOX_MEMORY_MAX": str(MEMORY_MAX),
        "ROOTYARD_SANDBOX_PIDS_MAX": str(PIDS_MAX),
        "ROOTYARD_SANDBOX_CPU_MAX": CPU_MAX,
        "ROOTYARD_SANDBOX_WORKSPACE_MAX_BYTES": "8388608",
        "ROOTYARD_SANDBOX_TMP_MAX_BYTES": "8388608",
        "ROOTYARD_SANDBOX_ARTIFACTS_MAX_BYTES": "1048576",
        "ROOTYARD_SANDBOX_ARTIFACTS_POOL_MAX_BYTES": str(POOL_MAX_BYTES),
        "ROOTYARD_SANDBOX_MAX_ENTRIES": "2000",
    }


def new_pool():
    if not TMPFS_ROOT.is_dir():
        raise AssertionError(f"bounded tmpfs root does not exist: {TMPFS_ROOT}")
    pool = TMPFS_ROOT / ("runner32-cgroup-pool-" + uuid.uuid4().hex)
    pool.mkdir()
    os.chmod(pool, 0o700)
    return pool


MEMORY_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(268435456);
    if (!p) return 3;
    memset(p, 1, 268435456);
    puts("survived");
    return 0;
}
"""

PIDS_C = r"""
#include <stdio.h>
#include <unistd.h>
int main(void) {
    int n = 0;
    for (; n < 200; n++) {
        pid_t p = fork();
        if (p < 0) break;
        if (p == 0) { pause(); return 0; }
    }
    printf("forked=%d\n", n);
    return n < 200 ? 0 : 1;
}
"""

CPU_C = r"""
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
static void burn(void) {
    clock_t start = clock();
    volatile double x = 0;
    while ((double)(clock() - start) / CLOCKS_PER_SEC < 0.5) x += 1.1;
}
int main(void) {
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < 4; i++) {
        if (fork() == 0) { burn(); _exit(0); }
    }
    for (int i = 0; i < 4; i++) wait(NULL);
    clock_gettime(CLOCK_MONOTONIC, &b);
    printf("wall_ms=%ld\n", (long)((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000));
    return 0;
}
"""


def compile_and_run(source, name, extra=""):
    path = f"/tmp/{name}.c"
    binary = f"/tmp/{name}"
    return (
        f"cat > {path} <<'EOF'\n{source}\nEOF\n"
        f"gcc -O0 {path} -o {binary} && {binary}{extra}"
    )


class CgroupSandboxTest(unittest.TestCase):
    def start(self, h, workspace_id, argv, timeout=10):
        return json.loads(
            h.expect(
                f"/api/workspaces/{workspace_id}/sandbox-jobs",
                201,
                token=h.alice,
                method="POST",
                body={"argv": argv, "timeout_seconds": timeout, "lease_epoch": 1},
            )
        )

    def wait_done(self, h, job, timeout=40):
        def terminal():
            data = json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}", 200, token=h.alice))
            return data if data["state"] not in ("queued", "preparing", "running") else None

        return wait_for(terminal, timeout=timeout, message="cgroup job terminal")

    def logs(self, h, job):
        payload = json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}/logs", 200, token=h.alice))
        return (
            base64.b64decode(payload["stdout_base64"]),
            base64.b64decode(payload["stderr_base64"]),
        )

    def test_real_kernel_enforcement_and_reclaim(self):
        pool = new_pool()
        h = Harness(argparse.Namespace(binary=BINARY, keep=os.environ.get("ROOTYARD_KEEP_TEST") == "1"))
        h.env.update(sandbox_env())
        h.env["ROOTYARD_SANDBOX_ARTIFACTS_POOL"] = str(pool)
        self.assertEqual(h.env["ROOTYARD_SANDBOX_MODE"], "cgroup")
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
            root = Path(CGROUP_ROOT)

            # 1. Observe live cgroup controls and process attachment, then
            # cancel and prove the job cgroup is killed and removed.
            live = self.start(h, ws["id"], ["/bin/sh", "-c", "touch ready; while [ -f ready ]; do sleep 0.2; done"], 30)
            group = root / live["id"]
            wait_for(
                lambda: (group / "cgroup.procs").is_file() and (group / "cgroup.procs").read_text().strip(),
                message="cgroup attachment",
            )
            self.assertEqual((group / "memory.max").read_text().strip(), str(MEMORY_MAX))
            self.assertEqual((group / "pids.max").read_text().strip(), str(PIDS_MAX))
            self.assertEqual((group / "cpu.max").read_text().strip(), CPU_MAX)
            attached = {int(pid) for pid in (group / "cgroup.procs").read_text().split()}
            self.assertTrue(attached)
            self.assertEqual((group / "cgroup.type").read_text().strip(), "domain")
            h.expect(f"/api/sandbox-jobs/{live['id']}/stop", 200, token=h.alice, method="POST")
            self.assertEqual(self.wait_done(h, live)["state"], "cancelled")
            wait_for(lambda: not group.exists(), message="cgroup removal after cancellation")
            proof("live_controls")
            proof("cancel_cgroup_removed")

            # 2. Timeout is terminal, and its cgroup is reclaimed.
            timed = self.start(h, ws["id"], ["/bin/sh", "-c", "touch alive; sleep 20"], 1)
            self.assertEqual(self.wait_done(h, timed)["state"], "timed_out")
            wait_for(lambda: not (root / timed["id"]).exists(), message="timeout cgroup removal")
            proof("timeout_terminal_reclaim")

            # 3. Memory exhaustion is a kernel OOM failure, never success.
            memory = self.start(h, ws["id"], ["/bin/sh", "-c", compile_and_run(MEMORY_C, "m")], 30)
            self.assertEqual(self.wait_done(h, memory)["state"], "failed")
            memory_stdout, _ = self.logs(h, memory)
            self.assertNotIn(b"survived", memory_stdout)
            wait_for(lambda: not (root / memory["id"]).exists(), message="memory cgroup removal")
            proof("memory_oom")

            # 4. pids.max is a real kernel process limit.
            pids = self.start(h, ws["id"], ["/bin/sh", "-c", compile_and_run(PIDS_C, "p")], 30)
            self.assertEqual(self.wait_done(h, pids)["state"], "succeeded", self.logs(h, pids))
            pids_stdout, _ = self.logs(h, pids)
            forked = int(pids_stdout.split(b"forked=")[1].split()[0])
            self.assertGreater(forked, 0)
            self.assertLess(forked, PIDS_MAX, "pids.max was not enforced")
            proof("pids_enforced")

            # 5. Two CPU seconds across four children at a 50% aggregate quota
            # cannot complete in under three seconds of wall time.
            cpu = self.start(h, ws["id"], ["/bin/sh", "-c", compile_and_run(CPU_C, "c")], 30)
            self.assertEqual(self.wait_done(h, cpu)["state"], "succeeded", self.logs(h, cpu))
            cpu_stdout, _ = self.logs(h, cpu)
            wall_ms = int(cpu_stdout.split(b"wall_ms=")[1].split()[0])
            self.assertGreaterEqual(wall_ms, 3000, f"cpu.max did not aggregate-throttle: wall_ms={wall_ms}")
            proof("cpu_quota_aggregate")

            # 6. The private workspace tmpfs is a real disk bound; artifacts
            # still export, are authorization-scoped, and are reclaimed.
            disk = self.start(
                h,
                ws["id"],
                [
                    "/bin/sh",
                    "-c",
                    "mkdir -p /artifacts; "
                    "dd if=/dev/zero of=/workspace/fill bs=1M count=128 2>/tmp/dd.err || printf 'disk-full\\n'; "
                    "printf 'artifact-ok' > /artifacts/result.txt; tail -2 /tmp/dd.err",
                ],
                60,
            )
            self.assertEqual(self.wait_done(h, disk)["state"], "succeeded", self.logs(h, disk))
            disk_stdout, _ = self.logs(h, disk)
            self.assertIn(b"disk-full", disk_stdout)
            self.assertIn(b"No space left on device", disk_stdout)
            artifact = json.loads(
                h.expect(f"/api/sandbox-jobs/{disk['id']}/artifacts?path=result.txt", 200, token=h.alice)
            )
            self.assertEqual(base64.b64decode(artifact["content_base64"]), b"artifact-ok")
            self.assertEqual(h.http(f"/api/sandbox-jobs/{disk['id']}/logs", token=h.bob)[0], 404)
            self.assertEqual(h.http(f"/api/sandbox-jobs/{disk['id']}/artifacts?path=result.txt", token=h.bob)[0], 404)
            pool_job = pool / disk["id"]
            self.assertTrue((pool_job / "result.txt").is_file())
            proof("workspace_disk_enospc")
            proof("logs_artifact_auth")
            cleaned = json.loads(
                h.expect(f"/api/sandbox-jobs/{disk['id']}/cleanup", 200, token=h.alice, method="POST")
            )
            self.assertTrue(cleaned["removed"])
            wait_for(lambda: not pool_job.exists(), message="artifact pool reclamation")
            wait_for(lambda: not (h.root / "data/sandbox-jobs" / disk["id"]).exists(), message="job root reclamation")
            proof("artifact_cgroup_reclaim")

            # 7. Two concurrent native builds each compile in their own private
            # workspace and cannot read the other's state or platform secrets.
            def build_command(mark, other):
                return (
                    f"printf '#include <stdio.h>\\nint main(void){{puts(\"{mark}\");return 0;}}\\n' > {mark}.c; "
                    f"gcc {mark}.c -o {mark} && ./{mark}; "
                    f"printf %s {mark} > own.txt; mkdir -p /artifacts; printf %s {mark} > /artifacts/who.txt; "
                    f"test ! -e /workspace/{other}.txt; ! grep -qs {other} /workspace /tmp /home; "
                    "test ! -e /var/run/docker.sock; test ! -e /root; "
                    'test -z "$DATABASE_URL"; test -z "$ROOTYARD_SANDBOX_MODE"; env | sort'
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(self.start, h, ws["id"], ["/bin/sh", "-c", build_command(mark, other)], 30)
                    for mark, other in (("build-a", "build-b"), ("build-b", "build-a"))
                ]
                jobs = [future.result() for future in futures]
            for mark, job in zip(("build-a", "build-b"), jobs):
                self.assertEqual(self.wait_done(h, job)["state"], "succeeded", self.logs(h, job))
                stdout, _ = self.logs(h, job)
                self.assertIn(mark.encode(), stdout)
                self.assertNotIn(b"DATABASE_URL", stdout)
                self.assertNotIn(b"ROOTYARD_", stdout)
                self.assertNotIn(b"build-" + (b"b" if mark == "build-a" else b"a"), stdout.replace(mark.encode(), b""))
            proof("isolated_concurrent_builds")
            proof("platform_credentials_absent")

            # 8. A hard service crash leaves no descendant (including setsid
            # and double-fork children), then startup recovery reclaims the
            # stale cgroup and terminal root.
            crash = self.start(
                h,
                ws["id"],
                [
                    "/bin/sh",
                    "-c",
                    "touch alive; setsid /bin/sh -c 'sleep 271832' & "
                    "/bin/sh -c 'sleep 271832 & wait' & sleep 271832",
                ],
                60,
            )
            crash_group = root / crash["id"]
            wait_for(lambda: (crash_group / "cgroup.procs").is_file(), message="crash cgroup")
            crash_pid = int(h.sql(f"SELECT pid FROM sandbox_jobs WHERE id='{crash['id']}'"))
            self.assertTrue(process_alive(crash_pid))
            h.stop(hard=True)
            wait_for(lambda: not process_alive(crash_pid), message="crash namespace exit")
            wait_for(lambda: no_cmdline_contains(b"271832"), message="crash descendant teardown")
            self.assertTrue(no_cmdline_contains(b"271832"), "setsid/double-fork descendant survived crash")
            h.env["ROOTYARD_SANDBOX_RETENTION_SECONDS"] = "0"
            h.start()
            self.assertEqual(
                h.sql(f"SELECT state||','||coalesce(pid::text,'null') FROM sandbox_jobs WHERE id='{crash['id']}'"),
                "failed,null",
            )
            wait_for(lambda: not crash_group.exists(), message="stale cgroup reaped")
            wait_for(lambda: not (h.root / "data/sandbox-jobs" / crash["id"]).exists(), message="crash root reaped")
            proof("crash_descendants_reaped")
        finally:
            h.cleanup()
            shutil.rmtree(pool, ignore_errors=True)

    def test_fenced_attempt_uses_cgroup_backend(self):
        """A retry is a new fenced attempt and each attempt is really cgrouped."""
        pool = new_pool()
        binary = Path(BINARY).resolve()
        h = WebhooksHarness(argparse.Namespace(binary=str(binary), keep=os.environ.get("ROOTYARD_KEEP_TEST") == "1"))
        h.env.update(sandbox_env())
        h.env["ROOTYARD_SANDBOX_ARTIFACTS_POOL"] = str(pool)
        h.env["ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL"] = "4"
        h.env["ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO"] = "2"
        h.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = str(uuid.uuid4())
        try:
            h.setup()
            secret = "ci-native-cgroup-integration-secret"
            hook = h.document(
                h.webhookspath,
                201,
                method="POST",
                body={
                    "url": h.receiver.url,
                    "secret": secret,
                    "events": ["pull_request"],
                    "ci_contexts": ["ci/retry"],
                    "auto_ci_pin": True,
                },
            )
            h.document(
                f"/api/repos/alice/forge/integrations/{hook['id']}/trusted-contexts",
                200,
                method="PUT",
                body={"context": "ci/retry"},
            )
            h.document(
                h.pullspath,
                201,
                method="POST",
                body={"title": "native cgroup retry", "body": "fence", "head_ref": "refs/heads/feature", "base_ref": "refs/heads/main"},
            )
            deadline = time.monotonic() + 10
            rows = []
            while time.monotonic() < deadline:
                rows = h.sql("SELECT id::text||','||context FROM ci_runs ORDER BY context").splitlines()
                if len(rows) == 1:
                    break
                time.sleep(0.2)
            self.assertEqual(len(rows), 1)
            run = rows[0].split(",")[0]
            headers = {"Authorization": "Bearer " + secret}
            claims = f"/api/repos/alice/forge/integrations/{hook['id']}/runs/{run}/claim"
            jobs_path = f"/api/repos/alice/forge/integrations/{hook['id']}/runs/{run}/sandbox-jobs"
            status, raw, _ = h.http(claims, method="POST", body={"runner_id": "cgroup-runner"}, extra_headers=headers)
            self.assertEqual(status, 200, raw[:300])
            first = json.loads(raw)

            def tuple_for(value, runner):
                return {
                    "runner_id": runner,
                    "attempt": value["attempt"],
                    "lease_generation": value["lease_generation"],
                    "head_oid": value["head_oid"],
                    "storage_generation": value["storage_generation"],
                }

            def start_attempt(value):
                params = tuple_for(value, "cgroup-runner")
                status, raw, _ = h.http(
                    jobs_path,
                    method="POST",
                    body={
                        **params,
                        "argv": ["/bin/sh", "-c",
                                 ("printf '#include <stdio.h>\\nint main(void){puts(\"attempt-%d\");return 0;}\\n' > main.c; "
                                  "gcc main.c -o app && ./app; git rev-parse HEAD >/dev/null") % value["attempt"]],
                        "timeout_seconds": 20,
                    },
                    extra_headers=headers,
                )
                self.assertEqual(status, 201, raw[:300])
                return json.loads(raw), params

            def wait(job, params):
                suffix = "?" + urllib.parse.urlencode(params)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    status, raw, _ = h.http(jobs_path + "/" + job["id"] + suffix, extra_headers=headers)
                    self.assertEqual(status, 200, raw[:300])
                    result = json.loads(raw)
                    if result["state"] not in ("queued", "preparing", "running"):
                        return result
                    time.sleep(0.1)
                self.fail("CI cgroup sandbox did not terminate")

            first_job, first_params = start_attempt(first)
            self.assertEqual(wait(first_job, first_params)["state"], "succeeded")
            wait_for(lambda: not (Path(CGROUP_ROOT) / first_job["id"]).exists(), message="terminal CI cgroup removal")
            h.sql(f"UPDATE ci_runs SET lease_expires_unix=0 WHERE id='{run}'")
            status, raw, _ = h.http(claims, method="POST", body={"runner_id": "cgroup-runner"}, extra_headers=headers)
            self.assertEqual(status, 200, raw[:300])
            second = json.loads(raw)
            self.assertGreater(second["attempt"], first["attempt"])
            self.assertGreater(second["lease_generation"], first["lease_generation"])
            old_suffix = "?" + urllib.parse.urlencode(first_params)
            new_suffix = "?" + urllib.parse.urlencode(tuple_for(second, "cgroup-runner"))
            self.assertEqual(h.http(jobs_path + "/" + first_job["id"] + old_suffix, extra_headers=headers)[0], 409)
            self.assertEqual(h.http(jobs_path + "/" + first_job["id"] + new_suffix, extra_headers=headers)[0], 404)
            second_job, second_params = start_attempt(second)
            self.assertNotEqual(second_job["id"], first_job["id"])
            self.assertEqual(wait(second_job, second_params)["state"], "succeeded")
            wait_for(lambda: not (Path(CGROUP_ROOT) / second_job["id"]).exists(), message="terminal retry cgroup removal")
            self.assertEqual(
                h.sql(
                    f"SELECT state||','||ci_attempt||','||ci_lease_generation FROM sandbox_jobs WHERE id='{first_job['id']}'"
                ),
                f"succeeded,{first['attempt']},{first['lease_generation']}",
            )
            self.assertEqual(
                h.sql(
                    f"SELECT ci_attempt||','||ci_lease_generation FROM sandbox_jobs WHERE id='{second_job['id']}'"
                ),
                f"{second['attempt']},{second['lease_generation']}",
            )
            proof("fenced_attempt_new_attempt")
        finally:
            h.cleanup()
            shutil.rmtree(pool, ignore_errors=True)


def sha256_file(path):
    try:
        import hashlib

        digest = hashlib.sha256()
        with Path(path).open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def write_receipt(path, status, preflight_data, error=None):
    receipt = {
        "schema": "rootyard/native-kernel-cgroup-receipt/v1",
        "status": status,
        "profile": os.environ.get("ROOTYARD_SANDBOX_MODE", "unset"),
        "source_commit": os.environ.get("ROOTYARD_SOURCE_COMMIT") or os.environ.get("GITHUB_SHA"),
        "binary_sha256": sha256_file(BINARY),
        "test_file_sha256": sha256_file(Path(__file__).resolve()),
        "workflow_file_sha256": sha256_file(Path(".github/workflows/native-kernel-acceptance.yml")),
        "cgroup_root": CGROUP_ROOT,
        "tmpfs_root": str(TMPFS_ROOT),
        "pool_max_bytes_config": POOL_MAX_BYTES,
        "preflight": preflight_data,
        "assertions": dict(sorted(PROOF.items())),
        "required_assertions": sorted(REQUIRED_PROOF),
        "generated_unix": int(time.time()),
    }
    if error:
        receipt["detail"] = str(error)[:2000]
    if path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", default=os.environ.get("ROOTYARD_NATIVE_RECEIPT"))
    args = parser.parse_args()
    profile = os.environ.get("ROOTYARD_SANDBOX_MODE", "unset")
    if profile == "dev":
        write_receipt(args.receipt, "failed", {}, "native acceptance refuses ROOTYARD_SANDBOX_MODE=dev")
        return 1
    ok, diagnostics = preflight()
    print(json.dumps({"cgroup_preflight": diagnostics}, sort_keys=True), flush=True)
    if not ok:
        write_receipt(args.receipt, "blocked", diagnostics)
        print("BLOCKED: no usable delegated cgroup v2 subtree; cgroup acceptance was not executed.", flush=True)
        return 3
    if profile != "cgroup":
        write_receipt(
            args.receipt,
            "failed",
            diagnostics,
            "native acceptance requires ROOTYARD_SANDBOX_MODE=cgroup in the orchestrator profile",
        )
        return 1
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CgroupSandboxTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    missing = sorted(REQUIRED_PROOF - set(PROOF))
    if not result.wasSuccessful():
        error = "; ".join(test.id() for test, _ in result.failures + result.errors)
        write_receipt(args.receipt, "failed", diagnostics, error)
        return 1
    if missing:
        write_receipt(args.receipt, "failed", diagnostics, "native assertions did not execute: " + ",".join(missing))
        return 1
    write_receipt(args.receipt, "passed", diagnostics)
    return 0


if __name__ == "__main__":
    sys.exit(main())
