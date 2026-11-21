"""Native API, bubblewrap and checkpoint integration over a real FUSE mount.

Test-only backend selector, read once at import time:

* ``ROOTYARD_TEST_FUSE_BACKEND`` unset or ``fuse`` (default) runs the legacy
  in-process service mount (``ROOTYARD_WORKSPACE_MOUNT_MODE=fuse``).  That
  backend is NOT evidence for the independent helper or for its AutoUnmount
  SIGKILL contract: it must never be reported as a helper-cleanup run.
* ``ROOTYARD_TEST_FUSE_BACKEND=fuse-helper`` runs the same API scenario against
  the independent helper (``ROOTYARD_WORKSPACE_MOUNT_MODE=fuse-helper``).  The
  root workflow runs this selector later; it needs a qualified host (namespace
  root, fusermount3) and is not executed by this repository's default test run.

Any other value is a hard error rather than a silent fallback.
"""
import argparse
import base64
import errno
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import stat
import tempfile
import threading
import time
import unittest

from tests import fuse_helper_native_support as support
from tests import workspace_normal_shutdown_support as normal_shutdown
from tests.e2e import Harness
from tests.runtime_binary import select_runtime_binary
from tests.workspace_capture_acceptance import install_capture_read_gate, wait_capture_gate
from tests.workspace_fuse_service_acceptance import read_shutdown_outcome

LEGACY_BACKEND = "fuse"
HELPER_BACKEND = "fuse-helper"
BACKENDS = {"fuse": LEGACY_BACKEND, "fuse-helper": HELPER_BACKEND}
SELECTED = os.environ.get("ROOTYARD_TEST_FUSE_BACKEND", "fuse").strip() or "fuse"
if SELECTED not in BACKENDS:
    raise SystemExit(
        f"ROOTYARD_TEST_FUSE_BACKEND={SELECTED!r} is not a known backend; "
        f"expected one of {sorted(BACKENDS)}")
MOUNT_MODE = BACKENDS[SELECTED]


def confirmed_pidfd(pid, identity):
    """Open a pidfd and recheck the captured identity after the open."""
    if identity is None:
        raise AssertionError("helper identity is unavailable before pidfd open")
    fd = support.open_pidfd(pid)
    current = support.process_identity(pid)
    try:
        if (current is None
                or current["starttime"] != identity["starttime"]
                or current["pgid"] != pid):
            raise AssertionError("helper identity changed while opening pidfd")
    except BaseException:
        support.close_fd(fd)
        raise
    return fd


def signal_pidfd(fd, sig):
    """Signal only the held pidfd; never fall back to a numeric PID/group."""
    sender = getattr(signal, "pidfd_send_signal", None)
    if sender is None:
        raise AssertionError("pidfd_send_signal is unavailable")
    sender(fd, sig)


def wait_capture_state_settled(h, wid, after, timeout=10.0):
    """Wait until two capture commits have observed the completed writes.

    The sandbox job is already terminal, so its FUSE writes cannot change
    again.  A scan that started before ``after`` can still commit a partial
    fingerprint afterwards; the next scan starts only after that commit, sees
    the final overlay and leaves ``workspace_capture_state`` at the exact
    fingerprint the checkpoint reconcile/CAS expects.  This is a fixture
    barrier over the real scanner, not a retry of the product request.
    """
    deadline = time.monotonic() + timeout
    commits = set()
    while time.monotonic() < deadline:
        scanned_at = h.sql(
            "SELECT scanned_at::text FROM workspace_capture_state "
            f"WHERE workspace_id='{wid}' AND scanned_at > '{after}'::timestamptz")
        if scanned_at:
            commits.add(scanned_at)
            if len(commits) >= 2:
                return
        time.sleep(0.1)
    raise AssertionError(
        f"workspace {wid} did not settle capture state with two commits after {after}")


# The normal-shutdown case keeps the pre-existing five-second service exit
# bound used by the original SIGKILL case.  A helper-backend proof is required
# by the C3 matrix, but legacy in-process discovery must not present this as a
# helper run, so the method is gated by the import-time selector.
NORMAL_SIGTERM_BUDGET = 5.0
HELPER_NORMAL_SIGTERM = unittest.skipUnless(
    MOUNT_MODE == HELPER_BACKEND,
    "helper-backend normal SIGTERM proof requires ROOTYARD_TEST_FUSE_BACKEND=fuse-helper")


class WorkspaceFuseServiceTest(unittest.TestCase):
    # backend selects which mount implementation this API scenario proves:
    # "fuse" is the legacy in-process mount (no AutoUnmount contract), and
    # "fuse-helper" is the independent helper (AutoUnmount ownership boundary).
    backend = MOUNT_MODE

    def test_live_editor_capture_checkpoint_and_remount(self):
        binary, _ = select_runtime_binary()
        self.assertTrue(binary.is_file())
        with tempfile.TemporaryDirectory(prefix="rootyard-userns-wrapper-") as wrapper_dir:
            wrapper=Path(wrapper_dir)/"rootyard-userns"
            wrapper.write_text(f"#!/bin/sh\nexec unshare -Urm {shlex.quote(str(binary))} \"$@\"\n")
            wrapper.chmod(0o700)
            h=Harness(argparse.Namespace(binary=str(wrapper),keep=False))
            try:
                h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"]=MOUNT_MODE
                h.env["ROOTYARD_SANDBOX_MODE"]="dev"
                h.setup();h.api();h.roundtrip()
                ws=json.loads(h.expect("/api/workspaces",201,token=h.alice,method="POST",
                    body={"owner":"alice","repository":"demo","agent_id":"live-fuse","base_oid":h.second},
                    extra_headers={"Idempotency-Key":"live-fuse-create"}))
                wid=ws["id"]
                lower=h.root/"data/workspace-service/workspaces"/wid
                upper=h.root/"data/workspace-service/uppers"/wid
                self.assertEqual((lower/"hello.txt").read_bytes(),b"second\n")
                before=json.loads(h.expect(f"/api/workspaces/{wid}/files?path=hello.txt",200,token=h.alice))
                self.assertEqual(base64.b64decode(before["content_base64"]),b"second\n")
                job=json.loads(h.expect(f"/api/workspaces/{wid}/sandbox-jobs",201,token=h.alice,
                    method="POST",body={"argv":["/bin/sh","-c",
                        "printf 'normal editor save\n' > hello.tmp; mv hello.tmp hello.txt; "
                        "chmod 755 hello.txt; printf '*.tmp\n' > .gitignore; "
                        "printf ignored > ignored.tmp; git check-ignore ignored.tmp; "
                        "git add hello.txt .gitignore"],
                        "timeout_seconds":15,"lease_epoch":1,"workspace_access":"live"}))
                deadline=time.monotonic()+20
                while time.monotonic()<deadline:
                    result=json.loads(h.expect(f"/api/sandbox-jobs/{job['id']}",200,token=h.alice))
                    if result["state"] not in ("queued","running"):break
                    time.sleep(.1)
                self.assertEqual(result["state"],"succeeded")
                self.assertEqual((lower/"hello.txt").read_bytes(),b"second\n")
                self.assertEqual((upper/"hello.txt").read_bytes(),b"normal editor save\n")
                self.assertEqual(stat.S_IMODE((upper/"hello.txt").stat().st_mode),0o755)
                self.assertEqual((upper/".gitignore").read_bytes(),b"*.tmp\n")
                visible=json.loads(h.expect(f"/api/workspaces/{wid}/files?path=hello.txt",200,token=h.alice))
                self.assertEqual(base64.b64decode(visible["content_base64"]),b"normal editor save\n")
                staged=json.loads(h.expect(f"/api/workspaces/{wid}/files?path=hello.txt&view=index",200,token=h.alice))
                self.assertEqual(base64.b64decode(staged["content_base64"]),b"normal editor save\n")
                # A first capture can contain only a prefix of the job's writes;
                # the checkpoint's reconcile would then advance the revision
                # after we read it and reject our CAS.  Wait for the real
                # scanner to store the final overlay fingerprint first.
                marker=h.sql("SELECT clock_timestamp()::text")
                wait_capture_state_settled(h,wid,marker)
                current=json.loads(h.expect(f"/api/workspaces/{wid}",200,token=h.alice))
                self.assertGreater(current["revision"],0)
                event=json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=0",200,token=h.alice))
                self.assertIn("external_capture",[e["kind"] for e in event["events"]])
                checkpoint=json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",201,token=h.alice,
                    method="POST",body={"expected_workspace_revision":current["revision"],"lease_epoch":1},
                    extra_headers={"Idempotency-Key":"live-fuse-checkpoint"}))
                self.assertEqual(checkpoint["captured_revision"],current["revision"])
                self.assertEqual(checkpoint["workspace_revision"],current["revision"]+1)
                self.assertEqual(checkpoint["state"],"local_complete")
                cid=checkpoint["checkpoint_id"]
                self.assertEqual((h.root/"data/workspace-service/checkpoints"/cid/"hello.txt").read_bytes(),
                    b"normal editor save\n")
                self.assertEqual(stat.S_IMODE((h.root/"data/workspace-service/checkpoints"/cid/"hello.txt").stat().st_mode),0o755)
                late=json.loads(h.expect(f"/api/workspaces/{wid}/sandbox-jobs",201,token=h.alice,
                    method="POST",body={"argv":["/bin/sh","-c","sleep 4; printf stale > blocked.txt"],
                        "timeout_seconds":10,"lease_epoch":1,"workspace_access":"live"}))
                self.assertEqual(h.http(f"/api/workspaces/{wid}/lease",token=h.alice,
                    method="POST",body={"expected_lease_epoch":1})[0],409)
                h.sql(f"UPDATE workspaces SET lease_epoch=lease_epoch+1, "
                    f"lease_until=clock_timestamp()-interval '1 second' WHERE id='{wid}'")
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    late_state=json.loads(h.expect(f"/api/sandbox-jobs/{late['id']}",200,token=h.alice))
                    if late_state["state"] not in ("queued","running"):break
                    time.sleep(.1)
                self.assertEqual(late_state["state"],"cancelled")
                self.assertFalse((upper/"blocked.txt").exists())
                h.stop(hard=True)
                h.start()
                after=json.loads(h.expect(f"/api/workspaces/{wid}/files?path=hello.txt",200,token=h.alice))
                self.assertEqual(base64.b64decode(after["content_base64"]),b"normal editor save\n")
                self.assertEqual((lower/"hello.txt").read_bytes(),b"second\n")
            finally:h.cleanup()

    def test_api_sigkill_with_pending_kernel_writer(self):
        """SIGKILL the production API while a real FUSE write is parked.

        The capture read gate only marks the phase: the writer must separately
        expose a kernel wait (wchan or a write syscall bound to the exact
        mount) with an unchanged completed-write count.  The API process group
        is killed without Harness.stop's fallback; helper exit, the exact owned
        mount ID disappearing and caller failure are asserted before cleanup.
        """
        backend = HELPER_BACKEND
        binary, _ = select_runtime_binary()
        self.assertTrue(binary.is_file())
        with tempfile.TemporaryDirectory(prefix="rootyard-userns-wrapper-") as wrapper_dir:
            wrapper = Path(wrapper_dir) / "rootyard-userns"
            wrapper.write_text(f"#!/bin/sh\nexec unshare -Urm {shlex.quote(str(binary))} \"$@\"\n")
            wrapper.chmod(0o700)
            h = Harness(argparse.Namespace(binary=str(wrapper), keep=False))
            gate = None
            holder = None
            holder_identity = None
            writer = None
            helper_pid = None
            helper_identity = None
            api_pidfd = helper_pidfd = writer_pidfd = None
            mountpoint = None
            mount_id = None
            workspace_attempted = False
            workspace_created = False
            old_mount_cleared = False
            remount_started = False
            new_mount_cleared = True
            new_holder = None
            new_helper_pid = None
            new_helper_identity = None
            new_helper_pidfd = None
            new_holder_identity = None
            new_mount_id = None
            original_failure = None
            try:
                h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = backend
                h.env["ROOTYARD_SANDBOX_MODE"] = "dev"
                h.setup()
                h.api()
                h.roundtrip()
                workspace_attempted = True
                ws = json.loads(h.expect(
                    "/api/workspaces", 201, token=h.alice, method="POST",
                    body={"owner": "alice", "repository": "demo",
                          "agent_id": "pending-sigkill", "base_oid": h.second},
                    extra_headers={"Idempotency-Key": "pending-sigkill-create"}))
                wid = ws["id"]
                workspace_created = True
                current = json.loads(h.expect(f"/api/workspaces/{wid}", 200, token=h.alice))
                checkpoint = json.loads(h.expect(
                    f"/api/workspaces/{wid}/checkpoints", 201, token=h.alice, method="POST",
                    body={"expected_workspace_revision": current["revision"], "lease_epoch": 1},
                    extra_headers={"Idempotency-Key": "pending-sigkill-checkpoint"}))
                self.assertEqual(checkpoint["state"], "local_complete")
                checkpoint_id = checkpoint["checkpoint_id"]
                self.assertEqual(
                    h.sql(f"SELECT state FROM workspace_checkpoints WHERE id='{checkpoint_id}'"),
                    "local_complete")
                base_events = int(h.sql(
                    "SELECT count(*) FROM workspace_events "
                    f"WHERE workspace_id='{wid}' AND kind='external_capture'"))
                base_revision = int(h.sql(
                    f"SELECT revision FROM workspaces WHERE id='{wid}'"))

                # The gate is armed only after the durable workspace/checkpoint
                # state exists; the target raw upper file does not exist yet.
                h.stop()
                gate_target = h.root / "data/workspace-service/uppers" / wid / "gate-target.txt"
                gate_names = ("LD_PRELOAD", "ROOTYARD_TEST_CAPTURE_GATE",
                              "ROOTYARD_TEST_CAPTURE_TARGET")
                prior_env = {name: h.env.get(name) for name in gate_names}
                gate = install_capture_read_gate(h, gate_target)
                h.start()
                try:
                    for name, value in prior_env.items():
                        if value is None:
                            h.env.pop(name, None)
                        else:
                            h.env[name] = value
                except BaseException:
                    for name, value in prior_env.items():
                        if value is None:
                            h.env.pop(name, None)
                        else:
                            h.env[name] = value
                    raise

                api_pid = h.proc.pid
                self.assertEqual(os.getpgid(api_pid), api_pid,
                                 "production API is not the owned process-group leader")
                api_identity = support.process_identity(api_pid)
                self.assertIsNotNone(api_identity, "production API identity is unavailable")
                self.assertGreater(api_identity["starttime"], 0)
                api_pidfd = support.open_pidfd(api_pid)

                mountpoint = h.root / "data/workspace-service/mounts" / wid
                mount = support.wait_for_fuse_mount(api_pid, mountpoint)
                mount_id = int(mount["mount_id"])
                self.assertGreater(mount_id, 0)
                if backend == HELPER_BACKEND:
                    helper_pid = support.find_api_helper_pid(api_pid)
                    helper_identity = support.process_identity(helper_pid)
                    self.assertIsNotNone(helper_identity, "FUSE helper identity is unavailable")
                    self.assertEqual(helper_identity["pgid"], helper_pid,
                                     "FUSE helper is not in its own owned process group")
                    self.assertGreater(helper_identity["starttime"], api_identity["starttime"])
                    helper_pidfd = confirmed_pidfd(helper_pid, helper_identity)

                holder = support.spawn_api_namespace_holder(api_pid)
                holder_identity = support.process_identity(holder.pid)
                self.assertIsNotNone(holder_identity, "API namespace holder identity is unavailable")
                visible = support.wait_for_fuse_mount(holder.pid, mountpoint, timeout=5)
                self.assertEqual(int(visible["mount_id"]), mount_id,
                                 "holder namespace does not see the exact API mount")

                writer_script = h.root / "pending-fuse-writer.py"
                writer_script.write_text(support.PENDING_WRITER_SCRIPT, encoding="utf-8")
                writer_status = h.root / "pending-fuse-writer.json"
                writer = support.spawn_api_namespace_writer(
                    api_pid, writer_script, mountpoint, writer_status)
                writer_identity = support.process_identity(writer.pid)
                self.assertIsNotNone(writer_identity, "pending writer identity is unavailable")
                self.assertGreater(writer_identity["starttime"], 0)
                writer_pidfd = support.open_pidfd(writer.pid)

                hit = gate.with_suffix(".hit")
                wait_capture_gate(hit, timeout=30)
                self.assertFalse(gate.with_suffix(".timeout").exists(),
                                 "capture read gate expired before observation")
                evidence = support.wait_for_kernel_wait(
                    writer.pid, mountpoint, writer_status, timeout=10)
                self.assertFalse(gate.with_suffix(".timeout").exists(),
                                 "capture read gate expired before SIGKILL")
                self.assertGreaterEqual(evidence["attempts"], 1)
                self.assertEqual(evidence["attempts"], evidence["writes"] + 1)

                kill_ns = time.time_ns()
                os.killpg(api_pid, signal.SIGKILL)
                api_exit = support.wait_process_exit(h.proc, timeout=10)
                self.assertEqual(api_exit, -signal.SIGKILL,
                                 f"production API exit {api_exit}, expected SIGKILL")

                writer_exit = support.wait_process_exit(writer, timeout=support.EXIT_DEADLINE)
                self.assertEqual(writer_exit, 23,
                                 f"pending writer exit {writer_exit}, expected errno failure")
                status = support.writer_status(writer_status)
                self.assertIsNotNone(status, "pending writer wrote no safe error status")
                self.assertEqual(status["phase"], "error")
                self.assertIn(status["errno"],
                              (errno.EIO, errno.ENOTCONN, errno.EROFS,
                               errno.ECONNABORTED, errno.ENOENT),
                              f"pending writer error {status['errno']} is not an I/O/fence error")
                self.assertLess(status["success_ns"], kill_ns,
                                "a write succeeded after the API SIGKILL")
                self.assertGreaterEqual(status["writes"], evidence["writes"],
                                        "completed-byte count regressed after the parked attempt")

                if helper_pid is not None:
                    self.assertTrue(support.wait_pid_gone(helper_pid, support.EXIT_DEADLINE),
                                    "production FUSE helper did not exit after API SIGKILL")
                holder_now = support.process_identity(holder.pid)
                self.assertIsNotNone(holder_now, "crashed-API holder exited before proof")
                self.assertEqual(holder_now["starttime"], holder_identity["starttime"],
                                 "crashed-API holder identity changed before proof")
                self.assertTrue(
                    support.wait_for_mount_id_gone(
                        holder.pid, mountpoint, mount_id, support.EXIT_DEADLINE),
                    f"BLOCKED: {backend} did not remove exact owned mount ID "
                    f"{mount_id} before cleanup; in-process fuse has no AutoUnmount "
                    "ownership boundary")
                old_remaining = [
                    row for row in support.read_process_mountinfo(holder.pid)
                    if row["mountpoint"] == str(mountpoint)
                ]
                self.assertEqual(old_remaining, [],
                                 "crashed workspace mount was replaced after SIGKILL")
                self.assertEqual(int(h.sql(
                    "SELECT count(*) FROM workspace_events "
                    f"WHERE workspace_id='{wid}' AND kind='external_capture'")),
                    base_events, "a blocked capture was reported committed after API SIGKILL")
                self.assertEqual(int(h.sql(
                    f"SELECT revision FROM workspaces WHERE id='{wid}'")),
                    base_revision, "workspace revision advanced after API SIGKILL")
                self.assertEqual(
                    h.sql(f"SELECT state FROM workspace_checkpoints WHERE id='{checkpoint_id}'"),
                    "local_complete", "an in-flight checkpoint was falsely confirmed")

                # A fresh API must mount the same workspace again and read the
                # retained lower bytes.  Mount IDs are scoped to each API's
                # unshared mount namespace, so the fresh numeric ID is not a
                # cross-namespace comparison with the crashed API's ID; retain
                # it for exact fresh-holder and cleanup checks.  Capture this
                # fresh API/helper identity rather than reusing old evidence.
                support.terminate_process(holder)
                holder = None
                old_mount_cleared = True
                h.stop(hard=True)
                remount_started = True
                new_mount_cleared = False
                h.start()
                new_api_pid = h.proc.pid
                remount = support.wait_for_fuse_mount(new_api_pid, mountpoint)
                new_mount_id = int(remount["mount_id"])
                after = json.loads(h.expect(
                    f"/api/workspaces/{wid}/files?path=hello.txt", 200, token=h.alice))
                self.assertEqual(base64.b64decode(after["content_base64"]), b"second\n")

                # Capture the fresh identities only after the successful
                # remount/read, so normal-stop teardown is bound to the exact
                # API/helper that served this remount rather than a pre-read
                # observation.
                new_api_identity = support.process_identity(new_api_pid)
                self.assertIsNotNone(new_api_identity, "fresh API identity is unavailable")
                self.assertGreater(new_api_identity["starttime"],
                                   api_identity["starttime"])
                if backend == HELPER_BACKEND:
                    new_helper_pid = support.find_api_helper_pid(new_api_pid)
                    new_helper_identity = support.process_identity(new_helper_pid)
                    self.assertIsNotNone(new_helper_identity,
                                         "fresh FUSE helper identity is unavailable")
                    self.assertEqual(new_helper_identity["pgid"], new_helper_pid,
                                     "fresh FUSE helper is not in its own process group")
                    self.assertGreater(new_helper_identity["starttime"],
                                       new_api_identity["starttime"])
                    new_helper_pidfd = confirmed_pidfd(
                        new_helper_pid, new_helper_identity)

                # Attest the fresh mount in the fresh API's own namespace, then
                # use a fresh holder to keep that namespace observable across
                # normal graceful shutdown.  No old namespace/mount evidence is
                # reused and no foreign mount is scanned.
                new_holder = support.spawn_api_namespace_holder(new_api_pid)
                new_holder_identity = support.process_identity(new_holder.pid)
                self.assertIsNotNone(new_holder_identity,
                                     "fresh namespace holder identity is unavailable")
                new_visible = support.wait_for_fuse_mount(
                    new_holder.pid, mountpoint, timeout=5)
                self.assertEqual(int(new_visible["mount_id"]), new_mount_id,
                                 "fresh holder does not see the exact new mount")

                # Default graceful stop, bounded by the existing 5s Harness.stop
                # bound.  Do not take Harness.stop's SIGKILL/fallback branch:
                # normal shutdown must exit 0 and release the helper/mount before
                # the fixture root is deleted.
                self.assertEqual(os.getpgid(new_api_pid), new_api_pid,
                                 "fresh API is not the owned process-group leader")
                os.killpg(new_api_pid, signal.SIGTERM)
                new_api_exit = support.wait_process_exit(h.proc, timeout=5)
                self.assertEqual(new_api_exit, 0,
                                 f"normal service shutdown exit {new_api_exit}, expected 0")
                if new_helper_pid is not None:
                    self.assertTrue(
                        support.wait_pid_gone(new_helper_pid, support.EXIT_DEADLINE),
                        "fresh FUSE helper remained after normal shutdown")
                    new_helper_pid = None
                self.assertTrue(
                    support.wait_for_mount_id_gone(
                        new_holder.pid, mountpoint, new_mount_id,
                        support.EXIT_DEADLINE),
                    "fresh owned mount ID remained after normal shutdown")
                remaining = [
                    row for row in support.read_process_mountinfo(new_holder.pid)
                    if row["mountpoint"] == str(mountpoint)
                ]
                self.assertEqual(remaining, [],
                                 "fresh workspace mount remained after normal shutdown")
                holder_now = support.process_identity(new_holder.pid)
                self.assertIsNotNone(holder_now, "fresh holder exited before cleanup")
                self.assertEqual(holder_now["starttime"], new_holder_identity["starttime"],
                                 "fresh holder identity changed before cleanup")
                support.terminate_process(new_holder)
                new_holder = None
                new_mount_cleared = True
                new_mount_id = None
            except BaseException as error:
                original_failure = error
                raise
            finally:
                cleanup_failures = []

                def attempt(label, function):
                    try:
                        function()
                    except BaseException as error:
                        cleanup_failures.append((label, error))

                def clear_holder(holder, identity, mountpoint, mount_id, label):
                    """Prove the exact mount gone, then terminate its holder.

                    The holder stays alive on every failure path so its mount
                    namespace remains available as evidence; holder termination
                    is never used as mount-removal proof.
                    """
                    if (holder is None or identity is None
                            or mountpoint is None or mount_id is None):
                        raise AssertionError(f"{label}: holder/mount identity unavailable")
                    current = support.process_identity(holder.pid)
                    if (current is None
                            or current["starttime"] != identity["starttime"]):
                        raise AssertionError(f"{label}: holder identity changed")
                    if not support.wait_for_mount_id_gone(
                            holder.pid, mountpoint, mount_id, support.EXIT_DEADLINE):
                        raise AssertionError(f"{label}: mount ID {mount_id} remained")
                    remaining = [
                        row for row in support.read_process_mountinfo(holder.pid)
                        if row["mountpoint"] == str(mountpoint)
                    ]
                    if remaining:
                        raise AssertionError(f"{label}: mountpoint has a replacement mount")
                    support.terminate_process(holder)
                    current = support.process_identity(holder.pid)
                    if (current is not None and current["state"] != "Z"
                            and current["starttime"] == identity["starttime"]):
                        raise AssertionError(f"{label}: holder survived termination")

                if gate is not None:
                    attempt("release capture gate",
                            lambda: gate.with_suffix(".release").touch())
                attempt("stop pending writer",
                        lambda: support.terminate_process(writer))

                if h.proc is not None and h.proc.poll() is None:
                    group_owned = False
                    try:
                        group_owned = os.getpgid(h.proc.pid) == h.proc.pid
                    except BaseException as error:
                        cleanup_failures.append(("owned API process group", error))
                    if not group_owned:
                        cleanup_failures.append((
                            "owned API process group",
                            AssertionError("API Popen is not its process-group leader")))
                    else:
                        try:
                            os.killpg(h.proc.pid, signal.SIGTERM)
                            code = support.wait_process_exit(h.proc, timeout=5)
                            if code != 0:
                                cleanup_failures.append((
                                    "owned API graceful exit",
                                    AssertionError(f"API exit {code}, expected 0")))
                        except BaseException as error:
                            cleanup_failures.append(("owned API stop", error))
                            try:
                                os.killpg(h.proc.pid, signal.SIGKILL)
                            except OSError:
                                pass
                            try:
                                support.wait_process_exit(
                                    h.proc, timeout=support.EXIT_DEADLINE)
                            except BaseException as kill_error:
                                cleanup_failures.append(
                                    ("owned API hard stop", kill_error))
                if h.proc is not None and h.proc.poll() is None:
                    cleanup_failures.append((
                        "owned API residue",
                        AssertionError("API process remains after stop")))

                for pid, identity, pidfd, label in (
                        (helper_pid, helper_identity, helper_pidfd, "crashed-API"),
                        (new_helper_pid, new_helper_identity, new_helper_pidfd, "fresh")):
                    if pid is None:
                        continue
                    if identity is None or pidfd is None:
                        cleanup_failures.append((
                            f"{label} helper identity/pidfd unavailable",
                            AssertionError(
                                f"helper {pid} has no confirmed pidfd; no numeric fallback")))
                        continue
                    current = support.process_identity(pid)
                    if current is None:
                        continue
                    if current["starttime"] != identity["starttime"]:
                        cleanup_failures.append((
                            f"{label} helper identity changed",
                            AssertionError(
                                f"helper {pid} no longer matches the captured identity; no signal")))
                        continue
                    try:
                        own_group = os.getpgid(pid) == pid
                    except OSError:
                        own_group = False
                    if not own_group:
                        cleanup_failures.append((
                            f"{label} helper process group",
                            AssertionError(
                                f"helper {pid} process group is unresolved; no signal")))
                        continue
                    if support.wait_pid_gone(pid, support.EXIT_DEADLINE):
                        continue
                    current = support.process_identity(pid)
                    if current is None:
                        cleanup_failures.append((
                            f"{label} helper identity unavailable after wait",
                            AssertionError(
                                f"helper {pid} identity disappeared after wait; no signal")))
                        continue
                    if current["starttime"] != identity["starttime"]:
                        cleanup_failures.append((
                            f"{label} helper identity changed after wait",
                            AssertionError(
                                f"helper {pid} no longer matches after wait; no signal")))
                        continue
                    try:
                        own_group = os.getpgid(pid) == pid
                    except OSError:
                        own_group = False
                    if not own_group:
                        cleanup_failures.append((
                            f"{label} helper process group after wait",
                            AssertionError(
                                f"helper {pid} process group changed after wait; no signal")))
                        continue
                    try:
                        signal_pidfd(pidfd, signal.SIGKILL)
                    except BaseException as error:
                        cleanup_failures.append(
                            (f"{label} helper pidfd signal", error))
                        continue
                    if not support.wait_pid_gone(pid, support.EXIT_DEADLINE):
                        cleanup_failures.append((
                            f"{label} helper residue",
                            AssertionError(
                                f"helper {pid} remained after pidfd signal")))

                if not old_mount_cleared:
                    if not workspace_created:
                        if workspace_attempted:
                            cleanup_failures.append((
                                "crashed-API workspace outcome unknown",
                                AssertionError(
                                    "workspace creation outcome is unresolved; root retained")))
                        else:
                            old_mount_cleared = True
                    else:
                        try:
                            clear_holder(holder, holder_identity, mountpoint,
                                         mount_id, "crashed-API")
                        except BaseException as error:
                            cleanup_failures.append(("crashed-API mount/holder", error))
                        else:
                            holder = None
                            old_mount_cleared = True

                if not new_mount_cleared:
                    if not remount_started:
                        new_mount_cleared = True
                    else:
                        try:
                            clear_holder(new_holder, new_holder_identity, mountpoint,
                                         new_mount_id, "fresh")
                        except BaseException as error:
                            cleanup_failures.append(("fresh mount/holder", error))
                        else:
                            new_holder = None
                            new_mount_cleared = True

                for label, fd in (("close API pidfd", api_pidfd),
                                  ("close helper pidfd", helper_pidfd),
                                  ("close fresh helper pidfd", new_helper_pidfd),
                                  ("close writer pidfd", writer_pidfd)):
                    if fd is not None:
                        attempt(label, lambda fd=fd: os.close(fd))

                cleanup_allowed = (
                    old_mount_cleared and new_mount_cleared and not cleanup_failures)
                if cleanup_allowed and h.proc is not None and h.proc.poll() is None:
                    cleanup_failures.append((
                        "harness stop ownership unresolved",
                        AssertionError("API process is still live")))
                    cleanup_allowed = False
                if cleanup_allowed:
                    attempt("harness stop", lambda: h.stop())
                    attempt("harness cleanup", lambda: h.cleanup())
                else:
                    if h.proc is None or h.proc.poll() is not None:
                        # h.stop is safe here: Popen has no live child to signal.
                        attempt("harness stop", lambda: h.stop())
                    elif h.log is not None:
                        attempt("close harness log", lambda: h.log.close())
                        h.log = None
                    cleanup_failures.append((
                        "fixture root retained",
                        AssertionError(
                            "mount/process cleanup unproven; root/schema retained")))

                if cleanup_failures:
                    detail = "; ".join(
                        f"{label}: {type(error).__name__}"
                        for label, error in cleanup_failures)
                    note = "remount teardown failed: " + detail
                    if original_failure is not None:
                        original_failure.add_note(note)
                    else:
                        raise AssertionError(note)

    @HELPER_NORMAL_SIGTERM
    def test_normal_sigterm_helper_unmount_precedes_parked_git_join(self):
        """Normal SIGTERM releases a parked real FUSE writer before Git join.

        The production capture freeze is held through its ordinary raw-snapshot
        read by the repository's existing exact-path capture-read interposer.
        The interposer is installed before the API starts with an absent proxy
        target; all heavy setup completes first, then a test-owned symlink proxy
        points at a real regular upper ``.git/index``.  The next production Raw
        read hits the barrier and holds the real ``with_frozen`` closure.  The
        barrier is released immediately at SIGTERM; its fixed 15-second marker
        is only an emergency failure guard, never a wait or shutdown extension.
        A real HTTP workspace Git mutation
        runs real Git through a small test-only ``ROOTYARD_GIT`` wrapper that
        holds the completed child at an owned marker.  The Git mutation uses a
        second mounted workspace owned by the same API/helper: the production
        per-workspace mutation/scan gate serializes a capture freeze and a
        same-workspace Git body, so the held Git job runs on its own mount while
        the writer remains in the real kernel wait at the first mount.  Helper
        teardown owns every mount, so the held wrapper still proves that helper
        teardown precedes the Git join.  A raw partial-body PUT is already
        accepted but cannot reach PUT admission until shutdown closes it.

        An optional fixture-only preload is bound before SIGTERM to the exact
        helper, the parked writer descriptor and the three route mount IDs.  It
        records the real helper ``umount2(path, 0)`` entry/result and the one
        successful parked-FD close with the same CLOCK_MONOTONIC source.  The
        writer's single terminal failure path also records one post-return
        userspace sample for the failed parked-FD write.  Only fixed
        ``busy_target``/``writer_close``/``terminal_write`` values are projected
        into the failure diagnostic.  If the witness cannot be built or
        injected, all stay ``unknown``; it adds no wait/barrier, does not open a
        mounted path and is never a pass condition.
        """
        self._rootyard_diagnostic_phase = "setup"
        self._rootyard_diagnostic_api_exit = None
        self._rootyard_diagnostic_shutdown_outcome = "unknown"
        self._rootyard_diagnostic_busy_target = "unknown"
        self._rootyard_diagnostic_writer_close = "unknown"
        self._rootyard_diagnostic_terminal_write = "unknown"
        binary, _ = select_runtime_binary()
        self.assertTrue(binary.is_file())
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git, "real Git is unavailable")
        with tempfile.TemporaryDirectory(prefix="rootyard-userns-wrapper-") as wrapper_dir:
            wrapper = Path(wrapper_dir) / "rootyard-userns"
            wrapper.write_text(
                f"#!/bin/sh\nexec unshare -Urm {shlex.quote(str(binary))} \"$@\"\n")
            wrapper.chmod(0o700)
            h = Harness(argparse.Namespace(binary=str(wrapper), keep=False))
            marker = h.root / "normal-sigterm-git"
            proxy_target = h.root / "normal-sigterm-capture-target"
            h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = HELPER_BACKEND
            h.env["ROOTYARD_SANDBOX_MODE"] = "dev"
            git_wrapper = normal_shutdown.install_git_wrapper(h.root, real_git, marker)
            h.env["ROOTYARD_GIT"] = str(git_wrapper)

            gate_prefix = None
            writer = None
            writer_pidfd = None
            writer_status = None
            holders = []
            holder_identities = []
            namespace_mounts = []
            put = None
            git_thread = None
            git_wrapper_pid = None
            git_wrapper_starttime = None
            helper_pid = None
            helper_identity = None
            helper_pidfd = None
            api_pidfd = None
            witness_dir = None
            witness_library = None
            witness_binding = None
            original_failure = None
            mount_cleanup_proven = True
            try:
                # The existing exact-path capture interposer is installed into
                # this harness's own service child before the API starts.  Its
                # target proxy is absent, so setup reads cannot match yet.
                gate_prefix = install_capture_read_gate(h, proxy_target)
                # The optional witness is a separate fixture-only preload.  Its
                # absence leaves the original acceptance untouched and keeps
                # the diagnostic at "unknown"; it is never a pass condition.
                witness_dir = h.root / "normal-sigterm-witness"
                witness_library = normal_shutdown.install_busy_witness(
                    h, witness_dir)
                h.setup()
                api_pid = h.proc.pid
                self.assertEqual(os.getpgid(api_pid), api_pid,
                                 "production API is not the owned process-group leader")
                api_identity = support.process_identity(api_pid)
                self.assertIsNotNone(api_identity, "production API identity is unavailable")
                self.assertGreater(api_identity["starttime"], 0)
                api_pidfd = support.open_pidfd(api_pid)
                h.api()
                h.roundtrip()
                self._rootyard_diagnostic_phase = "API"

                def create_workspace(agent_id, key):
                    return json.loads(h.expect(
                        "/api/workspaces", 201, token=h.alice, method="POST",
                        body={"owner": "alice", "repository": "demo",
                              "agent_id": agent_id, "base_oid": h.second},
                        extra_headers={"Idempotency-Key": key}))

                def workspace_state(wid):
                    return json.loads(h.expect(
                        f"/api/workspaces/{wid}", 200, token=h.alice))

                def checkpoint(wid, key):
                    current = workspace_state(wid)
                    saved = json.loads(h.expect(
                        f"/api/workspaces/{wid}/checkpoints", 201,
                        token=h.alice, method="POST",
                        body={"expected_workspace_revision": current["revision"],
                              "lease_epoch": current["lease_epoch"]},
                        extra_headers={"Idempotency-Key": key}))
                    self.assertEqual(saved["state"], "local_complete")
                    return saved

                def mount_info(wid):
                    mountpoint = h.root / "data/workspace-service/mounts" / wid
                    row = support.wait_for_fuse_mount(api_pid, mountpoint)
                    mount_id = int(row["mount_id"])
                    self.assertGreater(mount_id, 0)
                    return mountpoint, mount_id

                def keep_namespace(mountpoint, mount_id):
                    holder = support.spawn_api_namespace_holder(api_pid)
                    holders.append(holder)
                    identity = support.process_identity(holder.pid)
                    self.assertIsNotNone(identity, "API namespace holder identity is unavailable")
                    visible = support.wait_for_fuse_mount(holder.pid, mountpoint, timeout=5)
                    self.assertEqual(int(visible["mount_id"]), mount_id,
                                     "holder namespace does not see the exact API mount")
                    holder_identities.append(identity)
                    namespace_mounts.append((holder, identity, mountpoint, mount_id))
                    return holder

                writer_ws = create_workspace("normal-sigterm-writer",
                                             "normal-sigterm-writer-create")
                mount_cleanup_proven = False
                writer_id = writer_ws["id"]
                writer_mount, writer_mount_id = mount_info(writer_id)
                writer_upper = h.root / "data/workspace-service/uppers" / writer_id
                writer_lower = h.root / "data/workspace-service/workspaces" / writer_id
                writer_checkpoint = checkpoint(writer_id,
                                               "normal-sigterm-writer-checkpoint")
                writer_checkpoint_id = writer_checkpoint["checkpoint_id"]
                writer_checkpoint_dir = (
                    h.root / "data/workspace-service/checkpoints" / writer_checkpoint_id)
                writer_checkpoint_digest = normal_shutdown.checkpoint_tree_digest(
                    writer_checkpoint_dir)
                writer_holder = keep_namespace(writer_mount, writer_mount_id)

                git_ws = create_workspace("normal-sigterm-git",
                                          "normal-sigterm-git-create")
                git_id = git_ws["id"]
                git_mount, git_mount_id = mount_info(git_id)
                git_upper = h.root / "data/workspace-service/uppers" / git_id
                git_lower = h.root / "data/workspace-service/workspaces" / git_id
                git_checkpoint = checkpoint(git_id, "normal-sigterm-git-checkpoint")
                git_checkpoint_id = git_checkpoint["checkpoint_id"]
                git_checkpoint_dir = (
                    h.root / "data/workspace-service/checkpoints" / git_checkpoint_id)
                git_checkpoint_digest = normal_shutdown.checkpoint_tree_digest(
                    git_checkpoint_dir)
                git_state = workspace_state(git_id)
                parked_body = {"content_base64": base64.b64encode(b"parked\n").decode(),
                               "expected_entry_version": 0,
                               "expected_workspace_revision": git_state["revision"],
                               "lease_epoch": git_state["lease_epoch"]}
                h.expect(f"/api/workspaces/{git_id}/files?path=parked.bin", 200,
                         token=h.alice, method="PUT", body=parked_body,
                         extra_headers={"Idempotency-Key": "normal-sigterm-parked"})
                git_state = workspace_state(git_id)
                parked_read = json.loads(h.expect(
                    f"/api/workspaces/{git_id}/files?path=parked.bin", 200,
                    token=h.alice))
                self.assertEqual(base64.b64decode(parked_read["content_base64"], validate=True),
                                 b"parked\n")
                git_holder = keep_namespace(git_mount, git_mount_id)

                put_ws = create_workspace("normal-sigterm-put",
                                          "normal-sigterm-put-create")
                put_id = put_ws["id"]
                put_mount, put_mount_id = mount_info(put_id)
                put_upper = h.root / "data/workspace-service/uppers" / put_id
                put_lower = h.root / "data/workspace-service/workspaces" / put_id
                put_checkpoint = checkpoint(put_id, "normal-sigterm-put-checkpoint")
                put_checkpoint_id = put_checkpoint["checkpoint_id"]
                put_checkpoint_dir = (
                    h.root / "data/workspace-service/checkpoints" / put_checkpoint_id)
                put_checkpoint_digest = normal_shutdown.checkpoint_tree_digest(
                    put_checkpoint_dir)
                put_state = workspace_state(put_id)
                put_revision_before = put_state["revision"]
                put_generation_before = put_state["git_generation"]
                put_target = put_mount / "normal-sigterm-put.txt"
                self.assertFalse(put_target.exists())

                writer_checkpoints_before = int(h.sql(
                    "SELECT count(*) FROM workspace_checkpoints "
                    f"WHERE workspace_id='{writer_id}'"))
                git_checkpoints_before = int(h.sql(
                    "SELECT count(*) FROM workspace_checkpoints "
                    f"WHERE workspace_id='{git_id}'"))
                put_checkpoints_before = int(h.sql(
                    "SELECT count(*) FROM workspace_checkpoints "
                    f"WHERE workspace_id='{put_id}'"))
                put_events_before = int(h.sql(
                    "SELECT count(*) FROM workspace_events "
                    f"WHERE workspace_id='{put_id}' AND kind='file_put'"))
                put_operations_before = int(h.sql(
                    "SELECT count(*) FROM workspace_operations "
                    f"WHERE workspace_id='{put_id}' AND kind='file_put'"))

                self._rootyard_diagnostic_phase = "workspace"
                helper_pid = support.find_api_helper_pid(api_pid)
                helper_identity = support.process_identity(helper_pid)
                self.assertIsNotNone(helper_identity, "FUSE helper identity is unavailable")
                self.assertEqual(helper_identity["pgid"], helper_pid,
                                 "FUSE helper is not in its own owned process group")
                self.assertGreater(helper_identity["starttime"], api_identity["starttime"])
                helper_pidfd = confirmed_pidfd(helper_pid, helper_identity)

                writer_script = h.root / "normal-sigterm-writer.py"
                writer_script.write_text(support.PENDING_WRITER_SCRIPT, encoding="utf-8")
                writer_status = h.root / "normal-sigterm-writer.json"
                writer = support.spawn_api_namespace_writer(
                    api_pid, writer_script, writer_mount, writer_status,
                    env=normal_shutdown.busy_witness_writer_env(
                        witness_library, witness_dir))
                writer_identity = support.process_identity(writer.pid)
                self.assertIsNotNone(writer_identity, "pending writer identity is unavailable")
                self.assertGreater(writer_identity["starttime"], 0)
                writer_pidfd = support.open_pidfd(writer.pid)
                normal_shutdown.wait_for_writer_writing(writer, writer_status, timeout=10)

                self._rootyard_diagnostic_phase = "Gitpark"
                normal_shutdown.clear_git_markers(marker)
                Path(str(marker) + ".trigger").touch()
                git_state = workspace_state(git_id)
                git_revision_before = git_state["revision"]
                git_generation_before = git_state["git_generation"]
                git_events_before = int(h.sql(
                    "SELECT count(*) FROM workspace_events "
                    f"WHERE workspace_id='{git_id}' AND kind='git'"))
                git_operations_before = int(h.sql(
                    "SELECT count(*) FROM workspace_operations "
                    f"WHERE workspace_id='{git_id}' AND kind='git'"))
                git_request = {"action": "add", "paths": ["parked.bin"],
                               "expected_git_generation": git_generation_before,
                               "expected_workspace_revision": git_revision_before,
                               "lease_epoch": git_state["lease_epoch"]}
                git_result = {}

                def run_git_request():
                    try:
                        status, raw, _ = h.http(
                            f"/api/workspaces/{git_id}/git", token=h.alice,
                            method="POST", body=git_request,
                            extra_headers={"Idempotency-Key": "normal-sigterm-git-add"})
                        git_result["status"] = status
                        git_result["raw"] = raw
                    except BaseException as error:
                        git_result["error_type"] = type(error).__name__

                git_thread = threading.Thread(
                    target=run_git_request, name="normal-sigterm-git", daemon=False)
                git_thread.start()
                git_hold = normal_shutdown.wait_for_git_hold(marker, timeout=10)
                self.assertEqual(git_hold["exit"], 0,
                                 "real Git add did not exit successfully")
                git_wrapper_pid = git_hold["pid"]
                git_wrapper_starttime = git_hold["starttime"]
                self.assertGreater(git_wrapper_starttime, 0)
                self.assertFalse(Path(str(marker) + ".release").exists(),
                                 "Git wrapper was released before SIGTERM")
                self.assertTrue(normal_shutdown.git_hold_active(marker))

                put_body = json.dumps({
                    "content_base64": base64.b64encode(b"put-after-shutdown\n").decode(),
                    "expected_entry_version": 0,
                    "expected_workspace_revision": put_revision_before,
                    "lease_epoch": put_state["lease_epoch"],
                }, separators=(",", ":")).encode()
                put = normal_shutdown.PartialPut(
                    "127.0.0.1", h.port,
                    f"/api/workspaces/{put_id}/files?path=normal-sigterm-put.txt",
                    h.alice["token"], put_body)
                put.start()
                put.wait_accepted(api_pid, timeout=5)
                self.assertFalse(put_target.exists())

                # All heavy setup is complete while the exact-path proxy is
                # absent.  The upper .git/index is a real regular file copied
                # from the workspace lower index; the proxy is only a test-owned
                # symlink to it.  The next production Raw read matches the
                # existing capture interposer and holds the real with_frozen
                # closure before the writer's next FUSE write is parked.
                self._rootyard_diagnostic_phase = "capturefreeze"
                normal_shutdown.enable_capture_proxy(
                    proxy_target, writer_upper / ".git/index",
                    writer_lower / ".git/index")
                wait_capture_gate(gate_prefix.with_suffix(".hit"), timeout=10)
                self.assertFalse(gate_prefix.with_suffix(".timeout").exists(),
                                 "capture read gate emergency timeout fired before hit")
                kernel_wait = support.wait_for_kernel_wait(
                    writer.pid, writer_mount, writer_status, timeout=15)
                self.assertEqual(kernel_wait["attempts"], kernel_wait["writes"] + 1)
                self.assertTrue(kernel_wait["kernel_wchan"] or kernel_wait["inflight_fd"],
                                "writer did not expose a real kernel FUSE wait")
                self.assertFalse(gate_prefix.with_suffix(".timeout").exists(),
                                 "capture read gate emergency timeout fired while frozen")

                # Bind the witness to the exact owned helper, writer and route
                # mounts before SIGTERM.  This is an immediate local read; it
                # adds no wait/barrier and any mismatch leaves both projected
                # fields at "unknown" without changing an acceptance assertion.
                if witness_library is not None:
                    try:
                        helper_mounts = support.read_process_mountinfo(helper_pid)
                        expected_mounts = {}
                        for label, mount_id in (
                                ("writer", writer_mount_id),
                                ("git", git_mount_id),
                                ("put", put_mount_id)):
                            row = next(
                                (row for row in helper_mounts
                                 if row["mount_id"] == mount_id), None)
                            if row is None:
                                raise AssertionError(
                                    "witness route mount identity is absent")
                            expected_mounts[label] = (
                                mount_id,
                                normal_shutdown.path_tag(row["mountpoint"]))
                        values = list(expected_mounts.values())
                        if (len(set(values)) != 3
                                or len({value[0] for value in values}) != 3
                                or len({value[1] for value in values}) != 3):
                            raise AssertionError(
                                "witness route mount identities are not distinct")
                        owned_mounts = {
                            (row["mount_id"],
                             normal_shutdown.path_tag(row["mountpoint"]))
                            for row in helper_mounts
                            if row["source"] == "rootyard-vfs"
                            and (row["fstype"] == "fuse"
                                 or row["fstype"].startswith("fuse."))
                        }
                        if not set(expected_mounts.values()).issubset(owned_mounts):
                            raise AssertionError(
                                "witness route mount ownership is unproved")
                        witness_binding = {
                            "helper_tag": normal_shutdown.process_tag(
                                helper_pid, helper_identity["starttime"]),
                            "writer_tag": normal_shutdown.process_tag(
                                writer.pid, writer_identity["starttime"]),
                            "expected_mounts": expected_mounts,
                            "owned_mounts": owned_mounts,
                        }
                    except BaseException:
                        witness_binding = None

                self.assertEqual(os.getpgid(api_pid), api_pid,
                                 "production API is not the owned process-group leader")
                deadline = time.monotonic() + NORMAL_SIGTERM_BUDGET

                def remaining():
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise AssertionError(
                            "normal SIGTERM five-second service budget exhausted")
                    return left

                self._rootyard_diagnostic_phase = "signal"
                os.killpg(api_pid, signal.SIGTERM)
                # The release is immediate: it is not a 15-second wait.  The
                # .timeout marker remains an emergency failure guard.
                gate_prefix.with_suffix(".release").touch()
                self.assertFalse(gate_prefix.with_suffix(".timeout").exists(),
                                 "capture read gate emergency timeout fired at SIGTERM")

                self.assertTrue(support.wait_for_mount_id_gone(
                    writer_holder.pid, writer_mount, writer_mount_id, remaining()),
                    "exact writer mount remained after normal SIGTERM")
                self.assertTrue(support.wait_for_mount_id_gone(
                    git_holder.pid, git_mount, git_mount_id, remaining()),
                    "exact Git workspace mount remained after normal SIGTERM")
                self.assertTrue(support.wait_for_mount_id_gone(
                    api_pid, put_mount, put_mount_id, remaining()),
                    "exact PUT workspace mount remained after normal SIGTERM")
                for holder, identity, mountpoint, label in (
                        (writer_holder, holder_identities[0], writer_mount, "writer"),
                        (git_holder, holder_identities[1], git_mount, "git")):
                    current = support.process_identity(holder.pid)
                    self.assertIsNotNone(current, f"{label} holder exited before proof")
                    self.assertEqual(current["starttime"], identity["starttime"],
                                     f"{label} holder identity changed before proof")
                    remaining_rows = [
                        row for row in support.read_process_mountinfo(holder.pid)
                        if row["mountpoint"] == str(mountpoint)
                    ]
                    self.assertEqual(remaining_rows, [],
                                     f"{label} mount was replaced after normal SIGTERM")
                mount_cleanup_proven = True

                self._rootyard_diagnostic_phase = "joins"
                self.assertTrue(support.wait_pid_gone(helper_pid, remaining()),
                                "production FUSE helper did not exit on normal SIGTERM")
                self.assertIsNone(h.proc.poll(),
                                  "API exited before the held Git wrapper was released")
                wrapper_now = support.process_identity(git_wrapper_pid)
                self.assertIsNotNone(wrapper_now,
                                     "held Git wrapper exited before its release marker")
                self.assertEqual(wrapper_now["starttime"], git_wrapper_starttime,
                                 "held Git wrapper starttime changed before release")
                self.assertNotEqual(wrapper_now["state"], "Z",
                                    "held Git wrapper was a zombie before release")
                self.assertTrue(normal_shutdown.git_hold_active(marker),
                                "Git wrapper was not still held when helper/mount proof completed")

                writer_exit = support.wait_process_exit(writer, timeout=remaining())
                self.assertEqual(writer_exit, 23,
                                 f"pending writer exit {writer_exit}, expected errno failure")
                writer_final = support.writer_status(writer_status)
                self.assertIsNotNone(writer_final, "pending writer wrote no safe error status")
                self.assertEqual(writer_final["phase"], "error")
                self.assertIn(writer_final["errno"],
                              (errno.EIO, errno.ENOTCONN, errno.EROFS,
                               errno.ECONNABORTED, errno.ENOENT),
                              f"pending writer error {writer_final['errno']} is not an I/O/fence error")
                self.assertGreaterEqual(writer_final["writes"], kernel_wait["writes"])
                self.assertGreaterEqual(writer_final["attempts"], kernel_wait["attempts"])

                put_outcome = put.finish(remaining)
                put = None
                self.assertEqual(put_outcome["status"], 503,
                                 "post-close PUT did not return the fixed 503")
                self.assertTrue(put_outcome["admission_closed"],
                                "post-close PUT did not return the fixed shutdown admission error")
                self.assertFalse(put_target.exists())
                self.assertFalse((put_upper / "normal-sigterm-put.txt").exists())
                self.assertFalse((put_lower / "normal-sigterm-put.txt").exists())

                normal_shutdown.release_git_hold(marker)
                git_thread.join(timeout=remaining())
                self.assertFalse(git_thread.is_alive(),
                                 "Git HTTP request did not resolve after wrapper release")
                api_exit = support.wait_process_exit(h.proc, timeout=remaining())
                self._rootyard_diagnostic_api_exit = api_exit
                if api_exit != 0:
                    # Read only the harness-owned tail, only when this exact
                    # exit-zero assertion is about to fail. A successful exit
                    # never opens the log.
                    self._rootyard_diagnostic_shutdown_outcome = (
                        read_shutdown_outcome(h.log))
                self.assertEqual(api_exit, 0,
                                 f"normal service shutdown exit {api_exit}, expected 0")

                reap_deadline = time.monotonic() + min(remaining(), 1.0)
                while (time.monotonic() < reap_deadline
                       and support.process_identity(helper_pid) is not None):
                    time.sleep(0.02)
                self.assertIsNone(support.process_identity(helper_pid),
                                  "helper PID was not fully reaped after API exit")
                self.assertFalse(gate_prefix.with_suffix(".timeout").exists(),
                                 "capture read gate emergency timeout fired during shutdown")

                self.assertEqual(int(h.sql(
                    f"SELECT revision FROM workspaces WHERE id='{put_id}'")),
                    put_revision_before)
                self.assertEqual(int(h.sql(
                    f"SELECT git_generation FROM workspaces WHERE id='{put_id}'")),
                    put_generation_before)
                self.assertEqual(int(h.sql(
                    "SELECT count(*) FROM workspace_events "
                    f"WHERE workspace_id='{put_id}' AND kind='file_put'")),
                    put_events_before)
                self.assertEqual(int(h.sql(
                    "SELECT count(*) FROM workspace_operations "
                    f"WHERE workspace_id='{put_id}' AND kind='file_put'")),
                    put_operations_before)

                git_status = git_result.get("status")
                if git_status == 200:
                    committed = json.loads(git_result["raw"])
                    self.assertEqual(committed["action"], "add")
                    self.assertEqual(committed["workspace_revision"],
                                     git_revision_before + 1)
                    self.assertEqual(committed["git_generation"],
                                     git_generation_before + 1)
                    self.assertEqual(int(h.sql(
                        f"SELECT revision FROM workspaces WHERE id='{git_id}'")),
                        git_revision_before + 1)
                    self.assertEqual(int(h.sql(
                        f"SELECT git_generation FROM workspaces WHERE id='{git_id}'")),
                        git_generation_before + 1)
                    self.assertEqual(h.sql(
                        "SELECT state FROM workspace_operations "
                        f"WHERE workspace_id='{git_id}' "
                        "AND idempotency_key='normal-sigterm-git-add'"),
                        "committed")
                    stored = json.loads(h.sql(
                        "SELECT result::text FROM workspace_operations "
                        f"WHERE workspace_id='{git_id}' "
                        "AND idempotency_key='normal-sigterm-git-add'"))
                    self.assertEqual(stored["workspace_revision"],
                                     committed["workspace_revision"])
                    self.assertEqual(stored["git_generation"],
                                     committed["git_generation"])
                    self.assertEqual(int(h.sql(
                        "SELECT count(*) FROM workspace_events "
                        f"WHERE workspace_id='{git_id}' AND kind='git'")),
                        git_events_before + 1)
                    self.assertEqual(int(h.sql(
                        "SELECT count(*) FROM workspace_operations "
                        f"WHERE workspace_id='{git_id}' AND kind='git'")),
                        git_operations_before + 1)
                    index_path = git_upper / ".git/index"
                    self.assertTrue(index_path.is_file(),
                                    "real Git did not persist an upper index")
                    self.assertGreater(index_path.stat().st_size, 0)
                    index_env = h.env.copy()
                    index_env["GIT_INDEX_FILE"] = str(index_path)
                    index_view = h.run(
                        ["git", "--git-dir", str(git_lower / ".git"),
                         "ls-files", "--stage", "--", "parked.bin"],
                        check=False, env=index_env)
                    self.assertEqual(index_view.returncode, 0)
                    self.assertTrue(b"parked.bin" in index_view.stdout,
                                    "real Git index does not contain parked.bin")
                else:
                    self.assertIn(git_status, (409, 500, 503, None),
                                  "Git mutation returned an undeclared outcome")
                    if git_status is None:
                        self.assertIn("error_type", git_result)
                    self.assertEqual(int(h.sql(
                        f"SELECT revision FROM workspaces WHERE id='{git_id}'")),
                        git_revision_before)
                    self.assertEqual(int(h.sql(
                        f"SELECT git_generation FROM workspaces WHERE id='{git_id}'")),
                        git_generation_before)
                    self.assertEqual(int(h.sql(
                        "SELECT count(*) FROM workspace_events "
                        f"WHERE workspace_id='{git_id}' AND kind='git'")),
                        git_events_before)
                    self.assertEqual(int(h.sql(
                        "SELECT count(*) FROM workspace_operations "
                        f"WHERE workspace_id='{git_id}' AND kind='git'")),
                        git_operations_before)

                self.assertEqual(int(h.sql(
                    "SELECT count(*) FROM workspace_checkpoints "
                    f"WHERE workspace_id='{writer_id}'")),
                    writer_checkpoints_before)
                self.assertEqual(int(h.sql(
                    "SELECT count(*) FROM workspace_checkpoints "
                    f"WHERE workspace_id='{git_id}'")),
                    git_checkpoints_before)
                self.assertEqual(int(h.sql(
                    "SELECT count(*) FROM workspace_checkpoints "
                    f"WHERE workspace_id='{put_id}'")),
                    put_checkpoints_before)
                for checkpoint_id, checkpoint_dir, expected_digest in (
                        (writer_checkpoint_id, writer_checkpoint_dir,
                         writer_checkpoint_digest),
                        (git_checkpoint_id, git_checkpoint_dir,
                         git_checkpoint_digest),
                        (put_checkpoint_id, put_checkpoint_dir,
                         put_checkpoint_digest)):
                    self.assertEqual(h.sql(
                        "SELECT state FROM workspace_checkpoints "
                        f"WHERE id='{checkpoint_id}'"), "local_complete")
                    self.assertEqual(
                        normal_shutdown.checkpoint_tree_digest(checkpoint_dir),
                        expected_digest,
                        "prior checkpoint tree bytes/modes/symlink identities changed")
            except BaseException as error:
                if getattr(self, "_rootyard_diagnostic_primary_phase", None) is None:
                    self._rootyard_diagnostic_primary_phase = getattr(
                        self, "_rootyard_diagnostic_phase", None)
                original_failure = error
                raise
            finally:
                self._rootyard_diagnostic_phase = "cleanup"
                # Read only the bounded local receipts.  This is not a wait and
                # is attempted before cleanup removes the fixture root; any
                # missing/partial/mismatched record remains "unknown".
                if witness_binding is not None and witness_dir is not None:
                    try:
                        target, close_state = normal_shutdown.project_busy_witness_receipts(
                            witness_dir,
                            helper_tag=witness_binding["helper_tag"],
                            writer_tag=witness_binding["writer_tag"],
                            expected_mounts=witness_binding["expected_mounts"],
                            owned_mounts=witness_binding["owned_mounts"],
                        )
                        self._rootyard_diagnostic_busy_target = target
                        self._rootyard_diagnostic_writer_close = close_state
                    except BaseException:
                        pass
                    try:
                        self._rootyard_diagnostic_terminal_write = (
                            normal_shutdown.project_terminal_write_return_receipts(
                                witness_dir,
                                writer_status,
                                helper_tag=witness_binding["helper_tag"],
                                writer_tag=witness_binding["writer_tag"],
                                expected_mounts=witness_binding["expected_mounts"],
                                owned_mounts=witness_binding["owned_mounts"],
                            ))
                    except BaseException:
                        pass
                cleanup_failures = []
                retain_fixture = not mount_cleanup_proven

                def attempt(label, function):
                    try:
                        function()
                    except BaseException as error:
                        cleanup_failures.append((label, error))

                def wait_identity_absent(pid, starttime, timeout):
                    """Bounded /proc wait; never waitpid() a non-child process."""
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        current = support.process_identity(pid)
                        if current is None:
                            return True
                        if current["starttime"] != starttime:
                            return False
                        time.sleep(0.02)
                    return False

                if gate_prefix is not None:
                    attempt("release capture gate",
                            lambda: gate_prefix.with_suffix(".release").touch())
                attempt("release Git wrapper",
                        lambda: normal_shutdown.release_git_hold(marker))
                if put is not None:
                    attempt("close partial PUT", put.close)
                attempt("stop pending writer",
                        lambda: support.terminate_process(writer))

                # Keep the namespace observers alive until the exact old mount
                # proof has been attempted, then stop them with their owner.
                if h.proc is not None and h.proc.poll() is None:
                    try:
                        os.killpg(h.proc.pid, signal.SIGTERM)
                        support.wait_process_exit(
                            h.proc, timeout=NORMAL_SIGTERM_BUDGET)
                    except BaseException:
                        try:
                            os.killpg(h.proc.pid, signal.SIGKILL)
                        except OSError:
                            pass
                        try:
                            support.wait_process_exit(
                                h.proc, timeout=support.EXIT_DEADLINE)
                        except BaseException as error:
                            cleanup_failures.append(("owned API", error))
                            retain_fixture = True

                if git_thread is not None and git_thread.is_alive():
                    git_thread.join(timeout=10)
                    if git_thread.is_alive():
                        cleanup_failures.append((
                            "Git HTTP thread",
                            AssertionError("owned request thread remained")))
                if git_wrapper_pid is not None:
                    current = support.process_identity(git_wrapper_pid)
                    if current is not None:
                        if current["starttime"] != git_wrapper_starttime:
                            cleanup_failures.append((
                                "Git wrapper identity",
                                AssertionError("wrapper PID no longer matches")))
                            retain_fixture = True
                        elif not support.wait_pid_gone(
                                git_wrapper_pid, support.EXIT_DEADLINE):
                            cleanup_failures.append((
                                "Git wrapper",
                                AssertionError("owned wrapper remained after release")))
                            retain_fixture = True

                for holder, identity, mountpoint, mount_id in namespace_mounts:
                    current = support.process_identity(holder.pid)
                    if current is None:
                        cleanup_failures.append((
                            "namespace observer",
                            AssertionError("observer exited before exact mount proof")))
                        retain_fixture = True
                        continue
                    if current["starttime"] != identity["starttime"]:
                        cleanup_failures.append((
                            "namespace observer identity",
                            AssertionError("observer starttime changed")))
                        retain_fixture = True
                        continue
                    try:
                        gone = support.wait_for_mount_id_gone(
                            holder.pid, mountpoint, mount_id,
                            support.EXIT_DEADLINE)
                    except BaseException as error:
                        cleanup_failures.append(("exact mount cleanup", error))
                        gone = False
                    if not gone:
                        cleanup_failures.append((
                            "exact mount cleanup",
                            AssertionError("owned mount remained after bounded wait")))
                        retain_fixture = True
                        continue
                    remaining = [
                        row for row in support.read_process_mountinfo(holder.pid)
                        if row["mountpoint"] == str(mountpoint)
                    ]
                    if remaining:
                        cleanup_failures.append((
                            "exact mount replacement",
                            AssertionError("mountpoint gained a replacement mount")))
                        retain_fixture = True

                for holder in holders:
                    attempt("stop namespace holder",
                            lambda holder=holder: support.terminate_process(holder))

                # The helper is not this test's child.  Stop it only through
                # its confirmed pidfd after the captured identity and owned
                # process group still match, then wait for /proc disappearance
                # rather than assuming an unavailable waitpid ownership.
                if helper_pid is not None and helper_identity is not None:
                    current = support.process_identity(helper_pid)
                    if current is None:
                        pass
                    elif (current["starttime"] != helper_identity["starttime"]
                          or current["pgid"] != helper_pid):
                        cleanup_failures.append((
                            "owned helper identity",
                            AssertionError("helper identity changed; no signal")))
                        retain_fixture = True
                    elif current["state"] == "Z":
                        if not wait_identity_absent(
                                helper_pid, helper_identity["starttime"],
                                support.EXIT_DEADLINE):
                            cleanup_failures.append((
                                "owned helper reap",
                                AssertionError("helper zombie was not reaped")))
                            retain_fixture = True
                    elif helper_pidfd is None:
                        cleanup_failures.append((
                            "owned helper pidfd",
                            AssertionError("helper pidfd unavailable; no PID signal")))
                        retain_fixture = True
                    else:
                        try:
                            signal_pidfd(helper_pidfd, signal.SIGKILL)
                        except BaseException as error:
                            cleanup_failures.append(
                                ("owned helper pidfd signal", error))
                            retain_fixture = True
                        if not wait_identity_absent(
                                helper_pid, helper_identity["starttime"],
                                support.EXIT_DEADLINE):
                            cleanup_failures.append((
                                "owned helper reap",
                                AssertionError("helper identity remained after pidfd signal")))
                            retain_fixture = True

                for label, fd in (("close API pidfd", api_pidfd),
                                  ("close helper pidfd", helper_pidfd),
                                  ("close writer pidfd", writer_pidfd)):
                    if fd is not None:
                        attempt(label, lambda fd=fd: os.close(fd))
                if retain_fixture:
                    h.args.keep = True
                    if h.log is not None:
                        attempt("close harness log", lambda: h.log.close())
                        h.log = None
                    cleanup_failures.append((
                        "fixture root/schema retained",
                        AssertionError("mount/child cleanup unproven")))
                else:
                    attempt("harness cleanup", h.cleanup)
                if cleanup_failures:
                    detail = "; ".join(
                        f"{label}: {type(error).__name__}"
                        for label, error in cleanup_failures)
                    note = "normal SIGTERM teardown failed: " + detail
                    if original_failure is not None:
                        original_failure.add_note(note)
                    else:
                        raise AssertionError(note)


if __name__=="__main__":unittest.main()
