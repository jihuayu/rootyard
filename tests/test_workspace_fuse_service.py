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
import signal
import stat
import tempfile
import time
import unittest

from tests import fuse_helper_native_support as support
from tests.e2e import Harness
from tests.runtime_binary import select_runtime_binary
from tests.workspace_capture_acceptance import install_capture_read_gate, wait_capture_gate

LEGACY_BACKEND = "fuse"
HELPER_BACKEND = "fuse-helper"
BACKENDS = {"fuse": LEGACY_BACKEND, "fuse-helper": HELPER_BACKEND}
SELECTED = os.environ.get("ROOTYARD_TEST_FUSE_BACKEND", "fuse").strip() or "fuse"
if SELECTED not in BACKENDS:
    raise SystemExit(
        f"ROOTYARD_TEST_FUSE_BACKEND={SELECTED!r} is not a known backend; "
        f"expected one of {sorted(BACKENDS)}")
MOUNT_MODE = BACKENDS[SELECTED]


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
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    current=json.loads(h.expect(f"/api/workspaces/{wid}",200,token=h.alice))
                    if current["revision"]>0:break
                    time.sleep(.2)
                self.assertGreater(current["revision"],0)
                event=json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=0",200,token=h.alice))
                self.assertIn("external_capture",[e["kind"] for e in event["events"]])
                checkpoint=json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",201,token=h.alice,
                    method="POST",body={"expected_workspace_revision":current["revision"],"lease_epoch":1},
                    extra_headers={"Idempotency-Key":"live-fuse-checkpoint"}))
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
        binary, _ = select_runtime_binary()
        self.assertTrue(binary.is_file())
        with tempfile.TemporaryDirectory(prefix="rootyard-userns-wrapper-") as wrapper_dir:
            wrapper = Path(wrapper_dir) / "rootyard-userns"
            wrapper.write_text(f"#!/bin/sh\nexec unshare -Urm {shlex.quote(str(binary))} \"$@\"\n")
            wrapper.chmod(0o700)
            h = Harness(argparse.Namespace(binary=str(wrapper), keep=False))
            gate = None
            holder = None
            writer = None
            helper_pid = None
            helper_identity = None
            api_pidfd = helper_pidfd = writer_pidfd = None
            new_holder = None
            new_helper_pid = None
            new_helper_identity = None
            new_holder_identity = None
            new_mount_id = None
            original_failure = None
            try:
                h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = MOUNT_MODE
                h.env["ROOTYARD_SANDBOX_MODE"] = "dev"
                h.setup()
                h.api()
                h.roundtrip()
                ws = json.loads(h.expect(
                    "/api/workspaces", 201, token=h.alice, method="POST",
                    body={"owner": "alice", "repository": "demo",
                          "agent_id": "pending-sigkill", "base_oid": h.second},
                    extra_headers={"Idempotency-Key": "pending-sigkill-create"}))
                wid = ws["id"]
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
                if self.backend == HELPER_BACKEND:
                    helper_pid = support.find_api_helper_pid(api_pid)
                    helper_identity = support.process_identity(helper_pid)
                    self.assertIsNotNone(helper_identity, "FUSE helper identity is unavailable")
                    self.assertEqual(helper_identity["pgid"], helper_pid,
                                     "FUSE helper is not in its own owned process group")
                    self.assertGreater(helper_identity["starttime"], api_identity["starttime"])
                    helper_pidfd = support.open_pidfd(helper_pid)

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
                self.assertTrue(
                    support.wait_for_mount_id_gone(
                        holder.pid, mountpoint, mount_id, support.EXIT_DEADLINE),
                    f"BLOCKED: {self.backend} did not remove exact owned mount ID "
                    f"{mount_id} before cleanup; in-process fuse has no AutoUnmount "
                    "ownership boundary")
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

                # A fresh API must mount the same workspace again, with a new
                # kernel mount ID, and read the retained lower bytes.  Capture
                # this fresh API/helper identity and mount ID rather than reusing
                # the crashed API's evidence.
                support.terminate_process(holder)
                holder = None
                h.stop(hard=True)
                h.start()
                new_api_pid = h.proc.pid
                remount = support.wait_for_fuse_mount(new_api_pid, mountpoint)
                new_mount_id = int(remount["mount_id"])
                self.assertNotEqual(new_mount_id, mount_id,
                                    "fresh API reused the crashed mount ID")
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
                if self.backend == HELPER_BACKEND:
                    new_helper_pid = support.find_api_helper_pid(new_api_pid)
                    new_helper_identity = support.process_identity(new_helper_pid)
                    self.assertIsNotNone(new_helper_identity,
                                         "fresh FUSE helper identity is unavailable")
                    self.assertEqual(new_helper_identity["pgid"], new_helper_pid,
                                     "fresh FUSE helper is not in its own process group")
                    self.assertGreater(new_helper_identity["starttime"],
                                       new_api_identity["starttime"])

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
                    and row["source"] == "rootyard-workspace"
                    and (row["fstype"] == "fuse" or row["fstype"].startswith("fuse."))
                ]
                self.assertEqual(remaining, [],
                                 "fresh workspace mount remained after normal shutdown")
                holder_now = support.process_identity(new_holder.pid)
                self.assertIsNotNone(holder_now, "fresh holder exited before cleanup")
                self.assertEqual(holder_now["starttime"], new_holder_identity["starttime"],
                                 "fresh holder identity changed before cleanup")
                support.terminate_process(new_holder)
                new_holder = None
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

                if gate is not None:
                    attempt("release capture gate",
                            lambda: gate.with_suffix(".release").touch())
                attempt("stop pending writer",
                        lambda: support.terminate_process(writer))
                attempt("stop crashed-API namespace holder",
                        lambda: support.terminate_process(holder))
                if helper_pid is not None:
                    current = support.process_identity(helper_pid)
                    if (helper_identity is not None and current is not None
                            and current["state"] != "Z"
                            and current["starttime"] == helper_identity["starttime"]):
                        attempt("kill crashed-API helper",
                                lambda: os.killpg(helper_pid, signal.SIGKILL))
                        if not support.wait_pid_gone(helper_pid, support.EXIT_DEADLINE):
                            cleanup_failures.append((
                                "crashed-API helper residue",
                                AssertionError(
                                    f"crashed-API helper {helper_pid} remained")))

                # A failure can leave the fresh API alive.  Reclaim only the
                # verified owned API process group, then still wait for the fresh
                # helper and mount before fixture-root deletion.
                if h.proc is not None and h.proc.poll() is None:
                    try:
                        os.killpg(h.proc.pid, signal.SIGTERM)
                        support.wait_process_exit(h.proc, timeout=5)
                    except BaseException as error:
                        cleanup_failures.append(("fresh API graceful stop", error))
                        try:
                            os.killpg(h.proc.pid, signal.SIGKILL)
                        except OSError:
                            pass
                        try:
                            support.wait_process_exit(
                                h.proc, timeout=support.EXIT_DEADLINE)
                        except BaseException as kill_error:
                            cleanup_failures.append(("fresh API hard stop", kill_error))

                if new_helper_pid is not None:
                    current = support.process_identity(new_helper_pid)
                    if (new_helper_identity is not None and current is not None
                            and current["starttime"] == new_helper_identity["starttime"]):
                        if not support.wait_pid_gone(
                                new_helper_pid, support.EXIT_DEADLINE):
                            cleanup_failures.append((
                                "fresh helper residue",
                                AssertionError(
                                    f"fresh helper {new_helper_pid} remained")))
                            if current["state"] != "Z":
                                attempt("kill fresh helper",
                                        lambda: os.killpg(
                                            new_helper_pid, signal.SIGKILL))
                                if not support.wait_pid_gone(
                                        new_helper_pid, support.EXIT_DEADLINE):
                                    cleanup_failures.append((
                                        "fresh helper unreaped",
                                        AssertionError(
                                            f"fresh helper {new_helper_pid} survived")))

                if new_mount_id is not None:
                    if new_holder is None:
                        cleanup_failures.append((
                            "fresh mount unattested",
                            AssertionError(
                                f"fresh mount ID {new_mount_id} has no holder")))
                    else:
                        holder_now = support.process_identity(new_holder.pid)
                        if (new_holder_identity is None or holder_now is None
                                or holder_now["starttime"]
                                != new_holder_identity["starttime"]):
                            cleanup_failures.append((
                                "fresh mount unattested",
                                AssertionError(
                                    f"fresh holder identity changed for mount ID "
                                    f"{new_mount_id}")))
                        else:
                            try:
                                gone = support.wait_for_mount_id_gone(
                                    new_holder.pid, mountpoint, new_mount_id,
                                    support.EXIT_DEADLINE)
                            except BaseException as error:
                                gone = False
                                cleanup_failures.append(("fresh mount wait", error))
                            if not gone:
                                cleanup_failures.append((
                                    "fresh mount residue",
                                    AssertionError(
                                        f"fresh mount ID {new_mount_id} remained "
                                        "before root deletion")))

                if new_holder is not None:
                    holder_now = support.process_identity(new_holder.pid)
                    if (new_holder_identity is not None and holder_now is not None
                            and holder_now["starttime"]
                            != new_holder_identity["starttime"]):
                        cleanup_failures.append((
                            "fresh holder identity changed",
                            AssertionError(
                                f"holder PID {new_holder.pid} now names another process")))
                    else:
                        attempt("stop fresh namespace holder",
                                lambda: support.terminate_process(new_holder))

                for label, fd in (("close API pidfd", api_pidfd),
                                  ("close helper pidfd", helper_pidfd),
                                  ("close writer pidfd", writer_pidfd)):
                    if fd is not None:
                        attempt(label, lambda fd=fd: os.close(fd))

                # Both final steps are attempted even if earlier cleanup failed.
                attempt("harness stop", lambda: h.stop())
                attempt("harness cleanup", lambda: h.cleanup())

                if cleanup_failures:
                    detail = "; ".join(
                        f"{label}: {type(error).__name__}"
                        for label, error in cleanup_failures)
                    note = "remount teardown failed: " + detail
                    if original_failure is not None:
                        original_failure.add_note(note)
                    else:
                        raise AssertionError(note)


if __name__=="__main__":unittest.main()
