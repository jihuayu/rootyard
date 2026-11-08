#!/usr/bin/env python3
"""Real helper/native FUSE lifecycle tests for ``--workspace-fuse-helper``.

The harness runs itself inside ``unshare -Urm --propagation private`` (a private
owned mount namespace), spawns the real service binary in helper mode and
drives the length-prefixed control protocol from a test parent.  Every mount is
a real kernel FUSE mount under the owned temporary root; there is no stub
filesystem and no fallback that could turn a missing native mount into a pass.

Scope of this file: tests only.  No production source is modified.  A case is
only ``passed`` when every assertion executed against the real binary; a case
that could not reproduce a required race is reported ``partial``/``blocked``
with an explicit limitation and makes the report non-green.

Usage:
    python3 tests/fuse_helper_lifecycle.py --binary target/debug/rootyard \
        --report evidence/fuse-helper-lifecycle.json
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import signal
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fuse_helper_native_support as support

REQUIRED_CASES = [
    "hello_handshake_and_frame_version",
    "generation_and_operation_id_validation",
    "workspace_and_db_epoch_rejection",
    "unknown_fields_oversize_and_truncated_frames",
    "two_native_mounts_a_freeze_thaw_and_b_progress",
    "finish_fence_timely_ok_queued_write_erofs_and_handoff",
    "stale_and_wrong_epoch_finish_cannot_release_other_freeze",
    "abort_freeze_before_begin_tombstone",
    "mount_cancel_and_retry",
    "normal_shutdown_exit_zero_and_mounts_gone",
    "heartbeat_eof_watchdog_fences_and_exits",
    "child_sigkill_mounts_unconfirmable_and_queued_writes_fail",
    "independent_parent_sigkill_orphans_helper",
]


class Suite:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.binary = Path(args.binary).resolve()
        self.repo = Path(__file__).resolve().parents[1]
        self.log_dir = Path(args.work_dir or Path(os.environ.get("TMPDIR", "/tmp")) / f"rootyard-fuse-logs-{os.getpid()}")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.cases: list[dict] = []
        self.helpers: list[support.HelperProcess] = []
        self.notes: list[str] = []
        self.entry_ns = support.ns_inode("mnt")
        self.caller_ns = int(os.environ.get("ROOTYARD_FUSE_HELPER_CALLER_NS", "0") or 0)
        self.baseline_mountinfo = support.parse_mountinfo()

    def spawn(self, label: str) -> support.HelperProcess:
        helper = support.HelperProcess(self.binary, self.log_dir, label)
        self.helpers.append(helper)
        return helper

    def require(self, condition, message: str) -> None:
        if not condition:
            raise AssertionError(support.redact(message))

    def expect_protocol(self, reply: support.Reply, helper: support.HelperProcess,
                        op: str | None = None) -> support.Reply:
        frame = reply.frame
        self.require(frame.get("protocol") == support.PROTOCOL_VERSION,
                     f"reply protocol {frame.get('protocol')} != {support.PROTOCOL_VERSION}")
        self.require(frame.get("generation") == helper.generation,
                     f"reply generation {frame.get('generation')} != {helper.generation}")
        self.require(reply.request_id == frame.get("request_id"), "reply request id drifted")
        if op is not None:
            self.require(reply.op == op, f"expected reply {op}, got {reply.op} code={reply.code}")
        return reply

    def expect_ok(self, reply: support.Reply, helper: support.HelperProcess,
                  op: str = "ok") -> support.Reply:
        self.expect_protocol(reply, helper, op)
        self.require(reply.ok, f"expected ok, got error {reply.code}: {reply.message}")
        return reply

    def expect_error(self, reply: support.Reply, helper: support.HelperProcess,
                     code: int | None = None) -> support.Reply:
        self.expect_protocol(reply, helper)
        self.require(reply.op == "error", f"expected error, got {reply.op} args={reply.args}")
        if code is not None:
            self.require(reply.code == code, f"expected errno {code}, got {reply.code}: {reply.message}")
        return reply

    def expect_dead_control(self, helper: support.HelperProcess, workspace: str,
                            label: str) -> str:
        try:
            reply = helper.marker(workspace, 1, timeout=3.0)
        except (support.ChildExited, support.RpcError, TimeoutError, OSError) as error:
            return support.redact(error)
        self.require(reply.op == "error", f"{label}: expected unusable control, got {reply.op}")
        return f"error {reply.code}: {reply.message}"

    def assert_no_owned_mount(self, root: Path, label: str) -> None:
        deadline = time.monotonic() + 6.0
        while time.monotonic() < deadline:
            rows = support.owned_mounts(root)
            if not rows:
                return
            time.sleep(0.05)
        rows = support.owned_mounts(root)
        self.require(not rows, f"{label}: owned mountpoints still mounted after helper death: "
                               f"{[r['mountpoint'] for r in rows]}")

    def release(self, helper: support.HelperProcess | None, fixture: support.WorkFixture | None,
                label: str) -> dict:
        evidence: dict = {"helper": label}
        if helper is not None:
            if helper.proc.poll() is None:
                helper.kill()
            try:
                evidence["exit_code"] = helper.wait_exit(2.0)
            except support.HarnessError:
                evidence["exit_code"] = helper.proc.poll()
            helper.stop()
            evidence["helper_log_tail"] = helper.log_tail() if evidence["exit_code"] not in (None, 0) else ""
        if fixture is not None:
            self.assert_no_owned_mount(fixture.root, label)
            evidence["umount_backstop"] = support.umount_owned(fixture.root)
            self.assert_no_owned_mount(fixture.root, label)
            evidence["mountinfo"] = [row["mountpoint"] for row in support.owned_mounts(fixture.root)]
            evidence["fixture_cleanup"] = fixture.cleanup(
                lambda: self.assert_no_owned_mount(fixture.root, label))
        return evidence

    def run_case(self, name: str, fn) -> None:
        started = time.monotonic()
        outcome = {"name": name, "status": "failed", "detail": "", "evidence": {}, "seconds": 0.0}
        try:
            result = fn()
            if isinstance(result, dict) and result.pop("_partial_reason", None):
                outcome["status"] = "partial"
                outcome["detail"] = support.redact(result.pop("_partial_detail", ""))
                outcome["evidence"] = result
            else:
                outcome["status"] = "passed"
                outcome["evidence"] = result
        except Exception as error:  # noqa: BLE001 - every failure belongs in the report
            outcome["status"] = "failed"
            outcome["detail"] = support.redact(f"{type(error).__name__}: {error}")
            outcome["traceback"] = support.redact(traceback.format_exc())
        finally:
            outcome["seconds"] = round(time.monotonic() - started, 3)
            self.cases.append(outcome)
            print(f"[{outcome['status']}] {name}: {outcome['detail'] or 'ok'} ({outcome['seconds']}s)",
                  file=sys.stderr, flush=True)

    def final_cleanup(self) -> dict:
        evidence = {"helpers_killed": [], "umount_backstop": []}
        for helper in self.helpers:
            if helper.proc.poll() is None:
                helper.kill()
                evidence["helpers_killed"].append({"pid": helper.proc.pid, "exit": helper.proc.poll()})
            helper.stop()
        # No fixture roots are retained by design; only owned mountpoints are
        # checked again here to prove the whole run left the namespace clean.
        final = support.parse_mountinfo()
        owned = support.owned_mounts(self.repo, final)
        evidence["owned_repo_mounts"] = owned
        return evidence


def mount_pair(suite: Suite, helper: support.HelperProcess, fixture: support.WorkFixture):
    a = fixture.workspace("a")
    b = fixture.workspace("b")
    ra = helper.mount(fixture.root, a, 1)
    suite.expect_ok(ra, helper, "mounted")
    rb = helper.mount(fixture.root, b, 1)
    suite.expect_ok(rb, helper, "mounted")
    suite.require(ra.args.get("epoch") == 1 and rb.args.get("epoch") == 1,
                  f"mount epoch replies were {ra.args} / {rb.args}")
    suite.require((fixture.mounts[a] / "a.txt").read_text() == "lower-a\n",
                  "lower file A is not visible through the native FUSE mount")
    suite.require((fixture.mounts[b] / "b.txt").read_text() == "lower-b\n",
                  "lower file B is not visible through the native FUSE mount")
    return a, b


def write_read(path: Path, payload: bytes) -> bytes:
    with open(path, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return path.read_bytes()


def case_hello(suite: Suite) -> dict:
    helper = suite.spawn("hello")
    fixture = None
    try:
        hello = helper.hello()
        suite.expect_ok(hello, helper)
        suite.require(isinstance(hello.args, dict) and hello.args.get("op_id") in (None, 0),
                      f"hello reply args {hello.args}")
        bad = suite.spawn("bad-version")
        try:
            reply = bad.hello(version=2)
            suite.expect_protocol(reply, bad)
            suite.require(reply.op == "error" and reply.code == errno.EPROTO,
                          f"hello version 2 was not rejected with EPROTO: {reply.op}/{reply.code}")
        finally:
            code = bad.wait_exit(8.0)
            suite.require(code != 0, f"bad-version helper exited 0 ({code})")
            bad.stop()
        return {"hello": "ok", "bad_version_reply": "EPROTO", "bad_version_exit": code}
    finally:
        suite.release(helper, fixture, "hello")


def case_generation_opid(suite: Suite) -> dict:
    helper = suite.spawn("generation")
    fixture = support.WorkFixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        stale = support.Frame(helper.generation + 1, helper.request_id(), "marker", None, a, 1)
        helper.send_frame(stale)
        frame = helper.read(5.0)
        reply = support.Reply(frame, stale.request_id)
        suite.expect_error(reply, helper, errno.ESTALE)
        suite.require(helper.state_phase(a, 1) in ("healthy", "frozen"),
                      "helper stopped serving after a stale-generation frame")
        unknown = helper.call("not_a_helper_operation", None, workspace=a, db_epoch=1)
        suite.expect_error(unknown, helper, errno.EPROTO)
        op_id = 7001
        suite.expect_ok(helper.freeze_begin(a, 1, op_id), helper)
        busy = helper.freeze_begin(b, 1, op_id)
        suite.expect_error(busy, helper, errno.EEXIST)
        again = helper.freeze_begin(a, 1, 7002)
        suite.expect_error(again, helper, errno.EBUSY)
        suite.expect_ok(helper.freeze_finish(a, 1, op_id, True)[0], helper)
        return {"stale_generation": "ESTALE", "unknown_op": "EPROTO",
                "duplicate_op_id": "EEXIST", "second_freeze": "EBUSY"}
    finally:
        suite.release(helper, fixture, "generation")


def case_workspace_epoch(suite: Suite) -> dict:
    helper = suite.spawn("workspace-epoch")
    fixture = support.WorkFixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a = fixture.workspace("a")
        missing = helper.call("mount", {"root": str(fixture.root), "workspace": a,
                                       "lease_until": int(time.time()) + 3600, "lazy": False},
                              workspace=None, db_epoch=1)
        suite.expect_error(missing, helper, errno.EINVAL)
        mismatch = helper.call("mount", {"root": str(fixture.root), "workspace": a,
                                        "lease_until": int(time.time()) + 3600, "lazy": False},
                               workspace=str(__import__("uuid").uuid4()), db_epoch=1)
        suite.expect_error(mismatch, helper, errno.EINVAL)
        zero = helper.call("mount", {"root": str(fixture.root), "workspace": a,
                                    "lease_until": int(time.time()) + 3600, "lazy": False},
                           workspace=a, db_epoch=0)
        suite.expect_error(zero, helper, errno.EINVAL)
        suite.expect_ok(helper.mount(fixture.root, a, 1), helper, "mounted")
        wrong_freeze = helper.freeze_begin(a, 999, 8001)
        suite.expect_error(wrong_freeze, helper, errno.ESTALE)
        wrong_finish = helper.freeze_finish(a, 999, 8001, True)[0]
        suite.expect_error(wrong_finish, helper, errno.ESTALE)
        wrong_handoff = helper.handoff(a, 9)
        suite.expect_error(wrong_handoff, helper, errno.ESTALE)
        return {"mount_without_workspace": "EINVAL", "envelope_mismatch": "EINVAL",
                "mount_epoch_zero": "EINVAL", "wrong_epoch_freeze": "ESTALE",
                "wrong_epoch_handoff": "ESTALE"}
    finally:
        suite.release(helper, fixture, "workspace-epoch")


def case_malformed_frames(suite: Suite) -> dict:
    evidence = {}
    cases = [
        ("unknown-field", b'{"protocol":1,"generation":5,"request_id":1,"workspace":null,'
                          b'"db_epoch":0,"op":"hello","args":{"pid":1,"version":1},"extra":true}'),
        ("oversize", b"{" + b"x" * (support.MAX_FRAME_BYTES + 1) + b"}"),
        ("zero-length", b""),
        ("truncated-json", b'{"protocol":1,"generation":5'),
    ]
    for label, payload in cases:
        helper = suite.spawn(f"malformed-{label}")
        try:
            helper.hello()
            if label == "truncated-json":
                helper.send_frame(support.Frame(helper.generation, helper.request_id(), "hello",
                                                {"pid": 1, "version": 1}))
                with helper.lock:
                    helper.control.sendall(support.struct.pack(">I", len(payload)) + payload)
            else:
                with helper.lock:
                    helper.control.sendall(support.struct.pack(">I", len(payload)) + payload)
            code = helper.wait_exit(8.0)
            suite.require(code != 0, f"{label}: helper survived a malformed frame with exit 0")
            evidence[label] = code
        finally:
            if helper.proc.poll() is None:
                helper.kill()
            helper.stop()
    helper = suite.spawn("bad-protocol-field")
    try:
        helper.hello()
        frame = support.Frame(helper.generation, helper.request_id(), "marker", None, None, 0,
                              protocol=99)
        helper.send_frame(frame)
        code = helper.wait_exit(8.0)
        suite.require(code != 0, "protocol field 99 was accepted")
        evidence["protocol-field"] = code
    finally:
        if helper.proc.poll() is None:
            helper.kill()
        helper.stop()
    return evidence


def _park(helper: support.HelperProcess, workspace: str, epoch: int, op_id: int,
          mountpoint: Path, name: str) -> tuple[support.ParkedWriter, int]:
    writer = support.ParkedWriter(mountpoint / name)
    writer.start()
    writer.wait_started()
    reply = helper.freeze_begin(workspace, epoch, op_id)
    if not reply.ok:
        writer.finish(2.0)
        raise AssertionError(f"freeze_begin failed: {reply.code} {reply.message}")
    before = writer.quiesce(0.45)
    if not writer.is_alive():
        raise AssertionError(f"writer was not parked by freeze: error={writer.error}")
    if writer.bytes != before:
        raise AssertionError(f"writer progressed {before}->{writer.bytes} while frozen")
    return writer, before


def case_two_mounts_thaw(suite: Suite) -> dict:
    helper = suite.spawn("thaw")
    fixture = support.WorkFixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        suite.require(helper.state_phase(a, 1) in ("healthy", "frozen"),
                      f"unexpected A phase {helper.state_phase(a, 1)}")
        writer, parked_bytes = _park(helper, a, 1, 9001, fixture.mounts[a], "a-parked.bin")
        try:
            with open(fixture.mounts[b] / "from-b.txt", "wb") as handle:
                handle.write(b"B continues during A freeze\n")
                handle.flush()
                os.fsync(handle.fileno())
            suite.require((fixture.mounts[b] / "from-b.txt").read_bytes() ==
                          b"B continues during A freeze\n", "B read did not observe B write during A freeze")
            suite.require((fixture.mounts[b] / "b.txt").read_text() == "lower-b\n",
                          "B lower read failed during A freeze")
            reply, elapsed = helper.freeze_finish(a, 1, 9001, True)
            suite.expect_ok(reply, helper)
            suite.require(elapsed < 6.0, f"finish_thaw took {elapsed:.2f}s")
            deadline = time.monotonic() + 8.0
            while writer.bytes <= parked_bytes and time.monotonic() < deadline and writer.is_alive():
                time.sleep(0.02)
            suite.require(writer.bytes > parked_bytes,
                          f"parked A write did not resume after thaw ({parked_bytes}->{writer.bytes})")
            writer.finish()
            suite.require(writer.error is None, f"writer failed after thaw: {writer.error}")
            suite.require(os.path.getsize(fixture.mounts[a] / "a-parked.bin") == writer.bytes,
                          "visible A file size does not match the completed write")
            return {"workspace_a": a, "workspace_b": b, "parked_bytes": parked_bytes,
                    "completed_bytes": writer.bytes, "thaw_seconds": round(elapsed, 3),
                    "b_write_while_a_frozen": True}
        finally:
            if writer.is_alive():
                writer.finish(3.0)
    finally:
        suite.release(helper, fixture, "thaw")


def case_fence_handoff(suite: Suite) -> dict:
    helper = suite.spawn("fence")
    fixture = support.WorkFixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        writer, parked = _park(helper, a, 1, 9101, fixture.mounts[a], "a-fenced.bin")
        try:
            reply, elapsed = helper.freeze_finish(a, 1, 9101, False)
            suite.expect_ok(reply, helper)
            suite.require(elapsed < 6.0, f"finish_fence reply took {elapsed:.2f}s")
            writer.finished.wait(8.0)
            suite.require(writer.error is not None,
                          f"parked write did not fail after fence (bytes={writer.bytes})")
            suite.require(writer.error.errno == errno.EROFS,
                          f"parked write errno {writer.error.errno}, expected EROFS")
            suite.require(helper.state_phase(a, 1).startswith("fenced"),
                          f"gate phase after fence is {helper.state_phase(a, 1)!r}")
            attempt = open(fixture.mounts[a] / "new-after-fence.txt", "wb")
            try:
                attempt.write(b"must fail\n")
                attempt.flush()
                os.fsync(attempt.fileno())
                raise AssertionError("new write succeeded while gate was fenced")
            except OSError as error:
                suite.require(error.errno in (errno.EROFS, errno.EAGAIN, errno.EIO),
                              f"new fenced write errno {error.errno}")
            finally:
                attempt.close()
            until = int(time.time()) + 3600
            handoff = helper.handoff(a, 2, until)
            suite.expect_ok(handoff, helper)
            suite.require(handoff.db_epoch == 2, f"handoff reply epoch {handoff.db_epoch}")
            suite.require(write_read(fixture.mounts[a] / "epoch2.txt", b"epoch two\n") == b"epoch two\n",
                          "next-epoch write did not succeed after handoff")
            suite.require(helper.state_phase(a, 2).startswith("healthy"),
                          f"gate phase after handoff is {helper.state_phase(a, 2)!r}")
            suite.require((fixture.mounts[b] / "b.txt").read_text() == "lower-b\n",
                          "B mount broke during A fence/handoff")
            return {"fence_seconds": round(elapsed, 3), "queue_errno": errno.EROFS,
                    "new_epoch": 2, "parked_bytes": parked,
                    "new_write_after_handoff": True}
        finally:
            if writer.is_alive():
                writer.finish(3.0)
    finally:
        suite.release(helper, fixture, "fence")


def case_stale_finish_isolated(suite: Suite) -> dict:
    helper = suite.spawn("stale-finish")
    fixture = support.WorkFixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        wa, _ = _park(helper, a, 1, 9201, fixture.mounts[a], "a-stale.bin")
        wb, _ = _park(helper, b, 1, 9202, fixture.mounts[b], "b-stale.bin")
        try:
            foreign = helper.freeze_finish(b, 1, 9201, True)[0]
            suite.expect_error(foreign, helper, errno.ESTALE)
            suite.require(helper.state_phase(a, 1).startswith("frozen"),
                          "foreign finish changed A from frozen")
            suite.require(helper.state_phase(b, 1).startswith("frozen"),
                          "foreign finish changed B from frozen")
            wrong_epoch = helper.call("freeze_finish", {"op_id": 9201, "epoch": 2, "thaw": True},
                                      workspace=a, db_epoch=1)
            suite.expect_error(wrong_epoch, helper, errno.ESTALE)
            suite.require(helper.state_phase(a, 1).startswith("frozen"),
                          "wrong op epoch released A")
            suite.expect_ok(helper.freeze_finish(b, 1, 9202, True)[0], helper)
            wb.finish()
            suite.require(wb.error is None, f"B writer failed on legitimate thaw: {wb.error}")
            suite.require(wa.is_alive() and wa.bytes == wa.quiesce(0.3),
                          "A write resumed although A freeze was never finished")
            suite.require(helper.state_phase(a, 1).startswith("frozen"),
                          "A was released by B's thaw")
            suite.expect_ok(helper.freeze_finish(a, 1, 9201, True)[0], helper)
            wa.finish()
            suite.require(wa.error is None, f"A writer failed on its own thaw: {wa.error}")
            return {"foreign_finish": "ESTALE", "wrong_epoch_finish": "ESTALE",
                    "b_released_only_by_b": True, "a_stayed_frozen": True}
        finally:
            for writer in (wa, wb):
                if writer.is_alive():
                    writer.finish(3.0)
    finally:
        suite.release(helper, fixture, "stale-finish")


def case_abort_tombstone(suite: Suite) -> dict:
    helper = suite.spawn("abort-freeze")
    fixture = support.WorkFixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a = fixture.workspace("a")
        suite.expect_ok(helper.mount(fixture.root, a, 1), helper, "mounted")
        suite.require(helper.state_phase(a, 1).startswith("healthy"), "mount is not healthy")
        abort = helper.call("abort_freeze", {"op_id": 9301}, workspace=a, db_epoch=1)
        suite.expect_ok(abort, helper)
        late = helper.freeze_begin(a, 1, 9301)
        suite.expect_error(late, helper, errno.ESTALE)
        suite.require(helper.state_phase(a, 1).startswith("healthy"),
                      "tombstoned begin left the gate frozen/fenced")
        suite.require(write_read(fixture.mounts[a] / "after-tombstone.txt", b"still writable\n") ==
                      b"still writable\n", "gate was orphaned after tombstoned begin")
        suite.expect_ok(helper.freeze_begin(a, 1, 9302), helper)
        suite.expect_ok(helper.freeze_finish(a, 1, 9302, True)[0], helper)
        return {"abort_before_begin": "ok", "late_begin": "ESTALE",
                "orphan_freeze": False, "write_after": True}
    finally:
        suite.release(helper, fixture, "abort-freeze")


def case_mount_cancel(suite: Suite) -> dict:
    helper = suite.spawn("mount-cancel")
    fixture = support.WorkFixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a = fixture.workspace("a")
        args = {"root": str(fixture.root.resolve()), "workspace": a,
                "lease_until": int(time.time()) + 3600, "lazy": False}
        first, _ = helper.send("mount", args, workspace=a, db_epoch=1)
        abort, _ = helper.send("abort_mount", {"request": first}, workspace=a, db_epoch=1)
        replies = {}
        deadline = time.monotonic() + 12.0
        while len(replies) < 2 and time.monotonic() < deadline:
            frame = helper.read(max(0.1, deadline - time.monotonic()))
            rid = frame.get("request_id")
            if rid in (first, abort):
                replies[rid] = support.Reply(frame, rid)
        suite.require(first in replies and abort in replies,
                      f"missing mount/abort replies: {sorted(replies)}")
        mount_reply, abort_reply = replies[first], replies[abort]
        suite.expect_ok(abort_reply, helper)
        pending_cancel = mount_reply.op == "error" and mount_reply.code in (errno.ECANCELED, errno.ESTALE)
        retry = helper.mount(fixture.root, a, 1)
        suite.expect_ok(retry, helper, "mounted")
        suite.require(write_read(fixture.mounts[a] / "retry.txt", b"retry\n") == b"retry\n",
                      "retry mount is not writable")
        result = {"first_mount_op": mount_reply.op, "first_mount_errno": mount_reply.code,
                  "abort_reply": "ok", "retry": "mounted", "retry_write": True,
                  "pending_cancel_observed": pending_cancel}
        if not pending_cancel:
            result["_partial_reason"] = True
            result["_partial_detail"] = (
                "mount completed before abort was processed; the abort really cancelled a published "
                "mount but admitted-pending cancellation was NOT observed. No barrier exists to force "
                "the pending window, so the pending-cancel claim is not made.")
        return result
    finally:
        suite.release(helper, fixture, "mount-cancel")


def case_shutdown(suite: Suite) -> dict:
    helper = suite.spawn("shutdown")
    fixture = support.WorkFixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        suite.require((fixture.mounts[a] / "a.txt").exists() and (fixture.mounts[b] / "b.txt").exists(),
                      "mounts not usable before shutdown")
        reply = helper.shutdown()
        suite.expect_protocol(reply, helper, "shutting_down")
        code = helper.wait_exit(support.EXIT_DEADLINE)
        suite.require(code == 0, f"normal shutdown exit was {code}, expected 0")
        suite.assert_no_owned_mount(fixture.root, "shutdown")
        suite.require(helper.proc.poll() == 0, "child was not reaped with exit 0")
        return {"reply": "shutting_down", "exit": code, "mounts_gone": True, "reaped": True}
    finally:
        suite.release(helper, fixture, "shutdown")


def case_heartbeat_eof(suite: Suite) -> dict:
    helper = suite.spawn("heartbeat-eof")
    fixture = support.WorkFixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        writer, parked = _park(helper, a, 1, 9401, fixture.mounts[a], "a-hb.bin")
        try:
            helper.close_heartbeat()
            writer.finished.wait(support.EXIT_DEADLINE)
            suite.require(writer.error is not None,
                          f"pending write survived heartbeat EOF (bytes={writer.bytes})")
            suite.require(writer.error.errno in (errno.EROFS, errno.EIO, errno.ENOTCONN),
                          f"pending write errno after heartbeat EOF: {writer.error.errno}")
            code = helper.wait_exit(support.EXIT_DEADLINE)
            suite.require(code != 0, f"heartbeat EOF exited 0 ({code})")
            suite.assert_no_owned_mount(fixture.root, "heartbeat-eof")
            dead = suite.expect_dead_control(helper, b, "heartbeat-eof")
            return {"watchdog_exit": code, "queue_errno": writer.error.errno,
                    "parked_bytes": parked, "control": dead, "mounts_gone": True}
        finally:
            if writer.is_alive():
                writer.finish(3.0)
    finally:
        suite.release(helper, fixture, "heartbeat-eof")


def case_child_sigkill(suite: Suite) -> dict:
    helper = suite.spawn("sigkill")
    fixture = support.WorkFixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        writer, parked = _park(helper, a, 1, 9501, fixture.mounts[a], "a-kill.bin")
        try:
            helper.signal(signal.SIGKILL)
            code = helper.wait_exit(support.EXIT_DEADLINE)
            suite.require(code == -signal.SIGKILL, f"child exit {code}, expected SIGKILL")
            writer.finished.wait(support.EXIT_DEADLINE)
            suite.require(writer.error is not None,
                          f"queued write survived helper SIGKILL (bytes={writer.bytes})")
            suite.require(writer.error.errno in (errno.EIO, errno.ENOTCONN, errno.EROFS),
                          f"queued write errno after SIGKILL: {writer.error.errno}")
            for ws in (a, b):
                try:
                    write_read(fixture.mounts[ws] / "after-kill.txt", b"must not land\n")
                    raise AssertionError(f"workspace {ws} stayed writable after helper SIGKILL")
                except OSError as error:
                    suite.require(error.errno in (errno.EIO, errno.ENOTCONN, errno.ENOENT),
                                  f"post-SIGKILL write errno {error.errno} on {ws}")
            suite.assert_no_owned_mount(fixture.root, "sigkill")
            dead_a = suite.expect_dead_control(helper, a, "sigkill-a")
            dead_b = suite.expect_dead_control(helper, b, "sigkill-b")
            return {"exit": code, "queue_errno": writer.error.errno, "parked_bytes": parked,
                    "post_kill_write": "error", "control_a": dead_a, "control_b": dead_b,
                    "mounts_gone": True}
        finally:
            if writer.is_alive():
                writer.finish(3.0)
    finally:
        suite.release(helper, fixture, "sigkill")


def case_parent_sigkill(suite: Suite) -> dict:
    """A real parent stub is SIGKILLed while the helper serves a mounted workspace.

    This is the RPC-level abrupt-parent-loss scenario.  The API-level
    ``Harness(mode="fuse-helper")`` variant is not executed here because that
    harness mode does not exist in this tree; the report states that limitation.
    """
    fixture = support.WorkFixture()
    ready = fixture.root / "stub-ready.json"
    a = fixture.workspace("a")
    stub_pid = os.fork()
    if stub_pid == 0:  # pragma: no cover - child stub process
        try:
            helper = support.HelperProcess(suite.binary, suite.log_dir, "parent-stub")
            helper.hello()
            helper.mount(fixture.root, a, 1)
            ready.write_text(json.dumps({"helper_pid": helper.proc.pid, "workspace": a,
                                         "mountpoint": str(fixture.mounts[a])}))
            while True:
                time.sleep(1)
        except BaseException:
            os._exit(3)
    try:
        deadline = time.monotonic() + 20.0
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        suite.require(ready.exists(), "parent stub did not finish handshake+mount")
        info = json.loads(ready.read_text())
        suite.require(os.path.exists(info["mountpoint"]), "stub mountpoint is absent")
        os.kill(stub_pid, signal.SIGKILL)
        os.waitpid(stub_pid, 0)
        helper_pid = int(info["helper_pid"])
        exited = support.wait_pid_gone(helper_pid, support.EXIT_DEADLINE)
        suite.require(exited, f"orphaned helper pid {helper_pid} stayed alive after parent SIGKILL")
        suite.assert_no_owned_mount(fixture.root, "parent-sigkill")
        return {"parent_stub": "SIGKILL", "helper_pid": helper_pid,
                "orphan_exited": exited, "mounts_gone": True,
                "api_harness_case": "not_executed"}
    finally:
        try:
            os.kill(stub_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(stub_pid, os.WNOHANG)
        except ChildProcessError:
            pass
        suite.release(None, fixture, "parent-sigkill")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--list", action="store_true", help="List required case names and exit")
    args = parser.parse_args()
    if args.list:
        print("\n".join(REQUIRED_CASES))
        return 0
    args.binary = str(Path(args.binary).resolve())
    args.work_dir = None

    # Re-exec the whole harness inside a private owned mount namespace before
    # any fixture or helper exists.  The token/entry check proves the namespace
    # changed and records caller/child inodes in the report.
    try:
        support.ensure_namespace(Path(__file__).resolve(), sys.argv[1:])
    except support.HarnessError as error:
        print(f"namespace entry failed: {support.redact(error)}", file=sys.stderr)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps({
                "status": "failed", "executed_cases": [], "partial_failures": [
                    {"name": "namespace_entry", "status": "failed", "detail": support.redact(error)}],
                "limitations": ["Harness did not enter the private owned mount namespace."],
            }, indent=2) + "\n")
        return 1

    suite = Suite(args)
    receipt_start = support.binary_receipt(suite.binary) if suite.binary.is_file() else {"sha256": None}
    candidate_paths = [Path(__file__).resolve(), Path(__file__).with_name("fuse_helper_native_support.py")]
    candidate_paths += [
        suite.repo / "src/main.rs",
        suite.repo / "src/workspace_lab/fuse_helper.rs",
        suite.repo / "src/workspace_lab/fuse_helper/protocol.rs",
        suite.repo / "src/workspace_lab/fuse_helper/client.rs",
        suite.repo / "src/workspace_lab/fuse_helper/server.rs",
        suite.repo / "src/workspace_lab/fuse_helper/server_ops.rs",
        suite.repo / "src/workspace_lab/fuse_mount.rs",
        suite.repo / "src/workspace_lab/mutation_gate.rs",
        suite.repo / "src/workspace_lab/fuse_dispatch.rs",
    ]
    input_digest, input_rows = support.digest_files(candidate_paths)
    pre = support.preconditions(suite.binary)
    limitations = [
        "The API-level Harness(mode='fuse-helper') SIGKILL case is NOT executed: tests/e2e.py has no "
        "such harness mode in this candidate. The independent-helper abrupt-parent-loss scenario is "
        "covered at RPC level by SIGKILLing a real parent stub process.",
        "Mount-cancel pending cancellation depends on the real mount/abort race; if the mount is "
        "published before abort is processed the case is reported partial and NOT claimed as pending cancel.",
        "Queued writes are parked by the production freeze dispatch (FIFO reply hold), not by a sleep "
        "in the harness; no lazy unmount or global FUSE abort is used.",
        "Every FUSE mount lives under the owned temporary root in a private mount namespace; no host "
        "mount is touched, no LSM policy is changed and no other mount is accessed.",
        "Compilation and native execution are owned by the root workflow; this harness only executes "
        "an already built --binary and never runs Cargo.",
    ]
    case_fns = [
        (REQUIRED_CASES[0], case_hello),
        (REQUIRED_CASES[1], case_generation_opid),
        (REQUIRED_CASES[2], case_workspace_epoch),
        (REQUIRED_CASES[3], case_malformed_frames),
        (REQUIRED_CASES[4], case_two_mounts_thaw),
        (REQUIRED_CASES[5], case_fence_handoff),
        (REQUIRED_CASES[6], case_stale_finish_isolated),
        (REQUIRED_CASES[7], case_abort_tombstone),
        (REQUIRED_CASES[8], case_mount_cancel),
        (REQUIRED_CASES[9], case_shutdown),
        (REQUIRED_CASES[10], case_heartbeat_eof),
        (REQUIRED_CASES[11], case_child_sigkill),
        (REQUIRED_CASES[12], case_parent_sigkill),
    ]
    blocked = None
    if pre["missing"]:
        blocked = "missing preconditions: " + ", ".join(pre["missing"])
    try:
        if blocked:
            for name, _ in case_fns:
                suite.cases.append({"name": name, "status": "blocked", "detail": blocked,
                                    "evidence": {}, "seconds": 0.0})
        else:
            for name, fn in case_fns:
                suite.run_case(name, fn)
    except BaseException as error:
        suite.cases.append({"name": "suite", "status": "failed",
                            "detail": support.redact(f"{type(error).__name__}: {error}"),
                            "evidence": {}, "seconds": 0.0})
    finally:
        try:
            final = suite.final_cleanup()
        except Exception as error:  # noqa: BLE001
            final = {"error": support.redact(error)}
            suite.cases.append({"name": "final_cleanup", "status": "failed",
                                "detail": final["error"], "evidence": {}, "seconds": 0.0})

    receipt_end = support.binary_receipt(suite.binary) if suite.binary.is_file() else {"sha256": None}
    digest_end, _ = support.digest_files(candidate_paths)
    matched = {
        "binary_sha256": receipt_start.get("sha256") == receipt_end.get("sha256"),
        "candidate_input_digest": input_digest == digest_end,
        "receipt_stable": receipt_start == receipt_end,
    }
    by_name = {case["name"]: case for case in suite.cases}
    executed = [case["name"] for case in suite.cases if case["status"] in ("passed", "failed", "partial")]
    failures = [{"name": case["name"], "status": case["status"],
                 "detail": case.get("detail", "")} for case in suite.cases if case["status"] != "passed"]
    all_required_passed = all(by_name.get(name, {}).get("status") == "passed" for name in REQUIRED_CASES)
    passed = bool(all_required_passed and all(matched.values()) and not blocked and not failures)
    report = {
        "status": "passed" if passed else ("blocked" if blocked else "partial" if any(
            case["status"] in ("partial", "blocked", "unexecuted") for case in suite.cases) else "failed"),
        "passed": passed,
        "required": {
            "binary_sha256": receipt_start.get("sha256"),
            "candidate_input_digest": input_digest,
            "executed_cases": REQUIRED_CASES,
            "native_fuse_mounts": 2,
        },
        "receipt": {
            "binary": receipt_start,
            "binary_now": receipt_end,
            "candidate_inputs": input_rows,
            "candidate_input_digest_at_end": digest_end,
        },
        "matched": matched,
        "preconditions": pre,
        "namespace": {
            "entry": "unshare -Urm --propagation private",
            "caller_mount_ns": suite.caller_ns,
            "helper_harness_mount_ns": suite.entry_ns,
            "changed_from_caller": suite.entry_ns != suite.caller_ns,
            "baseline_mounts": len(suite.baseline_mountinfo),
        },
        "executed_cases": executed,
        "cases": suite.cases,
        "partial_failures": failures,
        "limitations": limitations,
        "final_cleanup": final,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "passed": passed,
                      "executed_cases": executed,
                      "partial_failures": failures,
                      "report": str(args.report)}, indent=2))
    if not suite.args.keep:
        try:
            suite.log_dir.rmdir()
        except OSError:
            pass
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
