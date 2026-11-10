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
    "child_sigkill_auto_unmount_and_queued_writes_fail",
    "independent_parent_sigkill_orphans_helper",
    "concurrent_same_workspace_mount_admission_single_kernel_mount",
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
        self.writers: list[support.ParkedWriter] = []
        self.fixtures: list[support.WorkFixture] = []
        self.cleanup_errors: list[dict] = []
        self.uncertain_owner_roots: set[Path] = set()
        self.notes: list[str] = []
        self.entry_ns = support.ns_inode("mnt")
        self.caller_ns = int(os.environ.get("ROOTYARD_FUSE_HELPER_CALLER_NS", "0") or 0)
        self.baseline_mountinfo = support.parse_mountinfo()

    def spawn(self, label: str) -> support.HelperProcess:
        helper = support.HelperProcess(self.binary, self.log_dir, label)
        self.helpers.append(helper)
        return helper

    def fixture(self) -> support.WorkFixture:
        fixture = support.WorkFixture()
        self.fixtures.append(fixture)
        return fixture

    def track_writer(self, writer: support.ParkedWriter,
                     helper: support.HelperProcess | None = None) -> support.ParkedWriter:
        writer.owner_helper = helper
        writer.owner_pid = helper.proc.pid if helper is not None else None
        self.writers.append(writer)
        return writer

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
                  op: str = "ok", workspace: str | None = None,
                  epoch: int | None = None) -> support.Reply:
        self.expect_protocol(reply, helper, op)
        self.require(reply.ok, f"expected ok, got error {reply.code}: {reply.message}")
        if workspace is not None:
            self.require(reply.workspace == workspace,
                         f"successful reply workspace {reply.workspace!r} != {workspace!r}")
        if epoch is not None:
            self.require(reply.db_epoch == epoch,
                         f"successful reply epoch {reply.db_epoch!r} != {epoch!r}")
        return reply

    def expect_pre_handshake_error(self, reply: support.Reply, helper: support.HelperProcess,
                                   code: int) -> support.Reply:
        """Pre-handshake errors have generation 0 and are validated field by field."""
        frame = reply.frame
        self.require(frame.get("protocol") == support.PROTOCOL_VERSION,
                     f"pre-handshake error protocol {frame.get('protocol')} != {support.PROTOCOL_VERSION}")
        self.require(reply.request_id == frame.get("request_id"),
                     "pre-handshake error request id drifted")
        self.require(frame.get("generation") == 0,
                     f"pre-handshake error generation {frame.get('generation')} != 0")
        self.require(reply.op == "error",
                     f"pre-handshake expected error, got {reply.op} args={reply.args}")
        self.require(reply.code == code,
                     f"pre-handshake expected errno {code}, got {reply.code}: {reply.message}")
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

    def expect_owned_ids_gone(self, fixture: support.WorkFixture, ids: list[int], label: str,
                              timeout: float = 10.0) -> list[int]:
        """Require the exact owned mount IDs captured before an owner death to be gone.

        This is the qualified AutoUnmount contract, asserted BEFORE any normal
        owned cleanup backstop runs: the dying helper closes its last FUSE
        descriptor and the fusermount3 monitor socket, so fusermount3 unmounts
        exactly its own mounts without an explicit umount from this harness or
        from the API parent. The backstop must never mask a violation here.
        """
        def mounted() -> list[int]:
            rows = {row["mount_id"] for row in support.owned_mounts(fixture.root)}
            return [mount_id for mount_id in ids if mount_id in rows]

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not mounted():
                return []
            time.sleep(0.05)
        remaining = mounted()
        self.require(not remaining,
                     f"{label}: owned mount IDs still mounted {timeout}s after owner death: {remaining}")
        return []

    def expect_fresh_mount(self, fixture: support.WorkFixture, workspace: str, label: str) -> dict:
        """Mount the same workspace UUID path with a fresh helper afterwards.

        Proves the killed owner's mount identity really disappeared rather than
        being stacked, hidden or merely reported clean: the path must be
        mountable and readable/writable again by a new owner.
        """
        helper = self.spawn(label)
        try:
            self.expect_ok(helper.hello(), helper)
            reply = helper.mount(fixture.root, workspace, 1)
            self.expect_ok(reply, helper, "mounted", workspace=workspace, epoch=1)
            mountpoint = fixture.mounts[workspace]
            written = write_read(mountpoint / "fresh-mount.txt", b"fresh mount after auto-unmount\n")
            self.require((mountpoint / "fresh-mount.txt").exists(),
                         f"{label}: fresh same-UUID path mount is not usable")
            self.require(any(row["mountpoint"] == str(mountpoint) for row in support.owned_mounts(fixture.root)),
                         f"{label}: fresh same-UUID mount {mountpoint} missing from mountinfo")
            return {"workspace": workspace, "mountpoint": str(mountpoint),
                    "write_read": written.decode()}
        finally:
            self.release(helper, fixture, f"{label}-release")

    def _cleanup_error(self, step: str, error: BaseException, evidence: dict) -> None:
        row = {"step": step, "error": support.redact(f"{type(error).__name__}: {error}")}
        self.cleanup_errors.append(row)
        evidence.setdefault("errors", []).append(row)

    def release(self, helper: support.HelperProcess | None, fixture: support.WorkFixture | None,
                label: str, *, helper_pid: int | None = None,
                helper_confirmed_dead: bool = False) -> dict:
        """Release only resources owned by this helper, in safety order.

        Writers are associated with their helper and historical/finished
        writers are never re-joined by a later case.  A live fixture is never
        walked or removed unless the FD owner is confirmed dead, owned writers
        have terminated and mountinfo is empty.
        """
        evidence: dict = {"helper": label, "owner_pid": helper.proc.pid if helper else helper_pid}
        if helper is None:
            if helper_pid is None:
                owned_writers = [w for w in self.writers if getattr(w, "owner_helper", None) is None]
            else:
                owned_writers = [w for w in self.writers if getattr(w, "owner_pid", None) == helper_pid]
        else:
            owned_writers = [w for w in self.writers if getattr(w, "owner_helper", None) is helper]
        for writer in owned_writers:
            try:
                writer.request_stop()
            except Exception as error:  # noqa: BLE001
                self._cleanup_error(f"writer-stop:{writer.path}", error, evidence)
        evidence["writers_signalled"] = len(owned_writers)
        owner_dead = False
        if helper is not None:
            if helper.proc.poll() is None:
                try:
                    helper.kill()
                except Exception as error:  # noqa: BLE001
                    self._cleanup_error("helper-kill", error, evidence)
            try:
                evidence["exit_code"] = helper.wait_exit(support.EXIT_DEADLINE)
                owner_dead = True
            except Exception as error:  # noqa: BLE001
                evidence["exit_code"] = helper.proc.poll()
                self._cleanup_error("helper-reap", error, evidence)
            try:
                helper.stop()
            except Exception as error:  # noqa: BLE001
                self._cleanup_error("helper-stop", error, evidence)
            evidence["helper_log_tail"] = (
                helper.log_tail() if evidence.get("exit_code") not in (None, 0) else "")
        else:
            owner_dead = bool(helper_confirmed_dead)
            if helper_pid is not None:
                owner_dead = owner_dead or support.process_state(helper_pid) in (None, "Z")
        evidence["owner_confirmed_dead"] = owner_dead
        if not owner_dead:
            if fixture is not None:
                self.uncertain_owner_roots.add(fixture.root)
            self._cleanup_error("owner-dead", support.HarnessError(
                "helper FD owner not confirmed dead; refusing writer join and mount cleanup"), evidence)
            evidence["cleanup_skipped"] = "owner-not-confirmed-dead"
            return evidence
        joined = []
        for writer in owned_writers:
            try:
                writer.join(support.THREAD_DEADLINE)
            except Exception as error:  # noqa: BLE001
                self._cleanup_error(f"writer-join:{writer.path}", error, evidence)
            joined.append({"path": str(writer.path), "alive": writer.is_alive(),
                           "bytes": writer.bytes, "error": support.redact(writer.error)
                           if writer.error else None})
            if writer.is_alive():
                self._cleanup_error(f"writer-join:{writer.path}",
                                    support.HarnessError("writer did not terminate after owner death"),
                                    evidence)
        evidence["writers_joined"] = joined
        writers_gone = not any(writer.is_alive() for writer in owned_writers)
        evidence["writers_gone"] = writers_gone
        if fixture is None:
            return evidence
        if not writers_gone:
            self._cleanup_error("fixture-retained", support.HarnessError(
                "writers still alive; refusing to unmount/remove a possibly live FUSE mount"), evidence)
            evidence["cleanup_skipped"] = "writers-alive"
            return evidence
        try:
            evidence["umount_backstop"] = support.umount_owned(fixture.root)
        except Exception as error:  # noqa: BLE001
            self._cleanup_error("umount", error, evidence)
            evidence["umount_backstop"] = []
        try:
            remaining = [row["mountpoint"] for row in support.owned_mounts(fixture.root)]
            evidence["mountinfo"] = remaining
            if remaining:
                self._cleanup_error("mountinfo", support.HarnessError(
                    f"owned mounts remain: {remaining}"), evidence)
        except Exception as error:  # noqa: BLE001
            self._cleanup_error("mountinfo-read", error, evidence)
            remaining = None
        remove = remaining == []
        try:
            evidence["fixture_cleanup"] = fixture.cleanup(
                lambda: evidence.setdefault("mountinfo_before_temp",
                                            [row["mountpoint"] for row in support.owned_mounts(fixture.root)]),
                remove=remove)
        except Exception as error:  # noqa: BLE001
            self._cleanup_error("fixture-cleanup", error, evidence)
        return evidence

    def run_case(self, name: str, fn) -> None:
        started = time.monotonic()
        outcome = {"name": name, "status": "failed", "detail": "", "evidence": {}, "seconds": 0.0}
        self.cleanup_errors = []
        try:
            result = fn(self)
            cleanup = list(self.cleanup_errors)
            if cleanup:
                outcome["status"] = "failed"
                outcome["detail"] = "cleanup failed: " + "; ".join(
                    f"{row['step']}: {row['error']}" for row in cleanup)
                outcome["evidence"] = result if isinstance(result, dict) else {}
                outcome["evidence"]["cleanup_errors"] = cleanup
            elif isinstance(result, dict) and result.pop("_partial_reason", None):
                outcome["status"] = "partial"
                outcome["detail"] = support.redact(result.pop("_partial_detail", ""))
                outcome["evidence"] = result
            else:
                outcome["status"] = "passed"
                outcome["evidence"] = result
        except Exception as error:  # noqa: BLE001 - every failure belongs in the report
            outcome["status"] = "failed"
            outcome["detail"] = support.redact(f"{type(error).__name__}: {error}")
            outcome["cleanup_errors"] = list(self.cleanup_errors)
            outcome["traceback"] = support.redact(traceback.format_exc())
        finally:
            outcome["seconds"] = round(time.monotonic() - started, 3)
            self.cases.append(outcome)
            print(f"[{outcome['status']}] {name}: {outcome['detail'] or 'ok'} ({outcome['seconds']}s)",
                  file=sys.stderr, flush=True)

    def final_cleanup(self) -> dict:
        evidence: dict = {"helpers": [], "writers": [], "umount_backstop": [],
                          "fixture_cleanup": [], "errors": []}

        def record(step: str, error: BaseException) -> None:
            evidence["errors"].append({"step": step,
                                      "error": support.redact(f"{type(error).__name__}: {error}")})

        live_writers = [writer for writer in self.writers if writer.is_alive()]
        for writer in live_writers:
            try:
                writer.request_stop()
            except Exception as error:  # noqa: BLE001
                record(f"writer-stop:{writer.path}", error)
        helpers_dead = True
        for helper in self.helpers:
            row = {"pid": helper.proc.pid}
            if helper.proc.poll() is None:
                try:
                    helper.kill()
                except Exception as error:  # noqa: BLE001
                    record(f"helper-kill:{helper.label}", error)
            try:
                row["exit"] = helper.wait_exit(support.EXIT_DEADLINE)
            except Exception as error:  # noqa: BLE001
                row["exit"] = helper.proc.poll()
                helpers_dead = False
                record(f"helper-reap:{helper.label}", error)
            try:
                helper.stop()
            except Exception as error:  # noqa: BLE001
                record(f"helper-stop:{helper.label}", error)
            evidence["helpers"].append(row)
        evidence["helpers_dead"] = helpers_dead
        if helpers_dead:
            for writer in live_writers:
                try:
                    writer.join(support.THREAD_DEADLINE)
                except Exception as error:  # noqa: BLE001
                    record(f"writer-join:{writer.path}", error)
                evidence["writers"].append({"path": str(writer.path), "alive": writer.is_alive(),
                                            "bytes": writer.bytes})
                if writer.is_alive():
                    record(f"writer-join:{writer.path}", support.HarnessError(
                        "writer did not terminate after all helper owners died"))
        writers_gone = not any(writer.is_alive() for writer in self.writers)
        evidence["writers_gone"] = writers_gone
        if not helpers_dead or not writers_gone:
            record("fixture-retained", support.HarnessError(
                "helper owner or writer termination was not confirmed; refusing to walk/remove FUSE fixtures"))
            evidence["cleanup_skipped"] = "owner-or-writer-not-confirmed"
        else:
            for fixture in self.fixtures:
                if fixture.root in self.uncertain_owner_roots:
                    record(f"fixture-retained:{fixture.root}", support.HarnessError(
                        "external helper owner was not confirmed dead; refusing final mount cleanup"))
                    continue
                try:
                    evidence["umount_backstop"].extend(support.umount_owned(fixture.root))
                    remaining = [row["mountpoint"] for row in support.owned_mounts(fixture.root)]
                    if remaining:
                        record(f"mountinfo:{fixture.root}", support.HarnessError(
                            f"owned mounts remain: {remaining}"))
                    evidence["fixture_cleanup"].append(
                        fixture.cleanup(lambda: None, remove=not remaining))
                except Exception as error:  # noqa: BLE001
                    record(f"fixture-cleanup:{fixture.root}", error)
        roots = [self.repo, *(fixture.root for fixture in self.fixtures)]
        try:
            evidence["owned_mounts"] = [row["mountpoint"] for root in roots
                                        for row in support.owned_mounts(root)]
        except Exception as error:  # noqa: BLE001
            record("mountinfo-final-read", error)
            evidence["owned_mounts"] = []
        if evidence["owned_mounts"]:
            record("mountinfo-final", support.HarnessError(
                f"owned mounts remain after cleanup: {evidence['owned_mounts']}"))
        return evidence


def mount_pair(suite: Suite, helper: support.HelperProcess, fixture: support.WorkFixture):
    a = fixture.workspace("a")
    b = fixture.workspace("b")
    ra = helper.mount(fixture.root, a, 1)
    suite.expect_ok(ra, helper, "mounted", workspace=a, epoch=1)
    rb = helper.mount(fixture.root, b, 1)
    suite.expect_ok(rb, helper, "mounted", workspace=b, epoch=1)
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
            suite.expect_pre_handshake_error(reply, bad, errno.EPROTO)
        finally:
            code = bad.wait_exit(8.0)
            suite.require(code != 0, f"bad-version helper exited 0 ({code})")
            bad.stop()
        return {"hello": "ok", "bad_version_reply": "EPROTO", "bad_version_exit": code}
    finally:
        suite.release(helper, fixture, "hello")


def case_generation_opid(suite: Suite) -> dict:
    helper = suite.spawn("generation")
    fixture = suite.fixture()
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
        suite.expect_ok(helper.freeze_begin(a, 1, op_id), helper, workspace=a, epoch=1)
        busy = helper.freeze_begin(b, 1, op_id)
        suite.expect_error(busy, helper, errno.EEXIST)
        again = helper.freeze_begin(a, 1, 7002)
        suite.expect_error(again, helper, errno.EBUSY)
        suite.expect_ok(helper.freeze_finish(a, 1, op_id, True)[0], helper, workspace=a, epoch=1)
        return {"stale_generation": "ESTALE", "unknown_op": "EPROTO",
                "duplicate_op_id": "EEXIST", "second_freeze": "EBUSY"}
    finally:
        suite.release(helper, fixture, "generation")


def case_workspace_epoch(suite: Suite) -> dict:
    helper = suite.spawn("workspace-epoch")
    fixture = suite.fixture()
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
        suite.expect_ok(helper.mount(fixture.root, a, 1), helper, "mounted", workspace=a, epoch=1)
        wrong_freeze = helper.freeze_begin(a, 999, 8001)
        suite.expect_error(wrong_freeze, helper, errno.ESTALE)
        wrong_finish = helper.freeze_finish(a, 999, 8001, True)[0]
        suite.expect_error(wrong_finish, helper, errno.ESTALE)
        # A trusted parent may explicitly authorize a newer epoch. A stale
        # epoch after that handoff must be rejected.
        suite.expect_ok(helper.handoff(a, 2), helper, workspace=a, epoch=2)
        wrong_handoff = helper.handoff(a, 1)
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
                          b'"db_epoch":0,"op":"hello","args":{"pid":1,"version":1},"extra":true}',
         "exact"),
        ("oversize", b"{" + b"x" * (support.MAX_FRAME_BYTES + 1) + b"}", "exact"),
        ("zero-length", b"", "exact"),
        # Complete frame prefix followed by bytes that are not valid JSON.
        ("invalid-json", b'{"protocol":1,"generation":5', "exact"),
        # True truncation: the length prefix promises 72 more bytes than are
        # sent, then the write side is closed so the helper sees EOF mid-frame.
        ("truncated-frame", b'{"protocol":1,"generation":5,"request_id":2,"op":"hello"',
         "truncated"),
    ]
    for label, payload, kind in cases:
        helper = suite.spawn(f"malformed-{label}")
        try:
            helper.hello()
            declared = len(payload) + 64 if kind == "truncated" else len(payload)
            with helper.lock:
                helper.control.sendall(support.raw_frame(payload, declared))
                if kind == "truncated":
                    helper.control.shutdown(support.socket.SHUT_WR)
            code = helper.wait_exit(8.0)
            suite.require(code != 0, f"{label}: helper survived a malformed frame with exit 0")
            evidence[label] = {"exit": code, "declared_bytes": declared,
                               "sent_bytes": len(payload),
                               "eof_after_prefix": kind == "truncated"}
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


def _park(suite: Suite, helper: support.HelperProcess, workspace: str, epoch: int, op_id: int,
          mountpoint: Path, name: str) -> tuple[support.ParkedWriter, int]:
    writer = suite.track_writer(support.ParkedWriter(mountpoint / name), helper)
    writer.start()
    writer.wait_started()
    reply = helper.freeze_begin(workspace, epoch, op_id)
    if not reply.ok:
        writer.request_stop()
        raise AssertionError(f"freeze_begin failed: {reply.code} {reply.message}")
    before = writer.quiesce(0.15)
    time.sleep(0.30)
    if helper.state_phase(workspace, epoch) != "frozen":
        raise AssertionError("gate did not remain frozen while the write was parked")
    if not writer.is_alive():
        raise AssertionError(f"writer was not parked by freeze: error={writer.error}")
    if writer.bytes != before:
        raise AssertionError(f"writer progressed {before}->{writer.bytes} while frozen")
    return writer, before


def case_two_mounts_thaw(suite: Suite) -> dict:
    helper = suite.spawn("thaw")
    fixture = suite.fixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        suite.require(helper.state_phase(a, 1) in ("healthy", "frozen"),
                      f"unexpected A phase {helper.state_phase(a, 1)}")
        writer, parked_bytes = _park(suite, helper, a, 1, 9001, fixture.mounts[a], "a-parked.bin")
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
            suite.expect_ok(reply, helper, workspace=a, epoch=1)
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
            writer.request_stop()
    finally:
        suite.release(helper, fixture, "thaw")


def case_fence_handoff(suite: Suite) -> dict:
    helper = suite.spawn("fence")
    fixture = suite.fixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        writer, parked = _park(suite, helper, a, 1, 9101, fixture.mounts[a], "a-fenced.bin")
        try:
            reply, elapsed = helper.freeze_finish(a, 1, 9101, False)
            suite.expect_ok(reply, helper, workspace=a, epoch=1)
            suite.require(elapsed < 6.0, f"finish_fence reply took {elapsed:.2f}s")
            writer.finished.wait(8.0)
            suite.require(writer.error is not None,
                          f"parked write did not fail after fence (bytes={writer.bytes})")
            suite.require(writer.error.errno == errno.EROFS,
                          f"parked write errno {writer.error.errno}, expected EROFS")
            suite.require(helper.state_phase(a, 1).startswith("fenced"),
                          f"gate phase after fence is {helper.state_phase(a, 1)!r}")
            attempt = None
            try:
                attempt = open(fixture.mounts[a] / "new-after-fence.txt", "wb")
                attempt.write(b"must fail\n")
                attempt.flush()
                os.fsync(attempt.fileno())
                raise AssertionError("new write succeeded while gate was fenced")
            except OSError as error:
                suite.require(error.errno in (errno.EROFS, errno.EAGAIN, errno.EIO),
                              f"new fenced write errno {error.errno}")
            finally:
                if attempt is not None:
                    attempt.close()
            until = int(time.time()) + 3600
            handoff = helper.handoff(a, 2, until)
            suite.expect_ok(handoff, helper, workspace=a, epoch=2)
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
            writer.request_stop()
    finally:
        suite.release(helper, fixture, "fence")


def case_stale_finish_isolated(suite: Suite) -> dict:
    helper = suite.spawn("stale-finish")
    fixture = suite.fixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        wa, _ = _park(suite, helper, a, 1, 9201, fixture.mounts[a], "a-stale.bin")
        wb, _ = _park(suite, helper, b, 1, 9202, fixture.mounts[b], "b-stale.bin")
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
            suite.expect_ok(helper.freeze_finish(b, 1, 9202, True)[0], helper, workspace=b, epoch=1)
            wb.finish()
            suite.require(wb.error is None, f"B writer failed on legitimate thaw: {wb.error}")
            suite.require(wa.is_alive() and wa.bytes == wa.quiesce(0.3),
                          "A write resumed although A freeze was never finished")
            suite.require(helper.state_phase(a, 1).startswith("frozen"),
                          "A was released by B's thaw")
            suite.expect_ok(helper.freeze_finish(a, 1, 9201, True)[0], helper, workspace=a, epoch=1)
            wa.finish()
            suite.require(wa.error is None, f"A writer failed on its own thaw: {wa.error}")
            return {"foreign_finish": "ESTALE", "wrong_epoch_finish": "ESTALE",
                    "b_released_only_by_b": True, "a_stayed_frozen": True}
        finally:
            for writer in (wa, wb):
                writer.request_stop()
    finally:
        suite.release(helper, fixture, "stale-finish")


def case_abort_tombstone(suite: Suite) -> dict:
    helper = suite.spawn("abort-freeze")
    fixture = suite.fixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a = fixture.workspace("a")
        suite.expect_ok(helper.mount(fixture.root, a, 1), helper, "mounted", workspace=a, epoch=1)
        suite.require(helper.state_phase(a, 1).startswith("healthy"), "mount is not healthy")
        abort = helper.call("abort_freeze", {"op_id": 9301}, workspace=a, db_epoch=1)
        suite.expect_ok(abort, helper, workspace=a, epoch=1)
        late = helper.freeze_begin(a, 1, 9301)
        suite.expect_error(late, helper, errno.ESTALE)
        suite.require(helper.state_phase(a, 1).startswith("healthy"),
                      "tombstoned begin left the gate frozen/fenced")
        suite.require(write_read(fixture.mounts[a] / "after-tombstone.txt", b"still writable\n") ==
                      b"still writable\n", "gate was orphaned after tombstoned begin")
        suite.expect_ok(helper.freeze_begin(a, 1, 9302), helper, workspace=a, epoch=1)
        suite.expect_ok(helper.freeze_finish(a, 1, 9302, True)[0], helper, workspace=a, epoch=1)
        return {"abort_before_begin": "ok", "late_begin": "ESTALE",
                "orphan_freeze": False, "write_after": True}
    finally:
        suite.release(helper, fixture, "abort-freeze")


def case_mount_cancel(suite: Suite) -> dict:
    helper = suite.spawn("mount-cancel")
    fixture = suite.fixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a = fixture.workspace("a")
        args = {"root": str(fixture.root.resolve()), "workspace": a,
                "lease_until": int(time.time()) + 3600, "lazy": False}
        first, _ = helper.send("mount", args, workspace=a, db_epoch=1)
        abort, _ = helper.send("abort_mount", {"request": first}, workspace=a, db_epoch=0)
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
        suite.expect_ok(abort_reply, helper, workspace=a, epoch=0)
        pending_cancel = mount_reply.op == "error" and mount_reply.code in (errno.ECANCELED, errno.ESTALE)
        retry = helper.mount(fixture.root, a, 1)
        suite.expect_ok(retry, helper, "mounted", workspace=a, epoch=1)
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
    fixture = suite.fixture()
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
    fixture = suite.fixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        writer, parked = _park(suite, helper, a, 1, 9401, fixture.mounts[a], "a-hb.bin")
        try:
            helper.close_heartbeat()
            writer.finished.wait(support.EXIT_DEADLINE)
            suite.require(writer.error is not None,
                          f"pending write survived heartbeat EOF (bytes={writer.bytes})")
            suite.require(writer.error.errno in (errno.EROFS, errno.EIO, errno.ENOTCONN, errno.ECONNABORTED),
                          f"pending write errno after heartbeat EOF: {writer.error.errno}")
            code = helper.wait_exit(support.EXIT_DEADLINE)
            suite.require(code != 0, f"heartbeat EOF exited 0 ({code})")
            owned = [row["mountpoint"] for row in support.owned_mounts(fixture.root)]
            dead = suite.expect_dead_control(helper, b, "heartbeat-eof")
            return {"watchdog_exit": code, "queue_errno": writer.error.errno,
                    "parked_bytes": parked, "control": dead,
                    "owned_mounts_before_release": owned}
        finally:
            writer.request_stop()
    finally:
        suite.release(helper, fixture, "heartbeat-eof")


def case_child_sigkill(suite: Suite) -> dict:
    """SIGKILLed helper: AutoUnmount removes its exact mounts, writer fails.

    The asserted contract is the helper's ownership boundary on a qualified
    environment (private mount namespace, namespace root, fusermount3): the
    exact mount IDs captured before the kill must disappear in bounded time
    after the helper exit and queued-writer termination, BEFORE the normal
    owned cleanup backstop. A fresh helper must then be able to mount the same
    workspace UUID path. API-parent SIGKILL semantics are NOT covered here.
    """
    helper = suite.spawn("sigkill")
    fixture = suite.fixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        a, b = mount_pair(suite, helper, fixture)
        owned_rows = support.owned_mounts(fixture.root)
        owned_ids = sorted(row["mount_id"] for row in owned_rows)
        suite.require(sorted(row["mountpoint"] for row in owned_rows) == sorted([str(fixture.mounts[a]), str(fixture.mounts[b])]),
                      f"owned mount IDs before kill {owned_ids} do not match the requested mounts")
        writer, parked = _park(suite, helper, a, 1, 9501, fixture.mounts[a], "a-kill.bin")
        try:
            helper.signal(signal.SIGKILL)
            code = helper.wait_exit(support.EXIT_DEADLINE)
            suite.require(code == -signal.SIGKILL, f"child exit {code}, expected SIGKILL")
            writer.finished.wait(support.EXIT_DEADLINE)
            suite.require(writer.error is not None,
                          f"queued write survived helper SIGKILL (bytes={writer.bytes})")
            suite.require(writer.error.errno in (errno.EIO, errno.ENOTCONN, errno.EROFS, errno.ECONNABORTED),
                          f"queued write errno after SIGKILL: {writer.error.errno}")
            for ws in (a, b):
                if not any(row["mountpoint"] == str(fixture.mounts[ws])
                           for row in support.owned_mounts(fixture.root)):
                    # The bare mountpoint is an ordinary directory after
                    # unmount; writing it would not probe the old FUSE session.
                    continue
                try:
                    write_read(fixture.mounts[ws] / "after-kill.txt", b"must not land\n")
                    raise AssertionError(f"workspace {ws} stayed writable after helper SIGKILL")
                except OSError as error:
                    suite.require(error.errno in (errno.EIO, errno.ENOTCONN, errno.ENOENT, errno.ECONNABORTED),
                                  f"post-SIGKILL write errno {error.errno} on {ws}")
            suite.require(writer.finished.is_set(), "queued writer did not terminate before the mount check")
            # AutoUnmount contract: the kernel closed the helper's last FUSE
            # descriptor and fusermount3 saw its monitor socket close, so it
            # unmounted exactly the captured mount IDs. Required BEFORE the
            # normal owned cleanup backstop so the backstop cannot mask it.
            gone = suite.expect_owned_ids_gone(fixture, owned_ids, "child-sigkill")
            remount = suite.expect_fresh_mount(fixture, a, "sigkill-remount")
            dead_a = suite.expect_dead_control(helper, a, "sigkill-a")
            dead_b = suite.expect_dead_control(helper, b, "sigkill-b")
            return {"exit": code, "queue_errno": writer.error.errno, "parked_bytes": parked,
                    "post_kill_write": "error", "control_a": dead_a, "control_b": dead_b,
                    "mount_ids_before_kill": owned_ids, "mount_ids_after_kill": gone,
                    "auto_unmount": "owned mount IDs gone before the cleanup backstop",
                    "fresh_same_uuid_mount": remount,
                    "explicit_cleanup": "normal non-lazy umount remains the release backstop only"}
        finally:
            writer.request_stop()
    finally:
        suite.release(helper, fixture, "sigkill")


def case_parent_sigkill(suite: Suite) -> dict:
    """A real RPC parent stub is SIGKILLed while the helper serves a mount.

    This exercises an external RPC parent process, not the production API
    client and not the API-level ``Harness(mode="fuse-helper")`` path (that
    harness mode does not exist in this tree).  Consequently it cannot prove
    production client deadline or RAII behaviour; that remains a limitation.
    """
    fixture = suite.fixture()
    ready = fixture.root / "stub-ready.json"
    pid_path = fixture.root / "stub-helper-pid.json"
    a = fixture.workspace("a")
    helper_pid: int | None = None
    stub_pid = os.fork()
    if stub_pid == 0:  # pragma: no cover - child stub process
        child_helper = None
        try:
            child_helper = support.HelperProcess(suite.binary, suite.log_dir, "parent-stub")
            pid_path.write_text(json.dumps({"helper_pid": child_helper.proc.pid}))
            hello = child_helper.hello()
            suite.expect_ok(hello, child_helper, workspace=None, epoch=0)
            mount = child_helper.mount(fixture.root, a, 1)
            suite.expect_ok(mount, child_helper, "mounted", workspace=a, epoch=1)
            owned = [row["mountpoint"] for row in support.owned_mounts(fixture.root)]
            suite.require(str(fixture.mounts[a]) in owned,
                          f"stub mountpoint not in owned mountinfo: {owned}")
            lower = (fixture.mounts[a] / "a.txt").read_text()
            suite.require(lower == "lower-a\n", f"stub lower read {lower!r}")
            written = write_read(fixture.mounts[a] / "stub-probe.txt", b"stub alive\n")
            suite.require(written == b"stub alive\n", "stub real mount write/read failed")
            ready.write_text(json.dumps({
                "helper_pid": child_helper.proc.pid, "workspace": a,
                "mountpoint": str(fixture.mounts[a]), "hello": hello.op,
                "mount_reply": mount.op, "owned_mounts": owned,
                "lower_read": lower, "probe_read": written.decode(),
            }))
            while True:
                time.sleep(1)
        except BaseException as error:  # noqa: BLE001 - report setup failure to parent
            ready.write_text(json.dumps({
                "setup_error": support.redact(f"{type(error).__name__}: {error}"),
                "helper_pid": child_helper.proc.pid if child_helper is not None else None,
            }))
            if child_helper is not None:
                try:
                    child_helper.kill()
                except Exception:  # noqa: BLE001
                    pass
            os._exit(3)
    try:
        deadline = time.monotonic() + 20.0
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        suite.require(ready.exists(), "parent RPC stub did not finish handshake+mount")
        info = json.loads(ready.read_text())
        helper_pid = info.get("helper_pid")
        suite.require(not info.get("setup_error"),
                      f"parent RPC stub setup failed: {info.get('setup_error')}")
        suite.require(info.get("hello") == "ok" and info.get("mount_reply") == "mounted",
                      f"stub did not assert successful hello/mount replies: {info}")
        suite.require(str(fixture.mounts[a]) in info.get("owned_mounts", []),
                      "stub did not prove an actual owned FUSE mount")
        suite.require(info.get("lower_read") == "lower-a\n"
                      and info.get("probe_read") == "stub alive\n",
                      "stub did not prove real mount read/write before readiness")
        owned_ids = [row["mount_id"] for row in support.owned_mounts(fixture.root)
                     if row["mountpoint"] == str(fixture.mounts[a])]
        suite.require(len(owned_ids) == 1,
                      f"parent stub did not capture its exact owned mount ID: {info.get('owned_mounts')}")
        os.kill(stub_pid, signal.SIGKILL)
        os.waitpid(stub_pid, 0)
        stub_pid = 0
        helper_pid = int(info["helper_pid"])
        exited = support.wait_pid_gone(helper_pid, support.EXIT_DEADLINE)
        suite.require(exited, f"orphaned helper pid {helper_pid} stayed alive after parent SIGKILL")
        # Same AutoUnmount contract as the direct child SIGKILL: the orphaned
        # helper's death must remove exactly its captured mount ID in bounded
        # time, before this case's normal owned cleanup backstop runs.
        gone = suite.expect_owned_ids_gone(fixture, owned_ids, "parent-sigkill")
        remount = suite.expect_fresh_mount(fixture, a, "parent-sigkill-remount")
        return {"parent_stub": "SIGKILL", "helper_pid": helper_pid,
                "orphan_exited": exited, "hello_mount_asserted": True,
                "real_mount_read_write": True,
                "mount_ids_before_kill": owned_ids, "mount_ids_after_kill": gone,
                "auto_unmount": "orphaned helper's owned mount ID gone before the cleanup backstop",
                "fresh_same_uuid_mount": remount,
                "api_harness_case": "not_executed",
                "api_client_sigkill": "not claimed: this is an external RPC parent stub, "
                                      "not the production API client",
                "coverage": "external RPC parent stub (not production API client)"}
    finally:
        if stub_pid:
            try:
                os.kill(stub_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(stub_pid, 0)
            except ChildProcessError:
                pass
        if helper_pid is None and pid_path.exists():
            try:
                helper_pid = int(json.loads(pid_path.read_text()).get("helper_pid"))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                helper_pid = None
        if helper_pid is not None and support.process_state(helper_pid) not in (None, "Z"):
            try:
                os.kill(helper_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            support.wait_pid_gone(helper_pid, support.EXIT_DEADLINE)
        owner_dead = bool(helper_pid is not None and support.process_state(helper_pid) in (None, "Z"))
        suite.release(None, fixture, "parent-sigkill", helper_pid=helper_pid,
                      helper_confirmed_dead=owner_dead)


def case_concurrent_mount_admission(suite: Suite) -> dict:
    """Burst same-workspace mounts and require exactly one kernel mount.

    Regression for the pending -> mounts recheck: several valid Mount frames
    may all observe Missing before the first publishes. They are sent without
    waiting so the helper operation pool runs them concurrently. Only the
    documented transient admission errors are tolerated; helper death, an
    unexpected reply or a second kernel mount fails the case.
    """
    helper = suite.spawn("concurrent-admission")
    fixture = suite.fixture()
    try:
        suite.expect_ok(helper.hello(), helper)
        workspace = fixture.workspace("a")
        mountpoint = fixture.mounts[workspace]
        args = {"root": str(fixture.root.resolve()), "workspace": workspace,
                "lease_until": int(time.time()) + 3600, "lazy": False}
        burst = [helper.send("mount", args, workspace=workspace, db_epoch=1)[0]
                 for _ in range(5)]
        suite.require(len(set(burst)) == 5, f"mount request ids not distinct: {burst}")
        replies: dict[int, support.Reply] = {}
        deadline = time.monotonic() + 25.0
        while len(replies) < len(burst):
            remaining = deadline - time.monotonic()
            suite.require(remaining > 0, f"timed out after {len(replies)}/{len(burst)} replies; "
                                         f"helper exit={helper.proc.poll()} requests={burst}")
            try:
                frame = helper.read(max(0.1, remaining))
            except (support.ChildExited, TimeoutError, OSError) as error:
                code = helper.proc.poll()
                if code is None:
                    try:
                        code = helper.wait_exit(2.0)
                    except support.HarnessError:
                        code = helper.proc.poll()
                raise AssertionError(support.redact(
                    f"helper died/control failed after {len(replies)}/{len(burst)} replies: "
                    f"{type(error).__name__}: {error}; child exit={code}")) from None
            rid = frame.get("request_id")
            suite.require(rid in burst, f"unexpected reply request_id {rid}: {frame}")
            suite.require(rid not in replies, f"duplicate reply for request {rid}: {frame}")
            replies[rid] = support.Reply(frame, rid)
        rows, mounted = [], 0
        for rid in burst:
            reply = replies[rid]
            suite.expect_protocol(reply, helper)
            if reply.op == "mounted":
                suite.require(reply.workspace == workspace and reply.db_epoch == 1,
                              f"mount {rid} success workspace/epoch {reply.workspace}/{reply.db_epoch}")
                mounted += 1
                rows.append({"request_id": rid, "op": "mounted", "epoch": reply.db_epoch})
            else:
                suite.require(reply.op == "error", f"mount {rid} unexpected op {reply.op}")
                suite.require(reply.code in (errno.EBUSY, errno.EEXIST, errno.ETIMEDOUT, errno.ECANCELED),
                              f"mount {rid} disallowed errno {reply.code}: {reply.message}")
                rows.append({"request_id": rid, "op": "error", "errno": reply.code})
        suite.require(mounted >= 1, f"no concurrent mount succeeded: {rows}")
        suite.require(helper.proc.poll() is None, f"helper exited after burst: {helper.proc.poll()}")
        phase = helper.state_phase(workspace, 1)
        suite.require(phase == "healthy", f"phase after admission is {phase!r}")
        owned = support.owned_mounts(fixture.root)
        path_ids = sorted(row["mount_id"] for row in owned if row["mountpoint"] == str(mountpoint))
        suite.require(len(path_ids) == 1, f"expected one kernel mount for {mountpoint}, got {path_ids}; "
                                          f"owned={[(r['mountpoint'], r['mount_id']) for r in owned]}")
        suite.require(len(owned) == 1 and owned[0]["mount_id"] == path_ids[0],
                      f"extra owned mounts after concurrent admission: "
                      f"{[(r['mountpoint'], r['mount_id']) for r in owned]}")
        probe = b"concurrent admission write\n"
        suite.require(write_read(mountpoint / "admission.txt", probe) == probe,
                      "write/read through the admitted mount failed")
        suite.require((mountpoint / "a.txt").read_text() == "lower-a\n",
                      "lower file unreadable through the admitted mount")
        unmount = helper.call("unmount", None, workspace=workspace, db_epoch=0)
        suite.expect_ok(unmount, helper, "unmounted", workspace=workspace)
        suite.assert_no_owned_mount(fixture.root, "concurrent-admission-unmount")
        shutdown = helper.shutdown()
        suite.expect_protocol(shutdown, helper, "shutting_down")
        child_exit = helper.wait_exit(support.EXIT_DEADLINE)
        suite.require(child_exit == 0, f"shutdown exit {child_exit}, expected 0")
        suite.assert_no_owned_mount(fixture.root, "concurrent-admission-shutdown")
        return {"request_ids": burst, "reply_count": len(replies), "requests": rows,
                "mounted_replies": mounted, "kernel_mount_ids": path_ids,
                "single_kernel_mount": True, "phase_after_admission": phase,
                "write_read": probe.decode().strip(), "unmount": "unmounted",
                "child_exit": child_exit,
                "owned_mounts_after_exit": len(support.owned_mounts(fixture.root))}
    finally:
        suite.release(helper, fixture, "concurrent-admission")


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
    source_digest_before = ""
    try:
        source_digest_before = support.source_digest(suite.repo)
        original_receipt = support.read_build_receipt(suite.binary)
        suite.binary = support.snapshot_binary(
            suite.binary, suite.binary.with_suffix(".build.json"),
            suite.log_dir / "snapshots",
            expected_sha256=original_receipt.get("binary_sha256"),
            expected_source_digest=source_digest_before)
    except (OSError, support.HarnessError) as error:
        detail = support.redact(f"{type(error).__name__}: {error}")
        print(f"immutable binary snapshot failed: {detail}", file=sys.stderr)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({
            "status": "blocked", "passed": False, "executed_cases": [],
            "partial_failures": [{"name": "immutable_binary_snapshot", "status": "blocked",
                                  "detail": detail}],
            "limitations": ["No helper child was executed because the build receipt/source digest "
                            "did not verify or the binary could not be snapshotted."],
        }, indent=2) + "\n")
        return 1
    receipt_start = support.binary_receipt(suite.binary)
    # Tests digest is deliberately separate from the build source digest.  The
    # build receipt source manifest comes from scripts/build_native.source_digest
    # (exact src/migrations/schema/vendor trees plus required Cargo/build files),
    # never a whole-repo rglob that could ingest target/.
    candidate_paths = [Path(__file__).resolve(), Path(__file__).with_name("fuse_helper_native_support.py")]
    input_digest, input_rows = support.digest_files(candidate_paths)
    pre = support.preconditions(suite.binary, suite.repo)
    limitations = [
        "The API-level Harness(mode='fuse-helper') SIGKILL case is NOT executed: tests/e2e.py has no "
        "such harness mode in this candidate. The independent-helper abrupt-parent-loss scenario is "
        "covered by an external RPC parent stub, NOT by the production API client.",
        "External RPC waits in this harness are not proof of production client deadlines or RAII. "
        "No Python test can establish the API client's signal/cleanup guarantees; that API SIGKILL "
        "limitation remains.",
        "Mount-cancel pending cancellation depends on the real mount/abort race; if the mount is "
        "published before abort is processed the case is reported partial and NOT claimed as pending cancel.",
        "Queued writes are parked by the production freeze dispatch (FIFO reply hold), not by a sleep "
        "in the harness; no lazy unmount or global FUSE abort is used.",
        "Every FUSE mount lives under the owned temporary root in a private mount namespace; no host "
        "mount is touched, no LSM policy is changed and no other mount is accessed.",
        "The SIGKILL cases assert the qualified AutoUnmount contract: the exact owned mount IDs "
        "captured before the kill must disappear in bounded time after the owner is confirmed dead "
        "and the queued writer has terminated, BEFORE the normal owned cleanup backstop, and a fresh "
        "helper must then mount and use the same workspace UUID path again. This is the fuse-helper "
        "deployment contract on a qualified host; it is NOT an assumption that any killed FUSE "
        "mount disappears, and the backstop is never used as evidence for it.",
        "Qualification is host policy, not harness capability: AutoUnmount needs fusermount3 and a "
        "caller allowed to use auto_unmount/allow_other, so the supported shape is a private user "
        "and mount namespace entered as namespace root (unshare -Urm). This harness targets that "
        "namespace-root shape; native qualification of a conventional non-root host is pending and "
        "may need user_allow_other in the host fuse.conf. Nothing here edits a global fuse.conf or "
        "an LSM policy, the session ACL stays owner-only (no explicit AllowOther/AllowRoot), and no "
        "unsupported rootless guarantee is implied.",
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
        (REQUIRED_CASES[13], case_concurrent_mount_admission),
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

    final_errors = final.get("errors") or ([{"step": "final_cleanup", "error": final["error"]}]
                                           if final.get("error") else [])
    if final_errors:
        suite.cases.append({"name": "final_cleanup", "status": "failed",
                            "detail": "; ".join(f"{row.get('step')}: {row.get('error')}"
                                                for row in final_errors),
                            "evidence": {"final_cleanup": final}, "seconds": 0.0})
    receipt_end = support.binary_receipt(suite.binary) if suite.binary.is_file() else {"sha256": None}
    digest_end, _ = support.digest_files(candidate_paths)
    try:
        source_digest_after = support.source_digest(suite.repo)
    except support.HarnessError as error:
        source_digest_after = None
        final_errors.append({"step": "source-digest-after", "error": support.redact(error)})
    matched = {
        "binary_sha256": receipt_start.get("sha256") == receipt_end.get("sha256"),
        "candidate_input_digest": input_digest == digest_end,
        "receipt_stable": receipt_start == receipt_end,
        "source_digest_stable": source_digest_after == source_digest_before,
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
            "immutable_binary": str(suite.binary),
            "build_source_digest": source_digest_before,
            "tests_input_digest": input_digest,
            "executed_cases": REQUIRED_CASES,
            "native_fuse_mounts": 2,
        },
        "receipt": {
            "binary": receipt_start,
            "binary_now": receipt_end,
            "build_source_digest_before": source_digest_before,
            "build_source_digest_after": source_digest_after,
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
