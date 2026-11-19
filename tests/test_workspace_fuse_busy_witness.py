#!/usr/bin/env python3
"""Pure contract tests for the fixture-only FUSE busy witness projection.

These tests use synthetic receipt records only.  They do not start the service,
FUSE, PostgreSQL, Git, a child process, a thread, or the network.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock

import workspace_normal_shutdown_support as normal_shutdown
from workspace_normal_shutdown_support import (
    BUSY_TARGETS,
    MAX_RECEIPT_BYTES,
    MAX_RECEIPTS,
    UNKNOWN,
    WRITER_CLOSE_STATES,
    fnv1a64,
    parse_witness_receipt,
    path_tag,
    process_tag,
    project_busy_witness,
    project_busy_witness_receipts,
)


HELPER_TAG = process_tag(4100, 9100)
WRITER_TAG = process_tag(4200, 9200)
WRITER_PATH = "/fixture/workspace-service/mounts/writer"
GIT_PATH = "/fixture/workspace-service/mounts/git"
PUT_PATH = "/fixture/workspace-service/mounts/put"
OTHER_PATH = "/fixture/workspace-service/mounts/other"
EXPECTED = {
    "writer": (11, path_tag(WRITER_PATH)),
    "git": (12, path_tag(GIT_PATH)),
    "put": (13, path_tag(PUT_PATH)),
}
OWNED = set(EXPECTED.values()) | {(14, path_tag(OTHER_PATH))}


def _umount(*, entry=1000, result=2000, mount_id=11, path=None,
            rc=-1, error=errno.EBUSY, owned=1, tag=HELPER_TAG):
    return {
        "kind": "umount",
        "role": "helper",
        "entry_ns": entry,
        "result_ns": result,
        "mount_id": mount_id,
        "path_hash": path_tag(path or WRITER_PATH),
        "proc_tag": tag,
        "rc": rc,
        "errno": error,
        "flags": 0,
        "owned": owned,
    }


def _close(*, entry=100, result=900, rc=0, error=0, tag=WRITER_TAG):
    return {
        "kind": "close",
        "role": "writer",
        "entry_ns": entry,
        "result_ns": result,
        "mount_id": 0,
        "path_hash": 0,
        "proc_tag": tag,
        "rc": rc,
        "errno": error,
        "flags": 0,
        "owned": 0,
    }


def _project(records):
    return project_busy_witness(
        records,
        helper_tag=HELPER_TAG,
        writer_tag=WRITER_TAG,
        expected_mounts=EXPECTED,
        owned_mounts=OWNED,
    )


def _project_with(records, *, expected=None, owned=None):
    return project_busy_witness(
        records,
        helper_tag=HELPER_TAG,
        writer_tag=WRITER_TAG,
        expected_mounts=EXPECTED if expected is None else expected,
        owned_mounts=OWNED if owned is None else owned,
    )


def _line(record):
    return (
        "W1 kind={kind} role={role} entry_ns={entry_ns} result_ns={result_ns} "
        "mount_id={mount_id} path_hash={path_hash:016x} proc_tag={proc_tag:016x} "
        "rc={rc} errno={errno} flags={flags} owned={owned}\n"
    ).format(**record).encode("ascii")


def _write_private(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return path


class BusyWitnessProjectionTest(unittest.TestCase):
    def test_targets_and_states_are_closed_sets(self):
        self.assertEqual(
            BUSY_TARGETS, frozenset(("writer", "git", "put", "other_owned", "unknown")))
        self.assertEqual(WRITER_CLOSE_STATES, frozenset((
            "completed_before_unmount_entry", "began_after_busy_return",
            "overlapping", "unknown")))

    def test_successful_close_before_entry_is_the_clear_writer_case(self):
        self.assertEqual(
            _project([_umount(), _close()]),
            ("writer", "completed_before_unmount_entry"))

    def test_close_that_began_after_the_busy_return_is_not_the_writer(self):
        self.assertEqual(
            _project([_umount(), _close(entry=2100, result=2200)]),
            ("writer", "began_after_busy_return"))

    def test_overlapping_close_is_reported_as_overlapping(self):
        self.assertEqual(
            _project([_umount(entry=1000, result=2000),
                      _close(entry=1500, result=2500)]),
            ("writer", "overlapping"))
        self.assertEqual(
            _project([_umount(entry=1000, result=2000),
                      _close(entry=500, result=3000)]),
            ("writer", "overlapping"))
        self.assertEqual(
            _project([_umount(entry=1000, result=2000),
                      _close(entry=1500, result=1800)]),
            ("writer", "overlapping"))
        # Equal timestamps are not proof of completion before the entry.
        self.assertEqual(
            _project([_umount(entry=1000, result=2000),
                      _close(entry=500, result=1000)]),
            ("writer", "overlapping"))
        # A close that started exactly at the busy return is also uncertain.
        self.assertEqual(
            _project([_umount(entry=1000, result=2000),
                      _close(entry=2000, result=2100)]),
            ("writer", "overlapping"))
        # Both sampled boundaries equal the busy call boundaries.
        self.assertEqual(
            _project([_umount(entry=1000, result=2000),
                      _close(entry=1000, result=2000)]),
            ("writer", "overlapping"))

    def test_failed_close_never_qualifies(self):
        self.assertEqual(
            _project([_umount(), _close(rc=-1, error=errno.EIO)]),
            ("writer", "unknown"))
        self.assertEqual(
            _project([_umount(), _close(rc=-1, error=0)]),
            ("writer", "unknown"))
        # A successful close is rc == 0; stale errno is not a failure signal.
        self.assertEqual(
            _project([_umount(), _close(rc=0, error=errno.EIO)]),
            ("writer", "completed_before_unmount_entry"))

    def test_git_and_put_busy_targets_are_distinct(self):
        self.assertEqual(
            _project([_umount(mount_id=12, path=GIT_PATH),
                      _close(entry=2100, result=2200)]),
            ("git", "began_after_busy_return"))
        self.assertEqual(
            _project([_umount(mount_id=13, path=PUT_PATH),
                      _close()]),
            ("put", "completed_before_unmount_entry"))

    def test_other_owned_requires_independent_owned_binding(self):
        self.assertEqual(
            _project([_umount(mount_id=14, path=OTHER_PATH), _close()]),
            ("other_owned", "completed_before_unmount_entry"))
        self.assertEqual(
            _project([_umount(mount_id=14, path=OTHER_PATH, owned=0), _close()]),
            (UNKNOWN, "completed_before_unmount_entry"))

    def test_unbound_or_mismatched_identity_is_unknown(self):
        self.assertEqual(
            _project([_umount(mount_id=99, path=OTHER_PATH), _close()]),
            (UNKNOWN, "completed_before_unmount_entry"))
        self.assertEqual(
            _project([_umount(path=OTHER_PATH), _close()]),
            (UNKNOWN, "completed_before_unmount_entry"))
        self.assertEqual(
            _project([_umount(owned=0), _close()]),
            (UNKNOWN, "completed_before_unmount_entry"))

    def test_identity_attribution_requires_three_distinct_owned_mounts(self):
        duplicate = dict(EXPECTED)
        duplicate["git"] = EXPECTED["writer"]
        self.assertEqual(
            _project_with([_umount(), _close()], expected=duplicate),
            (UNKNOWN, "completed_before_unmount_entry"))
        duplicate_id = dict(EXPECTED)
        duplicate_id["git"] = (EXPECTED["writer"][0], EXPECTED["git"][1])
        self.assertEqual(
            _project_with([_umount(), _close()], expected=duplicate_id),
            (UNKNOWN, "completed_before_unmount_entry"))
        duplicate_path = dict(EXPECTED)
        duplicate_path["git"] = (EXPECTED["git"][0], EXPECTED["writer"][1])
        self.assertEqual(
            _project_with([_umount(), _close()], expected=duplicate_path),
            (UNKNOWN, "completed_before_unmount_entry"))
        missing = {"writer": EXPECTED["writer"], "git": EXPECTED["git"]}
        self.assertEqual(
            _project_with([_umount(), _close()], expected=missing),
            (UNKNOWN, "completed_before_unmount_entry"))
        invalid = dict(EXPECTED)
        invalid["put"] = None
        self.assertEqual(
            _project_with([_umount(), _close()], expected=invalid),
            (UNKNOWN, "completed_before_unmount_entry"))
        unowned = set(OWNED) - {EXPECTED["git"]}
        self.assertEqual(
            _project_with([_umount(mount_id=12, path=GIT_PATH), _close()],
                          owned=unowned),
            (UNKNOWN, "completed_before_unmount_entry"))

    def test_unknown_binding_cannot_imply_other_owned(self):
        # A missing route binding must not make an owned identity look like a
        # fourth, independently attributed mount.
        missing = {"writer": EXPECTED["writer"], "git": EXPECTED["git"]}
        self.assertEqual(
            _project_with([_umount(mount_id=14, path=OTHER_PATH), _close()],
                          expected=missing),
            (UNKNOWN, "completed_before_unmount_entry"))
        # Nor may an unowned route binding license an "owner" inference.
        unowned = set(OWNED) - {EXPECTED["put"]}
        self.assertEqual(
            _project_with([_umount(mount_id=14, path=OTHER_PATH), _close()],
                          owned=unowned),
            (UNKNOWN, "completed_before_unmount_entry"))

    def test_ambiguous_busy_or_close_or_trace_is_unknown(self):
        self.assertEqual(_project([]), (UNKNOWN, UNKNOWN))
        self.assertEqual(
            _project([_umount(rc=0, error=0), _close()]),
            (UNKNOWN, UNKNOWN))
        self.assertEqual(
            _project([_umount(), _umount(mount_id=12, path=GIT_PATH), _close()]),
            (UNKNOWN, UNKNOWN))
        self.assertEqual(
            _project([_umount(), _close(), _close()]),
            ("writer", UNKNOWN))
        self.assertEqual(
            _project([_umount(tag=process_tag(9999, 9999)), _close()]),
            (UNKNOWN, UNKNOWN))
        self.assertEqual(
            _project([_umount(), _close(tag=process_tag(9999, 9999))]),
            ("writer", UNKNOWN))

    def test_non_busy_umount_errors_do_not_become_busy_targets(self):
        self.assertEqual(
            _project([_umount(error=errno.EIO), _close()]),
            (UNKNOWN, UNKNOWN))

    def test_identity_helpers_are_opaque_and_deterministic(self):
        self.assertEqual(fnv1a64(b""), 14695981039346656037)
        self.assertEqual(path_tag(WRITER_PATH), path_tag(WRITER_PATH))
        self.assertNotEqual(path_tag(WRITER_PATH), path_tag(GIT_PATH))
        self.assertGreater(process_tag(4100, 9100), 0)
        self.assertEqual(process_tag(0, 9100), 0)
        self.assertEqual(process_tag(4100, True), 0)
        self.assertNotIn(WRITER_PATH, json.dumps({
            "path": path_tag(WRITER_PATH),
            "process": process_tag(4100, 9100),
        }))


class BusyWitnessReceiptParserTest(unittest.TestCase):
    def test_round_trip_and_bounds(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "helper.receipt"
            _write_private(path, _line(_umount()) + _line(_umount(mount_id=12, path=GIT_PATH)))
            records = parse_witness_receipt(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["kind"], "umount")
            self.assertEqual(project_busy_witness_receipts(
                root,
                helper_tag=HELPER_TAG,
                writer_tag=WRITER_TAG,
                expected_mounts=EXPECTED,
                owned_mounts=OWNED,
            ), (UNKNOWN, UNKNOWN))

    def test_missing_empty_oversized_and_truncated_receipts_are_unknown(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            self.assertEqual(project_busy_witness_receipts(
                directory,
                helper_tag=HELPER_TAG,
                writer_tag=WRITER_TAG,
                expected_mounts=EXPECTED,
                owned_mounts=OWNED,
            ), (UNKNOWN, UNKNOWN))
            _write_private(directory / "helper.receipt", b"")
            _write_private(directory / "writer.receipt", b"")
            self.assertIsNone(parse_witness_receipt(directory / "helper.receipt"))
            _write_private(
                directory / "helper.receipt",
                b"W1 kind=umount\n" + b"x" * (MAX_RECEIPT_BYTES + 1))
            self.assertIsNone(parse_witness_receipt(directory / "helper.receipt"))
            _write_private(directory / "helper.receipt", _line(_umount())[:-1])
            self.assertIsNone(parse_witness_receipt(directory / "helper.receipt"))

    def test_malformed_duplicate_missing_and_extra_fields_are_rejected(self):
        record = _umount()
        good = _line(record)
        variants = (
            good.replace(b"kind=umount", b"kind=bogus"),
            good.replace(b"role=helper", b"role=writer"),
            good.replace(b"mount_id=11", b"mount_id=-1"),
            good.replace(b"proc_tag=", b"proc_tag=Z"),
            good.replace(b"entry_ns=1000", b"entry_ns=0"),
            good.replace(b"result_ns=2000", b"result_ns=999"),
            good.replace(b"flags=0", b"flags=2"),
            good + b" extra=1\n",
            good.replace(b"kind=umount ", b"kind=umount kind=umount "),
            good.replace(b"path_hash=" + format(record["path_hash"], "016x").encode(),
                         b"path_hash=not-hex"),
        )
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "helper.receipt"
            for variant in variants:
                with self.subTest(variant=variant[:80]):
                    _write_private(path, variant)
                    self.assertIsNone(parse_witness_receipt(path))

    def test_too_many_records_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "helper.receipt"
            _write_private(path, _line(_umount()) * (MAX_RECEIPTS + 1))
            self.assertIsNone(parse_witness_receipt(path))

    def test_close_receipt_cannot_claim_a_mount_identity(self):
        record = _close()
        record["mount_id"] = 11
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "writer.receipt"
            _write_private(path, _line(record))
            self.assertIsNone(parse_witness_receipt(path))

    def test_project_receipts_returns_only_closed_values(self):
        with tempfile.TemporaryDirectory() as root:
            _write_private(Path(root) / "helper.receipt", _line(_umount()))
            _write_private(Path(root) / "writer.receipt", _line(_close()))
            target, state = project_busy_witness_receipts(
                root,
                helper_tag=HELPER_TAG,
                writer_tag=WRITER_TAG,
                expected_mounts=EXPECTED,
                owned_mounts=OWNED,
            )
        self.assertIn(target, BUSY_TARGETS)
        self.assertIn(state, WRITER_CLOSE_STATES)
        self.assertEqual((target, state), ("writer", "completed_before_unmount_entry"))

    def test_receipt_requires_private_regular_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "helper.receipt"
            _write_private(path, _line(_umount()))
            self.assertIsNotNone(parse_witness_receipt(path))
            path.chmod(0o644)
            self.assertIsNone(parse_witness_receipt(path))
            path.chmod(0o4600)
            self.assertIsNone(parse_witness_receipt(path))
            path.chmod(0o600)
            with mock.patch.object(normal_shutdown.os, "geteuid",
                                   return_value=os.geteuid() + 1):
                self.assertIsNone(parse_witness_receipt(path))
            hard = Path(root) / "hard.receipt"
            os.link(path, hard)
            self.assertIsNone(parse_witness_receipt(hard))
            link = Path(root) / "linked.receipt"
            link.symlink_to(path)
            self.assertIsNone(parse_witness_receipt(link))
            fifo = Path(root) / "fifo.receipt"
            os.mkfifo(fifo)
            self.assertIsNone(parse_witness_receipt(fifo))

    def test_private_receipt_creation_is_empty_0600_regular(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "helper.receipt"
            self.assertTrue(normal_shutdown._create_private_receipt(path))
            info = path.stat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(info.st_mode & 0o777, 0o600)
            self.assertEqual(path.read_bytes(), b"")
            path.write_bytes(b"stale")
            self.assertTrue(normal_shutdown._create_private_receipt(path))
            self.assertEqual(path.read_bytes(), b"")


class BusyWitnessInstallGuardTest(unittest.TestCase):
    def _harness(self, run):
        return types.SimpleNamespace(
            root=Path(tempfile.mkdtemp(prefix="witness-guard-")),
            env={"LD_PRELOAD": "/gate.so"},
            run=run,
        )

    def test_missing_compiler_leaves_acceptance_environment_untouched(self):
        h = self._harness(lambda *args, **kwargs: self.fail("compiler was invoked"))
        with mock.patch.object(normal_shutdown.sys, "platform", "linux"), \
                mock.patch.object(normal_shutdown.Path, "is_dir", return_value=True), \
                mock.patch.object(normal_shutdown.shutil, "which", return_value=None):
            self.assertIsNone(
                normal_shutdown.install_busy_witness(h, h.root / "witness"))
        self.assertEqual(h.env, {"LD_PRELOAD": "/gate.so"})

    def test_build_failure_leaves_acceptance_environment_untouched(self):
        def fail_build(*args, **kwargs):
            raise RuntimeError("fixture compiler unavailable")

        h = self._harness(fail_build)
        with mock.patch.object(normal_shutdown.sys, "platform", "linux"), \
                mock.patch.object(normal_shutdown.Path, "is_dir", return_value=True), \
                mock.patch.object(normal_shutdown.shutil, "which",
                                  return_value="/usr/bin/gcc"):
            self.assertIsNone(
                normal_shutdown.install_busy_witness(h, h.root / "witness"))
        self.assertEqual(h.env, {"LD_PRELOAD": "/gate.so"})
        self.assertIsNone(normal_shutdown.busy_witness_writer_env(None, h.root))


class BusyWitnessSourceContractTest(unittest.TestCase):
    """Source-only checks; the Linux fixture is never compiled locally."""

    SOURCE = Path(__file__).with_name("fixtures") / "fuse_busy_witness.c"

    def _block(self, text, marker):
        start = text.index(marker)
        end = text.find("\n}\n", start)
        self.assertNotEqual(end, -1, marker)
        return text[start:end]

    def test_forwarded_hooks_do_not_use_lazy_resolution_or_formatting(self):
        text = self.SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("pthread_once", text)
        self.assertNotIn("PTHREAD_ONCE_INIT", text)
        for marker in ("int umount2(", "int close(", "int execve(",
                       "int execv(", "int execvp(", "int execvpe(",
                       "int posix_spawn(", "int posix_spawnp("):
            block = self._block(text, marker)
            self.assertNotIn("dlsym", block, marker)
            self.assertNotIn("snprintf", block, marker)

    def test_receipt_open_is_private_and_never_creates(self):
        text = self.SOURCE.read_text(encoding="utf-8")
        block = self._block(text, "static void open_receipt")
        for token in ("O_NOFOLLOW", "O_NONBLOCK", "fstat", "S_ISREG",
                      "WITNESS_RECEIPT_MODE", "WITNESS_MAX_RECEIPT_BYTES",
                      "geteuid", "st_nlink"):
            self.assertIn(token, block)
        self.assertNotIn("O_CREAT", block)

    def test_umount_records_only_ebusy_after_the_return_sample(self):
        text = self.SOURCE.read_text(encoding="utf-8")
        block = self._block(text, "int umount2(")
        self.assertIn("flags != 0", block)
        self.assertIn("result != -1 || saved_errno != EBUSY", block)
        sample = block.index("result_ns = monotonic_ns();")
        self.assertLess(sample, block.index("mount_identity("))
        self.assertLess(sample, block.index("record_event("))
        self.assertNotIn("O_CREAT", block)

    def test_record_event_is_one_bounded_pid_guarded_write(self):
        text = self.SOURCE.read_text(encoding="utf-8")
        block = self._block(text, "static void record_event")
        self.assertIn("(long)getpid() != witness_pid", block)
        self.assertEqual(block.count("SYS_write"), 1)
        self.assertIn("One bounded append-only write", block)
        self.assertNotIn("while (", block)

    def test_helper_environment_is_prepared_and_pid_guarded(self):
        text = self.SOURCE.read_text(encoding="utf-8")
        self.assertIn("prepare_api_environment", text)
        self.assertIn("witness_env_ready", text)
        self.assertIn("(long)getpid() != witness_pid", text)
        self.assertIn("witness_self_exe", text)
        self.assertLess(
            text.index("static void prepare_api_environment"),
            text.index("__attribute__((constructor))"),
        )


if __name__ == "__main__":
    unittest.main()
