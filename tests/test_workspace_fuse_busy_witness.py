#!/usr/bin/env python3
"""Pure contract tests for the fixture-only FUSE busy witness projection.

These tests use synthetic receipt records only.  They do not start the service,
FUSE, PostgreSQL, Git, a child process, a thread, or the network.
"""
from __future__ import annotations

import errno
import json
from pathlib import Path
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


def _line(record):
    return (
        "W1 kind={kind} role={role} entry_ns={entry_ns} result_ns={result_ns} "
        "mount_id={mount_id} path_hash={path_hash:016x} proc_tag={proc_tag:016x} "
        "rc={rc} errno={errno} flags={flags} owned={owned}\n"
    ).format(**record).encode("ascii")


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

    def test_failed_close_never_qualifies(self):
        self.assertEqual(
            _project([_umount(), _close(rc=-1, error=errno.EIO)]),
            ("writer", "unknown"))

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
            path.write_bytes(_line(_umount()) + _line(_umount(mount_id=12, path=GIT_PATH)))
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
            (directory / "helper.receipt").write_bytes(b"")
            (directory / "writer.receipt").write_bytes(b"")
            self.assertIsNone(parse_witness_receipt(directory / "helper.receipt"))
            (directory / "helper.receipt").write_bytes(
                b"W1 kind=umount\n" + b"x" * (MAX_RECEIPT_BYTES + 1))
            self.assertIsNone(parse_witness_receipt(directory / "helper.receipt"))
            (directory / "helper.receipt").write_bytes(_line(_umount())[:-1])
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
                    path.write_bytes(variant)
                    self.assertIsNone(parse_witness_receipt(path))

    def test_too_many_records_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "helper.receipt"
            path.write_bytes(_line(_umount()) * (MAX_RECEIPTS + 1))
            self.assertIsNone(parse_witness_receipt(path))

    def test_close_receipt_cannot_claim_a_mount_identity(self):
        record = _close()
        record["mount_id"] = 11
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "writer.receipt"
            path.write_bytes(_line(record))
            self.assertIsNone(parse_witness_receipt(path))

    def test_project_receipts_returns_only_closed_values(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "helper.receipt").write_bytes(_line(_umount()))
            Path(root, "writer.receipt").write_bytes(_line(_close()))
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


if __name__ == "__main__":
    unittest.main()
