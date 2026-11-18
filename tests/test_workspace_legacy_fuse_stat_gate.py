#!/usr/bin/env python3
"""Pure regressions for the one-use legacy workspace metadata gate.

These tests read the real C fixture and acceptance source and exercise only
bounded payload/marker helpers in a temporary directory. They never compile or
preload C, start a process, enter a namespace, call statx, mount FUSE, touch
PostgreSQL, or use the network.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests import workspace_legacy_fuse_shutdown_fixtures as fixtures
from tests import workspace_legacy_fuse_shutdown_support as legacy_support
from tests.workspace_legacy_fuse_shutdown_support import LegacyAcceptanceError


ROOT = Path(__file__).resolve().parents[1]
GATE_SOURCE = ROOT / "tests/fixtures/legacy_stat_gate.c"
ACCEPTANCE_SOURCE = ROOT / "tests/workspace_legacy_fuse_shutdown_acceptance.py"


def _payload(**overrides):
    value = {
        "schema": fixtures.STAT_GATE_SCHEMA,
        "version": fixtures.STAT_GATE_VERSION,
        "events": 1,
        "held": 1,
        "timed_out": 0,
        "duplicate": 0,
        "abi_verified": 1,
        "scope_verified": 1,
        "identity_verified": 1,
        "lookup": "statx",
        "struct_size": fixtures.STAT_GATE_STATX_SIZE,
        "statx_type": 1,
        "real_success": 1,
        "is_regular": 1,
        "is_directory": 0,
    }
    value.update(overrides)
    return value


class StatGateTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.gate = Path(self.directory.name) / "gate"

    def marker(self, suffix):
        return Path(f"{self.gate}.{suffix}")

    def test_only_exact_audited_statx_regular_file_is_accepted(self):
        self.assertEqual(fixtures.validate_stat_gate_outcome(_payload()), _payload())
        rejected = (
            _payload(events=2),
            _payload(held=0),
            _payload(timed_out=1),
            _payload(duplicate=1),
            _payload(abi_verified=0),
            _payload(scope_verified=0),
            _payload(identity_verified=0),
            _payload(lookup="stat64"),
            _payload(struct_size=0),
            _payload(struct_size=144),
            _payload(struct_size=255),
            _payload(struct_size=257),
            _payload(statx_type=0),
            _payload(real_success=0),
            _payload(is_regular=0),
            _payload(is_directory=1),
            _payload(schema="other"),
            _payload(version=True),
            _payload(extra=True),
            _payload(mode=0o100600),
            {key: value for key, value in _payload().items() if key != "statx_type"},
        )
        for payload in rejected:
            with self.subTest(payload=payload):
                with self.assertRaises(LegacyAcceptanceError):
                    fixtures.validate_stat_gate_outcome(payload)

    def test_markers_fail_closed_and_release_is_bound_to_positive_identity(self):
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.wait_stat_gate(self.gate, timeout=0.01)
        for suffix in ("duplicate", "abi", "scope", "identity", "timeout"):
            with self.subTest(suffix=suffix):
                marker = self.marker(suffix)
                marker.write_bytes(b"bad\n")
                try:
                    with self.assertRaises(LegacyAcceptanceError):
                        fixtures.wait_stat_gate(self.gate, timeout=0.01)
                finally:
                    marker.unlink()
        self.marker("hit").write_text("123 456\n", encoding="utf-8")
        self.assertEqual(
            fixtures.wait_stat_gate(self.gate, timeout=0.01),
            {"pid": 123, "starttime": 456},
        )
        fixtures.release_stat_gate(self.gate, 123, 456)
        self.assertEqual(
            self.marker("release").read_text(encoding="ascii"), "123 456\n"
        )
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.release_stat_gate(self.gate, 123, 456)
        for pid, starttime in ((0, 456), (123, 0), (-1, 456), (123, -1), (True, 456), (123, False)):
            with self.subTest(pid=pid, starttime=starttime):
                with self.assertRaises(LegacyAcceptanceError):
                    fixtures.release_stat_gate(self.gate, pid, starttime)

    def test_missing_malformed_oversized_and_marker_outcomes_are_rejected_once(self):
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.read_stat_gate_outcome(self.gate)
        self.marker("identity").write_bytes(b"bad\n")
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.read_stat_gate_outcome(self.gate)
        self.marker("identity").unlink()
        self.marker("outcome").write_text("{not json", encoding="utf-8")
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.read_stat_gate_outcome(self.gate)
        self.marker("outcome").write_text(" " * 4097, encoding="utf-8")
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.read_stat_gate_outcome(self.gate)
        self.marker("outcome").write_text(json.dumps(_payload()) + "\n", encoding="utf-8")
        self.assertEqual(fixtures.read_stat_gate_outcome(self.gate), _payload())

    def test_c_source_uses_libc_statx_and_bounded_audited_outcome(self):
        source = GATE_SOURCE.read_text(encoding="utf-8")
        for token in (
            "int statx(int dirfd, const char *pathname",
            "struct statx *statxbuf",
            "requires the pinned glibc statx ABI",
            "_Static_assert(sizeof(struct statx) == 256",
            "_Static_assert(offsetof(struct statx, stx_mode) == 28",
            "memcpy(&real_statx, &symbol, sizeof(real_statx))",
            'readlink("/proc/self/exe"',
            "getpgrp() != getpid()",
            "strcmp(path, target) != 0",
            "read_self_identity",
            'snprintf(path, sizeof(path), "%s.hit", gate)',
            "wait_for_release(gate, self_pid, self_starttime)",
            'touch_marker(gate, "identity")',
            "atomic_compare_exchange_strong(&state, &prior, 1)",
            "stx_mask & STATX_TYPE",
            "S_ISREG(statxbuf->stx_mode)",
            "S_ISDIR(statxbuf->stx_mode)",
            "sizeof(struct statx)",
            "errno = result_errno;",
        ):
            self.assertIn(token, source)
        for forbidden in (
            "gate_statx", "realpath(", "struct stat64", "int stat(",
            "int lstat(", "int fstatat(", "int fstatat64(",
            '\\"mode\\"', '\\"errno\\"', '\\"result\\"', "syscall(", "SYS_statx",
        ):
            self.assertNotIn(forbidden, source)

    def test_acceptance_binds_identity_snapshots_and_single_receipt(self):
        text = ACCEPTANCE_SOURCE.read_text(encoding="utf-8")
        start = text.index(
            "    def test_partial_reconcile_failure_cleans_earlier_owned_mount"
        )
        end = text.index("    def test_post_reconcile_api_bind_failure_cleans_owned_mount", start)
        case = text[start:end]
        ordered = (
            "ordered[-1]",
            'git_dir.rename(corrupt_name)',
            '(broken_lower / ".git").write_text',
            "corrupt_git.is_symlink()",
            "snapshot_stat_gate_env",
            "install_stat_gate",
            "_start_oracle_service",
            "restore_stat_gate_env",
            "wait_stat_gate",
            "capture_service_identity",
            'hit_identity["pid"]',
            'hit_identity["starttime"]',
            "_attach_holder",
            "wait_owned_mount",
            "assert_owned_mounts_snapshot",
            "namespace = int(holder_proof",
            "recheck_service_identity",
            "_arm_cleanup_deadline",
            "release_stat_gate",
            "wait_process_exit",
            "read_stat_gate_outcome",
        )
        positions = [case.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("self.assertEqual(len(created), 3", case)
        self.assertIn("self.assertEqual(len(healthy), 2", case)
        self.assertIn("legacy_support.owned_leftovers(holder.pid, [broken_paths[\"mountpoint\"]])", case)
        self.assertIn('"tests/fixtures/legacy_stat_gate.c"', text)
        self.assertIn("real_regular_file", case)
        self.assertIn('rechecked_identity["service_pid"]', case)
        self.assertIn('rechecked_identity["service_starttime"]', case)
        self.assertIn("read_stat_gate_outcome(gate)", case)
        self.assertNotIn("read_stat_gate_outcome(gate,", case)
        self.assertNotIn("stat.S_ISREG", case)
        self.assertNotIn('stat_gate["mode"]', case)
        detail = case.split('CASE_DETAILS[self.id()]["stat_gate"] = {', 1)[1]
        for forbidden in ("service_pid", "service_starttime", "mount_id", "holder_pid"):
            self.assertNotIn(forbidden, detail)

    def test_final_mountinfo_snapshot_reads_once_and_requires_both_ids(self):
        first = Path("/fixture/mount-a")
        second = Path("/fixture/mount-b")
        rows = [
            {"mountpoint": str(first), "mount_id": 11,
             "source": legacy_support.FUSE_SOURCE, "fstype": "fuse.rootyard"},
            {"mountpoint": str(second), "mount_id": 12,
             "source": legacy_support.FUSE_SOURCE, "fstype": "fuse.rootyard"},
        ]
        calls = []

        def read_once(pid):
            calls.append(pid)
            return list(rows)

        with mock.patch.object(legacy_support.support, "read_process_mountinfo", side_effect=read_once):
            self.assertEqual(
                legacy_support.assert_owned_mounts_snapshot(123, ((first, 11), (second, 12))),
                2,
            )
        self.assertEqual(calls, [123])

        for expected, broken_rows in (
            (((first, 11), (second, 12)), rows[:1]),
            (((first, 11), (second, 12)), [rows[0], dict(rows[1], mount_id=99)]),
            (((first, 11), (second, 12)), [rows[0], dict(rows[1], source="other")]),
        ):
            with self.subTest(expected=expected):
                with mock.patch.object(
                    legacy_support.support, "read_process_mountinfo", return_value=broken_rows
                ):
                    with self.assertRaises(LegacyAcceptanceError):
                        legacy_support.assert_owned_mounts_snapshot(123, expected)

    def test_gate_environment_is_restored_to_its_exact_prior_state(self):
        class Harness:
            env = {"LD_PRELOAD": "/old", "ROOTYARD_TEST_STAT_GATE": "/old",
                   "ROOTYARD_TEST_STAT_GATE_TARGET": "/old",
                   "ROOTYARD_TEST_STAT_GATE_EXE": "/old", "KEEP": "yes"}

        harness = Harness()
        prior = fixtures.snapshot_stat_gate_env(harness)
        harness.env.update(LD_PRELOAD="/new", ROOTYARD_TEST_STAT_GATE="/new",
                           ROOTYARD_TEST_STAT_GATE_TARGET="/new",
                           ROOTYARD_TEST_STAT_GATE_EXE="/new")
        fixtures.restore_stat_gate_env(harness, prior)
        self.assertEqual(harness.env, Harness.env)
        for name in fixtures.STAT_GATE_ENV_NAMES:
            harness.env.pop(name)
        prior = fixtures.snapshot_stat_gate_env(harness)
        harness.env.update(LD_PRELOAD="/new", ROOTYARD_TEST_STAT_GATE="/new",
                           ROOTYARD_TEST_STAT_GATE_TARGET="/new",
                           ROOTYARD_TEST_STAT_GATE_EXE="/new")
        fixtures.restore_stat_gate_env(harness, prior)
        self.assertEqual(harness.env, {"KEEP": "yes"})


if __name__ == "__main__":
    unittest.main()
