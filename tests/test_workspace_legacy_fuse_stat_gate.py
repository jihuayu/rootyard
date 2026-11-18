#!/usr/bin/env python3
"""Pure regressions for the one-use legacy workspace metadata gate.

These tests read the real C fixture and acceptance source and exercise only
bounded payload/marker helpers in a temporary directory. They never compile or
preload C, start a process, enter a namespace, call statx/stat, mount FUSE,
touch PostgreSQL, or use the network.
"""
from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import unittest

from tests import workspace_legacy_fuse_shutdown_fixtures as fixtures
from tests.workspace_legacy_fuse_shutdown_support import LegacyAcceptanceError


ROOT = Path(__file__).resolve().parents[1]
GATE_SOURCE = ROOT / "tests/fixtures/legacy_stat_gate.c"
ACCEPTANCE_SOURCE = ROOT / "tests/workspace_legacy_fuse_shutdown_acceptance.py"


def _regular_mode():
    return stat.S_IFREG | 0o600


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
        "lookup": "statx",
        "struct_size": 256,
        "result": 0,
        "errno": 0,
        "mode": _regular_mode(),
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

    def test_only_a_real_regular_file_lookup_is_accepted(self):
        self.assertEqual(fixtures.validate_stat_gate_outcome(_payload()), _payload())
        rejected = (
            _payload(result=-1),
            _payload(errno=-1),
            _payload(mode=stat.S_IFDIR | 0o700),
            _payload(is_regular=0),
            _payload(is_directory=1),
            _payload(held=0),
            _payload(timed_out=1),
            _payload(duplicate=1),
            _payload(abi_verified=0),
            _payload(scope_verified=0),
            _payload(events=2),
            _payload(lookup="openat"),
            _payload(struct_size=0),
            _payload(schema="other"),
            _payload(result=True),
            _payload(extra=True),
            {key: value for key, value in _payload().items() if key != "mode"},
        )
        for payload in rejected:
            with self.subTest(payload=payload):
                with self.assertRaises(LegacyAcceptanceError):
                    fixtures.validate_stat_gate_outcome(payload)

    def test_markers_fail_closed_and_release_is_single_use(self):
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.wait_stat_gate(self.gate, timeout=0.01)
        for suffix in ("duplicate", "abi", "scope", "timeout"):
            with self.subTest(suffix=suffix):
                marker = self.marker(suffix)
                marker.write_bytes(b"bad\n")
                try:
                    with self.assertRaises(LegacyAcceptanceError):
                        fixtures.wait_stat_gate(self.gate, timeout=0.01)
                finally:
                    marker.unlink()
        self.marker("hit").write_bytes(b"held\n")
        fixtures.release_stat_gate(self.gate)
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.release_stat_gate(self.gate)

    def test_missing_malformed_and_oversized_outcomes_are_rejected(self):
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.read_stat_gate_outcome(self.gate, timeout=0.01)
        self.marker("outcome").write_text("{not json", encoding="utf-8")
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.read_stat_gate_outcome(self.gate, timeout=0.01)
        self.marker("outcome").write_text(" " * 4097, encoding="utf-8")
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.read_stat_gate_outcome(self.gate, timeout=0.01)
        self.marker("outcome").write_text(json.dumps(_payload()) + "\n", encoding="utf-8")
        self.assertEqual(
            fixtures.read_stat_gate_outcome(self.gate, timeout=0.01), _payload()
        )

    def test_source_is_one_use_exact_path_and_preserves_the_real_call(self):
        source = GATE_SOURCE.read_text(encoding="utf-8")
        for token in (
            "int gate_statx(int dirfd, const char *pathname",
            "int stat(const char *path, struct stat *buf)",
            "int stat64(const char *path, struct stat64 *buf)",
            "int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags)",
            'int gate_statx(int dirfd, const char *pathname, int flags, unsigned int mask,\n'
            '               struct gate_statx *statxbuf) __asm__("statx");',
            "RESOLVE_SYMBOL(\"statx\", real_statx)",
            "target_path_matches", "strcmp(path, target) == 0",
            "scope_matches", 'readlink("/proc/self/exe"',
            "getpgrp() != getpid()",
            "atomic_compare_exchange_strong(&state, &prior, 1)",
            "touch_marker(gate, \"hit\")", "wait_for_release(gate)",
            "touch_marker(configured_gate, \"duplicate\")", "touch_marker(configured_gate, \"abi\")",
            "touch_marker(gate, \"scope\")", "touch_marker(gate, \"timeout\")",
            "int result = call_real_statx", "call_real_statx(dirfd, pathname, flags, mask, statxbuf)",
            "call_real_stat64(path, buf)", "int result_errno = errno",
            "errno = result_errno;", "finish_hold(gate, \"statx\"",
            "S_ISREG(mode)", "S_ISDIR(mode)",
        ):
            self.assertIn(token, source)
        self.assertIn("_Static_assert(sizeof(struct gate_statx) == 256", source)
        self.assertIn("_Static_assert(offsetof(struct gate_statx, stx_mode) == 28", source)
        self.assertNotIn("stx_mode =", source)
        self.assertNotIn("struct gate_statx observed", source)
        self.assertNotIn("S_IFREG", source)

    def test_acceptance_holds_the_third_lookup_before_observing_healthy_mounts(self):
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
            "_attach_holder",
            "wait_owned_mount",
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
