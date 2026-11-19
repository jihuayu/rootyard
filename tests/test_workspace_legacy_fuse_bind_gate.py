#!/usr/bin/env python3
"""Pure regressions for the fixture-owned API bind gate.

These tests read the real C fixture and acceptance source and exercise only
bounded file/payload helpers in a temporary directory. They never compile or
preload C, start a process, enter a namespace, bind a socket, mount FUSE, touch
PostgreSQL, or use the network.
"""
from __future__ import annotations

import errno
import json
from pathlib import Path
import tempfile
import unittest

from tests import workspace_legacy_fuse_shutdown_fixtures as fixtures
from tests.workspace_legacy_fuse_shutdown_support import LegacyAcceptanceError


ROOT = Path(__file__).resolve().parents[1]
GATE_SOURCE = ROOT / "tests/fixtures/api_bind_gate.c"
ACCEPTANCE_SOURCE = ROOT / "tests/workspace_legacy_fuse_shutdown_acceptance.py"


def _payload(**overrides):
    value = {
        "schema": fixtures.API_BIND_GATE_SCHEMA,
        "version": fixtures.API_BIND_GATE_VERSION,
        "events": 1,
        "held": 1,
        "timed_out": 0,
        "duplicate": 0,
        "abi_verified": 1,
        "bind_result": -1,
        "bind_errno": errno.EADDRINUSE,
    }
    value.update(overrides)
    return value


class BindGateTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.gate = Path(self.directory.name) / "gate"

    def marker(self, suffix):
        return Path(f"{self.gate}.{suffix}")

    def test_only_a_real_eaddrinuse_outcome_is_accepted(self):
        self.assertEqual(fixtures.validate_api_bind_gate_outcome(_payload()), _payload())
        rejected = (
            _payload(bind_result=0),
            _payload(bind_errno=errno.EACCES),
            _payload(held=0),
            _payload(timed_out=1),
            _payload(duplicate=1),
            _payload(abi_verified=0),
            _payload(events=2),
            _payload(schema="other"),
            _payload(bind_result=True),
            _payload(extra=True),
            {key: value for key, value in _payload().items() if key != "bind_errno"},
        )
        for payload in rejected:
            with self.subTest(payload=payload):
                with self.assertRaises(LegacyAcceptanceError):
                    fixtures.validate_api_bind_gate_outcome(payload)

    def test_markers_fail_closed_and_release_is_single_use(self):
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.wait_api_bind_gate(self.gate, timeout=0.01)
        for suffix in ("duplicate", "abi", "timeout"):
            with self.subTest(suffix=suffix):
                marker = self.marker(suffix)
                marker.write_bytes(b"bad\n")
                try:
                    with self.assertRaises(LegacyAcceptanceError):
                        fixtures.wait_api_bind_gate(self.gate, timeout=0.01)
                finally:
                    marker.unlink()
        self.marker("hit").write_bytes(b"held\n")
        fixtures.release_api_bind_gate(self.gate)
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.release_api_bind_gate(self.gate)

    def test_missing_malformed_and_oversized_outcomes_are_rejected(self):
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.read_api_bind_gate_outcome(self.gate, timeout=0.01)
        self.marker("outcome").write_text("{not json", encoding="utf-8")
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.read_api_bind_gate_outcome(self.gate, timeout=0.01)
        self.marker("outcome").write_text(" " * 4097, encoding="utf-8")
        with self.assertRaises(LegacyAcceptanceError):
            fixtures.read_api_bind_gate_outcome(self.gate, timeout=0.01)
        self.marker("outcome").write_text(json.dumps(_payload()) + "\n", encoding="utf-8")
        self.assertEqual(fixtures.read_api_bind_gate_outcome(self.gate, timeout=0.01), _payload())

    def test_only_exact_ipv4_loopback_is_accepted(self):
        self.assertEqual(fixtures.parse_api_bind_gate_address("127.0.0.1:8080"), "127.0.0.1:8080")
        for value in (
            None, "", "127.0.0.1", "0.0.0.0:8080", "::1:8080", "[::1]:8080",
            "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:not-a-port", "localhost:8080",
        ):
            with self.subTest(value=value):
                with self.assertRaises(LegacyAcceptanceError):
                    fixtures.parse_api_bind_gate_address(value)

    def test_source_holds_bind_before_holder_and_releases_after_deadline(self):
        source = GATE_SOURCE.read_text(encoding="utf-8")
        for token in (
            "int bind(int fd, const struct sockaddr *address, socklen_t length)",
            'dlsym(RTLD_NEXT, "bind")', "call_real_bind(fd, address, length)",
            "errno = result_errno;", "socket_abi_is_verified", "touch_marker(gate, \"duplicate\")",
            "touch_marker(gate, \"timeout\")", "write_outcome(gate, result, result_errno",
        ):
            self.assertIn(token, source)
        self.assertNotIn("SO_REUSEPORT", source)
        text = ACCEPTANCE_SOURCE.read_text(encoding="utf-8")
        start = text.index("    def test_post_reconcile_api_bind_failure_cleans_owned_mount")
        end = text.index("    def test_sigterm_during_blocked_startup_joins_mounted_owner", start)
        case = text[start:end]
        ordered = (
            "bind_owned_conflict", "snapshot_api_bind_gate_env", "install_api_bind_gate",
            "restore_api_bind_gate_env", "wait_api_bind_gate", "_attach_holder",
            "wait_owned_mount", "_arm_cleanup_deadline", "release_api_bind_gate",
            "wait_process_exit", "read_api_bind_gate_outcome", "close_conflict",
        )
        positions = [case.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("real_eaddrinuse", case)
        self.assertIn('"tests/fixtures/api_bind_gate.c"', text)

    def test_gate_environment_is_restored_to_its_exact_prior_state(self):
        class Harness:
            env = {"LD_PRELOAD": "/old", "ROOTYARD_TEST_BIND_GATE": "/old",
                   "ROOTYARD_TEST_BIND_GATE_ADDR": "127.0.0.1:9", "KEEP": "yes"}

        harness = Harness()
        prior = fixtures.snapshot_api_bind_gate_env(harness)
        harness.env.update(LD_PRELOAD="/new", ROOTYARD_TEST_BIND_GATE="/new",
                           ROOTYARD_TEST_BIND_GATE_ADDR="127.0.0.1:10")
        fixtures.restore_api_bind_gate_env(harness, prior)
        self.assertEqual(harness.env, Harness.env)
        for name in fixtures.API_BIND_GATE_ENV_NAMES:
            harness.env.pop(name)
        prior = fixtures.snapshot_api_bind_gate_env(harness)
        harness.env.update(LD_PRELOAD="/new", ROOTYARD_TEST_BIND_GATE="/new",
                           ROOTYARD_TEST_BIND_GATE_ADDR="127.0.0.1:10")
        fixtures.restore_api_bind_gate_env(harness, prior)
        self.assertEqual(harness.env, {"KEEP": "yes"})


if __name__ == "__main__":
    unittest.main()
