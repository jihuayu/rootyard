#!/usr/bin/env python3
"""Hermetic tests for the bounded #178 live-fixture capacity envelope.

These tests never spawn a child, thread, Git, HTTP, S3, PostgreSQL, proxy,
server or network.  They exercise pure arithmetic, environment copying and the
success-report binding only.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import pando_pack_compression_eval as cli  # noqa: E402
from pack_compression_eval import capacity  # noqa: E402
from pack_compression_eval.failure_diagnostics import build_failure_record  # noqa: E402


class CapacityEnvelopeTest(unittest.TestCase):
    def test_canonical_envelope_is_exact_and_bounded(self) -> None:
        envelope = capacity.derive_capacity_envelope()
        self.assertEqual(
            envelope,
            {
                "concurrent_branches": 3,
                "request_ceiling_bytes": 128 * 1024 * 1024,
                "inflight_bytes": 384 * 1024 * 1024,
            },
        )
        self.assertEqual(envelope["inflight_bytes"], envelope["concurrent_branches"] * envelope["request_ceiling_bytes"])
        self.assertLessEqual(envelope["inflight_bytes"], capacity.MAX_INFLIGHT_BYTES)
        self.assertEqual(
            capacity.derive_capacity_envelope(concurrent_branches=3, request_ceiling_bytes=128 * 1024 * 1024),
            envelope,
        )

    def test_derive_rejects_invalid_and_overflow_inputs(self) -> None:
        for bad in (0, -1, 4, True, "3", None, 3.0):
            with self.subTest(concurrent_branches=bad):
                with self.assertRaises(ValueError):
                    capacity.derive_capacity_envelope(concurrent_branches=bad)
        for bad in (0, -1, 129 * 1024 * 1024, True, "128", None, 2**63):
            with self.subTest(request_ceiling_bytes=bad):
                with self.assertRaises(ValueError):
                    capacity.derive_capacity_envelope(request_ceiling_bytes=bad)

    def test_build_server_env_copies_base_and_injects_exact_values(self) -> None:
        base = {"KEEP": "yes"}
        before = dict(base)
        env = capacity.build_server_env(base)
        self.assertEqual(base, before)
        self.assertEqual(env["KEEP"], "yes")
        self.assertEqual(env[capacity.REQUEST_ENV], str(128 * 1024 * 1024))
        self.assertEqual(env[capacity.INFLIGHT_ENV], str(384 * 1024 * 1024))
        supplied = capacity.build_server_env({"A": "b"}, capacity.derive_capacity_envelope())
        self.assertEqual(supplied[capacity.REQUEST_ENV], env[capacity.REQUEST_ENV])
        self.assertEqual(supplied[capacity.INFLIGHT_ENV], env[capacity.INFLIGHT_ENV])

    def test_build_server_env_rejects_bad_envelopes(self) -> None:
        good = capacity.derive_capacity_envelope()
        with self.assertRaises(ValueError):
            capacity.build_server_env({}, {**good, "extra": 1})
        with self.assertRaises(ValueError):
            capacity.build_server_env({}, {**good, "inflight_bytes": good["inflight_bytes"] - 1})
        with self.assertRaises(ValueError):
            capacity.build_server_env({}, {"concurrent_branches": 4, **{k: v for k, v in good.items() if k != "concurrent_branches"}})
        with self.assertRaises(ValueError):
            capacity.build_server_env({}, "not-a-mapping")  # type: ignore[arg-type]

    def test_build_server_env_never_mutates_os_environ(self) -> None:
        before = dict(os.environ)
        env = capacity.build_server_env(os.environ)
        self.assertEqual(dict(os.environ), before)
        self.assertIn(capacity.REQUEST_ENV, env)
        self.assertIn(capacity.INFLIGHT_ENV, env)

    def test_sanitize_capacity_fails_closed(self) -> None:
        canonical = capacity.derive_capacity_envelope()
        self.assertEqual(capacity.sanitize_capacity(canonical), canonical)
        sentinel = "SENTINEL_SECRET_capacity"
        for bad in (
            None,
            {},
            {**canonical, "concurrent_branches": 4},
            {**canonical, "request_ceiling_bytes": "128"},
            {**canonical, "inflight_bytes": 1},
            {**canonical, "inflight_bytes": 16 * 1024 * 1024 * 1024},
            {**canonical, "injected": sentinel},
        ):
            with self.subTest(bad=bad):
                projected = capacity.sanitize_capacity(bad)
                self.assertEqual(
                    projected,
                    {"concurrent_branches": None, "request_ceiling_bytes": None, "inflight_bytes": None},
                )
                self.assertNotIn(sentinel, json.dumps(projected, sort_keys=True))

    def test_overprovisioned_inflight_is_rejected_by_projection_and_failure_report(self) -> None:
        overprovisioned = {
            "concurrent_branches": 3,
            "request_ceiling_bytes": 128 * 1024 * 1024,
            "inflight_bytes": 16 * 1024 * 1024 * 1024,
        }
        expected = {"concurrent_branches": None, "request_ceiling_bytes": None, "inflight_bytes": None}
        self.assertEqual(capacity.sanitize_capacity(overprovisioned), expected)
        self.assertEqual(build_failure_record(fixture_capacity=overprovisioned)["fixture_capacity"], expected)
        canonical = capacity.derive_capacity_envelope()
        self.assertEqual(capacity.sanitize_capacity(canonical), canonical)
        self.assertEqual(build_failure_record(fixture_capacity=canonical)["fixture_capacity"], canonical)

    def test_success_report_binding_attaches_exact_capacity(self) -> None:
        envelope = capacity.derive_capacity_envelope()
        environment = {"git_version": "git 2.43"}
        bound = cli._bind_fixture_capacity(environment, {"fixture_capacity": envelope})
        self.assertEqual(bound["fixture_capacity"], envelope)
        self.assertEqual(environment["fixture_capacity"], envelope)
        self.assertNotIn("fixture_capacity", cli._bind_fixture_capacity({"git_version": "git"}, None))
        self.assertNotIn(
            "fixture_capacity",
            cli._bind_fixture_capacity({"git_version": "git"}, {"fixture_capacity": "not-a-mapping"}),
        )


if __name__ == "__main__":
    unittest.main()
