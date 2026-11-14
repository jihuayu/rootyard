#!/usr/bin/env python3
"""Deterministic regressions for no-hook PR reconciliation polling.

No binary, PostgreSQL or Git repository is required. The probes are stateful
stand-ins for the independently-read progress marker, queued ``ci_runs`` row
and job pin ref used by ``tests/webhook_pr_sync.py``.
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import webhook_pr_sync as pr_sync  # noqa: E402


HEAD = "a" * 40
BASE = "b" * 40
JOB = "job-pull-version-exact"


class QueuedPinPollTest(unittest.TestCase):
    def test_marker_run_and_stale_pin_are_retried_until_exact_convergence(self):
        states = iter([
            (False, JOB, HEAD),       # run/pin visible, marker not committed yet
            (True, None, None),       # marker visible, queued run query still empty
            (True, JOB, BASE),        # queued run visible, pin still points at base
            (True, JOB, HEAD),        # all observations converge
        ])
        calls = []
        current = (False, JOB, HEAD)

        def marker():
            nonlocal current
            calls.append("marker")
            current = next(states)
            return current[0]

        def queued_run():
            calls.append("queued_run")
            return current[1]

        def pin_oid(job_id):
            calls.append(("pin", job_id))
            return current[2]

        job = pr_sync.wait_queued_pin(
            "transient PR sync observation", marker, queued_run, pin_oid,
            HEAD, timeout=1.0, interval=0.0,
        )
        self.assertEqual(job, JOB)
        self.assertEqual(calls, [
            "marker",
            "marker", "queued_run",
            "marker", "queued_run", ("pin", JOB),
            "marker", "queued_run", ("pin", JOB),
        ])

    def test_stale_pin_times_out_instead_of_accepting_the_job(self):
        pinned = []

        def pin_oid(job_id):
            pinned.append(job_id)
            return BASE

        with self.assertRaisesRegex(
            AssertionError, r"timeout after .*waiting for permanently stale pin"
        ):
            pr_sync.wait_queued_pin(
                "permanently stale pin", lambda: True, lambda: JOB, pin_oid,
                HEAD, timeout=0.05, interval=0.001,
            )
        self.assertTrue(pinned)
        self.assertEqual(set(pinned), {JOB})

    def test_probe_errors_propagate_without_retry(self):
        def failure(message):
            def boom():
                raise RuntimeError(message)
            return boom

        cases = (
            ("marker", "marker failed"),
            ("queued_run", "queued_run failed"),
            ("pin", "pin failed"),
        )
        for failing, message in cases:
            calls = []
            boom = failure(message)

            def marker(failing=failing, boom=boom):
                calls.append("marker")
                if failing == "marker":
                    return boom()
                return True

            def queued_run(failing=failing, boom=boom):
                calls.append("queued_run")
                if failing == "queued_run":
                    return boom()
                return JOB

            def pin(job_id, failing=failing, boom=boom):
                calls.append(("pin", job_id))
                if failing == "pin":
                    return boom()
                return HEAD

            with self.subTest(probe=failing):
                with self.assertRaisesRegex(RuntimeError, message):
                    pr_sync.wait_queued_pin(
                        "probe failure", marker, queued_run, pin, HEAD,
                        timeout=1.0, interval=0.0,
                    )
                if failing == "marker":
                    self.assertEqual(calls, ["marker"])
                elif failing == "queued_run":
                    self.assertEqual(calls, ["marker", "queued_run"])
                else:
                    self.assertEqual(calls, ["marker", "queued_run", ("pin", JOB)])


if __name__ == "__main__":
    unittest.main()
