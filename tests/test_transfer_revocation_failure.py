#!/usr/bin/env python3
"""Hermetic tests for finite Issue #37 partial-failure evidence."""
import json
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))

import ci_job_checkouts as checkouts  # noqa: E402
import transfer_revocation_failure as failure  # noqa: E402
from transfer_revocation_source import (  # noqa: E402
    SOURCE_FAILURE_WCHAN,
    SOURCE_PROOF_KIND_OWNED_STDOUT_PIPE_FULL,
)
import transfer_revocation_timing as timing  # noqa: E402
import transfer_revocation_transport as transport  # noqa: E402


class FailureEvidenceTests(unittest.TestCase):
    def test_primary_failure_survives_cleanup_and_unknown_stays_unproven(self):
        evidence = failure.FailureEvidence(subcase="pat_revoked", bound_ms=1200)
        evidence.start()
        evidence.enter_phase("source_bind")
        evidence.note("source_bind", "os_error")
        evidence.fail("source_bind", "source_bind", errno_value=5)
        evidence.cleanup(None)
        self.assertEqual(evidence.snapshot()["cleanup"]["state"], "passed")
        self.assertEqual(evidence.snapshot()["primary_failure_phase"], "source_bind")
        self.assertEqual(evidence.snapshot()["exception_class"], "source_bind")
        evidence.cleanup(OSError(5, "secret cleanup text"))
        snapshot = evidence.snapshot()
        self.assertEqual(snapshot["primary_failure_phase"], "source_bind")
        self.assertEqual(snapshot["cleanup"]["state"], "failed")
        self.assertEqual(snapshot["cleanup"]["exception_class"], "os_error")
        self.assertIsNone(snapshot["final_proof"])
        self.assertNotIn("secret", json.dumps(snapshot))

    def test_initial_and_final_clock_evidence_are_distinct(self):
        evidence = failure.FailureEvidence(subcase="pat_expired")
        evidence.start()
        initial = {
            "kind": "db_clock_expiry_bracket", "earliest_ns": 10,
            "latest_ns": 20, "width_ms": 0.001, "samples": 1,
        }
        final = {
            "kind": "db_clock_expiry_bracket", "earliest_ns": 30,
            "latest_ns": 40, "width_ms": 0.002, "samples": 2,
        }
        evidence.set_clock("initial", initial)
        self.assertEqual(evidence.snapshot()["initial_clock"]["earliest_ns"], 10)
        self.assertIsNone(evidence.snapshot()["final_clock"])
        self.assertIsNone(evidence.snapshot()["final_proof"])
        evidence.set_clock("final", final)
        snapshot = evidence.snapshot()
        self.assertEqual(snapshot["initial_clock"]["earliest_ns"], 10)
        self.assertEqual(snapshot["final_clock"]["earliest_ns"], 30)
        self.assertIsNone(snapshot["final_proof"])
        evidence.fail("final_clock_reconcile", "final_clock")
        self.assertEqual(snapshot["primary_failure_phase"], None)
        self.assertEqual(evidence.snapshot()["primary_failure_phase"], "final_clock_reconcile")

    def test_subcase_inventory_reports_started_finished_and_not_run(self):
        evidence = failure.FailureEvidence(
            case="bounded_active_transfer_revocation",
            subcases=failure.BOUNDED_SUBCASES,
        )
        evidence.start()
        child = evidence.start_subcase("pat_revoked")
        child.fail("trigger_commit", "trigger")
        evidence.finish_subcase("pat_revoked")
        done = evidence.start_subcase("pat_expired")
        done.finish_transfer(True, final=False)
        evidence.finish_subcase("pat_expired")
        snapshot = evidence.snapshot()
        self.assertEqual(snapshot["subcases"]["pat_revoked"]["primary_failure_phase"],
                         "trigger_commit")
        self.assertEqual(snapshot["subcases"]["pat_expired"]["subcase_state"], "finished")
        self.assertEqual(snapshot["subcases"]["generation_changed"]["subcase_state"],
                         "not_run")
        self.assertEqual(len(snapshot["subcases"]), 7)

    def test_injected_failures_keep_first_phase_and_finite_class(self):
        for phase in failure.PHASES:
            evidence = failure.FailureEvidence(subcase="db_outage_fail_closed")
            evidence.start()
            evidence.enter_phase(phase)
            evidence.fail(phase, "assertion")
            evidence.fail("final_bound_assert", "final_proof")
            snapshot = evidence.snapshot()
            self.assertEqual(snapshot["primary_failure_phase"], phase)
            self.assertEqual(snapshot["exception_class"], "assertion")
            self.assertEqual(snapshot["terminal_state"], "failed")
            self.assertIsNone(snapshot["final_proof"])
            self.assertTrue(all(code in failure.EXCEPTION_CLASSES
                                for code in (snapshot["exception_class"],)))

    def test_untrusted_payload_is_rejected_and_unknown_keys_are_dropped(self):
        evidence = failure.FailureEvidence(subcase="pat_revoked")
        evidence.start()
        evidence.set_source_witness({
            "failure_code": 2, "fatal_failure_code": 0, "qualified": False,
            "object_path": "/secret/object", "info": "fd=7 /secret",
            "argv": ["secret"], "body": b"secret",
        })
        text = json.dumps(evidence.snapshot())
        self.assertIn('"failure_code": 2', text)
        self.assertNotIn("/secret", text)
        self.assertNotIn("argv", text)
        for call in (
            lambda: evidence.set_http_status("200"),
            lambda: evidence.set_metric("pre_trigger_pause_ms", float("nan")),
            lambda: evidence.set_metric("initial_bytes_received", float("inf")),
            lambda: evidence.set_source_witness({"failure_code": "secret"}),
            lambda: evidence.set_backpressure({"last_reset_reason": "secret"}),
            lambda: evidence.set_stop({"kind": "secret"}),
            lambda: evidence.set_group({"groups": "secret"}),
            lambda: evidence.set_proof_components({"source_witness": "yes"}),
        ):
            with self.assertRaises(ValueError):
                call()

    def test_known_partial_metrics_are_retained(self):
        evidence = failure.FailureEvidence(subcase="pat_expired")
        evidence.start()
        evidence.set_http_status(206)
        evidence.set_timestamp("first_byte_ns", 123)
        evidence.set_metric("initial_bytes_received", 1024)
        evidence.set_stop({
            "kind": "timeout", "observed_ns": 456,
            "received_bytes": 99, "confirmed_transport_stop": False,
        })
        evidence.set_backpressure({
            "qualified": False, "sample_count": 3,
            "last_reset_reason": "sample_gap",
            "source_witness": {"failure_code": 1, "qualified": False},
            "fixture_four_tuple": {"server_port": 1},
        })
        evidence.set_group({
            "armed": True, "stop_upper_ns": 500, "groups": [
                {"members_observed_max": 2, "reuse_detected": False,
                 "pgid": 12345, "leader_starttime": 999},
            ],
        })
        snapshot = evidence.snapshot()
        self.assertEqual(snapshot["http_status"], 206)
        self.assertEqual(snapshot["timestamps"]["first_byte_ns"], 123)
        self.assertEqual(snapshot["metrics"]["initial_bytes_received"], 1024)
        self.assertEqual(snapshot["transport_stop"]["kind"], "timeout")
        self.assertEqual(snapshot["backpressure"]["last_reset_reason"], "sample_gap")
        self.assertNotIn("fixture_four_tuple", snapshot["backpressure"])
        self.assertEqual(snapshot["group"]["group_count"], 1)
        self.assertNotIn("pgid", snapshot["group"]["groups"][0])

    def test_pre_trigger_projection_retains_only_fixed_fatal_wchan_diagnostics(self):
        evidence = failure.FailureEvidence(subcase="db_outage_fail_closed")
        source = {
            "fatal_failure_code": SOURCE_FAILURE_WCHAN,
            "qualified": False,
            "wchan_shape": "zero",
            "wchan_writer_recheck": "same_writer_running",
        }
        evidence.set_pre_trigger_evidence(source_witness=dict(
            source, raw_wchan="secret", source_writer_starttime=123))
        self.assertEqual(evidence.snapshot()["pre_trigger"]["source_witness"], source)
        for name in ("wchan_shape", "wchan_writer_recheck"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence.set_pre_trigger_evidence(source_witness=dict(
                    source, **{name: "secret"}))
        evidence.set_pre_trigger_evidence(source_witness=dict(
            source, fatal_failure_code=0, qualified=True))
        self.assertEqual(evidence.snapshot()["pre_trigger"]["source_witness"], {
            "fatal_failure_code": 0, "qualified": True,
        })

    def test_pre_trigger_projection_retains_only_fixed_pipe_proof_kind(self):
        evidence = failure.FailureEvidence(subcase="generation_changed")
        source = {
            "qualified": True,
            "source_proof_kind_code": SOURCE_PROOF_KIND_OWNED_STDOUT_PIPE_FULL,
            "source_pipe_full": True,
        }
        evidence.set_pre_trigger_evidence(source_witness=dict(
            source, raw_pipe_payload="secret", source_pipe_capacity=65536,
            source_writer_starttime=123))
        self.assertEqual(evidence.snapshot()["pre_trigger"]["source_witness"], source)
        for name, value in (
            ("source_pipe_full", "yes"),
            ("source_proof_kind_code", -1),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence.set_pre_trigger_evidence(source_witness=dict(
                    source, **{name: value}))

    def test_safe_failure_has_no_raw_exception_text(self):
        evidence = failure.FailureEvidence(subcase="generation_changed")
        evidence.start()
        evidence.enter_phase("transport_request")
        evidence.fail_exception(RuntimeError("secret /tmp/path oid=abc body=x"))
        error = evidence.safe_failure()
        self.assertEqual(error.code, "runtime_error")
        self.assertEqual(str(error), "runtime_error")
        self.assertNotIn("secret", str(error))
        self.assertNotIn("secret", json.dumps(error.partial))

    def test_successful_cleanup_does_not_promote_unproven_proof(self):
        evidence = failure.FailureEvidence(subcase="concurrent_job_cancel")
        evidence.start()
        evidence.enter_phase("trigger_commit")
        evidence.cleanup(None)
        self.assertEqual(evidence.snapshot()["terminal_state"], "unproven")
        self.assertIsNone(evidence.snapshot()["final_proof"])
        evidence.set_final_proof(True)
        self.assertEqual(evidence.snapshot()["terminal_state"], "passed")


class ReaderEvidenceTests(unittest.TestCase):
    def test_missing_reader_completion_is_a_safe_failure(self):
        evidence = failure.FailureEvidence(subcase="pat_revoked")
        evidence.start()
        with self.assertRaises(failure.SafeFailure) as caught:
            failure.reader_stop_or_fail(
                evidence, {"reader_finished": False},
                timed_out=False, received=10, now_ns=123,
            )
        self.assertEqual(caught.exception.code, "reader_missing_completion")
        self.assertEqual(caught.exception.partial["primary_failure_phase"],
                         "transport_stop_observe")

    def test_reader_exception_is_reduced_to_finite_code(self):
        evidence = failure.FailureEvidence(subcase="pat_revoked")
        evidence.start()
        with self.assertRaises(failure.SafeFailure) as caught:
            failure.reader_stop_or_fail(
                evidence,
                {"reader_finished": True, "reader_error_class": "value_error",
                 "reader_error_errno": 5},
                timed_out=False, received=0, now_ns=1,
            )
        self.assertEqual(caught.exception.code, "value_error")
        self.assertEqual(caught.exception.partial["errno"], 5)
        self.assertNotIn("secret", json.dumps(caught.exception.partial))

    def test_reader_exception_preserves_observed_resume(self):
        evidence = failure.FailureEvidence(subcase="pat_revoked")
        evidence.start()
        with self.assertRaises(failure.SafeFailure) as caught:
            failure.reader_stop_or_fail(
                evidence,
                {"reader_resume_ns": 1_000_000_000, "reader_finished": True,
                 "reader_error_class": "value_error", "reader_error_errno": 5},
                timed_out=False, received=0, now_ns=1_100_000_000,
                lower_ns=100_000_000, resume_ns=800_000_000,
            )
        snapshot = caught.exception.partial
        self.assertEqual(snapshot["timestamps"]["reader_resume_ns"], 1_000_000_000)
        self.assertEqual(snapshot["metrics"]["post_trigger_pause_ms"], 900.0)
        self.assertEqual(
            snapshot["metrics"]["reader_resume_delta_from_target_ms"], 200.0)
        self.assertEqual(snapshot["primary_failure_phase"], "transport_stop_observe")
        self.assertEqual(snapshot["exception_class"], "value_error")
        self.assertIsNone(snapshot["final_proof"])

    def test_reader_observed_false_main_join_is_truthful(self):
        evidence = failure.FailureEvidence(subcase="pat_revoked")
        evidence.start()
        stop = failure.reader_stop_or_fail(
            evidence,
            {"reader_finished": True,
             "stop": timing.StopObservation(timing.StopKind.INCOMPLETE_READ, 5, 1)},
            timed_out=False, received=1, now_ns=6,
            lower_ns=1, resume_ns=2,
        )
        snapshot = evidence.snapshot()
        self.assertEqual(stop.kind, timing.StopKind.INCOMPLETE_READ)
        self.assertIs(snapshot["reader"]["alive_after_main_join"], False)
        evidence.cleanup(None)
        self.assertEqual(evidence.snapshot()["cleanup"]["state"], "passed")

    def test_reader_timeout_is_unproven_not_a_pass(self):
        evidence = failure.FailureEvidence(subcase="pat_revoked")
        evidence.start()
        stop = failure.reader_stop_or_fail(
            evidence, {}, timed_out=True, received=3, now_ns=99,
        )
        self.assertEqual(stop.kind, timing.StopKind.TIMEOUT)
        snapshot = evidence.snapshot()
        self.assertEqual(snapshot["terminal_state"], "unproven")
        self.assertFalse(snapshot["transport_stop"]["confirmed_transport_stop"])
        self.assertEqual(snapshot["cleanup"]["state"], "unresolved")
        self.assertEqual(snapshot["cleanup"]["exception_class"], "reader_timeout")
        self.assertTrue(snapshot["reader"]["alive_after_main_join"])
        evidence.set_reader_state(alive_after_cleanup_join=True)
        evidence.cleanup(None)
        self.assertEqual(evidence.snapshot()["cleanup"]["state"], "unresolved")


class _CaseHarness(checkouts.JobCheckoutHarness):
    def __init__(self):
        self.results = []
        self.secrets = []
        self.base_db = "db"
        self.db = "db"


class CaseSerializationTests(unittest.TestCase):
    def test_failed_case_row_gets_fixed_code_and_nested_safe_proof(self):
        harness = _CaseHarness()

        def fails(evidence):
            evidence.start()
            evidence.enter_phase("transport_request")
            evidence.fail_exception(RuntimeError("secret /tmp/path oid=abc"))
            raise RuntimeError("secret /tmp/path oid=abc")

        with self.assertRaises(failure.SafeFailure):
            harness.run_case_with_partial(
                "bounded_active_transfer_revocation", fails,
                failure.BOUNDED_SUBCASES,
            )
        row = harness.results[0]
        self.assertEqual(row["name"], "bounded_active_transfer_revocation")
        self.assertEqual(row["status"], "failed")
        self.assertIn("seconds", row)
        self.assertEqual(row["error"], "runtime_error")
        self.assertNotIn("secret", row["error"])
        proof = row["partial_proof"]
        self.assertEqual(proof["terminal_state"], "failed")
        self.assertEqual(proof["subcases"]["pat_revoked"]["subcase_state"], "not_run")
        self.assertNotIn("secret", json.dumps(proof))

    def test_successful_case_schema_stays_compatible(self):
        harness = _CaseHarness()

        def passes(evidence):
            evidence.start()
            evidence.set_final_proof(True)
            return {"all_proven": True}

        harness.run_case_with_partial(
            "mirror_cannot_bypass_revocation_via_origin", passes,
            failure.MIRROR_SUBCASES,
        )
        row = harness.results[0]
        self.assertEqual(row["status"], "passed")
        self.assertEqual(row["detail"], {"all_proven": True})
        self.assertNotIn("partial_proof", row)

    def test_failed_subcase_is_finished_with_fixed_code(self):
        harness = _CaseHarness()
        evidence = failure.FailureEvidence(
            case="bounded_active_transfer_revocation",
            subcases=failure.BOUNDED_SUBCASES,
        )
        evidence.start()

        def fails(*args, **kwargs):
            raise RuntimeError("secret /tmp/path")

        with self.assertRaises(RuntimeError):
            harness._run_subcase(evidence, "pat_revoked", fails)
        snapshot = evidence.snapshot()["subcases"]["pat_revoked"]
        self.assertEqual(snapshot["subcase_state"], "finished")
        self.assertEqual(snapshot["primary_failure_phase"], "transport_request")
        self.assertEqual(snapshot["exception_class"], "runtime_error")
        self.assertNotIn("secret", json.dumps(snapshot))

    def test_expiry_subcase_keeps_initial_and_final_clock_distinct(self):
        harness = _CaseHarness()
        evidence = failure.FailureEvidence(
            case="bounded_active_transfer_revocation",
            subcases=failure.BOUNDED_SUBCASES,
        )
        evidence.start()
        child = evidence.start_subcase("pat_expired")
        child.set_clock("initial", {
            "kind": "db_clock_expiry_bracket", "earliest_ns": 10,
            "latest_ns": 20, "width_ms": 0.001, "samples": 1,
        })
        clock = types.SimpleNamespace(report=lambda: {
            "kind": "db_clock_expiry_bracket", "earliest_ns": 30,
            "latest_ns": 40, "width_ms": 0.002, "samples": 2,
        })
        harness._finish_expiry_subcase(
            evidence, "pat_expired", {"configured_bound_proven": True}, clock,
        )
        snapshot = evidence.snapshot()["subcases"]["pat_expired"]
        self.assertEqual(snapshot["initial_clock"]["earliest_ns"], 10)
        self.assertEqual(snapshot["final_clock"]["earliest_ns"], 30)
        self.assertTrue(snapshot["final_proof"])
        self.assertEqual(snapshot["subcase_state"], "finished")

    def test_only_two_b1200_callables_use_partial_wrapper(self):
        source = (ROOT / "tests" / "ci_job_checkouts.py").read_text(encoding="utf-8")
        self.assertEqual(source.count("harness.run_case_with_partial("), 2)
        self.assertIn("harness.case(name, getattr(harness, name))", source)
        self.assertIn("def bounded_active_transfer_revocation(self, evidence=None)",
                      source)
        self.assertIn("def mirror_cannot_bypass_revocation_via_origin(self, evidence=None)",
                      source)


class TransportEntryTests(unittest.TestCase):
    def test_transport_entry_reduces_configuration_error_without_io(self):
        with self.assertRaises(failure.SafeFailure) as caught:
            transport.run_timed_transfer(
                base="http://127.0.0.1:1", path="/", method="GET", headers={},
                body=None, expected_size=1, initial_bytes=1,
                framing="content_length", service_pid=None, bound_ms=1200,
            )
        self.assertEqual(caught.exception.code, "value_error")
        self.assertNotIn("a committed trigger", json.dumps(caught.exception.partial))


if __name__ == "__main__":
    unittest.main()
