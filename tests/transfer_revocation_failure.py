#!/usr/bin/env python3
"""Finite, safe partial evidence for Issue #37 bounded transfers.

Only fixed enums, booleans, and bounded numeric metrics already present in the
transfer/probe reports are projected. Raw exception text, paths, argv, OIDs,
bodies, SQL, DSNs, environment values, and provider text are never stored.
"""
import http.client

from transfer_revocation_failure_projection import (
    BACKPRESSURE_BOOLS,
    BACKPRESSURE_INTS,
    BACKPRESSURE_NUMS,
    METRIC_BOUNDS,
    SAFE_ERRNOS,
    PROOF_COMPONENTS,
    SOURCE_BOOLS,
    SOURCE_INTS,
    TIMESTAMP_FIELDS,
    bool_or_none as _bool_or_none,
    bool_value as _bool,
    int_or_none as _int_or_none,
    int_value as _int,
    num_or_none as _num_or_none,
    num_value as _num,
    project as _project,
    safe_errno,
)
from transfer_revocation_failure_reader import reader_stop_or_fail

SCHEMA = "rootyard.transfer_partial_evidence.v1"

PHASES = (
    "fixture_upload", "fixture_commit_push", "scoped_restart_sync",
    "source_precheck", "transport_request", "http_admission", "framing_check",
    "initial_read", "active_barrier_check", "source_bind",
    "concurrent_start_barrier", "group_observer_arm",
    "persistent_pressure_observe", "pre_trigger_finalize", "trigger_commit",
    "natural_expiry_hold", "reader_resume", "transport_stop_observe",
    "post_trigger_pressure_sample", "group_quiescence",
    "group_cleanup_sanity", "final_clock_sample", "final_clock_reconcile",
    "post_revocation_denial", "final_bound_assert", "transfer_cleanup",
    "scoped_service_restore",
)
PHASE_SET = frozenset(PHASES)

BOUNDED_SUBCASES = (
    "pat_revoked", "pat_expired", "member_removed_slow_lfs",
    "generation_changed", "concurrent_job_cancel",
    "concurrent_job_expired_lfs", "db_outage_fail_closed",
)
MIRROR_SUBCASES = ("mirror_source_token_abort",)
SUBCASE_SET = frozenset(BOUNDED_SUBCASES + MIRROR_SUBCASES)
CASE_SET = frozenset({
    "bounded_active_transfer_revocation",
    "mirror_cannot_bypass_revocation_via_origin",
})
TERMINAL_STATES = ("not_run", "unproven", "failed", "passed")
SUBCASE_STATES = ("not_run", "started", "finished")
EXCEPTION_CLASSES = frozenset({
    "assertion", "value_error", "type_error", "key_error", "index_error",
    "os_error", "timeout", "http_exception", "runtime_error",
    "source_precheck", "source_bind", "http_status", "framing", "initial_read",
    "active_barrier", "reader_timeout", "reader_exception",
    "reader_missing_completion", "trigger", "final_clock", "final_proof",
    "cleanup", "unexpected",
})
STOP_KINDS = frozenset({
    "incomplete_read", "short_eof", "reset", "timeout", "complete", "local_error",
})
CLOCK_KIND = "db_clock_expiry_bracket"
RESET_REASONS = frozenset({
    "not_started", "not_required", "net_table_missing", "netns_mismatch",
    "probe0_not_pending", "source_unqualified", "service_inode_not_owned",
    "service_inode_missing", "server_tx_not_positive", "client_rx_not_positive",
    "sample_timing_missing", "sample_duration", "nonmonotonic_sample",
    "sample_gap", "inode_changed", "receiver_queue_changed",
})
class SafeFailure(AssertionError):
    def __init__(self, code="unexpected", partial=None):
        self.code = _enum(code, EXCEPTION_CLASSES, "exception_class", default="unexpected")
        self.partial = partial if isinstance(partial, dict) else {}
        super().__init__(self.code)

    def __str__(self):
        return self.code

def _enum(value, allowed, name, *, default=None):
    if value not in allowed:
        if default is not None:
            return default
        raise ValueError(f"invalid {name} enum")
    return value

def _phase(value, default=None):
    return _enum(value, PHASE_SET, "phase", default=default)


def _exception_class(value, default="unexpected"):
    return _enum(value, EXCEPTION_CLASSES, "exception_class", default=default)


def safe_error_class(error):
    if isinstance(error, SafeFailure):
        return error.code
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, AssertionError):
        return "assertion"
    if isinstance(error, ValueError):
        return "value_error"
    if isinstance(error, TypeError):
        return "type_error"
    if isinstance(error, KeyError):
        return "key_error"
    if isinstance(error, IndexError):
        return "index_error"
    if isinstance(error, OSError):
        return "os_error"
    if isinstance(error, http.client.HTTPException):
        return "http_exception"
    if isinstance(error, RuntimeError):
        return "runtime_error"
    return "unexpected"


def _backpressure_value(report):
    if report is None:
        return None
    if not isinstance(report, dict):
        raise ValueError("backpressure report must be a mapping")
    value = _project(report, bools=BACKPRESSURE_BOOLS,
                     ints=BACKPRESSURE_INTS, nums=BACKPRESSURE_NUMS)
    if "last_reset_reason" in report:
        value["last_reset_reason"] = _enum(
            report["last_reset_reason"], RESET_REASONS, "reset_reason")
    value["source_witness"] = None if report.get("source_witness") is None else _project(
        report["source_witness"], bools=SOURCE_BOOLS, ints=SOURCE_INTS)
    return value


class FailureEvidence:
    def __init__(self, *, case=None, subcase=None, bound_ms=1200, subcases=()):
        if case is not None:
            _enum(case, CASE_SET, "case")
        if subcase is not None:
            _enum(subcase, SUBCASE_SET, "subcase")
        self.case = case
        self.subcase = subcase
        self.bound_ms = _int(bound_ms, "bound_ms", low=1, high=600_000)
        self.phase = None
        self.terminal_state = "not_run"
        self.primary_failure_phase = None
        self.exception_class = None
        self.errno = None
        self.subcase_state = "not_run" if subcase is not None else None
        self.http_status = None
        self.transport_proof = None
        self.final_proof = None
        self.cleanup_state = "not_run"
        self.cleanup_exception_class = None
        self._phases = []
        self._notes = []
        self._timestamps = {name: None for name in TIMESTAMP_FIELDS}
        self._metrics = {name: None for name in METRIC_BOUNDS}
        self._initial_clock = None
        self._final_clock = None
        self._stop = None
        self._source_witness = None
        self._backpressure = None
        self._pre_source = None
        self._pre_backpressure = None
        self._group = None
        self._reader = {
            "finished": None, "alive_after_main_join": None,
            "alive_after_cleanup_join": None, "daemon": None,
            "error_class": None,
        }
        self._proof_components = {name: None for name in PROOF_COMPONENTS}
        self._subcases = {}
        for name in subcases:
            _enum(name, SUBCASE_SET, "subcase")
            self._subcases[name] = None

    def start(self):
        if self.terminal_state == "not_run":
            self.terminal_state = "unproven"
        if self.subcase is not None and self.subcase_state == "not_run":
            self.subcase_state = "started"
        return self

    def enter_phase(self, phase):
        phase = _phase(phase)
        self.phase = phase
        self._append_phase(phase, "started")
        if self.terminal_state == "not_run":
            self.terminal_state = "unproven"
        return self

    def finish_phase(self, phase=None):
        self._append_phase(_phase(phase or self.phase), "finished")
        return self

    def _append_phase(self, phase, state):
        self._phases.append({"phase": phase, "state": state, "exception_class": None})
        if len(self._phases) > len(PHASES) * 2:
            del self._phases[0]

    def note(self, phase, code):
        self._notes.append({"phase": _phase(phase), "exception_class": _exception_class(code)})
        if len(self._notes) > 16:
            del self._notes[0]
        return self

    def fail(self, phase, code, errno_value=None):
        phase = _phase(phase or self.phase or "transport_request")
        code = _exception_class(code)
        if self.primary_failure_phase is None:
            self.primary_failure_phase = phase
            self.exception_class = code
            self.errno = errno_value if errno_value in SAFE_ERRNOS else None
        self.terminal_state = "failed"
        return self

    def fail_exception(self, error, phase=None):
        return self.fail(phase or self.phase, safe_error_class(error), safe_errno(error))

    def mark_unproven(self):
        if self.terminal_state != "failed":
            self.terminal_state = "unproven"
        return self

    def finish_transfer(self, proof, *, final):
        self.set_transport_proof(proof)
        if final:
            self.set_final_proof(proof)
        elif proof is True and self.terminal_state != "failed":
            self.terminal_state = "unproven"
        if self.subcase is not None:
            self.subcase_state = "finished"
        return self

    def cleanup(self, error=None):
        if error is None:
            if self.cleanup_state != "unresolved":
                self.cleanup_state = "passed"
                self.cleanup_exception_class = None
        else:
            self.cleanup_state = "failed"
            self.cleanup_exception_class = safe_error_class(error)
            self.fail("transfer_cleanup", self.cleanup_exception_class, safe_errno(error))
        return self

    def mark_cleanup_unresolved(self, code="reader_timeout"):
        self.cleanup_state = "unresolved"
        self.cleanup_exception_class = _exception_class(code)
        return self

    def set_reader_state(self, *, finished=None, alive_after_main_join=None,
                         alive_after_cleanup_join=None, daemon=None,
                         error_class=None):
        if finished is not None:
            self._reader["finished"] = _bool(finished, "reader_finished")
        if alive_after_main_join is not None:
            self._reader["alive_after_main_join"] = _bool(
                alive_after_main_join, "reader_alive_after_main_join")
        if alive_after_cleanup_join is not None:
            self._reader["alive_after_cleanup_join"] = _bool(
                alive_after_cleanup_join, "reader_alive_after_cleanup_join")
        if daemon is not None:
            self._reader["daemon"] = _bool(daemon, "reader_daemon")
        if error_class is not None:
            self._reader["error_class"] = _exception_class(error_class)
        return self

    def set_pre_trigger_evidence(self, *, source_witness=None, backpressure=None):
        self._pre_source = None if source_witness is None else _project(
            source_witness, bools=SOURCE_BOOLS, ints=SOURCE_INTS)
        self._pre_backpressure = _backpressure_value(backpressure)
        return self

    def set_http_status(self, status):
        self.http_status = _int_or_none(status, "http_status", low=100, high=599)
        return self

    def set_timestamp(self, name, value):
        if name not in TIMESTAMP_FIELDS:
            raise ValueError("unknown timestamp field")
        self._timestamps[name] = _int_or_none(value, name)
        return self

    def set_metric(self, name, value):
        if name not in METRIC_BOUNDS:
            raise ValueError("unknown metric field")
        low, high = METRIC_BOUNDS[name]
        if name == "configured_bound_ms":
            self._metrics[name] = _int_or_none(value, name, low=low, high=high)
        else:
            self._metrics[name] = _num_or_none(value, name, low=low, high=high)
        return self

    def set_clock(self, which, report):
        if which not in ("initial", "final"):
            raise ValueError("clock slot must be initial or final")
        if report is None:
            value = None
        else:
            if not isinstance(report, dict) or report.get("kind") != CLOCK_KIND:
                raise ValueError("unexpected clock report")
            value = {
                "kind": CLOCK_KIND,
                "earliest_ns": _int_or_none(report.get("earliest_ns"), "earliest_ns"),
                "latest_ns": _int_or_none(report.get("latest_ns"), "latest_ns"),
                "width_ms": _num_or_none(report.get("width_ms"), "width_ms"),
                "samples": _int_or_none(report.get("samples"), "samples", high=1 << 20),
            }
        if which == "initial":
            self._initial_clock = value
        else:
            self._final_clock = value
        return self

    def set_source_witness(self, report):
        self._source_witness = None if report is None else _project(
            report, bools=SOURCE_BOOLS, ints=SOURCE_INTS)
        return self

    def set_backpressure(self, report):
        self._backpressure = _backpressure_value(report)
        return self

    def set_group(self, report):
        if report is None:
            self._group = None
            return self
        if not isinstance(report, dict):
            raise ValueError("group report must be a mapping")
        value = _project(report, bools=("armed",),
                         ints=("stop_upper_ns",),
                         nums=("stop_upper_after_lower_ms", "max_poll_gap_ms"))
        groups = report.get("groups")
        if groups is not None and not isinstance(groups, list):
            raise ValueError("group rows must be a list")
        rows = []
        for row in (groups or [])[:16]:
            if not isinstance(row, dict):
                raise ValueError("group row must be a mapping")
            rows.append(_project(
                row, bools=("reuse_detected",),
                ints=("members_observed_max", "first_live_ns", "last_live_ns",
                      "quiescent_ns"),
                nums=("last_live_after_lower_ms", "quiescent_after_lower_ms")))
        value["group_count"] = len(rows)
        value["groups"] = rows
        self._group = value
        return self

    def set_stop(self, report):
        if report is None:
            self._stop = None
            return self
        if not isinstance(report, dict):
            raise ValueError("stop report must be a mapping")
        self._stop = {
            "kind": _enum(report.get("kind"), STOP_KINDS, "stop_kind"),
            "observed_ns": _int_or_none(report.get("observed_ns"), "observed_ns"),
            "received_bytes": _int_or_none(report.get("received_bytes"), "received_bytes"),
            "confirmed_transport_stop": _bool_or_none(
                report.get("confirmed_transport_stop"), "confirmed_transport_stop"),
        }
        return self

    def set_proof_components(self, report):
        if report is None:
            self._proof_components = {name: None for name in PROOF_COMPONENTS}
            return self
        if not isinstance(report, dict):
            raise ValueError("proof components must be a mapping")
        for name in PROOF_COMPONENTS:
            if name in report:
                self._proof_components[name] = _bool_or_none(report[name], name)
        return self

    def set_transport_proof(self, value):
        self.transport_proof = _bool_or_none(value, "transport_proof")
        return self

    def set_final_proof(self, value):
        self.final_proof = _bool_or_none(value, "final_proof")
        if self.final_proof is True and self.primary_failure_phase is None:
            self.terminal_state = "passed"
        elif self.final_proof is False and self.terminal_state != "failed":
            self.terminal_state = "unproven"
        return self

    def start_subcase(self, name):
        name = _enum(name, SUBCASE_SET, "subcase")
        child = FailureEvidence(subcase=name, bound_ms=self.bound_ms)
        child.start()
        self._subcases[name] = child
        return child

    def get_subcase(self, name):
        return self._subcases.get(name)

    def finish_subcase(self, name, child=None):
        name = _enum(name, SUBCASE_SET, "subcase")
        child = child or self._subcases.get(name)
        if child is None:
            raise ValueError("subcase was not started")
        child.subcase_state = "finished"
        self._subcases[name] = child
        return child

    def snapshot(self):
        subcases = {}
        for name, child in self._subcases.items():
            subcases[name] = ({"subcase": name, "subcase_state": "not_run"}
                              if child is None else child.snapshot())
        return {
            "schema": SCHEMA,
            "case": self.case,
            "subcase": self.subcase,
            "bound_ms": self.bound_ms,
            "phase": self.phase,
            "terminal_state": _enum(self.terminal_state, TERMINAL_STATES, "terminal_state"),
            "primary_failure_phase": self.primary_failure_phase,
            "exception_class": self.exception_class,
            "errno": self.errno,
            "subcase_state": self.subcase_state,
            "http_status": self.http_status,
            "timestamps": dict(self._timestamps),
            "metrics": dict(self._metrics),
            "initial_clock": self._initial_clock,
            "final_clock": self._final_clock,
            "transport_stop": self._stop,
            "source_witness": self._source_witness,
            "backpressure": self._backpressure,
            "pre_trigger": {
                "source_witness": self._pre_source,
                "backpressure": self._pre_backpressure,
            },
            "group": self._group,
            "reader": dict(self._reader),
            "proof_components": dict(self._proof_components),
            "transport_proof": self.transport_proof,
            "final_proof": self.final_proof,
            "cleanup": {"state": self.cleanup_state,
                        "exception_class": self.cleanup_exception_class},
            "phases": [dict(item) for item in self._phases],
            "notes": [dict(item) for item in self._notes],
            "subcases": subcases,
        }

    def safe_failure(self, default_code="unexpected"):
        return SafeFailure(self.exception_class or default_code, self.snapshot())
