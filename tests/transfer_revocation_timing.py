#!/usr/bin/env python3
"""Typed clock and strict transport-stop evidence for Issue #37.

All elapsed-time decisions use ``time.monotonic_ns``. A mutation trigger is
bracketed by a committed operation. A natural expiry is mapped from the
authoritative PostgreSQL clock into that same monotonic clock and sampled both
before and after the scenario. A timeout, local close, or deadline expiry is not
a server-stop observation.
"""
from dataclasses import dataclass
import errno
import http.client
import socket
import time


NS_PER_MS = 1_000_000
MAX_CLOCK_MAPPING_SKEW_NS = 100 * NS_PER_MS
CONFIRMED_STOP_KINDS = frozenset({"incomplete_read", "short_eof", "reset"})


class InconsistentClockMapping(RuntimeError):
    """The authoritative clock did not map consistently across a scenario."""


@dataclass(frozen=True)
class TriggerInterval:
    kind: str
    t_before_ns: int
    t_after_ns: int

    def __post_init__(self):
        if self.t_after_ns < self.t_before_ns:
            raise ValueError("trigger interval end precedes start")

    @classmethod
    def measure(cls, kind, operation):
        before = time.monotonic_ns()
        result = operation()
        after = time.monotonic_ns()
        return cls(kind=kind, t_before_ns=before, t_after_ns=after), result

    @property
    def duration_ns(self):
        return self.t_after_ns - self.t_before_ns

    def deadline_ns(self, bound_ms):
        return self.t_before_ns + int(bound_ms) * NS_PER_MS

    def report(self):
        return {
            "kind": self.kind,
            "t_before_ns": self.t_before_ns,
            "t_after_ns": self.t_after_ns,
            "duration_ms": round(self.duration_ns / NS_PER_MS, 3),
        }


@dataclass(frozen=True)
class DbClockSample:
    start_ns: int
    end_ns: int
    epoch_seconds: float

    def __post_init__(self):
        if self.end_ns < self.start_ns:
            raise ValueError("clock sample end precedes start")

    def map_expiry(self, expiry_epoch_seconds):
        delta_ns = int(round((float(expiry_epoch_seconds) - self.epoch_seconds) * 1_000_000_000))
        return self.start_ns + delta_ns, self.end_ns + delta_ns


@dataclass(frozen=True)
class ExpiryClock:
    earliest_ns: int
    latest_ns: int
    width_ns: int
    samples: int

    def report(self):
        return {
            "kind": "db_clock_expiry_bracket",
            "earliest_ns": self.earliest_ns,
            "latest_ns": self.latest_ns,
            "width_ms": round(self.width_ns / NS_PER_MS, 3),
            "samples": self.samples,
        }


def reconcile_expiry(samples, expiry_epoch_seconds):
    """Map a real DB-clock expiry conservatively, rejecting clock jumps."""
    if not samples:
        raise ValueError("at least one DB clock sample is required")
    mappings = [sample.map_expiry(expiry_epoch_seconds) for sample in samples]
    centers = [start + (end - start) // 2 for start, end in mappings]
    if max(centers) - min(centers) > MAX_CLOCK_MAPPING_SKEW_NS:
        raise InconsistentClockMapping("DB clock mapping changed during scenario")
    earliest = min(start for start, _ in mappings)
    latest = max(end for _, end in mappings)
    return ExpiryClock(earliest_ns=earliest, latest_ns=latest,
                       width_ns=latest - earliest, samples=len(samples))


class StopKind:
    INCOMPLETE_READ = "incomplete_read"
    SHORT_EOF = "short_eof"
    RESET = "reset"
    TIMEOUT = "timeout"
    COMPLETE = "complete"
    LOCAL_ERROR = "local_error"


@dataclass(frozen=True)
class StopObservation:
    kind: str
    observed_ns: int
    received: int

    @property
    def confirmed(self):
        return self.kind in CONFIRMED_STOP_KINDS

    def report(self):
        return {
            "kind": self.kind,
            "observed_ns": self.observed_ns,
            "received_bytes": self.received,
            "confirmed_transport_stop": self.confirmed,
        }


def classify_read_error(error):
    if isinstance(error, http.client.IncompleteRead):
        return StopKind.INCOMPLETE_READ, len(error.partial or b"")
    if isinstance(error, http.client.RemoteDisconnected):
        return StopKind.RESET, 0
    if isinstance(error, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return StopKind.RESET, 0
    if isinstance(error, (socket.timeout, TimeoutError)):
        return StopKind.TIMEOUT, 0
    if isinstance(error, OSError):
        if error.errno in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE, errno.ENETRESET):
            return StopKind.RESET, 0
        if error.errno == errno.ETIMEDOUT:
            return StopKind.TIMEOUT, 0
        return StopKind.LOCAL_ERROR, 0
    if isinstance(error, http.client.HTTPException):
        return StopKind.LOCAL_ERROR, 0
    return StopKind.LOCAL_ERROR, 0


def classify_clean_eof(*, framing, received, expected_size):
    if framing == "content_length" and received < expected_size:
        return StopKind.SHORT_EOF
    return StopKind.COMPLETE


def read_until_transport_stop(*, response, sock, expected_size, initial_received,
                              resume_ns, deadline_ns, framing):
    """Read promptly after resume; only confirmed truncation/reset is a stop."""
    received = int(initial_received)
    now_ns = time.monotonic_ns()
    if resume_ns > now_ns:
        time.sleep((resume_ns - now_ns) / 1_000_000_000)
    while True:
        now_ns = time.monotonic_ns()
        remaining_ns = deadline_ns - now_ns
        if remaining_ns <= 0:
            return StopObservation(StopKind.TIMEOUT, now_ns, received)
        sock.settimeout(remaining_ns / 1_000_000_000)
        try:
            chunk = response.read1(64 * 1024)
        except Exception as error:  # classified into a fixed, reportable kind
            kind, partial = classify_read_error(error)
            received += partial
            return StopObservation(kind, time.monotonic_ns(), received)
        if not chunk:
            kind = classify_clean_eof(
                framing=framing, received=received, expected_size=expected_size
            )
            return StopObservation(kind, time.monotonic_ns(), received)
        received += len(chunk)
        if received >= expected_size:
            return StopObservation(StopKind.COMPLETE, time.monotonic_ns(), received)


def apply_natural_expiry_clock(result, clock, bound_ms):
    """Re-evaluate and rewrite relative evidence against the final E_lower."""
    final_lower_ns = clock.earliest_ns
    deadline_ns = final_lower_ns + int(bound_ms) * NS_PER_MS
    result.setdefault("initial_lower_bound_ns", result.get("lower_bound_ns"))
    result.setdefault("initial_trigger", result.get("trigger"))
    clock_report = clock.report()
    result["expiry_clock"] = clock_report
    result["trigger"] = clock_report
    result["lower_bound_ns"] = final_lower_ns
    result["deadline_ns"] = deadline_ns
    result["clock_uncertainty_ms"] = clock_report["width_ms"]

    first_byte_ns = result.get("first_byte_ns")
    if isinstance(first_byte_ns, int):
        result["pre_trigger_pause_ms"] = round(
            (final_lower_ns - first_byte_ns) / NS_PER_MS, 3
        )

    client = result["client_stop"]
    client_ok = bool(
        client["confirmed_transport_stop"] and client["observed_ns"] <= deadline_ns
    )
    result["client_stop_after_lower_ms"] = round(
        (client["observed_ns"] - final_lower_ns) / NS_PER_MS, 3
    )
    result["client_stop_within_deadline"] = client_ok

    actual_resume_ns = result.get("actual_reader_resume_ns")
    actual_resume_ok = bool(
        isinstance(actual_resume_ns, int) and actual_resume_ns < deadline_ns
    )
    result["actual_reader_resume_after_lower_ms"] = (
        round((actual_resume_ns - final_lower_ns) / NS_PER_MS, 3)
        if isinstance(actual_resume_ns, int) else None
    )
    result["actual_post_trigger_pause_ms"] = (
        round((actual_resume_ns - final_lower_ns) / NS_PER_MS, 3)
        if isinstance(actual_resume_ns, int) else None
    )
    target_pause_ms = result.get("post_trigger_pause_target_ms")
    result["post_trigger_pause_ms"] = result["actual_post_trigger_pause_ms"]
    result["planned_reader_resume_after_lower_ms"] = target_pause_ms
    result["reader_resume_delta_from_target_ms"] = (
        round(result["actual_reader_resume_after_lower_ms"] - target_pause_ms, 3)
        if target_pause_ms is not None and result["actual_reader_resume_after_lower_ms"] is not None
        else None
    )
    result["actual_reader_resume_within_deadline"] = actual_resume_ok

    post_sample_ns = result.get("post_trigger_backpressure_sample_ns")
    result["post_trigger_backpressure_sample_after_lower_ms"] = (
        round((post_sample_ns - final_lower_ns) / NS_PER_MS, 3)
        if isinstance(post_sample_ns, int) else None
    )
    pre_sample = result.get("pre_trigger_backpressure_sample") or {}
    pre_sample_ns = pre_sample.get("observed_ns")
    result["pre_trigger_backpressure_sample_after_lower_ms"] = (
        round((pre_sample_ns - final_lower_ns) / NS_PER_MS, 3)
        if isinstance(pre_sample_ns, int) else None
    )
    max_gap_ns = int(
        (result.get("backpressure", {}).get("max_gap_ms") or 100.0) * NS_PER_MS
    )

    group = result.get("git_group") or {}
    group_required = bool(result.get("group_required", True))
    group_stop_ns = group.get("stop_upper_ns")
    if group_required:
        group_ok = bool(isinstance(group_stop_ns, int) and group_stop_ns <= deadline_ns)
    else:
        group_ok = None
    for observation in group.get("groups", []):
        if isinstance(observation.get("last_live_ns"), int):
            observation["last_live_after_lower_ms"] = round(
                (observation["last_live_ns"] - final_lower_ns) / NS_PER_MS, 3
            )
        if isinstance(observation.get("quiescent_ns"), int):
            observation["quiescent_after_lower_ms"] = round(
                (observation["quiescent_ns"] - final_lower_ns) / NS_PER_MS, 3
            )
    if isinstance(group.get("stop_upper_ns"), int):
        group["stop_upper_after_lower_ms"] = round(
            (group["stop_upper_ns"] - final_lower_ns) / NS_PER_MS, 3
        )

    max_gap_ms = (result.get("backpressure") or {}).get("max_gap_ms")
    pre_order_ok = bool(
        isinstance(first_byte_ns, int)
        and isinstance(pre_sample_ns, int)
        and isinstance(max_gap_ms, (int, float))
        and final_lower_ns > first_byte_ns
        and pre_sample_ns <= final_lower_ns
        and final_lower_ns - pre_sample_ns <= int(max_gap_ms * NS_PER_MS)
    )

    components = dict(result.get("proof_components") or {})
    required_components = (
        "trigger_within_deadline",
        "backpressure_qualified",
        "source_witness",
        "group_post_sanity",
        "target_pause_within_bound",
        "pre_trigger_window",
    )
    for key in required_components:
        if type(components.get(key)) is not bool:
            components[key] = False
    components["client_stop_within_deadline"] = client_ok
    components["actual_reader_resume_within_deadline"] = actual_resume_ok
    components["pre_trigger_window"] = bool(
        components["pre_trigger_window"] and pre_order_ok
    )
    if group_required:
        components["git_group_within_deadline"] = group_ok
    else:
        components.pop("git_group_within_deadline", None)
    result["proof_components"] = components
    result["group_required"] = group_required
    result["git_group_within_deadline"] = group_ok
    result["configured_bound_proven"] = all(components.values())
    return result
