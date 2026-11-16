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
    """Re-evaluate a natural-expiry result against the reconciled earliest bound."""
    deadline_ns = clock.earliest_ns + int(bound_ms) * NS_PER_MS
    client = result["client_stop"]
    client_ok = bool(client["confirmed_transport_stop"] and client["observed_ns"] <= deadline_ns)
    group = result.get("git_group", {})
    group_stop_ms = group.get("stop_upper_after_lower_ms")
    if group_stop_ms is None:
        group_ok = result.get("git_group_within_deadline", True)
    else:
        group_stop_ns = result["lower_bound_ns"] + int(round(group_stop_ms * NS_PER_MS))
        group_ok = group_stop_ns <= deadline_ns
    result["expiry_clock"] = clock.report()
    result["deadline_ns"] = deadline_ns
    result["client_stop_within_deadline"] = client_ok
    result["git_group_within_deadline"] = group_ok
    result["configured_bound_proven"] = bool(
        result["configured_bound_proven"]
        and client_ok
        and group_ok
        and result["client_stop_after_lower_ms"] >= 0
    )
    return result
