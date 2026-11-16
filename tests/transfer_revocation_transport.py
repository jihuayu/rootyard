#!/usr/bin/env python3
"""Real loopback transfer driver and backpressure evidence for Issue #37."""
import http.client
import os
import time
import socket
import threading
from urllib.parse import urlsplit

import transfer_revocation_observer as revocation_observer
from transfer_revocation_probe import BackpressureProbe, parse_proc_net_tcp
from transfer_revocation_observer import (
    ProcGroupObserver,
    discover_groups,
    read_proc_table,
)
from transfer_revocation_timing import (
    NS_PER_MS,
    StopKind,
    StopObservation,
    TriggerInterval,
    read_until_transport_stop,
)


class SmallBufferHTTPConnection(http.client.HTTPConnection):
    """Loopback HTTP connection whose SO_RCVBUF is set before connect."""

    def __init__(self, host, port, *, timeout=15, rcvbuf=16 * 1024):
        self.requested_so_rcvbuf = rcvbuf
        self.effective_so_rcvbuf = None
        super().__init__(host, port, timeout=timeout)

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self.requested_so_rcvbuf is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                int(self.requested_so_rcvbuf))
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            self.effective_so_rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        except Exception:
            sock.close()
            raise
        self.sock = sock


def _owned_group_ids(service_pids, uid=None):
    table = read_proc_table(uid=uid)
    return {identity.pgid for identity in discover_groups(table, service_pids)}


def _sleep_until(target_ns):
    while True:
        remaining = target_ns - time.monotonic_ns()
        if remaining <= 0:
            return
        time.sleep(min(remaining / 1_000_000_000, 0.05))


def _ms(ns):
    return round(ns / NS_PER_MS, 3)


def run_timed_transfer(
    *,
    base,
    path,
    method,
    headers,
    body,
    expected_size,
    initial_bytes,
    framing,
    service_pid,
    bound_ms,
    trigger=None,
    trigger_kind="committed_mutation",
    natural_expiry=None,
    post_pause_ms=800,
    rcvbuf=16 * 1024,
    require_backpressure=True,
    require_group=True,
    active_barrier_check=None,
    start_barrier=None,
    source_witness=None,
    source_witness_factory=None,
    source_precheck=None,
    transfer_kind="git",
):
    """Open one real transfer, trigger it, and report conservative evidence."""
    if trigger is None and natural_expiry is None:
        raise ValueError("a committed trigger or natural expiry is required")
    if require_group and service_pid is None:
        raise ValueError("a fixture service PID is required for Git group evidence")
    parsed = urlsplit(base)
    host, port = parsed.hostname, parsed.port
    bound_ns = int(bound_ms) * NS_PER_MS
    post_pause_ns = int(post_pause_ms) * NS_PER_MS
    baseline_groups = _owned_group_ids([service_pid], uid=os.geteuid()) if require_group else set()
    source_precheck_ok = True
    if source_precheck is not None:
        try:
            source_precheck_ok = bool(source_precheck())
        except Exception:
            source_precheck_ok = False
    connection = SmallBufferHTTPConnection(host, port, timeout=15, rcvbuf=rcvbuf)
    response = None
    observer = None
    probe = None
    reader = None
    trigger_ready = None
    trigger_state = {}
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        assert response.status == 200, "transfer was not admitted"
        if framing == "content_length":
            content_length = response.getheader("Content-Length")
            assert content_length is not None and int(content_length) == expected_size
        first = response.read(initial_bytes)
        assert first, "transfer returned no initial bytes"
        first_ns = time.monotonic_ns()
        if active_barrier_check is not None and not active_barrier_check():
            raise AssertionError("authority barrier bypassed active transfer")

        if source_witness is not None:
            try:
                source_witness.bind()
            except Exception:
                pass
        if start_barrier is not None:
            start_barrier.wait(timeout=15)

        if require_group:
            observer = ProcGroupObserver([service_pid]).arm(exclude_pgids=baseline_groups)
            observer.start(max_duration_s=30.0)
        if source_witness_factory is not None:
            try:
                source_witness = source_witness_factory(observer)
            except Exception:
                source_witness = None
            if source_witness is not None:
                try:
                    source_witness.bind()
                except Exception:
                    pass
        if require_backpressure:
            probe = BackpressureProbe(
                service_pid=service_pid,
                client_socket=connection.sock,
                source_witness=source_witness,
                requested_rcvbuf=connection.requested_so_rcvbuf,
                effective_rcvbuf=connection.effective_so_rcvbuf,
            )
        trigger_ready = threading.Event()

        def body_reader():
            trigger_ready.wait(timeout=10)
            state = trigger_state.get("value")
            if state is None:
                return
            lower_ns, resume_ns, deadline_ns = state
            now_ns = time.monotonic_ns()
            if resume_ns > now_ns:
                time.sleep((resume_ns - now_ns) / 1_000_000_000)
            trigger_state["reader_resume_ns"] = time.monotonic_ns()
            trigger_state["stop"] = read_until_transport_stop(
                response=response,
                sock=connection.sock,
                expected_size=expected_size,
                initial_received=len(first),
                resume_ns=0,
                deadline_ns=deadline_ns,
                framing=framing,
            )

        reader = threading.Thread(target=body_reader, name="revocation-body-reader", daemon=True)
        reader.start()

        if probe is not None:
            probe.wait_persistent()
        if observer is not None:
            observer.sample_once()
        interval = None
        if trigger is not None:
            if probe is not None:
                probe.finalize()
            interval, _ = TriggerInterval.measure(trigger_kind, trigger)
            lower_ns = interval.t_before_ns
            deadline_ns = interval.deadline_ns(bound_ms)
            trigger_report = interval.report()
        else:
            lower_ns = natural_expiry.earliest_ns
            deadline_ns = lower_ns + bound_ns
            trigger_report = natural_expiry.report()
            if probe is not None:
                probe.hold_until(lower_ns - 20 * NS_PER_MS)
                probe.finalize()
        resume_ns = lower_ns + post_pause_ns
        trigger_state["value"] = (lower_ns, resume_ns, deadline_ns)
        trigger_ready.set()
        pre_trigger_sample = probe.last_sample if probe is not None else None

        if probe is not None:
            sample_at = max(lower_ns, resume_ns - 20 * NS_PER_MS)
            _sleep_until(sample_at)
            post_sample = probe.sample()
            post_sample_ns = time.monotonic_ns()
        else:
            post_sample = None
            post_sample_ns = None
        reader.join(timeout=max(1.0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000 + 2.0))
        if reader.is_alive():
            stop = StopObservation(StopKind.TIMEOUT, time.monotonic_ns(), len(first))
        else:
            stop = trigger_state.get("stop")
            if stop is None:
                raise AssertionError("body reader ended without an observation")
        reader_resume_ns = trigger_state.get("reader_resume_ns")

        if observer is not None:
            observer_deadline_ns = deadline_ns + 100 * NS_PER_MS
            revocation_observer.wait_for_quiescence_until(
                observer, observer_deadline_ns
            )
            observer.stop()
        group_ok = observer.proven(lower_ns, deadline_ns) if observer is not None else True
        group_sanity_ok = True
        if observer is not None:
            try:
                observer.wait_no_live(timeout_s=2.5)
            except AssertionError:
                group_sanity_ok = False

        if probe is not None:
            pre_trigger_ok = probe.pre_trigger_valid(lower_ns)
        else:
            pre_trigger_ok = lower_ns > first_ns
        source_report = (
            (pre_trigger_sample or {}).get("source_report") or {}
            if pre_trigger_sample is not None else {}
        )
        source_ok = bool(
            source_precheck_ok
            and source_report.get("qualified")
            and (pre_trigger_sample or {}).get("source_qualified")
        )
        client_ok = stop.confirmed and stop.observed_ns <= deadline_ns
        trigger_ok = interval is None or interval.t_after_ns <= deadline_ns
        backpressure_ok = (not require_backpressure) or bool(
            probe and probe.persistent and probe.window.qualified
        )
        post_pause_ok = post_pause_ns <= bound_ns
        actual_resume_ok = bool(
            reader_resume_ns is not None and reader_resume_ns < deadline_ns
        )
        group_required = bool(require_group)
        proof_components = {
            "client_stop_within_deadline": client_ok,
            "group_post_sanity": group_sanity_ok,
            "trigger_within_deadline": trigger_ok,
            "backpressure_qualified": backpressure_ok,
            "source_witness": source_ok,
            "target_pause_within_bound": post_pause_ok,
            "actual_reader_resume_within_deadline": actual_resume_ok,
            "pre_trigger_window": pre_trigger_ok,
        }
        if group_required:
            proof_components["git_group_within_deadline"] = group_ok
        proof = all(proof_components.values())
        result = {
            "configured_bound_ms": int(bound_ms),
            "trigger": trigger_report,
            "lower_bound_ns": lower_ns,
            "deadline_ns": deadline_ns,
            "trigger_within_deadline": trigger_ok,
            "pre_trigger_pause_ms": _ms(lower_ns - first_ns),
            "pre_trigger_backpressure_established": bool(pre_trigger_ok and backpressure_ok),
            "post_trigger_pause_target_ms": _ms(post_pause_ns),
            "post_trigger_pause_ms": (
                _ms(reader_resume_ns - lower_ns) if reader_resume_ns is not None else None
            ),
            "planned_reader_resume_after_lower_ms": _ms(resume_ns - lower_ns),
            "reader_resume_after_lower_ms": (
                _ms(reader_resume_ns - lower_ns) if reader_resume_ns is not None else None
            ),
            "actual_reader_resume_ns": reader_resume_ns,
            "reader_resume_delta_from_target_ms": (
                _ms(reader_resume_ns - resume_ns) if reader_resume_ns is not None else None
            ),
            "actual_reader_resume_within_deadline": actual_resume_ok,
            "post_pause_within_deadline": post_pause_ok,
            "first_byte_ns": first_ns,
            "initial_bytes_received": len(first),
            "transfer_incomplete_at_trigger": len(first) < expected_size,
            "backpressure": probe.report() if probe is not None else {
                "persistent": None,
                "reason": "not required",
            },
            "pre_trigger_backpressure_sample": pre_trigger_sample,
            "post_trigger_backpressure_sample": post_sample,
            "source_witness": source_report,
            "source_precheck_ok": source_precheck_ok,
            "post_trigger_backpressure_sample_ns": post_sample_ns,
            "post_trigger_backpressure_sample_after_lower_ms": (
                _ms(post_sample_ns - lower_ns) if post_sample_ns is not None else None
            ),
            "client_stop": stop.report(),
            "client_stop_after_lower_ms": _ms(stop.observed_ns - lower_ns),
            "client_stop_within_deadline": client_ok,
            "transfer_kind": transfer_kind,
            "group_required": group_required,
            "git_group": observer.report(lower_ns) if observer is not None else {
                "required": False,
                "reason": "no native Git child for LFS",
            },
            "git_group_within_deadline": group_ok if group_required else None,
            "post_transfer_group_stopped": group_sanity_ok,
            "proof_components": proof_components,
            "configured_bound_proven": proof,
        }
        return result
    finally:
        if trigger_ready is not None:
            trigger_ready.set()
        if observer is not None:
            observer.stop()
        if reader is not None:
            reader.join(timeout=2.0)
        if response is not None:
            response.close()
        connection.close()
