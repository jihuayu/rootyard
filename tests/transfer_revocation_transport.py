#!/usr/bin/env python3
"""Real loopback transfer driver and backpressure evidence for Issue #37."""
from dataclasses import dataclass
import http.client
import os
import time
from pathlib import Path
import socket
import struct
import threading
from urllib.parse import urlsplit

import transfer_revocation_observer as revocation_observer
from transfer_revocation_backpressure import SustainedStallWindow
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


@dataclass(frozen=True)
class NetTcpEntry:
    local_host: str
    local_port: int
    remote_host: str
    remote_port: int
    state: str
    tx_queue: int
    rx_queue: int
    timer_active: int
    inode: int


def _ipv4_from_hex(value):
    return socket.inet_ntoa(struct.pack("<I", int(value, 16)))


def parse_proc_net_tcp(text):
    """Parse only the fixed numeric fields from a proc net table."""
    entries = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or fields[0] == "sl":
            continue
        try:
            local_hex, local_port_hex = fields[1].split(":")
            remote_hex, remote_port_hex = fields[2].split(":")
            tx_raw, rx_raw = fields[4].split(":")
            timer_active = int(fields[5].split(":", 1)[0], 16)
            entries.append(NetTcpEntry(
                local_host=_ipv4_from_hex(local_hex),
                local_port=int(local_port_hex, 16),
                remote_host=_ipv4_from_hex(remote_hex),
                remote_port=int(remote_port_hex, 16),
                state=fields[3],
                tx_queue=int(tx_raw, 16),
                rx_queue=int(rx_raw, 16),
                timer_active=timer_active,
                inode=int(fields[9]),
            ))
        except (ValueError, IndexError, struct.error):
            continue
    return entries


def server_fd_owns_inode(service_pid, inode, proc_root=Path("/proc")):
    if not inode:
        return False
    fd_dir = Path(proc_root) / str(service_pid) / "fd"
    try:
        entries = list(fd_dir.iterdir())
    except OSError:
        return False
    target = f"socket:[{inode}]"
    for entry in entries:
        try:
            if entry.is_symlink() and str(Path(entry).readlink()) == target:
                return True
        except OSError:
            continue
    return False


class BackpressureProbe:
    """Observe a sustained, owned server-sender stall while the reader pauses."""

    def __init__(self, *, service_pid, server_port, client_socket, requested_rcvbuf,
                 effective_rcvbuf, min_duration_s=0.5, max_gap_s=0.1,
                 proc_root=Path("/proc"), net_path=Path("/proc/net/tcp")):
        self.service_pid = service_pid
        self.server_port = int(server_port)
        self.client_port = int(client_socket.getsockname()[1])
        self.requested_rcvbuf = requested_rcvbuf
        self.effective_rcvbuf = int(effective_rcvbuf)
        self.proc_root = Path(proc_root)
        self.net_path = Path(net_path)
        self.window = SustainedStallWindow(
            min_duration_ns=int(min_duration_s * 1_000_000_000),
            max_gap_ns=int(max_gap_s * 1_000_000_000),
        )
        self.persistent = False
        self.last_sample = None

    def sample(self):
        try:
            text = self.net_path.read_text(encoding="utf-8")
        except OSError:
            return {"net_table_available": False, "persistent": False}
        entries = parse_proc_net_tcp(text)
        server = next((entry for entry in entries
                       if entry.local_port == self.server_port
                       and entry.remote_port == self.client_port), None)
        client = next((entry for entry in entries
                       if entry.local_port == self.client_port
                       and entry.remote_port == self.server_port), None)
        inode = server.inode if server is not None else 0
        return {
            "net_table_available": server is not None,
            "server_tx_queue": server.tx_queue if server is not None else None,
            "client_rx_queue": client.rx_queue if client is not None else None,
            "server_socket_inode": inode or None,
            "server_fd_owned": server_fd_owns_inode(
                self.service_pid, inode, proc_root=self.proc_root
            ) if inode else False,
            "effective_so_rcvbuf": self.effective_rcvbuf,
        }

    def _observe(self):
        observed_ns = time.monotonic_ns()
        sample = self.sample()
        sample["observed_ns"] = observed_ns
        self.last_sample = sample
        qualified = self.window.observe(sample, observed_ns)
        return qualified, observed_ns

    def wait_persistent(self, *, timeout_s=2.0):
        deadline = time.monotonic_ns() + int(timeout_s * 1_000_000_000)
        while True:
            qualified, now_ns = self._observe()
            if qualified:
                self.persistent = True
                return self
            if now_ns >= deadline:
                self.persistent = False
                return self
            time.sleep(0.02)

    def hold_until(self, target_ns):
        while True:
            now_ns = time.monotonic_ns()
            if now_ns >= target_ns:
                return self
            self._observe()
            time.sleep(min(0.02, max(0.0, (target_ns - time.monotonic_ns()) / 1_000_000_000)))
        return self

    def finalize(self):
        self._observe()
        self.persistent = bool(self.window.qualified)
        return self.persistent

    def pre_trigger_valid(self, lower_bound_ns):
        if not self.persistent or self.last_sample is None:
            return False
        observed_ns = self.last_sample["observed_ns"]
        gap_ns = abs(lower_bound_ns - observed_ns)
        return gap_ns <= self.window.max_gap_ns

    def report(self):
        report = self.window.report()
        report.update({
            "persistent": self.persistent,
            "requested_so_rcvbuf": self.requested_rcvbuf,
            "effective_so_rcvbuf": self.effective_rcvbuf,
            "fixture_four_tuple": {
                "server_port": self.server_port,
                "client_port": self.client_port,
            },
            "server_fd_owned": bool(
                self.last_sample and self.last_sample.get("server_fd_owned")
            ),
        })
        return report


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
    source_bounded_producer=True,
    source_producer_kind="bounded_pipe_or_channel",
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

        if require_backpressure:
            probe = BackpressureProbe(
                service_pid=service_pid,
                server_port=port,
                client_socket=connection.sock,
                requested_rcvbuf=connection.requested_so_rcvbuf,
                effective_rcvbuf=connection.effective_so_rcvbuf,
            )
        if start_barrier is not None:
            start_barrier.wait(timeout=15)

        if require_group:
            observer = ProcGroupObserver([service_pid]).arm(exclude_pgids=baseline_groups)
            observer.start(max_duration_s=30.0)
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
        large_unfinished = (expected_size - len(first)) >= 8 * 1024 * 1024
        source_bounded = bool(source_bounded_producer)
        source_ok = large_unfinished and source_bounded
        client_ok = stop.confirmed and stop.observed_ns <= deadline_ns
        trigger_ok = interval is None or interval.t_after_ns <= deadline_ns
        backpressure_ok = (not require_backpressure) or bool(
            probe and probe.persistent and probe.window.qualified
        )
        post_pause_ok = post_pause_ns <= bound_ns
        actual_resume_ok = bool(
            reader_resume_ns is not None and reader_resume_ns < deadline_ns
        )
        proof_components = {
            "client_stop_within_deadline": client_ok,
            "git_group_within_deadline": group_ok,
            "group_post_sanity": group_sanity_ok,
            "trigger_within_deadline": trigger_ok,
            "backpressure_qualified": backpressure_ok,
            "source_preconditions": source_ok if require_backpressure else True,
            "target_pause_within_bound": post_pause_ok,
            "actual_reader_resume_within_deadline": actual_resume_ok,
            "pre_trigger_window": pre_trigger_ok,
        }
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
            "source_preconditions": {
                "large_unfinished_payload": large_unfinished,
                "source_bounded_producer_channels": source_bounded,
                "source_producer_kind": source_producer_kind,
                "zero_window_witness_available": False,
            },
            "post_trigger_backpressure_sample_ns": post_sample_ns,
            "post_trigger_backpressure_sample_after_lower_ms": (
                _ms(post_sample_ns - lower_ns) if post_sample_ns is not None else None
            ),
            "client_stop": stop.report(),
            "client_stop_after_lower_ms": _ms(stop.observed_ns - lower_ns),
            "client_stop_within_deadline": client_ok,
            "git_group": observer.report(lower_ns) if observer is not None else {
                "required": False,
                "reason": "no native Git child for LFS",
            },
            "git_group_within_deadline": group_ok,
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
