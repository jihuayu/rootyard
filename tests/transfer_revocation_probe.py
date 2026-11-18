#!/usr/bin/env python3
"""Strict owned transport probe for Issue #37 backpressure evidence."""
from collections import deque
from dataclasses import dataclass, replace
import os
from pathlib import Path
import socket
import struct
import time

from transfer_revocation_backpressure import SustainedStallWindow
from transfer_revocation_git_source import GitSourceWitness
from transfer_revocation_source import (
    LfsSourceWitness,
    SOURCE_FAILURE_IDENTITY,
    SOURCE_FAILURE_NO_MATCH,
)


MAX_TIMELINE_ENTRIES = 16


@dataclass(frozen=True)
class Cert:
    start_ns: int
    completed_ns: int
    epoch: int
    window_start_ns: int
    server_inode: int
    client_inode: int
    source_anchor: tuple | None
    source_qualified: bool
    server_fd_owned: bool
    client_inode_owned: bool
    same_netns: bool


@dataclass(frozen=True)
class EpochEvent:
    """An observation bracket for an invalidation or identity change."""

    start_ns: int
    end_ns: int
    new_epoch: int
    new_source_anchor: tuple | None
    kind: str


@dataclass(frozen=True)
class TimelineBaseline:
    coverage_watermark_ns: int = 0
    epoch: int = 0
    source_anchor: tuple | None = None


class PreTriggerTimeline:
    """Retain bounded snapshots of observations and their observed epochs."""

    def __init__(self):
        self._entries = deque(maxlen=MAX_TIMELINE_ENTRIES)
        self._baseline = TimelineBaseline()
        self._epoch = 0
        self._source_anchor = None
        self._transport_identity = None

    @property
    def entries(self):
        return tuple(self._entries)

    @property
    def baseline(self):
        return self._baseline

    def covers(self, lower_ns):
        """Check eviction and invalidation overlap before considering any cert."""
        return lower_ns >= self._baseline.coverage_watermark_ns and not any(
            isinstance(entry, EpochEvent) and entry.start_ns <= lower_ns < entry.end_ns
            for entry in self._entries
        )

    def _append(self, entry):
        if len(self._entries) == MAX_TIMELINE_ENTRIES:
            evicted = self._entries[0]
            baseline = self._baseline
            if isinstance(evicted, EpochEvent):
                self._baseline = TimelineBaseline(
                    max(baseline.coverage_watermark_ns, evicted.end_ns),
                    evicted.new_epoch,
                    evicted.new_source_anchor,
                )
            else:
                self._baseline = replace(baseline, coverage_watermark_ns=max(
                    baseline.coverage_watermark_ns, evicted.completed_ns,
                ))
        self._entries.append(entry)

    def record(self, sample, window, source_anchor: tuple | None):
        start_ns = sample["sample_start_ns"]
        end_ns = sample["observed_ns"]
        server_inode = sample["server_socket_inode"]
        client_inode = sample["client_socket_inode"]
        same_netns = bool(sample["same_netns"])
        source_qualified = bool(sample["source_qualified"])
        source_failure = (sample.get("source_report") or {}).get("failure_code")
        transport_identity = (server_inode, client_inode, same_netns)

        kind = None
        if source_failure == SOURCE_FAILURE_IDENTITY or (
            source_qualified and self._source_anchor is not None
            and source_anchor != self._source_anchor
        ):
            kind = "source_identity"
        elif not source_qualified:
            kind = "source_unqualified"
        elif not same_netns or (
            self._transport_identity is not None
            and transport_identity != self._transport_identity
        ):
            kind = "inode/netns"
        elif not window.samples:
            kind = "reset"

        if kind is not None:
            self._epoch += 1
            self._append(EpochEvent(start_ns, end_ns, self._epoch, source_anchor, kind))
        self._source_anchor = source_anchor
        self._transport_identity = transport_identity
        if window.qualified:
            self._append(Cert(
                start_ns, end_ns, self._epoch, window.started_ns, server_inode, client_inode,
                source_anchor, source_qualified, bool(sample["server_fd_owned"]),
                bool(sample["client_inode_owned"]), same_netns,
            ))


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
    """Parse only fixed numeric transport fields from a proc net table."""
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


def find_tcp_pair(entries, *, client_host, client_port, server_host, server_port):
    """Return exactly one ESTABLISHED pair in both directions, else None."""
    server_rows = [
        entry for entry in entries
        if entry.local_host == server_host and entry.local_port == server_port
        and entry.remote_host == client_host and entry.remote_port == client_port
        and entry.state == "01"
    ]
    client_rows = [
        entry for entry in entries
        if entry.local_host == client_host and entry.local_port == client_port
        and entry.remote_host == server_host and entry.remote_port == server_port
        and entry.state == "01"
    ]
    if len(server_rows) != 1 or len(client_rows) != 1:
        return None
    return server_rows[0], client_rows[0]


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
    """Sample one strict transport pair plus its owned source witness."""

    def __init__(self, *, service_pid, client_socket, source_witness,
                 requested_rcvbuf, effective_rcvbuf, min_duration_s=0.5,
                 max_gap_s=0.1, same_netns=None, proc_root=Path("/proc"),
                 net_path=None):
        self.service_pid = int(service_pid)
        self.client_socket = client_socket
        self.source_witness = source_witness
        self.requested_rcvbuf = requested_rcvbuf
        self.effective_rcvbuf = int(effective_rcvbuf)
        self.proc_root = Path(proc_root)
        self.net_path = Path(net_path) if net_path is not None else (
            self.proc_root / str(service_pid) / "net" / "tcp"
        )
        self.client_host, self.client_port = client_socket.getsockname()[:2]
        self.server_host, self.server_port = client_socket.getpeername()[:2]
        self.client_inode = os.fstat(client_socket.fileno()).st_ino
        self.same_netns_override = same_netns
        self.window = SustainedStallWindow(
            min_duration_ns=int(min_duration_s * 1_000_000_000),
            max_gap_ns=int(max_gap_s * 1_000_000_000),
        )
        self.persistent = False
        self.last_sample = None
        self.timeline = PreTriggerTimeline()

    def _same_netns(self):
        if self.same_netns_override is not None:
            return bool(self.same_netns_override)
        try:
            service_ns = os.stat(self.proc_root / str(self.service_pid) / "ns" / "net")
            client_ns = os.stat("/proc/self/ns/net")
        except OSError:
            return False
        return service_ns.st_ino == client_ns.st_ino

    def sample(self):
        try:
            text = self.net_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        entries = parse_proc_net_tcp(text)
        pair = find_tcp_pair(
            entries,
            client_host=self.client_host, client_port=self.client_port,
            server_host=self.server_host, server_port=self.server_port,
        )
        if pair is None:
            server = client = None
            server_fd_owned = client_inode_owned = False
            probe0_pending = False
            server_tx = client_rx = None
            inode = None
        else:
            server, client = pair
            server_fd_owned = server_fd_owns_inode(
                self.service_pid, server.inode, proc_root=self.proc_root
            )
            client_inode_owned = client.inode == self.client_inode
            probe0_pending = server.timer_active == 4
            server_tx = server.tx_queue
            client_rx = client.rx_queue
            inode = server.inode
        if self.source_witness is None:
            source_report = {
                "witness_version": 1,
                "witness_kind_code": 0,
                "witness_available": False,
                "qualified": False,
                "failure_code": SOURCE_FAILURE_NO_MATCH,
            }
        else:
            try:
                source_report = self.source_witness.sample()
            except Exception:
                source_report = {
                    "witness_version": 1,
                    "witness_kind_code": 0,
                    "witness_available": False,
                    "qualified": False,
                    "failure_code": SOURCE_FAILURE_NO_MATCH,
                }
        return {
            "net_table_available": pair is not None,
            "same_netns": self._same_netns(),
            "server_tx_queue": server_tx,
            "client_rx_queue": client_rx,
            "server_socket_inode": inode,
            "client_socket_inode": self.client_inode,
            "client_inode_owned": client_inode_owned,
            "server_fd_owned": server_fd_owned,
            "probe0_pending": probe0_pending,
            "timer_active": server.timer_active if server is not None else None,
            "source_qualified": bool(source_report.get("qualified")),
            "source_report": source_report,
        }

    def _source_anchor(self, sample):
        """Copy the identity already observed by the source witness."""
        if not sample["source_qualified"]:
            return None
        witness = self.source_witness
        if isinstance(witness, LfsSourceWitness) and witness.identity is not None:
            return (witness.witness_kind_code, witness.identity.pid, witness.identity.starttime,
                    witness.fd, witness.st_dev, witness.st_ino, witness.mnt_id)
        if isinstance(witness, GitSourceWitness):
            service, writer = witness.service_identity, witness.writer
            if service is not None and writer is not None:
                return (witness.witness_kind_code, service.pid, service.starttime,
                        writer.tgid, writer.tid, writer.starttime, writer.pipe_inode,
                        writer.service_fd)
        return None

    def _observe(self):
        sample_start_ns = time.monotonic_ns()
        sample = self.sample()
        observed_ns = time.monotonic_ns()
        sample["sample_start_ns"] = sample_start_ns
        sample["sample_duration_ns"] = max(0, observed_ns - sample_start_ns)
        sample["observed_ns"] = observed_ns
        self.last_sample = sample
        qualified = self.window.observe(sample, observed_ns)
        self.timeline.record(sample, self.window, self._source_anchor(sample))
        return qualified, observed_ns

    def wait_persistent(self, *, timeout_s=5.0):
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

    def select_pre_trigger_cert(self, lower_bound_ns):
        from transfer_revocation_timing import select_pre_trigger_cert

        return select_pre_trigger_cert(self.timeline, lower_bound_ns)

    def pre_trigger_valid(self, lower_bound_ns):
        if not self.persistent or self.last_sample is None:
            return False
        observed_ns = self.last_sample["observed_ns"]
        if observed_ns > lower_bound_ns:
            return False
        return lower_bound_ns - observed_ns <= self.window.max_gap_ns

    def report(self):
        report = self.window.report()
        sample = self.last_sample or {}
        report.update({
            "persistent": self.persistent,
            "requested_so_rcvbuf": self.requested_rcvbuf,
            "effective_so_rcvbuf": self.effective_rcvbuf,
            "fixture_four_tuple": {
                "server_port": self.server_port,
                "client_port": self.client_port,
            },
            "same_netns": bool(sample.get("same_netns")),
            "server_fd_owned": bool(sample.get("server_fd_owned")),
            "client_inode_owned": bool(sample.get("client_inode_owned")),
            "probe0_pending": bool(sample.get("probe0_pending")),
            "source_witness": sample.get("source_report") or {},
        })
        return report
