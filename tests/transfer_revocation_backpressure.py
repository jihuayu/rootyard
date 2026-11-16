#!/usr/bin/env python3
"""Sustained sender-stall window for Issue #37 backpressure evidence."""
from dataclasses import dataclass, field


@dataclass
class SustainedStallWindow:
    """Accept only a continuous, owned sender-stall interval.

    A qualifying sample has an observable fixture inode owned by the service,
    positive server TX queue, positive client RX queue, and a receiver queue
    that never decreases while the body reader is paused. The window starts at
    the first qualifying sample and resets on any missing, unobservable, or
    nonqualifying sample, or on an invalid sampling gap.
    """

    min_duration_ns: int
    max_gap_ns: int = 100_000_000
    started_ns: int = 0
    last_sample_ns: int = 0
    last_rx_queue: int = 0
    inode: int = 0
    samples: list = field(default_factory=list)
    qualified: bool = False
    reset_count: int = 0
    last_reset_reason: str = "not_started"

    def reset(self, reason):
        if self.started_ns or self.samples:
            self.reset_count += 1
        self.started_ns = 0
        self.last_sample_ns = 0
        self.last_rx_queue = 0
        self.inode = 0
        self.samples = []
        self.qualified = False
        self.last_reset_reason = reason

    def _reason_if_invalid(self, sample, now_ns):
        if not sample.get("net_table_available"):
            return "net_table_missing"
        if not sample.get("server_fd_owned"):
            return "service_inode_not_owned"
        inode = sample.get("server_socket_inode")
        tx_queue = sample.get("server_tx_queue")
        rx_queue = sample.get("client_rx_queue")
        if not isinstance(inode, int) or inode <= 0:
            return "service_inode_missing"
        if not isinstance(tx_queue, int) or tx_queue <= 0:
            return "server_tx_not_positive"
        if not isinstance(rx_queue, int) or rx_queue <= 0:
            return "client_rx_not_positive"
        if self.samples:
            if now_ns < self.last_sample_ns:
                return "nonmonotonic_sample"
            if now_ns - self.last_sample_ns > self.max_gap_ns:
                return "sample_gap"
            if inode != self.inode:
                return "inode_changed"
            if rx_queue < self.last_rx_queue:
                return "receiver_drained"
        return None

    def observe(self, sample, now_ns):
        reason = self._reason_if_invalid(sample, now_ns)
        if reason is not None:
            self.reset(reason)
            return False
        if not self.samples:
            self.started_ns = now_ns
            self.inode = sample["server_socket_inode"]
        self.last_sample_ns = now_ns
        self.last_rx_queue = sample["client_rx_queue"]
        self.samples.append(sample)
        if now_ns - self.started_ns >= self.min_duration_ns:
            self.qualified = True
        return self.qualified

    @property
    def last_sample_after_start_ns(self):
        return self.last_sample_ns if self.samples else 0

    def report(self):
        has_window = bool(self.samples)
        tx_values = [item["server_tx_queue"] for item in self.samples]
        rx_values = [item["client_rx_queue"] for item in self.samples]
        gaps = [
            self.samples[index]["observed_ns"] - self.samples[index - 1]["observed_ns"]
            for index in range(1, len(self.samples))
        ]
        return {
            "qualified": self.qualified,
            "min_duration_ms": round(self.min_duration_ns / 1_000_000, 3),
            "max_gap_ms": round(self.max_gap_ns / 1_000_000, 3),
            "sample_count": len(self.samples),
            "first_valid_stall_ns": self.started_ns if has_window else None,
            "last_sample_ns": self.last_sample_ns or None,
            "observed_window_ms": (
                round((self.last_sample_ns - self.started_ns) / 1_000_000, 3)
                if has_window else 0.0
            ),
            "max_observed_gap_ms": (
                round(max(gaps) / 1_000_000, 3) if gaps else 0.0
            ),
            "server_tx_positive_every_sample": bool(tx_values) and all(
                value > 0 for value in tx_values
            ),
            "client_rx_positive_every_sample": bool(rx_values) and all(
                value > 0 for value in rx_values
            ),
            "receiver_nondraining": bool(rx_values) and all(
                rx_values[index] >= rx_values[index - 1]
                for index in range(1, len(rx_values))
            ),
            "server_tx_queue_min": min(tx_values) if tx_values else None,
            "server_tx_queue_max": max(tx_values) if tx_values else None,
            "client_rx_queue_min": min(rx_values) if rx_values else None,
            "client_rx_queue_max": max(rx_values) if rx_values else None,
            "server_socket_inode": self.inode or None,
            "reset_count": self.reset_count,
            "last_reset_reason": self.last_reset_reason,
        }
