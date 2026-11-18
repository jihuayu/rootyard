#!/usr/bin/env python3
"""Private finite projection vocabulary for Issue #37 partial evidence."""
import errno
import math

PROOF_COMPONENTS = (
    "client_stop_within_deadline", "group_post_sanity",
    "trigger_within_deadline", "backpressure_qualified", "source_witness",
    "target_pause_within_bound", "actual_reader_resume_within_deadline",
    "pre_trigger_window", "git_group_within_deadline",
)
SOURCE_BOOLS = (
    "witness_available", "witness_bound", "qualified",
    "source_identity_unique", "source_position_unchanged", "source_unfinished",
    "source_pipe_full",
)
SOURCE_INTS = (
    "witness_version", "witness_kind_code", "failure_code",
    "fatal_failure_code", "source_position", "source_size", "source_remaining",
    "source_proof_kind_code",
)
BACKPRESSURE_BOOLS = (
    "qualified", "server_tx_positive_every_sample",
    "client_rx_positive_every_sample", "probe0_every_sample",
    "source_qualified_every_sample", "receiver_queue_unchanged",
)
BACKPRESSURE_NUMS = (
    "min_duration_ms", "max_gap_ms", "max_sample_duration_ms",
    "qualified_span_ms", "observed_window_ms", "max_observed_gap_ms",
    "max_observed_sample_duration_ms",
)
BACKPRESSURE_INTS = (
    "sample_count", "first_valid_stall_ns", "first_sample_end_ns",
    "last_sample_start_ns", "last_sample_ns", "server_tx_queue_min",
    "server_tx_queue_max", "client_rx_queue_min", "client_rx_queue_max",
    "reset_count",
)
METRIC_BOUNDS = {
    "pre_trigger_pause_ms": (-1_000_000_000, 1_000_000_000),
    "post_trigger_pause_ms": (-1_000_000_000, 1_000_000_000),
    "reader_resume_after_lower_ms": (-1_000_000_000, 1_000_000_000),
    "reader_resume_delta_from_target_ms": (-1_000_000_000, 1_000_000_000),
    "client_stop_after_lower_ms": (-1_000_000_000, 1_000_000_000),
    "post_trigger_backpressure_sample_after_lower_ms": (-1_000_000_000, 1_000_000_000),
    "initial_bytes_received": (0, 1 << 63),
    "post_trigger_pause_target_ms": (0, 1_000_000_000),
    "configured_bound_ms": (0, 600_000),
}
TIMESTAMP_FIELDS = (
    "first_byte_ns", "trigger_before_ns", "trigger_after_ns",
    "reader_resume_ns", "stop_ns", "post_trigger_backpressure_sample_ns",
)
SAFE_ERRNOS = frozenset({
    code for code in (
        errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE, errno.ETIMEDOUT,
        errno.ECONNREFUSED, errno.EIO, errno.ENOENT, errno.EACCES, errno.EMFILE,
        errno.ENFILE,
    ) if isinstance(code, int)
})


def bool_value(value, name):
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")
    return value


def bool_or_none(value, name):
    return None if value is None else bool_value(value, name)


def int_value(value, name, *, low=0, high=(1 << 63)):
    if type(value) is not int or value < low or value > high:
        raise ValueError(f"{name} must be a bounded integer")
    return value


def int_or_none(value, name, *, low=0, high=(1 << 63)):
    return None if value is None else int_value(value, name, low=low, high=high)


def num_value(value, name, *, low=-1_000_000_000, high=1_000_000_000):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number")
    if value < low or value > high:
        raise ValueError(f"{name} outside bounded range")
    return value


def num_or_none(value, name, *, low=-1_000_000_000, high=1_000_000_000):
    return None if value is None else num_value(value, name, low=low, high=high)


def project(source, *, bools=(), ints=(), nums=(), base=None):
    if source is not None and not isinstance(source, dict):
        raise ValueError("evidence payload must be a mapping")
    out = dict(base or {})
    for name in bools:
        if source is not None and name in source:
            out[name] = bool_or_none(source[name], name)
    for name in ints:
        if source is not None and name in source:
            out[name] = int_or_none(source[name], name)
    for name in nums:
        if source is not None and name in source:
            out[name] = num_or_none(source[name], name)
    return out


def safe_errno(error):
    if not isinstance(error, OSError):
        return None
    value = getattr(error, "errno", None)
    return value if value in SAFE_ERRNOS else None
