"""Bounded verified multi-repository metrics for failure artifacts (Refs #178).

Only groups returned after the fresh-clone/strict-fsck revalidation reach this
projection.  Repository ids, clone paths, OIDs, fixtures, environment, raw Git
output, payloads and rich S3 buckets are never copied into the fixed records.
"""

from __future__ import annotations

from collections.abc import Mapping
import math
from typing import Any

from .pack_matrix import CANDIDATE_CONFIGS
from .telemetry import percentile_stats

MULTI_REPO_COMPLETED_FIELD = "multi_repo_completed"
MULTI_REPO_COMPLETED_LIMIT = 4
MULTI_REPO_CONFIG_NAMES = frozenset(spec.name for spec in CANDIDATE_CONFIGS)
_S3_FIELDS = ("get_requests", "get_bytes", "put_requests", "put_bytes")


def _finite(value: Any, *, positive: bool = False) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    if not math.isfinite(number) or (number <= 0 if positive else number < 0):
        return None
    return round(number, 3)


def _raw_values(item: Mapping[str, Any]) -> tuple[list[Any], list[Any], list[Any]] | None:
    samples = item.get("push_samples")
    if samples is not None:
        if not isinstance(samples, (list, tuple)) or len(samples) != 3:
            return None
        if not all(isinstance(sample, Mapping) for sample in samples):
            return None
        if "all_verified" in item and item.get("all_verified") is not True:
            return None
        if item.get("verified_samples", 3) != 3:
            return None
        if any(sample.get("push_verified") is False for sample in samples):
            return None
        if any(sample.get("first_attempt") is False for sample in samples):
            return None
        return (
            [sample.get("push_ms") for sample in samples],
            [sample.get("client_invocation_start_ms") for sample in samples],
            [sample.get("client_invocation_end_ms") for sample in samples],
        )
    push_ms, starts, ends = (
        item.get("push_ms"), item.get("client_invocation_start_ms"), item.get("client_invocation_end_ms"),
    )
    if not all(isinstance(values, (list, tuple)) and len(values) == 3 for values in (push_ms, starts, ends)):
        return None
    return list(push_ms), list(starts), list(ends)


def _project(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, Mapping):
        return None
    config_name = item.get("config_name")
    if not isinstance(config_name, str) or config_name not in MULTI_REPO_CONFIG_NAMES:
        return None
    values = _raw_values(item)
    if values is None:
        return None
    pushes = [_finite(value) for value in values[0]]
    starts = [_finite(value) for value in values[1]]
    ends = [_finite(value, positive=True) for value in values[2]]
    if any(value is None for value in (*pushes, *starts, *ends)):
        return None
    if not all(start < end for start, end in zip(starts, ends, strict=True)):
        return None
    overlap_ms = round(max(0.0, min(ends) - max(starts)), 3)
    if overlap_ms <= 0:
        return None
    s3 = item.get("s3_push")
    if not isinstance(s3, Mapping) or s3.get("observed") is not True:
        return None
    counters: dict[str, int] = {}
    for field in _S3_FIELDS:
        value = s3.get(field)
        if type(value) is not int or value < 0:
            return None
        counters[field] = value
    return {
        "config_name": config_name,
        "push_ms": pushes,
        "client_invocation_start_ms": starts,
        "client_invocation_end_ms": ends,
        "push_stats": percentile_stats(pushes),
        "client_invocation_overlap": {
            "scope": "client_invocations_only",
            "all_overlap": True,
            "overlap_ms": overlap_ms,
            "server_internal_overlap_claimed": False,
        },
        "s3_push": {"observed": True, **counters},
    }


def sanitize_multi_repo_completed(value: Any) -> list[dict[str, Any]]:
    """Project at most one safe record per known candidate configuration."""
    if not isinstance(value, (list, tuple)):
        return []
    seen: set[str] = set()
    projected: list[dict[str, Any]] = []
    for item in value:
        record = _project(item)
        if record is None or record["config_name"] in seen:
            continue
        seen.add(record["config_name"])
        projected.append(record)
        if len(projected) == MULTI_REPO_COMPLETED_LIMIT:
            break
    return projected


sanitize_multi_repo_groups = sanitize_multi_repo_completed


def sanitize_multi_repo_group(value: Any) -> dict[str, Any] | None:
    """Project one completed group, or ``None`` when it is malformed."""
    records = sanitize_multi_repo_completed([value])
    return records[0] if records else None


__all__ = [
    "MULTI_REPO_COMPLETED_FIELD",
    "MULTI_REPO_COMPLETED_LIMIT",
    "MULTI_REPO_CONFIG_NAMES",
    "sanitize_multi_repo_completed",
    "sanitize_multi_repo_group",
    "sanitize_multi_repo_groups",
]
