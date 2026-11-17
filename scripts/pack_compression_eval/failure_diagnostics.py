"""Finite, source-owned failure diagnostics for the live pack evaluation (Refs #178).

The helpers in this module deliberately retain only fixed classification IDs,
bounded numeric counters and already-validated digest/commit bindings.  Raw
process stderr, argv, URLs, headers, bodies, environment values, SQL/DSNs,
provider text and filesystem paths are never accepted into a failure record.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
import os
from pathlib import Path
import re
from typing import Any

from .capacity import sanitize_capacity
from .cleanup_diagnostics import sanitize_cleanup
from .concurrent_outcomes import (
    FAILURE_CLASSES,
    HTTP_SUBPHASES,
    PHASES,
    finite_http_subphase,
    sanitize_concurrent_outcomes,
)
from .corpus import DATASET_ARCHETYPES, OBJECT_FORMATS
from .pack_matrix import CANDIDATE_CONFIGS

FAILURE_SCHEMA = "rootyard/pando-pack-compression-eval-failure/v1"
FAILURE_STATUS = "failed"
OBJECT_FORMAT_SET = frozenset(OBJECT_FORMATS)
ARCHETYPE_SET = frozenset(DATASET_ARCHETYPES)
CONFIG_SET = frozenset(("baseline",) + tuple(spec.name for spec in CANDIDATE_CONFIGS))
PROGRESS_PHASES = PHASES + ("none", "baseline_reads", "candidate_reads")
RECEIPT_SCHEMAS = frozenset(("rootyard/native-build-receipt/v2", "v1", "v2"))
MODES = ("full", "git-only")
SCALES = ("quick", "full")
COMPLETED_KEYS = (
    "baseline_repos_completed",
    "baseline_seed_pushes_completed",
    "baseline_wave_pushes_completed",
    "cold_clone_samples_completed",
    "warm_clone_samples_completed",
    "browse_requests_completed",
    "candidate_configs_completed",
    "candidate_pushes_completed",
    "candidate_reads_completed",
    "concurrent_pushes_completed",
    "acked_refs_verified",
)
KNOWN_S3_METHODS = ("GET", "PUT", "HEAD", "DELETE", "POST")
KNOWN_S3_STATUSES = frozenset(
    (200, 204, 206, 301, 302, 304, 307, 308, 400, 401, 403, 404, 405, 409, 412, 416, 500, 501, 502, 503, 504)
)
BINDING_FIELDS = (
    "receipt_verified",
    "binary_sha256",
    "binary_size_bytes",
    "receipt_sha256",
    "workspace_commit",
    "source_inputs_sha256",
    "config_digest",
    "receipt_schema",
    "source_commit_at_failure",
    "source_dirty_at_failure",
)
_RECORD_FIELDS = (
    "mode",
    "scale",
    "seed",
    "phase",
    "failure_class",
    "archetype",
    "object_format",
    "config",
    "repo_ordinal",
    "wave_ordinal",
    "target_ordinal",
    "branch_ordinal",
    "git_returncode",
    "signal",
    "http_status",
    "http_subphase",
    "elapsed_ms",
    "last_completed_phase",
    "completed",
    "s3",
    "bindings", "fixture_capacity",
    "concurrent_worker_outcomes",
    "cleanup",
)
_HTTP_PATTERNS = (
    re.compile(rb"\bHTTP\s+(\d{3})\b"),
    re.compile(rb"returned error:\s*(\d{3})\b"),
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40,64}$")


def _choice(value: Any, allowed: tuple[str, ...] | frozenset[str], default: str = "unknown") -> str:
    return value if isinstance(value, str) and value in allowed else default


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _optional_count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 2**63 - 1 else None


def _count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value if 0 <= value <= 2**63 - 1 else 0


def _ordinal(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 1_000_000 else None


def _signal(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1 <= value <= 127 else None


def _http_status(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 100 <= value <= 599 else None


def _elapsed(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return round(number, 3) if math.isfinite(number) and number >= 0 else None


def _sha(value: Any) -> str | None:
    return value if isinstance(value, str) and _SHA256.fullmatch(value) else None


def _commit(value: Any) -> str | None:
    return value if isinstance(value, str) and _COMMIT.fullmatch(value) else None


def _bool_or_none(value: Any) -> bool | None:
    return value if type(value) is bool else None


def completed_counts(value: Any = None) -> dict[str, int]:
    """Return every source-known completion counter with invalid values zeroed."""
    source = value if isinstance(value, Mapping) else {}
    return {key: _count(source.get(key)) for key in COMPLETED_KEYS}


def finite_http_status(stderr: bytes | bytearray | None) -> int | None:
    """Parse only an unambiguous finite HTTP status from in-memory stderr.

    The raw bytes are not retained.  Two different statuses, an out-of-range
    number, or no match all classify as unknown (``None``).
    """
    if not isinstance(stderr, (bytes, bytearray)):
        return None
    found = set()
    for pattern in _HTTP_PATTERNS:
        for match in pattern.finditer(bytes(stderr)):
            value = int(match.group(1))
            if 100 <= value <= 599:
                found.add(value)
    return found.pop() if len(found) == 1 else None


def child_outcome(returncode: Any) -> tuple[int | None, int | None]:
    """Return the numeric returncode and a direct negative-returncode signal."""
    code = _optional_int(returncode)
    if code is None:
        return None, None
    signal = _signal(-code) if code < 0 else None
    return code, signal


def sanitize_s3_snapshot(snapshot: Any) -> dict[str, Any]:
    """Keep finite S3 aggregate counts and known status buckets only."""
    source = snapshot if isinstance(snapshot, Mapping) else {}
    result: dict[str, Any] = {
        "observed": source.get("observed") is True,
        "get_requests": _count(source.get("get_requests")),
        "get_bytes": _count(source.get("get_bytes")),
        "put_requests": _count(source.get("put_requests")),
        "put_bytes": _count(source.get("put_bytes")),
        "head_requests": _count(source.get("head_requests")),
        "delete_requests": _count(source.get("delete_requests")),
        "error_responses": _count(source.get("error_responses")),
        "other_requests": 0,
        "status_counts": {},
    }
    methods = source.get("req_counts_by_method")
    if isinstance(methods, Mapping):
        result["other_requests"] = sum(
            _count(count) for method, count in methods.items() if method not in KNOWN_S3_METHODS
        )
    statuses: dict[str, int] = {}
    raw_statuses = source.get("status_counts")
    if isinstance(raw_statuses, Mapping):
        for raw_code, raw_count in raw_statuses.items():
            count = _count(raw_count)
            if count == 0:
                continue
            try:
                code = int(str(raw_code), 10)
            except (TypeError, ValueError):
                code = -1
            bucket = str(code) if code in KNOWN_S3_STATUSES else "unknown"
            statuses[bucket] = statuses.get(bucket, 0) + count
    result["status_counts"] = {key: statuses[key] for key in sorted(statuses)}
    return result


def sanitize_bindings(bindings: Any) -> dict[str, Any]:
    """Keep only validated digest/commit identifiers; never a filesystem path."""
    source = bindings if isinstance(bindings, Mapping) else {}
    schema = source.get("receipt_schema")
    return {
        "receipt_verified": source.get("receipt_verified") is True,
        "binary_sha256": _sha(source.get("binary_sha256")),
        "binary_size_bytes": _optional_count(source.get("binary_size_bytes")),
        "receipt_sha256": _sha(source.get("receipt_sha256")),
        "workspace_commit": _commit(source.get("workspace_commit")),
        "source_inputs_sha256": _sha(source.get("source_inputs_sha256")),
        "config_digest": _sha(source.get("config_digest")),
        "receipt_schema": schema if isinstance(schema, str) and schema in RECEIPT_SCHEMAS else "unknown",
        "source_commit_at_failure": _commit(source.get("source_commit_at_failure")),
        "source_dirty_at_failure": _bool_or_none(source.get("source_dirty_at_failure")),
    }


def bindings_from_receipt(receipt_info: Any, source_meta: Any = None) -> dict[str, Any]:
    """Project verified receipt metadata without its executable path."""
    info = receipt_info if isinstance(receipt_info, Mapping) else {}
    meta = source_meta if isinstance(source_meta, Mapping) else {}
    return sanitize_bindings(
        {
            "receipt_verified": info.get("receipt_verified"),
            "binary_sha256": info.get("sha256"),
            "binary_size_bytes": info.get("size_bytes"),
            "receipt_sha256": info.get("receipt_sha256"),
            "workspace_commit": info.get("workspace_commit"),
            "source_inputs_sha256": info.get("source_inputs_sha256"),
            "config_digest": info.get("config_digest"),
            "receipt_schema": info.get("receipt_schema"),
            "source_commit_at_failure": meta.get("source_commit"),
            "source_dirty_at_failure": meta.get("source_dirty"),
        }
    )


def build_failure_record(
    *,
    mode: Any = "unknown",
    scale: Any = "unknown",
    seed: Any = None,
    phase: Any = "unknown",
    failure_class: Any = "unclassified",
    archetype: Any = "unknown",
    object_format: Any = "unknown",
    config: Any = "unknown",
    repo_ordinal: Any = None,
    wave_ordinal: Any = None,
    target_ordinal: Any = None,
    branch_ordinal: Any = None,
    git_returncode: Any = None,
    signal: Any = None,
    http_status: Any = None,
    http_subphase: Any = "unknown",
    elapsed_ms: Any = None,
    last_completed_phase: Any = "unknown",
    completed: Any = None,
    s3: Any = None,
    bindings: Any = None, fixture_capacity: Any = None,
    concurrent_worker_outcomes: Any = None,
    cleanup: Any = None,
) -> dict[str, Any]:
    """Build one fixed-schema failure record from source-known fields only."""
    return {
        "schema_version": FAILURE_SCHEMA,
        "issue": "#178",
        "passed": False,
        "status": FAILURE_STATUS,
        "mode": _choice(mode, MODES),
        "scale": _choice(scale, SCALES),
        "seed": _optional_int(seed),
        "phase": _choice(phase, PHASES),
        "failure_class": _choice(failure_class, FAILURE_CLASSES, "unclassified"),
        "archetype": _choice(archetype, ARCHETYPE_SET),
        "object_format": _choice(object_format, OBJECT_FORMAT_SET),
        "config": _choice(config, CONFIG_SET),
        "repo_ordinal": _ordinal(repo_ordinal),
        "wave_ordinal": _ordinal(wave_ordinal),
        "target_ordinal": _ordinal(target_ordinal),
        "branch_ordinal": _ordinal(branch_ordinal),
        "git_returncode": _optional_int(git_returncode),
        "signal": _signal(signal),
        "http_status": _http_status(http_status),
        "http_subphase": _choice(http_subphase, HTTP_SUBPHASES),
        "elapsed_ms": _elapsed(elapsed_ms),
        "last_completed_phase": _choice(last_completed_phase, PROGRESS_PHASES),
        "completed": completed_counts(completed),
        "s3": sanitize_s3_snapshot(s3),
        "bindings": sanitize_bindings(bindings), "fixture_capacity": sanitize_capacity(fixture_capacity),
        "concurrent_worker_outcomes": sanitize_concurrent_outcomes(concurrent_worker_outcomes),
        "cleanup": sanitize_cleanup(cleanup),
    }


def enrich_failure_record(record: Any, **overrides: Any) -> dict[str, Any]:
    """Re-normalize a record with explicit overrides such as final S3 counters."""
    source = dict(record) if isinstance(record, Mapping) else {}
    source.update(overrides)
    return build_failure_record(**{key: source.get(key) for key in _RECORD_FIELDS})


def push_context(progress: Any, phase: Any, **values: Any) -> dict[str, Any]:
    """Build caller-owned finite push context from the live progress map."""
    source = progress if isinstance(progress, Mapping) else {}
    completed = source.get("completed") if isinstance(source.get("completed"), Mapping) else {}
    return {"phase": phase, **values, "completed": dict(completed), "last_completed_phase": source.get("last_completed_phase")}


def failure_record_from_exception(
    exc: BaseException,
    *,
    mode: Any,
    scale: Any,
    seed: Any,
    source_meta: Any = None,
) -> dict[str, Any]:
    """Normalize a structured or generic exception into one safe failure record."""
    record = getattr(exc, "record", None)
    if not isinstance(record, Mapping):
        record = {}
    merged_bindings = dict(record.get("bindings") or {}) if isinstance(record.get("bindings"), Mapping) else {}
    if isinstance(source_meta, Mapping):
        merged_bindings["source_commit_at_failure"] = source_meta.get("source_commit")
        merged_bindings["source_dirty_at_failure"] = source_meta.get("source_dirty")
    return enrich_failure_record(
        record,
        mode=mode,
        scale=scale,
        seed=seed,
        bindings=merged_bindings,
    )


def git_failure_record(
    context: Any,
    *,
    failure_class: str = "git_push",
    returncode: Any = None,
    elapsed_ms: Any = None,
    stderr: bytes | bytearray | None = None,
) -> dict[str, Any]:
    """Build a push-boundary record; raw stderr is parsed and never retained."""
    values = context if isinstance(context, Mapping) else {}
    code, signal = child_outcome(returncode)
    status = finite_http_status(stderr)
    return build_failure_record(
        phase=values.get("phase"),
        failure_class=failure_class,
        archetype=values.get("archetype"),
        object_format=values.get("object_format"),
        config=values.get("config"),
        repo_ordinal=values.get("repo_ordinal"),
        wave_ordinal=values.get("wave_ordinal"),
        target_ordinal=values.get("target_ordinal"),
        branch_ordinal=values.get("branch_ordinal"),
        git_returncode=code,
        signal=signal,
        http_status=status,
        http_subphase=finite_http_subphase(stderr, status),
        elapsed_ms=elapsed_ms,
        completed=values.get("completed"),
        last_completed_phase=values.get("last_completed_phase"),
    )


def safe_summary(record: Mapping[str, Any]) -> str:
    """Return only fixed phase/class IDs for the process final boundary."""
    phase = _choice(record.get("phase"), PHASES)
    failure_class = _choice(record.get("failure_class"), FAILURE_CLASSES, "unclassified")
    return f"phase={phase} failure_class={failure_class}"


class FailureArtifactError(RuntimeError):
    """A failure whose finite record has already been written."""

    def __init__(self, record: Mapping[str, Any]) -> None:
        self.record = enrich_failure_record(record)
        self.summary = safe_summary(self.record)
        super().__init__(self.summary)


class LiveEvalFailure(FailureArtifactError):
    """A live-evaluation failure carrying only finite diagnostic fields."""


def attach_cleanup(exc: FailureArtifactError, cleanup: Any) -> None:
    """Attach finite cleanup outcomes without changing the primary failure."""
    if isinstance(exc, FailureArtifactError):
        exc.record = enrich_failure_record(exc.record, cleanup=cleanup)
        exc.summary = safe_summary(exc.record)


def finalize_cleanup(
    active: BaseException | None,
    cleanup: Any,
    *,
    s3: Any,
    completed: Any,
    last_completed_phase: Any,
    bindings: Any, fixture_capacity: Any = None,
) -> None:
    """Preserve a live failure, or fail a successful run whose cleanup failed."""
    if isinstance(active, FailureArtifactError):
        attach_cleanup(active, cleanup)
    elif active is None and sanitize_cleanup(cleanup)["failures"]:
        raise LiveEvalFailure(
            build_failure_record(
                phase="cleanup", failure_class="cleanup_failure", s3=s3, completed=completed,
                last_completed_phase=last_completed_phase,
                bindings=bindings, fixture_capacity=fixture_capacity, cleanup=cleanup,
            )
        ) from None


def failure_path_for(report_path: Path | str) -> Path:
    """Return the failure artifact sibling of the configured success report."""
    return Path(report_path).with_suffix(".failure.json")


def write_failure_json(path: Path | str, record: Mapping[str, Any]) -> Path:
    """Atomically write one normalized failure record."""
    destination = Path(path)
    normalized = enrich_failure_record(record)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name("." + destination.name + ".tmp")
    try:
        temporary.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
    finally:
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:
            pass
    return destination


__all__ = [
    "COMPLETED_KEYS",
    "FAILURE_SCHEMA",
    "FailureArtifactError",
    "LiveEvalFailure",
    "attach_cleanup",
    "bindings_from_receipt",
    "build_failure_record",
    "child_outcome",
    "completed_counts",
    "enrich_failure_record",
    "failure_path_for",
    "failure_record_from_exception",
    "finalize_cleanup",
    "finite_http_status",
    "git_failure_record",
    "push_context",
    "safe_summary",
    "sanitize_bindings",
    "sanitize_s3_snapshot",
    "write_failure_json",
]
