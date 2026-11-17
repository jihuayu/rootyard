"""Finite outcomes for the #178 concurrent push workers.

The live fixture launches three push workers plus one browse/PG worker.  The
existing ordered ``fut.result()`` loop already waits for each worker.  This
module observes every future, retains one fixed outcome per push branch, and
returns the original first exception so the caller can re-raise that exact
object after the executor context has waited for all workers.

No outcome carries raw exception text, ``str``/``repr``, a traceback, URL,
header, credential, SQL/DSN, environment value, argv, body or provider string.
Unknown or malformed context fails closed to the fixed ``unknown`` ids.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

PHASES = (
    "baseline_seed_push",
    "baseline_wave_push",
    "candidate_push",
    "concurrent_push",
    "live_setup",
    "ack_verification",
    "cleanup",
    "unknown",
)
FAILURE_CLASSES = (
    "git_push",
    "git_timeout",
    "git_spawn",
    "popen_failed",
    "exited_early",
    "readiness_timeout",
    "cleanup_failure",
    "unclassified",
)
HTTP_SUBPHASES = ("unknown", "info_refs", "receive_pack")

CONCURRENT_OUTCOME_LIMIT = 3
CONCURRENT_OUTCOME_FIELDS = (
    "branch_ordinal",
    "outcome",
    "phase",
    "failure_class",
    "http_status",
    "http_subphase",
    "git_returncode",
    "signal",
)
OUTCOMES = ("passed", "failed", "unknown")


def _choice(value: Any, allowed: tuple[str, ...] | frozenset[str], default: str = "unknown") -> str:
    return value if isinstance(value, str) and value in allowed else default


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _signal(value: Any) -> int | None:
    code = _optional_int(value)
    return code if code is not None and 1 <= code <= 127 else None


def _http_status(value: Any) -> int | None:
    code = _optional_int(value)
    return code if code is not None and 100 <= code <= 599 else None


def finite_http_subphase(stderr: bytes | bytearray | None, status: int | None) -> str:
    """Return a fixed subphase only from an unambiguous Git stderr marker.

    A generic ``unable to access`` message with a bare repository URL is not
    enough evidence for the advertisement GET.  ``info_refs`` additionally
    requires the fixed ``info/refs`` + ``service=git-receive-pack`` marker, and
    ``receive_pack`` requires Git's fixed ``RPC failed`` marker.  Everything
    else stays ``unknown`` rather than guessing a phase.
    """
    if status is None or not isinstance(stderr, (bytes, bytearray)):
        return "unknown"
    data = bytes(stderr)
    if b"RPC failed" in data:
        return "receive_pack"
    if b"info/refs" in data and b"service=git-receive-pack" in data:
        return "info_refs"
    return "unknown"


def _fixed_outcome(branch_ordinal: int | None, outcome: str, record: Mapping[str, Any] | None) -> dict[str, Any]:
    source = record if isinstance(record, Mapping) else {}
    if outcome == "failed":
        return {
            "branch_ordinal": branch_ordinal,
            "outcome": "failed",
            "phase": _choice(source.get("phase"), PHASES),
            "failure_class": _choice(source.get("failure_class"), FAILURE_CLASSES, "unclassified"),
            "http_status": _http_status(source.get("http_status")),
            "http_subphase": _choice(source.get("http_subphase"), HTTP_SUBPHASES),
            "git_returncode": _optional_int(source.get("git_returncode")),
            "signal": _signal(source.get("signal")),
        }
    return {
        "branch_ordinal": branch_ordinal,
        "outcome": outcome,
        "phase": "unknown",
        "failure_class": "unclassified",
        "http_status": None,
        "http_subphase": "unknown",
        "git_returncode": None,
        "signal": None,
    }


def finite_worker_outcome(branch_ordinal: int, exc: BaseException | None = None) -> dict[str, Any]:
    """Build one fixed outcome without inspecting raw exception text."""
    branch = branch_ordinal if 0 <= branch_ordinal < CONCURRENT_OUTCOME_LIMIT else None
    if exc is None:
        return _fixed_outcome(branch, "passed", None)
    record = getattr(exc, "record", None)
    if not isinstance(record, Mapping):
        return _fixed_outcome(branch, "unknown", None)
    return _fixed_outcome(branch, "failed", record)


def sanitize_concurrent_outcomes(value: Any) -> list[dict[str, Any]]:
    """Project a bounded outcome list, rejecting malformed/injected entries.

    The list is capped at the three known branch ids.  Entries with unlisted or
    missing keys, duplicate branch ids, wrong types, or unrecognized outcome ids
    are rejected.  Unrecognized phase/class/subphase strings are normalized to
    the fixed ``unknown`` ids so no caller text can surface.
    """
    if not isinstance(value, (list, tuple)) or len(value) > CONCURRENT_OUTCOME_LIMIT:
        return []
    fields = set(CONCURRENT_OUTCOME_FIELDS)
    seen: set[int] = set()
    projected: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item.keys()) != fields:
            continue
        branch = item.get("branch_ordinal")
        if isinstance(branch, bool) or not isinstance(branch, int) or not 0 <= branch < CONCURRENT_OUTCOME_LIMIT:
            continue
        if branch in seen:
            continue
        outcome = item.get("outcome")
        if outcome not in OUTCOMES:
            continue
        seen.add(branch)
        projected.append(_fixed_outcome(branch, outcome, item))
    return projected


def collect_concurrent_outcomes(
    futures: Sequence[Any],
    browse_future: Any,
    *,
    branch_count: int,
    progress: dict[str, Any] | None = None,
) -> BaseException | None:
    """Observe every worker in the existing order and return the first error.

    The caller re-raises the returned object only after its executor context has
    already waited for all workers.  No new thread, retry, deadline or wait is
    introduced: each ``result()`` is the same ordered observation the phase
    already performed.
    """
    outcomes: list[dict[str, Any]] = []
    first_error: BaseException | None = None
    for index, future in enumerate(list(futures) + [browse_future]):
        try:
            future.result()
        except BaseException as exc:  # noqa: BLE001 - preserve the original object
            if first_error is None:
                first_error = exc
            if index < branch_count:
                outcomes.append(finite_worker_outcome(index, exc))
        else:
            if index < branch_count:
                outcomes.append(finite_worker_outcome(index, None))
    if progress is not None:
        progress["concurrent_worker_outcomes"] = sanitize_concurrent_outcomes(outcomes)
    return first_error
