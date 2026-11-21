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
import itertools
import math
import re
from typing import Any

from .operation_verdict import OPERATION_VERDICTS, read_operation_verdict

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
# Bounded per-ref verdict for this worker's own expected push destination only.
# ``stale_info`` covers stock Git's ``[rejected] (stale info)`` plus
# ``[remote rejected] (stale info)``; any other classified ``!`` rejection of
# that same destination is ``other_ref_rejection``.  Everything absent,
# malformed, duplicated, off-target or non-``!`` stays ``unknown`` so it can
# never turn into a definite failure of the current ref.
PUSH_REF_VERDICTS = ("unknown", "stale_info", "other_ref_rejection")

CONCURRENT_OUTCOME_LIMIT = 3
CONCURRENT_OUTCOME_FIELDS = (
    "branch_ordinal",
    "outcome",
    "phase",
    "failure_class",
    "http_status",
    "http_subphase",
    "push_ref_verdict",
    "operation_verdict",
    "git_returncode",
    "signal",
    "elapsed_ms",
)
OUTCOMES = ("passed", "failed", "unknown")
# Fields added after the original outcome schema.  A record without any subset
# of them is still readable: every missing field projects its fixed unknown id.
_LATE_OUTCOME_FIELDS = ("elapsed_ms", "push_ref_verdict", "operation_verdict")


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


def finite_elapsed_ms(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return round(number, 3) if math.isfinite(number) and number >= 0 else None


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


# Stock ``git push --porcelain`` summary column for one rejected ref.
_PORCELAIN_REJECTION = re.compile(rb"^(?:\[rejected\]|\[remote rejected\]) \(([^()\x00-\x1f\x7f]{1,200})\)$")
_PORCELAIN_STALE_REASON = b"stale info"
# Optional stock framing around the single ref status line: one leading
# ``To <remote>`` line and one trailing ``Done`` line.  The remote is
# untrusted and is never decoded, retained or compared.
_PORCELAIN_TO_PREFIX = b"To "
_PORCELAIN_DONE = b"Done"
_PORCELAIN_TO_LIMIT = 8192


def _is_porcelain_to_line(line: bytes) -> bool:
    """Accept only a bounded ``To <remote>`` frame whose remote is never read."""
    if not line.startswith(_PORCELAIN_TO_PREFIX) or len(line) > _PORCELAIN_TO_LIMIT:
        return False
    remote = line[len(_PORCELAIN_TO_PREFIX):]
    return bool(remote) and b"\x00" not in remote and b"\t" not in remote


def push_expected_destination(ref_target: Any) -> str | None:
    """Return the bounded destination ref of this worker's own push refspec.

    ``HEAD:refs/heads/conc_0`` yields ``refs/heads/conc_0``.  Anything that is
    not a plain ``refs/`` destination (missing, relative, glob, control or
    non-ASCII bytes, absurdly long) yields ``None`` so the verdict fails closed.
    """
    if not isinstance(ref_target, str) or not ref_target:
        return None
    refspec = ref_target[1:] if ref_target.startswith("+") else ref_target
    destination = refspec.rsplit(":", 1)[1] if ":" in refspec else refspec
    if not destination.startswith("refs/") or len(destination) > 1024:
        return None
    if any(not 0x21 <= ord(ch) <= 0x7E for ch in destination):
        return None
    return destination


def finite_push_ref_verdict(stdout: bytes | bytearray | None, expected_destination: Any) -> str:
    """Classify at most one stock-Git porcelain line for one known destination.

    Only ``git push --porcelain`` stdout is inspected.  Stock Git wraps the
    single ref status line in optional framing: at most one leading ``To
    <remote>`` line and at most one trailing exact ``Done`` line.  That framing
    is stripped and discarded without ever decoding, retaining or comparing the
    untrusted remote.  After stripping, exactly one well-formed status line
    carrying the ``!`` flag whose destination equals the caller's own expected
    ref may be classified.  ``stale_info`` accepts both stock spellings,
    ``[rejected] (stale info)`` and ``[remote rejected] (stale info)``; any
    other classified rejection of that same destination is
    ``other_ref_rejection``.  Any second status line, duplicate/forged framing,
    extra unrelated content, malformed bytes, an off-target destination or a
    non-``!`` flag stays ``unknown``: ignored extra input can never upgrade
    itself into a definite failure of the current ref.  Raw bytes are not
    retained and no ref name, remote, path or user text escapes this function.
    """
    status = _single_push_status(stdout, expected_destination)
    if status is None or status[0] != b"!":
        return "unknown"
    _, summary = status
    match = _PORCELAIN_REJECTION.fullmatch(summary)
    if match is None:
        return "unknown"
    return "stale_info" if match.group(1) == _PORCELAIN_STALE_REASON else "other_ref_rejection"


def _single_push_status(
    stdout: bytes | bytearray | None, expected_destination: Any,
) -> tuple[bytes, bytes] | None:
    """Return the flag and summary from one well-framed status for the given ref."""
    if not isinstance(stdout, (bytes, bytearray)) or not isinstance(expected_destination, str):
        return None
    if not expected_destination or not expected_destination.startswith("refs/"):
        return None
    data = bytes(stdout)
    if data.endswith(b"\n"):
        data = data[:-1]
    if not data:
        return None
    lines = [line[:-1] if line.endswith(b"\r") else line for line in data.split(b"\n")]
    if _is_porcelain_to_line(lines[0]):
        lines = lines[1:]
    if lines and lines[-1] == _PORCELAIN_DONE:
        lines = lines[:-1]
    if len(lines) != 1:
        return None
    parts = lines[0].split(b"\t")
    if len(parts) != 3:
        return None
    flag, refs, summary = parts
    if b":" not in refs:
        return None
    _source, raw_destination = refs.rsplit(b":", 1)
    try:
        destination = raw_destination.decode("ascii")
    except UnicodeDecodeError:
        return None
    if destination != expected_destination:
        return None
    return flag, summary


def confirms_new_branch(stdout: bytes | bytearray | None, expected_destination: str | None) -> bool:
    return _single_push_status(stdout, expected_destination) == (b"*", b"[new branch]")


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
            "push_ref_verdict": _choice(source.get("push_ref_verdict"), PUSH_REF_VERDICTS),
            "operation_verdict": _choice(source.get("operation_verdict"), OPERATION_VERDICTS),
            "git_returncode": _optional_int(source.get("git_returncode")),
            "signal": _signal(source.get("signal")),
            "elapsed_ms": finite_elapsed_ms(source.get("elapsed_ms")),
        }
    return {
        "branch_ordinal": branch_ordinal,
        "outcome": outcome,
        "phase": "unknown",
        "failure_class": "unclassified",
        "http_status": None,
        "http_subphase": "unknown",
        "push_ref_verdict": "unknown",
        "operation_verdict": "unknown",
        "git_returncode": None,
        "signal": None,
        "elapsed_ms": finite_elapsed_ms(source.get("elapsed_ms")) if outcome == "passed" else None,
    }


def finite_worker_outcome(
    branch_ordinal: int, exc: BaseException | None = None, *, elapsed_ms: Any = None
) -> dict[str, Any]:
    """Build one fixed outcome without inspecting raw exception text."""
    branch = branch_ordinal if 0 <= branch_ordinal < CONCURRENT_OUTCOME_LIMIT else None
    if exc is None:
        return _fixed_outcome(branch, "passed", {"elapsed_ms": elapsed_ms})
    record = getattr(exc, "record", None)
    if not isinstance(record, Mapping):
        return _fixed_outcome(branch, "unknown", None)
    return _fixed_outcome(branch, "failed", record)


def sanitize_concurrent_outcomes(value: Any) -> list[dict[str, Any]]:
    """Project a bounded outcome list, rejecting malformed/injected entries.

    The list is capped at the three known branch ids.  Entries with unlisted or
    missing keys, duplicate branch ids, wrong types, or unrecognized outcome ids
    are rejected.  Older receipts predating any of the late fields stay readable:
    a missing ``elapsed_ms`` becomes null and a missing per-ref or operation
    verdict becomes ``unknown``.  Unrecognized phase/class/subphase/verdict
    strings are normalized to ``unknown`` so no caller text can surface.
    """
    if not isinstance(value, (list, tuple)) or len(value) > CONCURRENT_OUTCOME_LIMIT:
        return []
    fields = frozenset(CONCURRENT_OUTCOME_FIELDS)
    accepted_fields = tuple(
        fields - frozenset(removed)
        for size in range(len(_LATE_OUTCOME_FIELDS) + 1)
        for removed in itertools.combinations(_LATE_OUTCOME_FIELDS, size)
    )
    seen: set[int] = set()
    projected: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping) or frozenset(item.keys()) not in accepted_fields:
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
            elapsed_ms = future.result()
        except BaseException as exc:  # noqa: BLE001 - preserve the original object
            if first_error is None:
                first_error = exc
            if index < branch_count:
                outcomes.append(finite_worker_outcome(index, exc))
        else:
            if index < branch_count:
                outcomes.append(finite_worker_outcome(index, elapsed_ms=elapsed_ms))
    if progress is not None:
        progress["concurrent_worker_outcomes"] = sanitize_concurrent_outcomes(outcomes)
    return first_error


def _operation_verdict_for(
    branch: Any,
    base_url: Any,
    repo: Any,
    token: Any,
    operations: Any,
) -> str:
    """One bounded read-only query; every failure mode is a fixed ``unknown``."""
    pair = operations.get(branch) if isinstance(operations, Mapping) else None
    if not isinstance(pair, tuple) or len(pair) != 2 or not all(isinstance(value, str) for value in pair):
        return "unknown"
    if not isinstance(repo, Mapping):
        return "unknown"
    try:
        answer = read_operation_verdict(
            base_url,
            repo.get("owner"),
            repo.get("name"),
            pair[0],
            token,
            repository_id=repo.get("id"),
            expected_ref=pair[1],
        )
    except Exception:  # noqa: BLE001 - a query failure is a bounded unknown
        return "unknown"
    return _choice(answer, OPERATION_VERDICTS)


def annotate_stale_operations(
    progress: dict[str, Any],
    base_url: str,
    repo: Mapping[str, Any],
    token: str,
    operations: Mapping[int, tuple[str, str]],
) -> None:
    """Attach one durable-operation verdict to each ``stale_info`` worker.

    Must be called only after every concurrent future has joined and before the
    caller re-raises its original first error.  Exactly one read-only query runs
    per stale worker; a transport failure, unlisted answer, missing operation or
    malformed response leaves ``unknown``.  This function never raises and never
    touches the caller's first-exception object, so it cannot replace the
    original error or turn the phase into a pass.  Only the fixed enum reaches
    the progress map, which is re-projected through the ordinary sanitizer.
    """
    outcomes = progress.get("concurrent_worker_outcomes") if isinstance(progress, dict) else None
    if not isinstance(outcomes, (list, tuple)):
        return
    rows: list[dict[str, Any]] = []
    for item in outcomes:
        row = dict(item) if isinstance(item, Mapping) else {}
        if row.get("push_ref_verdict") == "stale_info":
            row["operation_verdict"] = _operation_verdict_for(
                row.get("branch_ordinal"), base_url, repo, token, operations
            )
        rows.append(row)
    progress["concurrent_worker_outcomes"] = sanitize_concurrent_outcomes(rows)
