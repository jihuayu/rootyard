"""Bounded, read-only durable-operation classification for #282.

One failed concurrent push worker may be a durable server-side refusal rather
than a transport failure.  This module issues at most one bounded, read-only GET
of the existing job-owned operation endpoint
(``/api/repos/{owner}/{name}/operations/{operation}``, see
``src/blob_git_gateway/api.rs``) with the same issuer token that performed the
push, and reduces the response in memory to one fixed enum.

The wire view is exactly ``OperationView {operation_id, state, terminal}`` where
``state`` is the operation state and ``terminal`` is the persisted
``PackCommitTerminal`` (see ``src/ref_store/core/pack_commit/receipt.rs``):
per-ref results tagged by ``outcome`` and an optional ``rejection {code,
detail}``.  Two durable refusals are distinguishable:

* ``revision_mismatch`` + ``admitted base was superseded`` with every expected
  ref ``not_applied`` / ``old_oid_mismatch``: the served base was superseded.
* ``no_ref_applied`` + ``all_rejected`` with the same per-ref facts: the
  publication decision rejected every ref (per-ref CAS loss).

Transport is scoped to this run's own fixed base origin: a literal loopback
address with an explicit port and no path/query/userinfo.  The exchange uses a
direct ``http.client`` connection on that origin, so it never consults proxy
environment variables and never follows a redirect (a 3xx answer is simply a
non-200 failure, and the redirect target is never contacted).  One absolute
deadline covers connect, request headers and every body read, so a peer that
trickles bytes inside a per-receive socket timeout cannot stretch the exchange;
the connection is closed synchronously in ``finally``.  There is no thread,
retry or background request left behind for cleanup.

Nothing from the response (operation id, repository id, ref, rejection text,
headers, URL, token) is retained, logged, raised or returned.  Only the enum
leaves this module; every transport failure, non-200 answer, oversized body,
unparseable body, identity mismatch or unrecognized combination is ``unknown``.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import time
from typing import Any
import urllib.parse
import uuid

OPERATION_VERDICTS = ("unknown", "admitted_base_superseded", "per_ref_cas_rejected")
OPERATION_QUERY_TIMEOUT_SECONDS = 5.0
OPERATION_RESPONSE_MAX_BYTES = 64 * 1024

_SUPERSEDED_CODE = "revision_mismatch"
_SUPERSEDED_DETAIL = "admitted base was superseded"
_CAS_CODE = "no_ref_applied"
_CAS_DETAIL = "all_rejected"
_NOT_APPLIED_REASON = "old_oid_mismatch"
_TERMINAL_REJECTED = "rejected"
_BODY_CHUNK_BYTES = 16 * 1024
_MAX_TOKEN_CHARS = 4096


def _uuid(value: Any) -> uuid.UUID | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        return None


def classify_operation_view(
    document: Any,
    *,
    operation_id: str,
    repository_id: str,
    expected_ref: str,
) -> str:
    """Return one fixed verdict from an in-memory operation view document.

    Identity is bound strictly: the view must name this exact operation UUID, be
    the durable ``rejected`` state whose terminal also names ``rejected``, carry
    this exact repository UUID, and carry exactly one per-ref result for the
    caller's own expected ref with ``not_applied`` / ``old_oid_mismatch``.  Only
    then may the terminal rejection code/detail pair select the fixed enum.
    """
    expected_operation = _uuid(operation_id)
    expected_repository = _uuid(repository_id)
    if expected_operation is None or expected_repository is None:
        return "unknown"
    if not isinstance(expected_ref, str) or not expected_ref.startswith("refs/"):
        return "unknown"
    if not isinstance(document, dict):
        return "unknown"
    if _uuid(document.get("operation_id")) != expected_operation:
        return "unknown"
    if document.get("state") != _TERMINAL_REJECTED:
        return "unknown"
    terminal = document.get("terminal")
    if not isinstance(terminal, dict) or terminal.get("kind") != _TERMINAL_REJECTED:
        return "unknown"
    if _uuid(terminal.get("repository_id")) != expected_repository:
        return "unknown"
    refs = terminal.get("refs")
    if not isinstance(refs, list) or len(refs) != 1:
        return "unknown"
    result = refs[0]
    if not isinstance(result, dict):
        return "unknown"
    if result.get("outcome") != "not_applied" or result.get("name") != expected_ref:
        return "unknown"
    if result.get("reason") != _NOT_APPLIED_REASON:
        return "unknown"
    rejection = terminal.get("rejection")
    if not isinstance(rejection, dict):
        return "unknown"
    code = rejection.get("code")
    detail = rejection.get("detail")
    if code == _SUPERSEDED_CODE and detail == _SUPERSEDED_DETAIL:
        return "admitted_base_superseded"
    if code == _CAS_CODE and detail == _CAS_DETAIL:
        return "per_ref_cas_rejected"
    return "unknown"


def _valid_token(token: Any) -> bool:
    """Only one bounded ASCII bearer token may be sent, and only to the origin."""
    return (
        isinstance(token, str)
        and 0 < len(token) <= _MAX_TOKEN_CHARS
        and all(0x21 <= ord(char) <= 0x7E for char in token)
    )


def _origin(base_url: Any) -> tuple[str, int] | None:
    """Return the fixed loopback origin, or ``None`` for anything else.

    The transport is anchored to this run's own base origin: plain HTTP, a
    literal loopback address, an explicit port, no userinfo, and no path,
    query or fragment.  A redirect target, proxy URL, credential-bearing URL or
    remote host can never become the origin of the issuer token.
    """
    if not isinstance(base_url, str) or not base_url:
        return None
    try:
        parsed = urllib.parse.urlsplit(base_url)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme != "http" or not parsed.hostname or port is None:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        return None
    try:
        if not ipaddress.ip_address(parsed.hostname).is_loopback:
            return None
    except ValueError:
        return None
    return parsed.hostname, port


def _remaining(deadline: float) -> float:
    """One absolute deadline for connect, headers and every body read."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("operation query deadline exceeded")
    return remaining


class _DeadlineSocket(socket.socket):
    """A connected socket that refuses all I/O past one absolute deadline.

    ``socket.timeout`` alone bounds each blocking call, not the exchange: a
    peer that trickles a byte inside every per-recv timeout can stretch an
    unbounded header or body read.  Re-arming the timeout with the time left
    before every send/receive makes the whole exchange fail at the deadline.
    """

    def __init__(self, raw: socket.socket, deadline: float) -> None:
        family, kind, proto = raw.family, raw.type, raw.proto
        self._deadline = deadline
        super().__init__(family, kind, proto, fileno=raw.detach())
        self.settimeout(_remaining(deadline))

    def _arm(self) -> None:
        self.settimeout(_remaining(self._deadline))

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        self._arm()
        return super().recv(bufsize, flags)

    def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
        self._arm()
        return super().recv_into(buffer, nbytes, flags)

    def send(self, data: Any, flags: int = 0) -> int:
        self._arm()
        return super().send(data, flags)

    def sendall(self, data: Any, flags: int = 0) -> None:
        self._arm()
        return super().sendall(data, flags)


class _BoundedHTTPConnection(http.client.HTTPConnection):
    """One fresh direct loopback connection: no proxy handler, no redirect hop."""

    def __init__(self, host: str, port: int, deadline: float) -> None:
        super().__init__(host, port, timeout=_remaining(deadline))
        self._deadline = deadline

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), _remaining(self._deadline))
        self.sock = _DeadlineSocket(raw, self._deadline)


def _bounded_request(
    origin: tuple[str, int],
    operation: uuid.UUID,
    owner: str,
    name: str,
    token: str,
    deadline: float,
    max_bytes: int,
) -> bytes | None:
    """Issue exactly one GET against the fixed origin, or return ``None``.

    ``http.client`` never consults proxy environment variables and never follows
    a redirect, so a 3xx answer is simply a non-200 failure.  The socket, the
    request, the response and its body are all bounded by one deadline and
    closed in ``finally``; no thread, retry or background request is created.
    """
    path = "/api/repos/{}/{}/operations/{}".format(
        urllib.parse.quote(owner, safe=""), urllib.parse.quote(name, safe=""), operation
    )
    connection = None
    response = None
    try:
        connection = _BoundedHTTPConnection(origin[0], origin[1], deadline)
        connection.putrequest("GET", path)
        connection.putheader("Authorization", f"Bearer {token}")
        connection.putheader("Accept", "application/json")
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        if response.status != 200:
            return None
        body = bytearray()
        while len(body) <= max_bytes:
            chunk = response.read(min(_BODY_CHUNK_BYTES, max_bytes + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        if not body or len(body) > max_bytes:
            return None
        return bytes(body)
    except Exception:  # noqa: BLE001 - every transport failure is a fixed unknown
        return None
    finally:
        for item in (response, connection):
            try:
                if item is not None:
                    item.close()
            except Exception:  # noqa: BLE001 - cleanup must never raise
                pass


def read_operation_verdict(
    base_url: str,
    owner: str,
    name: str,
    operation_id: str,
    token: str,
    *,
    repository_id: str,
    expected_ref: str,
    timeout: float = OPERATION_QUERY_TIMEOUT_SECONDS,
    max_bytes: int = OPERATION_RESPONSE_MAX_BYTES,
) -> str:
    """Perform one bounded read-only operation GET and return one fixed verdict.

    The request never runs on behalf of another identity: ``token`` must be the
    same issuer token that performed the push.  Any failure mode returns
    ``unknown`` and never raises, so a caller's original first error is never
    replaced or converted into a pass.
    """
    operation = _uuid(operation_id)
    if operation is None or not _valid_token(token):
        return "unknown"
    if not all(isinstance(value, str) and value for value in (base_url, owner, name, repository_id)):
        return "unknown"
    if _uuid(repository_id) is None:
        return "unknown"
    if not isinstance(expected_ref, str) or not expected_ref.startswith("refs/"):
        return "unknown"
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
        return "unknown"
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1024 <= max_bytes <= OPERATION_RESPONSE_MAX_BYTES:
        return "unknown"
    origin = _origin(base_url)
    if origin is None:
        return "unknown"
    try:
        body = _bounded_request(
            origin, operation, owner, name, token, time.monotonic() + float(timeout), max_bytes
        )
    except Exception:  # noqa: BLE001 - defensive: a helper bug is still a bounded unknown
        return "unknown"
    if body is None:
        return "unknown"
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "unknown"
    return classify_operation_view(
        document,
        operation_id=str(operation),
        repository_id=repository_id,
        expected_ref=expected_ref,
    )


__all__ = [
    "OPERATION_QUERY_TIMEOUT_SECONDS",
    "OPERATION_RESPONSE_MAX_BYTES",
    "OPERATION_VERDICTS",
    "classify_operation_view",
    "read_operation_verdict",
]
