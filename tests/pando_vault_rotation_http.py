#!/usr/bin/env python3
"""One owned, deadline-bounded Vault HTTP transaction for issue #21.

The whole HTTP operation -- connect/TLS, headers and the bounded body read --
runs in one private child.  The parent never opens a socket or calls urllib: it
sends only one bounded JSON object on the child's stdin and accepts only one
fixed-shape JSON result.  The already-approved
``BoundedCommandRunner``/``ProcessRunner`` owns that child's exact process group
and kills/reaps it at the shared absolute deadline, so a server that trickles
headers or body bytes cannot hold the harness past ``D``.

The raw response body is returned in RAM only.  It is never written to a
report, log, model or disk, and no token, URL, request header, exception text or
raw error body is placed in a failure projection.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import os
from pathlib import Path
import re
import sys

from pando_vault_rotation_budget import DEADLINE_CODES
from pando_vault_rotation_support import QualificationError

CHILD_SCRIPT = Path(__file__).with_name("pando_vault_rotation_http_child.py")
MAX_BODY = 256 * 1024
MAX_INPUT_BYTES = 512 * 1024
MAX_RESULT_BYTES = 512 * 1024
HTTP_CAP_SECONDS = 5.0
SAFE_CHILD_ENV = {
    "PATH": os.defpath,
    "PYTHONIOENCODING": "utf-8",
    "PYTHONNOUSERSITE": "1",
}
FAILURE_CODES = frozenset({
    "input_invalid",
    "input_too_large",
    "url_invalid",
    "request_failed",
    "response_invalid",
})
CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
STATUS_MIN = 100
STATUS_MAX = 599
BODY_LIMIT = MAX_BODY + 1


class HttpRequest:
    """A tiny request value without a secret-bearing representation."""

    def __init__(self, method, url, data=None, headers=None):
        self.method = method
        self.url = url
        self.data = data
        self.headers = dict(headers or {})

    def __repr__(self):
        return "<HttpRequest>"


class HttpResponse:
    """RAM-only response returned by the owned child transaction."""

    def __init__(self, status, body):
        self.status = status
        self._body = bytes(body)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, limit=-1):
        if limit is None or limit < 0:
            return self._body
        return self._body[:limit]


def _unavailable(stage):
    return QualificationError("vault_api_failed", stage)


def _deadline(error, stage):
    return QualificationError(error.code, stage)


def _cap(requested):
    if (
        not isinstance(requested, (int, float))
        or isinstance(requested, bool)
        or not math.isfinite(requested)
        or requested <= 0
    ):
        raise _unavailable("vault_http")
    return min(float(requested), HTTP_CAP_SECONDS)


def _no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _max_encoded_bytes(decoded_limit):
    return 4 * ((decoded_limit + 2) // 3)


def _token(headers):
    token = None
    for name, value in headers.items():
        if str(name).lower() == "x-vault-token":
            token = value
            break
    if token is None:
        return None
    if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
        raise _unavailable("vault_http")
    return token


def _request_payload(request, timeout):
    if not isinstance(request, HttpRequest):
        raise _unavailable("vault_http")
    if not isinstance(request.method, str) or not request.method:
        raise _unavailable("vault_http")
    if not isinstance(request.url, str) or not request.url:
        raise _unavailable("vault_http")
    data = request.data
    if data is not None and not isinstance(data, (bytes, bytearray)):
        raise _unavailable("vault_http")
    try:
        value = {
            "method": request.method,
            "url": request.url,
            "token": _token(request.headers),
            "body_b64": (
                None if data is None
                else base64.b64encode(bytes(data)).decode("ascii")),
            "timeout": timeout,
        }
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise _unavailable("vault_http") from None
    if len(encoded) > MAX_INPUT_BYTES:
        raise _unavailable("vault_http")
    return encoded


def _decode_result(raw, stage):
    if not isinstance(raw, (bytes, bytearray)):
        raise _unavailable(stage)
    if len(raw) > MAX_RESULT_BYTES:
        raise _unavailable(stage)
    try:
        value = json.loads(
            bytes(raw).decode("utf-8"), object_pairs_hook=_no_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise _unavailable(stage) from None
    if not isinstance(value, dict):
        raise _unavailable(stage)
    ok = value.get("ok")
    if ok is True:
        if set(value) != {"ok", "status", "body_b64"}:
            raise _unavailable(stage)
        status = value.get("status")
        if type(status) is not int or not STATUS_MIN <= status <= STATUS_MAX:
            raise _unavailable(stage)
        encoded = value.get("body_b64")
        if not isinstance(encoded, str):
            raise _unavailable(stage)
        if len(encoded) > _max_encoded_bytes(BODY_LIMIT):
            raise _unavailable(stage)
        try:
            body = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError, ValueError):
            raise _unavailable(stage) from None
        if len(body) > BODY_LIMIT:
            raise _unavailable(stage)
        if not 200 <= status < 300 and body:
            raise _unavailable(stage)
        return status, body
    if ok is False:
        if set(value) != {"ok", "code"}:
            raise _unavailable(stage)
        code = value.get("code")
        if (
            not isinstance(code, str)
            or CODE_RE.fullmatch(code) is None
            or code not in FAILURE_CODES
        ):
            raise _unavailable(stage)
        raise _unavailable(stage)
    raise _unavailable(stage)


class BoundedHttpOpener:
    """Run one whole Vault HTTP transaction in one owned private child.

    A caller may still inject a fake opener for the existing pure contracts.
    The live fixture always uses this opener; there is no inline urllib path.
    """

    def __init__(self, runner, budget=None, child=CHILD_SCRIPT):
        self.runner = runner
        self.budget = budget
        self.child = Path(child)

    def _effective(self, timeout, stage):
        effective = _cap(HTTP_CAP_SECONDS if timeout is None else timeout)
        if self.budget is not None:
            effective = self.budget.clamp(effective, stage)
        return effective

    def open(self, request, timeout=None):
        stage = "vault_http"
        effective = self._effective(timeout, stage)
        stdin = _request_payload(request, effective)
        try:
            result = self.runner.run(
                [os.path.abspath(sys.executable), str(self.child)],
                env=dict(SAFE_CHILD_ENV),
                input=stdin,
                timeout=effective,
            )
        except QualificationError as error:
            if self.budget is not None and self.budget.expired():
                raise QualificationError("vault_deadline_exceeded", stage) from None
            if error.code in DEADLINE_CODES:
                raise _deadline(error, stage) from None
            raise _unavailable(stage) from None
        except Exception:
            if self.budget is not None and self.budget.expired():
                raise QualificationError("vault_deadline_exceeded", stage) from None
            raise _unavailable(stage) from None
        if self.budget is not None:
            # A child that returns after the work/cleanup deadline is never a
            # successful transaction, even when its stdout happens to parse.
            self.budget.late(stage)
        if type(getattr(result, "returncode", None)) is not int:
            raise _unavailable(stage)
        if result.returncode != 0:
            raise _unavailable(stage)
        raw = getattr(result, "stdout", None)
        status, body = _decode_result(raw, stage)
        if self.budget is not None:
            self.budget.late(stage)
        return HttpResponse(status, body)
