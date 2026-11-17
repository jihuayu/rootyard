#!/usr/bin/env python3
"""Private bounded HTTP transaction child for the Vault rotation harness.

The parent owns this process through the approved bounded runner.  This child
reads one bounded JSON object from stdin, performs exactly one Vault HTTP
transaction in the same process (connect/TLS, headers and the bounded body
read), and writes one fixed-shape JSON object to stdout.  A blocked urllib call
is bounded by the parent's absolute deadline kill/reap; the socket timeout here
is only a secondary stall bound.

The child never receives a URL/token in argv or environment, and it never
writes a URL, token, request/response header, response error body or raw
exception text.  A non-2xx HTTP response is reported by status only with an
empty body.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 256 * 1024
MAX_INPUT_BYTES = 512 * 1024
MAX_REQUEST_BODY = 256 * 1024
BODY_LIMIT = MAX_BODY + 1
HTTP_CAP_SECONDS = 5.0
ALLOWED_METHODS = frozenset({
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
})
ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})
INPUT_KEYS = {"method", "url", "token", "body_b64", "timeout"}
FAILURE_CODES = frozenset({
    "input_invalid",
    "input_too_large",
    "url_invalid",
    "request_failed",
    "response_invalid",
})
STATUS_MIN = 100
STATUS_MAX = 599


def _failure(code):
    return {"ok": False, "code": code}


def _success(status, body):
    return {
        "ok": True,
        "status": status,
        "body_b64": base64.b64encode(bytes(body)).decode("ascii"),
    }


def _no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _decode_input(raw):
    if len(raw) > MAX_INPUT_BYTES:
        return None, _failure("input_too_large")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_no_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return None, _failure("input_invalid")
    if not isinstance(value, dict) or set(value) != INPUT_KEYS:
        return None, _failure("input_invalid")
    method = value.get("method")
    url = value.get("url")
    token = value.get("token")
    body_b64 = value.get("body_b64")
    timeout = value.get("timeout")
    if not isinstance(method, str) or method not in ALLOWED_METHODS:
        return None, _failure("input_invalid")
    if not isinstance(url, str) or not url:
        return None, _failure("input_invalid")
    if token is not None and (
        not isinstance(token, str)
        or not token
        or "\r" in token
        or "\n" in token
    ):
        return None, _failure("input_invalid")
    if body_b64 is not None and not isinstance(body_b64, str):
        return None, _failure("input_invalid")
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        return None, _failure("input_invalid")
    body = None
    if body_b64 is not None:
        try:
            body = base64.b64decode(body_b64.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError, ValueError):
            return None, _failure("input_invalid")
        if len(body) > MAX_REQUEST_BODY:
            return None, _failure("input_invalid")
    return {
        "method": method,
        "url": url,
        "token": token,
        "body": body,
        "timeout": min(float(timeout), HTTP_CAP_SECONDS),
    }, None


def _validate_url(url):
    if not isinstance(url, str) or not url:
        return False
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.hostname not in ALLOWED_HOSTS:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    if parsed.fragment:
        return False
    if port is None or not 1 <= port <= 65535:
        return False
    if not parsed.path.startswith("/v1/"):
        return False
    return True


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect without reading Location or opening a new URL."""

    def http_error_301(self, req, fp, code, msg, headers):
        return None

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def _default_opener():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirectHandler())


def run_transaction(value, opener=None):
    """Perform one transaction; used directly by pure fake tests."""
    method = value["method"]
    url = value["url"]
    token = value["token"]
    body = value["body"]
    timeout = value["timeout"]
    if not _validate_url(url):
        return _failure("url_invalid")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    try:
        request = urllib.request.Request(
            url, data=body, method=method, headers=headers)
        active = _default_opener() if opener is None else opener
        with active.open(request, timeout=timeout) as response:
            status = getattr(response, "status", None)
            if type(status) is not int or not STATUS_MIN <= status <= STATUS_MAX:
                return _failure("response_invalid")
            if not 200 <= status < 300:
                # Never read or project a non-2xx body.  This also covers a
                # synthetic response object (for example 304) that urllib did
                # not turn into HTTPError.
                return _success(status, b"")
            raw = response.read(BODY_LIMIT)
            if not isinstance(raw, (bytes, bytearray)):
                return _failure("response_invalid")
            raw = bytes(raw)
            if len(raw) > BODY_LIMIT:
                return _failure("response_invalid")
    except urllib.error.HTTPError as error:
        status = getattr(error, "code", None)
        try:
            error.close()
        except (OSError, ValueError, AttributeError):
            pass
        if type(status) is not int or not STATUS_MIN <= status <= STATUS_MAX:
            return _failure("response_invalid")
        # The error body is deliberately never read or forwarded.
        raw = b""
    except (urllib.error.URLError, OSError, ValueError, TypeError):
        return _failure("request_failed")
    except Exception:
        return _failure("request_failed")
    return _success(status, raw)


def main(argv=None):
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        value, failure = _decode_input(raw)
        result = failure if failure is not None else run_transaction(value)
    except Exception:
        result = _failure("input_invalid")
    try:
        sys.stdout.write(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
