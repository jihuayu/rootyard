"""Authenticated HTTP/1.1 Byte-Range object server and Garage S3 client for #179."""
from __future__ import annotations

from dataclasses import dataclass, field
import datetime as dt
import hashlib
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from .fixture_builder import RepoArtifactSet


@dataclass
class AuthorizationGrant:
    token: str
    tenant_id: str
    repo_id: str
    revoked: bool = False


@dataclass
class PinLease:
    pin_id: str
    tenant_id: str
    repo_id: str
    history_incarnation: str
    membership_version: int
    active: bool = True


@dataclass
class ServerFault:
    """Deterministic server/provider fault configuration for fail-closed tests."""

    mode: str | None = None
    target_pack: str | None = None
    drop_pack: str | None = None


@dataclass
class ServerTelemetry:
    full_gets: int = 0
    range_gets: int = 0
    bytes_sent: int = 0
    denied_requests: int = 0
    drift_rejections: int = 0
    gc_rejections: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return {
                "full_gets": self.full_gets,
                "range_gets": self.range_gets,
                "bytes_sent": self.bytes_sent,
                "denied_requests": self.denied_requests,
                "drift_rejections": self.drift_rejections,
                "gc_rejections": self.gc_rejections,
            }


class RangeObjectServer:
    """Real loopback HTTP/1.1 object store enforcing auth, realm drift, pins, and Range 206."""

    def __init__(self, artifacts: RepoArtifactSet, simulated_rtt_ms: float = 0.0) -> None:
        self.artifacts = artifacts
        self.simulated_rtt_s = max(0.0, simulated_rtt_ms / 1000.0)
        self.live_history = artifacts.history_incarnation
        self.live_membership = artifacts.membership_version
        self.grants: dict[str, AuthorizationGrant] = {}
        self.pins: dict[str, PinLease] = {}
        self.swept_packs: set[str] = set()
        self.pack_etags: dict[str, str] = {
            name: hashlib.sha256(data).hexdigest() for name, data in artifacts.pack_bytes.items()
        }
        self.idx_etags: dict[str, str] = {
            name: hashlib.sha256(data).hexdigest() for name, data in artifacts.idx_bytes.items()
        }
        self.fault = ServerFault()
        self.telemetry = ServerTelemetry()
        self._state_lock = threading.Lock()
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:
                server_ref._handle_get(self)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> "RangeObjectServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=2.0)

    def add_grant(self, token: str, tenant_id: str, repo_id: str) -> None:
        with self._state_lock:
            self.grants[token] = AuthorizationGrant(token=token, tenant_id=tenant_id, repo_id=repo_id)

    def revoke_grant(self, token: str) -> None:
        with self._state_lock:
            if token in self.grants:
                self.grants[token].revoked = True

    def acquire_pin(self, pin_id: str) -> PinLease:
        with self._state_lock:
            lease = PinLease(
                pin_id=pin_id,
                tenant_id=self.artifacts.tenant_id,
                repo_id=self.artifacts.repo_id,
                history_incarnation=self.live_history,
                membership_version=self.live_membership,
                active=True,
            )
            self.pins[pin_id] = lease
            return lease

    def release_pin(self, pin_id: str) -> None:
        with self._state_lock:
            if pin_id in self.pins:
                self.pins[pin_id].active = False

    def try_gc_sweep_pack(self, pack_name: str, history: str, membership: int) -> bool:
        """Compaction/GC gate (#122/#151/#153): refuses removal while ANY matching pin stays active."""
        with self._state_lock:
            for lease in self.pins.values():
                if lease.active and lease.history_incarnation == history and lease.membership_version == membership:
                    return False
            self.swept_packs.add(pack_name)
            return True

    def advance_history(self, new_history: str) -> None:
        with self._state_lock:
            self.live_history = new_history

    def advance_membership(self, new_version: int) -> None:
        with self._state_lock:
            self.live_membership = new_version

    def _send_json(self, handler: BaseHTTPRequestHandler, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)

    def _check_auth(self, handler: BaseHTTPRequestHandler, tenant: str, repo: str) -> bool:
        auth = handler.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.startswith("Bearer ") else ""
        with self._state_lock:
            grant = self.grants.get(token)
            ok = (
                grant is not None
                and not grant.revoked
                and grant.tenant_id == tenant
                and grant.repo_id == repo
            )
        if not ok:
            with self.telemetry.lock:
                self.telemetry.denied_requests += 1
            self._send_json(handler, HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return False
        return True

    def _handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        if self.simulated_rtt_s > 0.0:
            time.sleep(self.simulated_rtt_s)
        parts = [p for p in urllib.parse.urlsplit(handler.path).path.split("/") if p]
        # Auth endpoint: /v1/repos/{tenant}/{repo}/auth-check
        if len(parts) == 5 and parts[:2] == ["v1", "repos"] and parts[4] == "auth-check":
            tenant, repo = parts[2], parts[3]
            if not self._check_auth(handler, tenant, repo):
                return
            with self._state_lock:
                body = {"history": self.live_history, "membership": self.live_membership}
            self._send_json(handler, HTTPStatus.OK, body)
            return

        # Object path: /v1/repos/{tenant}/{repo}/history/{h}/membership/{m}/{kind}/{name}
        if len(parts) != 10 or parts[:2] != ["v1", "repos"] or parts[4] != "history" or parts[6] != "membership":
            self._send_json(handler, HTTPStatus.NOT_FOUND, {"error": "bad path"})
            return
        tenant, repo, hist, mem_raw, kind, name = parts[2], parts[3], parts[5], parts[7], parts[8], parts[9]
        if not self._check_auth(handler, tenant, repo):
            return
        try:
            mem = int(mem_raw)
        except ValueError:
            self._send_json(handler, HTTPStatus.BAD_REQUEST, {"error": "bad membership"})
            return
        with self._state_lock:
            if tenant != self.artifacts.tenant_id or repo != self.artifacts.repo_id:
                self._send_json(handler, HTTPStatus.NOT_FOUND, {"error": "unknown repo"})
                return
            if hist != self.live_history or mem != self.live_membership:
                with self.telemetry.lock:
                    self.telemetry.drift_rejections += 1
                self._send_json(handler, HTTPStatus.CONFLICT, {"error": "history_or_membership_drift"})
                return
            if kind == "packs" and (name in self.swept_packs or self.fault.drop_pack == name):
                with self.telemetry.lock:
                    self.telemetry.gc_rejections += 1
                self._send_json(handler, HTTPStatus.GONE, {"error": "evicted_or_swept"})
                return
            if kind == "packs":
                blob = self.artifacts.pack_bytes.get(name)
                etag = self.pack_etags.get(name, "")
            elif kind == "idx":
                blob = self.artifacts.idx_bytes.get(name)
                etag = self.idx_etags.get(name, "")
            else:
                blob, etag = None, ""
            fault = ServerFault(self.fault.mode, self.fault.target_pack)
        if blob is None:
            self._send_json(handler, HTTPStatus.NOT_FOUND, {"error": "missing artifact"})
            return
        if_match = handler.headers.get("If-Match")
        effective_etag = "forged-etag-drift" if fault.mode == "etag_mismatch" and fault.target_pack == name else etag
        if if_match and if_match.strip('"') != effective_etag:
            self._send_json(handler, HTTPStatus.PRECONDITION_FAILED, {"error": "etag_mismatch"})
            return

        range_hdr = handler.headers.get("Range")
        if range_hdr:
            if not range_hdr.startswith("bytes="):
                self._send_json(handler, HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE, {"error": "bad range"})
                return
            s_raw, e_raw = range_hdr[6:].split("-", 1)
            start = int(s_raw)
            end = min(int(e_raw), len(blob) - 1) if e_raw else len(blob) - 1
            if start < 0 or start > end or end >= len(blob):
                self._send_json(handler, HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE, {"error": "range bounds"})
                return
            payload = blob[start : end + 1]
            announced_len = len(payload)
            if fault.mode == "bitflip_206" and (fault.target_pack in (None, name)) and payload:
                mut = bytearray(payload)
                mut[-1] ^= 0xFF
                payload = bytes(mut)
            elif fault.mode == "truncate_206" and (fault.target_pack in (None, name)) and len(payload) > 4:
                payload = payload[:-4]
            handler.send_response(HTTPStatus.PARTIAL_CONTENT)
            handler.send_header("Accept-Ranges", "bytes")
            handler.send_header("ETag", f'"{effective_etag}"')
            handler.send_header("Content-Range", f"bytes {start}-{end}/{len(blob)}")
            handler.send_header("Content-Length", str(announced_len))
            if len(payload) < announced_len:
                handler.send_header("Connection", "close")
                handler.close_connection = True
            handler.end_headers()
            handler.wfile.write(payload)
            with self.telemetry.lock:
                self.telemetry.range_gets += 1
                self.telemetry.bytes_sent += len(payload)
            return

        handler.send_response(HTTPStatus.OK)
        handler.send_header("Accept-Ranges", "bytes")
        handler.send_header("ETag", f'"{effective_etag}"')
        handler.send_header("Content-Length", str(len(blob)))
        handler.end_headers()
        handler.wfile.write(blob)
        with self.telemetry.lock:
            self.telemetry.full_gets += 1
            self.telemetry.bytes_sent += len(blob)


class GarageS3Client:
    """Minimal stdlib AWS SigV4 path-style S3 client for `owned_garage_fixture.sh` Range 206 verification."""

    def __init__(self, endpoint: str, bucket: str, region: str, access_key: str, secret_key: str) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.bucket = bucket
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key

    @classmethod
    def from_env_file(cls, path: Path) -> "GarageS3Client":
        values: dict[str, str] = {}
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip().strip("'\"")
        req = (
            "ROOTYARD_OBJECT_STORE_ENDPOINT",
            "ROOTYARD_OBJECT_STORE_BUCKET",
            "ROOTYARD_OBJECT_STORE_REGION",
            "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
            "ROOTYARD_OBJECT_STORE_SECRET_KEY",
        )
        missing = [k for k in req if not values.get(k)]
        if missing:
            raise RuntimeError(f"missing Garage S3 env keys: {missing}")
        return cls(values[req[0]], values[req[1]], values[req[2]], values[req[3]], values[req[4]])

    def _signed_request(
        self, method: str, key: str, body: bytes = b"", extra_headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], bytes]:
        now = dt.datetime.now(dt.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        parsed = urllib.parse.urlsplit(self.endpoint)
        host = parsed.netloc
        canon_uri = "/" + urllib.parse.quote(f"{self.bucket}/{key.lstrip('/')}", safe="/~_-.")
        payload_hash = hashlib.sha256(body).hexdigest()
        hdrs: dict[str, str] = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        for hk, hv in (extra_headers or {}).items():
            hdrs[hk.lower()] = hv
        signed_names = sorted(hdrs)
        canon_hdrs = "".join(f"{k}:{hdrs[k]}\n" for k in signed_names)
        signed_hdrs = ";".join(signed_names)
        canon_req = f"{method}\n{canon_uri}\n\n{canon_hdrs}\n{signed_hdrs}\n{payload_hash}"
        scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canon_req.encode()).hexdigest()}"

        def _h(k: bytes, m: str) -> bytes:
            return hmac.new(k, m.encode("utf-8"), hashlib.sha256).digest()

        k_signing = _h(_h(_h(_h(b"AWS4" + self.secret_key.encode("utf-8"), date_stamp), self.region), "s3"), "aws4_request")
        sig = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        auth = f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, SignedHeaders={signed_hdrs}, Signature={sig}"
        req_hdrs = {**hdrs, "Authorization": auth}
        req = urllib.request.Request(f"{self.endpoint}{canon_uri}", data=body if method == "PUT" else None, method=method, headers=req_hdrs)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
        except urllib.error.HTTPError as err:
            return err.code, {k.lower(): v for k, v in err.headers.items()}, err.read()

    def put_object(self, key: str, data: bytes) -> str:
        status, hdrs, _ = self._signed_request("PUT", key, data)
        if status not in (200, 201):
            raise RuntimeError(f"S3 PUT failed ({status}) for {key}")
        return hdrs.get("etag", "").strip('"')

    def get_range(self, key: str, start: int, end: int, if_match: str | None = None) -> tuple[int, dict[str, str], bytes]:
        extra = {"Range": f"bytes={start}-{end}"}
        if if_match:
            extra["If-Match"] = f'"{if_match}"'
        return self._signed_request("GET", key, b"", extra)
