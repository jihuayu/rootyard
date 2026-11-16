"""Range-read client, #163-style full-pack cached client, and metric collectors."""
from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import json
from pathlib import Path
import time
import urllib.parse
import zlib

from .fixture_builder import RepoArtifactSet
from .git_pack_codec import (
    MAX_DELTA_DEPTH,
    TYPE_NAMES,
    FailClosedError,
    PackIndex,
    PackObjectSpan,
    apply_git_delta,
    decode_pack_entry_header,
    hash_bytes,
    hash_len_for,
    verify_commit_closure,
    verify_git_object,
)


@dataclass
class RunCounters:
    get_requests_full: int = 0
    get_requests_range: int = 0
    bytes_downloaded: int = 0
    logical_bytes: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def total_gets(self) -> int:
        return self.get_requests_full + self.get_requests_range

    def amplification(self) -> float:
        if self.logical_bytes <= 0:
            return 0.0
        return round(self.bytes_downloaded / self.logical_bytes, 4)


class _BaseHttpClient:
    def __init__(
        self,
        base_url: str,
        artifacts: RepoArtifactSet,
        token: str,
        scratch_dir: Path,
        tenant_override: str | None = None,
        repo_override: str | None = None,
        history_override: str | None = None,
        membership_override: int | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or 80
        self.artifacts = artifacts
        self.tenant = tenant_override or artifacts.tenant_id
        self.repo = repo_override or artifacts.repo_id
        self.history = history_override or artifacts.history_incarnation
        self.membership = membership_override if membership_override is not None else artifacts.membership_version
        self.token = token
        self.scratch_dir = scratch_dir
        self.scratch_dir.mkdir(parents=True, exist_ok=True)
        self.counters = RunCounters()

    def _http_get(self, path: str, headers: dict[str, str] | None = None, count_as: str = "range") -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5.0)
        hdrs = {"Authorization": f"Bearer {self.token}", "Connection": "close"}
        if headers:
            hdrs.update(headers)
        try:
            conn.request("GET", path, headers=hdrs)
            resp = conn.getresponse()
            try:
                body = resp.read()
            except http.client.IncompleteRead as exc:
                raise FailClosedError("truncated_range", f"short HTTP body ({len(exc.partial)} bytes)") from exc
            resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_hdrs, body
        finally:
            conn.close()

    def verify_auth_and_realm(self) -> None:
        path = f"/v1/repos/{self.tenant}/{self.repo}/auth-check"
        status, _hdrs, body = self._http_get(path, count_as="auth")
        if status in (401, 403):
            raise FailClosedError("unauthorized", "principal token revoked or unauthorized")
        if status != 200:
            raise FailClosedError("unauthorized", f"auth check returned HTTP {status}")
        data = json.loads(body.decode("utf-8"))
        if data.get("history") != self.history:
            raise FailClosedError("history_drift", f"bound {self.history} != live {data.get('history')}")
        if data.get("membership") != self.membership:
            raise FailClosedError("membership_drift", f"bound {self.membership} != live {data.get('membership')}")

    def _artifact_path(self, kind: str, name: str) -> str:
        return f"/v1/repos/{self.tenant}/{self.repo}/history/{self.history}/membership/{self.membership}/{kind}/{name}"

    def scratch_disk_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.scratch_dir.rglob("*") if p.is_file())


class RangeReadClient(_BaseHttpClient):
    """OID -> .idx/MIDX byte-range client with CRC32, decompression, delta, and hash verification."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.indices: dict[str, PackIndex] = {}
        self.oid_map: dict[str, str] = {}
        self.etags: dict[str, str] = {}
        self.object_cache: dict[str, tuple[str, bytes]] = {}
        self.span_cache: dict[tuple[str, int], PackObjectSpan] = {}

    def load_indices(self, verify_etags: dict[str, str] | None = None) -> None:
        self.verify_auth_and_realm()
        for pname in sorted(self.artifacts.idx_bytes):
            idx_cache = self.scratch_dir / f"{pname}.idx"
            if not idx_cache.exists():
                status, hdrs, data = self._http_get(self._artifact_path("idx", pname))
                if status == 403:
                    raise FailClosedError("unauthorized", "denied reading index")
                if status == 409:
                    raise FailClosedError("membership_drift", "realm drift on index GET")
                if status != 200:
                    raise FailClosedError("invalid_index", f"index GET HTTP {status}")
                self.counters.get_requests_full += 1
                self.counters.bytes_downloaded += len(data)
                idx_cache.write_bytes(data)
                self.etags[pname] = hdrs.get("etag", "").strip('"')
            else:
                data = idx_cache.read_bytes()
            pack_len = len(self.artifacts.pack_bytes[pname])
            parsed = PackIndex.parse(pname, data, pack_len, self.artifacts.algo)
            self.indices[pname] = parsed
            for oid_hex, span in parsed.entries.items():
                self.oid_map[oid_hex] = pname
                self.span_cache[(pname, span.offset)] = span
            if verify_etags and pname in verify_etags:
                self.etags[pname] = verify_etags[pname]

    def fetch_object(self, oid_hex: str, *, verify_closure: bool = False) -> tuple[str, bytes]:
        t0 = time.perf_counter()
        self.verify_auth_and_realm()
        res = self._resolve_object(oid_hex, depth=0, seen=set())
        if verify_closure and res[0] == "commit":
            verify_commit_closure(lambda child: self._resolve_object(child, depth=0, seen=set()), self.artifacts.algo, oid_hex)
        self.counters.logical_bytes += len(res[1])
        self.counters.latencies_ms.append((time.perf_counter() - t0) * 1000.0)
        return res

    def _fetch_range_span(self, pack_name: str, start: int, end_inclusive: int) -> bytes:
        expected_len = end_inclusive - start + 1
        req_hdrs = {"Range": f"bytes={start}-{end_inclusive}"}
        if pack_name in self.etags:
            req_hdrs["If-Match"] = f'"{self.etags[pack_name]}"'
        status, hdrs, body = self._http_get(self._artifact_path("packs", pack_name), headers=req_hdrs)
        if status == 403:
            raise FailClosedError("unauthorized", "denied reading pack range")
        if status == 409:
            raise FailClosedError("membership_drift", "realm changed before range GET")
        if status == 410:
            raise FailClosedError("pin_evicted", f"pack {pack_name} swept/evicted")
        if status == 412:
            raise FailClosedError("corrupt_checksum", f"ETag If-Match mismatch for {pack_name}")
        if status != 206:
            raise FailClosedError("truncated_range", f"expected 206 Partial Content, got HTTP {status}")
        cr = hdrs.get("content-range", "")
        if not cr.startswith(f"bytes {start}-{end_inclusive}/"):
            raise FailClosedError("truncated_range", f"unexpected Content-Range {cr!r}")
        if len(body) != expected_len:
            raise FailClosedError("truncated_range", f"expected {expected_len} bytes, received {len(body)}")
        self.counters.get_requests_range += 1
        self.counters.bytes_downloaded += len(body)
        return body

    def _resolve_object(self, oid_hex: str, depth: int, seen: set[tuple[str, int]]) -> tuple[str, bytes]:
        if oid_hex in self.object_cache:
            return self.object_cache[oid_hex]
        pack_name = self.oid_map.get(oid_hex)
        if not pack_name:
            raise FailClosedError("missing_object", f"OID {oid_hex} absent from index")
        span = self.indices[pack_name].entries[oid_hex]
        res = self._resolve_span(span, expected_oid=oid_hex, depth=depth, seen=seen)
        self.object_cache[oid_hex] = res
        return res

    def _resolve_span(
        self,
        span: PackObjectSpan,
        expected_oid: str | None,
        depth: int,
        seen: set[tuple[str, int]],
    ) -> tuple[str, bytes]:
        if depth > MAX_DELTA_DEPTH:
            raise FailClosedError("invalid_index", "delta chain depth exceeded limit")
        key = (span.pack_name, span.offset)
        if key in seen:
            raise FailClosedError("invalid_index", f"delta cycle at {key}")
        seen = seen | {key}
        raw_entry = self._fetch_range_span(span.pack_name, span.offset, span.next_offset - 1)
        if span.crc32 is not None and (zlib.crc32(raw_entry) & 0xFFFFFFFF) != span.crc32:
            raise FailClosedError("corrupt_checksum", f"CRC32 mismatch at {span.pack_name}:{span.offset}")
        otype, expected_sz, hdr_len, base_off, base_oid = decode_pack_entry_header(
            raw_entry, span.offset, self.artifacts.algo
        )
        comp = raw_entry[hdr_len:]
        decomp = zlib.decompressobj()
        try:
            payload = decomp.decompress(comp) + decomp.flush()
        except zlib.error as exc:
            raise FailClosedError("corrupt_checksum", f"zlib decode error: {exc}") from exc
        if not decomp.eof or decomp.unused_data or len(payload) != expected_sz:
            raise FailClosedError("corrupt_checksum", "decompressed stream mismatch")
        if otype in TYPE_NAMES:
            obj_type, obj_raw = TYPE_NAMES[otype], payload
        elif otype == 6 and base_off is not None:
            base_span = self.span_cache.get((span.pack_name, base_off))
            if base_span is None:
                raise FailClosedError("missing_delta_base", f"missing ofs-delta base {base_off}")
            obj_type, base_raw = self._resolve_span(base_span, None, depth + 1, seen)
            obj_raw = apply_git_delta(base_raw, payload)
        elif otype == 7 and base_oid is not None:
            if base_oid not in self.oid_map:
                raise FailClosedError("missing_delta_base", f"missing cross-pack delta base {base_oid}")
            obj_type, base_raw = self._resolve_object(base_oid, depth + 1, seen)
            obj_raw = apply_git_delta(base_raw, payload)
        else:
            raise FailClosedError("corrupt_checksum", "invalid delta entry")
        if expected_oid is not None:
            verify_git_object(self.artifacts.algo, obj_type, obj_raw, expected_oid)
        return obj_type, obj_raw


class FullPackCachedClient(_BaseHttpClient):
    """#163-style full-pack immutable cache baseline (checks auth & realm on every request)."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.indices: dict[str, PackIndex] = {}
        self.oid_map: dict[str, str] = {}
        self.pack_paths: dict[str, Path] = {}

    def _ensure_pack_cached(self, pack_name: str) -> None:
        if pack_name in self.pack_paths and self.pack_paths[pack_name].exists():
            return
        idx_path = self.scratch_dir / f"{pack_name}.idx"
        pack_path = self.scratch_dir / pack_name
        if not idx_path.exists():
            st, _h, idx_raw = self._http_get(self._artifact_path("idx", pack_name))
            if st != 200:
                raise FailClosedError("invalid_index", f"full index GET HTTP {st}")
            self.counters.get_requests_full += 1
            self.counters.bytes_downloaded += len(idx_raw)
            idx_path.write_bytes(idx_raw)
        if not pack_path.exists():
            st, _h, pack_raw = self._http_get(self._artifact_path("packs", pack_name))
            if st == 410:
                raise FailClosedError("pin_evicted", f"pack {pack_name} evicted")
            if st != 200:
                raise FailClosedError("missing_object", f"full pack GET HTTP {st}")
            hlen = hash_len_for(self.artifacts.algo)
            if hash_bytes(self.artifacts.algo, pack_raw[:-hlen]) != pack_raw[-hlen:]:
                raise FailClosedError("corrupt_checksum", f"{pack_name}: full pack checksum mismatch")
            self.counters.get_requests_full += 1
            self.counters.bytes_downloaded += len(pack_raw)
            pack_path.write_bytes(pack_raw)
        pack_len = pack_path.stat().st_size
        parsed = PackIndex.parse(pack_name, idx_path.read_bytes(), pack_len, self.artifacts.algo)
        self.indices[pack_name] = parsed
        self.pack_paths[pack_name] = pack_path
        for oid in parsed.entries:
            self.oid_map[oid] = pack_name

    def fetch_object(self, oid_hex: str) -> tuple[str, bytes]:
        t0 = time.perf_counter()
        self.verify_auth_and_realm()
        for pname in sorted(self.artifacts.pack_bytes):
            self._ensure_pack_cached(pname)
        res = self._read_local_oid(oid_hex, depth=0)
        self.counters.logical_bytes += len(res[1])
        self.counters.latencies_ms.append((time.perf_counter() - t0) * 1000.0)
        return res

    def _read_local_oid(self, oid_hex: str, depth: int) -> tuple[str, bytes]:
        if depth > MAX_DELTA_DEPTH:
            raise FailClosedError("invalid_index", "delta chain depth exceeded")
        pack_name = self.oid_map.get(oid_hex)
        if not pack_name:
            raise FailClosedError("missing_object", f"OID {oid_hex} absent")
        span = self.indices[pack_name].entries[oid_hex]
        res = self._read_local_span(span, depth)
        verify_git_object(self.artifacts.algo, res[0], res[1], oid_hex)
        return res

    def _read_local_span(self, span: PackObjectSpan, depth: int) -> tuple[str, bytes]:
        with self.pack_paths[span.pack_name].open("rb") as fh:
            fh.seek(span.offset)
            entry_raw = fh.read(span.next_offset - span.offset)
        otype, expected_sz, hdr_len, base_off, base_oid = decode_pack_entry_header(
            entry_raw, span.offset, self.artifacts.algo
        )
        payload = zlib.decompress(entry_raw[hdr_len:])
        assert len(payload) == expected_sz
        if otype in TYPE_NAMES:
            return TYPE_NAMES[otype], payload
        if otype == 6 and base_off is not None:
            bspan = self.indices[span.pack_name].by_offset[base_off]
            btype, braw = self._read_local_span(bspan, depth + 1)
            return btype, apply_git_delta(braw, payload)
        if otype == 7 and base_oid is not None:
            btype, braw = self._read_local_oid(base_oid, depth + 1)
            return btype, apply_git_delta(braw, payload)
        raise FailClosedError("corrupt_checksum", "invalid local pack entry")
