"""Real stock-Git pack, .idx v2, MIDX v1, thin-delta, and identity codec."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Callable, Literal

HashAlgo = Literal["sha1", "sha256"]
TYPE_NAMES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
IDX_MAGIC = b"\xfftOc"
MIDX_MAGIC = b"MIDX"
MAX_DELTA_DEPTH = 50


class FailClosedError(RuntimeError):
    """Typed fail-closed error: partial or unverified object bytes are never returned."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PackObjectSpan:
    oid_hex: str
    pack_name: str
    offset: int
    next_offset: int
    crc32: int | None


def hash_len_for(algo: HashAlgo) -> int:
    return 20 if algo == "sha1" else 32


def hash_bytes(algo: HashAlgo, data: bytes) -> bytes:
    return hashlib.sha1(data).digest() if algo == "sha1" else hashlib.sha256(data).digest()


def verify_git_object(algo: HashAlgo, obj_type: str, payload: bytes, expected_oid_hex: str) -> None:
    if obj_type not in ("commit", "tree", "blob", "tag"):
        raise FailClosedError("object_identity_mismatch", f"unsupported type {obj_type!r}")
    header = f"{obj_type} {len(payload)}\0".encode("ascii")
    actual_hex = hash_bytes(algo, header + payload).hex()
    if actual_hex != expected_oid_hex:
        raise FailClosedError(
            "object_identity_mismatch",
            f"expected {expected_oid_hex} got {actual_hex}",
        )


def decode_pack_entry_header(buf: bytes, entry_offset: int, algo: HashAlgo) -> tuple[int, int, int, int | None, str | None]:
    """Decode `(obj_type, uncompressed_size, payload_pos, base_offset, base_oid_hex)`."""
    if not buf:
        raise FailClosedError("truncated_range", "empty pack entry buffer")
    pos = 0
    first = buf[pos]
    pos += 1
    obj_type = (first >> 4) & 0x07
    size = first & 0x0F
    shift = 4
    while first & 0x80:
        if pos >= len(buf):
            raise FailClosedError("truncated_range", "truncated entry size varint")
        first = buf[pos]
        pos += 1
        size |= (first & 0x7F) << shift
        shift += 7
    base_offset: int | None = None
    base_oid_hex: str | None = None
    if obj_type == 6:  # OBJ_OFS_DELTA
        if pos >= len(buf):
            raise FailClosedError("truncated_range", "truncated ofs-delta header")
        c = buf[pos]
        pos += 1
        neg = c & 0x7F
        while c & 0x80:
            if pos >= len(buf):
                raise FailClosedError("truncated_range", "truncated ofs-delta varint")
            c = buf[pos]
            pos += 1
            neg = ((neg + 1) << 7) | (c & 0x7F)
        base_offset = entry_offset - neg
        if base_offset < 12 or base_offset >= entry_offset:
            raise FailClosedError("invalid_index", f"illegal ofs-delta base offset {base_offset}")
    elif obj_type == 7:  # OBJ_REF_DELTA
        hlen = hash_len_for(algo)
        if pos + hlen > len(buf):
            raise FailClosedError("truncated_range", "truncated ref-delta base OID")
        base_oid_hex = buf[pos : pos + hlen].hex()
        pos += hlen
    elif obj_type not in TYPE_NAMES:
        raise FailClosedError("corrupt_checksum", f"invalid pack object type {obj_type}")
    return obj_type, size, pos, base_offset, base_oid_hex


def _delta_size(delta: bytes, pos: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while True:
        if pos >= len(delta):
            raise FailClosedError("truncated_range", "truncated delta size header")
        b = delta[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return val, pos


def apply_git_delta(base_raw: bytes, delta: bytes) -> bytes:
    """Reconstruct target object bytes from base + Git binary delta stream."""
    src_len, pos = _delta_size(delta, 0)
    if src_len != len(base_raw):
        raise FailClosedError("object_identity_mismatch", f"delta src_len {src_len} != base {len(base_raw)}")
    tgt_len, pos = _delta_size(delta, pos)
    out = bytearray()
    while pos < len(delta):
        cmd = delta[pos]
        pos += 1
        if cmd & 0x80:
            cp_off, cp_size = 0, 0
            for i in range(4):
                if cmd & (1 << i):
                    if pos >= len(delta):
                        raise FailClosedError("truncated_range", "truncated delta copy offset")
                    cp_off |= delta[pos] << (8 * i)
                    pos += 1
            for i in range(3):
                if cmd & (1 << (4 + i)):
                    if pos >= len(delta):
                        raise FailClosedError("truncated_range", "truncated delta copy size")
                    cp_size |= delta[pos] << (8 * i)
                    pos += 1
            if cp_size == 0:
                cp_size = 0x10000
            if cp_off + cp_size > len(base_raw):
                raise FailClosedError("object_identity_mismatch", "delta copy out of base bounds")
            out.extend(base_raw[cp_off : cp_off + cp_size])
        elif cmd > 0:
            if pos + cmd > len(delta):
                raise FailClosedError("truncated_range", "truncated delta insert payload")
            out.extend(delta[pos : pos + cmd])
            pos += cmd
        else:
            raise FailClosedError("corrupt_checksum", "illegal zero delta opcode")
    if len(out) != tgt_len:
        raise FailClosedError("object_identity_mismatch", f"delta output {len(out)} != target {tgt_len}")
    return bytes(out)


class PackIndex:
    """Parser for Git pack `.idx` v2 supporting SHA-1 and SHA-256 with exact next-offset spans."""

    def __init__(
        self,
        pack_name: str,
        algo: HashAlgo,
        entries: dict[str, PackObjectSpan],
        by_offset: dict[int, PackObjectSpan],
        pack_size: int,
    ) -> None:
        self.pack_name = pack_name
        self.algo = algo
        self.entries = entries
        self.by_offset = by_offset
        self.pack_size = pack_size

    @classmethod
    def parse(cls, pack_name: str, idx_bytes: bytes, pack_size: int, algo: HashAlgo) -> "PackIndex":
        hlen = hash_len_for(algo)
        if len(idx_bytes) < 8 + 256 * 4 + 2 * hlen or idx_bytes[:4] != IDX_MAGIC:
            raise FailClosedError("invalid_index", f"{pack_name}: missing v2 magic")
        version = struct.unpack(">I", idx_bytes[4:8])[0]
        if version != 2:
            raise FailClosedError("invalid_index", f"{pack_name}: unsupported idx version {version}")
        if hash_bytes(algo, idx_bytes[:-hlen]) != idx_bytes[-hlen:]:
            raise FailClosedError("corrupt_checksum", f"{pack_name}: idx trailing checksum mismatch")
        fanout = struct.unpack(">256I", idx_bytes[8 : 8 + 1024])
        count = fanout[255]
        oid_off = 8 + 1024
        crc_off = oid_off + count * hlen
        off4_off = crc_off + count * 4
        large_off = off4_off + count * 4
        min_len = large_off + 2 * hlen
        if len(idx_bytes) < min_len:
            raise FailClosedError("invalid_index", f"{pack_name}: truncated idx body")
        raw_items: list[tuple[str, int, int]] = []
        for i in range(count):
            oid_hex = idx_bytes[oid_off + i * hlen : oid_off + (i + 1) * hlen].hex()
            crc = struct.unpack(">I", idx_bytes[crc_off + i * 4 : crc_off + (i + 1) * 4])[0]
            o4 = struct.unpack(">I", idx_bytes[off4_off + i * 4 : off4_off + (i + 1) * 4])[0]
            if o4 & 0x80000000:
                lidx = o4 & 0x7FFFFFFF
                lpos = large_off + lidx * 8
                if lpos + 8 > len(idx_bytes) - 2 * hlen:
                    raise FailClosedError("invalid_index", f"{pack_name}: out-of-bounds large offset")
                offset = struct.unpack(">Q", idx_bytes[lpos : lpos + 8])[0]
            else:
                offset = o4
            raw_items.append((oid_hex, offset, crc))
        sorted_offsets = sorted(item[1] for item in raw_items)
        pack_data_end = pack_size - hlen
        next_map: dict[int, int] = {}
        for idx_pos, off in enumerate(sorted_offsets):
            nxt = sorted_offsets[idx_pos + 1] if idx_pos + 1 < len(sorted_offsets) else pack_data_end
            if nxt <= off or nxt > pack_data_end:
                raise FailClosedError("invalid_index", f"{pack_name}: invalid object span [{off}, {nxt})")
            next_map[off] = nxt
        entries: dict[str, PackObjectSpan] = {}
        by_offset: dict[int, PackObjectSpan] = {}
        for oid_hex, off, crc in raw_items:
            span = PackObjectSpan(oid_hex=oid_hex, pack_name=pack_name, offset=off, next_offset=next_map[off], crc32=crc)
            entries[oid_hex] = span
            by_offset[off] = span
        return cls(pack_name=pack_name, algo=algo, entries=entries, by_offset=by_offset, pack_size=pack_size)


class MultiPackIndex:
    """Parser for Git `multi-pack-index` (MIDX v1) supporting SHA-1 and SHA-256."""

    def __init__(self, algo: HashAlgo, pack_names: list[str], mapping: dict[str, tuple[str, int]]) -> None:
        self.algo = algo
        self.pack_names = pack_names
        self.mapping = mapping

    @classmethod
    def parse(cls, midx_bytes: bytes, expected_algo: HashAlgo) -> "MultiPackIndex":
        hlen = hash_len_for(expected_algo)
        if len(midx_bytes) < 12 + hlen or midx_bytes[:4] != MIDX_MAGIC:
            raise FailClosedError("invalid_index", "missing MIDX magic")
        version, hash_ver, chunk_cnt, _base_cnt, pack_cnt = struct.unpack(">BBBBI", midx_bytes[4:12])
        expected_hash_ver = 1 if expected_algo == "sha1" else 2
        if version != 1 or hash_ver != expected_hash_ver:
            raise FailClosedError("invalid_index", f"MIDX version/hash mismatch ({version}, {hash_ver})")
        if hash_bytes(expected_algo, midx_bytes[:-hlen]) != midx_bytes[-hlen:]:
            raise FailClosedError("corrupt_checksum", "MIDX trailing checksum mismatch")
        chunks: dict[bytes, bytes] = {}
        table_pos = 12
        entries_raw: list[tuple[bytes, int]] = []
        for _ in range(chunk_cnt + 1):
            cid, off = struct.unpack(">4sQ", midx_bytes[table_pos : table_pos + 12])
            entries_raw.append((cid, off))
            table_pos += 12
        for i in range(chunk_cnt):
            cid, start = entries_raw[i]
            _, end = entries_raw[i + 1]
            chunks[cid] = midx_bytes[start:end]
        for req in (b"PNAM", b"OIDF", b"OIDL", b"OOFF"):
            if req not in chunks:
                raise FailClosedError("invalid_index", f"MIDX missing chunk {req!r}")
        raw_names = [p.decode("utf-8") for p in chunks[b"PNAM"].split(b"\x00") if p]
        if len(raw_names) != pack_cnt:
            raise FailClosedError("invalid_index", "MIDX PNAM count != pack_count")
        pack_names = [n[:-4] + ".pack" if n.endswith(".idx") else n for n in raw_names]
        fanout = struct.unpack(">256I", chunks[b"OIDF"][:1024])
        count = fanout[255]
        oidl, ooff, loff = chunks[b"OIDL"], chunks[b"OOFF"], chunks.get(b"LOFF", b"")
        mapping: dict[str, tuple[str, int]] = {}
        for i in range(count):
            oid_hex = oidl[i * hlen : (i + 1) * hlen].hex()
            pidx, raw_off = struct.unpack(">II", ooff[i * 8 : (i + 1) * 8])
            if pidx >= len(pack_names):
                raise FailClosedError("invalid_index", "MIDX invalid pack_int_id")
            if raw_off & 0x80000000:
                lidx = raw_off & 0x7FFFFFFF
                off = struct.unpack(">Q", loff[lidx * 8 : (lidx + 1) * 8])[0]
            else:
                off = raw_off
            mapping[oid_hex] = (pack_names[pidx], off)
        return cls(algo=expected_algo, pack_names=pack_names, mapping=mapping)


@dataclass
class RepoArtifactSet:
    algo: HashAlgo
    tenant_id: str
    repo_id: str
    history_incarnation: str
    membership_version: int
    pack_bytes: dict[str, bytes]
    idx_bytes: dict[str, bytes]
    idx_parsed: dict[str, PackIndex]
    midx_bytes: bytes | None
    midx_parsed: MultiPackIndex | None
    commit_oids: list[str]
    sparse_blob_oids: list[str]
    cross_pack_delta_oids: list[str]
    all_oids: list[str]
    tree_root_oid: str
    cross_pack_delta_bases: dict[str, str]


def parse_git_tree_entries(tree_raw: bytes, algo: HashAlgo) -> list[tuple[str, str, str]]:
    """Parse raw binary Git tree into `(mode, name, oid_hex)` tuples."""
    hlen = hash_len_for(algo)
    pos = 0
    entries: list[tuple[str, str, str]] = []
    while pos < len(tree_raw):
        sp = tree_raw.find(b" ", pos)
        nul = tree_raw.find(b"\x00", sp + 1 if sp >= 0 else pos)
        if sp < 0 or nul < 0 or nul + 1 + hlen > len(tree_raw):
            raise FailClosedError("corrupt_checksum", "malformed Git tree entry")
        mode = tree_raw[pos:sp].decode("ascii")
        name = tree_raw[sp + 1 : nul].decode("utf-8", errors="replace")
        oid_hex = tree_raw[nul + 1 : nul + 1 + hlen].hex()
        entries.append((mode, name, oid_hex))
        pos = nul + 1 + hlen
    return entries


def verify_commit_closure(
    fetch_object: Callable[[str], tuple[str, bytes]],
    algo: HashAlgo,
    commit_oid: str,
    max_nodes: int = 4096,
) -> int:
    """Verify full commit + tree + blob closure via `fetch_object`; fails closed on any gap."""
    otype, c_raw = fetch_object(commit_oid)
    if otype != "commit":
        raise FailClosedError("incomplete_closure", f"expected commit {commit_oid}, got {otype}")
    tree_line = next((ln for ln in c_raw.decode("utf-8", errors="strict").splitlines() if ln.startswith("tree ")), None)
    if tree_line is None:
        raise FailClosedError("incomplete_closure", f"commit {commit_oid} lacks tree")
    stack = [tree_line.split(" ", 1)[1].strip()]
    seen: set[str] = {commit_oid}
    while stack:
        tree_oid = stack.pop()
        if tree_oid in seen:
            continue
        seen.add(tree_oid)
        if len(seen) > max_nodes:
            raise FailClosedError("incomplete_closure", "closure exceeded bounded limit")
        ttype, traw = fetch_object(tree_oid)
        if ttype != "tree":
            raise FailClosedError("incomplete_closure", f"expected tree {tree_oid}, got {ttype}")
        for mode, _name, child_oid in parse_git_tree_entries(traw, algo):
            if mode == "40000":
                stack.append(child_oid)
            elif mode == "160000":
                continue  # gitlink submodule
            elif child_oid not in seen:
                seen.add(child_oid)
                btype, _braw = fetch_object(child_oid)
                if btype != "blob":
                    raise FailClosedError("incomplete_closure", f"expected blob {child_oid}, got {btype}")
    return len(seen)

