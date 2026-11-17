"""Stock-Git SHA-1 and SHA-256 multi-pack and cross-pack thin-delta fixture generator."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
import subprocess
import zlib

from .git_pack_codec import (
    IDX_MAGIC,
    TYPE_NAMES,
    FailClosedError,
    HashAlgo,
    MultiPackIndex,
    PackIndex,
    apply_git_delta,
    decode_pack_entry_header,
    hash_bytes,
    hash_len_for,
)


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


def _git(repo: Path, *args: str, stdin_bytes: bytes | None = None) -> bytes:
    res = subprocess.run(["git", "-C", str(repo), *args], input=stdin_bytes, check=True, capture_output=True)
    return res.stdout


def build_real_git_fixtures(work_dir: Path, algo: HashAlgo, scale: str = "quick") -> RepoArtifactSet:
    """Create real stock-Git SHA-1 or SHA-256 multi-pack repository + cross-pack thin delta."""
    repo = work_dir / f"repo_{algo}"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", f"--object-format={algo}", str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.name", "pando-eval")
    _git(repo, "config", "user.email", "pando-eval@example.invalid")

    commit_count = 6 if scale == "quick" else 16
    file_count = 16 if scale == "quick" else 40
    blob_unit = 4096 if scale == "quick" else 24576
    commits: list[str] = []

    def _diverse_text(fidx: int) -> bytes:
        chunk_rows = blob_unit // 64
        lines = [f"{fidx:03d}:{r:04d}:{hashlib.sha256(f'{fidx}:{r}'.encode()).hexdigest()[:48]}\n" for r in range(chunk_rows)]
        return "".join(lines).encode("utf-8")

    mid = max(2, commit_count // 2)
    for idx in range(commit_count):
        if idx == 0:
            for fidx in range(file_count):
                sub = repo / f"dir_{fidx % 4}"
                sub.mkdir(exist_ok=True)
                tag = f"base-file-{fidx}\n".encode("utf-8")
                (sub / f"asset_{fidx:03d}.txt").write_bytes(_diverse_text(fidx) + tag * 4)
            # Incompressible unique binary assets to represent realistic multi-pack archive weight.
            bin_blocks = 8 if scale == "quick" else 256
            bin_payload = b"".join(hashlib.sha256(f"media:{i}".encode()).digest() * 16 for i in range(bin_blocks))
            (repo / "media.bin").write_bytes(bin_payload)
        else:
            fidx = idx % file_count
            target = repo / f"dir_{fidx % 4}" / f"asset_{fidx:03d}.txt"
            target.write_bytes(_diverse_text(fidx) + f"revision-{idx}-delta-tail\n".encode("utf-8"))
        _git(repo, "add", "-A")
        _git(repo, "commit", "-m", f"commit-{idx}")
        commits.append(_git(repo, "rev-parse", "HEAD").decode().strip())

    base_commit = commits[mid - 1]
    tip_commit = commits[-1]
    _git(repo, "repack", "-a", "-d", "--write-midx")
    thin_bytes = _git(repo, "pack-objects", "--revs", "--thin", "--stdout", stdin_bytes=f"{tip_commit}\n^{base_commit}\n".encode())
    thin_name = f"pack-thin-{hash_bytes(algo, thin_bytes).hex()[:16]}.pack"
    _git(repo, "fsck", "--full", "--strict")

    pack_dir = repo / ".git" / "objects" / "pack"
    pack_bytes: dict[str, bytes] = {}
    idx_bytes: dict[str, bytes] = {}
    idx_parsed: dict[str, PackIndex] = {}
    for pf in sorted(pack_dir.glob("*.pack")):
        pb = pf.read_bytes()
        ib = pf.with_suffix(".idx").read_bytes()
        pack_bytes[pf.name] = pb
        idx_bytes[pf.name] = ib
        idx_parsed[pf.name] = PackIndex.parse(pf.name, ib, len(pb), algo)

    delta_oids, delta_bases, thin_idx_bytes = _index_thin_pack(repo, thin_bytes, algo)
    pack_bytes[thin_name] = thin_bytes
    idx_bytes[thin_name] = thin_idx_bytes
    idx_parsed[thin_name] = PackIndex.parse(thin_name, thin_idx_bytes, len(thin_bytes), algo)

    midx_path = pack_dir / "multi-pack-index"
    midx_raw = midx_path.read_bytes() if midx_path.exists() else None
    midx_obj = MultiPackIndex.parse(midx_raw, algo) if midx_raw else None

    rev_objects = _git(repo, "rev-list", "--objects", "--all").decode("utf-8").splitlines()
    all_oids = [line.split(" ", 1)[0] for line in rev_objects if line]
    sparse_blobs = [
        line.split(" ", 1)[0] for line in rev_objects if " " in line and line.split(" ", 1)[1].startswith("dir_")
    ][:8]
    tree_root_oid = _git(repo, "rev-parse", f"{tip_commit}^{{tree}}").decode().strip()

    return RepoArtifactSet(
        algo=algo,
        tenant_id="tenant-alpha",
        repo_id=f"repo-{algo}-{scale}",
        history_incarnation="hist-0001",
        membership_version=1,
        pack_bytes=pack_bytes,
        idx_bytes=idx_bytes,
        idx_parsed=idx_parsed,
        midx_bytes=midx_raw,
        midx_parsed=midx_obj,
        commit_oids=commits,
        sparse_blob_oids=sparse_blobs,
        cross_pack_delta_oids=delta_oids,
        all_oids=all_oids,
        tree_root_oid=tree_root_oid,
        cross_pack_delta_bases=delta_bases,
    )


def _index_thin_pack(repo: Path, thin_bytes: bytes, algo: HashAlgo) -> tuple[list[str], dict[str, str], bytes]:
    hlen = hash_len_for(algo)
    ver, count = struct.unpack(">II", thin_bytes[4:12])
    assert ver == 2
    pos = 12
    records: list[tuple[bytes, int, int]] = []
    delta_oids: list[str] = []
    delta_bases: dict[str, str] = {}
    temp_resolved: dict[int, tuple[str, bytes]] = {}
    for _ in range(count):
        start = pos
        otype, _sz, hlen_hdr, boff, boid = decode_pack_entry_header(thin_bytes[pos:], pos, algo)
        pos += hlen_hdr
        decomp = zlib.decompressobj()
        raw = decomp.decompress(thin_bytes[pos:])
        pos += len(thin_bytes[pos:]) - len(decomp.unused_data)
        crc = zlib.crc32(thin_bytes[start:pos]) & 0xFFFFFFFF
        if otype in TYPE_NAMES:
            obj_type, obj_raw = TYPE_NAMES[otype], raw
        elif otype == 6 and boff is not None:
            obj_type, base_raw = temp_resolved[boff]
            obj_raw = apply_git_delta(base_raw, raw)
        elif otype == 7 and boid is not None:
            obj_type = _git(repo, "cat-file", "-t", boid).decode().strip()
            base_raw = _git(repo, "cat-file", obj_type, boid)
            obj_raw = apply_git_delta(base_raw, raw)
        else:
            raise FailClosedError("invalid_index", "unexpected thin entry")
        oid_raw = hash_bytes(algo, f"{obj_type} {len(obj_raw)}\0".encode("ascii") + obj_raw)
        if otype == 7 and obj_type == "blob" and boid is not None:
            oid_hex = oid_raw.hex()
            delta_oids.append(oid_hex)
            delta_bases[oid_hex] = boid
        temp_resolved[start] = (obj_type, obj_raw)
        records.append((oid_raw, start, crc))
    return delta_oids, delta_bases, _encode_idx_v2(records, thin_bytes[-hlen:], algo)


def _encode_idx_v2(records: list[tuple[bytes, int, int]], pack_sha: bytes, algo: HashAlgo) -> bytes:
    records_sorted = sorted(records, key=lambda r: r[0])
    fanout = [0] * 256
    for oid_raw, _, _ in records_sorted:
        for b in range(oid_raw[0], 256):
            fanout[b] += 1
    out = bytearray(IDX_MAGIC + struct.pack(">I", 2) + struct.pack(">256I", *fanout))
    for oid_raw, _, _ in records_sorted:
        out.extend(oid_raw)
    for _, _, crc in records_sorted:
        out.extend(struct.pack(">I", crc))
    for _, off, _ in records_sorted:
        assert off < 0x80000000
        out.extend(struct.pack(">I", off))
    out.extend(pack_sha)
    out.extend(hash_bytes(algo, bytes(out)))
    return bytes(out)
