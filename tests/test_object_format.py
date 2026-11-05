#!/usr/bin/env python3
"""Unit and contract tests for Track 2 (`F46`, `F47`): Git SHA-256 Object-Format
Compatibility Matrix & Smart HTTP v1/v2 Capability Negotiation.
"""
import hashlib
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]


def _compute_dual_git_oid(obj_type: str, data: bytes) -> tuple[str, str]:
    header = f"{obj_type} {len(data)}\0".encode("ascii")
    raw = header + data
    return hashlib.sha1(raw).hexdigest(), hashlib.sha256(raw).hexdigest()


def _parse_raw_tree(data: bytes, raw_oid_len: int) -> list[tuple[str, str, str]]:
    pos = 0
    entries = []
    while pos < len(data):
        sp = data.index(b" ", pos)
        mode = data[pos:sp].decode("ascii")
        nul = data.index(b"\0", sp + 1)
        name = data[sp + 1 : nul].decode("utf-8")
        oid_end = nul + 1 + raw_oid_len
        if oid_end > len(data):
            raise ValueError("truncated tree entry OID")
        oid = data[nul + 1 : oid_end].hex()
        entries.append((mode, name, oid))
        pos = oid_end
    return entries


def _verify_pack_trailer_and_entries(pack_bytes: bytes, raw_oid_len: int) -> dict:
    if len(pack_bytes) < 12 + raw_oid_len or pack_bytes[:4] != b"PACK":
        raise ValueError("invalid pack header")
    version, obj_count = struct.unpack("!II", pack_bytes[4:12])
    if version != 2:
        raise ValueError(f"unexpected pack version {version}")
    trailer_pos = len(pack_bytes) - raw_oid_len
    trailer = pack_bytes[trailer_pos:]
    expected_trailer = (
        hashlib.sha1(pack_bytes[:trailer_pos]).digest()
        if raw_oid_len == 20
        else hashlib.sha256(pack_bytes[:trailer_pos]).digest()
    )
    if trailer != expected_trailer:
        raise ValueError("pack trailer digest mismatch")
    return {
        "version": version,
        "object_count": obj_count,
        "trailer_hex": trailer.hex(),
        "raw_oid_len": raw_oid_len,
    }


class ObjectFormatContractTest(unittest.TestCase):
    def test_object_format_submodules_and_line_bounds(self) -> None:
        browse_of = ROOT / "src/browse/object_format.rs"
        pando_of = ROOT / "src/pando_lab/object_format.rs"
        browse_rs = ROOT / "src/browse.rs"

        self.assertTrue(browse_of.is_file(), "Missing src/browse/object_format.rs")
        self.assertTrue(pando_of.is_file(), "Missing src/pando_lab/object_format.rs")
        self.assertLess(len(browse_of.read_text(encoding="utf-8").splitlines()), 480)
        self.assertLess(len(pando_of.read_text(encoding="utf-8").splitlines()), 480)
        self.assertLess(len(browse_rs.read_text(encoding="utf-8").splitlines()), 90)
        self.assertFalse((ROOT / "src/browse/mod.rs").exists())

        for path in (ROOT / "src/browse").glob("*.rs"):
            self.assertLess(
                len(path.read_text(encoding="utf-8").splitlines()),
                540,
                f"{path} exceeds 540-line bound",
            )
        for path in (ROOT / "src/pando_lab").glob("*.rs"):
            self.assertLess(
                len(path.read_text(encoding="utf-8").splitlines()),
                840,
                f"{path} exceeds 840-line bound",
            )

        for mod_path in (browse_of, pando_of):
            src = mod_path.read_text(encoding="utf-8")
            self.assertIn("#[serde(deny_unknown_fields)]", src)
            self.assertNotIn("tempfile::", src)

    def test_browse_and_pando_object_format_routes_and_cli_wiring(self) -> None:
        browse_rs = (ROOT / "src/browse.rs").read_text(encoding="utf-8")
        self.assertIn("pub mod object_format;", browse_rs)
        for route in (
            '"/api/repos/{owner}/{name}/object-format"',
            '"/api/repos/{owner}/{name}/object-format/negotiate"',
            '"/api/repos/{owner}/{name}/object-format/drill"',
        ):
            self.assertIn(route, browse_rs)

        browse_of = (ROOT / "src/browse/object_format.rs").read_text(encoding="utf-8")
        for sym in (
            "pub enum ObjectFormat",
            "pub fn detect_oid_format",
            "pub fn valid_oid_for_format",
            "pub fn valid_non_zero_oid_for_format",
            "pub async fn detect_repo_object_format",
            "pub async fn get_object_format",
            "pub async fn negotiate_object_format",
            "pub async fn run_object_format_drill",
        ):
            self.assertIn(sym, browse_of)

        pando_mod = (ROOT / "src/pando_lab/mod.rs").read_text(encoding="utf-8")
        self.assertIn("pub mod object_format;", pando_mod)
        for subcmd in (
            'Some("object-format-detect")',
            'Some("verify-object-format")',
            'Some("compat-matrix")',
        ):
            self.assertIn(subcmd, pando_mod)

        pando_http = (ROOT / "src/pando_lab/http.rs").read_text(encoding="utf-8")
        self.assertIn('tail == "object-format"', pando_http)

        pando_of = (ROOT / "src/pando_lab/object_format.rs").read_text(encoding="utf-8")
        for sym in (
            "pub fn compute_object_oid",
            "pub fn parse_tree_with_format",
            "pub fn parse_commit_with_format",
            "pub fn parse_tag_with_format",
            "pub fn verify_pack_dual_format",
            "pub fn walk_reachable_with_format",
            "run_compat_matrix_drill",
        ):
            self.assertIn(sym, pando_of)

        schema_sql = (ROOT / "experimental/pando/schema.sql").read_text(encoding="utf-8")
        self.assertIn("^[0-9a-f]{40}([0-9a-f]{24})?$", schema_sql)
        self.assertIsNone(re.search(r"\bBETWEEN\b", schema_sql, re.IGNORECASE))
        self.assertIsNone(re.search(r"\b(?:BIG)?SERIAL\b", schema_sql, re.IGNORECASE))

    def test_real_git_sha1_and_sha256_compat_matrix_and_lfs_interop(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rootyard-m25-sha256-") as tmp:
            tmp_path = Path(tmp)
            env = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "GIT_AUTHOR_NAME": "Rootyard Test",
                "GIT_AUTHOR_EMAIL": "test@rootyard.invalid",
                "GIT_COMMITTER_NAME": "Rootyard Test",
                "GIT_COMMITTER_EMAIL": "test@rootyard.invalid",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
            }
            lfs_payload = b"dual-hash-lfs-binary-content-\x00\xff\n" * 64
            lfs_sha256 = hashlib.sha256(lfs_payload).hexdigest()
            pointer_bytes = (
                f"version https://git-lfs.github.com/spec/v1\n"
                f"oid sha256:{lfs_sha256}\n"
                f"size {len(lfs_payload)}\n"
            ).encode("ascii")

            results = {}
            for fmt, hex_len, raw_len in (("sha1", 40, 20), ("sha256", 64, 32)):
                bare = tmp_path / f"bare-{fmt}.git"
                work = tmp_path / f"work-{fmt}"
                subprocess.run(
                    [
                        "git",
                        "init",
                        "--bare",
                        "--initial-branch=main",
                        f"--object-format={fmt}",
                        str(bare),
                    ],
                    env=env,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "git",
                        "init",
                        "--initial-branch=main",
                        f"--object-format={fmt}",
                        str(work),
                    ],
                    env=env,
                    check=True,
                    capture_output=True,
                )
                (work / "src").mkdir()
                (work / "src/lib.rs").write_text("pub fn version() -> u32 { 1 }\n")
                (work / "model.bin").write_bytes(pointer_bytes)
                subprocess.run(["git", "add", "."], cwd=work, env=env, check=True)
                subprocess.run(
                    ["git", "commit", "-m", f"commit in {fmt}"],
                    cwd=work,
                    env=env,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "tag", "-a", "v1.0", "-m", f"tag in {fmt}"],
                    cwd=work,
                    env=env,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "push", str(bare), "HEAD:refs/heads/main", "refs/tags/v1.0"],
                    cwd=work,
                    env=env,
                    check=True,
                    capture_output=True,
                )

                detected = subprocess.check_output(
                    ["git", "--git-dir", str(bare), "rev-parse", "--show-object-format"],
                    env=env,
                    text=True,
                ).strip()
                self.assertEqual(detected, fmt)

                commit_oid = subprocess.check_output(
                    ["git", "--git-dir", str(bare), "rev-parse", "refs/heads/main"],
                    env=env,
                    text=True,
                ).strip()
                tag_oid = subprocess.check_output(
                    ["git", "--git-dir", str(bare), "rev-parse", "refs/tags/v1.0"],
                    env=env,
                    text=True,
                ).strip()
                tree_oid = subprocess.check_output(
                    ["git", "--git-dir", str(bare), "rev-parse", f"{commit_oid}^{{tree}}"],
                    env=env,
                    text=True,
                ).strip()
                self.assertEqual(len(commit_oid), hex_len)
                self.assertEqual(len(tag_oid), hex_len)
                self.assertEqual(len(tree_oid), hex_len)

                # Verify raw tree binary OIDs (20-byte for sha1, 32-byte for sha256)
                raw_tree = subprocess.check_output(
                    ["git", "--git-dir", str(bare), "cat-file", "tree", tree_oid],
                    env=env,
                )
                entries = _parse_raw_tree(raw_tree, raw_len)
                self.assertEqual([e[1] for e in entries], ["model.bin", "src"])
                self.assertTrue(all(len(e[2]) == hex_len for e in entries))

                # Verify dual-hash computation on the LFS pointer blob matches Git's native OID
                ptr_blob_oid = entries[0][2]
                sha1_calc, sha256_calc = _compute_dual_git_oid("blob", pointer_bytes)
                expected_blob_oid = sha1_calc if fmt == "sha1" else sha256_calc
                self.assertEqual(ptr_blob_oid, expected_blob_oid)

                # Verify packfile trailer (20-byte SHA-1 vs 32-byte SHA-256)
                pack_bytes = subprocess.run(
                    ["git", "--git-dir", str(bare), "pack-objects", "--stdout", "--revs"],
                    input=f"{tag_oid}\n".encode(),
                    env=env,
                    check=True,
                    capture_output=True,
                ).stdout
                pack_info = _verify_pack_trailer_and_entries(pack_bytes, raw_len)
                self.assertEqual(len(pack_info["trailer_hex"]), hex_len)
                self.assertGreaterEqual(pack_info["object_count"], 5)

                results[fmt] = {
                    "commit_oid": commit_oid,
                    "tree_oid": tree_oid,
                    "tag_oid": tag_oid,
                    "ptr_blob_oid": ptr_blob_oid,
                }

            # Cross-format push between sha256 worktree and sha1 bare repo must be rejected by Git
            cross_push = subprocess.run(
                [
                    "git",
                    "push",
                    str(tmp_path / "bare-sha1.git"),
                    "HEAD:refs/heads/cross-format",
                ],
                cwd=tmp_path / "work-sha256",
                env=env,
                check=False,
                capture_output=True,
            )
            self.assertNotEqual(cross_push.returncode, 0)


if __name__ == "__main__":
    unittest.main()
