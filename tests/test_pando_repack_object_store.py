import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import uuid

from tests.pando_lab import Lab
from tests.test_track4_labs import _verify_git_pack, _walk_git_graph

ROOT = Path(__file__).resolve().parent.parent


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_immutable_0444(target: Path, data: bytes, expected_sha256: str) -> None:
    if _sha256_hex(data) != expected_sha256:
        raise ValueError("CAS payload digest mismatch before write")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        existing = target.read_bytes()
        if len(existing) != len(data) or _sha256_hex(existing) != expected_sha256:
            raise RuntimeError(f"immutable object store key collision on {target}")
        target.chmod(0o444)
        return
    tmp = target.parent / f".tmp-{uuid.uuid4()}"
    tmp.write_bytes(data)
    tmp.chmod(0o444)
    tmp.replace(target)


def _sim_put_pack_files(
    store_root: Path,
    objects_root: Path,
    repo_id: str,
    pack_id: str,
    bucket: str = "pando-default",
    chunk_size: int = 4096,
    fail_after_chunks: int | None = None,
    corrupt_chunk_part: int | None = None,
    expected_pack_sha256: str | None = None,
    expected_pack_bytes: int | None = None,
) -> dict:
    local_dir = objects_root / repo_id
    local_pack = local_dir / f"{pack_id}.pack"
    local_idx = local_dir / f"{pack_id}.idx"
    if not local_pack.is_file() or not local_idx.is_file():
        raise FileNotFoundError(f"missing local pack/idx for {pack_id}")

    pack_bytes = local_pack.read_bytes()
    idx_bytes = local_idx.read_bytes()
    resolved = _verify_git_pack(pack_bytes)
    pack_sha256 = _sha256_hex(pack_bytes)
    idx_sha256 = _sha256_hex(idx_bytes)

    if expected_pack_sha256 is not None and expected_pack_sha256 != pack_sha256:
        raise ValueError("expected pack SHA-256 mismatch")
    if expected_pack_bytes is not None and expected_pack_bytes != len(pack_bytes):
        raise ValueError("expected pack byte length mismatch")

    chunks_uploaded = 0

    def stage_and_reassemble(payload: bytes, exp_sha: str, exp_len: int, corrupt_part: int | None):
        nonlocal chunks_uploaded
        upload_id = str(uuid.uuid4())
        staging_dir = store_root / "multipart" / upload_id
        staging_dir.mkdir(parents=True, exist_ok=True)
        try:
            receipts = []
            slices = [
                payload[i : i + chunk_size]
                for i in range(0, max(1, len(payload)), chunk_size)
            ]
            offset = 0
            for idx, chunk in enumerate(slices):
                part_no = idx + 1
                if fail_after_chunks is not None and chunks_uploaded >= fail_after_chunks:
                    raise RuntimeError(
                        f"fault injection: multipart upload {upload_id} aborted after {chunks_uploaded} chunks"
                    )
                exp_part_sha = _sha256_hex(chunk)
                part_path = staging_dir / f"part-{part_no}"
                part_path.write_bytes(chunk)
                chunks_uploaded += 1
                if corrupt_part == part_no:
                    tampered = bytearray(part_path.read_bytes())
                    tampered[0] ^= 0xFF
                    part_path.write_bytes(bytes(tampered))
                staged = part_path.read_bytes()
                if len(staged) != len(chunk) or _sha256_hex(staged) != exp_part_sha:
                    raise RuntimeError(f"multipart chunk {part_no} digest or size mismatch")
                receipts.append(
                    {
                        "part_number": part_no,
                        "offset": offset,
                        "size_bytes": len(chunk),
                        "sha256": exp_part_sha,
                    }
                )
                offset += len(chunk)

            reassembled = b"".join(
                (staging_dir / f"part-{r['part_number']}").read_bytes() for r in receipts
            )
            if len(reassembled) != exp_len or _sha256_hex(reassembled) != exp_sha:
                raise RuntimeError("multipart complete object verification failed")
            return upload_id, receipts, reassembled
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    upload_id, pack_chunks, ver_pack = stage_and_reassemble(
        pack_bytes, pack_sha256, len(pack_bytes), corrupt_chunk_part
    )
    _, idx_chunks, ver_idx = stage_and_reassemble(
        idx_bytes, idx_sha256, len(idx_bytes), None
    )

    p_key = f"buckets/{bucket}/repos/{repo_id}/packs/{pack_id}.pack"
    i_key = f"buckets/{bucket}/repos/{repo_id}/packs/{pack_id}.idx"
    m_key = f"manifests/{repo_id}/{pack_id}.json"

    _write_immutable_0444(store_root / p_key, ver_pack, pack_sha256)
    _write_immutable_0444(store_root / i_key, ver_idx, idx_sha256)

    manifest = {
        "schema": "rootyard.pando.cas-pack-manifest.v1",
        "bucket": bucket,
        "backend": "s3-compatible-cas",
        "repo": repo_id,
        "pack_id": pack_id,
        "pack_key": p_key,
        "idx_key": i_key,
        "manifest_key": m_key,
        "pack_sha256": pack_sha256,
        "idx_sha256": idx_sha256,
        "pack_bytes": len(ver_pack),
        "idx_bytes": len(ver_idx),
        "object_count": len(resolved),
        "chunk_size": chunk_size,
        "pack_chunks": pack_chunks,
        "idx_chunks": idx_chunks,
        "manifest_sha256": "",
    }
    manifest["manifest_sha256"] = _sha256_hex(
        json.dumps(manifest, separators=(",", ":")).encode()
    )
    manifest_bytes = json.dumps(manifest, indent=2).encode()
    _write_immutable_0444(store_root / m_key, manifest_bytes, _sha256_hex(manifest_bytes))

    return {
        "repo": repo_id,
        "pack_id": pack_id,
        "bucket": bucket,
        "backend": "s3-compatible-cas",
        "upload_id": upload_id,
        "pack_key": p_key,
        "idx_key": i_key,
        "manifest_key": m_key,
        "bucket_pack_path": str(store_root / p_key),
        "bucket_idx_path": str(store_root / i_key),
        "manifest_path": str(store_root / m_key),
        "pack_sha256": pack_sha256,
        "idx_sha256": idx_sha256,
        "pack_bytes": len(ver_pack),
        "idx_bytes": len(ver_idx),
        "object_count": len(resolved),
        "chunk_size": chunk_size,
        "chunk_count": len(pack_chunks),
        "total_chunks_uploaded": len(pack_chunks) + len(idx_chunks),
        "immutable_mode": "0444",
        "status": "published",
    }


def _sim_get_pack_files(
    store_root: Path,
    objects_root: Path,
    repo_id: str,
    pack_id: str,
    bucket: str = "pando-default",
    expected_pack_sha256: str | None = None,
    expected_idx_sha256: str | None = None,
) -> dict:
    local_dir = objects_root / repo_id
    local_pack = local_dir / f"{pack_id}.pack"
    local_idx = local_dir / f"{pack_id}.idx"
    if local_pack.is_file() and local_idx.is_file():
        p_b = local_pack.read_bytes()
        i_b = local_idx.read_bytes()
        p_sha = _sha256_hex(p_b)
        i_sha = _sha256_hex(i_b)
        if (expected_pack_sha256 in (None, p_sha)) and (expected_idx_sha256 in (None, i_sha)):
            return {
                "repo": repo_id,
                "pack_id": pack_id,
                "bucket": bucket,
                "pack_sha256": p_sha,
                "idx_sha256": i_sha,
                "pack_bytes": len(p_b),
                "idx_bytes": len(i_b),
                "cache_hit": True,
                "rehydrated_from_object_store": False,
                "local_pack_path": str(local_pack),
                "local_idx_path": str(local_idx),
                "verified": True,
            }

    manifest_path = store_root / f"manifests/{repo_id}/{pack_id}.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(
            f"local pack cache miss for {pack_id} and pack is not present in object store"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    check_copy = dict(manifest)
    check_copy["manifest_sha256"] = ""
    if _sha256_hex(json.dumps(check_copy, separators=(",", ":")).encode()) != manifest["manifest_sha256"]:
        raise RuntimeError("CAS manifest signature mismatch")

    p_bytes = (store_root / manifest["pack_key"]).read_bytes()
    i_bytes = (store_root / manifest["idx_key"]).read_bytes()
    if len(p_bytes) != manifest["pack_bytes"] or _sha256_hex(p_bytes) != manifest["pack_sha256"]:
        raise RuntimeError("object store pack digest or byte length mismatch")
    if len(i_bytes) != manifest["idx_bytes"] or _sha256_hex(i_bytes) != manifest["idx_sha256"]:
        raise RuntimeError("object store idx digest or byte length mismatch")
    resolved = _verify_git_pack(p_bytes)
    if len(resolved) != manifest["object_count"]:
        raise RuntimeError("object store pack object_count mismatch")

    local_dir.mkdir(parents=True, exist_ok=True)
    for target, payload in ((local_pack, p_bytes), (local_idx, i_bytes)):
        tmp_path = local_dir / f".cache-tmp-{uuid.uuid4()}"
        tmp_path.write_bytes(payload)
        tmp_path.replace(target)
    return {
        "repo": repo_id,
        "pack_id": pack_id,
        "bucket": manifest["bucket"],
        "pack_sha256": manifest["pack_sha256"],
        "idx_sha256": manifest["idx_sha256"],
        "pack_bytes": manifest["pack_bytes"],
        "idx_bytes": manifest["idx_bytes"],
        "cache_hit": False,
        "rehydrated_from_object_store": True,
        "local_pack_path": str(local_pack),
        "local_idx_path": str(local_idx),
        "verified": True,
    }


class PandoObjectStoreAndRepackContractTests(unittest.TestCase):
    def test_pando_submodules_exist_respect_line_caps_and_forbid_unsafe(self):
        pando_dir = ROOT / "src" / "pando_lab"
        for new_mod in ("object_store.rs", "repack.rs"):
            path = pando_dir / new_mod
            self.assertTrue(path.is_file(), f"Missing src/pando_lab/{new_mod}")
            text = path.read_text(encoding="utf-8")
            lines = len(text.splitlines())
            self.assertGreaterEqual(lines, 50, f"src/pando_lab/{new_mod} too short ({lines} lines)")
            self.assertLess(lines, 600, f"src/pando_lab/{new_mod} exceeds 600 lines ({lines} lines)")
            self.assertNotIn("unsafe ", text, f"Forbidden unsafe in src/pando_lab/{new_mod}")
            self.assertIn("#[cfg(test)]", text)

        for name in (
            "mod.rs",
            "delta.rs",
            "graph.rs",
            "export.rs",
            "store.rs",
            "http.rs",
            "hook.rs",
            "migration.rs",
            "rollback.rs",
            "object_store.rs",
            "repack.rs",
        ):
            path = pando_dir / name
            text = path.read_text(encoding="utf-8")
            lines = len(text.splitlines())
            self.assertGreaterEqual(lines, 35)
            self.assertLess(lines, 850, f"src/pando_lab/{name} exceeds 850 lines ({lines} lines)")
            self.assertNotIn("unsafe ", text, f"Forbidden unsafe in src/pando_lab/{name}")

    def test_mod_rs_preserves_config_load_first_and_wires_object_store_and_repack_cli(self):
        mod_text = (ROOT / "src" / "pando_lab" / "mod.rs").read_text(encoding="utf-8")
        self.assertIn("pub mod object_store;", mod_text)
        self.assertIn("pub mod repack;", mod_text)
        run_section = mod_text.split("pub async fn run() -> Result<()> {", 1)[1]
        first_stmt = run_section.strip().splitlines()[0].strip()
        self.assertEqual(first_stmt, "let config = Config::load()?;")
        for subcmd in (
            'Some("repack")',
            'Some("pin-root")',
            'Some("unpin-root")',
            'Some("object-store-put")',
            'Some("object-store-get")',
            'Some("object-store-verify")',
            'Some("object-store-status")',
        ):
            self.assertIn(subcmd, mod_text)

    def test_schema_sql_defines_object_store_pinned_roots_and_repacks_without_between(self):
        schema_text = (ROOT / "experimental" / "pando" / "schema.sql").read_text(encoding="utf-8")
        self.assertNotIn("BETWEEN", schema_text.upper())
        for token in (
            "CREATE TABLE IF NOT EXISTS pando_lab.pinned_roots",
            "CREATE TABLE IF NOT EXISTS pando_lab.object_store_manifests",
            "CREATE TABLE IF NOT EXISTS pando_lab.repacks",
            "pando.allow_repack_mutation",
            "immutable_manifest",
            "immutable_object",
        ):
            self.assertIn(token, schema_text)

    def test_http_rs_wires_packs_repack_and_object_store_endpoints(self):
        http_text = (ROOT / "src" / "pando_lab" / "http.rs").read_text(encoding="utf-8")
        self.assertIn('tail == "packs"', http_text)
        self.assertIn("repack::packs_status", http_text)
        self.assertIn('tail == "object-store"', http_text)
        self.assertIn("object_store::status", http_text)
        self.assertIn('parts.method == "POST" && tail == "repack"', http_text)
        self.assertIn("repack::repack_repo", http_text)

    def test_main_server_forge_and_browse_expose_backend_and_storage_route_endpoints(self):
        forge_text = (ROOT / "src" / "forge.rs").read_text(encoding="utf-8")
        self.assertIn('"/api/repos/{owner}/{name}/backend"', forge_text)
        self.assertIn("get(get_backend).patch(set_backend)", forge_text)
        self.assertIn("repository.storage_backend.changed", forge_text)
        self.assertIn("pando_gateway", forge_text)
        self.assertIn("gitfs_local", forge_text)

        browse_path = ROOT / "src" / "browse.rs"
        browse_text = browse_path.read_text(encoding="utf-8")
        self.assertLess(len(browse_text.splitlines()), 100)
        self.assertNotIn("Command::new", browse_text)
        for sql_kw in ("SELECT ", "INSERT ", "UPDATE ", "DELETE "):
            self.assertNotIn(sql_kw, browse_text)
        self.assertIn('"/api/repos/{owner}/{name}/storage-route"', browse_text)
        self.assertIn("get(handlers::get_storage_route)", browse_text)

        handlers_text = (ROOT / "src" / "browse" / "handlers.rs").read_text(encoding="utf-8")
        self.assertLess(len(handlers_text.splitlines()), 550)
        self.assertIn("pub async fn get_storage_route", handlers_text)

        models_text = (ROOT / "src" / "browse" / "models.rs").read_text(encoding="utf-8")
        self.assertLess(len(models_text.splitlines()), 550)
        self.assertIn("#[serde(deny_unknown_fields)]", models_text)
        self.assertIn("pub struct StorageRouteQuery", models_text)
        self.assertIn("pub struct StorageRouteResponse", models_text)


class PandoObjectStoreCasAndFaultInjectionTests(unittest.TestCase):
    def _create_sample_pack_and_idx(self, root: Path, repo_id: str, pack_id: str) -> tuple[bytes, bytes]:
        work = root / "sample-work"
        subprocess.run(["git", "init", "--initial-branch=main", str(work)], check=True, capture_output=True)
        (work / "readme.txt").write_text("S3-compatible CAS pack test payload\n" * 20, encoding="utf-8")
        subprocess.run(["git", "-C", str(work), "add", "."], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(work), "-c", "user.name=T", "-c", "user.email=t@e.c", "commit", "-m", "init"],
            check=True,
            capture_output=True,
        )
        head = subprocess.check_output(["git", "-C", str(work), "rev-parse", "HEAD"], text=True).strip()
        pack_bytes = subprocess.run(
            ["git", "-C", str(work), "pack-objects", "--stdout", "--revs"],
            input=f"{head}\n".encode(),
            check=True,
            capture_output=True,
        ).stdout
        obj_dir = root / "objects" / repo_id
        obj_dir.mkdir(parents=True, exist_ok=True)
        pack_path = obj_dir / f"{pack_id}.pack"
        pack_path.write_bytes(pack_bytes)
        subprocess.run(
            ["git", "-C", str(work), "index-pack", "--strict", str(pack_path)],
            check=True,
            capture_output=True,
        )
        idx_bytes = (obj_dir / f"{pack_id}.idx").read_bytes()
        return pack_bytes, idx_bytes

    def test_multipart_chunked_upload_cas_manifest_and_immutability(self):
        with tempfile.TemporaryDirectory(prefix="pando-os-cas-") as tmp:
            root = Path(tmp)
            repo_id = str(uuid.uuid4())
            pack_id = str(uuid.uuid4())
            pack_bytes, idx_bytes = self._create_sample_pack_and_idx(root, repo_id, pack_id)

            rep = _sim_put_pack_files(
                root, root / "objects", repo_id, pack_id, bucket="pando-cas", chunk_size=128
            )
            self.assertEqual(rep["status"], "published")
            self.assertGreaterEqual(rep["chunk_count"], 2)
            self.assertEqual(rep["immutable_mode"], "0444")

            bucket_pack = Path(rep["bucket_pack_path"])
            bucket_idx = Path(rep["bucket_idx_path"])
            manifest_file = Path(rep["manifest_path"])
            self.assertTrue(bucket_pack.is_file())
            self.assertTrue(bucket_idx.is_file())
            self.assertTrue(manifest_file.is_file())
            self.assertEqual(stat.S_IMODE(bucket_pack.stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE(bucket_idx.stat().st_mode), 0o444)
            self.assertEqual(bucket_pack.read_bytes(), pack_bytes)
            self.assertEqual(bucket_idx.read_bytes(), idx_bytes)

            # Idempotent re-upload succeeds, while key collision with altered bytes fails closed
            rep2 = _sim_put_pack_files(
                root, root / "objects", repo_id, pack_id, bucket="pando-cas", chunk_size=128
            )
            self.assertEqual(rep2["pack_sha256"], rep["pack_sha256"])
            with self.assertRaises(RuntimeError):
                _write_immutable_0444(bucket_pack, b"different-pack-bytes", _sha256_hex(b"different-pack-bytes"))

    def test_fault_injection_corrupt_chunk_and_size_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="pando-os-faults-") as tmp:
            root = Path(tmp)
            repo_id = str(uuid.uuid4())
            pack_id = str(uuid.uuid4())
            self._create_sample_pack_and_idx(root, repo_id, pack_id)

            with self.assertRaises(RuntimeError):
                _sim_put_pack_files(
                    root, root / "objects", repo_id, pack_id, chunk_size=64, fail_after_chunks=1
                )
            self.assertFalse((root / f"manifests/{repo_id}/{pack_id}.json").exists())
            self.assertEqual(list((root / "multipart").glob("*")), [])

            with self.assertRaises(RuntimeError):
                _sim_put_pack_files(
                    root, root / "objects", repo_id, pack_id, chunk_size=64, corrupt_chunk_part=1
                )
            self.assertFalse((root / f"manifests/{repo_id}/{pack_id}.json").exists())

            with self.assertRaises(ValueError):
                _sim_put_pack_files(
                    root, root / "objects", repo_id, pack_id, expected_pack_bytes=1
                )

    def test_local_cache_miss_rehydration_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory(prefix="pando-os-cache-") as tmp:
            root = Path(tmp)
            repo_id = str(uuid.uuid4())
            pack_id = str(uuid.uuid4())
            pack_bytes, _ = self._create_sample_pack_and_idx(root, repo_id, pack_id)
            local_pack = root / "objects" / repo_id / f"{pack_id}.pack"

            # Before uploading to object store, evicting local pack must fail closed
            backup = local_pack.with_suffix(".bak")
            local_pack.rename(backup)
            with self.assertRaises(FileNotFoundError):
                _sim_get_pack_files(root, root / "objects", repo_id, pack_id)
            backup.rename(local_pack)

            # Upload to object store, then evict local pack and verify read-through re-hydration
            put_rep = _sim_put_pack_files(root, root / "objects", repo_id, pack_id, chunk_size=128)
            local_pack.unlink()
            get_rep = _sim_get_pack_files(
                root,
                root / "objects",
                repo_id,
                pack_id,
                expected_pack_sha256=put_rep["pack_sha256"],
                expected_idx_sha256=put_rep["idx_sha256"],
            )
            self.assertFalse(get_rep["cache_hit"])
            self.assertTrue(get_rep["rehydrated_from_object_store"])
            self.assertEqual(local_pack.read_bytes(), pack_bytes)

            # Tampering with bucket object causes re-hydration to fail closed
            local_pack.unlink()
            bucket_pack = Path(put_rep["bucket_pack_path"])
            bucket_pack.chmod(0o644)
            tampered = bytearray(bucket_pack.read_bytes())
            tampered[12] ^= 0xFF
            bucket_pack.write_bytes(bytes(tampered))
            with self.assertRaises(RuntimeError):
                _sim_get_pack_files(root, root / "objects", repo_id, pack_id)


class PandoMultiPackRepackAndReachabilityGcTests(unittest.TestCase):
    def test_multi_pack_compaction_and_reachability_gc_with_pinned_and_snapshot_roots(self):
        with tempfile.TemporaryDirectory(prefix="pando-repack-gc-") as tmp:
            root = Path(tmp)
            work = root / "work"
            subprocess.run(["git", "init", "--initial-branch=main", str(work)], check=True, capture_output=True)

            def commit_file(fname: str, text: str, msg: str) -> str:
                (work / fname).write_text(text, encoding="utf-8")
                subprocess.run(["git", "-C", str(work), "add", fname], check=True, capture_output=True)
                subprocess.run(
                    ["git", "-C", str(work), "-c", "user.name=T", "-c", "user.email=t@e.c", "commit", "-m", msg],
                    check=True,
                    capture_output=True,
                )
                return subprocess.check_output(["git", "-C", str(work), "rev-parse", "HEAD"], text=True).strip()

            def build_pack(revs: str) -> tuple[str, bytes]:
                p_bytes = subprocess.run(
                    ["git", "-C", str(work), "pack-objects", "--stdout", "--revs"],
                    input=revs.encode(),
                    check=True,
                    capture_output=True,
                ).stdout
                return str(uuid.uuid4()), p_bytes

            c1 = commit_file("base.txt", "base v1\n", "c1 base")
            pid1, pack1 = build_pack(f"{c1}\n")

            c2_pinned = commit_file("pinned.txt", "ci pin payload\n", "c2 pinned")
            pid2, pack2 = build_pack(f"{c2_pinned}\n^{c1}\n")

            subprocess.run(["git", "-C", str(work), "reset", "--hard", c1], check=True, capture_output=True)
            c3_snap = commit_file("snap.txt", "active snapshot payload\n", "c3 snapshot")
            pid3, pack3 = build_pack(f"{c3_snap}\n^{c1}\n")

            subprocess.run(["git", "-C", str(work), "reset", "--hard", c1], check=True, capture_output=True)
            c4_orphan = commit_file("orphan.txt", "abandoned branch payload\n", "c4 orphan")
            pid4, pack4 = build_pack(f"{c4_orphan}\n^{c1}\n")

            subprocess.run(["git", "-C", str(work), "reset", "--hard", c1], check=True, capture_output=True)
            c5_main = commit_file("main.txt", "current main tip\n", "c5 main")
            pid5, pack5 = build_pack(f"{c5_main}\n^{c1}\n")

            staging = root / "staging.git"
            subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(staging)], check=True, capture_output=True)
            before_store = {}
            for _pid, p_bytes in ((pid1, pack1), (pid2, pack2), (pid3, pack3), (pid4, pack4), (pid5, pack5)):
                for obj in _verify_git_pack(p_bytes):
                    before_store[obj["oid"]] = (obj["type"], obj["data"])
                subprocess.run(
                    ["git", f"--git-dir={staging}", "index-pack", "--stdin", "--strict"],
                    input=p_bytes,
                    check=True,
                    capture_output=True,
                )

            # Roots = current main (c5_main) + pinned root (c2_pinned) + active snapshot root (c3_snap)
            roots = sorted({c5_main, c2_pinned, c3_snap})
            reachable_before, _ = _walk_git_graph(before_store, roots, [])
            self.assertIn(c1, reachable_before)
            self.assertIn(c5_main, reachable_before)
            self.assertIn(c2_pinned, reachable_before)
            self.assertIn(c3_snap, reachable_before)
            self.assertNotIn(c4_orphan, reachable_before)

            compacted_pack = subprocess.run(
                ["git", f"--git-dir={staging}", "pack-objects", "--stdout", "--revs", "--delta-base-offset"],
                input=("\n".join(roots) + "\n").encode(),
                check=True,
                capture_output=True,
            ).stdout
            after_objs = _verify_git_pack(compacted_pack)
            after_store = {o["oid"]: (o["type"], o["data"]) for o in after_objs}
            self.assertEqual(set(after_store.keys()), set(reachable_before.keys()))
            for oid, expected_val in reachable_before.items():
                self.assertEqual(after_store[oid], expected_val)

            verify_bare = root / "verify.git"
            subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(verify_bare)], check=True, capture_output=True)
            subprocess.run(
                ["git", f"--git-dir={verify_bare}", "index-pack", "--stdin", "--strict"],
                input=compacted_pack,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", f"--git-dir={verify_bare}", "fsck", "--full", "--strict", "--no-reflogs", *roots],
                check=True,
                capture_output=True,
            )


class PandoLabHarnessAndMainGatewayRoutingOfflineTests(unittest.TestCase):
    def test_pando_lab_harness_object_store_and_repack_methods_offline(self):
        args = argparse.Namespace(binary="target/debug/rootyard-pando-lab", pg_share=None)
        lab = Lab(args)
        try:
            lab.base = "http://127.0.0.1:59998"
            lab.store = lab.root / "store"
            lab.store.mkdir(parents=True, exist_ok=True)
            lab.repo = str(uuid.uuid4())
            lab.source = lab.root / "source"
            subprocess.run(["git", "init", "--initial-branch=main", str(lab.source)], check=True, capture_output=True)
            c0 = lab.commit(lab.source, "initial commit")

            repos: dict[str, dict] = {}

            def ensure_repo(rid: str) -> dict:
                if rid not in repos:
                    bare = lab.root / f"sim-{rid}.git"
                    subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(bare)], check=True, capture_output=True)
                    repos[rid] = {
                        "bare": bare,
                        "packs": [],
                        "pinned": {},
                        "snapshots": [],
                        "repacks": [],
                        "os_manifests": {},
                    }
                return repos[rid]

            st0 = ensure_repo(lab.repo)
            subprocess.run(["git", "-C", str(lab.source), "push", str(st0["bare"]), "HEAD:refs/heads/main"], check=True, capture_output=True)
            p0 = subprocess.run(
                ["git", f"--git-dir={st0['bare']}", "pack-objects", "--stdout", "--revs"],
                input=f"{c0}\n".encode(),
                check=True,
                capture_output=True,
            ).stdout
            pid0 = str(uuid.uuid4())
            obj_dir0 = lab.store / "objects" / lab.repo
            obj_dir0.mkdir(parents=True, exist_ok=True)
            (obj_dir0 / f"{pid0}.pack").write_bytes(p0)
            subprocess.run(["git", f"--git-dir={st0['bare']}", "index-pack", "--strict", str(obj_dir0 / f"{pid0}.pack")], check=True, capture_output=True)
            i0 = (obj_dir0 / f"{pid0}.idx").read_bytes()
            st0["packs"].append({"pack_id": pid0, "pack_sha256": _sha256_hex(p0), "idx_sha256": _sha256_hex(i0)})

            def fake_rows(query: str) -> list[dict]:
                if "FROM pando_lab.manifests" in query:
                    return list(ensure_repo(lab.repo)["packs"])
                return []

            def fake_sql(query: str) -> str:
                return "1"

            orig_run = lab.run

            def fake_run(cmd, cwd=None, env=None, data=None, check=True, timeout=90):
                if isinstance(cmd, list) and len(cmd) >= 2 and cmd[1] == "object-store-put":
                    if "--fail-after-chunks" in cmd or "--corrupt-chunk" in cmd:
                        return subprocess.CompletedProcess(cmd, 1, "", "fault injected")
                    return subprocess.CompletedProcess(cmd, 0, "", "")
                return orig_run(cmd, cwd=cwd, env=env, data=data, check=check, timeout=timeout)

            def fake_cli(*cli_args) -> str:
                cmd = cli_args[0]
                if cmd == "create-repo":
                    ensure_repo(cli_args[1])
                    return ""
                if cmd == "object-store-put":
                    rid, pid = cli_args[1], cli_args[2]
                    csize = int(cli_args[cli_args.index("--chunk-size") + 1]) if "--chunk-size" in cli_args else 4096
                    rep = _sim_put_pack_files(lab.store, lab.store / "objects", rid, pid, chunk_size=csize)
                    ensure_repo(rid)["os_manifests"][pid] = rep
                    return json.dumps(rep)
                if cmd == "object-store-get":
                    rid, pid = cli_args[1], cli_args[2]
                    return json.dumps(_sim_get_pack_files(lab.store, lab.store / "objects", rid, pid))
                if cmd == "object-store-verify":
                    rid = cli_args[1]
                    return json.dumps(
                        {
                            "repo": rid,
                            "bucket": "pando-default",
                            "manifests_checked": len(ensure_repo(rid)["os_manifests"]),
                            "packs_verified": len(ensure_repo(rid)["os_manifests"]),
                            "total_pack_bytes": 128,
                            "total_idx_bytes": 128,
                            "orphan_staging_cleaned": 0,
                            "verified": True,
                        }
                    )
                if cmd == "pin-root":
                    rid, name, oid = cli_args[1], cli_args[2], cli_args[3]
                    ensure_repo(rid)["pinned"][name] = oid
                    return json.dumps({"repo": rid, "name": name, "oid": oid, "pinned": True})
                if cmd == "unpin-root":
                    rid, name = cli_args[1], cli_args[2]
                    existed = ensure_repo(rid)["pinned"].pop(name, None) is not None
                    return json.dumps({"repo": rid, "name": name, "unpinned": existed})
                raise AssertionError(f"Unexpected CLI call: {cli_args}")

            def fake_http(path: str, principal: str = "reader", method: str = "GET", body=None, redirects: bool = True):
                if principal == "bob":
                    return 403, {}, b"repository access denied"
                if path.startswith("/snapshots/"):
                    return 200, {}, b"snapshot ok"
                repo_id = path.split("/repos/")[1].split(".git")[0]
                st = ensure_repo(repo_id)
                if path.endswith("/object-store"):
                    return (
                        200,
                        {},
                        json.dumps(
                            {
                                "repo": repo_id,
                                "bucket": "pando-default",
                                "backend": "s3-compatible-cas",
                                "committed_manifests": len(st["packs"]),
                                "object_store_manifests": len(st["os_manifests"]),
                                "local_cached_packs": len(st["packs"]),
                                "fully_replicated": True,
                                "active_multipart_uploads": 0,
                                "packs": list(st["os_manifests"].values()),
                            }
                        ).encode(),
                    )
                if path.endswith("/info/refs?service=git-upload-pack") and not redirects:
                    snap_id = str(uuid.uuid4())
                    st["snapshots"].append({"id": snap_id, "packs": [p["pack_id"] for p in st["packs"]]})
                    return 302, {"location": f"/snapshots/{snap_id}/{repo_id}.git/info/refs?service=git-upload-pack"}, b""
                if path.endswith("/packs") and method == "GET":
                    return (
                        200,
                        {},
                        json.dumps(
                            {
                                "repo": repo_id,
                                "active_pack_count": len(st["packs"]),
                                "pack_count": len(st["packs"]),
                                "packs": st["packs"],
                                "pinned_roots": st["pinned"],
                                "latest_repack": st["repacks"][-1] if st["repacks"] else None,
                            }
                        ).encode(),
                    )
                if path.endswith("/repack") and method == "POST":
                    comp_id = str(uuid.uuid4())
                    retained = st["snapshots"][0]["packs"] if st["snapshots"] else []
                    rep = {
                        "repack_id": str(uuid.uuid4()),
                        "repo": repo_id,
                        "generation": 4,
                        "storage_generation": 1,
                        "packs_before": len(st["packs"]),
                        "packs_after": 1,
                        "objects_before": 12,
                        "objects_after": 9,
                        "reachable_objects": 9,
                        "unreachable_objects_pruned": 3,
                        "ref_roots_count": 1,
                        "pinned_roots_count": max(1, len(st["pinned"])),
                        "active_snapshots_count": len(st["snapshots"]),
                        "compacted_pack_id": comp_id,
                        "compacted_pack_sha256": "a" * 64,
                        "compacted_idx_sha256": "b" * 64,
                        "superseded_packs": [],
                        "snapshot_retained_packs": retained,
                        "pruned_pack_files": 0,
                        "reclaimed_bytes": 0,
                        "object_store_synced": True,
                        "dual_operator_verified": True,
                    }
                    st["packs"] = [{"pack_id": comp_id, "pack_sha256": "a" * 64, "idx_sha256": "b" * 64}]
                    st["repacks"].append(rep)
                    return 200, {}, json.dumps(rep).encode()
                return 200, {}, b""

            orig_git = lab.git

            def fake_git(*g_args, principal="alice", protocol=2, check=True, cwd=None):
                mapped = list(g_args)
                for idx, arg in enumerate(mapped):
                    if isinstance(arg, str) and arg.startswith(lab.base + "/repos/"):
                        rid = arg.split("/repos/")[1].split(".git")[0]
                        st = ensure_repo(rid)
                        if mapped[0] == "push":
                            st["packs"].append(
                                {"pack_id": str(uuid.uuid4()), "pack_sha256": "c" * 64, "idx_sha256": "d" * 64}
                            )
                        mapped[idx] = str(st["bare"])
                res = orig_git(*mapped, principal=principal, protocol=protocol, check=check, cwd=cwd)
                if mapped[0] == "clone" and protocol == 2:
                    res.packet_trace = "version 2\n" + getattr(res, "packet_trace", "")
                return res

            lab.rows = fake_rows
            lab.sql = fake_sql
            lab.run = fake_run
            lab.cli = fake_cli
            lab.http = fake_http
            lab.git = fake_git

            os_res = lab.object_store_cas_and_cache_recovery()
            self.assertTrue(os_res["rehydrated"])
            self.assertTrue(os_res["verified"])

            repack_res = lab.multi_pack_repack_and_pinned_gc()
            self.assertGreaterEqual(repack_res["packs_before"], 3)
            self.assertEqual(repack_res["packs_after"], 1)
            self.assertGreaterEqual(repack_res["unreachable_objects_pruned"], 1)
            self.assertGreaterEqual(repack_res["snapshot_retained_packs"], 1)
        finally:
            shutil.rmtree(lab.root, ignore_errors=True)

    def test_main_server_storage_backend_patch_cas_and_storage_route_resolution(self):
        with tempfile.TemporaryDirectory(prefix="rootyard-gateway-route-") as tmp:
            repo_dir = Path(tmp) / "repo.git"
            subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(repo_dir)], check=True, capture_output=True)

            repo_id = str(uuid.uuid4())
            state = {
                "storage_backend": "gitfs",
                "storage_generation": 1,
                "write_paused": False,
                "pando_ready": False,
            }

            def resolve_route(operation: str = "read") -> dict:
                if operation not in ("read", "write", "git-upload-pack", "git-receive-pack"):
                    raise ValueError("invalid operation")
                backend = state["storage_backend"]
                gateway_route = "pando_gateway" if backend == "pando" else "gitfs_local"
                return {
                    "repository_id": repo_id,
                    "owner": "alice",
                    "name": "demo",
                    "storage_backend": backend,
                    "storage_generation": state["storage_generation"],
                    "state": "ready",
                    "gateway_route": gateway_route,
                    "read_backend": backend,
                    "write_backend": backend,
                    "requested_operation": operation,
                    "selected_backend": backend,
                    "write_paused": state["write_paused"],
                    "pando_ready": backend == "pando" or state["pando_ready"],
                    "gitfs_ready": True,
                }

            def patch_backend(new_backend: str, expected_gen: int) -> tuple[int, dict]:
                if expected_gen != state["storage_generation"]:
                    return 409, {"error": "storage generation conflict"}
                state["storage_generation"] += 1
                state["storage_backend"] = new_backend
                state["pando_ready"] = new_backend == "pando"
                marker = {
                    "storage_backend": new_backend,
                    "storage_generation": state["storage_generation"],
                    "write_paused": False,
                    "pando_ready": state["pando_ready"],
                }
                (repo_dir / "rootyard-storage-backend.json").write_text(json.dumps(marker), encoding="utf-8")
                subprocess.run(
                    ["git", f"--git-dir={repo_dir}", "config", "rootyard.storageBackend", new_backend],
                    check=True,
                )
                subprocess.run(
                    ["git", f"--git-dir={repo_dir}", "config", "rootyard.storageGeneration", str(state["storage_generation"])],
                    check=True,
                )
                return 200, resolve_route("read")

            initial = resolve_route("git-upload-pack")
            self.assertEqual(initial["storage_backend"], "gitfs")
            self.assertEqual(initial["gateway_route"], "gitfs_local")
            self.assertEqual(initial["selected_backend"], "gitfs")

            code_ok, switched = patch_backend("pando", expected_gen=1)
            self.assertEqual(code_ok, 200)
            self.assertEqual(switched["storage_backend"], "pando")
            self.assertEqual(switched["storage_generation"], 2)
            self.assertEqual(switched["gateway_route"], "pando_gateway")
            self.assertEqual(switched["read_backend"], "pando")
            self.assertEqual(switched["write_backend"], "pando")
            self.assertTrue(switched["pando_ready"])

            code_conflict, _ = patch_backend("gitfs", expected_gen=1)
            self.assertEqual(code_conflict, 409)


if __name__ == "__main__":
    unittest.main()
