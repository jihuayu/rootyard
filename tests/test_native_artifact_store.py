"""Focused offline tests for the narrow native artifact CAS helper.

These tests never invoke Cargo, rustc, Git or any builder.  They seal fixtures
through the public API and assert immutable CAS/reflink/copy semantics,
snapshot independence, traversal guards and no-overwrite receipts.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import native_artifact_store as artifacts  # noqa: E402


def _mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ArtifactStoreTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = Path(tempfile.mkdtemp(prefix="rootyard-artifact-store-test-"))
        self.addCleanup(shutil.rmtree, self.tempdir, ignore_errors=True)
        self.store_root = self.tempdir / "cas"
        self.source = self.tempdir / "target" / "debug" / "rootyard"
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b"rootyard-native-binary-v1")
        os.chmod(self.source, 0o755)
        self.commit = "a" * 40
        self.config_key = artifacts.configuration_key(
            {"profile": "dev", "features": ["pando-lab"], "target": "aarch64-unknown-linux-gnu"}
        )

    def seal(self, source=None, **overrides):
        arguments = {
            "store_root": self.store_root,
            "commit": self.commit,
            "config_key": self.config_key,
        }
        arguments.update(overrides)
        return artifacts.seal_binary(source or self.source, **arguments)

    # -- canonical keys and safe IDs ----------------------------------------
    def test_configuration_key_is_canonical_and_sorted(self):
        first = artifacts.configuration_key({"b": [2, 3], "a": 1})
        second = artifacts.configuration_key({"a": 1, "b": [2, 3]})
        expected = hashlib.sha256(b'{"a":1,"b":[2,3]}').hexdigest()
        self.assertEqual(first, second)
        self.assertEqual(first, expected)

        nested_a = {"z": {"b": True, "a": None}, "unicode": "根"}
        nested_b = {"unicode": "根", "z": {"a": None, "b": True}}
        self.assertEqual(
            artifacts.configuration_key(nested_a),
            artifacts.configuration_key(nested_b),
        )

        with self.assertRaises(artifacts.ArtifactStoreError):
            artifacts.configuration_key(["not", "a", "mapping"])
        with self.assertRaises(artifacts.ArtifactStoreError):
            artifacts.configuration_key({"bad": float("nan")})

    def test_new_build_id_is_safe_and_unique(self):
        pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
        values = {artifacts.new_build_id() for _ in range(200)}
        self.assertEqual(len(values), 200)
        for value in values:
            self.assertRegex(value, pattern)
            self.assertNotIn("/", value)
            self.assertNotIn("..", value)

    # -- sealing, reuse and independence ------------------------------------
    def test_seal_creates_independent_readonly_object_and_snapshot(self):
        data = self.source.read_bytes()
        snapshot_before = _mode(self.source)
        sealed = self.seal()

        self.assertFalse(sealed.reused)
        self.assertEqual(sealed.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(sealed.commit, self.commit)
        self.assertEqual(sealed.config_key, self.config_key)
        self.assertEqual(sealed.binary_path.name, "rootyard")
        self.assertEqual(sealed.receipt_path.parent, sealed.binary_path.parent)
        self.assertFalse(sealed.receipt_path.exists())

        self.assertTrue(sealed.object_path.is_file())
        self.assertTrue(sealed.binary_path.is_file())
        self.assertEqual(sealed.object_path.read_bytes(), data)
        self.assertEqual(sealed.binary_path.read_bytes(), data)
        self.assertEqual(_sha(sealed.object_path), sealed.sha256)
        self.assertEqual(_sha(sealed.binary_path), sealed.sha256)

        self.assertEqual(_mode(sealed.object_path) & 0o222, 0)
        self.assertEqual(_mode(sealed.binary_path) & 0o222, 0)
        self.assertEqual(_mode(self.source), snapshot_before)
        self.assertNotEqual(
            os.stat(self.source).st_ino, os.stat(sealed.object_path).st_ino
        )
        # Preferred snapshot publication is an owned immutable CAS hard-link.
        self.assertEqual(
            os.stat(sealed.binary_path).st_ino, os.stat(sealed.object_path).st_ino
        )

        marker = self.store_root / artifacts.MARKER_NAME
        self.assertTrue(marker.is_file())
        self.assertEqual(_mode(marker) & 0o222, 0)
        if sealed.method == "copy":
            self.assertEqual(sealed.copied_bytes, len(data))
        elif sealed.method == "reflink":
            self.assertEqual(sealed.copied_bytes, 0)
        else:
            self.fail(f"unexpected new-object method: {sealed.method}")

    def test_identical_bytes_reuse_one_object_but_keep_new_snapshots_and_receipts(self):
        first = self.seal(name="rootyard")
        second_source = self.tempdir / "other" / "rootyard"
        second_source.parent.mkdir()
        second_source.write_bytes(self.source.read_bytes())
        second = self.seal(second_source, name="rootyard")

        self.assertTrue(second.reused)
        self.assertEqual(second.method, "reuse")
        self.assertEqual(second.copied_bytes, 0)
        self.assertEqual(first.object_path, second.object_path)
        self.assertEqual(first.sha256, second.sha256)
        self.assertNotEqual(first.binary_path, second.binary_path)
        self.assertNotEqual(first.receipt_path, second.receipt_path)

        first_receipt = artifacts.write_receipt(
            first,
            {"sha256": first.sha256, "commit": first.commit, "fresh": False},
        )
        second_receipt = artifacts.write_receipt(
            second,
            {"sha256": second.sha256, "commit": second.commit, "fresh": True},
        )
        self.assertEqual(first_receipt, first.receipt_path)
        self.assertEqual(second_receipt, second.receipt_path)
        self.assertFalse(json.loads(first_receipt.read_text())["fresh"])
        self.assertTrue(json.loads(second_receipt.read_text())["fresh"])

    def test_source_modification_after_seal_leaves_object_and_snapshot_unchanged(self):
        sealed = self.seal()
        old_bytes = sealed.binary_path.read_bytes()
        old_object = sealed.object_path.read_bytes()

        self.source.write_bytes(b"changed-mutable-compiler-output")
        self.assertEqual(sealed.binary_path.read_bytes(), old_bytes)
        self.assertEqual(sealed.object_path.read_bytes(), old_object)
        self.assertEqual(_sha(sealed.binary_path), sealed.sha256)

        replacement = self.seal()
        self.assertFalse(replacement.reused)
        self.assertNotEqual(replacement.sha256, sealed.sha256)
        self.assertNotEqual(replacement.object_path, sealed.object_path)
        self.assertEqual(sealed.binary_path.read_bytes(), old_bytes)

    # -- refusal and validation ---------------------------------------------
    def test_expected_sha256_mismatch_is_refused_before_store_creation(self):
        with self.assertRaises(artifacts.ArtifactStoreError):
            self.seal(expected_sha256="0" * 64)
        self.assertFalse(self.store_root.exists())
        self.assertEqual(self.source.read_bytes(), b"rootyard-native-binary-v1")

    def test_existing_object_with_wrong_bytes_is_refused_without_repair(self):
        seed = self.tempdir / "seed"
        seed.write_bytes(b"seed")
        seed_sealed = self.seal(seed)
        config_dir = (
            self.store_root
            / artifacts.SNAPSHOTS_DIR
            / self.commit
            / self.config_key
        )
        before_builds = {entry.name for entry in config_dir.iterdir()}

        target_bytes = self.source.read_bytes()
        sha = hashlib.sha256(target_bytes).hexdigest()
        object_path = self.store_root / artifacts.OBJECTS_DIR / artifacts.SHA256_DIR / sha
        object_path.write_bytes(b"corrupt-object-bytes")
        os.chmod(object_path, 0o444)

        with self.assertRaises(artifacts.ArtifactStoreError):
            self.seal()
        self.assertEqual(object_path.read_bytes(), b"corrupt-object-bytes")
        self.assertEqual(
            {entry.name for entry in config_dir.iterdir()},
            before_builds,
        )
        self.assertIn(seed_sealed.build_id, before_builds)

    def test_write_receipt_validates_hashes_commit_and_never_overwrites(self):
        sealed = self.seal()
        payload = {
            "sha256": sealed.sha256,
            "commit": sealed.commit,
            "fresh": False,
            "note": "wip-evidence-kept",
        }
        path = artifacts.write_receipt(sealed, payload)
        original = path.read_bytes()
        self.assertEqual(json.loads(original), payload)
        self.assertEqual(_mode(path) & 0o222, 0)

        with self.assertRaises(artifacts.ArtifactStoreError):
            artifacts.write_receipt(sealed, {"fresh": True})
        self.assertEqual(path.read_bytes(), original)

        other = self.seal(name="rootyard-other")
        with self.assertRaises(artifacts.ArtifactStoreError):
            artifacts.write_receipt(
                other, {"sha256": "0" * 64, "commit": other.commit}
            )
        self.assertFalse(other.receipt_path.exists())

        tampered_commit = sealed.__class__(
            sha256=sealed.sha256,
            object_path=sealed.object_path,
            binary_path=sealed.binary_path,
            receipt_path=sealed.receipt_path,
            commit="b" * 40,
            config_key=sealed.config_key,
            build_id=sealed.build_id,
            method=sealed.method,
            reused=sealed.reused,
            copied_bytes=sealed.copied_bytes,
        )
        with self.assertRaises(artifacts.ArtifactStoreError):
            artifacts.write_receipt(tampered_commit, {"fresh": True})

    def test_write_receipt_refuses_tampered_snapshot(self):
        sealed = self.seal()
        os.unlink(sealed.binary_path)
        sealed.binary_path.write_bytes(b"tampered-snapshot")
        os.chmod(sealed.binary_path, 0o444)

        with self.assertRaises(artifacts.ArtifactStoreError):
            artifacts.write_receipt(sealed, {"fresh": True})
        self.assertFalse(sealed.receipt_path.exists())

    def test_write_receipt_refuses_preexisting_symlink_target(self):
        sealed = self.seal()
        outside = self.tempdir / "outside-receipt"
        outside.write_text("preserve-me", encoding="utf-8")
        os.symlink(outside, sealed.receipt_path)

        with self.assertRaises(artifacts.ArtifactStoreError):
            artifacts.write_receipt(sealed, {"fresh": True})
        self.assertEqual(outside.read_text(encoding="utf-8"), "preserve-me")
        self.assertTrue(sealed.receipt_path.is_symlink())

    # -- traversal / store safety -------------------------------------------
    def test_traversal_and_symlink_inputs_are_refused(self):
        bad_arguments = (
            {"commit": "../escape"},
            {"config_key": "../escape"},
            {"build_id": "../../escape"},
            {"name": "../escape"},
        )
        for overrides in bad_arguments:
            with self.subTest(overrides=overrides):
                with self.assertRaises(artifacts.ArtifactStoreError):
                    self.seal(**overrides)
        self.assertFalse(self.store_root.exists())

        link = self.tempdir / "source-link"
        os.symlink(self.source, link)
        with self.assertRaises(artifacts.ArtifactStoreError):
            self.seal(link)

        store_link = self.tempdir / "store-link"
        os.symlink(self.store_root, store_link)
        with self.assertRaises(artifacts.ArtifactStoreError):
            self.seal(store_root=store_link)

        # A symlinked commit/config component must not be traversed.
        self.seal()
        outside = self.tempdir / "outside-config"
        outside.mkdir()
        config_dir = self.store_root / artifacts.SNAPSHOTS_DIR / self.commit
        other_config = artifacts.configuration_key({"profile": "other"})
        os.symlink(outside, config_dir / other_config)
        with self.assertRaises(artifacts.ArtifactStoreError):
            self.seal(config_key=other_config)
        self.assertFalse((outside / "rootyard").exists())

        # A symlink at the expected object path is refused, never reused.
        other_source = self.tempdir / "other-source"
        other_source.write_bytes(b"a-different-source-content")
        sha = hashlib.sha256(other_source.read_bytes()).hexdigest()
        object_path = self.store_root / artifacts.OBJECTS_DIR / artifacts.SHA256_DIR / sha
        os.symlink(other_source, object_path)
        with self.assertRaises(artifacts.ArtifactStoreError):
            self.seal(other_source)
        self.assertTrue(object_path.is_symlink())

    def test_unsafe_unowned_or_unmarked_stores_are_refused(self):
        self.seal()
        os.chmod(self.store_root, 0o777)
        try:
            with self.assertRaises(artifacts.ArtifactStoreError):
                self.seal()
        finally:
            os.chmod(self.store_root, 0o755)

        rogue = self.tempdir / "rogue-store"
        rogue.mkdir()
        keep = rogue / "keep-evidence"
        keep.write_text("do-not-delete", encoding="utf-8")
        with self.assertRaises(artifacts.ArtifactStoreError):
            self.seal(store_root=rogue)
        self.assertEqual(keep.read_text(encoding="utf-8"), "do-not-delete")
        self.assertFalse((rogue / artifacts.MARKER_NAME).exists())

        other_root = self.tempdir / "other-cas"
        real_uid = os.geteuid() if hasattr(os, "geteuid") else 0
        with mock.patch.object(artifacts, "_current_uid", return_value=real_uid + 1):
            with self.assertRaises(artifacts.ArtifactStoreError):
                self.seal(store_root=other_root)

    # -- clone fallback and concurrency -------------------------------------
    def test_unsupported_clone_falls_back_to_one_copy(self):
        with mock.patch.object(artifacts, "_reflink_supported", return_value=True), \
                mock.patch.object(artifacts, "_try_ficlone", return_value=False):
            sealed = self.seal()
        self.assertEqual(sealed.method, "copy")
        self.assertEqual(sealed.copied_bytes, len(self.source.read_bytes()))
        self.assertEqual(sealed.object_path.read_bytes(), self.source.read_bytes())

    def test_unverified_clone_is_discarded_for_a_verified_copy(self):
        with mock.patch.object(artifacts, "_reflink_supported", return_value=True), \
                mock.patch.object(artifacts, "_try_ficlone", return_value=True):
            sealed = self.seal()
        self.assertEqual(sealed.method, "copy")
        self.assertEqual(sealed.copied_bytes, len(self.source.read_bytes()))
        self.assertEqual(sealed.object_path.read_bytes(), self.source.read_bytes())

    def test_verified_clone_is_reported_as_reflink(self):
        def fake_clone(source_fd, dest_fd):
            os.lseek(source_fd, 0, os.SEEK_SET)
            os.lseek(dest_fd, 0, os.SEEK_SET)
            while True:
                chunk = os.read(source_fd, 65536)
                if not chunk:
                    break
                os.write(dest_fd, chunk)
            return True

        with mock.patch.object(artifacts, "_reflink_supported", return_value=True), \
                mock.patch.object(artifacts, "_try_ficlone", side_effect=fake_clone):
            sealed = self.seal()
        self.assertEqual(sealed.method, "reflink")
        self.assertEqual(sealed.copied_bytes, 0)
        self.assertEqual(sealed.object_path.read_bytes(), self.source.read_bytes())

    def test_concurrent_publish_reuses_one_validated_object(self):
        workers = 8
        barrier = threading.Barrier(workers)

        def worker(index):
            barrier.wait()
            return self.seal(build_id=f"build-{index:02d}")

        with ThreadPoolExecutor(max_workers=workers) as pool:
            sealed = list(pool.map(worker, range(workers)))

        self.assertEqual(len({item.sha256 for item in sealed}), 1)
        self.assertEqual(len({item.object_path for item in sealed}), 1)
        self.assertEqual(len({item.binary_path for item in sealed}), workers)
        self.assertEqual(len({item.receipt_path for item in sealed}), workers)
        self.assertEqual(sum(1 for item in sealed if item.reused), workers - 1)
        self.assertEqual(
            sum(1 for item in sealed if item.method in {"copy", "reflink"}), 1
        )
        object_path = sealed[0].object_path
        expected = _sha(object_path)
        for item in sealed:
            self.assertEqual(item.sha256, expected)
            self.assertTrue(item.binary_path.is_file())
            self.assertEqual(_sha(item.binary_path), expected)
        self.assertFalse(list(object_path.parent.glob(".*.tmp")))

    def test_concurrent_publish_across_processes_reuses_one_object(self):
        import multiprocessing

        if not hasattr(os, "fork"):
            self.skipTest("process-level concurrency needs fork")
        context = multiprocessing.get_context("fork")
        result_dir = self.tempdir / "process-results"
        result_dir.mkdir()
        workers = 6

        def worker(index):
            sealed = self.seal(build_id=f"proc-{index:02d}")
            (result_dir / f"{index}.json").write_text(
                json.dumps(
                    {
                        "sha256": sealed.sha256,
                        "object": str(sealed.object_path),
                        "binary": str(sealed.binary_path),
                        "method": sealed.method,
                        "reused": sealed.reused,
                    }
                ),
                encoding="utf-8",
            )

        processes = [
            context.Process(target=worker, args=(index,)) for index in range(workers)
        ]
        for process in processes:
            process.start()
        try:
            for process in processes:
                process.join(timeout=30)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
        self.assertEqual([process.exitcode for process in processes], [0] * workers)

        records = [
            json.loads((result_dir / f"{index}.json").read_text(encoding="utf-8"))
            for index in range(workers)
        ]
        self.assertEqual(len({record["sha256"] for record in records}), 1)
        self.assertEqual(len({record["object"] for record in records}), 1)
        self.assertEqual(len({record["binary"] for record in records}), workers)
        self.assertEqual(sum(1 for record in records if record["reused"]), workers - 1)
        for record in records:
            self.assertTrue(Path(record["binary"]).is_file())
            self.assertEqual(_sha(record["binary"]), record["sha256"])

    # -- preserve unknown and historical paths ------------------------------
    def test_unknown_paths_and_old_records_are_never_deleted_or_rewritten(self):
        first = self.seal()
        receipt = artifacts.write_receipt(
            first, {"sha256": first.sha256, "commit": first.commit, "fresh": False}
        )
        sentinel = self.store_root / "operator-evidence.txt"
        sentinel.write_bytes(b"preserve-this")
        old_snapshot = first.binary_path.read_bytes()
        old_receipt = receipt.read_bytes()

        self.source.write_bytes(b"new-evidence-producing-content")
        second = self.seal()
        self.assertFalse(second.reused)
        self.assertEqual(sentinel.read_bytes(), b"preserve-this")
        self.assertEqual(first.binary_path.read_bytes(), old_snapshot)
        self.assertEqual(receipt.read_bytes(), old_receipt)
        self.assertTrue(first.binary_path.exists())
        self.assertTrue(first.object_path.exists())


if __name__ == "__main__":
    unittest.main()
