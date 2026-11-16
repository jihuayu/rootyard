#!/usr/bin/env python3
"""Pure fake-context tests for the DB envelope negative-oracle seam.

No PostgreSQL, Vault, provider, subprocess, network or product binary is used.
Temporary files are dummy mirror/cache bytes only.  The tests capture the exact
one-field DB mutation, both cold CLI probes, cache eviction and restoration.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation_negative as negative  # noqa: E402
import pando_vault_rotation_support as support  # noqa: E402

REPO = "11111111-1111-4111-8111-111111111111"
PACK = "22222222-2222-4222-8222-222222222222"
ORIGINAL_MAC = "a" * 64
ORIGINAL_DIGEST = "b" * 64


class FakePsql:
    def __init__(self, record):
        self.record = record
        self.calls = []

    def set_envelope_auth(self, repo, pack, mac, cipher_sha):
        self.calls.append(("set", repo, pack, mac, cipher_sha))
        self.record["envelope_mac"] = mac
        self.record["ciphertext_sha256"] = cipher_sha

    def restore_envelope_auth(self, repo, pack, mac, cipher_sha):
        self.calls.append(("restore", repo, pack, mac, cipher_sha))
        self.record["envelope_mac"] = mac
        self.record["ciphertext_sha256"] = cipher_sha


class FakeContext:
    def __init__(self, root, results=None):
        self.root = type("Root", (), {"path": Path(root)})()
        self.repo = REPO
        self.pack_ids = [PACK]
        self.environment = {"fake": "1"}
        self.record = {
            "repo": REPO,
            "pack_id": PACK,
            "envelope_mac": ORIGINAL_MAC,
            "ciphertext_sha256": ORIGINAL_DIGEST,
        }
        self.psql = FakePsql(self.record)
        self.results = list(results or [])
        self.cli_calls = []
        self.db_at_cli = []
        self.evict_calls = []

    def envelope(self, pack):
        assert pack == PACK
        return dict(self.record)

    def cipher(self, pack):
        assert pack == PACK
        return b"PANDOENC-dummy-cipher-bytes"

    def evict(self, pack_ids=None):
        self.evict_calls.append(None if pack_ids is None else list(pack_ids))
        owned = self.pack_ids if pack_ids is None else pack_ids
        for pack in owned:
            for suffix in (".pack", ".idx"):
                path = (Path(self.root.path) / "objects" / self.repo
                        / (pack + suffix))
                if path.exists():
                    path.unlink()

    def run_status(self, args, env=None, stage="cli", timeout=90):
        self.cli_calls.append((list(args), stage))
        self.db_at_cli.append(dict(self.record))
        if not self.results:
            return support.Completed(args, 1, b"", b"")
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class DbEnvelopeFieldTamperTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.mirror = (self.root / "object_store" / "envelopes" / REPO
                       / (PACK + ".json"))
        self.mirror.parent.mkdir(parents=True)
        self.mirror.write_text(json.dumps({
            "repo": REPO,
            "pack_id": PACK,
            "envelope_mac": ORIGINAL_MAC,
            "ciphertext_sha256": ORIGINAL_DIGEST,
        }))
        self.ctx = FakeContext(self.root)
        owned = self.root / "objects" / REPO
        owned.mkdir(parents=True)
        (owned / (PACK + ".pack")).write_bytes(b"dummy pack cache")
        (owned / (PACK + ".idx")).write_bytes(b"dummy idx cache")

    def tearDown(self):
        self.temporary.cleanup()

    def test_mac_only_mutation_keeps_digest_and_runs_both_cold_cli_probes(self):
        self.assertTrue(negative.probe_db_envelope_field_tamper(
            self.ctx, PACK, "envelope_mac", "db_mac"))
        mutations = [call for call in self.ctx.psql.calls if call[0] == "set"]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][3], "0" * 64)
        self.assertEqual(mutations[0][4], ORIGINAL_DIGEST)
        self.assertEqual([call[0][0] for call in self.ctx.cli_calls],
                         ["kms-verify", "object-store-get"])
        self.assertEqual(self.ctx.evict_calls, [None, [PACK]])
        for observed in self.ctx.db_at_cli:
            self.assertEqual(observed["envelope_mac"], "0" * 64)
            self.assertEqual(observed["ciphertext_sha256"], ORIGINAL_DIGEST)
        self.assertEqual(self.ctx.envelope(PACK)["envelope_mac"], ORIGINAL_MAC)
        self.assertEqual(self.ctx.envelope(PACK)["ciphertext_sha256"],
                         ORIGINAL_DIGEST)
        self.assertEqual(self.ctx.psql.calls[-1],
                         ("restore", REPO, PACK, ORIGINAL_MAC, ORIGINAL_DIGEST))
        self.assertEqual(json.loads(self.mirror.read_text())["envelope_mac"],
                         ORIGINAL_MAC)
        self.assertFalse((self.root / "objects" / REPO / (PACK + ".pack")).exists())
        self.assertFalse((self.root / "objects" / REPO / (PACK + ".idx")).exists())

    def test_digest_only_mutation_keeps_mac(self):
        self.assertTrue(negative.probe_db_envelope_field_tamper(
            self.ctx, PACK, "ciphertext_sha256", "db_digest"))
        mutations = [call for call in self.ctx.psql.calls if call[0] == "set"]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][3], ORIGINAL_MAC)
        self.assertEqual(mutations[0][4], "0" * 64)
        for observed in self.ctx.db_at_cli:
            self.assertEqual(observed["envelope_mac"], ORIGINAL_MAC)
            self.assertEqual(observed["ciphertext_sha256"], "0" * 64)
        self.assertEqual(self.ctx.envelope(PACK)["envelope_mac"], ORIGINAL_MAC)
        self.assertEqual(self.ctx.envelope(PACK)["ciphertext_sha256"],
                         ORIGINAL_DIGEST)

    def test_unexpected_probe_success_still_restores_exact_db_fixture(self):
        self.ctx.results = [support.Completed(["fake"], 0, b"{}", b"")]
        with self.assertRaises(support.QualificationError) as caught:
            negative.probe_db_envelope_field_tamper(
                self.ctx, PACK, "ciphertext_sha256", "db_digest")
        self.assertEqual(caught.exception.code,
                         "db_digest_verify_unexpected_success")
        self.assertEqual(self.ctx.envelope(PACK)["envelope_mac"], ORIGINAL_MAC)
        self.assertEqual(self.ctx.envelope(PACK)["ciphertext_sha256"],
                         ORIGINAL_DIGEST)
        self.assertEqual(self.ctx.psql.calls[-1][0], "restore")

    def test_missing_mirror_blocks_mutation_before_any_db_write(self):
        self.mirror.unlink()
        with self.assertRaises(support.QualificationError) as caught:
            negative.probe_db_envelope_field_tamper(
                self.ctx, PACK, "envelope_mac", "db_mac")
        self.assertEqual(caught.exception.code, "healthy_mirror_missing")
        self.assertEqual(self.ctx.psql.calls, [])
        self.assertEqual(self.ctx.envelope(PACK)["envelope_mac"], ORIGINAL_MAC)

    def test_mirror_must_match_healthy_db_before_mutation(self):
        self.mirror.write_text(json.dumps({
            "repo": REPO,
            "pack_id": PACK,
            "envelope_mac": "c" * 64,
            "ciphertext_sha256": ORIGINAL_DIGEST,
        }))
        with self.assertRaises(support.QualificationError) as caught:
            negative.probe_db_envelope_field_tamper(
                self.ctx, PACK, "ciphertext_sha256", "db_digest")
        self.assertEqual(caught.exception.code, "healthy_mirror_db_mismatch")
        self.assertEqual(self.ctx.psql.calls, [])


if __name__ == "__main__":
    unittest.main()
