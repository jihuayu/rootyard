"""Pure synthetic checks for the narrow Blob-only stock-push diagnostic.

No Git process, service, database, network or Cargo is used. The diagnostic may
inspect synthetic stdout/stderr internally, but must expose only an integer exit
status, a fixed porcelain flag/summary class, and fixed stderr signatures.
"""
import json
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))
import blob_only_service as blob  # noqa: E402

SECRETS = (
    "secret-ref",
    "refs/heads/secret-ref",
    "remote-rejected-ref",
    "secret.example",
    "user:token",
    "token-123",
    "/tmp/secret",
    "raw stderr body",
    "raw stdout body",
)


def process(stdout=b"", stderr=b"", returncode=1):
    return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


class BlobOnlyGitFailureDiagnosticsTest(unittest.TestCase):
    def assert_closed(self, diagnostic):
        encoded = json.dumps(diagnostic)
        for secret in SECRETS:
            self.assertNotIn(secret, encoded)
        self.assertIs(type(diagnostic["exit"]), int)
        self.assertIs(type(diagnostic["flag"]), str)
        self.assertIs(type(diagnostic["summary"]), str)
        self.assertTrue(all(type(value) is str for value in diagnostic["stderr"]))

    def test_fake_refspec_and_path_markers_cannot_forge_summary(self):
        diagnostic = blob.push_failure(process(
            stdout=(b"!\trefs/heads/remote-rejected-ref:/tmp/secret/remote-rejected-ref"
                    b"\t[up to date]\n"),
            stderr=b"error: failed to push some refs to https://user:token@secret.example/r.git\n",
        ))
        self.assertEqual(diagnostic["flag"], "!")
        self.assertEqual(diagnostic["summary"], "up-to-date")
        self.assertNotEqual(diagnostic["summary"], "remote-rejected")
        self.assertIn("failed-to-push", diagnostic["stderr"])
        self.assert_closed(diagnostic)

    def test_rejection_summary_and_http_signature_are_attributed(self):
        diagnostic = blob.push_failure(process(
            stdout=b"!\trefs/heads/secret-ref:/tmp/secret\t[remote rejected] (pre-receive hook declined)\n",
            stderr=(b"fatal: unable to access "
                    b"'https://user:token@secret.example/secret.git/': "
                    b"The requested URL returned error: 503\n"),
        ))
        self.assertEqual(diagnostic["flag"], "!")
        self.assertEqual(diagnostic["summary"], "remote-rejected")
        self.assertIn("unable to access", diagnostic["stderr"])
        self.assertIn("http", diagnostic["stderr"])
        self.assert_closed(diagnostic)

    def test_ordinary_exit_rpc_disconnect_and_unknown_outcome(self):
        rpc = blob.push_failure(process(
            stdout=b"",
            stderr=b"error: RPC failed; curl 56 Unexpected disconnect\n",
        ))
        self.assertEqual(rpc["exit"], 1)
        self.assertEqual(rpc["flag"], "none")
        self.assertEqual(rpc["summary"], "unclassified")
        self.assertIn("rpc", rpc["stderr"])
        self.assertIn("disconnect", rpc["stderr"])
        self.assert_closed(rpc)

        unknown = blob.push_failure(process(
            stdout=b"raw stdout body",
            stderr=b"raw stderr body token-123",
            returncode=None,
        ))
        self.assertEqual(unknown["exit"], -1)
        self.assertEqual(unknown["flag"], "none")
        self.assertEqual(unknown["summary"], "unclassified")
        self.assertEqual(unknown["stderr"], ["unclassified"])
        self.assert_closed(unknown)

    def test_original_git_failure_is_unchanged(self):
        self.assertEqual(
            blob.git_failure(process(
                stdout=b"!\trefs/heads/secret-ref:/tmp/secret\t[remote rejected]\n",
                stderr=b"non-fast-forward\n",
                returncode=1,
            )),
            {"exit": 1, "markers": ["non-fast-forward"]},
        )
        self.assertEqual(
            blob.git_failure(process(
                stdout=b"!\trefs/heads/secret-ref:/tmp/secret\t[remote rejected]\n",
                stderr=b"",
                returncode=1,
            )),
            {"exit": 1, "markers": []},
        )


if __name__ == "__main__":
    unittest.main()
