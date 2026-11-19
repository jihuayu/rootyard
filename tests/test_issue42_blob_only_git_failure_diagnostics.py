"""Pure synthetic checks for the Blob-only Git failure diagnostic contract.

No Git process, service, database, network or Cargo is used. The diagnostics
may inspect synthetic stdout/stderr internally, but must expose only an integer
exit status, fixed class strings and fixed porcelain flags.
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
        self.assertIs(type(diagnostic["unknown"]), bool)
        self.assertIs(type(diagnostic["porcelain"]["entries"]), int)
        for key in ("ok", "rejected"):
            self.assertIs(type(diagnostic["porcelain"][key]), bool)
        for key in ("unpack_ok", "unpack_failed", "ok", "ng"):
            self.assertIs(type(diagnostic["report_status"][key]), bool)
        self.assertTrue(all(type(value) is str for value in diagnostic["classes"]))
        self.assertTrue(all(type(value) is str for value in diagnostic["markers"]))
        self.assertTrue(all(value in blob._DIAGNOSTIC_PORCELAIN_FLAGS
                            for value in diagnostic["porcelain"]["flags"]))

    def test_porcelain_rejection_is_classified(self):
        diagnostic = blob.git_failure(process(
            stdout=(b"To https://user:token@secret.example/secret.git\n"
                    b"!\trefs/heads/secret-ref:refs/heads/secret-ref "
                    b"[remote rejected] (non-fast-forward)\n"
                    b"Done\n"),
            stderr=(b"error: failed to push some refs to "
                    b"'https://user:token@secret.example/secret.git'\n"),
        ))
        self.assertEqual(diagnostic["exit"], 1)
        self.assertEqual(diagnostic["porcelain"],
                         {"entries": 1, "ok": False, "rejected": True, "flags": ["!"]})
        self.assertIn("porcelain-rejected", diagnostic["classes"])
        self.assertIn("porcelain-remote-rejected", diagnostic["classes"])
        self.assertIn("porcelain-non-fast-forward", diagnostic["classes"])
        self.assertIn("stderr-failed-to-push", diagnostic["classes"])
        self.assertFalse(diagnostic["unknown"])
        self.assert_closed(diagnostic)

    def test_report_status_ng_and_unpack_failure_are_classified(self):
        rejected = blob.git_failure(process(
            stdout=b"unpack ok\nng refs/heads/secret-ref protected branch\n",
            stderr=b"error: failed to push some refs\n",
        ))
        self.assertTrue(rejected["report_status"]["unpack_ok"])
        self.assertTrue(rejected["report_status"]["ng"])
        self.assertIn("report-status-ng", rejected["classes"])
        self.assertIn("report-status-protected-branch", rejected["classes"])
        self.assert_closed(rejected)

        unpack_failed = blob.git_failure(process(
            stdout=b"unpack index-pack failed\n",
            stderr=b"",
        ))
        self.assertTrue(unpack_failed["report_status"]["unpack_failed"])
        self.assertIn("report-status-unpack-failed", unpack_failed["classes"])
        self.assert_closed(unpack_failed)

    def test_transport_auth_and_http_classes_are_closed(self):
        diagnostic = blob.git_failure(process(
            stdout=b"",
            stderr=(b"fatal: unable to access "
                    b"'https://user:token@secret.example/secret.git/': "
                    b"The requested URL returned error: 503\n"),
        ))
        self.assertIn("stderr-unable-to-access", diagnostic["classes"])
        self.assertIn("stderr-http-503", diagnostic["classes"])
        self.assert_closed(diagnostic)

    def test_unknown_fallback_and_non_integer_exit_are_closed(self):
        diagnostic = blob.git_failure(process(
            stdout=b"raw stdout body /tmp/secret",
            stderr=b"raw stderr body token-123",
            returncode=None,
        ))
        self.assertEqual(diagnostic["exit"], -1)
        self.assertTrue(diagnostic["unknown"])
        self.assertEqual(diagnostic["classes"], ["unclassified"])
        self.assert_closed(diagnostic)

    def test_porcelain_success_flag_is_reported_without_refname(self):
        diagnostic = blob.git_failure(process(
            stdout=(b"To https://user:token@secret.example/secret.git\n"
                    b" \trefs/heads/secret-ref:refs/heads/secret-ref [new branch]\n"
                    b"Done\n"),
            stderr=b"",
        ))
        self.assertTrue(diagnostic["porcelain"]["ok"])
        self.assertEqual(diagnostic["porcelain"]["flags"], [" "])
        self.assertIn("porcelain-ok", diagnostic["classes"])
        self.assert_closed(diagnostic)


if __name__ == "__main__":
    unittest.main()
