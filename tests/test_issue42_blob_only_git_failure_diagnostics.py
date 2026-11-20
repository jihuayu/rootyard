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
        self.assertIs(type(diagnostic["http_status"]), str)
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
        self.assertEqual(diagnostic["http_status"], "unknown")
        self.assert_closed(diagnostic)

    def test_http_status_uses_only_the_closed_allowlist(self):
        for code in ("400", "403", "404", "409", "422", "429", "500", "502", "503", "504"):
            diagnostic = blob.push_failure(process(
                stderr=(b"error: RPC failed; HTTP " + code.encode() + b" curl 22 "
                        b"The requested URL returned error: " + code.encode() + b"\n"),
            ))
            self.assertEqual(diagnostic["http_status"], code)
            self.assert_closed(diagnostic)
        for code in ("200", "301", "302", "304", "600", "999"):
            diagnostic = blob.push_failure(process(
                stderr=(b"error: RPC failed; HTTP " + code.encode() + b" curl 22 "
                        b"The requested URL returned error: " + code.encode() + b"\n"),
            ))
            self.assertEqual(diagnostic["http_status"], "unknown")
            self.assert_closed(diagnostic)

    def test_rpc_http_status_is_attributed_only_once(self):
        diagnostic = blob.push_failure(process(
            stderr=(b"error: RPC failed; HTTP 502 curl 22 "
                    b"The requested URL returned error: 502\n"),
        ))
        self.assertEqual(diagnostic["http_status"], "502")
        self.assert_closed(diagnostic)
        conflicting = blob.push_failure(process(
            stderr=(b"error: RPC failed; HTTP 502 curl 22 "
                    b"The requested URL returned error: 503\n"),
        ))
        self.assertEqual(conflicting["http_status"], "unknown")
        self.assert_closed(conflicting)

    def test_fatal_only_proxy_connect_and_bare_rpc_are_unknown(self):
        fatal_only = blob.push_failure(process(
            stderr=(b"fatal: unable to access "
                    b"'https://user:token@secret.example/repo.git/info/refs"
                    b"?service=git-receive-pack': "
                    b"The requested URL returned error: 503\n"),
        ))
        self.assertEqual(fatal_only["http_status"], "unknown")
        self.assertIn("http", fatal_only["stderr"])
        self.assert_closed(fatal_only)

        proxy = blob.push_failure(process(
            stderr=(b"error: RPC failed; HTTP 407 curl 56 "
                    b"Received HTTP code 407 from proxy after CONNECT\n"),
        ))
        self.assertEqual(proxy["http_status"], "unknown")
        self.assertIn("rpc", proxy["stderr"])
        self.assert_closed(proxy)

        bare = blob.push_failure(process(
            stderr=b"error: RPC failed; HTTP 503 curl\n",
        ))
        self.assertEqual(bare["http_status"], "unknown")
        self.assert_closed(bare)

        known_good = blob.push_failure(process(
            stderr=(b"error: RPC failed; HTTP 503 curl 22 "
                    b"The requested URL returned error: 503\n"),
        ))
        self.assertEqual(known_good["http_status"], "503")
        self.assert_closed(known_good)

    def test_fatal_url_digits_never_supply_status(self):
        quoted = blob.push_failure(process(
            stderr=(b"fatal: unable to access "
                    b"'https://user:token@secret.example/http 500/"
                    b"The requested URL returned error: 503/status/429.git': "
                    b"Could not resolve host: secret.example\n"),
        ))
        self.assertEqual(quoted["http_status"], "unknown")
        self.assert_closed(quoted)
        unquoted = blob.push_failure(process(
            stderr=(b"fatal: unable to access "
                    b"https://user:token@secret.example/http:500/returned-error:503.git: "
                    b"Could not resolve host: secret.example\n"),
        ))
        self.assertEqual(unquoted["http_status"], "unknown")
        self.assert_closed(unquoted)
        noisy = blob.push_failure(process(
            stderr=(b"fatal: unable to access "
                    b"'https://user:token@secret.example/http 500/r.git': "
                    b"The requested URL returned error: 500\n"
                    b"error: RPC failed; HTTP 503 curl 22 "
                    b"The requested URL returned error: 503\n"),
        ))
        self.assertEqual(noisy["http_status"], "503")
        self.assert_closed(noisy)

    def test_sideband_headers_and_prefixes_cannot_supply_status(self):
        for stderr in (
            b"remote: HTTP 503\n",
            b"remote: The requested URL returned error: 503\n",
            b"X-HTTP 503\n",
            b"proxy: HTTP 503\n",
            b"HTTP/1.1 503 Service Unavailable\n",
            b"error: proxy handshake failed; HTTP 503\n",
            b"warning: unable to access 'https://user:token@secret.example/r.git/': "
            b"The requested URL returned error: 503\n",
        ):
            diagnostic = blob.push_failure(process(stderr=stderr))
            self.assertEqual(diagnostic["http_status"], "unknown")
            self.assert_closed(diagnostic)

        mixed = blob.push_failure(process(
            stderr=(b"remote: HTTP 503\n"
                    b"remote: The requested URL returned error: 500\n"
                    b"X-HTTP 500\n"
                    b"HTTP/1.1 500 Internal Server Error\n"
                    b"fatal: unable to access 'https://user:token@secret.example/r.git/': "
                    b"The requested URL returned error: 500\n"
                    b"error: RPC failed; HTTP 503 curl 22 "
                    b"The requested URL returned error: 503\n"),
        ))
        self.assertEqual(mixed["http_status"], "503")
        self.assert_closed(mixed)

        conflicting = blob.push_failure(process(
            stderr=(b"error: RPC failed; HTTP 503 curl 22 "
                    b"The requested URL returned error: 503\n"
                    b"error: RPC failed; HTTP 500 curl 22 "
                    b"The requested URL returned error: 500\n"),
        ))
        self.assertEqual(conflicting["http_status"], "unknown")
        self.assert_closed(conflicting)

    def test_ambiguous_and_challenge_only_statuses_are_unknown(self):
        ambiguous = blob.push_failure(process(
            stderr=(b"error: RPC failed; HTTP 500 curl 22 "
                    b"The requested URL returned error: 500\n"
                    b"error: RPC failed; HTTP 503 curl 22 "
                    b"The requested URL returned error: 503\n"),
        ))
        self.assertEqual(ambiguous["http_status"], "unknown")
        self.assert_closed(ambiguous)
        challenge = blob.push_failure(process(
            stderr=(b"remote: HTTP Basic: Access denied\n"
                    b"fatal: Authentication failed for "
                    b"'https://user:token@secret.example/r.git/'\n"),
        ))
        self.assertEqual(challenge["http_status"], "unknown")
        self.assert_closed(challenge)

    def test_http_status_output_contains_no_raw_stderr_or_headers(self):
        diagnostic = blob.push_failure(process(
            stdout=b"raw stdout body",
            stderr=(b"error: RPC failed; HTTP 503 curl 22 "
                    b"The requested URL returned error: 503\n"
                    b"Authorization: Bearer token-123\n"
                    b"WWW-Authenticate: Basic realm=\"secret.example\"\n"),
        ))
        self.assertEqual(diagnostic["http_status"], "503")
        self.assertEqual(set(diagnostic),
                         {"exit", "flag", "summary", "http_status", "stderr"})
        encoded = json.dumps(diagnostic)
        for raw in ("Authorization", "WWW-Authenticate", "Bearer",
                    "secret.example", "token-123", "raw stdout body"):
            self.assertNotIn(raw, encoded)
        self.assert_closed(diagnostic)

    def test_ordinary_exit_rpc_disconnect_and_unknown_outcome(self):
        rpc = blob.push_failure(process(
            stdout=b"",
            stderr=b"error: RPC failed; curl 56 Unexpected disconnect\n",
        ))
        self.assertEqual(rpc["exit"], 1)
        self.assertEqual(rpc["flag"], "none")
        self.assertEqual(rpc["summary"], "unclassified")
        self.assertEqual(rpc["http_status"], "unknown")
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
        self.assertEqual(unknown["http_status"], "unknown")
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
