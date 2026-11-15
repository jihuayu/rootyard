#!/usr/bin/env python3
"""Contract and structural tests for Issue #37 bounded active transfer revocation."""
import ast
import http.client
import os
from pathlib import Path
import sys
import time
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))


class TestTransferRevocationContract(unittest.TestCase):
    def test_modular_structure_and_hygiene(self):
        revocation = ROOT / "src" / "git_http" / "revocation.rs"
        revocation_tests = ROOT / "src" / "git_http" / "revocation_tests.rs"
        self.assertTrue(revocation.is_file(), "Missing src/git_http/revocation.rs")
        self.assertTrue(revocation_tests.is_file(), "Missing src/git_http/revocation_tests.rs")
        self.assertFalse((ROOT / "src" / "git_http" / "mod.rs").exists())

        for rel in (
            "src/git_http/revocation.rs",
            "src/git_http/revocation_tests.rs",
            "src/auth.rs",
            "src/config.rs",
            "src/git_http/pando_receive.rs",
            "src/lfs/handlers.rs",
            "src/ci_checkouts/authority.rs",
            "src/ci_checkouts/mirror_lfs.rs",
            "src/ci_checkouts/mirror_prepare.rs",
            "src/mirror/sync.rs",
        ):
            path = ROOT / rel
            lines = len(path.read_text(encoding="utf-8").splitlines())
            self.assertLessEqual(lines, 500, f"{rel} exceeds 500-line submodule bound ({lines}L)")

        for rel in (
            "src/git_http/revocation.rs",
            "src/git_http/revocation_tests.rs",
            "src/git_http/process.rs",
            "src/auth.rs",
            "src/ci_checkouts/mirror_lfs.rs",
            "src/ci_checkouts/mirror_prepare.rs",
            "src/mirror/sync.rs",
        ):
            src = (ROOT / rel).read_text(encoding="utf-8")
            self.assertNotIn("#[allow(dead_code)]", src, f"{rel} must not use #[allow(dead_code)]")

    def test_revocation_bound_env_and_docs(self):
        revocation_src = (ROOT / "src" / "git_http" / "revocation.rs").read_text(encoding="utf-8")
        for symbol in (
            'pub const REVOCATION_BOUND_ENV: &str = "ROOTYARD_TRANSFER_REVOCATION_BOUND_MS"',
            "pub const DEFAULT_REVOCATION_BOUND_MS: u64 = 3_000;",
            "pub const MIN_REVOCATION_BOUND_MS: u64 = 300;",
            "pub const MAX_REVOCATION_BOUND_MS: u64 = 60_000;",
            "pub struct RevocationBound",
            "pub(crate) fn validate_env()",
            "pub(crate) fn bound()",
            "pub(crate) async fn verify_transfer_authority(",
            "pub(crate) async fn transfer_authorized(",
            "pub(crate) async fn await_with_reauth<",
            "pub(crate) async fn collect_git_output_reauthorized<",
            "pub(crate) fn stream_body_with_reauth<",
        ):
            self.assertIn(symbol, revocation_src, f"Missing symbol in revocation.rs: {symbol}")

        config_src = (ROOT / "src" / "config.rs").read_text(encoding="utf-8")
        self.assertIn("crate::git_http::revocation::validate_env()?", config_src)

        docs_src = (ROOT / "docs" / "ci-mirror.md").read_text(encoding="utf-8")
        self.assertIn("ROOTYARD_TRANSFER_REVOCATION_BOUND_MS", docs_src)
        self.assertIn("check_interval", docs_src)
        self.assertIn("reauth_timeout", docs_src)
        self.assertIn("stop_grace", docs_src)

    def test_auth_process_and_streaming_wiring(self):
        auth_src = (ROOT / "src" / "auth.rs").read_text(encoding="utf-8")
        for snippet in (
            "pub async fn verify_active_transfer(",
            "verify_active_inner(",
            "verify_token(",
            "resolve_effective_role(",
            "authorize_repository_for_request(",
            "storage_generation",
        ):
            self.assertIn(snippet, auth_src, f"Missing active transfer check in src/auth.rs: {snippet}")

        proc_src = (ROOT / "src" / "git_http" / "process.rs").read_text(encoding="utf-8")
        for snippet in (
            "pub(super) async fn stop_with_grace(",
            "async fn terminate_group_with_grace(",
            "async fn wait_pid_group_quiescent(",
            "pub(crate) fn group_quiescent(",
            "super::revocation::bound().stop_grace",
        ):
            self.assertIn(snippet, proc_src, f"Missing bounded cleanup helper in process.rs: {snippet}")

        git_http_src = (ROOT / "src" / "git_http.rs").read_text(encoding="utf-8")
        self.assertIn("pub(crate) mod revocation;", git_http_src)
        self.assertIn("revocation::await_with_reauth(", git_http_src)
        self.assertIn("process.stop_with_grace(bound.stop_grace)", git_http_src)

        pando_src = (ROOT / "src" / "git_http" / "pando_receive.rs").read_text(encoding="utf-8")
        self.assertIn("super::revocation::bound()", pando_src)
        self.assertIn("process.stop_with_grace(bound.stop_grace)", pando_src)

        lfs_src = (ROOT / "src" / "lfs" / "handlers.rs").read_text(encoding="utf-8")
        self.assertIn("stream_body_with_reauth(", lfs_src)
        self.assertIn("verify_active_transfer(", lfs_src)

        mirror_lfs_src = (ROOT / "src" / "ci_checkouts" / "mirror_lfs.rs").read_text(encoding="utf-8")
        self.assertIn("revocation::stream_body_with_reauth(", mirror_lfs_src)
        self.assertIn("ci_checkouts::still_authorized(", mirror_lfs_src)

    def test_mirror_prepare_origin_non_bypass(self):
        auth_src = (ROOT / "src" / "ci_checkouts" / "authority.rs").read_text(encoding="utf-8")
        self.assertIn("AND r.storage_generation=$3", auth_src)

        prep_src = (ROOT / "src" / "ci_checkouts" / "mirror_prepare.rs").read_text(encoding="utf-8")
        for snippet in (
            "enum PrepareAuth",
            "pub(crate) async fn user_job_active(",
            "pub(crate) async fn verify_mirror_sync_authority(",
            "revocation::await_with_reauth(",
            "prep_auth.verify(",
        ):
            self.assertIn(snippet, prep_src, f"Missing non-bypass guard in mirror_prepare.rs: {snippet}")

        sync_src = (ROOT / "src" / "mirror" / "sync.rs").read_text(encoding="utf-8")
        self.assertIn("pub(crate) async fn sync_user_job(", sync_src)
        self.assertIn("collect_git_output_reauthorized(", sync_src)
        self.assertIn("verify_mirror_sync_authority(", sync_src)

    def test_acceptance_harnesses_declare_revocation_cases(self):
        harness_path = ROOT / "tests" / "ci_job_checkouts.py"
        harness_src = harness_path.read_text(encoding="utf-8")
        tree = ast.parse(harness_src, filename=str(harness_path))
        cls = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "JobCheckoutHarness"
        )
        methods = {node.name for node in cls.body if isinstance(node, ast.FunctionDef)}
        for expected in ("bounded_active_transfer_revocation", "mirror_cannot_bypass_revocation_via_origin"):
            self.assertIn(expected, methods, f"Missing method {expected} in JobCheckoutHarness")
            self.assertIn(f'"{expected}"', harness_src, f"Missing main() registration for {expected}")

        standalone_src = (ROOT / "tests" / "transfer_revocation.py").read_text(encoding="utf-8")
        for expected in (
            "ROOTYARD_TRANSFER_REVOCATION_BOUND_MS",
            "collaborators/bob",
            "storage_generation=2",
            "expires_at",
        ):
            self.assertIn(expected, standalone_src)

    def test_harness_stream_helpers_handle_non_float_and_float_revoke_returns(self):
        extra = {}
        if not hasattr(os, "O_DIRECTORY") and "owned_fuse_cleanup" not in sys.modules:
            extra["owned_fuse_cleanup"] = types.ModuleType("owned_fuse_cleanup")
        with mock.patch.dict(sys.modules, extra):
            import ci_job_checkouts  # noqa: E402

        class FakeResponse:
            def __init__(self, *, content_length=None):
                self.status = 200
                self._content_length = content_length
                self._calls = 0

            def getheader(self, name):
                if name == "Content-Length":
                    return str(self._content_length)
                return None

            def read(self, _amt=None):
                self._calls += 1
                if self._calls == 1:
                    return b"x" * 4096 if self._content_length is None else b"x" * 1024
                if self._calls == 2:
                    return b"y" * 128
                raise http.client.IncompleteRead(b"")

        class FakeConn:
            def __init__(self, content_length=None):
                self._content_length = content_length
                self.closed = False

            def request(self, *_args, **_kwargs):
                pass

            def getresponse(self):
                return FakeResponse(content_length=self._content_length)

            def close(self):
                self.closed = True

        class DummyHarness:
            _barrier_available = lambda self: False  # noqa: E731
            _stream_git_until_revoked = ci_job_checkouts.JobCheckoutHarness._stream_git_until_revoked
            _stream_lfs_until_revoked = ci_job_checkouts.JobCheckoutHarness._stream_lfs_until_revoked

        dummy = DummyHarness()
        token = {"token": "ryt_dummy"}
        for revoke_fn in (
            lambda: "cli stdout",
            lambda: b"http body",
            lambda: None,
            lambda: time.monotonic(),
        ):
            with mock.patch("http.client.HTTPConnection", return_value=FakeConn()):
                git_res = dummy._stream_git_until_revoked(
                    "http://127.0.0.1:9", "/git/a/b.git", token, "0" * 40, 1024 * 1024, revoke_fn
                )
                self.assertLess(git_res["elapsed_seconds"], 5.0)
            with mock.patch("http.client.HTTPConnection", return_value=FakeConn(content_length=1024 * 1024)):
                lfs_res = dummy._stream_lfs_until_revoked(
                    "http://127.0.0.1:9", "/lfs/obj", token, 1024 * 1024, revoke_fn, pause_after_first=0.0
                )
                self.assertLess(lfs_res["elapsed_seconds"], 5.0)


if __name__ == "__main__":
    unittest.main()
