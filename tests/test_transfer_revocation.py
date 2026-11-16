#!/usr/bin/env python3
"""Contract and structural tests for Issue #37 bounded active transfer revocation."""
import ast
import http.client
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))

import transfer_revocation_observer as revocation_observer  # noqa: E402
import transfer_revocation_timing as revocation_timing  # noqa: E402
import transfer_revocation_transport as revocation_transport  # noqa: E402


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

    def test_trigger_interval_uses_t_before_and_never_resets_on_api_return(self):
        interval = revocation_timing.TriggerInterval("revoke", 1_000_000_000, 1_400_000_000)
        self.assertEqual(interval.duration_ns, 400_000_000)
        self.assertEqual(interval.deadline_ns(1200), 2_200_000_000)
        self.assertEqual(
            interval.deadline_ns(1200) - interval.t_after_ns,
            800_000_000,
            "the deadline must not be recomputed from mutation completion",
        )
        with self.assertRaises(ValueError):
            revocation_timing.TriggerInterval("bad", 1, 0)

    def test_natural_expiry_uses_earliest_mapping_and_rejects_jump(self):
        first = revocation_timing.DbClockSample(1_000_000_000, 1_000_100_000, 100.0)
        second = revocation_timing.DbClockSample(2_000_000_000, 2_000_100_000, 101.0)
        clock = revocation_timing.reconcile_expiry([first, second], 110.0)
        self.assertEqual(clock.earliest_ns, 11_000_000_000)
        self.assertEqual(clock.latest_ns, 11_000_100_000)
        self.assertEqual(clock.samples, 2)
        with self.assertRaises(revocation_timing.InconsistentClockMapping):
            revoked = revocation_timing.DbClockSample(1_000_000_000, 1_000_100_000, 100.0)
            jumped = revocation_timing.DbClockSample(1_000_000_000, 1_000_100_000, 100.2)
            revocation_timing.reconcile_expiry([revoked, jumped], 110.0)

    def test_timeout_local_close_and_deadline_are_not_confirmed_server_stops(self):
        kind, _ = revocation_timing.classify_read_error(socket.timeout("local read timeout"))
        self.assertEqual(kind, revocation_timing.StopKind.TIMEOUT)
        self.assertFalse(revocation_timing.StopObservation(kind, 1, 0).confirmed)
        for error in (ConnectionResetError(), ConnectionAbortedError(), BrokenPipeError()):
            stop, _ = revocation_timing.classify_read_error(error)
            self.assertEqual(stop, revocation_timing.StopKind.RESET)

    def test_confirmed_truncation_short_eof_and_complete_are_distinct(self):
        incomplete, partial = revocation_timing.classify_read_error(
            http.client.IncompleteRead(b"x" * 17)
        )
        self.assertEqual(incomplete, revocation_timing.StopKind.INCOMPLETE_READ)
        self.assertEqual(partial, 17)
        self.assertTrue(revocation_timing.StopObservation(
            incomplete, 1, 17).confirmed)
        self.assertEqual(
            revocation_timing.classify_clean_eof(
                framing="content_length", received=10, expected_size=20
            ),
            revocation_timing.StopKind.SHORT_EOF,
        )
        self.assertEqual(
            revocation_timing.classify_clean_eof(
                framing="content_length", received=20, expected_size=20
            ),
            revocation_timing.StopKind.COMPLETE,
        )
        self.assertFalse(revocation_timing.StopObservation(
            revocation_timing.StopKind.COMPLETE, 1, 20).confirmed)

    def test_owned_group_discovery_tracks_all_members_not_only_git_names(self):
        table = {
            100: revocation_observer.ProcStat(100, "S", 1, 100, 10),
            200: revocation_observer.ProcStat(200, "S", 100, 200, 20),
            201: revocation_observer.ProcStat(201, "S", 200, 200, 21),
            300: revocation_observer.ProcStat(300, "S", 999, 300, 30),
        }
        groups = revocation_observer.discover_groups(table, [100])
        self.assertEqual(groups, [revocation_observer.GroupIdentity(200, 200, 20)])
        track = revocation_observer.GroupTrack(groups[0])
        track.observe([table[200], table[201]], 1_000)
        self.assertEqual(track.max_members, 2)
        self.assertEqual(track.last_live_ns, 1_000)

    def test_pid_or_pgid_reuse_is_a_counterexample_not_a_pass(self):
        identity = revocation_observer.GroupIdentity(200, 200, 1_000)
        reused = {200: revocation_observer.ProcStat(200, "S", 100, 200, 2_000)}
        self.assertTrue(revocation_observer.leader_reused(identity, reused))
        self.assertFalse(revocation_observer.leader_reused(identity, {
            200: revocation_observer.ProcStat(200, "S", 100, 200, 1_000)
        }))
        observer = revocation_observer.ProcGroupObserver([100], clock=lambda: 0)
        observer.armed_ns = 100
        observer.max_poll_gap_ns = 10
        observer._tracks = {200: revocation_observer.GroupTrack(
            identity, first_live_ns=100, last_live_ns=500,
            quiescent_ns=800, max_members=2,
        )}
        self.assertTrue(observer.proven(400, 1_200))
        observer._tracks[200].reuse_detected = True
        self.assertFalse(observer.proven(400, 1_200))

    def test_proc_table_reader_does_not_need_environment_or_cmdline(self):
        with tempfile.TemporaryDirectory() as root:
            proc = Path(root)
            (proc / "200").mkdir()
            (proc / "200" / "stat").write_text(
                "200 (git with spaces) S 100 200 200 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0\n"
            )
            table = revocation_observer.read_proc_table(proc, uid=None)
            self.assertEqual(table[200].ppid, 100)
            self.assertEqual(table[200].pgid, 200)
            self.assertEqual(table[200].starttime, 20)
            self.assertFalse((proc / "200" / "environ").exists())
            self.assertFalse((proc / "200" / "cmdline").exists())

    def test_backpressure_net_parser_reads_only_fixture_queue_fields(self):
        text = (
            "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:1F90 0100007F:D431 01 00001000:00000000 00:00000000 00000000  1000        0 424242 1\n"
        )
        entries = revocation_transport.parse_proc_net_tcp(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].local_host, "127.0.0.1")
        self.assertEqual(entries[0].local_port, 8080)
        self.assertEqual(entries[0].remote_port, 54321)
        self.assertEqual(entries[0].tx_queue, 4096)
        self.assertEqual(entries[0].inode, 424242)

    def test_harness_helpers_declare_bound_evidence(self):
        for rel in ("tests/transfer_revocation_timing.py",
                    "tests/transfer_revocation_observer.py",
                    "tests/transfer_revocation_transport.py"):
            path = ROOT / rel
            self.assertLessEqual(len(path.read_text(encoding="utf-8").splitlines()), 500, rel)
        common = ("configured_bound_proven", "run_timed_transfer",
                  "apply_natural_expiry_clock", "client_stop")
        for rel in ("tests/ci_job_checkouts.py", "tests/transfer_revocation.py"):
            source = (ROOT / rel).read_text(encoding="utf-8")
            for expected in common:
                self.assertIn(expected, source, f"{rel} missing {expected}")
        ci_source = (ROOT / "tests/ci_job_checkouts.py").read_text(encoding="utf-8")
        for expected in ("TriggerInterval", "ProcGroupObserver"):
            self.assertIn(expected, ci_source, f"ci_job_checkouts.py missing {expected}")


if __name__ == "__main__":
    unittest.main()
