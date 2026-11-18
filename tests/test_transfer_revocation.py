#!/usr/bin/env python3
"""Contract and structural tests for Issue #37 bounded active transfer revocation."""
import ast
from dataclasses import FrozenInstanceError, replace
import http.client
import json
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

import ci_job_checkouts  # noqa: E402
import transfer_revocation_backpressure as revocation_backpressure  # noqa: E402
import transfer_revocation_observer as revocation_observer  # noqa: E402
import transfer_revocation_probe as revocation_probe  # noqa: E402
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

    def test_mirror_pre_release_gate_ignores_authorized_paused_primary_child(self):
        harness = ci_job_checkouts.JobCheckoutHarness.__new__(
            ci_job_checkouts.JobCheckoutHarness
        )
        primary, paused, mirror = 4100, 4101, 4200
        released = {"value": False}

        def table(uid=None):
            rows = {
                primary: revocation_observer.ProcStat(primary, "S", 1, primary, 10),
                mirror: revocation_observer.ProcStat(mirror, "S", 1, mirror, 20),
            }
            if not released["value"]:
                rows[paused] = revocation_observer.ProcStat(
                    paused, "S", primary, paused, 11
                )
            return rows

        class Clock:
            def __init__(self):
                self.now = 0.0
                self.sleeps = 0

            def monotonic(self):
                return self.now

            def sleep(self, seconds):
                self.sleeps += 1
                self.now += seconds

        clock = Clock()
        stats = {"reads": 0}

        def read_table(uid=None):
            stats["reads"] += 1
            return table()

        with mock.patch.object(
            ci_job_checkouts.revocation_observer, "read_proc_table", side_effect=read_table
        ), mock.patch.object(
            ci_job_checkouts,
            "time",
            types.SimpleNamespace(monotonic=clock.monotonic, sleep=clock.sleep),
        ):
            harness._wait_no_owned_children([mirror], timeout=0.2)
            self.assertEqual(stats["reads"], 1)
            self.assertEqual(clock.sleeps, 0)

            stats["reads"] = 0
            with self.assertRaises(AssertionError):
                harness._wait_no_owned_children([primary, mirror], timeout=0.2)
            self.assertEqual(stats["reads"], 4)
            self.assertEqual(clock.sleeps, 4)

            released["value"] = True
            stats["reads"] = 0
            harness._wait_no_owned_children([primary, mirror], timeout=0.2)
            self.assertEqual(stats["reads"], 1)
            self.assertEqual(clock.sleeps, 4)

    def test_pre_release_gate_source_order_is_mirror_only(self):
        path = ROOT / "tests" / "ci_job_checkouts.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        cls = next(node for node in tree.body
                   if isinstance(node, ast.ClassDef) and node.name == "JobCheckoutHarness")
        method = next(node for node in cls.body
                      if isinstance(node, ast.FunctionDef)
                      and node.name == "mirror_cannot_bypass_revocation_via_origin")

        def pid_roots(call):
            node = call.args[0]
            self.assertIsInstance(node, ast.List)
            names = []
            for item in node.elts:
                self.assertIsInstance(item, ast.Attribute)
                self.assertEqual(item.attr, "pid")
                self.assertIsInstance(item.value, ast.Attribute)
                names.append(item.value.attr)
            return names

        gate_calls = sorted(
            (node for node in ast.walk(method)
             if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute)
             and node.func.attr == "_wait_no_owned_children"),
            key=lambda node: (node.lineno, node.col_offset),
        )
        self.assertEqual(len(gate_calls), 2)
        pre, post = gate_calls
        self.assertEqual(pid_roots(pre), ["mirror_proc"])
        self.assertEqual(pid_roots(post), ["proc", "mirror_proc"])
        self.assertLess(pre.lineno, post.lineno)

        phase_line = min(
            node.lineno for node in ast.walk(method)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "enter_phase"
            and node.args and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "post_revocation_denial"
        )
        release_lines = [
            node.lineno for node in ast.walk(method)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "touch"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "release"
        ]
        self.assertGreater(pre.lineno, phase_line)
        self.assertTrue(any(pre.lineno < line < post.lineno for line in release_lines))

    def test_original_seventeen_top_level_case_inventory_is_preserved(self):
        path = ROOT / "tests" / "ci_job_checkouts.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        main = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        names = None
        for node in ast.walk(main):
            if (isinstance(node, ast.Tuple) and node.elts
                    and all(isinstance(item, ast.Constant) and isinstance(item.value, str)
                            for item in node.elts)):
                candidate = [item.value for item in node.elts]
                if "bounded_active_transfer_revocation" in candidate:
                    names = candidate
                    break
        self.assertEqual(names, [
            "setup_checkout",
            "native_clones_and_closure",
            "declared_tags_and_target_history",
            "object_wants_do_not_escape",
            "native_denials_survive_backend_exit",
            "early_stdin_failure_preserves_denial",
            "route_and_audience_scope",
            "immutable_issuance_and_concurrency",
            "source_evidence_and_input_validation",
            "cancel_revoke_and_issuer_fences",
            "live_database_and_repository_fences",
            "tampered_job_views_fail_closed",
            "authorization_rechecked_after_closure",
            "issuer_revoked_during_source_verification",
            "deleted_source_ref_and_primary_offline",
            "bounded_active_transfer_revocation",
            "mirror_cannot_bypass_revocation_via_origin",
        ])

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
            "   0: 0100007F:1F90 0100007F:D431 01 00001000:00000000 04:00000000 00000000  1000        0 424242 1\n"
        )
        entries = revocation_transport.parse_proc_net_tcp(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].local_host, "127.0.0.1")
        self.assertEqual(entries[0].local_port, 8080)
        self.assertEqual(entries[0].remote_port, 54321)
        self.assertEqual(entries[0].tx_queue, 4096)
        self.assertEqual(entries[0].timer_active, 4)
        self.assertEqual(entries[0].inode, 424242)

    def test_bounded_observer_wait_terminates_at_fixed_deadline(self):
        class FakeClock:
            def __init__(self):
                self.now_ns = 0
                self.sleeps = []

            def __call__(self):
                return self.now_ns

            def sleep(self, seconds):
                self.sleeps.append(seconds)
                self.now_ns += int(seconds * 1_000_000_000)

        class NeverQuiescent:
            all_quiescent = False

        clock = FakeClock()
        result = revocation_observer.wait_for_quiescence_until(
            NeverQuiescent(), 1_000_000_000, clock=clock,
            interval_ns=100_000_000, sleep=clock.sleep,
        )
        self.assertFalse(result)
        self.assertEqual(clock.now_ns, 1_000_000_000)
        self.assertLessEqual(len(clock.sleeps), 10)

    def test_observer_finished_without_quiescence_is_not_success(self):
        class FinishedButLive:
            all_quiescent = False
            finished = True

        class FrozenClock:
            def __call__(self):
                return 2_000_000_000

        self.assertFalse(revocation_observer.wait_for_quiescence_until(
            FinishedButLive(), 1_000_000_000, clock=FrozenClock(),
            interval_ns=10_000_000, sleep=lambda _seconds: None,
        ))

    def test_observer_quiescence_returns_without_opening_a_second_window(self):
        class ImmediatelyQuiescent:
            all_quiescent = True

        class FrozenClock:
            def __call__(self):
                return 50_000_000

        self.assertTrue(revocation_observer.wait_for_quiescence_until(
            ImmediatelyQuiescent(), 50_000_000, clock=FrozenClock(),
            interval_ns=10_000_000, sleep=lambda _seconds: None,
        ))

    @staticmethod
    def _stall_sample(now_ns, *, tx=4096, rx=4096, inode=17, owned=True,
                      net=True, probe0=True, source=True):
        return {
            "observed_ns": now_ns,
            "sample_start_ns": now_ns,
            "sample_duration_ns": 0,
            "net_table_available": net,
            "same_netns": net,
            "probe0_pending": probe0,
            "source_qualified": source,
            "server_tx_queue": tx,
            "client_rx_queue": rx,
            "server_socket_inode": inode,
            "server_fd_owned": owned,
            "client_inode_owned": owned,
        }

    def test_backpressure_rejects_receiver_rx_without_sender_tx(self):
        window = revocation_backpressure.SustainedStallWindow(200_000_000)
        self.assertFalse(window.observe(self._stall_sample(0, tx=0, rx=8192), 0))
        self.assertEqual(window.last_reset_reason, "server_tx_not_positive")
        self.assertFalse(window.qualified)

    def test_backpressure_transient_positive_does_not_qualify(self):
        window = revocation_backpressure.SustainedStallWindow(
            200_000_000, max_gap_ns=100_000_000
        )
        self.assertFalse(window.observe(self._stall_sample(0), 0))
        self.assertFalse(window.observe(self._stall_sample(20_000_000), 20_000_000))
        self.assertFalse(window.observe(self._stall_sample(40_000_000, tx=0), 40_000_000))
        self.assertFalse(window.observe(self._stall_sample(60_000_000), 60_000_000))
        self.assertFalse(window.observe(self._stall_sample(80_000_000), 80_000_000))
        self.assertFalse(window.qualified)
        self.assertGreaterEqual(window.reset_count, 1)

    def test_backpressure_invalid_gap_resets_qualified_window(self):
        window = revocation_backpressure.SustainedStallWindow(
            200_000_000, max_gap_ns=100_000_000
        )
        self.assertFalse(window.observe(self._stall_sample(0), 0))
        self.assertFalse(window.observe(self._stall_sample(20_000_000), 20_000_000))
        self.assertFalse(window.observe(self._stall_sample(200_000_000), 200_000_000))
        self.assertEqual(window.last_reset_reason, "sample_gap")
        self.assertFalse(window.observe(self._stall_sample(220_000_000), 220_000_000))
        self.assertFalse(window.qualified)

    def test_backpressure_time_before_first_qualified_sample_does_not_count(self):
        window = revocation_backpressure.SustainedStallWindow(250_000_000)
        for now in (0, 50_000_000, 100_000_000, 150_000_000, 200_000_000):
            self.assertFalse(window.observe(self._stall_sample(now, tx=0), now))
        for now in (300_000_000, 350_000_000, 400_000_000, 450_000_000):
            self.assertFalse(window.observe(self._stall_sample(now), now))
        self.assertFalse(window.qualified,
                         "wait spent before the first valid stall must not count")

    def test_backpressure_continuous_qualified_window_is_accepted(self):
        window = revocation_backpressure.SustainedStallWindow(
            250_000_000, max_gap_ns=100_000_000
        )
        for now in range(0, 301_000_000, 20_000_000):
            window.observe(self._stall_sample(now), now)
        self.assertTrue(window.qualified)
        report = window.report()
        self.assertTrue(report["server_tx_positive_every_sample"])
        self.assertTrue(report["client_rx_positive_every_sample"])
        self.assertTrue(report["receiver_queue_unchanged"])
        self.assertTrue(report["probe0_every_sample"])
        self.assertTrue(report["source_qualified_every_sample"])
        self.assertGreaterEqual(report["observed_window_ms"], 250.0)

    def test_backpressure_receiver_growth_and_drain_both_reset(self):
        window = revocation_backpressure.SustainedStallWindow(200_000_000)
        window.observe(self._stall_sample(0, rx=8192), 0)
        window.observe(self._stall_sample(20_000_000, rx=16384), 20_000_000)
        self.assertEqual(window.last_reset_reason, "receiver_queue_changed")
        window.observe(self._stall_sample(40_000_000, rx=8192), 40_000_000)
        window.observe(self._stall_sample(60_000_000, rx=4096), 60_000_000)
        self.assertEqual(window.last_reset_reason, "receiver_queue_changed")

    def test_backpressure_probe0_and_source_failures_reset(self):
        window = revocation_backpressure.SustainedStallWindow(200_000_000)
        window.observe(self._stall_sample(0, probe0=False), 0)
        self.assertEqual(window.last_reset_reason, "probe0_not_pending")
        window.observe(self._stall_sample(20_000_000, source=False), 20_000_000)
        self.assertEqual(window.last_reset_reason, "source_unqualified")
        window.observe(self._stall_sample(40_000_000), 40_000_000)
        window.observe(self._stall_sample(60_000_000, inode=18), 60_000_000)
        self.assertEqual(window.last_reset_reason, "inode_changed")

    def test_backpressure_sample_duration_and_missing_timing_fail_closed(self):
        window = revocation_backpressure.SustainedStallWindow(100_000_000)
        slow = self._stall_sample(0)
        slow["sample_duration_ns"] = 150_000_000
        self.assertFalse(window.observe(slow, 0))
        self.assertEqual(window.last_reset_reason, "sample_duration")
        missing = self._stall_sample(20_000_000)
        missing.pop("sample_start_ns")
        self.assertFalse(window.observe(missing, 20_000_000))
        self.assertEqual(window.last_reset_reason, "sample_timing_missing")

    def test_post_qualified_invalid_sample_clears_qualification(self):
        window = revocation_backpressure.SustainedStallWindow(
            100_000_000, max_gap_ns=50_000_000
        )
        for now in (0, 20_000_000, 40_000_000, 60_000_000, 80_000_000, 100_000_000):
            window.observe(self._stall_sample(now), now)
        self.assertTrue(window.qualified)
        window.observe(self._stall_sample(120_000_000, source=False), 120_000_000)
        self.assertFalse(window.qualified)
        self.assertEqual(window.last_reset_reason, "source_unqualified")
        for now in (140_000_000, 160_000_000, 180_000_000, 200_000_000):
            window.observe(self._stall_sample(now), now)
        self.assertFalse(window.qualified)
        for now in (220_000_000, 240_000_000, 260_000_000, 280_000_000, 300_000_000,
                    320_000_000):
            window.observe(self._stall_sample(now), now)
        self.assertTrue(window.qualified)

    def _natural_result_fixture(self, *, client_observed_ns, probe=None):
        if probe is None:
            probe = self._timeline_probe()
            self._observe_timeline(probe, 980_000_000, 980_000_000)
        all_true = {
            "client_stop_within_deadline": True,
            "git_group_within_deadline": True,
            "group_post_sanity": True,
            "trigger_within_deadline": True,
            "backpressure_qualified": True,
            "source_witness": True,
            "target_pause_within_bound": True,
            "actual_reader_resume_within_deadline": True,
            "pre_trigger_window": True,
        }
        report = {
            "initial_lower_bound_ns": 1_100_000_000,
            "lower_bound_ns": 1_100_000_000,
            "deadline_ns": 2_300_000_000,
            "first_byte_ns": 500_000_000,
            "client_stop": {
                "confirmed_transport_stop": True,
                "observed_ns": client_observed_ns,
                "kind": "reset",
                "received_bytes": 4096,
            },
            "client_stop_after_lower_ms": 100.0,
            "actual_reader_resume_ns": 1_850_000_000,
            "post_trigger_pause_target_ms": 800.0,
            "post_trigger_backpressure_sample_ns": 1_840_000_000,
            "pre_trigger_backpressure_sample": {"observed_ns": 980_000_000},
            "backpressure": {"persistent": True, "max_gap_ms": 100.0},
            "source_witness": {"qualified": True},
            "source_precheck_ok": True,
            "group_required": True,
            "transfer_kind": "git",
            "post_transfer_group_stopped": True,
            "post_pause_within_deadline": True,
            "pre_trigger_backpressure_established": True,
            "git_group": {
                "stop_upper_ns": 1_900_000_000,
                "groups": [{
                    "last_live_ns": 1_700_000_000,
                    "quiescent_ns": 1_900_000_000,
                }],
            },
            "git_group_within_deadline": True,
            "proof_components": all_true,
            "configured_bound_proven": True,
        }
        return revocation_timing.NaturalExpiryResult(report, probe.timeline)

    def test_tcp_pair_requires_unique_established_reversed_four_tuples(self):
        rows = (
            "   0: 0100007F:1F90 0100007F:D431 01 00001000:00000000 04:00000000 "
            "00000000  1000        0 424242 1\n"
            "   1: 0100007F:D431 0100007F:1F90 01 00000000:00002000 00:00000000 "
            "00000000  1000        0 424243 1\n"
        )
        entries = revocation_probe.parse_proc_net_tcp(rows)
        pair = revocation_probe.find_tcp_pair(
            entries, client_host="127.0.0.1", client_port=54321,
            server_host="127.0.0.1", server_port=8080,
        )
        self.assertIsNotNone(pair)
        self.assertEqual(pair[0].timer_active, 4)
        duplicate = entries + entries
        self.assertIsNone(revocation_probe.find_tcp_pair(
            duplicate, client_host="127.0.0.1", client_port=54321,
            server_host="127.0.0.1", server_port=8080,
        ))
        listening = revocation_probe.parse_proc_net_tcp(
            rows.replace(" 01 ", " 0A ")
        )
        self.assertIsNone(revocation_probe.find_tcp_pair(
            listening, client_host="127.0.0.1", client_port=54321,
            server_host="127.0.0.1", server_port=8080,
        ))

    def test_pre_trigger_window_rejects_post_trigger_and_stale_samples(self):
        probe = object.__new__(revocation_probe.BackpressureProbe)
        probe.persistent = True
        probe.window = type("Window", (), {"max_gap_ns": 100_000_000})()
        probe.last_sample = {"observed_ns": 101_000_000}
        self.assertFalse(probe.pre_trigger_valid(100_000_000),
                         "a post-trigger sample must not qualify")
        probe.last_sample = {"observed_ns": 0}
        self.assertFalse(probe.pre_trigger_valid(200_000_000),
                         "a stale sample beyond the maximum gap must not qualify")
        probe.last_sample = {"observed_ns": 150_000_000}
        self.assertTrue(probe.pre_trigger_valid(200_000_000))

    @staticmethod
    def _timeline_probe(min_duration_ns=0):
        probe = object.__new__(revocation_probe.BackpressureProbe)
        probe.window = revocation_backpressure.SustainedStallWindow(min_duration_ns)
        probe.timeline = revocation_probe.PreTriggerTimeline()
        probe.persistent = False
        witness = object.__new__(revocation_probe.GitSourceWitness)
        witness.service_identity = types.SimpleNamespace(pid=100, starttime=5)
        witness.writer = types.SimpleNamespace(
            tgid=200, tid=201, starttime=7, pipe_inode=19, service_fd=4,
        )
        probe.source_witness = witness
        return probe

    def _observe_timeline(self, probe, start_ns, end_ns, *, finalize=False, **fields):
        sample = self._stall_sample(end_ns)
        sample["client_socket_inode"] = 18
        sample.update(fields)
        clock = mock.Mock(side_effect=[start_ns, end_ns])
        with mock.patch.object(revocation_probe, "time", types.SimpleNamespace(monotonic_ns=clock)):
            with mock.patch.object(probe, "sample", return_value=sample):
                if finalize:
                    probe.finalize()
                else:
                    probe._observe()
        return sample

    def test_pre_trigger_timeline_captures_finalize_and_later_source_loss(self):
        probe = self._timeline_probe(min_duration_ns=5)
        timeline = probe.timeline
        self._observe_timeline(probe, 10, 11)
        self.assertEqual(timeline.entries, ())
        self._observe_timeline(probe, 16, 17)
        earlier, = timeline.entries
        self._observe_timeline(probe, 20, 30, finalize=True)
        self.assertEqual(timeline.entries, (
            earlier, replace(earlier, start_ns=20, completed_ns=30),
        ))
        self.assertTrue(timeline.covers(25))
        self.assertLessEqual(earlier.completed_ns, 25)
        self.assertIs(probe.select_pre_trigger_cert(25), earlier)
        finalize_cert = timeline.entries[-1]
        self.assertIs(probe.select_pre_trigger_cert(30), finalize_cert)
        self.assertFalse(probe.pre_trigger_valid(25))
        self.assertTrue(probe.pre_trigger_valid(30))

        self._observe_timeline(probe, 40, 50, finalize=True, source_qualified=False)
        self.assertEqual(timeline.entries[-1], revocation_probe.EpochEvent(
            40, 50, 1, None, "source_unqualified",
        ))
        self.assertIs(timeline.entries[0], earlier)
        for lower_ns, covered in ((25, True), (39, True), (40, False), (49, False),
                                  (50, True), (51, True)):
            with self.subTest(lower_ns=lower_ns):
                self.assertEqual(timeline.covers(lower_ns), covered)
        self.assertFalse(probe.pre_trigger_valid(50))
        for lower_ns, expected in ((25, earlier), (39, finalize_cert),
                                   (40, None), (49, None), (50, None), (51, None)):
            with self.subTest(lower_ns=lower_ns):
                self.assertIs(probe.select_pre_trigger_cert(lower_ns), expected)

    def test_pre_trigger_timeline_freezes_source_identity_and_same_time_entries(self):
        probe = self._timeline_probe()
        sample = self._observe_timeline(probe, 12, 12)
        snapshot = probe.timeline.entries
        cert, = snapshot
        self.assertEqual(cert, revocation_probe.Cert(
            12, 12, 0, 12, 17, 18, (2, 100, 5, 200, 201, 7, 19, 4),
            True, True, True, True,
        ))
        sample["client_socket_inode"] = 99
        sample["server_fd_owned"] = False
        probe.source_witness.writer.pipe_inode = 29
        self._observe_timeline(probe, 20, 20)
        stored, event, same_time_cert = probe.timeline.entries
        anchor = (2, 100, 5, 200, 201, 7, 29, 4)
        self.assertEqual(event, revocation_probe.EpochEvent(20, 20, 1, anchor, "source_identity"))
        self.assertEqual(same_time_cert, replace(
            cert, start_ns=20, completed_ns=20, epoch=1, source_anchor=anchor,
        ))
        self.assertTrue(probe.timeline.covers(20))
        self.assertIs(probe.select_pre_trigger_cert(20), same_time_cert)
        probe.source_witness.writer.pipe_inode = 39
        self._observe_timeline(probe, 22, 23)
        self.assertEqual(snapshot, (cert,))
        self.assertIs(stored, cert)
        self.assertEqual((cert.client_inode, cert.server_fd_owned, cert.source_anchor[-2]),
                         (18, True, 19))
        self.assertEqual(event.new_source_anchor, anchor)
        for entry, field in ((cert, "epoch"), (event, "new_epoch"), (probe.timeline.baseline, "epoch")):
            with self.subTest(entry=type(entry).__name__):
                with self.assertRaises(FrozenInstanceError):
                    setattr(entry, field, 99)

    def test_pre_trigger_timeline_captures_lfs_anchor_without_a_source_resample(self):
        probe = self._timeline_probe()
        witness = object.__new__(revocation_probe.LfsSourceWitness)
        witness.identity = types.SimpleNamespace(pid=100, starttime=5)
        witness.fd, witness.st_dev, witness.st_ino, witness.mnt_id = 4, 9, 19, 3
        probe.source_witness = witness
        with mock.patch.object(witness, "sample") as resample:
            self._observe_timeline(probe, 12, 12)
            witness.st_ino = 29
            self._observe_timeline(probe, 20, 22)
        resample.assert_not_called()
        cert, event, next_cert = probe.timeline.entries
        self.assertEqual(cert.source_anchor, (1, 100, 5, 4, 9, 19, 3))
        self.assertEqual(event.kind, "source_identity")
        self.assertEqual(event.new_source_anchor, (1, 100, 5, 4, 9, 29, 3))
        self.assertEqual(next_cert.source_anchor, event.new_source_anchor)

    def test_pre_trigger_timeline_captures_reset_and_transport_invalidation(self):
        for fields, kind, source_qualified in (
            ({"probe0_pending": False}, "reset", True),
            ({"server_socket_inode": 27}, "inode/netns", True),
            ({"same_netns": False}, "inode/netns", True),
            ({"client_inode_owned": False}, "reset", True),
            ({"source_report": {"failure_code": revocation_probe.SOURCE_FAILURE_IDENTITY}},
             "source_identity", False),
        ):
            with self.subTest(fields=fields):
                probe = self._timeline_probe()
                self._observe_timeline(probe, 12, 12)
                self._observe_timeline(probe, 20, 22, source_qualified=source_qualified, **fields)
                cert, event = probe.timeline.entries
                self.assertEqual(event, revocation_probe.EpochEvent(
                    20, 22, 1, cert.source_anchor if source_qualified else None, kind,
                ))
                self.assertFalse(probe.timeline.covers(20))
                self.assertTrue(probe.timeline.covers(22))
                self.assertFalse(probe.window.qualified)
                self.assertIs(probe.select_pre_trigger_cert(19), cert)
                self.assertIsNone(probe.select_pre_trigger_cert(20))
                self.assertIsNone(probe.select_pre_trigger_cert(22))

    def test_pre_trigger_timeline_evicted_event_covers_only_from_end(self):
        probe = self._timeline_probe()
        timeline = probe.timeline
        self._observe_timeline(probe, 12, 12)
        old_baseline = timeline.baseline
        probe.source_witness.writer.pipe_inode = 29
        self._observe_timeline(probe, 20, 30)
        old_cert, event, same_time_cert = timeline.entries
        self.assertIs(probe.select_pre_trigger_cert(19), old_cert)
        self.assertIsNone(probe.select_pre_trigger_cert(29))
        self.assertIs(probe.select_pre_trigger_cert(30), same_time_cert)
        for now_ns in range(32, 47):
            self._observe_timeline(probe, now_ns, now_ns)

        self.assertEqual(len(timeline.entries), 16)
        self.assertNotIn(event, timeline.entries)
        self.assertEqual(old_baseline, revocation_probe.TimelineBaseline())
        self.assertEqual(timeline.baseline, revocation_probe.TimelineBaseline(
            30, event.new_epoch, event.new_source_anchor,
        ))
        for lower_ns in (19, 20, 25, 29):
            with self.subTest(lower_ns=lower_ns):
                self.assertFalse(timeline.covers(lower_ns))
                self.assertIsNone(probe.select_pre_trigger_cert(lower_ns))
        self.assertIs(timeline.entries[0], same_time_cert)
        self.assertEqual(same_time_cert.completed_ns, 30)
        self.assertEqual(same_time_cert.epoch, timeline.baseline.epoch)
        self.assertEqual(same_time_cert.source_anchor, timeline.baseline.source_anchor)
        self.assertTrue(timeline.covers(30))
        self.assertTrue(timeline.covers(31))
        self.assertIs(probe.select_pre_trigger_cert(30), same_time_cert)
        self.assertIs(probe.select_pre_trigger_cert(31), same_time_cert)

        self._observe_timeline(probe, 47, 47)
        self.assertNotIn(same_time_cert, timeline.entries)
        self.assertEqual(timeline.baseline.coverage_watermark_ns, 30)
        for lower_ns in (30, 31):
            with self.subTest(lower_ns=lower_ns):
                self.assertTrue(timeline.covers(lower_ns))
                self.assertTrue(all(entry.completed_ns > lower_ns for entry in timeline.entries))
                self.assertIsNone(probe.select_pre_trigger_cert(lower_ns))
        self._observe_timeline(probe, 48, 48)
        self.assertEqual(timeline.baseline.coverage_watermark_ns, 32)
        self.assertFalse(timeline.covers(31))
        self.assertTrue(timeline.covers(32))
        self.assertTrue(all(entry.completed_ns > 32 for entry in timeline.entries))
        self.assertIsNone(probe.select_pre_trigger_cert(32))

    def test_pre_trigger_selector_rejects_missing_stale_and_post_bound_certificates(self):
        probe = self._timeline_probe()
        self.assertIsNone(probe.select_pre_trigger_cert(1_000_000_000))
        self._observe_timeline(probe, 1_000_000_000, 1_000_000_000)
        cert, = probe.timeline.entries
        for lower_ns, expected in (
            (999_999_999, None),
            (1_000_000_000, cert),
            (1_100_000_000, cert),
            (1_100_000_001, None),
        ):
            with self.subTest(lower_ns=lower_ns):
                self.assertIs(probe.select_pre_trigger_cert(lower_ns), expected)

    def test_pre_trigger_selector_requires_observed_epoch_anchor_and_flags(self):
        probe = self._timeline_probe()
        self._observe_timeline(probe, 1_000_000_000, 1_000_000_000)
        original, = probe.timeline.entries
        event_end = 1_021_000_000
        event = revocation_probe.EpochEvent(
            1_020_000_000, event_end, 1, original.source_anchor, "reset",
        )
        cert = replace(original, start_ns=event_end, completed_ns=1_022_000_000, epoch=1)
        for fields in (
            {}, {"epoch": 0}, {"source_anchor": (1,)}, {"source_qualified": False},
            {"server_fd_owned": False}, {"client_inode_owned": False}, {"same_netns": False},
        ):
            with self.subTest(fields=fields):
                timeline = revocation_probe.PreTriggerTimeline()
                candidate = replace(cert, **fields)
                for entry in (original, event, candidate):
                    timeline._append(entry)
                self.assertIsNone(revocation_timing.select_pre_trigger_cert(timeline, event_end))
                expected = None if fields else candidate
                self.assertIs(revocation_timing.select_pre_trigger_cert(
                    timeline, candidate.completed_ns,
                ), expected)

    def test_pre_trigger_timeline_watermark_is_max_across_mixed_evictions(self):
        probe = self._timeline_probe()
        self._observe_timeline(probe, 12, 12)
        cert, = probe.timeline.entries
        timeline = revocation_probe.PreTriggerTimeline()
        event = revocation_probe.EpochEvent(20, 50, 1, cert.source_anchor, "source_identity")
        earlier_end = revocation_probe.EpochEvent(41, 45, 2, None, "source_unqualified")
        next_event = revocation_probe.EpochEvent(60, 80, 3, cert.source_anchor, "inode/netns")
        # Exercise both eviction paths with synthetic timestamps below a prior end.
        for entry in (
            event, replace(cert, start_ns=30, completed_ns=40, epoch=1),
            earlier_end, next_event,
        ):
            timeline._append(entry)
        for now_ns in range(81, 93):
            timeline._append(replace(cert, start_ns=now_ns, completed_ns=now_ns, epoch=3))
        for now_ns, watermark, epoch, anchor in (
            (93, 50, 1, event.new_source_anchor),
            (94, 50, 1, event.new_source_anchor),
            (95, 50, 2, None),
            (96, 80, 3, next_event.new_source_anchor),
            (97, 81, 3, next_event.new_source_anchor),
        ):
            with self.subTest(now_ns=now_ns):
                timeline._append(replace(cert, start_ns=now_ns, completed_ns=now_ns, epoch=3))
                self.assertEqual(len(timeline.entries), 16)
                self.assertEqual(timeline.baseline, revocation_probe.TimelineBaseline(
                    watermark, epoch, anchor,
                ))
                self.assertFalse(timeline.covers(watermark - 1))
                self.assertTrue(timeline.covers(watermark))

    def test_natural_expiry_requalification_uses_reconciled_earliest_deadline(self):
        clock = revocation_timing.ExpiryClock(1_000_000_000, 1_000_100_000, 100_000, 2)
        result = revocation_timing.apply_natural_expiry_clock(
            self._natural_result_fixture(client_observed_ns=2_200_100_000), clock, 1200
        )
        self.assertEqual(result["deadline_ns"], 2_200_000_000)
        self.assertFalse(result["client_stop_within_deadline"])
        self.assertFalse(result["configured_bound_proven"],
                         "a stop after E_lower+B must not be requalified as a pass")
        later = revocation_timing.apply_natural_expiry_clock(
            self._natural_result_fixture(client_observed_ns=2_199_000_000), clock, 1200
        )
        self.assertTrue(later["configured_bound_proven"])

    def test_natural_finalization_rewrites_all_relative_fields_from_final_lower(self):
        clock = revocation_timing.ExpiryClock(1_000_000_000, 1_000_100_000, 100_000, 2)
        result = revocation_timing.apply_natural_expiry_clock(
            self._natural_result_fixture(client_observed_ns=2_000_000_000), clock, 1200
        )
        self.assertEqual(result["lower_bound_ns"], 1_000_000_000)
        self.assertEqual(result["initial_lower_bound_ns"], 1_100_000_000)
        self.assertEqual(result["client_stop_after_lower_ms"], 1000.0)
        self.assertEqual(result["actual_reader_resume_after_lower_ms"], 850.0)
        self.assertEqual(result["actual_post_trigger_pause_ms"], 850.0)
        self.assertEqual(result["post_trigger_pause_ms"], 850.0)
        self.assertEqual(result["reader_resume_delta_from_target_ms"], 50.0)
        self.assertEqual(result["post_trigger_backpressure_sample_after_lower_ms"], 840.0)
        self.assertEqual(result["pre_trigger_backpressure_sample_after_lower_ms"], -20.0)
        self.assertEqual(result["git_group"]["stop_upper_after_lower_ms"], 900.0)
        self.assertEqual(result["git_group"]["groups"][0]["quiescent_after_lower_ms"], 900.0)
        self.assertEqual(result["clock_uncertainty_ms"], 0.1)
        self.assertTrue(result["configured_bound_proven"])
        self.assertNotIn("ryj_", json.dumps(result))
        self.assertNotIn("Authorization", json.dumps(result))

    def test_actual_reader_resume_after_final_deadline_is_not_a_pass(self):
        clock = revocation_timing.ExpiryClock(1_000_000_000, 1_000_100_000, 100_000, 2)
        fixture = self._natural_result_fixture(client_observed_ns=2_100_000_000)
        fixture["actual_reader_resume_ns"] = 2_250_000_000
        result = revocation_timing.apply_natural_expiry_clock(fixture, clock, 1200)
        self.assertFalse(result["actual_reader_resume_within_deadline"])
        self.assertFalse(result["configured_bound_proven"])

    def test_missing_source_component_cannot_default_to_true(self):
        clock = revocation_timing.ExpiryClock(1_000_000_000, 1_000_100_000, 100_000, 2)
        fixture = self._natural_result_fixture(client_observed_ns=2_000_000_000)
        del fixture["proof_components"]["source_witness"]
        result = revocation_timing.apply_natural_expiry_clock(fixture, clock, 1200)
        self.assertFalse(result["proof_components"]["source_witness"])
        self.assertFalse(result["configured_bound_proven"])

    def test_lfs_finalization_explicitly_omits_not_required_group_check(self):
        clock = revocation_timing.ExpiryClock(1_000_000_000, 1_000_100_000, 100_000, 2)
        fixture = self._natural_result_fixture(client_observed_ns=2_000_000_000)
        fixture["group_required"] = False
        fixture["git_group"] = {}
        fixture["git_group_within_deadline"] = None
        fixture["proof_components"].pop("git_group_within_deadline", None)
        result = revocation_timing.apply_natural_expiry_clock(fixture, clock, 1200)
        self.assertNotIn("git_group_within_deadline", result["proof_components"])
        self.assertIsNone(result["git_group_within_deadline"])
        self.assertTrue(result["configured_bound_proven"])

    def test_pre_trigger_final_expiry_reselects_at_earlier_lower_bound(self):
        ms = revocation_timing.NS_PER_MS
        probe = self._timeline_probe(min_duration_ns=500 * ms)
        for now_ms in range(400, 1041, 20):
            self._observe_timeline(probe, now_ms * ms, (now_ms + 1) * ms)
        finalize = self._observe_timeline(
            probe, 1060 * ms, 1065 * ms, finalize=True, source_qualified=False,
            source_report={"qualified": False},
        )
        clock = revocation_timing.ExpiryClock(1000 * ms, 1100 * ms, 100 * ms, 2)
        self.assertEqual(probe.select_pre_trigger_cert(clock.earliest_ns).completed_ns, 981 * ms)

        def fake_reader(*, target, daemon, **_kwargs):
            thread = mock.Mock(daemon=daemon)
            thread.join.side_effect = (step() for step in (target, lambda: None))
            thread.is_alive.return_value = False
            return thread

        for initial_ms, initial_completion in ((1050, 1041 * ms), (1100, None)):
            with self.subTest(initial_ms=initial_ms):
                initial_clock = revocation_timing.ExpiryClock(
                    initial_ms * ms, 1100 * ms, (1100 - initial_ms) * ms, 1,
                )
                initial_cert = probe.select_pre_trigger_cert(initial_clock.earliest_ns)
                self.assertEqual(getattr(initial_cert, "completed_ns", None), initial_completion)
                connection = mock.Mock()
                connection.getresponse.return_value = mock.Mock(status=200)
                connection.getresponse.return_value.read.return_value = b"x"
                timestamps_ms = (400, initial_ms + 780, initial_ms + 780,
                                 initial_ms + 800, initial_ms + 800, 2000)
                fake_time = types.SimpleNamespace(
                    monotonic_ns=mock.Mock(side_effect=[stamp * ms for stamp in timestamps_ms]),
                )
                stop = revocation_timing.StopObservation(
                    revocation_timing.StopKind.RESET, 2000 * ms, 1,
                )
                with mock.patch.multiple(
                    revocation_transport,
                    BackpressureProbe=mock.Mock(return_value=probe),
                    SmallBufferHTTPConnection=mock.Mock(return_value=connection),
                    threading=types.SimpleNamespace(Event=mock.Mock, Thread=fake_reader),
                    time=fake_time,
                    _sleep_until=mock.Mock(),
                    read_until_transport_stop=mock.Mock(return_value=stop),
                ), mock.patch.multiple(
                    probe, wait_persistent=mock.Mock(), hold_until=mock.Mock(),
                    finalize=mock.Mock(), sample=mock.Mock(return_value={"source_qualified": False}),
                    report=mock.Mock(return_value={"persistent": False, "max_gap_ms": 100.0}),
                ):
                    fixture = revocation_transport.run_timed_transfer(
                        base="http://127.0.0.1:1", path="/", method="GET", headers={}, body=None,
                        expected_size=4, initial_bytes=1, framing="chunked", service_pid=None,
                        require_group=False, bound_ms=1200, natural_expiry=initial_clock,
                        evidence=mock.Mock(),
                    )
                proof_keys = ("pre_trigger_window", "backpressure_qualified", "source_witness")
                for key in proof_keys:
                    self.assertEqual(fixture["proof_components"][key], initial_cert is not None)
                self.assertEqual(fixture["source_witness"], {"qualified": False})
                self.assertEqual(json.loads(json.dumps(fixture)), dict(fixture))
                result = revocation_timing.apply_natural_expiry_clock(fixture, clock, 1200)
                self.assertTrue(result["configured_bound_proven"])
                for key in proof_keys:
                    self.assertTrue(result["proof_components"][key])
                self.assertIs(result["pre_trigger_backpressure_sample"], finalize)
                self.assertEqual(result["pre_trigger_backpressure_sample_after_lower_ms"], 65.0)
                self.assertEqual(json.loads(json.dumps(result)), dict(result))

    def test_pre_trigger_final_expiry_rejects_post_bound_or_stale_certificates(self):
        clock = revocation_timing.ExpiryClock(1_000_000_000, 1_000_100_000, 100_000, 2)
        for observed_ns in (1_000_000_001, 899_999_999):
            with self.subTest(observed_ns=observed_ns):
                probe = self._timeline_probe()
                self._observe_timeline(probe, observed_ns, observed_ns)
                fixture = self._natural_result_fixture(client_observed_ns=2_000_000_000, probe=probe)
                result = revocation_timing.apply_natural_expiry_clock(fixture, clock, 1200)
                self.assertFalse(result["configured_bound_proven"])
                for key in ("pre_trigger_window", "backpressure_qualified", "source_witness"):
                    self.assertFalse(result["proof_components"][key])

    def test_pre_trigger_final_expiry_requires_timeline_and_source_precheck(self):
        clock = revocation_timing.ExpiryClock(1_000_000_000, 1_000_100_000, 100_000, 2)
        fixture = self._natural_result_fixture(client_observed_ns=2_000_000_000)
        result = revocation_timing.apply_natural_expiry_clock(dict(fixture), clock, 1200)
        self.assertFalse(result["proof_components"]["pre_trigger_window"])
        self.assertFalse(result["configured_bound_proven"])

        fixture["source_precheck_ok"] = False
        result = revocation_timing.apply_natural_expiry_clock(fixture, clock, 1200)
        self.assertTrue(result["proof_components"]["pre_trigger_window"])
        self.assertFalse(result["proof_components"]["source_witness"])
        self.assertFalse(result["configured_bound_proven"])

    def test_read_timeout_is_never_a_confirmed_transport_stop(self):
        class FakeSocket:
            def settimeout(self, _timeout):
                pass

        class FakeResponse:
            def read1(self, _amount):
                raise socket.timeout("local read timeout")

        result = revocation_timing.read_until_transport_stop(
            response=FakeResponse(), sock=FakeSocket(), expected_size=1024,
            initial_received=10, resume_ns=0,
            deadline_ns=time.monotonic_ns() + 100_000_000,
            framing="content_length",
        )
        self.assertEqual(result.kind, revocation_timing.StopKind.TIMEOUT)
        self.assertFalse(result.confirmed)

    def test_observer_rejects_unobservable_premature_or_late_group_stop(self):
        identity = revocation_observer.GroupIdentity(200, 200, 1_000)
        observer = revocation_observer.ProcGroupObserver([100], clock=lambda: 0)
        observer.armed_ns = 100_000_000
        observer.max_poll_gap_ns = 10_000_000
        observer._tracks = {200: revocation_observer.GroupTrack(
            identity, first_live_ns=100_000_000, last_live_ns=500_000_000,
            quiescent_ns=1_300_000_000, max_members=1,
        )}
        self.assertFalse(observer.proven(400_000_000, 1_200_000_000))
        observer._tracks[200].quiescent_ns = 800_000_000
        self.assertTrue(observer.proven(400_000_000, 1_200_000_000))
        observer._tracks[200].last_live_ns = 10_000_000
        self.assertFalse(observer.proven(400_000_000, 1_200_000_000))
        observer._tracks[200].last_live_ns = 500_000_000
        observer.unavailable_reason = "proc unobservable"
        self.assertFalse(observer.proven(400_000_000, 1_200_000_000))
        observer.unavailable_reason = None
        observer._tracks[200].quiescent_ns = 100_000_000
        self.assertFalse(observer.proven(400_000_000, 1_200_000_000),
                         "a group already stopped before the trigger is not a bound pass")

    def test_harness_helpers_declare_bound_evidence(self):
        for rel in ("tests/transfer_revocation_timing.py",
                    "tests/transfer_revocation_observer.py",
                    "tests/transfer_revocation_backpressure.py",
                    "tests/transfer_revocation_source.py",
                    "tests/transfer_revocation_git_source.py",
                    "tests/transfer_revocation_probe.py",
                    "tests/transfer_revocation_transport.py"):
            path = ROOT / rel
            self.assertLessEqual(len(path.read_text(encoding="utf-8").splitlines()), 500, rel)
        common = ("configured_bound_proven", "run_timed_transfer",
                  "apply_natural_expiry_clock", "client_stop")
        for rel in ("tests/ci_job_checkouts.py", "tests/transfer_revocation.py"):
            source = (ROOT / rel).read_text(encoding="utf-8")
            for expected in common:
                self.assertTrue(expected in source, f"{rel} missing {expected}")
        ci_source = (ROOT / "tests/ci_job_checkouts.py").read_text(encoding="utf-8")
        for expected in ("TriggerInterval", "ProcGroupObserver", "16 * 1024",
                         "require_backpressure=True"):
            self.assertTrue(expected in ci_source, f"ci_job_checkouts.py missing {expected}")
        transport = (ROOT / "tests/transfer_revocation_transport.py").read_text(encoding="utf-8")
        for expected in ("SO_RCVBUF", "getsockopt", "deadline_ns = lower_ns + bound_ns",
                         "post_pause_ns <= bound_ns", "post_transfer_group_stopped",
                         "source_witness", "source_witness_factory",
                         "actual_reader_resume_ns", "proof_components"):
            self.assertTrue(expected in transport, f"transport missing {expected}")
        probe = (ROOT / "tests/transfer_revocation_probe.py").read_text(encoding="utf-8")
        for expected in ("fixture_four_tuple", "server_fd_owned", "client_inode_owned",
                         "probe0_pending", "find_tcp_pair", "source_qualified"):
            self.assertTrue(expected in probe, f"probe missing {expected}")
        backpressure = (ROOT / "tests" / "transfer_revocation_backpressure.py").read_text(encoding="utf-8")
        for expected in ("server_tx_positive_every_sample",
                         "client_rx_positive_every_sample",
                         "receiver_queue_unchanged", "probe0_every_sample",
                         "source_qualified_every_sample", "sample_gap",
                         "max_sample_duration"):
            self.assertTrue(expected in backpressure, f"backpressure helper missing {expected}")
        docs = (ROOT / "docs" / "ci-mirror.md").read_text(encoding="utf-8")
        for expected in ("S_upper - E_lower <= B", "small `SO_RCVBUF`",
                         "probe0_pending", "not a literal `snd_wnd==0`",
                         "exactly unchanged RX plateau", "500 ms",
                         "pipe_write", "st_dev", "fails/unproven",
                         "actual monotonic resume", "final validated natural-expiry",
                         "A timeout, local close, or harness cancellation is never a",
                         "no additive CI"):
            self.assertTrue(expected in docs, f"docs missing {expected}")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for helper in ("tests/transfer_revocation_timing.py",
                       "tests/transfer_revocation_observer.py",
                       "tests/transfer_revocation_backpressure.py",
                       "tests/transfer_revocation_source.py",
                       "tests/transfer_revocation_git_source.py",
                       "tests/transfer_revocation_probe.py",
                       "tests/transfer_revocation_transport.py"):
            self.assertTrue(f"--harness {helper}" in workflow, f"workflow missing {helper}")


if __name__ == "__main__":
    unittest.main()
