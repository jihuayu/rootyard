#!/usr/bin/env python3
"""Hermetic tests for finite live-benchmark failure diagnostics (Refs #178).

These tests never contact HTTP, S3, PostgreSQL or a benchmark process.  They
use fake CompletedProcess values, known in-memory stdout/stderr strings,
temporary files and mocked CLI collaborators.  One class drives real stock Git
against a temporary local bare repository only, to lock the actual
``push --quiet --porcelain`` framing; it never touches a remote or a service.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import pando_pack_compression_eval as cli  # noqa: E402
from pack_compression_eval import live_server  # noqa: E402
from pack_compression_eval.capacity import derive_capacity_envelope  # noqa: E402
from pack_compression_eval.failure_diagnostics import (  # noqa: E402
    FAILURE_SCHEMA,
    FailureArtifactError,
    LiveEvalFailure,
    bindings_from_receipt,
    build_failure_record,
    completed_counts,
    enrich_failure_record,
    failure_path_for,
    failure_record_from_exception,
    finite_http_status,
    finite_http_subphase,
    finite_push_ref_verdict,
    git_failure_record,
    push_expected_destination,
    safe_summary,
    sanitize_bindings,
    sanitize_s3_snapshot,
    write_failure_json,
)

SENTINEL = "SENTINEL_SECRET_ff4e6e1f"
HEX64 = "a" * 64
HEX40 = "b" * 40


class FiniteFailureDiagnosticsTest(unittest.TestCase):
    def test_finite_http_status_is_unambiguous_only(self) -> None:
        self.assertEqual(finite_http_status(b"error: RPC failed; HTTP 503 curl 22"), 503)
        self.assertEqual(finite_http_status(b"fatal: The requested URL returned error: 503"), 503)
        self.assertEqual(finite_http_status(b"HTTP 503 ... HTTP 503"), 503)
        self.assertIsNone(finite_http_status(b"HTTP 503 ... HTTP 500"))
        self.assertIsNone(finite_http_status(b"HTTP 999"))
        self.assertIsNone(finite_http_status(b"no status here"))
        self.assertIsNone(finite_http_status(None))

    def test_build_failure_record_whitelists_ids_and_counts(self) -> None:
        record = build_failure_record(
            mode=SENTINEL,
            scale=SENTINEL,
            seed=SENTINEL,
            phase=SENTINEL,
            failure_class=SENTINEL,
            archetype=SENTINEL,
            object_format=SENTINEL,
            config=SENTINEL,
            repo_ordinal=-1,
            wave_ordinal="1",
            target_ordinal=2**100,
            branch_ordinal=9999999,
            git_returncode=SENTINEL,
            signal=999,
            http_status=999,
            http_subphase=SENTINEL,
            push_ref_verdict=SENTINEL,
            elapsed_ms=float("inf"),
            last_completed_phase=SENTINEL,
            completed={
                SENTINEL: 5,
                "candidate_pushes_completed": -3,
                "acked_refs_verified": 2,
            },
            s3={
                "observed": True,
                "req_counts_by_method": {SENTINEL: 4, "GET": 1},
                "status_counts": {SENTINEL: 10, "200": 2},
            },
            bindings={
                "binary_sha256": SENTINEL,
                "binary_size_bytes": -4,
                "workspace_commit": SENTINEL,
                "receipt_schema": SENTINEL,
                "source_commit_at_failure": SENTINEL,
            },
        )

        self.assertEqual(record["schema_version"], FAILURE_SCHEMA)
        self.assertFalse(record["passed"])
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["mode"], "unknown")
        self.assertEqual(record["scale"], "unknown")
        self.assertIsNone(record["seed"])
        self.assertEqual(record["phase"], "unknown")
        self.assertEqual(record["failure_class"], "unclassified")
        self.assertEqual(record["archetype"], "unknown")
        self.assertEqual(record["object_format"], "unknown")
        self.assertEqual(record["config"], "unknown")
        self.assertIsNone(record["repo_ordinal"])
        self.assertIsNone(record["wave_ordinal"])
        self.assertIsNone(record["target_ordinal"])
        self.assertIsNone(record["branch_ordinal"])
        self.assertIsNone(record["git_returncode"])
        self.assertIsNone(record["signal"])
        self.assertIsNone(record["http_status"])
        self.assertEqual(record["http_subphase"], "unknown")
        self.assertEqual(record["push_ref_verdict"], "unknown")
        self.assertIsNone(record["elapsed_ms"])
        self.assertEqual(record["last_completed_phase"], "unknown")
        self.assertEqual(record["completed"], completed_counts({"acked_refs_verified": 2}))
        self.assertEqual(record["completed"]["candidate_pushes_completed"], 0)
        self.assertEqual(record["completed"]["acked_refs_verified"], 2)
        self.assertEqual(record["s3"]["status_counts"], {"200": 2, "unknown": 10})
        self.assertEqual(record["s3"]["other_requests"], 4)
        self.assertEqual(record["cleanup"]["failures"], [])
        self.assertFalse(record["cleanup"]["attempted"])
        self.assertIsNone(record["bindings"]["binary_sha256"])
        self.assertIsNone(record["bindings"]["binary_size_bytes"])
        self.assertIsNone(record["bindings"]["workspace_commit"])
        self.assertEqual(record["bindings"]["receipt_schema"], "unknown")
        self.assertEqual(
            record["fixture_capacity"],
            {"concurrent_branches": None, "request_ceiling_bytes": None, "inflight_bytes": None},
        )
        self.assertEqual(record["concurrent_worker_outcomes"], [])
        self.assertNotIn(SENTINEL, json.dumps(record, sort_keys=True))
        self.assertNotIn(SENTINEL, safe_summary(record))

    def test_fixture_capacity_is_projected_as_fixed_numbers(self) -> None:
        envelope = derive_capacity_envelope()
        record = build_failure_record(fixture_capacity=envelope)
        self.assertEqual(record["fixture_capacity"], envelope)
        self.assertEqual(
            record["fixture_capacity"],
            {
                "concurrent_branches": 3,
                "request_ceiling_bytes": 134217728,
                "inflight_bytes": 436207616,
            },
        )
        self.assertEqual(enrich_failure_record(record)["fixture_capacity"], envelope)

        for bad in (
            {"concurrent_branches": 4, "request_ceiling_bytes": 134217728, "inflight_bytes": 536870912},
            {**envelope, "request_ceiling_bytes": "134217728"},
            {**envelope, "inflight_bytes": 402653184},
            {**envelope, "inflight_bytes": 436207617},
            {**envelope, "inflight_bytes": 436207616.0},
            {**envelope, "x": SENTINEL},
            {SENTINEL: 3},
        ):
            with self.subTest(bad=bad):
                projected = build_failure_record(fixture_capacity=bad)["fixture_capacity"]
                self.assertEqual(
                    projected,
                    {"concurrent_branches": None, "request_ceiling_bytes": None, "inflight_bytes": None},
                )
                self.assertNotIn(SENTINEL, json.dumps(projected, sort_keys=True))

    def test_s3_snapshot_keeps_known_statuses_and_unknown_bucket(self) -> None:
        result = sanitize_s3_snapshot(
            {
                "observed": True,
                "get_requests": 2,
                "get_bytes": 10,
                "put_requests": 3,
                "put_bytes": 20,
                "head_requests": 4,
                "delete_requests": 5,
                "error_responses": 6,
                "req_counts_by_method": {"GET": 2, SENTINEL: 7},
                "status_counts": {"200": 2, "503": 1, "999": 4, SENTINEL: 5},
            }
        )

        self.assertTrue(result["observed"])
        self.assertEqual(result["get_requests"], 2)
        self.assertEqual(result["put_requests"], 3)
        self.assertEqual(result["head_requests"], 4)
        self.assertEqual(result["delete_requests"], 5)
        self.assertEqual(result["error_responses"], 6)
        self.assertEqual(result["other_requests"], 7)
        self.assertEqual(result["status_counts"], {"200": 2, "503": 1, "unknown": 9})
        self.assertNotIn(SENTINEL, json.dumps(result, sort_keys=True))

    def test_bindings_drop_paths_and_invalid_identifiers(self) -> None:
        bindings = bindings_from_receipt(
            {
                "path": SENTINEL,
                "receipt_verified": True,
                "sha256": HEX64,
                "size_bytes": 12,
                "receipt_sha256": HEX64,
                "workspace_commit": HEX40,
                "source_inputs_sha256": HEX64,
                "config_digest": HEX64,
                "receipt_schema": "rootyard/native-build-receipt/v2",
            },
            {"source_commit": HEX40, "source_dirty": False},
        )

        self.assertTrue(bindings["receipt_verified"])
        self.assertEqual(bindings["binary_sha256"], HEX64)
        self.assertEqual(bindings["binary_size_bytes"], 12)
        self.assertEqual(bindings["source_commit_at_failure"], HEX40)
        self.assertFalse(bindings["source_dirty_at_failure"])
        self.assertEqual(bindings["receipt_schema"], "rootyard/native-build-receipt/v2")
        self.assertNotIn(SENTINEL, json.dumps(bindings, sort_keys=True))

        invalid = sanitize_bindings(
            {
                "binary_sha256": SENTINEL,
                "binary_size_bytes": -1,
                "workspace_commit": SENTINEL,
                "receipt_schema": SENTINEL,
                "source_dirty_at_failure": SENTINEL,
            }
        )
        self.assertIsNone(invalid["binary_sha256"])
        self.assertIsNone(invalid["binary_size_bytes"])
        self.assertIsNone(invalid["workspace_commit"])
        self.assertEqual(invalid["receipt_schema"], "unknown")
        self.assertIsNone(invalid["source_dirty_at_failure"])
        self.assertNotIn(SENTINEL, json.dumps(invalid, sort_keys=True))


class PushBoundaryFailureTest(unittest.TestCase):
    def context(self) -> dict:
        return {
            "phase": "baseline_seed_push",
            "archetype": "text_history",
            "object_format": "sha1",
            "config": "baseline",
            "repo_ordinal": 2,
            "wave_ordinal": None,
            "completed": completed_counts({"baseline_repos_completed": 1}),
            "last_completed_phase": "live_setup",
        }

    def test_http_subphase_is_only_unambiguous(self) -> None:
        self.assertEqual(finite_http_subphase(b"error: RPC failed; HTTP 503 curl 22", 503), "receive_pack")
        self.assertEqual(
            finite_http_subphase(
                b"fatal: unable to access 'http://host/git/o/r.git/info/refs?service=git-receive-pack': "
                b"The requested URL returned error: 503",
                503,
            ),
            "info_refs",
        )
        self.assertEqual(
            finite_http_subphase(
                b"fatal: unable to access 'http://host/git/o/r.git': The requested URL returned error: 503",
                503,
            ),
            "unknown",
        )
        self.assertEqual(finite_http_subphase(b"info/refs?service=git-receive-pack", None), "unknown")
        self.assertEqual(finite_http_subphase(None, 503), "unknown")

    def test_push_failure_keeps_finite_context_and_never_raw_stderr(self) -> None:
        fake = subprocess.CompletedProcess(
            args=[SENTINEL],
            returncode=128,
            stdout=b"",
            stderr=f"fatal: {SENTINEL} http://user:pass@host/repo HTTP 503\n".encode(),
        )
        with mock.patch.object(live_server, "run_git", return_value=(fake, 12.5)):
            with self.assertRaises(LiveEvalFailure) as caught:
                live_server.push_with_pack_config(
                    "git",
                    Path("/tmp") / SENTINEL,
                    f"http://{SENTINEL}@example.invalid/repo",
                    None,
                    "HEAD:refs/heads/main",
                    {SENTINEL: SENTINEL},
                    context=self.context(),
                )

        record = caught.exception.record
        self.assertEqual(record["phase"], "baseline_seed_push")
        self.assertEqual(record["failure_class"], "git_push")
        self.assertEqual(record["archetype"], "text_history")
        self.assertEqual(record["object_format"], "sha1")
        self.assertEqual(record["config"], "baseline")
        self.assertEqual(record["repo_ordinal"], 2)
        self.assertEqual(record["git_returncode"], 128)
        self.assertEqual(record["http_status"], 503)
        self.assertEqual(record["http_subphase"], "unknown")
        self.assertEqual(record["elapsed_ms"], 12.5)
        self.assertEqual(record["completed"]["baseline_repos_completed"], 1)
        self.assertEqual(record["last_completed_phase"], "live_setup")
        self.assertNotIn(SENTINEL, json.dumps(record, sort_keys=True))
        self.assertNotIn(SENTINEL, str(caught.exception))

    def test_push_failure_classifies_unambiguous_subphase(self) -> None:
        fake = subprocess.CompletedProcess(
            args=["git", "push"],
            returncode=128,
            stdout=b"",
            stderr=b"error: RPC failed; HTTP 503 curl 22 The requested URL returned error: 503\n",
        )
        with mock.patch.object(live_server, "run_git", return_value=(fake, 12.5)):
            with self.assertRaises(LiveEvalFailure) as caught:
                live_server.push_with_pack_config(
                    "git", Path("/tmp"), "http://example.invalid/repo", None, "HEAD:main", {},
                    context=self.context(),
                )
        self.assertEqual(caught.exception.record["http_status"], 503)
        self.assertEqual(caught.exception.record["http_subphase"], "receive_pack")
        self.assertNotIn("curl", json.dumps(caught.exception.record, sort_keys=True))

    def test_push_timeout_and_spawn_are_classified_safely(self) -> None:
        with mock.patch.object(live_server, "run_git", side_effect=subprocess.TimeoutExpired(SENTINEL, 180)):
            with self.assertRaises(LiveEvalFailure) as caught:
                live_server.push_with_pack_config("git", Path("/tmp"), "remote", None, "HEAD:main", {}, context=self.context())
        self.assertEqual(caught.exception.record["failure_class"], "git_timeout")
        self.assertNotIn(SENTINEL, json.dumps(caught.exception.record, sort_keys=True))

        with mock.patch.object(live_server, "run_git", side_effect=OSError(SENTINEL)):
            with self.assertRaises(LiveEvalFailure) as caught:
                live_server.push_with_pack_config("git", Path("/tmp"), "remote", None, "HEAD:main", {}, context=self.context())
        self.assertEqual(caught.exception.record["failure_class"], "git_spawn")
        self.assertNotIn(SENTINEL, json.dumps(caught.exception.record, sort_keys=True))

    def test_push_success_keeps_elapsed_semantics(self) -> None:
        fake = subprocess.CompletedProcess(args=["git", "push"], returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(live_server, "run_git", return_value=(fake, 7.5)):
            elapsed = live_server.push_with_pack_config(
                "git", Path("/tmp"), "remote", None, "HEAD:main", {}, context=self.context()
            )
        self.assertEqual(elapsed, 7.5)

    def test_fixture_operation_pin_is_invocation_local(self) -> None:
        operation = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
        fake = subprocess.CompletedProcess(args=["git", "push"], returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(live_server, "run_git", return_value=(fake, 1.0)) as run:
            live_server.push_with_pack_config(
                "git", Path("/tmp"), "http://example.invalid/repo", None, "HEAD:refs/heads/main", {},
                context=self.context(), fixture_operation=operation,
            )
        self.assertEqual(
            run.call_args.args[1],
            [
                "-c", "credential.helper=",
                "-c", f"http.extraHeader=X-Rootyard-Operation: {operation}",
                "push", "--quiet", "--porcelain", "http://example.invalid/repo", "HEAD:refs/heads/main",
            ],
        )
        with mock.patch.object(live_server, "run_git", return_value=(fake, 1.0)) as default_run:
            live_server.push_with_pack_config("git", Path("/tmp"), "remote", None, "HEAD:main", {})
        self.assertEqual(
            default_run.call_args.args[1],
            ["-c", "credential.helper=", "push", "--quiet", "--porcelain", "remote", "HEAD:main"],
        )

    def test_fixture_operation_must_be_a_uuid_and_never_reaches_git(self) -> None:
        for bad in ("x\nInjected: y", "", "not-a-uuid", None):
            with self.subTest(bad=bad):
                with mock.patch.object(live_server, "run_git") as run:
                    if bad is None:
                        fake = subprocess.CompletedProcess(args=["git", "push"], returncode=0, stdout=b"", stderr=b"")
                        with mock.patch.object(live_server, "run_git", return_value=(fake, 1.0)):
                            live_server.push_with_pack_config(
                                "git", Path("/tmp"), "remote", None, "HEAD:main", {}, fixture_operation=None
                            )
                    else:
                        with self.assertRaises(ValueError):
                            live_server.push_with_pack_config(
                                "git", Path("/tmp"), "remote", None, "HEAD:main", {}, fixture_operation=bad
                            )
                run.assert_not_called()


class PushRefVerdictTest(unittest.TestCase):
    """Bounded per-ref verdict from this worker's own porcelain stdout line."""

    DESTINATION = "refs/heads/conc_1"

    def context(self) -> dict:
        return {
            "phase": "concurrent_push",
            "archetype": "text_history",
            "object_format": "sha1",
            "config": "baseline",
            "repo_ordinal": 0,
            "branch_ordinal": 1,
            "completed": completed_counts({}),
            "last_completed_phase": "live_setup",
        }

    def push_failure(
        self,
        stdout: bytes,
        *,
        stderr: bytes = b"",
        ref_target: str | None = None,
        returncode: int = 1,
    ) -> dict:
        fake = subprocess.CompletedProcess(
            args=["git", "push", "--quiet", "--porcelain"], returncode=returncode, stdout=stdout, stderr=stderr
        )
        with mock.patch.object(live_server, "run_git", return_value=(fake, 9.0)):
            with self.assertRaises(LiveEvalFailure) as caught:
                live_server.push_with_pack_config(
                    "git",
                    Path("/tmp"),
                    "http://example.invalid/repo",
                    None,
                    ref_target or f"HEAD:{self.DESTINATION}",
                    {},
                    context=self.context(),
                )
        return caught.exception.record

    def porcelain(self, summary: str, *, flag: str = "!", destination: str | None = None) -> bytes:
        target = destination or self.DESTINATION
        return f"{flag}\tHEAD:{target}\t{summary}\n".encode()

    def test_both_stock_stale_spellings_are_stale_info(self) -> None:
        for summary in ("[rejected] (stale info)", "[remote rejected] (stale info)"):
            with self.subTest(summary=summary):
                record = self.push_failure(self.porcelain(summary))
                self.assertEqual(record["push_ref_verdict"], "stale_info")
                self.assertEqual(record["failure_class"], "git_push")
                self.assertEqual(record["git_returncode"], 1)
                self.assertEqual(record["branch_ordinal"], 1)

    def test_other_rejection_of_this_destination_is_bounded(self) -> None:
        for summary in ("[remote rejected] (pre-receive hook declined)", "[rejected] (non-fast-forward)"):
            with self.subTest(summary=summary):
                self.assertEqual(
                    self.push_failure(self.porcelain(summary))["push_ref_verdict"], "other_ref_rejection"
                )

    def test_missing_stdout_is_unknown(self) -> None:
        for stdout in (b"", b"\n"):
            with self.subTest(stdout=stdout):
                self.assertEqual(self.push_failure(stdout)["push_ref_verdict"], "unknown")

    def test_expected_destination_comes_only_from_this_workers_refspec(self) -> None:
        self.assertEqual(push_expected_destination("HEAD:refs/heads/conc_1"), "refs/heads/conc_1")
        self.assertEqual(push_expected_destination("+HEAD:refs/heads/main"), "refs/heads/main")
        self.assertEqual(push_expected_destination("refs/heads/main"), "refs/heads/main")
        for bad in (None, "", "HEAD", "HEAD:main", "HEAD:refs/heads/a\tb", 7):
            with self.subTest(bad=bad):
                self.assertIsNone(push_expected_destination(bad))

    def test_off_target_and_non_bang_lines_are_unknown(self) -> None:
        off_target = self.porcelain("[rejected] (stale info)", destination="refs/heads/conc_2")
        self.assertEqual(self.push_failure(off_target)["push_ref_verdict"], "unknown")
        up_to_date = self.porcelain("[up to date]", flag="=")
        self.assertEqual(self.push_failure(up_to_date)["push_ref_verdict"], "unknown")
        forced = self.porcelain("[forced update]", flag="+")
        self.assertEqual(self.push_failure(forced)["push_ref_verdict"], "unknown")
        # No destination can be derived from the refspec, so nothing is classified.
        record = self.push_failure(self.porcelain("[rejected] (stale info)"), ref_target="HEAD")
        self.assertEqual(record["push_ref_verdict"], "unknown")

    def test_duplicate_conflicting_or_extra_lines_are_unknown(self) -> None:
        stale = self.porcelain("[rejected] (stale info)")
        other = self.porcelain("[remote rejected] (pre-receive hook declined)")
        duplicated = stale + stale
        self.assertEqual(self.push_failure(duplicated)["push_ref_verdict"], "unknown")
        conflicting = stale + other
        self.assertEqual(self.push_failure(conflicting)["push_ref_verdict"], "unknown")
        with_off_target = stale + self.porcelain("[rejected] (stale info)", destination="refs/heads/conc_0")
        self.assertEqual(self.push_failure(with_off_target)["push_ref_verdict"], "unknown")

    def test_malformed_or_unrelated_stdout_is_unknown(self) -> None:
        for stdout in (
            b"stale info\n",
            b"!\trefs/heads/conc_1\n",
            b"!\tno-colon\t[rejected] (stale info)\n",
            b"!\tHEAD:refs/heads/conc_1\t(stale info)\n",
            b"!\tHEAD:refs/heads/conc_1\t[rejected] (stale info) trailing\n",
            b"!\tHEAD:refs/heads/conc_1\t[rejected] ()\n",
            b"!\tHEAD:refs/heads/conc_1\t[rejected] (stale info)\textra\n",
            b"\x00\xff\xfe binary noise",
        ):
            with self.subTest(stdout=stdout):
                self.assertEqual(self.push_failure(stdout)["push_ref_verdict"], "unknown")

    def envelope(self, *status_lines: bytes, remote: bytes = b"https://example.invalid/git/o/r.git") -> bytes:
        frames = [b"To " + remote, *status_lines, b"Done"]
        return b"\n".join(frames) + b"\n"

    def test_stock_envelope_with_both_stale_spellings(self) -> None:
        for summary in ("[rejected] (stale info)", "[remote rejected] (stale info)"):
            with self.subTest(summary=summary):
                record = self.push_failure(self.envelope(self.porcelain(summary).rstrip(b"\n")))
                self.assertEqual(record["push_ref_verdict"], "stale_info")
                encoded = json.dumps(record, sort_keys=True)
                self.assertNotIn("To ", encoded)
                self.assertNotIn("Done", encoded)
                self.assertNotIn(self.DESTINATION, encoded)

    def test_stock_envelope_with_real_different_rejection(self) -> None:
        record = self.push_failure(
            self.envelope(self.porcelain("[remote rejected] (pre-receive hook declined)").rstrip(b"\n"))
        )
        self.assertEqual(record["push_ref_verdict"], "other_ref_rejection")
        self.assertEqual(record["failure_class"], "git_push")

    def test_optional_framing_halves_are_independently_accepted(self) -> None:
        stale = self.porcelain("[rejected] (stale info)").rstrip(b"\n")
        self.assertEqual(self.push_failure(b"To https://h.invalid/r.git\n" + stale + b"\n")["push_ref_verdict"], "stale_info")
        self.assertEqual(self.push_failure(stale + b"\nDone\n")["push_ref_verdict"], "stale_info")
        # Bare single status line (no framing at all) still classifies.
        self.assertEqual(self.push_failure(stale + b"\n")["push_ref_verdict"], "stale_info")

    def test_envelope_duplicate_status_lines_stay_unknown(self) -> None:
        stale = self.porcelain("[rejected] (stale info)").rstrip(b"\n")
        other = self.porcelain("[remote rejected] (pre-receive hook declined)").rstrip(b"\n")
        for stdout in (self.envelope(stale, stale), self.envelope(stale, other)):
            with self.subTest(stdout=stdout):
                self.assertEqual(self.push_failure(stdout)["push_ref_verdict"], "unknown")

    def test_envelope_extra_or_forged_content_never_upgrades_to_rejection(self) -> None:
        stale = self.porcelain("[rejected] (stale info)").rstrip(b"\n")
        for stdout in (
            self.envelope(stale, b"junk"),
            b"junk\n" + self.envelope(stale),
            self.envelope(stale) + b"junk\n",
            b"To https://h.invalid/r.git\nDone\n" + stale + b"\n",
            b"To https://h.invalid/r.git\n" + stale + b"\nDone\nDone\n",
            b"To https://h.invalid/r.git\nTo https://h.invalid/r.git\n" + stale + b"\nDone\n",
            b"To \n" + stale + b"\nDone\n",
            b"To https://h.invalid/r.git\nstale info\nDone\n",
        ):
            with self.subTest(stdout=stdout):
                self.assertEqual(self.push_failure(stdout)["push_ref_verdict"], "unknown")

    def test_untrusted_to_remote_is_never_retained(self) -> None:
        stale = self.porcelain("[rejected] (stale info)").rstrip(b"\n")
        record = self.push_failure(self.envelope(stale, remote=f"https://{SENTINEL}@hidden.invalid/r.git".encode()))
        self.assertEqual(record["push_ref_verdict"], "stale_info")
        encoded = json.dumps(record, sort_keys=True)
        self.assertNotIn(SENTINEL, encoded)
        self.assertNotIn("hidden.invalid", encoded)
        self.assertNotIn("https://", encoded)

    def test_verdict_and_stderr_http_fields_are_independent(self) -> None:
        record = self.push_failure(
            self.porcelain("[rejected] (stale info)"),
            stderr=b"fatal: unable to access 'http://example.invalid/repo/info/refs?service=git-receive-pack': "
            b"The requested URL returned error: 503\n",
        )
        self.assertEqual(record["push_ref_verdict"], "stale_info")
        self.assertEqual(record["http_status"], 503)
        self.assertEqual(record["http_subphase"], "info_refs")
        silent = self.push_failure(self.porcelain("[remote rejected] (stale info)"), stderr=b"")
        self.assertIsNone(silent["http_status"])
        self.assertEqual(silent["http_subphase"], "unknown")

    def test_stdout_stays_available_to_other_consumers(self) -> None:
        raw = self.porcelain("[rejected] (stale info)")
        fake = subprocess.CompletedProcess(args=["git", "push"], returncode=1, stdout=raw, stderr=b"")
        with mock.patch.object(live_server, "run_git", return_value=(fake, 3.0)):
            with self.assertRaises(LiveEvalFailure):
                live_server.push_with_pack_config(
                    "git",
                    Path("/tmp"),
                    "http://example.invalid/repo",
                    None,
                    f"HEAD:{self.DESTINATION}",
                    {},
                    context=self.context(),
                )
        self.assertEqual(fake.stdout, raw)
        self.assertEqual(fake.stderr, b"")
        self.assertEqual(fake.returncode, 1)

    def test_verdict_never_retains_stdout_stderr_ref_or_sentinel(self) -> None:
        raw = (
            f"!\t{SENTINEL}:{self.DESTINATION}\t[remote rejected] (stale info)\n"
        ).encode()
        record = self.push_failure(raw, stderr=f"fatal: {SENTINEL} HTTP 503\n".encode())
        self.assertEqual(record["push_ref_verdict"], "stale_info")
        encoded = json.dumps(record, sort_keys=True)
        self.assertNotIn(SENTINEL, encoded)
        self.assertNotIn(self.DESTINATION, encoded)
        self.assertNotIn("stale info", encoded)
        self.assertNotIn("example.invalid", encoded)


class StockGitPorcelainEnvelopeTest(unittest.TestCase):
    """Lock the actual stock-Git ``--quiet --porcelain`` framing offline.

    Only a temporary local bare repository and local working trees are used;
    there is no network, service, container or native runtime involvement.
    """

    def setUp(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("stock git is not available")
        self.git = git
        self._tmp = tempfile.TemporaryDirectory(prefix="pack-eval-porcelain-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "HOME": str(self.root),
            }
        )
        self.identity = ("-c", "user.name=pack-eval", "-c", "user.email=pack-eval@example.invalid")

    def git_run(self, *args: str, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            [self.git, *args],
            cwd=str(cwd) if cwd is not None else None,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if check and proc.returncode != 0:
            self.fail(f"stock git {args[0]} failed: {proc.stderr.decode(errors='replace')[:200]}")
        return proc

    def commit(self, work: Path, name: str, content: str) -> str:
        (work / "f.txt").write_text(content, encoding="utf-8")
        self.git_run("add", "f.txt", cwd=work)
        self.git_run(*self.identity, "commit", "-qm", name, cwd=work)
        return self.git_run("rev-parse", "HEAD", cwd=work).stdout.decode().strip()

    def test_stock_git_frames_one_ref_status_and_reports_real_rejections(self) -> None:
        remote = self.root / "remote.git"
        self.git_run("init", "--bare", "-q", "--initial-branch=main", str(remote))
        first = self.root / "first"
        self.git_run("init", "-q", str(first))
        seed_oid = self.commit(first, "seed", "seed\n")
        self.git_run("push", "-q", "--porcelain", str(remote), "HEAD:refs/heads/main", cwd=first)

        second = self.root / "second"
        self.git_run("clone", "-q", str(remote), str(second))
        self.commit(second, "remote-move", "remote\n")
        self.git_run("push", "-q", "--porcelain", str(remote), "HEAD:refs/heads/main", cwd=second)

        self.commit(first, "local-move", "local\n")
        diverted = self.git_run(
            "push", "--quiet", "--porcelain", "--force-with-lease=refs/heads/main:" + seed_oid,
            str(remote), "HEAD:refs/heads/main", cwd=first, check=False,
        )
        self.assertNotEqual(diverted.returncode, 0)
        stale_lines = diverted.stdout.decode("utf-8", "replace").splitlines()
        self.assertEqual(len(stale_lines), 3)
        self.assertTrue(stale_lines[0].startswith("To "))
        self.assertEqual(stale_lines[2], "Done")
        self.assertIn(b"[rejected] (stale info)", diverted.stdout)
        self.assertEqual(finite_push_ref_verdict(diverted.stdout, "refs/heads/main"), "stale_info")

        rejected = self.git_run(
            "push", "--quiet", "--porcelain", str(remote), "HEAD:refs/heads/main", cwd=first, check=False
        )
        self.assertNotEqual(rejected.returncode, 0)
        rejected_lines = rejected.stdout.decode("utf-8", "replace").splitlines()
        self.assertEqual(len(rejected_lines), 3)
        self.assertTrue(rejected_lines[0].startswith("To "))
        self.assertEqual(rejected_lines[2], "Done")
        # A real different rejection reason ("fetch first"/"non-fast-forward"
        # depending on local remote-tracking state) is bounded, not stale info.
        self.assertIn(b"\t[rejected] (", rejected.stdout)
        self.assertNotIn(b"stale info", rejected.stdout)
        self.assertEqual(finite_push_ref_verdict(rejected.stdout, "refs/heads/main"), "other_ref_rejection")

        record = git_failure_record(
            {"phase": "concurrent_push", "branch_ordinal": 2},
            returncode=rejected.returncode,
            elapsed_ms=5.0,
            stderr=rejected.stderr,
            stdout=rejected.stdout,
            expected_destination="refs/heads/main",
        )
        self.assertEqual(record["push_ref_verdict"], "other_ref_rejection")
        self.assertEqual(record["git_returncode"], rejected.returncode)
        self.assertIsNone(record["http_status"])
        self.assertEqual(record["http_subphase"], "unknown")
        encoded = json.dumps(record, sort_keys=True)
        self.assertNotIn(str(self.root), encoded)
        self.assertNotIn("refs/heads/main", encoded)


class FailureArtifactTest(unittest.TestCase):
    def test_legacy_receipt_without_verdict_projects_unknown(self) -> None:
        legacy = {
            "schema_version": FAILURE_SCHEMA,
            "phase": "concurrent_push",
            "failure_class": "git_push",
            "http_status": 503,
            "http_subphase": "receive_pack",
            "git_returncode": 1,
            "concurrent_worker_outcomes": [
                {
                    "branch_ordinal": 0,
                    "outcome": "failed",
                    "phase": "concurrent_push",
                    "failure_class": "git_push",
                    "http_status": None,
                    "http_subphase": "unknown",
                    "git_returncode": 1,
                    "signal": None,
                    "elapsed_ms": 4.0,
                }
            ],
        }
        record = enrich_failure_record(legacy)
        self.assertEqual(record["push_ref_verdict"], "unknown")
        self.assertEqual(record["http_status"], 503)
        self.assertEqual(record["http_subphase"], "receive_pack")
        self.assertEqual(record["concurrent_worker_outcomes"][0]["push_ref_verdict"], "unknown")
        self.assertEqual(record["concurrent_worker_outcomes"][0]["elapsed_ms"], 4.0)

    def test_failure_record_from_exception_merges_source_meta(self) -> None:
        failure = LiveEvalFailure(
            build_failure_record(
                phase="candidate_push",
                failure_class="git_push",
                config="rootyard_default",
                bindings={"binary_sha256": HEX64, "workspace_commit": HEX40},
            )
        )
        record = failure_record_from_exception(
            failure,
            mode="full",
            scale="quick",
            seed=178,
            source_meta={"source_commit": "c" * 40, "source_dirty": False},
        )
        self.assertEqual(record["mode"], "full")
        self.assertEqual(record["scale"], "quick")
        self.assertEqual(record["seed"], 178)
        self.assertEqual(record["bindings"]["binary_sha256"], HEX64)
        self.assertEqual(record["bindings"]["workspace_commit"], HEX40)
        self.assertEqual(record["bindings"]["source_commit_at_failure"], "c" * 40)
        self.assertFalse(record["bindings"]["source_dirty_at_failure"])

    def test_write_failure_json_is_versioned_and_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pack-eval-failure-") as tmp:
            report = Path(tmp) / "report.json"
            path = failure_path_for(report)
            self.assertEqual(path, Path(tmp) / "report.failure.json")
            written = write_failure_json(
                path,
                build_failure_record(
                    phase=SENTINEL,
                    failure_class=SENTINEL,
                    archetype=SENTINEL,
                    object_format=SENTINEL,
                    config=SENTINEL,
                    bindings={"binary_sha256": SENTINEL},
                ),
            )
            raw = written.read_text(encoding="utf-8")
            data = json.loads(raw)
            self.assertEqual(data["schema_version"], FAILURE_SCHEMA)
            self.assertFalse(data["passed"])
            self.assertNotIn(SENTINEL, raw)
            self.assertFalse((Path(tmp) / ".report.failure.json.tmp").exists())

    def test_run_evaluation_writes_failure_artifact_without_success_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pack-eval-run-") as tmp:
            root = Path(tmp)
            work = root / "work"
            work.mkdir()
            failure = LiveEvalFailure(
                build_failure_record(
                    phase="baseline_seed_push",
                    failure_class="git_push",
                    archetype="text_history",
                    object_format="sha1",
                    config="baseline",
                    repo_ordinal=0,
                    git_returncode=128,
                    http_status=503,
                    completed={"baseline_seed_pushes_completed": 0},
                    bindings={
                        "receipt_verified": True,
                        "binary_sha256": HEX64,
                        "binary_size_bytes": 10,
                        "receipt_sha256": HEX64,
                        "workspace_commit": HEX40,
                        "source_inputs_sha256": HEX64,
                        "config_digest": HEX64,
                        "receipt_schema": "rootyard/native-build-receipt/v2",
                    },
                )
            )
            config = cli.EvalConfig(
                mode="full",
                scale="quick",
                report_path=root / "report.json",
                summary_md=None,
                binary="fake-binary",
                git="git",
                seed=178,
                require_receipt=True,
                keep=False,
            )
            with (
                mock.patch.object(cli, "resolve_trusted_git", return_value="git"),
                mock.patch.object(cli.subprocess, "check_output", return_value="git version 2.0"),
                mock.patch.object(cli, "seed_multi_push_bare_repo", return_value={}),
                mock.patch.object(cli, "evaluate_repo_pack_matrix", return_value={}),
                mock.patch.object(cli, "run_correctness_suite", return_value={}),
                mock.patch.object(cli, "_derive_candidate_summary", return_value={}),
                mock.patch.object(cli, "resolve_live_env", return_value=SimpleNamespace(secrets=[])),
                mock.patch.object(cli, "run_live_serve_blob_eval", side_effect=failure),
                mock.patch.object(
                    cli,
                    "_git_source_meta",
                    return_value={"source_commit": "d" * 40, "source_dirty": False},
                ),
                mock.patch.object(cli.tempfile, "mkdtemp", return_value=str(work)),
            ):
                with self.assertRaises(FailureArtifactError) as caught:
                    cli.run_evaluation(config)

            self.assertFalse((root / "report.json").exists())
            failure_path = root / "report.failure.json"
            self.assertTrue(failure_path.is_file())
            raw = failure_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            self.assertFalse(data["passed"])
            self.assertEqual(data["phase"], "baseline_seed_push")
            self.assertEqual(data["failure_class"], "git_push")
            self.assertEqual(data["git_returncode"], 128)
            self.assertEqual(data["http_status"], 503)
            self.assertEqual(data["bindings"]["binary_sha256"], HEX64)
            self.assertEqual(data["bindings"]["source_commit_at_failure"], "d" * 40)
            self.assertNotIn(SENTINEL, raw)
            self.assertNotIn(SENTINEL, str(caught.exception))

    def test_main_returns_nonzero_and_prints_only_safe_summary(self) -> None:
        failure = FailureArtifactError(
            build_failure_record(
                phase="baseline_seed_push",
                failure_class="git_push",
                archetype=SENTINEL,
                config=SENTINEL,
            )
        )
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory(prefix="pack-eval-main-") as tmp:
            with mock.patch.object(cli, "run_evaluation", side_effect=failure), mock.patch.object(cli.sys, "stderr", stderr):
                code = cli.main(["--report", str(Path(tmp) / "report.json"), "--binary", "fake"])
        output = stderr.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("phase=baseline_seed_push", output)
        self.assertIn("failure_class=git_push", output)
        self.assertNotIn(SENTINEL, output)


if __name__ == "__main__":
    unittest.main()
