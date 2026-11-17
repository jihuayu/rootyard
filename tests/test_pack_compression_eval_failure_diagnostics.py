#!/usr/bin/env python3
"""Hermetic tests for finite live-benchmark failure diagnostics (Refs #178).

These tests never spawn Git, HTTP, S3, PostgreSQL or a benchmark process.  They
use fake CompletedProcess values, known in-memory stderr strings, temporary
files and mocked CLI collaborators.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
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
    git_failure_record,
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
                "inflight_bytes": 402653184,
            },
        )
        self.assertEqual(enrich_failure_record(record)["fixture_capacity"], envelope)

        for bad in (
            {"concurrent_branches": 4, "request_ceiling_bytes": 134217728, "inflight_bytes": 536870912},
            {"concurrent_branches": 3, "request_ceiling_bytes": "134217728", "inflight_bytes": 402653184},
            {"concurrent_branches": 3, "request_ceiling_bytes": 134217728, "inflight_bytes": 1},
            {"concurrent_branches": 3, "request_ceiling_bytes": 134217728, "inflight_bytes": 402653184, "x": SENTINEL},
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


class FailureArtifactTest(unittest.TestCase):
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
