import math
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts.pack_compression_eval.corpus import isolated_git_env, run_git
from scripts.pack_compression_eval.failure_diagnostics import LiveEvalFailure, completed_counts, git_failure_record
from scripts.pack_compression_eval.live_reads import measure_fetches
from scripts.pack_compression_eval.live_server import fetch_and_fsck
from scripts.pack_compression_eval.report import _validate_fetch_group
from scripts.pack_compression_eval.telemetry import percentile_stats


class PackCompressionFetchTest(unittest.TestCase):
    def test_bare_fetch_checks_exact_tip_for_both_object_formats(self):
        git = shutil.which("git")
        self.assertIsNotNone(git)
        for object_format, width in (("sha1", 40), ("sha256", 64)):
            with self.subTest(object_format=object_format), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                env = isolated_git_env({})
                env.update(
                    GIT_AUTHOR_NAME="Fixture",
                    GIT_AUTHOR_EMAIL="fixture@example.invalid",
                    GIT_COMMITTER_NAME="Fixture",
                    GIT_COMMITTER_EMAIL="fixture@example.invalid",
                )
                source = root / "source"

                def git_ok(args, cwd=None):
                    result, _ = run_git(git, args, cwd, env)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                    return result.stdout.strip()

                git_ok(["init", "--quiet", f"--object-format={object_format}", "--initial-branch=main", str(source)])
                (source / "fixture.txt").write_text("fetch witness\n")
                git_ok(["add", "fixture.txt"], source)
                git_ok(["commit", "--quiet", "-m", "fixture"], source)
                git_ok(["tag", "outside-fetch-refspec"], source)
                head = git_ok(["rev-parse", "HEAD"], source).decode("ascii")
                self.assertEqual(len(head), width)

                decoy = root / "decoy.git"
                git_ok(["init", "--bare", "--quiet", f"--object-format={object_format}", str(decoy)])
                decoy_config = (decoy / "config").read_bytes()
                contaminated_env = {
                    **env,
                    "GIT_DIR": str(decoy),
                    "GIT_OBJECT_DIRECTORY": str(decoy / "objects"),
                    "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(source / ".git/objects"),
                }
                context = {"phase": "baseline_fetch", "object_format": object_format}
                for label in ("cold", "warm"):
                    client = root / f"{label}.git"
                    duration = fetch_and_fsck(git, source.as_uri(), client, contaminated_env, head, object_format, context=context)
                    self.assertTrue(math.isfinite(duration) and duration >= 0)
                    self.assertEqual(git_ok(["for-each-ref", "--format=%(refname)"], client), b"refs/heads/main")
                    self.assertEqual(git_ok(["show", "refs/heads/main:fixture.txt"], client), b"fetch witness")
                self.assertEqual(git_ok(["for-each-ref"], decoy), b"")
                self.assertEqual((decoy / "config").read_bytes(), decoy_config)

                with self.assertRaises(LiveEvalFailure) as failure:
                    fetch_and_fsck(git, source.as_uri(), root / "wrong-oid.git", env, "0" * width, object_format, context=context)
                self.assertEqual(failure.exception.record["phase"], "baseline_fetch")
                self.assertEqual(failure.exception.record["failure_class"], "fetch_ack_mismatch")

    def test_fetch_phases_use_same_restarted_server_and_separate_s3_counters(self):
        target = {
            "repo": {"clone_path": "/fixture.git"},
            "ro": {"username": "fixture", "token": "fixture-token"},
            "head_oid": "a" * 40,
            "archetype": "text_history",
            "object_format": "sha1",
        }
        proxy = mock.Mock()
        counter = 0
        fetches = []

        def reset():
            nonlocal counter
            counter = 0

        def fetch(_git, url, destination, _env, _oid, _format, *, context):
            nonlocal counter
            counter += 1
            fetches.append((url, destination.name, context["phase"]))
            return 4.0

        proxy.reset_counters.side_effect = reset
        proxy.snapshot.side_effect = lambda: {"get_requests": counter}
        owner, sampler, start = mock.Mock(), mock.Mock(), mock.Mock()
        start.return_value = SimpleNamespace(pid=5), "http://127.0.0.1:1234", None
        owner.stop.return_value.stopped = True
        progress = {"completed": completed_counts()}
        with mock.patch("scripts.pack_compression_eval.live_reads.fetch_and_fsck", side_effect=fetch):
            _, result = measure_fetches(
                "git", [target], Path("/fixture"), {}, Path("/fixture/askpass"), proxy, progress,
                config="baseline", owner=owner, sampler=sampler, start=start,
            )
        owner.stop.assert_called_once_with()
        start.assert_called_once_with("serve-blob-fetch-baseline.log")
        sampler.set_pids.assert_called_once_with([5], new_epoch=True)
        self.assertEqual(fetches, [
            ("http://127.0.0.1:1234/fixture.git", "fetch-baseline-cold-0.git", "baseline_fetch"),
            ("http://127.0.0.1:1234/fixture.git", "fetch-baseline-warm-0.git", "baseline_fetch"),
        ])
        self.assertEqual(result["s3_fetch_cold"]["get_requests"], 1)
        self.assertEqual(result["s3_fetch_warm"]["get_requests"], 1)
        self.assertEqual(progress["completed"]["cold_fetch_samples_completed"], 1)
        self.assertEqual(progress["completed"]["warm_fetch_samples_completed"], 1)

    def test_fetch_records_http_status_without_inferring_a_push_subphase(self):
        stderr = b"error: RPC failed; HTTP 503 curl 22"
        for phase in ("baseline_fetch", "candidate_fetch"):
            with self.subTest(phase=phase):
                failure = git_failure_record({"phase": phase}, failure_class="git_fetch", stderr=stderr)
                self.assertEqual((failure["http_status"], failure["http_subphase"]), (503, "unknown"))
        push = git_failure_record({"phase": "concurrent_push"}, stderr=stderr)
        self.assertEqual((push["http_status"], push["http_subphase"]), (503, "receive_pack"))

    def test_fetch_report_percentiles_must_match_samples(self):
        cohort = [("text_history", "sha256")]
        record = {
            "fetch_samples": [{
                "repo_ordinal": 0, "archetype": "text_history", "object_format": "sha256",
                "cold_fetch_ms": 20, "warm_fetch_ms": 5,
            }],
            "cold_fetch_stats": percentile_stats([20]),
            "warm_fetch_stats": percentile_stats([5]),
            "s3_fetch_cold": {"observed": True, "get_requests": 1, "get_bytes": 100},
            "s3_fetch_warm": {"observed": True, "get_requests": 0, "get_bytes": 0},
        }
        _validate_fetch_group(record, "baseline", cohort)
        record["cold_fetch_stats"]["p99_ms"] = 999.0
        with self.assertRaisesRegex(ValueError, "fetch statistics do not match samples"):
            _validate_fetch_group(record, "baseline", cohort)
