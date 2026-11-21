#!/usr/bin/env python3
"""Hermetic tests for the three-repository first incremental push checkpoint.

The only real Git operations are local work-tree clones and pushes into
temporary bare fixture repositories.  No HTTP service, PostgreSQL, S3 endpoint,
tenant, or external network is contacted.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pack_compression_eval import multi_repo  # noqa: E402
from pack_compression_eval.corpus import isolated_git_env, run_git  # noqa: E402
from pack_compression_eval.failure_diagnostics import (  # noqa: E402
    LiveEvalFailure,
    completed_counts,
    git_failure_record,
    push_expected_destination,
)
from pack_compression_eval.pack_matrix import CANDIDATE_CONFIGS  # noqa: E402
from pack_compression_eval.report import _validate_multi_repo_group  # noqa: E402
from pack_compression_eval.telemetry import percentile_stats  # noqa: E402

GIT = shutil.which("git")
COHORT = (("compressed_media", "sha1"), ("large_binary", "sha1"), ("text_history", "sha256"))


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.env = isolated_git_env({})
        self.base_url = ""

    def target(self, ordinal: int, archetype: str, object_format: str) -> dict:
        source = self.root / f"source-{ordinal}"
        source.mkdir()
        self.git(["init", "--quiet", f"--object-format={object_format}", "--initial-branch=main", str(source)], None)
        (source / "README.md").write_text(f"seeded main {ordinal}\n", encoding="utf-8")
        (source / "src").mkdir()
        (source / "src" / "lib.txt").write_text("seeded fixture content\n", encoding="utf-8")
        self.git(["add", "-A"], source)
        self.git(["commit", "--quiet", "-m", f"seed {ordinal}"], source)
        head = self.git(["rev-parse", "HEAD"], source).decode("ascii").strip()
        bare = self.root / f"remote-{ordinal}.git"
        self.git(["clone", "--bare", "--quiet", str(source), str(bare)], None)
        return {
            "archetype": archetype,
            "object_format": object_format,
            "head_oid": head,
            "work_dir": source,
            "repo": {"id": f"repository-{ordinal}", "clone_path": str(bare), "owner": "fixture", "name": f"repo-{ordinal}"},
            "rw": {"username": "fixture-writer", "token": "rw-secret-sentinel"},
            "ro": {"username": "fixture-writer", "token": "ro-secret-sentinel"},
        }

    def targets(self) -> list[dict]:
        return [self.target(index, *COHORT[index]) for index in range(3)]

    def git(self, args: list[str], cwd: Path | None) -> bytes:
        proc, _ = run_git(GIT, args, cwd, self.env)
        if proc.returncode != 0:
            raise AssertionError(proc.stderr.decode(errors="replace"))
        return proc.stdout.strip()


class FakeProxy:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.counters = 0

    def reset_counters(self, *, settle_timeout=None) -> None:
        self.events.append("reset")
        self.counters = 0

    def snapshot(self, *, settle_timeout=None) -> dict:
        self.events.append("snapshot")
        self.counters += 1
        return {
            "observed": True,
            "get_requests": 0,
            "get_bytes": 0,
            "put_requests": 1,
            "put_bytes": 100,
            "status_counts": {"200": 1},
            "req_counts_by_method": {"PUT": 1},
        }


def local_push(git_bin, work_dir, remote_url, spec, ref_target, env, *, context=None, fixture_operation=None):
    proc, elapsed = run_git(
        git_bin, ["-c", "credential.helper=", "push", "--quiet", "--porcelain", remote_url, ref_target],
        work_dir, env,
    )
    if proc.returncode != 0:
        raise LiveEvalFailure(
            git_failure_record(
                context, returncode=proc.returncode, elapsed_ms=elapsed, stderr=proc.stderr,
                stdout=proc.stdout, expected_destination=push_expected_destination(ref_target),
            )
        )
    return elapsed


class MultiRepoTargetSelectionTest(unittest.TestCase):
    def test_first_two_and_final_are_identical_for_quick_and_full(self) -> None:
        quick = [{"ordinal": index, "archetype": arch, "object_format": fmt} for index, (arch, fmt) in enumerate(COHORT)]
        full = [
            {"ordinal": index, "archetype": arch, "object_format": "sha1"}
            for index, arch in enumerate(("compressed_media", "large_binary", "text_history", "small_deltas", "similar_files", "multi_repo"))
        ]
        full.append({"ordinal": len(full), "archetype": "text_history", "object_format": "sha256"})
        for rows in (quick, full):
            selected = multi_repo.select_multi_repo_targets(rows)
            self.assertEqual(len(selected), 3)
            self.assertEqual([(row["archetype"], row["object_format"]) for row in selected], list(COHORT))
            self.assertEqual([selected[0]["ordinal"], selected[1]["ordinal"]], [0, 1])
            self.assertEqual(selected[2]["ordinal"], len(rows) - 1)

    def test_cohort_fails_closed_on_duplicate_ids_or_mixed_writers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="multi-repo-cohort-") as tmp:
            fixture = Fixture(Path(tmp))
            targets = fixture.targets()
            progress = {"completed": completed_counts(), "last_completed_phase": "candidate_reads"}
            for mutate in (
                lambda rows: rows[1]["repo"].update(id=rows[0]["repo"]["id"]),
                lambda rows: rows[2]["rw"].update(username="other-writer"),
            ):
                rows = copy.deepcopy(targets)
                mutate(rows)
                with self.subTest(target=rows[1]["repo"]["id"]):
                    with mock.patch.object(multi_repo, "push_with_pack_config", side_effect=local_push):
                        with self.assertRaises(LiveEvalFailure) as caught:
                            multi_repo.run_multi_repo_first_pushes(
                                GIT, "", rows, CANDIDATE_CONFIGS[0], FakeProxy(), fixture.root, progress,
                                config="fixture-config", run_env={}, askpass=fixture.root / "askpass.sh",
                            )
                    self.assertEqual(caught.exception.record["phase"], multi_repo.MULTI_REPO_VERIFY_PHASE)
                    self.assertEqual(caught.exception.record["failure_class"], "multi_repo_cohort")
                    self.assertNotIn("rw-secret-sentinel", json.dumps(caught.exception.record))


class MultiRepoCheckpointTest(unittest.TestCase):
    def test_real_local_first_pushes_verify_fixed_ref_and_leave_main_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(prefix="multi-repo-checkpoint-") as tmp:
            fixture = Fixture(Path(tmp))
            targets = fixture.targets()
            progress = {"completed": completed_counts(), "last_completed_phase": "candidate_reads"}
            proxy = FakeProxy()

            def verify_after_snapshot(*args, **kwargs):
                self.assertIn("snapshot", proxy.events)
                return real_clone_and_fsck(*args, **kwargs)

            real_clone_and_fsck = multi_repo.clone_and_fsck
            with mock.patch.object(multi_repo, "push_with_pack_config", side_effect=local_push), \
                    mock.patch.object(multi_repo, "clone_and_fsck", side_effect=verify_after_snapshot):
                result = multi_repo.run_multi_repo_first_pushes(
                    GIT, "", targets, CANDIDATE_CONFIGS[0], proxy, fixture.root, progress,
                    config="fixture-config", run_env={"GIT_DIR": "/no-such-git-dir"}, askpass=fixture.root / "askpass.sh",
                )

            self.assertEqual(proxy.events, ["reset", "snapshot"])
            self.assertEqual(result["cohort_size"], 3)
            self.assertEqual([sample["repo_ordinal"] for sample in result["push_samples"]], [0, 1, 2])
            self.assertEqual(result["push_stats"], percentile_stats([sample["push_ms"] for sample in result["push_samples"]]))
            self.assertTrue(result["all_verified"])
            self.assertEqual(result["verified_samples"], 3)
            self.assertTrue(result["repository_ids_distinct"])
            self.assertTrue(result["clone_paths_distinct"])
            self.assertTrue(result["same_writer_cohort"])
            self.assertEqual(result["client_invocation_overlap"]["scope"], "client_invocations_only")
            self.assertFalse(result["client_invocation_overlap"]["server_internal_overlap_claimed"])
            self.assertEqual(progress["completed"]["multi_repo_pushes_completed"], 3)
            self.assertEqual(progress["completed"]["multi_repo_verifications_completed"], 3)
            self.assertEqual(progress["completed"]["multi_repo_configs_completed"], 1)
            _validate_multi_repo_group(result, "fixture-config")
            self.assertEqual(len({sample["repository_id"] for sample in result["push_samples"]}), 3)
            self.assertEqual(len({sample["push_oid"] for sample in result["push_samples"]}), 3)

            for ordinal, target in enumerate(targets):
                remote_head = fixture.git(["rev-parse", "refs/heads/main"], Path(target["repo"]["clone_path"]))
                fired = fixture.git(["rev-parse", multi_repo.MULTI_REPO_REF], Path(target["repo"]["clone_path"]))
                self.assertEqual(remote_head.decode("ascii"), target["head_oid"])
                self.assertEqual(fired.decode("ascii"), result["push_samples"][ordinal]["push_oid"])
                self.assertEqual(fixture.git(["rev-parse", "refs/heads/main"], Path(target["work_dir"])).decode("ascii"), target["head_oid"])

            encoded = json.dumps(result, sort_keys=True)
            self.assertNotIn(str(fixture.root), encoded)
            self.assertNotIn("rw-secret-sentinel", encoded)
            self.assertNotIn("ro-secret-sentinel", encoded)

    def test_head_mismatch_fails_before_any_push(self) -> None:
        with tempfile.TemporaryDirectory(prefix="multi-repo-head-") as tmp:
            fixture = Fixture(Path(tmp))
            targets = fixture.targets()
            targets[1]["head_oid"] = "0" * 40
            progress = {"completed": completed_counts(), "last_completed_phase": "candidate_reads"}
            with mock.patch.object(multi_repo, "push_with_pack_config", side_effect=local_push) as push:
                with self.assertRaises(LiveEvalFailure) as caught:
                    multi_repo.run_multi_repo_first_pushes(
                        GIT, "", targets, CANDIDATE_CONFIGS[0], FakeProxy(), fixture.root, progress,
                        config="fixture-config", run_env={}, askpass=fixture.root / "askpass.sh",
                    )
            push.assert_not_called()
            self.assertEqual(caught.exception.record["failure_class"], "multi_repo_head_mismatch")
            self.assertEqual(caught.exception.record["repo_ordinal"], 1)
            self.assertEqual(progress["completed"]["multi_repo_pushes_completed"], 0)

    def test_push_failure_is_collected_once_and_kept_finite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="multi-repo-failure-") as tmp:
            fixture = Fixture(Path(tmp))
            progress = {"completed": completed_counts(), "last_completed_phase": "candidate_reads"}
            sentinel = "PUSH_FAILURE_SENTINEL_ee91"
            original = LiveEvalFailure(
                git_failure_record(
                    {"phase": multi_repo.MULTI_REPO_PUSH_PHASE, "completed": completed_counts(),
                     "last_completed_phase": "candidate_reads"},
                    failure_class="git_push", returncode=128, elapsed_ms=4.0,
                    stderr=f"error: HTTP 503 {sentinel}\n".encode(),
                )
            )

            def fail_one(git_bin, work_dir, remote_url, spec, ref_target, env, *, context=None, fixture_operation=None):
                if context and context.get("repo_ordinal") == 1:
                    raise original
                return local_push(git_bin, work_dir, remote_url, spec, ref_target, env, context=context)

            with mock.patch.object(multi_repo, "push_with_pack_config", side_effect=fail_one):
                with self.assertRaises(LiveEvalFailure) as caught:
                    multi_repo.run_multi_repo_first_pushes(
                        GIT, "", fixture.targets(), CANDIDATE_CONFIGS[0], FakeProxy(), fixture.root, progress,
                        config="fixture-config", run_env={}, askpass=fixture.root / "askpass.sh",
                    )
            self.assertIs(caught.exception, original)
            self.assertEqual(caught.exception.record["phase"], multi_repo.MULTI_REPO_PUSH_PHASE)
            self.assertEqual(caught.exception.record["http_status"], 503)
            self.assertEqual(progress["completed"]["multi_repo_configs_completed"], 0)
            self.assertEqual(progress["completed"]["multi_repo_verifications_completed"], 0)
            self.assertNotIn(sentinel, json.dumps(caught.exception.record))


class MultiRepoReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.group = {
            "config_name": "fixture-config",
            "fixed_ref": multi_repo.MULTI_REPO_REF,
            "cohort_size": 3,
            "repository_ids_distinct": True,
            "clone_paths_distinct": True,
            "same_writer_cohort": True,
            "writer_cohort_size": 1,
            "push_samples": [
                {
                    "repo_ordinal": ordinal,
                    "repository_id": f"repository-{ordinal}",
                    "clone_path_sha256": "a" * 63 + str(ordinal),
                    "archetype": archetype,
                    "object_format": fmt,
                    "base_oid": str(ordinal) * (40 if fmt == "sha1" else 64),
                    "push_oid": str(ordinal + 1) * (40 if fmt == "sha1" else 64),
                    "verified_ref_oid": str(ordinal + 1) * (40 if fmt == "sha1" else 64),
                    "verified_main_oid": str(ordinal) * (40 if fmt == "sha1" else 64),
                    "first_attempt": True,
                    "retry_count": 0,
                    "push_verified": True,
                    "known_file_verified": True,
                    "push_ms": float(ordinal + 1),
                    "client_invocation_start_ms": float(ordinal),
                    "client_invocation_end_ms": float(ordinal + 10),
                }
                for ordinal, (archetype, fmt) in enumerate(COHORT)
            ],
            "push_stats": percentile_stats([1.0, 2.0, 3.0]),
            "s3_push": {"observed": True, "get_requests": 0, "get_bytes": 0, "put_requests": 3, "put_bytes": 300},
            "verified_samples": 3,
            "all_verified": True,
            "verification": {
                "fresh_stock_clone": True, "strict_fsck": True, "exact_oid": True,
                "known_file": True, "main_unchanged": True, "outside_push_and_s3_timing": True,
            },
            "client_invocation_overlap": {
                "scope": "client_invocations_only", "all_overlap": True, "overlap_ms": 8.0,
                "server_internal_overlap_claimed": False,
            },
            "first_attempt_only": True,
        }

    def test_valid_group_passes(self) -> None:
        _validate_multi_repo_group(self.group, "fixture-config")

    def test_mutations_fail_closed(self) -> None:
        cases = (
            ("cohort size", lambda group: group["push_samples"].pop()),
            ("statistics", lambda group: group["push_stats"].update(p99_ms=999.0)),
            ("unverified", lambda group: group["push_samples"][1].update(push_verified=False)),
            ("repository ids not distinct", lambda group: group["push_samples"][1].update(repository_id=group["push_samples"][0]["repository_id"])),
            ("overlap evidence", lambda group: group["client_invocation_overlap"].update(overlap_ms=99.0)),
            ("did not overlap", lambda group: group["push_samples"][2].update(
                client_invocation_start_ms=20.0, client_invocation_end_ms=30.0,
            )),
            ("interval invalid", lambda group: group["push_samples"][0].update(client_invocation_end_ms=0)),
            ("sample invalid", lambda group: group["push_samples"].__setitem__(1, None)),
            ("not confirmed", lambda group: group.update(all_verified=False)),
        )
        for message, mutate in cases:
            group = copy.deepcopy(self.group)
            mutate(group)
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    _validate_multi_repo_group(group, "fixture-config")


if __name__ == "__main__":
    unittest.main()
