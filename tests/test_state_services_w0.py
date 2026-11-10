#!/usr/bin/env python3
"""Unit and smoke tests for W0 state-services documentation/contract tooling."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import zlib
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import state_services_baseline as baseline  # noqa: E402
import state_services_checks as checks  # noqa: E402


class StateServicesDocumentsTest(unittest.TestCase):
    def test_design_snapshot_is_verbatim_issue_copy(self):
        snapshot = checks.validate_snapshot()
        design = snapshot["design_snapshot"]
        self.assertEqual(design["source_sha256"], design["checked_in_sha256"])
        self.assertTrue(design["copied_verbatim"])
        self.assertFalse(design["is_part_of_archived_source_snapshot"])

    def test_producer_inventory_symbols_and_categories(self):
        inventory = checks.validate_producers()
        categories = {entry["category"] for entry in inventory["entries"]}
        self.assertTrue(checks.REQUIRED_CATEGORIES <= categories)
        ids = [entry["id"] for entry in inventory["entries"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(any(entry["id"] == "publish.gitfs.receive_pack" for entry in inventory["entries"]))
        self.assertTrue(any(entry["id"] == "publish.pando.commit_refs" for entry in inventory["entries"]))

    def test_deployment_contract_accepts_only_implemented_profiles(self):
        contract = checks.validate_deployment()
        selectable = {p["id"] for p in contract["profiles"] if p["selectable_now"]}
        self.assertEqual(selectable, {"legacy-gitfs-postgres", "pando-postgres-pack-store"})
        self.assertFalse(any(p["selectable_now"] for p in contract["profiles"] if p["status"] == "proposed"))

    def test_declared_workload_satisfies_runner_contract(self):
        workload = json.loads((ROOT / "docs/design/state-services/workloads/w0-bounded.json").read_text(encoding="utf-8"))
        baseline.validate_workload(workload)
        facts = baseline.admission(workload)
        self.assertLessEqual(facts["estimate_bytes"], workload["bounds"]["max_temp_bytes"])

    def test_budgets_are_provisional_and_measurable(self):
        budgets = checks.validate_budgets()
        self.assertEqual(budgets["status"], "provisional_unmeasured")
        self.assertIsNone(budgets["baseline_evidence"])
        for budget in budgets["budgets"]:
            self.assertEqual(budget["decision"], "not_frozen")
            self.assertIsNone(budget["bound"])

    def test_implemented_profiles_reject_other_wal_authorities(self):
        contract = checks.load(checks.STATE / "deployment-contract.json")
        schema = checks.load(checks.STATE / "config.schema.json")
        for relative in contract["config_validation"]["accepted_examples"]:
            document = checks.load(ROOT / relative)
            for invalid in ("raft-native-store", "blob", "memory"):
                with self.subTest(profile=document["profile"], wal=invalid):
                    candidate = dict(document, metadata_wal_store=invalid)
                    self.assertTrue(checks.validate_schema(candidate, schema, schema))
            omitted = dict(document)
            omitted.pop('metadata_wal_store', None)
            self.assertTrue(checks.validate_schema(omitted, schema, schema))

    def test_table_inventory_rejects_mentions_without_ddl(self):
        self.assertFalse(checks.declares_table('-- CREATE TABLE ghost(id int);', 'ghost'))
        self.assertFalse(checks.declares_table('/* CREATE TABLE ghost(id int); */ SELECT 1;', 'ghost'))
        self.assertFalse(checks.declares_table('SELECT * FROM ghost;', 'ghost'))
        self.assertTrue(checks.declares_table('CREATE TABLE IF NOT EXISTS ghost(id int);', 'ghost'))
        self.assertTrue(checks.declares_table('ALTER TABLE ghost ADD COLUMN v int;', 'ghost'))

    def test_dependency_selection_distinguishes_verified_and_candidate(self):
        dependencies = checks.validate_dependencies()
        opendal = next(c for c in dependencies["candidates"] if c["crate"] == "opendal")
        self.assertEqual(opendal["version"], "0.57.0")
        self.assertEqual(opendal["rust_version"], "1.85")
        rocks = next(c for c in dependencies["candidates"] if c["crate"] == "rocksdb")
        self.assertEqual(rocks["verification"], "candidate_unverified")
        self.assertIsNone(rocks["version"])


class StateServicesRunnerTest(unittest.TestCase):
    def test_percentile_and_unavailable_never_pass(self):
        self.assertEqual(baseline.percentile([10], 0.95), 10.0)
        metrics = {"git.receive_pack.small_pack.latency_ms": baseline.unavailable("not run")}
        budget = {
            "id": "x",
            "metric": "git.receive_pack.small_pack.latency_ms",
            "statistic": "p95",
            "unit": "ms",
            "decision": "frozen",
            "bound": 1.0,
        }
        evaluation = baseline.evaluate_budgets({"budgets": [budget]}, metrics)
        self.assertEqual(evaluation[0]["status"], "unmeasured")
        self.assertIsNone(evaluation[0]["observed"])

WORKLOAD = {
    "schema": "rootyard.state-services.workload/v1",
    "id": "test-tiny",
    "seed": 106,
    "bounds": {"wall_clock_seconds": 30, "max_git_push_ops": 4, "max_cas_ops": 8, "max_temp_bytes": 4194304},
    "git": {
        "repo_count": 1,
        "pushes_per_repo": 2,
        "commits_per_push": 1,
        "file_bytes": 64,
        "cas_rounds": 2,
        "cas_concurrency": 2,
        "fsck": True,
    },
    "pg": {"enabled": False, "sample_count": 0},
    "api": {"enabled": False, "request_count": 0},
    "blob": {"enabled": False, "put_count": 0, "get_count": 0},
}
RUNNER = ROOT / "scripts" / "state_services_baseline.py"


def workload_with(**changes):
    workload = copy.deepcopy(WORKLOAD)
    git = changes.pop("git", None)
    bounds = changes.pop("bounds", None)
    workload.update(changes)
    if git:
        workload["git"].update(git)
    if bounds:
        workload["bounds"].update(bounds)
    return workload


def fixture_root_names():
    return {name for name in os.listdir(tempfile.gettempdir()) if name.startswith("rootyard-w0-git-")}


class WorkloadContractTest(unittest.TestCase):
    """Invalid, oversize and overflowing workloads are rejected without effects."""

    def test_factors_must_be_integers_within_positivity_and_hard_limits(self):
        invalid = [
            {"repo_count": 0}, {"pushes_per_repo": 0}, {"commits_per_push": 0}, {"file_bytes": -1},
            {"cas_rounds": -1}, {"cas_concurrency": 0}, {"repo_count": True}, {"file_bytes": 1.0},
            {"repo_count": "2"}, {"repo_count": baseline.RUNNER_LIMITS["max_git_repos"] + 1},
            {"file_bytes": baseline.RUNNER_LIMITS["max_file_bytes"] + 1, },
            {"cas_concurrency": baseline.RUNNER_LIMITS["max_cas_concurrency"] + 1},
            {"commits_per_push": baseline.RUNNER_LIMITS["max_commits_per_push"] + 1},
            {"fsck": "yes"},
        ]
        for change in invalid:
            with self.subTest(change=change):
                workload = workload_with(git=change)
                if change.get("file_bytes"):
                    workload["bounds"].update(max_git_push_ops=1000, max_temp_bytes=1 << 29)
                with self.assertRaises(ValueError):
                    baseline.validate_workload(workload)

    def test_bounds_must_be_finite_positive_and_within_runner_limits(self):
        invalid = [
            {"wall_clock_seconds": 0}, {"wall_clock_seconds": -1}, {"wall_clock_seconds": float("inf")},
            {"wall_clock_seconds": float("nan")}, {"wall_clock_seconds": True},
            {"wall_clock_seconds": baseline.RUNNER_LIMITS["max_wall_clock_seconds"] + 1},
            {"max_temp_bytes": 0}, {"max_temp_bytes": 1.5}, {"max_temp_bytes": baseline.RUNNER_LIMITS["max_temp_bytes"] + 1},
            {"max_git_push_ops": -1}, {"max_cas_ops": "8"},
        ]
        for change in invalid:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    baseline.validate_workload(workload_with(bounds=change))

    def test_pg_section_must_match_enabled_flag(self):
        for pg in ({"enabled": True, "sample_count": 0}, {"enabled": False, "sample_count": 3},
                   {"enabled": True, "sample_count": baseline.RUNNER_LIMITS["max_pg_samples"] + 1},
                   {"enabled": "true", "sample_count": 1}, {"enabled": True}):
            with self.subTest(pg=pg):
                with self.assertRaises(ValueError):
                    baseline.validate_workload(workload_with(pg=pg))

    def test_enabled_sections_reject_non_integer_counts(self):
        for section in ("api", "blob"):
            for change in ({"request_count": -1}, {"put_count": "1"}, {"get_count": 1.0}):
                workload = workload_with(**{section: dict(WORKLOAD[section], **change)})
                with self.subTest(section=section, change=change):
                    with self.assertRaises(ValueError):
                        baseline.validate_workload(workload)

    def test_oversize_products_are_rejected_without_overflow(self):
        far = 10 ** 30
        cases = [
            {"git": {"repo_count": far}, "bounds": {"max_git_push_ops": far}},
            {"git": {"pushes_per_repo": far}, "bounds": {"max_git_push_ops": far}},
            {"git": {"cas_rounds": far}, "bounds": {"max_cas_ops": far}},
            {"git": {"cas_concurrency": 1 << 40, "cas_rounds": 0}, "bounds": {"max_cas_ops": 8}},
            {"git": {"repo_count": 3}, "bounds": {"max_git_push_ops": 5}},
            {"git": {"cas_rounds": 3, "cas_concurrency": 3}, "bounds": {"max_cas_ops": 8}},
        ]
        for change in cases:
            with self.subTest(change=str(change)[:80]):
                with self.assertRaises(ValueError):
                    baseline.validate_workload(workload_with(**change))

    def test_cas_concurrency_must_be_one_when_rounds_are_zero(self):
        with self.assertRaises(ValueError):
            baseline.validate_workload(workload_with(git={"cas_rounds": 0, "cas_concurrency": 4}))
        baseline.validate_workload(workload_with(git={"cas_rounds": 0, "cas_concurrency": 1}))

    def test_reduced_push_override_must_be_a_positive_integer_when_admissible(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workload.json"
            path.write_text(json.dumps(workload_with()), encoding="utf-8")
            for bad in ("0", "-1", str(baseline.RUNNER_LIMITS["max_pushes_per_repo"] + 1)):
                with self.subTest(override=bad), self.assertRaises(SystemExit):
                    baseline.main(["--workload", str(path), "--out", str(Path(tmp) / "r.json"),
                                   "--allow-dirty", "--returned-pushes-per-repo", bad])
                self.assertFalse((Path(tmp) / "r.json").exists())

    def test_rejection_starts_no_process_and_creates_no_output(self):
        for change in ({"git": {"repo_count": 0}}, {"bounds": {"wall_clock_seconds": -5}},
                       {"git": {"repo_count": 10 ** 30}, "bounds": {"max_git_push_ops": 10 ** 30}},
                       {"git": {"file_bytes": baseline.RUNNER_LIMITS["max_file_bytes"] + 1}}):
            with self.subTest(change=str(change)[:60]), tempfile.TemporaryDirectory() as tmp:
                workload_path = Path(tmp) / "workload.json"
                out_dir = Path(tmp) / "out"
                workload_path.write_text(json.dumps(workload_with(**change)), encoding="utf-8")
                before = fixture_root_names()
                result = subprocess.run(
                    [sys.executable, str(RUNNER), "--workload", str(workload_path),
                     "--out", str(out_dir / "report.json"), "--allow-dirty"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("workload rejected before any measurement", result.stderr)
                self.assertFalse(out_dir.exists(), "rejected workload must not create the report directory")
                self.assertEqual(fixture_root_names(), before, "rejected workload must not create a fixture")

    def test_oversize_temp_admission_is_rejected_before_effects(self):
        workload = workload_with(bounds={"max_temp_bytes": 65536})
        with self.assertRaises(ValueError) as caught:
            baseline.admission(workload)
        self.assertIn("max_temp_bytes", str(caught.exception))
        self.assertIn("one push per repository estimates", str(caught.exception))

    def test_full_run_needing_reduction_points_at_returned_override(self):
        baseline.validate_workload(workload_with(git={"pushes_per_repo": 2, "commits_per_push": 1}))
        estimate_full = baseline.estimate_temp_bytes(workload_with(git={"pushes_per_repo": 2}))
        estimate_one = baseline.estimate_temp_bytes(workload_with(git={"pushes_per_repo": 2}), 1)
        self.assertLess(estimate_one, estimate_full)
        budget = (estimate_full + estimate_one) // 2
        with self.assertRaises(ValueError):
            baseline.admission(workload_with(git={"pushes_per_repo": 2}, bounds={"max_temp_bytes": budget}))
        facts = baseline.admission(workload_with(git={"pushes_per_repo": 2}, bounds={"max_temp_bytes": budget}), 1)
        self.assertEqual(facts["returned_pushes_per_repo"], 1)


def make_budget(workload, returned=None):
    budget = baseline.TempBudget(workload["bounds"]["max_temp_bytes"],
                                 baseline.estimate_temp_bytes(workload, returned))
    budget.admit()
    return budget


def run_fixture(workload):
    """Admit and start the owned fixture, then the runner bound to its TMPDIR."""
    budget = make_budget(workload)
    tmpdir = baseline.client_fixture(budget)
    runner = baseline.Runner(time.monotonic() + 30, tmpdir=tmpdir)
    try:
        return baseline.run_git_workload(workload, runner, 106, budget=budget)
    finally:
        if budget.root is not None:  # remove only the root this run created
            baseline.shutil.rmtree(budget.root, ignore_errors=True)


class TempAdmissionTest(unittest.TestCase):
    """The temp budget is enforced during the run, not only after it."""

    def test_outside_file_is_never_changed_or_deleted(self):
        workload = workload_with(git={"repo_count": 1, "pushes_per_repo": 1, "file_bytes": 0})
        with tempfile.TemporaryDirectory() as outside:
            untouched = Path(outside) / "unrelated.txt"
            untouched.write_bytes(b"operator data")
            script = textwrap.dedent(f"""
                import os
                open({str(untouched)!r}, "ab").write(b"x")
                open(os.path.join(os.environ["TMPDIR"], "child-scratch"), "wb").write(b"scratch")
                """)
            original_write = baseline._write_bounded

            def write_then_probe(path, payload, size, runner, budget):
                original_write(path, payload, size, runner, budget)
                runner.run([sys.executable, "-c", script], label="temp probe")

            baseline._write_bounded = write_then_probe
            try:
                metrics, truncated, _budget = run_fixture(workload)
            finally:
                baseline._write_bounded = original_write
            self.assertFalse(truncated)
            self.assertEqual(untouched.read_bytes(), b"operator datax")
        # The child scratch file is inside the fixture and charged before cleanup.
        self.assertGreaterEqual(metrics["runner.temp_bytes"]["observed_bytes"], len(b"scratch"))

    def test_child_temp_dir_is_redirected_into_the_budgeted_fixture(self):
        workload = workload_with(git={"repo_count": 1, "pushes_per_repo": 1, "file_bytes": 0})
        script = textwrap.dedent("""
            import os, subprocess, sys, tempfile
            for name in ("TMPDIR", "TMP", "TEMP"):
                print(name, os.environ[name])
            print("made", tempfile.mkdtemp())
            child = subprocess.run([sys.executable, "-c", "import os; print(os.environ['TMPDIR'])"],
                                   capture_output=True, text=True, check=True)
            print("grandchild", child.stdout.strip())
            """)
        seen = {}
        original_run = baseline.Runner.run

        def recording(run_self, command, **options):
            output = original_run(run_self, command, **options)
            if options.get("label") == "temp probe":
                seen["output"] = baseline._decode(output)
                seen["env"] = run_self.child_env
                seen["tmpdir"] = run_self.tmpdir
            return output

        original_write = baseline._write_bounded

        def write_then_probe(path, payload, size, runner, budget):
            original_write(path, payload, size, runner, budget)
            runner.run([sys.executable, "-c", script], label="temp probe")

        baseline._write_bounded = write_then_probe
        try:
            with mock.patch.object(baseline.Runner, "run", recording):
                _metrics, truncated, _budget = run_fixture(workload)
        finally:
            baseline._write_bounded = original_write
        self.assertFalse(truncated)
        lines = dict(line.split(" ", 1) for line in seen["output"].splitlines())
        tmpdir = seen["tmpdir"]
        for name in ("TMPDIR", "TMP", "TEMP"):
            self.assertEqual(lines[name], str(tmpdir))
            self.assertEqual(seen["env"][name], str(tmpdir))
        self.assertEqual(lines["grandchild"], str(tmpdir))
        self.assertTrue(Path(lines["made"]).is_relative_to(tmpdir), "mkdtemp must land in the owned TMPDIR")

    def test_owned_temp_overflow_after_a_measured_push_is_truncated_and_cleaned(self):
        workload = workload_with(git={"repo_count": 1, "pushes_per_repo": 1, "file_bytes": 0})
        script = textwrap.dedent(f"""
            import os, tempfile
            tempfile.mkdtemp()
            with open(os.path.join(os.environ["TMPDIR"], "blob"), "wb") as handle:
                handle.write(b"\\0" * {workload["bounds"]["max_temp_bytes"]})
            """)
        before = set(os.listdir(tempfile.gettempdir()))
        original_run = baseline.Runner.run

        def push_then_overflow(run_self, command, **options):
            output = original_run(run_self, command, **options)
            if options.get("label") == "git push":
                # After the push time is taken and before its checkpoint.
                run_self.run([sys.executable, "-c", script], label="temp probe")
            return output

        with mock.patch.object(baseline.Runner, "run", push_then_overflow):
            metrics, truncated, budget = run_fixture(workload)
        temp = metrics["runner.temp_bytes"]
        self.assertTrue(truncated)
        self.assertEqual(metrics["git.receive_pack.small_pack.latency_ms"]["n"], 1)
        self.assertIn("git push: owned fixture tree holds", temp["stop_reason"])
        self.assertIn("beyond max_temp_bytes", temp["stop_reason"])
        # The peak is the real observed size, not clamped to the budget.
        self.assertGreater(temp["peak_charged_bytes"], temp["budget_bytes"])
        self.assertEqual(temp["peak_charged_bytes"], budget.peak)
        self.assertNotIn("cleanup_error", temp)
        self.assertEqual(set(os.listdir(tempfile.gettempdir())), before,
                         "the overflowed fixture and its TMPDIR contents must be removed")

    def test_owned_temp_overflow_before_any_push_is_refused_and_caller_cleans(self):
        workload = workload_with(git={"repo_count": 1, "pushes_per_repo": 1, "file_bytes": 0})

        def write_then_overflow(path, payload, size, runner, budget):
            open(path, "ab").write(b"\0" * workload["bounds"]["max_temp_bytes"])

        budget = make_budget(workload)
        original_write = baseline._write_bounded
        baseline._write_bounded = write_then_overflow
        try:
            tmpdir = baseline.client_fixture(budget)
            runner = baseline.Runner(time.monotonic() + 30, tmpdir=tmpdir)
            with self.assertRaises(baseline.BudgetViolation):
                baseline.run_git_workload(workload, runner, 106, budget=budget)
        finally:
            baseline._write_bounded = original_write
        # The caller still holds the same budget and its own fixture to clean up.
        self.assertIsNotNone(budget.root)
        self.assertGreater(budget.peak, budget.budget)
        self.assertIsNone(budget.cleanup())
        self.assertFalse(budget.root)

    def test_reported_temp_metric_carries_budget_facts(self):
        workload = workload_with(git={"repo_count": 1, "pushes_per_repo": 1, "commits_per_push": 1, "file_bytes": 64})
        metrics, _, budget = run_fixture(workload)
        temp = metrics["runner.temp_bytes"]
        for key in ("budget_bytes", "admission_estimate_bytes", "peak_charged_bytes", "checkpoints"):
            self.assertIn(key, temp)
        self.assertLessEqual(temp["peak_charged_bytes"], temp["budget_bytes"])
        self.assertEqual(temp["peak_charged_bytes"], budget.peak)
        self.assertEqual(temp["checkpoints"], budget.checkpoints)
        self.assertGreater(budget.checkpoints, 0)
        self.assertLessEqual(temp["peak_charged_bytes"], temp["admission_estimate_bytes"],
                             "a completed run stays within the admitted estimate")
        self.assertEqual(temp["returned_pushes_per_repo"], workload["git"]["pushes_per_repo"])

    def test_temp_left_after_a_child_run_is_still_charged_at_final_accounting(self):
        workload = workload_with(git={"repo_count": 1, "pushes_per_repo": 1, "file_bytes": 0})
        budget = make_budget(workload)
        baseline.client_fixture(budget)
        try:
            # The work reported its child trees dropped, then leftover bytes
            # appear before the final measurement.
            budget.child_trees_dropped = True
            (budget.root / "tmp" / "late").write_bytes(b"\0" * (budget.budget + 1))
            # Here that final measurement is the gentle one, so it reports the
            # size instead of refusing: the bytes are stated, never dropped.
            budget.finish()
            self.assertGreater(budget.peak, budget.budget)
            self.assertEqual(budget.observed, budget.peak)
        finally:
            self.assertIsNone(budget.cleanup())
        self.assertFalse(budget.root)


class DeadlineAndCancellationTest(unittest.TestCase):
    """A stalled child is cancelled with the remaining time and its group is cleaned up."""

    def stalled_child(self, hold=30.0):
        script = textwrap.dedent(f"""
            import subprocess, sys, time
            if sys.argv[1] == "spawn":
                subprocess.Popen([sys.executable, "-c", "import time; time.sleep({hold})"])
            time.sleep({hold})
        """)
        return [sys.executable, "-c", script, "spawn"]

    def test_stalled_child_is_killed_within_remaining_time_and_group_is_reaped(self):
        runner = baseline.Runner(time.monotonic() + 1.0, tmpdir=tempfile.gettempdir(), kill_grace=0.01)
        started = time.monotonic()
        with self.assertRaises(baseline.RunnerTimeout):
            runner.run([sys.executable, "-c", "import time; time.sleep(30)"], label="stalled")
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(runner.timeouts, 1)
        self.assertEqual(runner.groups_killed, 1)
        self.assertEqual(runner.live_runs, 0)

    def test_grandchild_in_same_group_is_killed_with_the_leader(self):
        marker = "\n".join([
            "import os, subprocess, sys, time",
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])",
            "open(sys.argv[1] + '.child', 'w').write(str(child.pid))",
            "time.sleep(30)",
        ])
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "marker"
            runner = baseline.Runner(time.monotonic() + 0.7, tmpdir=tempfile.gettempdir(), kill_grace=0.5)
            with self.assertRaises(baseline.RunnerTimeout):
                runner.run([sys.executable, "-c", marker, str(target)], label="grandchild")
            child_pid = int(Path(str(target) + ".child").read_text())
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and Path(f"/proc/{child_pid}").exists():
                try:
                    state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
                except OSError:
                    break
                if state == "Z":  # orphaned zombie under init; it holds no resources
                    break
                time.sleep(0.02)
            try:
                state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
            except OSError:
                state = "gone"
            self.assertIn(state, {"gone", "Z"}, f"grandchild {child_pid} still {state}")

    def test_worktree_parent_inside_a_repository_is_not_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
            nested = repo / "nested-tmp"
            nested.mkdir()
            self.assertIsNone(baseline._isolated_worktree_parent(nested))
            self.assertEqual(baseline._isolated_worktree_parent(Path(tmp)), Path(tmp).resolve())
        self.assertEqual(baseline._isolated_worktree_parent(), Path(tempfile.gettempdir()).resolve())

    def test_children_are_spawned_in_their_own_session(self):
        seen = []

        class Recorder:
            def __init__(self, command, **options):
                seen.append(options)
                self.command = command

            def wait(self, timeout=None):
                return 0

            @property
            def returncode(self):
                return 0

            stdout = None
            stderr = None

        with tempfile.TemporaryDirectory() as tmp:
            runner = baseline.Runner(time.monotonic() + 5, tmpdir=tmp, popen=Recorder)
            self.assertEqual(runner.run(["true"], label="probe"), b"")
        self.assertTrue(seen and seen[0]["start_new_session"])
        # Children are pointed at the owned TMPDIR rather than the shared one.
        for name in ("TMPDIR", "TMP", "TEMP"):
            self.assertEqual(seen[0]["env"][name], tmp)

    def test_command_after_deadline_is_not_started(self):
        runner = baseline.Runner(time.monotonic() - 0.01, tmpdir=tempfile.gettempdir())
        with self.assertRaises(baseline.RunnerTimeout):
            runner.run([sys.executable, "-c", "pass"], label="never")
        self.assertEqual(runner.runs, 0)
        self.assertEqual(runner.skipped, 1)

    def test_stall_cap_stops_a_child_before_the_global_deadline(self):
        runner = baseline.Runner(time.monotonic() + 30, tmpdir=tempfile.gettempdir(), stall_seconds=0.3,
                                 kill_grace=0.01)
        started = time.monotonic()
        with self.assertRaises(baseline.RunnerTimeout):
            runner.run([sys.executable, "-c", "import time; time.sleep(30)"], label="stalled")
        # The child was stopped by its own cap, not by the 30 s global deadline.
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(runner.stall_timeouts, 1)
        self.assertEqual(runner.timeouts, 1)
        self.assertFalse(runner.expired())
        happenings = runner.happenings()
        self.assertEqual(happenings["stall_timeouts"], 1)
        self.assertEqual(happenings["stall_seconds"], 0.3)
        self.assertGreaterEqual(happenings["max_cleanup_grace_seconds"], runner.kill_grace)
        self.assertEqual(runner.live_runs, 0)

    def test_budget_is_reported_even_when_no_push_completes(self):
        workload = workload_with(git={"repo_count": 1, "pushes_per_repo": 1, "file_bytes": 0})
        budget = make_budget(workload)
        tmpdir = baseline.client_fixture(budget)
        original_write = baseline._write_bounded

        def overflow(path, payload, size, runner, budget):
            open(path, "ab").write(b"\0" * workload["bounds"]["max_temp_bytes"])

        baseline._write_bounded = overflow
        try:
            runner = baseline.Runner(time.monotonic() + 30, tmpdir=tmpdir)
            with self.assertRaises(baseline.BudgetViolation) as caught:
                baseline.run_git_workload(workload, runner, 106, budget=budget)
        finally:
            baseline._write_bounded = original_write
        # The same instance survives the refusal and still owns/reports the tree.
        self.assertIsNotNone(budget.root)
        self.assertGreater(budget.checkpoints, 0)
        self.assertGreater(budget.peak, 0)
        self.assertEqual(budget.estimate, baseline.estimate_temp_bytes(workload))
        self.assertIn("owned fixture tree holds", str(caught.exception))
        self.assertIsNone(budget.cleanup())
        self.assertFalse(budget.root)
        self.assertFalse(budget.root)

    def test_absolute_deadline_covers_cas_rounds(self):
        workload = workload_with(git={"repo_count": 1, "pushes_per_repo": 2, "commits_per_push": 1, "file_bytes": 64,
                                      "cas_rounds": 200, "cas_concurrency": 2, "fsck": False},
                                 bounds={"max_cas_ops": 400})
        baseline.validate_workload(workload)
        budget = make_budget(workload)
        tmpdir = baseline.client_fixture(budget)
        runner = baseline.Runner(time.monotonic() + 0.35, tmpdir=tmpdir, kill_grace=0.01)
        try:
            metrics, truncated, _budget = baseline.run_git_workload(workload, runner, 106, budget=budget)
        finally:
            budget.cleanup()
        self.assertTrue(truncated)
        # Fast children finish before the deadline, so the truncation may come
        # from the between-rounds remaining-time check instead of cancellation.
        self.assertGreaterEqual(runner.timeouts + runner.skipped, 1)
        self.assertLess(metrics["git.update_ref.cas_conflict.latency_ms"]["cas_attempts"], 400)
        self.assertTrue(metrics["runner.temp_bytes"]["checkpoints"] > 0)
        self.assertGreaterEqual(metrics["git.receive_pack.small_pack.latency_ms"]["n"], 1)

    def test_pg_subprocesses_use_the_shared_remaining_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "psql"
            fake.write_text("#!/bin/sh\necho $$ > \"$0.pid\"\nexec sleep 30\n", encoding="utf-8")
            fake.chmod(0o755)
            dsn = Path(tmp) / "dsn"
            dsn.write_text("postgresql://r@127.0.0.1/db", encoding="utf-8")
            workload = workload_with(pg={"enabled": True, "sample_count": 3})
            runner = baseline.Runner(time.monotonic() + 0.6, tmpdir=tmp, kill_grace=0.01)
            original = baseline.shutil.which
            baseline.shutil.which = lambda name: str(fake) if name == "psql" else original(name)
            started = time.monotonic()
            try:
                budget = baseline.TempBudget(1 << 20, 1 << 19)
                budget.admitted = True
                metrics = baseline.run_pg_workload(workload, runner, str(dsn), budget)
            finally:
                baseline.shutil.which = original
            self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(metrics["pg.round_trip.latency_ms"]["status"], "unavailable")
        self.assertEqual(runner.timeouts, 1)
        self.assertEqual(runner.live_runs, 0)


class ReportContractTest(unittest.TestCase):
    def run_report(self, workload, extra=()):
        with tempfile.TemporaryDirectory() as tmp:
            workload_path = Path(tmp) / "workload.json"
            report_path = Path(tmp) / "report.json"
            workload_path.write_text(json.dumps(workload), encoding="utf-8")
            subprocess.run([sys.executable, str(RUNNER), "--workload", str(workload_path),
                            "--out", str(report_path), "--allow-dirty", *extra],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return json.loads(report_path.read_text(encoding="utf-8"))

    def test_tiny_runner_emits_real_git_and_null_unavailable_metrics(self):
        report = self.run_report(workload_with())
        self.assertEqual(report["schema"], "rootyard.state-services.baseline/v1")
        self.assertTrue(report["identity"]["source"]["commit"])
        self.assertIsNone(report["identity"]["binary"]["sha256"])
        for key in ("git.receive_pack.small_pack.latency_ms", "git.update_ref.cas_conflict.latency_ms", "git.fsck.closure.duration_ms"):
            self.assertEqual(report["metrics"][key]["status"], "measured")
            self.assertGreaterEqual(report["metrics"][key]["n"], 1)
        for key in ("pg.round_trip.latency_ms", "api.push.e2e.latency_ms", "blob.put.latency_ms", "blob.get.latency_ms"):
            self.assertEqual(report["metrics"][key]["status"], "unavailable")
            self.assertIsNone(report["metrics"][key]["value"])
        self.assertTrue(all(item["status"] != "pass" for item in report["budget_evaluation"]))
        self.assertTrue(report["limitations"])

    def test_main_reports_the_budget_that_enforced_the_run(self):
        report = self.run_report(workload_with())
        budget = report["limits"]["temp_budget"]
        self.assertEqual(budget["budget_bytes"], WORKLOAD["bounds"]["max_temp_bytes"])
        self.assertEqual(budget["estimate_bytes"], report["limits"]["admission"]["estimate_bytes"])
        self.assertEqual(report["metrics"]["runner.temp_bytes"]["peak_charged_bytes"], budget["peak_charged_bytes"])
        self.assertGreater(budget["peak_charged_bytes"], 0)
        self.assertGreater(budget["checkpoints"], 0)

    def test_report_records_contract_provenance(self):
        report = self.run_report(workload_with())
        identity = report["identity"]
        self.assertEqual(identity["runner"]["sha256"], checks.sha256_file(RUNNER))
        self.assertEqual(identity["workload"]["id"], WORKLOAD["id"])
        self.assertEqual(len(identity["workload"]["sha256"]), 64)
        self.assertEqual(identity["workload"]["bounds"]["max_temp_bytes"], WORKLOAD["bounds"]["max_temp_bytes"])
        self.assertEqual(identity["budgets"]["status"], "provisional_unmeasured")
        limits = report["limits"]
        self.assertEqual(limits["runner_limits"], baseline.RUNNER_LIMITS)
        self.assertEqual(limits["admission_params"], baseline.ADMISSION)
        self.assertLessEqual(limits["admission"]["estimate_bytes"], WORKLOAD["bounds"]["max_temp_bytes"])
        self.assertEqual(limits["admission"]["returned_pushes_per_repo"], WORKLOAD["git"]["pushes_per_repo"])
        for key in ("subprocess_runs", "max_live_subprocesses", "timeouts", "failures", "skipped_after_deadline"):
            self.assertIn(key, report["subprocess"])
        self.assertFalse(report["truncated"])

    def test_dsn_and_credentials_never_reach_the_report(self):
        secret = "s3cr3t-Pa55"
        with tempfile.TemporaryDirectory() as tmp:
            dsn = Path(tmp) / "dsn"
            dsn.write_text(f"postgresql://runner:{secret}@127.0.0.1:5432/rootyard?password={secret}\n", encoding="utf-8")
            workload = workload_with(pg={"enabled": True, "sample_count": 1})
            workload_path = Path(tmp) / "workload.json"
            workload_path.write_text(json.dumps(workload), encoding="utf-8")
            out = Path(tmp) / "report.json"
            subprocess.run([sys.executable, str(RUNNER), "--workload", str(workload_path), "--out", str(out),
                            "--pg-dsn-file", str(dsn), "--allow-dirty"],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            text = out.read_text(encoding="utf-8")
        self.assertNotIn(secret, text)
        self.assertNotIn("127.0.0.1:5432", text)

    def test_redaction_and_scan_detect_secret_shapes(self):
        redacted = baseline.redact({"dsn": "a", "note": "see postgresql://u:pw@host/db", "nested": [{"password": "x"}]})
        self.assertNotIn("pw", json.dumps(redacted))
        self.assertEqual(baseline.redact({"k": "postgresql://u@host/db"})["k"], "postgresql://[redacted]@host/db")
        findings = baseline.scan_report_text('{"dsn": "postgresql://u:pw@h/db"}', "postgresql://u:pw@h/db")
        self.assertIn("uri_userinfo", findings)
        self.assertIn("dsn_file_contents", findings)
        # Key/value DSNs carry the secret only in the password= term.
        key_value = "host=127.0.0.1 password=kv-secret dbname=rootyard"
        self.assertEqual(baseline.scan_report_text('{"pg": "baseline leaked kv-secret"}', key_value), {"dsn_password"})
        self.assertEqual(baseline.scan_report_text('{"pg": "unavailable"}', key_value), set())
        self.assertEqual(baseline.scan_report_text('{"status": "measured", "value": 1}'), set())


if __name__ == "__main__":
    unittest.main()
