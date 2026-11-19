#!/usr/bin/env python3
"""Static regression for the A4 installer-phase evidence projection."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import a4_redis_wake_partition as a4

WORKFLOW = ROOT / ".github" / "workflows" / "a4-redis-wake-external-native.yml"


def workflow_phase_prefix():
    text = WORKFLOW.read_text(encoding="utf-8")
    start_marker = "          python3 - <<'PY'\n"
    end_marker = "\n          PY\n"
    start = text.index(start_marker) + len(start_marker)
    end = text.index(end_marker, start)
    code = textwrap.dedent(text[start:end])
    return code.split("\ndef main():", 1)[0]


class InstallerPhaseProjectionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / "workspace"
        self.runner = Path(self.temp.name) / "runner"
        (self.workspace / "scripts").mkdir(parents=True)
        (self.runner / "a4").mkdir(parents=True)
        (self.workspace / "scripts" / "install_ci_native_tools.sh").write_bytes(
            (ROOT / "scripts" / "install_ci_native_tools.sh").read_bytes()
        )
        self.old_cwd = os.getcwd()
        self.old_runner_temp = os.environ.get("RUNNER_TEMP")
        os.chdir(self.workspace)
        os.environ["RUNNER_TEMP"] = str(self.runner)
        self.addCleanup(self._restore_environment)
        namespace = {}
        exec(compile(workflow_phase_prefix(), str(WORKFLOW), "exec"), namespace)
        self.phase = namespace["installer_phase"]
        self.complete = namespace["installer_complete"]
        self.case_evidence = namespace["case_evidence"]
        self.case_stages = namespace["CASE_STAGES"]
        self.repo_create_codes = namespace["REPO_CREATE_CODES"]
        self.worker_startup_codes = namespace["WORKER_STARTUP_CODES"]
        self.phase_path = self.runner / "a4" / "native-tools-phase.json"
        self.wrapper_sha = hashlib.sha256(
            (self.workspace / "scripts" / "install_ci_native_tools.sh").read_bytes()
        ).hexdigest()
        self.phases = namespace["PHASE_NAMES"]
        self.modes = namespace["PHASE_MODES"]

    def _restore_environment(self):
        os.chdir(self.old_cwd)
        if self.old_runner_temp is None:
            os.environ.pop("RUNNER_TEMP", None)
        else:
            os.environ["RUNNER_TEMP"] = self.old_runner_temp

    def _write_record(self, payload):
        self.phase_path.write_text(json.dumps(payload), encoding="utf-8")

    def _record(self, mode="install", phase="provenance", state="complete", wrapper=None):
        return {
            "mode": mode,
            "phase": phase,
            "state": state,
            "wrapper_sha256": self.wrapper_sha if wrapper is None else wrapper,
        }

    def test_actual_extracted_function_accepts_producer_state_combinations(self):
        producer_phases = {
            "install": self.phases,
            "preflight": {"setup", "preflight", "provenance"},
        }
        self.assertEqual(set(producer_phases), self.modes)
        for mode, phases in producer_phases.items():
            for phase in sorted(phases):
                for state in ("entered", "failed"):
                    with self.subTest(mode=mode, phase=phase, state=state):
                        record = self._record(mode, phase, state)
                        self._write_record(record)
                        self.assertEqual(self.phase(), {"available": True, **record})
            with self.subTest(mode=mode, phase="provenance", state="complete"):
                record = self._record(mode, "provenance", "complete")
                self._write_record(record)
                self.assertEqual(self.phase(), {"available": True, **record})

    def test_nonstring_typed_values_are_fixed_unavailable(self):
        bad_values = (["install"], 7, {"mode": "install"})
        for field in ("mode", "phase", "state"):
            for value in bad_values:
                with self.subTest(field=field, value=value):
                    record = self._record()
                    record[field] = value
                    self._write_record(record)
                    self.assertEqual(self.phase(), {"available": False})
        for value in (["sha"], 7, {"sha": "x"}):
            with self.subTest(field="wrapper_sha256", value=value):
                record = self._record(wrapper=value)
                self._write_record(record)
                self.assertEqual(self.phase(), {"available": False})

    def test_duplicate_top_level_keys_are_fixed_unavailable(self):
        wrapper = self.wrapper_sha
        raw = (
            '{"mode":"invalid","mode":"install","phase":"provenance",'
            f'"state":"complete","wrapper_sha256":"{wrapper}"}}'
        )
        self.phase_path.write_text(raw, encoding="utf-8")
        self.assertEqual(self.phase(), {"available": False})
        raw_phase = (
            '{"mode":"install","phase":"invalid","phase":"provenance",'
            f'"state":"complete","wrapper_sha256":"{wrapper}"}}'
        )
        self.phase_path.write_text(raw_phase, encoding="utf-8")
        self.assertEqual(self.phase(), {"available": False})

    def test_oversize_and_wrong_hash_are_fixed_unavailable(self):
        self.phase_path.write_bytes(b"x" * 513)
        self.assertEqual(self.phase(), {"available": False})
        self._write_record(self._record(wrapper="0" * 64))
        self.assertEqual(self.phase(), {"available": False})

    def test_acceptance_predicate_requires_complete_installer_phase(self):
        self.phase_path.unlink(missing_ok=True)
        absent = self.phase()
        self.assertEqual(absent, {"available": False})
        self.assertFalse(self.complete(absent))

        self._write_record(self._record(wrapper="0" * 64))
        forged = self.phase()
        self.assertEqual(forged, {"available": False})
        self.assertFalse(self.complete(forged))

        wrapper = self.wrapper_sha
        self.phase_path.write_text(
            '{"mode":"invalid","mode":"install","phase":"provenance",'
            f'"state":"complete","wrapper_sha256":"{wrapper}"}}',
            encoding="utf-8",
        )
        malformed = self.phase()
        self.assertEqual(malformed, {"available": False})
        self.assertFalse(self.complete(malformed))

        self._write_record(self._record(phase="git_build", state="entered"))
        incomplete = self.phase()
        self.assertTrue(incomplete["available"])
        self.assertFalse(self.complete(incomplete))

        self._write_record(self._record(mode="preflight"))
        wrong_mode = self.phase()
        self.assertTrue(wrong_mode["available"])
        self.assertFalse(self.complete(wrong_mode))

        self._write_record(self._record())
        valid = self.phase()
        self.assertTrue(valid["available"])
        self.assertTrue(self.complete(valid))

    def test_pass_predicate_uses_completed_installer_phase(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        status_lines = [line.strip() for line in text.splitlines() if 'status = "passed"' in line]
        self.assertEqual(len(status_lines), 1)
        self.assertIn("phase_complete", status_lines[0])
        self.assertIn("phase_complete = installer_complete(phase)", text)
        self.assertIn("elif phase_only:", text)
        self.assertIn('stage = "installer_phase"', text)

    def test_failed_case_evidence_uses_only_whitelisted_stages(self):
        self.assertEqual(self.case_stages, set(a4.CASE_STAGES))
        observations = {"owned_cleanup_completed": True}
        passed = self.case_evidence(
            {"name": a4.CASE, "status": "passed", "stage": "healthy_push"}, observations
        )
        self.assertNotIn("stage", passed)
        unrelated = self.case_evidence({"name": "other", "status": "skipped"}, observations)
        self.assertNotIn("stage", unrelated)
        failed = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "healthy_push"}, observations
        )
        self.assertEqual(failed["stage"], "healthy_push")
        missing = self.case_evidence({"name": a4.CASE, "status": "failed"}, observations)
        self.assertEqual(missing["stage"], "unavailable")
        for bad_stage in ("private/repo/url", "", 7, ["healthy_push"], {"stage": "healthy_push"}):
            with self.subTest(stage=bad_stage):
                rejected = self.case_evidence(
                    {"name": a4.CASE, "status": "failed", "stage": bad_stage}, observations
                )
                self.assertEqual(rejected["stage"], "unavailable")
                self.assertNotIn("private", repr(rejected))

    def test_evidence_payload_uses_case_evidence_projection(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('"case": case_evidence(case, observations)', text)


    def test_repo_create_evidence_uses_only_whitelisted_codes(self):
        self.assertEqual(self.repo_create_codes, set(a4.REPO_CREATE_CODES))
        observations = {"owned_cleanup_completed": False}
        failed = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "repo_create",
             "repo_create": "post_status_5xx"}, observations
        )
        self.assertEqual(failed["stage"], "repo_create")
        self.assertEqual(failed["repo_create"], "post_status_5xx")
        missing = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "repo_create"}, observations
        )
        self.assertEqual(missing["repo_create"], "unavailable")
        for bad_code in ("private/repo/url", "", 7, ["post_status_5xx"], {"code": "post_shape"}):
            with self.subTest(code=bad_code):
                rejected = self.case_evidence(
                    {"name": a4.CASE, "status": "failed", "stage": "repo_create",
                     "repo_create": bad_code}, observations
                )
                self.assertEqual(rejected["repo_create"], "unavailable")
                self.assertNotIn("private", repr(rejected))
        other_stage = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "healthy_push",
             "repo_create": "post_status_5xx"}, observations
        )
        self.assertNotIn("repo_create", other_stage)
        passed = self.case_evidence(
            {"name": a4.CASE, "status": "passed", "stage": "repo_create",
             "repo_create": "post_status_5xx"}, observations
        )
        self.assertNotIn("repo_create", passed)


    def test_workflow_prepares_public_cluster_authority_before_harness(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        prepare = "Prepare the public serving schema"
        harness = "Run real external A4 acceptance"
        self.assertIn(prepare, text)
        self.assertIn(harness, text)
        self.assertLess(text.index(prepare), text.index(harness))
        block = text[text.index(prepare):text.index(harness)]
        self.assertIn(
            'env DATABASE_URL="$ROOTYARD_TEST_DATABASE_URL" "$binary" migrate',
            block,
        )
        self.assertIn("public.cluster_authority", block)
        self.assertIn("psql \"$ROOTYARD_TEST_DATABASE_URL\"", block)
        self.assertIn('if [ "$authority" != "t" ]', block)
        self.assertIn(
            "ROOTYARD_TEST_DATABASE_URL: postgresql://rootyard@127.0.0.1:55432/rootyard_a4_wake",
            text,
        )
        self.assertIn("image: postgres:17", text)
        upload = text[text.index("Upload closed report and typed evidence"):]
        self.assertNotIn("public-migrate.log", upload)


    def test_worker_startup_evidence_uses_only_whitelisted_codes(self):
        self.assertEqual(self.worker_startup_codes, set(a4.WORKER_STARTUP_CODES))
        observations = {"owned_cleanup_completed": False}
        failed = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "worker_startup",
             "worker_startup": "catch_up"}, observations
        )
        self.assertEqual(failed["stage"], "worker_startup")
        self.assertEqual(failed["worker_startup"], "catch_up")
        missing = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "worker_startup"}, observations
        )
        self.assertEqual(missing["worker_startup"], "unavailable")
        closed = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "worker_startup",
             "worker_startup": "unavailable"}, observations
        )
        self.assertEqual(closed["worker_startup"], "unavailable")
        for bad_code in ("private/worker/log", "", 7, ["catch_up"], {"code": "claim"}):
            with self.subTest(code=bad_code):
                rejected = self.case_evidence(
                    {"name": a4.CASE, "status": "failed", "stage": "worker_startup",
                     "worker_startup": bad_code}, observations
                )
                self.assertEqual(rejected["worker_startup"], "unavailable")
                self.assertNotIn("private", repr(rejected))
        other_stage = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "healthy_push",
             "worker_startup": "catch_up"}, observations
        )
        self.assertNotIn("worker_startup", other_stage)
        passed = self.case_evidence(
            {"name": a4.CASE, "status": "passed", "stage": "worker_startup",
             "worker_startup": "catch_up"}, observations
        )
        self.assertNotIn("worker_startup", passed)



if __name__ == "__main__":
    unittest.main()
