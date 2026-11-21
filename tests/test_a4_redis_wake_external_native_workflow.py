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
        self.invalid_hints_codes = namespace["INVALID_HINT_CODES"]
        self.owned_flushall_codes = namespace["OWNED_FLUSHALL_CODES"]
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


    def test_owned_flushall_evidence_uses_only_whitelisted_codes(self):
        self.assertEqual(self.owned_flushall_codes, set(a4.OWNED_FLUSHALL_CODES))
        observations = {"owned_cleanup_completed": False}
        failed = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "owned_flushall",
             "owned_flushall": "ownership"}, observations
        )
        self.assertEqual(failed["stage"], "owned_flushall")
        self.assertEqual(failed["owned_flushall"], "ownership")
        missing = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "owned_flushall"}, observations
        )
        self.assertEqual(missing["owned_flushall"], "unavailable")
        closed = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "owned_flushall",
             "owned_flushall": "unavailable"}, observations
        )
        self.assertEqual(closed["owned_flushall"], "unavailable")
        for bad_code in ("private/socket/path", "", 7, ["ownership"], {"code": "flush"}):
            with self.subTest(code=bad_code):
                rejected = self.case_evidence(
                    {"name": a4.CASE, "status": "failed", "stage": "owned_flushall",
                     "owned_flushall": bad_code}, observations
                )
                self.assertEqual(rejected["owned_flushall"], "unavailable")
                self.assertNotIn("private", repr(rejected))
        for other_stage in ("healthy_push", "healed_wake", "denials"):
            with self.subTest(cross_stage=other_stage):
                cross = self.case_evidence(
                    {"name": a4.CASE, "status": "failed", "stage": other_stage,
                     "owned_flushall": "ownership"}, observations
                )
                self.assertNotIn("owned_flushall", cross)
        passed = self.case_evidence(
            {"name": a4.CASE, "status": "passed", "stage": "owned_flushall",
             "owned_flushall": "ownership"}, observations
        )
        self.assertNotIn("owned_flushall", passed)


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

    def test_invalid_hints_evidence_uses_only_whitelisted_codes(self):
        self.assertEqual(self.invalid_hints_codes, set(a4.INVALID_HINT_CODES))
        observations = {"owned_cleanup_completed": False}
        failed = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "invalid_hints",
             "invalid_hints": "snapshot_equality"}, observations
        )
        self.assertEqual(failed["stage"], "invalid_hints")
        self.assertEqual(failed["invalid_hints"], "snapshot_equality")
        missing = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "invalid_hints"}, observations
        )
        self.assertEqual(missing["invalid_hints"], "unavailable")
        closed = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "invalid_hints",
             "invalid_hints": "unavailable"}, observations
        )
        self.assertEqual(closed["invalid_hints"], "unavailable")
        for bad_code in ("private/sql/row", "", 7, ["claim_equality"], {"code": "baseline_idle"}):
            with self.subTest(code=bad_code):
                rejected = self.case_evidence(
                    {"name": a4.CASE, "status": "failed", "stage": "invalid_hints",
                     "invalid_hints": bad_code}, observations
                )
                self.assertEqual(rejected["invalid_hints"], "unavailable")
                self.assertNotIn("private", repr(rejected))
        other_stage = self.case_evidence(
            {"name": a4.CASE, "status": "failed", "stage": "healthy_push",
             "invalid_hints": "snapshot_equality"}, observations
        )
        self.assertNotIn("invalid_hints", other_stage)
        passed = self.case_evidence(
            {"name": a4.CASE, "status": "passed", "stage": "invalid_hints",
             "invalid_hints": "snapshot_equality"}, observations
        )
        self.assertNotIn("invalid_hints", passed)



LEGACY_REF = "codex/goal-issue111-a4-redis-external-native-20261119"
PROMOTION_REF = "codex/goal-issue111-a4-external-promotion-20261121"


def step_block(name):
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index(f"      - name: {name}\n")
    following = text.find("\n      - ", start + 1)
    return text[start:] if following < 0 else text[start:following + 1]


class PromotionWorkflowWiringTest(unittest.TestCase):
    def test_push_filter_and_job_condition_name_exactly_two_refs(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        trigger = text[text.index("on:"):text.index("permissions:")]
        branches = [line.strip() for line in trigger.splitlines() if line.strip().startswith("- ")]
        self.assertEqual(branches, [f"- {LEGACY_REF}", f"- {PROMOTION_REF}"])

        job_condition = text[text.index("    if: >-"):text.index("    runs-on:")]
        self.assertIn("github.event_name == 'push'", job_condition)
        self.assertIn(f"github.ref == 'refs/heads/{LEGACY_REF}'", job_condition)
        self.assertIn(f"github.ref == 'refs/heads/{PROMOTION_REF}'", job_condition)
        self.assertIn("github.repository == 'jihuayu/rootyard'", job_condition)

    def test_promotion_harness_is_new_ref_only_and_runs_before_garage_stop(self):
        legacy = step_block("Run real external A4 acceptance")
        promotion = step_block("Run real external A4 replica promotion acceptance")
        self.assertIn(f"if: github.ref == 'refs/heads/{LEGACY_REF}'", legacy)
        self.assertNotIn(PROMOTION_REF, legacy)
        self.assertIn(f"if: github.ref == 'refs/heads/{PROMOTION_REF}'", promotion)
        self.assertNotIn(LEGACY_REF, promotion)
        for required in (
            "set -euo pipefail",
            "set -a",
            '. "$RUNNER_TEMP/a4-object-store.env"',
            "export ROOTYARD_BLOB_DELETE=disabled",
            "export ROOTYARD_TEST_REDIS_SERVER=\"/usr/bin/redis-server\"",
            "python3 tests/a4_redis_external_promotion.py \\",
            '--binary "$RUNNER_TEMP/a4-native/rootyard" \\',
            '--git "$ROOTYARD_GIT" \\',
            '--expect-commit "$GITHUB_SHA" \\',
            '--report "$RUNNER_TEMP/a4/promotion-report.json"',
        ):
            self.assertIn(required, promotion)
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertLess(
            text.index("Run real external A4 replica promotion acceptance"),
            text.index("Stop owned Garage S3 fixture"),
        )
        self.assertLess(
            text.index("Stop owned Garage S3 fixture"),
            text.index("Write typed external A4 promotion evidence"),
        )

    def test_legacy_evidence_and_artifact_remain_on_the_legacy_ref(self):
        evidence = step_block("Write typed acceptance evidence")
        upload = step_block("Upload closed report and typed evidence")
        for block in (evidence, upload):
            self.assertIn(f"if: always() && github.ref == 'refs/heads/{LEGACY_REF}'", block)
        self.assertIn("name: a4-redis-wake-external-native-${{ github.run_id }}-${{ github.run_attempt }}", upload)
        self.assertIn("test-results/a4/report.json", upload)
        self.assertIn("test-results/a4/evidence.json", upload)
        self.assertIn("if-no-files-found: error", upload)

    def test_promotion_evidence_reuses_manifest_and_module_witness_checks(self):
        block = step_block("Write typed external A4 promotion evidence")
        for required in (
            "python3 scripts/native_report_manifest.py --mode job",
            '--binary "$RUNNER_TEMP/a4-native/rootyard"',
            '--build-receipt "$RUNNER_TEMP/a4-native/rootyard.build.json"',
            '--expect-commit "$GITHUB_SHA"',
            "--harness tests/a4_redis_external_promotion.py",
            "--harness tests/a4_redis_wake_partition.py",
            '--report "promotion=$report"',
            '--require-case "promotion=real_a4_external_redis_replica_promotion"',
            '--manifest-out "$manifest"',
            "promotion.validate_case_detail(detail)",
            "promotion.require_promotion_witness(projected)",
            'report.get("source_tree") != tree',
            'report.get("source_inputs_sha256") != manifest.get("source_inputs_sha256")',
            'report.get("binary_sha256") != manifest.get("binary_sha256")',
            'report.get("build_receipt_sha256") != (manifest.get("build_receipt") or {}).get("sha256")',
            'report.get("harness_sha256") != harnesses.get("tests/a4_redis_external_promotion.py")',
            'report.get("fixture_harness_sha256") != harnesses.get("tests/a4_redis_wake_partition.py")',
            'if [ "$result" -eq 0 ] && [ "$status" = "passed" ]',
            "exit \"$result\"",
        ):
            self.assertIn(required, block)
        self.assertIn("if: always() && github.ref == 'refs/heads/" + PROMOTION_REF + "'", block)

    def test_promotion_evidence_python_block_compiles(self):
        lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
        start = next(
            index for index, line in enumerate(lines)
            if line.startswith('          python3 -I - "$status"')
        )
        heredoc = next(index for index in range(start, len(lines)) if "<<'PY'" in lines[index])
        end = next(index for index in range(heredoc + 1, len(lines)) if lines[index] == "          PY")
        compile(
            textwrap.dedent("\n".join(lines[heredoc + 1:end])),
            str(WORKFLOW),
            "exec",
        )

    def test_promotion_failure_stage_is_closed_and_report_upload_is_separate(self):
        block = step_block("Write typed external A4 promotion evidence")
        for stage in ("garage_setup", "harness", "garage_cleanup", "report_missing", "binding"):
            self.assertIn(f"stage={stage}", block)
        for stage in ("witness", "cleanup"):
            self.assertIn(f'"{stage}"', block)
        self.assertIn('failure({}, "witness")', block)
        self.assertIn("except Exception:", block)
        for forbidden in ("str(error)", "repr(error)", "traceback", "exc_info"):
            self.assertNotIn(forbidden, block)

        report_upload = step_block("Upload sanitized external A4 promotion report")
        failure_upload = step_block("Upload closed external A4 promotion failure evidence")
        self.assertIn("name: a4-redis-external-promotion-${{ github.run_id }}-${{ github.run_attempt }}", report_upload)
        self.assertIn("steps.promotion_evidence.outputs.report_staged == 'true'", report_upload)
        self.assertIn("test-results/a4-promotion/report.json", report_upload)
        self.assertNotIn("test-results/a4-promotion/evidence.json", report_upload)
        self.assertIn("name: a4-redis-external-promotion-failure-${{ github.run_id }}-${{ github.run_attempt }}", failure_upload)
        self.assertIn("steps.promotion_evidence.outputs.report_staged != 'true'", failure_upload)
        self.assertIn("test-results/a4-promotion/evidence.json", failure_upload)
        self.assertNotIn("test-results/a4-promotion/report.json", failure_upload)

    def test_garage_cleanup_stays_unconditional(self):
        block = step_block("Stop owned Garage S3 fixture")
        self.assertIn("if: always()", block)
        self.assertNotIn(LEGACY_REF, block)
        self.assertNotIn(PROMOTION_REF, block)
        self.assertIn("scripts/owned_garage_fixture.sh stop", block)


if __name__ == "__main__":
    unittest.main()
