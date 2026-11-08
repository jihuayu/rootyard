#!/usr/bin/env python3
"""Unit and smoke tests for W0 state-services documentation/contract tooling."""
import json
import subprocess
import sys
import tempfile
import unittest
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

    def test_tiny_runner_emits_real_git_and_null_unavailable_metrics(self):
        workload = {
            "schema": "rootyard.state-services.workload/v1",
            "id": "test-tiny",
            "seed": 106,
            "bounds": {"wall_clock_seconds": 30, "max_git_push_ops": 4, "max_cas_ops": 8, "max_temp_bytes": 1048576},
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
        with tempfile.TemporaryDirectory() as tmp:
            workload_path = Path(tmp) / "workload.json"
            report_path = Path(tmp) / "report.json"
            workload_path.write_text(json.dumps(workload), encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "state_services_baseline.py"),
                    "--workload",
                    str(workload_path),
                    "--out",
                    str(report_path),
                    "--allow-dirty",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
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


if __name__ == "__main__":
    unittest.main()
