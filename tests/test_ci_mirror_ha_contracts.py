#!/usr/bin/env python3
"""Static contracts for live multi-mirror and multi-controller HA qualification (#34)."""
from __future__ import annotations

import ast
import importlib.util
import io
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci-mirror-ha.yml"
QUAL_SCRIPT = ROOT / "tests" / "ci_mirror_ha_qualification.py"
DOCS = ROOT / "docs" / "ci-mirror.md"


def _load_qualification_module():
    spec = importlib.util.spec_from_file_location("ci_mirror_ha_qualification_under_test", QUAL_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the HA qualification harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


QUAL_MODULE = _load_qualification_module()

PINNED_CARGO_FORK_REV = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
PINNED_CARGO_FORK_VER = "1.101.0"
PINNED_RUST_VERSION = "1.99.1"


class CiMirrorHaContractsTest(unittest.TestCase):
    def test_qualification_harness_syntax_flags_and_no_mirror_mocks(self) -> None:
        self.assertTrue(QUAL_SCRIPT.is_file(), f"Missing {QUAL_SCRIPT}")
        raw = QUAL_SCRIPT.read_bytes()
        self.assertNotIn(b"\r", raw, "ci_mirror_ha_qualification.py must use pure LF endings")
        src = raw.decode("utf-8")
        tree = ast.parse(src)

        # Must run real `rootyard serve-mirror` daemons, never loopback Python HTTP mirror mocks.
        self.assertNotIn("http.server", src)
        self.assertNotIn("HTTPServer", src)
        self.assertNotIn("BaseHTTPRequestHandler", src)

        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn("http.server", imported)

        for tok in (
            "serve-mirror",
            "\"serve\"",
            "\"worker\"",
            "\"reconcile\"",
            "ci-mirrors",
            "SIGKILL",
            "fsck",
            "--strict",
            "failover",
            "ready",
            "waiting",
            "denied",
            "missing",
            "overloaded",
            "x-rootyard-ci-state",
            "ROOTYARD_CI_MIRROR_SOURCE_TOKEN",
            "ROOTYARD_CI_MIRROR_PREWARM_ORIGINS",
            "ROOTYARD_CI_MIRROR_PREWARM_TOKEN",
            "live_pgid_processes",
        ):
            self.assertIn(tok, src, f"ci_mirror_ha_qualification.py missing {tok}")

        proc = subprocess.run(
            [sys.executable, str(QUAL_SCRIPT), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        for flag in ("--binary", "--report", "--keep"):
            self.assertIn(flag, proc.stdout)

    def test_multi_daemon_uuid_keepalive_and_prewarm_bugfixes(self) -> None:
        mirror_rs = ROOT / "src" / "mirror.rs"
        webhooks_rs = ROOT / "src" / "webhooks.rs"
        self.assertLess(len(mirror_rs.read_text(encoding="utf-8").splitlines()), 140)
        self.assertLess(len(webhooks_rs.read_text(encoding="utf-8").splitlines()), 100)
        self.assertFalse((ROOT / "src" / "mirror" / "mod.rs").exists())
        self.assertFalse((ROOT / "src" / "webhooks" / "mod.rs").exists())

        orch_src = (ROOT / "src" / "mirror" / "orchestration.rs").read_text(encoding="utf-8")
        self.assertLess(len(orch_src.splitlines()), 450)
        self.assertNotIn("#[allow(", orch_src)
        self.assertIn("parse_mirror_uuid_opt", orch_src)
        self.assertIn("Uuid::parse_str", orch_src)
        self.assertIn("ensure_heartbeat_keepalive", orch_src)
        self.assertIn("mirror_uuid", orch_src)

        mirrors_src = (ROOT / "src" / "webhooks" / "mirrors.rs").read_text(encoding="utf-8")
        self.assertLess(len(mirrors_src.splitlines()), 500)
        self.assertNotIn("#[allow(", mirrors_src)
        self.assertIn('row.get::<_, Uuid>("mirror_id").to_string()', mirrors_src)
        self.assertGreaterEqual(mirrors_src.count("#[serde(deny_unknown_fields)]"), 2)

        ctrl_src = (ROOT / "src" / "webhooks" / "ci_controller.rs").read_text(encoding="utf-8")
        self.assertLess(len(ctrl_src.splitlines()), 500)
        self.assertNotIn("#[allow(", ctrl_src)
        self.assertIn("LIMIT 8", ctrl_src)
        self.assertIn("JoinSet", ctrl_src)
        self.assertNotIn("LIMIT 1", ctrl_src.split("trigger_coalesced_prewarm", 1)[1])

    def test_checkout_snapshot_is_one_coherent_fact(self) -> None:
        ctrl_src = (ROOT / "src" / "webhooks" / "ci_controller.rs").read_text(encoding="utf-8")
        sql_src = ctrl_src.split("const CHECKOUT_SNAPSHOT_SQL", 1)[1].split(
            "pub(crate) async fn select_ready_mirror", 1
        )[0]
        sql = " ".join(sql_src.split())
        self.assertEqual(sql.count("statement_timestamp()"), 1)
        self.assertNotIn("clock_timestamp()", sql)
        for cte in (
            "now_fact AS MATERIALIZED",
            "lease_counts AS MATERIALIZED",
            "mirror_facts AS MATERIALIZED",
            "eligible AS MATERIALIZED",
            "winner AS MATERIALIZED",
            "origin_counts AS MATERIALIZED",
        ):
            self.assertIn(cte, sql)
        self.assertIn("GROUP BY c.source_url", sql)
        self.assertIn("FROM origin_counts o", sql)
        self.assertIn("winner AS MATERIALIZED (SELECT url FROM eligible WHERE $7::boolean", sql)
        self.assertIn("SELECT (SELECT count(*) FROM eligible) AS ready_avail", sql)
        self.assertIn("(SELECT count(*) FROM mirror_facts WHERE target_ready) AS ready_total", sql)
        self.assertIn("(SELECT count(*) FROM mirror_facts WHERE NOT target_ready) AS healthy_unready", sql)
        self.assertIn(
            "ORDER BY active_leases ASC,(capacity-active_leases) DESC,heartbeat_unix DESC,mirror_id ASC LIMIT 1",
            sql,
        )
        self.assertIn("m.heartbeat_unix>now_fact.now_epoch::bigint-$4", sql)
        self.assertIn("c.lease_expires_unix>now_fact.now_epoch", sql)
        self.assertIn("count(*) FILTER (WHERE c.repository_id=$1) AS per_repo_active", sql)
        lease_src = sql.split("lease_counts AS MATERIALIZED", 1)[1].split(
            "mirror_facts AS MATERIALIZED", 1
        )[0]
        self.assertNotIn("repository_id", lease_src)
        self.assertNotIn("pg_advisory", sql)

        runs_src = (ROOT / "src" / "webhooks" / "runs.rs").read_text(encoding="utf-8")
        claim_src = runs_src.split("pub async fn claim", 1)[1].split("pub async fn heartbeat", 1)[0]
        self.assertLess(
            claim_src.index("pg_advisory_xact_lock(1062026)"),
            claim_src.index("choose_checkout_source"),
        )
        ops_src = (ROOT / "src" / "webhooks" / "run_ops.rs").read_text(encoding="utf-8")
        failover_src = ops_src.split("pub async fn failover", 1)[1]
        self.assertLess(
            failover_src.index("pg_advisory_xact_lock(1062026)"),
            failover_src.index("choose_checkout_source"),
        )

    def test_ci_mirror_ha_workflow_and_docs_contracts(self) -> None:
        self.assertTrue(WORKFLOW.is_file(), f"Missing {WORKFLOW}")
        raw_yml = WORKFLOW.read_bytes()
        self.assertNotIn(b"\r", raw_yml, "ci-mirror-ha.yml must use pure LF endings")
        yml = raw_yml.decode("utf-8")
        self.assertNotIn("\t", yml)
        self.assertTrue(yml.startswith("name: "))

        for tok in (
            "postgres:17",
            f"rustup toolchain install {PINNED_RUST_VERSION}",
            "scripts/install_ci_cargo_fork.sh install",
            "scripts/install_ci_cargo_fork.sh verify",
            PINNED_CARGO_FORK_VER,
            PINNED_CARGO_FORK_REV,
            "scripts/check_design_docs.py",
            "tests/ci_mirror_ha_qualification.py",
            "tests/ci_runs_regressions.py",
            "tests/ci_mirror.py",
            "test_ci_mirror_ha_contracts",
        ):
            self.assertIn(tok, yml, f"ci-mirror-ha.yml missing {tok}")

        docs_src = DOCS.read_text(encoding="utf-8")
        for anchor in (
            "ci_mirror_ha_qualification.py",
            "test_ci_mirror_ha_contracts.py",
            "ci-mirror-ha.yml",
            "UUID",
        ):
            self.assertIn(anchor, docs_src, f"docs/ci-mirror.md missing {anchor}")

    def test_bounded_response_and_report_helpers(self) -> None:
        module = QUAL_MODULE
        limit = 7
        self.assertEqual(module.read_bounded(io.BytesIO(b"a" * limit), limit), b"a" * limit)
        with self.assertRaises(AssertionError) as raised:
            module.read_bounded(io.BytesIO(b"a" * (limit + 1)), limit)
        self.assertEqual(str(raised.exception), "HTTP response exceeded 7 byte bounded cap")
        self.assertNotIn("a" * (limit + 1), str(raised.exception))

        payload = "x" * (limit + 1)
        kept, within_limit = module.bounded_report_payload(payload, limit)
        self.assertEqual(kept, payload)
        self.assertFalse(within_limit)
        kept, within_limit = module.bounded_report_payload("x" * limit, limit)
        self.assertEqual(kept, "x" * limit)
        self.assertTrue(within_limit)

        self.assertTrue(issubclass(module.HttpTransportError, OSError))

        src = QUAL_SCRIPT.read_text(encoding="utf-8")
        self.assertTrue("read_bounded(resp)" in src, "success response read is not bounded")
        self.assertTrue("read_bounded(err)" in src, "error response read is not bounded")
        self.assertTrue("bounded_report_payload(payload)" in src, "report payload is not size guarded")
        self.assertTrue('raise HttpTransportError("HTTP request failed") from None' in src, "transport error is not fixed")

    def test_checkout_token_registration_is_immediate_and_fixed(self) -> None:
        class FakeHarness:
            def __init__(self) -> None:
                self.secrets: list[str] = []

            def add_secret(self, value: str) -> None:
                if value and value not in self.secrets:
                    self.secrets.append(value)

        fake = FakeHarness()
        token = "ryj_" + "a" * 64
        returned = QUAL_MODULE.HaQualificationHarness.register_checkout_token(
            fake, {"checkout": {"token": token}}
        )
        self.assertEqual(returned, token)
        self.assertEqual(fake.secrets, [token])
        for claimed in (
            {},
            [],
            {"checkout": {}},
            {"checkout": {"token": ""}},
            {"checkout": {"token": "not-a-token"}},
            {"checkout": {"token": token + "\n"}},
        ):
            with self.assertRaises(AssertionError) as raised:
                QUAL_MODULE.HaQualificationHarness.register_checkout_token(fake, claimed)
            self.assertEqual(
                str(raised.exception),
                "claim response did not contain a bounded checkout token",
            )
            self.assertNotIn(token, str(raised.exception))

    def test_scenario_d_registers_token_before_any_assert(self) -> None:
        tree = ast.parse(QUAL_SCRIPT.read_text(encoding="utf-8"))
        cls = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "HaQualificationHarness"
        )
        scenario = next(
            node for node in cls.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "scenario_d_controlled_readiness_claim_transition"
        )
        token_line = None
        for node in ast.walk(scenario):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "checkout_token"
            ):
                self.assertIsInstance(node.value, ast.Call)
                self.assertIsInstance(node.value.func, ast.Attribute)
                self.assertEqual(node.value.func.attr, "register_checkout_token")
                token_line = node.lineno
        self.assertIsNotNone(token_line)
        first_claimed_assert = None
        for node in ast.walk(scenario):
            if isinstance(node, ast.Assert):
                if not (isinstance(node.msg, ast.Constant) and isinstance(node.msg.value, str)):
                    self.fail(f"Scenario D assert at line {node.lineno} does not use a fixed message")
                if "claimed" in {name.id for name in ast.walk(node) if isinstance(name, ast.Name)} and first_claimed_assert is None:
                    first_claimed_assert = node.lineno
        self.assertIsNotNone(first_claimed_assert)
        self.assertLess(token_line, first_claimed_assert)

    def test_scenario_d_pushes_to_live_controller2_same_repo(self) -> None:
        tree = ast.parse(QUAL_SCRIPT.read_text(encoding="utf-8"))
        cls = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "HaQualificationHarness"
        )
        scenario = next(
            node for node in cls.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "scenario_d_controlled_readiness_claim_transition"
        )

        def self_attr(node, name: str) -> bool:
            return (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "self"
                and node.attr == name
            )

        def repo1_clone_path(node) -> bool:
            return (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "self"
                and node.value.attr == "repo1"
                and isinstance(node.slice, ast.Constant)
                and node.slice.value == "clone_path"
            )

        pushes = []
        for node in ast.walk(scenario):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "git"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "push"
            ):
                pushes.append(node)
            if isinstance(node, ast.Constant) and node.value == "origin":
                self.fail(f"Scenario D references dead origin at line {node.lineno}")
            if self_attr(node, "c1_base"):
                self.fail(f"Scenario D references dead controller-1 at line {node.lineno}")
        self.assertEqual(len(pushes), 1)
        push = pushes[0]
        self.assertEqual(len(push.args), 3)
        destination = push.args[1]
        self.assertIsInstance(destination, ast.BinOp)
        self.assertIsInstance(destination.op, ast.Add)
        self.assertTrue(self_attr(destination.left, "c2_base"))
        self.assertTrue(repo1_clone_path(destination.right))
        self.assertEqual(push.args[2].value, "HEAD:refs/heads/feat-e")
        keywords = {keyword.arg: keyword.value for keyword in push.keywords}
        self.assertTrue(self_attr(keywords.get("cwd"), "work1"))
        self.assertTrue(self_attr(keywords.get("token"), "alice"))
        for node in ast.walk(scenario):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"start_daemon", "git"}
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in {"controller-1", "remote", "config"}
            ):
                self.fail(f"Scenario D changes controller/auth/global state at line {node.lineno}")

    def test_all_checkout_tokens_register_before_assertions(self) -> None:
        tree = ast.parse(QUAL_SCRIPT.read_text(encoding="utf-8"))
        cls = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "HaQualificationHarness"
        )
        methods = {
            node.name: node for node in cls.body if isinstance(node, ast.FunctionDef)
        }
        direct = {
            "scenario_a_pr_prewarm_and_live_mirror_checkout": {"claimed": False},
            "scenario_b_sigkill_dual_crash_and_failover": {
                "c_b1": False,
                "c_b2": False,
                "c2_test": False,
                "c_lint": False,
                "fo_direct": False,
            },
            "scenario_c_coalesced_prewarm_and_origin_burst": {
                "waiting_doc": True,
                "woken_doc": False,
            },
            "scenario_d_controlled_readiness_claim_transition": {"claimed": False},
        }
        response_lists = {
            "scenario_c_coalesced_prewarm_and_origin_burst": ("res1", "res2", "wq_res"),
        }

        def parent_blocks(func):
            blocks = {}
            for node in ast.walk(func):
                for field_name in ("body", "orelse", "finalbody"):
                    block = getattr(node, field_name, None)
                    if isinstance(block, list):
                        for statement in block:
                            blocks.setdefault(statement, block)
            return blocks

        def assigned_names(node):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = set()
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name):
                        names.add(child.id)
            return names

        def find_assignment(func, name):
            for node in ast.walk(func):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and name in assigned_names(node):
                    return node
            return None

        def immediate_call(func, name):
            assignment = find_assignment(func, name)
            self.assertIsNotNone(assignment, f"missing assignment for {name}")
            block = parent_blocks(func).get(assignment)
            self.assertIsNotNone(block, f"missing parent block for {name}")
            index = block.index(assignment)
            self.assertLess(index + 1, len(block), f"missing immediate registration for {name}")
            statement = block[index + 1]
            if isinstance(statement, ast.Expr):
                call = statement.value
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                call = statement.value
            else:
                call = None
            self.assertIsInstance(call, ast.Call, f"immediate registration is not a call for {name}")
            self.assertIsInstance(call.func, ast.Attribute)
            self.assertTrue(call.args, f"immediate registration has no argument for {name}")
            self.assertIsInstance(call.args[0], ast.Name)
            self.assertEqual(call.args[0].id, name)
            return call

        token_names = set()
        for scenario, names in direct.items():
            func = methods[scenario]
            for name, optional in names.items():
                call = immediate_call(func, name)
                self.assertEqual(call.func.attr, "register_checkout_token")
                required = next((kw.value for kw in call.keywords if kw.arg == "required"), None)
                if optional:
                    self.assertIsInstance(required, ast.Constant)
                    self.assertFalse(required.value)
                else:
                    self.assertIsNone(required)
                token_names.add(name)
        for scenario, names in response_lists.items():
            func = methods[scenario]
            for name in names:
                call = immediate_call(func, name)
                self.assertEqual(call.func.attr, "register_checkout_tokens")
                token_names.add(name)
        token_names.update({"ready1", "over1", "ready2", "over2", "wq_res", "leased2_ids", "release_doc"})
        for func in methods.values():
            for node in ast.walk(func):
                if isinstance(node, ast.Assert):
                    names = {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}
                    if names & token_names:
                        self.assertIsInstance(node.msg, ast.Constant)
                        self.assertIsInstance(node.msg.value, str)
        self.assertTrue(
            '["checkout"]["token"]' not in QUAL_SCRIPT.read_text(encoding="utf-8"),
            "direct checkout token extraction remains",
        )

    def test_require_int_rejects_bool_float_and_other_stand_ins(self) -> None:
        self.assertEqual(QUAL_MODULE.require_int(1, "counter"), 1)
        self.assertEqual(QUAL_MODULE.require_int(0, "counter"), 0)
        for value in (True, False, 1.0, 1.5, "1", None):
            with self.assertRaises(AssertionError) as raised:
                QUAL_MODULE.require_int(value, "counter")
            self.assertEqual(str(raised.exception), "counter is not an integer")

    def test_untrusted_counters_use_require_int(self) -> None:
        tree = ast.parse(QUAL_SCRIPT.read_text(encoding="utf-8"))
        cls = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "HaQualificationHarness"
        )
        methods = {
            node.name: node for node in cls.body if isinstance(node, ast.FunctionDef)
        }
        counter_names = {
            "attempt",
            "lease_generation",
            "storage_generation",
            "ready_available_mirrors",
            "ready_total_mirrors",
            "healthy_unready_mirrors",
        }
        for scenario in (
            "scenario_a_pr_prewarm_and_live_mirror_checkout",
            "scenario_b_sigkill_dual_crash_and_failover",
            "scenario_c_coalesced_prewarm_and_origin_burst",
            "scenario_d_controlled_readiness_claim_transition",
        ):
            for node in ast.walk(methods[scenario]):
                if not isinstance(node, ast.Assert):
                    continue
                for child in ast.walk(node.test):
                    if (
                        isinstance(child, ast.Call)
                        and isinstance(child.func, ast.Attribute)
                        and child.func.attr == "get"
                        and child.args
                        and isinstance(child.args[0], ast.Constant)
                        and child.args[0].value in counter_names
                    ):
                        self.fail("direct untrusted counter comparison remains")
                    if (
                        isinstance(child, ast.Subscript)
                        and isinstance(child.slice, ast.Constant)
                        and child.slice.value in counter_names
                    ):
                        self.fail("direct untrusted counter comparison remains")
        src = QUAL_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("isinstance(pr_number, int)", src)

    def test_initialization_failure_is_bounded_and_cleans_root(self) -> None:
        src = QUAL_SCRIPT.read_text(encoding="utf-8")
        self.assertTrue('root = Path(tempfile.mkdtemp(prefix="rootyard-ci-mirror-ha-"))' in src, "main-owned temp root creation missing")
        self.assertTrue("harness = HaQualificationHarness(args, root)" in src, "main did not pass the owned root")
        self.assertTrue('"error": "qualification harness initialization failed"' in src, "fixed initialization failure report missing")
        self.assertTrue("shutil.rmtree(root, ignore_errors=True)" in src, "initialization failure root cleanup missing")
        self.assertTrue("harness.cleanup(stop_daemons=False, remove_root=reaped)" in src, "bounded cleanup call missing")
        self.assertLess(
            src.index("    try:\n        root = Path(tempfile.mkdtemp"),
            src.index("        harness = HaQualificationHarness(args, root)"),
        )
        self.assertLess(
            src.index("        harness = HaQualificationHarness(args, root)"),
            src.index("shutil.rmtree(root, ignore_errors=True)"),
        )

    def test_source_token_scan_states_and_final_scan_order(self) -> None:
        src = QUAL_SCRIPT.read_text(encoding="utf-8")
        self.assertTrue("live_pgid_processes(self.tracked_pgids)" in src, "live-writer ownership check missing")
        self.assertTrue('"live_writer"' in src, "live-writer failure state missing")
        self.assertTrue('"oversize"' in src, "oversize failure state missing")
        self.assertTrue("MAX_LOG_BYTES" in src, "per-log cap missing")
        self.assertTrue("MAX_TOTAL_LOG_BYTES" in src, "total log cap missing")
        self.assertTrue("source_token_zero_leak" not in src, "stale unbounded leak claim remains")
        self.assertTrue('entry["log_path"].read_text' not in src, "unbounded C log scan remains")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            clean = root / "clean.log"
            clean.write_text("ordinary content\n", encoding="utf-8")
            leaked = root / "leaked.log"
            leaked.write_text("prefix TOKEN suffix\n", encoding="utf-8")
            clean_bytes = len("ordinary content\n".encode("utf-8"))
            leaked_bytes = len("prefix TOKEN suffix\n".encode("utf-8"))
            self.assertEqual(
                QUAL_MODULE.scan_token_in_logs([clean], "TOKEN"),
                {"state": "clean", "scanned": 1, "bytes": clean_bytes},
            )
            result = QUAL_MODULE.scan_token_in_logs([clean, leaked], "TOKEN")
            self.assertEqual(
                result,
                {"state": "leaked", "scanned": 2, "bytes": clean_bytes + leaked_bytes},
            )
            self.assertNotIn("leaked.log", repr(result))
            self.assertNotIn("prefix", repr(result))
            self.assertEqual(
                QUAL_MODULE.scan_token_in_logs([clean], ""),
                {"state": "unavailable", "scanned": 0, "bytes": 0},
            )
            self.assertEqual(
                QUAL_MODULE.scan_token_in_logs([clean, root / "missing.log"], "TOKEN"),
                {"state": "missing", "scanned": 1, "bytes": clean_bytes},
            )
            per_log_oversized = root / "per-log-oversized.log"
            per_log_oversized.write_bytes(b"x" * 8)
            self.assertEqual(
                QUAL_MODULE.scan_token_in_logs(
                    [per_log_oversized], "TOKEN", per_log_limit=7, total_limit=100
                ),
                {"state": "oversize", "scanned": 0, "bytes": 0},
            )
            first = root / "first.log"
            first.write_bytes(b"a" * 4)
            second = root / "second.log"
            second.write_bytes(b"b" * 4)
            self.assertEqual(
                QUAL_MODULE.scan_token_in_logs(
                    [first, second], "TOKEN", per_log_limit=100, total_limit=6
                ),
                {"state": "oversize", "scanned": 1, "bytes": 4},
            )

        tree = ast.parse(QUAL_SCRIPT.read_text(encoding="utf-8"))
        main = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        outer_try = next(node for node in main.body if isinstance(node, ast.Try) and node.finalbody)
        nodes = [node for statement in outer_try.finalbody for node in ast.walk(statement)]

        def call_lines(attribute: str) -> list[int]:
            return [
                node.lineno for node in nodes
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == attribute
            ]

        reap_lines = call_lines("reap_owned_processes")
        scan_lines = call_lines("scan_source_token_logs")
        cleanup_lines = call_lines("cleanup")
        write_lines = call_lines("write_text")
        print_lines = [
            node.lineno for node in nodes
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
        ]
        size_guard_lines = [
            node.lineno for node in nodes
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "bounded_report_payload"
        ]
        payload_print_lines = [
            node.lineno for node in nodes
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "payload"
        ]
        failure_print_lines = [
            node.lineno for node in nodes
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "failure_trace"
        ]
        for found in (
            reap_lines,
            scan_lines,
            cleanup_lines,
            write_lines,
            print_lines,
            size_guard_lines,
            payload_print_lines,
            failure_print_lines,
        ):
            self.assertTrue(found)
        reaped_if = next(
            node for statement in outer_try.finalbody for node in ast.walk(statement)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "reaped"
        )
        reaped_scan_lines = [
            node.lineno for node in ast.walk(reaped_if)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "scan_source_token_logs"
        ]
        self.assertTrue(reaped_scan_lines)
        self.assertLess(min(reap_lines), min(reaped_scan_lines))
        cleanup_calls = [
            node for statement in outer_try.finalbody for node in ast.walk(statement)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "cleanup"
        ]
        self.assertTrue(any(any(keyword.arg == "remove_root" for keyword in call.keywords) for call in cleanup_calls))
        self.assertLess(min(scan_lines), min(cleanup_lines))
        self.assertLess(min(scan_lines), min(write_lines))
        self.assertLess(min(scan_lines), min(failure_print_lines))
        self.assertLess(min(size_guard_lines), min(write_lines))
        self.assertLess(min(size_guard_lines), min(payload_print_lines))


if __name__ == "__main__":
    unittest.main()
