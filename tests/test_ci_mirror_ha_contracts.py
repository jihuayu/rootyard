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
        self.assertIn("read_bounded(resp)", src)
        self.assertIn("read_bounded(err)", src)
        self.assertIn("bounded_report_payload(payload)", src)
        self.assertIn('raise HttpTransportError("HTTP request failed") from None', src)

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

    def test_source_token_scan_states_and_final_scan_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            clean = root / "clean.log"
            clean.write_text("ordinary content\n", encoding="utf-8")
            leaked = root / "leaked.log"
            leaked.write_text("prefix TOKEN suffix\n", encoding="utf-8")
            self.assertEqual(
                QUAL_MODULE.scan_token_in_logs([clean], "TOKEN"),
                {"state": "clean", "scanned": 1},
            )
            result = QUAL_MODULE.scan_token_in_logs([clean, leaked], "TOKEN")
            self.assertEqual(result, {"state": "leaked", "scanned": 2})
            self.assertNotIn("leaked.log", repr(result))
            self.assertNotIn("prefix", repr(result))
            self.assertEqual(
                QUAL_MODULE.scan_token_in_logs([clean], ""),
                {"state": "unavailable", "scanned": 0},
            )
            self.assertEqual(
                QUAL_MODULE.scan_token_in_logs([clean, root / "missing.log"], "TOKEN"),
                {"state": "missing", "scanned": 1},
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
        for found in (scan_lines, cleanup_lines, write_lines, print_lines, size_guard_lines, payload_print_lines):
            self.assertTrue(found)
        self.assertLess(min(scan_lines), min(cleanup_lines))
        self.assertLess(min(scan_lines), min(write_lines))
        self.assertLess(min(scan_lines), min(print_lines))
        self.assertLess(min(size_guard_lines), min(write_lines))
        self.assertLess(min(size_guard_lines), min(payload_print_lines))


if __name__ == "__main__":
    unittest.main()
