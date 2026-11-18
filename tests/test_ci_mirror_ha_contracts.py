#!/usr/bin/env python3
"""Static contracts for live multi-mirror and multi-controller HA qualification (#34)."""
from __future__ import annotations

import ast
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci-mirror-ha.yml"
QUAL_SCRIPT = ROOT / "tests" / "ci_mirror_ha_qualification.py"
DOCS = ROOT / "docs" / "ci-mirror.md"

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


if __name__ == "__main__":
    unittest.main()
