#!/usr/bin/env python3
"""Contract tests binding observability/worker docs and alert runbooks to Rust sources."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROM_JOB = "rootyard-metrics"
PROMPTOOL = os.environ.get("PROMPTOOL") or shutil.which("promtool")
RULES_FIXTURE = ROOT / "tests" / "fixtures" / "prometheus" / "rootyard-metrics.rules.yml"
RULE_TEST_FIXTURE = ROOT / "tests" / "fixtures" / "prometheus" / "rootyard-metrics.test.yml"


def _promql_blocks(text: str) -> str:
    return "\n".join(re.findall(r"```promql\n(.*?)```", text, re.S))


def _validate_scrape_failure_alert(page_name: str, text: str) -> None:
    """Require a job-scoped per-instance `up` alert and reject body-based predicates."""
    promql = _promql_blocks(text)
    expected = re.search(
        rf'(?m)^\s*up\{{job="{re.escape(PROM_JOB)}"\}}\s*==\s*0\s*$',
        promql,
    )
    if not expected:
        raise AssertionError(
            f"{page_name}: missing job-scoped per-instance alert `up{{job=\"rootyard-metrics\"}} == 0`"
        )
    for pattern, message in (
        (
            r"absent\s*\(\s*rootyard_postgres_up\s*\)",
            "rootyard_postgres_up is absent from a rejected 503 body and absent() misses a single failed target",
        ),
        (
            r"rootyard_postgres_up\s*==\s*0",
            "rootyard_postgres_up 0 exists only in a 503 body that Prometheus does not ingest",
        ),
        (
            r"(?m)^\s*up\s*==\s*0\s*$",
            "bare up == 0 also pages on unrelated jobs; scope it with job=\"rootyard-metrics\"",
        ),
    ):
        if re.search(pattern, promql):
            raise AssertionError(f"{page_name}: {message}")


def _validate_manual_503_diagnostics(page_name: str, text: str) -> None:
    """Require the 503 body to be described as manual data, never as scraped samples."""
    paragraphs = [
        re.sub(r"[`*_]", "", re.sub(r"\s+", " ", p)).strip().lower()
        for p in re.split(r"\n\s*\n", text)
    ]
    matching = [p for p in paragraphs if "503 body" in p]
    if not matching:
        raise AssertionError(f"{page_name}: missing the HTTP 503 body diagnostic contract")
    if not any(
        "manual diagnostic" in p and ("not ingested" in p or "not collected" in p)
        for p in matching
    ):
        raise AssertionError(
            f"{page_name}: 503 body must be described in one paragraph as a manual diagnostic "
            "that Prometheus does not ingest or collect"
        )
    for paragraph in matching:
        for misleading in (
            "ingests the 503 body",
            "prometheus ingests the 503",
            "prometheus collects the 503",
            "503 body is ingested",
        ):
            if misleading in paragraph:
                raise AssertionError(f"{page_name}: misleading 503 ingestion claim: {misleading!r}")


def _rust_non_test_source(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    return text.split("\n#[cfg(test)]", 1)[0]


def _parse_rust_metrics() -> dict[str, dict[str, set[str]]]:
    """Return {metric_name: {label_key: {allowed_values}}} from Rust metrics modules."""
    metrics_rs = _rust_non_test_source(ROOT / "src" / "metrics.rs")
    workers_rs = _rust_non_test_source(ROOT / "src" / "metrics_workers.rs")
    lfs_rs = _rust_non_test_source(ROOT / "src" / "lfs" / "remote_metrics.rs")

    for field in ("pub remote_failures_total: u64", "pub repair_backlog: u64"):
        if field not in lfs_rs:
            raise AssertionError(f"Missing LFS remote metric field in remote_metrics.rs: {field}")

    job_kinds = re.findall(r'\("([a-z_]+)",\s*"([a-z_]+)"\)', workers_rs)
    job_states_m = re.search(r"pub const JOB_STATES:\s*\[&str;\s*\d+\]\s*=\s*\[([^\]]+)\]", workers_rs)
    backends_m = re.search(r"pub const BACKENDS:\s*\[&str;\s*\d+\]\s*=\s*\[([^\]]+)\]", workers_rs)
    scan_states_m = re.search(r"pub const SCAN_STATES:\s*\[&str;\s*\d+\]\s*=\s*\[([^\]]+)\]", workers_rs)
    if not (job_kinds and job_states_m and backends_m and scan_states_m):
        raise AssertionError("Failed to parse constant label tables from src/metrics_workers.rs")

    job_states = set(re.findall(r'"([a-z_]+)"', job_states_m.group(1)))
    backends = set(re.findall(r'"([a-z_]+)"', backends_m.group(1)))
    scan_states = set(re.findall(r'"([a-z_]+)"', scan_states_m.group(1)))
    kind_backends = {b for b, _ in job_kinds}
    kinds = {k for _, k in job_kinds}

    metrics: dict[str, dict[str, set[str]]] = {}
    for src in (metrics_rs, workers_rs):
        for name in re.findall(r'\b(?:gauge|counter)\(\s*(?:&mut\s+)?output,\s*"(rootyard_[a-z0-9_]+)"', src):
            metrics.setdefault(name, {})
        for name in re.findall(r"# HELP (rootyard_[a-z0-9_]+)\b", src):
            metrics.setdefault(name, {})

    for name, key, val in re.findall(
        r'(rootyard_[a-z0-9_]+)\{\{([a-z_]+)=\\"([a-z_]+)\\"\}\}',
        metrics_rs,
    ):
        metrics.setdefault(name, {}).setdefault(key, set()).add(val)

    repo_states_m = re.search(r'for \(state, count\) in \[([^\]]+)\]\.iter\(\)\.zip\(s\.repositories\)', metrics_rs)
    if not repo_states_m:
        raise AssertionError("Failed to parse rootyard_repositories states from src/metrics.rs")
    metrics["rootyard_repositories"] = {"state": set(re.findall(r'"([a-z_]+)"', repo_states_m.group(1)))}

    metrics["rootyard_storage_maintenance_jobs"] = {
        "backend": kind_backends,
        "kind": kinds,
        "state": job_states,
    }
    metrics["rootyard_storage_maintenance_oldest_queued_age_seconds"] = {
        "backend": kind_backends,
        "kind": kinds,
    }
    metrics["rootyard_storage_maintenance_repos"] = {
        "backend": backends,
        "state": scan_states,
    }
    metrics["rootyard_storage_maintenance_oldest_overdue_scan_age_seconds"] = {
        "backend": backends,
    }
    return metrics


def _parse_enum_as_str(src: str, enum_name: str) -> set[str]:
    block = re.search(
        rf"impl\s+{enum_name}\s*\{{.*?fn\s+as_str\(self\)\s*->\s*&'static\s+str\s*\{{(.*?)\n\s*\}}",
        src,
        re.S,
    )
    if not block:
        raise AssertionError(f"Missing {enum_name}::as_str in Rust source")
    values = set(re.findall(r'=>\s*"([a-z_]+)"', block.group(1)))
    if not values:
        raise AssertionError(f"No string arms found in {enum_name}::as_str")
    return values


def _parse_rust_observability() -> dict[str, set[str]]:
    obs_rs = _rust_non_test_source(ROOT / "src" / "observability.rs")
    worker_rs = _rust_non_test_source(ROOT / "src" / "observability" / "worker.rs")
    remote_err_rs = _rust_non_test_source(ROOT / "src" / "storage" / "remote_errors.rs")

    events = set(re.findall(r'event\.insert\("event"\.to_owned\(\),\s*json!\("([a-z_]+)"\)\)', obs_rs))
    scopes = set(re.findall(r'event\.insert\("scope"\.to_owned\(\),\s*json!\("([a-z_]+)"\)\)', obs_rs))
    kinds = set(re.findall(r'Classification::kind\("([a-z_]+)"\)', obs_rs))
    kinds.update(re.findall(r'\bkind:\s*"([a-z_]+)"', obs_rs))
    for ternary_m in re.finditer(r'kind:\s*if\s+[^{]+\{\s*"([a-z_]+)"\s*\}\s*else\s*\{\s*"([a-z_]+)"\s*\}', obs_rs):
        kinds.update(ternary_m.groups())

    workers = _parse_enum_as_str(worker_rs, "WorkerKind")
    phases = _parse_enum_as_str(worker_rs, "Phase")
    remote_ops = _parse_enum_as_str(remote_err_rs, "RemoteOp")

    return {
        "events": events,
        "scopes": scopes,
        "kinds": kinds,
        "workers": workers,
        "phases": phases,
        "remote_ops": remote_ops,
    }


class ObservabilityRunbookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.metrics = _parse_rust_metrics()
        cls.obs = _parse_rust_observability()
        cls.doc_paths = sorted((ROOT / "docs").glob("observability-*.md")) + [
            ROOT / "docs" / "worker-diagnostics.md"
        ]
        if len(cls.doc_paths) < 3:
            raise AssertionError(f"Expected observability-*.md + worker-diagnostics.md, got {cls.doc_paths}")

    def test_rust_parsers_discover_complete_contracts(self) -> None:
        self.assertIn("rootyard_error", self.obs["events"])
        self.assertEqual(self.obs["scopes"], {"request", "worker", "detached"})
        self.assertTrue(
            {"database", "database_pool", "io", "http", "timeout", "join", "remote_store", "internal", "unknown"}
            <= self.obs["kinds"]
        )
        self.assertEqual(
            self.obs["workers"],
            {"webhooks_background", "storage_lifecycle", "workspace_capture", "workspace_remote_gc", "durable_dispatch"},
        )
        self.assertEqual(
            self.obs["phases"],
            {"round", "scan", "reconcile", "deliver", "claim", "execute", "collect", "dispatch", "subscribe"},
        )
        self.assertEqual(len(self.obs["remote_ops"]), 8)
        for required_metric in (
            "rootyard_error_log_dropped_total",
            "rootyard_postgres_up",
            "rootyard_db_pool_available",
            "rootyard_db_pool_waiting",
            "rootyard_lfs_remote_failures_total",
            "rootyard_lfs_remote_repair_backlog",
            "rootyard_operations_unresolved",
            "rootyard_webhook_delivery_oldest_age_seconds",
            "rootyard_event_delivery_oldest_age_seconds",
            "rootyard_workspace_capture_oldest_age_seconds",
            "rootyard_workspace_capture_never_sampled",
            "rootyard_workspace_lease_expired",
            "rootyard_storage_maintenance_jobs",
            "rootyard_storage_maintenance_oldest_queued_age_seconds",
            "rootyard_storage_maintenance_repos",
            "rootyard_storage_maintenance_oldest_overdue_scan_age_seconds",
        ):
            self.assertIn(required_metric, self.metrics)

    def test_docs_line_caps_balanced_fences_and_relative_links(self) -> None:
        for page in self.doc_paths:
            text = page.read_text(encoding="utf-8")
            lines = text.splitlines()
            self.assertLess(len(lines), 500, f"{page.name} exceeds 500-line cap ({len(lines)})")
            fences = re.findall(r"^\s*(`{3,}|~{3,})[^\n]*$", text, re.M)
            self.assertEqual(len(fences) % 2, 0, f"{page.name}: unbalanced code fences")
            without_code = re.sub(r"```.*?```", "", text, flags=re.S)
            for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", without_code):
                clean = target.split("#", 1)[0]
                if not clean or re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", clean):
                    continue
                resolved = (page.parent / clean).resolve()
                self.assertTrue(resolved.is_relative_to(ROOT), f"{page.name}: link escapes repo: {target}")
                self.assertTrue(resolved.exists(), f"{page.name}: broken relative link: {target}")

    def _validate_doc_metrics(self, page_name: str, text: str) -> set[str]:
        seen_metrics: set[str] = set()
        for token in re.findall(r"\b(rootyard_[a-z0-9_]+)\b", text):
            if token in self.obs["events"]:
                continue
            self.assertIn(token, self.metrics, f"{page_name} references unknown metric {token!r}")
            seen_metrics.add(token)

        for metric, selector in re.findall(r"\b(rootyard_[a-z0-9_]+)\{([^}]*)\}", text):
            self.assertIn(metric, self.metrics, f"{page_name}: unknown metric {metric!r}")
            allowed_labels = self.metrics[metric]
            for part in [p.strip() for p in selector.split(",") if p.strip()]:
                if "=" in part:
                    key, raw_val = part.split("=", 1)
                    key = re.sub(r"[!~]+$", "", key.strip())
                    val = raw_val.strip().strip('"')
                    self.assertIn(key, allowed_labels, f"{page_name}: {metric} has no label {key!r}")
                    self.assertIn(
                        val,
                        allowed_labels[key],
                        f"{page_name}: {metric} label {key!r} does not export value {val!r}",
                    )
                else:
                    self.assertIn(part, allowed_labels, f"{page_name}: {metric} has no label {part!r}")

        for promql_block in re.findall(r"```promql\n(.*?)```", text, re.S):
            for group_keys, expr_tail in re.findall(
                r"\bby\s*\(([^)]+)\)\s*\(\s*(?:[a-z_]+\s*\(\s*)*(rootyard_[a-z0-9_]+)",
                promql_block,
            ):
                self.assertIn(expr_tail, self.metrics, f"{page_name}: unknown metric {expr_tail!r}")
                allowed_labels = self.metrics[expr_tail]
                for key in [k.strip() for k in group_keys.split(",") if k.strip()]:
                    self.assertIn(
                        key,
                        allowed_labels,
                        f"{page_name}: PromQL 'by ({group_keys})' uses unexported label {key!r} on {expr_tail}",
                    )
        return seen_metrics

    def _validate_doc_observability_fields(self, page_name: str, text: str) -> None:
        field_sets = {
            "kind": self.obs["kinds"],
            "scope": self.obs["scopes"],
            "worker": self.obs["workers"],
            "phase": self.obs["phases"],
            "remote_op": self.obs["remote_ops"],
        }
        for json_block in re.findall(r"```json\n(.*?)```", text, re.S):
            record = json.loads(json_block.strip())
            self.assertIsInstance(record, dict)
            if "event" in record:
                self.assertIn(record["event"], self.obs["events"], f"{page_name} JSON has invalid event={record['event']!r}")
            for key, valid in field_sets.items():
                if key in record:
                    self.assertIn(record[key], valid, f"{page_name} JSON has invalid {key}={record[key]!r}")

        for key, valid in field_sets.items():
            patterns = (
                rf'\b{key}\s*:\s*"([a-z_]+)"',
                rf'"{key}"\s*:\s*"([a-z_]+)"',
                rf'\.{key}\s*==\s*"([a-z_]+)"',
            )
            for pat in patterns:
                for val in re.findall(pat, text):
                    self.assertIn(val, valid, f"{page_name} references unknown {key}={val!r}")

    def test_every_referenced_metric_and_label_exists_in_rust_source(self) -> None:
        seen_metrics: set[str] = set()
        for page in self.doc_paths:
            seen_metrics.update(self._validate_doc_metrics(page.name, page.read_text(encoding="utf-8")))
        self.assertGreaterEqual(len(seen_metrics), 16)

    def test_every_referenced_kind_scope_worker_phase_and_remote_op_exists_in_rust(self) -> None:
        for page in self.doc_paths:
            self._validate_doc_observability_fields(page.name, page.read_text(encoding="utf-8"))

    def test_operational_navigation_entrypoints_link_observability_docs(self) -> None:
        expected_targets = {
            (ROOT / "docs" / "observability-alerts.md").resolve(),
            (ROOT / "docs" / "observability-errors.md").resolve(),
            (ROOT / "docs" / "worker-diagnostics.md").resolve(),
        }
        for rel in ("docs/README.md", "docs/operations.md", "docs/metrics.md"):
            nav_page = ROOT / rel
            without_code = re.sub(r"```.*?```", "", nav_page.read_text(encoding="utf-8"), flags=re.S)
            resolved_links = set()
            for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", without_code):
                clean = target.strip().split()[0].split("#", 1)[0]
                if not clean or re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", clean):
                    continue
                resolved_links.add((nav_page.parent / clean).resolve())
            for req in expected_targets:
                self.assertIn(req, resolved_links, f"{rel} missing markdown link to {req.name}")
        metrics_doc = (ROOT / "docs" / "metrics.md").read_text(encoding="utf-8")
        self.assertIn("test_observability_backlog.py", metrics_doc)

    def test_runbook_covers_all_three_alert_classes_and_removes_stale_disclaimers(self) -> None:
        combined = "\n".join(p.read_text(encoding="utf-8") for p in self.doc_paths)
        for stale in (
            "Still open: remote repair metrics",
            "Native fault injection for `webhooks_background`",
            "Their scope wrapping has unit\n  coverage only",
        ):
            self.assertNotIn(stale, combined, f"Stale pre-closure disclaimer remained in docs: {stale!r}")

        alerts_doc = (ROOT / "docs" / "observability-alerts.md").read_text(encoding="utf-8")
        for required_token in (
            "`read` / `triage` / `write` / `maintain` / `admin`",
            "401",
            "403",
            "404",
            "409",
            "429",
            "57014",
            "53300",
            "23503",
            "23505",
            "23514",
            "remote_store",
            "remote_status",
            "rootyard_postgres_up",
            'up{job="rootyard-metrics"} == 0',
            "RootyardMetricsScrapeFailed",
            "rootyard_db_pool_available",
            "rootyard_db_pool_waiting",
            "rootyard_lfs_remote_failures_total",
            "rootyard_lfs_remote_repair_backlog",
            "rootyard_operations_unresolved",
            "rootyard_webhook_delivery_oldest_age_seconds",
            "rootyard_event_delivery_oldest_age_seconds",
            "rootyard_workspace_capture_oldest_age_seconds",
            "rootyard_workspace_capture_never_sampled",
            "rootyard_workspace_lease_expired",
            "rootyard_storage_maintenance_oldest_queued_age_seconds",
            "expired_running_lease",
            'max by (backend, kind) (changes(rootyard_storage_maintenance_jobs{state="failed"}[15m])) > 0',
            "RootyardExpiredBrowserSessionBacklog",
            "rootyard_error_log_dropped_total",
        ):
            self.assertIn(required_token, alerts_doc, f"Runbook missing required coverage token {required_token!r}")

    def test_scrape_failure_docs_are_job_scoped_and_per_instance(self) -> None:
        for rel in ("docs/observability-alerts.md", "docs/metrics.md"):
            page = ROOT / rel
            text = page.read_text(encoding="utf-8")
            _validate_scrape_failure_alert(page.name, text)
            _validate_manual_503_diagnostics(page.name, text)
            for stale in (
                "absent(rootyard_postgres_up)",
                "rootyard_postgres_up == 0",
                "rootyard_postgres_up=0",
            ):
                self.assertNotIn(stale, text, f"{page.name}: stale body-only alert predicate {stale!r}")

    def test_prometheus_rule_fixture_covers_one_failed_target_only(self) -> None:
        rules = RULES_FIXTURE.read_text(encoding="utf-8")
        rule_tests = RULE_TEST_FIXTURE.read_text(encoding="utf-8")
        self.assertIn("alert: RootyardMetricsScrapeFailed", rules)
        self.assertIn(f'expr: up{{job="{PROM_JOB}"}} == 0', rules)
        self.assertIn("for: 1m", rules)
        for required in (
            f'up{{job="{PROM_JOB}",instance="127.0.0.1:9108"}}',
            f'up{{job="{PROM_JOB}",instance="127.0.0.1:9109"}}',
            'up{job="unrelated-metrics",instance="127.0.0.1:9200"}',
            "instance: 127.0.0.1:9109",
            "exp_alerts: []",
        ):
            self.assertIn(required, rule_tests, f"Prometheus fixture missing {required!r}")

    def test_prometheus_rule_fixture_behavior(self) -> None:
        if not PROMPTOOL:
            message = (
                "promtool is not installed; run `promtool check rules "
                f"{RULES_FIXTURE} && promtool test rules {RULE_TEST_FIXTURE}`"
            )
            if os.environ.get("ROOTYARD_REQUIRE_PROMPTOOL") == "1":
                self.fail(message)
            self.skipTest(message)
        checked = subprocess.run(
            [PROMPTOOL, "check", "rules", str(RULES_FIXTURE)],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr or checked.stdout)
        tested = subprocess.run(
            [PROMPTOOL, "test", "rules", str(RULE_TEST_FIXTURE)],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(tested.returncode, 0, tested.stderr or tested.stdout)

    def test_validators_reject_omitted_or_body_based_scrape_alerts(self) -> None:
        valid_503_note = "\nA 503 body is a manual diagnostic and is not ingested.\n"
        for snippet in (
            "```promql\nrootyard_postgres_up == 1\n```\n" + valid_503_note,
            "```promql\nabsent(rootyard_postgres_up)\n```\n" + valid_503_note,
            "```promql\nrootyard_postgres_up == 0\n```\n" + valid_503_note,
            "```promql\nup == 0\n```\n" + valid_503_note,
        ):
            with self.subTest(snippet=snippet):
                with self.assertRaises(AssertionError):
                    _validate_scrape_failure_alert("synthetic.md", snippet)

        for snippet in (
            "```promql\nup{job=\"rootyard-metrics\"} == 0\n```\nA manual diagnostic: Prometheus ingests the 503 body.\n",
            "```promql\nup{job=\"rootyard-metrics\"} == 0\n```\nPrometheus discards the 503 body and does not ingest it.\n",
            "```promql\nup{job=\"rootyard-metrics\"} == 0\n```\nA manual diagnostic says the 503 body is ingested by Prometheus.\n",
            "```promql\nup{job=\"rootyard-metrics\"} == 0\n```\nA manual diagnostic retains the 503 body.\n",
        ):
            with self.subTest(snippet=snippet):
                with self.assertRaises(AssertionError):
                    _validate_manual_503_diagnostics("synthetic.md", snippet)

    def test_validators_reject_synthetic_invalid_metrics_labels_and_fields(self) -> None:
        invalid_metric_snippets = (
            "Alert on `rootyard_nonexistent_counter_total > 0`.",
            'Check `rootyard_repositories{tenant="alice"} > 0`.',
            "Check `rootyard_repositories{tenant} > 0`.",
            'Check `rootyard_postgres_up{state="ready"} == 1`.',
            'Check `rootyard_repositories{state="deleted"} > 0`.',
            'Check `rootyard_storage_maintenance_jobs{state="succeeded"} > 0`.',
            '```promql\nmax by (tenant) (rootyard_storage_maintenance_jobs{state="failed"}) > 0\n```',
            '```promql\nmax by (tenant) (changes(rootyard_storage_maintenance_jobs{state="failed"}[15m])) > 0\n```',
            "```promql\nmax by (backend) (rootyard_postgres_up) == 0\n```",
        )
        for snippet in invalid_metric_snippets:
            with self.subTest(snippet=snippet):
                with self.assertRaises(AssertionError):
                    self._validate_doc_metrics("synthetic.md", snippet)

        invalid_field_snippets = (
            '```json\n{"event":"rootyard_error","kind":"bogus_kind"}\n```',
            '```json\n{"event":"rootyard_error","scope":"bogus_scope"}\n```',
            '```json\n{"event":"rootyard_error","worker":"bogus_worker"}\n```',
            '```json\n{"event":"rootyard_error","phase":"bogus_phase"}\n```',
            '```json\n{"event":"rootyard_error","remote_op":"bogus_op"}\n```',
            'Filter `kind:"bogus_kind"` in logs.',
            'jq `select(.worker == "session_gc")`',
            'Match `phase:"bogus_phase"` on worker events.',
            'Inspect `"remote_op":"list_buckets"` failures.',
            'jq `select(.scope == "background")`',
        )
        for snippet in invalid_field_snippets:
            with self.subTest(snippet=snippet):
                with self.assertRaises(AssertionError):
                    self._validate_doc_observability_fields("synthetic.md", snippet)


if __name__ == "__main__":
    unittest.main()

