"""Static contracts for the S4 CI pin / Namespace GitView slice (Refs #147).

These checks are intentionally static: this module must never invoke `cargo`,
`rustc`, `rustup` or `install_ci_cargo_fork.sh`. The cargo-fork workflow guard in
`tests/test_ci_cargo_fork_workflows.py` inspects this very package, so a build
attempt from here would mask the fork check it is meant to protect.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
CI_PINS = SRC / "ci_pins"
TESTS = ROOT / "tests"

TOUCHED = [
    SRC / "ci_pins.rs",
    CI_PINS / "issue.rs",
    CI_PINS / "lifecycle.rs",
    CI_PINS / "s4_models.rs",
    CI_PINS / "s4_schema.rs",
    CI_PINS / "s4_pin.rs",
    CI_PINS / "s4_release.rs",
    CI_PINS / "s4_authority.rs",
    CI_PINS / "s4_checkout.rs",
    CI_PINS / "s4_transport.rs",
    CI_PINS / "s4_tests.rs",
    SRC / "ci_checkouts" / "authority.rs",
    SRC / "ci_checkouts" / "handlers.rs",
    SRC / "namespace_service" / "handlers.rs",
    SRC / "namespace_service" / "views.rs",
    SRC / "namespace_service" / "reverse.rs",
    SRC / "namespace_service" / "reverse_git.rs",
    SRC / "namespace_service" / "s4_git_view.rs",
    SRC / "namespace_service" / "s4_git_view_reverse.rs",
    TESTS / "s4_ci_pins_git_view.rs",
    TESTS / "s4_ci_pins_git_view_support" / "harness.rs",
]

ZERO_TOUCH = [
    SRC / "ci_checkouts.rs",
    SRC / "namespace_service.rs",
    SRC / "git_http.rs",
    SRC / "lib.rs",
    SRC / "application.rs",
    SRC / "browse" / "policy.rs",
]

WORKFLOW = ROOT / ".github" / "workflows" / "s4-ci-pins-git-view.yml"
DOC = ROOT / "docs" / "s4-ci-pins-git-view.md"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class LayoutContracts(unittest.TestCase):
    def test_every_touched_file_exists_and_is_line_bounded(self) -> None:
        for path in TOUCHED:
            self.assertTrue(path.is_file(), f"missing {path}")
            lines = len(text(path).splitlines())
            self.assertLess(lines, 500, f"{path} has {lines} lines")

    def test_ci_pins_facade_stays_a_thin_dispatcher(self) -> None:
        lines = len(text(SRC / "ci_pins.rs").splitlines())
        self.assertLess(lines, 100, f"ci_pins.rs has {lines} lines")

    def test_no_module_file_was_introduced(self) -> None:
        for directory in (CI_PINS, SRC / "namespace_service"):
            for path in directory.rglob("mod.rs"):
                self.fail(f"mod.rs is forbidden: {path}")

    def test_zero_touch_roots_are_untouched_by_new_modules(self) -> None:
        for path in ZERO_TOUCH:
            self.assertTrue(path.is_file(), f"missing {path}")
            body = text(path)
            for module in ("s4_transport", "s4_git_view", "s4_authority", "s4_release"):
                self.assertNotIn(module, body, f"{path} must not reference {module}")


class SourceContracts(unittest.TestCase):
    def test_no_allow_attributes(self) -> None:
        for path in TOUCHED + sorted(TESTS.glob("s4_ci_pins_git_view*.rs")):
            body = text(path)
            self.assertNotIn("#[allow(", body, path)
            self.assertNotIn("#![allow(", body, path)
            self.assertNotIn("#![rustfmt::skip]", body, path)

    def test_no_tempfile_in_production_sources(self) -> None:
        for path in TOUCHED:
            self.assertNotIn("tempfile::", text(path), path)
            self.assertNotIn("use tempfile", text(path), path)

    def test_deserialize_requests_deny_unknown_fields(self) -> None:
        pattern = re.compile(
            r"#\[derive\((?P<derive>[^)]*Deserialize[^)]*)\)\]\s*(?:#\[[^\]]*\]\s*)*"
            r"pub struct (?P<name>\w+)"
        )
        for path in TOUCHED:
            body = text(path)
            for match in pattern.finditer(body):
                self.assertIn(
                    "deny_unknown_fields",
                    match.group(0),
                    f"{path}: {match.group('name')} must deny unknown fields",
                )

    def test_only_the_dedicated_schema_is_created(self) -> None:
        schema = text(CI_PINS / "s4_schema.rs")
        self.assertIn("CREATE SCHEMA IF NOT EXISTS s4_ci_retention", schema)
        self.assertNotIn("public.", schema)
        for statement in re.findall(r"CREATE TABLE IF NOT EXISTS (\S+)", schema):
            self.assertTrue(
                statement.startswith("s4_ci_retention."),
                f"table outside the S4 schema: {statement}",
            )

    def test_no_blob_backend_literal(self) -> None:
        for path in TOUCHED:
            self.assertNotIn("storage_backend='blob'", text(path), path)
            self.assertNotIn('storage_backend == "blob"', text(path), path)

    def test_refstore_backend_constant_is_used(self) -> None:
        self.assertIn("PG_REFSTORE_BACKEND", text(CI_PINS / "s4_pin.rs"))
        self.assertIn("PG_REFSTORE_BACKEND", text(SRC / "ci_checkouts" / "authority.rs"))

    def test_transport_routes_are_registered(self) -> None:
        facade = text(SRC / "ci_pins.rs")
        for suffix in ("info/refs", "git-upload-pack", "git-receive-pack"):
            self.assertIn(suffix, facade)
        self.assertIn("DefaultBodyLimit", facade)

    def test_transport_is_read_only_and_narrow(self) -> None:
        transport = text(CI_PINS / "s4_transport.rs")
        authority = text(CI_PINS / "s4_authority.rs")
        self.assertIn("CI transport is read-only", transport)
        self.assertIn("wide user credentials cannot access CI transport", transport)
        self.assertIn("checkout authorization revoked during transfer", transport)
        self.assertIn("allowAnySHA1InWant", transport)
        self.assertIn("16 * 1024", transport)
        self.assertIn("100", transport)
        self.assertIn("guarded_chunks", transport)
        self.assertIn("revoked", authority)
        self.assertNotIn("tempfile", transport)
        self.assertNotIn("unreachable!", transport)
        self.assertNotIn("unreachable!", text(CI_PINS / "s4_checkout.rs"))

    def test_view_creation_is_one_transaction(self) -> None:
        body = text(SRC / "namespace_service" / "s4_git_view.rs")
        for needle in (
            "register_serving_in_tx",
            "recheck_serving_source_pin_live_in_tx",
            "git_view_bindings",
            "workspace_view_history",
            "finish_tx",
        ):
            self.assertIn(needle, body)
        self.assertNotIn("bundle\", \"create\", file, \"--all\"", body)

    def test_reverse_merge_is_fully_published(self) -> None:
        body = text(SRC / "namespace_service" / "s4_git_view_reverse.rs")
        for needle in (
            "PgAuthorizedCommit",
            "PgArtifactHoldStore",
            "ProtectedUploader",
            "register_publication",
            "PrepareOutcome",
            "begin_serving_pending_in_tx",
            "workspace_changeset_steps",
        ):
            self.assertIn(needle, body)
        self.assertNotIn("501", body)
        self.assertNotIn("NOT_IMPLEMENTED", body)

    def test_line_endings_are_pure_lf(self) -> None:
        for path in TOUCHED + [WORKFLOW, DOC]:
            data = path.read_bytes()
            self.assertNotIn(b"\r\n", data, f"CRLF in {path}")
            self.assertTrue(data.endswith(b"\n"), f"missing final newline in {path}")


class WorkflowContracts(unittest.TestCase):
    def test_workflow_pins_toolchains_and_service(self) -> None:
        body = text(WORKFLOW)
        self.assertIn("ubuntu-latest", body)
        self.assertIn("postgres:17", body)
        self.assertIn("1.99.1", body)
        self.assertIn("1.101.0", body)
        self.assertIn("64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b", body)

    def test_workflow_runs_the_required_gates(self) -> None:
        body = text(WORKFLOW)
        for command in (
            "cargo fmt --all -- --check",
            "python3 scripts/check_design_docs.py",
            "tests.test_s4_ci_pins_git_view_contracts",
            "tests.test_namespace_online_contracts",
            "tests.test_ci_mirror_ha_contracts",
            "tests.test_ci_cargo_fork_workflows",
            "cargo clippy --locked --all-targets --features pando-lab -- -D warnings",
            "cargo test --locked --lib ci_pins::",
            "cargo test --locked --lib namespace_service::",
            "cargo test --locked --test s4_ci_pins_git_view -- --ignored --test-threads=1",
        ):
            self.assertIn(command, body)
        self.assertNotIn("\t", body)

    def test_workflow_requires_a_database_url(self) -> None:
        self.assertIn("ROOTYARD_TEST_DATABASE_URL", text(WORKFLOW))


class DocumentationContracts(unittest.TestCase):
    def test_doc_uses_refs_only_and_names_the_schema(self) -> None:
        body = text(DOC)
        self.assertIn("Refs #147", body)
        self.assertNotIn("Closes #147", body)
        self.assertNotIn("Fixes #147", body)
        self.assertIn("pg_refstore", body)
        self.assertIn("s4_ci_retention", body)

    def test_doc_describes_one_transaction_and_bounded_revocation(self) -> None:
        body = text(DOC)
        self.assertIn("register_serving_in_tx", body)
        self.assertIn("PgAuthorizedCommit", body)
        self.assertIn("16 KiB", body)
        self.assertIn("revocation", body)
        self.assertNotIn("Known limitations", body)
        self.assertNotIn("501", body)


if __name__ == "__main__":
    unittest.main()
