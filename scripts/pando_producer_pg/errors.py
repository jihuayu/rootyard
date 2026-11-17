"""Fixed, report-safe failures for the producer PostgreSQL runner.

Every failure carries one registered stage and one registered code.  Neither
messages nor exception text are retained, so a DSN, SQL statement, argv,
runtime path, provider body or raw child output cannot reach a report, log or
terminal error line through this type.
"""
from __future__ import annotations

STAGES = frozenset(
    (
        "input",
        "source",
        "selection",
        "setup",
        "execute",
        "binding",
        "report",
        "cleanup",
        "internal",
    )
)

CODES = frozenset(
    (
        "invalid_arguments",
        "missing_expected_commit",
        "missing_report",
        "missing_bootstrap",
        "timeout_invalid",
        "source_root_missing",
        "schema_missing",
        "git_missing",
        "product_receipt_missing",
        "product_receipt_invalid",
        "product_receipt_source_mismatch",
        "product_receipt_artifact_missing",
        "git_unavailable",
        "source_not_clean",
        "commit_mismatch",
        "tree_mismatch",
        "source_capture_failed",
        "source_capture_deadline_exceeded",
        "source_recheck_failed",
        "source_recheck_deadline_exceeded",
        "source_drift",
        "post_case_deadline_exceeded",
        "cargo_failed",
        "cargo_timeout",
        "cargo_output_invalid",
        "selection_deadline_exceeded",
        "selection_rehash_deadline_exceeded",
        "build_not_finished",
        "build_failed",
        "artifact_missing",
        "artifact_ambiguous",
        "artifact_target",
        "artifact_kind",
        "artifact_profile",
        "artifact_executable",
        "artifact_fresh_invalid",
        "artifact_source_missing",
        "artifact_source_outside",
        "escape_variable_present",
        "root_create_failed",
        "postgres_validate_failed",
        "postgres_create_failed",
        "postgres_create_unknown",
        "schema_read_failed",
        "schema_hash_mismatch",
        "schema_init_failed",
        "schema_init_timeout",
        "child_environment_failed",
        "setup_deadline_exceeded",
        "case_timeout",
        "case_spawn_failed",
        "nonzero_exit",
        "zero_tests",
        "summary_missing",
        "summary_mismatch",
        "case_missing",
        "case_mismatch",
        "case_failed",
        "case_ignored",
        "duplicate_case",
        "unexpected_case",
        "output_invalid",
        "not_run",
        "not_run_deadline",
        "binary_changed",
        "binary_unreadable",
        "binary_rehash_deadline_exceeded",
        "binary_recheck_deadline_exceeded",
        "report_write_failed",
        "report_projection_rejected",
        "cleanup_deadline_exceeded",
        "overall_deadline_exceeded",
        "postgres_drop_failed",
        "postgres_drop_unverified",
        "postgres_create_outcome_unknown",
        "root_remove_failed",
        "root_remove_unverified",
        "root_remove_timeout",
        "cleanup_unresolved",
        "process_spawn_failed",
        "process_failed",
        "process_timeout",
        "process_unreaped",
        "process_output_exceeded",
        "internal_error",
    )
)


class RunnerError(RuntimeError):
    """A fail-closed refusal with only a registered stage and code."""

    def __init__(self, stage, code):
        if stage not in STAGES or code not in CODES:
            raise ValueError("unregistered producer PG failure")
        self.stage = stage
        self.code = code
        super().__init__(code)


def require(condition, stage, code):
    if not condition:
        raise RunnerError(stage, code)
