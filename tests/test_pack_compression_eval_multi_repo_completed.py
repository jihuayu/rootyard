#!/usr/bin/env python3
"""Hermetic tests for completed multi-repository failure projections (Refs #178)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pack_compression_eval.failure_diagnostics import (  # noqa: E402
    LiveEvalFailure,
    build_failure_record,
    enrich_failure_record,
    failure_record_from_exception,
    finalize_cleanup,
    write_failure_json,
)
from pack_compression_eval.multi_repo_diagnostics import (  # noqa: E402
    MULTI_REPO_COMPLETED_LIMIT,
    sanitize_multi_repo_completed,
    sanitize_multi_repo_group,
)
from pack_compression_eval.pack_matrix import CANDIDATE_CONFIGS, LIVE_COMPARISON_CONFIG_NAMES  # noqa: E402
from pack_compression_eval.telemetry import percentile_stats  # noqa: E402

SENTINEL = "SENTINEL_SECRET_multi_repo_completed_7d31"
CONFIG = CANDIDATE_CONFIGS[0].name


def raw_group(
    config: str = CONFIG,
    pushes: tuple[object, ...] = (1.0, 2.5, 4.0),
    starts: tuple[object, ...] = (0.0, 1.0, 2.0),
    ends: tuple[object, ...] = (10.0, 11.0, 12.0),
) -> dict:
    return {
        "config_name": config,
        "all_verified": True,
        "verified_samples": 3,
        "first_attempt_only": True,
        "repository_ids": [f"{SENTINEL}-{ordinal}" for ordinal in range(3)],
        "clone_paths": [f"/{SENTINEL}/clone-{ordinal}" for ordinal in range(3)],
        "push_samples": [
            {
                "repo_ordinal": ordinal,
                "repository_id": f"{SENTINEL}-{ordinal}",
                "clone_path": f"/{SENTINEL}/clone-{ordinal}",
                "push_oid": SENTINEL,
                "push_ms": pushes[ordinal],
                "client_invocation_start_ms": starts[ordinal],
                "client_invocation_end_ms": ends[ordinal],
                "push_verified": True,
                "first_attempt": True,
                "retry_count": 0,
                "environment": SENTINEL,
                "raw_git": SENTINEL,
                "payload": SENTINEL,
            }
            for ordinal in range(3)
        ],
        "s3_push": {
            "observed": True,
            "get_requests": 2,
            "get_bytes": 20,
            "put_requests": 3,
            "put_bytes": 30,
            "status_counts": {SENTINEL: 9},
            "raw": SENTINEL,
        },
    }


def projected(config: str = CONFIG) -> dict:
    return {
        "config_name": config,
        "all_verified": True,
        "verified_samples": 3,
        "first_attempt_only": True,
        "push_ms": [1.0, 2.5, 4.0],
        "client_invocation_start_ms": [0.0, 1.0, 2.0],
        "client_invocation_end_ms": [10.0, 11.0, 12.0],
        "push_stats": percentile_stats([1.0, 2.5, 4.0]),
        "client_invocation_overlap": {
            "scope": "client_invocations_only",
            "all_overlap": True,
            "overlap_ms": 8.0,
            "server_internal_overlap_claimed": False,
        },
        "s3_push": {
            "observed": True,
            "get_requests": 2,
            "get_bytes": 20,
            "put_requests": 3,
            "put_bytes": 30,
        },
    }


class MultiRepoCompletedProjectionTest(unittest.TestCase):
    def test_verified_group_keeps_only_bounded_measurements(self) -> None:
        record = sanitize_multi_repo_group(raw_group())
        self.assertEqual(record, projected())
        self.assertEqual(sanitize_multi_repo_completed([raw_group()]), [projected()])
        encoded = json.dumps(record, sort_keys=True)
        self.assertNotIn(SENTINEL, encoded)
        for field in ("repository_id", "clone_path", "push_oid", "push_samples", "status_counts", "environment", "raw_git", "payload"):
            self.assertNotIn(field, encoded)
        self.assertEqual(record["client_invocation_start_ms"], [0.0, 1.0, 2.0])
        self.assertEqual(record["client_invocation_end_ms"], [10.0, 11.0, 12.0])

    def test_repeat_sanitation_and_failure_normalization_are_idempotent(self) -> None:
        once = sanitize_multi_repo_completed([raw_group()])
        self.assertEqual(sanitize_multi_repo_completed(once), once)
        self.assertEqual(sanitize_multi_repo_completed([raw_group(), raw_group()]), once)
        for field, bad in (
            ("all_verified", False),
            ("verified_samples", True),
            ("first_attempt_only", False),
        ):
            broken = copy.deepcopy(once)
            broken[0][field] = bad
            self.assertEqual(sanitize_multi_repo_completed(broken), [])
        for field in ("all_verified", "verified_samples", "first_attempt_only"):
            broken = copy.deepcopy(once)
            broken[0].pop(field)
            self.assertEqual(sanitize_multi_repo_completed(broken), [])
        built = build_failure_record(multi_repo_completed=once)
        self.assertEqual(built["multi_repo_completed"], once)
        enriched = enrich_failure_record(built, phase="multi_repo_verify", failure_class="multi_repo_verify")
        self.assertEqual(enriched["multi_repo_completed"], once)

    def test_source_held_first_error_survives_and_writes_safely(self) -> None:
        groups = sanitize_multi_repo_completed([raw_group()])
        earlier = LiveEvalFailure(
            build_failure_record(
                phase="multi_repo_first_push", failure_class="git_push",
                bindings={"binary_sha256": "a" * 64}, multi_repo_completed=groups,
            )
        )
        normalized = failure_record_from_exception(
            earlier, mode="full", scale="quick", seed=178,
            source_meta={"source_commit": "b" * 40, "source_dirty": False},
        )
        self.assertEqual(normalized["multi_repo_completed"], groups)
        self.assertEqual(normalized["bindings"]["binary_sha256"], "a" * 64)
        self.assertEqual(normalized["bindings"]["source_commit_at_failure"], "b" * 40)

        late = enrich_failure_record(
            earlier.record, phase="candidate_push", failure_class="git_push",
            cleanup={"failures": ["server_stop_timeout"], "attempted": True},
        )
        self.assertEqual(late["multi_repo_completed"], groups)
        self.assertEqual(late["cleanup"]["failures"], ["server_stop_timeout"])
        with tempfile.TemporaryDirectory(prefix="multi-repo-completed-") as tmp:
            path = write_failure_json(Path(tmp) / "report.failure.json", earlier.record)
            written = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(written["multi_repo_completed"], groups)
            self.assertEqual(written["phase"], "multi_repo_first_push")
            self.assertNotIn(SENTINEL, path.read_text(encoding="utf-8"))

        with self.assertRaises(LiveEvalFailure) as caught:
            finalize_cleanup(
                None, {"failures": ["server_stop_timeout"], "attempted": True},
                s3=None, completed={"multi_repo_configs_completed": 1},
                last_completed_phase="multi_repo_verify", bindings=None,
                multi_repo_completed=groups,
            )
        self.assertEqual(caught.exception.record["multi_repo_completed"], groups)
        self.assertEqual(caught.exception.record["cleanup"]["failures"], ["server_stop_timeout"])

    def test_malformed_missing_untyped_oversized_and_sentinel_entries_are_dismissed(self) -> None:
        bad: list[object] = [
            None,
            "not-a-mapping",
            {"config_name": SENTINEL, "push_ms": [1, 2, 3]},
            raw_group("baseline"),
        ]
        for field in ("all_verified", "verified_samples"):
            missing = raw_group()
            missing.pop(field)
            bad.append(missing)
        for field, value in (
            ("all_verified", 1), ("all_verified", False), ("verified_samples", True),
            ("verified_samples", 4), ("first_attempt_only", 1), ("first_attempt_only", False),
        ):
            variant = raw_group()
            variant[field] = value
            bad.append(variant)
        for field in ("push_verified", "first_attempt", "retry_count"):
            missing = raw_group()
            missing["push_samples"][0].pop(field)
            bad.append(missing)
            for value in (1, False):
                variant = raw_group()
                variant["push_samples"][0][field] = value
                bad.append(variant)
        for value in (0.0, "0"):
            variant = raw_group()
            variant["push_samples"][0]["retry_count"] = value
            bad.append(variant)
        bad.extend(
            (
                raw_group(starts=(1.0, 2.0, 3.0)),
                raw_group(starts=(-1.0, 0.0, 1.0)),
                raw_group(starts=(0.0, 1.0, 1e308)),
                raw_group(ends=(0.0, 1.0, 2.0)),
                raw_group(ends=(1e308, 1.0, 2.0)),
                raw_group(pushes=(1e308, 2.5, 4.0)),
                raw_group(pushes=(1.0, float("inf"), 4.0)),
                raw_group(starts=(0.0, 5.0, 6.0), ends=(1.0, 2.0, 3.0)),
                raw_group(starts=(0.0, 1.0, 2.0), ends=(1.0, 1.5, 2.5)),
            )
        )
        unverified = raw_group()
        unverified["all_verified"] = False
        bad.append(unverified)
        for field in ("get_requests", "get_bytes", "put_requests", "put_bytes"):
            for value in (-1, True, 1.0, 1 << 63, 1 << 100):
                variant = raw_group()
                variant["s3_push"][field] = value
                bad.append(variant)
            missing = raw_group()
            missing["s3_push"].pop(field)
            bad.append(missing)
        for observed in (False, None):
            variant = raw_group()
            variant["s3_push"]["observed"] = observed
            bad.append(variant)
        for item in bad:
            with self.subTest(item=item):
                self.assertEqual(sanitize_multi_repo_completed([item]), [])
        records = sanitize_multi_repo_completed([raw_group(), raw_group(), *bad])
        self.assertEqual(records, [projected()])
        encoded = json.dumps(records, sort_keys=True)
        self.assertNotIn(SENTINEL, encoded)
        self.assertNotIn("raw", encoded)

    def test_projection_binds_to_live_cohort_and_limit(self) -> None:
        groups = [raw_group(name) for name in LIVE_COMPARISON_CONFIG_NAMES]
        records = sanitize_multi_repo_completed(groups)
        self.assertEqual(len(records), 4)
        self.assertEqual(len(records), MULTI_REPO_COMPLETED_LIMIT)
        self.assertEqual([record["config_name"] for record in records], list(LIVE_COMPARISON_CONFIG_NAMES))
        offline = next(spec.name for spec in CANDIDATE_CONFIGS if spec.name not in LIVE_COMPARISON_CONFIG_NAMES)
        self.assertEqual(sanitize_multi_repo_completed([raw_group(offline)]), [])
        self.assertEqual(sanitize_multi_repo_completed([raw_group("baseline")]), [])
        self.assertEqual(sanitize_multi_repo_completed("not-a-list"), [])


if __name__ == "__main__":
    unittest.main()
