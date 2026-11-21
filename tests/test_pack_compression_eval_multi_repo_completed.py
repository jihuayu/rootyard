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
from pack_compression_eval.pack_matrix import CANDIDATE_CONFIGS  # noqa: E402
from pack_compression_eval.telemetry import percentile_stats  # noqa: E402

SENTINEL = "SENTINEL_SECRET_multi_repo_completed_7d31"
CONFIG = CANDIDATE_CONFIGS[0].name


def raw_group(
    config: str = CONFIG,
    pushes: tuple[object, ...] = (1.0, 2.5, 4.0),
    starts: tuple[object, ...] = (10.0, 11.0, 12.0),
    ends: tuple[object, ...] = (20.0, 21.0, 22.0),
) -> dict:
    return {
        "config_name": config,
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
        "push_ms": [1.0, 2.5, 4.0],
        "client_invocation_start_ms": [10.0, 11.0, 12.0],
        "client_invocation_end_ms": [20.0, 21.0, 22.0],
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
        # Intervals are already origin-relative and must not be rebased again.
        self.assertEqual(record["client_invocation_start_ms"], [10.0, 11.0, 12.0])
        self.assertEqual(record["client_invocation_end_ms"], [20.0, 21.0, 22.0])

    def test_repeat_sanitation_and_failure_normalization_are_idempotent(self) -> None:
        once = sanitize_multi_repo_completed([raw_group()])
        self.assertEqual(sanitize_multi_repo_completed(once), once)
        self.assertEqual(sanitize_multi_repo_completed([raw_group(), raw_group()]), once)
        built = build_failure_record(multi_repo_completed=once)
        self.assertEqual(built["multi_repo_completed"], once)
        enriched = enrich_failure_record(built, phase="multi_repo_verify", failure_class="multi_repo_verify")
        self.assertEqual(enriched["multi_repo_completed"], once)
        with tempfile.TemporaryDirectory(prefix="multi-repo-completed-") as tmp:
            path = write_failure_json(Path(tmp) / "report.failure.json", built)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["multi_repo_completed"], once)

    def test_completed_groups_survive_later_structured_generic_and_cleanup_failure(self) -> None:
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

        with self.assertRaises(LiveEvalFailure) as caught:
            finalize_cleanup(
                None, {"failures": ["server_stop_timeout"], "attempted": True},
                s3=None, completed={"multi_repo_configs_completed": 1},
                last_completed_phase="multi_repo_verify", bindings=None,
                multi_repo_completed=groups,
            )
        self.assertEqual(caught.exception.record["multi_repo_completed"], groups)
        self.assertEqual(caught.exception.record["cleanup"]["failures"], ["server_stop_timeout"])

    def test_malformed_unrecognized_duplicate_and_sentinel_entries_are_dismissed(self) -> None:
        valid = raw_group()
        bad = [
            None,
            {"config_name": SENTINEL, "push_ms": [1, 2, 3]},
            raw_group("baseline"),
            raw_group(CANDIDATE_CONFIGS[1].name, pushes=(1.0, float("inf"), 3.0)),
            raw_group(CANDIDATE_CONFIGS[2].name, pushes=(1.0, -1.0, 3.0)),
            raw_group(CANDIDATE_CONFIGS[3].name, pushes=(1.0, True, 3.0)),
            raw_group(CANDIDATE_CONFIGS[4].name, starts=(0.0, 1.0, 2.0), ends=(0.0, 1.5, 2.5)),
            raw_group(CANDIDATE_CONFIGS[5].name, starts=(0.0, 1.0, 2.0), ends=(1.0, 1.5, 2.5)),
            raw_group(CANDIDATE_CONFIGS[6].name, starts=(0.0, 1.0, float("inf")), ends=(1.0, 2.0, 3.0)),
        ]
        unverified = raw_group(CANDIDATE_CONFIGS[0].name)
        unverified["all_verified"] = False
        bad.append(unverified)
        rejected = raw_group(CANDIDATE_CONFIGS[1].name)
        rejected["push_samples"][1]["push_verified"] = False
        bad.append(rejected)
        s3_bad = raw_group(CANDIDATE_CONFIGS[7].name)
        s3_bad["s3_push"] = {"observed": False, "get_requests": 1, "get_bytes": 1, "put_requests": 1, "put_bytes": 1}
        bad.append(s3_bad)
        for field in ("get_requests", "get_bytes", "put_requests", "put_bytes"):
            mutated = copy.deepcopy(raw_group(CANDIDATE_CONFIGS[0].name))
            mutated["s3_push"][field] = -1
            bad.append(mutated)
            mutated = copy.deepcopy(raw_group(CANDIDATE_CONFIGS[1].name))
            mutated["s3_push"][field] = True
            bad.append(mutated)
        self.assertEqual(sanitize_multi_repo_completed([unverified]), [])
        self.assertEqual(sanitize_multi_repo_completed([rejected]), [])
        records = sanitize_multi_repo_completed([valid, valid, *bad])
        self.assertEqual(records, [projected()])
        encoded = json.dumps(records, sort_keys=True)
        self.assertNotIn(SENTINEL, encoded)
        self.assertNotIn("raw", encoded)

    def test_projection_limit_and_unknown_configs(self) -> None:
        groups = [raw_group(spec.name) for spec in CANDIDATE_CONFIGS[: MULTI_REPO_COMPLETED_LIMIT + 1]]
        records = sanitize_multi_repo_completed(groups)
        self.assertEqual(len(records), MULTI_REPO_COMPLETED_LIMIT)
        self.assertEqual([record["config_name"] for record in records], [spec.name for spec in CANDIDATE_CONFIGS[:MULTI_REPO_COMPLETED_LIMIT]])
        self.assertEqual(sanitize_multi_repo_completed([raw_group("baseline")]), [])
        self.assertEqual(sanitize_multi_repo_completed("not-a-list"), [])


if __name__ == "__main__":
    unittest.main()
