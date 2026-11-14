#!/usr/bin/env python3
"""Private-owner Pull Request, Review, Check Run, Branch Rule, and Atomic Merge contract."""
import argparse
import concurrent.futures
import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import traceback
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from forge import ForgeHarness  # noqa: E402
from schema_baseline import SCHEMA_VERSION_CSV, SCHEMA_VERSIONS  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]

# `forge_check_runs` contract fields returned by the checks API (`CHECK_FIELDS`
# in `src/pulls/models.rs`). Rows this harness writes must not move at all.
CHECK_ROW_FIELDS = (
    "repository_id",
    "commit_oid",
    "context",
    "attempt",
    "sequence",
    "status",
    "conclusion",
    "output",
    "created_at",
    "updated_at",
)
# Only the always-on pull synchronizer writes `ci/default`
# (`src/webhooks/delivery.rs`); `ci/test` and `ci/lint` are harness-written here.
AUTOMATIC_CHECK_CONTEXT = "ci/default"
MANUAL_CHECK_CONTEXTS = frozenset({"ci/lint", "ci/test"})
AUTOMATIC_CHECK_OUTPUT = "queued by pull request synchronization"
AUTOMATIC_CONFIG_SHA256 = hashlib.sha256(
    b"rootyard-ci-config-v1\0ci/default"
).hexdigest()
CHECK_STATUSES = frozenset({"queued", "in_progress", "completed"})
CHECK_CONCLUSIONS = frozenset(
    {"success", "failure", "neutral", "cancelled", "timed_out", "skipped"}
)
CHECK_DIAGNOSTIC_LIMIT = 8
# The only 409 errors `upsert_check_inner` in `src/pulls/checks.rs` raises when
# the row's `(attempt, sequence)` changed after the caller's read. Either one is
# retried by `advance_check` against a re-read row; every other 409 is fatal.
ADVANCE_CHECK_CAS_CONFLICTS = frozenset(
    {
        "conflicting check run state for same attempt and sequence",
        "stale check run attempt or sequence",
    }
)
ADVANCE_CHECK_MAX_CONFLICTS = 5
ADVANCE_CHECK_DEADLINE_SECONDS = 5.0


def migration_009_path() -> Path:
    promoted = ROOT / "migrations/009_forge_pulls.sql"
    if promoted.is_file():
        return promoted
    return ROOT / "src/pulls/009_forge_pulls.sql"


class PullsHarness(ForgeHarness):
    def case(self, name, fn):
        """Run one case, keeping a redacted traceback as failure evidence.

        A bare ``assert x == y`` raises ``AssertionError`` with an empty message,
        so recording only ``str(error)`` leaves a CI report that cannot name the
        failing statement. The traceback stays fully redacted: harness secrets and
        database URLs are substituted, and no environment is dumped.
        """
        started = time.monotonic()
        try:
            detail = fn()
        except Exception as error:
            self.results.append(
                dict(
                    name=name,
                    status="failed",
                    seconds=round(time.monotonic() - started, 4),
                    error=self.redact(error),
                    traceback=self.redact(traceback.format_exc()),
                )
            )
            print(
                f"{name}: failed\n{self.redact(traceback.format_exc())}",
                file=sys.stderr,
                flush=True,
            )
            raise
        self.results.append(
            dict(
                name=name,
                status="passed",
                seconds=round(time.monotonic() - started, 4),
                detail=detail,
            )
        )
        print(name + ": passed", flush=True)

    def issue_token(
        self, username: str, create_user: bool = False, read_only: bool = False
    ) -> dict:
        if create_user:
            res = self.account("create-user", username)
            if not read_only:
                return res
        cmd = ["create-token", username]
        if read_only:
            cmd.append("--read-only")
        return self.account(*cmd)

    def document(
        self, path, code=200, token=None, json_body=None, headers=None, **kwargs
    ):
        if json_body is not None:
            kwargs["body"] = json_body
        if headers is not None:
            kwargs["extra_headers"] = headers
        status, body, resp_headers = self.http(path, token=token or self.alice, **kwargs)
        norm_headers = {k.lower(): v for k, v in resp_headers.items()}
        expected = code if isinstance(code, tuple) else (code,)
        assert status in expected, f"{path}: expected {code}, got {status}: {body[:200]!r}"
        assert norm_headers.get("cache-control") == "no-store", norm_headers
        assert "application/json" in norm_headers.get("content-type", ""), norm_headers
        return json.loads(body)

    def json_exchange(self, path, code, **kwargs):
        """Return `(status, body, headers)` without raising when `code` is unexpected.

        `document` assert-fails on the first unexpected status, which hides the
        error body needed to decide whether it is retryable. `(status, headers,
        body)` is checked here exactly as `document` checks it, so no-store and
        JSON are still required on every response.
        """
        status, body, resp_headers = self.http(path, **kwargs)
        norm_headers = {k.lower(): v for k, v in resp_headers.items()}
        expected = code if isinstance(code, tuple) else (code,)
        assert status in expected, f"{path}: expected {code}, got {status}: {body[:200]!r}"
        assert norm_headers.get("cache-control") == "no-store", norm_headers
        assert "application/json" in norm_headers.get("content-type", ""), norm_headers
        return status, body, norm_headers

    def check_contexts(self, items: list) -> list:
        """Assert the check contexts recorded for one commit.

        Always-on work legitimately queues the documented `ci/default`
        placeholder for an open pull whose base ref has no branch rule yet, and
        whether that row exists at this instant is a real timing race. Contexts
        are globally sorted and unique, so the two contexts this test drives must
        appear exactly once each, any `ci/default` row must be exactly the
        service's queued placeholder, and every other context is a failure.
        """
        contexts = [item["context"] for item in items]
        assert contexts == sorted(set(contexts)), contexts
        assert contexts.count("ci/test") == 1, contexts
        assert contexts.count("ci/lint") == 1, contexts
        assert contexts in (
            ["ci/lint", "ci/test"],
            ["ci/default", "ci/lint", "ci/test"],
        ), contexts
        for item in items:
            if item["context"] == "ci/default":
                assert item["status"] == "queued", item
                assert item["attempt"] == 1 and item["sequence"] == 1, item
                assert item["conclusion"] is None, item
                assert item["output"] == "queued by pull request synchronization", item
        return contexts

    def split_check_rows(self, document: dict) -> tuple:
        """Partition one `/checks` payload into manual and automatic rows.

        Returns `(manual, automatic)`: `manual` maps context to the full API row
        for the contexts this harness writes itself, and `automatic` is the
        scheduler-owned `ci/default` row or `None`. Duplicate or unknown
        contexts fail, and every item must be accounted for exactly once, so a
        restart comparison cannot silently drop a row.
        """
        manual, automatic = {}, None
        for item in document["items"]:
            context = item["context"]
            if context == AUTOMATIC_CHECK_CONTEXT:
                assert automatic is None, self.redact(item)
                automatic = item
                continue
            assert context in MANUAL_CHECK_CONTEXTS, self.redact(item)
            assert context not in manual, self.redact(item)
            manual[context] = item
        assert len(document["items"]) == len(manual) + (automatic is not None), (
            self.redact(document["items"])
        )
        return manual, automatic

    def check_row_diff(self, manual_before: dict, manual_after: dict) -> str:
        """Render a bounded, redacted per-field diff of two check-row maps."""
        lines = []
        for context in sorted(set(manual_before) | set(manual_after)):
            left, right = manual_before.get(context), manual_after.get(context)
            if left == right:
                continue
            if left is None or right is None:
                label = "added" if left is None else "removed"
                lines.append(f"{context}: {label} {right or left}")
                continue
            for field in CHECK_ROW_FIELDS:
                if left.get(field) != right.get(field):
                    lines.append(
                        f"{context}.{field}: {left.get(field)!r} -> {right.get(field)!r}"
                    )
        if not lines:
            lines.append("no field differences")
        return self.redact(
            "check rows changed across restart (bounded to "
            f"{CHECK_DIAGNOSTIC_LIMIT} entries): " + "; ".join(
                lines[:CHECK_DIAGNOSTIC_LIMIT]
            )
        )

    def automatic_check_binding(self, repository_id: str, head_oid: str) -> dict:
        """Read durable scheduler records for one commit's `ci/default` row.

        `src/webhooks/delivery.rs` queues the placeholder together with a
        `ci_runs` job and a `ci_pull_sync_progress` marker for one
        `(pull, version, head, base, storage_generation)`, so a job joined to a
        completed marker for that same tuple is durable evidence that the
        automatic synchronizer orchestrated this commit and context. It is
        supporting evidence, not an authenticity proof: matching recorded rows
        cannot by themselves exclude another writer. The marker is a GC root
        (`src/storage_lifecycle/retention.rs`), so no pruning is expected; a
        future retention policy that pruned it would leave only the `ci_runs`
        rows, which still bind commit, context and job identity.
        """
        digest_filter = (
            f"count(*) FILTER (WHERE r.config_sha256 = '{AUTOMATIC_CONFIG_SHA256}')"
        )
        rows = self.sql(
            "SELECT count(*)::text || ':' || "
            + digest_filter
            + "::text || ':' || count(DISTINCT r.job_id)::text || ':' || "
            + "count(*) FILTER (WHERE c.ci_run_id = r.id)::text || ':' || "
            + "count(DISTINCT c.ci_run_id)::text "
            + "FROM ci_runs r JOIN ci_pull_sync_progress s "
            + "ON s.repository_id = r.repository_id AND s.pull_number = r.pull_number "
            + "AND s.pull_version = r.pull_version AND s.head_oid = r.head_oid "
            + "AND s.base_oid = r.base_oid "
            + "AND s.storage_generation = r.storage_generation "
            + "JOIN forge_check_runs c ON c.repository_id = r.repository_id "
            + "AND c.commit_oid = r.head_oid AND c.context = r.context "
            + f"WHERE r.repository_id='{repository_id}' "
            + f"AND r.context='{AUTOMATIC_CHECK_CONTEXT}' AND r.head_oid='{head_oid}' "
            + f"AND c.commit_oid='{head_oid}' "
            + f"AND c.context='{AUTOMATIC_CHECK_CONTEXT}'"
        ).split(":")
        return dict(
            synced_jobs=int(rows[0]),
            matching_config=int(rows[1]),
            jobs=int(rows[2]),
            direct_links=int(rows[3]),
            linked_ids=int(rows[4]),
        )

    def assert_automatic_check_row(
        self, row: dict, repository_id: str, head_oid: str
    ) -> None:
        """Validate one scheduler-owned `ci/default` row against outer identity.

        Identity is taken from the enclosing document and its manual rows, never
        from this row's own fields, so a row bound to another repository, commit
        or context fails even when it first appears only after the restart. The
        finite status/conclusion vocabulary and positive `(attempt, sequence)`
        counters hold for every attempt; the exact initial placeholder form is
        required only for the `(1, 1) queued` row `delivery.rs` inserts.
        """
        diff = self.redact(row)
        assert row["context"] == AUTOMATIC_CHECK_CONTEXT, diff
        assert row["repository_id"] == repository_id, diff
        assert row["commit_oid"] == head_oid, diff
        assert row["status"] in CHECK_STATUSES, diff
        assert isinstance(row["attempt"], int) and row["attempt"] >= 1, diff
        assert isinstance(row["sequence"], int) and row["sequence"] >= 1, diff
        assert isinstance(row["output"], str), diff
        if row["status"] == "completed":
            assert row["conclusion"] in CHECK_CONCLUSIONS, diff
        else:
            assert row["conclusion"] is None, diff
        if (row["attempt"], row["sequence"]) == (1, 1) and row["status"] == "queued":
            assert row["output"] == AUTOMATIC_CHECK_OUTPUT, diff

    def assert_automatic_check_advance(self, before: dict, after: dict) -> None:
        """Bound a change to the same `ci/default` row across the restart.

        `upsert_callback_check_run` (`src/webhooks/signing.rs`) accepts a write
        only when `(attempt, sequence)` moves forward, and a newer `attempt`
        starts a fresh status lifecycle for that same row: `completed` on
        attempt 1 may legitimately become `queued`/`in_progress` on attempt 2.
        The API also permits another status with a later sequence in the same
        attempt; it does not enforce a status ladder. The finite vocabulary
        and positive counters are checked for every row by
        `assert_automatic_check_row`. When `(attempt, sequence)` did not move the
        row must be byte-identical (no silent rewrite).
        """
        diff = self.check_row_diff(
            {AUTOMATIC_CHECK_CONTEXT: before}, {AUTOMATIC_CHECK_CONTEXT: after}
        )
        assert after["created_at"] == before["created_at"], diff
        assert (after["attempt"], after["sequence"]) >= (
            before["attempt"],
            before["sequence"],
        ), diff
        if after["attempt"] == before["attempt"]:
            assert after["sequence"] >= before["sequence"], diff
        else:
            assert after["attempt"] > before["attempt"], diff
        if (after["attempt"], after["sequence"]) == (
            before["attempt"],
            before["sequence"],
        ):
            assert after == before, diff

    def assert_checks_survive_restart(self, before: dict, after: dict) -> tuple:
        """Assert the pull checklist survives a hard restart with its contract.

        Every `ci/test`/`ci/lint` row this harness wrote must be byte-identical,
        including `created_at`/`updated_at`, and must not appear or disappear.

        The only tolerated change is the scheduler-owned `ci/default` row, which
        the always-on pull synchronizer may queue for the pull's head while the
        process is down or restarting (`ON CONFLICT DO NOTHING`, so it can also
        arrive late for a commit other open pulls share). That allowance is
        bounded: each present row is validated against the head/repository of
        this document, keeps the immutable commit/context identity and positive
        counters, stays inside the finite status/conclusion vocabulary, and is
        backed by a durable `ci_runs` job joined to a `ci_pull_sync_progress`
        marker for that same pull version, head, base and storage generation.
        """
        assert after["pull_number"] == before["pull_number"], (
            before["pull_number"],
            after["pull_number"],
        )
        assert after["head_oid"] == before["head_oid"], (
            before["head_oid"],
            after["head_oid"],
        )
        assert after["next_after"] == before["next_after"], (
            before["next_after"],
            after["next_after"],
        )
        manual_before, automatic_before = self.split_check_rows(before)
        manual_after, automatic_after = self.split_check_rows(after)
        diff = self.check_row_diff(manual_before, manual_after)
        assert set(manual_after) == set(manual_before), diff
        assert set(manual_before) == set(MANUAL_CHECK_CONTEXTS), diff
        for context in sorted(manual_before):
            assert manual_after[context] == manual_before[context], diff
        repository_id = manual_before["ci/test"]["repository_id"]
        for row in (automatic_before, automatic_after):
            if row is not None:
                self.assert_automatic_check_row(row, repository_id, before["head_oid"])
        if automatic_before is not None:
            # No write path deletes a check row, so a present automatic row may
            # advance but must never vanish across the restart.
            assert automatic_after is not None, self.check_row_diff(
                {AUTOMATIC_CHECK_CONTEXT: automatic_before}, {}
            )
            self.assert_automatic_check_advance(automatic_before, automatic_after)
        if automatic_before is not None or automatic_after is not None:
            binding = self.automatic_check_binding(repository_id, before["head_oid"])
            assert binding["synced_jobs"] >= 1, binding
            assert binding["matching_config"] >= 1, binding
            assert binding["jobs"] >= 1, binding
            if binding["linked_ids"]:
                assert binding["direct_links"] >= 1, binding
        return manual_after, automatic_after or automatic_before

    def restart_check_contract_selftest(self) -> None:
        """Prove the restart validators reject regressions and allow a retry.

        Synthetic rows only, no server or database: a legitimate retry on a
        newer attempt or sequence must pass, while a foreign identity or a
        rewritten row with unchanged counters must fail. This pins the two
        restart bugs as fixed behaviour rather than
        mirroring the implementation in the acceptance path.
        """
        repository_id, head = self.repo["id"], "0" * 40
        base = {
            "repository_id": repository_id,
            "commit_oid": head,
            "context": AUTOMATIC_CHECK_CONTEXT,
            "attempt": 1,
            "sequence": 2,
            "status": "completed",
            "conclusion": "success",
            "output": "scripts passed",
            "created_at": "2026-01-01 00:00:00+00",
            "updated_at": "2026-01-01 00:00:01+00",
        }
        retry = {
            **base,
            "attempt": 2,
            "sequence": 1,
            "status": "queued",
            "conclusion": None,
            "output": "retry queued",
            "updated_at": "2026-01-01 00:00:02+00",
        }
        self.assert_automatic_check_row(base, repository_id, head)
        self.assert_automatic_check_row(retry, repository_id, head)
        self.assert_automatic_check_advance(base, retry)  # newer attempt, fresh lifecycle
        sequenced = {**base, "sequence": 3, "status": "in_progress", "conclusion": None}
        self.assert_automatic_check_row(sequenced, repository_id, head)
        self.assert_automatic_check_advance(base, sequenced)
        rejected = (
            ({**base, "repository_id": str(uuid.uuid4())}, "foreign repository"),
            ({**base, "commit_oid": "f" * 40}, "foreign commit"),
            ({**base, "context": "ci/other"}, "foreign context"),
            ({**base, "conclusion": None}, "completed without conclusion"),
            ({**base, "status": "bogus"}, "unknown status"),
            ({**base, "attempt": 0}, "non-positive attempt"),
            (
                {**retry, "attempt": 1, "sequence": 1, "output": "forged queue"},
                "non-placeholder initial queue",
            ),
        )
        for row, label in rejected:
            try:
                self.assert_automatic_check_row(row, repository_id, head)
            except AssertionError:
                continue
            raise AssertionError(
                f"automatic check validator accepted a {label}: {self.redact(row)}"
            )
        # Changing status without advancing the counters is still a rewrite.
        regressed = {**base, "status": "in_progress", "conclusion": None}
        try:
            self.assert_automatic_check_advance(base, regressed)
        except AssertionError:
            pass
        else:
            raise AssertionError("an unsequenced status rewrite was accepted")
        rewritten = {**base, "output": "rewritten", "updated_at": "2026-01-01 00:00:03+00"}
        try:
            self.assert_automatic_check_advance(base, rewritten)
        except AssertionError:
            pass
        else:
            raise AssertionError("a rewritten scheduler row was accepted")
        manual = {
            "ci/lint": {"context": "ci/lint", "status": "completed"},
            "ci/test": {"context": "ci/test", "status": "completed"},
        }
        leaked = self.check_row_diff(manual, {"ci/lint": manual["ci/lint"]})
        assert "ci/test: removed" in leaked, leaked
        assert "ci/other: added" in self.check_row_diff(
            manual, {**manual, "ci/other": {"context": "ci/other"}}
        )
        try:
            self.split_check_rows(
                {"items": [base, {"context": "ci/other", "status": "completed"}]}
            )
        except AssertionError:
            pass
        else:
            raise AssertionError("an unknown check context was accepted")

    def merge_version(self) -> int:
        """Fence a mutation with the version the API currently reports."""
        return self.document(self.pr1_path)["version"]

    def sync_pull_head(self, pre_push: dict, head_oid: str) -> dict:
        """Record a real Git push on PR #1, accepting whichever writer wins.

        The push is the truth the service must observe; both the explicit CAS
        PATCH and the always-on background ref synchronizer may record it. A 409
        is accepted only for the exact version observed before the push, and only
        after a fresh GET proves the pushed head, the unchanged base and a
        strictly monotonic version. Any other status still fails, so this is a
        contract check rather than a blind retry.
        """
        current = self.document(self.pr1_path)
        if current["head_oid"] != head_oid:
            status, body, headers = self.http(
                self.pr1_path,
                token=self.alice,
                method="PATCH",
                body={"expected_version": pre_push["version"], "head_oid": head_oid},
            )
            if status == 200:
                norm = {k.lower(): v for k, v in headers.items()}
                assert norm.get("cache-control") == "no-store", norm
                assert "application/json" in norm.get("content-type", ""), norm
                patched = json.loads(body)
                assert patched["head_oid"] == head_oid, patched["head_oid"]
                assert patched["base_oid"] == pre_push["base_oid"], patched["base_oid"]
                assert patched["version"] == pre_push["version"] + 1, patched["version"]
            else:
                # Only losing the CAS to the background synchronizer is valid.
                assert status == 409, (status, body[:200])
        synced = self.document(self.pr1_path)
        assert synced["head_oid"] == head_oid, synced["head_oid"]
        assert synced["base_oid"] == pre_push["base_oid"], synced["base_oid"]
        assert synced["version"] > pre_push["version"], synced["version"]
        # Whichever writer won, the pre-push version is stale for every writer.
        self.document(
            self.pr1_path,
            409,
            method="PATCH",
            body={"expected_version": pre_push["version"], "title": "Stale after head sync"},
        )
        return synced

    def listed_check_row(self, commit_oid: str, context: str):
        """Return the exact row `/commits/{oid}/checks` lists for one context.

        The listing is fenced on `commit_oid` and must contain the context at
        most once; any other shape is a contract failure, not a retry signal.
        """
        path = f"/api/repos/alice/forge/commits/{commit_oid}/checks"
        listed = self.document(path, token=self.reader)
        assert listed.get("commit_oid") == commit_oid, listed
        items = listed.get("items")
        assert isinstance(items, list), listed
        matches = [item for item in items if item["context"] == context]
        assert len(matches) <= 1, (commit_oid, context, items)
        return matches[0] if matches else None

    def advance_check(
        self,
        commit_oid: str,
        context: str,
        status: str,
        conclusion,
        output,
        *,
        max_conflicts: int = ADVANCE_CHECK_MAX_CONFLICTS,
        deadline_seconds: float = ADVANCE_CHECK_DEADLINE_SECONDS,
    ) -> dict:
        """Advance one check run from the state the service currently records.

        A branch rule exists for the base ref now, so the synchronizer may already
        have queued `(attempt 1, sequence 1)` for this context on the freshly
        synchronized head. Ordering is server-validated on `(attempt, sequence)`,
        so the next transition is derived from the observed row instead of a
        hardcoded sequence that would collide with the service's placeholder.

        The GET and the POST are not one transaction: the always-on pull-ref
        synchronizer can insert or advance the row in between, and the write then
        answers 409 `conflicting check run state for same attempt and sequence`
        (or `stale check run attempt or sequence`). Only those exact CAS conflicts
        retry, bounded by `max_conflicts` attempts and a monotonic deadline; each
        one re-reads the same commit/context and asks for a strictly greater
        `(1, sequence)`, so an already completed success is never accepted as the
        requested failure. Any other status, error, malformed body, wrong commit,
        context or attempt fails immediately.
        """
        path = f"/api/repos/alice/forge/commits/{commit_oid}/checks"
        attempt = 1
        floor = 0
        started = time.monotonic()
        conflicts = 0
        while True:
            existing = self.listed_check_row(commit_oid, context)
            if existing is not None:
                assert isinstance(existing.get("attempt"), int), existing
                assert existing["attempt"] == attempt, (
                    f"{context} on {commit_oid}: expected attempt {attempt}, "
                    f"observed attempt {existing['attempt']}: {existing}"
                )
                assert isinstance(existing.get("sequence"), int), existing
                floor = max(floor, existing["sequence"])
            sequence = floor + 1
            status_code, body, _headers = self.json_exchange(
                path,
                (200, 201, 409),
                token=self.alice,
                method="POST",
                body={
                    "context": context,
                    "status": status,
                    "conclusion": conclusion,
                    "output": output,
                    "attempt": attempt,
                    "sequence": sequence,
                },
            )
            if status_code in (200, 201):
                run = json.loads(body)
                assert run.get("commit_oid") == commit_oid, run
                assert run["context"] == context and run["status"] == status, run
                assert run["conclusion"] == conclusion and run["attempt"] == attempt, run
                assert run["output"] == output, run
                assert run["sequence"] == sequence, run
                return run
            error = json.loads(body)
            assert isinstance(error, dict), error
            assert error.get("error") in ADVANCE_CHECK_CAS_CONFLICTS, (
                f"{path}: expected an exact check CAS 409, got {error}"
            )
            conflicts += 1
            if conflicts >= max_conflicts:
                raise AssertionError(
                    f"{path}: {context} at sequence > {floor} still conflicted after "
                    f"{conflicts} attempts with {error['error']!r}"
                )
            remaining = deadline_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise AssertionError(
                    f"{path}: {context} check CAS conflicts persisted past the "
                    f"{deadline_seconds}s deadline ({conflicts} attempts, "
                    f"last {error['error']!r})"
                )
            time.sleep(min(0.05, remaining))

    @contextlib.contextmanager
    def held_advisory_barrier(self, key: int):
        """Hold one transaction-scoped advisory lock in an owned psql session.

        The fixture session owns the only release point for
        ``pg_advisory_xact_lock(key)``. Release is bounded: it COMMITs and reaps
        psql, or terminates the owned backend and kills psql. If a race
        assertion fails first, the context manager still releases the lock so a
        parked service COMMIT cannot outlive this case or block later cases.
        """
        # Tag this fixture so the service-backend pollers cannot mistake it for
        # the real creator. Read the pipe as bytes: a text wrapper can pull a
        # second marker line out of the fd, making select() wait on an empty
        # kernel buffer even though the PID is already buffered in Python.
        env = {**self.env, "PGAPPNAME": "rootyard-fixture-barrier"}
        proc = subprocess.Popen(
            ["psql", "--dbname", self.db, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        pid = None
        released = False
        pending = b""

        def backend_gone() -> bool:
            if pid is None:
                return True
            try:
                return self.sql(
                    "SELECT count(*) FROM pg_stat_activity "
                    f"WHERE pid={pid} "
                    "AND application_name='rootyard-fixture-barrier'"
                ) == "0"
            except Exception:
                return False

        def await_backend_exit(seconds: float) -> bool:
            deadline = time.monotonic() + seconds
            while True:
                if backend_gone():
                    return True
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.005)

        try:
            proc.stdin.write(
                f"BEGIN; SELECT 'barrier_ready', pg_advisory_xact_lock({key}); "
                "SELECT 'ready|' || pg_backend_pid();\n".encode()
            )
            proc.stdin.flush()
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and pid is None:
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if line.strip().startswith(b"ready|"):
                        pid = int(line.strip().split(b"|", 1)[1])
                        break
                if pid is not None:
                    break
                if proc.poll() is not None:
                    break
                ready, _, _ = select.select(
                    [proc.stdout], [], [], max(0.0, deadline - time.monotonic())
                )
                if not ready:
                    break
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                pending += chunk
            assert pid is not None, "fixture advisory barrier did not become ready"

            def release():
                nonlocal released
                if released:
                    return
                if proc.poll() is None:
                    try:
                        proc.stdin.write(b"COMMIT;\n\\q\n")
                        proc.stdin.flush()
                        proc.wait(timeout=5)
                    except Exception:
                        pass
                if proc.poll() is not None:
                    # psql exit closes the session and releases the xact lock.
                    released = True
                    assert proc.returncode == 0, "fixture advisory barrier COMMIT failed"
                    return
                # Guaranteed release: terminate the backend, which drops the
                # transaction-level advisory lock even if psql is wedged.
                try:
                    self.sql(f"SELECT pg_terminate_backend({pid})")
                except Exception:
                    pass
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.stdin.close()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                if await_backend_exit(5.0):
                    released = True
                    raise AssertionError(
                        "fixture advisory barrier did not release cleanly"
                    )
                raise AssertionError(
                    "fixture advisory barrier could not be released"
                )

            yield pid, release
        finally:
            terminate = False
            if proc.poll() is None:
                try:
                    proc.stdin.write(b"COMMIT;\n\\q\n")
                    proc.stdin.flush()
                except Exception:
                    terminate = True
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    terminate = True
                if terminate and pid is not None:
                    try:
                        self.sql(f"SELECT pg_terminate_backend({pid})")
                    except Exception:
                        pass
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    await_backend_exit(5.0)
            try:
                proc.communicate(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def wait_for_check_race_commit(self, fixture_pid: int, dispatch) -> int:
        """Wait for one real service orchestration parked at deferred COMMIT.

        The fixture advisory lock is held by ``fixture_pid``. The orchestration
        insert is complete but uncommitted, so the row is invisible to a manual
        GET while its unique key is already reserved. Only a backend belonging
        to the real service and blocked by this fixture session counts; a
        dispatch that finished without parking is a failed setup, not something
        to retry.
        """
        query = (
            "SELECT pid::text FROM pg_stat_activity "
            "WHERE state='active' AND wait_event_type='Lock' "
            "AND wait_event='advisory' AND application_name='rootyard' "
            f"AND {fixture_pid} = ANY(pg_blocking_pids(pid)) "
            f"AND pid <> {fixture_pid} ORDER BY pid"
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            rows = [row for row in self.sql(query).splitlines() if row]
            if len(rows) > 1:
                raise AssertionError(
                    self.redact(
                        "multiple service backends parked at the fixture "
                        f"COMMIT barrier: {rows}"
                    )
                )
            if rows:
                return int(rows[0])
            if dispatch.done():
                status, body, _ = dispatch.result()
                raise AssertionError(
                    self.redact(
                        "pull orchestration finished without parking at the "
                        f"fixture COMMIT barrier: {status} {body[:200]!r}"
                    )
                )
            time.sleep(0.01)
        raise AssertionError(
            "pull orchestration never parked at the fixture COMMIT barrier"
        )

    def wait_for_check_race_insert(self, manual, orchestration_pid: int) -> int:
        """Wait until the manual HTTP transaction blocks in its check INSERT.

        The statement carries the new ``ON CONFLICT ... DO NOTHING RETURNING``
        shape, which distinguishes it from orchestration's queued insert. The
        orchestration backend is already parked at deferred COMMIT, so the row
        is uncommitted and the manual INSERT must wait on PostgreSQL's unique
        key. A completed request without that wait never exercised the race.
        """
        query = (
            "SELECT pid::text FROM pg_stat_activity "
            "WHERE state='active' AND wait_event_type='Lock' "
            "AND wait_event <> 'advisory' "
            "AND query LIKE '%ON CONFLICT (tenant_id,repository_id,commit_oid,context) "
            "DO NOTHING RETURNING%' "
            f"AND {orchestration_pid} = ANY(pg_blocking_pids(pid)) "
            f"AND pid <> {orchestration_pid} ORDER BY pid"
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            rows = [row for row in self.sql(query).splitlines() if row]
            if len(rows) > 1:
                raise AssertionError(
                    "multiple manual check inserts waited on the "
                    f"orchestration-owned unique key: {rows}"
                )
            if rows:
                return int(rows[0])
            if manual.done():
                manual.result()  # Surface a generic 503 or any helper failure.
                raise AssertionError(
                    "manual check request completed without waiting on the "
                    "orchestration-owned unique key"
                )
            time.sleep(0.005)
        raise AssertionError(
            "manual check request never blocked on the orchestration-owned unique key"
        )

    def advance_check_racing_orchestration(
        self,
        commit_oid: str,
        context: str,
        status: str,
        conclusion,
        output,
        *,
        expected_sequence: int,
    ) -> dict:
        """Race one real manual check transition against pull orchestration.

        A fixture-owned deferred constraint trigger parks actual service
        orchestration at COMMIT after it inserted the same
        ``(tenant_id, repository_id, commit_oid, context)`` primary key. The
        orchestration row is uncommitted, so ``advance_check`` reads no row and
        its POST must wait on the unique index. Releasing the barrier commits the
        queued winner; the manual request must reconcile it through the normal
        attempt/sequence contract, never a generic unique-violation 503.

        The existing ``advance_check`` status, error, commit, context, attempt,
        conclusion, output and sequence assertions still apply; a 503 still
        fails immediately. Only the fixture lock is synthetic.
        """
        dispatch_path = "/api/repos/alice/forge/webhooks/dispatch"
        key_filter = (
            f"tenant_id='{self.alice['user_id']}' "
            f"AND repository_id='{self.repo['id']}' "
            f"AND commit_oid='{commit_oid}' AND context='{context}'"
        )
        pr = self.document(self.pr1_path)
        assert pr["head_oid"] == commit_oid, pr
        marker_filter = (
            f"repository_id='{self.repo['id']}' "
            f"AND pull_number={pr['number']} AND pull_version={pr['version']}"
        )
        marker_sql = (
            "SELECT count(*) FROM ci_pull_sync_progress "
            f"WHERE {marker_filter} "
            f"AND head_oid='{commit_oid}' AND base_oid='{pr['base_oid']}' "
            "AND storage_generation=(SELECT storage_generation FROM repositories "
            f"WHERE id='{self.repo['id']}')"
        )
        # The durable marker makes the always-on repair path skip this pull;
        # the explicit dispatch is the deterministic orchestration trigger.
        # If the marker is missing, one ordinary dispatch recreates it before
        # the barrier is armed.
        if self.sql(marker_sql) != "1":
            self.document(dispatch_path, 200, method="POST", body={})
            assert self.sql(marker_sql) == "1", "pull orchestration marker missing"
        # Advisory locks are database-wide, not schema-scoped. A random key
        # keeps parallel runs in the same test database from sharing a barrier.
        race_key = uuid.uuid4().int & ((1 << 63) - 1)
        try:
            with self.held_advisory_barrier(race_key) as (
                fixture_pid,
                release_barrier,
            ):
                # Install the deferred trigger while the fixture already owns
                # the advisory key. Every real insert from this point parks at
                # COMMIT after reserving the unique key; an ON CONFLICT loser
                # inserts no row and therefore cannot fake the parked creator
                # the pollers below require.
                self.sql(
                    "SET lock_timeout='2000ms'; SET statement_timeout='5000ms';\n"
                    f"""
                    CREATE OR REPLACE FUNCTION fixture_check_creation_barrier()
                    RETURNS trigger LANGUAGE plpgsql AS $fn$
                    BEGIN
                        IF NEW.tenant_id = '{self.alice['user_id']}'
                           AND NEW.repository_id = '{self.repo['id']}'
                           AND NEW.commit_oid = '{commit_oid}'
                           AND NEW.context = '{context}' THEN
                            -- Keep the parked service COMMIT finite if this
                            -- fixture is ever abandoned, while leaving ample
                            -- time for the manual INSERT to be observed.
                            PERFORM set_config('lock_timeout', '30000ms', true);
                            PERFORM set_config('statement_timeout', '35000ms', true);
                            PERFORM pg_advisory_xact_lock({race_key});
                        END IF;
                        RETURN NEW;
                    END
                    $fn$
                    """
                )
                self.sql(
                    "SET lock_timeout='2000ms'; SET statement_timeout='5000ms'; "
                    "DROP TRIGGER IF EXISTS fixture_check_creation_barrier "
                    "ON forge_check_runs"
                )
                self.sql(
                    "SET lock_timeout='2000ms'; SET statement_timeout='5000ms';\n"
                    """
                    CREATE CONSTRAINT TRIGGER fixture_check_creation_barrier
                    AFTER INSERT ON forge_check_runs
                    DEFERRABLE INITIALLY DEFERRED
                    FOR EACH ROW
                    EXECUTE FUNCTION fixture_check_creation_barrier()
                    """
                )
                # Remove only the scheduler's exact queued placeholder so the
                # manual request starts from an absent row. The durable marker
                # above keeps the bounded repair path from re-queueing it; the
                # explicit dispatch below is the intended orchestration writer.
                queued = self.listed_check_row(commit_oid, context)
                if queued is not None:
                    assert (
                        queued["status"] == "queued"
                        and queued["attempt"] == 1
                        and queued["sequence"] == 1
                        and queued["conclusion"] is None
                        and queued["output"] == AUTOMATIC_CHECK_OUTPUT
                    ), queued
                    self.sql(
                        "SET lock_timeout='2000ms'; SET statement_timeout='5000ms'; "
                        f"DELETE FROM forge_check_runs WHERE {key_filter}"
                    )
                assert self.listed_check_row(commit_oid, context) is None
                parked = self.sql(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE state='active' AND wait_event_type='Lock' "
                    "AND wait_event='advisory' AND application_name='rootyard' "
                    f"AND {fixture_pid} = ANY(pg_blocking_pids(pid))"
                )
                assert parked == "0", "an unexpected service writer parked before dispatch"

                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    try:
                        dispatch = pool.submit(
                            self.http,
                            dispatch_path,
                            token=self.alice,
                            method="POST",
                            body={},
                        )
                        orchestration_pid = self.wait_for_check_race_commit(
                            fixture_pid, dispatch
                        )
                        manual = pool.submit(
                            self.advance_check,
                            commit_oid,
                            context,
                            status,
                            conclusion,
                            output,
                            deadline_seconds=30.0,
                        )
                        manual_pid = self.wait_for_check_race_insert(
                            manual, orchestration_pid
                        )
                        # The fixture owns the only release point. The real
                        # manual transaction and service orchestration now
                        # resolve on PostgreSQL's unique key.
                        release_barrier()
                        dispatch_status, dispatch_body, _ = dispatch.result(timeout=15)
                        assert dispatch_status == 200, (
                            dispatch_status,
                            dispatch_body[:200],
                        )
                        summary = json.loads(dispatch_body)
                        assert summary["orchestrated_pulls"] >= 1, summary
                        run = manual.result(timeout=15)
                    finally:
                        # Never leave a parked service COMMIT holding the
                        # executor open if an assertion above failed first.
                        # release_barrier has its own terminate/kill fallback.
                        try:
                            release_barrier()
                        except Exception:
                            pass

                assert manual_pid != orchestration_pid
                assert self.sql(marker_sql) == "1", (
                    "pull orchestration marker disappeared"
                )
                assert run["repository_id"] == self.repo["id"], run
                assert run["commit_oid"] == commit_oid, run
                assert run["context"] == context, run
                assert run["status"] == status, run
                assert run["conclusion"] == conclusion, run
                assert run["output"] == output, run
                assert run["attempt"] == 1, run
                assert run["sequence"] == expected_sequence, run
                persisted = self.sql(
                    "SELECT commit_oid || '|' || context || '|' || attempt || '|' || "
                    "sequence || '|' || status || '|' || COALESCE(conclusion, '') || "
                    "'|' || output FROM forge_check_runs WHERE " + key_filter
                )
                assert persisted == (
                    f"{commit_oid}|{context}|1|{expected_sequence}|{status}|"
                    f"{conclusion or ''}|{output}"
                ), persisted
                # The manual reconcile moves only the monotonic payload. The
                # scheduler insert owns no CI provenance yet, so all four
                # provenance columns must still be NULL rather than rewritten.
                provenance = self.sql(
                    "SELECT concat_ws('|', "
                    "COALESCE(issuer_webhook_id::text, 'NULL'), "
                    "COALESCE(ci_run_id::text, 'NULL'), "
                    "COALESCE(ci_base_oid, 'NULL'), "
                    "COALESCE(ci_lease_generation::text, 'NULL')) "
                    "FROM forge_check_runs WHERE " + key_filter
                )
                assert provenance == "NULL|NULL|NULL|NULL", provenance
                # The same marker also proves the queued winner came from real
                # pull orchestration for this exact candidate and context.
                orchestration = self.sql(
                    "SELECT state || '|' || head_oid || '|' || base_oid || '|' || "
                    "context || '|' || pull_version::text FROM ci_runs WHERE "
                    f"repository_id='{self.repo['id']}' "
                    f"AND pull_number={pr['number']} "
                    f"AND pull_version={pr['version']} AND context='{context}'"
                )
                assert orchestration == (
                    f"queued|{commit_oid}|{pr['base_oid']}|{context}|{pr['version']}"
                ), orchestration
                candidate = self.document(self.pr1_path)
                assert candidate["head_oid"] == commit_oid, candidate
                assert candidate["base_oid"] == pr["base_oid"], candidate
                assert candidate["version"] == pr["version"], candidate
                assert self.listed_check_row(commit_oid, context) == run
                return run
        finally:
            cleanup_error = None
            try:
                self.sql(
                    "SET lock_timeout='2000ms'; SET statement_timeout='5000ms'; "
                    "DROP TRIGGER IF EXISTS fixture_check_creation_barrier "
                    "ON forge_check_runs"
                )
            except Exception as error:
                cleanup_error = error
            try:
                self.sql(
                    "SET lock_timeout='2000ms'; SET statement_timeout='5000ms'; "
                    "DROP FUNCTION IF EXISTS fixture_check_creation_barrier()"
                )
            except Exception as error:
                cleanup_error = cleanup_error or error
            # Keep an earlier race failure as the primary report, but never
            # silently leave the fixture trigger/function behind.
            if cleanup_error is not None:
                active = sys.exc_info()[1]
                if active is None:
                    raise cleanup_error
                add_note = getattr(active, "add_note", None)
                if add_note is not None:
                    add_note(
                        "fixture trigger cleanup also failed: "
                        + self.redact(cleanup_error)
                    )

    def ensure_migration_009(self):
        if self.sql("SELECT to_regclass('forge_pulls') IS NOT NULL") != "t":
            self.run(
                [
                    "psql",
                    self.db,
                    "-X",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-f",
                    str(migration_009_path()),
                ]
            )

    def init_repo_branches(self, clone_url_path: str, work_dir: Path, token: dict):
        self.git("clone", self.base + clone_url_path, str(work_dir), token=token)
        self.git("config", "user.name", token["username"], cwd=work_dir)
        self.git(
            "config",
            "user.email",
            f"{token['username']}@rootyard.local",
            cwd=work_dir,
        )
        (work_dir / "README.md").write_text("rootyard\n")
        self.git("add", "README.md", cwd=work_dir)
        self.git("commit", "-m", "initial main commit", cwd=work_dir)
        base_oid = (
            self.git("rev-parse", "HEAD", cwd=work_dir).stdout.decode().strip()
        )
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work_dir, token=token)

        (work_dir / "feature.txt").write_text("feature v1\n")
        self.git("add", "feature.txt", cwd=work_dir)
        self.git("commit", "-m", "add feature v1", cwd=work_dir)
        feat1_oid = (
            self.git("rev-parse", "HEAD", cwd=work_dir).stdout.decode().strip()
        )
        self.git(
            "push", "origin", "HEAD:refs/heads/feature", cwd=work_dir, token=token
        )
        return base_oid, feat1_oid

    def setup(self):
        super().setup()
        self.alice_read = self.reader
        self.ensure_migration_009()
        self.pullspath = "/api/repos/alice/forge/pulls"
        self.checkspath = "/api/repos/alice/forge/checks"
        self.rulespath = "/api/repos/alice/forge/branch-rules"
        self.other_pullspath = "/api/repos/alice/other/pulls"
        self.bob_pullspath = "/api/repos/bob/forge/pulls"

        self.work = self.root / "work-alice-forge"
        self.base_oid, self.feat1_oid = self.init_repo_branches(
            "/git/alice/forge.git", self.work, self.alice
        )
        (self.work / "feature.txt").write_text("feature v2\n")
        self.git("add", "feature.txt", cwd=self.work)
        self.git("commit", "-m", "update feature v2", cwd=self.work)
        self.feat2_oid = (
            self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        )
        self.git(
            "push",
            "origin",
            "HEAD:refs/heads/feature-v2",
            cwd=self.work,
            token=self.alice,
        )

        # Create non-fast-forward diverged branches from base_oid.
        self.git("checkout", "--detach", self.base_oid, cwd=self.work)
        (self.work / "other_file.txt").write_text("target branch change\n")
        self.git("add", "other_file.txt", cwd=self.work)
        self.git("commit", "-m", "diverged target", cwd=self.work)
        self.diverged_base_oid = (
            self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        )
        self.git(
            "push",
            "origin",
            "HEAD:refs/heads/target-nonff",
            cwd=self.work,
            token=self.alice,
        )

        self.git("checkout", "--detach", self.base_oid, cwd=self.work)
        (self.work / "source_file.txt").write_text("source branch change\n")
        self.git("add", "source_file.txt", cwd=self.work)
        self.git("commit", "-m", "diverged source", cwd=self.work)
        self.diverged_head_oid = (
            self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        )
        self.git(
            "push",
            "origin",
            "HEAD:refs/heads/source-nonff",
            cwd=self.work,
            token=self.alice,
        )

        self.other_base_oid, self.other_feat_oid = self.init_repo_branches(
            "/git/alice/other.git", self.root / "work-alice-other", self.alice
        )
        self.bob_base_oid, self.bob_feat_oid = self.init_repo_branches(
            "/git/bob/forge.git", self.root / "work-bob-forge", self.bob
        )

    def migration(self):
        self.stop()
        assert (
            self.sql("SELECT count(*) FROM schema_migrations WHERE version=9") == "1"
        )
        drops = (
            "DROP TABLE forge_pull_reviews, forge_pulls, forge_pull_counters, "
            "forge_check_runs, forge_branch_rules"
        )
        replay = "DELETE FROM schema_migrations WHERE version=9"
        if 9 in SCHEMA_VERSIONS:
            # Dropping these tables also discards the migration 72 constraints and
            # triggers plus the migration 107 columns and its trusted-context table.
            # Replaying only version 9 would leave the current schema marked applied
            # but physically older, poisoning every later case in this schema.
            drops += ", forge_trusted_check_contexts"
            replay = "DELETE FROM schema_migrations WHERE version IN (9,72,107)"
        self.sql(drops + "; " + replay + "; CREATE TABLE forge_pull_reviews(dummy integer)")
        if 9 in SCHEMA_VERSIONS:
            failed = self.run([self.args.binary, "migrate"], check=False)
        else:
            failed = self.run(
                [
                    "psql",
                    self.db,
                    "-X",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "--single-transaction",
                    "-f",
                    str(migration_009_path()),
                ],
                check=False,
            )
        assert failed.returncode != 0
        assert (
            self.sql("SELECT count(*) FROM schema_migrations WHERE version=9") == "0"
        )
        assert (
            self.sql(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema=current_schema() AND table_name IN ("
                "'forge_pulls','forge_pull_counters','forge_check_runs','forge_branch_rules')"
            )
            == "0"
        )
        self.sql("DROP TABLE forge_pull_reviews")
        if 9 in SCHEMA_VERSIONS:
            self.cli("migrate")
            self.cli("migrate")
            assert (
                self.sql(
                    "SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations"
                )
                == SCHEMA_VERSION_CSV
            )
        else:
            self.ensure_migration_009()
        assert (
            self.sql("SELECT count(*) FROM schema_migrations WHERE version=9") == "1"
        )
        if 9 in SCHEMA_VERSIONS:
            assert self.sql(
                "SELECT string_agg(column_name,',' ORDER BY column_name) "
                "FROM information_schema.columns WHERE table_schema=current_schema() "
                "AND table_name='forge_check_runs' AND column_name IN "
                "('issuer_webhook_id','ci_run_id','ci_base_oid','ci_lease_generation')"
            ) == "ci_base_oid,ci_lease_generation,ci_run_id,issuer_webhook_id"
            assert self.sql(
                "SELECT count(*) FROM information_schema.tables WHERE "
                "table_schema=current_schema() AND table_name='forge_trusted_check_contexts'"
            ) == "1"
        self.start()

    def lifecycle_and_diff(self):
        self.pr1 = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "Add feature",
                "body": "Initial PR\n<script>raw</script>",
                "head_ref": "refs/heads/feature",
                "base_ref": "refs/heads/main",
            },
            extra_headers={"Idempotency-Key": "create-pr-1"},
        )
        assert (
            self.pr1["number"] == 1
            and self.pr1["state"] == "open"
            and self.pr1["version"] == 1
        )
        assert self.pr1["head_oid"] == self.feat1_oid
        assert self.pr1["base_oid"] == self.base_oid
        assert self.pr1["merge_commit_oid"] is None
        assert self.pr1["merged_storage_generation"] is None

        # Idempotent replay of PR creation returns identical 201 response.
        replayed = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "Add feature",
                "body": "Initial PR\n<script>raw</script>",
                "head_ref": "refs/heads/feature",
                "base_ref": "refs/heads/main",
            },
            extra_headers={"Idempotency-Key": "create-pr-1"},
        )
        assert replayed == self.pr1

        self.pr1_path = self.pullspath + "/1"
        fetched = self.document(self.pr1_path, token=self.reader)
        assert fetched == self.pr1

        diff = self.document(self.pr1_path + "/diff", token=self.reader)
        assert diff["pull_number"] == 1
        assert diff["base_oid"] == self.base_oid
        assert diff["head_oid"] == self.feat1_oid
        assert diff["fast_forward"] is True
        assert "+feature v1" in diff["diff"]

        closed = self.document(
            self.pr1_path,
            method="PATCH",
            body={
                "expected_version": 1,
                "title": "Add feature (updated)",
                "state": "closed",
            },
        )
        assert closed["version"] == 2 and closed["state"] == "closed"
        self.document(
            self.pr1_path,
            409,
            method="PATCH",
            body={"expected_version": 1, "title": "Stale"},
        )
        self.document(
            self.pr1_path,
            400,
            method="PATCH",
            body={"expected_version": 2, "state": "merged"},
        )
        reopened = self.document(
            self.pr1_path,
            method="PATCH",
            body={"expected_version": 2, "state": "open", "body": "Reopened"},
        )
        assert reopened["version"] == 3 and reopened["state"] == "open"

    def reviews_and_head_binding(self):
        reviews_path = self.pr1_path + "/reviews"
        # Wrong/stale commit_oid must be rejected with 409 Conflict.
        self.document(
            reviews_path,
            409,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.base_oid,
                "body": "Wrong commit",
            },
        )
        r1 = self.document(
            reviews_path,
            201,
            method="POST",
            body={
                "state": "commented",
                "commit_oid": self.feat1_oid,
                "body": "Looks promising",
            },
        )
        assert (
            r1["number"] == 1
            and r1["pull_number"] == 1
            and r1["pull_version"] == 3
        )
        r2 = self.document(
            reviews_path,
            201,
            method="POST",
            body={
                "state": "changes_requested",
                "commit_oid": self.feat1_oid,
                "body": "Needs tests",
            },
        )
        assert r2["number"] == 2 and r2["state"] == "changes_requested"
        r3 = self.document(
            reviews_path,
            201,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.feat1_oid,
                "body": "LGTM",
            },
            extra_headers={"Idempotency-Key": "review-pr1-3"},
        )
        assert r3["number"] == 3 and r3["state"] == "approved"
        assert (
            self.document(
                reviews_path,
                201,
                method="POST",
                body={
                    "state": "approved",
                    "commit_oid": self.feat1_oid,
                    "body": "LGTM",
                },
                extra_headers={"Idempotency-Key": "review-pr1-3"},
            )
            == r3
        )
        # Reviews do not increment PR content version.
        assert self.document(self.pr1_path)["version"] == 3

        page1 = self.document(reviews_path + "?limit=2", token=self.reader)
        assert [i["number"] for i in page1["items"]] == [1, 2]
        assert page1["next_after"] == 2
        page2 = self.document(reviews_path + "?limit=2&after=2", token=self.reader)
        assert [i["number"] for i in page2["items"]] == [3]
        assert page2["next_after"] is None

    def checks_and_monotonic_ordering(self):
        c1 = self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "queued",
                "attempt": 1,
                "sequence": 1,
            },
        )
        assert c1["status"] == "queued" and c1["attempt"] == 1 and c1["sequence"] == 1

        c2 = self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "in_progress",
                "attempt": 1,
                "sequence": 2,
            },
        )
        assert c2["status"] == "in_progress" and c2["sequence"] == 2

        # Out-of-order lower sequence must fail with 409.
        self.document(
            self.checkspath,
            409,
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "queued",
                "attempt": 1,
                "sequence": 1,
            },
        )

        self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "completed",
                "conclusion": "failure",
                "output": "1 failed",
                "attempt": 1,
                "sequence": 3,
            },
        )
        self.document(
            self.checkspath,
            409,
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "in_progress",
                "attempt": 1,
                "sequence": 2,
            },
        )

        # Retry attempt 2 supersedes attempt 1.
        commit_checks_path = f"/api/repos/alice/forge/commits/{self.feat1_oid}/checks"
        c_attempt2 = self.document(
            commit_checks_path,
            (200, 201),
            method="POST",
            body={
                "context": "ci/test",
                "status": "completed",
                "conclusion": "success",
                "output": "all passed",
                "attempt": 2,
                "sequence": 1,
            },
        )
        assert c_attempt2["attempt"] == 2 and c_attempt2["conclusion"] == "success"

        # Stale attempt 1 is rejected even with high sequence.
        self.document(
            commit_checks_path,
            409,
            method="POST",
            body={
                "context": "ci/test",
                "status": "completed",
                "conclusion": "failure",
                "attempt": 1,
                "sequence": 99,
            },
        )

        # Idempotent retry at exact (attempt=2, sequence=1) with identical payload succeeds.
        self.document(
            commit_checks_path,
            (200, 201),
            method="POST",
            body={
                "context": "ci/test",
                "status": "completed",
                "conclusion": "success",
                "output": "all passed",
                "attempt": 2,
                "sequence": 1,
            },
        )
        # Conflicting state at same (attempt=2, sequence=1) is rejected with 409.
        self.document(
            commit_checks_path,
            409,
            method="POST",
            body={
                "context": "ci/test",
                "status": "completed",
                "conclusion": "failure",
                "output": "all passed",
                "attempt": 2,
                "sequence": 1,
            },
        )

        self.document(
            commit_checks_path,
            (200, 201),
            method="POST",
            body={
                "context": "ci/lint",
                "status": "completed",
                "conclusion": "success",
                "attempt": 1,
                "sequence": 1,
            },
        )

        by_commit = self.document(commit_checks_path, token=self.reader)
        assert by_commit["commit_oid"] == self.feat1_oid, by_commit["commit_oid"]
        self.check_contexts(by_commit["items"])
        by_pull = self.document(self.pr1_path + "/checks", token=self.reader)
        assert by_pull["pull_number"] == 1, by_pull["pull_number"]
        assert by_pull["head_oid"] == self.feat1_oid, by_pull["head_oid"]
        self.check_contexts(by_pull["items"])

    def branch_rules_and_stale_invalidation(self):
        rule = self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "required_approvals": 1,
                "required_checks": ["ci/test"],
                "require_fast_forward": True,
            },
        )
        assert rule["version"] == 1 and rule["branch_ref"] == "refs/heads/main"

        self.document(
            self.rulespath,
            409,
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "expected_version": 99,
                "required_approvals": 1,
                "required_checks": ["ci/test", "ci/lint"],
                "require_fast_forward": True,
            },
        )
        updated_rule = self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "expected_version": 1,
                "required_approvals": 1,
                "required_checks": ["ci/test", "ci/lint"],
                "require_fast_forward": True,
            },
        )
        assert updated_rule["version"] == 2
        listed = self.document(self.rulespath, token=self.reader)
        assert len(listed["items"]) == 1 and listed["items"][0]["version"] == 2

        # The state this test observed before the push; later fenced mutations
        # use a fresh GET instead, because the always-on synchronizer may record
        # the push first and bump the version legitimately.
        pre_push = self.document(self.pr1_path)
        assert pre_push["head_oid"] == self.feat1_oid, pre_push["head_oid"]
        assert pre_push["base_oid"] == self.base_oid, pre_push["base_oid"]
        assert pre_push["version"] == 3, pre_push["version"]

        # Advance refs/heads/feature in native Git to feat2_oid.
        self.git(
            "push",
            "origin",
            f"{self.feat2_oid}:refs/heads/feature",
            cwd=self.work,
            token=self.alice,
        )
        # Merge with the old expected_head_oid must fail because the live ref
        # moved to feat2_oid, whether or not the pull row has caught up yet. The
        # version is the freshly reported one, so only the head fence can 409.
        self.document(
            self.pr1_path + "/merge",
            409,
            method="POST",
            body={
                "expected_version": self.merge_version(),
                "expected_head_oid": self.feat1_oid,
                "expected_base_oid": self.base_oid,
            },
        )

        # Update PR #1 head_oid to feat2_oid; the background synchronizer may get
        # there first, and both writers must converge on exactly this state.
        synced = self.sync_pull_head(pre_push, self.feat2_oid)
        assert synced["version"] == 4, synced["version"]

        # Merge must now fail with 409 because reviews and checks on feat1_oid do not apply to feat2_oid!
        self.document(
            self.pr1_path + "/merge",
            409,
            method="POST",
            body={
                "expected_version": self.merge_version(),
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
        )

        # Approve feat2_oid, but required checks are still missing on feat2_oid.
        self.document(
            self.pr1_path + "/reviews",
            201,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.feat2_oid,
                "body": "Approved v2",
            },
        )
        self.document(
            self.pr1_path + "/merge",
            409,
            method="POST",
            body={
                "expected_version": self.merge_version(),
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
        )

        # Add passing ci/test and failing ci/lint on feat2_oid -> merge still blocked.
        self.advance_check(self.feat2_oid, "ci/test", "completed", "success", "all passed")
        # The first ci/lint transition is the exact absent-row race from verify
        # run 43571388702. Keep the pull-version progress marker so the
        # always-on repair path skips it, then trigger real dispatch
        # orchestration and park its queued insert at deferred COMMIT. Let the
        # real manual POST wait on the unique index, then release it. The
        # helper must end on the committed manual payload (sequence 2 after the
        # exact queued-row CAS conflict), not a generic 503.
        raced = self.advance_check_racing_orchestration(
            self.feat2_oid, "ci/lint", "completed", "failure", "1 failed",
            expected_sequence=2,
        )
        assert raced["sequence"] == 2, raced
        candidate = self.document(self.pr1_path)
        assert candidate["head_oid"] == self.feat2_oid, candidate["head_oid"]
        assert candidate["base_oid"] == self.base_oid, candidate["base_oid"]
        assert candidate["version"] == 4, candidate["version"]
        self.document(
            self.pr1_path + "/merge",
            409,
            method="POST",
            body={
                "expected_version": self.merge_version(),
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
        )

        # Advance ci/lint to success on feat2_oid -> all branch rules satisfied.
        self.advance_check(self.feat2_oid, "ci/lint", "completed", "success", "all passed")

        # Require 2 approvals; an intervening changes_requested must invalidate prior approvals on feat2_oid.
        self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "expected_version": 2,
                "required_approvals": 2,
                "required_checks": ["ci/test", "ci/lint"],
                "require_fast_forward": True,
            },
        )
        self.document(
            self.pr1_path + "/reviews",
            201,
            method="POST",
            body={
                "state": "changes_requested",
                "commit_oid": self.feat2_oid,
                "body": "Request changes after first approval",
            },
        )
        self.document(
            self.pr1_path + "/reviews",
            201,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.feat2_oid,
                "body": "First approval after changes_requested",
            },
        )
        # Only 1 approval after changes_requested -> merge must still be blocked with 409.
        self.document(
            self.pr1_path + "/merge",
            409,
            method="POST",
            body={
                "expected_version": self.merge_version(),
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
        )
        # Second approval after changes_requested satisfies required_approvals=2.
        self.document(
            self.pr1_path + "/reviews",
            201,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.feat2_oid,
                "body": "Second approval after changes_requested",
            },
        )
        # The next case merges with exactly this head, base and version; no
        # background writer may have changed them while this case ran.
        settled = self.document(self.pr1_path)
        assert settled["head_oid"] == self.feat2_oid, settled["head_oid"]
        assert settled["base_oid"] == self.base_oid, settled["base_oid"]
        assert settled["version"] == 4, settled["version"]

    def atomic_merge_and_idempotency(self):
        merge_path = self.pr1_path + "/merge"
        # CAS precondition mismatches must return 409.
        for bad_payload in (
            {
                "expected_version": 3,
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
            {
                "expected_version": 4,
                "expected_head_oid": self.feat1_oid,
                "expected_base_oid": self.base_oid,
            },
            {
                "expected_version": 4,
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.feat1_oid,
            },
            {
                "expected_version": 4,
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
                "storage_generation": 99,
            },
        ):
            self.document(merge_path, 409, method="POST", body=bad_payload)

        merge_payload = {
            "expected_version": 4,
            "expected_head_oid": self.feat2_oid,
            "expected_base_oid": self.base_oid,
            "storage_generation": 1,
            "strategy": "fast_forward",
        }
        merged = self.document(
            merge_path,
            200,
            method="POST",
            body=merge_payload,
            extra_headers={"Idempotency-Key": "merge-pr-1"},
        )
        assert merged["state"] == "merged" and merged["version"] == 5
        assert merged["merge_commit_oid"] == self.feat2_oid
        assert merged["merged_storage_generation"] == 1

        # Verify native Git ref refs/heads/main moved to feat2_oid.
        ls_out = (
            self.git(
                "ls-remote",
                self.base + "/git/alice/forge.git",
                "refs/heads/main",
                token=self.alice,
            )
            .stdout.decode()
            .strip()
        )
        assert ls_out.startswith(self.feat2_oid), ls_out

        # Verify operations and outbox recorded the merge ref update.
        ops = self.document("/api/repos/alice/forge/operations")
        assert isinstance(ops, list)
        assert any(
            op["outcome"] == "recorded"
            and op["evidence_summary"]["kind"] == "pull_merge"
            for op in ops
        )

        # Idempotent replay of merge returns identical 200 response.
        replayed = self.document(
            merge_path,
            200,
            method="POST",
            body=merge_payload,
            extra_headers={"Idempotency-Key": "merge-pr-1"},
        )
        assert replayed == merged

        # Conflicting payload with same Idempotency-Key returns 409.
        self.document(
            merge_path,
            409,
            method="POST",
            body={**merge_payload, "strategy": "merge_commit"},
            extra_headers={"Idempotency-Key": "merge-pr-1"},
        )

        # Merged PR is terminal.
        self.document(
            self.pr1_path,
            409,
            method="PATCH",
            body={"expected_version": 5, "state": "open"},
        )
        self.document(
            self.pr1_path + "/reviews",
            409,
            method="POST",
            body={
                "state": "commented",
                "commit_oid": self.feat2_oid,
                "body": "After merge",
            },
        )
        self.document(merge_path, 409, method="POST", body=merge_payload)

        # Non-fast-forward PR #2 with merge_commit strategy.
        pr2 = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "Non-FF merge",
                "head_ref": "refs/heads/source-nonff",
                "base_ref": "refs/heads/target-nonff",
            },
        )
        assert pr2["number"] == 2
        diff2 = self.document(f"{self.pullspath}/2/diff")
        assert diff2["fast_forward"] is False

        self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/target-nonff",
                "required_approvals": 0,
                "required_checks": [],
                "require_fast_forward": True,
            },
        )
        # Fast-forward fails because branches diverged; merge_commit fails because rule requires FF.
        for strat in ("fast_forward", "merge_commit"):
            self.document(
                f"{self.pullspath}/2/merge",
                409,
                method="POST",
                body={
                    "expected_version": 1,
                    "expected_head_oid": self.diverged_head_oid,
                    "expected_base_oid": self.diverged_base_oid,
                    "strategy": strat,
                },
            )
        # Allow merge_commit on target-nonff and merge PR #2.
        self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/target-nonff",
                "expected_version": 1,
                "required_approvals": 0,
                "required_checks": [],
                "require_fast_forward": False,
            },
        )
        merged2 = self.document(
            f"{self.pullspath}/2/merge",
            200,
            method="POST",
            body={
                "expected_version": 1,
                "expected_head_oid": self.diverged_head_oid,
                "expected_base_oid": self.diverged_base_oid,
                "strategy": "merge_commit",
            },
        )
        assert merged2["state"] == "merged"
        assert (
            merged2["merge_commit_oid"] is not None
            and merged2["merge_commit_oid"] != self.diverged_head_oid
        )

    def access_and_boundaries(self):
        read_paths = [
            self.pullspath,
            self.pr1_path,
            self.pr1_path + "/diff",
            self.pr1_path + "/reviews",
            self.pr1_path + "/checks",
            f"/api/repos/alice/forge/commits/{self.feat2_oid}/checks",
            self.rulespath,
        ]
        for path in read_paths:
            self.expect(path, 401)
            self.document(path, 404, token=self.bob)
            self.document(path, token=self.reader)

        write_calls = [
            (
                self.pullspath,
                "POST",
                {
                    "title": "Denied",
                    "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main",
                },
            ),
            (
                self.pr1_path,
                "PATCH",
                {"expected_version": 5, "title": "Denied"},
            ),
            (
                self.pr1_path + "/reviews",
                "POST",
                {
                    "state": "approved",
                    "commit_oid": self.feat2_oid,
                    "body": "Denied",
                },
            ),
            (
                self.checkspath,
                "POST",
                {
                    "commit_oid": self.feat2_oid,
                    "context": "ci/denied",
                    "status": "queued",
                },
            ),
            (
                self.rulespath,
                "PUT",
                {"branch_ref": "refs/heads/main", "required_approvals": 1},
            ),
            (
                self.pr1_path + "/merge",
                "POST",
                {
                    "expected_version": 5,
                    "expected_head_oid": self.feat2_oid,
                    "expected_base_oid": self.base_oid,
                },
            ),
        ]
        for path, method, body in write_calls:
            self.document(path, 403, token=self.reader, method=method, body=body)
            self.document(path, 404, token=self.bob, method=method, body=body)

        # Validation boundaries (400 and 422).
        for bad_title in ("", " \t", "a\nb", "a\0b", "x" * 257):
            self.document(
                self.pullspath,
                400,
                method="POST",
                body={
                    "title": bad_title,
                    "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main",
                },
            )
        self.document(
            self.pullspath,
            400,
            method="POST",
            body={
                "title": "Same branch",
                "head_ref": "refs/heads/main",
                "base_ref": "refs/heads/main",
            },
        )
        for spoof_field in (
            "author_id",
            "tenant_id",
            "repository_id",
            "state",
            "number",
            "merge_commit_oid",
        ):
            self.expect(
                self.pullspath,
                422,
                token=self.alice,
                method="POST",
                body={
                    "title": "spoof",
                    "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main",
                    spoof_field: str(uuid.uuid4()),
                },
            )
        for suffix in (
            "?limit=0",
            "?limit=101",
            "?after=-1",
            "?extra=1",
            "?state=invalid",
        ):
            self.expect(self.pullspath + suffix, 400, token=self.alice)

        # Recovering repository freezes all Track 1 endpoints with 409.
        self.sql(
            f"UPDATE repositories SET state='recovering' WHERE id='{self.repo['id']}'"
        )
        try:
            for path in read_paths:
                self.document(path, 409)
            for path, method, body in write_calls:
                self.document(path, 409, method=method, body=body)
        finally:
            self.sql(
                f"UPDATE repositories SET state='ready' WHERE id='{self.repo['id']}'"
            )

    def concurrency_and_pagination(self):
        before = int(
            self.sql(
                f"SELECT count(*) FROM forge_pulls WHERE repository_id='{self.repo['id']}'"
            )
        )

        def create_pr(i):
            return self.document(
                self.pullspath,
                201,
                method="POST",
                body={
                    "title": f"Concurrent PR {i}",
                    "head_ref": "refs/heads/feature-v2",
                    "base_ref": "refs/heads/target-nonff",
                },
            )["number"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            numbers = list(ex.map(create_pr, range(12)))
        assert len(set(numbers)) == 12
        assert sorted(numbers) == list(range(before + 1, before + 13))

        target_pr_path = f"{self.pullspath}/{numbers[0]}"
        current = self.document(target_pr_path)

        def patch_pr(i):
            return self.http(
                target_pr_path,
                token=self.alice,
                method="PATCH",
                body={
                    "expected_version": current["version"],
                    "title": f"CAS title {i}",
                },
            )[0]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            codes = list(ex.map(patch_pr, range(8)))
        assert codes.count(200) == 1 and codes.count(409) == 7, codes

        seen = []
        cursor = 0
        while cursor is not None:
            page = self.document(f"{self.pullspath}?limit=5&after={cursor}")
            assert len(page["items"]) <= 5
            seen.extend(p["number"] for p in page["items"])
            cursor = page["next_after"]
        assert seen == list(range(1, before + 13)), seen

    def database_boundaries_and_rollback(self):
        tenant, repo, wrong = (
            self.alice["user_id"],
            self.repo["id"],
            self.bob["user_id"],
        )
        bad_sqls = [
            f"INSERT INTO forge_pulls(tenant_id,repository_id,number,author_id,title,head_ref,base_ref,head_oid,base_oid) "
            f"VALUES('{wrong}','{repo}',900,'{wrong}','cross tenant','refs/heads/feature','refs/heads/main','{self.feat1_oid}','{self.base_oid}')",
            f"INSERT INTO forge_pulls(tenant_id,repository_id,number,author_id,title,head_ref,base_ref,head_oid,base_oid) "
            f"VALUES('{tenant}','{repo}',900,'{wrong}','spoof author','refs/heads/feature','refs/heads/main','{self.feat1_oid}','{self.base_oid}')",
            f"INSERT INTO forge_pulls(tenant_id,repository_id,number,author_id,title,state,head_ref,base_ref,head_oid,base_oid) "
            f"VALUES('{tenant}','{repo}',900,'{tenant}','merged without oid','merged','refs/heads/feature','refs/heads/main','{self.feat1_oid}','{self.base_oid}')",
            f"INSERT INTO forge_check_runs(tenant_id,repository_id,commit_oid,context,status) "
            f"VALUES('{tenant}','{repo}','{self.feat1_oid}','ci/bad','completed')",
        ]
        for stmt in bad_sqls:
            res = self.run(
                ["psql", self.db, "-X", "-v", "ON_ERROR_STOP=1", "-c", stmt],
                check=False,
            )
            assert res.returncode != 0

        counter = self.sql(
            f"SELECT next_number FROM forge_pull_counters WHERE repository_id='{repo}'"
        )
        self.sql(
            "ALTER TABLE forge_pulls ADD CONSTRAINT fixture_failure CHECK (title <> 'injected pull failure')"
        )
        try:
            self.document(
                self.pullspath,
                503,
                method="POST",
                body={
                    "title": "injected pull failure",
                    "head_ref": "refs/heads/feature-v2",
                    "base_ref": "refs/heads/target-nonff",
                },
            )
        finally:
            self.sql("ALTER TABLE forge_pulls DROP CONSTRAINT fixture_failure")
        assert (
            self.sql(
                f"SELECT next_number FROM forge_pull_counters WHERE repository_id='{repo}'"
            )
            == counter
        )

    def restart(self):
        self.restart_check_contract_selftest()
        pr1 = self.document(self.pr1_path)
        reviews = self.document(self.pr1_path + "/reviews")
        checks = self.document(self.pr1_path + "/checks")
        rules = self.document(self.rulespath)
        self.stop(hard=True)
        self.start()
        assert self.document(self.pr1_path) == pr1
        assert self.document(self.pr1_path + "/reviews") == reviews
        # Manual check rows stay byte-identical; only the scheduler-owned
        # `ci/default` row may appear or advance across the restart.
        self.assert_checks_survive_restart(
            checks, self.document(self.pr1_path + "/checks")
        )
        assert self.document(self.rulespath) == rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = PullsHarness(args)
    success = False
    try:
        for name in (
            "setup",
            "migration",
            "lifecycle_and_diff",
            "reviews_and_head_binding",
            "checks_and_monotonic_ordering",
            "branch_rules_and_stale_invalidation",
            "atomic_merge_and_idempotency",
            "access_and_boundaries",
            "concurrency_and_pagination",
            "database_boundaries_and_rollback",
            "restart",
        ):
            harness.case(name, getattr(harness, name))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(
                dict(
                    name="cleanup",
                    status="failed",
                    error=harness.redact(error),
                    traceback=harness.redact(traceback.format_exc()),
                )
            )
            success = False
        report = dict(
            passed=success,
            cases=harness.results,
            binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            limitations=[
                "Personal owner-only tenancy, not organization/collaborator ACLs.",
                "Same-generation atomic merge covers local bare repositories and PostgreSQL outbox.",
            ],
        )
        if args.keep:
            report["retained_directory"] = str(harness.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
