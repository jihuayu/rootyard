#!/usr/bin/env python3
"""Repository read-only Browse API and atomic multi-ref CAS transaction tests."""
import argparse
import base64
import concurrent.futures
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness  # noqa: E402

ZERO_OID = "0" * 40

# The reconciler only auto-clears its own durable push ambiguity marker.  A
# manual fence must use an unrelated reason so a concurrent worker cannot turn
# the expected 409 into a 200 and hide the read/transaction gate.
MANUAL_RECOVERY_REASON = "manual_test_browse_recovery_fence"

CASE_NAMES = (
    "setup_repos",
    "refs_and_pagination",
    "commits_and_pagination",
    "tree_and_blob",
    "compare_revisions",
    "ref_transactions_atomic_cas",
    "idempotency_and_concurrency",
    "access_and_fences",
    "object_format_and_negotiation",
    "bounded_ref_and_commit_pages",
    "selective_ref_prefix",
    "protected_writes_and_ref_ack_failure",
)


class BrowseHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.actor_labels = {}

    def account(self, *args):
        account = super().account(*args)
        self.register_token(account)
        if account.get("token_id"):
            if args and args[0] == "create-user":
                self.actor_labels[account["token_id"]] = (
                    "owner" if args[1] == "alice" else "non-member"
                )
            elif "--read-only" in args:
                self.actor_labels[account["token_id"]] = "read-only"
            else:
                self.actor_labels[account["token_id"]] = "token"
        return account

    def register_token(self, account):
        """Keep raw and Git Basic credential forms out of every diagnostic."""
        token = account.get("token")
        if not isinstance(token, str) or not token:
            return
        forms = [token]
        username = account.get("username")
        if isinstance(username, str) and username:
            forms.append(base64.b64encode((username + ":" + token).encode()).decode())
        for form in forms:
            if form not in self.secrets:
                self.secrets.append(form)

    def actor_label(self, token):
        """Return a stable role label, never a token id or credential."""
        if not token:
            return "anonymous"
        label = self.actor_labels.get(token.get("token_id"))
        if label:
            return label
        if token.get("read_only"):
            return "read-only"
        return "unknown"

    @staticmethod
    def _sql_literal(value):
        return str(value).replace("'", "''")

    def repository_diagnostics(self):
        """Current schema and repository row facts for an unexpected response."""
        repo = getattr(self, "repo", {}) or {}
        repo_id = repo.get("id") if isinstance(repo, dict) else None
        details = {
            "schema": getattr(self, "schema", "unknown"),
            "repository_id": repo_id or "unknown",
            "role_effective_identity": "unavailable",
            "row_effective_identity": "unavailable",
            "current_state": "unavailable",
            "recovery_reason": None,
        }
        if not repo_id:
            return details
        query = (
            "SELECT json_build_object("
            "'schema',current_schema(),"
            "'repository_id',r.id::text,"
            "'owner_id',r.owner_id::text,"
            "'owner',ns.slug,"
            "'name',r.name,"
            "'state',r.state,"
            "'recovery_reason',r.recovery_reason,"
            "'storage_generation',r.storage_generation,"
            "'storage_backend',r.storage_backend,"
            "'row_effective_identity',json_build_object("
            "'id',r.id::text,'owner_id',r.owner_id::text,"
            "'owner',ns.slug,'name',r.name)) "
            "FROM repositories r LEFT JOIN namespaces ns ON ns.id=r.owner_id "
            "WHERE r.id='" + self._sql_literal(repo_id) + "'"
        )
        try:
            raw = self.sql(query)
            if not raw:
                details["current_state"] = "missing"
                details["row_effective_identity"] = "missing"
                return details
            row = json.loads(raw)
        except Exception as error:  # noqa: BLE001 - diagnostic collection must not mask
            details["current_state"] = "query_failed"
            details["row_effective_identity"] = "query_failed"
            details["diagnostic_error"] = type(error).__name__
            return details
        details.update({
            "schema": row.get("schema") or details["schema"],
            "repository_id": row.get("repository_id") or details["repository_id"],
            "current_state": row.get("state") or "unknown",
            "recovery_reason": row.get("recovery_reason"),
            "storage_generation": row.get("storage_generation"),
            "storage_backend": row.get("storage_backend"),
            "row_effective_identity": row.get("row_effective_identity"),
        })
        return details

    def _server_log_tail(self, limit=4000):
        log = self.root / "server.log"
        try:
            return log.read_text(errors="replace")[-limit:]
        except FileNotFoundError:
            return ""
        except Exception as error:  # noqa: BLE001 - type only, never str(error)
            return "unavailable:" + type(error).__name__

    def http_failure_detail(
        self, path, expected, status, body, headers, token, note=None, error_type=None
    ):
        """Redacted facts for an unexpected HTTP result; never renders argv or creds."""
        if isinstance(body, bytes):
            body_text = body.decode(errors="replace")
        elif body is None:
            body_text = ""
        else:
            body_text = str(body)
        details = {
            "request_path": path,
            "actor": self.actor_label(token),
            "expected_status": expected,
            "observed_status": status,
            "response_content_type": headers.get("content-type")
            or headers.get("Content-Type"),
            "response_body": body_text[:1000],
            "server_log_tail": self._server_log_tail(),
        }
        details.update(self.repository_diagnostics())
        if note:
            details["note"] = note
        if error_type:
            details["http_error"] = error_type
        summary = f"{path}: expected {expected}, got {status}"
        if body_text:
            summary += f": {body_text[:300]!r}"
        return self.redact(summary + "\n" + json.dumps(details, sort_keys=True))

    def document(self, path, code=200, token=None, **kwargs):
        actor = token or self.alice
        try:
            status, body, headers = self.http(path, token=actor, **kwargs)
        except Exception as error:  # noqa: BLE001 - retain type only, not str(error)
            raise AssertionError(
                self.http_failure_detail(
                    path, code, "exception", b"", {}, actor,
                    error_type=type(error).__name__,
                )
            ) from None
        norm_headers = {k.lower(): v for k, v in headers.items()}
        expected = code if isinstance(code, tuple) else (code,)
        if status not in expected:
            raise AssertionError(
                self.http_failure_detail(path, code, status, body, headers, actor)
            )
        notes = []
        if norm_headers.get("cache-control") != "no-store":
            notes.append(f"cache-control={norm_headers.get('cache-control')!r}")
        if "application/json" not in norm_headers.get("content-type", ""):
            notes.append(f"content-type={norm_headers.get('content-type')!r}")
        if notes:
            raise AssertionError(
                self.http_failure_detail(
                    path, code, status, body, headers, actor, note="; ".join(notes)
                )
            )
        try:
            return json.loads(body)
        except Exception as error:  # noqa: BLE001 - retain type only
            raise AssertionError(
                self.http_failure_detail(
                    path, code, status, body, headers, actor,
                    note="invalid JSON response: " + type(error).__name__,
                )
            ) from None

    @contextmanager
    def recovery_fence(self):
        """Set an operator/manual fence and always restore the ready row."""
        repo_id = self._sql_literal(self.repo["id"])
        self.sql(
            "UPDATE repositories SET state='recovering', recovery_reason='"
            + MANUAL_RECOVERY_REASON
            + "' WHERE id='" + repo_id + "'"
        )
        try:
            yield
        finally:
            self.sql(
                "UPDATE repositories SET state='ready', recovery_reason=NULL WHERE id='"
                + repo_id + "'"
            )

    def repo_api(self, suffix="", repo="demo", owner="alice"):
        return f"/api/repos/{owner}/{repo}{suffix}"

    def setup_repos(self):
        super().setup()
        self.api()
        self.roundtrip()
        self.other = self.document("/api/repos", 201, method="POST", body={"name": "other"})
        self.bob_repo = self.document(
            "/api/repos", 201, token=self.bob, method="POST", body={"name": "demo"}
        )

        # Add nested directories and a binary file on main -> self.third
        (self.work / "src" / "sub").mkdir(parents=True, exist_ok=True)
        (self.work / "assets").mkdir(parents=True, exist_ok=True)
        self.lib_rs_text = "pub fn add(a: i32, b: i32) -> i32 { a + b }\n"
        self.sub_mod_text = "pub const VERSION: u32 = 1;\n"
        self.logo_bytes = b"\x00\x01\x02rootyard\xff\xfe"
        (self.work / "src" / "lib.rs").write_text(self.lib_rs_text)
        (self.work / "src" / "sub" / "mod.rs").write_text(self.sub_mod_text)
        (self.work / "assets" / "logo.bin").write_bytes(self.logo_bytes)
        self.git("add", "src/lib.rs", "src/sub/mod.rs", "assets/logo.bin", cwd=self.work)
        self.git("commit", "-m", "third commit with nested tree and binary", cwd=self.work)
        self.third = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=self.work, token=self.alice)

        # Create feature branch with an extra commit -> self.feature_oid
        self.git("checkout", "-b", "feature", cwd=self.work)
        (self.work / "feature.txt").write_text("feature work\n")
        self.git("add", "feature.txt", cwd=self.work)
        self.git("commit", "-m", "feature commit", cwd=self.work)
        self.feature_oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/feature", cwd=self.work, token=self.alice)

        # Push lightweight tag v1.0 pointing to self.second
        self.git("tag", "v1.0", self.second, cwd=self.work)
        self.git("push", "origin", "refs/tags/v1.0", cwd=self.work, token=self.alice)

        # Create a controller-owned CI retention pin so refs/rootyard-ci/jobs/<id> exists
        self.ci_job_id = str(uuid.uuid4())
        self.document(
            self.repo_api("/ci-pins"),
            (200, 201),
            method="POST",
            body={
                "job_id": self.ci_job_id,
                "target_oid": self.first,
                "storage_generation": 1,
            },
        )

    def refs_and_pagination(self):
        for tok in (self.alice, self.reader):
            refs_doc = self.document(self.repo_api("/refs"), token=tok)
            assert refs_doc["repository_id"] == self.repo["id"]
            assert refs_doc["storage_generation"] == 1
            assert refs_doc["head"] == {
                "kind": "symbolic",
                "target": "refs/heads/main",
                "oid": self.third,
            }
            names = [item["name"] for item in refs_doc["items"]]
            assert names == ["refs/heads/feature", "refs/heads/main", "refs/tags/v1.0"], names
            assert all(not n.startswith("refs/rootyard-ci") for n in names)

        branches_only = self.document(self.repo_api("/refs?prefix=refs/heads/"))
        assert [r["name"] for r in branches_only["items"]] == [
            "refs/heads/feature",
            "refs/heads/main",
        ]
        assert all(r["kind"] == "branch" for r in branches_only["items"])

        tags_only = self.document(self.repo_api("/refs?prefix=refs/tags/"))
        assert [r["name"] for r in tags_only["items"]] == ["refs/tags/v1.0"]
        assert tags_only["items"][0]["kind"] == "tag"
        assert tags_only["items"][0]["oid"] == self.second

        # Reserved CI prefix must be rejected
        self.document(self.repo_api("/refs?prefix=refs/rootyard-ci/"), 400)

        # Keyset cursor pagination over refs
        collected = []
        cursor = None
        while True:
            q = "/refs?limit=1" + (f"&after={cursor}" if cursor else "")
            page = self.document(self.repo_api(q))
            collected.extend(r["name"] for r in page["items"])
            cursor = page["next_after"]
            if cursor is None:
                break
        assert collected == ["refs/heads/feature", "refs/heads/main", "refs/tags/v1.0"]

    def bounded_ref_and_commit_pages(self):
        # Valid packed refs exceed the old 4 MiB output cap. A one-item page
        # must ask Git for only that page, including when resolving HEAD.
        self.git("--git-dir=" + str(self.bare), "pack-refs", "--all")
        packed = self.bare / "packed-refs"
        existing = [line for line in packed.read_text().splitlines() if line and not line.startswith(("#", "^"))]
        long_tags = [f"{self.third} refs/tags/perf-{i:05d}-{'x' * 200}" for i in range(20000)]
        packed.write_text("# pack-refs with: peeled fully-peeled sorted\n" + "\n".join(sorted(existing + long_tags, key=lambda line: line.split(" ", 1)[1])) + "\n")
        assert packed.stat().st_size > 4 * 1024 * 1024, packed.stat().st_size
        first = self.document(self.repo_api("/refs?limit=1"))
        assert first["items"][0]["name"].startswith("refs/heads/"), first
        heads = self.document(self.repo_api("/refs?limit=1&prefix=refs/heads/"))
        assert heads["items"][0]["name"] == first["items"][0]["name"], heads
        second = self.document(self.repo_api("/refs?limit=1&after=refs/heads/feature"))
        assert second["items"][0]["name"] > "refs/heads/feature", second
        tail = self.document(self.repo_api("/refs?limit=1&after=refs/tags/perf-19998-" + "x" * 200))
        assert tail["items"][0]["name"].startswith("refs/tags/perf-19999-"), tail
        assert self.document(self.repo_api("/commits?limit=1"))["items"][0]["oid"] == self.third

        # A transparent Git wrapper records the actual number of cat-file
        # processes for a short and a longer page.
        for _ in range(20):
            self.git("commit", "--allow-empty", "-m", "batch-page", cwd=self.work)
        self.git("push", "origin", "HEAD:refs/heads/batch-page", cwd=self.work, token=self.alice)
        count_path = self.root / "cat-file-count"
        wrapper = self.root / "git-count-wrapper"
        wrapper.write_text("#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = cat-file ]; then echo x >> '" + str(count_path) + "'; fi\ndone\nexec /usr/bin/git \"$@\"\n")
        wrapper.chmod(0o700)
        self.stop()
        self.env["ROOTYARD_GIT"] = str(wrapper)
        self.start()
        for size in (1, 20):
            before = len(count_path.read_text().splitlines()) if count_path.exists() else 0
            page = self.document(self.repo_api(f"/commits?rev=refs/heads/batch-page&limit={size}"))
            assert len(page["items"]) == size
            after = len(count_path.read_text().splitlines())
            assert after - before == 2, (size, after - before)
        packed.write_text("# pack-refs with: peeled fully-peeled sorted\n" + "\n".join(existing) + "\n")

    def selective_ref_prefix(self):
        # A literal prefix narrower than a whole namespace must count the page
        # after the filter.  a1/a2 sort in front of the only z-matches, so
        # asking Git for the first page of heads and filtering that page
        # afterwards would have answered an empty page for refs/heads/z.
        def refs(prefix, limit=20, after=None):
            query = "limit=" + str(limit) + "&prefix=" + urllib.parse.quote(prefix, safe="")
            if after is not None:
                query += "&after=" + urllib.parse.quote(after, safe="")
            page = self.document(self.repo_api("/refs?" + query))
            return [item["name"] for item in page["items"]], page["next_after"]

        def walk(limit=1):
            collected, cursor = [], None
            while len(collected) <= 4096:
                query = "/refs?limit=" + str(limit)
                if cursor is not None:
                    query += "&after=" + urllib.parse.quote(cursor, safe="")
                page = self.document(self.repo_api(query))
                collected.extend(item["name"] for item in page["items"])
                cursor = page["next_after"]
                if cursor is None:
                    return collected, None
            return collected, cursor

        def write(ref_name, old_oid, new_oid):
            self.document(self.repo_api("/ref-transactions"), 200, method="POST", body={
                "updates": [{"ref_name": ref_name, "old_oid": old_oid, "new_oid": new_oid}]})

        def local(*args):
            return self.git("--git-dir=" + str(self.bare), *args)

        created = ("refs/heads/a1", "refs/heads/a2", "refs/heads/z1", "refs/heads/z2")
        # Refs Git returns but Browse must never show: reserve-managed proposal
        # refs inside the public heads namespace, plus a valid Git name past the
        # 1024-byte public limit.  They sort between a1 and z1, so a page that
        # counts raw Git records instead of public refs is truncated here.
        hidden = ("refs/heads/rootyard-proposals/one", "refs/heads/rootyard-proposals/two",
                  "refs/heads/long/" + "/".join(["x" * 200] * 6))
        try:
            for name in created:
                write(name, ZERO_OID, self.third)
            for name in hidden:
                local("update-ref", name, self.third)
            # A limit-1 walk of the namespace-wide listing must deliver every
            # public ref exactly once and hide the non-public ones.
            expected = sorted(
                name for name in local("for-each-ref", "--format=%(refname)").stdout.decode().splitlines()
                if name.startswith(("refs/heads/", "refs/tags/"))
                and len(name) <= 1024
                and not name.startswith(("refs/heads/rootyard-proposals/", "refs/rootyard-ci/")))
            collected, cursor = walk()
            assert cursor is None, collected
            assert collected == expected, (collected, expected)
            assert len(set(collected)) == len(collected), collected
            assert not [name for name in collected if name in hidden], collected
            names, cursor = refs("refs/heads/z", limit=1)
            assert names == ["refs/heads/z1"], names
            assert cursor == "refs/heads/z1", cursor
            # The cursor page continues inside the same literal prefix.
            names, cursor = refs("refs/heads/z", limit=1, after=cursor)
            assert names == ["refs/heads/z2"], names
            assert cursor is None, cursor
            # The full exact ref name is still a one-item page.
            assert refs("refs/heads/z2")[0] == ["refs/heads/z2"]
            # A narrow tag prefix keeps the existing tag and nothing else.
            assert refs("refs/tags/v1")[0] == ["refs/tags/v1.0"]
            assert refs("refs/heads/zzz")[0] == []
            # `*` is a literal byte here, never a Git pattern: as a pattern it
            # would match every branch, as a literal it matches none.
            assert refs("refs/heads/*")[0] == []
        finally:
            for name in hidden:
                local("update-ref", "-d", name)
            for name in created:
                write(name, self.third, ZERO_OID)
        # The fixture is back to the refs the other cases assert.
        assert refs("refs/heads/z")[0] == [] and refs("refs/heads/a")[0] == []

    def protected_writes_and_ref_ack_failure(self):
        self.git("push", "origin", self.third + ":refs/heads/release", cwd=self.work, token=self.alice)
        rule = {
            "required_approvals": 2, "required_checks": ["ci/required"],
            "require_fast_forward": True, "prevent_deletion": True,
            "prevent_force_push": True,
        }
        for branch in ("main", "release"):
            self.document(self.repo_api("/branch-rules"), 201, method="POST",
                          body={"branch_ref": "refs/heads/" + branch, **rule})
        assert self.git("push", "origin", "HEAD:refs/heads/main", cwd=self.work,
                        token=self.alice, check=False).returncode != 0
        assert self.git("push", "origin", ":refs/heads/release", cwd=self.work,
                        token=self.alice, check=False).returncode != 0
        self.document(self.repo_api("/ref-transactions"), 403, method="POST", body={
            "updates": [{"ref_name": "refs/heads/main", "old_oid": self.third,
                         "new_oid": self.second}]})
        assert self.git("--git-dir=" + str(self.bare), "rev-parse", "refs/heads/main").stdout.decode().strip() == self.third
        assert self.git("--git-dir=" + str(self.bare), "rev-parse", "refs/heads/release").stdout.decode().strip() == self.third
        self.git("push", "origin", "HEAD:refs/heads/unprotected", cwd=self.work, token=self.alice)

        before_marker = self.root / "fail-before-update"
        after_marker = self.root / "fail-after-update"
        wrapper = self.root / "git-fault-wrapper"
        wrapper.write_text("#!/bin/sh\nupdate=0\nfor a in \"$@\"; do [ \"$a\" = update-ref ] && update=1; done\n"
                           + "if [ \"$update\" = 1 ] && [ -f '" + str(before_marker) + "' ]; then exit 42; fi\n"
                           + "/usr/bin/git \"$@\"\nrc=$?\n"
                           + "if [ \"$update\" = 1 ] && [ \"$rc\" = 0 ] && [ -f '" + str(after_marker) + "' ]; then exit 42; fi\n"
                           + "exit \"$rc\"\n")
        wrapper.chmod(0o700)
        self.stop()
        self.env["ROOTYARD_GIT"] = str(wrapper)
        self.start()
        before_marker.touch()
        operations_before = int(self.sql("SELECT count(*) FROM git_operations WHERE repository_id='" + self.repo["id"] + "'"))
        self.document(self.repo_api("/ref-transactions"), 409, method="POST", body={
            "updates": [{"ref_name": "refs/heads/fault-before", "old_oid": ZERO_OID,
                         "new_oid": self.feature_oid}]})
        before_marker.unlink()
        assert self.git("--git-dir=" + str(self.bare), "show-ref", "--verify", "refs/heads/fault-before", check=False).returncode != 0
        assert self.sql("SELECT outcome FROM git_operations WHERE repository_id='" + self.repo["id"] + "' ORDER BY sequence DESC LIMIT 1") == "no_ref_changes"
        assert int(self.sql("SELECT count(*) FROM git_operations WHERE repository_id='" + self.repo["id"] + "'")) == operations_before + 1

        after_marker.touch()
        events_before = int(self.sql("SELECT count(*) FROM outbox_events WHERE repository_id='" + self.repo["id"] + "'"))
        payload = {"updates": [{"ref_name": "refs/heads/fault-after", "old_oid": ZERO_OID,
                                "new_oid": self.feature_oid}]}
        response = self.document(self.repo_api("/ref-transactions"), 200, method="POST",
                                 body=payload, extra_headers={"Idempotency-Key": "fault-after"})
        after_marker.unlink()
        assert self.git("--git-dir=" + str(self.bare), "rev-parse", "refs/heads/fault-after").stdout.decode().strip() == self.feature_oid
        assert int(self.sql("SELECT count(*) FROM outbox_events WHERE repository_id='" + self.repo["id"] + "'")) == events_before + 1
        self.stop()
        self.start()
        replay = self.document(self.repo_api("/ref-transactions"), 200, method="POST",
                               body=payload, extra_headers={"Idempotency-Key": "fault-after"})
        assert replay == response

    def commits_and_pagination(self):
        log_doc = self.document(self.repo_api("/commits"))
        assert [c["oid"] for c in log_doc["items"]] == [
            self.third,
            self.second,
            self.first,
        ]
        assert log_doc["next_after"] is None

        page1 = self.document(self.repo_api("/commits?limit=2"))
        assert [c["oid"] for c in page1["items"]] == [self.third, self.second]
        assert page1["next_after"] == 2
        page2 = self.document(self.repo_api(f"/commits?limit=2&after={page1['next_after']}"))
        assert [c["oid"] for c in page2["items"]] == [self.first]
        assert page2["next_after"] is None

        detail = self.document(self.repo_api(f"/commits/{self.third}"), token=self.reader)
        assert detail["oid"] == self.third
        assert detail["parents"] == [self.second]
        assert detail["author_name"] == "E2E"
        assert detail["author_email"] == "e2e@example.invalid"
        assert "third commit" in detail["subject"]
        assert "src/lib.rs" in detail["changed_paths"]
        assert "assets/logo.bin" in detail["changed_paths"]

        for bad_oid in ("not-an-oid", self.third.upper(), ZERO_OID):
            self.document(self.repo_api(f"/commits/{bad_oid}"), 400)
        self.document(self.repo_api(f"/commits/{'f' * 40}"), 404)
        self.document(self.repo_api(f"/commits/{detail['tree_oid']}"), 404)

    def tree_and_blob(self):
        root_tree = self.document(self.repo_api(f"/tree/{self.third}"))
        root_tree_q = self.document(self.repo_api(f"/tree?oid={self.third}"))
        assert root_tree == root_tree_q
        assert [e["name"] for e in root_tree["items"]] == [
            "assets",
            "hello.txt",
            "payload.bin",
            "src",
        ]

        # Cursor pagination on tree entries
        t_page1 = self.document(self.repo_api(f"/tree/{self.third}?limit=2"))
        assert [e["name"] for e in t_page1["items"]] == ["assets", "hello.txt"]
        assert t_page1["next_after"] == "hello.txt"
        t_page2 = self.document(
            self.repo_api(f"/tree/{self.third}?limit=2&after={t_page1['next_after']}")
        )
        assert [e["name"] for e in t_page2["items"]] == ["payload.bin", "src"]
        assert t_page2["next_after"] is None

        # Subdirectory tree inspection
        src_tree = self.document(self.repo_api(f"/tree/{self.third}?path=src"))
        assert [e["path"] for e in src_tree["items"]] == ["src/lib.rs", "src/sub"]
        sub_tree = self.document(self.repo_api(f"/tree/{self.third}?path=src/sub"))
        assert [e["path"] for e in sub_tree["items"]] == ["src/sub/mod.rs"]
        lib_blob_oid = src_tree["items"][0]["oid"]

        # Path traversal & non-tree rejections
        for bad_path in ("../etc/passwd", "/etc/passwd", "src/../lib.rs", "src//lib.rs", ".git/HEAD"):
            self.document(self.repo_api(f"/tree/{self.third}?path={bad_path}"), 400)
        self.document(self.repo_api(f"/tree/{self.third}?path=hello.txt"), 404)

        # UTF-8 text blob inspection by OID and by (commit, path)
        blob_by_oid = self.document(self.repo_api(f"/blob/{lib_blob_oid}"), token=self.reader)
        blob_by_path = self.document(
            self.repo_api(f"/blob?oid={self.third}&path=src/lib.rs"), token=self.reader
        )
        assert blob_by_oid == blob_by_path
        assert blob_by_oid["is_binary"] is False
        assert blob_by_oid["content"] == self.lib_rs_text
        assert base64.b64decode(blob_by_oid["content_base64"]) == self.lib_rs_text.encode()
        assert blob_by_oid["size"] == len(self.lib_rs_text.encode())

        # Binary blob inspection
        bin_blob = self.document(self.repo_api(f"/blob?oid={self.third}&path=assets/logo.bin"))
        assert bin_blob["is_binary"] is True
        assert bin_blob["content"] is None
        assert base64.b64decode(bin_blob["content_base64"]) == self.logo_bytes
        assert bin_blob["size"] == len(self.logo_bytes)

        # Non-blob OID rejected on /blob/{oid}
        self.document(self.repo_api(f"/blob/{self.third}"), 404)
        self.document(self.repo_api(f"/blob/{root_tree['tree_oid']}"), 404)

    def compare_revisions(self):
        cmp_ff = self.document(
            self.repo_api(f"/compare?base={self.first}&head={self.third}"),
            token=self.reader,
        )
        assert cmp_ff["base_oid"] == self.first
        assert cmp_ff["head_oid"] == self.third
        assert cmp_ff["merge_base_oid"] == self.first
        assert cmp_ff["ahead"] == 2
        assert cmp_ff["behind"] == 0
        assert cmp_ff["fast_forward"] is True
        assert [c["oid"] for c in cmp_ff["commits"]] == [self.third, self.second]
        assert "src/lib.rs" in cmp_ff["diff"]

        # Create divergent branch from self.second
        self.git("checkout", "-b", "divergent", self.second, cwd=self.work)
        (self.work / "divergent.txt").write_text("divergent line\n")
        self.git("add", "divergent.txt", cwd=self.work)
        self.git("commit", "-m", "divergent commit", cwd=self.work)
        self.divergent_oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/divergent", cwd=self.work, token=self.alice)

        cmp_div = self.document(
            self.repo_api(f"/compare?base={self.divergent_oid}&head={self.feature_oid}")
        )
        assert cmp_div["merge_base_oid"] == self.second
        assert cmp_div["ahead"] == 2
        assert cmp_div["behind"] == 1
        assert cmp_div["fast_forward"] is False

        self.document(self.repo_api(f"/compare?base=bad..spec&head={self.third}"), 400)
        self.document(self.repo_api(f"/compare?base={'f' * 40}&head={self.third}"), 404)

    def ref_transactions_atomic_cas(self):
        # 1. Atomic multi-ref creation
        res = self.document(
            self.repo_api("/ref-transactions"),
            200,
            method="POST",
            body={
                "storage_generation": 1,
                "atomic": True,
                "updates": [
                    {
                        "ref_name": "refs/heads/release",
                        "old_oid": ZERO_OID,
                        "new_oid": self.third,
                    },
                    {
                        "ref_name": "refs/tags/v2.0",
                        "old_oid": ZERO_OID,
                        "new_oid": self.third,
                    },
                ],
            },
        )
        assert res["atomic"] is True
        assert res["storage_generation"] == 1
        assert len(res["updates"]) == 2

        refs_now = {
            r["name"]: r["oid"] for r in self.document(self.repo_api("/refs"))["items"]
        }
        assert refs_now["refs/heads/release"] == self.third
        assert refs_now["refs/tags/v2.0"] == self.third

        # 2. All-or-nothing CAS conflict: update 1 valid, update 2 has wrong old_oid
        self.document(
            self.repo_api("/ref-transactions"),
            409,
            method="POST",
            body={
                "storage_generation": 1,
                "atomic": True,
                "updates": [
                    {
                        "ref_name": "refs/heads/release",
                        "old_oid": self.third,
                        "new_oid": self.feature_oid,
                    },
                    {
                        "ref_name": "refs/heads/main",
                        "old_oid": self.first,
                        "new_oid": self.feature_oid,
                    },
                ],
            },
        )
        refs_after_conflict = {
            r["name"]: r["oid"] for r in self.document(self.repo_api("/refs"))["items"]
        }
        assert refs_after_conflict["refs/heads/release"] == self.third
        assert refs_after_conflict["refs/heads/main"] == self.third

        # 3. Directory/File (D/F) prefix conflict
        self.document(
            self.repo_api("/ref-transactions"),
            (400, 409),
            method="POST",
            body={
                "storage_generation": 1,
                "atomic": True,
                "updates": [
                    {
                        "ref_name": "refs/heads/release/nested",
                        "old_oid": ZERO_OID,
                        "new_oid": self.third,
                    }
                ],
            },
        )

        # 4. Reserved CI namespace and HEAD deletion rejection
        self.document(
            self.repo_api("/ref-transactions"),
            (400, 403, 422),
            method="POST",
            body={
                "storage_generation": 1,
                "atomic": True,
                "updates": [
                    {
                        "ref_name": f"refs/rootyard-ci/jobs/{uuid.uuid4()}",
                        "old_oid": ZERO_OID,
                        "new_oid": self.third,
                    }
                ],
            },
        )
        self.document(
            self.repo_api("/ref-transactions"),
            (400, 409),
            method="POST",
            body={
                "storage_generation": 1,
                "atomic": True,
                "updates": [
                    {
                        "ref_name": "refs/heads/main",
                        "old_oid": self.third,
                        "new_oid": ZERO_OID,
                    }
                ],
            },
        )

        # 5. Stale storage_generation rejection
        self.document(
            self.repo_api("/ref-transactions"),
            409,
            method="POST",
            body={
                "storage_generation": 2,
                "atomic": True,
                "updates": [
                    {
                        "ref_name": "refs/heads/release",
                        "old_oid": self.third,
                        "new_oid": self.feature_oid,
                    }
                ],
            },
        )

        # 6. Deleting non-HEAD branch succeeds
        self.document(
            self.repo_api("/ref-transactions"),
            200,
            method="POST",
            body={
                "storage_generation": 1,
                "atomic": True,
                "updates": [
                    {
                        "ref_name": "refs/heads/release",
                        "old_oid": self.third,
                        "new_oid": ZERO_OID,
                    }
                ],
            },
        )

        # 7. Reliability & Outbox integration
        ops = self.document(self.repo_api("/operations"))
        assert any(o["id"] == res["operation_id"] and o["outcome"] == "recorded" for o in ops)
        self.cli("worker-once")
        projected = self.sql(
            f"SELECT oid FROM repository_ref_projection WHERE repository_id='{self.repo['id']}' AND ref_name='refs/tags/v2.0' AND NOT deleted"
        )
        assert projected == self.third, projected

    def idempotency_and_concurrency(self):
        idem_body = {
            "storage_generation": 1,
            "atomic": True,
            "updates": [
                {
                    "ref_name": "refs/heads/idem-branch",
                    "old_oid": ZERO_OID,
                    "new_oid": self.third,
                }
            ],
        }
        first_res = self.document(
            self.repo_api("/ref-transactions"),
            200,
            method="POST",
            body=idem_body,
            extra_headers={"Idempotency-Key": "tx-key-1"},
        )
        # Advance idem-branch to feature_oid, then replay tx-key-1
        self.document(
            self.repo_api("/ref-transactions"),
            200,
            method="POST",
            body={
                "storage_generation": 1,
                "atomic": True,
                "updates": [
                    {
                        "ref_name": "refs/heads/idem-branch",
                        "old_oid": self.third,
                        "new_oid": self.feature_oid,
                    }
                ],
            },
        )
        replay_res = self.document(
            self.repo_api("/ref-transactions"),
            200,
            method="POST",
            body=idem_body,
            extra_headers={"Idempotency-Key": "tx-key-1"},
        )
        assert replay_res == first_res

        # Conflicting payload with same Idempotency-Key returns 409
        self.document(
            self.repo_api("/ref-transactions"),
            409,
            method="POST",
            body={
                "storage_generation": 1,
                "atomic": True,
                "updates": [
                    {
                        "ref_name": "refs/heads/idem-branch",
                        "old_oid": ZERO_OID,
                        "new_oid": self.first,
                    }
                ],
            },
            extra_headers={"Idempotency-Key": "tx-key-1"},
        )

        for bad_key in ("", "x" * 129, "bad key"):
            self.document(
                self.repo_api("/ref-transactions"),
                400,
                method="POST",
                body=idem_body,
                extra_headers={"Idempotency-Key": bad_key},
            )

        # Concurrent 8-way CAS race on refs/heads/feature
        def attempt():
            status, _, _ = self.http(
                self.repo_api("/ref-transactions"),
                token=self.alice,
                method="POST",
                body={
                    "storage_generation": 1,
                    "atomic": True,
                    "updates": [
                        {
                            "ref_name": "refs/heads/feature",
                            "old_oid": self.feature_oid,
                            "new_oid": self.third,
                        }
                    ],
                },
            )
            return status

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(lambda _: attempt(), range(8)))
        assert statuses.count(200) == 1, statuses
        assert statuses.count(409) == 7, statuses

    def access_and_fences(self):
        read_paths = [
            self.repo_api("/refs"),
            self.repo_api("/commits"),
            self.repo_api(f"/commits/{self.third}"),
            self.repo_api(f"/tree/{self.third}"),
            self.repo_api(f"/blob?oid={self.third}&path=src/lib.rs"),
            self.repo_api(f"/compare?base={self.first}&head={self.third}"),
        ]
        for path in read_paths:
            self.expect(path, 401)
            self.document(path, 404, token=self.bob)
            self.document(path, 200, token=self.reader)

        tx_body = {
            "storage_generation": 1,
            "atomic": True,
            "updates": [
                {
                    "ref_name": "refs/heads/denied",
                    "old_oid": ZERO_OID,
                    "new_oid": self.third,
                }
            ],
        }
        self.expect(self.repo_api("/ref-transactions"), 401, method="POST", body=tx_body)
        self.document(
            self.repo_api("/ref-transactions"),
            403,
            token=self.reader,
            method="POST",
            body=tx_body,
        )
        self.document(
            self.repo_api("/ref-transactions"),
            404,
            token=self.bob,
            method="POST",
            body=tx_body,
        )

        # Repository recovering fence.  Use a manual reason, never the
        # reconciler-owned push ambiguity marker, because a concurrent worker
        # would legitimately auto-heal that marker and return 200 here.
        with self.recovery_fence():
            for path in read_paths:
                self.document(path, 409)
            self.document(self.repo_api("/ref-transactions"), 409, method="POST", body=tx_body)

    def object_format_and_negotiation(self):
        status_doc = self.document(self.repo_api("/object-format"), token=self.reader)
        assert status_doc["repository_id"] == self.repo["id"]
        assert status_doc["object_format"] == "sha1"
        assert status_doc["oid_hex_len"] == 40
        assert status_doc["raw_oid_bytes"] == 20
        assert status_doc["lfs_hash_algo"] == "sha256"
        assert status_doc["protocol_v2_supported"] is True
        assert "object-format=sha1" in status_doc["capabilities"]
        assert len(status_doc["compatibility_matrix"]) >= 4

        neg_ok = self.document(
            self.repo_api("/object-format/negotiate"),
            200,
            method="POST",
            body={
                "operation": "git-receive-pack",
                "protocol_version": 2,
                "client_object_format": "sha1",
                "client_capabilities": ["atomic", "ofs-delta", "object-format=sha1"],
                "client_agent": "git/2.43.0",
            },
        )
        assert neg_ok["admitted"] is True
        assert neg_ok["negotiated_object_format"] == "sha1"
        assert "atomic" in neg_ok["admitted_capabilities"]

        neg_conflict = self.document(
            self.repo_api("/object-format/negotiate"),
            409,
            method="POST",
            body={
                "operation": "git-receive-pack",
                "protocol_version": 2,
                "client_object_format": "sha256",
                "client_capabilities": ["atomic", "object-format=sha256"],
            },
        )
        assert neg_conflict["admitted"] is False
        assert neg_conflict["repository_object_format"] == "sha1"

        drill_doc = self.document(
            self.repo_api("/object-format/drill"),
            200,
            method="POST",
            body={"verify_lfs_interop": True},
        )
        assert drill_doc["passed"] is True
        assert drill_doc["sha1_drill"]["oid_hex_len"] == 40
        assert drill_doc["sha256_drill"]["oid_hex_len"] == 64
        assert len(drill_doc["sha256_drill"]["commit_oid"]) == 64
        assert drill_doc["cross_format_ref_tx_rejected"] is True
        assert drill_doc["lfs_sha256_in_both_formats"] is True

        # Mixed SHA-1 + SHA-256 ref transaction must be rejected with 409 Conflict
        self.document(
            self.repo_api("/ref-transactions"),
            409,
            method="POST",
            body={
                "storage_generation": 1,
                "atomic": True,
                "updates": [
                    {
                        "ref_name": "refs/heads/mixed-format",
                        "old_oid": ZERO_OID,
                        "new_oid": "a" * 64,
                    }
                ],
            },
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = BrowseHarness(args)
    success = False
    try:
        for name in CASE_NAMES:
            harness.case(name, getattr(harness, name))
        executed = [item["name"] for item in harness.results]
        if executed != list(CASE_NAMES):
            raise AssertionError(
                "native case inventory mismatch: expected "
                + repr(list(CASE_NAMES))
                + ", executed "
                + repr(executed)
            )
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(
                dict(name="cleanup", status="failed", error=harness.redact(error))
            )
            success = False
        binary_path = Path(args.binary)
        binary_sha = (
            hashlib.sha256(binary_path.read_bytes()).hexdigest()
            if binary_path.is_file()
            else None
        )
        report = dict(
            passed=success,
            case_count=len(CASE_NAMES),
            cases_run=len(harness.results),
            cases_passed=sum(1 for item in harness.results if item["status"] == "passed"),
            cases_failed=sum(1 for item in harness.results if item["status"] == "failed"),
            cases=harness.results,
            binary_sha256=binary_sha,
            limitations=[
                "Browse blob endpoint enforces a 4 MiB maximum object size cap.",
                "Ref transactions support up to 128 atomic ref updates per request.",
            ],
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
