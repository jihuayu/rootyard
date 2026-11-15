#!/usr/bin/env python3
"""Root-only real-service HTTP fixture for authorized retention-root browsing.

Source-only until Root executes it with the attested binary, real PostgreSQL/S3/
stock Git and the owned Blob profile. Repository, snapshot, root, pack and
receipt data come only through real API/A3/A4/A5/Git/root endpoints; no ready,
snapshot, root, receipt, grant or byte proof is fabricated.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import time
import urllib.parse
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import blob_only_service as blob  # noqa: E402
import refstore_snapshot_http as snapshot  # noqa: E402
from refstore_roots_http import RootsHttpHarness  # noqa: E402

ROOT_BROWSE_CASE = "roots_http_browse_selected_closures"
ROOT_BROWSE_SHA256_CASE = "roots_http_browse_sha256"
ROOT_SCOPE_FENCE_CASE = "roots_http_post_json_scope_revocation_fence"

LIMITATIONS = [
    "Root-only real-service HTTP fixture; only py-compiled/static-inspected by the implementation worker.",
    "Repositories, source snapshots, roots, pins, receipts and packs come from real API/A3/A4/A5/Git/root paths; no SQL or fabricated authority rows are used.",
    "The fixture does not claim current native/HTTP/CI acceptance, Root byte session proof, hosted CI inventory or full issue107 closure.",
    "Current repository realm/backend/cluster rejection is not forced here: the real production gate mutation seam needed to hold and narrow all of those live authorities is outside this HTTP fixture. Existing coordinator fixtures cover source-level realm/backend/anchor checks, not this HTTP race.",
    "Stored A5 snapshot/ref/pack prune is not forced by this fixture; the ByIntent source-metadata-miss fallback remains coordinator/source coverage, not this HTTP race.",
    "The post-JSON ContentsRead-removal case uses one test-only Python passthrough wrapper as the serve-blob ROOTYARD_GIT executor plus a run-owned deferred DELETE trigger/advisory blocker. The wrapper is not the production Git profile or binary receipt and is reported separately from the upstream stock Git hash. This is fixture timing, not a product pause hook or a broader fault matrix.",
    "If an owned blocker/request/server/trigger cannot be proven stopped, this fixture preserves its random schema and scratch for diagnosis and reports unresolved cleanup. Confirmed runs still use the normal schema-drop/removal cleanup; this is test reconciliation, not a product retention path.",
]


class RootBrowseHttpHarness(RootsHttpHarness):
    def _root_tree(self, repo, root, *, oid=None, path=None, after=None, limit=None, token=None):
        suffix = "/" + str(root) + "/tree"
        return self._request("GET", self._query_path(self._roots_path(repo, suffix), {
            "oid": oid, "path": path, "after": after, "limit": limit,
        }), token or self.alice)

    def _root_blob(self, repo, root, oid, *, path=None, token=None):
        suffix = "/" + str(root) + "/blob/" + urllib.parse.quote(str(oid), safe="")
        return self._request("GET", self._query_path(self._roots_path(repo, suffix), {"path": path}),
                             token or self.alice)

    def _selector_root(self, repo, key, source_snapshot_id, selector):
        create = self._intent(key, source_snapshot_id, selector=selector)
        status, receipt = self._create_root(repo, create)
        assert status == 201, (status, receipt)
        self._assert_receipt(receipt)
        return receipt["root_id"]

    def _assert_no_content(self, status, data):
        assert status >= 400, status
        assert set(data) == {"error"}, data
        assert "content" not in data and "content_base64" not in data and "items" not in data

    def roots_http_browse_selected_closures(self):
        repo, remote, work, _initial = self.seed("roots-http-browse")
        head = self.commit_files(work, "root browse contents", {
            "a.txt": "alpha\n",
            "dir/b.txt": "beta\n",
            "large.bin": b"x" * (1 << 20),
        })
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        assert self.remote_refs(remote).get("refs/heads/main") == head
        tag = self.git("tag", "-a", "root-browse-tag", "-m", "browse tag", cwd=work)
        assert tag.returncode == 0
        tag_oid = self.git("rev-parse", "refs/tags/root-browse-tag", cwd=work).stdout.decode().strip()
        pushed_tag = self.git("push", "origin", "refs/tags/root-browse-tag", cwd=work,
                              token=self.alice, check=False)
        assert pushed_tag.returncode == 0, blob.git_failure(pushed_tag)
        tree_oid = self.git("rev-parse", "HEAD^{tree}", cwd=work).stdout.decode().strip()
        blob_oid = self.git("rev-parse", "HEAD:a.txt", cwd=work).stdout.decode().strip()
        large_oid = self.git("rev-parse", "HEAD:large.bin", cwd=work).stdout.decode().strip()
        snapshot_id = self._create(repo, "roots-http-browse-source", 300)[1]["snapshot_id"]

        snapshot_root = self._selector_root(repo, "roots-http-browse-snapshot",
                                            snapshot_id, {"kind": "snapshot"})
        tree_root = self._selector_root(repo, "roots-http-browse-tree",
                                        snapshot_id, {"kind": "oids", "oids": [tree_oid]})
        blob_root = self._selector_root(repo, "roots-http-browse-blob",
                                        snapshot_id, {"kind": "oids", "oids": [blob_oid]})
        commit_root = self._selector_root(repo, "roots-http-browse-commit",
                                          snapshot_id, {"kind": "oids", "oids": [head]})
        tag_root = self._selector_root(repo, "roots-http-browse-tag-root",
                                       snapshot_id, {"kind": "oids", "oids": [tag_oid]})
        expired_source = self._create(repo, "roots-http-browse-expiring-source", 1)[1]
        expired_root = self._selector_root(repo, "roots-http-browse-expiring-root",
                                           expired_source["snapshot_id"], {"kind": "snapshot"})
        self._await_pin_expiry(repo, expired_source["pin_id"], "roots-http-browse-expiring-source")
        status, _ = self._release(repo, snapshot_id, "roots-http-browse-source-release", 1)
        assert status == 200, ("source pin release", status)

        baseline_ledger = self._ledger(repo)
        baseline_roots = self._root_rows(repo)

        # Snapshot root: exact captured HEAD, path and direct blob reads.
        status, snapshot_tree = self._root_tree(repo, snapshot_root)
        assert status == 200, (status, snapshot_tree)
        self._assert_tree_view(snapshot_tree)
        assert snapshot_tree["oid"] == head, snapshot_tree
        assert self._tree_item(snapshot_tree, "a.txt")["kind"] == "blob"
        status, snapshot_blob = self._root_blob(repo, snapshot_root, "HEAD", path="a.txt")
        assert status == 200 and snapshot_blob["content"] == "alpha\n", (status, snapshot_blob)
        self._assert_blob_view(snapshot_blob)
        status, snapshot_direct = self._root_blob(repo, snapshot_root, blob_oid)
        assert status == 200 and snapshot_direct["oid"] == blob_oid, (status, snapshot_direct)
        status, first_page = self._root_tree(repo, snapshot_root, limit=1)
        assert status == 200 and first_page["next_after"], (status, first_page)
        status, second_page = self._root_tree(repo, snapshot_root, after=first_page["next_after"], limit=1)
        assert status == 200 and second_page["items"], (status, second_page)
        status, invalid_path = self._root_tree(repo, snapshot_root, path="../escape")
        assert status == 400, (status, invalid_path)
        self._assert_no_content(status, invalid_path)

        # Snapshot bytes remain readable after the source pin is gone.
        status, snapshot_tree_after = self._root_tree(repo, snapshot_root)
        assert status == 200 and snapshot_tree_after["oid"] == head, (status, snapshot_tree_after)
        status, snapshot_blob_after = self._root_blob(repo, snapshot_root, blob_oid)
        assert status == 200 and snapshot_blob_after["content"] == "alpha\n", (status, snapshot_blob_after)
        status, expired_tree = self._root_tree(repo, expired_root)
        assert status == 200 and expired_tree["oid"] == head, (status, expired_tree)
        status, expired_blob = self._root_blob(repo, expired_root, blob_oid)
        assert status == 200 and expired_blob["content"] == "alpha\n", (status, expired_blob)

        # Explicit selected tree: whole selected closure, no original HEAD/refs.
        status, default_tree = self._root_tree(repo, tree_root)
        assert status == 404, ("oid-root HEAD was not unborn", status)
        self._assert_no_content(status, default_tree)
        status, selected_tree = self._root_tree(repo, tree_root, oid=tree_oid)
        assert status == 200 and selected_tree["tree_oid"] == tree_oid, (status, selected_tree)
        assert self._tree_item(selected_tree, "dir")["kind"] == "tree"
        status, descendant_blob = self._root_blob(repo, tree_root, tree_oid, path="dir/b.txt")
        assert status == 200 and descendant_blob["content"] == "beta\n", (status, descendant_blob)
        synthetic_ref = "refs/roots/oid/" + tree_oid
        status, synthetic = self._root_tree(repo, tree_root, oid=synthetic_ref)
        assert status == 200 and synthetic["tree_oid"] == tree_oid, (status, synthetic)
        status, synthetic_path = self._root_blob(repo, tree_root, synthetic_ref, path="a.txt")
        assert status == 200 and synthetic_path["content"] == "alpha\n", (status, synthetic_path)
        unknown_synthetic = "refs/roots/oid/" + ("f" * len(tree_oid))
        status, unknown = self._root_tree(repo, tree_root, oid=unknown_synthetic)
        assert status == 404, ("unknown synthetic ref used a native fallback", status)
        self._assert_no_content(status, unknown)
        wrong_format = "refs/roots/oid/" + ("a" * 64)
        status, wrong = self._root_tree(repo, tree_root, oid=wrong_format)
        assert status == 404, ("wrong-format synthetic ref matched installed SHA1 refs", status)
        self._assert_no_content(status, wrong)
        for rejected in [
            "refs/roots/oid/",
            "refs/roots/oid/" + "a" * 39,
            "refs/roots/oid/" + "0" * 40,
            "refs/roots/oid/" + "A" * 40,
            "refs/private/selected",
            "refs/roots/oid/" + tree_oid + "/child",
        ]:
            status, data = self._root_tree(repo, tree_root, oid=rejected, token=self.bob)
            assert status == 400, ("private/malformed root spec reached auth/materialization", rejected, status)
            self._assert_no_content(status, data)
        for direct in ["HEAD", "refs/heads/main", "refs/roots/oid/" + tree_oid]:
            status, data = self._root_blob(repo, snapshot_root, direct, token=self.bob)
            assert status == 400, ("direct no-path revision was not rejected", direct, status)
            self._assert_no_content(status, data)
        status, unselected_head = self._root_tree(repo, tree_root, oid=head)
        assert status == 404, ("unselected captured HEAD was reachable", status)
        self._assert_no_content(status, unselected_head)
        status, unselected_ref = self._root_tree(repo, tree_root, oid="main")
        assert status == 404, ("unselected captured ref was reachable", status)

        # Explicit selected commit and tag: descendants/history are in closure.
        status, commit_tree = self._root_tree(repo, commit_root, oid=head)
        assert status == 200 and commit_tree["oid"] == head, (status, commit_tree)
        status, commit_blob = self._root_blob(repo, commit_root, head, path="a.txt")
        assert status == 200 and commit_blob["content"] == "alpha\n", (status, commit_blob)
        status, tag_tree = self._root_tree(repo, tag_root, oid=tag_oid)
        assert status == 200 and tag_tree["oid"] == head, (status, tag_tree)
        status, tag_blob = self._root_blob(repo, tag_root, tag_oid, path="a.txt")
        assert status == 200 and tag_blob["content"] == "alpha\n", (status, tag_blob)

        # Explicit selected blob: only that blob, no invented HEAD/tree.
        status, blob_tree = self._root_tree(repo, blob_root)
        assert status == 404, (status, blob_tree)
        status, blob_direct = self._root_blob(repo, blob_root, blob_oid)
        assert status == 200 and blob_direct["oid"] == blob_oid, (status, blob_direct)
        status, blob_as_tree = self._root_tree(repo, blob_root, oid=blob_oid)
        assert status == 404, (status, blob_as_tree)
        status, blob_unsynced = self._root_tree(repo, blob_root, oid=head)
        assert status == 404, (status, blob_unsynced)

        # Effective retained blob ceiling (memory/144) refuses oversized bytes.
        status, oversize = self._root_blob(repo, snapshot_root, large_oid)
        assert status == 413, (status, oversize)
        self._assert_no_content(status, oversize)

        # Tokenless root browse must carry exactly the API Bearer challenge and
        # no-store/no-session, not the ordinary current-Browse behavior.
        self._assert_unauthorized("GET", self._roots_path(repo, "/" + str(snapshot_root) + "/tree"))
        self._assert_unauthorized("GET", self._roots_path(repo, "/" + str(snapshot_root) + "/blob/" + blob_oid))

        # Cross-repository, non-member, and current ContentsRead-removal denies.
        other_repo, _other_remote, _other_work, _other_oid = self.seed("roots-http-browse-other")
        status, data = self._root_tree(other_repo, snapshot_root)
        assert status == 404, ("cross-repository root was observable", status)
        self._assert_no_content(status, data)
        status, data = self._root_tree(repo, snapshot_root, token=self.bob)
        assert status == 404, ("non-member root was observable", status)
        self._assert_no_content(status, data)
        scoped = self._issue_scoped(repo, "roots-http-browse-scoped", ["contents_read", "contents_write"])
        status, _ = self._root_tree(repo, snapshot_root, token=scoped)
        assert status == 200, ("pre-narrow ContentsRead root read failed", status)
        self._patch_scope(repo, scoped, ["contents_write"])
        status, data = self._root_tree(repo, snapshot_root, token=scoped)
        assert status == 403, ("contents-read narrowing did not refuse root browse", status)
        self._assert_no_content(status, data)
        status, data = self._root_blob(repo, snapshot_root, blob_oid, token=scoped)
        assert status == 403, ("contents-read narrowing did not refuse root blob", status)
        self._assert_no_content(status, data)

        assert self._ledger(repo) == baseline_ledger, "root browse changed snapshot ledger rows"
        assert self._root_rows(repo) == baseline_roots, "root browse changed root rows"

        # Released root is refused without a body; this is the only later mutation.
        status, _ = self._delete_root(repo, snapshot_root, self._release_body("roots-http-browse-release"))
        assert status == 200, ("root release", status)
        status, released = self._root_tree(repo, snapshot_root)
        assert status == 409, (status, released)
        self._assert_no_content(status, released)
        self.no_bare(repo, "after retention root browse HTTP")
        return {"snapshot_root": snapshot_root, "tag_root": tag_root, "blob_root": blob_root}

    def roots_http_browse_sha256(self):
        repo, _remote, work, _oid = self.seed("roots-http-browse-sha256", object_format="sha256")
        head = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        tree_oid = self.git("rev-parse", "HEAD^{tree}", cwd=work).stdout.decode().strip()
        blob_oid = self.git("rev-parse", "HEAD:base.txt", cwd=work).stdout.decode().strip()
        assert len(head) == len(tree_oid) == len(blob_oid) == 64
        snapshot_id = self._create(repo, "roots-http-browse-sha256-source", 300)[1]["snapshot_id"]
        root = self._selector_root(repo, "roots-http-browse-sha256-root",
                                   snapshot_id, {"kind": "snapshot"})
        status, tree = self._root_tree(repo, root)
        assert status == 200 and tree["oid"] == head, (status, tree)
        status, blob_view = self._root_blob(repo, root, blob_oid)
        assert status == 200 and blob_view["oid"] == blob_oid, (status, blob_view)
        explicit = self._selector_root(repo, "roots-http-browse-sha256-tree", snapshot_id,
                                       {"kind": "oids", "oids": [tree_oid]})
        status, _ = self._root_tree(repo, explicit)
        assert status == 404, ("sha256 explicit root invented HEAD", status)
        status, explicit_tree = self._root_tree(repo, explicit, oid=tree_oid)
        assert status == 200 and explicit_tree["tree_oid"] == tree_oid, (status, explicit_tree)
        synthetic_ref = "refs/roots/oid/" + tree_oid
        status, synthetic_tree = self._root_tree(repo, explicit, oid=synthetic_ref)
        assert status == 200 and synthetic_tree["tree_oid"] == tree_oid, (status, synthetic_tree)
        return {"root": root, "explicit_tree": explicit}


    def _sql_until(self, query, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("fixture SQL observation deadline exhausted")
        env = self.env.copy()
        env["PGDATABASE"] = self.db
        try:
            completed = subprocess.run(
                ["psql", "--dbname", self.db, "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", query],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=remaining)
        except subprocess.TimeoutExpired:
            raise AssertionError("fixture SQL observation deadline exhausted") from None
        if completed.returncode != 0:
            raise AssertionError("fixture SQL observation failed")
        return completed.stdout.decode().strip()

    @staticmethod
    def _quote_ident(value):
        return '"' + str(value).replace('"', '""') + '"'

    def _scope_wrapper(self, race_dir, target_oid):
        race_dir.mkdir(mode=0o700, exist_ok=False)
        wrapper = race_dir / "trusted-git-passthrough.py"
        marker = race_dir / "entered"
        release = race_dir / "release"
        upstream = str(Path(self.profile.git).resolve())
        interpreter = str(Path(sys.executable).resolve())
        source = f"""#!{interpreter}
import os, sys, time
UPSTREAM = {upstream!r}
MARKER = {str(marker.resolve())!r}
RELEASE = {str(release.resolve())!r}
TARGET = {target_oid!r}
if len(sys.argv) >= 4 and sys.argv[-3:] == ["cat-file", "blob", TARGET]:
    try:
        fd = os.open(MARKER, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    deadline = time.monotonic() + 15.0
    while not os.path.exists(RELEASE):
        if time.monotonic() >= deadline:
            os._exit(1)
        time.sleep(0.02)
os.execv(UPSTREAM, [UPSTREAM, *sys.argv[1:]])
"""
        wrapper.write_text(source)
        wrapper.chmod(0o700)
        return wrapper, marker, release

    def _create_scope_gate(self, function, trigger, target_token_id, repository_id, key, deadline):
        schema = self._quote_ident(self.schema)
        function_sql = schema + "." + self._quote_ident(function)
        trigger_sql = self._quote_ident(trigger)
        table = schema + ".token_repository_scopes"
        self._sql_until(
            "CREATE OR REPLACE FUNCTION " + function_sql + "() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN "
            "IF OLD.token_id = '" + str(uuid.UUID(target_token_id)) + "'::uuid "
            "AND OLD.repository_id = '" + str(uuid.UUID(repository_id)) + "'::uuid "
            "AND OLD.action = 'contents_read' THEN "
            "PERFORM pg_advisory_xact_lock(" + str(int(key)) + "); "
            "END IF; "
            "RETURN OLD; "
            "END $$; "
            "CREATE CONSTRAINT TRIGGER " + trigger_sql + " AFTER DELETE ON " + table + " "
            "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION " + function_sql + "();", deadline)

    def _drop_scope_gate(self, function, trigger, deadline):
        schema = self._quote_ident(self.schema)
        self._sql_until(
            "SET lock_timeout='5s'; "
            "DROP TRIGGER IF EXISTS " + self._quote_ident(trigger) + " ON " + schema + ".token_repository_scopes; "
            "DROP FUNCTION IF EXISTS " + schema + "." + self._quote_ident(function) + "();", deadline)

    def _owned_blocker_pid(self, application_name, key, deadline):
        classid, objid = self._advisory_key_parts(key)
        return self._sql_until(
            "SELECT a.pid FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid "
            "WHERE a.datname=current_database() AND a.application_name='"
            + str(application_name).replace("'", "''") + "' AND l.locktype='advisory' AND l.granted "
            "AND l.classid::bigint=" + str(classid) + " AND l.objid::bigint=" + str(objid)
            + " AND l.objsubid=1 LIMIT 1", deadline)

    def _stop_local_process(self, process, deadline):
        if process is None:
            return True
        if process.poll() is not None:
            return True
        try:
            process.terminate()
        except Exception:
            pass
        remaining = max(0.1, deadline - time.monotonic())
        try:
            process.wait(timeout=min(5.0, remaining))
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=min(5.0, max(0.1, deadline - time.monotonic())))
            except Exception:
                return process.poll() is not None
        except Exception:
            return process.poll() is not None
        return process.poll() is not None

    def _start_owned_blocker(self, key, application_name, deadline):
        env = self.env.copy()
        env["PGDATABASE"] = self.db
        env["PGAPPNAME"] = application_name
        process = subprocess.Popen(
            ["psql", "--dbname", self.db, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c",
             "SET application_name='" + application_name + "'; "
             "SELECT pg_advisory_lock(" + str(key) + "); SELECT pg_sleep(300);"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        self._root_scope_blocker = process
        try:
            self._wait_until(lambda: self._owned_blocker_pid(application_name, key, deadline),
                             deadline, "fixture advisory blocker did not hold the exact key")
            return process
        except Exception:
            if not self._release_owned_blocker(process, application_name, key, deadline):
                self._root_scope_unresolved = {
                    "reason": "owned blocker startup could not be reconciled",
                    "blocker": process,
                }
            raise

    def _release_owned_blocker(self, process, application_name, key, deadline):
        self._root_scope_blocker = process
        local_stopped = False
        lock_gone = False
        pid = None
        try:
            try:
                pid = self._owned_blocker_pid(application_name, key, deadline)
            except Exception:
                pass
            if pid:
                try:
                    self._sql_until("SELECT pg_terminate_backend(" + str(int(pid)) + ")", deadline)
                except Exception:
                    pass
        finally:
            # Popen ownership is retained until the local process is confirmed
            # dead/reaped, independent of SQL lookup or backend termination.
            try:
                local_stopped = self._stop_local_process(process, deadline)
            except Exception:
                local_stopped = False
        while time.monotonic() < deadline:
            try:
                if not self._owned_blocker_pid(application_name, key, deadline):
                    lock_gone = True
                    break
            except Exception:
                pass
            time.sleep(0.05)
        if local_stopped and lock_gone:
            self._root_scope_blocker = None
            return True
        self._root_scope_blocker = process
        return False

    def _waiting_commit_pid_until(self, key, deadline):
        classid, objid = self._advisory_key_parts(key)
        return self._sql_until(
            "SELECT a.pid FROM pg_stat_activity a "
            "JOIN pg_locks l ON l.pid=a.pid AND l.locktype='advisory' "
            "WHERE a.datname=current_database() AND a.state='active' "
            "AND regexp_replace(a.query, '\\s+', '', 'g') IN ('COMMIT','COMMIT;') "
            "AND a.wait_event_type='Lock' AND a.wait_event='advisory' "
            "AND l.granted=false AND l.classid::bigint=" + str(classid)
            + " AND l.objid::bigint=" + str(objid) + " AND l.objsubid=1 LIMIT 1", deadline)

    def _touch_gate(self, path):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            pass

    def _wait_until(self, predicate, deadline, message):
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.05)
        raise AssertionError(message)

    def _final_auth_waiting_on_patch(self, patch_pid, deadline):
        return int(self._sql_until(
            "SELECT count(*) FROM pg_stat_activity a "
            "WHERE a.datname=current_database() AND a.state='active' "
            "AND a.wait_event_type='Lock' "
            "AND a.query LIKE '%SELECT t.read_only, t.is_restricted%' "
            "AND a.query LIKE '%FOR SHARE OF t%' "
            "AND " + str(int(patch_pid)) + " = ANY(pg_blocking_pids(a.pid))", deadline)) == 1

    def _wait_future(self, future, deadline):
        remaining = max(0.1, deadline - time.monotonic())
        return future.result(timeout=remaining)

    def cleanup(self):
        # Preserve both the run-owned random schema and scratch when any owned
        # blocker/request/server/trigger could not be proven stopped. A normal
        # confirmed run retains the existing e2e cleanup (schema drop/removal).
        if getattr(self, "_root_scope_unresolved", None) is not None:
            try:
                self.stop()
            except Exception:
                pass
            return
        super().cleanup()

    def roots_http_post_json_scope_revocation_fence(self):
        repo, remote, work, _head = self.seed("roots-http-scope-fence")
        head = self.commit_files(work, "root post-json fence", {"fence.txt": "post-json fence\n"})
        pushed = self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice, check=False)
        assert pushed.returncode == 0, blob.git_failure(pushed)
        assert self.remote_refs(remote).get("refs/heads/main") == head
        target_oid = self.git("rev-parse", "HEAD:fence.txt", cwd=work).stdout.decode().strip()
        snapshot_id = self._create(repo, "roots-http-scope-snapshot", 300)[1]["snapshot_id"]
        root_id = self._selector_root(repo, "roots-http-scope-root", snapshot_id, {"kind": "snapshot"})
        target = self._issue_scoped(repo, "roots-http-scope-target", ["contents_read", "contents_write"])
        fixture_hash = blob.sha256_file(Path(__file__).resolve())
        upstream_hash = blob.sha256_file(Path(self.profile.git))
        race_dir = self.root / ("root-scope-fence-" + uuid.uuid4().hex)
        wrapper, marker, release = self._scope_wrapper(race_dir, target_oid)
        wrapper_hash = blob.sha256_file(wrapper)
        key = uuid.uuid4().int & 0x7FFFFFFFFFFFFFFF
        if key == 0:
            key = 1
        application_name = "rootyard-root-scope-" + uuid.uuid4().hex
        function = "rootyard_root_scope_gate_" + uuid.uuid4().hex
        trigger = "rootyard_root_scope_trigger_" + uuid.uuid4().hex
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        blocker = None
        trigger_created = False
        gate_released = False
        blocker_released = False
        trigger_dropped = False
        root_future = None
        patch_future = None
        deadline = time.monotonic() + 2.0
        self._root_scope_unresolved = None
        self._root_scope_blocker = None
        self._root_scope_executor = executor
        try:
            self.stop()
            self.start(overrides={"ROOTYARD_GIT": str(wrapper)}, label="root-scope-fence")
            trigger_deadline = time.monotonic() + 10.0
            trigger_created = True
            self._create_scope_gate(function, trigger, target["id"], repo["id"], key, trigger_deadline)
            blocker = self._start_owned_blocker(key, application_name, trigger_deadline)
            deadline = time.monotonic() + 16.0
            root_future = executor.submit(self._root_blob, repo, root_id, target_oid, token=target)
            self._wait_until(lambda: marker.exists(), deadline, "terminal root-blob Git gate was not entered")
            assert not root_future.done(), "root blob returned before the terminal Git gate"
            patch_future = executor.submit(self._patch_scope, repo, target, ["contents_write"])
            patch_pid = self._wait_until(lambda: self._waiting_commit_pid_until(key, deadline),
                                         deadline, "PATCH COMMIT never waited on the scope-delete trigger")
            assert not patch_future.done(), "PATCH returned before its deferred COMMIT fence"
            self._touch_gate(release)
            gate_released = True
            self._wait_until(lambda: self._final_auth_waiting_on_patch(int(patch_pid), deadline),
                             deadline, "final root authorization did not wait on the PATCH token lock")
            assert not patch_future.done(), "PATCH committed before final-auth observation"
            assert not root_future.done(), "root blob returned before the final-auth fence"
            observed_terminal_gate = True
            observed_final_auth = True
            if not self._release_owned_blocker(blocker, application_name, key, deadline):
                self._root_scope_unresolved = {
                    "reason": "owned blocker release could not be proven",
                    "blocker": blocker,
                }
                raise AssertionError("root scope fence cleanup unresolved")
            blocker = None
            blocker_released = True
            patch_view = self._wait_future(patch_future, deadline)
            get_status, get_data, _headers = self._wait_future(root_future, deadline)
            assert get_status == 403, ("root blob was not denied after committed scope narrowing", get_status)
            assert set(get_data) == {"error"}, get_data
            assert "content" not in get_data and "content_base64" not in get_data and "items" not in get_data
            grants = [grant for grant in patch_view.get("repository_grants", [])
                      if str(grant.get("repository_id")) == str(repo["id"])]
            assert len(grants) == 1, grants
            actions = set(grants[0].get("actions", []))
            assert actions == {"contents_write"}, actions
            self._drop_scope_gate(function, trigger, time.monotonic() + 10.0)
            trigger_created = False
            trigger_dropped = True
            self._root_scope_unresolved = None
            self._root_scope_blocker = None
            return {
                "observed_terminal_gate": observed_terminal_gate,
                "observed_final_auth_blocked_by_patch": observed_final_auth,
                "patch_status": 200,
                "get_status": get_status,
                "error_only_response": True,
                "test_only_wrapper_sha256": wrapper_hash,
                "upstream_stock_git_sha256": upstream_hash,
                "root_browse_fixture_sha256": fixture_hash,
                "cleanup_gate_released": gate_released,
                "cleanup_blocker_released": blocker_released,
                "cleanup_trigger_dropped": trigger_dropped,
            }
        finally:
            cleanup_deadline = time.monotonic() + 10.0
            cleanup_errors = []
            unresolved_reasons = []
            try:
                self._touch_gate(release)
                gate_released = True
            except Exception:
                cleanup_errors.append("wrapper gate release")
            if blocker is not None:
                try:
                    if self._release_owned_blocker(blocker, application_name, key, cleanup_deadline):
                        blocker = None
                        blocker_released = True
                    else:
                        self._root_scope_blocker = blocker
                        unresolved_reasons.append("owned blocker")
                except Exception:
                    self._root_scope_blocker = blocker
                    unresolved_reasons.append("owned blocker")
            unfinished = []
            for label, future in (("root request", root_future), ("PATCH request", patch_future)):
                if future is None:
                    continue
                if not future.done():
                    try:
                        self._wait_future(future, cleanup_deadline)
                    except Exception:
                        pass
                if not future.done():
                    unfinished.append(label)
            if unfinished:
                try:
                    self.stop(hard=True)
                except Exception:
                    cleanup_errors.append("owned server stop")
            still_unfinished = []
            for label, future in (("root request", root_future), ("PATCH request", patch_future)):
                if future is None or future.done():
                    continue
                try:
                    self._wait_future(future, cleanup_deadline)
                except Exception:
                    pass
                if not future.done():
                    still_unfinished.append(label)
            unresolved_reasons.extend(label + " not settled" for label in still_unfinished)
            if still_unfinished:
                try:
                    executor.shutdown(wait=False)
                except Exception:
                    cleanup_errors.append("executor shutdown")
                self._root_scope_executor = executor
            else:
                try:
                    executor.shutdown(wait=True)
                except Exception:
                    cleanup_errors.append("executor shutdown")
                self._root_scope_executor = None
            if trigger_created:
                try:
                    self._drop_scope_gate(function, trigger, cleanup_deadline)
                    trigger_dropped = True
                    trigger_created = False
                except Exception:
                    unresolved_reasons.append("scope trigger cleanup")
            if cleanup_errors:
                unresolved_reasons.extend(cleanup_errors)
            existing = getattr(self, "_root_scope_unresolved", None)
            if existing is not None:
                unresolved_reasons.append(str(existing.get("reason", "preexisting unresolved state")))
            if unresolved_reasons:
                self._root_scope_unresolved = {
                    "reason": "; ".join(unresolved_reasons),
                    "blocker": blocker,
                }
                raise AssertionError("root scope fence cleanup unresolved")
            self._root_scope_unresolved = None
            self._root_scope_blocker = None
            self._root_scope_executor = None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="absolute attested rootyard binary")
    parser.add_argument("--git", help="absolute trusted Git (defaults to ROOTYARD_GIT)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args(argv)
    env = os.environ.copy()
    try:
        profile = snapshot.SnapshotHttpProfile(str(Path(args.binary).resolve()), args.git, env)
        blob_profile = blob.check_blob_profile(env)
        blob.need(env.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
        blob.need(__import__("shutil").which("psql"), "psql is required")
    except Exception as error:
        blob.write_report(args.report, {
            "kind": "rootyard/refstore-root-browse-http", "passed": False,
            "preflight_failed": True, "error": str(error), "cases": [],
            "expected_cases": [], "limitations": LIMITATIONS,
        })
        print("preflight failed: " + str(error), file=sys.stderr)
        return 2
    args.binary = str(profile.binary)
    harness = RootBrowseHttpHarness(args, profile, blob_profile)
    cases = [ROOT_BROWSE_CASE, ROOT_BROWSE_SHA256_CASE, ROOT_SCOPE_FENCE_CASE]
    success = False
    try:
        harness.prepare()
        for name in cases:
            harness.case(name, getattr(harness, name))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append({"name": "cleanup", "status": "failed", "error": harness.redact(error)})
            success = False
        report = blob.build_report(harness, profile, blob_profile, cases, success)
        report["kind"] = "rootyard/refstore-root-browse-http"
        report["limitations"] = LIMITATIONS
        blob.write_report(args.report, report)
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
