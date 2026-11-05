#!/usr/bin/env python3
"""Separate primary/read-mirror Git integration tests on an isolated SQL schema.

Requires ROOTYARD_TEST_DATABASE_URL for a disposable dedicated PostgreSQL database.
No external hosts, real credentials, deployments, or production repositories are used.
"""
import argparse
import base64
import http.client
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import uuid

from e2e import Harness


class MirrorHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.mirror_proc = None
        self.mirror_log = None
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.mirror_base = f"http://127.0.0.1:{port}"
        self.mirror_env = self.env.copy()
        self.mirror_env.update(ROOTYARD_BIND=f"127.0.0.1:{port}",
                               ROOTYARD_DATA_DIR=str(self.root / "mirror-data"),
                               ROOTYARD_PRIMARY_URL=self.base)

    def mirror_http(self, path, token=None, method="GET", body=None, basic=False):
        headers = {}
        if token:
            headers["Authorization"] = ("Basic " + base64.b64encode(
                (token["username"] + ":" + token["token"]).encode()).decode()
                if basic else "Bearer " + token["token"])
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        # Direct HTTP deliberately does not follow redirects: a fallback to
        # the primary must not accidentally pass a mirror assertion.
        connection = http.client.HTTPConnection(self.mirror_env["ROOTYARD_BIND"], timeout=20)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def mirror_expect(self, path, codes, **kwargs):
        status, body, headers = self.mirror_http(path, **kwargs)
        assert status in (codes if isinstance(codes, tuple) else (codes,)), f"Mirror expected {codes}, got {status}: {body[:300]!r}"
        assert "location" not in {name.lower() for name in headers}, "Mirror must not redirect"
        return body

    def start_mirror(self):
        self.mirror_log = open(self.root / "mirror.log", "ab")
        self.mirror_proc = subprocess.Popen([self.args.binary, "serve-mirror"], env=self.mirror_env,
                                            stdout=self.mirror_log, stderr=self.mirror_log,
                                            start_new_session=True)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert self.mirror_proc.poll() is None, "Mirror exited; inspect retained mirror.log"
            try:
                if self.mirror_http("/health/ready")[0] == 200:
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(.1)
        raise AssertionError("Mirror readiness timeout")

    def stop_mirror(self):
        if self.mirror_proc:
            if self.mirror_proc.poll() is None:
                os.killpg(self.mirror_proc.pid, signal.SIGTERM)
                try:
                    self.mirror_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(self.mirror_proc.pid, signal.SIGKILL)
                    self.mirror_proc.wait()
            self.mirror_proc = None
        if self.mirror_log:
            self.mirror_log.close()
            self.mirror_log = None

    def path(self, oid):
        return f"/ci/{oid}/git/alice/demo.git"

    def advertise(self, oid):
        return self.path(oid) + "/info/refs?service=git-upload-pack"

    def sync(self, token=None, codes=200):
        return self.mirror_expect("/api/repos/alice/demo/mirror-sync", codes,
                                  token=token or self.reader, method="POST", body=b"")

    def clone_at(self, oid, name):
        target = self.root / name
        self.git("clone", self.mirror_base + self.path(oid), str(target), token=self.reader)
        assert self.git("rev-parse", "HEAD", cwd=target).stdout.decode().strip() == oid
        assert self.git("symbolic-ref", "HEAD", cwd=target).stdout.strip() == b"refs/heads/main"
        self.git("fsck", "--full", cwd=target)
        return target

    def apply_staged_migration_030(self):
        sql_path = Path(__file__).resolve().parents[1] / "src" / "mirror" / "030_ci_mirror.sql"
        if not sql_path.is_file():
            sql_path = Path(__file__).resolve().parents[1] / "migrations" / "030_ci_mirror.sql"
        if self.sql("SELECT to_regclass('ci_mirror_evictions') IS NOT NULL") != "t":
            self.sql(sql_path.read_text())

    def create_pin(self, oid=None, job=None, generation=1, token=None, codes=(200, 201)):
        body = dict(
            job_id=job or str(uuid.uuid4()),
            target_oid=oid or self.first,
            storage_generation=generation,
        )
        raw = self.expect(
            "/api/repos/alice/demo/ci-pins",
            codes,
            token=token or self.alice,
            method="POST",
            body=body,
        )
        ok_codes = codes if isinstance(codes, tuple) else (codes,)
        return json.loads(raw) if (200 in ok_codes or 201 in ok_codes) else raw

    def list_pins(self, token=None, codes=200):
        raw = self.expect(
            "/api/repos/alice/demo/ci-pins",
            codes,
            token=token or self.reader,
            method="GET",
        )
        return json.loads(raw) if codes == 200 else raw

    def release_pin(self, job, method="DELETE", token=None, codes=200, body=None):
        path = (
            f"/api/repos/alice/demo/ci-pins/{job}"
            if method == "DELETE"
            else f"/api/repos/alice/demo/ci-pins/{job}/release"
        )
        req_body = body if body is not None else (b"" if method == "POST" else None)
        raw = self.expect(
            path,
            codes,
            token=token or self.alice,
            method=method,
            body=req_body,
        )
        return json.loads(raw) if codes == 200 else raw

    def evict(self, endpoint="mirror-evict", body=None, token=None, codes=200):
        raw = self.mirror_expect(
            f"/api/repos/alice/demo/{endpoint}",
            codes,
            token=token or self.alice,
            method="POST",
            body=body if body is not None else {},
        )
        return json.loads(raw) if codes == 200 else raw

    def mirror_status(self, token=None, codes=200):
        raw = self.mirror_expect(
            "/api/repos/alice/demo/mirror-status",
            codes,
            token=token or self.reader,
            method="GET",
        )
        return json.loads(raw) if codes == 200 else raw

    def mirror_metrics(self, codes=200):
        status, body, headers = self.mirror_http("/metrics", method="GET")
        expected = codes if isinstance(codes, tuple) else (codes,)
        assert status in expected, (status, body[:300])
        return status, body.decode("utf-8", errors="replace"), headers

    def setup_mirror(self):
        self.setup()
        self.api()
        self.roundtrip()
        self.start_mirror()
        self.mirror_expect("/health/live", 200)

    def sync_and_pinned_clone(self):
        self.mirror_expect(self.advertise(self.first), 409, token=self.reader)
        result = json.loads(self.sync())
        assert result["repository_id"] == self.repo["id"]
        assert result["storage_generation"] == 1 and result["snapshot"]
        self.clone_at(self.first, "pinned-first")
        self.pinned_second = self.clone_at(self.second, "pinned-second")
        refs = self.git("ls-remote", self.mirror_base + self.path(self.first), token=self.reader).stdout.decode().splitlines()
        assert set(refs) == {self.first + "\tHEAD", self.first + "\trefs/heads/main"}, refs
        # Advance the primary after pinning. A normal clone must still land on
        # the requested historical commit, never today's primary branch tip.
        (self.work / "hello.txt").write_text("third\n")
        self.git("commit", "-am", "third", cwd=self.work)
        self.third = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
        self.mirror_expect(self.advertise(self.third), 409, token=self.reader)
        self.sync()
        self.clone_at(self.first, "pinned-first-after-sync")
        self.git("fetch", "origin", cwd=self.pinned_second, token=self.reader)
        assert self.git("rev-parse", "origin/main", cwd=self.pinned_second).stdout.decode().strip() == self.second
        self.clone_at(self.third, "pinned-third")
        self.mirror_expect(self.advertise("f" * 40), 409, token=self.reader)
        blob = self.git("rev-parse", self.first + ":hello.txt", cwd=self.work).stdout.decode().strip()
        self.mirror_expect(self.advertise(blob), 409, token=self.reader)
        for invalid in (self.first.upper(), self.first[:12], "not-an-oid"):
            self.mirror_expect(self.advertise(invalid), (400, 404), token=self.reader)
        return {"ordinary_clone_exact_head": True, "fetch_remains_pinned": True}

    def pin_survives_source_deletion(self):
        branch = "ci-pin-retention-fixture"
        self.git("checkout", "-b", branch, cwd=self.work)
        try:
            self.git("commit", "--allow-empty", "-m", "unique pinned branch", cwd=self.work)
            oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
            self.git("push", "origin", f"HEAD:refs/heads/{branch}", cwd=self.work, token=self.alice)
        finally:
            self.git("checkout", "main", cwd=self.work)
        self.sync()
        clone = self.clone_at(oid, "unique-branch-before-deletion")
        self.git("push", "origin", f":refs/heads/{branch}", cwd=self.work, token=self.alice)
        assert not self.git("ls-remote", self.remote, f"refs/heads/{branch}", token=self.reader).stdout.strip()
        latest = json.loads(self.sync())
        latest_bare = (self.root / "mirror-data" / "repos" / self.repo["id"] /
                       latest["snapshot"] / "repository.git")
        assert self.git("--no-replace-objects", "--git-dir=" + str(latest_bare),
                        "cat-file", "-e", oid, check=False).returncode != 0, "Fixture commit still exists in latest snapshot"
        self.clone_at(oid, "unique-branch-after-deletion")
        self.git("fetch", "origin", cwd=clone, token=self.reader)
        assert self.git("rev-parse", "origin/main", cwd=clone).stdout.decode().strip() == oid
        return {"deleted_source_branch_absent": True, "new_snapshot_lacks_commit": True,
                "earlier_pin_still_clones_and_fetches": True}

    def replacement_refs_cannot_spoof_type(self):
        blob = self.git("--no-replace-objects", "rev-parse", self.third + ":hello.txt", cwd=self.work).stdout.decode().strip()
        tree = self.git("--no-replace-objects", "rev-parse", self.third + "^{tree}", cwd=self.work).stdout.decode().strip()
        actual_commit = self.run(["git", "--no-replace-objects", "commit-tree", tree, "-p", self.third],
                                 cwd=self.work, data=b"replacement type fixture\n").stdout.decode().strip()
        branch = "refs/heads/ci-replacement-fixture"
        replace_refs = [f"refs/replace/{oid}" for oid in (blob, tree, actual_commit)]
        self.git("--no-replace-objects", "push", "origin", f"{actual_commit}:{branch}",
                 f"{self.third}:{replace_refs[0]}", f"{self.third}:{replace_refs[1]}",
                 f"{blob}:{replace_refs[2]}", cwd=self.work, token=self.alice)
        try:
            result = json.loads(self.sync())
            snapshot = (self.root / "mirror-data" / "repos" / self.repo["id"] /
                        result["snapshot"] / "repository.git")
            # Establish that the adversarial refs really reached the snapshot.
            for ref, replacement in zip(replace_refs, (self.third, self.third, blob)):
                assert self.git("--no-replace-objects", "--git-dir=" + str(snapshot),
                                "rev-parse", ref).stdout.decode().strip() == replacement
            self.mirror_expect(self.advertise(blob), 409, token=self.reader)
            self.mirror_expect(self.advertise(tree), 409, token=self.reader)
            self.clone_at(actual_commit, "real-commit-replaced-with-blob")
        finally:
            self.git("--no-replace-objects", "push", "origin", *[":" + ref for ref in replace_refs],
                     ":" + branch, cwd=self.work, token=self.alice)
            self.sync()
        return {"blob_and_tree_replacements_rejected": True, "real_commit_not_hidden_by_replacement": True}

    def corrupted_pin_fails_closed(self):
        root = self.root / "mirror-data" / "repos" / self.repo["id"]
        metadata = json.loads((root / f"pin-1-{self.first}.json").read_text())
        pin = root / metadata["snapshot"] / "pins" / f"{self.first}.git"
        # Mutate only a stopped mirror's synthetic fixture, and restore it in
        # finally. The mirror must never serve the substituted commit.
        for filename, replacement in (("HEAD", f"{self.third}\n"),
                                      ("refs/heads/main", f"{self.third}\n")):
            path = pin / filename
            original = path.read_bytes()
            self.stop_mirror()
            try:
                path.write_text(replacement)
                self.start_mirror()
                self.mirror_expect(self.advertise(self.first), 503, token=self.reader)
            finally:
                self.stop_mirror()
                path.write_bytes(original)
                self.start_mirror()
        self.clone_at(self.first, "restored-pin-after-corruption")
        return {"changed_pin_head_rejected": True, "changed_pin_ref_rejected": True}

    def authorization_and_writes(self):
        advertisement = self.advertise(self.first)
        self.mirror_expect(advertisement, 401)
        self.mirror_expect(advertisement, 401, token={"token": "invalid"})
        self.mirror_expect(advertisement, (403, 404), token=self.bob)
        self.sync(token=self.bob, codes=(403, 404))
        self.mirror_expect("/api/repos/alice/demo/mirror-sync", 401, method="POST", body=b"")
        revoked = self.account("create-token", "alice", "--read-only")
        self.mirror_expect(advertisement, 200, token=revoked)
        self.cli("revoke-token", revoked["token_id"])
        self.mirror_expect(advertisement, 401, token=revoked)
        self.mirror_expect(self.path(self.first) + "/git-upload-pack", 401, token=revoked,
                           method="POST", body=b"0000")
        self.sync(token=revoked, codes=401)
        for path, method in ((self.path(self.first) + "/info/refs?service=git-receive-pack", "GET"),
                             (self.path(self.first) + "/git-receive-pack", "POST")):
            self.mirror_expect(path, (403, 404, 405), token=self.alice, method=method,
                               body=b"0000" if method == "POST" else None)
        self.mirror_expect("/git/alice/demo.git/info/refs?service=git-upload-pack", (403, 404), token=self.reader)
        self.mirror_expect("/api/repos", (403, 404, 405), token=self.alice, method="POST", body={"name": "forbidden"})
        assert not self.git("push", self.mirror_base + self.path(self.first), "HEAD:main", cwd=self.work,
                            token=self.alice, check=False).returncode == 0

    def local_pack_and_failed_sync(self):
        self.stop()
        try:
            self.clone_at(self.third, "primary-offline")
            self.sync(codes=503)
            self.clone_at(self.third, "after-failed-sync")
        finally:
            self.start()
        return {"primary_stopped_during_clone": True, "failed_sync_preserves_snapshot": True}

    def corrupt_primary_preserves_snapshot(self):
        # Deliberately corrupt only this harness's synthetic primary repository.
        # A ref to a missing object makes a full-clone sync fail. This tests the
        # transfer failure boundary, not corruption injected after Git fsck.
        pointer = self.root / "mirror-data" / "repos" / self.repo["id"] / "current.json"
        before = pointer.read_bytes()
        broken_ref = self.bare / "refs" / "heads" / "ci-mirror-broken-fixture"
        assert not broken_ref.exists()
        broken_ref.write_text("e" * 40 + "\n")
        try:
            self.sync(codes=503)
            assert pointer.read_bytes() == before, "Failed sync replaced published snapshot"
            self.clone_at(self.third, "after-corrupt-primary")
        finally:
            broken_ref.unlink()
        self.git("--git-dir=" + str(self.bare), "fsck", "--full")
        return {"missing_primary_object_rejected": True, "published_pointer_unchanged": True}

    def authoritative_fences(self):
        repo_id = self.repo["id"]
        self.sql(f"UPDATE repositories SET state='recovering' WHERE id='{repo_id}'")
        try:
            self.mirror_expect(self.advertise(self.first), 503, token=self.reader)
            self.sync(codes=503)
        finally:
            self.sql(f"UPDATE repositories SET state='ready' WHERE id='{repo_id}'")
        self.sql(f"UPDATE repositories SET storage_generation=storage_generation+1 WHERE id='{repo_id}'")
        try:
            self.mirror_expect(self.advertise(self.first), 409, token=self.reader)
        finally:
            self.sql(f"UPDATE repositories SET storage_generation=storage_generation-1 WHERE id='{repo_id}'")
        # Break an authoritative auth query only in this run-owned schema. This
        # is not a PostgreSQL server/network outage and claims no outage SLA.
        self.sql("ALTER TABLE tokens RENAME TO ci_mirror_unavailable_tokens")
        try:
            self.mirror_expect(self.advertise(self.first), (500, 503), token=self.reader)
            self.sync(codes=(500, 503))
        finally:
            self.sql("ALTER TABLE ci_mirror_unavailable_tokens RENAME TO tokens")
        self.mirror_expect(self.advertise(self.first), 200, token=self.reader)
        return {"ready_state_and_generation_checked": True, "auth_query_failure_closed": True}

    def role_volume_guards(self):
        self.stop_mirror()
        self.stop()
        try:
            # Both processes are stopped: failures cannot be explained by a
            # live directory lock. A durable role marker must reject reuse.
            primary_on_mirror = self.run([self.args.binary, "serve"], env=self.mirror_env, check=False)
            assert primary_on_mirror.returncode != 0, "Primary accepted mirror-owned volume"
            mirror_on_primary_env = self.mirror_env.copy()
            mirror_on_primary_env["ROOTYARD_DATA_DIR"] = self.env["ROOTYARD_DATA_DIR"]
            mirror_on_primary = self.run([self.args.binary, "serve-mirror"], env=mirror_on_primary_env, check=False)
            assert mirror_on_primary.returncode != 0, "Mirror accepted primary-owned volume"
        finally:
            self.start()
            self.start_mirror()
        self.clone_at(self.third, "after-mirror-restart")

    def pin_listing_and_lease_coordinated_release(self):
        job_active = str(uuid.uuid4())
        job_idle = str(uuid.uuid4())
        pin_active = self.create_pin(oid=self.first, job=job_active)
        pin_idle = self.create_pin(oid=self.second, job=job_idle)
        assert pin_active["state"] == "pinned" and pin_active["job_id"] == job_active
        assert pin_idle["state"] == "pinned" and pin_idle["job_id"] == job_idle

        self.expect("/api/repos/alice/demo/ci-pins", 401, method="GET")
        self.expect("/api/repos/alice/demo/ci-pins", (403, 404), token=self.bob, method="GET")
        listed = self.list_pins(token=self.reader)
        by_job = {item["job_id"]: item for item in listed}
        assert job_active in by_job and job_idle in by_job
        assert by_job[job_active]["target_oid"] == self.first
        assert by_job[job_idle]["target_oid"] == self.second

        # Read-only and non-owner tokens cannot release source pins.
        self.release_pin(job_active, method="DELETE", token=self.reader, codes=403)
        self.release_pin(job_active, method="POST", token=self.bob, codes=(403, 404))

        # Active checkout lease blocks source pin release with 409 Conflict.
        repo_id = self.repo["id"]
        owner_id = pin_active["owner_id"]
        plan_json = json.dumps(
            dict(
                version=1,
                job_id=job_active,
                owner_id=owner_id,
                repository_id=repo_id,
                storage_generation=1,
                object_format="sha1",
                target_oid=self.first,
                source_receipt_sha256="a" * 64,
                mirror_audience=str(uuid.uuid4()),
                expires_unix=int(time.time()) + 1800,
            )
        )
        self.sql(
            f"INSERT INTO ci_checkout_jobs (repository_id, job_id, owner_id, plan, cancelled, revoked, expires_unix) "
            f"VALUES ('{repo_id}', '{job_active}', '{owner_id}', '{plan_json}'::jsonb, false, false, extract(epoch FROM clock_timestamp())::bigint + 1800)"
        )
        self.release_pin(job_active, method="DELETE", codes=409)
        self.release_pin(job_active, method="POST", codes=409)
        assert self.git("--git-dir=" + str(self.bare), "rev-parse", f"refs/rootyard-ci/jobs/{job_active}").stdout.decode().strip() == self.first

        # Revoke the checkout lease, then release both pins and verify idempotent replay.
        self.expect(f"/api/repos/alice/demo/ci-checkouts/{job_active}/revoke", 200, token=self.alice, method="POST", body=b"")
        released_active = self.release_pin(job_active, method="DELETE", codes=200)
        assert released_active["state"] == "released" and released_active["released"] is True
        replay_active = self.release_pin(job_active, method="DELETE", codes=200)
        assert replay_active["state"] == "released"
        assert self.git("--git-dir=" + str(self.bare), "rev-parse", "--verify", f"refs/rootyard-ci/jobs/{job_active}", check=False).returncode != 0

        released_idle = self.release_pin(job_idle, method="POST", codes=200)
        assert released_idle["state"] == "released" and released_idle["released"] is True
        remaining = {item["job_id"] for item in self.list_pins(token=self.reader)}
        assert job_active not in remaining and job_idle not in remaining
        return {"pin_list_verified": True, "active_lease_blocks_release_409": True, "released_after_revoke": True}

    def watermark_and_lru_eviction_safety(self):
        self.apply_staged_migration_030()
        protected_job = str(uuid.uuid4())
        self.create_pin(oid=self.first, job=protected_job)
        self.sync()
        self.clone_at(self.first, "eviction-protected-first")
        self.clone_at(self.second, "eviction-unprotected-second")

        report = self.evict(endpoint="mirror-evict", body={"target_bytes": 1})
        assert report["repository_id"] == self.repo["id"]
        assert report["storage_generation"] == 1
        assert report["evicted_pins"] >= 1
        assert self.first in report["protected_oids"]

        # Protected OID and current snapshot remain usable after eviction.
        self.clone_at(self.first, "eviction-protected-first-after")
        self.clone_at(self.third, "eviction-current-third-after")
        recorded = int(self.sql(f"SELECT count(*) FROM ci_mirror_evictions WHERE repository_id='{self.repo['id']}'"))
        assert recorded >= 1

        # Release the source pin so subsequent prune can reclaim the previously protected pin.
        self.release_pin(protected_job, method="DELETE", codes=200)
        prune_report = self.evict(endpoint="mirror-prune", body={})
        assert prune_report["retained_pins"] == 0
        return {"protected_pin_preserved": True, "unreferenced_evicted": True, "sql_audit_recorded": True}

    def sync_rate_limiting_and_observability(self):
        self.mirror_expect("/api/repos/alice/demo/mirror-status", 401, method="GET")
        self.mirror_expect("/api/repos/alice/demo/mirror-status", (403, 404), token=self.bob, method="GET")
        self.mirror_expect("/api/repos/alice/demo/mirror-evict", 401, method="POST", body={})
        self.mirror_expect("/api/repos/alice/demo/mirror-evict", (403, 404), token=self.bob, method="POST", body={})

        status = self.mirror_status(token=self.reader)
        assert status["repository_id"] == self.repo["id"]
        assert status["storage_generation"] == 1
        assert status["current_snapshot"] is not None
        assert status["snapshot_count"] >= 1
        assert status["sync_limit"] >= 1
        assert status["evictions_total"] >= 1

        code, metrics_text, headers = self.mirror_metrics(codes=200)
        assert code == 200
        assert "no-store" in headers.get("Cache-Control", headers.get("cache-control", ""))
        for metric in (
            "rootyard_mirror_sync_in_flight",
            "rootyard_mirror_sync_limit",
            "rootyard_mirror_sync_total",
            "rootyard_mirror_sync_rate_limited_total",
            "rootyard_mirror_evictions_total",
            "rootyard_mirror_reclaimed_bytes_total",
            "rootyard_mirror_disk_bytes",
        ):
            assert metric in metrics_text, f"Missing metric {metric}"
        for secret in (self.alice["token"], self.reader["token"], "alice/demo"):
            assert secret not in metrics_text
        return {"status_endpoint_verified": True, "prometheus_metrics_verified": True}

    def cleanup(self):
        self.stop_mirror()
        super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a disposable dedicated database")
    harness = MirrorHarness(args)
    success = False
    try:
        for name in ("setup_mirror", "sync_and_pinned_clone", "pin_survives_source_deletion",
                     "replacement_refs_cannot_spoof_type", "corrupted_pin_fails_closed",
                     "authorization_and_writes",
                     "local_pack_and_failed_sync", "corrupt_primary_preserves_snapshot",
                     "authoritative_fences", "role_volume_guards",
                     "pin_listing_and_lease_coordinated_release",
                     "watermark_and_lru_eviction_safety",
                     "sync_rate_limiting_and_observability"):
            harness.case(name, getattr(harness, name))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(dict(name="cleanup", status="failed", error=harness.redact(error)))
            success = False
        report = dict(passed=success, cases=harness.results,
                      binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      limitations=["Synthetic loopback processes and isolated schema, not a production scaling benchmark.",
                                   "Auth dependency failure uses a renamed fixture table, not a PostgreSQL server outage.",
                                   "No disk-full, power-loss, concurrent sync, or in-flight revocation guarantee tested."])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
