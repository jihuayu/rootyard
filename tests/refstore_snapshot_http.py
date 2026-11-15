#!/usr/bin/env python3
"""Root-only real-service HTTP contract for durable snapshot metadata.

The implementation worker only py-compiles and statically inspects this file.
Root runs it on the final reviewed Linux source with the attested standalone
CLI, real PostgreSQL/S3 and stock Git.

The controller still owns authorization, current role/scope, ready
binding/backend/realm/cluster fencing and the final commit. This fixture only
drives the bounded HTTP DTOs and asserts safe projections, statuses, replay and
no-effect state. It never creates a ready repository, ACK, terminal, artifact
grant or successful receipt through SQL.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import blob_commit_unknown_service as checkpoint  # noqa: E402
import blob_only_service as blob  # noqa: E402

CREATE_READ = "snapshot_http_create_read_replay_after_ref_advance"
LIFECYCLE = "snapshot_http_renew_release_expiry_and_exact_replay"
AUTHZ = "snapshot_http_authz_malformed_and_cross_repo_refusals"
CASES = (CREATE_READ, LIFECYCLE, AUTHZ)

LIMITATIONS = [
    "Root-only real-service HTTP fixture: requires the attested standalone binary, real PostgreSQL/S3/stock Git and the owned Blob profile. The implementation worker only py-compiled it.",
    "The repository and captured refs/packs come from real API provisioning and stock Git publication; no ready/ACK/terminal/artifact-grant/receipt row is fabricated.",
    "The fixture exercises the bounded HTTP DTO/receipt projections and coordinator decisions. It does not claim byte-closure materialization, a #174 session/HWM, root/retention HTTP or full issue107 closure.",
    "The token/collaborator metadata cases are fixture inputs: read-only/restricted tokens use the real token API and real PATCH where shown; the write collaborator role row is labeled initial role metadata, not production collaborator API transport.",
    "Exact rows/counters are compared through the run-owned schema. No kernel, power-loss, distributed or scalability claim is made.",
]


def input_hashes():
    root = Path(__file__).resolve().parent
    names = (Path(__file__).name, "blob_commit_unknown_service.py", "blob_only_service.py",
             "e2e.py", "native_evidence.py", "ops_provenance.py", "owned_fuse_cleanup.py")
    return {name: blob.sha256_file(root / name) for name in names}


class SnapshotHttpProfile(checkpoint.CheckpointProfile):
    def __init__(self, binary, git_flag, env):
        super().__init__(binary, git_flag, env)
        self.snapshot_http_sha256 = blob.sha256_file(Path(__file__))


class SnapshotHttpHarness(checkpoint.CheckpointHarness):
    def _snapshots_path(self, repo, suffix=""):
        return ("/api/repos/" + urllib.parse.quote(repo["owner"], safe="") + "/"
                + urllib.parse.quote(repo["name"], safe="") + "/snapshots" + suffix)

    def _request(self, method, path, token, body=None):
        status, raw, headers = self.http(path, token=token, method=method, body=body)
        assert blob.header_value(headers, "cache-control") == "no-store", (status, headers)
        assert blob.header_value(headers, "x-rootyard-session") is None, headers
        return status, (json.loads(raw) if raw else None), headers

    def _create(self, repo, key, lease, token=None):
        return self._request("POST", self._snapshots_path(repo), token or self.alice,
                             {"idempotency_key": key, "lease_seconds": lease})

    def _read(self, repo, snapshot, token=None):
        return self._request("GET", self._snapshots_path(repo, "/" + str(snapshot)), token or self.alice)

    def _await_pin_expiry(self, repo, pin_id, label):
        """Poll the real DB clock against the immutable active-pin expiry."""
        rid = str(uuid.UUID(repo["id"]))
        pid = str(uuid.UUID(pin_id))
        until = time.monotonic() + 10
        while time.monotonic() < until:
            state = self.sql(
                "SELECT (expires_at <= clock_timestamp())::text FROM ref_store_core_pins "
                "WHERE pin_id='" + pid + "' AND repository_id='" + rid + "'"
            )
            assert state in ("true", "false"), (label, state)
            if state == "true":
                return
            time.sleep(0.05)
        raise AssertionError(label + ": pin did not expire naturally within 10s")

    def _renew(self, repo, snapshot, key, generation, lease, token=None):
        return self._request("POST", self._snapshots_path(repo, "/" + str(snapshot) + "/renew"),
                             token or self.alice,
                             {"idempotency_key": key, "expected_generation": generation,
                              "lease_seconds": lease})

    def _release(self, repo, snapshot, key, generation, token=None):
        return self._request("DELETE", self._snapshots_path(repo, "/" + str(snapshot)),
                             token or self.alice,
                             {"idempotency_key": key, "expected_generation": generation})

    def _issue_scoped(self, repo, label, actions, read_only=False):
        payload = {
            "display_name": label,
            "expires_in_days": 1,
            "read_only": read_only,
            "repository_grants": [{"repository_id": repo["id"], "actions": list(actions)}],
            "namespace_grants": [],
        }
        status, data, _ = self._request("POST", "/api/tokens", self.alice, payload)
        assert status == 201, (label, status, data)
        self.secrets.append(data["secret"])
        assert data.get("is_restricted") is True, data
        return {"username": "alice", "token": data["secret"], "id": data["id"],
                "scope_version": data["scope_version"]}

    def _patch_scope(self, repo, token, actions):
        body = {
            "expected_scope_version": token["scope_version"],
            "repository_grants": [{"repository_id": repo["id"], "actions": list(actions)}],
            "namespace_grants": [],
        }
        status, data, _ = self._request("PATCH", "/api/tokens/" + token["id"], self.alice, body)
        assert status == 200, (status, data)
        token["scope_version"] = data["scope_version"]
        return data

    def _insert_write_collaborator(self, repo, user_id):
        rid = str(uuid.UUID(repo["id"]))
        uid = str(uuid.UUID(user_id))
        owner = self.sql("SELECT owner_id FROM repositories WHERE id='" + rid + "'")
        assert owner, "fixture repository has no owner"
        self.sql("INSERT INTO repository_collaborators(repository_id,tenant_id,user_id,role) "
                 "VALUES('" + rid + "','" + owner + "','" + uid + "','write')")
        return owner

    def _ledger(self, repo):
        rid = str(uuid.UUID(repo["id"]))
        owner = "(SELECT owner_id FROM repositories WHERE id='" + rid + "')"
        query = (
            "SELECT jsonb_build_object("
            "'refs',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.ref_name),'[]'::jsonb) "
            "        FROM ref_store_core_refs r WHERE r.repository_id='" + rid + "'),"
            "'gate',(SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY g.repository_id),'[]'::jsonb) "
            "        FROM ref_store_core_gates g WHERE g.repository_id='" + rid + "'),"
            "'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.event_id),'[]'::jsonb) "
            "          FROM ref_store_core_events e WHERE e.repository_id='" + rid + "'),"
            "'snapshots',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.snapshot_id),'[]'::jsonb) "
            "             FROM ref_store_core_snapshots s WHERE s.repository_id='" + rid + "'),"
            "'pins',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.pin_id),'[]'::jsonb) "
            "        FROM ref_store_core_pins p WHERE p.repository_id='" + rid + "'),"
            "'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.request_id),'[]'::jsonb) "
            "            FROM ref_store_core_receipts c WHERE c.repository_id='" + rid + "'),"
            "'history',(SELECT coalesce(jsonb_agg(to_jsonb(h) ORDER BY h.request_id),'[]'::jsonb) "
            "           FROM ref_store_core_pack_snapshot_history h WHERE h.repository_id='" + rid + "'),"
            "'snapshot_refs',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.snapshot_id,r.ref_name),'[]'::jsonb) "
            "                 FROM ref_store_core_snapshot_refs r "
            "                 JOIN ref_store_core_snapshots s USING(snapshot_id) WHERE s.repository_id='" + rid + "'),"
            "'snapshot_packs',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.snapshot_id,p.pack_id),'[]'::jsonb) "
            "                  FROM ref_store_core_snapshot_packs p WHERE p.repository_id='" + rid + "'),"
            "'pack_usage',(SELECT coalesce(jsonb_agg(to_jsonb(u)),'[]'::jsonb) "
            "              FROM ref_store_core_pack_snapshot_repo_usage u WHERE u.repository_id='" + rid + "'),"
            "'pack_tenant_usage',(SELECT coalesce(jsonb_agg(to_jsonb(u)),'[]'::jsonb) "
            "                     FROM ref_store_core_pack_snapshot_tenant_usage u WHERE u.tenant_id=" + owner + "),"
            "'a2_repo_usage',(SELECT coalesce(jsonb_agg(to_jsonb(u)),'[]'::jsonb) "
            "                 FROM ref_store_core_repo_usage u WHERE u.repository_id='" + rid + "'),"
            "'a2_tenant_usage',(SELECT coalesce(jsonb_agg(to_jsonb(u)),'[]'::jsonb) "
            "                   FROM ref_store_core_tenant_usage u WHERE u.tenant_id=" + owner + ")"
            ")::text"
        )
        return self.sql(query)

    @staticmethod
    def _forbidden_markers(view):
        text = json.dumps(view, sort_keys=True).lower()
        for marker in ("provider", "backend_identity", "locator", "hold_id", "namespace",
                       "blob_key", "object_key", "secret", "x-rootyard-session",
                       "high_watermark", "s3://"):
            assert marker not in text, (marker, view)

    def _assert_create_view(self, view):
        assert set(view) == {
            "action", "snapshot_id", "pin_id", "pin_generation", "gate_revision", "gate_digest",
            "head_ref", "head_oid", "ref_count", "refs_digest", "membership_digest", "pack_count",
            "pack_mode", "snapshot_digest", "logical_bytes", "expires_at_unix_micros",
            "expires_at_is_historical", "replayed", "receipt_only", "receipt_grants_live_lease",
            "complete_registered_pack_membership", "complete_git_read_snapshot",
        }, view
        assert view["action"] == "create", view
        assert view["pack_mode"] == "pack_verified", view
        assert view["receipt_only"] is True and view["receipt_grants_live_lease"] is False, view
        assert view["complete_registered_pack_membership"] is False, view
        assert view["complete_git_read_snapshot"] is False, view
        assert view["pack_count"] >= 1 and view["ref_count"] >= 1, view
        self._forbidden_markers(view)

    def _assert_pin_view(self, view):
        assert set(view) == {
            "action", "snapshot_id", "pin_id", "pin_generation", "expires_at_unix_micros",
            "released_at_unix_micros", "release_reason", "expires_at_is_historical", "replayed",
            "receipt_only", "receipt_grants_live_lease", "complete_git_read_snapshot",
        }, view
        assert view["action"] in ("renew", "release"), view
        assert view["receipt_only"] is True and view["receipt_grants_live_lease"] is False, view
        assert view["complete_git_read_snapshot"] is False, view
        self._forbidden_markers(view)

    def _assert_read_view(self, view):
        assert set(view) == {
            "snapshot_id", "pin_id", "pin_generation", "gate_revision", "gate_digest",
            "head_ref", "head_oid", "ref_count", "refs", "pack_count", "pack_mode", "packs",
            "membership_digest", "snapshot_digest", "logical_bytes", "expires_at_unix_micros",
            "source_kind", "complete_registered_pack_membership", "complete_git_read_snapshot",
        }, view
        assert view["pack_mode"] == "pack_verified", view
        assert view["source_kind"] == "retained_durable", view
        assert view["complete_registered_pack_membership"] is True, view
        assert view["complete_git_read_snapshot"] is False, view
        assert view["pack_count"] >= 1 and view["ref_count"] >= 1, view
        for reference in view["refs"]:
            assert set(reference) == {"name", "oid"}, reference
        for pack in view["packs"]:
            assert set(pack) == {
                "pack_id", "registration_id", "artifact_set_digest", "joined_revision",
                "artifact_count", "verified_bytes", "artifacts",
            }, pack
            assert pack["artifact_count"] == len(pack["artifacts"]) >= 2, pack
            for artifact in pack["artifacts"]:
                assert set(artifact) == {"role", "sha256", "length"}, artifact
                assert artifact["role"] in ("pack", "idx"), artifact
        self._forbidden_markers(view)

    def _main_ref(self, view):
        matches = [item["oid"] for item in view["refs"] if item["name"] == "refs/heads/main"]
        assert len(matches) == 1, view["refs"]
        return matches[0]

    def snapshot_http_create_read_replay_after_ref_advance(self):
        repo, _remote, work, old_oid = self.seed("snap-http")
        baseline = self._ledger(repo)
        status, created, _ = self._create(repo, "create-one", 300)
        assert status == 201, (status, created)
        self._assert_create_view(created)
        snapshot = created["snapshot_id"]
        pin = created["pin_id"]
        gate = created["gate_revision"]
        expires = created["expires_at_unix_micros"]
        after_create = self._ledger(repo)
        assert after_create != baseline, "create did not append durable metadata"

        status, read, _ = self._read(repo, snapshot)
        assert status == 200, (status, read)
        self._assert_read_view(read)
        assert read["snapshot_id"] == snapshot and read["pin_id"] == pin, read
        assert read["head_ref"] == "refs/heads/main" and read["head_oid"] == old_oid, read
        assert read["gate_revision"] == gate, read
        assert self._main_ref(read) == old_oid, read["refs"]

        new_oid = self.commit_files(work, "snapshot advance", {"advance.txt": "advance\n"})
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        assert new_oid != old_oid
        after_advance = self._ledger(repo)
        assert after_advance != after_create, "second ref publication did not advance the gate"

        status, replay, _ = self._create(repo, "create-one", 300)
        assert status == 200 and replay["replayed"] is True, (status, replay)
        assert replay["snapshot_id"] == snapshot and replay["pin_id"] == pin, replay
        assert replay["gate_revision"] == gate and replay["expires_at_unix_micros"] == expires, replay
        assert replay["expires_at_is_historical"] is True, replay
        assert self._create(repo, "create-one", 300)[1]["replayed"] is True
        assert self._ledger(repo) == after_advance, "exact create replay changed durable state"

        status, changed, _ = self._create(repo, "create-one", 301)
        assert status == 409, (status, changed)
        assert self._ledger(repo) == after_advance, "changed create intent changed durable state"

        status, historical, _ = self._read(repo, snapshot)
        assert status == 200, (status, historical)
        assert historical["gate_revision"] == gate and historical["head_oid"] == old_oid, historical
        assert self._main_ref(historical) == old_oid, historical["refs"]
        assert self._ledger(repo) == after_advance, "historical read changed durable state"
        return {
            "snapshot_id": snapshot,
            "pin_id": pin,
            "gate_revision": gate,
            "created_oid": old_oid,
            "advanced_oid": new_oid,
            "create_replayed_after_advance": True,
            "changed_intent_conflict": True,
            "historical_read_kept_old_gate_and_refs": True,
        }

    def snapshot_http_renew_release_expiry_and_exact_replay(self):
        repo, _remote, _work, _oid = self.seed("snap-life")
        status, created, _ = self._create(repo, "life-create", 300)
        assert status == 201, (status, created)
        snapshot = created["snapshot_id"]
        after_create = self._ledger(repo)

        status, renewed, _ = self._renew(repo, snapshot, "renew-one", 1, 120)
        assert status == 200, (status, renewed)
        self._assert_pin_view(renewed)
        assert renewed["action"] == "renew" and renewed["replayed"] is False, renewed
        assert renewed["pin_generation"] == 2 and renewed["expires_at_is_historical"] is False, renewed
        after_renew = self._ledger(repo)
        assert after_renew != after_create, "renew did not append a live receipt"

        status, replayed, _ = self._renew(repo, snapshot, "renew-one", 1, 120)
        assert status == 200 and replayed["replayed"] is True, (status, replayed)
        assert replayed["pin_generation"] == 2 and replayed["expires_at_is_historical"] is True, replayed
        assert self._ledger(repo) == after_renew, "exact renew replay changed durable state"

        status, changed_lease, _ = self._renew(repo, snapshot, "renew-one", 1, 121)
        assert status == 409, (status, changed_lease)
        status, stale, _ = self._renew(repo, snapshot, "renew-stale", 1, 120)
        assert status == 409, (status, stale)
        assert self._ledger(repo) == after_renew, "renew conflicts changed durable state"

        status, read, _ = self._read(repo, snapshot)
        assert status == 200 and read["pin_generation"] == 2, (status, read)

        status, released, _ = self._release(repo, snapshot, "release-one", 2)
        assert status == 200, (status, released)
        self._assert_pin_view(released)
        assert released["action"] == "release" and released["replayed"] is False, released
        assert released["pin_generation"] == 2 and released["released_at_unix_micros"] is not None, released
        assert released["release_reason"] == "client_done" and released["expires_at_is_historical"] is True, released
        after_release = self._ledger(repo)
        assert after_release != after_renew, "release did not append a terminal receipt"

        status, release_replay, _ = self._release(repo, snapshot, "release-one", 2)
        assert status == 200 and release_replay["replayed"] is True, (status, release_replay)
        assert self._ledger(repo) == after_release, "exact release replay changed durable state"

        status, released_read, _ = self._read(repo, snapshot)
        assert status == 409, (status, released_read)
        status, released_renew, _ = self._renew(repo, snapshot, "renew-after-release", 2, 120)
        assert status == 409, (status, released_renew)
        assert self._ledger(repo) == after_release, "released denial changed durable state"

        status, expired, _ = self._create(repo, "expired-create", 1)
        assert status == 201, (status, expired)
        expired_id = expired["snapshot_id"]
        self._await_pin_expiry(repo, expired["pin_id"], "expired-create")
        expired_baseline = self._ledger(repo)
        status, expired_read, _ = self._read(repo, expired_id)
        assert status == 409, (status, expired_read)
        status, expired_renew, _ = self._renew(repo, expired_id, "renew-expired", 1, 120)
        assert status == 409, (status, expired_renew)
        assert self._ledger(repo) == expired_baseline, "expired denial changed durable state"
        return {
            "snapshot_id": snapshot,
            "renew_generation": 2,
            "released": True,
            "release_reason": "client_done",
            "released_read_status": 409,
            "expired_read_status": 409,
            "exact_renew_release_replay": True,
        }

    def snapshot_http_authz_malformed_and_cross_repo_refusals(self):
        repo, _remote, _work, _oid = self.seed("snap-authz")
        status, created, _ = self._create(repo, "authz-create", 300)
        assert status == 201, (status, created)
        snapshot = created["snapshot_id"]
        baseline = self._ledger(repo)

        # Unrestricted read-only owner token: read works; mutations are refused.
        status, read, _ = self._read(repo, snapshot, token=self.reader)
        assert status == 200, (status, read)
        for label, call in (
            ("read-only create", lambda: self._create(repo, "readonly-create", 300, token=self.reader)),
            ("read-only renew", lambda: self._renew(repo, snapshot, "readonly-renew", 1, 120, token=self.reader)),
            ("read-only release", lambda: self._release(repo, snapshot, "readonly-release", 1, token=self.reader)),
        ):
            code, payload, _ = call()
            assert code == 403, (label, code, payload)
        assert self._ledger(repo) == baseline, "read-only mutations changed durable state"

        # Restricted ContentsRead token accepts read; mutation is refused.
        reader = self._issue_scoped(repo, "restricted-reader", ["contents_read"], read_only=True)
        status, _, _ = self._read(repo, snapshot, token=reader)
        assert status == 200
        status, _, _ = self._create(repo, "restricted-reader-create", 300, token=reader)
        assert status == 403

        # Real API PATCH narrowing: write grant removed, read grant retained.
        patched = self._issue_scoped(repo, "patched", ["contents_read", "contents_write"])
        self._patch_scope(repo, patched, ["contents_read"])
        status, _, _ = self._read(repo, snapshot, token=patched)
        assert status == 200
        status, _, _ = self._create(repo, "patched-create", 300, token=patched)
        assert status == 403
        assert self._ledger(repo) == baseline, "scope-narrowed refusals changed durable state"

        # Write-only scoped token can create on a separate repo but cannot read it.
        write_repo, _wr, _ww, _wo = self.seed("snap-write-only")
        write_only = self._issue_scoped(write_repo, "write-only", ["contents_write"])
        status, write_created, _ = self._create(write_repo, "write-only-create", 300, token=write_only)
        assert status == 201, (status, write_created)
        status, _, _ = self._read(write_repo, write_created["snapshot_id"], token=write_only)
        assert status == 403

        # Non-member and then initial fixture-only write collaborator role.
        status, _, _ = self._read(repo, snapshot, token=self.bob)
        assert status == 404
        status, _, _ = self._create(repo, "bob-nonmember", 300, token=self.bob)
        assert status == 404
        self._insert_write_collaborator(repo, self.bob["user_id"])
        status, _, _ = self._read(repo, snapshot, token=self.bob)
        assert status == 403
        status, _, _ = self._create(repo, "bob-write-collab", 300, token=self.bob)
        assert status == 403
        assert self._ledger(repo) == baseline, "non-member/collaborator refusals changed durable state"

        # Repository-scoped snapshot selector under another same-owner repo.
        cross_repo, _cr, _cw, _co = self.seed("snap-cross")
        cross_baseline = self._ledger(cross_repo)
        status, _, _ = self._read(cross_repo, snapshot)
        assert status == 404
        assert self._ledger(cross_repo) == cross_baseline, "cross-repository refusal changed state"

        # Invalid credentials.
        status, _, _ = self._read(repo, snapshot, token={"token": "ryt_" + "0" * 64})
        assert status == 401

        # Malformed selector/DTO/key/lease/generation and unknown fields.
        malformed = [
            ("malformed snapshot selector", "GET", self._snapshots_path(repo, "/not-a-uuid"), None, 400),
            ("nil snapshot selector", "GET", self._snapshots_path(repo, "/" + str(uuid.UUID(int=0))), None, 400),
            ("unknown create field", "POST", self._snapshots_path(repo),
             {"idempotency_key": "unknown-field", "lease_seconds": 300, "snapshot_id": snapshot}, 400),
            ("empty key", "POST", self._snapshots_path(repo),
             {"idempotency_key": "", "lease_seconds": 300}, 400),
            ("non-opaque key", "POST", self._snapshots_path(repo),
             {"idempotency_key": "bad key", "lease_seconds": 300}, 400),
            ("zero lease", "POST", self._snapshots_path(repo),
             {"idempotency_key": "zero-lease", "lease_seconds": 0}, 400),
            ("oversized lease", "POST", self._snapshots_path(repo),
             {"idempotency_key": "large-lease", "lease_seconds": 1000000}, 400),
            ("zero generation", "POST", self._snapshots_path(repo, "/" + str(snapshot) + "/renew"),
             {"idempotency_key": "zero-generation", "expected_generation": 0, "lease_seconds": 120}, 400),
            ("unknown release field", "DELETE", self._snapshots_path(repo, "/" + str(snapshot)),
             {"idempotency_key": "unknown-release", "expected_generation": 1, "reason": "client_done"}, 400),
        ]
        for label, method, path, body, expected in malformed:
            status, payload, _ = self._request(method, path, self.alice, body)
            assert status == expected, (label, status, payload)
        assert self._ledger(repo) == baseline, "malformed requests changed durable state"
        return {
            "snapshot_id": snapshot,
            "read_only_write_status": 403,
            "restricted_write_status": 403,
            "write_only_read_status": 403,
            "nonmember_status": 404,
            "write_collaborator_status": 403,
            "cross_repo_status": 404,
            "invalid_token_status": 401,
            "malformed_cases": len(malformed),
        }


def select_cases(names):
    if not names:
        return list(CASES)
    unknown = [name for name in names if name not in CASES]
    if unknown:
        raise blob.ProfileError("unknown case(s): " + ", ".join(unknown))
    selected = [name for name in CASES if name in set(names)]
    if not selected:
        raise blob.ProfileError("no cases selected; a zero-case run cannot be green")
    return selected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="absolute attested rootyard binary")
    parser.add_argument("--git", help="absolute trusted Git (defaults to ROOTYARD_GIT)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args(argv)
    env = os.environ.copy()
    hashes = None
    try:
        hashes = input_hashes()
        profile = SnapshotHttpProfile(str(Path(args.binary).resolve()), args.git, env)
        blob_profile = blob.check_blob_profile(env)
        blob.need(env.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
        blob.need(shutil.which("psql"), "psql is required")
        selected = select_cases(args.case)
    except Exception as error:
        blob.write_report(args.report, {
            "kind": "rootyard/refstore-snapshot-http", "passed": False,
            "preflight_failed": True, "error": str(error), "cases": [],
            "expected_cases": [], "skips": 0, "limitations": LIMITATIONS,
            "harness_inputs_sha256": hashes or {},
        })
        print("preflight failed: " + str(error), file=sys.stderr)
        return 2

    args.binary = str(profile.binary)
    harness = SnapshotHttpHarness(args, profile, blob_profile)
    success = False
    try:
        harness.prepare()
        for name in selected:
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
        report = blob.build_report(harness, profile, blob_profile, selected, success)
        hashes_now = input_hashes()
        report["kind"] = "rootyard/refstore-snapshot-http"
        report["checkpoint_sha256"] = hashes_now[Path(__file__).name]
        report["harness_inputs_sha256"] = hashes_now
        report["harness_inputs"] = {"input_hashes": hashes_now}
        report["limitations"] = LIMITATIONS
        errors = []
        if hashes_now != hashes:
            errors.append("harness/helper source changed during native acceptance")
        if blob.sha256_file(profile.binary) != profile.build["binary_sha256"]:
            errors.append("executed binary changed during native acceptance")
        if blob.sha256_file(profile.binary.with_suffix(".build.json")) != profile.receipt_sha256:
            errors.append("build receipt changed during native acceptance")
        if errors:
            report["inputs_unchanged"] = False
            report["passed"] = False
            prior = report.get("binding_error")
            report["binding_error"] = "; ".join(errors + ([prior] if prior else []))
        blob.write_report(args.report, report)
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
