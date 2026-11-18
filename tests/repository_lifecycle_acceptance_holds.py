"""Checkpoint 1 DB-backed purge-hold cases for Issue #85 literal acceptance.

Every case creates its own fresh API-ready GitFS repository, pushes a real
stock-Git commit, uploads real LFS bytes, soft-deletes through the lifecycle
API with a zero-second grace window, inserts exactly one schema-valid hold
fixture, and proves that the HTTP purge response reports that single hold.
The fixture is then released through its own API or metadata row and a fresh
control purge is required to succeed.

The backup and serving-read fixtures are explicitly metadata-only.  They do
not claim that Pando created a backup, that a Blob read producer ran, or that
physical bytes were captured.  No repository ready/ref/ACK/operation state,
ownership, grant or terminal row is changed by SQL.
"""
from __future__ import annotations

import hashlib
import json
import uuid

from repository_lifecycle_acceptance_support import fresh_key


def _quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def _repo(h, stem):
    h.phase("create_repository")
    name = f"{stem}-{uuid.uuid4().hex[:10]}"
    return h.create_repository({"owner": "alice", "name": name}, token=h.alice)


def _lifecycle(h, repo):
    h.phase("read_lifecycle")
    return h.doc(f"/api/repos/alice/{repo['name']}/lifecycle", 200, token=h.alice)


def _bare(h, repo):
    return h.root / "data" / "repos" / f"{repo['id']}.git"


def _lfs_path(h, repo, oid):
    return h.root / "data" / "lfs" / repo["id"] / oid


def _native_head(h, repo, ref="refs/heads/main"):
    result = h.git("--git-dir", str(_bare(h, repo)), "rev-parse", "--verify", ref)
    return result.stdout.decode().strip()


def _seed(h, repo):
    """Create a real Git commit and real LFS bytes through the real API/Git."""
    h.phase("seed_git")
    work = h.root / f"hold-work-{repo['id']}"
    head_oid = h.push_file(
        "alice", repo["name"], work, "README.md", "hold fixture\n", "main", "seed hold", h.alice
    )
    assert len(head_oid) == 40
    h.phase("verify_native_head")
    assert _native_head(h, repo) == head_oid
    h.phase("seed_lfs")
    payload = b"issue85-hold-lfs-" * 64 + repo["id"].encode()
    lfs_oid = h.batch_upload("alice", repo["name"], payload, h.alice)
    h.phase("verify_lfs_bytes")
    path = _lfs_path(h, repo, lfs_oid)
    assert path.is_file()
    assert path.read_bytes() == payload
    assert (
        h.expect(
            f"/git/alice/{repo['name']}.git/info/lfs/objects/{lfs_oid}/{len(payload)}",
            200,
            token=h.alice,
        )
        == payload
    )
    return head_oid, lfs_oid, payload


def _soft_delete_zero(h, repo, version):
    h.phase("soft_delete_zero_grace")
    deleted = h.doc(
        f"/api/repos/alice/{repo['name']}",
        200,
        token=h.alice,
        method="DELETE",
        body={"expected_version": version, "grace_period_seconds": 0},
        extra_headers={"Idempotency-Key": fresh_key("accept-soft-delete")},
    )
    assert deleted["deleted"] is True
    assert deleted["version"] == version + 1
    return deleted


def _blocked_purge(h, repo, version, expected_kind):
    """Require 409 with exactly one hold of the expected class and count 1."""
    h.phase("blocked_purge")
    status, body, _ = h.raw_http(
        f"/api/repos/alice/{repo['name']}/purge",
        token=h.alice,
        method="POST",
        body={
            "expected_version": version,
            "confirm_repository": f"alice/{repo['name']}",
        },
        extra_headers={"Idempotency-Key": fresh_key("accept-purge-blocked")},
    )
    assert status == 409
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        raise AssertionError("blocked purge response is not JSON") from None
    holds = payload.get("holds")
    assert isinstance(holds, list)
    assert len(holds) == 1
    hold = holds[0]
    assert isinstance(hold, dict)
    assert hold.get("kind") == expected_kind
    assert hold.get("blocking_count") == 1


def _assert_retained(h, repo, head_oid, lfs_oid, lfs_bytes):
    """The blocked purge must not remove the native head or LFS bytes."""
    h.phase("assert_data_retained")
    assert _native_head(h, repo) == head_oid
    path = _lfs_path(h, repo, lfs_oid)
    assert path.is_file()
    assert path.read_bytes() == lfs_bytes


def _control_purge(h, repo, version):
    h.phase("control_purge")
    purged = h.doc(
        f"/api/repos/alice/{repo['name']}/purge",
        200,
        token=h.alice,
        method="POST",
        body={
            "expected_version": version,
            "confirm_repository": f"alice/{repo['name']}",
        },
        extra_headers={"Idempotency-Key": fresh_key("accept-purge-control")},
    )
    assert purged["purged"] is True
    assert purged["repository_id"] == repo["id"]
    h.phase("assert_purged")
    remaining = h.sql(
        "SELECT count(*) FROM repositories "
        f"WHERE id = {_quote(repo['id'])}"
    )
    assert remaining == "0"


def _digest(label):
    return hashlib.sha256(label.encode()).hexdigest()


def backup_root_blocks_purge(h):
    """Migration-148 backup_snapshot metadata root blocks final purge."""
    repo = _repo(h, "accept-backup")
    lifecycle = _lifecycle(h, repo)
    head_oid, lfs_oid, lfs_bytes = _seed(h, repo)
    deleted = _soft_delete_zero(h, repo, lifecycle["version"])

    h.phase("insert_retention_root")
    authority = h.sql(
        "SELECT authority_id FROM pando_storage_authorities WHERE singleton"
    )
    owner = h.sql(f"SELECT owner_id FROM repositories WHERE id = {_quote(repo['id'])}")
    assert authority
    assert owner
    root_id = str(uuid.uuid4())
    # Migration 148 creates the root shape; migration 151 rebinds tenant_id to
    # namespaces(id) (a personal namespace id equals its owner user id) and keeps
    # FK (repository_id, tenant_id) -> repositories(id, owner_id).  The CHECK
    # requires active => released_at IS NULL.
    h.sql(
        "INSERT INTO pando_retention_roots "
        "(id, authority_id, tenant_id, repository_id, root_kind, state, "
        " restore_generation, retain_until, released_at) VALUES ("
        f"{_quote(root_id)}, {_quote(authority)}, {_quote(owner)}, {_quote(repo['id'])}, "
        "'backup_snapshot', 'active', 0, NULL, NULL)"
    )
    h.phase("verify_retention_fixture")
    row = h.sql(
        "SELECT state || ':' || repository_id::text || ':' || tenant_id::text "
        f"FROM pando_retention_roots WHERE id = {_quote(root_id)}"
    )
    assert row == f"active:{repo['id']}:{owner}"
    active = h.sql(
        "SELECT count(*) FROM pando_retention_roots "
        f"WHERE id = {_quote(root_id)} AND state = 'active'"
    )
    assert active == "1"

    _blocked_purge(h, repo, deleted["version"], "backup_retention_root")
    _assert_retained(h, repo, head_oid, lfs_oid, lfs_bytes)

    h.phase("release_retention_root")
    h.sql(
        "UPDATE pando_retention_roots "
        "SET state = 'released', released_at = clock_timestamp() "
        f"WHERE id = {_quote(root_id)} AND state = 'active'"
    )
    still_active = h.sql(
        "SELECT count(*) FROM pando_retention_roots "
        f"WHERE id = {_quote(root_id)} AND state = 'active'"
    )
    assert still_active == "0"

    _control_purge(h, repo, deleted["version"])
    return {
        "fixture": "migration148_retention_metadata",
        "fixture_scope": "metadata_only",
        "producer_claim": "none",
        "hold_kind": "backup_retention_root",
        "hold_count": 1,
        "control_purge": "passed",
        "git_retained": True,
        "lfs_retained": True,
        "native_head_retained": True,
    }


def serving_read_header_blocks_purge(h):
    """Migration-146 unexpired serving-read header blocks final purge."""
    repo = _repo(h, "accept-read")
    lifecycle = _lifecycle(h, repo)
    head_oid, lfs_oid, lfs_bytes = _seed(h, repo)
    deleted = _soft_delete_zero(h, repo, lifecycle["version"])

    h.phase("insert_serving_read_header")
    owner = h.sql(f"SELECT owner_id FROM repositories WHERE id = {_quote(repo['id'])}")
    assert owner
    pin_id = str(uuid.uuid4())
    snapshot_id = str(uuid.uuid4())
    incarnation = str(uuid.uuid4())
    # Migration 146 strict CHECKs: fresh UUID identity, purpose/format enums,
    # positive epochs, 64-hex digests, 40-hex real HEAD, ref_count 0,
    # pack_count 1, logical_bytes 1, lease_seconds 60, unexpired expires_at,
    # and FK (repository_id, tenant_id) -> repositories(id, owner_id).
    h.sql(
        "INSERT INTO ref_store_core_serving_reads "
        "(pin_id, snapshot_id, repository_id, tenant_id, owner_id, purpose, "
        " object_format, history_incarnation, authority_epoch, group_epoch, "
        " backend_identity, gate_revision, gate_digest, head_ref, head_oid, "
        " ref_count, refs_digest, pack_count, membership_digest, snapshot_digest, "
        " logical_bytes, lease_seconds, expires_at) VALUES ("
        f"{_quote(pin_id)}, {_quote(snapshot_id)}, {_quote(repo['id'])}, "
        f"{_quote(owner)}, {_quote(owner)}, 'verification', 'sha1', "
        f"{_quote(incarnation)}, 1, 1, {_quote(_digest('backend'))}, 1, "
        f"{_quote(_digest('gate'))}, 'refs/heads/main', {_quote(head_oid)}, 0, "
        f"{_quote(_digest('refs'))}, 1, {_quote(_digest('membership'))}, "
        f"{_quote(_digest('snapshot'))}, 1, 60, "
        "clock_timestamp() + interval '1 minute')"
    )
    h.phase("verify_serving_read_fixture")
    row = h.sql(
        "SELECT pin_id::text || ':' || (expires_at > clock_timestamp())::text "
        "|| ':' || repository_id::text || ':' || tenant_id::text || ':' "
        "|| owner_id::text || ':' || head_oid "
        "FROM ref_store_core_serving_reads "
        f"WHERE pin_id = {_quote(pin_id)}"
    )
    assert row == f"{pin_id}:true:{repo['id']}:{owner}:{owner}:{head_oid}"
    active = h.sql(
        "SELECT count(*) FROM ref_store_core_serving_reads "
        f"WHERE repository_id = {_quote(repo['id'])} "
        "AND expires_at > clock_timestamp()"
    )
    assert active == "1"

    _blocked_purge(h, repo, deleted["version"], "active_read_lease")
    _assert_retained(h, repo, head_oid, lfs_oid, lfs_bytes)

    h.phase("release_serving_read_header")
    # No child rows are inserted; deleting the header is the only intended
    # release and its own children (if any existed) would cascade.
    h.sql(
        "DELETE FROM ref_store_core_serving_reads "
        f"WHERE pin_id = {_quote(pin_id)}"
    )
    absent = h.sql(
        "SELECT count(*) FROM ref_store_core_serving_reads "
        f"WHERE pin_id = {_quote(pin_id)}"
    )
    assert absent == "0"

    _control_purge(h, repo, deleted["version"])
    return {
        "fixture": "migration146_serving_read_header",
        "fixture_scope": "metadata_only",
        "producer_claim": "none",
        "hold_kind": "active_read_lease",
        "hold_count": 1,
        "control_purge": "passed",
        "git_retained": True,
        "lfs_retained": True,
        "native_head_retained": True,
    }


def ci_pin_blocks_purge(h):
    """A real CI-pin API pin over a real commit blocks final purge."""
    repo = _repo(h, "accept-cipin")
    lifecycle = _lifecycle(h, repo)
    head_oid, lfs_oid, lfs_bytes = _seed(h, repo)

    h.phase("issue_ci_pin")
    job = str(uuid.uuid4())
    pin = h.doc(
        f"/api/repos/alice/{repo['name']}/ci-pins",
        200,
        token=h.alice,
        method="POST",
        body={
            "job_id": job,
            "target_oid": head_oid,
            "storage_generation": repo["storage_generation"],
        },
    )
    assert pin["state"] == "pinned"
    assert pin["job_id"] == job
    assert pin["target_oid"] == head_oid
    assert pin["repository_id"] == repo["id"]
    assert pin["storage_generation"] == repo["storage_generation"]
    h.phase("verify_ci_pin")
    fetched = h.doc(
        f"/api/repos/alice/{repo['name']}/ci-pins/{job}", 200, token=h.alice
    )
    assert fetched["state"] == "pinned"
    assert fetched["target_oid"] == head_oid
    h.git("--git-dir", str(_bare(h, repo)), "cat-file", "-e", head_oid + "^{commit}")
    native_pin = _native_head(h, repo, f"refs/rootyard-ci/jobs/{job}")
    assert native_pin == head_oid

    deleted = _soft_delete_zero(h, repo, lifecycle["version"])
    _blocked_purge(h, repo, deleted["version"], "active_ci_pin")
    _assert_retained(h, repo, head_oid, lfs_oid, lfs_bytes)

    h.phase("restore_after_hold")
    restored = h.doc(
        f"/api/repos/alice/{repo['name']}/restore",
        200,
        token=h.alice,
        method="POST",
        body={"expected_version": deleted["version"]},
        extra_headers={"Idempotency-Key": fresh_key("accept-restore")},
    )
    assert restored["deleted"] is False

    h.phase("release_ci_pin")
    released = h.doc(
        f"/api/repos/alice/{repo['name']}/ci-pins/{job}",
        200,
        token=h.alice,
        method="DELETE",
    )
    assert released.get("released") is True
    h.phase("verify_ci_pin_absent")
    h.expect(
        f"/api/repos/alice/{repo['name']}/ci-pins/{job}", 404, token=h.alice
    )
    refs = h.git(
        "--git-dir",
        str(_bare(h, repo)),
        "for-each-ref",
        "--format=%(refname)",
        f"refs/rootyard-ci/jobs/{job}",
    ).stdout.decode().strip()
    assert refs == ""

    h.phase("soft_delete_again")
    deleted_again = _soft_delete_zero(h, repo, restored["version"])
    _control_purge(h, repo, deleted_again["version"])
    return {
        "fixture": "ci_pin_api_over_real_oid",
        "hold_kind": "active_ci_pin",
        "hold_count": 1,
        "control_purge": "passed",
        "git_retained": True,
        "lfs_retained": True,
        "native_head_retained": True,
    }
