"""Checkpoint 2 rename-alias real Git/LFS write acceptance for Issue #85.

The fixture is an independent API-created repository.  A local clone keeps the
old alias as its explicit origin.  After a real rename, the case proves that
stock Git can still push a new commit through the old HTTP origin (receive-pack
following the 308 to canonical) and that an authorized LFS batch through the
old alias redirects to the canonical batch, uploads real bytes and reads them
back from the canonical object path.  A restricted read-only-scope token proves
the original ACL-before-redirect contract: reads redirect, writes are denied
without a Location disclosure, and refs/object visibility remains unchanged.
"""
from __future__ import annotations

import hashlib
import json
import urllib.parse
import uuid

from repository_lifecycle_acceptance_holds import (
    _bare,
    _lifecycle,
    _native_head,
    _repo,
)
from repository_lifecycle_acceptance_support import fresh_key

LFS_MIME = "application/vnd.git-lfs+json"


def _batch_body(operation, oid, size):
    return {
        "operation": operation,
        "transfers": ["basic"],
        "objects": [{"oid": oid, "size": size}],
        "hash_algo": "sha256",
    }


def _encode(value):
    return json.dumps(value).encode()


def _href_path(href):
    parsed = urllib.parse.urlsplit(href)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def _object_path(owner, name, oid, size):
    return f"/git/{owner}/{name}.git/info/lfs/objects/{oid}/{size}"


def _batch_path(owner, name):
    return f"/git/{owner}/{name}.git/info/lfs/objects/batch"


def _request_batch(h, path, payload, token):
    return h.raw_http(
        path,
        token=token,
        method="POST",
        content_type=LFS_MIME,
        extra_headers={"Accept": LFS_MIME},
        body=_encode(payload),
    )


def rename_alias_accepts_real_git_and_lfs_writes(h):
    repo = _repo(h, "accept-alias")
    old_name = repo["name"]
    canonical = f"{old_name}-canon"
    lifecycle = _lifecycle(h, repo)

    h.phase("clone_old_origin")
    work = h.root / f"alias-work-{repo['id']}"
    old_git_url = h.base + f"/git/alice/{old_name}.git"
    h.git("clone", old_git_url, str(work), token=h.alice)
    h.git("config", "user.name", "alice", cwd=work)
    h.git("config", "user.email", "alice@example.invalid", cwd=work)
    h.git("config", "http.followRedirects", "true", cwd=work)
    assert (
        h.git("config", "--get", "remote.origin.url", cwd=work)
        .stdout.decode()
        .strip()
        .rstrip("/")
        == old_git_url.rstrip("/")
    )

    h.phase("seed_before_rename")
    (work / "README.md").write_text("alias seed\n")
    h.git("add", "README.md", cwd=work)
    h.git("commit", "-m", "seed alias", cwd=work)
    seed_oid = h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
    h.git("push", "origin", "HEAD:main", cwd=work, token=h.alice)
    assert _native_head(h, repo) == seed_oid
    seed_lfs = b"alias-seed-lfs-" * 64 + repo["id"].encode()
    seed_lfs_oid = h.batch_upload("alice", old_name, seed_lfs, h.alice)

    h.phase("rename")
    renamed = h.doc(
        f"/api/repos/alice/{old_name}/rename",
        200,
        token=h.alice,
        method="POST",
        body={"new_name": canonical, "expected_version": lifecycle["version"]},
        extra_headers={"Idempotency-Key": fresh_key("accept-rename")},
    )
    assert renamed["name"] == canonical
    assert any(
        alias["owner"] == "alice" and alias["name"] == old_name
        for alias in renamed["aliases"]
    )

    old_git_prefix = f"/git/alice/{old_name}.git"
    canonical_git_url = h.base + f"/git/alice/{canonical}.git"
    old_batch = _batch_path("alice", old_name)
    canonical_batch = _batch_path("alice", canonical)

    h.phase("alias_git_receive_pack")
    (work / "after-rename.txt").write_text("after rename\n")
    h.git("add", "after-rename.txt", cwd=work)
    h.git("commit", "-m", "after rename", cwd=work)
    new_oid = h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
    assert len(new_oid) == 40 and new_oid != seed_oid
    assert (
        h.git("config", "--get", "remote.origin.url", cwd=work)
        .stdout.decode()
        .strip()
        .rstrip("/")
        == old_git_url.rstrip("/")
    )
    h.git(
        "-c",
        "http.followRedirects=true",
        "push",
        "origin",
        "HEAD:main",
        cwd=work,
        token=h.alice,
    )
    remote_head = h.git(
        "ls-remote", canonical_git_url, "refs/heads/main", token=h.alice
    ).stdout.decode().split()
    assert remote_head and remote_head[0] == new_oid
    assert remote_head[1] == "refs/heads/main"

    h.phase("alias_lfs_batch_redirect")
    lfs_bytes = b"alias-write-lfs-" * 64 + uuid.uuid4().bytes
    lfs_oid = hashlib.sha256(lfs_bytes).hexdigest()
    upload_body = _batch_body("upload", lfs_oid, len(lfs_bytes))
    status, _, headers = _request_batch(h, old_batch, upload_body, h.alice)
    assert status == 308
    assert headers.get("location") == canonical_batch
    assert headers.get("cache-control") == "no-store"

    h.phase("alias_lfs_upload")
    status, body, _ = _request_batch(h, canonical_batch, upload_body, h.alice)
    assert status == 200
    result = json.loads(body)["objects"][0]
    assert result["oid"] == lfs_oid
    assert result["size"] == len(lfs_bytes)
    actions = result.get("actions") or {}
    upload = actions.get("upload")
    verify = actions.get("verify")
    assert isinstance(upload, dict) and isinstance(verify, dict)
    upload_path = _href_path(upload["href"])
    verify_path = _href_path(verify["href"])
    base_netloc = urllib.parse.urlsplit(h.base).netloc
    assert urllib.parse.urlsplit(upload["href"]).netloc == base_netloc
    assert urllib.parse.urlsplit(verify["href"]).netloc == base_netloc
    assert upload_path == _object_path("alice", canonical, lfs_oid, len(lfs_bytes))
    assert verify_path == f"/git/alice/{canonical}.git/info/lfs/verify"
    status, _, _ = h.raw_http(
        upload_path,
        token=h.alice,
        method="PUT",
        body=lfs_bytes,
        content_type="application/octet-stream",
        extra_headers=upload.get("header") or {},
    )
    assert status in (200, 201)
    verify_headers = {"Accept": LFS_MIME}
    verify_headers.update(verify.get("header") or {})
    status, _, _ = h.raw_http(
        verify_path,
        token=h.alice,
        method="POST",
        content_type=LFS_MIME,
        extra_headers=verify_headers,
        body=_encode({"oid": lfs_oid, "size": len(lfs_bytes)}),
    )
    assert status == 200
    status, body, _ = h.raw_http(
        _object_path("alice", canonical, lfs_oid, len(lfs_bytes)), token=h.alice
    )
    assert status == 200
    assert body == lfs_bytes
    assert hashlib.sha256(body).hexdigest() == lfs_oid

    h.phase("restricted_token")
    restricted = h.issue_scoped_token(
        h.alice,
        "accept-alias-read",
        [{"repository_id": repo["id"], "actions": ["contents_read"]}],
    )
    old_refs = f"{old_git_prefix}/info/refs?service=git-upload-pack"
    canonical_refs = f"/git/alice/{canonical}.git/info/refs?service=git-upload-pack"
    status, _, headers = h.raw_http(old_refs, token=restricted, basic=True)
    assert status == 308
    assert headers.get("location") == canonical_refs
    assert headers.get("cache-control") == "no-store"
    status, _, _ = h.raw_http(canonical_refs, token=restricted, basic=True)
    assert status == 200

    download_body = _batch_body("download", seed_lfs_oid, len(seed_lfs))
    status, _, headers = _request_batch(h, old_batch, download_body, restricted)
    assert status == 308
    assert headers.get("location") == canonical_batch
    status, body, _ = _request_batch(h, canonical_batch, download_body, restricted)
    assert status == 200
    downloaded = json.loads(body)["objects"][0]
    assert downloaded["oid"] == seed_lfs_oid
    assert "download" in (downloaded.get("actions") or {})
    status, body, _ = h.raw_http(
        _object_path("alice", canonical, seed_lfs_oid, len(seed_lfs)),
        token=restricted,
    )
    assert status == 200 and body == seed_lfs

    h.phase("restricted_write_denials")
    refs_before = h.git(
        "ls-remote", canonical_git_url, token=restricted
    ).stdout.decode()
    status, _, headers = h.raw_http(
        f"{old_git_prefix}/info/refs?service=git-receive-pack",
        token=restricted,
        basic=True,
    )
    assert status == 403
    assert "location" not in headers

    (work / "denied.txt").write_text("denied write\n")
    h.git("add", "denied.txt", cwd=work)
    h.git("commit", "-m", "denied write", cwd=work)
    denied_oid = h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
    denied_push = h.git(
        "-c",
        "http.followRedirects=true",
        "push",
        "origin",
        "HEAD:refs/heads/restricted-denied",
        cwd=work,
        token=restricted,
        check=False,
    )
    assert denied_push.returncode != 0

    denied_lfs = b"alias-denied-lfs-" * 64 + uuid.uuid4().bytes
    denied_lfs_oid = hashlib.sha256(denied_lfs).hexdigest()
    denied_upload = _batch_body("upload", denied_lfs_oid, len(denied_lfs))
    status, _, headers = _request_batch(h, old_batch, denied_upload, restricted)
    assert status == 403
    assert "location" not in headers

    h.phase("assert_denial_unchanged")
    refs_after = h.git(
        "ls-remote", canonical_git_url, token=restricted
    ).stdout.decode()
    assert refs_after == refs_before
    assert "refs/heads/restricted-denied" not in refs_after
    assert denied_oid not in refs_after
    status, body, _ = h.raw_http(
        _object_path("alice", canonical, seed_lfs_oid, len(seed_lfs)),
        token=restricted,
    )
    assert status == 200 and body == seed_lfs
    status, _, _ = h.raw_http(
        _object_path("alice", canonical, denied_lfs_oid, len(denied_lfs)),
        token=restricted,
    )
    assert status == 404
    assert h.git(
        "ls-remote", canonical_git_url, "refs/heads/main", token=restricted
    ).stdout.decode().split()[0] == new_oid

    return {
        "fixture": "rename_alias_real_git_lfs",
        "alias_git_write": "passed",
        "alias_lfs_write": "passed",
        "canonical_head": "new_oid_verified",
        "canonical_bytes": "hash_verified",
        "restricted_read": "redirected",
        "restricted_write": "denied",
        "denied_mutation": "unchanged",
    }
