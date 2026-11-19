#!/usr/bin/env python3
"""Source-only witness for the documented hosted FUSE compatibility state.

This file is deliberately not named ``test_*.py``: it is a separately selected
acceptance source, not part of the default unittest discovery or CI wiring. It
has not been executed by the source-only checkpoint that added it. A qualified
Linux host must provide a real PostgreSQL test database, ``/dev/fuse``, user and
mount namespace support (``unshare -Urm``), bubblewrap, and a source-bound
prebuilt ``rootyard`` binary.

Minimal invocation (the same backend selector used by
``tests/test_workspace_fuse_service.py`` is honoured)::

    ROOTYARD_TEST_FUSE_COMPAT_WITNESS=1 \
    ROOTYARD_TEST_FUSE_BACKEND=fuse \
    ROOTYARD_TEST_DATABASE_URL=postgresql://.../rootyard_test \
    ROOTYARD_BIN=/absolute/path/to/source-bound/rootyard \
    python3 tests/workspace_fuse_compat_witness.py -v

The case exercises only the already-documented supported hosted state:

* a real workspace is created through the authorised service API and exposed
  through the real FUSE mount;
* ``HEAD`` is detached on that actual mount with the stock Git binary;
* a tracked inert ``filter=lfs`` pointer and ``.gitattributes`` are captured
  byte-for-byte, with no local executable filter driver and no LFS hydration;
* an ordinary working-tree write and one hosted Git index mutation (``add``)
  run through the service's owned native Git route;
* bounded ``status``/``diff``/index/``HEAD``/``fsck`` checks run against the
  actual mounted workspace;
* a coherent local checkpoint is captured, the service is stopped and started
  to force an unmount/remount, and a bounded local checkpoint restore is made;
* the original service-owned source repository stays byte/ref/object stable.

The fixture owns its disposable service data directory and its loopback Git
remote, but it does not own an external remote checkpoint/object store. It
therefore performs a local checkpoint restore and makes **no** remote publish,
remote restore or cross-host claim. True remote proof remains open.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import time
import unittest
from urllib.parse import quote

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for directory in (REPO_ROOT, TESTS_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from lfs import LfsHarness  # noqa: E402
from runtime_binary import select_runtime_binary  # noqa: E402
from test_workspace_fuse_service import MOUNT_MODE  # noqa: E402

WITNESS_GATE = "ROOTYARD_TEST_FUSE_COMPAT_WITNESS"
HELLO = b"ordinary write through live mount\n"
OLD_HELLO = b"second\n"
ATTRS_NAME = ".gitattributes"
POINTER_NAME = "lfs-pointer.bin"
# Exactly 12 deterministic bytes; the pointer below is the only source
# representation of this object. The service must already possess the verified
# object before the source push introduces a pointer that references it.
LFS_PAYLOAD = b"rootyard-lfs"
LFS_SIZE = len(LFS_PAYLOAD)
LFS_OID = hashlib.sha256(LFS_PAYLOAD).hexdigest()
ATTRS = (
    b"# Inert LFS marker: this fixture configures no local clean/smudge driver.\n"
    b"lfs-pointer.bin filter=lfs diff=lfs -text\n"
)
POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n"
    b"oid sha256:" + LFS_OID.encode("ascii") + b"\n"
    b"size " + str(LFS_SIZE).encode("ascii") + b"\n"
)
ARTIFACT_LIMIT = 16 * 1024 * 1024


def _blob_oid(data: bytes) -> bytes:
    """Return the exact SHA-1 Git blob object id for ``data`` without Git."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest().encode()


class WorkspaceFuseCompatWitnessTest(unittest.TestCase):
    def setUp(self):
        if os.environ.get(WITNESS_GATE) != "1":
            self.fail(
                f"this source-only witness is fail-closed; set {WITNESS_GATE}=1 "
                "on a qualified Linux FUSE host before selecting it"
            )
        if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
            self.fail("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
        if not sys.platform.startswith("linux"):
            self.fail("the hosted FUSE witness requires Linux user/mount namespaces")
        if not Path("/dev/fuse").exists():
            self.fail("the hosted FUSE witness requires a usable /dev/fuse")

    # -- bounded service helpers ------------------------------------------------

    def state(self, h, wid):
        return json.loads(h.expect(f"/api/workspaces/{wid}", 200, token=h.alice))

    def view(self, h, wid, path, view=None):
        query = "?path=" + quote(path, safe="")
        if view is not None:
            query += "&view=" + quote(view, safe="")
        payload = json.loads(
            h.expect(f"/api/workspaces/{wid}/files{query}", 200, token=h.alice)
        )
        raw = base64.b64decode(payload["content_base64"])
        self.assertEqual(payload["sha256"], hashlib.sha256(raw).hexdigest())
        return raw

    def live_job(self, h, wid, lease_epoch, script, timeout=30):
        created = json.loads(
            h.expect(
                f"/api/workspaces/{wid}/sandbox-jobs",
                201,
                token=h.alice,
                method="POST",
                body={
                    "argv": ["/bin/sh", "-c", script],
                    "timeout_seconds": timeout,
                    "lease_epoch": lease_epoch,
                    "workspace_access": "live",
                },
            )
        )
        deadline = time.monotonic() + timeout + 15
        result = None
        while time.monotonic() < deadline:
            result = json.loads(
                h.expect(f"/api/sandbox-jobs/{created['id']}", 200, token=h.alice)
            )
            if result["state"] not in ("queued", "preparing", "running"):
                break
            time.sleep(0.1)
        else:
            self.fail(
                f"live FUSE job {created['id']} did not reach a terminal state "
                f"within {timeout + 15}s"
            )
        if result["state"] != "succeeded":
            detail = ""
            status, raw, _ = h.http(
                f"/api/sandbox-jobs/{created['id']}/logs", token=h.alice
            )
            if status == 200:
                logs = json.loads(raw)
                stdout = base64.b64decode(logs.get("stdout_base64", ""))[-2000:]
                stderr = base64.b64decode(logs.get("stderr_base64", ""))[-2000:]
                detail = f" stdout={stdout!r} stderr={stderr!r}"
            self.fail(
                f"live FUSE job {created['id']} ended {result['state']} "
                f"exit={result.get('exit_code')}{detail}"
            )
        return result

    def artifact(self, h, job, name):
        payload = json.loads(
            h.expect(
                f"/api/sandbox-jobs/{job['id']}/artifacts?path={quote(name, safe='')}",
                200,
                token=h.alice,
            )
        )
        raw = base64.b64decode(payload["content_base64"])
        self.assertEqual(payload["path"], name)
        self.assertEqual(payload["size"], len(raw))
        self.assertLessEqual(len(raw), ARTIFACT_LIMIT)
        return raw

    def assert_fsck_clean(self, output):
        lowered = output.lower()
        for marker in (b"error", b"fatal", b"missing", b"broken"):
            self.assertNotIn(marker, lowered, output[-2000:])

    def probe_script(self, prefix):
        """Read-only checks against the actual mounted workspace.

        ``GIT_OPTIONAL_LOCKS=0`` prevents status/index refreshes from changing
        the fingerprint between the hosted Git commit and checkpoint capture.
        ``--no-ext-diff`` and the scrubbed Git environment keep the inert LFS
        attributes from invoking any external driver.
        """
        return f"""set -eu
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 GIT_OPTIONAL_LOCKS=0 LC_ALL=C
cd /workspace
mkdir -p /artifacts
if git symbolic-ref -q HEAD > /artifacts/{prefix}_symref; then
  echo "HEAD is attached; expected a detached HEAD" >&2
  exit 1
fi
git --no-optional-locks status --porcelain=v1 -z > /artifacts/{prefix}_status
git --no-optional-locks diff --cached --full-index --no-color --no-ext-diff --no-textconv -- hello.txt > /artifacts/{prefix}_diff
git --no-optional-locks ls-files -s -- {ATTRS_NAME} hello.txt {POINTER_NAME} > /artifacts/{prefix}_index
git rev-parse HEAD > /artifacts/{prefix}_head
cat .git/HEAD > /artifacts/{prefix}_git_head
git cat-file -p HEAD:{POINTER_NAME} > /artifacts/{prefix}_head_pointer
git cat-file -p HEAD:{ATTRS_NAME} > /artifacts/{prefix}_head_attrs
git cat-file -p :hello.txt > /artifacts/{prefix}_index_hello
cat hello.txt > /artifacts/{prefix}_work_hello
cat {POINTER_NAME} > /artifacts/{prefix}_work_pointer
cat {ATTRS_NAME} > /artifacts/{prefix}_work_attrs
git fsck --full --strict > /artifacts/{prefix}_fsck 2>&1
"""

    def verify_mounted_state(self, h, wid, lease_epoch, expected, prefix):
        job = self.live_job(h, wid, lease_epoch, self.probe_script(prefix))
        self.assertEqual(self.artifact(h, job, f"{prefix}_symref"), b"")
        self.assertEqual(self.artifact(h, job, f"{prefix}_status"), expected["status"])
        self.assertEqual(self.artifact(h, job, f"{prefix}_diff"), expected["diff"])
        self.assertEqual(
            sorted(self.artifact(h, job, f"{prefix}_index").splitlines()),
            expected["index"],
        )
        self.assertEqual(self.artifact(h, job, f"{prefix}_head"), expected["head"])
        self.assertEqual(self.artifact(h, job, f"{prefix}_git_head"), expected["git_head"])
        self.assertEqual(self.artifact(h, job, f"{prefix}_head_pointer"), POINTER)
        self.assertEqual(self.artifact(h, job, f"{prefix}_head_attrs"), ATTRS)
        self.assertEqual(self.artifact(h, job, f"{prefix}_index_hello"), HELLO)
        self.assertEqual(self.artifact(h, job, f"{prefix}_work_hello"), HELLO)
        self.assertEqual(self.artifact(h, job, f"{prefix}_work_pointer"), POINTER)
        self.assertEqual(self.artifact(h, job, f"{prefix}_work_attrs"), ATTRS)
        self.assert_fsck_clean(self.artifact(h, job, f"{prefix}_fsck"))

    def add_with_retry(self, h, wid, key):
        for attempt in range(12):
            current = self.state(h, wid)
            status, raw, _ = h.http(
                f"/api/workspaces/{wid}/git",
                token=h.alice,
                method="POST",
                body={
                    "action": "add",
                    "paths": ["hello.txt"],
                    "expected_git_generation": current["git_generation"],
                    "expected_workspace_revision": current["revision"],
                    "lease_epoch": current["lease_epoch"],
                },
                extra_headers={"Idempotency-Key": f"{key}-{attempt}"},
            )
            if status == 200:
                return json.loads(raw)
            if status != 409 or b"workspace version or lease conflict" not in raw:
                self.fail(f"hosted Git add failed: status={status} body={raw[:500]!r}")
            time.sleep(0.2)
        self.fail("hosted Git add did not commit within the bounded retry window")

    def checkpoint_with_retry(self, h, wid, key):
        for attempt in range(12):
            current = self.state(h, wid)
            status, raw, _ = h.http(
                f"/api/workspaces/{wid}/checkpoints",
                token=h.alice,
                method="POST",
                body={
                    "expected_workspace_revision": current["revision"],
                    "lease_epoch": current["lease_epoch"],
                },
                extra_headers={"Idempotency-Key": f"{key}-{attempt}"},
            )
            if status == 201:
                checkpoint = json.loads(raw)
                self.assertEqual(checkpoint["state"], "local_complete")
                self.assertEqual(checkpoint["captured_revision"], current["revision"])
                return checkpoint
            if status != 409 or b"workspace version or lease conflict" not in raw:
                self.fail(
                    f"checkpoint failed: status={status} body={raw[:500]!r}"
                )
            time.sleep(0.2)
        self.fail("checkpoint did not commit within the bounded retry window")

    def source_facts(self, h):
        git_dir = "--git-dir=" + str(h.bare)
        fsck = h.git(git_dir, "fsck", "--full", "--strict")
        return {
            "head": h.git(git_dir, "rev-parse", "HEAD").stdout.strip(),
            "refs": h.git(git_dir, "show-ref").stdout,
            "fsck": b"\n".join(sorted((fsck.stdout + fsck.stderr).splitlines())),
            "pointer": h.git(git_dir, "cat-file", "-p", f"HEAD:{POINTER_NAME}").stdout,
            "attrs": h.git(git_dir, "cat-file", "-p", f"HEAD:{ATTRS_NAME}").stdout,
            "work_head": h.git("rev-parse", "HEAD", cwd=h.work).stdout.strip(),
            "work_status": h.git(
                "--no-optional-locks",
                "status",
                "--porcelain=v1",
                "-z",
                cwd=h.work,
            ).stdout,
        }

    # -- witness ---------------------------------------------------------------

    def test_detached_inert_lfs_checkpoint_remount_and_local_restore(self):
        binary, _ = select_runtime_binary()
        self.assertTrue(binary.is_file())
        with tempfile.TemporaryDirectory(
            prefix="rootyard-fuse-compat-witness-"
        ) as wrapper_dir:
            wrapper = Path(wrapper_dir) / "rootyard-userns"
            wrapper.write_text(
                "#!/bin/sh\nexec unshare -Urm "
                + shlex.quote(str(binary))
                + ' "$@"\n'
            )
            wrapper.chmod(0o700)
            h = LfsHarness(argparse.Namespace(binary=str(wrapper), keep=False))
            try:
                h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = MOUNT_MODE
                h.env["ROOTYARD_SANDBOX_MODE"] = "dev"
                h.setup()
                h.api()
                h.roundtrip()

                # Register, upload, verify and read back the deterministic
                # 12-byte object before the source push can reference it. The
                # pointer stays inert in Git; this only makes the promised LFS
                # bytes available to the existing pre-receive verifier.
                self.assertEqual(LFS_SIZE, 12)
                self.assertEqual(LFS_OID, hashlib.sha256(LFS_PAYLOAD).hexdigest())
                upload = h.lfs_batch(
                    "upload", [{"oid": LFS_OID, "size": LFS_SIZE}], token=h.alice
                )
                self.assertEqual(upload["transfer"], "basic")
                self.assertEqual(len(upload["objects"]), 1)
                uploaded = upload["objects"][0]
                self.assertEqual(uploaded["oid"], LFS_OID)
                self.assertEqual(uploaded["size"], LFS_SIZE)
                upload_action = uploaded["actions"]["upload"]
                verify_action = uploaded["actions"]["verify"]
                status, _, _ = h.lfs_put(
                    upload_action["href"], LFS_PAYLOAD, token=h.alice, code=200
                )
                self.assertEqual(status, 200)
                verified = h.lfs_verify(
                    verify_action["href"], LFS_OID, LFS_SIZE, token=h.alice, code=200
                )
                self.assertEqual(verified.get("verified"), True)
                self.assertEqual(verified.get("oid"), LFS_OID)
                self.assertEqual(verified.get("size"), LFS_SIZE)
                download = h.lfs_batch(
                    "download", [{"oid": LFS_OID, "size": LFS_SIZE}], token=h.alice
                )
                self.assertEqual(download["objects"][0]["oid"], LFS_OID)
                self.assertEqual(download["objects"][0]["size"], LFS_SIZE)
                download_href = download["objects"][0]["actions"]["download"]["href"]
                status, readback, _ = h.lfs_get(
                    download_href, token=h.alice, code=200
                )
                self.assertEqual(status, 200)
                self.assertEqual(readback, LFS_PAYLOAD)
                self.assertEqual(hashlib.sha256(readback).hexdigest(), LFS_OID)

                # Fixture: a real source commit whose HEAD tracks an inert LFS
                # pointer and its attributes. No local filter driver exists.
                self.assertEqual(
                    h.git(
                        "config",
                        "--local",
                        "--get-regexp",
                        "^filter\\.",
                        cwd=h.work,
                        check=False,
                    ).stdout,
                    b"",
                    "source fixture unexpectedly has a local filter driver",
                )
                (h.work / ATTRS_NAME).write_bytes(ATTRS)
                (h.work / POINTER_NAME).write_bytes(POINTER)
                h.git("add", "--", ATTRS_NAME, POINTER_NAME, cwd=h.work)
                self.assertEqual(
                    h.git("cat-file", "-p", f":{POINTER_NAME}", cwd=h.work).stdout,
                    POINTER,
                    "source add hydrated the inert LFS pointer",
                )
                h.git(
                    "commit",
                    "-m",
                    "test: track inert LFS pointer and attributes",
                    cwd=h.work,
                )
                base_oid = (
                    h.git("rev-parse", "HEAD", cwd=h.work)
                    .stdout.decode()
                    .strip()
                )
                h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice)
                self.assertEqual(
                    h.git("show", f"HEAD:{POINTER_NAME}", cwd=h.work).stdout,
                    POINTER,
                )
                self.assertEqual(
                    h.git("show", f"HEAD:{ATTRS_NAME}", cwd=h.work).stdout,
                    ATTRS,
                )
                self.assertEqual(
                    h.git(
                        "check-attr", "filter", "--", POINTER_NAME, cwd=h.work
                    ).stdout,
                    f"{POINTER_NAME}: filter: lfs\n".encode(),
                )
                source_before = self.source_facts(h)
                self.assertEqual(source_before["head"], base_oid.encode())
                self.assertEqual(source_before["pointer"], POINTER)
                self.assertEqual(source_before["attrs"], ATTRS)

                workspace = json.loads(
                    h.expect(
                        "/api/workspaces",
                        201,
                        token=h.alice,
                        method="POST",
                        body={
                            "owner": "alice",
                            "repository": "demo",
                            "agent_id": "fuse-compat-witness",
                            "base_oid": base_oid,
                        },
                        extra_headers={
                            "Idempotency-Key": "fuse-compat-witness-create"
                        },
                    )
                )
                wid = workspace["id"]
                self.assertEqual(workspace["state"], "ready")
                self.assertEqual(
                    self.view(h, wid, POINTER_NAME, "head"), POINTER
                )
                self.assertEqual(self.view(h, wid, ATTRS_NAME, "head"), ATTRS)

                # Mutate only through the actual mount. The ordinary write and
                # detached HEAD happen in one bounded live job; the hosted Git
                # route then owns the index mutation.
                prepare = f"""set -eu
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 GIT_OPTIONAL_LOCKS=0 LC_ALL=C
cd /workspace
mkdir -p /artifacts
git -c core.hooksPath=/dev/null -c core.fsmonitor=false -c gc.auto=0 checkout --detach HEAD
printf %s {shlex.quote(HELLO.decode())} > hello.txt
test -z "$(git config --local --get-regexp '^(filter|diff|merge)[.]' || true)"
test "$(git check-attr filter -- {POINTER_NAME})" = "{POINTER_NAME}: filter: lfs"
git rev-parse HEAD > /artifacts/pre_head
cat .git/HEAD > /artifacts/pre_git_head
cat {POINTER_NAME} > /artifacts/pre_work_pointer
cat {ATTRS_NAME} > /artifacts/pre_work_attrs
"""
                prepare_job = self.live_job(
                    h, wid, self.state(h, wid)["lease_epoch"], prepare
                )
                self.assertEqual(
                    self.artifact(h, prepare_job, "pre_head").strip(),
                    base_oid.encode(),
                )
                self.assertEqual(
                    self.artifact(h, prepare_job, "pre_git_head").strip(),
                    base_oid.encode(),
                )
                self.assertEqual(
                    self.artifact(h, prepare_job, "pre_work_pointer"), POINTER
                )
                self.assertEqual(
                    self.artifact(h, prepare_job, "pre_work_attrs"), ATTRS
                )

                added = self.add_with_retry(
                    h, wid, "fuse-compat-witness-add"
                )
                self.assertEqual(added["action"], "add")
                self.assertEqual(base64.b64decode(added["output_base64"]), b"")
                self.assertEqual(self.view(h, wid, "hello.txt", "working"), HELLO)
                self.assertEqual(self.view(h, wid, "hello.txt", "index"), HELLO)
                self.assertEqual(self.view(h, wid, "hello.txt", "head"), OLD_HELLO)
                self.assertEqual(
                    self.view(h, wid, POINTER_NAME, "working"), POINTER
                )
                self.assertEqual(self.view(h, wid, ATTRS_NAME, "working"), ATTRS)

                old_oid = _blob_oid(OLD_HELLO)
                new_oid = _blob_oid(HELLO)
                expected = {
                    "status": b"M  hello.txt\0",
                    "diff": (
                        b"diff --git a/hello.txt b/hello.txt\n"
                        b"index " + old_oid + b".." + new_oid + b" 100644\n"
                        b"--- a/hello.txt\n"
                        b"+++ b/hello.txt\n"
                        b"@@ -1 +1 @@\n"
                        b"-second\n"
                        b"+ordinary write through live mount\n"
                    ),
                    "index": sorted(
                        [
                            b"100644 " + _blob_oid(ATTRS) + b" 0\t" + ATTRS_NAME.encode(),
                            b"100644 " + _blob_oid(HELLO) + b" 0\thello.txt",
                            b"100644 " + _blob_oid(POINTER) + b" 0\t" + POINTER_NAME.encode(),
                        ]
                    ),
                    "head": base_oid.encode() + b"\n",
                    "git_head": base_oid.encode() + b"\n",
                }
                self.verify_mounted_state(
                    h,
                    wid,
                    self.state(h, wid)["lease_epoch"],
                    expected,
                    "pre",
                )

                checkpoint = self.checkpoint_with_retry(
                    h, wid, "fuse-compat-witness-checkpoint"
                )
                cid = checkpoint["checkpoint_id"]
                self.assertEqual(checkpoint["state"], "local_complete")
                checkpoint_dir = (
                    h.root
                    / "data/workspace-service/checkpoints"
                    / cid
                )
                self.assertEqual((checkpoint_dir / "hello.txt").read_bytes(), HELLO)
                self.assertEqual(
                    (checkpoint_dir / POINTER_NAME).read_bytes(), POINTER
                )
                self.assertEqual(
                    (checkpoint_dir / ATTRS_NAME).read_bytes(), ATTRS
                )
                self.assertEqual(
                    (checkpoint_dir / ".git/HEAD").read_text(encoding="utf-8").strip(),
                    base_oid,
                )
                self.assertEqual(
                    h.git("rev-parse", "HEAD", cwd=checkpoint_dir)
                    .stdout.decode()
                    .strip(),
                    base_oid,
                )
                self.assertEqual(
                    h.git(
                        "cat-file", "-p", f"HEAD:{POINTER_NAME}", cwd=checkpoint_dir
                    ).stdout,
                    POINTER,
                )
                self.assertEqual(
                    h.git(
                        "cat-file", "-p", f"HEAD:{ATTRS_NAME}", cwd=checkpoint_dir
                    ).stdout,
                    ATTRS,
                )
                self.assertEqual(
                    h.git(
                        "--no-optional-locks",
                        "status",
                        "--porcelain=v1",
                        "-z",
                        cwd=checkpoint_dir,
                    ).stdout,
                    expected["status"],
                )
                self.assertEqual(
                    sorted(
                        h.git(
                            "--no-optional-locks",
                            "ls-files",
                            "-s",
                            "--",
                            ATTRS_NAME,
                            "hello.txt",
                            POINTER_NAME,
                            cwd=checkpoint_dir,
                        ).stdout.splitlines()
                    ),
                    expected["index"],
                )
                self.assertEqual(
                    h.git("cat-file", "-p", ":hello.txt", cwd=checkpoint_dir).stdout,
                    HELLO,
                )
                checkpoint_fsck = h.git(
                    "fsck", "--full", "--strict", cwd=checkpoint_dir
                )
                self.assert_fsck_clean(checkpoint_fsck.stdout + checkpoint_fsck.stderr)
                self.assertEqual(self.source_facts(h), source_before)

                # Force a real unmount/remount, then re-check the same state.
                h.stop(hard=True)
                h.start()
                self.assertEqual(self.view(h, wid, "hello.txt", "working"), HELLO)
                self.assertEqual(self.view(h, wid, "hello.txt", "index"), HELLO)
                self.assertEqual(self.view(h, wid, "hello.txt", "head"), OLD_HELLO)
                self.assertEqual(
                    self.view(h, wid, POINTER_NAME, "working"), POINTER
                )
                self.assertEqual(self.view(h, wid, ATTRS_NAME, "working"), ATTRS)
                self.verify_mounted_state(
                    h,
                    wid,
                    self.state(h, wid)["lease_epoch"],
                    expected,
                    "remount",
                )

                # Bounded local restore. No remote publish is attempted and no
                # remote/cross-host durability is claimed by this fixture.
                restored = json.loads(
                    h.expect(
                        f"/api/checkpoints/{cid}/restore",
                        201,
                        token=h.alice,
                        method="POST",
                        body={"agent_id": "fuse-compat-witness-restored"},
                        extra_headers={
                            "Idempotency-Key": "fuse-compat-witness-restore"
                        },
                    )
                )
                rid = restored["id"]
                self.assertNotEqual(rid, wid)
                self.assertEqual(restored["state"], "ready")
                self.assertEqual(self.view(h, rid, "hello.txt", "working"), HELLO)
                self.assertEqual(self.view(h, rid, "hello.txt", "index"), HELLO)
                self.assertEqual(self.view(h, rid, "hello.txt", "head"), OLD_HELLO)
                self.assertEqual(
                    self.view(h, rid, POINTER_NAME, "working"), POINTER
                )
                self.assertEqual(self.view(h, rid, ATTRS_NAME, "working"), ATTRS)
                restored_dir = (
                    h.root / "data/workspace-service/workspaces" / rid
                )
                self.assertEqual(
                    (restored_dir / ".git/HEAD").read_text(encoding="utf-8").strip(),
                    base_oid,
                )
                self.assertEqual((restored_dir / "hello.txt").read_bytes(), HELLO)
                self.assertEqual(
                    (restored_dir / POINTER_NAME).read_bytes(), POINTER
                )
                self.assertEqual((restored_dir / ATTRS_NAME).read_bytes(), ATTRS)
                self.assertEqual(
                    h.git("cat-file", "-p", ":hello.txt", cwd=restored_dir).stdout,
                    HELLO,
                )
                restored_fsck = h.git(
                    "fsck", "--full", "--strict", cwd=restored_dir
                )
                self.assert_fsck_clean(restored_fsck.stdout + restored_fsck.stderr)
                self.verify_mounted_state(
                    h,
                    rid,
                    self.state(h, rid)["lease_epoch"],
                    expected,
                    "restore",
                )
                self.assertEqual(self.source_facts(h), source_before)
            finally:
                h.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
