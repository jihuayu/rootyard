#!/usr/bin/env python3
"""Repository read-only Browse API and atomic multi-ref CAS transaction tests."""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness  # noqa: E402

ZERO_OID = "0" * 40


class BrowseHarness(Harness):
    def document(self, path, code=200, token=None, **kwargs):
        status, body, headers = self.http(path, token=token or self.alice, **kwargs)
        norm_headers = {k.lower(): v for k, v in headers.items()}
        if isinstance(code, tuple):
            assert status in code, f"{path}: expected {code}, got {status}: {body[:300]!r}"
        else:
            assert status == code, f"{path}: expected {code}, got {status}: {body[:300]!r}"
        assert norm_headers.get("cache-control") == "no-store", norm_headers
        assert "application/json" in norm_headers.get("content-type", ""), norm_headers
        return json.loads(body)

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

        # Repository recovering fence
        self.sql(
            f"UPDATE repositories SET state='recovering', recovery_reason='push_outcome_unknown' WHERE id='{self.repo['id']}'"
        )
        try:
            for path in read_paths:
                self.document(path, 409)
            self.document(self.repo_api("/ref-transactions"), 409, method="POST", body=tx_body)
        finally:
            self.sql(
                f"UPDATE repositories SET state='ready', recovery_reason=NULL WHERE id='{self.repo['id']}'"
            )

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
        for name in (
            "setup_repos",
            "refs_and_pagination",
            "commits_and_pagination",
            "tree_and_blob",
            "compare_revisions",
            "ref_transactions_atomic_cas",
            "idempotency_and_concurrency",
            "access_and_fences",
            "object_format_and_negotiation",
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
            cases=harness.results,
            binary_sha256=binary_sha,
            limitations=[
                "Personal owner-only tenancy; non-owners receive 404 Not Found.",
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
