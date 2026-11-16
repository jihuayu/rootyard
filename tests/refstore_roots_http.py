#!/usr/bin/env python3
"""Root-only real-service HTTP fixture for retention-root metadata/intent transport.

This is source-only until Root runs it with the attested standalone binary, real
PostgreSQL/S3/trusted Git and the owned Blob profile. Repository/source/snapshot
state comes only from the real API/provision/A3/A4/A5/Git paths inherited from
the snapshot fixture; no ready/ACK/grant/pack/root/receipt row is fabricated.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import blob_only_service as blob  # noqa: E402
import refstore_snapshot_http as snapshot  # noqa: E402

ROOTS_CASE = "roots_http_metadata_create_release_and_intent"

LIMITATIONS = [
    "Root-only real-service HTTP fixture; only py-compiled/static-inspected by the implementation worker.",
    "Repositories, source snapshots, pins, roots and receipts are created through real API/A3/A4/A5/Git/root paths; no SQL or fabricated authority rows are used.",
    "The fixture does not claim Root byte browsing, post-JSON finalization, hosted CI inventory, native acceptance or full issue107 closure. Root tree/blob source coverage lives in the sibling tests/refstore_root_browse_http.py fixture.",
    "Authorization/role inputs use the existing real token API and labeled initial collaborator metadata where the public grant transport is outside this metadata checkpoint.",
    "The fixture does not delete/prune stored A5 snapshot/ref/pack rows and does not force the ByIntent source-metadata-miss fallback. Existing coordinator fixtures cover source-pin release and the pre-existing Absent-target tombstone barrier, not this ByIntent-specific race.",
]


class RootsHttpHarness(snapshot.SnapshotHttpHarness):
    _RECEIPT_EXPECTATIONS = {
        "register": (1, "active"),
        "release": (2, "released"),
    }

    def _roots_path(self, repo, suffix=""):
        return self._repo_path(repo, "/roots" + suffix)

    def _create_root(self, repo, create, token=None):
        status, data, _ = self._request("POST", self._roots_path(repo), token or self.alice, create)
        return status, data

    def _read_root(self, repo, root_id, token=None):
        status, data, _ = self._request("GET", self._roots_path(repo, "/" + str(root_id)), token or self.alice)
        return status, data

    def _delete_root(self, repo, root_id, body, token=None):
        status, data, _ = self._request("DELETE", self._roots_path(repo, "/" + str(root_id)),
                                        token or self.alice, body)
        return status, data

    def _release_intent(self, repo, body, token=None):
        status, data, _ = self._request("POST", self._roots_path(repo, "/release-intent"),
                                        token or self.alice, body)
        return status, data

    @staticmethod
    def _intent(key, source_snapshot_id, purpose="ci", selector=None):
        return {
            "idempotency_key": key,
            "source_snapshot_id": source_snapshot_id,
            "purpose": purpose,
            "selector": selector or {"kind": "snapshot"},
        }

    @staticmethod
    def _release_body(key, reason="fixture release"):
        return {"idempotency_key": key, "reason": reason}

    def _assert_receipt(self, data, expected_action="register"):
        # The sibling browse fixture only creates roots and keeps calling the
        # finite register default. Every roots-module lifecycle call is explicit.
        assert expected_action in self._RECEIPT_EXPECTATIONS, \
            "receipt expected action is not in the finite source allowlist"
        expected_generation, expected_state = self._RECEIPT_EXPECTATIONS[expected_action]
        assert set(data) == {"action", "root_id", "generation", "replayed",
                             "created_at_unix_micros", "receipt_only", "receipt_state"}, \
            "receipt shape differs"
        assert data["receipt_only"] is True, "receipt_only is not true"
        assert data["action"] == expected_action, \
            "receipt action differs from the finite expected action"
        assert data["generation"] == expected_generation, \
            "receipt generation differs from the expected lifecycle generation"
        assert data["receipt_state"] == expected_state, \
            "receipt state differs from the expected lifecycle state"
        self._forbidden_markers(data)

    def _assert_metadata(self, data):
        assert set(data) == {"root_id", "current_state", "generation", "purpose", "selector_kind",
                             "object_format", "head_ref", "head_oid", "ref_count", "pack_count",
                             "oid_count"}, "metadata shape differs"
        assert data["current_state"] in ("active", "released"), \
            "metadata state is not a finite lifecycle state"
        # Metadata generation is the retained capture generation, not the
        # receipt lifecycle generation; it must remain 1 after release.
        assert data["generation"] == 1, "metadata retained capture generation is not 1"
        self._forbidden_markers(data)

    def _assert_unauthorized(self, method, path, body=None):
        status, _raw, headers = self.http(path, token=None, method=method, body=body)
        assert status == 401, "unauthorized status differs"
        assert blob.header_value(headers, "www-authenticate") == 'Bearer realm="Rootyard"', \
            "unauthorized www-authenticate differs"
        assert blob.header_value(headers, "cache-control") == "no-store", \
            "unauthorized cache-control differs"
        assert blob.header_value(headers, "x-rootyard-session") is None, \
            "unauthorized session header is present"

    def roots_http_metadata_create_release_and_intent(self):
        repo, _remote, _work, old_oid = self.seed("roots-http-metadata")
        snapshot_one = self._create(repo, "roots-http-source-one", 300)[1]["snapshot_id"]
        create = self._intent("roots-http-create", snapshot_one)

        status, receipt = self._create_root(repo, create)
        assert status == 201, "root create status differs"
        self._assert_receipt(receipt, "register")
        root_id = receipt["root_id"]
        assert receipt["action"] == "register", "root create action differs"
        status, retry = self._create_root(repo, create)
        assert status == 200 and retry["replayed"] is True, \
            "root create replay status/replayed differs"
        self._assert_receipt(retry, "register")
        assert retry["root_id"] == root_id, "root create replay root_id differs"

        status, metadata = self._read_root(repo, root_id)
        assert status == 200, "root metadata status differs"
        self._assert_metadata(metadata)
        assert metadata["current_state"] == "active" and metadata["purpose"] == "ci", \
            "root metadata active purpose differs"
        assert metadata["selector_kind"] == "snapshot", "root metadata selector kind differs"

        # Changed purpose/source/selector under the same create key all conflict
        # without touching the active root or charging another root.
        changed = dict(create, purpose="workspace")
        status, _ = self._create_root(repo, changed)
        assert status == 409, "changed purpose status differs"
        changed = dict(create, selector={"kind": "oids", "oids": [old_oid]})
        status, _ = self._create_root(repo, changed)
        assert status == 409, "changed selector status differs"
        snapshot_other = self._create(repo, "roots-http-source-other", 300)[1]["snapshot_id"]
        changed = dict(create, source_snapshot_id=snapshot_other)
        status, _ = self._create_root(repo, changed)
        assert status == 409, "changed source status differs"
        status, still_active = self._read_root(repo, root_id)
        assert status == 200 and still_active["current_state"] == "active", \
            "active root changed after create refusal"

        # Read-only owner metadata is allowed; metadata-only rejection remains 403
        # for mutations.
        status, _read_metadata = self._read_root(repo, root_id, token=self.reader)
        assert status == 200, "read-only root metadata status differs"
        status, _ = self._create_root(repo, self._intent("roots-http-reader-write", snapshot_other),
                                      token=self.reader)
        assert status == 403, "read-only create status differs"

        # Existing-root release remains source-independent after the source pin is
        # actually released through the snapshot API.
        status, _, _ = self._release(repo, snapshot_one, "roots-http-source-release", 1)
        assert status == 200, "source pin release status differs"
        status, released = self._delete_root(repo, root_id, self._release_body("roots-http-release"))
        assert status == 200, "root release status differs"
        self._assert_receipt(released, "release")
        assert released["action"] == "release" and released["receipt_state"] == "released", \
            "root release action/state differs"
        status, reused = self._delete_root(repo, root_id, self._release_body("roots-http-release"))
        assert status == 200 and reused["replayed"] is True, \
            "root release replay status/replayed differs"
        self._assert_receipt(reused, "release")
        status, released_metadata = self._read_root(repo, root_id)
        assert status == 200 and released_metadata["current_state"] == "released", \
            "released root metadata status/state differs"

        # Release-before-register: no client root id; exact replay is independent
        # of the source metadata after the source pin is released.
        snapshot_two = self._create(repo, "roots-http-source-two", 300)[1]["snapshot_id"]
        intent_body = {
            "create": self._intent("roots-http-intent", snapshot_two),
            "idempotency_key": "roots-http-intent-release",
            "reason": "release before register",
        }
        status, intent_receipt = self._release_intent(repo, intent_body)
        assert status == 200, "release-intent create status differs"
        self._assert_receipt(intent_receipt, "release")
        intent_root = intent_receipt["root_id"]
        assert intent_receipt["action"] == "release", "release-intent create action differs"
        status, _ = self._read_root(repo, intent_root)
        assert status == 404, "release-before-register metadata status differs"
        status, _, _ = self._release(repo, snapshot_two, "roots-http-source-two-release", 1)
        assert status == 200, "source two release status differs"
        status, intent_replay = self._release_intent(repo, intent_body)
        assert status == 200 and intent_replay["replayed"] is True, \
            "release-intent replay status/replayed differs"
        self._assert_receipt(intent_replay, "release")
        assert intent_replay["root_id"] == intent_root, "release-intent replay root_id differs"

        changed_intent = json.loads(json.dumps(intent_body))
        changed_intent["create"]["purpose"] = "workspace"
        status, _ = self._release_intent(repo, changed_intent)
        assert status == 409, "changed release intent status differs"

        baseline = self._ledger(repo)
        root_baseline = self._root_rows(repo)

        # Authentication/validation and transport contracts.
        status, _ = self._create_root(repo, self._intent("roots-http-bob", snapshot_other), token=self.bob)
        assert status == 404, "non-member create status differs"
        other_repo, _other_remote, _other_work, _other_oid = self.seed("roots-http-foreign")
        status, _ = self._read_root(other_repo, root_id)
        assert status == 404, "foreign root status differs"
        status, _ = self._read_root(repo, "00000000-0000-0000-0000-000000000000")
        assert status == 400, "nil root id status differs"
        forged = dict(self._intent("roots-http-forged", snapshot_other), register_digest="00" * 32)
        status, _ = self._create_root(repo, forged)
        assert status == 400, "forged authority field status differs"
        bad_purpose = dict(self._intent("roots-http-purpose", snapshot_other), purpose="not-a-purpose")
        status, _ = self._create_root(repo, bad_purpose)
        assert status == 400, "invalid purpose status differs"
        too_many = dict(self._intent("roots-http-oids", snapshot_other),
                        selector={"kind": "oids", "oids": [old_oid] * 257})
        status, _ = self._create_root(repo, too_many)
        assert status == 400, "oversized selector status differs"
        self._assert_unauthorized("POST", self._roots_path(repo),
                                  self._intent("roots-http-unauth", snapshot_other))
        self._assert_unauthorized("GET", self._roots_path(repo, "/" + str(root_id)))
        self._assert_unauthorized("DELETE", self._roots_path(repo, "/" + str(root_id)),
                                  self._release_body("roots-http-unauth-release"))
        self._assert_unauthorized("POST", self._roots_path(repo, "/release-intent"),
                                  {"create": self._intent("roots-http-unauth-intent", snapshot_other),
                                   "idempotency_key": "roots-http-unauth-intent-release",
                                   "reason": "unauthorized"})

        self.no_bare(repo, "after retention root metadata HTTP")
        assert self._ledger(repo) == baseline, "root metadata HTTP changed unexpected snapshot rows"
        assert self._root_rows(repo) == root_baseline, "root metadata refusals changed root rows"
        return {
            "root_id": root_id,
            "release_intent_root_id": intent_root,
            "metadata_state_after_release": released_metadata["current_state"],
            "safe_receipt_fields": True,
            "safe_metadata_fields": True,
        }


    def _root_rows(self, repo):
        rid = str(uuid.UUID(repo["id"]))
        query = (
            "SELECT jsonb_build_object("
            "'heads',(SELECT count(*) FROM ref_store_core_root_heads WHERE repository_id='" + rid + "'),"
            "'captures',(SELECT count(*) FROM ref_store_core_roots WHERE repository_id='" + rid + "'),"
            "'refs',(SELECT count(*) FROM ref_store_core_root_refs WHERE repository_id='" + rid + "'),"
            "'oids',(SELECT count(*) FROM ref_store_core_root_oids WHERE repository_id='" + rid + "'),"
            "'packs',(SELECT count(*) FROM ref_store_core_root_packs WHERE repository_id='" + rid + "'),"
            "'tombstones',(SELECT count(*) FROM ref_store_core_root_tombstones WHERE repository_id='" + rid + "'),"
            "'receipts',(SELECT count(*) FROM ref_store_core_root_receipts WHERE repository_id='" + rid + "'),"
            "'repo_usage',(SELECT coalesce(jsonb_agg(to_jsonb(u)),'[]'::jsonb) "
            "              FROM ref_store_core_root_repo_usage u WHERE u.repository_id='" + rid + "')"
            ")::text"
        )
        return self.sql(query)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="absolute attested rootyard binary")
    parser.add_argument("--git", help="absolute trusted Git (defaults to ROOTYARD_GIT)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args(argv)
    env = os.environ.copy()
    hashes = None
    try:
        hashes = blob.http_input_hashes()
        profile = snapshot.SnapshotHttpProfile(str(Path(args.binary).resolve()), args.git, env)
        blob_profile = blob.check_blob_profile(env)
        blob.need(env.get("ROOTYARD_TEST_DATABASE_URL"), "ROOTYARD_TEST_DATABASE_URL is required")
        blob.need(__import__("shutil").which("psql"), "psql is required")
    except Exception as error:
        blob.write_report(args.report, {
            "kind": "rootyard/refstore-roots-http", "passed": False,
            "preflight_failed": True, "error": str(error), "cases": [],
            "expected_cases": [], "limitations": LIMITATIONS,
            "harness_inputs_sha256": hashes or {},
        })
        print("preflight failed: " + str(error), file=sys.stderr)
        return 2
    args.binary = str(profile.binary)
    harness = RootsHttpHarness(args, profile, blob_profile)
    success = False
    try:
        harness.prepare()
        harness.case(ROOTS_CASE, harness.roots_http_metadata_create_release_and_intent)
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append({"name": "cleanup", "status": "failed", "error": harness.redact(error)})
            success = False
        report = blob.build_report(harness, profile, blob_profile, [ROOTS_CASE], success)
        report["kind"] = "rootyard/refstore-roots-http"
        blob.bind_http_report(report, Path(__file__).name, hashes, profile)
        report["limitations"] = LIMITATIONS
        blob.write_report(args.report, report)
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
