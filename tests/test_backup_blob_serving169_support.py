#!/usr/bin/env python3
"""Offline contract tests for the issue #169 format22 paired-backup fixture.

Static/unit only: no binary, PostgreSQL, S3 or boto3 is required. These tests
pin the three pieces the native drill relies on so a native failure means a
product result, not a fixture drift:

* the independent ``core-pack-artifact-set-v2`` rebuild. When
  ``ROOTYARD_FORMAT22_FIXTURE_DIGEST_VECTOR`` points at the JSON printed by
  the source-bound fixture's ``--digest-vector`` mode, the rebuild must equal
  ``ArtifactSetDigest::of`` exactly; without it the rebuild is checked against
  its own canonical properties;
* the corruption plan: exactly the four issue-#169 negatives, each a single
  statement over API-produced rows with no guarded-column write;
* the positive format22 expectations and the native seed-marker contract.
"""
import json
import os
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_blob_serving169_support as support  # noqa: E402

CANARY = "issue169-offline-canary"


def registration_id():
    return str(uuid.uuid4())


def artifact_rows(tenant=None):
    tenant = tenant or str(uuid.uuid4())
    common = {"tenant_id": tenant, "authority_id": str(uuid.uuid4()), "authority_generation": 1,
              "provider": "s3", "backend_identity": "ab" * 32}
    return [dict(common, role="pack", slot=0, hold_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()),
                 namespace="core-pack", sha256="11" * 32, content_length=4096),
            dict(common, role="idx", slot=1, hold_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()),
                 namespace="core-pack", sha256="22" * 32, content_length=1200)]


class ArtifactSetDigestTest(unittest.TestCase):
    def test_rebuild_is_order_independent_and_sensitive_to_every_field(self):
        rows = artifact_rows()
        digest = support.artifact_set_digest(rows)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(digest, support.artifact_set_digest(list(reversed(rows))))
        self.assertEqual(digest, support.artifact_set_digest([json.dumps(row) for row in rows]))
        for field, value in (("sha256", "33" * 32), ("content_length", 1201), ("namespace", "core-pack2"),
                             ("provider", "azblob"), ("backend_identity", "cd" * 32),
                             ("authority_generation", 2), ("attempt_id", str(uuid.uuid4()))):
            changed = [dict(row) for row in rows]
            changed[1][field] = value
            self.assertNotEqual(support.artifact_set_digest(changed), digest, field)

    def test_swapped_identities_are_not_equal(self):
        rows = artifact_rows()
        swapped = [dict(rows[0], hold_id=rows[1]["hold_id"], sha256=rows[1]["sha256"],
                        content_length=rows[1]["content_length"]),
                   dict(rows[1], hold_id=rows[0]["hold_id"], sha256=rows[0]["sha256"],
                        content_length=rows[0]["content_length"])]
        self.assertNotEqual(support.artifact_set_digest(swapped), support.artifact_set_digest(rows))

    def test_production_parity_vector_when_provided(self):
        path = os.environ.get("ROOTYARD_FORMAT22_FIXTURE_DIGEST_VECTOR")
        if not path:
            self.skipTest("ROOTYARD_FORMAT22_FIXTURE_DIGEST_VECTOR is not set (native parity needs the fixture)")
        vector = json.loads(Path(path).read_text())
        self.assertEqual(vector["kind"], "rootyard/format22-artifact-set-digest-vector")
        self.assertEqual(vector["domain"], support.ARTIFACT_SET_DOMAIN)
        self.assertEqual(support.artifact_set_digest(vector["rows"]), vector["digest"])
        self.assertEqual(vector["digest"], vector["digest_reversed"])


class CorruptionPlanTest(unittest.TestCase):
    def test_plan_is_exactly_the_four_issue_negatives(self):
        first, second = sorted((registration_id(), registration_id()))
        cases = support.corruption_plan([second, first], [second, first])
        self.assertEqual([case.name for case in cases], list(support.CORRUPTION_CASES))
        self.assertEqual(len({case.statement for case in cases}), 4)
        for case in cases:
            self.assertIn(first, case.statement, case.name)
            self.assertNotIn(second, case.statement, case.name)
            self.assertTrue(case.statement.startswith(("DELETE FROM public.ref_store_core_pack_artifacts ",
                                                       "UPDATE public.ref_store_core_pack_publications ")))
            for guarded in (" slot=", " repository_id=", " pack_id=", " tenant_id=", " backend_identity=",
                            " sha256=", " content_length=", " hold_id="):
                self.assertNotIn(guarded, case.statement, case.name)
        by_name = {case.name: case for case in cases}
        self.assertIn("role='pack'", by_name["missing_pack"].statement)
        self.assertIn("role='idx'", by_name["missing_idx"].statement)
        self.assertNotIn("role=", by_name["missing_all_artifacts"].statement)
        self.assertIn("SET artifact_set_digest=", by_name["wrong_artifact_set_digest"].statement)
        self.assertIn("artifact_set_digest<>", by_name["wrong_artifact_set_digest"].statement)

    def test_plan_requires_a_retained_registration_and_two_registrations(self):
        first, second = registration_id(), registration_id()
        with self.assertRaisesRegex(AssertionError, "retained"):
            support.corruption_plan([first, second], [])
        with self.assertRaisesRegex(AssertionError, "two registered packs"):
            support.corruption_plan([first], [first])

    def test_missing_artifact_cases_break_the_pack_artifact_ledger(self):
        target = registration_id()
        for name in ("missing_pack", "missing_idx", "missing_all_artifacts"):
            case = support.BUILDERS[name](target)
            self.assertEqual(case.broken_rows, ("ref_store_core_pack_artifacts",), name)
            self.assertIn("ref_store_core_pack_memberships", case.requires, name)
        wrong = support.BUILDERS["wrong_artifact_set_digest"](target, "44" * 32)
        self.assertEqual(wrong.broken_rows, ("ref_store_core_pack_publications",))
        self.assertEqual(wrong.fingerprint_tables(),
                         ["ref_store_core_pack_artifacts", "ref_store_core_pack_memberships",
                          "ref_store_core_pack_publications"])

    def test_sql_literals_refuse_injection_and_bad_identifiers(self):
        with self.assertRaises(AssertionError):
            support.q("x' OR true --")
        with self.assertRaises(AssertionError):
            support.CorruptionCase("bad name", "SELECT 1", ("ref_store_core_pack_artifacts",))
        with self.assertRaisesRegex(AssertionError, "not a uuid"):
            support.missing_pack("0" * 64)
        with self.assertRaisesRegex(AssertionError, "non-zero sha256"):
            support.wrong_digest(registration_id(), "0" * 64)
        self.assertEqual(support.uuid_array([]), "'{}'::uuid[]")
        self.assertEqual(support.uuid_array(["a"]), "ARRAY['a'::uuid]::uuid[]")
        self.assertEqual(support.text_array([]), "'{}'::text[]")


def ready_repo(repo_id, tenant):
    return {"id": repo_id, "owner_id": tenant, "tenant_id": tenant, "state": "ready",
            "storage_backend": "pg_refstore"}


def positive_inputs(producer=None):
    tenant = str(uuid.uuid4())
    producer = producer or str(uuid.uuid4())
    registrations = [registration_id(), registration_id()]
    artifacts = []
    for registration in registrations:
        for row in artifact_rows():
            artifacts.append(dict(row, registration_id=registration))
    repos = [ready_repo(str(uuid.uuid4()), tenant), ready_repo(str(uuid.uuid4()), tenant)]
    roots = [{"root_id": str(uuid.uuid4()), "state": "active", "owner_id": producer},
             {"root_id": str(uuid.uuid4()), "state": "released", "owner_id": producer}]
    expected = {"format": 22, "schema_versions": [147], "registered_packs": registrations,
                "artifacts": len(artifacts), "roots": roots, "repos": repos, "producer": producer}
    carry = {table: {"rows": 2, "sha256": "00" * 32} for table in support._CARRY_TABLES}
    manifest = {"format": 22, "schema_versions": [147],
                "repositories": [{"id": repo["id"], "backend": "pg_refstore"} for repo in repos],
                "blob_closure": {"artifacts": len(artifacts), "bytes": sum(row["content_length"] for row in artifacts),
                                 "provider": "s3", "backend_identity": "ab" * 32},
                "blob_artifacts": artifacts, "refstore": carry, "files": {
                    "blob/" + row["hold_id"]: {"kind": "file", "bytes": row["content_length"]} for row in artifacts}}
    return manifest, expected


class Format22ManifestTest(unittest.TestCase):
    def test_positive_manifest_with_active_released_roots_and_distinct_producer(self):
        manifest, expected = positive_inputs()
        detail = support.format22_manifest_checks(manifest, expected)
        self.assertEqual(detail["registrations"], 2)
        self.assertEqual(detail["roots"], {"active": 1, "released": 1})
        self.assertTrue(detail["producer_distinct_from_tenant"])

    def test_missing_artifact_is_refused(self):
        manifest, expected = positive_inputs()
        manifest["blob_artifacts"] = manifest["blob_artifacts"][:-1]
        manifest["blob_closure"]["artifacts"] -= 1
        expected["artifacts"] -= 1
        with self.assertRaisesRegex(AssertionError, "one pack"):
            support.format22_manifest_checks(manifest, expected)

    def test_a_pack_without_its_idx_is_refused(self):
        manifest, expected = positive_inputs()
        manifest["blob_artifacts"] = [row for index, row in enumerate(manifest["blob_artifacts"]) if index != 1]
        manifest["blob_closure"]["artifacts"] -= 1
        expected["artifacts"] -= 1
        expected["registered_packs"] = expected["registered_packs"][1:]
        with self.assertRaisesRegex(AssertionError, "one pack"):
            support.format22_manifest_checks(manifest, expected)

    def test_producer_equal_to_tenant_is_refused(self):
        manifest, expected = positive_inputs()
        with self.assertRaisesRegex(AssertionError, "producer equals a repository tenant"):
            support.format22_manifest_checks(manifest, dict(expected, producer=expected["repos"][0]["owner_id"]))

    def test_roots_must_be_non_empty_active_and_released(self):
        manifest, expected = positive_inputs()
        with self.assertRaisesRegex(AssertionError, "released root set"):
            support.format22_manifest_checks(manifest, dict(expected, roots=expected["roots"][:1]))
        with self.assertRaisesRegex(AssertionError, "active root set"):
            support.format22_manifest_checks(manifest, dict(expected, roots=expected["roots"][1:]))

    def test_foreign_backend_or_non_refstore_repository_is_refused(self):
        manifest, expected = positive_inputs()
        manifest["repositories"][0]["backend"] = "gitfs"
        with self.assertRaisesRegex(AssertionError, "not pg_refstore"):
            support.format22_manifest_checks(manifest, expected)
        manifest, expected = positive_inputs()
        manifest["blob_artifacts"][0]["backend_identity"] = "ef" * 32
        with self.assertRaisesRegex(AssertionError, "another backend identity"):
            support.format22_manifest_checks(manifest, expected)

    def test_roots_or_pins_carry_must_be_present(self):
        manifest, expected = positive_inputs()
        manifest["refstore"]["ref_store_core_root_packs"]["rows"] = 0
        with self.assertRaisesRegex(AssertionError, "ref_store_core_root_packs"):
            support.format22_manifest_checks(manifest, expected)

    def test_not_format22_is_refused(self):
        manifest, expected = positive_inputs()
        manifest["format"] = 21
        with self.assertRaisesRegex(AssertionError, "not format22"):
            support.format22_manifest_checks(manifest, expected)


class NativeFixtureContractTest(unittest.TestCase):
    def marker(self, producer=None):
        tenant = str(uuid.uuid4())
        producer = producer or str(uuid.uuid4())
        return {"kind": support.MARKER_KIND, "format": 22,
                "repositories": [ready_repo(str(uuid.uuid4()), tenant), ready_repo(str(uuid.uuid4()), tenant)],
                "producer_owner_id": producer,
                "registrations": [{"registration_id": registration_id(), "roles": ["idx", "pack"],
                                   "artifact_set_digest": "55" * 32} for _ in range(2)],
                "roots": [{"root_id": str(uuid.uuid4()), "state": "active", "tenant_id": tenant, "owner_id": producer},
                          {"root_id": str(uuid.uuid4()), "state": "released", "tenant_id": tenant,
                           "owner_id": producer}]}

    def test_valid_marker(self):
        detail = support.native_marker_checks(self.marker())
        self.assertEqual(detail["registrations"], 2)
        self.assertTrue(detail["producer_distinct_from_tenant"])

    def test_marker_rejects_credentials_or_dsn(self):
        marker = self.marker()
        marker["leak"] = "postgresql://user:secret@127.0.0.1/db"
        with self.assertRaisesRegex(AssertionError, "leaks postgresql://"):
            support.native_marker_checks(marker)

    def test_marker_requires_distinct_producer_and_both_root_states(self):
        marker = self.marker()
        with self.assertRaisesRegex(AssertionError, "producer owner must differ"):
            support.native_marker_checks(dict(marker, producer_owner_id=marker["repositories"][0]["owner_id"]))
        marker["roots"] = marker["roots"][:1]
        with self.assertRaisesRegex(AssertionError, "active and released"):
            support.native_marker_checks(marker)

    def test_argv_is_path_only_and_env_is_scrubbed(self):
        tmp = Path("/tmp")
        argv = support.native_fixture_argv(tmp / "fixture", tmp / "seed.json", tmp / "data", "format22-169-x",
                                           tmp / "git", {"ROOTYARD_EXPECTED_SOURCE_COMMIT": "66" * 32})
        self.assertEqual(argv[1], "--seed")
        self.assertNotIn("postgres", " ".join(argv))
        env = support.NativeFixtureRequest(tmp / "fixture", "postgresql://u@h/db", tmp / "git", tmp / "seed.json",
                                           tmp / "data", "format22-169-x").env(
            {"ROOTYARD_BLOB_ROOT": "outer", "ROOTYARD_BLOB_BUCKET": "b"})
        self.assertEqual(env, {"ROOTYARD_BLOB_BUCKET": "b"})
        with self.assertRaisesRegex(AssertionError, "relative run-owned prefix"):
            support.native_fixture_argv(tmp / "f", tmp / "s", tmp / "d", "/abs", tmp / "git")

    def test_relative_paths_are_refused(self):
        with self.assertRaisesRegex(AssertionError, "absolute"):
            support.native_fixture_argv("fixture", "seed.json", "/tmp/data", "format22-169-x", "/usr/bin/git")


if __name__ == "__main__":
    assert CANARY == "issue169-offline-canary"
    unittest.main()
