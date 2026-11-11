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
* the corruption plan and its oracle: exactly the four issue-#169 negatives,
  each bound to one API-produced registration, one clone-local privileged
  statement, the exact row/field the clone must prove changed, and the exact
  source-ledger validator violation a backup may refuse with (any other
  nonzero exit is refused by the harness);
* the positive format22 expectations and the native seed-marker contract,
  including its one nonempty serving read owned by a third real requester.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_blob_serving169_support as support  # noqa: E402
import schema_baseline  # noqa: E402

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

    def test_role_order_is_pack_before_idx_like_the_rust_vector(self):
        # tests/format22_support/digest_vectors.rs: the idx row (hold 0x11) is
        # first in input and sorts before pack on hold id, but Rust emits pack
        # (hold 0x31) first because PackArtifactRole derives Pack < Idx.
        vector_rows = [
            {"role": "idx", "slot": 1, "hold_id": str(uuid.UUID(bytes=bytes([0x11]) * 16)),
             "tenant_id": str(uuid.UUID(bytes=bytes([0x10]) * 16)),
             "authority_id": str(uuid.UUID(bytes=bytes([0x12]) * 16)),
             "authority_generation": 1, "attempt_id": str(uuid.UUID(bytes=bytes([0x13]) * 16)),
             "namespace": "core-pack", "sha256": "21" * 32, "content_length": 5,
             "provider": "s3", "backend_identity": "bb" * 32},
            {"role": "pack", "slot": 0, "hold_id": str(uuid.UUID(bytes=bytes([0x31]) * 16)),
             "tenant_id": str(uuid.UUID(bytes=bytes([0x10]) * 16)),
             "authority_id": str(uuid.UUID(bytes=bytes([0x12]) * 16)),
             "authority_generation": 2, "attempt_id": str(uuid.UUID(bytes=bytes([0x32]) * 16)),
             "namespace": "core-pack", "sha256": "41" * 32, "content_length": 4096,
             "provider": "s3", "backend_identity": "bb" * 32},
        ]
        self.assertEqual(support.artifact_set_digest(vector_rows),
                         "7477cb8de43a3c4cd2b2db62dcddc8b12697ccfadc15a38a9ea65f4aaa83cec5")
        self.assertEqual(support.artifact_set_digest(list(reversed(vector_rows))),
                         support.artifact_set_digest(vector_rows))
        with self.assertRaisesRegex(AssertionError, "role is not recognized"):
            support.artifact_set_digest([dict(vector_rows[0], role="other")])

    def test_production_parity_vector_when_provided(self):
        path = os.environ.get("ROOTYARD_FORMAT22_FIXTURE_DIGEST_VECTOR")
        if not path:
            self.skipTest("ROOTYARD_FORMAT22_FIXTURE_DIGEST_VECTOR is not set (native parity needs the fixture)")
        vector = json.loads(Path(path).read_text())
        self.assertEqual(vector["kind"], "rootyard/format22-artifact-set-digest-vector")
        self.assertEqual(vector["domain"], support.ARTIFACT_SET_DOMAIN)
        self.assertEqual(support.artifact_set_digest(vector["rows"]), vector["digest"])
        self.assertEqual(vector["digest"], vector["digest_reversed"])


def scope_pairs(registrations):
    """Explicit test-only actual repository/pack ids (never derived by support)."""
    return {registration: (str(uuid.uuid4()), str(uuid.uuid4())) for registration in registrations}


class CorruptionPlanTest(unittest.TestCase):
    def plan(self, pairs=None, digests=None):
        first, second = sorted((registration_id(), registration_id())) if pairs is None else sorted(pairs)
        pairs = pairs if pairs is not None else {first: ("pack", "idx"), second: ("pack", "idx")}
        digests = digests if digests is not None else {first: {hashlib.sha256(first.encode()).hexdigest()},
                                                       second: {hashlib.sha256(second.encode()).hexdigest()}}
        scopes = scope_pairs([first, second])
        return support.corruption_plan([second, first], [second, first], scopes, pairs, digests), first

    def test_plan_is_exactly_the_four_issue_negatives(self):
        cases, first = self.plan()
        self.assertEqual([case.name for case in cases], list(support.CORRUPTION_CASES))
        self.assertEqual(len({case.statement for case in cases}), 4)
        for case in cases:
            self.assertIn("'" + first + "'", case.statement, case.name)
            self.assertEqual(case.statement.count("::uuid"), 1, case.name)
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

    def test_every_case_is_bound_to_one_registration_and_its_validator_violation(self):
        cases, first = self.plan()
        self.assertEqual([case.name for case in cases], list(support.CORRUPTION_CASES))
        registrations = {case.registration.id for case in cases}
        self.assertEqual(registrations, {first})
        self.assertTrue(all(case.planned and case.registration.digest for case in cases))
        self.assertTrue(all(case.refusal is not None for case in cases))
        self.assertEqual([support.finding(case) for case in cases],
                         ["artifact:pack", "artifact:idx", "artifact:pack+idx", "publication:artifact_set_digest"])
        self.assertEqual([case.targets_digest for case in cases], [False, False, False, True])
        self.assertEqual([case.refusal.token for case in cases],
                         ["incomplete_pair", "incomplete_pair", "missing_artifacts", "declared_set_digest_mismatch"])
        self.assertNotEqual(cases[-1].wrong_value, cases[0].registration.digest)
        self.assertEqual([case.wrong_value for case in cases[:3]], [None, None, None])

    def test_plan_skips_a_registration_an_earlier_case_already_damaged(self):
        first, second = sorted((registration_id(), registration_id()))
        digest = hashlib.sha256(first.encode()).hexdigest()
        scopes = scope_pairs([first, second])
        pairs = {first: ("pack", "idx"), second: ("pack", "idx")}
        digests = {first: {digest, "0" * 63 + "1"}, second: {digest}}
        cases, chosen = self.plan(pairs, digests)
        self.assertEqual(chosen, first)
        pairs = {first: ("idx",), second: ("pack", "idx")}
        digests = {first: {digest}, second: {digest}}
        cases, chosen = self.plan(pairs, digests)
        self.assertEqual(chosen, first)
        self.assertEqual({case.registration.id for case in cases}, {second})
        pairs = {first: ("pack", "idx"), second: ("pack", "idx")}
        digests = {first: {"01" * 32, "02" * 32}, second: {"03" * 32}}
        cases, chosen = self.plan(pairs, digests)
        self.assertEqual(chosen, first)
        with self.assertRaisesRegex(AssertionError, "intact pack"):
            support.corruption_plan([first, second], [first, second], scopes,
                                    {first: ("pack",), second: ("idx",)},
                                    {first: {"01" * 32}, second: {"02" * 32}})

    def test_plan_uses_the_actual_publication_identities(self):
        first, second = sorted((registration_id(), registration_id()))
        scopes = scope_pairs([first, second])
        digests = {first: {"01" * 32}, second: {"02" * 32}}
        pairs = {first: ("pack", "idx"), second: ("pack", "idx")}
        cases = support.corruption_plan([second, first], [second, first], scopes, pairs, digests)
        repository, pack = scopes[first]
        self.assertEqual({case.registration.id for case in cases}, {first})
        for case in cases:
            self.assertEqual((case.registration.repository_id, case.registration.pack_id), (repository, pack))
            self.assertEqual(case.registration.scope(), (repository, pack, first))
        self.assertEqual(support.Registration(first, "01" * 32, repository, pack).scope(), (repository, pack, first))
        for broken in ({}, {first: (repository,)}):
            with self.assertRaisesRegex(AssertionError, "actual repository/pack scope"):
                support.corruption_plan([second, first], [second, first], broken, pairs, digests)

    def test_plan_requires_a_retained_registration_and_two_registrations(self):
        first, second = registration_id(), registration_id()
        scopes = scope_pairs([first, second])
        pairs = {first: ("pack", "idx"), second: ("pack", "idx")}
        digests = {first: {"01" * 32}, second: {"02" * 32}}
        # A live membership registration is a retained registration by itself:
        # no root, snapshot or serving read is required to hold it.
        cases = support.corruption_plan([second, first], [first], scopes, pairs, digests)
        self.assertEqual({case.registration.id for case in cases}, {first})
        with self.assertRaisesRegex(AssertionError, "retained"):
            support.corruption_plan([first, second], [], scopes, pairs, digests)
        with self.assertRaisesRegex(AssertionError, "two registered packs"):
            support.corruption_plan([first], [first], scope_pairs([first]))

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

    def test_corruption_sql_is_transaction_local_privileged_and_evidence_producing(self):
        cases, _ = self.plan()
        for case in cases:
            sql = support.corruption_sql(case)
            self.assertTrue(sql.startswith("BEGIN; SET LOCAL statement_timeout="), case.name)
            self.assertTrue(sql.endswith("COMMIT"), case.name)
            self.assertIn("SET LOCAL session_replication_role = replica; " + case.statement, sql)
            self.assertIn("\\echo " + support.CHANGED + " :ROW_COUNT", sql)
            self.assertLess(sql.index("RESET session_replication_role"), sql.rindex("COMMIT"))
            self.assertNotIn("tgdisable", sql)
            self.assertNotIn("DISABLE TRIGGER", sql)
            self.assertNotIn("ALTER TABLE", sql)
            self.assertNotIn("DROP FUNCTION", sql)
            self.assertEqual(sql.count("SET LOCAL session_replication_role"), 1)
            for table in support.GUARDED_TABLES:
                self.assertIn(table, sql)
            self.assertIn("'superuser'", sql)
            self.assertIn("rolsuper", sql)
            self.assertIn("'replication_role_default', current_setting('session_replication_role')='origin'", sql)
            for trigger in support.IMMUTABLE_TRIGGERS:
                self.assertIn("'" + trigger + "'", sql)
            self.assertIn("issue169_before ON COMMIT DROP", sql)
            # The evidence row is a normal SELECT so psql -qAt prints the JSON
            # object verbatim; COPY output would re-escape nested JSON strings.
            self.assertNotIn("COPY", sql, case.name)
            self.assertNotIn("TO STDOUT", sql, case.name)
            self.assertEqual(sql.count("\\echo " + support.CHANGED + " :ROW_COUNT\n"), 1, case.name)
            protocol = sql.split("\\echo " + support.CHANGED + " :ROW_COUNT\n", 1)[1]
            self.assertTrue(protocol.startswith("RESET session_replication_role; SELECT jsonb_build_object("),
                            case.name)
            self.assertTrue(protocol.endswith(")::text; COMMIT"), case.name)
            self.assertEqual(protocol.count(";"), 2, case.name)  # RESET, one SELECT, COMMIT
            # Two target subselects, two after facts, plus the joined-hold key.
            self.assertEqual(sql.split("\\echo ", 1)[0].count("jsonb_build_object("), 5, case.name)
        for case in cases:
            self.assertEqual(support.corruption_sql(case).count("SET LOCAL"), 3)

    def test_target_registration_is_excluded_from_both_after_facts(self):
        cases, _ = self.plan()
        for case in cases:
            excluded = "t.registration_id <> '" + case.registration.id + "'::uuid"
            facts = support._fact_sql(support.AFTER_TABLES, "'" + case.registration.id + "'::uuid")
            self.assertEqual(facts.count(excluded), len(support.AFTER_TABLES), case.name)
            self.assertNotIn("registration_id <>", support._fact_sql(support.AFTER_TABLES), case.name)
            sql = support.corruption_sql(case)
            # Both the before snapshot and the observed after fact exclude it.
            self.assertEqual(sql.count(excluded), 2 * len(support.AFTER_TABLES), case.name)
            self.assertNotIn("registration_id <>", support._fact_sql(support.GUARDED_TABLES), case.name)
            self.assertIn(support._target_sql("'" + case.registration.id + "'::uuid"), sql)
        with self.assertRaisesRegex(AssertionError, "planned corruption case"):
            support.corruption_sql(support.BUILDERS["missing_pack"](registration_id()))
        with self.assertRaisesRegex(AssertionError, "not a uuid"):
            support.Registration(registration_id(), "ab" * 32, "not-a-uuid", str(uuid.uuid4()))
        with self.assertRaisesRegex(AssertionError, "pack id is not a uuid"):
            support.Registration(registration_id(), "ab" * 32, str(uuid.uuid4()), "")

    def test_target_sql_joins_the_immutable_hold_by_hold_id(self):
        cases, _ = self.plan()
        for case in cases:
            target = support._target_sql("'" + case.registration.id + "'::uuid")
            self.assertIn(target, support.corruption_sql(case), case.name)
            # The hold is joined on the artifact's own hold_id, never on a
            # repository/tenant/namespace heuristic. The projected JSON value
            # originates from the UUID column, so it is cast back to uuid: a
            # bare ``uuid = text`` comparison can fail PostgreSQL type
            # resolution.
            self.assertIn("FROM public.artifact_holds h WHERE h.hold_id = (a.row->>'hold_id')::uuid",
                          target, case.name)
            self.assertNotIn("h.hold_id = a.row->>'hold_id'", target, case.name)
            self.assertEqual(target.count("(a.row->>'hold_id')::uuid"), 1, case.name)
            self.assertNotIn("FROM public.artifact_holds h LEFT JOIN", target, case.name)
            self.assertEqual(target.count("public.artifact_holds"), 1, case.name)
            self.assertIn("public.ref_store_core_pack_artifacts a WHERE a.registration_id="
                          "'" + case.registration.id + "'::uuid", target, case.name)
            # A missing or repeated hold join is an empty/ambiguous JSON array
            # that _digest_rows refuses, never a silent fallback value.
            self.assertIn("jsonb_build_object('" + support.HOLD_ROW + "', COALESCE((SELECT jsonb_agg(",
                          target)
            self.assertIn("), '[]'::jsonb))", target)
            self.assertNotEqual(support.HOLD_ROW, "tenant_id")
            self.assertNotIn("storage_tenant_id AS tenant_id", target)
            artifacts_sql = target.split("public.ref_store_core_pack_publications t", 1)[1]
            self.assertNotIn("repositories", artifacts_sql, case.name)

    def test_corruption_sql_includes_broken_rows_fields_only(self):
        cases, _ = self.plan()
        allowed = {"DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id='%s'::uuid AND role='%s'"
                   % (case.registration.id, role) if role else
                   "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id='%s'::uuid"
                   % case.registration.id for case, role in zip(cases[:3], ("pack", "idx", None))}
        self.assertEqual(len(allowed), 3)
        self.assertEqual({case.statement for case in cases[:3]}, allowed)
        self.assertIn("UPDATE public.ref_store_core_pack_publications SET artifact_set_digest='%s' WHERE "
                      "registration_id='%s'::uuid AND artifact_set_digest<>'%s'" % (cases[3].wrong_value,
                                                                                 cases[3].registration.id,
                                                                                 cases[3].wrong_value),
                      cases[3].statement)

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


def evidence_artifact(row, locator_tenant=None):
    """One stored A4 artifact row plus its joined migration-141 hold row.

    ``row`` keeps exactly the columns migration 142 stores: its ``tenant_id`` is
    the repository/gate tenant. The hold's ``storage_tenant_id`` is the locator
    tenant; ``locator_tenant`` defaults to the row's repository tenant, but the
    adversarial cases make them differ on purpose.
    """
    row = dict(row)
    hold = {"hold_id": row["hold_id"], "tenant_id": row["tenant_id"],
            "storage_tenant_id": locator_tenant or row["tenant_id"],
            "authority_id": row["authority_id"], "authority_generation": row["authority_generation"],
            "attempt_id": row["attempt_id"], "namespace": row["namespace"], "sha256": row["sha256"],
            "content_length": row["content_length"], "provider": row["provider"],
            "backend_identity": row["backend_identity"]}
    return dict(row, **{support.HOLD_ROW: [hold]})


def hold_digest(hold):
    """The canonical digest of one pair from the migration-141 hold rows alone."""
    return support.artifact_set_digest(
        [dict({key: hold[role][key] for key in support.LOCATOR_FIELDS}, role=role, slot=slot,
              hold_id=hold[role]["hold_id"], tenant_id=hold[role]["storage_tenant_id"],
              sha256=hold[role]["sha256"], content_length=hold[role]["content_length"],
              provider=hold[role]["provider"], backend_identity=hold[role]["backend_identity"])
         for role, slot in support.PAIR_ROLES])


def digests_of(publication, rows):
    """The stored digest of one pair, as production hashes it.

    ``rows`` maps role to the canonical identity built from the hold ledger:
    locator fields, ``storage_tenant_id``, physical ``sha256``/``content_length``,
    ``provider`` and ``backend_identity``. A publication digest is never used.
    """
    del publication
    columns = []
    for role, slot in support.PAIR_ROLES:
        row = rows[role]
        columns.append(dict({key: row[key] for key in support.LOCATOR_FIELDS}, role=role, slot=slot,
                            hold_id=row["hold_id"], tenant_id=row["storage_tenant_id"],
                            sha256=row["sha256"], content_length=row["content_length"],
                            provider=row["provider"], backend_identity=row["backend_identity"]))
    return support.artifact_set_digest(columns)


def locator_identity(rows):
    """Per role, the identity production hashes from the joined holds."""
    identity = {}
    for role, row in rows.items():
        hold = row[support.HOLD_ROW][0]
        identity[role] = dict({key: hold[key] for key in support.LOCATOR_FIELDS},
                              storage_tenant_id=hold["storage_tenant_id"], hold_id=row["hold_id"],
                              sha256=row["sha256"], content_length=row["content_length"],
                              provider=row["provider"], backend_identity=row["backend_identity"])
    return identity


def planned_cases():
    """Four planned cases built exactly like the native drill builds them."""
    first, second = sorted(registration_id() for _ in range(2))
    # The A4 artifact/hold ledger identity. The locator tenant is deliberately a
    # different tenant than the repository tenant the A4 row stores.
    repository_tenant, locator_tenant = str(uuid.uuid4()), str(uuid.uuid4())
    common = {"tenant_id": repository_tenant, "authority_id": str(uuid.uuid4()), "authority_generation": 3,
              "provider": "s3", "backend_identity": "ab" * 32}
    holds = {
        "pack": dict(common, role="pack", slot=0, hold_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()),
                     namespace="core-pack", sha256="ef" * 32, content_length=4096),
        "idx": dict(common, role="idx", slot=1, hold_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()),
                    namespace="core-pack", sha256="12" * 32, content_length=1200),
    }
    # The publication row as migration 142 stores it: it has no authority or
    # attempt identity and its tenant is the repository/gate tenant.
    publication = {"repository_id": str(uuid.uuid4()), "pack_id": str(uuid.uuid4()),
                   "tenant_id": repository_tenant}
    rows = {role: evidence_artifact(hold, locator_tenant) for role, hold in holds.items()}
    digest = digests_of(publication, locator_identity(rows))
    cases = support.corruption_plan([second, first], [second, first],
                                    scope_pairs([first, second]),
                                    {first: ("pack", "idx"), second: ("pack", "idx")},
                                    {first: {digest}, second: {"34" * 32}})
    # The enclosing repository/pack only come from the target registration (the
    # read join), as in the clone SQL.
    publication_row = dict(publication, registration_id=first, artifact_set_digest=digest,
                           repository_id=cases[0].registration.repository_id,
                           pack_id=cases[0].registration.pack_id)
    facts = {table: "00" for table in support.AFTER_TABLES}
    guarded = {table: "11" for table in support.GUARDED_TABLES}
    return cases, publication_row, rows, facts, guarded


def oracle_evidence(cases, publication, rows, facts, guarded):
    """Per-case evidence: the state only that case's DML leaves behind."""
    states = {
        "missing_pack": ([publication, [rows["idx"]]], 1),
        "missing_idx": ([publication, [rows["pack"]]], 1),
        "missing_all_artifacts": ([publication, []], 2),
        "wrong_artifact_set_digest": ([dict(publication, artifact_set_digest=cases[3].wrong_value),
                                       list(rows.values())], 1),
    }
    for case in cases:
        target, changed = states[case.name]
        yield case, changed, {"registration": case.registration.id, "superuser": True,
                              "replication_role_default": True,
                              "intact_triggers": len(support.IMMUTABLE_TRIGGERS),
                              "before": {"target": [publication, list(rows.values())], "after": facts,
                                         "guarded": guarded},
                              "target": target, "after": facts, "guarded": guarded}


class DigestIdentityTest(unittest.TestCase):
    """The canonical locator tenant is the joined hold, not the A4 artifact row."""

    def pair(self, pack_tenant=None, idx_tenant=None):
        common = {"tenant_id": str(uuid.uuid4()), "authority_id": str(uuid.uuid4()), "authority_generation": 2,
                  "provider": "s3", "backend_identity": "ab" * 32}
        rows = [dict(common, role="pack", slot=0, hold_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()),
                     namespace="core-pack", sha256="11" * 32, content_length=4096),
                dict(common, role="idx", slot=1, hold_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()),
                     namespace="core-pack", sha256="22" * 32, content_length=1200)]
        tenants = (pack_tenant, idx_tenant)
        return {row["role"]: evidence_artifact(row, tenants[index])
                for index, row in enumerate(rows)}

    def test_locator_tenant_comes_from_the_hold_not_the_artifact_row(self):
        pair = self.pair()
        rebuilt = support._digest_rows({}, pair)
        by_role = {row["role"]: row for row in rebuilt}
        for role in ("pack", "idx"):
            artifact, hold = pair[role], pair[role][support.HOLD_ROW][0]
            # The real A4 row keeps its repository/gate tenant untouched.
            self.assertEqual(artifact["tenant_id"], hold["tenant_id"])
            self.assertEqual(by_role[role]["tenant_id"], hold["storage_tenant_id"])
            for field in ("authority_id", "authority_generation", "attempt_id", "namespace"):
                self.assertEqual(by_role[role][field], hold[field], field)
            for field in ("hold_id", "sha256", "content_length", "provider", "backend_identity"):
                self.assertEqual(by_role[role][field], artifact[field], field)
        # The digest is the canonical projection: it equals a digest built from
        # the hold ledger alone.
        self.assertEqual(support.artifact_set_digest(rebuilt), hold_digest({r: v[support.HOLD_ROW][0]
                                                                            for r, v in pair.items()}))

    def held(self, pair, role, **changes):
        """A copy of ``pair`` whose ``role`` hold carries ``changes``."""
        copy = {name: dict(row, **{support.HOLD_ROW: [dict(hold) for hold in row[support.HOLD_ROW]]})
                for name, row in pair.items()}
        copy[role][support.HOLD_ROW][0].update(changes)
        return copy

    def test_a_differing_locator_tenant_changes_the_digest(self):
        pair = self.pair()
        same = support.artifact_set_digest(support._digest_rows({}, pair))
        # One role's locator tenant differs from the shared repository tenant
        # while the other role's still equals it: the hold tenant decides.
        adversarial = self.held(pair, "pack", storage_tenant_id=str(uuid.uuid4()))
        other = support.artifact_set_digest(support._digest_rows({}, adversarial))
        self.assertNotEqual(same, other)
        self.assertEqual(adversarial["idx"][support.HOLD_ROW][0]["storage_tenant_id"], adversarial["idx"]["tenant_id"])
        self.assertNotEqual(adversarial["pack"][support.HOLD_ROW][0]["storage_tenant_id"],
                            adversarial["pack"]["tenant_id"])
        # Substituting the artifact (repository) tenant for the pack role repeats
        # the base identity: the two inputs are distinct, so an artifact tenant
        # can never stand in for the locator tenant.
        self.assertEqual(support.artifact_set_digest(support._digest_rows(
            {}, self.held(pair, "pack", storage_tenant_id=pair["pack"]["tenant_id"]))), same)
        # A non-tenant locator field from the hold is equally significant.
        moved = self.held(pair, "idx", authority_generation=3)
        self.assertNotEqual(support.artifact_set_digest(support._digest_rows({}, moved)), same)

    def test_missing_or_ambiguous_hold_join_is_refused(self):
        pair = self.pair()
        broken = {
            "no hold key": {"pack": dict({key: value for key, value in pair["pack"].items()
                                          if key != support.HOLD_ROW}), "idx": pair["idx"]},
            "empty join": {role: dict(row, **{support.HOLD_ROW: []}) for role, row in pair.items()},
            "repeated join": {role: dict(row, **{support.HOLD_ROW: list(row[support.HOLD_ROW]) * 2})
                              for role, row in pair.items()},
        }
        for message in broken:
            try:
                support._digest_rows({}, broken[message])
            except AssertionError as error:
                self.assertIn("exactly one joined artifact_holds row", str(error), message)
            else:
                self.fail(message + ": a missing or repeated hold join was accepted")
        other_hold = [dict(pair["pack"][support.HOLD_ROW][0], hold_id=str(uuid.uuid4()))]
        with self.assertRaisesRegex(AssertionError, "not the artifact's own hold"):
            support._digest_rows({}, {"pack": dict(pair["pack"], **{support.HOLD_ROW: other_hold}),
                                      "idx": pair["idx"]})
        with self.assertRaisesRegex(AssertionError, "lacks a digest field"):
            support._digest_rows({}, {"pack": {key: value for key, value in pair["pack"].items()
                                               if key != "provider"}})
        with self.assertRaisesRegex(AssertionError, "disagrees with the artifact hash/length"):
            bad = dict(pair["idx"][support.HOLD_ROW][0], sha256="33" * 32)
            support._digest_rows({}, {"pack": pair["pack"], "idx": dict(pair["idx"], **{support.HOLD_ROW: [bad]})})
        # A publication digest or repository tenant is never an identity source:
        # it cannot stand in for a missing authority/attempt locator.
        publication = {"artifact_set_digest": "44" * 32, "tenant_id": str(uuid.uuid4()),
                       "authority_id": str(uuid.uuid4()), "attempt_id": str(uuid.uuid4())}
        no_locator = {role: dict({key: value for key, value in row.items() if key != support.HOLD_ROW},
                                 **{support.HOLD_ROW: [{key: value for key, value in row[support.HOLD_ROW][0].items()
                                                        if key not in ("authority_id", "attempt_id")}]})
                      for role, row in pair.items()}
        with self.assertRaisesRegex(AssertionError, "lacks a digest field"):
            support._digest_rows(publication, no_locator)


class CorruptionEvidenceTest(unittest.TestCase):
    def setUp(self):
        (cases, self.publication, self.rows, self.facts, self.guarded) = planned_cases()
        self.cases = cases
        self.by_name = {case.name: case for case in cases}

    def expectations(self):
        return list(oracle_evidence(self.cases, self.publication, self.rows, self.facts, self.guarded))

    def test_exactly_the_intended_row_is_proven_for_every_case(self):
        self.assertEqual(self.cases[0].registration.digest,
                         digests_of(self.publication, locator_identity(self.rows)))
        self.assertNotEqual(self.rows["pack"]["sha256"], self.rows["idx"]["sha256"])
        for case, changed, observed in self.expectations():
            detail = support.corruption_findings(case, changed, observed)
            self.assertEqual(detail["rows_changed"], changed)
            self.assertEqual(detail["finding"], support.finding(case))
            self.assertTrue(detail["clone_local_superuser"])
            self.assertTrue(detail["guarded_ledgers_unchanged"])

    def test_wrong_digest_case_rehashes_the_locator_identity_from_the_holds(self):
        case = self.by_name["wrong_artifact_set_digest"]
        identity = locator_identity(self.rows)
        self.assertEqual(case.registration.digest, digests_of(self.publication, identity))
        self.assertNotEqual(case.wrong_value, case.registration.digest)
        # The artifact rows carry a repository tenant; the holds carry the
        # locator tenant. They differ, and only the hold tenant rehashes.
        for role, row in self.rows.items():
            self.assertNotEqual(row["tenant_id"], row[support.HOLD_ROW][0]["storage_tenant_id"], role)
        self.assertNotIn("authority_id", self.publication)
        self.assertNotIn("attempt_id", self.publication)
        for case, changed, observed in self.expectations():
            if case.name == "wrong_artifact_set_digest":
                after = observed["target"][0]["artifact_set_digest"]
                self.assertEqual(after, case.wrong_value)
                self.assertEqual(observed["target"][1], observed["before"]["target"][1])
                self.assertEqual(support.corruption_findings(case, changed, observed)["stored_digest"], after)

    def test_a_digest_from_the_artifact_tenant_is_not_the_stored_digest(self):
        case = self.by_name["wrong_artifact_set_digest"]
        # Rehashing with the A4 repository tenant in place of the locator tenant
        # is a different (wrong) digest, so it can never be the stored one.
        for role, row in self.rows.items():
            forged = locator_identity(self.rows)
            forged[role] = dict(forged[role], storage_tenant_id=row["tenant_id"])
            self.assertNotEqual(digests_of(self.publication, forged), case.registration.digest, role)
        observed = next(state for case, _, state in self.expectations()
                        if case.name == "wrong_artifact_set_digest")
        self.assertEqual(support.corruption_findings(case, 1, observed)["stored_digest"], case.wrong_value)

    def test_an_unchanged_row_fails_setup(self):
        for case, changed, observed in self.expectations():
            for bad in (-1, 0, changed + 1):
                if bad == changed:
                    continue
                with self.assertRaises(AssertionError, msg=case.name):
                    support.corruption_findings(case, bad, observed)
            with self.assertRaises(AssertionError):
                support.corruption_findings(case, str(changed), observed)
            with self.assertRaises(AssertionError):
                support.corruption_findings(case, True, observed)

    def test_a_change_to_the_wrong_role_or_field_fails_setup(self):
        states = {case.name: (changed, dict(observed)) for case, changed, observed in self.expectations()}

        def mutate(name, change):
            changed, observed = states[name]
            observed = json.loads(json.dumps(observed))
            change(observed)
            return support.corruption_findings(self.by_name[name], changed, observed)

        with self.assertRaises(AssertionError):
            mutate("missing_pack", lambda o: o.update(target=[o["target"][0], [self.rows["idx"], self.rows["pack"]]]))
        with self.assertRaises(AssertionError):
            mutate("missing_idx", lambda o: o.update(target=[o["target"][0], [self.rows["idx"]]]))
        with self.assertRaises(AssertionError):
            mutate("missing_pack", lambda o: o["target"][1][0].update(sha256="99" * 32))
        with self.assertRaises(AssertionError):
            mutate("wrong_artifact_set_digest",
                   lambda o: o["target"][0].update(artifact_set_digest=self.by_name["wrong_artifact_set_digest"].registration.digest))
        with self.assertRaises(AssertionError):
            mutate("wrong_artifact_set_digest",
                   lambda o: o["target"][0].update(artifact_set_digest="00" * 32))
        with self.assertRaises(AssertionError):
            mutate("wrong_artifact_set_digest",
                   lambda o: o["target"][0].update(declared_bytes=1))
        with self.assertRaises(AssertionError):
            mutate("wrong_artifact_set_digest",
                   lambda o: o["target"][1][0].update(content_length=1))
        with self.assertRaises(AssertionError):
            mutate("missing_pack", lambda o: o["target"].__setitem__(0, None))
        with self.assertRaises(AssertionError):
            mutate("missing_pack", lambda o: o["target"][0].update(pack_id=str(uuid.uuid4())))
        with self.assertRaises(AssertionError):
            mutate("missing_pack", lambda o: o["target"][0].update(artifact_set_digest="77" * 32))

    def test_privilege_and_guard_evidence_is_required(self):
        for case, changed, observed in self.expectations():
            for key, value in (("superuser", False), ("replication_role_default", False),
                               ("intact_triggers", len(support.IMMUTABLE_TRIGGERS) - 1),
                               ("registration", str(uuid.uuid4()))):
                bad = dict(observed, **{key: value})
                with self.assertRaises(AssertionError, msg=case.name + ":" + key):
                    support.corruption_findings(case, changed, bad)
            touched = json.loads(json.dumps(observed))
            touched["guarded"] = dict(touched["guarded"], ref_store_core_pack_memberships="ff")
            with self.assertRaisesRegex(AssertionError, "memberships"):
                support.corruption_findings(case, changed, touched)
            touched = json.loads(json.dumps(observed))
            touched["after"] = dict(touched["after"], ref_store_core_pack_artifacts="ff")
            with self.assertRaisesRegex(AssertionError, "another pack artifact"):
                support.corruption_findings(case, changed, touched)
            with self.assertRaises(AssertionError):
                support.corruption_findings(case, changed, "{not json")
            with self.assertRaisesRegex(AssertionError, "trigger"):
                support.corruption_findings(case, changed, json.loads(json.dumps(observed).replace(
                    '"intact_triggers": %d' % len(support.IMMUTABLE_TRIGGERS), '"intact_triggers": 0')))


EXPECTED_PREFIX = ("Error: backup failed; requires stopped writers, supported dedicated database and safe new "
                   "destination; partial files may remain: source artifact ledger cannot be archived: ")


def summary_line(codes, count=None):
    """Exactly the one line the backup CLI prints for the typed refusal."""
    codes = sorted(codes)
    count = len(codes) if count is None else count
    return (EXPECTED_PREFIX + "source artifact ledger is inconsistent (" + str(count) + " violations; codes: " +
            ",".join(codes) + ")\n")


def required_codes(case):
    """The two summary codes every damaged A4 set must yield."""
    return sorted(case.refusal.required)


class ValidatorRefusalTest(unittest.TestCase):
    def setUp(self):
        (self.cases, *_rest) = planned_cases()
        self.by_name = {case.name: case for case in self.cases}

    def test_the_cli_summary_names_exactly_the_two_required_codes(self):
        for case in self.cases:
            codes = required_codes(case)
            line = summary_line(codes)
            self.assertTrue(line.startswith(EXPECTED_PREFIX))
            self.assertEqual(support.validator_refusal(line, case), "2|" + ",".join(codes))
            self.assertEqual(support.validator_refusal(line.encode(), case), "2|" + ",".join(codes))
            # The summary carries names only: no ids, reason tails or leaks.
            for leaked in case.registration.scope() + (case.registration.digest, "Caused by"):
                self.assertNotIn(leaked, line)
            # Neither required half is sufficient.
            with self.assertRaisesRegex(AssertionError, "lacks"):
                support.validator_refusal(summary_line(codes[:1]), case)
            with self.assertRaisesRegex(AssertionError, "lacks"):
                support.validator_refusal(summary_line(codes[1:]), case)
        self.assertEqual([required_codes(case) for case in self.cases],
                         [["canonical_pair_mismatch", "incomplete_pair"],
                          ["canonical_pair_mismatch", "incomplete_pair"],
                          ["canonical_pair_mismatch", "missing_artifacts"],
                          ["canonical_pair_mismatch", "declared_set_digest_mismatch"]])

    def test_multi_code_summaries_admit_only_existing_dependent_codes(self):
        for case in self.cases:
            required = required_codes(case)
            with self.assertRaisesRegex(AssertionError, "unrelated"):
                support.validator_refusal(summary_line(required + ["repository_realm_mismatch"]), case)
            for token in support.SET_TOKENS:
                if token in required:
                    continue
                with self.assertRaisesRegex(AssertionError, "unrelated code"):
                    support.validator_refusal(summary_line(required + [token]), case)
            for further in (["root_set_mismatch"], ["snapshot_set_mismatch"], list(support.DEPENDENT_TOKENS)):
                codes = sorted(set(required + further))
                valid = support.validator_refusal(summary_line(codes), case)
                self.assertEqual(valid.split("|", 1)[1], ",".join(codes))
        case = self.by_name["wrong_artifact_set_digest"]
        codes = sorted({"canonical_pair_mismatch", "declared_set_digest_mismatch"} | set(support.DEPENDENT_TOKENS))
        self.assertTrue(support.validator_refusal(summary_line(codes), case))

    def test_every_safe_code_name_is_accepted(self):
        self.assertEqual(support.OTHER_CODE, "other")
        self.assertEqual({"canonical_pair_mismatch", "incomplete_pair", "missing_artifacts",
                          "declared_set_digest_mismatch"}, set(support.SET_TOKENS))
        self.assertFalse(set(support.SET_TOKENS) & set(support.DEPENDENT_TOKENS))
        self.assertFalse(set(support.SET_TOKENS + support.DEPENDENT_TOKENS) & set(support.CLI_POLICY_TOKENS))

    def test_ids_dependent_codes_and_other_are_never_accepted(self):
        for case in self.cases:
            required = required_codes(case)
            canonical = case.refusal.required[0]
            with self.assertRaisesRegex(AssertionError, "unrelated code"):
                support.validator_refusal(summary_line(required + ["repository_realm_mismatch"]), case)
            with self.assertRaisesRegex(AssertionError, "unrelated code"):
                support.validator_refusal(summary_line(required + ["publication_binding_mismatch"]), case)
            with self.assertRaisesRegex(AssertionError, "other"):
                support.validator_refusal(summary_line(required + [support.OTHER_CODE]), case)
            with self.assertRaisesRegex(AssertionError, "CLI policy"):
                support.validator_refusal(summary_line(required + [support.CLI_POLICY_TOKENS[0]]), case)
            with self.assertRaisesRegex(AssertionError, "typed source-ledger summary"):
                support.validator_refusal(EXPECTED_PREFIX + "source artifact ledger is inconsistent (2 violations): " +
                                          canonical + ":" + ":".join(case.registration.scope()) + "\n", case)
        # The wrong cause token of another mutation is not this case's cause.
        case = self.by_name["wrong_artifact_set_digest"]
        for wrong in (["canonical_pair_mismatch", "incomplete_pair"],
                      ["canonical_pair_mismatch", "missing_artifacts"]):
            with self.assertRaisesRegex(AssertionError, "lacks declared_set_digest_mismatch"):
                support.validator_refusal(summary_line(wrong), case)

    def test_count_order_duplicates_and_shape_are_refused(self):
        case = self.by_name["missing_all_artifacts"]
        codes = required_codes(case)
        reversed_codes = ",".join(reversed(codes))
        refusals = (
            (summary_line(codes, count=0), "typed source-ledger summary"),
            (summary_line(codes, count=-1), "typed source-ledger summary"),
            (EXPECTED_PREFIX + "source artifact ledger is inconsistent (0 violations; codes: " + ",".join(codes) +
             ")\n", "typed source-ledger summary"),
            (EXPECTED_PREFIX + "source artifact ledger is inconsistent (2 violations; codes: " + reversed_codes +
             ")\n", "not sorted"),
            (EXPECTED_PREFIX + "source artifact ledger is inconsistent (3 violations; codes: " +
             ",".join([codes[0], codes[0], codes[1]]) + ")\n", "repeats"),
            (EXPECTED_PREFIX + "source artifact ledger is inconsistent (3 violations; codes: " +
             ",".join([codes[1], codes[0], codes[0]]) + ")\n", "not sorted|repeats"),
            (summary_line(codes + ["Other"]), "code name"),
            (summary_line(codes + ["private-ref"]), "code name"),
            (summary_line(codes + ["1"]), "code name"),
            (summary_line(codes).rstrip("\n"), "exactly one"),
            (summary_line(codes) + "Caused by: source artifact ledger cannot be read\n", "exactly one"),
            (summary_line(codes).replace(" violations; codes: ", " violations: "), "typed source-ledger summary"),
            (EXPECTED_PREFIX + "source artifact ledger is inconsistent (2 violations; codes: " +
             ", ".join(codes) + ")\n", "typed source-ledger summary"),
            (EXPECTED_PREFIX + "source artifact ledger is inconsistent (2 violations; codes: " + ",".join(codes) +
             "); Caused by: connection refused\n", "typed source-ledger summary"),
        )
        for text, message in refusals:
            with self.assertRaisesRegex(AssertionError, message, msg=text):
                support.validator_refusal(text, case)
        self.assertEqual(
            support.validator_refusal(summary_line(codes, count=3), case),
            "3|" + ",".join(codes),
        )

    def test_generic_and_unrelated_refusals_are_refused(self):
        case = self.by_name["missing_pack"]
        required = required_codes(case)
        generic = support.GENERIC_REFUSAL
        self.assertEqual(generic, "Error: backup failed; requires stopped writers, supported dedicated database "
                                  "and safe new destination; partial files may remain\n")
        plain = "backup failed; requires stopped writers, supported dedicated database and safe new destination; " \
                "partial files may remain\n"
        backend = generic + "Caused by: Blob closure backend differs\n"
        missing = generic + "Caused by: source artifact ledger cannot be archived: Caused by: source Blob artifact " \
                            "failed verified read-back: NotFound\n"
        old_list = EXPECTED_PREFIX + "source artifact ledger is inconsistent (2 violations): " + "\n"
        forged = "rootyard: backup failed: validator refused " + ",".join(required) + "\n"
        for text in (generic, plain, backend, missing, old_list, forged, "", "\n\n", summary_line(required)[:40] + "\n"):
            with self.assertRaises(AssertionError, msg=text):
                support.validator_refusal(text, case)
        for other in (summary_line(["canonical_pair_mismatch", "missing_artifacts"]),
                      summary_line([support.OTHER_CODE] + required)):
            with self.assertRaises(AssertionError):
                support.validator_refusal(other, case)
        # An unplanned (not database-proven) case is never an acceptance.
        other_case = support.BUILDERS["missing_pack"](case.registration.id)
        self.assertFalse(other_case.planned)


def ready_repo(repo_id, tenant):
    return {"id": repo_id, "owner_id": tenant, "tenant_id": tenant, "state": "ready",
            "storage_backend": "pg_refstore"}


def serving_read_marker(repo_id, tenant, owner=None, pack_count=2):
    return {"pin_id": str(uuid.uuid4()), "repository_id": repo_id, "tenant_id": tenant,
            "owner_id": owner or str(uuid.uuid4()), "pack_count": pack_count, "requester_distinct": True}


def archive_artifact():
    """One ``manifest.blob_artifacts`` entry in its real serialized shape.

    Format22 stores ``Vec<ledger::Artifact>``, whose unrenamed ``length: u64``
    field is written as ``length``; the A4 / ``artifact_holds`` column name
    ``content_length`` never reaches the archive. The optional
    ``artifact_set_digest``/``declared_by`` fields are omitted as the
    serializer omits them when unset. ``sha256`` is derived from the entry's own
    hold id, so a per-role placeholder can never be mistaken for a shared one.
    """
    hold_id = str(uuid.uuid4())
    return {
        "repository_id": str(uuid.uuid4()),
        "registration_id": registration_id(),
        "pack_id": str(uuid.uuid4()),
        "role": "pack",
        "slot": 0,
        "hold_id": hold_id,
        "acquire_request_id": str(uuid.uuid4()),
        "consume_request_id": str(uuid.uuid4()),
        "provider": "s3",
        "backend_identity": "ab" * 32,
        "sha256": hashlib.sha256(hold_id.encode()).hexdigest(),
        "length": 4096,
        "tenant_id": str(uuid.uuid4()),
        "authority_id": str(uuid.uuid4()),
        "generation": 1,
        "attempt_id": str(uuid.uuid4()),
        "namespace": "core-pack",
    }


def member(artifact, **changes):
    """The real ``manifest.files`` entry of one artifact.

    Mirrors ``Entry``: a regular ``file`` whose ``bytes`` is the artifact's own
    serialized ``length`` and whose ``sha256`` is its digest, stored under the
    exact ``ledger::Artifact::archive_path()``.
    """
    return support.archive_path(artifact), dict(
        {"kind": "file", "mode": 0o644, "bytes": artifact["length"], "sha256": artifact["sha256"],
         "target": None}, **changes)


def directory(path, **changes):
    """The real ``manifest.files`` entry of one archived Blob directory.

    ``export`` creates ``blob/{repository_id}`` and
    ``blob/{repository_id}/{pack_id}`` with ``private_dir``, and
    ``filesystem::inventory`` records each as ``Entry { kind: "directory",
    bytes: 0, sha256: None, target: None }`` with the ``mode`` of the created
    directory: ``private_dir`` requests ``0o700``, which the process umask may
    reduce, so ``mode`` is a non-bool integer subset of ``0o700`` (default
    ``0o700`` here, as with the usual ``umask 022``).
    """
    return path, dict({"kind": "directory", "mode": 0o700, "bytes": 0, "sha256": None, "target": None}, **changes)


def blob_inventory(artifacts):
    """The exact ``blob/`` entries ``blob_closure::entries`` records."""
    entries = dict(member(row) for row in artifacts)
    entries.update(directory(path) for path in support.archive_directories(artifacts))
    return entries


def positive_inputs(producer=None):
    tenant = str(uuid.uuid4())
    producer = producer or str(uuid.uuid4())
    registrations = [registration_id(), registration_id()]
    # One API-created repository holds every registration of the source, and the
    # archive carries the pack/idx pair of each registered pack (skipping the idx
    # slot of the scratch row), in the real wire shape.
    repos = [ready_repo(str(uuid.uuid4()), tenant), ready_repo(str(uuid.uuid4()), tenant)]
    artifacts = []
    for registration in registrations:
        identity = {"registration_id": registration, "repository_id": repos[0]["id"],
                    "pack_id": str(uuid.uuid4()), "tenant_id": tenant}
        # Real A4 pair: both roles commit under one publication, so they share
        # repository, pack and tenant identity; hold/requests, SHA and length
        # stay per artifact.
        for role, slot in support.PAIR_ROLES:
            artifacts.append(dict(archive_artifact(), role=role, slot=slot,
                                  length=4096 if role == "pack" else 1200, **identity))
    roots = [{"root_id": str(uuid.uuid4()), "state": "active", "owner_id": producer},
             {"root_id": str(uuid.uuid4()), "state": "released", "owner_id": producer}]
    versions = list(schema_baseline.SCHEMA_VERSIONS)
    expected = {"format": 22, "schema_versions": versions, "schema_baseline": list(versions),
                "registered_packs": registrations,
                "artifacts": len(artifacts), "roots": roots, "repos": repos, "producer": producer,
                "registration_scopes": {row["registration_id"]: (row["repository_id"], row["pack_id"])
                                        for row in artifacts},
                "serving_read": serving_read_marker(repos[0]["id"], tenant)}
    carry = {table: {"rows": 2, "sha256": "00" * 32} for table in support._CARRY_TABLES}
    manifest = {"format": 22, "schema_versions": list(versions),
                "repositories": [{"id": repo["id"], "backend": "pg_refstore"} for repo in repos],
                # `closure_of` and the file entries are both derived from the
                # archived `length`, never from an A4 column.
                "blob_closure": {"artifacts": len(artifacts), "bytes": sum(row["length"] for row in artifacts),
                                 "provider": "s3", "backend_identity": "ab" * 32},
                "blob_artifacts": artifacts, "refstore": carry,
                # `entries()` inventories the whole `blob/` tree: the artifact
                # files plus the two parent directories of each artifact, with
                # the same `Entry.kind` values the Rust inventory records.
                "files": blob_inventory(artifacts)}
    return manifest, expected


class CarryInventoryTest(unittest.TestCase):
    # Migration 144 root OID/tombstone ledgers, pinned independently of the
    # implementation tuple so a silent drop cannot derive its own expectation.
    MIGRATION_144_ROOT_LEDGERS = frozenset({"ref_store_core_root_oids", "ref_store_core_root_tombstones"})

    def test_migration_144_root_ledgers_are_in_the_carry_inventory(self):
        carry = set(support._CARRY_TABLES)
        self.assertEqual(len(support._CARRY_TABLES), len(carry), "carry inventory repeats a table")
        self.assertLessEqual(self.MIGRATION_144_ROOT_LEDGERS, carry,
                             "carry inventory must include the migration-144 root OIDs and tombstones")

    # Migration 146 serving-read ledger, pinned independently of the tuple.
    MIGRATION_146_SERVING_READ_TABLES = frozenset({
        "ref_store_core_serving_reads", "ref_store_core_serving_read_refs",
        "ref_store_core_serving_read_packs", "ref_store_core_serving_read_artifacts"})

    def test_migration_146_serving_read_ledger_is_in_the_carry_inventory(self):
        carry = set(support._CARRY_TABLES)
        self.assertLessEqual(self.MIGRATION_146_SERVING_READ_TABLES, carry,
                             "carry inventory must include the migration-146 serving-read header and children")
        for table in sorted(self.MIGRATION_146_SERVING_READ_TABLES):
            manifest, expected = positive_inputs()
            del manifest["refstore"][table]
            with self.assertRaisesRegex(AssertionError, "carry is missing " + table):
                support.format22_manifest_checks(manifest, expected)
            manifest, expected = positive_inputs()
            manifest["refstore"][table]["rows"] = 0
            with self.assertRaisesRegex(AssertionError, "carry is missing " + table):
                support.format22_manifest_checks(manifest, expected)


class Format22ManifestTest(unittest.TestCase):
    def test_positive_manifest_with_active_released_roots_and_distinct_producer(self):
        manifest, expected = positive_inputs()
        detail = support.format22_manifest_checks(manifest, expected)
        self.assertEqual(detail["registrations"], 2)
        self.assertEqual(detail["roots"], {"active": 1, "released": 1})
        self.assertTrue(detail["producer_distinct_from_tenant"])
        self.assertEqual(detail["serving_read"], {
            key: expected["serving_read"][key]
            for key in ("pin_id", "repository_id", "tenant_id", "owner_id", "pack_count")})

    def test_missing_or_misbound_serving_read_marker_is_refused(self):
        manifest, expected = positive_inputs()
        with self.assertRaisesRegex(AssertionError, "no validated serving_read"):
            support.format22_manifest_checks(manifest, dict(expected, serving_read=None))
        with self.assertRaisesRegex(AssertionError, "no nonempty pack count"):
            support.format22_manifest_checks(
                manifest, dict(expected, serving_read=dict(expected["serving_read"], pack_count=0)))
        with self.assertRaisesRegex(AssertionError, "pack_count differs"):
            support.format22_manifest_checks(
                manifest, dict(expected, serving_read=dict(expected["serving_read"], pack_count=3)))
        with self.assertRaisesRegex(AssertionError, "archive does not carry"):
            support.format22_manifest_checks(
                manifest, dict(expected, serving_read=dict(expected["serving_read"], repository_id=str(uuid.uuid4()))))
        with self.assertRaisesRegex(AssertionError, "tenant of its archived repository"):
            support.format22_manifest_checks(
                manifest, dict(expected, serving_read=dict(expected["serving_read"], tenant_id=str(uuid.uuid4()))))
        with self.assertRaisesRegex(AssertionError, "requester is a repository tenant"):
            support.format22_manifest_checks(
                manifest, dict(expected, serving_read=dict(
                    expected["serving_read"], owner_id=expected["repos"][0]["owner_id"])))

    def test_one_registration_shares_repository_pack_and_tenant_identity(self):
        # Real A4 pair: the pack and idx rows of one publication carry the same
        # repository, generated pack id and repository tenant; a per-role fixture
        # (three different ids per artifact) is not a source this drill can see.
        manifest, expected = positive_inputs()
        by_registration = {}
        for row in manifest["blob_artifacts"]:
            by_registration.setdefault(row["registration_id"], []).append(row)
        self.assertEqual(sorted(by_registration), sorted(expected["registered_packs"]))
        for registration, pair in by_registration.items():
            self.assertEqual([row["role"] for row in pair], ["pack", "idx"])
            for field in support.REGISTRATION_IDENTITY:
                self.assertEqual(len({row[field] for row in pair}), 1, field)
            # The identity the oracle compares against comes from the source.
            self.assertEqual(expected["registration_scopes"][registration],
                             (pair[0]["repository_id"], pair[0]["pack_id"]))
        self.assertEqual(len({pair[0]["pack_id"] for pair in by_registration.values()}), 2)
        self.assertLessEqual({row["repository_id"] for row in manifest["blob_artifacts"]},
                             {repo["id"] for repo in expected["repos"]})
        # Only hold/request ids, SHA and length are per artifact.
        packs = [row for row in manifest["blob_artifacts"] if row["role"] == "pack"]
        idxs = [row for row in manifest["blob_artifacts"] if row["role"] == "idx"]
        self.assertEqual(len({row["hold_id"] for row in manifest["blob_artifacts"]}), 4)
        self.assertEqual(len({row["sha256"] for row in manifest["blob_artifacts"]}), 4)
        self.assertNotEqual({row["length"] for row in packs}, {row["length"] for row in idxs})
        support.format22_manifest_checks(manifest, expected)

    def test_a_pair_that_does_not_share_its_identity_is_refused(self):
        for field in support.REGISTRATION_IDENTITY:
            with self.subTest(field):
                manifest, expected = positive_inputs()
                manifest["blob_artifacts"][1][field] = str(uuid.uuid4())
                with self.assertRaisesRegex(AssertionError, "disagree on their " + field
                                            + "|API did not create|scopes differ"):
                    support.format22_manifest_checks(manifest, expected)

    def test_pair_identity_drift_is_refused_without_registration_scopes(self):
        # The optional independent source scopes never carry the pair check:
        # each pair must share `repository_id`, `pack_id` and `tenant_id` on its
        # own, so a drift is refused on its exact field name even when
        # `registration_scopes` is absent.
        for field in support.REGISTRATION_IDENTITY:
            for scopes in ("absent", "kept"):
                with self.subTest(field=field, scopes=scopes):
                    manifest, expected = positive_inputs()
                    drifted = manifest["blob_artifacts"][1]
                    source = expected["registration_scopes"][drifted["registration_id"]]
                    if scopes == "absent":
                        del expected["registration_scopes"]
                    else:
                        # The source scope still names the un-drifted pair, so the
                        # pair check must refuse first, on its own field name.
                        self.assertEqual(source, (drifted["repository_id"], drifted["pack_id"]))
                    drifted[field] = str(uuid.uuid4())
                    manifest["files"] = blob_inventory(manifest["blob_artifacts"])
                    with self.assertRaisesRegex(AssertionError, "disagree on their " + field):
                        support.format22_manifest_checks(manifest, expected)
        # A missing or non-uuid identity is a drift too, not a silent empty scope.
        for value in (None, "", str(uuid.uuid4()).upper(), str(uuid.uuid4()).replace("-", "")):
            with self.subTest(value=value):
                manifest, expected = positive_inputs()
                del expected["registration_scopes"]
                manifest["blob_artifacts"][3]["pack_id"] = value
                with self.assertRaisesRegex(AssertionError, "disagree on their pack_id"):
                    support.format22_manifest_checks(manifest, expected)

    def test_an_agreed_pair_builds_one_scope_without_source_scopes(self):
        # Without `registration_scopes` an agreed pair still yields one
        # (repository_id, pack_id, tenant_id) scope, checked against the
        # API-created repositories, and the optional comparison is skipped.
        manifest, expected = positive_inputs()
        del expected["registration_scopes"]
        detail = support.format22_manifest_checks(manifest, expected)
        self.assertTrue(detail["pair_identity_shared"])
        for registration in expected["registered_packs"]:
            pair = [row for row in manifest["blob_artifacts"] if row["registration_id"] == registration]
            self.assertEqual(tuple(support._registration_scope(manifest["blob_artifacts"], registration, field)
                                   for field in support.REGISTRATION_IDENTITY),
                             (pair[0]["repository_id"], pair[0]["pack_id"], pair[0]["tenant_id"]))

    def test_malformed_source_scopes_are_refused(self):
        for value in ({"x": ("y",)}, "not-a-mapping",
                      {str(uuid.uuid4()): ("not-a-uuid", str(uuid.uuid4()))}):
            with self.subTest(value=value):
                manifest, expected = positive_inputs()
                expected["registration_scopes"] = value
                with self.assertRaisesRegex(AssertionError, "expected registration scopes are not a mapping"
                                            + "|not a \\(repository_id, pack_id\\) pair|expected repository id is not a uuid"):
                    support.format22_manifest_checks(manifest, expected)

    def test_two_registrations_may_not_share_a_pack_id(self):
        manifest, expected = positive_inputs()
        second_pack, second_idx = manifest["blob_artifacts"][2:]
        first_pack = manifest["blob_artifacts"][0]
        for row in (second_pack, second_idx):
            path = support.archive_path(row)
            entry = manifest["files"].pop(path)
            row["pack_id"] = first_pack["pack_id"]
            manifest["files"][support.archive_path(row)] = entry
        with self.assertRaisesRegex(AssertionError, "share a pack id"):
            support.format22_manifest_checks(manifest, expected)

    def test_artifact_repository_and_tenant_must_be_api_created_and_its_tenant(self):
        # A wrong but internally consistent identity is caught against the
        # expected repositories/tenants, not against byte totals. Only the
        # artifact rows move: the archive's frozen `blob/` inventory still
        # names the API repository, so the file and parent-directory checks
        # (which run earlier) cannot mask the identity result.
        manifest, expected = positive_inputs()
        foreign = str(uuid.uuid4())
        for row in manifest["blob_artifacts"]:
            row["repository_id"] = foreign
        with self.assertRaisesRegex(AssertionError, "API did not create"):
            support.format22_manifest_checks(manifest, expected)
        # One row of a pair naming a foreign repository is first and always a
        # pair-identity drift, even when `registration_scopes` is absent.
        for scopes in ("kept", "removed"):
            with self.subTest(scopes):
                manifest, expected = positive_inputs()
                manifest["blob_artifacts"][0]["repository_id"] = str(uuid.uuid4())
                manifest["files"] = blob_inventory(manifest["blob_artifacts"])
                if scopes == "removed":
                    del expected["registration_scopes"]
                with self.assertRaisesRegex(AssertionError, "disagree on their repository_id"):
                    support.format22_manifest_checks(manifest, expected)
        manifest, expected = positive_inputs()
        wrong = str(uuid.uuid4())
        for row in manifest["blob_artifacts"]:
            row["tenant_id"] = wrong
        with self.assertRaisesRegex(AssertionError, "tenant is not the tenant of its repository"):
            support.format22_manifest_checks(manifest, expected)
        # A repository the API created, but not the one the source publishes
        # these registrations under: only the source scopes can catch it.
        manifest, expected = positive_inputs()
        for row in manifest["blob_artifacts"]:
            row["repository_id"] = expected["repos"][1]["id"]
        manifest["files"] = blob_inventory(manifest["blob_artifacts"])
        with self.assertRaisesRegex(AssertionError, "scopes differ from the source publications"):
            support.format22_manifest_checks(manifest, expected)
        # Without the independent source scopes the self-consistent rows stand
        # alone, which is exactly why the native drill should pass them.
        del expected["registration_scopes"]
        support.format22_manifest_checks(manifest, expected)

    def test_archive_artifacts_use_the_serialized_length_field(self):
        # A real archive carries `ledger::Artifact`'s `length`, never the A4
        # column name `content_length`; the positive fixture proves the wire
        # shape the native archive actually writes.
        manifest, expected = positive_inputs()
        for entry in manifest["blob_artifacts"]:
            self.assertIn("length", entry)
            self.assertNotIn("content_length", entry)
        support.format22_manifest_checks(manifest, expected)

    def test_missing_or_wrong_archive_length_is_refused_without_key_error(self):
        def without(entry, field):
            return {key: value for key, value in entry.items() if key != field}

        def with_(entry, field, value):
            return dict(entry, **{field: value})

        # A non-object entry is only reachable through the reader itself: the
        # manifest checks index earlier archive fields before the byte proof.
        cases = (
            ("no length field", lambda row: without(row, "length"), "carries no length field", True),
            ("A4 column name only", lambda row: with_(without(row, "length"), "content_length", row["length"]),
             "carries no length field", True),
            ("length plus A4 column", lambda row: with_(row, "content_length", row["length"]), "content_length", True),
            ("verified locator length", lambda row: with_(row, "verified_length", row["length"]), "verified_length", True),
            ("null length", lambda row: with_(row, "length", None), "not a positive integer", True),
            ("boolean length", lambda row: with_(row, "length", True), "not a positive integer", True),
            ("zero length", lambda row: with_(row, "length", 0), "not a positive integer", True),
            ("negative length", lambda row: with_(row, "length", -4096), "not a positive integer", True),
            ("string length", lambda row: with_(row, "length", "4096"), "not a positive integer", True),
            ("not an object", lambda row: "4096", "not a JSON object", False),
        )
        for name, mutate, message, reachable in cases:
            with self.subTest(name):
                with self.assertRaisesRegex(AssertionError, message):
                    support.archive_length(mutate(archive_artifact()))
                if reachable:
                    manifest, expected = positive_inputs()
                    manifest["blob_artifacts"][0] = mutate(manifest["blob_artifacts"][0])
                    with self.assertRaisesRegex(AssertionError, message):
                        support.format22_manifest_checks(manifest, expected)

    def test_archive_length_must_agree_with_the_closure_bytes(self):
        fragment = archive_artifact()
        self.assertEqual(support.archive_length(fragment), 4096)
        self.assertEqual(support.archive_path(fragment), "blob/%s/%s/pack.pack"
                         % (fragment["repository_id"], fragment["pack_id"]))
        # An internally positive but inconsistent length must not pass: the
        # closure byte total is derived from these very fields.
        manifest, expected = positive_inputs()
        # Restore binds each member to its own artifact length, so the
        # aggregate inconsistency behind it is never reached.
        manifest["blob_artifacts"][0]["length"] += 1
        with self.assertRaisesRegex(AssertionError, "member length differs from its artifact length"):
            support.format22_manifest_checks(manifest, expected)
        # The aggregate is only ever counted over real regular-file members, so
        # a total that still closes cannot hide a member without a byte count.
        manifest, expected = positive_inputs()
        files = manifest["files"]
        dropped = files[support.archive_path(manifest["blob_artifacts"][0])]["bytes"]
        del files[support.archive_path(manifest["blob_artifacts"][0])]["bytes"]
        files[support.archive_path(manifest["blob_artifacts"][1])]["bytes"] += dropped
        self.assertEqual(sum(entry.get("bytes", 0) for name, entry in files.items() if name.startswith("blob/")),
                         manifest["blob_closure"]["bytes"])
        with self.assertRaisesRegex(AssertionError, "no integer byte count"):
            support.format22_manifest_checks(manifest, expected)

    def test_member_paths_are_the_rust_archive_path_not_the_hold_id(self):
        manifest, expected = positive_inputs()
        self.assertEqual(set(manifest["files"]),
                         {support.archive_path(row) for row in manifest["blob_artifacts"]}
                         | set(support.archive_directories(manifest["blob_artifacts"])))
        for row in manifest["blob_artifacts"]:
            self.assertEqual(support.archive_path(row), "blob/%s/%s/%s.%s"
                             % (row["repository_id"], row["pack_id"], row["role"], row["role"]))
            self.assertNotIn(row["hold_id"], support.archive_path(row))
        # The old synthetic `blob/<hold_id>` naming is refused even though every
        # byte, digest and count is unchanged.
        manifest, expected = positive_inputs()
        manifest["files"] = {"blob/" + row["hold_id"]: entry for row, (_, entry) in
                             zip(manifest["blob_artifacts"], [member(row) for row in manifest["blob_artifacts"]])}
        with self.assertRaisesRegex(AssertionError, "Blob members"):
            support.format22_manifest_checks(manifest, expected)
        # Moving exactly one member to its hold-id name is a missing member.
        manifest, expected = positive_inputs()
        row = manifest["blob_artifacts"][0]
        manifest["files"]["blob/" + row["hold_id"]] = manifest["files"].pop(support.archive_path(row))
        with self.assertRaisesRegex(AssertionError, "extra Blob members: blob/" + row["hold_id"] + "$"):
            support.format22_manifest_checks(manifest, expected)

    def test_blob_inventory_is_exactly_the_artifact_files_and_their_directories(self):
        # `blob_closure::export` creates `blob/{repository_id}` and
        # `blob/{repository_id}/{pack_id}` and `entries()` inventories the whole
        # `blob/` tree, so the real archive's `files` map carries those two
        # `directory` entries per artifact next to the artifact files.
        manifest, expected = positive_inputs()
        self.assertTrue(support.format22_manifest_checks(manifest, expected)["member_paths_exact"])
        artifacts = manifest["blob_artifacts"]
        files = [support.archive_path(row) for row in artifacts]
        directories = sorted({"/".join(path.split("/")[:2]) for path in files}
                             | {path.rsplit("/", 1)[0] for path in files})
        self.assertEqual(support.archive_directories(artifacts), directories)
        for path in directories:
            self.assertEqual(manifest["files"][path],
                             {"kind": "directory", "mode": 0o700, "bytes": 0, "sha256": None, "target": None})
            self.assertNotIn(path, files)

    def test_blob_directory_entry_pins_every_serialized_field(self):
        # `inventory` records a real directory as `Entry { kind: "directory",
        # mode, bytes: 0, sha256: None, target: None }`; kind alone is not the
        # entry. Each wrong field below keeps the path set, every kind and
        # every byte total intact, so only the directory-field oracle can
        # refuse it.
        cases = (
            ("bytes", 1, "carries non-zero bytes"),
            ("bytes", True, "carries non-zero bytes"),
            ("bytes", None, "carries non-zero bytes"),
            ("sha256", "00" * 32, "carries a sha256"),
            ("sha256", "", "carries a sha256"),
            ("target", "blob", "carries a target"),
            ("target", "", "carries a target"),
        )
        for field, value, reason in cases:
            with self.subTest(field=field, value=value):
                manifest, expected = positive_inputs()
                path = support.archive_directories(manifest["blob_artifacts"])[0]
                manifest["files"][path][field] = value
                with self.assertRaisesRegex(AssertionError, "Blob directory at " + re.escape(path) + " " + reason):
                    support.format22_manifest_checks(manifest, expected)
        # A dropped field is not the serialized entry either; `Option::None`
        # is a present JSON `null`, never an absent key.
        for field in ("sha256", "target"):
            with self.subTest(dropped=field):
                manifest, expected = positive_inputs()
                path = support.archive_directories(manifest["blob_artifacts"])[1]
                del manifest["files"][path][field]
                with self.assertRaisesRegex(AssertionError, "Blob directory at .* carries a " + field):
                    support.format22_manifest_checks(manifest, expected)

    def test_blob_directory_entry_refuses_every_unknown_field(self):
        # `backup::Entry` is `#[serde(deny_unknown_fields)]`, so a directory
        # entry has exactly `kind`, `mode`, `bytes`, `sha256` and `target`; an
        # extra key is a manifest Rust would refuse to load, not a directory.
        for key, value in (("length", 0), ("path", "blob"), ("size", 0), ("Kind", "directory"),
                           ("mode ", 0o700), ("", None), ("target_base64", None)):
            with self.subTest(unknown=key):
                manifest, expected = positive_inputs()
                path = support.archive_directories(manifest["blob_artifacts"])[0]
                manifest["files"][path][key] = value
                with self.assertRaisesRegex(
                        AssertionError,
                        "Blob directory at " + re.escape(path) + " carries an unknown field " + re.escape(key)):
                    support.format22_manifest_checks(manifest, expected)

    def test_blob_directory_mode_must_be_a_non_bool_subset_of_0o700(self):
        # `private_dir` asks for 0o700 and the umask may only clear bits, so a
        # bitwise-subset reduced mode (even 0) is a real archive, while a bool,
        # a non-integer, a negative or any group/world/special bit is not --
        # including numerically smaller modes such as 0o640 that carry group
        # bits.
        for mode in (0o700, 0o500, 0o600, 0o400, 0o100, 0):
            with self.subTest(mode=mode):
                manifest, expected = positive_inputs()
                for path in support.archive_directories(manifest["blob_artifacts"]):
                    manifest["files"][path]["mode"] = mode
                self.assertTrue(support.format22_manifest_checks(manifest, expected)["member_paths_exact"])
        # A mixed inventory, as an unusually restrictive umask could leave one
        # directory but not the other, is still a real archive.
        manifest, expected = positive_inputs()
        first = support.archive_directories(manifest["blob_artifacts"])[1]
        self.assertEqual(first.count("/"), 2)
        manifest["files"][first]["mode"] = 0o500
        support.format22_manifest_checks(manifest, expected)
        for mode, reason in ((True, "non-integer mode"), (False, "non-integer mode"),
                             (float(0o700), "non-integer mode"), ("448", "non-integer mode"), (None, "non-integer mode"),
                             (0o710, "outside"), (0o701, "outside"), (0o707, "outside"), (0o740, "outside"),
                             (0o704, "outside"), (0o1700, "outside"), (0o777, "outside"), (0o7777, "outside"),
                             # Numerically below 0o700 but carrying group bits, so not a bitwise subset.
                             (0o640, "subset"), (0o660, "subset"), (0o670, "subset"), (0o440, "subset"),
                             (-1, "outside"), (-0o400, "outside")):
            with self.subTest(mode=mode):
                manifest, expected = positive_inputs()
                path = support.archive_directories(manifest["blob_artifacts"])[2]
                manifest["files"][path]["mode"] = mode
                with self.assertRaisesRegex(AssertionError, "Blob directory at .* " + reason):
                    support.format22_manifest_checks(manifest, expected)
        # A directory with no `mode` at all is not the serialized `Entry`.
        manifest, expected = positive_inputs()
        path = support.archive_directories(manifest["blob_artifacts"])[-1]
        del manifest["files"][path]["mode"]
        with self.assertRaisesRegex(AssertionError, "Blob directory at .* non-integer mode"):
            support.format22_manifest_checks(manifest, expected)

    def test_missing_blob_directory_is_refused(self):
        for what in ("repository", "pack"):
            with self.subTest(what):
                manifest, expected = positive_inputs()
                path = support.archive_directories(manifest["blob_artifacts"])[0 if what == "repository" else 1]
                self.assertEqual(path.count("/"), 1 if what == "repository" else 2)
                del manifest["files"][path]
                with self.assertRaisesRegex(AssertionError, "missing Blob members: " + path):
                    support.format22_manifest_checks(manifest, expected)

    def test_extra_blob_directory_is_refused(self):
        manifest, expected = positive_inputs()
        pack_path = support.archive_path(manifest["blob_artifacts"][0]).rsplit("/", 1)[0]
        extra = pack_path + "/" + str(uuid.uuid4())
        manifest["files"].update([directory(extra)])
        # The extra directory carries no bytes, so every aggregate still closes.
        self.assertEqual(sum(entry["bytes"] for name, entry in manifest["files"].items() if name.startswith("blob/")),
                         manifest["blob_closure"]["bytes"])
        with self.assertRaisesRegex(AssertionError, "extra Blob directories: " + extra):
            support.format22_manifest_checks(manifest, expected)
        # A sibling repository directory that no artifact's archive path parents.
        manifest, expected = positive_inputs()
        extra = "blob/" + str(uuid.uuid4())
        manifest["files"].update([directory(extra)])
        with self.assertRaisesRegex(AssertionError, "extra Blob directories: " + extra):
            support.format22_manifest_checks(manifest, expected)
        # The real `blob/` root is a file-map entry in the manifest, but
        # `inventory` starts below it and `export` never records it as a member.
        manifest, expected = positive_inputs()
        manifest["files"].update([directory("blob/")])
        with self.assertRaisesRegex(AssertionError, "extra Blob directories"):
            support.format22_manifest_checks(manifest, expected)

    def test_blob_artifact_paths_and_parents_must_be_regular_files_and_directories(self):
        # A required parent announced as a file (the old file-only model) is
        # not what `export` writes.
        manifest, expected = positive_inputs()
        path = support.archive_directories(manifest["blob_artifacts"])[0]
        manifest["files"][path]["kind"] = "file"
        with self.assertRaisesRegex(AssertionError, "parent path is not a directory entry: " + path):
            support.format22_manifest_checks(manifest, expected)
        # An artifact path announced as a directory is never a regular file.
        for kind in ("directory", "dir", "symlink"):
            with self.subTest(kind):
                manifest, expected = positive_inputs()
                row = manifest["blob_artifacts"][2]
                manifest["files"][support.archive_path(row)]["kind"] = kind
                with self.assertRaisesRegex(AssertionError,
                                            "member at an artifact's archive path is not a regular file"):
                    support.format22_manifest_checks(manifest, expected)
        # Moving a member under its hold id leaves both its archive path and its
        # parent directories missing; the file itself is an extra member.
        manifest, expected = positive_inputs()
        row = manifest["blob_artifacts"][0]
        manifest["files"]["blob/" + row["hold_id"]] = manifest["files"].pop(support.archive_path(row))
        with self.assertRaisesRegex(AssertionError, "extra Blob members: blob/" + row["hold_id"] + "$"):
            support.format22_manifest_checks(manifest, expected)

    def test_extra_or_missing_blob_members_are_refused_beyond_their_totals(self):
        manifest, expected = positive_inputs()
        del manifest["files"][support.archive_path(manifest["blob_artifacts"][3])]
        with self.assertRaisesRegex(AssertionError, "missing Blob members: blob/"):
            support.format22_manifest_checks(manifest, expected)
        # A regular file under a plausible Blob tree that no artifact names.
        manifest, expected = positive_inputs()
        row = manifest["blob_artifacts"][0]
        stray = "blob/" + row["repository_id"] + "/" + str(uuid.uuid4()) + "/pack.pack"
        manifest["files"][stray] = member(row)[1]
        with self.assertRaisesRegex(AssertionError, "extra Blob members: " + stray + "$"):
            support.format22_manifest_checks(manifest, expected)
        manifest, expected = positive_inputs()
        manifest["files"]["blob/" + row["hold_id"]] = member(row)[1]
        with self.assertRaisesRegex(AssertionError, "extra Blob members: blob/" + row["hold_id"] + "$"):
            support.format22_manifest_checks(manifest, expected)
        # A Blob entry that is not a regular file is never a member.
        manifest, expected = positive_inputs()
        row = manifest["blob_artifacts"][2]
        manifest["files"][support.archive_path(row)]["kind"] = "dir"
        with self.assertRaisesRegex(AssertionError, "member at an artifact's archive path is not a regular file"):
            support.format22_manifest_checks(manifest, expected)
        manifest, expected = positive_inputs()
        idx = [art for art in manifest["blob_artifacts"] if art["role"] == "idx"][0]
        member_path = support.archive_path(idx)
        # Drop the whole registration from the closure but keep its two archive
        # paths and its parent directories: every count and total still agrees.
        manifest["files"][member_path]["kind"] = "dir"
        manifest["files"][member_path.replace("/idx.idx", "/pack.pack")]["kind"] = "dir"
        pair = [art for art in manifest["blob_artifacts"] if art["registration_id"] != idx["registration_id"]]
        manifest["blob_artifacts"] = pair
        manifest["blob_closure"]["artifacts"] = len(pair)
        manifest["blob_closure"]["bytes"] = sum(art["length"] for art in pair)
        expected["artifacts"] = len(pair)
        expected["registered_packs"].remove(idx["registration_id"])
        expected["registration_scopes"].pop(idx["registration_id"])
        with self.assertRaisesRegex(AssertionError, "extra Blob members"):
            support.format22_manifest_checks(manifest, expected)
        # A stranded directory that no artifact's archive path parents is an
        # extra directory even when every file is exactly right.
        manifest, expected = positive_inputs()
        pack_path = support.archive_path(manifest["blob_artifacts"][0]).rsplit("/", 1)[0]
        manifest["files"].update([directory(pack_path + "/" + str(uuid.uuid4()))])
        with self.assertRaisesRegex(AssertionError, "extra Blob directories"):
            support.format22_manifest_checks(manifest, expected)

    def test_compensating_member_lengths_cannot_pass_the_aggregate_totals(self):
        # Restore binds each Artifact::archive_path() to that artifact's own
        # length and digest, so one member's surplus never covers another's
        # deficit even when every aggregate total still closes.
        manifest, expected = positive_inputs()
        first, second = manifest["blob_artifacts"][0], manifest["blob_artifacts"][1]
        manifest["files"][support.archive_path(first)]["bytes"] = first["length"] + 7
        manifest["files"][support.archive_path(second)]["bytes"] = second["length"] - 7
        files = manifest["files"]
        self.assertEqual(sum(files[support.archive_path(row)]["bytes"] for row in manifest["blob_artifacts"]),
                         manifest["blob_closure"]["bytes"])
        self.assertEqual(sum(row["length"] for row in manifest["blob_artifacts"]), manifest["blob_closure"]["bytes"])
        with self.assertRaisesRegex(AssertionError, "member length differs from its artifact length"):
            support.format22_manifest_checks(manifest, expected)
        # A serialized length off by one with every member and the closure
        # total unchanged: the aggregate still closes, the locator does not.
        manifest, expected = positive_inputs()
        files = manifest["files"]
        manifest["blob_artifacts"][0]["length"] += 1
        self.assertEqual(sum(files[support.archive_path(row)]["bytes"] for row in manifest["blob_artifacts"]),
                         manifest["blob_closure"]["bytes"])
        with self.assertRaisesRegex(AssertionError, "member length differs from its artifact length"):
            support.format22_manifest_checks(manifest, expected)
        # A member carrying another artifact's real byte count is refused too.
        manifest, expected = positive_inputs()
        files = manifest["files"]
        files[support.archive_path(manifest["blob_artifacts"][0])]["bytes"] = manifest["blob_artifacts"][1]["length"]
        files[support.archive_path(manifest["blob_artifacts"][1])]["bytes"] = manifest["blob_artifacts"][0]["length"]
        with self.assertRaisesRegex(AssertionError, "member length differs from its artifact length"):
            support.format22_manifest_checks(manifest, expected)

    def test_each_member_digest_must_be_its_own_artifact_digest(self):
        for changes in (
            # Swapping two real digests keeps every aggregate byte/digest fact.
            lambda files, rows: [files[support.archive_path(rows[0])].update(sha256=rows[1]["sha256"]),
                                 files[support.archive_path(rows[1])].update(sha256=rows[0]["sha256"])],
            # A member with no digest at all.
            lambda files, rows: files[support.archive_path(rows[0])].pop("sha256"),
            # The artifact's own digest changed, the member didn't.
            lambda files, rows: rows[3].update(sha256="9f" * 32),
        ):
            manifest, expected = positive_inputs()
            changes(manifest["files"], manifest["blob_artifacts"])
            with self.assertRaisesRegex(AssertionError, "member digest differs from its artifact digest"):
                support.format22_manifest_checks(manifest, expected)

    def test_archive_length_separates_the_wire_field_from_the_source_column(self):
        # The wire length is the only byte proof: renaming it to the A4 SQL
        # column name, or a boolean slot that Python would read as slot 1, is
        # refused.
        manifest, expected = positive_inputs()
        row = manifest["blob_artifacts"][2]
        row["content_length"] = row.pop("length")
        with self.assertRaisesRegex(AssertionError, "carries no length field"):
            support.format22_manifest_checks(manifest, expected)
        with self.assertRaisesRegex(AssertionError, "slot is not an integer"):
            support.archive_length(dict(archive_artifact(), slot=True))
        manifest, expected = positive_inputs()
        manifest["blob_artifacts"][1]["slot"] = True
        with self.assertRaisesRegex(AssertionError, "slot is not an integer"):
            support.format22_manifest_checks(manifest, expected)

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

    def test_realistic_full_ordered_schema_vector_is_accepted(self):
        # Format22 returns every applied migration, not just its maximum: the
        # realistic archive carries the complete ascending baseline ending at 147.
        versions = list(schema_baseline.SCHEMA_VERSIONS)
        self.assertGreater(len(versions), 1)
        self.assertEqual(versions, sorted(set(versions)))
        self.assertEqual(versions[-1], 147)
        self.assertEqual(support.expected_schema_versions(versions, schema_baseline.SCHEMA_VERSIONS, 147), versions)
        manifest, expected = positive_inputs()
        self.assertEqual(manifest["schema_versions"], versions)
        support.format22_manifest_checks(manifest, expected)

    def test_missing_reordered_or_extra_schema_versions_are_refused(self):
        manifest, expected = positive_inputs()
        versions = list(schema_baseline.SCHEMA_VERSIONS)
        for bad in ([147],                 # only the maximum (the old wrong assumption)
                    versions[:-1],         # drop the current version
                    versions[1:],          # drop the first migration
                    versions[0:1] + versions[2:],  # drop a middle migration
                    versions[:-1] + [146, 147],    # duplicate an entry
                    [versions[1], versions[0]] + versions[2:],  # first two swapped
                    versions[:-1] + [versions[-1] + 1],  # an unknown extra max version
                    versions + [versions[-1] + 1]):  # an extra appended version
            with self.assertRaisesRegex(AssertionError, "unexpected schema versions", msg=str(bad)):
                support.format22_manifest_checks(dict(manifest, schema_versions=bad), expected)
        with self.assertRaisesRegex(AssertionError, "unexpected schema versions"):
            support.format22_manifest_checks(dict(manifest, schema_versions=None), expected)

    def test_expected_vector_cannot_be_derived_from_the_manifest_or_be_unbounded(self):
        # The oracle must be an independent full vector ending at the supported
        # current version, never a self-derived or malformed expectation.
        baseline = list(schema_baseline.SCHEMA_VERSIONS)
        for bad in ([147], [], [1, 2, 3], [147, 146], [146, 147, 148], [1, 1, 2, 147],
                    baseline[:-1], baseline[1:], baseline + [148]):
            with self.assertRaises(AssertionError, msg=str(bad)):
                support.expected_schema_versions(bad, baseline, 147)
        with self.assertRaises(AssertionError):
            support.expected_schema_versions(baseline, baseline, 148)
        with self.assertRaises(TypeError):
            support.expected_schema_versions(None, baseline, 147)


class Format22RestoredServingReadTest(unittest.TestCase):
    def marker(self, pack_count=2):
        return serving_read_marker(str(uuid.uuid4()), str(uuid.uuid4()), pack_count=pack_count)

    def observed(self, pack_count=2):
        return {"headers": 1, "bound_headers": 1, "refs": 3, "declared_ref_count": 3, "packs": pack_count,
                "declared_pack_count": pack_count, "packs_with_exact_pair": pack_count,
                "packs_with_verified_pair": pack_count, "artifacts": 2 * pack_count}

    def test_exact_marker_read_is_reported_as_bounded_counts_only(self):
        marker = self.marker()
        detail = support.format22_serving_read_checks(self.observed(), marker)
        self.assertEqual(detail, {"pin": True, "headers": 1, "refs_equal_declared": True, "pack_count": 2,
                                  "packs": 2, "packs_with_exact_pair": 2, "artifacts": 4, "verified_pairs": 2})
        self.assertEqual(json.loads(json.dumps(detail)), detail)
        self.assertNotIn(marker["pin_id"], json.dumps(detail))

    def test_sql_reads_every_migration_146_table_for_the_exact_pin(self):
        marker = self.marker()
        sql = support.format22_restore_sql(marker)
        for table in CarryInventoryTest.MIGRATION_146_SERVING_READ_TABLES:
            self.assertIn("public." + table + " ", sql)
        self.assertIn("WHERE pin_id='" + marker["pin_id"] + "'::uuid", sql)
        self.assertIn("'" + marker["pin_id"] + "'::uuid", sql)
        for key in ("repository_id", "tenant_id", "owner_id"):
            self.assertIn("'" + marker[key] + "'::uuid", sql)

    def test_wrong_reads_are_refused(self):
        marker = self.marker()
        cases = (
            (dict(self.observed(), headers=2), "exactly one marker serving-read header"),
            (dict(self.observed(), bound_headers=0), "not bound to the marker"),
            (dict(self.observed(), refs=2), "declared ref_count"),
            (dict(self.observed(), packs=1), "marker pack_count"),
            (dict(self.observed(), declared_pack_count=3), "marker pack_count"),
            (dict(self.observed(), packs_with_exact_pair=1), "slot-0 pack and slot-1 idx"),
            (dict(self.observed(), packs_with_verified_pair=1), "verified nonempty"),
            (dict(self.observed(), artifacts=3), "2 \\* pack_count"),
            (dict(self.observed(), declared_ref_count=-1, refs=0), "declared ref_count"),
        )
        for observed, message in cases:
            with self.assertRaisesRegex(AssertionError, message):
                support.format22_serving_read_checks(observed, marker)
        with self.assertRaisesRegex(AssertionError, "unexpected fields"):
            support.format22_serving_read_checks(dict(self.observed(), secrets="x"), marker)
        with self.assertRaisesRegex(AssertionError, "no nonempty pack count"):
            support.format22_serving_read_checks(self.observed(), self.marker(pack_count=0))


class NativeFixtureContractTest(unittest.TestCase):
    def marker(self, producer=None):
        tenant = str(uuid.uuid4())
        producer = producer or str(uuid.uuid4())
        repositories = [ready_repo(str(uuid.uuid4()), tenant), ready_repo(str(uuid.uuid4()), tenant)]
        return {"kind": support.MARKER_KIND, "format": 22,
                "repositories": repositories,
                "bound_repository_id": repositories[0]["id"],
                "tenant_id": tenant,
                "producer_owner_id": producer,
                "registrations": [{"registration_id": registration_id(), "roles": ["idx", "pack"],
                                   "artifact_set_digest": "55" * 32} for _ in range(2)],
                "roots": [{"root_id": str(uuid.uuid4()), "state": "active", "tenant_id": tenant, "owner_id": producer},
                          {"root_id": str(uuid.uuid4()), "state": "released", "tenant_id": tenant,
                           "owner_id": producer}],
                # The transient serving read is captured on the first API repo by
                # a third real user; pack_count equals the registration count.
                "serving_read": {"pin_id": str(uuid.uuid4()), "repository_id": repositories[0]["id"],
                                 "tenant_id": tenant, "owner_id": str(uuid.uuid4()), "pack_count": 2}}

    def test_valid_marker(self):
        detail = support.native_marker_checks(self.marker())
        self.assertEqual(detail["registrations"], 2)
        self.assertTrue(detail["producer_distinct_from_tenant"])

    def test_valid_marker_carries_one_nonempty_serving_read(self):
        marker = self.marker()
        detail = support.native_marker_checks(marker)
        serving_read = detail["serving_read"]
        self.assertEqual(serving_read["pin_id"], marker["serving_read"]["pin_id"])
        self.assertEqual(serving_read["pack_count"], detail["registrations"])
        self.assertTrue(serving_read["requester_distinct"])
        self.assertNotIn("expires_at", marker["serving_read"])

    def test_marker_requires_a_serving_read(self):
        marker = self.marker()
        serving_read = marker["serving_read"]
        del marker["serving_read"]
        with self.assertRaisesRegex(AssertionError, "no serving_read"):
            support.native_marker_checks(marker)
        with self.assertRaisesRegex(AssertionError, "unexpected fields"):
            support.native_marker_checks(dict(marker, serving_read=dict(serving_read, expires_at=1)))
        with self.assertRaisesRegex(AssertionError, "owner_id is not a valid uuid"):
            support.native_marker_checks(dict(marker, serving_read=dict(serving_read, owner_id="not-a-uuid")))
        with self.assertRaisesRegex(AssertionError, "no nonempty pack count"):
            support.native_marker_checks(dict(marker, serving_read=dict(serving_read, pack_count=0)))
        with self.assertRaisesRegex(AssertionError, "pack_count differs"):
            support.native_marker_checks(dict(marker, serving_read=dict(serving_read, pack_count=3)))

    def test_marker_serving_read_must_name_an_api_repository_and_a_third_requester(self):
        marker = self.marker()
        serving_read = marker["serving_read"]
        with self.assertRaisesRegex(AssertionError, "not API-created"):
            support.native_marker_checks(
                dict(marker, serving_read=dict(serving_read, repository_id=str(uuid.uuid4()))))
        with self.assertRaisesRegex(AssertionError, "owning tenant"):
            support.native_marker_checks(
                dict(marker, serving_read=dict(serving_read, tenant_id=str(uuid.uuid4()))))
        # The serving read must also be on the marker's bound repository, not
        # merely on another repository the same API created.
        with self.assertRaisesRegex(AssertionError, "bound_repository_id"):
            support.native_marker_checks(
                dict(marker, serving_read=dict(serving_read, repository_id=marker["repositories"][1]["id"])))
        with self.assertRaisesRegex(AssertionError, "marker.tenant_id"):
            support.native_marker_checks(dict(marker, tenant_id=str(uuid.uuid4())))
        with self.assertRaisesRegex(AssertionError, "requester is a repository tenant"):
            support.native_marker_checks(
                dict(marker, serving_read=dict(serving_read, owner_id=marker["repositories"][1]["owner_id"])))
        with self.assertRaisesRegex(AssertionError, "requester is the producer"):
            support.native_marker_checks(
                dict(marker, serving_read=dict(serving_read, owner_id=marker["producer_owner_id"])))

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
