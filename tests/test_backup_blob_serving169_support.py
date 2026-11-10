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
            self.assertEqual(sql.split("\\echo ", 1)[0].count("jsonb_build_object("), 4, case.name)
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

    def test_corruption_sql_includes_broken_rows_fields_only(self):
        cases, _ = self.plan()
        allowed = {"DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id='%s'::uuid AND role='%s'"
                   % (case.registration.id, role) if role else
                   "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id='%s'::uuid"
                   % case.registration.id for case, role in zip(cases[:3], ("pack", "idx", None))}
        self.assertEqual(len(allowed), 3)
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

def digests_of(publication, rows):
    """The stored digest of one pair, encoded like ``Artifact::line``."""
    return support.artifact_set_digest(
        [dict({key: row[key] for key in support.DIGEST_IDENTITY}, role=role, slot=slot, sha256=row["sha256"],
              content_length=row["content_length"]) for role, slot in support.PAIR_ROLES for row in (rows[role],)])


def planned_cases():
    """Four planned cases built exactly like the native drill builds them."""
    first, second = sorted(registration_id() for _ in range(2))
    publication = {"repository_id": str(uuid.uuid4()), "pack_id": str(uuid.uuid4()),
                   "hold_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()), "authority_id": str(uuid.uuid4()),
                   "authority_generation": 3, "attempt_id": str(uuid.uuid4()), "namespace": "core-pack",
                   "provider": "s3", "backend_identity": "ab" * 32}
    rows = {"pack": dict(publication, role="pack", slot=0, sha256="ef" * 32, content_length=4096),
            "idx": dict(publication, role="idx", slot=1, sha256="12" * 32, content_length=1200)}
    digest = digests_of(publication, rows)
    cases = support.corruption_plan([second, first], [second, first],
                                    scope_pairs([first, second]),
                                    {first: ("pack", "idx"), second: ("pack", "idx")},
                                    {first: {digest}, second: {"34" * 32}})
    # The publication mirrors the A4 row; the enclosing repository/pack only
    # come from the target registration (the read join), as in the clone SQL.
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


class CorruptionEvidenceTest(unittest.TestCase):
    def setUp(self):
        (cases, self.publication, self.rows, self.facts, self.guarded) = planned_cases()
        self.cases = cases
        self.by_name = {case.name: case for case in cases}

    def expectations(self):
        return list(oracle_evidence(self.cases, self.publication, self.rows, self.facts, self.guarded))

    def test_exactly_the_intended_row_is_proven_for_every_case(self):
        self.assertEqual(self.cases[0].registration.digest, digests_of(self.publication, self.rows))
        self.assertNotEqual(self.rows["pack"]["sha256"], self.rows["idx"]["sha256"])
        for case, changed, observed in self.expectations():
            detail = support.corruption_findings(case, changed, observed)
            self.assertEqual(detail["rows_changed"], changed)
            self.assertEqual(detail["finding"], support.finding(case))
            self.assertTrue(detail["clone_local_superuser"])
            self.assertTrue(detail["guarded_ledgers_unchanged"])

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
                "artifacts": len(artifacts), "roots": roots, "repos": repos, "producer": producer,
                "serving_read": serving_read_marker(repos[0]["id"], tenant)}
    carry = {table: {"rows": 2, "sha256": "00" * 32} for table in support._CARRY_TABLES}
    manifest = {"format": 22, "schema_versions": [147],
                "repositories": [{"id": repo["id"], "backend": "pg_refstore"} for repo in repos],
                "blob_closure": {"artifacts": len(artifacts), "bytes": sum(row["content_length"] for row in artifacts),
                                 "provider": "s3", "backend_identity": "ab" * 32},
                "blob_artifacts": artifacts, "refstore": carry, "files": {
                    "blob/" + row["hold_id"]: {"kind": "file", "bytes": row["content_length"]} for row in artifacts}}
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
