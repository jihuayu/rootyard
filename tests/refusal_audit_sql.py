"""SQL fragments of the #18 Git refusal audit, matched to the real schema.

Every table and column here is one a running server writes (see
``tests/test_browse_mixed_refs.py``, which pins them against the migrations and
``src/``); the audit is a single ``jsonb_build_object(...)::text`` row decoded by
``json.loads``, never a separator split.  Imported by ``mixed_ref_cases.py``.

Every SQL *value* comes from ``BrowseHarness._sql_literal``, which only escapes
(``'`` -> ``''``) and adds no delimiters: ``literal(value)`` wraps that escaped
result in single quotes, so a value can never become a SQL expression.
"""
import json
import re
import time

# The durable operation evidence written by the receive-pack path
# (``src/reliability.rs``).  ``finished`` and ``storage_generation_matches``
# are JSON booleans there and are projected with ``->`` so the interval JSON
# keeps them as booleans end to end.  ``interrupted`` and
# ``ungranted_without_hooks`` are the schema-backed text flags (the same text
# ``tests/pat_git_publication_fence.py`` and ``tests/independent_refs.py`` read
# with ``->>``).  A JSON ``null`` receipt is absence; a missing key is not.
EVIDENCE_TEXT_KEYS = ("interrupted", "ungranted_without_hooks")
EVIDENCE_BOOL_KEYS = ("finished", "storage_generation_matches")
EVIDENCE_KEYS = (*EVIDENCE_BOOL_KEYS, *EVIDENCE_TEXT_KEYS)

# A missing boolean key stays absent as the JSON string ``"missing"``, which the
# decoder and contract both reject: absence is never mistaken for ``false``.
EVIDENCE_MISSING_BOOL = "'\"missing\"'::jsonb"

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def audit_where(repo, actor, token):
    """One joined row: the operation carries this run's actor and token, and its admission agrees.

    ``repo``/``actor``/``token`` are complete SQL literals (``literal(...)``).
    The predicate is equality against exactly one identity: there is no lookup,
    no aggregation and no role inference, and no matching row is a failure.
    """
    return ("o.actor_id=" + actor + "::uuid AND o.token_id=" + token + "::uuid AND o.repository_id=" + repo
            + " AND a.actor_id=o.actor_id AND a.token_id=o.token_id AND a.repository_id=o.repository_id")


def audit_pairs(repo, refs, same):
    """``jsonb_build_object`` key/expression pairs for the newest row.

    ``refs`` are SQL literals of the pushed ref names (already sorted);
    ``same`` is ``audit_where``.  The SQL ``status`` only says settled/pending/
    missing; the judge re-derives every field so a bad invariant can never read
    as pending.
    """
    return [
        ("status", "CASE WHEN o.id IS NULL THEN 'missing' WHEN o.outcome='no_ref_changes' "
                         "AND o.settled_at IS NOT NULL AND a.state='ABORTED' AND " + same
                         + " THEN 'settled' ELSE 'pending' END"),
        ("created_at", "coalesce(o.created_at::text, '')"),
        ("outcome", "coalesce(o.outcome, '')"), ("settled", "o.settled_at IS NOT NULL"),
        ("aborted", "coalesce(a.state='ABORTED', false)"), ("repository_matches", same),
        ("ref_names", "coalesce(to_jsonb(a.ref_names), '[]'::jsonb)"),
        # The admission stores the sorted set; compare it to the same sorted set.
        ("refs_exactly", "coalesce(a.ref_names=ARRAY[" + ",".join(refs) + "]::text[], false)"),
        # A JSON null is not absence: ``-> ... IS NULL`` is also true for a
        # missing key, so the receipt must be absent by both tests.
        ("no_receipt", "o.evidence->'post_receive' IS NULL OR o.evidence->'post_receive'='null'::jsonb"),
        *((key, "coalesce(o.evidence->>'" + key + "', 'missing')") for key in EVIDENCE_KEYS),
        ("events", "coalesce((SELECT count(*) FROM outbox_events x WHERE x.operation_id=o.id), 0)"),
        ("admitted_now", "EXISTS (SELECT 1 FROM git_ref_admissions w WHERE w.repository_id=" + repo
                         + " AND w.state='ADMITTED')"),
        ("newer", "EXISTS (SELECT 1 FROM git_operations y WHERE y.repository_id=" + repo
                  + " AND y.sequence>o.sequence)"),
        ("reference_events", "coalesce(o.evidence->'reference_events', '[]'::jsonb)")]


def audit_query(pairs, repo, literal):
    """One statement: the newest operation row joined to its admission, as JSON.

    ``repo`` is a complete SQL literal; ``literal`` is ``_sql_literal``, wrapped
    in quotes here, and builds both the ``jsonb_build_object`` keys and the
    repository predicate.  The key expression is not a value the helper escapes.
    """
    obj = "jsonb_build_object(" + ",".join(literal(key) + ", " + expression for key, expression in pairs) + ")"
    return ("SELECT " + obj + "::text FROM git_operations o LEFT JOIN git_ref_admissions a ON a.writer_id=o.id "
            "WHERE o.id=coalesce((SELECT o.id FROM git_operations o WHERE o.repository_id=" + repo
            + " ORDER BY o.sequence DESC LIMIT 1), '00000000-0000-0000-0000-000000000000')")


def operation_highwater_query(repo_id, escape):
    if not isinstance(repo_id, str) or _UUID.fullmatch(repo_id) is None:
        raise ValueError("invalid repository id")
    return (
        "SELECT COALESCE(MAX(sequence), 0)::text FROM git_operations "
        "WHERE repository_id = '" + escape(repo_id) + "'::uuid"
    )


def operations_after_query(repo_id, sequence, actor_id, token_id, escape):
    pattern = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )

    def uuid_literal(value):
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise ValueError("invalid identifier")
        return "'" + escape(value) + "'::uuid"

    repo = uuid_literal(repo_id)
    actor = uuid_literal(actor_id)
    token = uuid_literal(token_id)
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise ValueError("invalid sequence")
    lowwater = str(sequence)

    row = ", ".join(
        [
            "'operation_id'", "o.id::text",
            "'sequence'", "o.sequence",
            "'outcome'", "o.outcome",
            "'settled'", "(COALESCE(o.settled_at IS NOT NULL, false))",
            "'finished'", "(COALESCE(o.evidence->'finished', " + EVIDENCE_MISSING_BOOL + "))",
            "'actor_and_token_match'",
            "(COALESCE(o.repository_id = %s AND o.actor_id = %s AND o.token_id = %s, false))"
            % (repo, actor, token),
            "'human_principal'",
            "(COALESCE(o.actor_id IS NOT NULL AND o.token_id IS NOT NULL"
            " AND o.service_principal_id IS NULL, false))",
            "'service_principal'",
            "(COALESCE(o.service_principal_id IS NOT NULL"
            " AND o.actor_id IS NULL AND o.token_id IS NULL, false))",
            "'evidence_no_receipt'",
            "(COALESCE(o.evidence->'post_receive' IS NULL"
            " OR o.evidence->'post_receive' = 'null'::jsonb, false))",
            "'interrupted'",
            "(COALESCE(o.evidence->>'interrupted', 'missing'))",
            "'storage_generation_matches'",
            "(COALESCE(o.evidence->'storage_generation_matches', " + EVIDENCE_MISSING_BOOL + "))",
            "'ungranted_without_hooks'",
            "(COALESCE(o.evidence->>'ungranted_without_hooks', 'missing'))",
            "'reference_events'",
            "(COALESCE(o.evidence->'reference_events', '[]'::jsonb))",
            "'admission_present'", "(COALESCE(a.writer_id IS NOT NULL, false))",
            "'admission_state'", "a.state",
            "'admission_settled'", "(COALESCE(a.settled_at IS NOT NULL, false))",
            "'admission_identity_matches'",
            "(COALESCE(a.actor_id = o.actor_id AND a.token_id = o.token_id"
            " AND a.repository_id = o.repository_id, false))",
            "'admission_ref_names'",
            "(COALESCE(to_jsonb(a.ref_names), '[]'::jsonb))",
            "'outbox_count'",
            "(SELECT COUNT(*) FROM outbox_events e WHERE e.operation_id = o.id)",
            "'outbox_ref_names'",
            "COALESCE((SELECT jsonb_agg(e.ref_name ORDER BY e.transaction_sequence, e.ref_name)"
            " FROM outbox_events e WHERE e.operation_id = o.id AND e.ref_name IS NOT NULL),"
            " '[]'::jsonb)",
        ]
    )

    return (
        "SELECT COALESCE(jsonb_agg(jsonb_build_object(%s) ORDER BY o.sequence, o.id),"
        " '[]'::jsonb)::text"
        " FROM git_operations o"
        " LEFT JOIN git_ref_admissions a"
        " ON a.writer_id = o.id AND a.repository_id = o.repository_id"
        " WHERE o.repository_id = %s AND o.sequence > %s"
        % (row, repo, lowwater)
    )


def service_release_valid_query(operation_id, repo_id, escape):
    uuid_pattern = re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    if not isinstance(operation_id, str) or not uuid_pattern.fullmatch(operation_id):
        raise ValueError("invalid operation id")
    if not isinstance(repo_id, str) or not uuid_pattern.fullmatch(repo_id):
        raise ValueError("invalid repository id")
    op_sql = escape(operation_id)
    repo_sql = escape(repo_id)
    return f"""
SELECT COALESCE(EXISTS (
    SELECT 1
    FROM git_operations o
    JOIN repositories r ON r.id = o.repository_id
    WHERE o.id = '{op_sql}'::uuid
      AND o.repository_id = '{repo_sql}'::uuid
      AND o.outcome = 'recorded'
      AND o.settled_at IS NOT NULL
      AND o.actor_id IS NULL
      AND o.token_id IS NULL
      AND o.service_principal_id IS NOT NULL
      AND o.actor_name = 'ci-scheduler'
      AND r.state = 'ready'
      AND r.storage_generation = o.storage_generation
      AND jsonb_typeof(o.evidence) = 'object'
      AND (SELECT count(*) FROM jsonb_object_keys(o.evidence)) = 7
      AND NOT (o.evidence ? 'action')
      AND jsonb_typeof(o.evidence -> 'version') = 'number'
      AND o.evidence -> 'version' = '1'::jsonb
      AND jsonb_typeof(o.evidence -> 'kind') = 'string'
      AND o.evidence ->> 'kind' = 'observed_immutable_ci_root'
      AND jsonb_typeof(o.evidence -> 'finished') = 'boolean'
      AND o.evidence -> 'finished' = 'true'::jsonb
      AND jsonb_typeof(o.evidence -> 'interrupted') = 'boolean'
      AND o.evidence -> 'interrupted' = 'false'::jsonb
      AND jsonb_typeof(o.evidence -> 'reference_events') = 'array'
      AND o.evidence -> 'reference_events' = '[]'::jsonb
      AND jsonb_typeof(o.evidence -> 'retained') = 'boolean'
      AND o.evidence -> 'retained' = 'true'::jsonb
      AND jsonb_typeof(o.evidence -> 'intent') = 'object'
      AND (SELECT count(*) FROM jsonb_object_keys(o.evidence -> 'intent')) = 8
      AND jsonb_typeof(o.evidence -> 'intent' -> 'version') = 'number'
      AND o.evidence -> 'intent' -> 'version' = '1'::jsonb
      AND jsonb_typeof(o.evidence -> 'intent' -> 'job_id') = 'string'
      AND (o.evidence -> 'intent' ->> 'job_id') ~ '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$'
      AND jsonb_typeof(o.evidence -> 'intent' -> 'owner_id') = 'string'
      AND o.evidence -> 'intent' ->> 'owner_id' = r.owner_id::text
      AND jsonb_typeof(o.evidence -> 'intent' -> 'repository_id') = 'string'
      AND o.evidence -> 'intent' ->> 'repository_id' = o.repository_id::text
      AND jsonb_typeof(o.evidence -> 'intent' -> 'storage_generation') = 'number'
      AND o.evidence -> 'intent' -> 'storage_generation' = to_jsonb(o.storage_generation)
      AND jsonb_typeof(o.evidence -> 'intent' -> 'object_format') = 'string'
      AND o.evidence -> 'intent' ->> 'object_format' IN ('sha1', 'sha256')
      AND jsonb_typeof(o.evidence -> 'intent' -> 'target_oid') = 'string'
      AND (
          (o.evidence -> 'intent' ->> 'object_format' = 'sha1'
           AND (o.evidence -> 'intent' ->> 'target_oid') ~ '^[0-9a-f]{{40}}$')
          OR
          (o.evidence -> 'intent' ->> 'object_format' = 'sha256'
           AND (o.evidence -> 'intent' ->> 'target_oid') ~ '^[0-9a-f]{{64}}$')
      )
      AND (o.evidence -> 'intent' ->> 'target_oid') ~ '[1-9a-f]'
      AND jsonb_typeof(o.evidence -> 'intent' -> 'retention_ref') = 'string'
      AND o.evidence -> 'intent' ->> 'retention_ref' = 'refs/rootyard-ci/jobs/' || (o.evidence -> 'intent' ->> 'job_id')
      AND EXISTS (
          SELECT 1 FROM ci_service_principals p
          WHERE p.id = o.service_principal_id
            AND p.repository_id = o.repository_id
            AND p.kind = 'ci-pin'
            AND p.active
      )
      AND NOT EXISTS (SELECT 1 FROM git_ref_admissions a WHERE a.writer_id = o.id)
      AND (SELECT count(*) FROM outbox_events e WHERE e.operation_id = o.id) = 1
      AND EXISTS (
          SELECT 1 FROM outbox_events e
          WHERE e.operation_id = o.id
            AND e.repository_id = o.repository_id
            AND e.storage_generation = o.storage_generation
            AND e.operation_sequence = o.sequence
            AND e.ref_name = o.evidence -> 'intent' ->> 'retention_ref'
            AND e.new_oid = o.evidence -> 'intent' ->> 'target_oid'
            AND e.old_oid IS DISTINCT FROM o.evidence -> 'intent' ->> 'target_oid'
            AND (
                (o.evidence -> 'intent' ->> 'object_format' = 'sha1'
                 AND e.old_oid ~ '^[0-9a-f]{{40}}$')
                OR
                (o.evidence -> 'intent' ->> 'object_format' = 'sha256'
                 AND e.old_oid ~ '^[0-9a-f]{{64}}$')
            )
      )
), false)::text"""


def evidence_problems(evidence):
    """Keys of a mapping whose evidence value does not have its schema type.

    Callers pass the complete evidence mapping (or a complete row): every key
    in both ``EVIDENCE_KEYS`` tuples is required, so a partial subset mapping
    is reported as missing the keys it does not carry.
    """
    if not isinstance(evidence, dict):
        return list(EVIDENCE_KEYS)
    problems = []
    for key in EVIDENCE_BOOL_KEYS:
        if evidence.get(key) is not True:
            problems.append(key)
    for key in EVIDENCE_TEXT_KEYS:
        value = evidence.get(key)
        if not (isinstance(value, str) and value in ("true", "false")):
            problems.append(key)
    return problems


def assert_evidence_contract(label, evidence):
    """The refusal receipt keys, typed exactly as the server stores them.

    ``finished``/``storage_generation_matches`` must be the JSON boolean
    ``True`` (``"true"`` as a string, ``1`` or a missing key all fail).
    ``interrupted``/``ungranted_without_hooks`` are the text flags and must be
    present as ``"true"`` or ``"false"``.  ``refusal_audit_verdict`` uses the
    same two key tuples, so SQL, decoder, verdict and this contract agree.
    """
    if not isinstance(evidence, dict):
        raise AssertionError(f"{label}: folded evidence must be an object, got {type(evidence).__name__}")
    missing = [key for key in EVIDENCE_KEYS if key not in evidence]
    if missing:
        raise AssertionError(f"{label}: folded evidence is missing {missing!r}")
    invalid = evidence_problems(evidence)
    if invalid:
        raise AssertionError(f"{label}: folded evidence has wrong types for {invalid!r}")
    return evidence


def fold_operation_evidence(audit, operations):
    """One operation's evidence keys, read from its own row, never a counter."""
    matching = [row for row in operations if row["operation_id"] == audit["operation_id"]]
    if len(matching) != 1:
        raise AssertionError(
            f"{audit['label']}: expected exactly one interval row for {audit['operation_id']!r}, "
            f"found {len(matching)}"
        )
    return {key: matching[0][key] for key in EVIDENCE_KEYS}


def refusal_audit_verdict(row, journal, refs):
    if not isinstance(row, dict):
        return {"status": "settled", "problems": ["row"]}
    if row.get("settled") is False:
        return {"status": "pending", "problems": []}

    problems = []

    if row.get("settled") is not True:
        problems.append("settled")
    if row.get("outcome") != "no_ref_changes":
        problems.append("outcome")
    if row.get("actor_and_token_match") is not True:
        problems.append("actor_and_token_match")
    if row.get("human_principal") is not True:
        problems.append("human_principal")
    if row.get("service_principal") is not False:
        problems.append("service_principal")
    if row.get("admission_present") is not True:
        problems.append("admission_present")
    if row.get("admission_state") != "ABORTED":
        problems.append("admission_state")
    if row.get("admission_settled") is not True:
        problems.append("admission_settled")
    if row.get("admission_identity_matches") is not True:
        problems.append("admission_identity_matches")

    expected_refs = sorted(refs)
    admission_ref_names = row.get("admission_ref_names")
    if not isinstance(admission_ref_names, list) or admission_ref_names != expected_refs:
        problems.append("admission_ref_names")

    outbox_count = row.get("outbox_count")
    if not isinstance(outbox_count, int) or isinstance(outbox_count, bool) or outbox_count != 0:
        problems.append("outbox_count")

    outbox_ref_names = row.get("outbox_ref_names")
    if not isinstance(outbox_ref_names, list) or outbox_ref_names != []:
        problems.append("outbox_ref_names")

    if row.get("evidence_no_receipt") is not True:
        problems.append("evidence_no_receipt")
    # One call on the complete row: the checker validates every evidence key,
    # so it must never receive a partial subset mapping.
    problems.extend(evidence_problems(row))

    interrupted = row.get("interrupted")
    ungranted = row.get("ungranted_without_hooks")
    if interrupted == "true" and ungranted != "true":
        problems.append("interrupted_ungranted_order")

    if not isinstance(journal, list) or journal != []:
        problems.append("journal")

    reference_events = row.get("reference_events")
    if not isinstance(reference_events, (list, dict)):
        problems.append("reference_events")
    else:
        events = [reference_events] if isinstance(reference_events, dict) else reference_events
        for event in events:
            if not isinstance(event, dict) or event.get("changes") != []:
                problems.append("reference_event_changes")
                break

    return {"status": "settled", "problems": list(dict.fromkeys(problems))}


def decode_operation_interval(raw, highwater):
    """Decode `operations_after_query` -At JSON text and enforce the decoder contract."""
    _ERR = "invalid operations interval"

    _KEY = (
        "operation_id",
        "sequence",
        "outcome",
        "settled",
        "finished",
        "actor_and_token_match",
        "human_principal",
        "service_principal",
        "evidence_no_receipt",
        "interrupted",
        "storage_generation_matches",
        "ungranted_without_hooks",
        "reference_events",
        "admission_present",
        "admission_state",
        "admission_settled",
        "admission_identity_matches",
        "admission_ref_names",
        "outbox_count",
        "outbox_ref_names",
    )
    _ALLOWED = frozenset(_KEY)

    _BOOL_KEYS = (
        "settled",
        *EVIDENCE_BOOL_KEYS,
        "actor_and_token_match",
        "human_principal",
        "service_principal",
        "evidence_no_receipt",
        "admission_present",
        "admission_settled",
        "admission_identity_matches",
    )

    _STR_KEYS = EVIDENCE_TEXT_KEYS

    _UUID_RE = re.compile(
        r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
    )

    def _is_int(value):
        return isinstance(value, int) and not isinstance(value, bool)

    def _is_str_list(value):
        return isinstance(value, list) and all(isinstance(item, str) for item in value)

    if not _is_int(highwater) or highwater < 0:
        raise ValueError(_ERR)
    if not isinstance(raw, str):
        raise ValueError(_ERR)

    try:
        parsed = json.loads(raw)
    except (ValueError, RecursionError):
        raise ValueError(_ERR) from None

    if not isinstance(parsed, list):
        raise ValueError(_ERR)

    seen_ids = set()
    previous_key = None

    for row in parsed:
        if not isinstance(row, dict):
            raise ValueError(_ERR)
        if set(row.keys()) != _ALLOWED or len(row) != len(_KEY):
            raise ValueError(_ERR)

        operation_id = row["operation_id"]
        if not isinstance(operation_id, str) or _UUID_RE.match(operation_id) is None:
            raise ValueError(_ERR)

        sequence = row["sequence"]
        if not _is_int(sequence) or sequence <= highwater:
            raise ValueError(_ERR)

        if not isinstance(row["outcome"], str):
            raise ValueError(_ERR)

        for name in _BOOL_KEYS:
            if not isinstance(row[name], bool):
                raise ValueError(_ERR)

        for name in _STR_KEYS:
            if not isinstance(row[name], str):
                raise ValueError(_ERR)

        admission_state = row["admission_state"]
        if admission_state is not None and not isinstance(admission_state, str):
            raise ValueError(_ERR)

        if not _is_str_list(row["admission_ref_names"]):
            raise ValueError(_ERR)
        if not _is_str_list(row["outbox_ref_names"]):
            raise ValueError(_ERR)

        outbox_count = row["outbox_count"]
        if not _is_int(outbox_count) or outbox_count < 0:
            raise ValueError(_ERR)

        # reference_events is intentionally opaque here.

        if operation_id in seen_ids:
            raise ValueError(_ERR)
        seen_ids.add(operation_id)

        key = (sequence, operation_id)
        if previous_key is not None and not (previous_key < key):
            raise ValueError(_ERR)
        previous_key = key

    return parsed


def audit_git_refusal_interval(before, label, refs, operation_rows_since, service_release_valid, pending_journal, ref_state):
    highwater = before["operation_highwater"]
    requested_refs = list(refs)
    deadline = time.monotonic() + 30
    ci_prefix = "refs/rootyard-ci/jobs/"
    retired_prefix = ".retired-"
    staging_prefix = ".tmp-operation-"

    if before["journal"] != []:
        raise AssertionError(
            f"{label}: journal must be empty before the interval, got {before['journal']!r}"
        )
    if before["state"] != "ready/-":
        raise AssertionError(
            f"{label}: harness state must be exactly 'ready/-' before the interval, "
            f"got {before['state']!r}"
        )

    def is_human_row(row):
        return (
            row["human_principal"] is True
            and row["service_principal"] is not True
            and row["actor_and_token_match"] is True
        )

    def is_service_row(row):
        return (
            row["human_principal"] is not True
            and row["service_principal"] is True
            and row["actor_and_token_match"] is not True
        )

    def validate_service_row(row):
        op_id = row["operation_id"]
        if not service_release_valid(row):
            raise AssertionError(
                f"{label}: settled service operation {op_id!r} is not a valid "
                f"same-repository ci-scheduler observed_immutable_ci_root operation "
                f"as validated by the owning source, with a single linked "
                f"rootyard-ci job outbox event"
            )
        outbox_refs = row["outbox_ref_names"]
        if (
            not isinstance(outbox_refs, list)
            or len(outbox_refs) != 1
            or not isinstance(outbox_refs[0], str)
            or not outbox_refs[0].startswith(ci_prefix)
        ):
            raise AssertionError(
                f"{label}: settled service operation {op_id!r} must link exactly "
                f"one '{ci_prefix}<job UUID>' outbox event, got {outbox_refs!r}"
            )
        return outbox_refs[0]

    def classify(rows):
        human = None
        service_rows = []
        service_ref_names = set()
        by_operation_id = {}
        for row in rows:
            op_id = row["operation_id"]
            by_operation_id[op_id] = row
            if is_human_row(row):
                if human is not None:
                    raise AssertionError(
                        f"{label}: more than one human operation row "
                        f"(operation_id={human['operation_id']!r} and {op_id!r})"
                    )
                human = row
            elif is_service_row(row):
                if row["settled"]:
                    service_ref_names.add(validate_service_row(row))
                service_rows.append(row)
            else:
                raise AssertionError(
                    f"{label}: unexpected principal combination on operation "
                    f"{op_id!r}: human_principal={row['human_principal']!r}, "
                    f"service_principal={row['service_principal']!r}, "
                    f"actor_and_token_match={row['actor_and_token_match']!r}"
                )
        return human, service_rows, service_ref_names, by_operation_id

    def check_human_verdict(human_row, journal):
        verdict = refusal_audit_verdict(human_row, journal, requested_refs)
        if not isinstance(verdict, dict):
            raise AssertionError(
                f"{label}: refusal_audit_verdict returned {type(verdict).__name__}, expected dict"
            )
        status = verdict["status"]
        problems = verdict["problems"]
        if status != "settled" or problems:
            raise AssertionError(
                f"{label}: settled human refusal operation {human_row['operation_id']!r} has invalid verdict: "
                f"status={status!r}, problems={problems!r}"
            )
        return verdict

    def unsettled(service_rows):
        for row in service_rows:
            if not row["settled"]:
                if not all(k in row for k in ("operation_id", "sequence")):
                    raise AssertionError(f"{label}: service row missing operation_id/sequence")
                return True
        return False

    def journal_entries(journal):
        if not isinstance(journal, list) or not all(
            isinstance(entry, str) for entry in journal
        ):
            raise AssertionError(
                f"{label}: journal must be a list of string directory basenames, "
                f"got {journal!r}"
            )
        return list(journal)

    def entry_match_kind(entry):
        # Returns (kind, sequence_or_None, operation_id) for recognized journal
        # directory basenames; raises for anything that is not a known form.
        if not isinstance(entry, str):
            raise AssertionError(
                f"{label}: pending journal entry {entry!r} is not a directory name"
            )
        if entry.startswith(retired_prefix):
            rest = entry[len(retired_prefix):]
            kind = "retired"
        elif entry.startswith(staging_prefix):
            rest = entry[len(staging_prefix):]
            kind = "tmp"
        else:
            rest = entry
            kind = "op"
        if kind == "tmp":
            return ("tmp", None, rest)
        seq_str, sep, op_id = rest.partition("-")
        if (
            not sep
            or len(seq_str) != 20
            or not seq_str.isdigit()
            or not op_id
            or "-" not in op_id
        ):
            raise AssertionError(
                f"{label}: pending journal entry {entry!r} is not a recognized "
                f"exact-format journal directory name "
                f"(expected '<20-digit sequence>-<operation id>', "
                f"'{retired_prefix}<...>' or '{staging_prefix}<operation id>')"
            )
        return (kind, int(seq_str), op_id)

    def match_entry(entry, by_operation_id):
        kind, sequence, op_id = entry_match_kind(entry)
        row = by_operation_id.get(op_id)
        if row is None:
            return None
        if kind == "tmp":
            # Highwater rows already limit tmp-operation staging to the interval.
            return row
        expected = f"{row['sequence']:020d}-{row['operation_id']}"
        if entry == expected or (
            kind == "retired" and f"{retired_prefix}{expected}" == entry
        ):
            return row
        return None

    def validate_journal_links(entries, by_operation_id, seen_unmatched):
        # Every journal directory must be linkable to an exact interval row. Entries
        # not yet visible are tracked; if one later vanishes before any exact row
        # appears, fail closed. Matched entries must belong to the one human refusal
        # or a source-validated service operation.
        unmatched = []
        for entry in entries:
            row = match_entry(entry, by_operation_id)
            if row is None:
                unmatched.append(entry)
        for entry in list(seen_unmatched):
            if entry not in entries and match_entry(entry, by_operation_id) is None:
                raise AssertionError(
                    f"{label}: pending journal {entry!r} disappeared before any exact "
                    f"interval operation row for it appeared (highwater={highwater!r})"
                )
        seen_unmatched.update(unmatched)
        seen_unmatched &= {e for e in entries if match_entry(e, by_operation_id) is None}
        for entry in entries:
            row = match_entry(entry, by_operation_id)
            if row is None:
                continue
            if not (is_human_row(row) or is_service_row(row)):
                raise AssertionError(
                    f"{label}: pending journal {entry!r} is linked to an operation "
                    f"with an unexpected principal: {row!r}"
                )
        return unmatched

    seen_unmatched = set()
    human = None
    service_rows_seen = []
    service_ref_names = set()
    after = None

    while True:
        if time.monotonic() > deadline:
            raise AssertionError(
                f"{label}: timed out waiting for settled Git refusal interval "
                f"(highwater={highwater!r}, requested_refs={requested_refs!r}, "
                f"pending_journal={pending_journal()!r})"
            )

        rows = operation_rows_since(highwater)
        human, service_rows, service_names, by_operation_id = classify(rows)
        current_journal = journal_entries(pending_journal())
        validate_journal_links(current_journal, by_operation_id, seen_unmatched)

        human_ready = (
            human is not None and human["settled"] and not unsettled(service_rows)
        )
        if human_ready:
            service_rows_seen = service_rows
            service_ref_names = set(service_names)

        if human_ready and not current_journal:
            after_candidate = ref_state()
            after_candidate_journal = journal_entries(after_candidate["journal"])
            if after_candidate_journal:
                validate_journal_links(
                    after_candidate_journal, by_operation_id, seen_unmatched
                )
                time.sleep(0.05)
                continue

            reread_rows = operation_rows_since(highwater)
            (
                reread_human,
                reread_service,
                reread_names,
                reread_by_id,
            ) = classify(reread_rows)
            reread_journal = journal_entries(pending_journal())
            validate_journal_links(reread_journal, reread_by_id, seen_unmatched)
            new_ids = set(reread_by_id) - set(by_operation_id)
            if reread_journal or new_ids:
                # New journals or operations arrived: repeat the causal
                # evaluation so every new service root is validated.
                continue
            if (
                reread_human is None
                or not reread_human["settled"]
                or unsettled(reread_service)
            ):
                time.sleep(0.05)
                continue

            human, service_rows_seen = reread_human, reread_service
            service_ref_names = set(reread_names)
            after = after_candidate
            break

        time.sleep(0.05)

    final_verdict = refusal_audit_verdict(human, after["journal"], requested_refs)
    if not isinstance(final_verdict, dict):
        raise AssertionError(
            f"{label}: final refusal_audit_verdict returned {type(final_verdict).__name__}, expected dict"
        )
    if final_verdict["status"] != "settled" or final_verdict["problems"]:
        raise AssertionError(
            f"{label}: final Git refusal verdict is not settled and clean: "
            f"status={final_verdict['status']!r}, problems={final_verdict['problems']!r}"
        )
    if before["journal"] != [] or after["journal"] != []:
        raise AssertionError(
            f"{label}: journal must be empty before and after, "
            f"before={before['journal']!r}, after={after['journal']!r}"
        )
    if before["state"] != "ready/-" or after["state"] != "ready/-":
        raise AssertionError(
            f"{label}: harness state must be exactly 'ready/-' before and after, "
            f"before={before['state']!r}, after={after['state']!r}"
        )

    before_refs = {name: oid for name, oid in before["refs"]}
    after_refs = {name: oid for name, oid in after["refs"]}
    changed_refs = {
        name
        for name in set(before_refs) | set(after_refs)
        if before_refs.get(name) != after_refs.get(name)
    }
    for name in requested_refs:
        if before_refs.get(name) != after_refs.get(name):
            raise AssertionError(
                f"{label}: requested ref {name!r} changed during Git refusal: "
                f"before={before_refs.get(name)!r}, after={after_refs.get(name)!r}"
            )
    unexpected = sorted(changed_refs - service_ref_names)
    if unexpected:
        raise AssertionError(
            f"{label}: refs changed without a validated CI service operation: "
            f"{unexpected!r} (validated service refs: {sorted(service_ref_names)!r})"
        )

    if before.get("api_refs") != after.get("api_refs"):
        raise AssertionError(
            f"{label}: public API refs changed during a refused Git request "
            f"(before={before.get('api_refs')!r}, after={after.get('api_refs')!r})"
        )
    evidence = assert_evidence_contract(label, fold_operation_evidence(
        {"label": label, "operation_id": human["operation_id"]}, reread_rows))

    return {
        "label": label,
        "evidence": evidence,
        "trigger": {
            "operation_id": human["operation_id"],
            "sequence": human["sequence"],
        },
        "service": [
            {
                "operation_id": row["operation_id"],
                "sequence": row["sequence"],
                "ref_names": sorted(
                    [n for n in (row["outbox_ref_names"] or []) if isinstance(n, str)]
                ),
            }
            for row in service_rows_seen
            if row["settled"]
        ],
        "service_ref_names": sorted(service_ref_names),
        "changed_refs": sorted(changed_refs),
        "final_verdict": final_verdict,
        "diagnostics": {
            "before_outcomes": before.get("outcomes"),
            "before_admissions": before.get("admissions"),
            "before_outbox": before.get("outbox"),
            "after_outcomes": after.get("outcomes"),
            "after_admissions": after.get("admissions"),
            "after_outbox": after.get("outbox"),
        },
    }


def audit_api_refusal_interval(before, after, label, refs, operation_rows_since, service_release_valid, ref_state):
    highwater = before["operation_highwater"]
    requested = list(refs)
    deadline = time.monotonic() + 30

    def classify(rows):
        settled_service_rows, pending_service_rows, allowed_service_ref_names = [], [], set()
        for row in rows:
            if row["human_principal"] is True:
                raise AssertionError(f"{label}: human operation row in response interval")
            if (row["human_principal"] is not False
                    or row["service_principal"] is not True
                    or row["actor_and_token_match"] is not False):
                raise AssertionError(f"{label}: unexpected operation row principal flags")
            if row["settled"] is False:
                pending_service_rows.append(row)
                continue
            if service_release_valid(row) is not True:
                raise AssertionError(f"{label}: service row not source-validated")
            outbox_names = row["outbox_ref_names"]
            if (not isinstance(outbox_names, list) or len(outbox_names) != 1
                    or not isinstance(outbox_names[0], str)
                    or not outbox_names[0].startswith("refs/rootyard-ci/jobs/")):
                raise AssertionError(f"{label}: service row outbox ref invalid")
            settled_service_rows.append(row)
            allowed_service_ref_names.add(outbox_names[0])
        return settled_service_rows, pending_service_rows, allowed_service_ref_names

    def wait(moment):
        if moment >= deadline:
            raise AssertionError(f"{label}: timed out waiting for service operations to settle")
        time.sleep(0.05)

    # The rows read once the refs are final are the proof, not a recount: every
    # read is classified (any human or unknown-principal row fails), and the
    # figures reported below come from that same last classified set.
    while True:
        _, pending_service_rows, _ = classify(operation_rows_since(highwater))
        if pending_service_rows:
            wait(time.monotonic())
            continue
        final_after = ref_state()
        final_rows = operation_rows_since(highwater)
        settled_service_rows, pending_service_rows, allowed_service_ref_names = classify(final_rows)
        if pending_service_rows:
            wait(time.monotonic())
            continue
        break

    for name, snapshot in (("before", before), ("after", final_after)):
        if snapshot["journal"] != []:
            raise AssertionError(f"{label}: {name} journal not empty")
        if snapshot["state"] != "ready/-":
            raise AssertionError(f"{label}: {name} state not ready/-")

    before_api_refs = before.get("api_refs")
    if not isinstance(before_api_refs, list):
        raise AssertionError(f"{label}: before api_refs missing or not a list")
    for name, snapshot in (("before", before), ("after", after), ("final_after", final_after)):
        api_refs = snapshot.get("api_refs")
        if not isinstance(api_refs, list):
            raise AssertionError(f"{label}: {name} api_refs missing or not a list")
        if api_refs != before_api_refs:
            raise AssertionError(f"{label}: {name} api_refs differ from before api_refs")

    before_refs = dict(before["refs"])
    after_refs = dict(final_after["refs"])
    changed = [name for name in sorted(set(before_refs) | set(after_refs))
               if before_refs.get(name) != after_refs.get(name)]
    for name in requested:
        if before_refs.get(name) != after_refs.get(name):
            raise AssertionError(f"{label}: requested ref {name!r} changed")
    disallowed = [name for name in changed if name not in allowed_service_ref_names]
    if disallowed:
        raise AssertionError(f"{label}: refs changed outside service outbox: {disallowed}")

    service_operations = [
        {
            "operation_id": row["operation_id"],
            "sequence": row["sequence"],
            "outbox_ref": row["outbox_ref_names"][0],
        }
        for row in settled_service_rows
    ]
    return {
        "label": label,
        # Zero by construction: classify() already failed on any human row.
        "user_operation_count": len([row for row in final_rows if row["human_principal"] is True]),
        "service_operations": service_operations,
        "changed_refs": changed,
        "diagnostics": {
            "response_highwater": after["operation_highwater"],
            "final_highwater": final_after["operation_highwater"],
            "before": {
                "outcomes": before["outcomes"],
                "admissions": before["admissions"],
                "outbox": before["outbox"],
                "operation_highwater": before["operation_highwater"],
            },
            "after": {
                "outcomes": final_after["outcomes"],
                "admissions": final_after["admissions"],
                "outbox": final_after["outbox"],
                "operation_highwater": final_after["operation_highwater"],
            },
        },
    }
