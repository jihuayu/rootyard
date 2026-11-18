-- Run with psql -X -f on a job-owned disposable PostgreSQL database. A failed
-- connection or assertion rolls back the whole scratch schema on disconnect.
\set ON_ERROR_STOP on
BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '2s';
CREATE SCHEMA issue42_attempt_scratch;
SET LOCAL search_path = issue42_attempt_scratch, pg_catalog, pg_temp;

CREATE TABLE schema_migrations (version int PRIMARY KEY);
CREATE TABLE repositories (id uuid PRIMARY KEY, owner_id uuid NOT NULL, UNIQUE (id, owner_id));
\ir ../../migrations/138_ref_store_operation_identity.sql
\ir ../../migrations/139_ref_store_core.sql
\ir ../../migrations/147_ref_store_serving_operations.sql
\ir issue42_attempt_contract.sql

CREATE FUNCTION fixture_id(n int) RETURNS uuid LANGUAGE sql IMMUTABLE AS $$
    SELECT ('00000000-0000-4000-8000-' || lpad(n::text, 12, '0'))::uuid
$$;

INSERT INTO repositories VALUES (fixture_id(1), fixture_id(2));
INSERT INTO ref_store_issuer_lanes(repository_id, issuer_id, lane, last_reserved_sequence)
VALUES (fixture_id(1), fixture_id(2), 'fixture', 1000);
INSERT INTO ref_store_core_gates(repository_id, tenant_id, object_format, history_incarnation,
                                 authority_epoch, group_epoch, head_ref, revision)
VALUES (fixture_id(1), fixture_id(2), 'sha1', fixture_id(3), 1, 1, 'refs/heads/main', 6);
INSERT INTO modeled_serving_scope VALUES (fixture_id(1), fixture_id(4), repeat('d', 64));
INSERT INTO ref_store_core_refs(repository_id, ref_name, oid, revision)
VALUES (fixture_id(1), 'refs/heads/main', repeat('a', 40), 6);

-- Model the existing A4 usage delta against nonzero counters. The pre-hold
-- stale fixture has no decision. Production separately closes an exact open
-- decision as rejected and retains earlier A3/A4 effects and charges.
CREATE TABLE fixture_a4_usage (
    repository_id uuid PRIMARY KEY REFERENCES repositories(id),
    registrations bigint NOT NULL,
    artifacts bigint NOT NULL,
    memberships bigint NOT NULL,
    logical_bytes bigint NOT NULL,
    receipts bigint NOT NULL
);
INSERT INTO fixture_a4_usage VALUES (fixture_id(1), 2, 4, 1, 4096, 5);

CREATE FUNCTION fixture_lock(public_no int, proposed_no int DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM lock_wrapper(fixture_id(1), fixture_id(public_no), fixture_id(proposed_no));
    PERFORM 1 FROM ref_store_issuer_lanes WHERE repository_id = fixture_id(1) AND issuer_id = fixture_id(2)
        AND lane = 'fixture' FOR UPDATE;
END $$;

CREATE FUNCTION fixture_public(n int) RETURNS void LANGUAGE sql AS $$
    INSERT INTO public_operations(repository_id, public_id, issuer_id, wire_digest, request_mode, backend_identity,
                                  realm, restore_incarnation)
    VALUES (fixture_id(1), fixture_id(n), fixture_id(2), repeat('a', 64), 'atomic', repeat('d', 64),
            ROW(fixture_id(1), fixture_id(2), 'sha1', fixture_id(3), 1, 1)::core_realm, fixture_id(4))
$$;

CREATE FUNCTION fixture_attempt(public_no int, slot_no int, private_no int) RETURNS void LANGUAGE sql AS $$
    INSERT INTO private_attempts(repository_id, public_id, slot, private_id, plan_digest, proof_digest, base_revision)
    VALUES (fixture_id(1), fixture_id(public_no), slot_no, fixture_id(private_no),
            repeat(CASE WHEN slot_no = 1 THEN 'd' ELSE 'b' END, 64),
            repeat(CASE WHEN slot_no = 1 THEN 'f' ELSE 'c' END, 64), CASE WHEN slot_no = 1 THEN 7 ELSE 6 END)
$$;

CREATE FUNCTION fixture_operation(n int, digest text DEFAULT repeat('b', 64)) RETURNS void LANGUAGE sql AS $$
    INSERT INTO ref_store_operations(repository_id, issuer_id, lane, sequence, operation_id, request_digest, state)
    VALUES (fixture_id(1), fixture_id(2), 'fixture', n, fixture_id(n), digest, 'pending')
$$;

CREATE FUNCTION fixture_bind(n int, parent_digest text, producer_digest text DEFAULT repeat('a', 64))
RETURNS void LANGUAGE sql AS $$
    INSERT INTO ref_store_serving_operations(repository_id, operation_id, issuer_id, producer_request_digest, plan_parent_digest)
    VALUES (fixture_id(1), fixture_id(n), fixture_id(2), producer_digest, parent_digest)
$$;

-- Exercise the actual 138 and 147 definitions in the same scratch transaction.
CREATE FUNCTION fixture_serving_operation(n int, parent_digest text DEFAULT repeat('b', 64)) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM fixture_operation(n, parent_digest);
    PERFORM fixture_bind(n, parent_digest);
END $$;

CREATE FUNCTION fixture_tombstone(n int) RETURNS void LANGUAGE sql AS $$
    INSERT INTO ref_store_cancellations(repository_id, issuer_id, lane, sequence, operation_id, request_digest)
    VALUES (fixture_id(1), fixture_id(2), 'fixture', n, fixture_id(n), repeat('b', 64))
$$;

CREATE FUNCTION fixture_cancel(n int, reason text) RETURNS void LANGUAGE sql AS $$
    UPDATE ref_store_operations SET state = 'cancelled', terminal_at = clock_timestamp(),
        terminal_result = jsonb_build_object('state', 'cancelled', 'reason', reason)
    WHERE (repository_id, operation_id) = (fixture_id(1), fixture_id(n))
$$;

CREATE FUNCTION fixture_core_commit(n int) RETURNS void LANGUAGE sql AS $$
    UPDATE ref_store_operations SET state = 'committed', terminal_at = clock_timestamp(), terminal_result = '{"revision":7}'
    WHERE (repository_id, operation_id) = (fixture_id(1), fixture_id(n))
$$;

CREATE FUNCTION fixture_event(n int, event_no int, revision_no bigint DEFAULT 7) RETURNS void LANGUAGE sql AS $$
    INSERT INTO ref_store_core_events(event_id, repository_id, revision, operation_id, outcome, payload)
    VALUES (fixture_id(event_no), fixture_id(1), revision_no, fixture_id(n), 'committed', '{"revision":7}')
$$;

CREATE FUNCTION fixture_stale_reject(n int, event_no int) RETURNS int LANGUAGE plpgsql AS $$
DECLARE
    wrapper public_operations;
    gate ref_store_core_gates;
    body text;
BEGIN
    SELECT w.* INTO STRICT wrapper FROM public_operations w
        JOIN private_attempts a ON (a.repository_id, a.public_id, a.slot) = (w.repository_id, w.public_id, w.current_slot)
        WHERE (a.repository_id, a.private_id) = (fixture_id(1), fixture_id(n)) AND w.state = 'pending';
    PERFORM 1 FROM fixture_a4_usage WHERE repository_id = fixture_id(1) FOR UPDATE;
    gate := lock_stale_gate(wrapper);
    body := format(
        '{"kind":"rejected","repository_id":"%s","revision":%s,"head_ref":%s,"mode":"metadata_only",'
        '"refs":[{"outcome":"not_applied","name":"refs/heads/main","reason":"old_oid_mismatch"}],'
        '"registrations":[],"rejection":{"code":"revision_mismatch","detail":"admitted base was superseded"}}',
        fixture_id(1), gate.revision, to_json(gate.head_ref));
    UPDATE ref_store_operations SET state = 'rejected', terminal_at = clock_timestamp(), terminal_result = body::jsonb
        WHERE (repository_id, operation_id) = (fixture_id(1), fixture_id(n));
    INSERT INTO ref_store_core_events(event_id, repository_id, revision, operation_id, outcome, payload)
    VALUES (fixture_id(event_no), fixture_id(1), gate.revision, fixture_id(n), 'rejected', body::jsonb);
    -- Charge::membership(0, 0, terminal_body_bytes) retains two body copies,
    -- two fixed row overheads and one receipt. The charge uses compact bytes.
    UPDATE fixture_a4_usage SET logical_bytes = logical_bytes + 2 * (256 + octet_length(body)), receipts = receipts + 1
        WHERE repository_id = fixture_id(1);
    RETURN octet_length(body);
END $$;

CREATE FUNCTION fixture_select_next(public_no int, private_no int) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM fixture_attempt(public_no, 1, private_no);
    UPDATE public_operations SET current_slot = 1 WHERE public_id = fixture_id(public_no);
    PERFORM fixture_serving_operation(private_no, repeat('d', 64));
END $$;

CREATE FUNCTION fixture_finish(public_no int, private_no int, event_no int, revision_no bigint DEFAULT 7,
                               public_event_no int DEFAULT NULL)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM fixture_core_commit(private_no);
    PERFORM fixture_event(private_no, event_no, revision_no);
    UPDATE public_operations SET state = 'committed', event_id = fixture_id(coalesce(public_event_no, event_no))
        WHERE public_id = fixture_id(public_no);
END $$;

CREATE FUNCTION fixture_assert(ok boolean, scenario text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF ok IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'fixture assertion failed: %', scenario;
    END IF;
END $$;

CREATE FUNCTION fixture_refuses(statement text, expected_state text, expected_constraint text DEFAULT NULL)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    failed_constraint text;
BEGIN
    BEGIN
        EXECUTE statement;
        SET CONSTRAINTS ALL IMMEDIATE;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS failed_constraint = CONSTRAINT_NAME;
        IF SQLSTATE <> expected_state OR (expected_constraint IS NOT NULL AND failed_constraint <> expected_constraint) THEN
            RAISE EXCEPTION 'fixture saw a different refusal';
        END IF;
        RETURN;
    END;
    RAISE EXCEPTION 'fixture expected a refusal';
END $$;

CREATE FUNCTION fixture_state() RETURNS jsonb LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_array(
        (SELECT jsonb_agg(v ORDER BY repository_id, public_id) FROM public_operations v),
        (SELECT jsonb_agg(v ORDER BY repository_id, public_id, slot) FROM private_attempts v),
        (SELECT jsonb_agg(v ORDER BY repository_id, issuer_id, lane) FROM ref_store_issuer_lanes v),
        (SELECT jsonb_agg(v ORDER BY repository_id, operation_id) FROM ref_store_operations v),
        (SELECT jsonb_agg(v ORDER BY repository_id, operation_id) FROM ref_store_serving_operations v),
        (SELECT jsonb_agg(v ORDER BY repository_id, operation_id) FROM ref_store_cancellations v),
        (SELECT jsonb_agg(v ORDER BY event_id) FROM ref_store_core_events v),
        (SELECT jsonb_agg(v ORDER BY repository_id) FROM fixture_a4_usage v),
        (SELECT jsonb_agg(v ORDER BY repository_id) FROM modeled_serving_scope v),
        (SELECT jsonb_agg(v ORDER BY repository_id) FROM ref_store_core_gates v),
        (SELECT jsonb_agg(v ORDER BY repository_id, ref_name) FROM ref_store_core_refs v)
    )
$$;

CREATE FUNCTION fixture_refuses_unchanged(statement text, expected_constraint text, expected_state text DEFAULT '23514')
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    before_state jsonb := fixture_state();
BEGIN
    PERFORM fixture_refuses(statement, expected_state, expected_constraint);
    PERFORM fixture_assert(fixture_state() = before_state, 'stale refusal leaves scratch state unchanged');
END $$;

DO $$
DECLARE
    repo constant uuid := fixture_id(1);
    issuer constant uuid := fixture_id(2);
    wire constant text := repeat('a', 64);
    request_mode constant text := 'atomic';
    backend constant text := repeat('d', 64);
    realm constant core_realm := ROW(repo, issuer, 'sha1', fixture_id(3), 1, 1)::core_realm;
    changed_realm constant core_realm := ROW(repo, issuer, 'sha1', fixture_id(3), 2, 1)::core_realm;
    incarnation constant uuid := fixture_id(4);
    retired_body_bytes int;
BEGIN
    PERFORM fixture_refuses('SELECT fixture_public(98)', '55000');
    PERFORM fixture_lock(20, 10);
    PERFORM fixture_assert(wrapper_lock_ids(repo, fixture_id(20), fixture_id(10)) = ARRAY[fixture_id(10), fixture_id(20)],
                           'normalized lock IDs put the smaller private ID first');
    PERFORM fixture_public(20);
    PERFORM fixture_refuses('SELECT fixture_attempt(20, 0, 20)', '23505');
    PERFORM fixture_attempt(20, 0, 10);
    PERFORM fixture_refuses('SELECT fixture_public(10)', '23505');
    PERFORM fixture_refuses('SELECT fixture_operation(10, repeat(''e'', 64))', '23514');
    PERFORM fixture_operation(10);
    PERFORM fixture_refuses_unchanged('SELECT fixture_bind(10, repeat(''e'', 64))', NULL, 'P0001');
    PERFORM fixture_refuses_unchanged('SELECT fixture_stale_reject(10, 110)', 'stale_serving_binding');
    PERFORM fixture_lock(20, 21);
    PERFORM fixture_refuses_unchanged('SELECT fixture_select_next(20, 21)', 'stale_serving_binding');
    PERFORM fixture_bind(10, repeat('b', 64));
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;

    PERFORM fixture_assert((SELECT route = 'wrapper' AND operation_id = fixture_id(20) AND state = 'pending' AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, wire, request_mode, backend, realm, incarnation)),
                           'exact public pending');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, repeat('b', 64), request_mode, backend, realm, incarnation)),
                           'core digest cannot replay wire');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL
                            FROM lookup_public(repo, fixture_id(20), fixture_id(3), wire, request_mode, backend, realm, incarnation)), 'issuer bound');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, wire, 'accepted_subset', backend, realm, incarnation)), 'request mode bound');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, wire, request_mode, repeat('e', 64), realm, incarnation)), 'backend bound');
    PERFORM fixture_assert((SELECT route = 'private' AND operation_id IS NULL AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(10), issuer, wire, request_mode, backend, realm, incarnation)),
                           'slot zero never reaches legacy lookup');
    PERFORM fixture_refuses('SELECT fixture_operation(20)', '23505');
    PERFORM fixture_refuses('SELECT fixture_tombstone(20)', '23505');
    PERFORM fixture_refuses('UPDATE private_attempts SET proof_digest = repeat(''e'', 64)', '55000');
    PERFORM fixture_refuses('DELETE FROM private_attempts', '55000');
    PERFORM fixture_refuses('UPDATE public_operations SET wire_digest = repeat(''e'', 64)', '23514');
    PERFORM fixture_refuses('SELECT fixture_core_commit(10)', '23514');

    PERFORM fixture_lock(30);
    PERFORM fixture_operation(30);
    INSERT INTO ref_store_serving_operations(repository_id, operation_id, issuer_id, producer_request_digest, plan_parent_digest)
    VALUES (repo, fixture_id(30), issuer, wire, repeat('b', 64));
    PERFORM fixture_core_commit(30);
    PERFORM fixture_event(30, 130);
    PERFORM fixture_tombstone(30);
    PERFORM fixture_assert((SELECT route = 'legacy_operation'
                            FROM lookup_public(repo, fixture_id(30), issuer, wire, request_mode, backend, realm, incarnation))
                           AND (SELECT state = 'committed' FROM ref_store_operations WHERE operation_id = fixture_id(30)),
                           'cancel after a legacy terminal preserves the replay route');
    PERFORM fixture_refuses('SELECT fixture_public(30)', '23505');
    PERFORM fixture_refuses('SELECT fixture_attempt(20, 1, 30)', '23505');

    PERFORM fixture_lock(40);
    PERFORM fixture_tombstone(40);
    PERFORM fixture_assert((SELECT route = 'legacy_tombstone' AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(40), issuer, wire, request_mode, backend, realm, incarnation)),
                           'cancel-before-register is only a fence');
    PERFORM fixture_refuses('SELECT fixture_public(40)', '23505');
    PERFORM fixture_refuses('SELECT fixture_attempt(20, 1, 40)', '23505');
    INSERT INTO ref_store_operations(repository_id, issuer_id, lane, sequence, operation_id, request_digest,
                                     state, terminal_result, terminal_at)
    VALUES (repo, issuer, 'fixture', 40, fixture_id(40), repeat('b', 64), 'cancelled',
            '{"state":"cancelled","reason":"cancel_before_register"}', clock_timestamp());
    PERFORM fixture_assert((SELECT route = 'legacy_operation'
                            FROM lookup_public(repo, fixture_id(40), issuer, wire, request_mode, backend, realm, incarnation))
                           AND (SELECT state = 'cancelled' FROM ref_store_operations WHERE operation_id = fixture_id(40)),
                           'registered legacy cancellation delegates to operation replay');

    PERFORM fixture_lock(50);
    PERFORM fixture_refuses('SELECT fixture_public(50)', '23503', 'current_attempt');

    -- Simulate a positively settled pre-effect rotation. The fixture does not
    -- determine whether a provider/transaction outcome qualifies for rotation.
    PERFORM fixture_lock(20, 21);
    PERFORM fixture_assert(wrapper_lock_ids(repo, fixture_id(20), fixture_id(10)) = ARRAY[fixture_id(10), fixture_id(20)],
                           'proposed ID already in set is deduplicated');
    PERFORM fixture_refuses('SELECT fixture_attempt(20, 0, 21)', '23505');
    PERFORM fixture_refuses('SELECT fixture_attempt(20, 2, 21)', '23514');
    PERFORM fixture_refuses_unchanged('SELECT fixture_stale_reject(10, 110)', 'stale_revision');
    UPDATE ref_store_core_gates SET revision = 7 WHERE repository_id = repo;

    UPDATE ref_store_core_gates SET authority_epoch = 2 WHERE repository_id = repo;
    PERFORM fixture_refuses_unchanged('SELECT fixture_stale_reject(10, 110)', 'stale_realm');
    PERFORM fixture_refuses_unchanged('SELECT fixture_select_next(20, 21)', 'stale_realm');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, wire, request_mode, backend, realm, incarnation)),
                           'current gate realm change fences lookup');
    UPDATE ref_store_core_gates SET authority_epoch = 1, history_incarnation = fixture_id(5) WHERE repository_id = repo;
    PERFORM fixture_refuses_unchanged('SELECT fixture_stale_reject(10, 110)', 'stale_realm');
    PERFORM fixture_refuses_unchanged('SELECT fixture_select_next(20, 21)', 'stale_realm');
    UPDATE ref_store_core_gates SET history_incarnation = fixture_id(3) WHERE repository_id = repo;

    UPDATE modeled_serving_scope SET restore_incarnation = fixture_id(5) WHERE repository_id = repo;
    PERFORM fixture_refuses_unchanged('SELECT fixture_stale_reject(10, 110)', 'stale_serving_scope');
    PERFORM fixture_refuses_unchanged('SELECT fixture_select_next(20, 21)', 'stale_serving_scope');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, wire, request_mode, backend, realm, incarnation)),
                           'current restore incarnation change fences lookup');
    UPDATE modeled_serving_scope SET restore_incarnation = incarnation, backend_identity = repeat('e', 64)
        WHERE repository_id = repo;
    PERFORM fixture_refuses_unchanged('SELECT fixture_stale_reject(10, 110)', 'stale_serving_scope');
    PERFORM fixture_refuses_unchanged('SELECT fixture_select_next(20, 21)', 'stale_serving_scope');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, wire, request_mode, backend, realm, incarnation)),
                           'current backend change fences lookup');
    UPDATE modeled_serving_scope SET backend_identity = backend WHERE repository_id = repo;

    -- 147 can store a different producer digest, but this wrapper must refuse
    -- it. A savepoint keeps the deliberately inconsistent admission local.
    BEGIN
        PERFORM fixture_lock(80, 81);
        PERFORM fixture_public(80);
        PERFORM fixture_attempt(80, 0, 81);
        PERFORM fixture_operation(81);
        PERFORM fixture_bind(81, repeat('b', 64), repeat('e', 64));
        PERFORM fixture_lock(80, 82);
        PERFORM fixture_refuses_unchanged('SELECT fixture_stale_reject(81, 181)', 'stale_serving_binding');
        PERFORM fixture_refuses_unchanged('SELECT fixture_select_next(80, 82)', 'stale_serving_binding');
        RAISE SQLSTATE 'P4201';
    EXCEPTION WHEN SQLSTATE 'P4201' THEN NULL;
    END;

    PERFORM fixture_refuses('SELECT fixture_select_next(20, 21)', '23514');
    PERFORM fixture_refuses($trial$DO $cancel$
        BEGIN
            PERFORM fixture_tombstone(10);
            PERFORM fixture_cancel(10, 'cancel_requested');
            PERFORM fixture_select_next(20, 21);
        END $cancel$; $trial$, '23514');
    PERFORM fixture_refuses('SELECT fixture_stale_reject(10, 110)', '23514');
    retired_body_bytes := fixture_stale_reject(10, 110);
    PERFORM fixture_select_next(20, 21);
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;
    PERFORM fixture_assert((SELECT current_slot = 1 AND state = 'pending' AND event_id IS NULL
                            FROM public_operations WHERE public_id = fixture_id(20))
                           AND (SELECT state = 'rejected' FROM ref_store_operations WHERE operation_id = fixture_id(10))
                           AND (SELECT outcome = 'rejected' AND revision = 7 AND operation_id = fixture_id(10)
                                FROM ref_store_core_events WHERE event_id = fixture_id(110))
                           AND (SELECT count(*) = 2 AND bool_and(producer_request_digest = wire AND plan_parent_digest =
                                    CASE operation_id WHEN fixture_id(10) THEN repeat('b', 64) ELSE repeat('d', 64) END)
                                FROM ref_store_serving_operations WHERE operation_id IN (fixture_id(10), fixture_id(21)))
                           AND NOT EXISTS (SELECT FROM ref_store_cancellations WHERE operation_id = fixture_id(10)),
                           'rotation preserves a rejected audit event and leaves public pending');
    PERFORM fixture_assert((SELECT registrations = 2 AND artifacts = 4 AND memberships = 1 AND receipts = 6
                                   AND logical_bytes = 4096 + 2 * (256 + retired_body_bytes)
                            FROM fixture_a4_usage WHERE repository_id = repo)
                           AND (SELECT revision = 7 AND head_ref = 'refs/heads/main' FROM ref_store_core_gates WHERE repository_id = repo)
                           AND (SELECT count(*) = 1 AND bool_and(oid = repeat('a', 40) AND revision = 6 AND ref_name = 'refs/heads/main')
                                FROM ref_store_core_refs WHERE repository_id = repo),
                           'rejection charges its retained terminal and event only, leaving gate and refs intact');
    PERFORM fixture_refuses('SELECT fixture_event(10, 111)', '55000');
    PERFORM fixture_refuses('SELECT fixture_core_commit(10)', '55000');
    PERFORM fixture_refuses('SELECT fixture_tombstone(10)', '55000');
    PERFORM fixture_assert((SELECT route = 'private' AND operation_id IS NULL AND state IS NULL
                            FROM lookup_public(repo, fixture_id(21), issuer, wire, request_mode, backend, realm, incarnation)),
                           'slot one never reaches legacy lookup');

    PERFORM fixture_lock(60, 61);
    PERFORM fixture_public(60);
    PERFORM fixture_attempt(60, 0, 61);
    PERFORM fixture_serving_operation(61);
    PERFORM fixture_tombstone(61);
    PERFORM fixture_cancel(61, 'cancel_requested');
    PERFORM fixture_refuses('SELECT fixture_event(61, 161)', '23514');
    PERFORM fixture_refuses('UPDATE public_operations SET state = ''cancelled'', request_mode = ''accepted_subset'' WHERE public_id = fixture_id(60)', '23514');
    PERFORM fixture_refuses('UPDATE public_operations SET state = ''cancelled'', backend_identity = repeat(''e'', 64) WHERE public_id = fixture_id(60)', '23514');
    UPDATE public_operations SET state = 'cancelled' WHERE public_id = fixture_id(60);

    PERFORM fixture_lock(20);
    PERFORM fixture_refuses('SELECT fixture_finish(20, 21, 121, 8)', '23514');
    PERFORM fixture_refuses('SELECT fixture_finish(20, 21, 121, 7, 110)', '23514');
    PERFORM fixture_finish(20, 21, 121);
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;

    PERFORM fixture_assert((SELECT route = 'wrapper' AND operation_id = fixture_id(60) AND state = 'cancelled' AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(60), issuer, wire, request_mode, backend, realm, incarnation))
                           AND NOT EXISTS (SELECT FROM ref_store_core_events WHERE operation_id = fixture_id(61)),
                           'public cancel has no event');
    PERFORM fixture_refuses('SELECT fixture_event(61, 161)', '55000');
    PERFORM fixture_assert((SELECT route = 'wrapper' AND operation_id = fixture_id(20) AND state = 'committed' AND event_id = fixture_id(121)
                            FROM lookup_public(repo, fixture_id(20), issuer, wire, request_mode, backend, realm, incarnation))
                           AND (SELECT count(*) = 2 FROM ref_store_core_events WHERE operation_id IN (fixture_id(10), fixture_id(21)))
                           AND (SELECT operation_id = fixture_id(21) AND outcome = 'committed' FROM ref_store_core_events WHERE event_id = fixture_id(121)),
                           'public terminal links only the winner and retains the retired audit event');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, wire, request_mode, backend, changed_realm, incarnation)),
                           'terminal replay requires the stored realm');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, wire, request_mode, backend, realm, fixture_id(5))),
                           'terminal replay requires the stored restore incarnation');
    PERFORM fixture_refuses('SELECT fixture_event(21, 122)', '55000');
    PERFORM fixture_refuses('UPDATE public_operations SET state = ''cancelled'', event_id = NULL WHERE public_id = fixture_id(20)', '23514');
    PERFORM fixture_refuses('DELETE FROM ref_store_core_events WHERE event_id = fixture_id(121)', '55000');

    PERFORM fixture_lock(70, 71);
    PERFORM fixture_public(70);
    PERFORM fixture_attempt(70, 0, 71);
    PERFORM fixture_serving_operation(71);
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;
    PERFORM fixture_refuses('UPDATE public_operations SET state = ''committed'', event_id = fixture_id(130) WHERE public_id = fixture_id(70)', '23514');
    PERFORM fixture_refuses('UPDATE public_operations SET state = ''committed'', event_id = fixture_id(121) WHERE public_id = fixture_id(70)', '23505');
END $$;

SET CONSTRAINTS ALL IMMEDIATE;
ROLLBACK;
