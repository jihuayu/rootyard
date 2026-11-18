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

CREATE FUNCTION fixture_lock(public_no int, proposed_no int DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM lock_wrapper(fixture_id(1), fixture_id(public_no), fixture_id(proposed_no));
    PERFORM 1 FROM ref_store_issuer_lanes WHERE repository_id = fixture_id(1) AND issuer_id = fixture_id(2)
        AND lane = 'fixture' FOR UPDATE;
END $$;

CREATE FUNCTION fixture_public(n int) RETURNS void LANGUAGE sql AS $$
    INSERT INTO public_operations(repository_id, public_id, issuer_id, wire_digest, realm_id, restore_incarnation)
    VALUES (fixture_id(1), fixture_id(n), fixture_id(2), repeat('a', 64), fixture_id(3), fixture_id(4))
$$;

CREATE FUNCTION fixture_attempt(public_no int, slot_no int, private_no int) RETURNS void LANGUAGE sql AS $$
    INSERT INTO private_attempts VALUES (fixture_id(1), fixture_id(public_no), slot_no, fixture_id(private_no),
                                        repeat('b', 64), repeat('c', 64))
$$;

CREATE FUNCTION fixture_operation(n int, digest text DEFAULT repeat('b', 64)) RETURNS void LANGUAGE sql AS $$
    INSERT INTO ref_store_operations(repository_id, issuer_id, lane, sequence, operation_id, request_digest, state)
    VALUES (fixture_id(1), fixture_id(2), 'fixture', n, fixture_id(n), digest, 'pending')
$$;

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

CREATE FUNCTION fixture_finish(public_no int, private_no int, event_no int, revision_no bigint DEFAULT 7)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM fixture_core_commit(private_no);
    PERFORM fixture_event(private_no, event_no, revision_no);
    UPDATE public_operations SET state = 'committed', event_id = fixture_id(event_no) WHERE public_id = fixture_id(public_no);
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

DO $$
DECLARE
    repo constant uuid := fixture_id(1);
    issuer constant uuid := fixture_id(2);
    wire constant text := repeat('a', 64);
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
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;

    PERFORM fixture_assert((SELECT route = 'wrapper' AND operation_id = fixture_id(20) AND state = 'pending' AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, wire)), 'exact public pending');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL
                            FROM lookup_public(repo, fixture_id(20), issuer, repeat('b', 64))), 'core digest cannot replay wire');
    PERFORM fixture_assert((SELECT route = 'conflict' AND operation_id IS NULL AND state IS NULL
                            FROM lookup_public(repo, fixture_id(20), fixture_id(3), wire)), 'issuer bound');
    PERFORM fixture_assert((SELECT route = 'private' AND operation_id IS NULL AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(10), issuer, wire)), 'slot zero never reaches legacy lookup');
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
    PERFORM fixture_assert((SELECT route = 'legacy_operation' FROM lookup_public(repo, fixture_id(30), issuer, wire))
                           AND (SELECT state = 'committed' FROM ref_store_operations WHERE operation_id = fixture_id(30)),
                           'cancel after a legacy terminal preserves the replay route');
    PERFORM fixture_refuses('SELECT fixture_public(30)', '23505');
    PERFORM fixture_refuses('SELECT fixture_attempt(20, 1, 30)', '23505');

    PERFORM fixture_lock(40);
    PERFORM fixture_tombstone(40);
    PERFORM fixture_assert((SELECT route = 'legacy_tombstone' AND state IS NULL AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(40), issuer, wire)), 'cancel-before-register is only a fence');
    PERFORM fixture_refuses('SELECT fixture_public(40)', '23505');
    PERFORM fixture_refuses('SELECT fixture_attempt(20, 1, 40)', '23505');
    INSERT INTO ref_store_operations(repository_id, issuer_id, lane, sequence, operation_id, request_digest,
                                     state, terminal_result, terminal_at)
    VALUES (repo, issuer, 'fixture', 40, fixture_id(40), repeat('b', 64), 'cancelled',
            '{"state":"cancelled","reason":"cancel_before_register"}', clock_timestamp());
    PERFORM fixture_assert((SELECT route = 'legacy_operation' FROM lookup_public(repo, fixture_id(40), issuer, wire))
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
    PERFORM fixture_tombstone(10);
    PERFORM fixture_cancel(10, 'cancel_requested');
    PERFORM fixture_attempt(20, 1, 21);
    UPDATE public_operations SET current_slot = 1 WHERE public_id = fixture_id(20);
    PERFORM fixture_operation(21);
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;
    PERFORM fixture_refuses('SELECT fixture_event(10, 110)', '55000');
    PERFORM fixture_refuses('SELECT fixture_core_commit(10)', '55000');
    PERFORM fixture_assert((SELECT route = 'private' AND operation_id IS NULL AND state IS NULL
                            FROM lookup_public(repo, fixture_id(21), issuer, wire)), 'slot one never reaches legacy lookup');

    PERFORM fixture_lock(60, 61);
    PERFORM fixture_public(60);
    PERFORM fixture_attempt(60, 0, 61);
    PERFORM fixture_operation(61);
    PERFORM fixture_tombstone(61);
    PERFORM fixture_cancel(61, 'cancel_requested');
    PERFORM fixture_refuses('SELECT fixture_event(61, 161)', '23514');
    UPDATE public_operations SET state = 'cancelled' WHERE public_id = fixture_id(60);

    PERFORM fixture_lock(20);
    PERFORM fixture_refuses('SELECT fixture_finish(20, 21, 121, 8)', '23514');
    PERFORM fixture_finish(20, 21, 121);
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;

    PERFORM fixture_assert((SELECT route = 'wrapper' AND operation_id = fixture_id(60) AND state = 'cancelled' AND event_id IS NULL
                            FROM lookup_public(repo, fixture_id(60), issuer, wire)), 'public cancel has no event');
    PERFORM fixture_refuses('SELECT fixture_event(61, 161)', '55000');
    PERFORM fixture_assert((SELECT route = 'wrapper' AND operation_id = fixture_id(20) AND state = 'committed' AND event_id = fixture_id(121)
                            FROM lookup_public(repo, fixture_id(20), issuer, wire))
                           AND (SELECT count(*) = 1 FROM ref_store_core_events WHERE operation_id IN (fixture_id(10), fixture_id(21))),
                           'public terminal links the single private winner');
    PERFORM fixture_refuses('SELECT fixture_event(21, 122)', '55000');
    PERFORM fixture_refuses('UPDATE public_operations SET state = ''cancelled'', event_id = NULL WHERE public_id = fixture_id(20)', '23514');
    PERFORM fixture_refuses('DELETE FROM ref_store_core_events WHERE event_id = fixture_id(121)', '55000');

    PERFORM fixture_lock(70, 71);
    PERFORM fixture_public(70);
    PERFORM fixture_attempt(70, 0, 71);
    PERFORM fixture_operation(71);
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;
    PERFORM fixture_refuses('UPDATE public_operations SET state = ''committed'', event_id = fixture_id(130) WHERE public_id = fixture_id(70)', '23514');
    PERFORM fixture_refuses('UPDATE public_operations SET state = ''committed'', event_id = fixture_id(121) WHERE public_id = fixture_id(70)', '23505');
END $$;

SET CONSTRAINTS ALL IMMEDIATE;
ROLLBACK;
