-- Real PG17 qualification for the three-attempt persistence contract.
-- Apply this fixture with psql -X -v rootyard_owned_disposable_pg17=on -f <this-file>.
-- Set issue42_candidate=off to show the original two-attempt schema rejects slot two.
\set ON_ERROR_STOP on
\if :{?rootyard_owned_disposable_pg17}
\else
    \set rootyard_owned_disposable_pg17 off
\endif
\if :rootyard_owned_disposable_pg17
\else
    DO $$ BEGIN RAISE EXCEPTION 'owned disposable PostgreSQL 17 is required'; END $$;
\endif
\if :{?issue42_candidate}
\else
    \set issue42_candidate on
\endif

BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL search_path = public, pg_catalog, pg_temp;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '2s';

DO $$
BEGIN
    IF current_setting('server_version_num')::int / 10000 <> 17
       OR (SELECT max(version) FROM schema_migrations) IS DISTINCT FROM 151
       OR to_regclass('public.ref_store_private_attempts') IS NOT NULL THEN
        RAISE EXCEPTION 'fixture requires PostgreSQL 17 with the registered M151 schema';
    END IF;
END $$;

\if :issue42_candidate
    \ir ref_store_three_attempt_migration_152.sql
\else
    \ir ref_store_public_attempts_migration_152.sql
\endif

-- Scratch helpers create M138/M147 evidence for the exact operation and wire.
CREATE FUNCTION pg_temp.reserve_attempt(
    repo uuid, public_op uuid, generation smallint, private_op uuid,
    issuer uuid, lane_name text, wire text, base bigint
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    parent text := encode(sha256(convert_to(private_op::text, 'UTF8')), 'hex');
BEGIN
    PERFORM rootyard_ref_store_lock_public_operation(repo, public_op, private_op);
    INSERT INTO ref_store_private_attempts
        (repository_id, public_id, slot, private_id, plan_digest, proof_digest, base_revision)
    VALUES (repo, public_op, generation, private_op, parent, repeat('d', 64), base);
    INSERT INTO ref_store_operations
        (repository_id, issuer_id, lane, sequence, operation_id, request_digest, state)
    VALUES (repo, issuer, lane_name, generation + 1, private_op, parent, 'pending');
    INSERT INTO ref_store_serving_operations
        (repository_id, operation_id, issuer_id, producer_request_digest, plan_parent_digest)
    VALUES (repo, private_op, issuer, wire, parent);
END $$;

CREATE FUNCTION pg_temp.record_terminal(
    repo uuid, private_op uuid, terminal_event uuid, revision bigint, terminal_state text, rejection_code text
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    terminal jsonb := jsonb_build_object(
        'kind', terminal_state, 'repository_id', repo, 'revision', revision,
        'head_ref', 'refs/heads/main', 'mode', 'metadata_only', 'refs', '[]'::jsonb, 'registrations', '[]'::jsonb,
        'rejection', CASE WHEN rejection_code IS NOT NULL
            THEN jsonb_build_object('code', rejection_code, 'detail', 'test terminal') END
    );
BEGIN
    UPDATE ref_store_operations SET state = terminal_state, terminal_result = terminal, terminal_at = clock_timestamp()
    WHERE (repository_id, operation_id) = (repo, private_op);
    INSERT INTO ref_store_core_events(event_id, repository_id, revision, operation_id, outcome, payload)
    VALUES (terminal_event, repo, revision, private_op, terminal_state, terminal);
END $$;

CREATE FUNCTION pg_temp.rotate(
    repo uuid, public_op uuid, predecessor smallint, retired_event uuid, next_op uuid,
    issuer uuid, lane_name text, wire text, base bigint
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM rootyard_ref_store_lock_public_operation(repo, public_op, next_op);
    IF to_regclass('public.ref_store_attempt_retirements') IS NOT NULL THEN
        INSERT INTO ref_store_attempt_retirements(repository_id, public_id, slot, event_id)
        VALUES (repo, public_op, predecessor, retired_event);
    END IF;
    PERFORM pg_temp.reserve_attempt(repo, public_op, (predecessor + 1)::smallint, next_op, issuer, lane_name, wire, base);
    IF to_regclass('public.ref_store_attempt_retirements') IS NULL THEN
        UPDATE ref_store_public_operations SET current_slot = predecessor + 1, retired_event_id = retired_event
        WHERE (repository_id, public_id) = (repo, public_op);
    ELSE
        UPDATE ref_store_public_operations SET current_slot = predecessor + 1
        WHERE (repository_id, public_id) = (repo, public_op);
    END IF;
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;
END $$;

DO $$
DECLARE
    repo uuid := gen_random_uuid();
    issuer uuid := gen_random_uuid();
    history uuid := gen_random_uuid();
    backend constant text := repeat('a', 64);
    wire constant text := repeat('c', 64);
    lane_name constant text := 'three-attempt-fixture';
    public_op uuid := gen_random_uuid();
    first_op uuid := gen_random_uuid();
    second_op uuid := gen_random_uuid();
    third_op uuid := gen_random_uuid();
    foreign_op uuid := gen_random_uuid();
    first_event uuid := gen_random_uuid();
    second_event uuid := gen_random_uuid();
    third_event uuid := gen_random_uuid();
    foreign_event uuid := gen_random_uuid();
BEGIN
    INSERT INTO users(id, username) VALUES (issuer, 'issue42-three-attempt-fixture');
    INSERT INTO repositories(id, owner_id, name, state, storage_backend, object_format)
    VALUES (repo, issuer, 'issue42-three-attempt-fixture', 'provisioning', 'pg_refstore', 'sha1');
    INSERT INTO ref_store_core_gates(repository_id, tenant_id, object_format, history_incarnation,
                                     authority_epoch, group_epoch, head_ref, revision)
    VALUES (repo, issuer, 'sha1', history, 1, 1, 'refs/heads/main', 6);
    INSERT INTO ref_store_core_protocol_repos(repository_id, tenant_id, object_format, history_incarnation,
                                             authority_epoch, group_epoch, decision_required)
    VALUES (repo, issuer, 'sha1', history, 1, 1, true);
    INSERT INTO ref_store_serving_repositories(repository_id, owner_id, name, object_format, history_incarnation,
                                                authority_epoch, group_epoch, backend_identity, state)
    VALUES (repo, issuer, 'issue42-three-attempt-fixture', 'sha1', history, 1, 1, backend, 'pending');
    UPDATE ref_store_serving_repositories SET state = 'ready' WHERE repository_id = repo;
    UPDATE repositories SET state = 'ready' WHERE id = repo;
    INSERT INTO ref_store_issuer_lanes(repository_id, issuer_id, lane, last_reserved_sequence)
    VALUES (repo, issuer, lane_name, 3), (repo, issuer, 'foreign-event', 1), (repo, issuer, 'other-attempt-lane', 3);

    PERFORM rootyard_ref_store_lock_public_operation(repo, public_op, first_op);
    INSERT INTO ref_store_public_operations(repository_id, public_id, admission_owner_id, issuer_id, wire_digest,
                                            request_mode, backend_identity, object_format, history_incarnation,
                                            authority_epoch, group_epoch, restore_incarnation)
    SELECT repo, public_op, issuer, issuer, wire, 'atomic', backend, 'sha1', history, 1, 1, incarnation
    FROM cluster_authority WHERE singleton;
    PERFORM pg_temp.reserve_attempt(repo, public_op, 0::smallint, first_op, issuer, lane_name, wire, 6);
    SET CONSTRAINTS ALL IMMEDIATE;
    SET CONSTRAINTS ALL DEFERRED;

    UPDATE ref_store_core_gates SET revision = 7 WHERE repository_id = repo;
    PERFORM pg_temp.record_terminal(repo, first_op, first_event, 7, 'rejected', 'revision_mismatch');
    IF to_regclass('public.ref_store_attempt_retirements') IS NOT NULL THEN
        BEGIN
            PERFORM pg_temp.reserve_attempt(repo, public_op, 2::smallint, third_op, issuer, lane_name, wire, 7);
            RAISE EXCEPTION 'wrapper skipped its second attempt';
        EXCEPTION WHEN check_violation THEN
            IF SQLERRM <> 'private attempt must occupy the next slot' THEN RAISE; END IF;
        END;
        BEGIN
            INSERT INTO ref_store_attempt_retirements(repository_id, public_id, slot, event_id)
            VALUES (repo, public_op, 0, first_event);
            SET CONSTRAINTS ALL IMMEDIATE;
            RAISE EXCEPTION 'retirement with no successor was accepted';
        EXCEPTION WHEN check_violation THEN
            IF SQLERRM <> 'public operation and private attempt evidence disagree' THEN RAISE; END IF;
        END;
    END IF;

    PERFORM pg_temp.rotate(repo, public_op, 0::smallint, first_event, second_op, issuer, lane_name, wire, 7);

    UPDATE ref_store_core_gates SET revision = 8 WHERE repository_id = repo;
    IF to_regclass('public.ref_store_attempt_retirements') IS NOT NULL THEN
        -- A durable event for another operation does not retire the current pending operation.
        INSERT INTO ref_store_operations
            (repository_id, issuer_id, lane, sequence, operation_id, request_digest, state)
        VALUES (repo, issuer, 'foreign-event', 1, foreign_op, wire, 'pending');
        PERFORM pg_temp.record_terminal(repo, foreign_op, foreign_event, 8, 'rejected', 'revision_mismatch');

        BEGIN
            PERFORM pg_temp.reserve_attempt(repo, public_op, 0::smallint, third_op, issuer, lane_name, wire, 8);
            RAISE EXCEPTION 'attempt sequence permitted moving backward';
        EXCEPTION WHEN check_violation THEN
            IF SQLERRM <> 'private attempt must occupy the next slot' THEN RAISE; END IF;
        END;
        BEGIN
            UPDATE ref_store_public_operations SET current_slot = 2 WHERE (repository_id, public_id) = (repo, public_op);
            RAISE EXCEPTION 'wrapper advanced without the next attempt and its retirement';
        EXCEPTION WHEN check_violation THEN
            IF SQLERRM <> 'rotation requires the current retirement and next attempt' THEN RAISE; END IF;
        END;
        BEGIN
            PERFORM pg_temp.rotate(repo, public_op, 1::smallint, foreign_event, third_op, issuer, lane_name, wire, 8);
            RAISE EXCEPTION 'pending attempt took a foreign terminal';
        EXCEPTION WHEN check_violation THEN
            IF SQLERRM <> 'retirement requires the exact current revision mismatch' THEN RAISE; END IF;
        END;
        BEGIN
            PERFORM pg_temp.rotate(repo, public_op, 1::smallint, second_event, third_op, issuer, lane_name, wire, 8);
            RAISE EXCEPTION 'unknown event was accepted as a terminal';
        EXCEPTION WHEN check_violation THEN
            IF SQLERRM <> 'retirement requires the exact current revision mismatch' THEN RAISE; END IF;
        END;
        BEGIN
            PERFORM pg_temp.record_terminal(repo, second_op, second_event, 9, 'rejected', 'old_oid_mismatch');
            UPDATE ref_store_core_gates SET revision = 9 WHERE repository_id = repo;
            PERFORM pg_temp.rotate(repo, public_op, 1::smallint, second_event, third_op, issuer, lane_name, wire, 9);
            RAISE EXCEPTION 'same-ref rejection admitted a retry';
        EXCEPTION WHEN check_violation THEN
            IF SQLERRM <> 'retirement requires the exact current revision mismatch' THEN RAISE; END IF;
        END;
    END IF;

    UPDATE ref_store_core_gates SET revision = 9 WHERE repository_id = repo;
    PERFORM pg_temp.record_terminal(repo, second_op, second_event, 9, 'rejected', 'revision_mismatch');
    IF to_regclass('public.ref_store_attempt_retirements') IS NOT NULL THEN
        BEGIN
            PERFORM pg_temp.rotate(repo, public_op, 1::smallint, second_event, third_op, issuer, 'other-attempt-lane', wire, 9);
            RAISE EXCEPTION 'successor switched issuer lane';
        EXCEPTION WHEN check_violation THEN
            IF SQLERRM <> 'public operation and private attempt evidence disagree' THEN RAISE; END IF;
        END;
    END IF;

    PERFORM pg_temp.rotate(repo, public_op, 1::smallint, second_event, third_op, issuer, lane_name, wire, 9);

    IF NOT EXISTS (SELECT FROM ref_store_public_operations WHERE (repository_id, public_id) = (repo, public_op)
        AND current_slot = 2 AND state = 'pending' AND event_id IS NULL)
       OR (SELECT array_agg(event_id ORDER BY slot) FROM ref_store_attempt_retirements
           WHERE (repository_id, public_id) = (repo, public_op)) IS DISTINCT FROM ARRAY[first_event, second_event] THEN
        RAISE EXCEPTION 'pending third attempt did not retain the two exact earlier terminals';
    END IF;

    BEGIN
        UPDATE ref_store_attempt_retirements SET event_id = second_event
        WHERE (repository_id, public_id, slot) = (repo, public_op, 0);
        RAISE EXCEPTION 'previous retirement was replaced';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        IF SQLERRM <> 'public operation history is retained while its repository exists' THEN RAISE; END IF;
    END;

    UPDATE ref_store_core_gates SET revision = 10 WHERE repository_id = repo;
    PERFORM pg_temp.record_terminal(repo, third_op, third_event, 10, 'committed', NULL);
    UPDATE ref_store_public_operations SET state = 'committed', event_id = third_event
    WHERE (repository_id, public_id) = (repo, public_op);
    SET CONSTRAINTS ALL IMMEDIATE;
    IF NOT EXISTS (SELECT FROM ref_store_public_operations WHERE (repository_id, public_id) = (repo, public_op)
        AND current_slot = 2 AND state = 'committed' AND event_id = third_event)
       OR (SELECT array_agg(event_id ORDER BY slot) FROM ref_store_attempt_retirements
           WHERE (repository_id, public_id) = (repo, public_op)) IS DISTINCT FROM ARRAY[first_event, second_event] THEN
        RAISE EXCEPTION 'third attempt terminal changed the prior retirements';
    END IF;
END $$;

ROLLBACK;

DO $$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) IS DISTINCT FROM 151
       OR to_regclass('public.ref_store_public_operations') IS NOT NULL
       OR to_regclass('public.ref_store_attempt_retirements') IS NOT NULL THEN
        RAISE EXCEPTION 'three-attempt fixture did not roll back to M151';
    END IF;
END $$;

\echo issue42_three_attempt_storage_passed
