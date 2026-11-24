-- Exercise the candidate M152 SQL from b2cdb23b against disposable PostgreSQL 17
-- loaded with the current application's registered migrations through M151:
-- psql -X -v rootyard_owned_disposable_pg17=on -f tests/fixtures/ref_store_schema152_storage.sql
-- The migration, rows and test role all roll back to the original M151 schema.
--
-- Legacy reserve, begin, cancel and lock-protected replay take the M138
-- repository/operation advisory key before the issuer lane. In a catalog
-- with M152 they check public/private claims in a separate READ COMMITTED
-- statement after acquiring that key. A matching claim refuses the legacy path
-- before it reads or writes legacy operation state.
-- M152 admission holds the sorted keys for the wrapper and its existing and
-- proposed attempts before the restore fence and issuer lane. It writes the
-- exact private M138 record and M147 wire/parent binding under those same
-- locks, which stay held through commit.
\set ON_ERROR_STOP on
\if :{?rootyard_owned_disposable_pg17}
\else
    \set rootyard_owned_disposable_pg17 off
\endif
\if :rootyard_owned_disposable_pg17
\else
    DO $$ BEGIN RAISE EXCEPTION 'owned disposable PostgreSQL 17 is required'; END $$;
\endif

BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL search_path = public, pg_catalog, pg_temp;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '2s';
SET LOCAL client_min_messages = warning;

DO $$
DECLARE
    repo uuid := gen_random_uuid();
    issuer uuid := gen_random_uuid();
    zero_id constant uuid := '00000000-0000-0000-0000-000000000000';
    digest constant text := repeat('f', 64);
BEGIN
    IF current_setting('server_version_num')::int / 10000 <> 17
       OR (SELECT max(version) FROM schema_migrations) IS DISTINCT FROM 151
       OR to_regclass('public.ref_store_private_attempts') IS NOT NULL THEN
        RAISE EXCEPTION 'fixture requires PostgreSQL 17 with the registered M151 schema';
    END IF;
    INSERT INTO users(id, username) VALUES (issuer, 'issue42-legacy-zero-probe');
    INSERT INTO repositories(id, owner_id, name, state, storage_backend, object_format)
    VALUES (repo, issuer, 'issue42-legacy-zero-probe', 'ready', 'gitfs', 'sha1');
    INSERT INTO ref_store_issuer_lanes(repository_id, issuer_id, lane, last_reserved_sequence)
    VALUES (repo, issuer, 'legacy-zero', 1);
    INSERT INTO ref_store_cancellations(repository_id, issuer_id, lane, sequence, operation_id, request_digest)
    VALUES (repo, issuer, 'legacy-zero', 1, zero_id, digest);
    INSERT INTO ref_store_operations(repository_id, issuer_id, lane, sequence, operation_id, request_digest,
                                     state, terminal_result, terminal_at)
    VALUES (repo, issuer, 'legacy-zero', 1, zero_id, digest, 'cancelled',
            '{"state":"cancelled","reason":"cancel_requested"}'::jsonb, clock_timestamp());
END $$;

-- Compare all columns of both historical rows, including their timestamps.
CREATE TEMP TABLE issue42_legacy_snapshot ON COMMIT DROP AS
SELECT o.repository_id, o.operation_id, to_jsonb(o) AS operation, to_jsonb(c) AS cancellation
FROM ref_store_operations o
JOIN ref_store_cancellations c USING (repository_id, operation_id)
JOIN repositories r ON r.id = o.repository_id
WHERE r.name = 'issue42-legacy-zero-probe' AND o.lane = 'legacy-zero';

\ir ref_store_public_attempts_migration_152.sql

DO $$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) IS DISTINCT FROM 152
       OR (SELECT count(*) FROM issue42_legacy_snapshot) <> 1
       OR NOT EXISTS (
           SELECT FROM issue42_legacy_snapshot s
           JOIN ref_store_operations o USING (repository_id, operation_id)
           JOIN ref_store_cancellations c USING (repository_id, operation_id)
           WHERE o.operation_id = '00000000-0000-0000-0000-000000000000'::uuid
             AND to_jsonb(o) = s.operation AND to_jsonb(c) = s.cancellation
       ) THEN
        RAISE EXCEPTION 'candidate migration changed the historical M138 zero-ID evidence';
    END IF;
END $$;

CREATE ROLE issue42_legacy_cancel_probe NOLOGIN;
GRANT USAGE ON SCHEMA public TO issue42_legacy_cancel_probe;
GRANT INSERT ON ref_store_cancellations TO issue42_legacy_cancel_probe;

DO $$
DECLARE
    repo uuid := gen_random_uuid();
    issuer uuid := gen_random_uuid();
    history uuid := gen_random_uuid();
    backend constant text := repeat('a', 64);
    parent_digest constant text := repeat('b', 64);
    wire_digest constant text := repeat('c', 64);
    proof_digest constant text := repeat('d', 64);
    public_op uuid;
    private_op uuid;
    next_op uuid;
    audit_event uuid;
    scope_revision bigint;
    scenario text;
    winner text;
    receipt jsonb;
    before_operation jsonb;
    before_event jsonb;
    before_wrapper jsonb;
    wrong_key text;
    failed_constraint text;
    zero_id constant uuid := '00000000-0000-0000-0000-000000000000';
    legacy_id uuid := gen_random_uuid();
    invalid_public uuid := gen_random_uuid();
    invalid_id uuid;
BEGIN
    INSERT INTO users(id, username) VALUES (issuer, 'issue42-cancel-probe');
    INSERT INTO repositories(id, owner_id, name, state, storage_backend, object_format)
    VALUES (repo, issuer, 'issue42-cancel-probe', 'provisioning', 'pg_refstore', 'sha1');
    INSERT INTO ref_store_core_gates(repository_id, tenant_id, object_format, history_incarnation,
                                     authority_epoch, group_epoch, head_ref, revision)
    VALUES (repo, issuer, 'sha1', history, 1, 1, 'refs/heads/main', 6);
    INSERT INTO ref_store_core_protocol_repos(repository_id, tenant_id, object_format, history_incarnation,
                                              authority_epoch, group_epoch, decision_required)
    VALUES (repo, issuer, 'sha1', history, 1, 1, true);
    INSERT INTO ref_store_serving_repositories(repository_id, owner_id, name, object_format, history_incarnation,
                                                authority_epoch, group_epoch, backend_identity, state)
    VALUES (repo, issuer, 'issue42-cancel-probe', 'sha1', history, 1, 1, backend, 'pending');
    UPDATE ref_store_serving_repositories SET state = 'ready' WHERE repository_id = repo;
    UPDATE repositories SET state = 'ready' WHERE id = repo;

    -- A nonzero legacy claim must still block a new public wrapper.
    INSERT INTO ref_store_issuer_lanes(repository_id, issuer_id, lane, last_reserved_sequence)
    VALUES (repo, issuer, 'legacy-existing', 1);
    INSERT INTO ref_store_operations(repository_id, issuer_id, lane, sequence, operation_id, request_digest, state)
    VALUES (repo, issuer, 'legacy-existing', 1, legacy_id, parent_digest, 'pending');

    FOREACH invalid_id IN ARRAY ARRAY[zero_id, legacy_id] LOOP
        BEGIN
            PERFORM rootyard_ref_store_lock_public_operation(repo, invalid_id);
            INSERT INTO ref_store_public_operations(repository_id, public_id, admission_owner_id, issuer_id, wire_digest,
                                                    request_mode, backend_identity, object_format, history_incarnation,
                                                    authority_epoch, group_epoch, restore_incarnation)
            SELECT repo, invalid_id, issuer, issuer, wire_digest, 'atomic', backend, 'sha1', history, 1, 1, incarnation
            FROM public.cluster_authority WHERE singleton;
            RAISE EXCEPTION 'invalid public identifier was accepted';
        EXCEPTION WHEN check_violation THEN
            GET STACKED DIAGNOSTICS failed_constraint = CONSTRAINT_NAME;
            IF invalid_id <> zero_id
               OR failed_constraint IS DISTINCT FROM 'ref_store_public_operations_public_id_check' THEN RAISE; END IF;
        WHEN unique_violation THEN
            IF invalid_id <> legacy_id THEN RAISE; END IF;
        END;
    END LOOP;

    BEGIN
        PERFORM rootyard_ref_store_lock_public_operation(repo, invalid_public, zero_id);
        INSERT INTO ref_store_public_operations(repository_id, public_id, admission_owner_id, issuer_id, wire_digest,
                                                request_mode, backend_identity, object_format, history_incarnation,
                                                authority_epoch, group_epoch, restore_incarnation)
        SELECT repo, invalid_public, issuer, issuer, wire_digest, 'atomic', backend, 'sha1', history, 1, 1, incarnation
        FROM public.cluster_authority WHERE singleton;
        INSERT INTO ref_store_private_attempts VALUES (repo, invalid_public, 0, zero_id, parent_digest, proof_digest, 6);
        RAISE EXCEPTION 'zero private identifier was accepted';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS failed_constraint = CONSTRAINT_NAME;
        IF failed_constraint IS DISTINCT FROM 'ref_store_private_attempts_private_id_check' THEN RAISE; END IF;
    END;

    FOREACH scenario IN ARRAY ARRAY['committed', 'rejected', 'retired', 'cancelled', 'pending'] LOOP
        SELECT ids[1], ids[2], ids[3] INTO public_op, private_op, next_op
        FROM (SELECT array_agg(id ORDER BY id) AS ids FROM (VALUES (gen_random_uuid()), (gen_random_uuid()), (gen_random_uuid())) keys(id)) s;
        audit_event := gen_random_uuid();
        PERFORM rootyard_ref_store_lock_public_operation(repo, public_op, private_op);
        SELECT revision INTO STRICT scope_revision FROM ref_store_core_gates WHERE repository_id = repo;
        INSERT INTO ref_store_issuer_lanes(repository_id, issuer_id, lane, last_reserved_sequence)
        VALUES (repo, issuer, scenario, 2);
        INSERT INTO ref_store_public_operations(repository_id, public_id, admission_owner_id, issuer_id, wire_digest,
                                                request_mode, backend_identity, object_format, history_incarnation,
                                                authority_epoch, group_epoch, restore_incarnation)
        SELECT repo, public_op, issuer, issuer, wire_digest, 'atomic', backend, 'sha1', history, 1, 1, incarnation
        FROM public.cluster_authority WHERE singleton;
        INSERT INTO ref_store_private_attempts VALUES (repo, public_op, 0, private_op, parent_digest, proof_digest, scope_revision);
        INSERT INTO ref_store_operations(repository_id, issuer_id, lane, sequence, operation_id, request_digest, state)
        VALUES (repo, issuer, scenario, 1, private_op, parent_digest, 'pending');
        IF scenario = 'pending' THEN
            BEGIN
                INSERT INTO ref_store_serving_operations(repository_id, operation_id, issuer_id,
                                                         producer_request_digest, plan_parent_digest)
                VALUES (repo, private_op, issuer, proof_digest, parent_digest);
                SET CONSTRAINTS ref_store_public_operation_evidence, ref_store_private_attempt_evidence IMMEDIATE;
                RAISE EXCEPTION 'pending private attempt accepted a different producer digest';
            EXCEPTION WHEN check_violation THEN
                GET STACKED DIAGNOSTICS failed_constraint = CONSTRAINT_NAME;
                IF failed_constraint IS DISTINCT FROM 'ref_store_public_attempt_evidence' THEN RAISE; END IF;
            END;
        END IF;
        INSERT INTO ref_store_serving_operations(repository_id, operation_id, issuer_id, producer_request_digest, plan_parent_digest)
        VALUES (repo, private_op, issuer, wire_digest, parent_digest);
        SET CONSTRAINTS ALL IMMEDIATE;
        SET CONSTRAINTS ALL DEFERRED;

        IF scenario IN ('committed', 'rejected', 'retired') THEN
            winner := CASE WHEN scenario = 'retired' THEN 'rejected' ELSE scenario END;
            IF scenario IN ('committed', 'retired') THEN
                UPDATE ref_store_core_gates SET revision = revision + 1 WHERE repository_id = repo
                    RETURNING revision INTO scope_revision;
            END IF;
            receipt := jsonb_build_object('kind', winner, 'repository_id', repo, 'revision', scope_revision,
                'head_ref', 'refs/heads/main', 'mode', 'metadata_only', 'refs', '[]'::jsonb, 'registrations', '[]'::jsonb,
                'rejection', CASE scenario
                    WHEN 'retired' THEN jsonb_build_object('code', 'revision_mismatch', 'detail', 'admitted base was superseded')
                    WHEN 'rejected' THEN jsonb_build_object('code', 'old_oid_mismatch', 'detail', 'reference changed')
                END);
            UPDATE ref_store_operations SET state = winner, terminal_result = receipt, terminal_at = clock_timestamp()
                WHERE (repository_id, operation_id) = (repo, private_op);
            INSERT INTO ref_store_core_events(event_id, repository_id, revision, operation_id, outcome, payload)
            VALUES (audit_event, repo, scope_revision, private_op, winner, receipt);
            IF scenario = 'retired' THEN
                PERFORM rootyard_ref_store_lock_public_operation(repo, public_op, next_op);
                INSERT INTO ref_store_private_attempts VALUES (repo, public_op, 1, next_op, repeat('e', 64), proof_digest, scope_revision);
                INSERT INTO ref_store_operations(repository_id, issuer_id, lane, sequence, operation_id, request_digest, state)
                VALUES (repo, issuer, scenario, 2, next_op, repeat('e', 64), 'pending');
                INSERT INTO ref_store_serving_operations(repository_id, operation_id, issuer_id, producer_request_digest, plan_parent_digest)
                VALUES (repo, next_op, issuer, wire_digest, repeat('e', 64));
                UPDATE ref_store_public_operations SET current_slot = 1, retired_event_id = audit_event
                    WHERE (repository_id, public_id) = (repo, public_op);
            ELSE
                UPDATE ref_store_public_operations SET state = winner, event_id = audit_event
                    WHERE (repository_id, public_id) = (repo, public_op);
            END IF;
            SET CONSTRAINTS ALL IMMEDIATE;
            SET CONSTRAINTS ALL DEFERRED;
        ELSIF scenario = 'cancelled' THEN
            INSERT INTO ref_store_cancellations(repository_id, issuer_id, lane, sequence, operation_id, request_digest)
            VALUES (repo, issuer, scenario, 1, private_op, parent_digest);
            UPDATE ref_store_operations SET state = 'cancelled', terminal_at = clock_timestamp(),
                terminal_result = '{"state":"cancelled","reason":"cancel_requested"}'::jsonb
                WHERE (repository_id, operation_id) = (repo, private_op);
            UPDATE ref_store_public_operations SET state = 'cancelled', cancelled_private_id = private_op
                WHERE (repository_id, public_id) = (repo, public_op);
            SET CONSTRAINTS ALL IMMEDIATE;
            SET CONSTRAINTS ALL DEFERRED;
            IF EXISTS (SELECT FROM ref_store_core_events WHERE (repository_id, operation_id) = (repo, private_op)) THEN
                RAISE EXCEPTION 'genuine cancellation created an event';
            END IF;
        END IF;

        FOREACH wrong_key IN ARRAY (CASE scenario WHEN 'pending' THEN ARRAY['pending']
            WHEN 'committed' THEN ARRAY['wrong_parent_digest', 'different_operation_at_lane'] ELSE ARRAY[]::text[] END) LOOP
            BEGIN
                INSERT INTO ref_store_cancellations(repository_id, issuer_id, lane, sequence, operation_id, request_digest)
                VALUES (repo, issuer, scenario, 1,
                        CASE WHEN wrong_key = 'different_operation_at_lane' THEN gen_random_uuid() ELSE private_op END,
                        CASE WHEN wrong_key = 'wrong_parent_digest' THEN proof_digest ELSE parent_digest END);
                SET CONSTRAINTS ref_store_private_cancellation_evidence IMMEDIATE;
                RAISE EXCEPTION 'invalid private tombstone was accepted';
            EXCEPTION WHEN check_violation THEN
                GET STACKED DIAGNOSTICS failed_constraint = CONSTRAINT_NAME;
                IF failed_constraint IS DISTINCT FROM 'ref_store_public_attempt_evidence' THEN RAISE; END IF;
            END;
        END LOOP;

        IF scenario IN ('committed', 'rejected', 'retired') THEN
            SELECT to_jsonb(o) INTO STRICT before_operation FROM ref_store_operations o
                WHERE (o.repository_id, o.operation_id) = (repo, private_op);
            SELECT to_jsonb(e) INTO STRICT before_event FROM ref_store_core_events e WHERE e.event_id = audit_event;
            SELECT to_jsonb(w) INTO STRICT before_wrapper FROM ref_store_public_operations w
                WHERE (w.repository_id, w.public_id) = (repo, public_op);
            IF scenario = 'committed' THEN SET LOCAL ROLE issue42_legacy_cancel_probe; END IF;
            INSERT INTO ref_store_cancellations(repository_id, issuer_id, lane, sequence, operation_id, request_digest)
            VALUES (repo, issuer, scenario, 1, private_op, parent_digest);
            SET CONSTRAINTS ref_store_private_cancellation_evidence IMMEDIATE;
            SET CONSTRAINTS ALL DEFERRED;
            IF scenario = 'committed' THEN RESET ROLE; END IF;
            IF (SELECT to_jsonb(o) FROM ref_store_operations o WHERE (o.repository_id, o.operation_id) = (repo, private_op))
                    IS DISTINCT FROM before_operation
               OR (SELECT to_jsonb(e) FROM ref_store_core_events e WHERE e.event_id = audit_event) IS DISTINCT FROM before_event
               OR (SELECT to_jsonb(w) FROM ref_store_public_operations w WHERE (w.repository_id, w.public_id) = (repo, public_op))
                    IS DISTINCT FROM before_wrapper THEN
                RAISE EXCEPTION 'late cancellation changed a durable winner';
            END IF;
        END IF;
    END LOOP;

    INSERT INTO ref_store_issuer_lanes(repository_id, issuer_id, lane, last_reserved_sequence)
    VALUES (repo, issuer, 'legacy-cancel', 1);
    SET LOCAL ROLE issue42_legacy_cancel_probe;
    IF has_table_privilege(current_user, 'public.ref_store_private_attempts', 'SELECT')
       OR has_function_privilege(current_user, 'public.rootyard_ref_store_private_cancellation_evidence()', 'EXECUTE') THEN
        RAISE EXCEPTION 'legacy caller fixture must lack private evidence privileges';
    END IF;
    INSERT INTO ref_store_cancellations(repository_id, issuer_id, lane, sequence, operation_id, request_digest)
    VALUES (repo, issuer, 'legacy-cancel', 1, gen_random_uuid(), parent_digest);
    SET CONSTRAINTS ref_store_private_cancellation_evidence IMMEDIATE;
    RESET ROLE;
END $$;

ROLLBACK;

DO $$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) IS DISTINCT FROM 151
       OR to_regclass('public.ref_store_public_operations') IS NOT NULL
       OR to_regclass('public.ref_store_private_attempts') IS NOT NULL
       OR to_regrole('issue42_legacy_cancel_probe') IS NOT NULL THEN
        RAISE EXCEPTION 'ambiguous fixture rollback';
    END IF;
END $$;
