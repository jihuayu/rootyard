-- Run against schema 152 in a job-owned PG17 database as the job's PG admin. All rows
-- and the restricted legacy-caller role below roll back together.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL search_path = public, pg_catalog, pg_temp;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '2s';
SET LOCAL client_min_messages = warning;

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
    initial_sequence bigint;
    scenario text;
    winner text;
    receipt jsonb;
    before_operation jsonb;
    before_event jsonb;
    before_wrapper jsonb;
    wrong_key text;
    wrong_wire text;
    failed_constraint text;
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

    FOREACH scenario IN ARRAY ARRAY['committed', 'rejected', 'retired', 'cancelled', 'pending'] LOOP
        SELECT ids[1], ids[2], ids[3] INTO public_op, private_op, next_op
        FROM (SELECT array_agg(id ORDER BY id) AS ids FROM (VALUES (gen_random_uuid()), (gen_random_uuid()), (gen_random_uuid())) keys(id)) s;
        audit_event := gen_random_uuid();
        PERFORM rootyard_ref_store_lock_public_operation(repo, public_op, private_op);
        SELECT revision INTO STRICT scope_revision FROM ref_store_core_gates WHERE repository_id = repo;
        INSERT INTO ref_store_issuer_lanes(repository_id, issuer_id, lane, last_reserved_sequence)
        VALUES (repo, issuer, scenario, CASE WHEN scenario = 'pending' THEN 0 ELSE 2 END);
        initial_sequence := 1;
        IF scenario = 'pending' THEN
            SELECT last_reserved_sequence + 1 INTO STRICT initial_sequence
            FROM ref_store_issuer_lanes
            WHERE (repository_id, issuer_id, lane) = (repo, issuer, scenario)
            FOR UPDATE;
        END IF;
        INSERT INTO ref_store_public_operations(repository_id, public_id, admission_owner_id, issuer_id, wire_digest,
                                                request_mode, backend_identity, object_format, history_incarnation,
                                                authority_epoch, group_epoch, restore_incarnation)
        SELECT repo, public_op, issuer, issuer, wire_digest, 'atomic', backend, 'sha1', history, 1, 1, incarnation
        FROM public.cluster_authority WHERE singleton;
        INSERT INTO ref_store_private_attempts VALUES (repo, public_op, 0, private_op, parent_digest, proof_digest, scope_revision);
        IF scenario = 'pending' THEN
            UPDATE ref_store_issuer_lanes SET last_reserved_sequence = initial_sequence, updated_at = clock_timestamp()
            WHERE (repository_id, issuer_id, lane) = (repo, issuer, scenario)
                AND last_reserved_sequence = initial_sequence - 1;
            IF NOT FOUND OR initial_sequence <> 1 THEN
                RAISE EXCEPTION 'slot zero must reserve the first issuer sequence after mapping';
            END IF;
        END IF;
        INSERT INTO ref_store_operations(repository_id, issuer_id, lane, sequence, operation_id, request_digest, state)
        VALUES (repo, issuer, scenario, initial_sequence, private_op, parent_digest, 'pending');
        IF scenario = 'pending' THEN
            FOREACH wrong_wire IN ARRAY ARRAY[NULL::text, proof_digest] LOOP
                BEGIN
                    IF wrong_wire IS NOT NULL THEN
                        INSERT INTO ref_store_serving_operations
                            (repository_id, operation_id, issuer_id, producer_request_digest, plan_parent_digest)
                        VALUES (repo, private_op, issuer, wrong_wire, parent_digest);
                    END IF;
                    SET CONSTRAINTS ref_store_private_attempt_evidence IMMEDIATE;
                    RAISE EXCEPTION 'slot zero accepted an absent or wrong producer binding';
                EXCEPTION WHEN check_violation THEN
                    GET STACKED DIAGNOSTICS failed_constraint = CONSTRAINT_NAME;
                    IF failed_constraint IS DISTINCT FROM 'ref_store_public_attempt_evidence' THEN RAISE; END IF;
                END;
            END LOOP;
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
