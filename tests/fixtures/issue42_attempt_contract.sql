-- Loaded only by issue42_attempt_contract_test.sql in its rollback-only schema.
DO $$
BEGIN
    IF current_schema() IS DISTINCT FROM 'issue42_attempt_scratch'
       OR current_setting('search_path') <> 'issue42_attempt_scratch, pg_catalog, pg_temp' THEN
        RAISE EXCEPTION 'fixture requires its isolated search path';
    END IF;
END $$;

CREATE TABLE public_operations (
    repository_id uuid NOT NULL REFERENCES repositories(id),
    public_id uuid NOT NULL,
    issuer_id uuid NOT NULL,
    wire_digest text NOT NULL CHECK (wire_digest ~ '^[0-9a-f]{64}$'),
    realm_id uuid NOT NULL,
    restore_incarnation uuid NOT NULL,
    current_slot smallint NOT NULL DEFAULT 0,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'committed', 'rejected', 'cancelled')),
    event_id uuid UNIQUE REFERENCES ref_store_core_events(event_id) DEFERRABLE INITIALLY DEFERRED,
    PRIMARY KEY (repository_id, public_id),
    CHECK ((state IN ('committed', 'rejected')) = (event_id IS NOT NULL))
);

CREATE TABLE private_attempts (
    repository_id uuid NOT NULL,
    public_id uuid NOT NULL,
    slot smallint NOT NULL CHECK (slot IN (0, 1)),
    private_id uuid NOT NULL,
    plan_digest text NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    proof_digest text NOT NULL CHECK (proof_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (repository_id, public_id, slot),
    UNIQUE (repository_id, private_id),
    -- Slot 0 uses a private UUID too, so neither slot can alias a public or legacy lookup.
    CHECK (public_id <> private_id),
    FOREIGN KEY (repository_id, public_id) REFERENCES public_operations(repository_id, public_id),
    FOREIGN KEY (repository_id, private_id) REFERENCES ref_store_operations(repository_id, operation_id)
        DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE public_operations ADD CONSTRAINT current_attempt
    FOREIGN KEY (repository_id, public_id, current_slot)
    REFERENCES private_attempts(repository_id, public_id, slot) DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION operation_lock_key(repo uuid, op uuid) RETURNS bigint LANGUAGE sql IMMUTABLE AS $$
    SELECT hashtextextended('rootyard-ref-store-operation-v1/' || repo::text || '/' || op::text, 0)
$$;

CREATE FUNCTION require_operation_lock(repo uuid, op uuid) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory'
        AND granted AND mode = 'ExclusiveLock' AND objsubid = 1
        AND ((classid::bigint << 32) | objid::bigint) = operation_lock_key(repo, op)
    ) THEN
        RAISE EXCEPTION 'operation lock required' USING ERRCODE = '55000';
    END IF;
END $$;

CREATE FUNCTION wrapper_lock_ids(repo uuid, public_op uuid, proposed uuid) RETURNS uuid[] LANGUAGE sql VOLATILE AS $$
    SELECT ARRAY(
        SELECT id FROM (
            SELECT public_op AS id UNION SELECT proposed
            UNION SELECT private_id FROM private_attempts WHERE repository_id = repo AND public_id = public_op
        ) ids WHERE id IS NOT NULL ORDER BY id
    )
$$;

-- Read without row locks, acquire the entire normalized set, then recheck under
-- the public key. If it changed, abort the transaction without extending the set.
-- Call before any wrapper or existing issuer-lane lock, including on replay/cancel.
CREATE FUNCTION lock_wrapper(repo uuid, public_op uuid, proposed uuid DEFAULT NULL)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    ids uuid[];
    op uuid;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'fixture requires read committed' USING ERRCODE = '55000';
    END IF;
    ids := wrapper_lock_ids(repo, public_op, proposed);
    FOREACH op IN ARRAY ids LOOP
        PERFORM pg_advisory_xact_lock(operation_lock_key(repo, op));
    END LOOP;
    IF ids IS DISTINCT FROM wrapper_lock_ids(repo, public_op, proposed) THEN
        RAISE EXCEPTION 'wrapper lock set changed' USING ERRCODE = '40001';
    END IF;
    PERFORM 1 FROM public_operations WHERE repository_id = repo AND public_id = public_op FOR UPDATE;
END $$;

CREATE FUNCTION guard_wrapper() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    attempt_id uuid;
BEGIN
    PERFORM require_operation_lock(NEW.repository_id, NEW.public_id);
    IF TG_OP = 'INSERT' THEN
        IF NEW.current_slot <> 0 OR NEW.state <> 'pending' THEN
            RAISE EXCEPTION 'wrapper must start pending at slot zero' USING ERRCODE = '23514';
        END IF;
        IF EXISTS (SELECT FROM ref_store_operations WHERE (repository_id, operation_id) = (NEW.repository_id, NEW.public_id))
           OR EXISTS (SELECT FROM ref_store_cancellations WHERE (repository_id, operation_id) = (NEW.repository_id, NEW.public_id))
           OR EXISTS (SELECT FROM private_attempts WHERE (repository_id, private_id) = (NEW.repository_id, NEW.public_id)) THEN
            RAISE EXCEPTION 'public operation identifier occupied' USING ERRCODE = '23505';
        END IF;
    ELSIF (OLD.repository_id, OLD.public_id, OLD.issuer_id, OLD.wire_digest, OLD.realm_id, OLD.restore_incarnation)
          IS DISTINCT FROM
          (NEW.repository_id, NEW.public_id, NEW.issuer_id, NEW.wire_digest, NEW.realm_id, NEW.restore_incarnation)
          OR OLD.state <> 'pending'
          OR NOT ((OLD.current_slot = 0 AND NEW.current_slot = 1 AND NEW.state = 'pending')
                  OR (OLD.current_slot = NEW.current_slot AND NEW.state <> 'pending')) THEN
        RAISE EXCEPTION 'invalid public operation transition' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        FOR attempt_id IN
            SELECT private_id FROM private_attempts WHERE (repository_id, public_id) = (OLD.repository_id, OLD.public_id)
        LOOP
            PERFORM require_operation_lock(OLD.repository_id, attempt_id);
        END LOOP;
        IF NEW.current_slot = 1 AND NOT EXISTS (
            SELECT FROM private_attempts WHERE (repository_id, public_id, slot) = (OLD.repository_id, OLD.public_id, 0)
        ) THEN
            RAISE EXCEPTION 'rotation requires slot zero history' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION guard_attempt_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM require_operation_lock(NEW.repository_id, NEW.public_id);
    PERFORM require_operation_lock(NEW.repository_id, NEW.private_id);
    IF NOT EXISTS (SELECT FROM public_operations WHERE (repository_id, public_id) = (NEW.repository_id, NEW.public_id)
                   AND current_slot = 0 AND state = 'pending') THEN
        RAISE EXCEPTION 'wrapper cannot reserve an attempt' USING ERRCODE = '23514';
    END IF;
    IF EXISTS (SELECT FROM public_operations WHERE (repository_id, public_id) = (NEW.repository_id, NEW.private_id))
       OR EXISTS (SELECT FROM ref_store_operations WHERE (repository_id, operation_id) = (NEW.repository_id, NEW.private_id))
       OR EXISTS (SELECT FROM ref_store_cancellations WHERE (repository_id, operation_id) = (NEW.repository_id, NEW.private_id)) THEN
        RAISE EXCEPTION 'private operation identifier occupied' USING ERRCODE = '23505';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION refuse_history_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'operation history is append only' USING ERRCODE = '55000';
END $$;

CREATE TRIGGER guard_wrapper BEFORE INSERT OR UPDATE ON public_operations
    FOR EACH ROW EXECUTE FUNCTION guard_wrapper();
CREATE TRIGGER preserve_wrapper BEFORE DELETE ON public_operations FOR EACH ROW EXECUTE FUNCTION refuse_history_mutation();
CREATE TRIGGER preserve_wrapper_truncate BEFORE TRUNCATE ON public_operations EXECUTE FUNCTION refuse_history_mutation();
CREATE TRIGGER guard_attempt BEFORE INSERT ON private_attempts FOR EACH ROW EXECUTE FUNCTION guard_attempt_insert();
CREATE TRIGGER preserve_attempt BEFORE UPDATE OR DELETE ON private_attempts
    FOR EACH ROW EXECUTE FUNCTION refuse_history_mutation();
CREATE TRIGGER preserve_attempt_truncate BEFORE TRUNCATE ON private_attempts EXECUTE FUNCTION refuse_history_mutation();
CREATE TRIGGER preserve_cancellation_truncate BEFORE TRUNCATE ON ref_store_cancellations EXECUTE FUNCTION refuse_history_mutation();

-- Scratch equivalents of the private adapter guard and the reciprocal legacy
-- claim checks. The caller holds advisory keys before touching the issuer lane.
CREATE FUNCTION guard_core_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    repo uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.repository_id ELSE NEW.repository_id END;
    op uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.operation_id ELSE NEW.operation_id END;
    attempt private_attempts;
    wrapper public_operations;
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM require_operation_lock(repo, op);
        IF EXISTS (SELECT FROM public_operations WHERE (repository_id, public_id) = (repo, op)) THEN
            RAISE EXCEPTION 'core operation identifier belongs to public wrapper' USING ERRCODE = '23505';
        END IF;
    END IF;
    SELECT * INTO attempt FROM private_attempts WHERE (repository_id, private_id) = (repo, op);
    IF NOT FOUND THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'private operation history is append only' USING ERRCODE = '55000';
    END IF;
    PERFORM require_operation_lock(repo, op);
    PERFORM require_operation_lock(repo, attempt.public_id);
    SELECT * INTO STRICT wrapper FROM public_operations WHERE (repository_id, public_id) = (repo, attempt.public_id);
    IF wrapper.current_slot <> attempt.slot OR wrapper.state <> 'pending' THEN
        RAISE EXCEPTION 'attempt is fenced' USING ERRCODE = '55000';
    END IF;
    IF TG_TABLE_NAME = 'ref_store_operations' THEN
        IF (NEW.issuer_id, NEW.request_digest) IS DISTINCT FROM (wrapper.issuer_id, attempt.plan_digest)
           OR (TG_OP = 'INSERT' AND NEW.state <> 'pending') THEN
            RAISE EXCEPTION 'private operation binding differs' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'ref_store_cancellations' THEN
        IF NOT EXISTS (
            SELECT FROM ref_store_operations o WHERE (o.repository_id, o.operation_id) = (repo, op)
            AND (o.issuer_id, o.lane, o.sequence, o.request_digest) = (NEW.issuer_id, NEW.lane, NEW.sequence, NEW.request_digest)
            AND o.state = 'pending'
        ) THEN
            RAISE EXCEPTION 'private cancellation binding differs' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER issue42_core_identity BEFORE INSERT OR UPDATE OR DELETE ON ref_store_operations
    FOR EACH ROW EXECUTE FUNCTION guard_core_identity();
CREATE TRIGGER issue42_core_identity BEFORE INSERT OR UPDATE OR DELETE ON ref_store_cancellations
    FOR EACH ROW EXECUTE FUNCTION guard_core_identity();
CREATE TRIGGER issue42_core_identity BEFORE INSERT OR UPDATE OR DELETE ON ref_store_core_events
    FOR EACH ROW EXECUTE FUNCTION guard_core_identity();

CREATE FUNCTION verify_wrapper() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    repo uuid := NEW.repository_id;
    public_op uuid;
    wrapper public_operations;
    attempt record;
BEGIN
    IF TG_TABLE_NAME IN ('public_operations', 'private_attempts') THEN
        public_op := NEW.public_id;
    ELSE
        SELECT public_id INTO public_op FROM private_attempts WHERE (repository_id, private_id) = (repo, NEW.operation_id);
        IF NOT FOUND THEN RETURN NULL; END IF;
    END IF;
    SELECT * INTO STRICT wrapper FROM public_operations WHERE (repository_id, public_id) = (repo, public_op);
    FOR attempt IN
        SELECT a.slot, o.state AS core_state, o.terminal_result, e.event_id, e.outcome, e.payload, e.revision,
               c.operation_id IS NOT NULL AS cancelled
        FROM private_attempts a
        LEFT JOIN ref_store_operations o ON (o.repository_id, o.operation_id) = (a.repository_id, a.private_id)
        LEFT JOIN ref_store_core_events e ON (e.repository_id, e.operation_id) = (a.repository_id, a.private_id)
        LEFT JOIN ref_store_cancellations c ON (c.repository_id, c.operation_id) = (a.repository_id, a.private_id)
        WHERE (a.repository_id, a.public_id) = (repo, public_op)
    LOOP
        IF (attempt.cancelled AND attempt.terminal_result IS DISTINCT FROM '{"state":"cancelled","reason":"cancel_requested"}'::jsonb)
           OR attempt.slot > wrapper.current_slot
           OR (attempt.slot < wrapper.current_slot AND
               (attempt.core_state IS DISTINCT FROM 'cancelled' OR NOT attempt.cancelled OR attempt.event_id IS NOT NULL))
           OR (attempt.slot = wrapper.current_slot AND
               (attempt.core_state IS DISTINCT FROM wrapper.state
                OR attempt.cancelled <> (wrapper.state = 'cancelled')
                OR attempt.event_id IS DISTINCT FROM wrapper.event_id
                OR (attempt.event_id IS NOT NULL AND
                    (attempt.outcome IS DISTINCT FROM wrapper.state
                     OR attempt.payload IS DISTINCT FROM attempt.terminal_result
                     OR attempt.payload->'revision' IS DISTINCT FROM to_jsonb(attempt.revision))))) THEN
            RAISE EXCEPTION 'wrapper and core terminal disagree' USING ERRCODE = '23514';
        END IF;
    END LOOP;
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER verify_wrapper AFTER INSERT OR UPDATE ON public_operations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION verify_wrapper();
CREATE CONSTRAINT TRIGGER verify_wrapper AFTER INSERT ON private_attempts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION verify_wrapper();
CREATE CONSTRAINT TRIGGER verify_wrapper AFTER INSERT OR UPDATE ON ref_store_operations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION verify_wrapper();
CREATE CONSTRAINT TRIGGER verify_wrapper AFTER INSERT ON ref_store_cancellations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION verify_wrapper();
CREATE CONSTRAINT TRIGGER verify_wrapper AFTER INSERT ON ref_store_core_events
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION verify_wrapper();

-- Internal routing result only. A legacy result delegates to the existing
-- binding/receipt path. A tombstone alone is a cancel fence, never a replay.
CREATE FUNCTION lookup_public(repo uuid, op uuid, issuer uuid, wire text)
RETURNS TABLE (route text, operation_id uuid, state text, event_id uuid) LANGUAGE sql STABLE AS $$
    SELECT CASE
               WHEN a.private_id IS NOT NULL THEN 'private'
               WHEN w.public_id IS NOT NULL AND (w.issuer_id, w.wire_digest) IS DISTINCT FROM (issuer, wire) THEN 'conflict'
               WHEN w.public_id IS NOT NULL THEN 'wrapper'
               WHEN o.operation_id IS NOT NULL THEN 'legacy_operation'
               WHEN c.operation_id IS NOT NULL THEN 'legacy_tombstone'
               ELSE 'unknown'
           END,
           CASE WHEN (w.issuer_id, w.wire_digest) = (issuer, wire) THEN w.public_id END,
           CASE WHEN (w.issuer_id, w.wire_digest) = (issuer, wire) THEN w.state END,
           CASE WHEN (w.issuer_id, w.wire_digest) = (issuer, wire) THEN w.event_id END
    FROM (VALUES (repo, op)) AS lookup_key(repository_id, operation_id)
    LEFT JOIN private_attempts a ON (a.repository_id, a.private_id) = (lookup_key.repository_id, lookup_key.operation_id)
    LEFT JOIN public_operations w ON (w.repository_id, w.public_id) = (lookup_key.repository_id, lookup_key.operation_id)
    LEFT JOIN ref_store_operations o ON (o.repository_id, o.operation_id) = (lookup_key.repository_id, lookup_key.operation_id)
    LEFT JOIN ref_store_cancellations c ON (c.repository_id, c.operation_id) = (lookup_key.repository_id, lookup_key.operation_id)
$$;
