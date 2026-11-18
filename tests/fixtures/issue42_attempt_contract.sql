-- Loaded only by issue42_attempt_contract_test.sql in its rollback-only schema.
DO $$
BEGIN
    IF current_schema() IS DISTINCT FROM 'issue42_attempt_scratch'
       OR current_setting('search_path') <> 'issue42_attempt_scratch, pg_catalog, pg_temp' THEN
        RAISE EXCEPTION 'fixture requires its isolated search path';
    END IF;
END $$;

CREATE TYPE core_realm AS (
    repository_id uuid, tenant_id uuid, object_format text, history_incarnation uuid,
    authority_epoch bigint, group_epoch bigint
);

-- Modeled authoritative inputs. The scratch schema has no serving registry,
-- provider profile, restore coordinator or protocol-realm enforcement.
CREATE TABLE modeled_serving_scope (
    repository_id uuid PRIMARY KEY REFERENCES repositories(id),
    restore_incarnation uuid NOT NULL,
    backend_identity text NOT NULL CHECK (backend_identity ~ '^[0-9a-f]{64}$')
);

CREATE TABLE public_operations (
    repository_id uuid NOT NULL REFERENCES repositories(id),
    public_id uuid NOT NULL,
    issuer_id uuid NOT NULL,
    wire_digest text NOT NULL CHECK (wire_digest ~ '^[0-9a-f]{64}$'),
    request_mode text NOT NULL CHECK (request_mode IN ('atomic', 'accepted_subset')),
    backend_identity text NOT NULL CHECK (backend_identity ~ '^[0-9a-f]{64}$'),
    realm core_realm NOT NULL CHECK (realm IS NOT NULL AND (realm).repository_id = repository_id),
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
    base_revision bigint NOT NULL CHECK (base_revision > 0),
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

CREATE FUNCTION gate_realm(g ref_store_core_gates) RETURNS core_realm LANGUAGE sql IMMUTABLE AS $$
    SELECT ROW((g).repository_id, (g).tenant_id, (g).object_format, (g).history_incarnation,
               (g).authority_epoch, (g).group_epoch)::core_realm
$$;

CREATE FUNCTION exact_serving_binding(w public_operations, private_op uuid, parent_digest text)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT FROM ref_store_serving_operations s JOIN ref_store_operations o USING (repository_id, operation_id)
        WHERE (s.repository_id, s.operation_id) = ((w).repository_id, private_op)
        AND (s.issuer_id, s.producer_request_digest, s.plan_parent_digest, o.issuer_id, o.request_digest)
            = ((w).issuer_id, (w).wire_digest, parent_digest, (w).issuer_id, parent_digest)
    )
$$;

-- The caller already holds the wrapper and operation advisory prefix. This
-- models the locked RealmExpectation comparison and the advanced-gate check.
CREATE FUNCTION lock_stale_gate(w public_operations) RETURNS ref_store_core_gates LANGUAGE plpgsql AS $$
DECLARE
    attempt private_attempts;
    scope modeled_serving_scope;
    gate ref_store_core_gates;
BEGIN
    PERFORM require_operation_lock(w.repository_id, w.public_id);
    SELECT * INTO attempt FROM private_attempts
        WHERE (repository_id, public_id, slot) = (w.repository_id, w.public_id, w.current_slot);
    IF FOUND THEN
        PERFORM require_operation_lock(w.repository_id, attempt.private_id);
    END IF;
    IF NOT exact_serving_binding(w, attempt.private_id, attempt.plan_digest) THEN
        RAISE EXCEPTION 'stale attempt serving binding differs' USING ERRCODE = '23514', CONSTRAINT = 'stale_serving_binding';
    END IF;
    SELECT * INTO scope FROM modeled_serving_scope WHERE repository_id = w.repository_id FOR SHARE;
    IF NOT FOUND OR (scope.restore_incarnation, scope.backend_identity) IS DISTINCT FROM (w.restore_incarnation, w.backend_identity) THEN
        RAISE EXCEPTION 'stale attempt serving scope differs' USING ERRCODE = '23514', CONSTRAINT = 'stale_serving_scope';
    END IF;
    SELECT * INTO gate FROM ref_store_core_gates WHERE repository_id = w.repository_id FOR UPDATE;
    IF NOT FOUND OR gate_realm(gate) IS DISTINCT FROM w.realm THEN
        RAISE EXCEPTION 'stale attempt realm differs' USING ERRCODE = '23514', CONSTRAINT = 'stale_realm';
    END IF;
    IF gate.revision <= attempt.base_revision THEN
        RAISE EXCEPTION 'stale rejection requires an advanced gate' USING ERRCODE = '23514', CONSTRAINT = 'stale_revision';
    END IF;
    RETURN gate;
END $$;

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
    ELSIF (OLD.repository_id, OLD.public_id, OLD.issuer_id, OLD.wire_digest, OLD.request_mode, OLD.backend_identity,
           OLD.realm, OLD.restore_incarnation)
          IS DISTINCT FROM
          (NEW.repository_id, NEW.public_id, NEW.issuer_id, NEW.wire_digest, NEW.request_mode, NEW.backend_identity,
           NEW.realm, NEW.restore_incarnation)
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
        IF OLD.current_slot = 0 AND NEW.current_slot = 1 THEN
            PERFORM lock_stale_gate(OLD);
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION guard_attempt_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    wrapper public_operations;
BEGIN
    PERFORM require_operation_lock(NEW.repository_id, NEW.public_id);
    PERFORM require_operation_lock(NEW.repository_id, NEW.private_id);
    SELECT * INTO wrapper FROM public_operations WHERE (repository_id, public_id) = (NEW.repository_id, NEW.public_id);
    IF NOT FOUND OR wrapper.current_slot <> 0 OR wrapper.state <> 'pending' THEN
        RAISE EXCEPTION 'wrapper cannot reserve an attempt' USING ERRCODE = '23514';
    END IF;
    IF EXISTS (SELECT FROM public_operations WHERE (repository_id, public_id) = (NEW.repository_id, NEW.private_id))
       OR EXISTS (SELECT FROM ref_store_operations WHERE (repository_id, operation_id) = (NEW.repository_id, NEW.private_id))
       OR EXISTS (SELECT FROM ref_store_cancellations WHERE (repository_id, operation_id) = (NEW.repository_id, NEW.private_id)) THEN
        RAISE EXCEPTION 'private operation identifier occupied' USING ERRCODE = '23505';
    END IF;
    IF NEW.slot = 1 THEN
        PERFORM lock_stale_gate(wrapper);
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
        IF TG_OP = 'UPDATE' AND NEW.state = 'rejected' AND NEW.terminal_result#>>'{rejection,code}' = 'revision_mismatch' THEN
            IF NEW.terminal_result->'revision' IS DISTINCT FROM to_jsonb((lock_stale_gate(wrapper)).revision) THEN
                RAISE EXCEPTION 'stale rejection revision differs from the locked gate' USING ERRCODE = '23514';
            END IF;
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
        SELECT a.slot, a.base_revision, o.state AS core_state, o.terminal_result, e.event_id, e.outcome, e.payload, e.revision,
               exact_serving_binding(wrapper, a.private_id, a.plan_digest) AS serving_bound,
               c.operation_id IS NOT NULL AS cancelled
        FROM private_attempts a
        LEFT JOIN ref_store_operations o ON (o.repository_id, o.operation_id) = (a.repository_id, a.private_id)
        LEFT JOIN ref_store_core_events e ON (e.repository_id, e.operation_id) = (a.repository_id, a.private_id)
        LEFT JOIN ref_store_cancellations c ON (c.repository_id, c.operation_id) = (a.repository_id, a.private_id)
        WHERE (a.repository_id, a.public_id) = (repo, public_op)
    LOOP
        IF NOT attempt.serving_bound THEN
            RAISE EXCEPTION 'private attempt lacks exact serving binding' USING ERRCODE = '23514', CONSTRAINT = 'attempt_serving_binding';
        END IF;
        IF (attempt.cancelled AND attempt.terminal_result IS DISTINCT FROM '{"state":"cancelled","reason":"cancel_requested"}'::jsonb)
           OR attempt.slot > wrapper.current_slot
           OR (attempt.event_id IS NOT NULL AND
               (attempt.outcome IS DISTINCT FROM attempt.core_state
                OR attempt.payload IS DISTINCT FROM attempt.terminal_result
                OR attempt.payload->'revision' IS DISTINCT FROM to_jsonb(attempt.revision)))
           OR (attempt.slot < wrapper.current_slot AND
               (attempt.core_state IS DISTINCT FROM 'rejected' OR attempt.cancelled OR attempt.event_id IS NULL
                OR attempt.revision <= attempt.base_revision
                OR attempt.payload->>'kind' IS DISTINCT FROM 'rejected'
                OR attempt.payload#>>'{rejection,code}' IS DISTINCT FROM 'revision_mismatch'
                OR attempt.payload->'registrations' IS DISTINCT FROM '[]'::jsonb))
           OR (attempt.slot = wrapper.current_slot AND
               (attempt.core_state IS DISTINCT FROM wrapper.state
                OR attempt.cancelled <> (wrapper.state = 'cancelled')
                OR attempt.event_id IS DISTINCT FROM wrapper.event_id)) THEN
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
CREATE FUNCTION lookup_public(repo uuid, op uuid, issuer uuid, wire text, mode text, backend text,
                              realm core_realm, incarnation uuid)
RETURNS TABLE (route text, operation_id uuid, state text, event_id uuid) LANGUAGE sql STABLE AS $$
    SELECT CASE
               WHEN a.private_id IS NOT NULL THEN 'private'
               WHEN w.public_id IS NOT NULL AND binding.matches IS NOT TRUE THEN 'conflict'
               WHEN w.public_id IS NOT NULL THEN 'wrapper'
               WHEN o.operation_id IS NOT NULL THEN 'legacy_operation'
               WHEN c.operation_id IS NOT NULL THEN 'legacy_tombstone'
               ELSE 'unknown'
           END,
           CASE WHEN binding.matches THEN w.public_id END,
           CASE WHEN binding.matches THEN w.state END,
           CASE WHEN binding.matches THEN w.event_id END
    FROM (VALUES (repo, op)) AS lookup_key(repository_id, operation_id)
    LEFT JOIN private_attempts a ON (a.repository_id, a.private_id) = (lookup_key.repository_id, lookup_key.operation_id)
    LEFT JOIN public_operations w ON (w.repository_id, w.public_id) = (lookup_key.repository_id, lookup_key.operation_id)
    LEFT JOIN ref_store_operations o ON (o.repository_id, o.operation_id) = (lookup_key.repository_id, lookup_key.operation_id)
    LEFT JOIN ref_store_cancellations c ON (c.repository_id, c.operation_id) = (lookup_key.repository_id, lookup_key.operation_id)
    LEFT JOIN ref_store_core_gates g ON g.repository_id = w.repository_id
    LEFT JOIN modeled_serving_scope s ON s.repository_id = w.repository_id
    CROSS JOIN LATERAL (
        SELECT (w.issuer_id, w.wire_digest, w.request_mode, w.backend_identity, w.realm, w.restore_incarnation) =
               ($3, $4, $5, $6, $7, $8)
               AND (w.realm, w.restore_incarnation, w.backend_identity) =
                   (gate_realm(g), s.restore_incarnation, s.backend_identity) AS matches
    ) binding
$$;
