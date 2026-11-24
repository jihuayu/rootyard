-- Durable public push identity with up to three private attempts.
-- A writer must claim all operation keys before the issuer lane and then use
-- the existing serving, gate, and decision lock order. Legacy reserve, begin,
-- cancel and replay need reciprocal UUID checks before a producer is enabled.

CREATE TABLE ref_store_public_operations (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE
        CHECK (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    public_id UUID NOT NULL CHECK (public_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    admission_owner_id UUID NOT NULL CHECK (admission_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    issuer_id UUID NOT NULL CHECK (issuer_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    wire_digest TEXT NOT NULL CHECK (wire_digest ~ '^[0-9a-f]{64}$'),
    request_mode TEXT NOT NULL CHECK (request_mode IN ('atomic', 'accepted_subset')),
    backend_identity TEXT NOT NULL CHECK (backend_identity ~ '^[0-9a-f]{64}$'),
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1', 'sha256')),
    history_incarnation UUID NOT NULL CHECK (history_incarnation <> '00000000-0000-0000-0000-000000000000'::uuid),
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch > 0),
    restore_incarnation UUID NOT NULL CHECK (restore_incarnation <> '00000000-0000-0000-0000-000000000000'::uuid),
    current_slot SMALLINT NOT NULL DEFAULT 0 CHECK (current_slot IN (0, 1, 2)),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'committed', 'rejected', 'cancelled')),
    event_id UUID UNIQUE REFERENCES ref_store_core_events(event_id) DEFERRABLE INITIALLY DEFERRED,
    cancelled_private_id UUID,
    PRIMARY KEY (repository_id, public_id),
    FOREIGN KEY (repository_id, cancelled_private_id)
        REFERENCES ref_store_cancellations(repository_id, operation_id) DEFERRABLE INITIALLY DEFERRED,
    CHECK ((state IN ('committed', 'rejected')) = (event_id IS NOT NULL)),
    CHECK ((state = 'cancelled') = (cancelled_private_id IS NOT NULL))
);

CREATE TABLE ref_store_private_attempts (
    repository_id UUID NOT NULL,
    public_id UUID NOT NULL,
    slot SMALLINT NOT NULL CHECK (slot IN (0, 1, 2)),
    private_id UUID NOT NULL CHECK (private_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    plan_digest TEXT NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    proof_digest TEXT NOT NULL CHECK (proof_digest ~ '^[0-9a-f]{64}$'),
    base_revision BIGINT NOT NULL CHECK (base_revision > 0),
    PRIMARY KEY (repository_id, public_id, slot),
    UNIQUE (repository_id, private_id),
    CHECK (public_id <> private_id),
    FOREIGN KEY (repository_id, public_id)
        REFERENCES ref_store_public_operations(repository_id, public_id) ON DELETE CASCADE,
    FOREIGN KEY (repository_id, private_id)
        REFERENCES ref_store_serving_operations(repository_id, operation_id) DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE ref_store_public_operations ADD CONSTRAINT ref_store_public_current_attempt
    FOREIGN KEY (repository_id, public_id, current_slot)
    REFERENCES ref_store_private_attempts(repository_id, public_id, slot) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE ref_store_attempt_retirements (
    repository_id uuid NOT NULL,
    public_id uuid NOT NULL,
    slot smallint NOT NULL CHECK (slot IN (0, 1)),
    event_id uuid NOT NULL UNIQUE REFERENCES ref_store_core_events(event_id) DEFERRABLE INITIALLY DEFERRED,
    PRIMARY KEY (repository_id, public_id, slot),
    FOREIGN KEY (repository_id, public_id, slot)
        REFERENCES ref_store_private_attempts(repository_id, public_id, slot)
        ON DELETE CASCADE
);

-- Inserted by the verified restore fence when it rotates cluster authority.
-- Terminal proof reads can follow this chain without rewriting restored evidence.
CREATE TABLE ref_store_restore_lineage (
    target_incarnation uuid PRIMARY KEY CHECK (target_incarnation <> '00000000-0000-0000-0000-000000000000'::uuid),
    source_incarnation uuid NOT NULL CHECK (source_incarnation <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (target_incarnation <> source_incarnation)
);

CREATE FUNCTION rootyard_ref_store_attempt_key(repo uuid, op uuid) RETURNS bigint LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT hashtextextended('rootyard-ref-store-operation-v1/' || repo::text || '/' || op::text, 0)
$$;

CREATE FUNCTION rootyard_ref_store_attempt_ids(repo uuid, public_op uuid, proposed uuid) RETURNS uuid[] LANGUAGE sql VOLATILE AS $$
    SELECT ARRAY(
        SELECT id FROM (
            SELECT public_op AS id UNION SELECT proposed
            UNION SELECT private_id FROM ref_store_private_attempts WHERE repository_id = repo AND public_id = public_op
        ) ids WHERE id IS NOT NULL ORDER BY id
    )
$$;

CREATE FUNCTION rootyard_ref_store_lock_public_operation(repo uuid, public_op uuid, proposed uuid DEFAULT NULL)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    ids uuid[];
    op uuid;
BEGIN
    IF repo IS NULL OR public_op IS NULL OR current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'public operation locks require a repository, operation and read committed transaction'
            USING ERRCODE = '55000';
    END IF;
    ids := rootyard_ref_store_attempt_ids(repo, public_op, proposed);
    FOREACH op IN ARRAY ids LOOP
        PERFORM pg_advisory_xact_lock(rootyard_ref_store_attempt_key(repo, op));
    END LOOP;
    IF ids IS DISTINCT FROM rootyard_ref_store_attempt_ids(repo, public_op, proposed) THEN
        RAISE EXCEPTION 'wrapper lock set changed' USING ERRCODE = '40001';
    END IF;
    PERFORM 1 FROM ref_store_public_operations WHERE repository_id = repo AND public_id = public_op FOR UPDATE;
END $$;

CREATE FUNCTION rootyard_ref_store_require_attempt_lock(repo uuid, op uuid) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory'
        AND objsubid = 1 AND mode = 'ExclusiveLock' AND granted
        AND ((classid::bigint << 32) | objid::bigint) = rootyard_ref_store_attempt_key(repo, op)
    ) THEN
        RAISE EXCEPTION 'operation advisory lock is required' USING ERRCODE = '55000';
    END IF;
END $$;

CREATE FUNCTION rootyard_ref_store_require_unclaimed_attempt(repo uuid, op uuid) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM rootyard_ref_store_require_attempt_lock(repo, op);
    IF EXISTS (SELECT FROM ref_store_operations WHERE (repository_id, operation_id) = (repo, op))
       OR EXISTS (SELECT FROM ref_store_cancellations WHERE (repository_id, operation_id) = (repo, op))
       OR EXISTS (SELECT FROM ref_store_public_operations WHERE (repository_id, public_id) = (repo, op))
       OR EXISTS (SELECT FROM ref_store_private_attempts WHERE (repository_id, private_id) = (repo, op)) THEN
        RAISE EXCEPTION 'operation identifier already claimed' USING ERRCODE = '23505';
    END IF;
END $$;

-- The repository lock protects the owner and lifecycle check. Serving writers
-- still hold the existing locks for authority, gate and protocol verification.
CREATE FUNCTION rootyard_ref_store_attempt_current_scope(w ref_store_public_operations)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
    repo repositories;
    gate_revision bigint;
BEGIN
    SELECT * INTO repo FROM repositories WHERE id = w.repository_id FOR SHARE;
    IF NOT FOUND OR repo.archived_at IS NOT NULL OR repo.deleted_at IS NOT NULL
       OR (repo.owner_id, repo.object_format, repo.state, repo.storage_backend, repo.transition_state)
          IS DISTINCT FROM (w.admission_owner_id, w.object_format, 'ready', 'pg_refstore', 'stable') THEN
        RAISE EXCEPTION 'public operation repository scope differs' USING ERRCODE = '23514';
    END IF;
    SELECT g.revision INTO gate_revision
    FROM ref_store_core_gates g
    JOIN ref_store_serving_repositories s USING (repository_id)
    JOIN ref_store_core_protocol_repos p USING (repository_id)
    JOIN public.cluster_authority c ON c.singleton
    WHERE g.repository_id = w.repository_id
      AND (g.tenant_id, g.object_format, g.history_incarnation, g.authority_epoch, g.group_epoch)
        = (w.admission_owner_id, w.object_format, w.history_incarnation, w.authority_epoch, w.group_epoch)
      AND (s.owner_id, s.object_format, s.history_incarnation, s.authority_epoch, s.group_epoch)
        = (g.tenant_id, g.object_format, g.history_incarnation, g.authority_epoch, g.group_epoch)
      AND (p.tenant_id, p.object_format, p.history_incarnation, p.authority_epoch, p.group_epoch)
        = (g.tenant_id, g.object_format, g.history_incarnation, g.authority_epoch, g.group_epoch)
      AND s.state = 'ready' AND s.name = repo.name AND p.decision_required
      AND s.backend_identity = w.backend_identity AND c.incarnation = w.restore_incarnation;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'public operation realm differs' USING ERRCODE = '23514';
    END IF;
    RETURN gate_revision;
END $$;

CREATE FUNCTION rootyard_ref_store_attempt_has_binding(w ref_store_public_operations, a ref_store_private_attempts)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT FROM ref_store_serving_operations s JOIN ref_store_operations o USING (repository_id, operation_id)
        WHERE (s.repository_id, s.operation_id) = ((a).repository_id, (a).private_id)
        AND (s.issuer_id, s.producer_request_digest, s.plan_parent_digest, o.issuer_id, o.request_digest)
            = ((w).issuer_id, (w).wire_digest, (a).plan_digest, (w).issuer_id, (a).plan_digest)
    )
$$;

CREATE FUNCTION rootyard_ref_store_attempt_stale_gate(w ref_store_public_operations, a ref_store_private_attempts)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
    gate_revision bigint;
BEGIN
    PERFORM rootyard_ref_store_require_attempt_lock(w.repository_id, a.private_id);
    IF NOT rootyard_ref_store_attempt_has_binding(w, a) THEN
        RAISE EXCEPTION 'stale attempt serving binding differs' USING ERRCODE = '23514';
    END IF;
    gate_revision := rootyard_ref_store_attempt_current_scope(w);
    IF gate_revision <= a.base_revision THEN
        RAISE EXCEPTION 'stale rejection requires an advanced gate' USING ERRCODE = '23514';
    END IF;
    RETURN gate_revision;
END $$;

CREATE FUNCTION rootyard_ref_store_public_operation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    attempt ref_store_private_attempts;
    gate_revision bigint;
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM rootyard_ref_store_require_unclaimed_attempt(NEW.repository_id, NEW.public_id);
        IF NEW.current_slot <> 0 OR NEW.state <> 'pending' THEN
            RAISE EXCEPTION 'public operation must begin pending on slot zero' USING ERRCODE = '23514';
        END IF;
        PERFORM rootyard_ref_store_attempt_current_scope(NEW);
        RETURN NEW;
    END IF;
    PERFORM rootyard_ref_store_require_attempt_lock(OLD.repository_id, OLD.public_id);
    IF (OLD.repository_id, OLD.public_id, OLD.admission_owner_id, OLD.issuer_id, OLD.wire_digest, OLD.request_mode,
        OLD.backend_identity, OLD.object_format, OLD.history_incarnation, OLD.authority_epoch, OLD.group_epoch, OLD.restore_incarnation)
        IS DISTINCT FROM
       (NEW.repository_id, NEW.public_id, NEW.admission_owner_id, NEW.issuer_id, NEW.wire_digest, NEW.request_mode,
        NEW.backend_identity, NEW.object_format, NEW.history_incarnation, NEW.authority_epoch, NEW.group_epoch, NEW.restore_incarnation)
       OR OLD.state <> 'pending' THEN
        RAISE EXCEPTION 'public operation identity or terminal is immutable' USING ERRCODE = '23514';
    END IF;
    FOR attempt IN SELECT * FROM ref_store_private_attempts WHERE (repository_id, public_id) = (OLD.repository_id, OLD.public_id)
    LOOP
        PERFORM rootyard_ref_store_require_attempt_lock(OLD.repository_id, attempt.private_id);
    END LOOP;
    IF NEW.current_slot = OLD.current_slot + 1 AND NEW.state = 'pending' THEN
        gate_revision := rootyard_ref_store_attempt_current_scope(OLD);
        IF NOT EXISTS (
            SELECT FROM ref_store_attempt_retirements r
            JOIN ref_store_core_events e ON e.event_id = r.event_id
            JOIN ref_store_private_attempts a
                ON (a.repository_id, a.public_id, a.slot) = (r.repository_id, r.public_id, NEW.current_slot)
            WHERE (r.repository_id, r.public_id, r.slot) = (OLD.repository_id, OLD.public_id, OLD.current_slot)
              AND e.revision = gate_revision AND a.base_revision = gate_revision
        ) THEN
            RAISE EXCEPTION 'rotation requires the current retirement and next attempt' USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.current_slot <> NEW.current_slot OR NEW.state = 'pending' THEN
        RAISE EXCEPTION 'invalid public operation transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION rootyard_ref_store_private_attempt_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    wrapper ref_store_public_operations;
    gate_revision bigint;
BEGIN
    PERFORM rootyard_ref_store_require_attempt_lock(NEW.repository_id, NEW.public_id);
    PERFORM rootyard_ref_store_require_unclaimed_attempt(NEW.repository_id, NEW.private_id);
    SELECT * INTO wrapper FROM ref_store_public_operations
    WHERE (repository_id, public_id) = (NEW.repository_id, NEW.public_id);
    IF NOT FOUND OR wrapper.state <> 'pending' THEN
        RAISE EXCEPTION 'public operation cannot reserve an attempt' USING ERRCODE = '23514';
    END IF;
    gate_revision := rootyard_ref_store_attempt_current_scope(wrapper);
    IF NEW.slot = 0 AND wrapper.current_slot = 0 THEN
        NULL; -- The primary key permits exactly one initial attempt.
    ELSIF NEW.slot = wrapper.current_slot + 1 AND NEW.slot <= 2 THEN
        IF NOT EXISTS (
            SELECT FROM ref_store_attempt_retirements r
            JOIN ref_store_core_events e ON e.event_id = r.event_id
            WHERE (r.repository_id, r.public_id, r.slot) = (NEW.repository_id, NEW.public_id, wrapper.current_slot)
              AND e.revision = gate_revision
        ) THEN
            RAISE EXCEPTION 'next attempt requires an exact retirement at the gate' USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'private attempt must occupy the next slot' USING ERRCODE = '23514';
    END IF;
    IF NEW.base_revision <> gate_revision THEN
        RAISE EXCEPTION 'private attempt base revision differs' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION rootyard_ref_store_attempt_retirement_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    wrapper ref_store_public_operations;
    retired ref_store_private_attempts;
    gate_revision bigint;
BEGIN
    PERFORM rootyard_ref_store_require_attempt_lock(NEW.repository_id, NEW.public_id);
    SELECT * INTO wrapper FROM ref_store_public_operations
    WHERE (repository_id, public_id) = (NEW.repository_id, NEW.public_id);
    SELECT * INTO retired FROM ref_store_private_attempts
    WHERE (repository_id, public_id, slot) = (NEW.repository_id, NEW.public_id, NEW.slot);
    IF retired.private_id IS NULL OR wrapper.state <> 'pending' OR wrapper.current_slot <> NEW.slot OR NEW.slot >= 2 THEN
        RAISE EXCEPTION 'retirement must select the current pending wrapper attempt' USING ERRCODE = '23514';
    END IF;
    gate_revision := rootyard_ref_store_attempt_stale_gate(wrapper, retired);
    IF NOT EXISTS (
        SELECT FROM ref_store_core_events e
        JOIN ref_store_operations o USING (repository_id, operation_id)
        WHERE (e.repository_id, e.operation_id, e.event_id, e.revision)
            = (NEW.repository_id, retired.private_id, NEW.event_id, gate_revision)
        AND (o.state, e.outcome, e.payload, e.payload->>'kind', e.payload->'repository_id', e.payload->'revision')
            = ('rejected', 'rejected', o.terminal_result, 'rejected', to_jsonb(NEW.repository_id), to_jsonb(gate_revision))
        AND e.payload#>>'{rejection,code}' = 'revision_mismatch'
        AND e.payload->'registrations' = '[]'::jsonb
    ) THEN
        RAISE EXCEPTION 'retirement requires the exact current revision mismatch' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION rootyard_ref_store_attempt_retain() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF NOT EXISTS (SELECT FROM repositories WHERE id = OLD.repository_id) THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'public operation history is retained while its repository exists' USING ERRCODE = '55000';
END $$;

CREATE TRIGGER ref_store_public_operation_guard BEFORE INSERT OR UPDATE ON ref_store_public_operations
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_public_operation_guard();
CREATE TRIGGER ref_store_private_attempt_insert BEFORE INSERT ON ref_store_private_attempts
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_private_attempt_insert();
CREATE TRIGGER ref_store_public_operation_retain BEFORE DELETE ON ref_store_public_operations
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_attempt_retain();
CREATE TRIGGER ref_store_private_attempt_retain BEFORE UPDATE OR DELETE ON ref_store_private_attempts
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_attempt_retain();
CREATE TRIGGER ref_store_public_operation_no_truncate BEFORE TRUNCATE ON ref_store_public_operations
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_attempt_retain();
CREATE TRIGGER ref_store_private_attempt_no_truncate BEFORE TRUNCATE ON ref_store_private_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_attempt_retain();

-- Check the committed shape after the 138 terminal, 139 event and public link
-- have been staged. The adapter must fence private core DML and update the
-- wrapper in the same transaction as terminal, cancellation or rotation DML.
CREATE FUNCTION rootyard_ref_store_verify_public_operation(repo uuid, public_op uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    wrapper ref_store_public_operations;
    attempt record;
    expected_slot smallint := 0;
    previous_lane text;
    previous_sequence bigint;
BEGIN
    SELECT * INTO wrapper FROM ref_store_public_operations WHERE (repository_id, public_id) = (repo, public_op);
    IF NOT FOUND THEN RETURN; END IF;
    FOR attempt IN
        SELECT a.slot, a.private_id, a.base_revision, next.base_revision AS next_base,
               o.state AS core_state, o.terminal_result, o.lane, o.sequence,
               r.event_id AS retired_event_id,
               e.event_id, e.outcome, e.payload, e.revision,
               rootyard_ref_store_attempt_has_binding(wrapper, a) AS serving_bound,
               c.operation_id IS NOT NULL AS has_tombstone,
               c.operation_id IS DISTINCT FROM k.operation_id AS tombstone_key_differs,
               (c.issuer_id, c.lane, c.sequence, c.request_digest) = (o.issuer_id, o.lane, o.sequence, o.request_digest) AS exact_tombstone
        FROM ref_store_private_attempts a
        LEFT JOIN ref_store_private_attempts next ON (next.repository_id, next.public_id, next.slot)
            = (a.repository_id, a.public_id, a.slot + 1)
        LEFT JOIN ref_store_attempt_retirements r ON (r.repository_id, r.public_id, r.slot)
            = (a.repository_id, a.public_id, a.slot)
        LEFT JOIN ref_store_operations o ON (o.repository_id, o.operation_id) = (a.repository_id, a.private_id)
        LEFT JOIN ref_store_core_events e ON (e.repository_id, e.operation_id) = (a.repository_id, a.private_id)
        LEFT JOIN ref_store_cancellations c ON (c.repository_id, c.operation_id) = (a.repository_id, a.private_id)
        LEFT JOIN ref_store_cancellations k ON (k.repository_id, k.issuer_id, k.lane, k.sequence)
            = (o.repository_id, o.issuer_id, o.lane, o.sequence)
        WHERE (a.repository_id, a.public_id) = (repo, public_op)
        ORDER BY a.slot
    LOOP
        IF NOT attempt.serving_bound
           OR attempt.slot <> expected_slot
           OR attempt.slot > wrapper.current_slot
           OR (attempt.slot > 0 AND (attempt.lane IS DISTINCT FROM previous_lane
                                   OR (attempt.sequence > previous_sequence) IS NOT TRUE))
           OR attempt.tombstone_key_differs
           OR (attempt.has_tombstone AND (attempt.exact_tombstone IS NOT TRUE OR attempt.core_state = 'pending'))
           OR (attempt.core_state = 'cancelled' AND
               (NOT attempt.has_tombstone
                OR attempt.terminal_result IS DISTINCT FROM '{"state":"cancelled","reason":"cancel_requested"}'::jsonb))
           OR (attempt.event_id IS NOT NULL AND
               (attempt.outcome IS DISTINCT FROM attempt.core_state
                OR attempt.payload IS DISTINCT FROM attempt.terminal_result
                OR attempt.payload->>'kind' IS DISTINCT FROM attempt.core_state
                OR attempt.payload->'repository_id' IS DISTINCT FROM to_jsonb(repo)
                OR attempt.payload->'revision' IS DISTINCT FROM to_jsonb(attempt.revision)))
           OR (attempt.slot < wrapper.current_slot AND
               (attempt.core_state IS DISTINCT FROM 'rejected' OR attempt.retired_event_id IS NULL
                OR attempt.event_id IS DISTINCT FROM attempt.retired_event_id
                OR (attempt.revision > attempt.base_revision) IS NOT TRUE
                OR attempt.next_base IS DISTINCT FROM attempt.revision
                OR attempt.payload#>>'{rejection,code}' IS DISTINCT FROM 'revision_mismatch'
                OR attempt.payload->'registrations' IS DISTINCT FROM '[]'::jsonb))
           OR (attempt.slot = wrapper.current_slot AND
               (attempt.retired_event_id IS NOT NULL OR attempt.core_state IS DISTINCT FROM wrapper.state
                OR (wrapper.state = 'cancelled' AND attempt.private_id IS DISTINCT FROM wrapper.cancelled_private_id)
                OR attempt.event_id IS DISTINCT FROM wrapper.event_id)) THEN
            RAISE EXCEPTION 'public operation and private attempt evidence disagree'
                USING ERRCODE = '23514', CONSTRAINT = 'ref_store_public_attempt_evidence';
        END IF;
        expected_slot := expected_slot + 1;
        previous_lane := attempt.lane;
        previous_sequence := attempt.sequence;
    END LOOP;
    IF expected_slot <> wrapper.current_slot + 1 THEN
        RAISE EXCEPTION 'public operation does not have a complete attempt prefix'
            USING ERRCODE = '23514', CONSTRAINT = 'ref_store_public_attempt_evidence';
    END IF;
END $$;

CREATE FUNCTION rootyard_ref_store_public_operation_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM rootyard_ref_store_verify_public_operation(NEW.repository_id, NEW.public_id);
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER ref_store_public_operation_evidence AFTER INSERT OR UPDATE ON ref_store_public_operations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_public_operation_evidence();
CREATE CONSTRAINT TRIGGER ref_store_private_attempt_evidence AFTER INSERT ON ref_store_private_attempts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_public_operation_evidence();

CREATE TRIGGER ref_store_attempt_retirement_insert BEFORE INSERT ON ref_store_attempt_retirements
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_attempt_retirement_insert();
CREATE TRIGGER ref_store_attempt_retirement_retain BEFORE UPDATE OR DELETE ON ref_store_attempt_retirements
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_attempt_retain();
CREATE TRIGGER ref_store_attempt_retirement_no_truncate BEFORE TRUNCATE ON ref_store_attempt_retirements
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_attempt_retain();
CREATE CONSTRAINT TRIGGER ref_store_attempt_retirement_evidence AFTER INSERT ON ref_store_attempt_retirements
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_public_operation_evidence();

-- Legacy cancellation callers need no privileges on the new tables. Only the
-- installed trigger may run this read-only verifier in its owning schema.
CREATE FUNCTION rootyard_ref_store_private_cancellation_evidence() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    public_op uuid;
BEGIN
    PERFORM set_config('search_path', format('pg_catalog, %I, pg_temp', TG_TABLE_SCHEMA), true);
    FOR public_op IN
        SELECT a.public_id FROM ref_store_private_attempts a
        WHERE (a.repository_id, a.private_id) = (NEW.repository_id, NEW.operation_id)
        UNION
        SELECT a.public_id FROM ref_store_operations o JOIN ref_store_private_attempts a
            ON (a.repository_id, a.private_id) = (o.repository_id, o.operation_id)
        WHERE (o.repository_id, o.issuer_id, o.lane, o.sequence) = (NEW.repository_id, NEW.issuer_id, NEW.lane, NEW.sequence)
    LOOP
        PERFORM rootyard_ref_store_verify_public_operation(NEW.repository_id, public_op);
    END LOOP;
    RETURN NULL;
END $$;

REVOKE EXECUTE ON FUNCTION rootyard_ref_store_private_cancellation_evidence() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER ref_store_private_cancellation_evidence AFTER INSERT OR UPDATE ON ref_store_cancellations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_private_cancellation_evidence();

INSERT INTO schema_migrations (version) VALUES (152) ON CONFLICT DO NOTHING;
