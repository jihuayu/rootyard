-- Experimental overlay for the rollback-only schema 152 fixture.
-- This shape is for pre-activation qualification on a fresh attempt catalog.

DO $$
BEGIN
    IF EXISTS (SELECT FROM ref_store_public_operations) THEN
        RAISE EXCEPTION 'three-attempt overlay requires an empty wrapper catalog';
    END IF;
END $$;

ALTER TABLE ref_store_public_operations
    DROP COLUMN retired_event_id,
    DROP CONSTRAINT ref_store_public_operations_current_slot_check,
    ADD CONSTRAINT ref_store_public_operations_current_slot_check CHECK (current_slot IN (0, 1, 2));
ALTER TABLE ref_store_private_attempts
    DROP CONSTRAINT ref_store_private_attempts_slot_check,
    ADD CONSTRAINT ref_store_private_attempts_slot_check CHECK (slot IN (0, 1, 2));

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

CREATE TRIGGER ref_store_attempt_retirement_insert BEFORE INSERT ON ref_store_attempt_retirements
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_attempt_retirement_insert();
CREATE TRIGGER ref_store_attempt_retirement_retain BEFORE UPDATE OR DELETE ON ref_store_attempt_retirements
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_attempt_retain();
CREATE TRIGGER ref_store_attempt_retirement_no_truncate BEFORE TRUNCATE ON ref_store_attempt_retirements
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_attempt_retain();
CREATE CONSTRAINT TRIGGER ref_store_attempt_retirement_evidence AFTER INSERT ON ref_store_attempt_retirements
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_public_operation_evidence();

CREATE OR REPLACE FUNCTION rootyard_ref_store_public_operation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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

CREATE OR REPLACE FUNCTION rootyard_ref_store_private_attempt_insert() RETURNS trigger LANGUAGE plpgsql AS $$
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

-- Deferred readback proves ordered contiguous history and all existing M138/M139/M147 bindings,
-- alongside immediate exact predecessor and saved-gate checks in the transition.
CREATE OR REPLACE FUNCTION rootyard_ref_store_verify_public_operation(repo uuid, public_op uuid)
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
