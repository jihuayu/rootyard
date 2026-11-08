-- Durable operation identity for the transitional PostgreSQL RefStore adapter.
--
-- This migration does NOT add read snapshots, durable pins, roots, holds,
-- publication decisions, GC integration or Raft state. It records one stable
-- operation identity, cancellation tombstones and an immutable terminal result
-- in the same transaction as the existing Pando ref/pack CAS. Existing Pando
-- long read leases remain the only read protection.
--
-- The root branch will serialize migration numbers; keep this file name clear
-- if it is renumbered. Do not auto-trim these rows: sequence cutoffs are not
-- closed by this increment.
CREATE TABLE ref_store_issuer_lanes (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    issuer_id UUID NOT NULL,
    lane TEXT NOT NULL CHECK (
        octet_length(lane) BETWEEN 1 AND 64
        AND lane !~ '[^A-Za-z0-9._:-]'
    ),
    last_reserved_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_reserved_sequence >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, issuer_id, lane)
);

CREATE TABLE ref_store_operations (
    repository_id UUID NOT NULL,
    issuer_id UUID NOT NULL,
    lane TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    operation_id UUID NOT NULL,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('pending','committed','rejected','cancelled')),
    terminal_result JSONB CHECK (terminal_result IS NULL OR jsonb_typeof(terminal_result) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    terminal_at TIMESTAMPTZ,
    PRIMARY KEY (repository_id, operation_id),
    UNIQUE (repository_id, issuer_id, lane, sequence),
    FOREIGN KEY (repository_id, issuer_id, lane)
        REFERENCES ref_store_issuer_lanes(repository_id, issuer_id, lane) ON DELETE CASCADE,
    CHECK ((state = 'pending') = (terminal_at IS NULL)),
    CHECK ((state = 'pending') = (terminal_result IS NULL))
);

CREATE INDEX ref_store_operations_lane_state
    ON ref_store_operations(repository_id, issuer_id, lane, state, sequence);

-- A cancel may be recorded before its operation is registered. This row is the
-- durable winner; registration observes it and inserts a terminal cancelled
-- operation instead of a pending one. Tombstones are never trimmed here.
CREATE TABLE ref_store_cancellations (
    repository_id UUID NOT NULL,
    issuer_id UUID NOT NULL,
    lane TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    operation_id UUID NOT NULL,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, issuer_id, lane, sequence),
    UNIQUE (repository_id, operation_id),
    FOREIGN KEY (repository_id, issuer_id, lane)
        REFERENCES ref_store_issuer_lanes(repository_id, issuer_id, lane) ON DELETE CASCADE
);

-- A pending operation may become terminal exactly once. Identity columns and a
-- terminal result can never be rewritten; a replay must return the stored row.
CREATE FUNCTION rootyard_ref_store_operation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.repository_id, NEW.issuer_id, NEW.lane, NEW.sequence,
        NEW.operation_id, NEW.request_digest)
       IS DISTINCT FROM
       (OLD.repository_id, OLD.issuer_id, OLD.lane, OLD.sequence,
        OLD.operation_id, OLD.request_digest)
    THEN
        RAISE EXCEPTION 'ref-store operation identity is immutable';
    END IF;
    IF OLD.state <> 'pending' THEN
        RAISE EXCEPTION 'ref-store terminal operation result is immutable';
    END IF;
    IF NEW.state = 'pending' THEN
        RAISE EXCEPTION 'ref-store pending operation update must become terminal';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER ref_store_operation_immutable
    BEFORE UPDATE ON ref_store_operations
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_operation_immutable();

CREATE FUNCTION rootyard_ref_store_cancellation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ref-store cancellation tombstone is immutable';
END $$;
CREATE TRIGGER ref_store_cancellation_immutable
    BEFORE UPDATE ON ref_store_cancellations
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_cancellation_immutable();

INSERT INTO schema_migrations (version) VALUES (138) ON CONFLICT DO NOTHING;
