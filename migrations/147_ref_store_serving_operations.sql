-- ===========================================================================
-- Migration 147 — durable producer-request binding for the served write path
-- (issue #144 exact HTTP replay / A3 integration).
--
-- Problem this table solves (and the reason it exists at all):
--
-- The core A3/A4 identity invariant is
--   `ref_store_operations.request_digest == PackCommitPlan::parent_digest`
--   `== A3 acquire/consume receipt.operation_digest`
--   `== stored registration ACK.parent_digest`.
-- Registration (`registered_pack`), the stored-registration reader and the A3
-- ledger all enforce that equality. It therefore must never be rewritten to
-- carry an HTTP wire digest: doing so unbinds every A3 receipt from the core
-- plan parent that the durable registration was written under.
--
-- The served HTTP path additionally needs ONE stable value to answer an exact
-- retry *before* running native Git or any A3/A4 write: the producer's request
-- digest over the decoded wire body plus repository/operation/format/mode/
-- commands (see `blob_git_gateway::operation::request_digest`). That binding is
-- deliberately kept in this SEPARATE table instead of overwriting the core
-- identity, so every existing library/A4/A3/registration path keeps its
-- original `identity.digest == parent_digest` semantics byte for byte.
--
-- Shape and lifetime:
--
--   * one fixed-width row per already quota-bounded migration-138 write
--     operation (`PRIMARY KEY (repository_id, operation_id)`), so this table can
--     never grow faster than the operation registry it is keyed by;
--   * `producer_request_digest` is the 64-hex producer wire digest;
--     `plan_parent_digest` is the *core* canonical plan parent digest and must
--     equal the parent operation's migration-138 `request_digest`;
--   * the row is written in the SAME transaction that inserts the pending
--     migration-138 operation, so a pending row and its producer binding are
--     atomic (a `COMMIT` acknowledges both, a rollback discards both);
--   * INSERT is only accepted for the identical issuer of a *pending* 138
--     operation whose `request_digest` equals `plan_parent_digest`; a known
--     operation without such a row can never be replayed as an ordinary Git
--     result by the serving endpoint (the gateway returns a typed conflict);
--   * UPDATE and TRUNCATE are always refused; DELETE is only reachable through
--     the parent `ref_store_operations` ON DELETE CASCADE. Reusing an existing
--     operation id with a different wire request is therefore impossible: the
--     mapping is immutable and the 138 identity is immutable.
--
-- What is deliberately absent: no per-GET / per-read row (serving reads keep
-- their own transient table in migration 146), no counters, no quota table, no
-- refund/GC consumer, no roots/decisions, no duplicate copy of the A3 ledger,
-- no derived or truncated UUID "proof" of any kind. This migration adds no
-- second write authority and no new route.
--
-- RESERVED migration number: like migration 141, this file is NOT registered
-- until Root integrates the module wiring and regenerates the true PostgreSQL
-- catalogs. It contains no hand-written catalog copy.
-- ===========================================================================

CREATE TABLE ref_store_serving_operations (
    repository_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    -- Issuer of the parent migration-138 operation. Not a new authority: it is
    -- only the value the insert guard below compares for exactness.
    issuer_id UUID NOT NULL,
    -- 64-hex producer request digest over the decoded wire body plus
    -- repository/operation/format/mode/commands. Never the core plan digest.
    producer_request_digest TEXT NOT NULL CHECK (producer_request_digest ~ '^[0-9a-f]{64}$'),
    -- 64-hex core canonical plan parent digest. Must equal the parent
    -- operation's migration-138 request_digest (checked by the insert guard).
    plan_parent_digest TEXT NOT NULL CHECK (plan_parent_digest ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, operation_id),
    -- The parent operation is the only owner of this binding: deleting the
    -- operation row is the only way a binding disappears.
    FOREIGN KEY (repository_id, operation_id)
        REFERENCES ref_store_operations(repository_id, operation_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 1. Insert may only bind a pending operation of the same issuer under the
--    exact core parent digest. This is a durable-SQL recheck of the same
--    invariant the typed writer enforces; a row can never be planted for a
--    foreign issuer, a terminal operation or a different plan parent.
-- ---------------------------------------------------------------------------
CREATE FUNCTION rootyard_ref_store_serving_operation_bind() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    parent_issuer UUID;
    parent_digest TEXT;
    parent_state TEXT;
BEGIN
    SELECT o.issuer_id, o.request_digest, o.state
      INTO parent_issuer, parent_digest, parent_state
      FROM ref_store_operations o
     WHERE o.repository_id = NEW.repository_id AND o.operation_id = NEW.operation_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving producer binding requires its migration-138 operation';
    END IF;
    IF NEW.issuer_id <> parent_issuer THEN
        RAISE EXCEPTION 'serving producer binding issuer differs from its operation';
    END IF;
    IF parent_state <> 'pending' THEN
        RAISE EXCEPTION 'serving producer binding requires a pending operation';
    END IF;
    IF NEW.plan_parent_digest <> parent_digest THEN
        RAISE EXCEPTION 'serving producer binding parent digest differs from the operation request digest';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER ref_store_serving_operation_bind
    BEFORE INSERT ON ref_store_serving_operations
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_serving_operation_bind();

-- ---------------------------------------------------------------------------
-- 2. A binding is immutable: no UPDATE, no TRUNCATE (not even cascaded from a
--    parent TRUNCATE). Only INSERT and the parent operation's DELETE cascade
--    may change this table.
-- ---------------------------------------------------------------------------
CREATE FUNCTION rootyard_ref_store_serving_operation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ref-store serving producer binding is immutable';
END $$;

CREATE TRIGGER ref_store_serving_operation_immutable
    BEFORE UPDATE ON ref_store_serving_operations
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_serving_operation_immutable();

CREATE TRIGGER ref_store_serving_operation_no_truncate
    BEFORE TRUNCATE ON ref_store_serving_operations
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_serving_operation_immutable();

-- ---------------------------------------------------------------------------
-- 3. DELETE is only reachable through the parent ON DELETE CASCADE.
--
--    The foreign key is immediate (not deferred), so by the time a cascaded
--    child delete reaches this trigger the parent `ref_store_operations` row is
--    already gone. A direct DELETE of a child row always still has its parent,
--    so this predicate refuses it deterministically without relying on trigger
--    nesting depth heuristics.
-- ---------------------------------------------------------------------------
CREATE FUNCTION rootyard_ref_store_serving_operation_cascade_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM ref_store_operations o
         WHERE o.repository_id = OLD.repository_id AND o.operation_id = OLD.operation_id
    ) THEN
        RAISE EXCEPTION 'serving producer binding may only be deleted by its operation cascade';
    END IF;
    RETURN OLD;
END $$;

CREATE TRIGGER ref_store_serving_operation_cascade_only
    BEFORE DELETE ON ref_store_serving_operations
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_serving_operation_cascade_only();

INSERT INTO schema_migrations (version) VALUES (147) ON CONFLICT DO NOTHING;
