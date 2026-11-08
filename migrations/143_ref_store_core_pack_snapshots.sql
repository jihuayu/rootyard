-- A5a: complete registered-pack-membership snapshots + durable pin + permanent
-- pack-snapshot history/usage (#107 foundation).
--
-- This migration is ADDITIVE over the frozen format-18/schema-142 surface: the
-- migration-141/142 tables keep their exact shape (only one reviewed composite
-- UNIQUE INDEX is added so a snapshot binding can carry a RESTRICT foreign key),
-- and the migration-140 snapshot header gains nullable/defaulted pack columns in
-- place. Every existing A2 row stays valid: `pack_mode` defaults to
-- 'metadata_only', `pack_count` to 0, both pack digests stay NULL and
-- `pack_membership_state` stays 'unavailable', so an old A2 receipt body
-- decodes and replays byte-identically.
--
-- What this migration does NOT claim: no verified Blob byte read, no native Git
-- closure, no `ReadSnapshot` serving route, no roots/decisions/accepted subsets,
-- no GC/detach/compaction, no encryption and no Blob-byte backup. A row written
-- here records the *registered* pack membership captured under one gate lock; it
-- is data, never a write proof, capability or Git-read attestation.
--
-- Lifetime boundaries:
--   * `ref_store_core_snapshot_packs` follows its snapshot/pin A2 lifetime: it
--     cascades only through a legitimate whole-repository delete, and a direct
--     row DML while the repository still exists is refused.
--   * `ref_store_core_pack_snapshot_history` and the two permanent usage tables
--     have NO business/repository/tenant foreign key. They survive repository,
--     user and tenant deletion, and are immutable/no-delete/no-truncate. The
--     counters are monotone: no refund, TTL deletion or reset path exists, so a
--     retained quota can never be re-granted by deleting a row.

-- ---------------------------------------------------------------------------
-- 1. Reviewed composite unique key on the UNCHANGED migration-142 membership
--    table. It is required before the new composite RESTRICT foreign key below
--    can bind `(repository_id, registration_id, pack_id, artifact_set_digest)`.
--    The tuple is trivially unique (the table's primary key is
--    `(repository_id, pack_id)`); migration 141/142 files are not modified.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX ref_store_core_pack_memberships_snapshot_identity
    ON ref_store_core_pack_memberships(repository_id, registration_id, pack_id, artifact_set_digest);

-- ---------------------------------------------------------------------------
-- 2. Additive pack columns on the A2 snapshot header.
--
--    The migration-140 column check is replaced (not dropped-and-forgotten) by
--    an equivalent table check that allows exactly two shapes:
--      metadata_only   -> pack_membership_state 'unavailable', 0 packs, no digests
--      pack_verified   -> pack_membership_state 'complete', 1..16 packs, both
--                         64-hex digests present
--    so a partially written or hand-edited header is impossible.
-- ---------------------------------------------------------------------------
ALTER TABLE ref_store_core_snapshots
    DROP CONSTRAINT ref_store_core_snapshots_pack_membership_state_check;

ALTER TABLE ref_store_core_snapshots
    ADD COLUMN pack_mode TEXT NOT NULL DEFAULT 'metadata_only'
        CHECK (pack_mode IN ('metadata_only','pack_verified')),
    ADD COLUMN pack_count INTEGER NOT NULL DEFAULT 0
        CHECK (pack_count >= 0 AND pack_count <= 16),
    ADD COLUMN membership_digest TEXT,
    ADD COLUMN snapshot_digest TEXT;

ALTER TABLE ref_store_core_snapshots
    ADD CONSTRAINT ref_store_core_snapshots_pack_state_check CHECK (
        (
            pack_mode = 'metadata_only'
            AND pack_membership_state = 'unavailable'
            AND pack_count = 0
            AND membership_digest IS NULL
            AND snapshot_digest IS NULL
        )
        OR (
            pack_mode = 'pack_verified'
            AND pack_membership_state = 'complete'
            AND pack_count >= 1
            -- PostgreSQL accepts a CHECK that evaluates to NULL, and a regex on a
            -- NULL column is NULL, so BOTH digests need an explicit
            -- `IS NOT NULL` term as well as the regex. Without it a pack row could
            -- be stored with a NULL digest and still pass the check.
            AND membership_digest IS NOT NULL AND membership_digest ~ '^[0-9a-f]{64}$'
            AND snapshot_digest IS NOT NULL AND snapshot_digest ~ '^[0-9a-f]{64}$'
        )
    );

-- ---------------------------------------------------------------------------
-- 3. Snapshot -> registered pack bindings.
--
--    One row per captured active membership. The composite foreign key to the
--    migration-142 membership tuple is RESTRICT (never cascade): a snapshot
--    binding this pack permanently blocks any membership detach/replacement. The
--    snapshot/tenant/repository side cascades only with a legitimate
--    whole-repository delete (the A2 snapshot delete guard already refuses a
--    direct delete while the repository row exists).
--
--    `joined_revision` is re-read from the publication by the adapter
--    (`joined_revision = publication.gate_revision + 1 <= snapshot.gate_revision`)
--    and must equal this stored value; the row alone is not trusted.
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_core_snapshot_packs (
    repository_id UUID NOT NULL,
    snapshot_id UUID NOT NULL,
    pack_id UUID NOT NULL,
    registration_id UUID NOT NULL,
    artifact_set_digest TEXT NOT NULL CHECK (artifact_set_digest ~ '^[0-9a-f]{64}$'),
    joined_revision BIGINT NOT NULL CHECK (joined_revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (snapshot_id, pack_id),
    FOREIGN KEY (repository_id, snapshot_id)
        REFERENCES ref_store_core_snapshots(repository_id, snapshot_id) ON DELETE CASCADE,
    FOREIGN KEY (repository_id, registration_id, pack_id, artifact_set_digest)
        REFERENCES ref_store_core_pack_memberships(repository_id, registration_id, pack_id, artifact_set_digest)
        ON DELETE RESTRICT
);

CREATE INDEX ref_store_core_snapshot_packs_registration
    ON ref_store_core_snapshot_packs(repository_id, registration_id, pack_id);

-- A binding is immutable; only the legitimate whole-repository cascade may
-- remove it (the parent repository row is already gone inside that same
-- transaction). Direct DELETE/TRUNCATE while the repository exists is refused.
CREATE FUNCTION rootyard_ref_store_core_snapshot_packs_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ref-store core pack snapshot binding is immutable';
END $$;

CREATE FUNCTION rootyard_ref_store_core_snapshot_packs_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM repositories WHERE id = OLD.repository_id) THEN
        RAISE EXCEPTION 'ref-store core pack snapshot binding cannot be deleted while its repository exists';
    END IF;
    RETURN OLD;
END $$;

CREATE TRIGGER ref_store_core_snapshot_packs_immutable
    BEFORE UPDATE ON ref_store_core_snapshot_packs
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_snapshot_packs_immutable();
CREATE TRIGGER ref_store_core_snapshot_packs_delete_guard
    BEFORE DELETE ON ref_store_core_snapshot_packs
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_snapshot_packs_delete_guard();
CREATE TRIGGER ref_store_core_snapshot_packs_no_truncate
    BEFORE TRUNCATE ON ref_store_core_snapshot_packs
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_snapshot_packs_immutable();

-- ---------------------------------------------------------------------------
-- 4. Permanent pack-snapshot history ledger (NO business foreign key).
--
--    One row per successful pack-snapshot create/renew/release, written in the
--    same transaction as its A2 receipt with the same canonical body bytes. It
--    survives repository/user deletion, so the exact historical receipt can be
--    resolved after the business rows are gone (`query_receipt`), and it records
--    the immutable snapshot identity (gate revision/digest, pack mode, refs and
--    membership digests, pack count, canonical snapshot digest) for every
--    mutation, including duplicates.
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_core_pack_snapshot_history (
    history_id UUID PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    snapshot_id UUID NOT NULL,
    pin_id UUID NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('created','renewed','released')),
    -- The exact canonical request digest the operation was admitted with, so a
    -- retention-only replay of this row is exact over EVERY request field
    -- (lease, release reason, expected gate revision/digest, scope, ids).
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    -- The historical gate proof captured with the snapshot, not the current gate.
    gate_revision BIGINT NOT NULL CHECK (gate_revision > 0),
    gate_digest TEXT NOT NULL CHECK (gate_digest ~ '^[0-9a-f]{64}$'),
    pack_mode TEXT NOT NULL CHECK (pack_mode = 'pack_verified'),
    refs_digest TEXT NOT NULL CHECK (refs_digest ~ '^[0-9a-f]{64}$'),
    membership_digest TEXT NOT NULL CHECK (membership_digest ~ '^[0-9a-f]{64}$'),
    pack_count INTEGER NOT NULL CHECK (pack_count >= 1 AND pack_count <= 16),
    snapshot_digest TEXT NOT NULL CHECK (snapshot_digest ~ '^[0-9a-f]{64}$'),
    -- Canonical retained-size accounting copied from the immutable header, so the
    -- permanent ledger alone can bound and audit what it retains.
    ref_count INTEGER NOT NULL CHECK (ref_count >= 0 AND ref_count <= 4096),
    logical_bytes BIGINT NOT NULL CHECK (logical_bytes > 0),
    body TEXT NOT NULL CHECK (octet_length(body) > 0 AND octet_length(body) <= 4096),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX ref_store_core_pack_snapshot_history_repository
    ON ref_store_core_pack_snapshot_history(repository_id, created_at);
CREATE INDEX ref_store_core_pack_snapshot_history_snapshot
    ON ref_store_core_pack_snapshot_history(snapshot_id, created_at);

CREATE TRIGGER ref_store_core_pack_snapshot_history_immutable
    BEFORE UPDATE OR DELETE ON ref_store_core_pack_snapshot_history
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_snapshot_history_no_truncate
    BEFORE TRUNCATE ON ref_store_core_pack_snapshot_history
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();

-- ---------------------------------------------------------------------------
-- 5. Permanent, no-cascade retained usage counters.
--
--    The migration-140 A2 counters cascade away with the repository/tenant, so
--    they cannot bound permanent history. These two tables carry NO foreign key
--    at all and are the permanent admission counters for every retained pack
--    snapshot row: snapshot headers, captured ref rows, pack bindings, pins,
--    history rows, receipts and logical bytes. A2's own counters are still
--    charged in the same transaction for the repository-lifetime rows; the two
--    sets bound two different lifetimes and are deliberately independent.
--
--    Fixed bounds (contract constants in
--    src/ref_store/core/pack_snapshot/contract.rs; tenant = exactly 4x repo for
--    every counter):
--      repo:   snapshots 64, refs 16384, bindings 1024, pins 64,
--              history 2048, receipts 2048, logical bytes 16 MiB
--      tenant: snapshots 256, refs 65536, bindings 4096, pins 256,
--              history 8192, receipts 8192, logical bytes 64 MiB
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_core_pack_snapshot_repo_usage (
    repository_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    snapshot_count BIGINT NOT NULL DEFAULT 0 CHECK (snapshot_count >= 0 AND snapshot_count <= 64),
    snapshot_ref_count BIGINT NOT NULL DEFAULT 0 CHECK (snapshot_ref_count >= 0 AND snapshot_ref_count <= 16384),
    binding_count BIGINT NOT NULL DEFAULT 0 CHECK (binding_count >= 0 AND binding_count <= 1024),
    pin_count BIGINT NOT NULL DEFAULT 0 CHECK (pin_count >= 0 AND pin_count <= 64),
    history_count BIGINT NOT NULL DEFAULT 0 CHECK (history_count >= 0 AND history_count <= 2048),
    receipt_count BIGINT NOT NULL DEFAULT 0 CHECK (receipt_count >= 0 AND receipt_count <= 2048),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0 AND logical_bytes <= 16777216)
);

CREATE TABLE ref_store_core_pack_snapshot_tenant_usage (
    tenant_id UUID PRIMARY KEY,
    snapshot_count BIGINT NOT NULL DEFAULT 0 CHECK (snapshot_count >= 0 AND snapshot_count <= 256),
    snapshot_ref_count BIGINT NOT NULL DEFAULT 0 CHECK (snapshot_ref_count >= 0 AND snapshot_ref_count <= 65536),
    binding_count BIGINT NOT NULL DEFAULT 0 CHECK (binding_count >= 0 AND binding_count <= 4096),
    pin_count BIGINT NOT NULL DEFAULT 0 CHECK (pin_count >= 0 AND pin_count <= 256),
    history_count BIGINT NOT NULL DEFAULT 0 CHECK (history_count >= 0 AND history_count <= 8192),
    receipt_count BIGINT NOT NULL DEFAULT 0 CHECK (receipt_count >= 0 AND receipt_count <= 8192),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0 AND logical_bytes <= 67108864)
);

--
-- The identity of a counter row is *every* column that is not a counter, so this
-- one function is safe for both row shapes: the tenant row has only `tenant_id`
-- and the repository row has `repository_id` + `tenant_id`. It is expressed over
-- the whole row instead of naming `repository_id`, because a repo row whose
-- `repository_id` could be moved would otherwise be re-pointed at another
-- repository and a fresh zero row re-inserted there — silently re-granting the
-- retained budget. Identity is compared with `to_jsonb` on both rows with the
-- counter keys removed, so no future non-counter column can be mutated either.
CREATE FUNCTION rootyard_ref_store_core_pack_snapshot_usage_monotone() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    counter_keys CONSTANT text[] := ARRAY[
        'snapshot_count','snapshot_ref_count','binding_count','pin_count','history_count','receipt_count',
        'logical_bytes'
    ];
    old_identity jsonb := to_jsonb(OLD);
    new_identity jsonb := to_jsonb(NEW);
BEGIN
    old_identity := old_identity - counter_keys;
    new_identity := new_identity - counter_keys;
    IF new_identity <> old_identity THEN
        RAISE EXCEPTION 'pack snapshot usage row identity is immutable';
    END IF;
    IF NEW.snapshot_count < OLD.snapshot_count
       OR NEW.snapshot_ref_count < OLD.snapshot_ref_count
       OR NEW.binding_count < OLD.binding_count
       OR NEW.pin_count < OLD.pin_count
       OR NEW.history_count < OLD.history_count
       OR NEW.receipt_count < OLD.receipt_count
       OR NEW.logical_bytes < OLD.logical_bytes THEN
        RAISE EXCEPTION 'pack snapshot usage counters are monotone and cannot be refunded';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER ref_store_core_pack_snapshot_repo_usage_monotone
    BEFORE UPDATE ON ref_store_core_pack_snapshot_repo_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_snapshot_usage_monotone();
CREATE TRIGGER ref_store_core_pack_snapshot_tenant_usage_monotone
    BEFORE UPDATE ON ref_store_core_pack_snapshot_tenant_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_snapshot_usage_monotone();

-- Usage rows are permanent: a deleted/truncated counter row would silently
-- re-grant retained budget, so both operations are refused unconditionally
-- (unlike the A2 counters, there is no cascade lifetime here at all).
CREATE TRIGGER ref_store_core_pack_snapshot_repo_usage_no_delete
    BEFORE DELETE ON ref_store_core_pack_snapshot_repo_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_snapshot_repo_usage_no_truncate
    BEFORE TRUNCATE ON ref_store_core_pack_snapshot_repo_usage
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_snapshot_tenant_usage_no_delete
    BEFORE DELETE ON ref_store_core_pack_snapshot_tenant_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_snapshot_tenant_usage_no_truncate
    BEFORE TRUNCATE ON ref_store_core_pack_snapshot_tenant_usage
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();

-- ---------------------------------------------------------------------------
-- 6. Permanent CREATE identity for pack snapshots and pins.
--
-- The A2 snapshot/pin rows cascade away with the repository, so without a
-- retained binding a deleted pack snapshot's snapshot id / pin id could be reused
-- by a new request (double-spend of an identity that old receipts still name).
-- The permanent create binding is therefore uniquely constrained, but only on the
-- `created` history row: renew/release rows legitimately repeat the same
-- snapshot/pin pair, so a plain UNIQUE(snapshot_id) on every history row would
-- reject a legitimate lifecycle entry.
--
-- The adapter also validates every lifecycle entry against the original create
-- row (repository/tenant/owner/snapshot/pin) inside its transaction; these
-- indexes are the durable last line of defence and make reuse a row error even
-- for direct DML.
CREATE UNIQUE INDEX ref_store_core_pack_snapshot_history_create_snapshot
    ON ref_store_core_pack_snapshot_history(snapshot_id) WHERE kind = 'created';
CREATE UNIQUE INDEX ref_store_core_pack_snapshot_history_create_pin
    ON ref_store_core_pack_snapshot_history(pin_id) WHERE kind = 'created';

INSERT INTO schema_migrations (version) VALUES (143) ON CONFLICT DO NOTHING;
