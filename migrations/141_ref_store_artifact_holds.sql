-- Global, permanent artifact-hold ledger for the trusted internal A3 slice
-- (#113 dependency of #107). RESERVED migration number: this file is NOT
-- registered until Root integrates the module wiring and regenerates the true
-- PostgreSQL catalogs. It intentionally contains no hand-written catalog copy.
--
-- Scope of this migration:
--   * one global acquire-request ledger (caller-fixed request UUID + semantic
--     digest, replay body) that is independent of migrations 138/139/140;
--   * one immutable, always-active, generation-1 hold row per acquired artifact;
--   * one immutable one-shot consume receipt per hold (unique slot);
--   * fixed 64-way global shard counters plus per-tenant and per-repository
--     retained admission counters.
--
-- What is deliberately absent: no release API, no TTL/expiry, no state
-- transition, no physical object dedup/reuse, no roots, no candidate/membership,
-- no retirement, no GC consumer and no serving route. A hold is retained for
-- ever, including after every error, timeout, cancellation, unknown completion
-- or owner/repository deletion.
--
-- Durability/lifetime boundary: no table here has a FOREIGN KEY to users,
-- repositories, issuer lanes, refs or any other business row, and there is no
-- ON DELETE CASCADE anywhere. Deleting a repository or a user therefore cannot
-- free a request, hold, receipt, quota counter or dedup identity; the ledger
-- remains authoritative and queryable. Direct UPDATE of a request/hold/receipt
-- row is refused by a trigger, direct DELETE is refused unconditionally and any
-- TRUNCATE of a ledger/quota table (including CASCADE from its own parent) is
-- refused at statement level, so only INSERT (including a fresh-schema COPY
-- restore) can write history. Quota, protection and dedup state can never be
-- reset. Every request, hold and consume receipt also records the physical Blob
-- backend identity hex of the store that was actually opened, so a stored row
-- can only be compared with - never replayed into - a different endpoint,
-- bucket, root prefix, region or stable account identity.
-- Logical counters below are admission/reservation bounds, not PostgreSQL WAL,
-- RSS, filesystem or provider-disk guarantees.

-- Fixed 64-way global budget. A shard is chosen only from the stable acquire
-- request UUID (never from a clock, repository or connection), so a replay
-- always charges the same shard. There is no dynamic cross-shard credit and no
-- global hot counter. 64 x 256 = 16384 holds, 64 x 128 MiB = 8 GiB declared,
-- 64 x 1 MiB = 64 MiB logical, 64 x 1024 = 65536 receipts.
CREATE TABLE artifact_hold_shards (
    shard_id INTEGER PRIMARY KEY CHECK (shard_id >= 0 AND shard_id < 64),
    hold_count BIGINT NOT NULL DEFAULT 0 CHECK (hold_count >= 0 AND hold_count <= 256),
    declared_bytes BIGINT NOT NULL DEFAULT 0 CHECK (declared_bytes >= 0 AND declared_bytes <= 134217728),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0 AND logical_bytes <= 1048576),
    receipt_count BIGINT NOT NULL DEFAULT 0 CHECK (receipt_count >= 0 AND receipt_count <= 1024),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO artifact_hold_shards(shard_id) SELECT generate_series(0, 63);

-- One row per trusted acquire call. `request_id` is caller-fixed and global
-- (not scoped by repository), so a replay is recognised across every
-- tenant/repository. `request_digest` is the caller's semantic digest over
-- scope/owner/purpose/operation/artifact specifications and deliberately does
-- not cover the fresh server attempt path, so the same request id must replay
-- byte-identically while a *new* attempt is a new request id.
--
-- `ack_body` is the immutable bounded ACK and is the only replay answer: a
-- replay returns this body (ids and locator identity) and never a grant.
CREATE TABLE artifact_hold_requests (
    request_id UUID PRIMARY KEY,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('ref_publication')),
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1','sha256')),
    history_incarnation UUID NOT NULL,
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch > 0),
    -- Exact parent operation binding from the migration-138 registry. It is
    -- copied here for attribution/recheck only; no foreign key is taken so the
    -- global ledger survives any business-row deletion.
    operation_issuer_id UUID NOT NULL,
    operation_lane TEXT NOT NULL CHECK (
        octet_length(operation_lane) >= 1 AND octet_length(operation_lane) <= 64
        AND operation_lane !~ '[^A-Za-z0-9._:-]'
    ),
    operation_sequence BIGINT NOT NULL CHECK (operation_sequence > 0),
    operation_id UUID NOT NULL,
    operation_digest TEXT NOT NULL CHECK (operation_digest ~ '^[0-9a-f]{64}$'),
    -- Exact unserved core gate proof the holds were admitted under.
    gate_revision BIGINT NOT NULL CHECK (gate_revision > 0),
    gate_digest TEXT NOT NULL CHECK (gate_digest ~ '^[0-9a-f]{64}$'),
    -- Physical Blob backend identity hex of the store that was actually
    -- opened. Non-secret and never a capability, but a body/row pair can only
    -- be replayed into the same provider + endpoint + bucket/container + root
    -- prefix + region + stable account identity.
    backend_identity TEXT NOT NULL CHECK (backend_identity ~ '^[0-9a-f]{64}$'),
    -- Stable consume id, allocated by this first acquire and reused verbatim by
    -- the one-shot consume, so a lost COMMIT acknowledgement is resolvable
    -- without minting a new random id. Unique per acquire and immutable.
    consume_request_id UUID NOT NULL UNIQUE,
    shard_id INTEGER NOT NULL CHECK (shard_id >= 0 AND shard_id < 64),
    artifact_count INTEGER NOT NULL CHECK (artifact_count >= 1 AND artifact_count <= 16),
    declared_bytes BIGINT NOT NULL CHECK (declared_bytes >= 0),
    logical_bytes BIGINT NOT NULL CHECK (logical_bytes > 0),
    ack_body TEXT NOT NULL CHECK (octet_length(ack_body) > 0 AND octet_length(ack_body) <= 65536),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    -- Parent key for the child holds; deliberately no cascade.
    UNIQUE (request_id, repository_id, tenant_id)
);

CREATE INDEX artifact_hold_requests_operation
    ON artifact_hold_requests(repository_id, operation_id, created_at);

-- One immutable hold per acquired artifact and per stable slot 0..=15. There is
-- no release: `state` is fixed `active` and `generation` fixed 1, so a hold id
-- can never be re-activated, re-used or retired in this increment. The full
-- physical identity (provider + tenant + storage authority/generation +
-- unique attempt id + namespace + sha256 + length) is recorded so a restart can
-- only reconstruct a *read-only* locator, never write authority.
CREATE TABLE artifact_holds (
    hold_id UUID PRIMARY KEY,
    request_id UUID NOT NULL,
    slot INTEGER NOT NULL CHECK (slot >= 0 AND slot < 16),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state = 'active'),
    generation INTEGER NOT NULL DEFAULT 1 CHECK (generation = 1),
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('ref_publication')),
    operation_id UUID NOT NULL,
    operation_digest TEXT NOT NULL CHECK (operation_digest ~ '^[0-9a-f]{64}$'),
    provider TEXT NOT NULL CHECK (provider IN ('s3','azblob')),
    backend_identity TEXT NOT NULL CHECK (backend_identity ~ '^[0-9a-f]{64}$'),
    storage_tenant_id UUID NOT NULL,
    authority_id UUID NOT NULL,
    authority_generation BIGINT NOT NULL CHECK (authority_generation > 0),
    attempt_id UUID NOT NULL,
    namespace TEXT NOT NULL CHECK (
        octet_length(namespace) >= 1 AND octet_length(namespace) <= 48
        AND namespace ~ '^[a-z0-9-]+$'
    ),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    content_length BIGINT NOT NULL CHECK (content_length >= 0 AND content_length <= 1099511627776),
    declared_bytes BIGINT NOT NULL CHECK (declared_bytes >= 0 AND declared_bytes <= 1099511627776),
    logical_bytes BIGINT NOT NULL CHECK (logical_bytes > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (request_id, slot),
    UNIQUE (request_id, hold_id),
    -- No two durable holds can name the same fresh physical attempt path on the
    -- same physical backend (attempt ids are random per intent, so this is
    -- defence in depth against a reused path/backend pair).
    UNIQUE (backend_identity, provider, storage_tenant_id, authority_id, authority_generation, attempt_id, namespace),
    FOREIGN KEY (request_id, repository_id, tenant_id)
        REFERENCES artifact_hold_requests(request_id, repository_id, tenant_id)
);

CREATE INDEX artifact_holds_operation ON artifact_holds(repository_id, operation_id);

-- Durable one-shot consumption. Exactly one receipt row may exist per hold
-- (`hold_id` primary key) and per stable slot (`unique (request_id, slot)`), so
-- a second consume of the same grant/slot is a durable conflict even after a
-- crash. `consume_request_id` groups the bounded receipts of one consume call;
-- a replay/query returns these rows and never a consumed token or IO.
CREATE TABLE artifact_hold_consume_receipts (
    hold_id UUID PRIMARY KEY,
    request_id UUID NOT NULL,
    consume_request_id UUID NOT NULL,
    consume_digest TEXT NOT NULL CHECK (consume_digest ~ '^[0-9a-f]{64}$'),
    slot INTEGER NOT NULL CHECK (slot >= 0 AND slot < 16),
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    operation_digest TEXT NOT NULL CHECK (operation_digest ~ '^[0-9a-f]{64}$'),
    gate_revision BIGINT NOT NULL CHECK (gate_revision > 0),
    gate_digest TEXT NOT NULL CHECK (gate_digest ~ '^[0-9a-f]{64}$'),
    body TEXT NOT NULL CHECK (octet_length(body) > 0 AND octet_length(body) <= 65536),
    -- The exact database-clock instant recorded inside `body`, stored as an
    -- integer so body/row agreement is an exact equality instead of a float
    -- round-trip. `consumed_at` is the human-readable copy of the same instant.
    consumed_at_unix_micros BIGINT NOT NULL CHECK (consumed_at_unix_micros > 0),
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (request_id, slot),
    UNIQUE (request_id, hold_id),
    FOREIGN KEY (request_id, hold_id) REFERENCES artifact_holds(request_id, hold_id)
);

CREATE INDEX artifact_hold_consume_receipts_request
    ON artifact_hold_consume_receipts(consume_request_id, hold_id);

-- Retained admission counters. They are charged atomically with the successful
-- request/hold/receipt rows and are never refunded: no release, expiry, error,
-- timeout, cancellation, unknown completion or owner deletion lowers them.
-- The CHECK ceilings repeat the exact contract bounds, so direct DML cannot
-- silently oversubscribe a repository, tenant or shard.
CREATE TABLE artifact_hold_repo_usage (
    repository_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    hold_count BIGINT NOT NULL DEFAULT 0 CHECK (hold_count >= 0 AND hold_count <= 256),
    declared_bytes BIGINT NOT NULL DEFAULT 0 CHECK (declared_bytes >= 0 AND declared_bytes <= 134217728),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0 AND logical_bytes <= 4194304),
    receipt_count BIGINT NOT NULL DEFAULT 0 CHECK (receipt_count >= 0 AND receipt_count <= 2048)
);

CREATE TABLE artifact_hold_tenant_usage (
    tenant_id UUID PRIMARY KEY,
    hold_count BIGINT NOT NULL DEFAULT 0 CHECK (hold_count >= 0 AND hold_count <= 1024),
    declared_bytes BIGINT NOT NULL DEFAULT 0 CHECK (declared_bytes >= 0 AND declared_bytes <= 536870912),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0 AND logical_bytes <= 16777216),
    receipt_count BIGINT NOT NULL DEFAULT 0 CHECK (receipt_count >= 0 AND receipt_count <= 8192)
);

-- Requests, holds and consume receipts are append-only: no UPDATE path exists
-- (holds are always active generation 1; receipts are terminal on insert).
CREATE FUNCTION rootyard_artifact_hold_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'artifact hold ledger row is immutable';
END $$;

CREATE TRIGGER artifact_hold_request_immutable
    BEFORE UPDATE ON artifact_hold_requests
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_immutable();

CREATE TRIGGER artifact_hold_hold_immutable
    BEFORE UPDATE ON artifact_holds
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_immutable();

CREATE TRIGGER artifact_hold_consume_receipt_immutable
    BEFORE UPDATE ON artifact_hold_consume_receipts
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_immutable();

-- There is no release/retirement path in this increment, so a direct DELETE of
-- any durable ledger row is refused unconditionally. Business deletion cannot
-- reach these rows at all because no cascade or parent foreign key exists.
CREATE FUNCTION rootyard_artifact_hold_no_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'artifact hold ledger rows are permanent and cannot be deleted';
END $$;

CREATE TRIGGER artifact_hold_request_no_delete
    BEFORE DELETE ON artifact_hold_requests
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_no_delete();

CREATE TRIGGER artifact_hold_hold_no_delete
    BEFORE DELETE ON artifact_holds
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_no_delete();

CREATE TRIGGER artifact_hold_consume_receipt_no_delete
    BEFORE DELETE ON artifact_hold_consume_receipts
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_no_delete();

CREATE TRIGGER artifact_hold_repo_usage_no_delete
    BEFORE DELETE ON artifact_hold_repo_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_no_delete();

CREATE TRIGGER artifact_hold_tenant_usage_no_delete
    BEFORE DELETE ON artifact_hold_tenant_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_no_delete();

CREATE TRIGGER artifact_hold_shard_no_delete
    BEFORE DELETE ON artifact_hold_shards
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_no_delete();

-- TRUNCATE is a second deletion path that row triggers do not observe, so every
-- ledger/quota table also refuses it unconditionally at statement level. This is
-- table-local: `TRUNCATE some_business_table CASCADE` cannot reach these tables
-- at all (there is no foreign key from a business row), while an explicit
-- `TRUNCATE artifact_hold_requests CASCADE` is refused here before it can clear
-- holds, receipts, protection, dedup or quota. A fresh-schema COPY/restore is
-- unaffected: COPY does not fire row triggers, and a restore re-creates the
-- tables rather than truncating live ones.
CREATE FUNCTION rootyard_artifact_hold_no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'artifact hold ledger and quota rows are permanent and cannot be truncated';
END $$;

CREATE TRIGGER artifact_hold_request_no_truncate
    BEFORE TRUNCATE ON artifact_hold_requests
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_artifact_hold_no_truncate();

CREATE TRIGGER artifact_hold_hold_no_truncate
    BEFORE TRUNCATE ON artifact_holds
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_artifact_hold_no_truncate();

CREATE TRIGGER artifact_hold_consume_receipt_no_truncate
    BEFORE TRUNCATE ON artifact_hold_consume_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_artifact_hold_no_truncate();

CREATE TRIGGER artifact_hold_repo_usage_no_truncate
    BEFORE TRUNCATE ON artifact_hold_repo_usage
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_artifact_hold_no_truncate();

CREATE TRIGGER artifact_hold_tenant_usage_no_truncate
    BEFORE TRUNCATE ON artifact_hold_tenant_usage
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_artifact_hold_no_truncate();

CREATE TRIGGER artifact_hold_shard_no_truncate
    BEFORE TRUNCATE ON artifact_hold_shards
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_artifact_hold_no_truncate();

-- Usage/shard counters only grow and their identity columns never change.
CREATE FUNCTION rootyard_artifact_hold_counter_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.hold_count < OLD.hold_count
        OR NEW.declared_bytes < OLD.declared_bytes
        OR NEW.logical_bytes < OLD.logical_bytes
        OR NEW.receipt_count < OLD.receipt_count THEN
        RAISE EXCEPTION 'artifact hold retained admission counters cannot decrease';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER artifact_hold_repo_usage_guard
    BEFORE UPDATE ON artifact_hold_repo_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_counter_guard();

CREATE TRIGGER artifact_hold_tenant_usage_guard
    BEFORE UPDATE ON artifact_hold_tenant_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_counter_guard();

CREATE TRIGGER artifact_hold_shard_guard
    BEFORE UPDATE ON artifact_hold_shards
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_counter_guard();

CREATE FUNCTION rootyard_artifact_hold_shard_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.shard_id <> OLD.shard_id THEN
        RAISE EXCEPTION 'artifact hold shard identity is immutable';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER artifact_hold_shard_identity
    BEFORE UPDATE ON artifact_hold_shards
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_shard_identity();

CREATE FUNCTION rootyard_artifact_hold_usage_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'artifact_hold_repo_usage' THEN
        IF NEW.repository_id <> OLD.repository_id OR NEW.tenant_id <> OLD.tenant_id THEN
            RAISE EXCEPTION 'artifact hold repository usage identity is immutable';
        END IF;
    ELSIF NEW.tenant_id <> OLD.tenant_id THEN
        RAISE EXCEPTION 'artifact hold tenant usage identity is immutable';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER artifact_hold_repo_usage_identity
    BEFORE UPDATE ON artifact_hold_repo_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_usage_identity();

CREATE TRIGGER artifact_hold_tenant_usage_identity
    BEFORE UPDATE ON artifact_hold_tenant_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_artifact_hold_usage_identity();

INSERT INTO schema_migrations (version) VALUES (141) ON CONFLICT DO NOTHING;
