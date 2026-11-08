-- A4a: durable one-time pack registration, append-only pack membership and the
-- persistent `metadata_only -> pack_verified` gate fence (#107 foundation).
--
-- This migration adds no serving path, no snapshot packs, no detach/compaction,
-- no GC consumer and no roots/decisions. Rows are permanent: there is no
-- UPDATE, DELETE, TRUNCATE, expiry or refund path for a registration, artifact,
-- membership, history row or usage counter.
--
-- Authority shape:
--   * one global `registration_id` per registered pack, with the exact parent
--     operation digest, complete trusted owner/purpose/repo/tenant/history/
--     format/epoch scope, stable A3 acquire/consume ids, planned content digest
--     and the actual immutable artifact-set digest;
--   * exactly one `pack` and one `idx` artifact row per registration, each
--     bound by composite foreign key to the SAME A3 acquire batch and to the
--     matching consume receipt row, so a publication can never be re-registered
--     under another pack/parent and a cloned publication cannot be reused;
--   * memberships are append-only with `joined_revision`;
--   * the first verified commit moves the gate to `pack_verified` inside its own
--     revision increment, and that transition can never be reversed.

-- Persistent authority fence on the existing core gate. The default keeps every
-- existing repository in the unchanged metadata-only mode, so an old A1 commit
-- path still works until one verified pack commit activates this gate.
ALTER TABLE ref_store_core_gates
    ADD COLUMN pack_mode TEXT NOT NULL DEFAULT 'metadata_only'
    CHECK (pack_mode IN ('metadata_only','pack_verified'));

CREATE FUNCTION rootyard_ref_store_core_gate_pack_mode_fence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.pack_mode = 'pack_verified' AND NEW.pack_mode <> 'pack_verified' THEN
        RAISE EXCEPTION 'ref-store core pack mode is one-way and cannot be downgraded';
    END IF;
    IF OLD.pack_mode = 'metadata_only' AND NEW.pack_mode = 'pack_verified'
       AND NEW.revision <= OLD.revision THEN
        RAISE EXCEPTION 'pack mode activation must happen inside a revision increment';
    END IF;
    IF NEW.pack_mode <> OLD.pack_mode AND NEW.revision = OLD.revision THEN
        RAISE EXCEPTION 'pack mode cannot change without a gate revision increment';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER ref_store_core_gate_pack_mode_fence
    BEFORE UPDATE ON ref_store_core_gates
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_gate_pack_mode_fence();

-- One durable registration per pack. `registration_id` is globally unique, so a
-- colliding id from another repository/tenant/owner/parent/backend/content is a
-- conflict and never an upsert. Unique acquire/consume ids prevent a publication
-- from being registered twice; the artifact rows additionally make every hold id
-- permanently single-use.
CREATE TABLE ref_store_core_pack_publications (
    registration_id UUID PRIMARY KEY,
    pack_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose = 'ref_publication'),
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1','sha256')),
    history_incarnation UUID NOT NULL,
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch > 0),
    -- Canonical parent plan digest (known semantic fields only, computed before
    -- the A3 acquire).
    parent_digest TEXT NOT NULL CHECK (parent_digest ~ '^[0-9a-f]{64}$'),
    plan_operation_id UUID NOT NULL,
    planned_pack_sha256 TEXT NOT NULL CHECK (planned_pack_sha256 ~ '^[0-9a-f]{64}$'),
    planned_pack_length BIGINT NOT NULL CHECK (planned_pack_length > 0),
    planned_idx_sha256 TEXT NOT NULL CHECK (planned_idx_sha256 ~ '^[0-9a-f]{64}$'),
    planned_idx_length BIGINT NOT NULL CHECK (planned_idx_length > 0),
    -- Digest of the actual immutable locator set that was read back and
    -- registered under this parent/registration/pack.
    artifact_set_digest TEXT NOT NULL CHECK (artifact_set_digest ~ '^[0-9a-f]{64}$'),
    acquire_request_id UUID NOT NULL UNIQUE,
    consume_request_id UUID NOT NULL UNIQUE,
    backend_identity TEXT NOT NULL CHECK (backend_identity ~ '^[0-9a-f]{64}$'),
    gate_revision BIGINT NOT NULL CHECK (gate_revision > 0),
    gate_digest TEXT NOT NULL CHECK (gate_digest ~ '^[0-9a-f]{64}$'),
    pack_mode TEXT NOT NULL CHECK (pack_mode IN ('metadata_only','pack_verified')),
    declared_bytes BIGINT NOT NULL CHECK (declared_bytes >= 0),
    logical_bytes BIGINT NOT NULL CHECK (logical_bytes > 0),
    -- Immutable bounded canonical ACK; the only replay answer for this id.
    ack_body TEXT NOT NULL CHECK (octet_length(ack_body) > 0 AND octet_length(ack_body) <= 65536),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, pack_id),
    UNIQUE (repository_id, parent_digest, pack_id)
);

CREATE INDEX ref_store_core_pack_publications_parent
    ON ref_store_core_pack_publications(repository_id, parent_digest, created_at);

-- Reviewed composite unique index on the unchanged migration-141 table, needed
-- only so the artifact FK above can bind the exact consume receipt row of the
-- same hold. Migration 141 itself is not altered.
CREATE UNIQUE INDEX artifact_hold_consume_receipts_consume_hold
    ON artifact_hold_consume_receipts(consume_request_id, hold_id);

-- Exactly one pack and one idx per registration. The composite foreign keys bind
-- each row to the same A3 acquire request batch (request_id, hold_id) and to the
-- matching consume receipt (consume_request_id, hold_id). Full immutable
-- artifact identity is duplicated here so a post-hoc locator/backend/format
-- change is a row/body mismatch, not a silent reinterpretation.
CREATE TABLE ref_store_core_pack_artifacts (
    registration_id UUID NOT NULL REFERENCES ref_store_core_pack_publications(registration_id),
    role TEXT NOT NULL CHECK (role IN ('pack','idx')),
    slot INTEGER NOT NULL CHECK (slot >= 0 AND slot < 16),
    -- Canonical pair: exactly slot 0 for the .pack and slot 1 for the .idx,
    -- matching RegisteredPack's sorted [pack, idx] view and its digest.
    CHECK ((role = 'pack' AND slot = 0) OR (role = 'idx' AND slot = 1)),
    hold_id UUID NOT NULL UNIQUE,
    acquire_request_id UUID NOT NULL,
    consume_request_id UUID NOT NULL,
    pack_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('s3','azblob')),
    backend_identity TEXT NOT NULL CHECK (backend_identity ~ '^[0-9a-f]{64}$'),
    namespace TEXT NOT NULL CHECK (
        octet_length(namespace) >= 1 AND octet_length(namespace) <= 48
        AND namespace ~ '^[a-z0-9-]+$'
    ),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    content_length BIGINT NOT NULL CHECK (content_length > 0),
    declared_bytes BIGINT NOT NULL CHECK (declared_bytes >= 0),
    logical_bytes BIGINT NOT NULL CHECK (logical_bytes > 0),
    PRIMARY KEY (registration_id, role),
    UNIQUE (registration_id, hold_id),
    UNIQUE (acquire_request_id, slot),
    FOREIGN KEY (acquire_request_id, hold_id) REFERENCES artifact_holds(request_id, hold_id),
    FOREIGN KEY (acquire_request_id, slot) REFERENCES artifact_holds(request_id, slot),
    FOREIGN KEY (consume_request_id, hold_id)
        REFERENCES artifact_hold_consume_receipts(consume_request_id, hold_id)
);

CREATE INDEX ref_store_core_pack_artifacts_pack ON ref_store_core_pack_artifacts(pack_id, role);
CREATE INDEX ref_store_core_pack_artifacts_hold ON ref_store_core_pack_artifacts(hold_id);

-- A4a part 2: append-only membership, permanent history ledger, monotone
-- retained usage counters and immutability guards.
--
-- Membership rows are never detached, replaced, compacted or re-joined: the
-- (repository_id, pack_id) pair is the identity and `joined_revision` records
-- the exact gate revision of the verified commit that attached it. A future
-- snapshot history table must reference these rows with RESTRICT, never cascade.

ALTER TABLE ref_store_core_pack_publications
    ADD CONSTRAINT ref_store_core_pack_publications_registration_pack_digest
    UNIQUE (repository_id, registration_id, pack_id, artifact_set_digest);

CREATE TABLE ref_store_core_pack_memberships (
    repository_id UUID NOT NULL,
    pack_id UUID NOT NULL,
    registration_id UUID NOT NULL,
    -- Pinned to the exact registered artifact-set digest, so a lineage row can
    -- never point at a publication whose physical artifact set changed meaning.
    artifact_set_digest TEXT NOT NULL CHECK (artifact_set_digest ~ '^[0-9a-f]{64}$'),
    joined_revision BIGINT NOT NULL CHECK (joined_revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, pack_id),
    -- Composite membership identity (repository + registration + pack + exact
    -- artifact set). Deliberately no business FK/cascade.
    FOREIGN KEY (repository_id, registration_id, pack_id, artifact_set_digest)
        REFERENCES ref_store_core_pack_publications(repository_id, registration_id, pack_id, artifact_set_digest)
);

CREATE INDEX ref_store_core_pack_memberships_revision
    ON ref_store_core_pack_memberships(repository_id, joined_revision);

-- Permanent ledger of pack-authority transitions. Never trimmed by TTL, never
-- rewritten, and independent of the business repository row (no cascade), so the
-- history of what was registered/activated survives deletion.
CREATE TABLE ref_store_core_pack_history (
    history_id UUID PRIMARY KEY,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('registered','committed','cancelled_after_registration')),
    registration_id UUID,
    pack_id UUID,
    parent_digest TEXT NOT NULL CHECK (parent_digest ~ '^[0-9a-f]{64}$'),
    revision BIGINT NOT NULL CHECK (revision > 0),
    operation_id UUID NOT NULL,
    artifact_set_digest TEXT,
    body TEXT NOT NULL CHECK (octet_length(body) > 0 AND octet_length(body) <= 65536),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX ref_store_core_pack_history_repository
    ON ref_store_core_pack_history(repository_id, created_at);
CREATE INDEX ref_store_core_pack_history_registration
    ON ref_store_core_pack_history(registration_id, created_at);

-- Retained logical admission counters. Charged atomically with the successful
-- rows and never refunded: an error, timeout, cancellation, unknown COMMIT or
-- owner deletion cannot lower them. The CHECK ceilings repeat the fixed contract
-- bounds (repo 128/256/16/8MiB/2048; tenant exactly 4x).
CREATE TABLE ref_store_core_pack_repo_usage (
    repository_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    registration_count BIGINT NOT NULL DEFAULT 0 CHECK (registration_count >= 0 AND registration_count <= 128),
    artifact_count BIGINT NOT NULL DEFAULT 0 CHECK (artifact_count >= 0 AND artifact_count <= 256),
    membership_count BIGINT NOT NULL DEFAULT 0 CHECK (membership_count >= 0 AND membership_count <= 16),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0 AND logical_bytes <= 8388608),
    receipt_count BIGINT NOT NULL DEFAULT 0 CHECK (receipt_count >= 0 AND receipt_count <= 2048)
);

CREATE TABLE ref_store_core_pack_tenant_usage (
    tenant_id UUID PRIMARY KEY,
    registration_count BIGINT NOT NULL DEFAULT 0 CHECK (registration_count >= 0 AND registration_count <= 512),
    artifact_count BIGINT NOT NULL DEFAULT 0 CHECK (artifact_count >= 0 AND artifact_count <= 1024),
    membership_count BIGINT NOT NULL DEFAULT 0 CHECK (membership_count >= 0 AND membership_count <= 64),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0 AND logical_bytes <= 33554432),
    receipt_count BIGINT NOT NULL DEFAULT 0 CHECK (receipt_count >= 0 AND receipt_count <= 8192)
);

-- Counters are monotone: an update may only raise them, so no refund path can
-- exist even through direct DML.
CREATE FUNCTION rootyard_ref_store_core_pack_usage_monotone() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id <> OLD.tenant_id THEN
        RAISE EXCEPTION 'pack usage tenant is immutable';
    END IF;
    IF NEW.registration_count < OLD.registration_count
       OR NEW.artifact_count < OLD.artifact_count
       OR NEW.membership_count < OLD.membership_count
       OR NEW.logical_bytes < OLD.logical_bytes
       OR NEW.receipt_count < OLD.receipt_count THEN
        RAISE EXCEPTION 'pack usage counters are monotone and cannot be refunded';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER ref_store_core_pack_repo_usage_monotone
    BEFORE UPDATE ON ref_store_core_pack_repo_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_usage_monotone();
CREATE TRIGGER ref_store_core_pack_tenant_usage_monotone
    BEFORE UPDATE ON ref_store_core_pack_tenant_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_usage_monotone();

-- Append-only guards: no UPDATE/DELETE/TRUNCATE on any A4-owned durable row.
CREATE FUNCTION rootyard_ref_store_core_pack_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ref-store core pack ledger is immutable';
END $$;

CREATE TRIGGER ref_store_core_pack_publications_immutable
    BEFORE UPDATE OR DELETE ON ref_store_core_pack_publications
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_publications_no_truncate
    BEFORE TRUNCATE ON ref_store_core_pack_publications
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_artifacts_immutable
    BEFORE UPDATE OR DELETE ON ref_store_core_pack_artifacts
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_artifacts_no_truncate
    BEFORE TRUNCATE ON ref_store_core_pack_artifacts
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_memberships_immutable
    BEFORE UPDATE OR DELETE ON ref_store_core_pack_memberships
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_memberships_no_truncate
    BEFORE TRUNCATE ON ref_store_core_pack_memberships
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_history_immutable
    BEFORE UPDATE OR DELETE ON ref_store_core_pack_history
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_history_no_truncate
    BEFORE TRUNCATE ON ref_store_core_pack_history
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();

-- Usage counters are monotone (UPDATE only) but must never be reset by deleting
-- or truncating the row: the immutable ledger outlives the counter, so a reset
-- would silently re-grant retained budget.
CREATE TRIGGER ref_store_core_pack_repo_usage_no_delete
    BEFORE DELETE ON ref_store_core_pack_repo_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_repo_usage_no_truncate
    BEFORE TRUNCATE ON ref_store_core_pack_repo_usage
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_tenant_usage_no_delete
    BEFORE DELETE ON ref_store_core_pack_tenant_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_pack_tenant_usage_no_truncate
    BEFORE TRUNCATE ON ref_store_core_pack_tenant_usage
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();

INSERT INTO schema_migrations (version) VALUES (142) ON CONFLICT DO NOTHING;
