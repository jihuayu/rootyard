-- ===========================================================================
-- Migration 146 — bounded TRANSIENT serving read pins (issue #107/#114/#144).
--
-- The durable A5a path (`ref_store_core_snapshots` + `ref_store_core_pins` +
-- permanent history/receipts, migrations 140/143) is immutable, permanent and
-- quota-bounded at 64 retained snapshots/pins per repository. It is the correct
-- shape for a *retained* snapshot, but it is the wrong shape for the per-GET
-- serving read path: every GET would append another permanent snapshot, pin,
-- receipt and history row and the gateway would fail after 64 reads.
--
-- This migration adds a SECOND, deliberately separate and transient pin family
-- for the serving read path only:
--
--   * one `ref_store_core_serving_reads` header row per captured serving read,
--     carrying the full captured identity (scope realm, the digest of the
--     *actually opened* Blob backend, gate revision/digest, HEAD, ref/membership
--     digests, pack count, snapshot digest and its conservative row bytes);
--   * its captured refs, its complete registered pack descriptors and the full
--     per-artifact physical identity (locator, provider, backend identity,
--     verified sha256/length). A future physical GC can therefore enumerate the
--     exact protected pack set of an active serving read WITHOUT re-reading the
--     A4 ledger. `ref_store_core_serving_read_protection(uuid)` is that
--     enumeration.
--
-- Lifetime and bounds (contract constants live in
-- `src/ref_store/core/pack_snapshot/serving_read_request.rs`):
--
--   * a serving read row is TRANSIENT: `DELETE` of a released/expired row is
--     permitted (there is no permanent read-receipt ledger and no refundable
--     "proof" to preserve), while `UPDATE` and `TRUNCATE` stay refused;
--   * active leases and total retained row bytes are bounded per repository and
--     per tenant by two mutable counter/mutex rows;
--   * expired rows are reclaimed in bounded batches by later captures, so an
--     unacknowledged capture `COMMIT` can only leak rows until its own bounded
--     lease elapses;
--   * nothing here can delete, refund or mutate an existing durable snapshot,
--     pin, receipt, history row, root or decision row, and no durable counter is
--     touched. The 64-per-repository retained A5a quota is unchanged.
--
-- GC note (documented, not implemented): physical Blob deletion is disabled by
-- default in this service. Any future GC that deletes pack/idx objects MUST
-- include the active rows of this table (and only these transient rows plus the
-- durable A5/A5b protections) in its protected set. A serving read row is
-- protection only until `expires_at`; after that the bounded reclaim path may
-- delete it.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. One transient serving read header per captured read.
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_core_serving_reads (
    pin_id UUID PRIMARY KEY,
    snapshot_id UUID NOT NULL UNIQUE,
    -- Immutable pin generation. A transient serving read is created once at
    -- generation 1 and never renewed: no caller can extend or reuse it.
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation >= 1),
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('verification','maintenance','backup','export','operator_audit')),
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1','sha256')),
    history_incarnation UUID NOT NULL,
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch > 0),
    -- Digest of the Blob backend the capturing engine actually had open. A
    -- stored copy is only a claim; the T2 recheck compares it with the identity
    -- of the live store and with the current serving binding.
    backend_identity TEXT NOT NULL CHECK (backend_identity ~ '^[0-9a-f]{64}$'),
    gate_revision BIGINT NOT NULL CHECK (gate_revision > 0),
    gate_digest TEXT NOT NULL CHECK (gate_digest ~ '^[0-9a-f]{64}$'),
    head_ref TEXT NOT NULL CHECK (octet_length(head_ref) BETWEEN 1 AND 1024),
    head_oid TEXT CHECK (head_oid IS NULL OR head_oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    ref_count INTEGER NOT NULL CHECK (ref_count >= 0 AND ref_count <= 4096),
    refs_digest TEXT NOT NULL CHECK (refs_digest ~ '^[0-9a-f]{64}$'),
    pack_count INTEGER NOT NULL CHECK (pack_count >= 1 AND pack_count <= 16),
    membership_digest TEXT NOT NULL CHECK (membership_digest ~ '^[0-9a-f]{64}$'),
    snapshot_digest TEXT NOT NULL CHECK (snapshot_digest ~ '^[0-9a-f]{64}$'),
    logical_bytes BIGINT NOT NULL CHECK (logical_bytes > 0),
    lease_seconds INTEGER NOT NULL CHECK (lease_seconds >= 1 AND lease_seconds <= 300),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, pin_id),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

CREATE INDEX ref_store_core_serving_reads_repository
    ON ref_store_core_serving_reads(repository_id, expires_at);
CREATE INDEX ref_store_core_serving_reads_tenant
    ON ref_store_core_serving_reads(tenant_id, expires_at);

-- ---------------------------------------------------------------------------
-- 2. Captured refs of one serving read (bounded 0..=4096 by the adapter).
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_core_serving_read_refs (
    pin_id UUID NOT NULL,
    ref_name TEXT NOT NULL CHECK (octet_length(ref_name) BETWEEN 1 AND 1024),
    oid TEXT NOT NULL CHECK (oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    PRIMARY KEY (pin_id, ref_name),
    FOREIGN KEY (pin_id) REFERENCES ref_store_core_serving_reads(pin_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 3. Complete registered pack descriptors of one serving read.
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_core_serving_read_packs (
    pin_id UUID NOT NULL,
    pack_id UUID NOT NULL,
    registration_id UUID NOT NULL,
    artifact_set_digest TEXT NOT NULL CHECK (artifact_set_digest ~ '^[0-9a-f]{64}$'),
    joined_revision BIGINT NOT NULL CHECK (joined_revision > 0),
    PRIMARY KEY (pin_id, pack_id),
    FOREIGN KEY (pin_id) REFERENCES ref_store_core_serving_reads(pin_id) ON DELETE CASCADE
);

CREATE INDEX ref_store_core_serving_read_packs_registration
    ON ref_store_core_serving_read_packs(registration_id, pack_id);

-- Full physical identity of every protected artifact. The rows are rebuilt into
-- `RegisteredPack`/`RegisteredArtifact` values by the adapter, which re-derives
-- the artifact-set digest from them: a stored digest alone is never a byte
-- proof.
CREATE TABLE ref_store_core_serving_read_artifacts (
    pin_id UUID NOT NULL,
    pack_id UUID NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('pack','idx')),
    slot INTEGER NOT NULL CHECK (slot IN (0,1)),
    hold_id UUID NOT NULL,
    locator_tenant_id UUID NOT NULL,
    locator_authority_id UUID NOT NULL,
    locator_authority_generation BIGINT NOT NULL CHECK (locator_authority_generation > 0),
    locator_attempt_id UUID NOT NULL,
    locator_namespace TEXT NOT NULL CHECK (octet_length(locator_namespace) BETWEEN 1 AND 48),
    locator_sha256 TEXT NOT NULL CHECK (locator_sha256 ~ '^[0-9a-f]{64}$'),
    locator_length BIGINT NOT NULL CHECK (locator_length > 0),
    provider TEXT NOT NULL CHECK (octet_length(provider) BETWEEN 1 AND 64),
    backend_identity TEXT NOT NULL CHECK (backend_identity ~ '^[0-9a-f]{64}$'),
    verified_sha256 TEXT NOT NULL CHECK (verified_sha256 ~ '^[0-9a-f]{64}$'),
    verified_length BIGINT NOT NULL CHECK (verified_length > 0),
    PRIMARY KEY (pin_id, pack_id, role),
    CHECK ((role = 'pack' AND slot = 0) OR (role = 'idx' AND slot = 1)),
    CHECK (locator_sha256 = verified_sha256 AND locator_length = verified_length),
    FOREIGN KEY (pin_id, pack_id) REFERENCES ref_store_core_serving_read_packs(pin_id, pack_id)
        ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 4. Bounded transient admission counters (mutable by design).
--
--    Unlike the migration-143 permanent counters these rows describe rows that
--    are allowed to expire and be deleted, so they are recomputed from the
--    actual rows under `FOR UPDATE` on every capture/release. The CHECKs are the
--    same fixed ceilings as the contract constants and are a database-side last
--    line of defence, never a refundable quota.
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_core_serving_read_repo_usage (
    repository_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    active_count BIGINT NOT NULL DEFAULT 0 CHECK (active_count >= 0 AND active_count <= 64),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0 AND logical_bytes <= 8388608)
);

CREATE TABLE ref_store_core_serving_read_tenant_usage (
    tenant_id UUID PRIMARY KEY,
    active_count BIGINT NOT NULL DEFAULT 0 CHECK (active_count >= 0 AND active_count <= 256),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0 AND logical_bytes <= 33554432)
);

-- ---------------------------------------------------------------------------
-- 5. Immutability: an active pin is never rewritten, only created and deleted.
--    Reusing `rootyard_ref_store_core_pack_immutable()` (migration 142) keeps a
--    single reviewed unconditional "refuse" body.
-- ---------------------------------------------------------------------------
CREATE TRIGGER ref_store_core_serving_reads_immutable
    BEFORE UPDATE ON ref_store_core_serving_reads
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_serving_reads_no_truncate
    BEFORE TRUNCATE ON ref_store_core_serving_reads
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_serving_read_refs_immutable
    BEFORE UPDATE ON ref_store_core_serving_read_refs
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_serving_read_refs_no_truncate
    BEFORE TRUNCATE ON ref_store_core_serving_read_refs
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_serving_read_packs_immutable
    BEFORE UPDATE ON ref_store_core_serving_read_packs
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_serving_read_packs_no_truncate
    BEFORE TRUNCATE ON ref_store_core_serving_read_packs
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_serving_read_artifacts_immutable
    BEFORE UPDATE ON ref_store_core_serving_read_artifacts
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();
CREATE TRIGGER ref_store_core_serving_read_artifacts_no_truncate
    BEFORE TRUNCATE ON ref_store_core_serving_read_artifacts
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_store_core_pack_immutable();

-- ---------------------------------------------------------------------------
-- 5b. Cascade-ONLY child deletes.
--
--     A transient serving read's refs/pack/artifact rows exist solely to protect
--     the captured bytes of a *live* header: `ref_store_core_serving_read_protection
--     (uuid)` enumerates exactly these pack rows. A direct DELETE of one child row
--     while the header survives would silently remove that pack from the GC
--     protection set of an unexpired lease (the T2 recheck would later refuse the
--     damaged capture, but the byte protection would already be gone).
--
--     The ONLY intended child deletion is the `ON DELETE CASCADE` of the parent
--     header, and PostgreSQL performs that cascade *after* the parent row has been
--     deleted. The guard therefore refuses a child DELETE precisely when the
--     parent header still exists, and lets the cascade through with no
--     `pg_trigger_depth` bypass and no superuser escape hatch. `UPDATE`/`TRUNCATE`
--     stay unconditionally refused by section 5, and the header itself stays fully
--     deletable (release, bounded reclaim, and the repository cascade).
-- ---------------------------------------------------------------------------
CREATE FUNCTION rootyard_ref_store_core_serving_read_child_cascade_only()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM ref_store_core_serving_reads WHERE pin_id = OLD.pin_id) THEN
        RAISE EXCEPTION 'ref-store core serving read child rows may only be deleted by their header cascade';
    END IF;
    RETURN OLD;
END $$;

CREATE TRIGGER ref_store_core_serving_read_refs_cascade_only
    BEFORE DELETE ON ref_store_core_serving_read_refs
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_serving_read_child_cascade_only();
CREATE TRIGGER ref_store_core_serving_read_packs_cascade_only
    BEFORE DELETE ON ref_store_core_serving_read_packs
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_serving_read_child_cascade_only();
CREATE TRIGGER ref_store_core_serving_read_artifacts_cascade_only
    BEFORE DELETE ON ref_store_core_serving_read_artifacts
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_serving_read_child_cascade_only();

-- ---------------------------------------------------------------------------
-- 6. Enumeration of the physical protection of one repository's active serving
--    reads. Read-only; used by a future GC and by the integration tests. It
--    claims nothing about current Blob bytes; it lists what an unexpired
--    transient pin currently protects.
-- ---------------------------------------------------------------------------
CREATE FUNCTION ref_store_core_serving_read_protection(p_repository_id UUID)
RETURNS TABLE (pack_id UUID, registration_id UUID, artifact_set_digest TEXT)
LANGUAGE sql STABLE AS $$
    SELECT p.pack_id, p.registration_id, p.artifact_set_digest
    FROM ref_store_core_serving_read_packs p
    JOIN ref_store_core_serving_reads r ON r.pin_id = p.pin_id
    WHERE r.repository_id = p_repository_id
      AND r.expires_at > clock_timestamp()
    ORDER BY p.pack_id
$$;

INSERT INTO schema_migrations (version) VALUES (146) ON CONFLICT DO NOTHING;
