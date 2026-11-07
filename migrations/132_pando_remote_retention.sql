-- Durable, authority-scoped remote artifact retention for Pando.
--
-- There is no safe way to treat an S3 LIST (or a pre-132 PackManifest v1,
-- whose remote keys are only tenant content-addressed) as a global reference
-- set. This migration therefore introduces a *new* deletable namespace that is
-- scoped to exactly one database installation ("storage authority"). Legacy
-- tenant-only objects are never registered here, so they are permanently
-- excluded from deletion. A restored deployment mints a new authority and
-- re-uploads its serving closure under that authority, so two databases that
-- share one bucket can never delete each other's bytes.
CREATE TABLE pando_storage_authorities (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    authority_id UUID NOT NULL UNIQUE,
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    rotated_at TIMESTAMPTZ
);
INSERT INTO pando_storage_authorities(singleton, authority_id)
    VALUES (true, gen_random_uuid()) ON CONFLICT (singleton) DO NOTHING;

-- One row per immutable encrypted object this authority has ever acknowledged
-- (pack ciphertext or its envelope). `object_generation` is the authority
-- generation baked into `remote_path`; resurrection of a retired/deleted
-- content address bumps the authority generation and writes a fresh path, so
-- a stale deleter can only ever remove the abandoned old object.
CREATE TABLE pando_remote_artifacts (
    authority_id UUID NOT NULL REFERENCES pando_storage_authorities(authority_id) ON DELETE RESTRICT,
    tenant_id UUID NOT NULL,
    namespace TEXT NOT NULL CHECK (namespace IN ('pando-cipher','pando-envelope')),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size BIGINT NOT NULL DEFAULT 0 CHECK (size >= 0),
    object_generation BIGINT NOT NULL CHECK (object_generation > 0),
    remote_path TEXT NOT NULL CHECK (octet_length(remote_path) <= 512),
    state TEXT NOT NULL DEFAULT 'reserved'
        CHECK (state IN ('reserved','active','retired','deleting','deleted')),
    reserved_owner UUID,
    lease_until TIMESTAMPTZ,
    claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    claimed_by UUID,
    delete_after TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT CHECK (last_error IS NULL OR octet_length(last_error) <= 2048),
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (authority_id, tenant_id, namespace, sha256),
    UNIQUE (remote_path),
    CHECK ((state = 'reserved') = (reserved_owner IS NOT NULL)),
    CHECK ((state = 'deleting') = (claimed_by IS NOT NULL))
);
CREATE INDEX pando_remote_artifacts_retireable
    ON pando_remote_artifacts(authority_id, tenant_id, delete_after)
    WHERE state IN ('retired','deleting');
CREATE INDEX pando_remote_artifacts_tenant
    ON pando_remote_artifacts(tenant_id, namespace, sha256);

-- Immutable linkage from a committed manifest to the exact encrypted objects
-- it needs. A manifest row that was never linked (legacy v1 or a crashed
-- publish) can never make its remote bytes a deletion candidate.
CREATE TABLE pando_manifest_artifacts (
    manifest_id UUID NOT NULL REFERENCES pando_pack_manifests(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL,
    authority_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    namespace TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    artifact_role TEXT NOT NULL CHECK (artifact_role IN ('pack-cipher','pack-envelope','index-cipher','index-envelope')),
    PRIMARY KEY (manifest_id, artifact_role),
    FOREIGN KEY (authority_id, tenant_id, namespace, sha256)
        REFERENCES pando_remote_artifacts(authority_id, tenant_id, namespace, sha256) ON DELETE CASCADE
);
CREATE INDEX pando_manifest_artifacts_artifact
    ON pando_manifest_artifacts(authority_id, tenant_id, namespace, sha256);
CREATE INDEX pando_manifest_artifacts_repository
    ON pando_manifest_artifacts(repository_id, manifest_id);

INSERT INTO schema_migrations (version) VALUES (132) ON CONFLICT DO NOTHING;
