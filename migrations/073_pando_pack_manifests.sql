-- A Pando pack is visible only after both encrypted artifacts and their
-- envelopes have been verified in remote object storage. The database row is
-- the publication point; remote staging without a row is an orphan, not data.
CREATE TABLE IF NOT EXISTS pando_pack_manifests (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    storage_generation BIGINT NOT NULL CHECK (storage_generation > 0),
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1', 'sha256')),
    manifest JSONB NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE,
    UNIQUE (repository_id, id)
);
CREATE INDEX IF NOT EXISTS pando_pack_manifests_repository_idx
    ON pando_pack_manifests (repository_id, storage_generation, created_at, id);

INSERT INTO schema_migrations (version) VALUES (73) ON CONFLICT DO NOTHING;
