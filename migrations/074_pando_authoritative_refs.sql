-- PostgreSQL owns Pando's currently promised refs and immutable pack-set list.
-- Local bare repositories are disposable read/write sessions, never authority.
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_storage_backend_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_storage_backend_check
    CHECK (storage_backend IN ('gitfs', 'pando'));

CREATE TABLE IF NOT EXISTS pando_repository_states (
    repository_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    storage_generation BIGINT NOT NULL CHECK (storage_generation > 0),
    ref_generation BIGINT NOT NULL DEFAULT 1 CHECK (ref_generation > 0),
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1','sha256')),
    state TEXT NOT NULL CHECK (state IN ('copying','serving','rollback')),
    pack_ids UUID[] NOT NULL DEFAULT '{}'::uuid[] CHECK (cardinality(pack_ids) <= 10000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (repository_id,tenant_id) REFERENCES repositories(id,owner_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pando_refs (
    repository_id UUID NOT NULL REFERENCES pando_repository_states(repository_id) ON DELETE CASCADE,
    ref_name TEXT NOT NULL CHECK (octet_length(ref_name) BETWEEN 6 AND 1024 AND ref_name LIKE 'refs/%' AND ref_name !~ '[[:cntrl:]]'),
    oid TEXT NOT NULL CHECK (oid ~ '^[0-9a-f]{40}$' OR oid ~ '^[0-9a-f]{64}$'),
    updated_generation BIGINT NOT NULL CHECK (updated_generation > 0),
    PRIMARY KEY (repository_id,ref_name)
);

CREATE INDEX IF NOT EXISTS pando_refs_repository_oid_idx ON pando_refs(repository_id,oid);

INSERT INTO schema_migrations (version) VALUES (74) ON CONFLICT DO NOTHING;
