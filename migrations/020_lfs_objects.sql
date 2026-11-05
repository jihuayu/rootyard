-- Per-repository Git LFS object metadata scoped to the personal repository owner.
-- Object bytes reside at <data_dir>/lfs/<repository_id>/<oid> as 0600 regular files
-- and become visible for download only after streaming SHA-256 and byte-size verification
-- transitions the row state from 'pending' to 'ready'.
CREATE TABLE lfs_objects (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    oid TEXT NOT NULL CHECK (oid COLLATE "C" ~ '^[0-9a-f]{64}$'),
    size BIGINT NOT NULL CHECK (size >= 0),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'ready')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, oid),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id)
);
INSERT INTO schema_migrations (version) VALUES (20);
