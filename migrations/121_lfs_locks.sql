CREATE TABLE lfs_locks (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    path TEXT NOT NULL CHECK (octet_length(path) BETWEEN 1 AND 1024),
    owner_user_id UUID NOT NULL REFERENCES users(id),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    locked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, path),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);
CREATE INDEX lfs_locks_repo_id_idx ON lfs_locks(repository_id, id);
INSERT INTO schema_migrations(version) VALUES (121) ON CONFLICT DO NOTHING;
