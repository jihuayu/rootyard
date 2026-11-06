-- A source-scoped, resumable data transfer. A completed row is written only
-- after destination fsck/ref verification and the placement transaction.
CREATE TABLE IF NOT EXISTS shard_replication_operations (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    source_node_id TEXT NOT NULL REFERENCES shard_nodes(node_id),
    target_node_id TEXT NOT NULL REFERENCES shard_nodes(node_id),
    source_route_epoch BIGINT NOT NULL CHECK (source_route_epoch > 0),
    source_generation BIGINT NOT NULL CHECK (source_generation > 0),
    refs_sha256 TEXT CHECK (refs_sha256 IS NULL OR refs_sha256 ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('copying', 'verified', 'completed', 'aborted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (source_node_id <> target_node_id)
);
CREATE INDEX IF NOT EXISTS shard_replication_repo_idx
    ON shard_replication_operations(repository_id, created_at DESC);
INSERT INTO schema_migrations (version) VALUES (83) ON CONFLICT DO NOTHING;
