CREATE TABLE workspace_remote_staging_objects (
    checkpoint_id UUID NOT NULL REFERENCES workspace_checkpoints(id),
    tenant_id UUID NOT NULL,
    digest TEXT NOT NULL,
    size BIGINT NOT NULL CHECK(size >= 0),
    kind TEXT NOT NULL CHECK(kind IN ('file','manifest')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(checkpoint_id,digest)
);
CREATE INDEX workspace_remote_staging_age_idx ON workspace_remote_staging_objects(created_at);
INSERT INTO schema_migrations(version) VALUES(95) ON CONFLICT DO NOTHING;
