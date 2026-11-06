CREATE TABLE workspace_namespaces (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    name TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    creator_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(owner_id,name,revision)
);
CREATE TABLE workspace_namespace_mounts (
    namespace_id UUID NOT NULL REFERENCES workspace_namespaces(id),
    mount_path TEXT NOT NULL,
    repository_id UUID NOT NULL REFERENCES repositories(id),
    owner_slug TEXT NOT NULL,
    repository_name TEXT NOT NULL,
    base_oid TEXT NOT NULL,
    PRIMARY KEY(namespace_id,mount_path)
);
CREATE TABLE workspace_views (
    id UUID PRIMARY KEY,
    namespace_id UUID NOT NULL REFERENCES workspace_namespaces(id),
    repository_id UUID NOT NULL REFERENCES repositories(id),
    mount_path TEXT NOT NULL,
    subdir TEXT NOT NULL,
    source_oid TEXT NOT NULL,
    projected_oid TEXT NOT NULL,
    epoch BIGINT NOT NULL DEFAULT 1,
    creator_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE workspace_view_history (
    view_id UUID NOT NULL REFERENCES workspace_views(id),
    source_oid TEXT NOT NULL,
    projected_oid TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    PRIMARY KEY(view_id,source_oid)
);
INSERT INTO schema_migrations(version) VALUES(93) ON CONFLICT DO NOTHING;
