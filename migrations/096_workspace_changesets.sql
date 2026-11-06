CREATE TABLE workspace_changesets (
    id UUID PRIMARY KEY,
    namespace_id UUID NOT NULL REFERENCES workspace_namespaces(id),
    state TEXT NOT NULL CHECK(state IN ('proposed','reviewed','integrating','partial','complete','conflict')),
    creator_id UUID NOT NULL REFERENCES users(id),
    reviewer_id UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE workspace_changeset_steps (
    changeset_id UUID NOT NULL REFERENCES workspace_changesets(id),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    repository_id UUID NOT NULL REFERENCES repositories(id),
    mount_path TEXT NOT NULL,
    owner_slug TEXT NOT NULL,
    repository_name TEXT NOT NULL,
    ref_name TEXT NOT NULL,
    old_oid TEXT NOT NULL,
    new_oid TEXT NOT NULL,
    storage_generation BIGINT NOT NULL,
    applied BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY(changeset_id,ordinal)
);
INSERT INTO schema_migrations(version) VALUES(96) ON CONFLICT DO NOTHING;
