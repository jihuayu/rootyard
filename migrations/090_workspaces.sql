-- Native workspace state. Files are staged under a private host directory;
-- PostgreSQL owns identity, authorization bindings, revisions and fencing.
CREATE TABLE workspaces (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id),
    owner_slug TEXT NOT NULL,
    repository_name TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    creator_id UUID NOT NULL REFERENCES users(id),
    parent_checkpoint_id UUID,
    last_checkpoint_id UUID,
    state TEXT NOT NULL CHECK (state IN ('creating','ready','checkpointing','failed','deleted')),
    host_id UUID NOT NULL,
    lease_epoch BIGINT NOT NULL DEFAULT 1 CHECK (lease_epoch > 0),
    lease_until TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    git_generation BIGINT NOT NULL DEFAULT 0 CHECK (git_generation >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX workspaces_repository_idx ON workspaces(repository_id, created_at DESC);
CREATE TABLE workspace_creations (
    actor_id UUID NOT NULL REFERENCES users(id),
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    PRIMARY KEY (actor_id, idempotency_key)
);
CREATE TABLE workspace_checkpoints (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    repository_id UUID NOT NULL REFERENCES repositories(id),
    captured_revision BIGINT NOT NULL,
    lease_epoch BIGINT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('local_complete','uploading','committed','failed')),
    manifest_digest TEXT,
    excluded_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    committed_at TIMESTAMPTZ
);
ALTER TABLE workspaces ADD CONSTRAINT workspaces_last_checkpoint_fk FOREIGN KEY (last_checkpoint_id) REFERENCES workspace_checkpoints(id);
ALTER TABLE workspaces ADD CONSTRAINT workspaces_parent_checkpoint_fk FOREIGN KEY (parent_checkpoint_id) REFERENCES workspace_checkpoints(id);
CREATE TABLE workspace_operations (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','committed','failed')),
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (workspace_id, idempotency_key)
);
CREATE TABLE workspace_entries (
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    path TEXT NOT NULL,
    entry_version BIGINT NOT NULL CHECK (entry_version > 0),
    digest TEXT,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (workspace_id, path)
);
CREATE TABLE workspace_events (
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    revision BIGINT NOT NULL,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (workspace_id, revision)
);
INSERT INTO schema_migrations (version) VALUES (90) ON CONFLICT DO NOTHING;
