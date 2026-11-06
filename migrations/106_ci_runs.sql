-- Immutable candidate input, mutable fenced execution state.
CREATE TABLE ci_runs (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    pull_number BIGINT NOT NULL,
    pull_version BIGINT NOT NULL,
    context TEXT NOT NULL,
    job_id UUID NOT NULL,
    head_oid TEXT NOT NULL,
    base_oid TEXT NOT NULL,
    storage_generation BIGINT NOT NULL,
    config_sha256 TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','leased','completed','cancelled')),
    attempt BIGINT NOT NULL DEFAULT 0,
    lease_generation BIGINT NOT NULL DEFAULT 0,
    lease_expires_unix BIGINT NOT NULL DEFAULT 0,
    runner_id TEXT,
    source_url TEXT,
    conclusion TEXT,
    result_sha256 TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(repository_id,pull_number,pull_version,context),
    FOREIGN KEY(repository_id,tenant_id) REFERENCES repositories(id,owner_id) ON DELETE CASCADE,
    CHECK (head_oid COLLATE "C" ~ '^[0-9a-f]{40}$'),
    CHECK (base_oid COLLATE "C" ~ '^[0-9a-f]{40}$'),
    CHECK (config_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$')
);
CREATE INDEX ci_runs_claim_idx ON ci_runs(state,lease_expires_unix,created_at);
CREATE TABLE ci_mirror_nodes (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    mirror_id UUID NOT NULL,
    audience UUID NOT NULL,
    url TEXT NOT NULL,
    storage_generation BIGINT NOT NULL,
    ready_oids JSONB NOT NULL DEFAULT '[]'::jsonb,
    capacity BIGINT NOT NULL CHECK (capacity > 0),
    active BOOLEAN NOT NULL DEFAULT true,
    heartbeat_unix BIGINT NOT NULL,
    PRIMARY KEY(repository_id,mirror_id)
);
INSERT INTO schema_migrations(version) VALUES(106) ON CONFLICT DO NOTHING;
