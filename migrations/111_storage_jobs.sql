-- Durable GitFS lifecycle work. Version 120 rebinds tenant_id FKs from
-- personal users to namespaces, preserving existing UUIDs during upgrade.
CREATE TABLE storage_maintenance_repo_state (
    repository_id UUID PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES users(id),
    last_scan_at TIMESTAMPTZ,
    last_scan_generation BIGINT,
    last_repack_at TIMESTAMPTZ,
    last_repack_loose_count BIGINT NOT NULL DEFAULT 0 CHECK (last_repack_loose_count >= 0),
    last_repack_pack_count BIGINT NOT NULL DEFAULT 0 CHECK (last_repack_pack_count >= 0),
    loose_count BIGINT NOT NULL DEFAULT 0 CHECK (loose_count >= 0),
    pack_count BIGINT NOT NULL DEFAULT 0 CHECK (pack_count >= 0),
    last_scan JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE storage_maintenance_jobs (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL CHECK (kind IN (
        'gitfs_stage_cleanup', 'gitfs_repack', 'gitfs_cache_hydrate',
        'gitfs_cache_evict', 'gitfs_unreachable_mark', 'gitfs_tombstone_delete'
    )),
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','succeeded','failed')),
    repository_generation BIGINT NOT NULL CHECK (repository_generation > 0),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    lease_owner UUID,
    lease_until TIMESTAMPTZ,
    not_before TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    progress JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    CHECK ((state='running') = (lease_owner IS NOT NULL AND lease_until IS NOT NULL)),
    CHECK (last_error IS NULL OR octet_length(last_error) <= 2048)
);
CREATE UNIQUE INDEX storage_maintenance_one_active_kind
    ON storage_maintenance_jobs(repository_id,kind)
    WHERE state IN ('queued','running');
CREATE INDEX storage_maintenance_claimable
    ON storage_maintenance_jobs(state,not_before,lease_until,created_at)
    WHERE state IN ('queued','running');
CREATE INDEX storage_maintenance_history
    ON storage_maintenance_jobs(repository_id,kind,completed_at DESC);

CREATE TABLE storage_maintenance_tombstones (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES users(id),
    oid TEXT NOT NULL CHECK (oid ~ '^[0-9a-f]{40}$' OR oid ~ '^[0-9a-f]{64}$'),
    object_kind TEXT NOT NULL CHECK (object_kind IN ('blob','tree','commit','tag')),
    repository_generation BIGINT NOT NULL CHECK (repository_generation > 0),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','retained','deleted')),
    marked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    delete_after TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT,
    deleted_at TIMESTAMPTZ,
    PRIMARY KEY (repository_id,oid),
    CHECK (last_error IS NULL OR octet_length(last_error) <= 2048)
);
CREATE INDEX storage_maintenance_tombstones_due
    ON storage_maintenance_tombstones(delete_after,repository_id)
    WHERE state='pending';

INSERT INTO schema_migrations (version) VALUES (111) ON CONFLICT DO NOTHING;
