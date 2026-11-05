-- Track 4 (Milestone M16): Multi-Node Consistent Shard Routing, Primary Lease/Epoch
-- Storage Fencing, and 4-Stage Automated Node Failover & Read-Only Degradation Drills.
-- All numeric bounds use explicit >=, <=, and < predicates for pg_dump catalog invariance.

CREATE TABLE IF NOT EXISTS shard_nodes (
    node_id TEXT PRIMARY KEY CHECK (
        (node_id COLLATE "C") ~ '^[a-z0-9][a-z0-9._-]{0,62}$'
    ),
    endpoint TEXT NOT NULL CHECK (
        octet_length(btrim(endpoint)) >= 1 AND octet_length(endpoint) <= 512
        AND endpoint !~ '[[:cntrl:]]'
    ),
    role TEXT NOT NULL DEFAULT 'primary' CHECK (
        role IN ('primary', 'replica', 'draining', 'fenced')
    ),
    status TEXT NOT NULL DEFAULT 'healthy' CHECK (
        status IN ('healthy', 'degraded', 'draining', 'fenced', 'offline')
    ),
    capacity_bytes BIGINT NOT NULL DEFAULT 107374182400 CHECK (capacity_bytes > 0),
    used_bytes BIGINT NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    lease_epoch BIGINT NOT NULL DEFAULT 1 CHECK (lease_epoch > 0),
    lease_expires_unix BIGINT NOT NULL DEFAULT 0 CHECK (lease_expires_unix >= 0),
    fenced_epoch BIGINT NOT NULL DEFAULT 0 CHECK (fenced_epoch >= 0),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (used_bytes <= capacity_bytes)
);

CREATE INDEX IF NOT EXISTS shard_nodes_role_status_idx
    ON shard_nodes (role, status, node_id ASC);

CREATE TABLE IF NOT EXISTS shard_virtual_buckets (
    bucket_id INTEGER PRIMARY KEY CHECK (
        bucket_id >= 0 AND bucket_id < 1024
    ),
    primary_node_id TEXT NOT NULL REFERENCES shard_nodes(node_id),
    read_replica_nodes JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(read_replica_nodes) = 'array'
        AND jsonb_array_length(read_replica_nodes) <= 16
    ),
    route_epoch BIGINT NOT NULL DEFAULT 1 CHECK (route_epoch > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS shard_virtual_buckets_primary_idx
    ON shard_virtual_buckets (primary_node_id, bucket_id ASC);

CREATE TABLE IF NOT EXISTS repository_shard_routes (
    tenant_id UUID NOT NULL REFERENCES users(id),
    repository_id UUID NOT NULL,
    bucket_id INTEGER NOT NULL CHECK (
        bucket_id >= 0 AND bucket_id < 1024
    ),
    primary_node_id TEXT NOT NULL REFERENCES shard_nodes(node_id),
    read_replica_nodes JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(read_replica_nodes) = 'array'
        AND jsonb_array_length(read_replica_nodes) <= 16
    ),
    replica_watermarks JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(replica_watermarks) = 'object'
    ),
    explicit_override BOOLEAN NOT NULL DEFAULT false,
    route_epoch BIGINT NOT NULL DEFAULT 1 CHECK (route_epoch > 0),
    fencing_token BIGINT NOT NULL DEFAULT 1 CHECK (fencing_token > 0),
    fenced_epoch BIGINT NOT NULL DEFAULT 0 CHECK (fenced_epoch >= 0),
    draining BOOLEAN NOT NULL DEFAULT false,
    read_only_degraded BOOLEAN NOT NULL DEFAULT false,
    degraded_reason TEXT NOT NULL DEFAULT '' CHECK (
        octet_length(degraded_reason) <= 1024
    ),
    in_flight_writes BIGINT NOT NULL DEFAULT 0 CHECK (in_flight_writes >= 0),
    required_generation BIGINT NOT NULL DEFAULT 1 CHECK (required_generation > 0),
    required_op_sequence BIGINT NOT NULL DEFAULT 0 CHECK (required_op_sequence >= 0),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id),
    UNIQUE (repository_id),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE,
    CHECK (fencing_token >= route_epoch)
);

CREATE INDEX IF NOT EXISTS repository_shard_routes_primary_idx
    ON repository_shard_routes (primary_node_id, route_epoch DESC);

CREATE INDEX IF NOT EXISTS repository_shard_routes_bucket_idx
    ON repository_shard_routes (bucket_id, repository_id ASC);

CREATE TABLE IF NOT EXISTS shard_failover_operations (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES users(id),
    repository_id UUID NOT NULL,
    old_primary_node_id TEXT NOT NULL REFERENCES shard_nodes(node_id),
    new_primary_node_id TEXT NOT NULL REFERENCES shard_nodes(node_id),
    old_route_epoch BIGINT NOT NULL CHECK (old_route_epoch > 0),
    new_route_epoch BIGINT NOT NULL CHECK (new_route_epoch > 0),
    fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
    storage_generation BIGINT NOT NULL DEFAULT 1 CHECK (storage_generation > 0),
    state TEXT NOT NULL DEFAULT 'draining' CHECK (
        state IN ('draining', 'fenced', 'verified', 'promoted', 'aborted')
    ),
    reason TEXT NOT NULL DEFAULT '' CHECK (octet_length(reason) <= 1024),
    snapshot JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(snapshot) = 'object'
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE,
    CHECK (
        old_primary_node_id <> new_primary_node_id
        AND new_route_epoch = old_route_epoch + 1
        AND fencing_token >= new_route_epoch
    )
);

CREATE INDEX IF NOT EXISTS shard_failover_operations_repo_idx
    ON shard_failover_operations (tenant_id, repository_id, created_at DESC, id DESC);

INSERT INTO schema_migrations (version) VALUES (60) ON CONFLICT DO NOTHING;
