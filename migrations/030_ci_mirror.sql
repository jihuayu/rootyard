CREATE TABLE ci_mirror_evictions (
    repository_id UUID NOT NULL REFERENCES repositories(id),
    eviction_id UUID NOT NULL,
    storage_generation BIGINT NOT NULL CHECK (storage_generation > 0),
    evicted_pins BIGINT NOT NULL CHECK (evicted_pins >= 0),
    evicted_job_views BIGINT NOT NULL CHECK (evicted_job_views >= 0),
    evicted_snapshots BIGINT NOT NULL CHECK (evicted_snapshots >= 0),
    reclaimed_bytes BIGINT NOT NULL CHECK (reclaimed_bytes >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, eviction_id)
);

CREATE INDEX ci_mirror_evictions_repo_created_idx
    ON ci_mirror_evictions (repository_id, created_at DESC, eviction_id DESC);

INSERT INTO schema_migrations (version) VALUES (30);
