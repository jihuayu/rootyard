CREATE TABLE sandbox_jobs (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    ci_run_id UUID,
    ci_attempt BIGINT,
    ci_lease_generation BIGINT,
    actor_id UUID NOT NULL REFERENCES users(id),
    host_id UUID NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','cancelled','timed_out')),
    pid INTEGER,
    exit_code INTEGER,
    argv JSONB NOT NULL,
    timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds BETWEEN 1 AND 3600),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX sandbox_jobs_workspace_idx ON sandbox_jobs(workspace_id,created_at DESC);
INSERT INTO schema_migrations(version) VALUES(92) ON CONFLICT DO NOTHING;
