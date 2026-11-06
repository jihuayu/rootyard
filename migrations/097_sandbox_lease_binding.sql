ALTER TABLE sandbox_jobs
    ADD COLUMN lease_epoch BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN workspace_access TEXT NOT NULL DEFAULT 'private'
        CHECK (workspace_access IN ('private', 'live'));
CREATE INDEX sandbox_jobs_active_workspace_idx ON sandbox_jobs(workspace_id, lease_epoch)
    WHERE state IN ('queued', 'running');
INSERT INTO schema_migrations(version) VALUES(97) ON CONFLICT DO NOTHING;
