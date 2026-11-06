-- A signed CI run is a distinct principal; it is never a fabricated user or workspace.
ALTER TABLE sandbox_jobs ALTER COLUMN workspace_id DROP NOT NULL;
ALTER TABLE sandbox_jobs ALTER COLUMN actor_id DROP NOT NULL;
ALTER TABLE sandbox_jobs
    ADD COLUMN ci_hook_id UUID REFERENCES forge_webhooks(id),
    ADD COLUMN ci_runner_id TEXT,
    ADD COLUMN ci_head_oid TEXT,
    ADD COLUMN ci_storage_generation BIGINT,
    ADD CONSTRAINT sandbox_jobs_principal_check CHECK (
        (workspace_id IS NOT NULL AND actor_id IS NOT NULL AND ci_run_id IS NULL
         AND ci_attempt IS NULL AND ci_lease_generation IS NULL AND ci_hook_id IS NULL
         AND ci_runner_id IS NULL AND ci_head_oid IS NULL AND ci_storage_generation IS NULL)
        OR
        (workspace_id IS NULL AND actor_id IS NULL AND ci_run_id IS NOT NULL
         AND ci_attempt > 0 AND ci_lease_generation > 0 AND ci_hook_id IS NOT NULL
         AND length(ci_runner_id) BETWEEN 1 AND 64
         AND ci_head_oid COLLATE "C" ~ '^[0-9a-f]+$'
         AND length(ci_head_oid) IN (40,64)
         AND ci_storage_generation > 0 AND workspace_access='private')
    );
CREATE UNIQUE INDEX sandbox_jobs_ci_attempt_unique
    ON sandbox_jobs(ci_run_id,ci_attempt,ci_lease_generation) WHERE ci_run_id IS NOT NULL;
INSERT INTO schema_migrations(version) VALUES(98) ON CONFLICT DO NOTHING;
