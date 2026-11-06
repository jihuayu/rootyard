ALTER TABLE sandbox_jobs DROP CONSTRAINT sandbox_jobs_state_check;
ALTER TABLE sandbox_jobs ADD CONSTRAINT sandbox_jobs_state_check
    CHECK (state IN ('queued','preparing','running','succeeded','failed','cancelled','timed_out'));
INSERT INTO schema_migrations(version) VALUES(114) ON CONFLICT DO NOTHING;
