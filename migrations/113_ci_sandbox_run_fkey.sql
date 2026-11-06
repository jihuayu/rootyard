ALTER TABLE sandbox_jobs
    ADD CONSTRAINT sandbox_jobs_ci_run_fkey FOREIGN KEY(ci_run_id) REFERENCES ci_runs(id);
INSERT INTO schema_migrations(version) VALUES(113) ON CONFLICT DO NOTHING;
