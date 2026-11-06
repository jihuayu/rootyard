ALTER TABLE workspace_checkpoints ADD COLUMN manifest_size BIGINT;
ALTER TABLE workspace_checkpoints ADD CONSTRAINT workspace_manifest_size_valid CHECK (manifest_size IS NULL OR manifest_size BETWEEN 1 AND 16777216);
INSERT INTO schema_migrations(version) VALUES(94) ON CONFLICT DO NOTHING;
