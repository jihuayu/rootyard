-- Git object identity is chosen once at repository creation and cannot change
-- while refs or objects are present.
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS object_format TEXT NOT NULL DEFAULT 'sha1';
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_object_format_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_object_format_check
    CHECK (object_format IN ('sha1', 'sha256'));

INSERT INTO schema_migrations (version) VALUES (70) ON CONFLICT DO NOTHING;
