-- Reserve audit IDs atomically across repositories. Gaps after rolled-back writes
-- are expected; the audit cursor is a stable ID, not a commit-order clock.
LOCK TABLE repository_audit_log IN ACCESS EXCLUSIVE MODE;
CREATE SEQUENCE IF NOT EXISTS repository_audit_log_id_seq AS bigint;
SELECT setval('repository_audit_log_id_seq', COALESCE((SELECT MAX(id) FROM repository_audit_log), 1),
              EXISTS(SELECT 1 FROM repository_audit_log));
ALTER TABLE repository_audit_log ALTER COLUMN id SET DEFAULT nextval('repository_audit_log_id_seq');
ALTER SEQUENCE repository_audit_log_id_seq OWNED BY repository_audit_log.id;
INSERT INTO schema_migrations (version) VALUES (110) ON CONFLICT DO NOTHING;
