-- Cluster authority is granted to individual tokens by a database administrator.
-- Repository ownership and repository RBAC never imply infrastructure authority.
CREATE TABLE IF NOT EXISTS cluster_operator_tokens (
    token_id UUID PRIMARY KEY REFERENCES tokens(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    granted_by TEXT NOT NULL CHECK (length(granted_by) BETWEEN 1 AND 128)
);

INSERT INTO schema_migrations (version) VALUES (80) ON CONFLICT DO NOTHING;
