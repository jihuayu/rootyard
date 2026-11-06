CREATE TABLE workspace_capture_state (
    workspace_id UUID PRIMARY KEY REFERENCES workspaces(id),
    fingerprint TEXT NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO schema_migrations (version) VALUES (91) ON CONFLICT DO NOTHING;
