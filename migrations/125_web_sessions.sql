ALTER TABLE tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'api'
    CHECK (kind IN ('api','browser'));
CREATE TABLE web_sessions (
    token_id UUID PRIMARY KEY REFERENCES tokens(id) ON DELETE CASCADE,
    csrf_digest BYTEA NOT NULL CHECK (octet_length(csrf_digest)=32),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX web_sessions_expiry_idx ON web_sessions(expires_at) WHERE NOT revoked;
INSERT INTO schema_migrations(version) VALUES(125) ON CONFLICT DO NOTHING;
