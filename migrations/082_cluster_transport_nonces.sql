-- One-use signed transport envelopes. PostgreSQL is the shared replay authority.
CREATE TABLE IF NOT EXISTS cluster_transport_nonces (
    nonce UUID PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS cluster_transport_nonces_expiry_idx
    ON cluster_transport_nonces(expires_at);
INSERT INTO schema_migrations (version) VALUES (82) ON CONFLICT DO NOTHING;
