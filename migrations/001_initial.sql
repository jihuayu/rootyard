CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    digest BYTEA NOT NULL UNIQUE CHECK (octet_length(digest) = 32),
    read_only BOOLEAN NOT NULL DEFAULT false,
    revoked BOOLEAN NOT NULL DEFAULT false,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS repositories (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id),
    name TEXT NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    state TEXT NOT NULL DEFAULT 'provisioning' CHECK (state IN ('provisioning', 'ready')),
    storage_backend TEXT NOT NULL DEFAULT 'gitfs' CHECK (storage_backend = 'gitfs'),
    storage_generation BIGINT NOT NULL DEFAULT 1 CHECK (storage_generation > 0),
    next_retry_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    provision_attempts BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, name)
);
CREATE INDEX IF NOT EXISTS repositories_pending ON repositories (next_retry_at, created_at) WHERE state = 'provisioning';
INSERT INTO schema_migrations (version) VALUES (1) ON CONFLICT DO NOTHING;
