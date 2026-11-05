-- Track A: External CI Webhooks, HMAC-SHA256 Signed Deliveries, and Idempotent Callbacks.
-- All numeric bounds use explicit >= and <= comparisons for pg_dump catalog invariance.

CREATE TABLE IF NOT EXISTS forge_webhooks (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    url TEXT NOT NULL CHECK (
        octet_length(url) >= 8 AND octet_length(url) <= 1024
        AND (
            url LIKE 'https://%'
            OR url LIKE 'http://127.0.0.1%'
            OR url LIKE 'http://[::1]%'
            OR url LIKE 'http://localhost%'
        )
    ),
    secret TEXT NOT NULL CHECK (
        octet_length(secret) >= 8 AND octet_length(secret) <= 256
    ),
    secret_sha256 TEXT NOT NULL CHECK (
        (secret_sha256 COLLATE "C") ~ '^[0-9a-f]{64}$'
    ),
    events JSONB NOT NULL DEFAULT '["push","pull_request"]'::jsonb CHECK (
        jsonb_typeof(events) = 'array'
        AND jsonb_array_length(events) >= 1
        AND jsonb_array_length(events) <= 16
    ),
    ci_contexts JSONB NOT NULL DEFAULT '["ci/default"]'::jsonb CHECK (
        jsonb_typeof(ci_contexts) = 'array'
        AND jsonb_array_length(ci_contexts) <= 64
    ),
    auto_ci_pin BOOLEAN NOT NULL DEFAULT true,
    active BOOLEAN NOT NULL DEFAULT true,
    max_attempts BIGINT NOT NULL DEFAULT 5 CHECK (
        max_attempts >= 1 AND max_attempts <= 20
    ),
    timeout_ms BIGINT NOT NULL DEFAULT 5000 CHECK (
        timeout_ms >= 100 AND timeout_ms <= 30000
    ),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS forge_webhooks_repo_active_idx
    ON forge_webhooks (tenant_id, repository_id, active, created_at ASC, id ASC);

CREATE TABLE IF NOT EXISTS forge_webhook_deliveries (
    id UUID PRIMARY KEY,
    webhook_id UUID NOT NULL REFERENCES forge_webhooks(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    sequence BIGINT NOT NULL DEFAULT 1 CHECK (sequence > 0),
    event_id TEXT NOT NULL CHECK (
        octet_length(event_id) >= 1 AND octet_length(event_id) <= 128
    ),
    event_type TEXT NOT NULL CHECK (
        event_type IN ('push', 'pull_request', 'check_run', 'ping')
    ),
    payload JSONB NOT NULL,
    request_headers JSONB NOT NULL,
    signature_256 TEXT NOT NULL CHECK (
        signature_256 LIKE 'sha256=%' AND octet_length(signature_256) = 71
    ),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending', 'leased', 'delivered', 'failed', 'dead_letter')
    ),
    attempts BIGINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts BIGINT NOT NULL DEFAULT 5 CHECK (
        max_attempts >= 1 AND max_attempts <= 20
    ),
    response_status INTEGER CHECK (
        response_status IS NULL OR (response_status >= 100 AND response_status <= 599)
    ),
    last_error TEXT,
    next_attempt_unix BIGINT NOT NULL DEFAULT 0 CHECK (next_attempt_unix >= 0),
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (webhook_id, event_id),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS forge_webhook_deliveries_hook_seq_idx
    ON forge_webhook_deliveries (tenant_id, repository_id, webhook_id, sequence ASC);

CREATE INDEX IF NOT EXISTS forge_webhook_deliveries_due_idx
    ON forge_webhook_deliveries (tenant_id, repository_id, state, next_attempt_unix ASC, sequence ASC);

CREATE TABLE IF NOT EXISTS forge_webhook_callbacks (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    webhook_id UUID NOT NULL REFERENCES forge_webhooks(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL CHECK (
        octet_length(event_id) >= 1 AND octet_length(event_id) <= 128
    ),
    request_sha256 TEXT NOT NULL CHECK (
        (request_sha256 COLLATE "C") ~ '^[0-9a-f]{64}$'
    ),
    response JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, event_id),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS forge_webhook_callbacks_hook_idx
    ON forge_webhook_callbacks (tenant_id, repository_id, webhook_id, created_at DESC);

INSERT INTO schema_migrations (version) VALUES (40) ON CONFLICT (version) DO NOTHING;
