-- A repository-local key namespace shared by Issue and comment creation.
-- Entries live as long as this database history; expiration would permit duplicates.
-- The application inserts a null response only inside the creation transaction,
-- and fills it before committing. Direct database administrators remain trusted.
CREATE TABLE forge_creation_requests (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    idempotency_key TEXT NOT NULL CHECK (
        octet_length(idempotency_key) >= 1 AND octet_length(idempotency_key) <= 128
        AND idempotency_key COLLATE "C" !~ '[^A-Za-z0-9._:-]'
    ),
    request JSONB NOT NULL CHECK (
        jsonb_typeof(request) = 'object' AND octet_length(request::text) <= 65536
    ),
    response JSONB CHECK (
        jsonb_typeof(response) = 'object' AND octet_length(response::text) <= 65536
    ),
    PRIMARY KEY (tenant_id, repository_id, idempotency_key),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id)
);
INSERT INTO schema_migrations (version) VALUES (7);
