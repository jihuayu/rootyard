-- Context ownership is explicit. Ordinary writable users can only write unbound contexts.
CREATE TABLE forge_trusted_check_contexts (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    context TEXT NOT NULL,
    webhook_id UUID REFERENCES forge_webhooks(id) ON DELETE SET NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(repository_id,context),
    FOREIGN KEY(repository_id,tenant_id) REFERENCES repositories(id,owner_id) ON DELETE CASCADE
);
ALTER TABLE forge_check_runs ADD COLUMN issuer_webhook_id UUID REFERENCES forge_webhooks(id) ON DELETE SET NULL;
ALTER TABLE forge_check_runs ADD COLUMN ci_run_id UUID REFERENCES ci_runs(id) ON DELETE SET NULL;
ALTER TABLE forge_check_runs ADD COLUMN ci_base_oid TEXT;
ALTER TABLE forge_check_runs ADD COLUMN ci_lease_generation BIGINT;
INSERT INTO schema_migrations(version) VALUES(107) ON CONFLICT DO NOTHING;
