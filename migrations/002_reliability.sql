ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_state_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_state_check CHECK (state IN ('provisioning','ready','recovering'));
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS recovery_reason TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS repositories_owner_identity ON repositories(id,owner_id);
CREATE UNIQUE INDEX IF NOT EXISTS tokens_user_identity ON tokens(id,user_id);
CREATE TABLE IF NOT EXISTS git_operations (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL,
    actor_id UUID NOT NULL REFERENCES users(id),
    token_id UUID NOT NULL,
    actor_name TEXT NOT NULL CHECK (length(actor_name) BETWEEN 1 AND 63),
    sequence BIGINT NOT NULL CHECK(sequence > 0),
    storage_generation BIGINT NOT NULL CHECK(storage_generation > 0),
    evidence JSONB NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('unknown','recorded','no_ref_changes')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    settled_at TIMESTAMPTZ,
    FOREIGN KEY(repository_id,actor_id) REFERENCES repositories(id,owner_id),
    FOREIGN KEY(token_id,actor_id) REFERENCES tokens(id,user_id),
    UNIQUE(repository_id,storage_generation,sequence),
    UNIQUE(id,repository_id,storage_generation,sequence)
);
CREATE INDEX IF NOT EXISTS operations_unknown_order ON git_operations(repository_id,storage_generation,sequence) WHERE outcome='unknown';
CREATE TABLE IF NOT EXISTS outbox_events (
    event_id TEXT PRIMARY KEY CHECK(event_id ~ '^[0-9a-f]{64}$'),
    operation_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    storage_generation BIGINT NOT NULL,
    operation_sequence BIGINT NOT NULL,
    transaction_sequence BIGINT NOT NULL CHECK(transaction_sequence > 0),
    ref_name TEXT NOT NULL CHECK(length(ref_name) BETWEEN 6 AND 1024 AND ref_name LIKE 'refs/%'),
    old_oid TEXT NOT NULL CHECK(old_oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    new_oid TEXT NOT NULL CHECK(new_oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK(length(old_oid)=length(new_oid)),
    FOREIGN KEY(operation_id,repository_id,storage_generation,operation_sequence)
      REFERENCES git_operations(id,repository_id,storage_generation,sequence),
    UNIQUE(operation_id,transaction_sequence,ref_name)
);
CREATE INDEX IF NOT EXISTS outbox_ref_order ON outbox_events(repository_id,ref_name,storage_generation,operation_sequence,transaction_sequence);
CREATE TABLE IF NOT EXISTS event_deliveries (
    event_id TEXT NOT NULL REFERENCES outbox_events(event_id),
    consumer TEXT NOT NULL CHECK(consumer IN ('audit-log','ref-index')),
    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','delivered')),
    lease_owner UUID,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK(lease_generation >= 0),
    lease_until TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    attempts BIGINT NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    last_error_code TEXT,
    delivered_at TIMESTAMPTZ,
    PRIMARY KEY(event_id,consumer),
    CHECK((state='leased' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
       OR (state<>'leased' AND lease_owner IS NULL AND lease_until IS NULL))
);
CREATE INDEX IF NOT EXISTS deliveries_ready ON event_deliveries(consumer,next_attempt_at) WHERE state <> 'delivered';
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY REFERENCES outbox_events(event_id),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
-- A rebuildable cache only. Native Git refs remain authoritative.
CREATE TABLE IF NOT EXISTS repository_ref_projection (
    repository_id UUID NOT NULL REFERENCES repositories(id),
    ref_name TEXT NOT NULL,
    oid TEXT,
    deleted BOOLEAN NOT NULL,
    storage_generation BIGINT NOT NULL,
    operation_sequence BIGINT NOT NULL,
    transaction_sequence BIGINT NOT NULL,
    event_id TEXT NOT NULL REFERENCES outbox_events(event_id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(repository_id,ref_name),
    CHECK((deleted AND oid IS NULL) OR (NOT deleted AND oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'))
);
INSERT INTO schema_migrations(version) VALUES(2) ON CONFLICT DO NOTHING;
