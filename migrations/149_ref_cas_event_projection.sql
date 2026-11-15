-- ===========================================================================
-- Migration 149 — Ref-CAS event replay cursors, immutable PG projections,
-- non-authorizing materialized ref view, and reliable projection jobs (#117).
--
-- Design invariants:
--   1. Durable replay frontiers live explicitly in `ref_cas_projection_cursors`
--      keyed by `(group_id, history_incarnation)` without SERIAL sequences;
--      replay never infers progress from `MAX(id)` or `MAX(sequence)`.
--   2. `ref_cas_projected_operations` stores optional snapshot `actor_id` /
--      `token_id` WITHOUT FKs to `tokens` and without membership triggers, so
--      revoked-token / removed-member committed Ref-CAS facts still project.
--   3. Historical projection rows carry `can_authorize_write = FALSE` with
--      `CHECK (can_authorize_write = FALSE)` and immutability triggers; they
--      never authorize new ref writes.
--   4. Unresolved (`queued`, `running`, `unknown_hold`) and terminal `failed`
--      jobs plus active operation/event dedup rows have no TTL expiration.
-- ===========================================================================

CREATE FUNCTION rootyard_ref_cas_projection_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ref-cas historical projection record is immutable';
END $$;

-- ---------------------------------------------------------------------------
-- 1. Durable per-stream replay cursor & archive truncation closure boundary.
-- ---------------------------------------------------------------------------
CREATE TABLE ref_cas_projection_cursors (
    group_id BIGINT NOT NULL CHECK (group_id >= 0),
    history_incarnation UUID NOT NULL,
    group_epoch BIGINT NOT NULL CHECK (group_epoch >= 1),
    applied_event_seq BIGINT NOT NULL DEFAULT 0 CHECK (applied_event_seq >= 0),
    applied_log_index BIGINT NOT NULL DEFAULT 0 CHECK (applied_log_index >= 0),
    applied_log_term BIGINT NOT NULL DEFAULT 0 CHECK (applied_log_term >= 0),
    last_event_id TEXT CHECK (last_event_id IS NULL OR (octet_length(last_event_id) >= 1 AND octet_length(last_event_id) <= 128)),
    truncation_cutoff_log_index BIGINT CHECK (truncation_cutoff_log_index IS NULL OR truncation_cutoff_log_index >= 1),
    truncation_cutoff_event_seq BIGINT CHECK (truncation_cutoff_event_seq IS NULL OR truncation_cutoff_event_seq >= 1),
    truncation_cutoff_log_term BIGINT CHECK (truncation_cutoff_log_term IS NULL OR truncation_cutoff_log_term >= 0),
    truncation_closure_digest TEXT CHECK (truncation_closure_digest IS NULL OR truncation_closure_digest ~ '^[0-9a-f]{64}$'),
    truncation_archive_uri TEXT CHECK (truncation_archive_uri IS NULL OR (octet_length(truncation_archive_uri) >= 1 AND octet_length(truncation_archive_uri) <= 1024)),
    stream_state TEXT NOT NULL DEFAULT 'active' CHECK (stream_state IN ('active', 'resync_required')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (group_id, history_incarnation),
    CHECK (
        (truncation_cutoff_log_index IS NULL
         AND truncation_cutoff_event_seq IS NULL
         AND truncation_cutoff_log_term IS NULL
         AND truncation_closure_digest IS NULL)
        OR
        (truncation_cutoff_log_index IS NOT NULL
         AND truncation_cutoff_event_seq IS NOT NULL
         AND truncation_cutoff_log_term IS NOT NULL
         AND truncation_closure_digest IS NOT NULL)
    )
);

-- ---------------------------------------------------------------------------
-- 2. Immutable projected Ref-CAS terminal operations ledger (non-authorizing).
-- ---------------------------------------------------------------------------
CREATE TABLE ref_cas_projected_operations (
    op_event_id TEXT PRIMARY KEY CHECK (op_event_id ~ '^[0-9a-f]{64}$'),
    history_incarnation UUID NOT NULL,
    group_id BIGINT NOT NULL CHECK (group_id >= 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch >= 1),
    log_index BIGINT NOT NULL CHECK (log_index >= 1),
    log_term BIGINT NOT NULL CHECK (log_term >= 0),
    event_seq BIGINT NOT NULL CHECK (event_seq >= 1),
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 0),
    outcome TEXT NOT NULL CHECK (octet_length(outcome) >= 1 AND octet_length(outcome) <= 64),
    head_ref TEXT CHECK (head_ref IS NULL OR (octet_length(head_ref) >= 1 AND octet_length(head_ref) <= 1024)),
    actor_id UUID,
    token_id UUID,
    applied_ref_count INTEGER NOT NULL CHECK (applied_ref_count >= 0),
    terminal_digest TEXT NOT NULL CHECK (terminal_digest ~ '^[0-9a-f]{64}$'),
    terminal_payload JSONB NOT NULL,
    can_authorize_write BOOLEAN NOT NULL DEFAULT FALSE CHECK (can_authorize_write = FALSE),
    projected_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (history_incarnation, group_id, group_epoch, log_index, operation_id),
    UNIQUE (history_incarnation, group_id, event_seq),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

CREATE INDEX ref_cas_projected_ops_repo_idx
    ON ref_cas_projected_operations (repository_id, group_epoch DESC, log_index DESC);

CREATE TRIGGER ref_cas_projected_operations_immutable
    BEFORE UPDATE ON ref_cas_projected_operations
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_cas_projection_immutable();

CREATE TRIGGER ref_cas_projected_operations_no_truncate
    BEFORE TRUNCATE ON ref_cas_projected_operations
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_cas_projection_immutable();

-- ---------------------------------------------------------------------------
-- 3. Immutable per-ref Ref-CAS projected event dedup ledger.
-- ---------------------------------------------------------------------------
CREATE TABLE ref_cas_projected_events (
    event_id TEXT PRIMARY KEY CHECK (event_id ~ '^[0-9a-f]{64}$'),
    op_event_id TEXT NOT NULL REFERENCES ref_cas_projected_operations(op_event_id) ON DELETE CASCADE,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    history_incarnation UUID NOT NULL,
    group_id BIGINT NOT NULL CHECK (group_id >= 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch >= 1),
    log_index BIGINT NOT NULL CHECK (log_index >= 1),
    log_term BIGINT NOT NULL CHECK (log_term >= 0),
    event_seq BIGINT NOT NULL CHECK (event_seq >= 1),
    operation_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 0),
    ref_sequence BIGINT NOT NULL CHECK (ref_sequence >= 1),
    ref_name TEXT NOT NULL CHECK (octet_length(ref_name) >= 1 AND octet_length(ref_name) <= 1024),
    old_oid TEXT CHECK (old_oid IS NULL OR old_oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    new_oid TEXT CHECK (new_oid IS NULL OR new_oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    deleted BOOLEAN NOT NULL,
    projected_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (op_event_id, ref_sequence),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

CREATE INDEX ref_cas_projected_events_repo_order_idx
    ON ref_cas_projected_events (repository_id, group_epoch ASC, log_index ASC, event_seq ASC, ref_sequence ASC);

CREATE TRIGGER ref_cas_projected_events_immutable
    BEFORE UPDATE ON ref_cas_projected_events
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_cas_projection_immutable();

CREATE TRIGGER ref_cas_projected_events_no_truncate
    BEFORE TRUNCATE ON ref_cas_projected_events
    FOR EACH STATEMENT EXECUTE FUNCTION rootyard_ref_cas_projection_immutable();

-- ---------------------------------------------------------------------------
-- 4. Materialized read-only Ref-CAS ref view (never authorizes new writes).
-- ---------------------------------------------------------------------------
CREATE TABLE ref_cas_projected_refs (
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    ref_name TEXT NOT NULL CHECK (octet_length(ref_name) >= 1 AND octet_length(ref_name) <= 1024),
    oid TEXT CHECK (oid IS NULL OR oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    deleted BOOLEAN NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 0),
    history_incarnation UUID NOT NULL,
    group_id BIGINT NOT NULL CHECK (group_id >= 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch >= 1),
    log_index BIGINT NOT NULL CHECK (log_index >= 1),
    log_term BIGINT NOT NULL CHECK (log_term >= 0),
    event_seq BIGINT NOT NULL CHECK (event_seq >= 1),
    op_event_id TEXT NOT NULL REFERENCES ref_cas_projected_operations(op_event_id) ON DELETE CASCADE,
    can_authorize_write BOOLEAN NOT NULL DEFAULT FALSE CHECK (can_authorize_write = FALSE),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, ref_name),
    CHECK (deleted OR oid IS NOT NULL),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 5. Reliable business jobs emitted atomically alongside PG projections.
-- ---------------------------------------------------------------------------
CREATE TABLE ref_cas_projection_jobs (
    job_key TEXT PRIMARY KEY CHECK (job_key ~ '^[0-9a-f]{64}$'),
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    op_event_id TEXT NOT NULL REFERENCES ref_cas_projected_operations(op_event_id) ON DELETE CASCADE,
    history_incarnation UUID NOT NULL,
    group_id BIGINT NOT NULL CHECK (group_id >= 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch >= 1),
    log_index BIGINT NOT NULL CHECK (log_index >= 1),
    event_seq BIGINT NOT NULL CHECK (event_seq >= 1),
    kind TEXT NOT NULL CHECK (kind IN ('ci_sync', 'repo_index_refresh', 'artifact_reconcile', 'backup_checkpoint')),
    scope_key TEXT NOT NULL CHECK (octet_length(scope_key) >= 1 AND octet_length(scope_key) <= 256),
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'unknown_hold')),
    attempt BIGINT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    lease_owner UUID,
    lease_until TIMESTAMPTZ,
    last_error TEXT CHECK (last_error IS NULL OR octet_length(last_error) <= 2048),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    CHECK ((state = 'running') = (lease_owner IS NOT NULL AND lease_until IS NOT NULL)),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

CREATE INDEX ref_cas_projection_jobs_claim_idx
    ON ref_cas_projection_jobs (state, created_at ASC, job_key ASC)
    WHERE state IN ('queued', 'running');

CREATE INDEX ref_cas_projection_jobs_repo_idx
    ON ref_cas_projection_jobs (repository_id, kind, state);

INSERT INTO schema_migrations (version) VALUES (149) ON CONFLICT DO NOTHING;
