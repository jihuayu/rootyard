-- Minimal PostgreSQL metadata core for the trusted RefStore increment (#107-A1).
--
-- This migration adds only one explicitly initialized gate per repository, the
-- current ref rows it owns, and immutable terminal/event receipts. It does NOT
-- add read snapshots, durable pins, roots, artifact holds, publication
-- decisions, pack memberships, blob receipts or GC consumption. There is no
-- foreign key to a blob/receipt table before #109, and no HTTP or serving
-- cutover: the legacy GitFS/Pando authorities and long read leases remain in
-- place, initializing a gate must never switch repository serving, and a
-- repository with a core gate is not serve-ready until a later explicit
-- cutover API exists.
--
-- Bootstrap is restricted to an explicitly unserved repository:
-- `repositories.state='provisioning'`, `storage_backend='gitfs'`,
-- `transition_state='stable'`, no `pando_repository_states` row and no legacy
-- `repository_ref_projection` row, with matching tenant and object format.
-- Every new core commit locks the same repository row after the migration-138
-- operation/lane registry and before the gate, and rechecks those conditions;
-- a repository that becomes ready/draining/Pando therefore rejects new core
-- mutations while immutable terminal replay and operation lookup still return
-- the old proof.
--
-- Operation identity, cancellation tombstones and terminal replay continue to
-- live in migration 138. A core commit records its terminal result and its
-- event in the same transaction as the gate/ref CAS. A request whose
-- worst-case committed or rejected terminal would exceed the unchanged 64 KiB
-- migration-138 terminal body is rejected before the registry is touched. Rows
-- are never trimmed or released by TTL here.
CREATE TABLE ref_store_core_gates (
    repository_id UUID PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1','sha256')),
    history_incarnation UUID NOT NULL,
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch > 0),
    head_ref TEXT NOT NULL CHECK (
        octet_length(head_ref) >= 12 AND octet_length(head_ref) <= 1024
        AND head_ref LIKE 'refs/heads/%' AND head_ref !~ '[[:cntrl:]]'
    ),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

-- Ref rows are the exact old/new CAS targets of the core. A tombstone is a real
-- DELETE in this transaction; a zero object id is not stored as a live ref.
CREATE TABLE ref_store_core_refs (
    repository_id UUID NOT NULL REFERENCES ref_store_core_gates(repository_id) ON DELETE CASCADE,
    ref_name TEXT NOT NULL CHECK (
        octet_length(ref_name) >= 6 AND octet_length(ref_name) <= 1024
        AND ref_name LIKE 'refs/%' AND ref_name !~ '[[:cntrl:]]'
    ),
    oid TEXT NOT NULL CHECK (oid ~ '^[0-9a-f]{40}$' OR oid ~ '^[0-9a-f]{64}$'),
    revision BIGINT NOT NULL CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, ref_name)
);

-- Prefix checks compare a batch against current rows and against each other in
-- the same gate-locked transaction; this index keeps the current-row probe
-- repository-scoped.
CREATE INDEX ref_store_core_refs_prefix ON ref_store_core_refs(repository_id, ref_name);

-- One immutable event per accepted or rejected operation, written in the same
-- transaction as the registry terminal result. `revision` is the gate revision
-- observed by the terminal result; a rejection does not advance it.
CREATE TABLE ref_store_core_events (
    event_id UUID PRIMARY KEY,
    repository_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 0),
    operation_id UUID NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('committed','rejected')),
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, operation_id),
    FOREIGN KEY (repository_id, operation_id)
        REFERENCES ref_store_operations(repository_id, operation_id) ON DELETE CASCADE
);

CREATE FUNCTION rootyard_ref_store_core_event_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ref-store core event is immutable';
END $$;
CREATE TRIGGER ref_store_core_event_immutable
    BEFORE UPDATE ON ref_store_core_events
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_event_immutable();

INSERT INTO schema_migrations (version) VALUES (139) ON CONFLICT DO NOTHING;
