-- ===========================================================================
-- Migration 145 — durable `pg_refstore` serving binding (new default authority).
--
-- A repository served by the PostgreSQL ref-store core is a *new* authority
-- kind, disjoint from the legacy native-GitFS and Pando backends:
--
--   * `repositories.storage_backend='pg_refstore'` is a third, explicitly
--     enumerated backend value (never the legacy default, never Pando);
--   * the durable authority is the single `ref_store_serving_repositories` row
--     below. It binds owner (tenant) + repository name + repository id +
--     object format + `history_incarnation` + `authority_epoch` + `group_epoch`
--     + the *actual opened* Blob backend identity digest. A bare
--     `repositories.state='ready'` row, a forged `storage_backend` string, or a
--     `repository_ref_projection` row is NOT authority;
--   * the row is written once per repository and its realm/identity columns are
--     immutable (trigger). A retry of the same provisioning keeps the stored
--     random ids; only a brand-new intent mints new ones;
--   * the row may only become `ready` when the matching migration-139 core gate
--     and the matching migration-144 protocol realm already exist in the same
--     transaction (trigger), so "ready" never precedes the protocol rows;
--   * `repositories.state='ready'` for a `pg_refstore` repository is refused
--     unless the serving row is already exactly `ready` (trigger). There is
--     therefore no second write authority and no ready row without a binding.
--
-- Nothing in this migration touches existing rows: no repository is flipped to
-- `pg_refstore`, no legacy `gitfs`/Pando repository becomes ready differently,
-- and the strict unserved `provisioning`/`gitfs` bootstrap used by the existing
-- non-serving core fixtures is unchanged. `gitfs`/`pando` repositories remain
-- served by their existing authority.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. A third, explicitly enumerated backend. The legacy default stays `gitfs`.
-- ---------------------------------------------------------------------------
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_storage_backend_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_storage_backend_check
    CHECK (storage_backend IN ('gitfs', 'pando', 'pg_refstore'));

-- ---------------------------------------------------------------------------
-- 2. The durable serving binding / provisioning intent.
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_serving_repositories (
    repository_id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    name TEXT NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1', 'sha256')),
    -- Random only when the intent row is first created; a retry reads the
    -- stored value back and must use exactly that value.
    history_incarnation UUID NOT NULL,
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch > 0),
    -- Digest of the actually opened Blob backend (see
    -- `blob_store::BlobBackendIdentity`). It is not a credential and it cannot
    -- be turned back into write authority: lookups compare it with the identity
    -- of the concrete store the serving engine has open.
    backend_identity TEXT NOT NULL CHECK (backend_identity ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('pending', 'ready')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    -- One durable intent per owner/repository name: concurrent provisioning of
    -- the same name converges on this row instead of creating a second one.
    UNIQUE (owner_id, name),
    FOREIGN KEY (repository_id, owner_id) REFERENCES repositories(id, owner_id)
        ON DELETE RESTRICT
);

CREATE INDEX ref_store_serving_repositories_owner ON ref_store_serving_repositories(owner_id, name);

-- Binding identity is immutable; the only legal transition is pending -> ready;
-- `ready` requires the exact gate + protocol realm and the pg_refstore backend
-- to exist in this very transaction.
CREATE FUNCTION rootyard_serving_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'the ref-store serving binding is durable authority and cannot be deleted';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF (NEW.repository_id, NEW.owner_id, NEW.name, NEW.object_format,
            NEW.history_incarnation, NEW.authority_epoch, NEW.group_epoch,
            NEW.backend_identity, NEW.created_at)
           IS DISTINCT FROM
           (OLD.repository_id, OLD.owner_id, OLD.name, OLD.object_format,
            OLD.history_incarnation, OLD.authority_epoch, OLD.group_epoch,
            OLD.backend_identity, OLD.created_at)
        THEN
            RAISE EXCEPTION 'the ref-store serving binding identity is immutable';
        END IF;
        IF OLD.state = 'ready' AND NEW.state <> 'ready' THEN
            RAISE EXCEPTION 'a ready ref-store serving binding is irreversible';
        END IF;
        IF OLD.state = 'pending' AND NEW.state NOT IN ('pending', 'ready') THEN
            RAISE EXCEPTION 'the ref-store serving binding only moves pending -> ready';
        END IF;
    END IF;
    -- Every binding row (pending or ready, insert or update) must name the
    -- exact durable repository row: id, owner namespace, name and object format.
    IF NOT EXISTS (
        SELECT 1 FROM repositories r
        WHERE r.id = NEW.repository_id AND r.owner_id = NEW.owner_id
          AND r.name = NEW.name AND r.object_format = NEW.object_format
          AND r.storage_backend = 'pg_refstore' AND r.transition_state = 'stable'
          AND (NEW.state = 'ready' OR r.state = 'provisioning')
    ) THEN
        RAISE EXCEPTION 'a serving binding must name the exact stable pg_refstore repository; pending requires provisioning';
    END IF;
    IF NEW.state = 'ready' THEN
        IF NOT EXISTS (
            SELECT 1 FROM repositories r
            WHERE r.id = NEW.repository_id AND r.owner_id = NEW.owner_id
              AND r.name = NEW.name AND r.object_format = NEW.object_format
              AND r.storage_backend = 'pg_refstore' AND r.transition_state = 'stable'
        ) THEN
            RAISE EXCEPTION 'a serving binding needs the exact stable pg_refstore repository row/name/format';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM ref_store_core_gates g
            WHERE g.repository_id = NEW.repository_id
              AND g.tenant_id = NEW.owner_id
              AND g.object_format = NEW.object_format
              AND g.history_incarnation = NEW.history_incarnation
              AND g.authority_epoch = NEW.authority_epoch
              AND g.group_epoch = NEW.group_epoch
        ) THEN
            RAISE EXCEPTION 'a ready serving binding needs the exact matching core gate';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM ref_store_core_protocol_repos p
            WHERE p.repository_id = NEW.repository_id
              AND p.tenant_id = NEW.owner_id
              AND p.object_format = NEW.object_format
              AND p.history_incarnation = NEW.history_incarnation
              AND p.authority_epoch = NEW.authority_epoch
              AND p.group_epoch = NEW.group_epoch
              AND p.decision_required
        ) THEN
            RAISE EXCEPTION 'a ready serving binding needs the exact matching protocol realm';
        END IF;
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END $$;

CREATE TRIGGER ref_store_serving_binding_guard
    BEFORE INSERT OR UPDATE OR DELETE ON ref_store_serving_repositories
    FOR EACH ROW EXECUTE FUNCTION rootyard_serving_binding_guard();

-- A `pg_refstore` repository only becomes ready once its binding is already
-- exactly ready; the backend itself is immutable in both directions. Legacy
-- gitfs/pando lifecycle updates (including the pando gitfs->pando cutover) are
-- not affected.
CREATE FUNCTION rootyard_pg_refstore_repository_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- TG_OP-safe: OLD is only valid for UPDATE/DELETE, NEW only for
    -- INSERT/UPDATE, so every branch below reads exactly one of them.
    IF TG_OP = 'INSERT' THEN
        -- Readiness is only ever published by the provisioning transaction
        -- after the matching gate/protocol/serving rows exist. A direct
        -- INSERT of a ready pg_refstore row is always refused.
        IF NEW.storage_backend = 'pg_refstore' AND NEW.state = 'ready' THEN
            RAISE EXCEPTION 'a pg_refstore repository cannot be inserted ready; provisioning publishes readiness';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    IF (OLD.storage_backend = 'pg_refstore' OR NEW.storage_backend = 'pg_refstore')
       AND OLD.storage_backend <> NEW.storage_backend THEN
        RAISE EXCEPTION 'the pg_refstore backend binding is immutable';
    END IF;
    IF OLD.storage_backend = 'pg_refstore' THEN
        IF NEW.id <> OLD.id OR NEW.owner_id <> OLD.owner_id OR NEW.name <> OLD.name
           OR NEW.object_format <> OLD.object_format THEN
            RAISE EXCEPTION 'a pg_refstore repository identity (id/owner/name/object format) is immutable';
        END IF;
        IF OLD.state = 'ready' AND NEW.state <> 'ready' THEN
            RAISE EXCEPTION 'a ready pg_refstore repository cannot leave ready';
        END IF;
    END IF;
    IF NEW.storage_backend = 'pg_refstore' AND NEW.state = 'ready' AND OLD.state <> 'ready' THEN
        IF NOT EXISTS (
            SELECT 1 FROM ref_store_serving_repositories s
            WHERE s.repository_id = NEW.id AND s.owner_id = NEW.owner_id
              AND s.name = NEW.name AND s.object_format = NEW.object_format
              AND s.state = 'ready'
        ) THEN
            RAISE EXCEPTION 'a pg_refstore repository cannot become ready before its serving binding is ready';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER repositories_pg_refstore_guard
    BEFORE INSERT OR UPDATE OR DELETE ON repositories
    FOR EACH ROW EXECUTE FUNCTION rootyard_pg_refstore_repository_guard();

-- ---------------------------------------------------------------------------
-- 3. No second write authority for a serving-bound repository.
--    Pando state/refs and the rebuildable native projection are refused for a
--    repository that has a durable pg_refstore serving binding. These guards
--    only fire for such repositories; every existing gitfs/pando repository is
--    untouched.
-- ---------------------------------------------------------------------------
CREATE FUNCTION rootyard_pg_refstore_no_second_authority() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM ref_store_serving_repositories s WHERE s.repository_id = NEW.repository_id) THEN
        RAISE EXCEPTION 'repository has a pg_refstore serving authority; % would be a second write authority', TG_TABLE_NAME;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER pando_state_pg_refstore_guard
    BEFORE INSERT OR UPDATE ON pando_repository_states
    FOR EACH ROW EXECUTE FUNCTION rootyard_pg_refstore_no_second_authority();

CREATE TRIGGER ref_projection_pg_refstore_guard
    BEFORE INSERT OR UPDATE ON repository_ref_projection
    FOR EACH ROW EXECUTE FUNCTION rootyard_pg_refstore_no_second_authority();

INSERT INTO schema_migrations (version) VALUES (145) ON CONFLICT DO NOTHING;
