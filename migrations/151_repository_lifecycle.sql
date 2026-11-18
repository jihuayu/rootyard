-- Issue #85: Repository Archive, Rename Aliases, Soft Delete/Recovery & Crash-Recoverable Ownership Transfer.
-- Explicit >= and <= range predicates only (never BETWEEN) for pg_dump catalog normalization invariance,
-- explicit DROP ... IF EXISTS / CREATE ... IF NOT EXISTS for idempotent replay, and make_interval(...) defaults
-- for intervalstyle='iso_8601' invariance.

ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS archived_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS deleted_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS purge_after TIMESTAMPTZ NULL;

ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_version_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_version_check CHECK (version > 0);

ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_deleted_purge_window_chk;
ALTER TABLE repositories ADD CONSTRAINT repositories_deleted_purge_window_chk
    CHECK (
        (deleted_at IS NULL AND purge_after IS NULL)
        OR (deleted_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after >= deleted_at)
    );

CREATE INDEX IF NOT EXISTS repositories_active_owner_name_idx
    ON repositories (owner_id, name)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS repositories_purge_due_idx
    ON repositories (purge_after)
    WHERE deleted_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS repository_aliases (
    id UUID PRIMARY KEY,
    alias_owner_id UUID NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    alias_name TEXT NOT NULL CHECK (
        alias_name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
        AND alias_name NOT IN ('.', '..')
        AND alias_name NOT LIKE '%..%'
    ),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT NOT NULL CHECK (reason IN ('rename', 'transfer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (alias_owner_id, alias_name)
);

CREATE INDEX IF NOT EXISTS repository_aliases_repo_idx
    ON repository_aliases (repository_id, created_at);

CREATE OR REPLACE FUNCTION enforce_repository_alias_disjoint()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'repository_aliases' THEN
        IF EXISTS (
            SELECT 1 FROM repositories r
            WHERE r.owner_id = NEW.alias_owner_id AND r.name = NEW.alias_name
        ) THEN
            RAISE EXCEPTION 'alias path collides with active or deleted repository' USING ERRCODE = '23505';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_TABLE_NAME = 'repositories' THEN
        IF EXISTS (
            SELECT 1 FROM repository_aliases a
            WHERE a.alias_owner_id = NEW.owner_id
              AND a.alias_name = NEW.name
              AND a.repository_id <> NEW.id
        ) THEN
            RAISE EXCEPTION 'repository path is reserved by an existing alias' USING ERRCODE = '23505';
        END IF;
        DELETE FROM repository_aliases
        WHERE alias_owner_id = NEW.owner_id
          AND alias_name = NEW.name
          AND repository_id = NEW.id;
        DELETE FROM repository_name_reservations
        WHERE namespace_id = NEW.owner_id
          AND name = NEW.name
          AND repository_id = NEW.id
          AND kind = 'alias';
        RETURN NEW;
    END IF;

    RETURN NEW;
END
$$;

CREATE TABLE IF NOT EXISTS repository_name_reservations (
    namespace_id UUID NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('repository', 'alias')),
    PRIMARY KEY (namespace_id, name)
);

CREATE INDEX IF NOT EXISTS repository_name_reservations_repo_idx
    ON repository_name_reservations (repository_id);

INSERT INTO repository_name_reservations (namespace_id, name, repository_id, kind)
SELECT owner_id, name, id, 'repository' FROM repositories
ON CONFLICT (namespace_id, name) DO NOTHING;

INSERT INTO repository_name_reservations (namespace_id, name, repository_id, kind)
SELECT alias_owner_id, alias_name, repository_id, 'alias' FROM repository_aliases
ON CONFLICT (namespace_id, name) DO NOTHING;

CREATE OR REPLACE FUNCTION sync_repository_name_reservation_repo()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.owner_id = NEW.owner_id AND OLD.name = NEW.name THEN
            RETURN NEW;
        END IF;
        DELETE FROM repository_name_reservations
        WHERE namespace_id = OLD.owner_id
          AND name = OLD.name
          AND repository_id = OLD.id
          AND kind = 'repository';
    END IF;
    INSERT INTO repository_name_reservations (namespace_id, name, repository_id, kind)
    VALUES (NEW.owner_id, NEW.name, NEW.id, 'repository');
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION sync_repository_name_reservation_alias()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM repository_name_reservations
        WHERE namespace_id = OLD.alias_owner_id
          AND name = OLD.alias_name
          AND repository_id = OLD.repository_id
          AND kind = 'alias';
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.alias_owner_id = NEW.alias_owner_id
           AND OLD.alias_name = NEW.alias_name
           AND OLD.repository_id = NEW.repository_id
        THEN
            RETURN NEW;
        END IF;
        DELETE FROM repository_name_reservations
        WHERE namespace_id = OLD.alias_owner_id
          AND name = OLD.alias_name
          AND repository_id = OLD.repository_id
          AND kind = 'alias';
    END IF;
    INSERT INTO repository_name_reservations (namespace_id, name, repository_id, kind)
    VALUES (NEW.alias_owner_id, NEW.alias_name, NEW.repository_id, 'alias');
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS repository_aliases_disjoint_guard ON repository_aliases;
CREATE TRIGGER repository_aliases_disjoint_guard
    BEFORE INSERT OR UPDATE ON repository_aliases
    FOR EACH ROW EXECUTE FUNCTION enforce_repository_alias_disjoint();

DROP TRIGGER IF EXISTS repositories_alias_disjoint_guard ON repositories;
CREATE TRIGGER repositories_alias_disjoint_guard
    BEFORE INSERT OR UPDATE OF owner_id, name ON repositories
    FOR EACH ROW EXECUTE FUNCTION enforce_repository_alias_disjoint();

DROP TRIGGER IF EXISTS repositories_name_reservation_sync ON repositories;
CREATE TRIGGER repositories_name_reservation_sync
    AFTER INSERT OR UPDATE OF owner_id, name ON repositories
    FOR EACH ROW EXECUTE FUNCTION sync_repository_name_reservation_repo();

DROP TRIGGER IF EXISTS repository_aliases_name_reservation_sync ON repository_aliases;
CREATE TRIGGER repository_aliases_name_reservation_sync
    AFTER INSERT OR UPDATE OR DELETE ON repository_aliases
    FOR EACH ROW EXECUTE FUNCTION sync_repository_name_reservation_alias();

CREATE TABLE IF NOT EXISTS repository_lifecycle_idempotency (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    actor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('archive', 'unarchive', 'rename', 'delete', 'restore', 'purge', 'transfer')),
    idempotency_key TEXT NOT NULL CHECK (octet_length(idempotency_key) >= 1 AND octet_length(idempotency_key) <= 128),
    request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    response_status INTEGER NOT NULL CHECK (response_status >= 200 AND response_status <= 599),
    response_body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, actor_id, action, idempotency_key)
);

CREATE TABLE IF NOT EXISTS repository_transfers (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    from_owner_id UUID NOT NULL REFERENCES namespaces(id),
    to_owner_id UUID NOT NULL REFERENCES namespaces(id),
    from_name TEXT NOT NULL,
    to_name TEXT NOT NULL,
    initiated_by UUID NOT NULL REFERENCES users(id),
    revoke_collaborators BOOLEAN NOT NULL DEFAULT true,
    keep_alias BOOLEAN NOT NULL DEFAULT true,
    expected_version BIGINT NOT NULL CHECK (expected_version > 0),
    state TEXT NOT NULL CHECK (state IN (
        'preparing',
        'draining',
        'copying_remote',
        'rekeying_db',
        'revoking_legacy',
        'completed',
        'rolling_back',
        'rolled_back',
        'failed'
    )),
    copied_objects JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_error TEXT NULL,
    lease_owner TEXT NULL,
    lease_until TIMESTAMPTZ NULL,
    lease_epoch BIGINT NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ NULL,
    CHECK (from_owner_id <> to_owner_id),
    CHECK (jsonb_typeof(copied_objects) = 'array')
);

CREATE UNIQUE INDEX IF NOT EXISTS repository_transfers_one_active_idx
    ON repository_transfers (repository_id)
    WHERE state NOT IN ('completed', 'rolled_back', 'failed');

CREATE INDEX IF NOT EXISTS repository_transfers_recovery_idx
    ON repository_transfers (state, updated_at)
    WHERE state NOT IN ('completed', 'rolled_back', 'failed');

CREATE TABLE IF NOT EXISTS remote_object_delete_claims (
    tenant_id UUID NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    namespace TEXT NOT NULL CHECK (namespace IN ('lfs', 'workspace')),
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    claim_generation BIGINT NOT NULL DEFAULT 1 CHECK (claim_generation > 0),
    deleting BOOLEAN NOT NULL DEFAULT true,
    delete_uncertain BOOLEAN NOT NULL DEFAULT false,
    lease_until TIMESTAMPTZ NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, namespace, digest)
);

CREATE INDEX IF NOT EXISTS remote_object_delete_claims_active_lease_idx
    ON remote_object_delete_claims (deleting, delete_uncertain, lease_until)
    WHERE deleting OR delete_uncertain;

-- Fix pando_retention_roots_tenant_id_fkey so organization namespaces are valid tenants.
ALTER TABLE pando_retention_roots DROP CONSTRAINT IF EXISTS pando_retention_roots_tenant_id_fkey;
ALTER TABLE pando_retention_roots ADD CONSTRAINT pando_retention_roots_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES namespaces(id) ON DELETE CASCADE;

-- Rebind composite (repository_id, tenant_id) -> repositories(id, owner_id) and child FKs
-- with ON UPDATE CASCADE ON DELETE CASCADE for atomic transfer and purge cascade.
ALTER TABLE ci_runs DROP CONSTRAINT IF EXISTS ci_runs_repository_id_tenant_id_fkey;
ALTER TABLE ci_runs ADD CONSTRAINT ci_runs_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_branch_rules DROP CONSTRAINT IF EXISTS forge_branch_rules_repository_id_tenant_id_fkey;
ALTER TABLE forge_branch_rules ADD CONSTRAINT forge_branch_rules_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_check_runs DROP CONSTRAINT IF EXISTS forge_check_runs_repository_id_tenant_id_fkey;
ALTER TABLE forge_check_runs ADD CONSTRAINT forge_check_runs_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_creation_requests DROP CONSTRAINT IF EXISTS forge_creation_requests_repository_id_tenant_id_fkey;
ALTER TABLE forge_creation_requests ADD CONSTRAINT forge_creation_requests_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_issue_counters DROP CONSTRAINT IF EXISTS forge_issue_counters_repository_id_tenant_id_fkey;
ALTER TABLE forge_issue_counters ADD CONSTRAINT forge_issue_counters_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_issues DROP CONSTRAINT IF EXISTS forge_issues_repository_id_tenant_id_fkey;
ALTER TABLE forge_issues ADD CONSTRAINT forge_issues_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_issue_comments DROP CONSTRAINT IF EXISTS forge_issue_comments_tenant_id_repository_id_issue_number_fkey;
ALTER TABLE forge_issue_comments ADD CONSTRAINT forge_issue_comments_tenant_id_repository_id_issue_number_fkey
    FOREIGN KEY (tenant_id, repository_id, issue_number) REFERENCES forge_issues(tenant_id, repository_id, number) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_pull_counters DROP CONSTRAINT IF EXISTS forge_pull_counters_repository_id_tenant_id_fkey;
ALTER TABLE forge_pull_counters ADD CONSTRAINT forge_pull_counters_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_pulls DROP CONSTRAINT IF EXISTS forge_pulls_repository_id_tenant_id_fkey;
ALTER TABLE forge_pulls ADD CONSTRAINT forge_pulls_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_pull_reviews DROP CONSTRAINT IF EXISTS forge_pull_reviews_tenant_id_repository_id_pull_number_fkey;
ALTER TABLE forge_pull_reviews ADD CONSTRAINT forge_pull_reviews_tenant_id_repository_id_pull_number_fkey
    FOREIGN KEY (tenant_id, repository_id, pull_number) REFERENCES forge_pulls(tenant_id, repository_id, number) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_trusted_check_contexts DROP CONSTRAINT IF EXISTS forge_trusted_check_contexts_repository_id_tenant_id_fkey;
ALTER TABLE forge_trusted_check_contexts ADD CONSTRAINT forge_trusted_check_contexts_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_webhooks DROP CONSTRAINT IF EXISTS forge_webhooks_repository_id_tenant_id_fkey;
ALTER TABLE forge_webhooks ADD CONSTRAINT forge_webhooks_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_webhook_callbacks DROP CONSTRAINT IF EXISTS forge_webhook_callbacks_repository_id_tenant_id_fkey;
ALTER TABLE forge_webhook_callbacks ADD CONSTRAINT forge_webhook_callbacks_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_webhook_deliveries DROP CONSTRAINT IF EXISTS forge_webhook_deliveries_repository_id_tenant_id_fkey;
ALTER TABLE forge_webhook_deliveries ADD CONSTRAINT forge_webhook_deliveries_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

-- Migration 150 Forge collaboration tables: rebind ALL foreign keys for transfer and purge cascades.
ALTER TABLE forge_labels DROP CONSTRAINT IF EXISTS forge_labels_repository_id_tenant_id_fkey;
ALTER TABLE forge_labels ADD CONSTRAINT forge_labels_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_issue_labels DROP CONSTRAINT IF EXISTS forge_issue_labels_tenant_id_repository_id_issue_number_fkey;
ALTER TABLE forge_issue_labels ADD CONSTRAINT forge_issue_labels_tenant_id_repository_id_issue_number_fkey
    FOREIGN KEY (tenant_id, repository_id, issue_number) REFERENCES forge_issues(tenant_id, repository_id, number) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_pull_labels DROP CONSTRAINT IF EXISTS forge_pull_labels_tenant_id_repository_id_pull_number_fkey;
ALTER TABLE forge_pull_labels ADD CONSTRAINT forge_pull_labels_tenant_id_repository_id_pull_number_fkey
    FOREIGN KEY (tenant_id, repository_id, pull_number) REFERENCES forge_pulls(tenant_id, repository_id, number) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_issue_assignees DROP CONSTRAINT IF EXISTS forge_issue_assignees_tenant_id_repository_id_issue_number_fkey;
ALTER TABLE forge_issue_assignees ADD CONSTRAINT forge_issue_assignees_tenant_id_repository_id_issue_number_fkey
    FOREIGN KEY (tenant_id, repository_id, issue_number) REFERENCES forge_issues(tenant_id, repository_id, number) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_pull_assignees DROP CONSTRAINT IF EXISTS forge_pull_assignees_tenant_id_repository_id_pull_number_fkey;
ALTER TABLE forge_pull_assignees ADD CONSTRAINT forge_pull_assignees_tenant_id_repository_id_pull_number_fkey
    FOREIGN KEY (tenant_id, repository_id, pull_number) REFERENCES forge_pulls(tenant_id, repository_id, number) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_pull_review_comments DROP CONSTRAINT IF EXISTS forge_pull_review_comments_tenant_id_repository_id_pull_nu_fkey;
ALTER TABLE forge_pull_review_comments ADD CONSTRAINT forge_pull_review_comments_tenant_id_repository_id_pull_nu_fkey
    FOREIGN KEY (tenant_id, repository_id, pull_number) REFERENCES forge_pulls(tenant_id, repository_id, number) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_pull_review_comments DROP CONSTRAINT IF EXISTS forge_pull_review_comments_tenant_id_repository_id_pull_n_fkey1;
ALTER TABLE forge_pull_review_comments ADD CONSTRAINT forge_pull_review_comments_tenant_id_repository_id_pull_n_fkey1
    FOREIGN KEY (tenant_id, repository_id, pull_number, review_number) REFERENCES forge_pull_reviews(tenant_id, repository_id, pull_number, number) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_pull_review_comments DROP CONSTRAINT IF EXISTS forge_pull_review_comments_tenant_id_repository_id_pull_n_fkey2;
ALTER TABLE forge_pull_review_comments ADD CONSTRAINT forge_pull_review_comments_tenant_id_repository_id_pull_n_fkey2
    FOREIGN KEY (tenant_id, repository_id, pull_number, in_reply_to_number) REFERENCES forge_pull_review_comments(tenant_id, repository_id, pull_number, number) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_comment_revisions DROP CONSTRAINT IF EXISTS forge_comment_revisions_repository_id_tenant_id_fkey;
ALTER TABLE forge_comment_revisions ADD CONSTRAINT forge_comment_revisions_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_subscriptions DROP CONSTRAINT IF EXISTS forge_subscriptions_repository_id_tenant_id_fkey;
ALTER TABLE forge_subscriptions ADD CONSTRAINT forge_subscriptions_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE forge_notifications DROP CONSTRAINT IF EXISTS forge_notifications_repository_id_tenant_id_fkey;
ALTER TABLE forge_notifications ADD CONSTRAINT forge_notifications_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE lfs_locks DROP CONSTRAINT IF EXISTS lfs_locks_repository_id_tenant_id_fkey;
ALTER TABLE lfs_locks ADD CONSTRAINT lfs_locks_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE lfs_objects DROP CONSTRAINT IF EXISTS lfs_objects_repository_id_tenant_id_fkey;
ALTER TABLE lfs_objects ADD CONSTRAINT lfs_objects_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE pando_pack_manifests DROP CONSTRAINT IF EXISTS pando_pack_manifests_repository_id_tenant_id_fkey;
ALTER TABLE pando_pack_manifests ADD CONSTRAINT pando_pack_manifests_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE pando_manifest_artifacts DROP CONSTRAINT IF EXISTS pando_manifest_artifacts_manifest_identity_fkey;
ALTER TABLE pando_manifest_artifacts ADD CONSTRAINT pando_manifest_artifacts_manifest_identity_fkey
    FOREIGN KEY (manifest_id, repository_id, tenant_id) REFERENCES pando_pack_manifests(id, repository_id, tenant_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE pando_repository_states DROP CONSTRAINT IF EXISTS pando_repository_states_repository_id_tenant_id_fkey;
ALTER TABLE pando_repository_states ADD CONSTRAINT pando_repository_states_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE pando_retention_roots DROP CONSTRAINT IF EXISTS pando_retention_roots_repository_id_tenant_id_fkey;
ALTER TABLE pando_retention_roots ADD CONSTRAINT pando_retention_roots_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE pando_retention_root_manifests DROP CONSTRAINT IF EXISTS pando_retention_root_manifest_root_id_authority_id_tenant__fkey;
ALTER TABLE pando_retention_root_manifests ADD CONSTRAINT pando_retention_root_manifest_root_id_authority_id_tenant__fkey
    FOREIGN KEY (root_id, authority_id, tenant_id) REFERENCES pando_retention_roots(id, authority_id, tenant_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE pando_retention_root_manifests DROP CONSTRAINT IF EXISTS pando_retention_root_manifest_manifest_id_repository_id_te_fkey;
ALTER TABLE pando_retention_root_manifests ADD CONSTRAINT pando_retention_root_manifest_manifest_id_repository_id_te_fkey
    FOREIGN KEY (manifest_id, repository_id, tenant_id) REFERENCES pando_pack_manifests(id, repository_id, tenant_id) ON UPDATE CASCADE ON DELETE RESTRICT;

ALTER TABLE repository_audit_log DROP CONSTRAINT IF EXISTS repository_audit_log_repository_id_tenant_id_fkey;
ALTER TABLE repository_audit_log ADD CONSTRAINT repository_audit_log_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE repository_collaborators DROP CONSTRAINT IF EXISTS repository_collaborators_repository_id_tenant_id_fkey;
ALTER TABLE repository_collaborators ADD CONSTRAINT repository_collaborators_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE repository_shard_routes DROP CONSTRAINT IF EXISTS repository_shard_routes_repository_id_tenant_id_fkey;
ALTER TABLE repository_shard_routes ADD CONSTRAINT repository_shard_routes_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE repository_teams DROP CONSTRAINT IF EXISTS repository_teams_repository_id_tenant_id_fkey;
ALTER TABLE repository_teams ADD CONSTRAINT repository_teams_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE shard_failover_operations DROP CONSTRAINT IF EXISTS shard_failover_operations_repository_id_tenant_id_fkey;
ALTER TABLE shard_failover_operations ADD CONSTRAINT shard_failover_operations_repository_id_tenant_id_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE storage_maintenance_jobs DROP CONSTRAINT IF EXISTS storage_maintenance_jobs_repository_owner_fkey;
ALTER TABLE storage_maintenance_jobs ADD CONSTRAINT storage_maintenance_jobs_repository_owner_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE storage_maintenance_repo_state DROP CONSTRAINT IF EXISTS storage_maintenance_repo_state_repository_owner_fkey;
ALTER TABLE storage_maintenance_repo_state ADD CONSTRAINT storage_maintenance_repo_state_repository_owner_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE storage_maintenance_tombstones DROP CONSTRAINT IF EXISTS storage_maintenance_tombstones_repository_owner_fkey;
ALTER TABLE storage_maintenance_tombstones ADD CONSTRAINT storage_maintenance_tombstones_repository_owner_fkey
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON UPDATE CASCADE ON DELETE CASCADE;

-- CI checkout tables retain historical owner_id audit columns (immutable issuer namespace) while cascading repository purge.
ALTER TABLE ci_checkout_jobs DROP CONSTRAINT IF EXISTS ci_checkout_jobs_repository_id_owner_id_fkey;
ALTER TABLE ci_checkout_jobs DROP CONSTRAINT IF EXISTS ci_checkout_jobs_repository_id_fkey;
ALTER TABLE ci_checkout_jobs ADD CONSTRAINT ci_checkout_jobs_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE ci_checkout_delegations DROP CONSTRAINT IF EXISTS ci_checkout_delegations_repository_id_owner_id_fkey;
ALTER TABLE ci_checkout_delegations DROP CONSTRAINT IF EXISTS ci_checkout_delegations_repository_id_fkey;
ALTER TABLE ci_checkout_delegations ADD CONSTRAINT ci_checkout_delegations_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE ci_checkout_delegations DROP CONSTRAINT IF EXISTS ci_checkout_delegations_parent_repository_id_parent_job_id_fkey;
ALTER TABLE ci_checkout_delegations ADD CONSTRAINT ci_checkout_delegations_parent_repository_id_parent_job_id_fkey
    FOREIGN KEY (parent_repository_id, parent_job_id) REFERENCES ci_checkout_jobs(repository_id, job_id) ON DELETE CASCADE;

ALTER TABLE ci_integration_checkout_jobs DROP CONSTRAINT IF EXISTS ci_integration_checkout_jobs_repository_id_owner_id_fkey;
ALTER TABLE ci_integration_checkout_jobs DROP CONSTRAINT IF EXISTS ci_integration_checkout_jobs_repository_id_fkey;
ALTER TABLE ci_integration_checkout_jobs ADD CONSTRAINT ci_integration_checkout_jobs_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE ci_integration_checkout_jobs DROP CONSTRAINT IF EXISTS ci_integration_checkout_jobs_run_id_fkey;
ALTER TABLE ci_integration_checkout_jobs ADD CONSTRAINT ci_integration_checkout_jobs_run_id_fkey
    FOREIGN KEY (run_id) REFERENCES ci_runs(id) ON DELETE CASCADE;

ALTER TABLE ci_mirror_evictions DROP CONSTRAINT IF EXISTS ci_mirror_evictions_repository_id_fkey;
ALTER TABLE ci_mirror_evictions ADD CONSTRAINT ci_mirror_evictions_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

-- Git operation / outbox / projection cascades (recovery_resolutions & operation_resolutions remain immutable & block purge via PurgeHold).
ALTER TABLE git_operations DROP CONSTRAINT IF EXISTS git_operations_repository_id_fkey;
ALTER TABLE git_operations ADD CONSTRAINT git_operations_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE git_operations DROP CONSTRAINT IF EXISTS git_operations_service_principal_fkey;
ALTER TABLE git_operations ADD CONSTRAINT git_operations_service_principal_fkey
    FOREIGN KEY (service_principal_id, repository_id) REFERENCES ci_service_principals(id, repository_id) ON DELETE CASCADE;

ALTER TABLE outbox_events DROP CONSTRAINT IF EXISTS outbox_events_operation_id_repository_id_storage_generatio_fkey;
ALTER TABLE outbox_events ADD CONSTRAINT outbox_events_operation_id_repository_id_storage_generatio_fkey
    FOREIGN KEY (operation_id, repository_id, storage_generation, operation_sequence)
    REFERENCES git_operations(id, repository_id, storage_generation, sequence) ON DELETE CASCADE;

ALTER TABLE event_deliveries DROP CONSTRAINT IF EXISTS event_deliveries_event_id_fkey;
ALTER TABLE event_deliveries ADD CONSTRAINT event_deliveries_event_id_fkey
    FOREIGN KEY (event_id) REFERENCES outbox_events(event_id) ON DELETE CASCADE;

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_id_fkey;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_id_fkey
    FOREIGN KEY (event_id) REFERENCES outbox_events(event_id) ON DELETE CASCADE;

ALTER TABLE repository_ref_projection DROP CONSTRAINT IF EXISTS repository_ref_projection_repository_id_fkey;
ALTER TABLE repository_ref_projection ADD CONSTRAINT repository_ref_projection_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE repository_ref_projection DROP CONSTRAINT IF EXISTS repository_ref_projection_event_id_fkey;
ALTER TABLE repository_ref_projection ADD CONSTRAINT repository_ref_projection_event_id_fkey
    FOREIGN KEY (event_id) REFERENCES outbox_events(event_id) ON DELETE CASCADE;

-- Workspaces / sandbox cascades during approved final purge.
ALTER TABLE workspaces DROP CONSTRAINT IF EXISTS workspaces_repository_id_fkey;
ALTER TABLE workspaces ADD CONSTRAINT workspaces_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE workspaces DROP CONSTRAINT IF EXISTS workspaces_last_checkpoint_fk;
ALTER TABLE workspaces ADD CONSTRAINT workspaces_last_checkpoint_fk
    FOREIGN KEY (last_checkpoint_id) REFERENCES workspace_checkpoints(id) ON DELETE SET NULL;

ALTER TABLE workspaces DROP CONSTRAINT IF EXISTS workspaces_parent_checkpoint_fk;
ALTER TABLE workspaces ADD CONSTRAINT workspaces_parent_checkpoint_fk
    FOREIGN KEY (parent_checkpoint_id) REFERENCES workspace_checkpoints(id) ON DELETE SET NULL;

ALTER TABLE workspace_checkpoints DROP CONSTRAINT IF EXISTS workspace_checkpoints_repository_id_fkey;
ALTER TABLE workspace_checkpoints ADD CONSTRAINT workspace_checkpoints_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE workspace_checkpoints DROP CONSTRAINT IF EXISTS workspace_checkpoints_workspace_id_fkey;
ALTER TABLE workspace_checkpoints ADD CONSTRAINT workspace_checkpoints_workspace_id_fkey
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;

ALTER TABLE workspace_capture_state DROP CONSTRAINT IF EXISTS workspace_capture_state_workspace_id_fkey;
ALTER TABLE workspace_capture_state ADD CONSTRAINT workspace_capture_state_workspace_id_fkey
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;

ALTER TABLE workspace_creations DROP CONSTRAINT IF EXISTS workspace_creations_workspace_id_fkey;
ALTER TABLE workspace_creations ADD CONSTRAINT workspace_creations_workspace_id_fkey
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;

ALTER TABLE workspace_entries DROP CONSTRAINT IF EXISTS workspace_entries_workspace_id_fkey;
ALTER TABLE workspace_entries ADD CONSTRAINT workspace_entries_workspace_id_fkey
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;

ALTER TABLE workspace_events DROP CONSTRAINT IF EXISTS workspace_events_workspace_id_fkey;
ALTER TABLE workspace_events ADD CONSTRAINT workspace_events_workspace_id_fkey
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;

ALTER TABLE workspace_operations DROP CONSTRAINT IF EXISTS workspace_operations_workspace_id_fkey;
ALTER TABLE workspace_operations ADD CONSTRAINT workspace_operations_workspace_id_fkey
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;

ALTER TABLE workspace_changeset_steps DROP CONSTRAINT IF EXISTS workspace_changeset_steps_repository_id_fkey;
ALTER TABLE workspace_changeset_steps ADD CONSTRAINT workspace_changeset_steps_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE workspace_namespace_mounts DROP CONSTRAINT IF EXISTS workspace_namespace_mounts_repository_id_fkey;
ALTER TABLE workspace_namespace_mounts ADD CONSTRAINT workspace_namespace_mounts_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE workspace_views DROP CONSTRAINT IF EXISTS workspace_views_repository_id_fkey;
ALTER TABLE workspace_views ADD CONSTRAINT workspace_views_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;

ALTER TABLE workspace_view_history DROP CONSTRAINT IF EXISTS workspace_view_history_view_id_fkey;
ALTER TABLE workspace_view_history ADD CONSTRAINT workspace_view_history_view_id_fkey
    FOREIGN KEY (view_id) REFERENCES workspace_views(id) ON DELETE CASCADE;

ALTER TABLE workspace_remote_staging_objects DROP CONSTRAINT IF EXISTS workspace_remote_staging_objects_checkpoint_id_fkey;
ALTER TABLE workspace_remote_staging_objects ADD CONSTRAINT workspace_remote_staging_objects_checkpoint_id_fkey
    FOREIGN KEY (checkpoint_id) REFERENCES workspace_checkpoints(id) ON DELETE CASCADE;

ALTER TABLE sandbox_jobs DROP CONSTRAINT IF EXISTS sandbox_jobs_workspace_id_fkey;
ALTER TABLE sandbox_jobs ADD CONSTRAINT sandbox_jobs_workspace_id_fkey
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;

ALTER TABLE sandbox_jobs DROP CONSTRAINT IF EXISTS sandbox_jobs_ci_run_fkey;
ALTER TABLE sandbox_jobs ADD CONSTRAINT sandbox_jobs_ci_run_fkey
    FOREIGN KEY (ci_run_id) REFERENCES ci_runs(id) ON DELETE CASCADE;

ALTER TABLE sandbox_jobs DROP CONSTRAINT IF EXISTS sandbox_jobs_ci_hook_id_fkey;
ALTER TABLE sandbox_jobs ADD CONSTRAINT sandbox_jobs_ci_hook_id_fkey
    FOREIGN KEY (ci_hook_id) REFERENCES forge_webhooks(id) ON DELETE CASCADE;

-- Trigger 1: protect_ci_checkout_job keeps CI checkout jobs & tombstones immutable/permanent while repo exists,
-- permitting parent-repository cascade DELETE only after repositories row deletion.
CREATE OR REPLACE FUNCTION protect_ci_checkout_job() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF NOT EXISTS (SELECT 1 FROM repositories r WHERE r.id = OLD.repository_id) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'CI checkout jobs and cancellation tombstones are permanent';
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'CI checkout jobs and cancellation tombstones are permanent';
    END IF;
    IF ROW(NEW.repository_id, NEW.job_id, NEW.owner_id, NEW.plan,
           NEW.issuer_token_id, NEW.credential_digest, NEW.expires_unix, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.repository_id, OLD.job_id, OLD.owner_id, OLD.plan,
           OLD.issuer_token_id, OLD.credential_digest, OLD.expires_unix, OLD.created_at)
       OR (OLD.cancelled AND NOT NEW.cancelled)
       OR (OLD.revoked AND NOT NEW.revoked) THEN
        RAISE EXCEPTION 'CI checkout authority is immutable except monotonic cancellation/revocation';
    END IF;
    RETURN NEW;
END;
$$;

-- Trigger 2: enforce_repository_actor_membership preserves all 137 checks and narrowly allows
-- ON UPDATE CASCADE tenant_id updates on Forge tables solely while repository_transfers.state = 'rekeying_db'.
CREATE OR REPLACE FUNCTION enforce_repository_actor_membership()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actor_user_id UUID; repo_owner_id UUID; repo_generation BIGINT; projected BOOLEAN := false;
BEGIN
    IF TG_TABLE_NAME='git_operations' THEN
      IF NEW.service_principal_id IS NOT NULL THEN
        IF NEW.actor_id IS NOT NULL OR NEW.token_id IS NOT NULL OR
           NEW.actor_name IS DISTINCT FROM 'ci-scheduler' OR
           NEW.outcome NOT IN ('unknown','recorded') OR
           (NEW.evidence->>'kind') IS DISTINCT FROM 'observed_immutable_ci_root' OR
           (NEW.evidence->'intent'->>'repository_id') IS DISTINCT FROM NEW.repository_id::text OR
           (NEW.evidence->'intent'->>'storage_generation') IS DISTINCT FROM NEW.storage_generation::text OR
           NOT COALESCE((NEW.evidence->'intent'->>'job_id') COLLATE "C" ~
             '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false) OR
           NOT COALESCE((NEW.evidence->'intent'->>'target_oid') COLLATE "C" ~
             '^([0-9a-f]{40}|[0-9a-f]{64})$',false) OR
           (NEW.evidence->'intent'->>'retention_ref') IS DISTINCT FROM
             ('refs/rootyard-ci/jobs/' || (NEW.evidence->'intent'->>'job_id')) OR
           NOT EXISTS(SELECT 1 FROM ci_service_principals s
               JOIN repositories r ON r.id=s.repository_id
               WHERE s.id=NEW.service_principal_id AND s.repository_id=NEW.repository_id
               AND s.kind='ci-pin' AND s.active AND r.state='ready'
               AND r.storage_generation=NEW.storage_generation
               AND (NEW.evidence->'intent'->>'owner_id')=r.owner_id::text
               AND (s.issuer_webhook_id IS NULL OR EXISTS(
                   SELECT 1 FROM forge_webhooks w JOIN forge_trusted_check_contexts b
                     ON b.webhook_id=w.id AND b.repository_id=w.repository_id AND b.active
                   WHERE w.id=s.issuer_webhook_id AND w.repository_id=s.repository_id AND w.active)))
        THEN RAISE EXCEPTION 'invalid CI service principal operation' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
      END IF;
      actor_user_id:=NEW.actor_id;
    ELSE
      actor_user_id:=NEW.author_id;
    END IF;
    SELECT owner_id,storage_generation INTO repo_owner_id,repo_generation FROM repositories WHERE id=NEW.repository_id;
    IF repo_owner_id IS NULL THEN
        RAISE EXCEPTION 'repository does not exist' USING ERRCODE='23503';
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME IN ('forge_issues', 'forge_issue_comments', 'forge_pulls', 'forge_pull_reviews', 'forge_pull_review_comments') THEN
        IF OLD.repository_id = NEW.repository_id
           AND OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
           AND NEW.tenant_id = repo_owner_id
           AND (to_jsonb(NEW) - 'tenant_id') = (to_jsonb(OLD) - 'tenant_id')
           AND EXISTS (
               SELECT 1 FROM repository_transfers t
               WHERE t.repository_id = NEW.repository_id
                 AND t.from_owner_id = OLD.tenant_id
                 AND t.to_owner_id = NEW.tenant_id
                 AND t.state = 'rekeying_db'
           ) THEN
            RETURN NEW;
        END IF;
    END IF;
    IF TG_TABLE_NAME='git_operations' THEN
      IF TG_OP='INSERT' THEN
        projected := EXISTS (
          SELECT 1 FROM git_ref_admissions a
          WHERE a.writer_id=NEW.id AND a.repository_id=NEW.repository_id
            AND a.actor_id=NEW.actor_id AND a.token_id=NEW.token_id
            AND ((a.state='COMMITTED' AND NEW.outcome IN ('unknown','recorded'))
              OR (a.state='ABORTED' AND NEW.outcome IN ('unknown','no_ref_changes'))))
          AND (
            (EXISTS (SELECT 1 FROM git_operations o WHERE o.id=NEW.id)
             AND EXISTS (
               SELECT 1 FROM git_operations o
               WHERE o.id=NEW.id AND o.repository_id=NEW.repository_id
                 AND o.actor_id IS NOT DISTINCT FROM NEW.actor_id
                 AND o.token_id IS NOT DISTINCT FROM NEW.token_id
                 AND o.service_principal_id IS NOT DISTINCT FROM NEW.service_principal_id
                 AND o.actor_name=NEW.actor_name AND o.sequence=NEW.sequence
                 AND o.storage_generation=NEW.storage_generation))
            OR (NOT EXISTS (SELECT 1 FROM git_operations o WHERE o.id=NEW.id)
                AND NEW.storage_generation=repo_generation));
      ELSE
        projected := OLD.id=NEW.id
          AND OLD.repository_id=NEW.repository_id
          AND OLD.actor_id IS NOT DISTINCT FROM NEW.actor_id
          AND OLD.token_id IS NOT DISTINCT FROM NEW.token_id
          AND OLD.service_principal_id IS NOT DISTINCT FROM NEW.service_principal_id
          AND OLD.actor_name=NEW.actor_name
          AND OLD.sequence=NEW.sequence
          AND OLD.storage_generation=NEW.storage_generation
          AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
          AND (OLD.outcome='unknown'
            OR (OLD.outcome=NEW.outcome
                AND NEW.evidence IS NOT DISTINCT FROM OLD.evidence
                AND NEW.settled_at IS NOT DISTINCT FROM OLD.settled_at))
          AND EXISTS (
            SELECT 1 FROM git_ref_admissions a
            WHERE a.writer_id=NEW.id AND a.repository_id=NEW.repository_id
              AND a.actor_id=NEW.actor_id AND a.token_id=NEW.token_id
              AND ((a.state='COMMITTED' AND NEW.outcome IN ('unknown','recorded'))
                OR (a.state='ABORTED' AND NEW.outcome IN ('unknown','no_ref_changes'))));
      END IF;
      IF projected THEN RETURN NEW; END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM namespaces WHERE id=repo_owner_id AND user_id=actor_user_id)
       OR EXISTS (SELECT 1 FROM organization_memberships
                  WHERE organization_id=repo_owner_id AND user_id=actor_user_id)
       OR EXISTS (SELECT 1 FROM repository_collaborators
                  WHERE repository_id=NEW.repository_id AND user_id=actor_user_id)
       OR EXISTS (SELECT 1 FROM repository_team_members
                  WHERE repository_id=NEW.repository_id AND user_id=actor_user_id)
    THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'actor is not a member or collaborator of repository' USING ERRCODE='23514';
END $$;

INSERT INTO schema_migrations (version) VALUES (151) ON CONFLICT DO NOTHING;
