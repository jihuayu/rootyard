ALTER TABLE pando_storage_authorities
    ADD COLUMN restore_generation BIGINT NOT NULL DEFAULT 0 CHECK (restore_generation >= 0),
    ADD COLUMN authority_epoch BIGINT NOT NULL DEFAULT 1 CHECK (authority_epoch >= 1),
    ADD COLUMN deployment_id UUID,
    ADD COLUMN volume_id UUID,
    ADD COLUMN db_system_identifier TEXT
        CHECK (db_system_identifier IS NULL OR (db_system_identifier ~ '^[0-9]+$' AND octet_length(db_system_identifier) <= 64)),
    ADD COLUMN db_database_oid BIGINT CHECK (db_database_oid IS NULL OR db_database_oid > 0),
    ADD COLUMN db_schema_oid BIGINT CHECK (db_schema_oid IS NULL OR db_schema_oid > 0),
    ADD COLUMN pg_timeline_id INTEGER CHECK (pg_timeline_id IS NULL OR pg_timeline_id > 0),
    ADD COLUMN backend_identity TEXT CHECK (backend_identity IS NULL OR backend_identity ~ '^[0-9a-f]{64}$'),
    ADD COLUMN proof_nonce UUID,
    ADD COLUMN remote_delete_fenced BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN remote_delete_fence_reason TEXT
        CHECK (remote_delete_fence_reason IS NULL OR octet_length(remote_delete_fence_reason) <= 512),
    ADD COLUMN attested_at TIMESTAMPTZ,
    ADD CONSTRAINT pando_storage_authorities_attestation_tuple_check CHECK (
        (
            deployment_id IS NULL
            AND volume_id IS NULL
            AND db_system_identifier IS NULL
            AND db_database_oid IS NULL
            AND db_schema_oid IS NULL
            AND pg_timeline_id IS NULL
            AND backend_identity IS NULL
            AND proof_nonce IS NULL
            AND attested_at IS NULL
        ) OR (
            deployment_id IS NOT NULL
            AND volume_id IS NOT NULL
            AND db_system_identifier IS NOT NULL
            AND db_database_oid IS NOT NULL
            AND db_schema_oid IS NOT NULL
            AND pg_timeline_id IS NOT NULL
            AND backend_identity IS NOT NULL
            AND proof_nonce IS NOT NULL
            AND attested_at IS NOT NULL
        )
    );

CREATE TABLE pando_retention_roots (
    id UUID PRIMARY KEY,
    authority_id UUID NOT NULL REFERENCES pando_storage_authorities(authority_id) ON DELETE RESTRICT,
    tenant_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repository_id UUID,
    root_kind TEXT NOT NULL CHECK (root_kind IN ('backup_snapshot', 'pitr_recovery_point', 'manual_pin')),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'released')),
    restore_generation BIGINT NOT NULL CHECK (restore_generation >= 0),
    external_lsn TEXT
        CHECK (external_lsn IS NULL OR (octet_length(external_lsn) <= 64 AND external_lsn ~ '^[0-9A-Fa-f]+/[0-9A-Fa-f]+$')),
    note TEXT CHECK (note IS NULL OR octet_length(note) <= 512),
    retain_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    released_at TIMESTAMPTZ,
    UNIQUE (id, authority_id, tenant_id),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE,
    CHECK (
        (state = 'active' AND released_at IS NULL)
        OR (state = 'released' AND released_at IS NOT NULL)
    )
);

CREATE TABLE pando_retention_root_manifests (
    root_id UUID NOT NULL,
    authority_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    manifest_id UUID NOT NULL,
    PRIMARY KEY (root_id, manifest_id),
    FOREIGN KEY (root_id, authority_id, tenant_id)
        REFERENCES pando_retention_roots(id, authority_id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (manifest_id, repository_id, tenant_id)
        REFERENCES pando_pack_manifests(id, repository_id, tenant_id) ON DELETE RESTRICT
);

CREATE INDEX pando_retention_roots_active_idx
    ON pando_retention_roots (authority_id, tenant_id, state, retain_until)
    WHERE state = 'active';

CREATE INDEX pando_retention_root_manifests_manifest_idx
    ON pando_retention_root_manifests (manifest_id, authority_id);

INSERT INTO schema_migrations (version) VALUES (148) ON CONFLICT DO NOTHING;
