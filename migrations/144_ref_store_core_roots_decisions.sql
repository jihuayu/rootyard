-- ===========================================================================
-- Migration 144 — retained roots, publication decisions/verdicts/quota, protocol state.
--
-- Additive only: no existing table changes shape. `ref_store_core_gates` keeps
-- its exact 139/142 row shape; `roots_revision` and the one-way
-- `decision_required` fence live in `ref_store_core_protocol_repos`. The roots fragment comes from the roots owner and the
-- decisions fragment from the publication-decisions owner; this file folds both
-- into the one migration/format-20 contract and adds no invented auth tables.
--
-- Properties:
--   * no retained roots/decisions table has a foreign key to
--     repositories/users/tenants/auth rows, so root headers, captured refs,
--     selector OIDs, complete pack identities, receipts, tombstones and
--     decision history survive a whole-repository delete, source pin
--     expiry/release, deleted collaborators/rules/reviews/checks/locks and
--     snapshot pruning;
--   * captures, refs, OIDs, pack bindings, receipt bodies, per-ref verdicts and
--     dependency observations are immutable (UPDATE/DELETE refused by trigger);
--     receipts are bounded JSON (<= 64 KiB) and contain no raw payload/secret;
--   * a root id is never reused: heads only move active(1) -> released(2);
--   * a decision is one-way OPEN -> CONSUMED | CANCELLED | REJECTED and its
--     identity/digests are immutable once installed;
--   * retained quota counters never decrease (no auto-prune, no refund);
--   * every retained row of one root/decision is created and charged inside the
--     caller's short transaction; an exact replay returns the stored receipt
--     before any lock or charge.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. Per-repository protocol state (separate table; NOT the 139 gate row shape)
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_core_protocol_repos (
    repository_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1', 'sha256')),
    history_incarnation UUID NOT NULL,
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch > 0),
    decision_required BOOLEAN NOT NULL DEFAULT FALSE,
    roots_revision BIGINT NOT NULL DEFAULT 0 CHECK (roots_revision >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Realm columns are immutable; `decision_required` is one-way; revision monotone.
CREATE OR REPLACE FUNCTION ref_store_core_protocol_repos_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.repository_id <> OLD.repository_id
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.object_format <> OLD.object_format
       OR NEW.history_incarnation <> OLD.history_incarnation
       OR NEW.authority_epoch <> OLD.authority_epoch
       OR NEW.group_epoch <> OLD.group_epoch THEN
        RAISE EXCEPTION 'ref_store_core_protocol_repos realm is immutable';
    END IF;
    IF OLD.decision_required AND NOT NEW.decision_required THEN
        RAISE EXCEPTION 'decision_required is a one-way fence';
    END IF;
    IF NEW.roots_revision < OLD.roots_revision THEN
        RAISE EXCEPTION 'roots_revision must be monotone';
    END IF;
    NEW.created_at := OLD.created_at;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ref_store_core_protocol_repos_guard BEFORE UPDATE ON ref_store_core_protocol_repos FOR EACH ROW EXECUTE FUNCTION ref_store_core_protocol_repos_guard();

CREATE OR REPLACE FUNCTION ref_store_core_root_immutable() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'retained roots row is immutable (% on %)', TG_OP, TG_TABLE_NAME; END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ref_store_core_root_no_delete() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'retained roots row cannot be deleted (% on %)', TG_OP, TG_TABLE_NAME; END; $$ LANGUAGE plpgsql;

CREATE TRIGGER ref_store_core_protocol_repos_no_delete BEFORE DELETE ON ref_store_core_protocol_repos FOR EACH ROW EXECUTE FUNCTION ref_store_core_root_no_delete();

-- ---------------------------------------------------------------------------
-- 2. Root head: one current state row per (repository, root id), ABA fence
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_core_root_heads (
    repository_id UUID NOT NULL,
    root_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN
        ('ci', 'workspace', 'pull_request', 'namespace', 'backup', 'export', 'operator_audit')),
    business_intent_digest TEXT NOT NULL CHECK (business_intent_digest ~ '^[0-9a-f]{64}$'),
    register_digest TEXT NOT NULL CHECK (register_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('active', 'released')),
    last_generation BIGINT NOT NULL CHECK (last_generation IN (1, 2)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, root_id),
    CHECK ((state = 'active' AND last_generation = 1) OR (state = 'released' AND last_generation = 2))
);

-- Heads: insert is a fresh active capture (1) or an immediate release-before-
-- register (released, 2); the only legal UPDATE is active(1) -> released(2).
CREATE OR REPLACE FUNCTION ref_store_core_root_heads_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'a root id is never deleted or reused';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NOT ((NEW.state = 'active' AND NEW.last_generation = 1)
             OR (NEW.state = 'released' AND NEW.last_generation = 2)) THEN
            RAISE EXCEPTION 'root head must start active/1 or released/2';
        END IF;
        NEW.created_at := clock_timestamp();
        NEW.updated_at := NEW.created_at;
        RETURN NEW;
    END IF;
    IF NEW.repository_id <> OLD.repository_id
       OR NEW.root_id <> OLD.root_id
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.owner_id <> OLD.owner_id
       OR NEW.purpose <> OLD.purpose
       OR NEW.business_intent_digest <> OLD.business_intent_digest
       OR NEW.register_digest <> OLD.register_digest THEN
        RAISE EXCEPTION 'root head identity is immutable';
    END IF;
    IF NOT (OLD.state = 'active' AND OLD.last_generation = 1
            AND NEW.state = 'released' AND NEW.last_generation = 2) THEN
        RAISE EXCEPTION 'a root head only moves active/1 -> released/2';
    END IF;
    NEW.created_at := OLD.created_at;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ref_store_core_root_heads_guard BEFORE INSERT OR UPDATE OR DELETE ON ref_store_core_root_heads FOR EACH ROW EXECUTE FUNCTION ref_store_core_root_heads_guard();

-- ---------------------------------------------------------------------------
-- 3. Immutable capture header, complete refs and exact selector OIDs
-- ---------------------------------------------------------------------------
CREATE TABLE ref_store_core_roots (
    repository_id UUID NOT NULL,
    root_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation = 1),
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN
        ('ci', 'workspace', 'pull_request', 'namespace', 'backup', 'export', 'operator_audit')),
    business_intent_digest TEXT NOT NULL CHECK (business_intent_digest ~ '^[0-9a-f]{64}$'),
    operation_id UUID NOT NULL,
    operation_digest TEXT NOT NULL CHECK (operation_digest ~ '^[0-9a-f]{64}$'),
    request_id UUID NOT NULL,
    selector_kind TEXT NOT NULL CHECK (selector_kind IN ('snapshot', 'oids')),
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1', 'sha256')),
    history_incarnation UUID NOT NULL,
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch > 0),
    source_snapshot_id UUID NOT NULL,
    source_pin_id UUID NOT NULL,
    source_pin_generation BIGINT NOT NULL CHECK (source_pin_generation > 0),
    source_read_digest TEXT NOT NULL CHECK (source_read_digest ~ '^[0-9a-f]{64}$'),
    gate_revision BIGINT NOT NULL CHECK (gate_revision > 0),
    gate_digest TEXT NOT NULL CHECK (gate_digest ~ '^[0-9a-f]{64}$'),
    head_ref TEXT NOT NULL CHECK (head_ref LIKE 'refs/%' AND length(head_ref) BETWEEN 6 AND 1024),
    head_oid TEXT,
    refs_digest TEXT NOT NULL CHECK (refs_digest ~ '^[0-9a-f]{64}$'),
    ref_count INT NOT NULL CHECK (ref_count BETWEEN 0 AND 4096),
    membership_digest TEXT NOT NULL CHECK (membership_digest ~ '^[0-9a-f]{64}$'),
    pack_set_digest TEXT NOT NULL CHECK (pack_set_digest ~ '^[0-9a-f]{64}$'),
    pack_count INT NOT NULL CHECK (pack_count BETWEEN 1 AND 16),
    oid_count INT NOT NULL CHECK (oid_count >= 1 AND oid_count <= 4096 AND (selector_kind = 'snapshot' OR oid_count <= 256)),
    native_binding_digest TEXT NOT NULL CHECK (native_binding_digest ~ '^[0-9a-f]{64}$'),
    roots_revision BIGINT NOT NULL CHECK (roots_revision > 0),
    register_digest TEXT NOT NULL CHECK (register_digest ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, root_id, generation),
    UNIQUE (repository_id, root_id, generation, request_id),
    CHECK ((object_format = 'sha1'   AND head_oid IS NOT NULL AND head_oid ~ '^[0-9a-f]{40}$')
        OR (object_format = 'sha256' AND head_oid IS NOT NULL AND head_oid ~ '^[0-9a-f]{64}$')
        OR head_oid IS NULL)
);

CREATE TRIGGER ref_store_core_roots_immutable BEFORE UPDATE OR DELETE ON ref_store_core_roots FOR EACH ROW EXECUTE FUNCTION ref_store_core_root_immutable();

CREATE TABLE ref_store_core_root_refs (
    repository_id UUID NOT NULL,
    root_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    ref_name TEXT NOT NULL CHECK (ref_name LIKE 'refs/%' AND length(ref_name) BETWEEN 6 AND 1024),
    oid TEXT NOT NULL CHECK (oid ~ '^[0-9a-f]{40}$' OR oid ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (repository_id, root_id, generation, ref_name),
    FOREIGN KEY (repository_id, root_id, generation)
        REFERENCES ref_store_core_roots (repository_id, root_id, generation) ON DELETE RESTRICT
);

CREATE TRIGGER ref_store_core_root_refs_immutable BEFORE UPDATE OR DELETE ON ref_store_core_root_refs FOR EACH ROW EXECUTE FUNCTION ref_store_core_root_immutable();

CREATE TABLE ref_store_core_root_oids (
    repository_id UUID NOT NULL,
    root_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    ordinal INT NOT NULL CHECK (ordinal >= 0 AND ordinal <= 4095),
    oid TEXT NOT NULL CHECK (oid ~ '^[0-9a-f]{40}$' OR oid ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (repository_id, root_id, generation, ordinal),
    UNIQUE (repository_id, root_id, generation, oid),
    FOREIGN KEY (repository_id, root_id, generation)
        REFERENCES ref_store_core_roots (repository_id, root_id, generation) ON DELETE RESTRICT
);

CREATE TRIGGER ref_store_core_root_oids_immutable BEFORE UPDATE OR DELETE ON ref_store_core_root_oids FOR EACH ROW EXECUTE FUNCTION ref_store_core_root_immutable();

-- One row per protected pack with the COMPLETE pack + both artifact identities
-- (storage tenant/authority/attempt/namespace/sha256/length, provider, backend
-- identity, verified read-back); it depends on no other surviving ledger row.
CREATE TABLE ref_store_core_root_packs (
    repository_id UUID NOT NULL,
    root_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    pack_id UUID NOT NULL,
    registration_id UUID NOT NULL,
    artifact_set_digest TEXT NOT NULL CHECK (artifact_set_digest ~ '^[0-9a-f]{64}$'),
    joined_revision BIGINT NOT NULL CHECK (joined_revision > 0),
    pack_slot INT NOT NULL CHECK (pack_slot = 0),
    pack_hold_id UUID NOT NULL,
    pack_storage_tenant_id UUID NOT NULL,
    pack_authority_id UUID NOT NULL,
    pack_authority_generation BIGINT NOT NULL CHECK (pack_authority_generation > 0),
    pack_attempt_id UUID NOT NULL,
    pack_namespace TEXT NOT NULL CHECK (length(pack_namespace) BETWEEN 1 AND 48),
    pack_sha256 TEXT NOT NULL CHECK (pack_sha256 ~ '^[0-9a-f]{64}$'),
    pack_length BIGINT NOT NULL CHECK (pack_length > 0),
    pack_provider TEXT NOT NULL CHECK (length(pack_provider) BETWEEN 1 AND 64),
    pack_backend_identity TEXT NOT NULL CHECK (pack_backend_identity ~ '^[0-9a-f]{64}$'),
    pack_verified_sha256 TEXT NOT NULL CHECK (pack_verified_sha256 = pack_sha256),
    pack_verified_length BIGINT NOT NULL CHECK (pack_verified_length = pack_length),
    idx_slot INT NOT NULL CHECK (idx_slot = 1),
    idx_hold_id UUID NOT NULL,
    idx_storage_tenant_id UUID NOT NULL,
    idx_authority_id UUID NOT NULL,
    idx_authority_generation BIGINT NOT NULL CHECK (idx_authority_generation > 0),
    idx_attempt_id UUID NOT NULL,
    idx_namespace TEXT NOT NULL CHECK (length(idx_namespace) BETWEEN 1 AND 48),
    idx_sha256 TEXT NOT NULL CHECK (idx_sha256 ~ '^[0-9a-f]{64}$'),
    idx_length BIGINT NOT NULL CHECK (idx_length > 0),
    idx_provider TEXT NOT NULL CHECK (length(idx_provider) BETWEEN 1 AND 64),
    idx_backend_identity TEXT NOT NULL CHECK (idx_backend_identity ~ '^[0-9a-f]{64}$'),
    idx_verified_sha256 TEXT NOT NULL CHECK (idx_verified_sha256 = idx_sha256),
    idx_verified_length BIGINT NOT NULL CHECK (idx_verified_length = idx_length),
    PRIMARY KEY (repository_id, root_id, generation, pack_id),
    FOREIGN KEY (repository_id, root_id, generation)
        REFERENCES ref_store_core_roots (repository_id, root_id, generation) ON DELETE RESTRICT
);

CREATE TRIGGER ref_store_core_root_packs_immutable BEFORE UPDATE OR DELETE ON ref_store_core_root_packs FOR EACH ROW EXECUTE FUNCTION ref_store_core_root_immutable();

-- Release fence, written whether or not a capture already exists: a delayed
-- `register` finds the tombstone, compares `expected_register_digest` and is
-- refused instead of creating protection the caller already released.
CREATE TABLE ref_store_core_root_tombstones (
    repository_id UUID NOT NULL,
    root_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation >= 2),
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN
        ('ci', 'workspace', 'pull_request', 'namespace', 'backup', 'export', 'operator_audit')),
    business_intent_digest TEXT NOT NULL CHECK (business_intent_digest ~ '^[0-9a-f]{64}$'),
    release_request_id UUID NOT NULL,
    release_digest TEXT NOT NULL CHECK (release_digest ~ '^[0-9a-f]{64}$'),
    expected_register_digest TEXT NOT NULL CHECK (expected_register_digest ~ '^[0-9a-f]{64}$'),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, root_id, generation)
);

CREATE TRIGGER ref_store_core_root_tombstones_immutable BEFORE UPDATE OR DELETE ON ref_store_core_root_tombstones FOR EACH ROW EXECUTE FUNCTION ref_store_core_root_immutable();

-- Idempotent receipts: bounded canonical JSON with no payload/ref/token material.
CREATE TABLE ref_store_core_root_receipts (
    request_id UUID PRIMARY KEY,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN
        ('ci', 'workspace', 'pull_request', 'namespace', 'backup', 'export', 'operator_audit')),
    business_intent_digest TEXT NOT NULL CHECK (business_intent_digest ~ '^[0-9a-f]{64}$'),
    root_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation IN (1, 2)),
    action TEXT NOT NULL CHECK (action IN ('register', 'release')),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    body JSONB NOT NULL CHECK (octet_length(body::text) <= 65536),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, request_id)
);

CREATE TRIGGER ref_store_core_root_receipts_immutable BEFORE UPDATE OR DELETE ON ref_store_core_root_receipts FOR EACH ROW EXECUTE FUNCTION ref_store_core_root_immutable();

-- Retained monotone counters: no auto-prune/refund; refusal is backpressure only.
CREATE TABLE ref_store_core_root_repo_usage (
    repository_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    roots BIGINT NOT NULL DEFAULT 0 CHECK (roots >= 0),
    root_oid_refs BIGINT NOT NULL DEFAULT 0 CHECK (root_oid_refs >= 0),
    pack_bindings BIGINT NOT NULL DEFAULT 0 CHECK (pack_bindings >= 0),
    receipts BIGINT NOT NULL DEFAULT 0 CHECK (receipts >= 0),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ref_store_core_root_tenant_usage (
    tenant_id UUID PRIMARY KEY,
    roots BIGINT NOT NULL DEFAULT 0 CHECK (roots >= 0),
    root_oid_refs BIGINT NOT NULL DEFAULT 0 CHECK (root_oid_refs >= 0),
    pack_bindings BIGINT NOT NULL DEFAULT 0 CHECK (pack_bindings >= 0),
    receipts BIGINT NOT NULL DEFAULT 0 CHECK (receipts >= 0),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION ref_store_core_root_usage_monotone() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'roots quota counters are retained and cannot be deleted';
    END IF;
    IF NEW.roots < OLD.roots
       OR NEW.root_oid_refs < OLD.root_oid_refs
       OR NEW.pack_bindings < OLD.pack_bindings
       OR NEW.receipts < OLD.receipts
       OR NEW.logical_bytes < OLD.logical_bytes THEN
        RAISE EXCEPTION 'roots quota counters are monotone';
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ref_store_core_root_repo_usage_monotone BEFORE UPDATE OR DELETE ON ref_store_core_root_repo_usage FOR EACH ROW EXECUTE FUNCTION ref_store_core_root_usage_monotone();

CREATE TRIGGER ref_store_core_root_tenant_usage_monotone BEFORE UPDATE OR DELETE ON ref_store_core_root_tenant_usage FOR EACH ROW EXECUTE FUNCTION ref_store_core_root_usage_monotone();

-- ---------------------------------------------------------------------------
-- 4. Publication decisions (fragment produced by the decisions owner)
-- ---------------------------------------------------------------------------
-- Stable scope rows so that "no rule / no lock / no review" is still a recorded
-- dependency. `version` is a monotone observed counter, never the sole
-- authority for a recheck (legacy writers do not bump it); the canonical fact
-- digest in ref_store_decision_dependencies is compared instead.
CREATE TABLE ref_store_decision_scopes (
    scope_kind TEXT NOT NULL CHECK (scope_kind IN (
        'token','parent_token','session','user','org_membership','org_team', 'repo_access','repo_lifecycle','branch_rules','pull','checks','reviews', 'lfs_locks','authority')),
    scope_id UUID NOT NULL,
    version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
    state TEXT NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN','CLOSING')),
    change_id UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (scope_kind, scope_id)
);

-- One decision per operation. `state` is one-way (OPEN -> CONSUMED |
-- CANCELLED | REJECTED) with exactly one terminal transition; expiry is
-- REJECTED with the stable code 'expired'. `token_digest` is the PG-only
-- credential identity and is never copied into a public receipt body.
CREATE TABLE ref_store_publication_decisions (
    decision_id UUID PRIMARY KEY,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    token_id UUID NOT NULL,
    token_digest TEXT NOT NULL CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    operation_id UUID NOT NULL,
    issuer_id UUID NOT NULL,
    lane TEXT NOT NULL CHECK (
        octet_length(lane) >= 1 AND octet_length(lane) <= 64
        AND lane !~ '[^A-Za-z0-9._:-]'
    ),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    mode TEXT NOT NULL CHECK (mode IN ('atomic','accepted_subset')),
    action TEXT NOT NULL DEFAULT 'push' CHECK (action IN ('push','merge')),
    merge_pull_number BIGINT,
    merge_version BIGINT,
    merge_head_oid TEXT,
    merge_base_oid TEXT,
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1','sha256')),
    history_incarnation UUID NOT NULL,
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch > 0),
    base_revision BIGINT NOT NULL CHECK (base_revision > 0),
    base_gate_digest TEXT NOT NULL CHECK (base_gate_digest ~ '^[0-9a-f]{64}$'),
    command_digest TEXT NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
    refs_digest TEXT NOT NULL CHECK (refs_digest ~ '^[0-9a-f]{64}$'),
    selected_refs_digest TEXT NOT NULL CHECK (selected_refs_digest ~ '^[0-9a-f]{64}$'),
    selection_digest TEXT NOT NULL CHECK (selection_digest ~ '^[0-9a-f]{64}$'),
    policy_digest TEXT NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    facts_digest TEXT NOT NULL CHECK (facts_digest ~ '^[0-9a-f]{64}$'),
    authz_digest TEXT NOT NULL CHECK (authz_digest ~ '^[0-9a-f]{64}$'),
    dependencies_digest TEXT NOT NULL CHECK (dependencies_digest ~ '^[0-9a-f]{64}$'),
    packs_digest TEXT NOT NULL CHECK (packs_digest ~ '^[0-9a-f]{64}$'),
    hold_receipts_digest TEXT NOT NULL CHECK (hold_receipts_digest ~ '^[0-9a-f]{64}$'),
    captured_oid_digest TEXT NOT NULL CHECK (captured_oid_digest ~ '^[0-9a-f]{64}$'),
    not_after_millis BIGINT NOT NULL CHECK (not_after_millis > 0),
    created_db_millis BIGINT NOT NULL CHECK (created_db_millis > 0),
    state TEXT NOT NULL CHECK (state IN ('OPEN','CONSUMED','CANCELLED','REJECTED')),
    consume_receipt_id UUID,
    proof_facts_digest TEXT CHECK (proof_facts_digest IS NULL OR proof_facts_digest ~ '^[0-9a-f]{64}$'),
    closed_code TEXT CHECK (closed_code IS NULL OR (octet_length(closed_code) BETWEEN 1 AND 64)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    consumed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    cancel_change_id UUID,
    UNIQUE (repository_id, operation_id),
    UNIQUE (decision_id, repository_id),
    CHECK (
        (action = 'push' AND merge_pull_number IS NULL AND merge_version IS NULL
         AND merge_head_oid IS NULL AND merge_base_oid IS NULL)
        OR
        (action = 'merge' AND merge_pull_number IS NOT NULL AND merge_pull_number > 0
         AND merge_version IS NOT NULL AND merge_version > 0
         AND merge_head_oid IS NOT NULL AND merge_base_oid IS NOT NULL
         AND merge_head_oid ~ '^[0-9a-f]+$' AND merge_base_oid ~ '^[0-9a-f]+$'
         AND length(merge_head_oid) = CASE object_format WHEN 'sha1' THEN 40 ELSE 64 END
         AND length(merge_base_oid) = CASE object_format WHEN 'sha1' THEN 40 ELSE 64 END)
    ),
    CHECK ((state = 'CONSUMED') = (consume_receipt_id IS NOT NULL AND consumed_at IS NOT NULL)),
    CHECK ((state <> 'CONSUMED') = (consume_receipt_id IS NULL)),
    CHECK ((state = 'CANCELLED') = (cancelled_at IS NOT NULL)),
    CHECK ((state = 'REJECTED') = (rejected_at IS NOT NULL)),
    CHECK (not_after_millis >= created_db_millis)
);

CREATE INDEX ref_store_publication_decisions_repo_op
    ON ref_store_publication_decisions (repository_id, operation_id);
CREATE INDEX ref_store_publication_decisions_open_expiry
    ON ref_store_publication_decisions (state, not_after_millis);

-- Exact dependency set observed after the lock wait: a changed version or
-- changed canonical fact digest at commit is a conflict, never a silent re-auth.
CREATE TABLE ref_store_decision_dependencies (
    decision_id UUID NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN (
        'token','parent_token','session','user','org_membership','org_team', 'repo_access','repo_lifecycle','branch_rules','pull','checks','reviews', 'lfs_locks','authority')),
    scope_id UUID NOT NULL,
    observed_version BIGINT NOT NULL CHECK (observed_version >= 0),
    observed_digest TEXT NOT NULL CHECK (observed_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (decision_id, scope_kind, scope_id)
);

-- Per-ref selection verdicts make "selection before the final closure proof"
-- durable and re-preparable; a partial selection is never rewritten in place.
CREATE TABLE ref_store_decision_refs (
    decision_id UUID NOT NULL,
    ref_ordinal INTEGER NOT NULL CHECK (ref_ordinal >= 0 AND ref_ordinal < 128),
    ref_name TEXT NOT NULL CHECK (
        octet_length(ref_name) >= 6 AND octet_length(ref_name) <= 1024
        AND ref_name LIKE 'refs/%' AND ref_name !~ '[[:cntrl:]]'
    ),
    verdict TEXT NOT NULL CHECK (verdict IN ('accept','reject')),
    reject_code TEXT CHECK (reject_code IS NULL OR reject_code !~ '[^a-z_]'),
    old_oid TEXT CHECK (old_oid IS NULL OR old_oid ~ '^[0-9a-f]{40}$' OR old_oid ~ '^[0-9a-f]{64}$'),
    new_oid TEXT CHECK (new_oid IS NULL OR new_oid ~ '^[0-9a-f]{40}$' OR new_oid ~ '^[0-9a-f]{64}$'),
    selection_verdict TEXT NOT NULL CHECK (
        selection_verdict = 'accepted' OR selection_verdict ~ '^rejected:(cas|policy|missing_target|bad_object_type|prefix_conflict|head_dependency):[[:print:]]{1,96}$'
    ),
    PRIMARY KEY (decision_id, ref_name),
    UNIQUE (decision_id, ref_ordinal),
    CHECK ((verdict = 'accept') = (selection_verdict = 'accepted')),
    CHECK ((verdict = 'reject') = (reject_code IS NOT NULL))
);

-- Decision-level cancel-before-install tombstone, written in the same
-- transaction as the migration-138 operation tombstone. `decision_id` starts
-- NULL when the cancel wins first; the single NULL -> id binding is the only
-- permitted update of this row.
CREATE TABLE ref_store_decision_cancellations (
    repository_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    decision_id UUID,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    actor_id UUID NOT NULL,
    reason TEXT NOT NULL CHECK (octet_length(reason) >= 1 AND octet_length(reason) <= 256 AND reason !~ '[[:cntrl:]]'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, operation_id),
    CHECK (decision_id IS NULL OR decision_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

CREATE INDEX ref_store_decision_cancellations_decision
    ON ref_store_decision_cancellations (decision_id) WHERE decision_id IS NOT NULL;

-- Retained admission usage. Counters are monotone: no refund on cancel, reject,
-- expiry, error, unknown completion or owner/repository deletion; no pruning or
-- retention cutoff may bypass them.
CREATE TABLE ref_store_decision_repo_usage (
    repository_id UUID PRIMARY KEY,
    decisions BIGINT NOT NULL DEFAULT 0 CHECK (decisions >= 0),
    ref_verdicts BIGINT NOT NULL DEFAULT 0 CHECK (ref_verdicts >= 0),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ref_store_decision_tenant_usage (
    tenant_id UUID PRIMARY KEY,
    decisions BIGINT NOT NULL DEFAULT 0 CHECK (decisions >= 0),
    ref_verdicts BIGINT NOT NULL DEFAULT 0 CHECK (ref_verdicts >= 0),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Decision identity/digests and the single terminal transition are immutable.
CREATE FUNCTION rootyard_publication_decision_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.decision_id, NEW.repository_id, NEW.tenant_id, NEW.owner_id, NEW.actor_id,
        NEW.token_id, NEW.token_digest, NEW.operation_id, NEW.issuer_id, NEW.lane,
        NEW.sequence, NEW.mode, NEW.object_format, NEW.history_incarnation,
        NEW.authority_epoch, NEW.group_epoch, NEW.base_revision, NEW.base_gate_digest,
        NEW.command_digest, NEW.refs_digest, NEW.selected_refs_digest,
        NEW.selection_digest, NEW.policy_digest, NEW.facts_digest, NEW.authz_digest,
        NEW.dependencies_digest, NEW.packs_digest, NEW.hold_receipts_digest,
        NEW.captured_oid_digest, NEW.not_after_millis, NEW.created_db_millis,
        NEW.action, NEW.merge_pull_number, NEW.merge_version, NEW.merge_head_oid, NEW.merge_base_oid)
       IS DISTINCT FROM
       (OLD.decision_id, OLD.repository_id, OLD.tenant_id, OLD.owner_id, OLD.actor_id,
        OLD.token_id, OLD.token_digest, OLD.operation_id, OLD.issuer_id, OLD.lane,
        OLD.sequence, OLD.mode, OLD.object_format, OLD.history_incarnation,
        OLD.authority_epoch, OLD.group_epoch, OLD.base_revision, OLD.base_gate_digest,
        OLD.command_digest, OLD.refs_digest, OLD.selected_refs_digest,
        OLD.selection_digest, OLD.policy_digest, OLD.facts_digest, OLD.authz_digest,
        OLD.dependencies_digest, OLD.packs_digest, OLD.hold_receipts_digest,
        OLD.captured_oid_digest, OLD.not_after_millis, OLD.created_db_millis,
        OLD.action, OLD.merge_pull_number, OLD.merge_version, OLD.merge_head_oid, OLD.merge_base_oid)
    THEN
        RAISE EXCEPTION 'publication decision identity and digests are immutable';
    END IF;
    IF OLD.state <> 'OPEN' THEN
        RAISE EXCEPTION 'publication decision terminal state is immutable';
    END IF;
    IF NEW.state = 'OPEN' THEN
        RAISE EXCEPTION 'publication decision update must become terminal';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER publication_decision_immutable BEFORE UPDATE ON ref_store_publication_decisions FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_immutable();

CREATE FUNCTION rootyard_publication_decision_no_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'publication decision history is never deleted or truncated'; END $$;

CREATE TRIGGER publication_decision_no_delete BEFORE DELETE ON ref_store_publication_decisions FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_no_delete();

CREATE TRIGGER publication_decision_refs_no_delete BEFORE DELETE ON ref_store_decision_refs FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_no_delete();

CREATE TRIGGER publication_decision_dependencies_no_delete BEFORE DELETE ON ref_store_decision_dependencies FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_no_delete();

-- Per-ref verdicts and dependency observations are write-once.
CREATE FUNCTION rootyard_publication_decision_child_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'publication decision child rows are immutable'; END $$;

CREATE TRIGGER publication_decision_refs_immutable BEFORE UPDATE ON ref_store_decision_refs FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_child_immutable();

CREATE TRIGGER publication_decision_dependencies_immutable BEFORE UPDATE ON ref_store_decision_dependencies FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_child_immutable();

-- A cancellation tombstone may only bind its decision id once.
CREATE FUNCTION rootyard_publication_decision_cancellation_bind() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.repository_id, NEW.operation_id, NEW.request_digest, NEW.actor_id, NEW.reason,
        NEW.created_at)
       IS DISTINCT FROM
       (OLD.repository_id, OLD.operation_id, OLD.request_digest, OLD.actor_id, OLD.reason,
        OLD.created_at)
    THEN
        RAISE EXCEPTION 'publication decision cancellation is immutable';
    END IF;
    IF OLD.decision_id IS NOT NULL THEN
        RAISE EXCEPTION 'publication decision cancellation decision id is already bound';
    END IF;
    IF NEW.decision_id IS NULL THEN
        RAISE EXCEPTION 'publication decision cancellation update must bind a decision id';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER publication_decision_cancellation_bind BEFORE UPDATE ON ref_store_decision_cancellations FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_cancellation_bind();

CREATE TRIGGER publication_decision_cancellation_no_delete BEFORE DELETE ON ref_store_decision_cancellations FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_no_delete();

-- Retained decision usage counters are monotone and never deleted.
CREATE FUNCTION rootyard_publication_decision_usage_monotone() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.decisions < OLD.decisions OR NEW.ref_verdicts < OLD.ref_verdicts
       OR NEW.logical_bytes < OLD.logical_bytes
    THEN
        RAISE EXCEPTION 'publication decision usage counters never decrease';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER publication_decision_repo_usage_monotone BEFORE UPDATE ON ref_store_decision_repo_usage FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_usage_monotone();

CREATE TRIGGER publication_decision_tenant_usage_monotone BEFORE UPDATE ON ref_store_decision_tenant_usage FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_usage_monotone();

CREATE TRIGGER publication_decision_repo_usage_no_delete BEFORE DELETE ON ref_store_decision_repo_usage FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_no_delete();

CREATE TRIGGER publication_decision_tenant_usage_no_delete BEFORE DELETE ON ref_store_decision_tenant_usage FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_no_delete();

-- Scope rows are control rows: re-observed (monotone version) and closed by a
-- revoke coordinator, but never deleted and never reopened.
CREATE FUNCTION rootyard_publication_decision_scope_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'publication decision scopes are never deleted';
    END IF;
    IF NEW.scope_kind <> OLD.scope_kind OR NEW.scope_id <> OLD.scope_id THEN
        RAISE EXCEPTION 'publication decision scope identity is immutable';
    END IF;
    IF NEW.version < OLD.version THEN
        RAISE EXCEPTION 'publication decision scope version is monotone';
    END IF;
    IF OLD.state = 'CLOSING' AND NEW.state <> 'CLOSING' THEN
        RAISE EXCEPTION 'publication decision scope state is one-way';
    END IF;
    IF OLD.change_id IS NOT NULL AND NEW.change_id IS DISTINCT FROM OLD.change_id THEN
        RAISE EXCEPTION 'publication decision scope change id is immutable';
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END $$;

CREATE TRIGGER publication_decision_scope_guard BEFORE UPDATE OR DELETE ON ref_store_decision_scopes FOR EACH ROW EXECUTE FUNCTION rootyard_publication_decision_scope_guard();

INSERT INTO schema_migrations (version) VALUES (144) ON CONFLICT DO NOTHING;
