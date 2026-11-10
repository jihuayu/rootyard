-- Bounded, metadata-only snapshot capture and durable metadata pin (#107-A2).
--
-- This migration adds immutable refs/HEAD metadata snapshots, an immutable
-- per-snapshot pin lease, one bounded successful-mutation receipt ledger for
-- create/renew/release, and retained repo/tenant admission usage counters.
--
-- It deliberately adds NO pack membership, blob receipt, artifact hold,
-- logical root, publication decision, Git object closure, HTTP route, serving
-- cutover or GC consumer. `pack_membership_state` is constrained to
-- 'unavailable': a refs/HEAD metadata page is not a Git ReadSnapshot, and a
-- metadata pin is not protective of Git objects. Migration 139's gate/ref/
-- event tables and migration 138's operation registry are not rewritten, and
-- no snapshot/pin row is ever recorded as a ref operation.
--
-- Lifecycle rules encoded here (the adapter enforces the same rules):
--   * Snapshot header and ref rows are immutable; they are never updated.
--   * A pin row is the only mutable metadata: renewal advances `generation` by
--     exactly one, and `active -> released` is the only terminal transition.
--     A released pin never returns to active, its identity columns and
--     `created_at` are immutable, and release keeps the generation and lease
--     timestamps unchanged, so a terminal pin id can never be reused.
--   * `expires_at` stops page reads and renewals only. It never deletes or
--     refunds anything: the pin/snapshot/receipt rows and the usage counters
--     stay for the life of the repository.
--   * Successful create/renew/release receipts are immutable and keyed by one
--     globally unique request id, so an exact retry replays the original
--     receipt instead of creating a second snapshot or lease.
--   * Usage counters are retained admission bounds (per repository and per
--     tenant) over all snapshot headers, snapshot ref rows, logical metadata
--     bytes and successful receipts, including expired and released history.
--     Reaching a bound is explicit backpressure, never eviction.
--
-- Repository lifetime boundary: every snapshot, snapshot ref, pin, receipt and
-- usage row belongs to the repository/tenant lifetime. While the parent
-- repository (or, for tenant usage, the parent user) row exists, a DIRECT
-- DELETE of any of these rows is rejected by a trigger, so a captured identity
-- or a retained quota counter can never be reset in place. Only a legitimate
-- whole-repository/user deletion cascade removes them, because the cascade
-- fires after the parent row is gone. There is still no physical GC or
-- retention expiry here: this is a logical no-delete ledger only.
CREATE TABLE ref_store_core_snapshots (
    snapshot_id UUID PRIMARY KEY,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('verification','maintenance','backup','export','operator_audit')),
    object_format TEXT NOT NULL CHECK (object_format IN ('sha1','sha256')),
    history_incarnation UUID NOT NULL,
    authority_epoch BIGINT NOT NULL CHECK (authority_epoch > 0),
    group_epoch BIGINT NOT NULL CHECK (group_epoch > 0),
    -- The exact gate proof the snapshot was captured under. Refs, HEAD and
    -- this revision/digest are read under the same gate lock as CommitRefs.
    gate_revision BIGINT NOT NULL CHECK (gate_revision > 0),
    gate_digest TEXT NOT NULL CHECK (gate_digest ~ '^[0-9a-f]{64}$'),
    head_ref TEXT COLLATE "C" NOT NULL CHECK (
        octet_length(head_ref) >= 12 AND octet_length(head_ref) <= 1024
        AND head_ref LIKE 'refs/heads/%' AND head_ref !~ '[[:cntrl:]]'
    ),
    head_oid TEXT CHECK (head_oid IS NULL OR head_oid ~ '^[0-9a-f]{40}$' OR head_oid ~ '^[0-9a-f]{64}$'),
    ref_count INTEGER NOT NULL CHECK (ref_count >= 0 AND ref_count <= 4096),
    refs_digest TEXT NOT NULL CHECK (refs_digest ~ '^[0-9a-f]{64}$'),
    pack_membership_state TEXT NOT NULL DEFAULT 'unavailable' CHECK (pack_membership_state = 'unavailable'),
    logical_bytes BIGINT NOT NULL CHECK (logical_bytes > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, snapshot_id),
    -- Full immutable identity of one captured snapshot. Every child pin must
    -- bind the complete scope, not merely the repository-local snapshot id.
    UNIQUE (repository_id, tenant_id, snapshot_id, owner_id, purpose),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

-- Immutable copy of the captured current refs. Byte-ordered ("C") text keeps
-- the keyset page order exactly the lexical byte order the cursor promises.
CREATE TABLE ref_store_core_snapshot_refs (
    snapshot_id UUID NOT NULL REFERENCES ref_store_core_snapshots(snapshot_id) ON DELETE CASCADE,
    ref_name TEXT COLLATE "C" NOT NULL CHECK (
        octet_length(ref_name) >= 6 AND octet_length(ref_name) <= 1024
        AND ref_name LIKE 'refs/%' AND ref_name !~ '[[:cntrl:]]'
    ),
    oid TEXT NOT NULL CHECK (oid ~ '^[0-9a-f]{40}$' OR oid ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (snapshot_id, ref_name)
);

-- One durable pin per immutable snapshot. `generation` is the CAS token for
-- renew/release; a release records the terminal generation without advancing
-- it, so an old-generation release can never end a newer renewed pin.
--
-- The pin binds the full immutable snapshot scope (repository, tenant,
-- snapshot, owner, purpose) through `UNIQUE (repository_id, tenant_id,
-- snapshot_id, owner_id, purpose)`; the tenant/owner/purpose columns cannot
-- disagree with the snapshot header.
CREATE TABLE ref_store_core_pins (
    pin_id UUID PRIMARY KEY,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    snapshot_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('verification','maintenance','backup','export','operator_audit')),
    create_request_id UUID NOT NULL,
    create_digest TEXT NOT NULL CHECK (create_digest ~ '^[0-9a-f]{64}$'),
    generation BIGINT NOT NULL CHECK (generation > 0),
    state TEXT NOT NULL CHECK (state IN ('active','released')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    renewed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    released_at TIMESTAMPTZ,
    release_request_id UUID,
    release_reason TEXT CHECK (
        release_reason IS NULL OR release_reason IN (
            'client_done','superseded','lease_abandoned','maintenance_complete','operator_request'
        )
    ),
    CHECK (expires_at > created_at),
    CHECK (
        (state = 'active' AND released_at IS NULL AND release_request_id IS NULL AND release_reason IS NULL)
        OR (state = 'released' AND released_at IS NOT NULL AND release_request_id IS NOT NULL
            AND release_reason IS NOT NULL)
    ),
    UNIQUE (repository_id, snapshot_id),
    UNIQUE (repository_id, pin_id),
    UNIQUE (repository_id, create_request_id),
    -- Stable parent key for the receipt ledger: a receipt can only bind a pin
    -- of the same repository, tenant and snapshot.
    UNIQUE (repository_id, tenant_id, pin_id, snapshot_id),
    FOREIGN KEY (repository_id, tenant_id, snapshot_id, owner_id, purpose)
        REFERENCES ref_store_core_snapshots(repository_id, tenant_id, snapshot_id, owner_id, purpose)
        ON DELETE CASCADE,
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
);

-- One successful-mutation receipt ledger for create/renew/release. The request
-- id is globally unique and the canonical digest covers the action and every
-- semantic field, so an identical retry replays the stored body and a changed
-- retry is a conflict. Rejected requests are not persisted here.
--
-- The ledger row itself is authoritative: the receipt body must agree with
-- `request_id`, `repository_id`, `tenant_id`, `action`, `pin_id`,
-- `snapshot_id` and `pin_generation`. The full parent pin key also binds the
-- tenant and snapshot, so a body can never point at a pin/snapshot of another
-- repository or snapshot scope.
CREATE TABLE ref_store_core_receipts (
    request_id UUID PRIMARY KEY,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('create','renew','release')),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    pin_id UUID NOT NULL,
    snapshot_id UUID NOT NULL,
    pin_generation BIGINT NOT NULL CHECK (pin_generation > 0),
    body TEXT NOT NULL CHECK (octet_length(body) > 0 AND octet_length(body) <= 4096),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (repository_id, tenant_id, pin_id, snapshot_id)
        REFERENCES ref_store_core_pins(repository_id, tenant_id, pin_id, snapshot_id) ON DELETE CASCADE
);

CREATE INDEX ref_store_core_receipts_pin ON ref_store_core_receipts(repository_id, pin_id);

-- Retained admission usage, charged atomically in the creating transaction and
-- never refunded by expiry or release. `tenant_id` is kept on the repository
-- row so a tenant rollup can be audited from either scope.
CREATE TABLE ref_store_core_repo_usage (
    repository_id UUID PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    snapshot_count BIGINT NOT NULL DEFAULT 0 CHECK (snapshot_count >= 0),
    snapshot_ref_count BIGINT NOT NULL DEFAULT 0 CHECK (snapshot_ref_count >= 0),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0),
    receipt_count BIGINT NOT NULL DEFAULT 0 CHECK (receipt_count >= 0)
);

CREATE TABLE ref_store_core_tenant_usage (
    tenant_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    snapshot_count BIGINT NOT NULL DEFAULT 0 CHECK (snapshot_count >= 0),
    snapshot_ref_count BIGINT NOT NULL DEFAULT 0 CHECK (snapshot_ref_count >= 0),
    logical_bytes BIGINT NOT NULL DEFAULT 0 CHECK (logical_bytes >= 0),
    receipt_count BIGINT NOT NULL DEFAULT 0 CHECK (receipt_count >= 0)
);

CREATE FUNCTION rootyard_ref_store_core_snapshot_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ref-store core metadata snapshot is immutable';
END $$;

CREATE TRIGGER ref_store_core_snapshot_immutable
    BEFORE UPDATE ON ref_store_core_snapshots
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_snapshot_immutable();

CREATE TRIGGER ref_store_core_snapshot_ref_immutable
    BEFORE UPDATE ON ref_store_core_snapshot_refs
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_snapshot_immutable();

CREATE FUNCTION rootyard_ref_store_core_receipt_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ref-store core mutation receipt is immutable';
END $$;

CREATE TRIGGER ref_store_core_receipt_immutable
    BEFORE UPDATE ON ref_store_core_receipts
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_receipt_immutable();

-- A pin may only be renewed (active -> active, generation + 1, live lease) or
-- released once (active -> released, same generation, unchanged lease). The
-- adapter CASes the generation; this trigger is the durable last line of
-- defence against a terminal pin id being reused, a release advancing the
-- generation/changing `expires_at`, or a same-generation update mutating a
-- live lease/time field. Direct COPY restore inserts rows and does not fire
-- this UPDATE-only guard.
CREATE FUNCTION rootyard_ref_store_core_pin_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state = 'released' THEN
        RAISE EXCEPTION 'ref-store core pin % is released and terminal', OLD.pin_id;
    END IF;
    IF NEW.pin_id <> OLD.pin_id
        OR NEW.repository_id <> OLD.repository_id
        OR NEW.tenant_id <> OLD.tenant_id
        OR NEW.snapshot_id <> OLD.snapshot_id
        OR NEW.owner_id <> OLD.owner_id
        OR NEW.purpose <> OLD.purpose
        OR NEW.create_request_id <> OLD.create_request_id
        OR NEW.create_digest <> OLD.create_digest
        OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'ref-store core pin identity is immutable';
    END IF;

    IF NEW.state = 'active' THEN
        -- The only live update is a renewal of a still-live pin: exactly one
        -- generation advance, the old lease still live, the new lease in the
        -- future but no farther than the 3600-second contract maximum, and
        -- monotone renewal/update timestamps. Microsecond differences between
        -- the adapter's separate clock_timestamp() calls are expected, so the
        -- comparisons use ordering, never equality. Release fields stay empty.
        -- This also blocks direct DML that would resurrect an expired active
        -- pin; an expired pin may still take the exact release branch below.
        IF NEW.generation <> OLD.generation + 1
            OR OLD.expires_at <= clock_timestamp()
            OR NEW.expires_at <= clock_timestamp()
            OR NEW.expires_at > clock_timestamp() + interval '3600 seconds'
            OR NEW.renewed_at IS NULL
            OR (OLD.renewed_at IS NOT NULL AND NEW.renewed_at < OLD.renewed_at)
            OR NEW.updated_at < OLD.updated_at
            OR NEW.released_at IS NOT NULL
            OR NEW.release_request_id IS NOT NULL
            OR NEW.release_reason IS NOT NULL THEN
            RAISE EXCEPTION 'ref-store core pin active update is not a valid renewal';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.state = 'released' THEN
        -- The only terminal transition is an exact release of the current
        -- generation: the generation and lease timestamps are unchanged and
        -- only the release fields are set.
        IF NEW.generation <> OLD.generation
            OR NEW.expires_at <> OLD.expires_at
            OR NEW.renewed_at IS DISTINCT FROM OLD.renewed_at
            OR NEW.updated_at < OLD.updated_at
            OR NEW.released_at IS NULL
            OR NEW.release_request_id IS NULL
            OR NEW.release_reason IS NULL
            OR NEW.released_at < OLD.created_at THEN
            RAISE EXCEPTION 'ref-store core pin release transition is invalid';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'ref-store core pin state % is not a supported transition', NEW.state;
END $$;

CREATE TRIGGER ref_store_core_pin_guard
    BEFORE UPDATE ON ref_store_core_pins
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pin_guard();

-- Direct deletes are refused while the parent repository still exists. A
-- legitimate whole-repository cascade deletes the parent first, so the parent
-- is already gone inside this same transaction and the delete is allowed.
-- Snapshot refs have no repository column, so they resolve their parent
-- snapshot header; a direct snapshot delete is itself refused above this point.
CREATE FUNCTION rootyard_ref_store_core_snapshot_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM repositories WHERE id = OLD.repository_id) THEN
        RAISE EXCEPTION 'ref-store core snapshot cannot be deleted while its repository exists';
    END IF;
    RETURN OLD;
END $$;

CREATE TRIGGER ref_store_core_snapshot_delete_guard
    BEFORE DELETE ON ref_store_core_snapshots
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_snapshot_delete_guard();

CREATE FUNCTION rootyard_ref_store_core_snapshot_ref_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM ref_store_core_snapshots s
        JOIN repositories r ON r.id = s.repository_id
        WHERE s.snapshot_id = OLD.snapshot_id
    ) THEN
        RAISE EXCEPTION 'ref-store core snapshot refs cannot be deleted while their snapshot and repository exist';
    END IF;
    RETURN OLD;
END $$;

CREATE TRIGGER ref_store_core_snapshot_ref_delete_guard
    BEFORE DELETE ON ref_store_core_snapshot_refs
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_snapshot_ref_delete_guard();

CREATE FUNCTION rootyard_ref_store_core_pin_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM repositories WHERE id = OLD.repository_id) THEN
        RAISE EXCEPTION 'ref-store core pin cannot be deleted while its repository exists';
    END IF;
    RETURN OLD;
END $$;

CREATE TRIGGER ref_store_core_pin_delete_guard
    BEFORE DELETE ON ref_store_core_pins
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_pin_delete_guard();

CREATE FUNCTION rootyard_ref_store_core_receipt_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM repositories WHERE id = OLD.repository_id) THEN
        RAISE EXCEPTION 'ref-store core receipt cannot be deleted while its repository exists';
    END IF;
    RETURN OLD;
END $$;

CREATE TRIGGER ref_store_core_receipt_delete_guard
    BEFORE DELETE ON ref_store_core_receipts
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_receipt_delete_guard();

CREATE FUNCTION rootyard_ref_store_core_repo_usage_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM repositories WHERE id = OLD.repository_id) THEN
        RAISE EXCEPTION 'ref-store core repository usage cannot be deleted while its repository exists';
    END IF;
    RETURN OLD;
END $$;

CREATE TRIGGER ref_store_core_repo_usage_delete_guard
    BEFORE DELETE ON ref_store_core_repo_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_repo_usage_delete_guard();

CREATE FUNCTION rootyard_ref_store_core_tenant_usage_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE id = OLD.tenant_id) THEN
        RAISE EXCEPTION 'ref-store core tenant usage cannot be deleted while its tenant exists';
    END IF;
    RETURN OLD;
END $$;

CREATE TRIGGER ref_store_core_tenant_usage_delete_guard
    BEFORE DELETE ON ref_store_core_tenant_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_tenant_usage_delete_guard();

-- Retained usage only grows. Expiry, release and retries never refund and no
-- identity is deleted to free room, so a counter decrease is a programming or
-- tampering error rather than a supported operation.
CREATE FUNCTION rootyard_ref_store_core_repo_usage_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.repository_id <> OLD.repository_id OR NEW.tenant_id <> OLD.tenant_id THEN
        RAISE EXCEPTION 'ref-store core repository usage identity is immutable';
    END IF;
    IF NEW.snapshot_count < OLD.snapshot_count
        OR NEW.snapshot_ref_count < OLD.snapshot_ref_count
        OR NEW.logical_bytes < OLD.logical_bytes
        OR NEW.receipt_count < OLD.receipt_count THEN
        RAISE EXCEPTION 'ref-store core retained repository usage cannot decrease';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER ref_store_core_repo_usage_guard
    BEFORE UPDATE ON ref_store_core_repo_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_repo_usage_guard();

CREATE FUNCTION rootyard_ref_store_core_tenant_usage_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id <> OLD.tenant_id THEN
        RAISE EXCEPTION 'ref-store core tenant usage identity is immutable';
    END IF;
    IF NEW.snapshot_count < OLD.snapshot_count
        OR NEW.snapshot_ref_count < OLD.snapshot_ref_count
        OR NEW.logical_bytes < OLD.logical_bytes
        OR NEW.receipt_count < OLD.receipt_count THEN
        RAISE EXCEPTION 'ref-store core retained tenant usage cannot decrease';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER ref_store_core_tenant_usage_guard
    BEFORE UPDATE ON ref_store_core_tenant_usage
    FOR EACH ROW EXECUTE FUNCTION rootyard_ref_store_core_tenant_usage_guard();

INSERT INTO schema_migrations (version) VALUES (140) ON CONFLICT DO NOTHING;
