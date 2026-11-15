-- Separate namespace, never applied by Rootyard's production migration runner.
CREATE SCHEMA IF NOT EXISTS pando_lab;
CREATE TABLE IF NOT EXISTS pando_lab.repositories (
 id uuid PRIMARY KEY, generation bigint NOT NULL DEFAULT 0,
 storage_generation bigint NOT NULL DEFAULT 1 CHECK(storage_generation>0),
 storage_backend text NOT NULL DEFAULT 'pando' CHECK(storage_backend IN ('gitfs','pando')),
 migration_state text NOT NULL DEFAULT 'idle' CHECK(migration_state IN ('idle','copying','verified','draining','fenced','switched_over','rolling_back','rolled_back','failed')),
 write_paused boolean NOT NULL DEFAULT false,
 gitfs_path text);
CREATE TABLE IF NOT EXISTS pando_lab.acl (
 repo uuid REFERENCES pando_lab.repositories, principal text NOT NULL,
 write_allowed boolean NOT NULL, PRIMARY KEY(repo,principal));
CREATE TABLE IF NOT EXISTS pando_lab.operations (
 id uuid PRIMARY KEY, repo uuid NOT NULL REFERENCES pando_lab.repositories,
 principal text NOT NULL, state text NOT NULL,
 commands jsonb NOT NULL DEFAULT '[]', result jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS pando_lab.manifests (
 repo uuid NOT NULL REFERENCES pando_lab.repositories, pack_id uuid NOT NULL,
 pack_sha256 text NOT NULL, idx_sha256 text NOT NULL,
 PRIMARY KEY(repo,pack_id));
CREATE TABLE IF NOT EXISTS pando_lab.objects (
 repo uuid NOT NULL, oid text NOT NULL CHECK(oid ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
 pack_id uuid NOT NULL, PRIMARY KEY(repo,oid),
 FOREIGN KEY(repo,pack_id) REFERENCES pando_lab.manifests(repo,pack_id));
CREATE TABLE IF NOT EXISTS pando_lab.refs (
 repo uuid NOT NULL, name text NOT NULL, oid text NOT NULL,
 PRIMARY KEY(repo,name), FOREIGN KEY(repo,oid) REFERENCES pando_lab.objects(repo,oid));
CREATE TABLE IF NOT EXISTS pando_lab.changes (
 repo uuid NOT NULL REFERENCES pando_lab.repositories, generation bigint NOT NULL,
 operation_id uuid NOT NULL REFERENCES pando_lab.operations, commands jsonb NOT NULL,
 PRIMARY KEY(repo,generation), UNIQUE(operation_id));
CREATE TABLE IF NOT EXISTS pando_lab.snapshots (
 id uuid PRIMARY KEY, repo uuid NOT NULL REFERENCES pando_lab.repositories,
 principal text NOT NULL, generation bigint NOT NULL, storage_generation bigint NOT NULL,
 refs jsonb NOT NULL, packs jsonb NOT NULL,
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '5 minutes');
CREATE TABLE IF NOT EXISTS pando_lab.migrations (
 id uuid PRIMARY KEY,
 repo uuid NOT NULL REFERENCES pando_lab.repositories,
 direction text NOT NULL CHECK(direction IN ('gitfs_to_pando','pando_to_gitfs')),
 state text NOT NULL CHECK(state IN ('COPYING','VERIFIED','DRAINED','FENCED','SWITCHED_OVER','ROLLING_BACK','ROLLED_BACK','FAILED')),
 gitfs_path text NOT NULL,
 old_storage_generation bigint NOT NULL,
 new_storage_generation bigint,
 copied_packs bigint NOT NULL DEFAULT 0,
 copied_objects bigint NOT NULL DEFAULT 0,
 post_switchover_commits bigint NOT NULL DEFAULT 0,
 diff_report jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS pando_lab.pinned_roots (
 repo uuid NOT NULL REFERENCES pando_lab.repositories,
 name text NOT NULL CHECK(octet_length(name)>=1 AND octet_length(name)<=256),
 oid text NOT NULL CHECK(oid ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(repo,name),
 FOREIGN KEY(repo,oid) REFERENCES pando_lab.objects(repo,oid));
CREATE TABLE IF NOT EXISTS pando_lab.object_store_manifests (
 repo uuid NOT NULL REFERENCES pando_lab.repositories,
 pack_id uuid NOT NULL,
 bucket text NOT NULL CHECK(octet_length(bucket)>=1 AND octet_length(bucket)<=128),
 pack_key text NOT NULL,
 idx_key text NOT NULL,
 manifest_key text NOT NULL,
 pack_sha256 text NOT NULL,
 idx_sha256 text NOT NULL,
 pack_bytes bigint NOT NULL CHECK(pack_bytes>=0),
 idx_bytes bigint NOT NULL CHECK(idx_bytes>=0),
 object_count bigint NOT NULL CHECK(object_count>=0),
 chunk_size bigint NOT NULL CHECK(chunk_size>=1),
 chunk_count bigint NOT NULL CHECK(chunk_count>=1),
 manifest_json jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(repo,pack_id));
CREATE TABLE IF NOT EXISTS pando_lab.repacks (
 id uuid PRIMARY KEY,
 repo uuid NOT NULL REFERENCES pando_lab.repositories,
 generation bigint NOT NULL CHECK(generation>=0),
 storage_generation bigint NOT NULL CHECK(storage_generation>=1),
 packs_before bigint NOT NULL CHECK(packs_before>=0),
 packs_after bigint NOT NULL CHECK(packs_after>=0),
 objects_before bigint NOT NULL CHECK(objects_before>=0),
 objects_after bigint NOT NULL CHECK(objects_after>=0),
 unreachable_objects_pruned bigint NOT NULL DEFAULT 0 CHECK(unreachable_objects_pruned>=0),
 pinned_roots_count bigint NOT NULL DEFAULT 0 CHECK(pinned_roots_count>=0),
 active_snapshots_count bigint NOT NULL DEFAULT 0 CHECK(active_snapshots_count>=0),
 compacted_pack_id uuid,
 superseded_packs jsonb NOT NULL DEFAULT '[]',
 snapshot_retained_packs jsonb NOT NULL DEFAULT '[]',
 reclaimed_bytes bigint NOT NULL DEFAULT 0 CHECK(reclaimed_bytes>=0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE OR REPLACE FUNCTION pando_lab.immutable_manifest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF current_setting('pando.allow_repack_mutation', true) = 'on'
    OR current_setting('pando_lab.allow_repack', true) = 'on' THEN
  IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
 END IF;
 RAISE EXCEPTION 'immutable object locator';
END $$;
CREATE OR REPLACE TRIGGER immutable_manifest BEFORE UPDATE OR DELETE ON pando_lab.manifests
 FOR EACH ROW EXECUTE FUNCTION pando_lab.immutable_manifest();
CREATE OR REPLACE TRIGGER immutable_object BEFORE UPDATE OR DELETE ON pando_lab.objects
 FOR EACH ROW EXECUTE FUNCTION pando_lab.immutable_manifest();
CREATE TABLE IF NOT EXISTS pando_lab.lifecycle_policies (
 repo UUID PRIMARY KEY REFERENCES pando_lab.repositories(id) ON DELETE CASCADE,
 max_active_packs INTEGER NOT NULL DEFAULT 4 CHECK (max_active_packs >= 1 AND max_active_packs <= 1000),
 cold_transition_age_secs BIGINT NOT NULL DEFAULT 86400 CHECK (cold_transition_age_secs >= 0),
 auto_repack_enabled BOOLEAN NOT NULL DEFAULT TRUE,
 kms_key_id TEXT NOT NULL DEFAULT 'kms-local-default-v1' CHECK (length(btrim(kms_key_id)) >= 3 AND length(kms_key_id) <= 128),
 kms_key_version INTEGER NOT NULL DEFAULT 1 CHECK (kms_key_version >= 1),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS pando_lab.kms_envelopes (
 repo UUID NOT NULL REFERENCES pando_lab.repositories(id) ON DELETE CASCADE,
 pack_id UUID NOT NULL,
 key_id TEXT NOT NULL CHECK (length(btrim(key_id)) >= 3 AND length(btrim(key_id)) <= 128),
 key_version INTEGER NOT NULL CHECK (key_version >= 1),
 cipher_suite TEXT NOT NULL DEFAULT 'AES-256-GCM-HMAC-SHA256' CHECK (cipher_suite IN ('AES-256-GCM-HMAC-SHA256', 'CHACHA20-POLY1305-SHA256')),
 plaintext_sha256 TEXT NOT NULL CHECK (plaintext_sha256 ~ '^[0-9a-f]{64}$'),
 envelope_mac TEXT NOT NULL CHECK (envelope_mac ~ '^[0-9a-f]{64}$'),
 storage_tier TEXT NOT NULL DEFAULT 'hot' CHECK (storage_tier IN ('hot', 'cold_archive')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (repo, pack_id));
ALTER TABLE pando_lab.kms_envelopes
 ADD COLUMN IF NOT EXISTS encryption_mode TEXT NOT NULL DEFAULT 'authenticated-envelope-v1'
  CHECK (encryption_mode IN ('authenticated-envelope-v1', 'synthetic-metadata-lab-only')),
 ADD COLUMN IF NOT EXISTS envelope_id UUID,
 ADD COLUMN IF NOT EXISTS nonce_prefix TEXT,
 ADD COLUMN IF NOT EXISTS wrapped_key_json TEXT,
 ADD COLUMN IF NOT EXISTS ciphertext_sha256 TEXT CHECK (ciphertext_sha256 IS NULL OR ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
 ADD COLUMN IF NOT EXISTS ciphertext_bytes BIGINT CHECK (ciphertext_bytes IS NULL OR ciphertext_bytes >= 0),
 ADD COLUMN IF NOT EXISTS provider_kind TEXT NOT NULL DEFAULT 'local-file-key-provider';
CREATE TABLE IF NOT EXISTS pando_lab.kms_keys (
 repo UUID NOT NULL REFERENCES pando_lab.repositories(id) ON DELETE CASCADE,
 key_id TEXT NOT NULL CHECK (length(btrim(key_id)) >= 3 AND length(key_id) <= 128),
 key_version INTEGER NOT NULL CHECK (key_version >= 1),
 key_sha256 TEXT NOT NULL CHECK (key_sha256 ~ '^[0-9a-f]{64}$'),
 status TEXT NOT NULL CHECK (status IN ('active', 'retained', 'revoked')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 revoked_at TIMESTAMPTZ,
 PRIMARY KEY (repo, key_id));
CREATE TABLE IF NOT EXISTS pando_lab.kms_key_policies (
 repo UUID PRIMARY KEY REFERENCES pando_lab.repositories(id) ON DELETE CASCADE,
 active_key_id TEXT NOT NULL DEFAULT 'kms-local-default-v1' CHECK (length(btrim(active_key_id)) >= 3 AND length(active_key_id) <= 128),
 active_key_version INTEGER NOT NULL DEFAULT 1 CHECK (active_key_version >= 1),
 retain_previous_generations BOOLEAN NOT NULL DEFAULT TRUE,
 min_readable_key_version INTEGER NOT NULL DEFAULT 1 CHECK (min_readable_key_version >= 1),
 provider_revoked BOOLEAN NOT NULL DEFAULT FALSE,
 encryption_mode TEXT NOT NULL DEFAULT 'authenticated-envelope-v1' CHECK (encryption_mode IN ('authenticated-envelope-v1', 'synthetic-metadata-lab-only')),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS pando_lab.kms_rotations (
 id UUID PRIMARY KEY,
 repo UUID NOT NULL REFERENCES pando_lab.repositories(id) ON DELETE CASCADE,
 from_key_id TEXT NOT NULL CHECK (length(btrim(from_key_id)) >= 3 AND length(from_key_id) <= 128),
 from_key_version INTEGER NOT NULL CHECK (from_key_version >= 1),
 to_key_id TEXT NOT NULL CHECK (length(btrim(to_key_id)) >= 3 AND length(to_key_id) <= 128),
 to_key_version INTEGER NOT NULL CHECK (to_key_version >= 1),
 state TEXT NOT NULL CHECK (state IN ('IN_PROGRESS', 'COMPLETED', 'ABORTED')),
 revoke_previous BOOLEAN NOT NULL DEFAULT FALSE,
 total_packs INTEGER NOT NULL DEFAULT 0 CHECK (total_packs >= 0),
 processed_packs INTEGER NOT NULL DEFAULT 0 CHECK (processed_packs >= 0),
 failed_pack_id UUID,
 checkpoint_json JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
