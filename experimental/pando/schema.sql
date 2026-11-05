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
 repo uuid NOT NULL, oid text NOT NULL CHECK(oid ~ '^[0-9a-f]{40}$'),
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
 oid text NOT NULL CHECK(oid ~ '^[0-9a-f]{40}$'),
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

