//! SQL reads of the paired-archive source validator.
//!
//! Every declared set is enumerated from its own declaring table, never from
//! the artifact rows, so a missing pack/idx pair cannot silently shrink the
//! result. The artifact side is always a LEFT JOIN, turning a missing row into
//! a NULL that the decoder reports instead of dropping the registration.
/// Every declared set row: source kind, declaring header and the complete pack
/// descriptor it stored. Only `pg_refstore` repositories declare packs, and each
/// kind is enumerated from its own table, never from the artifact rows, so a
/// missing pair cannot shrink the declared set:
///
/// * `membership`: the live pack set of the core gate;
/// * `snapshot_packs`: an A5 snapshot pack set;
/// * `root_packs`: a retained root (active or released; a release-before-register
///   tombstone has no capture row and therefore declares nothing);
/// * `serving_read_packs`: a transient serving read lease.
///
/// Each set row carries its own artifact-set digest and joined revision, so a
/// partial or re-pointed row is a mismatch instead of being averaged away.
pub(in crate::backup) const DECLARED_SETS: &str = "WITH scoped AS (
           SELECT 'membership'::text source,p.repository_id,p.pack_id,p.registration_id,p.artifact_set_digest,
                  p.joined_revision
             FROM public.ref_store_core_pack_memberships p
            UNION ALL
           SELECT 'snapshot_packs',p.repository_id,p.pack_id,p.registration_id,p.artifact_set_digest,
                  p.joined_revision
             FROM public.ref_store_core_snapshot_packs p
            UNION ALL
           SELECT 'root_packs',p.repository_id,p.pack_id,p.registration_id,p.artifact_set_digest,p.joined_revision
             FROM public.ref_store_core_root_packs p
            UNION ALL
           SELECT 'serving_read_packs',s.repository_id,p.pack_id,p.registration_id,p.artifact_set_digest,
                  p.joined_revision
             FROM public.ref_store_core_serving_read_packs p
             JOIN public.ref_store_core_serving_reads s ON s.pin_id=p.pin_id),
         declared AS (
           SELECT s.* FROM scoped s
             JOIN public.repositories r ON r.id=s.repository_id AND r.storage_backend='pg_refstore'),
         sets AS (
           SELECT d.repository_id,d.pack_id,d.registration_id,
                  array_agg(DISTINCT d.source ORDER BY d.source) declared_by,
                  array_agg(DISTINCT d.source||'='||d.artifact_set_digest||'@'||d.joined_revision ORDER BY d.source||'='||d.artifact_set_digest||'@'||d.joined_revision)
                    declared_sets
             FROM declared d
            GROUP BY d.repository_id,d.pack_id,d.registration_id),
         published AS (
           SELECT s.*,g.registration_id IS NOT NULL registered,
                  g.repository_id publication_repository_id,g.pack_id publication_pack_id,
                  g.tenant_id,g.owner_id,ge.tenant_id gate_tenant_id,r.owner_id actual_repository_owner,
                  g.history_incarnation,g.authority_epoch,g.group_epoch,g.object_format,
                  g.gate_revision,g.acquire_request_id,g.consume_request_id,g.artifact_set_digest publication_digest,
                  ARRAY(SELECT DISTINCT q.operation_id FROM public.artifact_holds h
                          JOIN public.artifact_hold_requests q ON q.request_id=h.request_id
                         WHERE h.hold_id IN (
                           SELECT f.hold_id FROM public.ref_store_core_pack_artifacts f
                            WHERE f.registration_id=s.registration_id)) issuer_operations
             FROM sets s
             LEFT JOIN public.ref_store_core_pack_publications g
               ON g.registration_id=s.registration_id AND g.repository_id=s.repository_id AND g.pack_id=s.pack_id
             LEFT JOIN public.repositories r ON r.id=s.repository_id
             LEFT JOIN public.ref_store_core_gates ge ON ge.repository_id=s.repository_id)";

/// The header-only declared rows (no artifact join) for
/// [`super::ledger::inventory`]: [`DECLARED_COLUMNS`] (0..19) plus the artifact
/// sentinel `NULL::text AS role` (20). [`decode_declared`] stops at a `role` of
/// `None` and never reads 21.., so this deliberately is *not* a mirror of
/// [`ARTIFACT_COLUMNS`]: only the "no artifact" sentinel is supplied.
pub(in crate::backup) fn declared_sql() -> String {
    format!(
        "{DECLARED_SETS}
         SELECT {DECLARED_COLUMNS},{ARTIFACT_SENTINEL}
           FROM published p
          ORDER BY p.repository_id,p.pack_id,p.registration_id"
    )
}

/// The registration columns of a declared set, used by both declared reads.
/// Positions (the `ORDER BY` key block first):
///
/// * 0..2 `(repository_id, pack_id, registration_id)` key, 3 registered;
/// * 4 publication tenant, 5 publication owner (the A3 pack producer);
/// * 6..12 realm (`history_incarnation`, `authority_epoch`, `group_epoch`,
///   `object_format`), gate revision, acquire and consume request;
/// * 13 publication digest, 14 declaring set kinds, 15 declaring sets;
/// * 16 actual `repositories.owner_id`, 17 core gate `tenant_id`;
/// * 18..19 the publication's own repository and pack.
pub(in crate::backup) const DECLARED_COLUMNS: &str =
    "p.repository_id,p.pack_id,p.registration_id,p.registered,p.tenant_id,p.owner_id,
        p.history_incarnation,p.authority_epoch,p.group_epoch,p.object_format,p.gate_revision,p.acquire_request_id,
        p.consume_request_id,p.publication_digest,p.declared_by,p.declared_sets,
        p.actual_repository_owner,p.gate_tenant_id,p.publication_repository_id,p.publication_pack_id";

/// The artifact columns of one declared registration (LEFT JOINed, so a missing
/// artifact, acquire request, hold or receipt is a NULL row rather than a
/// shrunk result). Positions 20..:
///
/// * 20..29 artifact row (`role`, `slot`, `hold_id`, acquire/consume request,
///   provider, backend identity, sha256, length, locator tenant);
/// * 30..31 the artifact row's own repository and pack (not in the locator
///   digest, so each is judged against the declared key);
/// * 32..35 acquire request (`request_id`, repository, tenant, owner) joined on
///   the hold's `request_id`;
/// * 36..48 hold (`request_id`, slot, repository, provider, backend identity,
///   storage tenant, authority id, authority generation, attempt, namespace,
///   sha256, length, tenant), then 49 hold owner;
/// * 50 receipt present, 51..53 consume receipt repository/tenant/owner (same
///   hold/request/consume ids as before), 54 receipts of this exact
///   hold/consume pair (outside the inner joins), 55 live issuer operation,
///   56 the hold's target slot.
pub(in crate::backup) const ARTIFACT_COLUMNS: &str =
    "a.role,a.slot,a.hold_id,a.acquire_request_id,a.consume_request_id,a.provider,
        a.backend_identity,a.sha256,a.content_length,a.tenant_id,a.repository_id,a.pack_id,
        q.request_id,q.repository_id,q.tenant_id,q.owner_id,
        h.request_id,h.slot,h.repository_id,h.provider,h.backend_identity,h.storage_tenant_id,
        h.authority_id,h.authority_generation,h.attempt_id,h.namespace,h.sha256,h.content_length,h.tenant_id,
        h.owner_id,
        c.hold_id IS NOT NULL,c.repository_id,c.tenant_id,c.owner_id,
        (SELECT count(*) FROM public.artifact_hold_consume_receipts x
           WHERE x.consume_request_id=a.consume_request_id AND x.hold_id=a.hold_id),
        COALESCE(h.operation_id=ANY(p.issuer_operations),FALSE),h.slot";

/// The absent-artifact sentinel of [`declared_sql`], the only extra column the
/// header-only shape needs.
pub(in crate::backup) const ARTIFACT_SENTINEL: &str = "NULL::text AS role";

/// Every declared registration with its publication, artifacts, durable hold
/// and consume receipt, optionally restricted to `ids` (a `uuid[]` parameter).
pub(in crate::backup) fn declared_query(restrict: bool) -> String {
    let (wanted, join) = if restrict {
        (
            ", wanted AS (SELECT unnest($1::uuid[]) registration_id)",
            " JOIN wanted w ON w.registration_id=p.registration_id",
        )
    } else {
        ("", "")
    };
    format!(
        "{DECLARED_SETS}{wanted}
         SELECT {DECLARED_COLUMNS},{ARTIFACT_COLUMNS}
           FROM published p{join}
           LEFT JOIN public.ref_store_core_pack_artifacts a ON a.registration_id=p.registration_id
           LEFT JOIN public.artifact_holds h ON h.hold_id=a.hold_id AND h.request_id=a.acquire_request_id
           LEFT JOIN public.artifact_hold_requests q ON q.request_id=h.request_id
           LEFT JOIN public.artifact_hold_consume_receipts c ON c.hold_id=a.hold_id
             AND c.consume_request_id=a.consume_request_id AND c.request_id=a.acquire_request_id
          ORDER BY p.repository_id,p.pack_id,p.registration_id,a.slot"
    )
}

/// A5 snapshots in pack-verified mode with their declared descriptors.
pub(in crate::backup) const SNAPSHOTS: &str =
    "SELECT s.repository_id,s.snapshot_id,s.tenant_id,s.history_incarnation,s.authority_epoch,
            s.group_epoch,s.object_format,s.pack_mode,s.pack_count,s.membership_digest,
            p.pack_id,p.registration_id,p.artifact_set_digest,p.joined_revision
       FROM public.ref_store_core_snapshots s
       LEFT JOIN public.ref_store_core_snapshot_packs p ON p.snapshot_id=s.snapshot_id
      WHERE s.pack_mode='pack_verified'
      ORDER BY s.repository_id,s.snapshot_id,p.pack_id";

/// Retained root captures with their complete pack rows.
pub(in crate::backup) const ROOTS: &str =
    "SELECT r.repository_id,r.root_id,r.generation,r.tenant_id,r.history_incarnation,
            r.authority_epoch,r.group_epoch,r.object_format,r.ref_count,r.oid_count,r.pack_count,r.refs_digest,
            r.pack_set_digest,r.register_digest,r.owner_id,r.purpose,r.business_intent_digest,r.selector_kind,
            r.head_ref,r.head_oid,r.native_binding_digest,
            k.pack_id,k.registration_id,k.artifact_set_digest,k.joined_revision,
            k.pack_slot,k.pack_hold_id,k.pack_storage_tenant_id,k.pack_authority_id,k.pack_authority_generation,
            k.pack_attempt_id,k.pack_namespace,k.pack_sha256,k.pack_length,k.pack_provider,k.pack_backend_identity,
            k.pack_verified_sha256,k.pack_verified_length,
            k.idx_slot,k.idx_hold_id,k.idx_storage_tenant_id,k.idx_authority_id,k.idx_authority_generation,
            k.idx_attempt_id,k.idx_namespace,k.idx_sha256,k.idx_length,k.idx_provider,k.idx_backend_identity,
            k.idx_verified_sha256,k.idx_verified_length
       FROM public.ref_store_core_roots r
       LEFT JOIN public.ref_store_core_root_packs k
         ON k.repository_id=r.repository_id AND k.root_id=r.root_id AND k.generation=r.generation
      ORDER BY r.repository_id,r.root_id,k.pack_id";

pub(in crate::backup) const ROOT_REFS: &str =
    "SELECT repository_id,root_id,generation,ref_name,oid FROM public.ref_store_core_root_refs
       ORDER BY repository_id,root_id,generation,ref_name";

pub(in crate::backup) const ROOT_OIDS: &str =
    "SELECT repository_id,root_id,generation,ordinal,oid FROM public.ref_store_core_root_oids
       ORDER BY repository_id,root_id,generation,ordinal";

pub(in crate::backup) const HEADS: &str =
    "SELECT repository_id,root_id,tenant_id,owner_id,purpose,business_intent_digest,
            register_digest,state,last_generation
       FROM public.ref_store_core_root_heads ORDER BY repository_id,root_id";

pub(in crate::backup) const TOMBSTONES: &str = "SELECT repository_id,root_id,generation,tenant_id,owner_id,purpose,
            business_intent_digest,expected_register_digest,release_digest
       FROM public.ref_store_core_root_tombstones ORDER BY repository_id,root_id";

/// One deployed `pg_refstore` repository: its serving binding and core gate.
pub(in crate::backup) const REALM: &str =
    "SELECT r.id,b.owner_id,b.object_format,b.history_incarnation,b.authority_epoch,b.group_epoch,
            g.tenant_id,g.object_format,g.history_incarnation,g.authority_epoch,g.group_epoch
       FROM public.repositories r
       LEFT JOIN public.ref_store_serving_repositories b ON b.repository_id=r.id
       LEFT JOIN public.ref_store_core_gates g ON g.repository_id=r.id
      WHERE r.storage_backend='pg_refstore'
      ORDER BY r.id";
