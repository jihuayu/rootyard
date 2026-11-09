//! Private native publication-facts engine (accepted-subset, feature 3).
//!
//! This is the ONLY place that can build a [`VerifiedPublicationFacts`] value.
//! The type has private fields, lives in this module and has no `Clone`, no
//! `Serialize`/`Deserialize`, no `Default` and no external constructor; the only
//! producer is [`PublicationFactsEngine::facts`], which ran real verified Blob
//! GETs, `git verify-pack`, `git index-pack`, native object-type probes, verified
//! ancestry, changed-path scans and LFS pointer/byte verification.
//!
//! Ordering contract (feature 3): facts are computed BEFORE any PostgreSQL
//! selection, and this module never touches a PostgreSQL client, pool or lease.
//! The same process-wide native pool (2) and view budget (2) as A4/A5b are used;
//! the native permit is released once every child is confirmed quiescent and the
//! bounded owned workspace + view budget stay with the returned facts until drop.
//! The final closure proof later reacquires the SAME pool through
//! `PackVerifier::verify_selected`; there is no second native pool anywhere.
//!
//! Global (whole operation) failures: registered pack/idx SHA-256, length or Git
//! pack integrity, a mismatched/missing Blob object, a missing OLD captured
//! object or non-commit old branch object, plan/baseline disagreement, fixed
//! bounds, the deadline and any native failure. Per-ref facts (not global yet):
//! missing NEW target OID, non-commit branch target, non-fast-forward ancestry
//! and LFS byte failures.
use super::download;
use super::lease::VerificationLease;
use super::publication_support::{
    check_workspace, facts_digest, membership_rows, old_ref_map, pair_bytes, preflight_workspace,
};
use super::view::NativeView;
use super::{acquire_slot, acquire_view_budget, arm, refuse};
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::CommitMode;
use crate::ref_store::contract::{OperationIdentity, RequestDigest};
use crate::ref_store::core::pack_commit::artifact::{RegisteredPack, packs_digest};
use crate::ref_store::core::pack_commit::context::{CapturedRef, MembershipDigest, PackCommitBaseline};
use crate::ref_store::core::pack_commit::contract::{
    MAX_ACTIVE_MEMBERSHIPS, MAX_BATCH_NEW_PACKS, PackArtifactRole, VERIFIER_MAX_OBJECTS, VERIFIER_MAX_PAIRS,
    VERIFIER_MAX_TOTAL_BYTES,
};
use crate::ref_store::core::pack_commit::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use crate::ref_store::core::pack_commit::facts::LfsByteWitness;
use crate::ref_store::core::pack_commit::facts::{RefFacts, VerifiedPackIdentity};
use crate::ref_store::core::pack_commit::plan::{PackCommitPlan, PackCommitScope};
use crate::ref_store::core::types::{GitObjectFormat, RefName};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// Opaque, immutable, natively verified publication facts.
pub(crate) struct VerifiedPublicationFacts {
    identity: OperationIdentity,
    parent_digest: RequestDigest,
    scope: PackCommitScope,
    commit_mode: CommitMode,
    head_ref: RefName,
    old_refs: Vec<CapturedRef>,
    old_membership_digest: MembershipDigest,
    old_packs_digest: RequestDigest,
    new_packs_digest: RequestDigest,
    refs: Vec<RefFacts>,
    pairs: usize,
    bytes: u64,
    digest: RequestDigest,
    /// Keeps the bounded owned workspace + view budget (no native permit) alive
    /// while the facts exist. Never exposes a path or read/write authority.
    _workspace: FactsWorkspace,
}

struct FactsWorkspace {
    _lease: Arc<VerificationLease>,
}

impl VerifiedPublicationFacts {
    #[allow(clippy::too_many_arguments)]
    fn mint(
        request: &Request<'_>,
        probe: super::probe::ProbeOutput,
        packs: Vec<VerifiedPackIdentity>,
        pairs: usize,
        bytes: u64,
        lease: Arc<VerificationLease>,
    ) -> Self {
        let refs = probe.refs;
        let plan = request.plan;
        let digest = facts_digest(
            plan,
            &request.realm_digest,
            &request.old_refs,
            request.old_membership_digest,
            request.old_packs_digest,
            request.new_packs_digest,
            &packs,
            &refs,
        );
        Self {
            identity: plan.identity().clone(),
            parent_digest: *plan.parent_digest(),
            scope: plan.scope().clone(),
            commit_mode: plan.commit_mode(),
            head_ref: request.head_ref.clone(),
            old_refs: request.old_refs.clone(),
            old_membership_digest: request.old_membership_digest,
            old_packs_digest: request.old_packs_digest,
            new_packs_digest: request.new_packs_digest,
            refs,
            pairs,
            bytes,
            digest,
            _workspace: FactsWorkspace { _lease: lease },
        }
    }

    pub(crate) fn repository_id(&self) -> Uuid {
        self.scope.repository_id()
    }

    pub(crate) fn tenant_id(&self) -> Uuid {
        self.scope.tenant_id()
    }

    pub(crate) fn owner_id(&self) -> Uuid {
        self.scope.owner_id()
    }

    pub(crate) fn object_format(&self) -> GitObjectFormat {
        self.scope.object_format()
    }

    pub(crate) fn history_incarnation(&self) -> Uuid {
        self.scope.history_incarnation()
    }

    pub(crate) fn authority_epoch(&self) -> i64 {
        self.scope.authority_epoch()
    }

    pub(crate) fn group_epoch(&self) -> i64 {
        self.scope.group_epoch()
    }

    pub(crate) fn facts_digest(&self) -> &RequestDigest {
        &self.digest
    }

    pub(crate) fn head_ref(&self) -> &RefName {
        &self.head_ref
    }

    pub(crate) fn old_refs(&self) -> &[CapturedRef] {
        &self.old_refs
    }

    pub(crate) fn old_membership_digest(&self) -> MembershipDigest {
        self.old_membership_digest
    }

    /// Digest over the complete verified OLD active pack set.
    pub(crate) fn old_packs_digest(&self) -> &RequestDigest {
        &self.old_packs_digest
    }

    /// Digest over the complete verified NEW registered pack set.
    pub(crate) fn new_packs_digest(&self) -> &RequestDigest {
        &self.new_packs_digest
    }

    pub(crate) fn ref_facts(&self, name: &str) -> Option<&RefFacts> {
        self.refs.iter().find(|facts| facts.name().as_str() == name)
    }

    pub(crate) fn verified_pairs(&self) -> usize {
        self.pairs
    }

    pub(crate) fn verified_bytes(&self) -> u64 {
        self.bytes
    }

    /// Always true for a returned value: there is no partial facts value.
    pub(crate) fn complete(&self) -> bool {
        true
    }

    /// Refuse unless these facts were computed for exactly this plan: same
    /// operation identity, parent digest, realm/scope, commit mode and every ref
    /// name in the original order.
    pub(crate) fn ensure_binds(&self, plan: &PackCommitPlan) -> Result<(), PackCommitError> {
        if self.parent_digest != *plan.parent_digest() || plan.identity() != &self.identity {
            return Err(mismatch("publication facts bind another original operation"));
        }
        if self.commit_mode != plan.commit_mode() {
            return Err(mismatch("publication facts bind another commit mode"));
        }
        let facts_scope = &self.scope;
        let plan_scope = plan.scope();
        if facts_scope.repository_id() != plan_scope.repository_id()
            || facts_scope.tenant_id() != plan_scope.tenant_id()
            || facts_scope.owner_id() != plan_scope.owner_id()
            || facts_scope.object_format() != plan_scope.object_format()
            || facts_scope.history_incarnation() != plan_scope.history_incarnation()
            || facts_scope.authority_epoch() != plan_scope.authority_epoch()
            || facts_scope.group_epoch() != plan_scope.group_epoch()
        {
            return Err(mismatch("publication facts bind another realm/scope"));
        }
        if self.refs.len() != plan.refs().len()
            || self.refs.iter().zip(plan.refs()).any(|(facts, update)| facts.name() != update.name())
        {
            return Err(mismatch("publication facts bind another ref batch"));
        }
        Ok(())
    }
}

impl std::fmt::Debug for VerifiedPublicationFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedPublicationFacts")
            .field("repository_id", &self.repository_id())
            .field("commit_mode", &self.commit_mode)
            .field("refs", &self.refs.len())
            .field("pairs", &self.pairs)
            .finish_non_exhaustive()
    }
}

fn mismatch(detail: &'static str) -> PackCommitError {
    PackCommitError::Rejected(PackCommitRejection::new(PackCommitRejectCode::ContextMismatch, detail))
}

fn rejected(code: PackCommitRejectCode, detail: &'static str) -> PackCommitError {
    PackCommitError::Rejected(PackCommitRejection::new(code, detail))
}

/// Native facts engine. Construction validates the absolute trusted Git binary
/// and grants nothing.
pub(crate) struct PublicationFactsEngine {
    store: BlobStore,
    git: PathBuf,
}

impl PublicationFactsEngine {
    pub(crate) fn new(store: BlobStore, git_binary: PathBuf) -> Result<Self, PackCommitError> {
        let git = super::binary::validate(&git_binary)?;
        Ok(Self { store, git })
    }

    /// Compute the complete per-ref native facts of one accepted-subset plan.
    pub(crate) async fn facts(
        &self,
        plan: &PackCommitPlan,
        baseline: &PackCommitBaseline,
        new_packs: Vec<RegisteredPack>,
        lfs: &dyn LfsByteWitness,
        deadline: Instant,
    ) -> Result<VerifiedPublicationFacts, PackCommitError> {
        let deadline = arm(deadline)?;
        let request = Request::check(plan, baseline, new_packs)?;
        let mut registered = Vec::with_capacity(request.old.len() + request.new.len());
        registered.extend(request.old.iter());
        registered.extend(request.new.iter());
        download::check_live_backend(&self.store, &registered)?;
        // View budget first, then the owned workspace, then native admission.
        let lease = VerificationLease::with_view_budget(acquire_view_budget(deadline).await?)?;
        let native = acquire_slot(deadline).await?;
        lease.admit_native(native);
        let view = NativeView::create(&self.git, Arc::clone(&lease), request.format)?;
        view.init(deadline).await?;
        check_workspace(&lease, deadline).await?;

        let mut indexed = BTreeSet::new();
        let mut objects = 0u64;
        let mut bytes = 0u64;
        for (index, pack) in request.old.iter().chain(request.new.iter()).enumerate() {
            let pair = pair_bytes(pack)?;
            bytes = bytes.checked_add(pair).ok_or_else(|| refuse("publication artifact bytes overflowed"))?;
            if bytes > VERIFIER_MAX_TOTAL_BYTES {
                return Err(refuse("publication facts exceed the verifier artifact-byte bound"));
            }
            preflight_workspace(&lease, pair.saturating_mul(2), deadline).await?;
            let download::PairInput { pack: pack_copy, idx, sha256, objects: declared } =
                download::fetch_pair(&self.store, pack, view.incoming(), index, &lease, deadline).await?;
            objects = objects.checked_add(declared).ok_or_else(|| refuse("publication object count overflowed"))?;
            if objects > VERIFIER_MAX_OBJECTS {
                return Err(refuse("publication facts exceed the verifier object bound"));
            }
            view.verify_registered_pair(&idx, deadline).await?;
            if indexed.insert(sha256) {
                preflight_workspace(&lease, pair, deadline).await?;
                view.index_pack(&pack_copy, deadline).await?;
            }
            check_workspace(&lease, deadline).await?;
        }
        view.check_pack_directory(indexed.len())?;

        // Attest the captured old refs inside the owned view. This is also the
        // "missing OLD captured closure" invariant: an incomplete old pack set
        // fails the whole operation here, before any selection.
        let old_map = old_ref_map(&request.old_refs, request.format)?;
        let old_head_oid = old_map.get(request.head_ref.as_str()).cloned();
        view.attest_refs(&request.head_ref, old_head_oid.as_deref(), &old_map, deadline).await?;

        let probe = super::probe::probe_refs(&view, request.plan, &old_map, lfs, &lease, deadline).await?;
        check_workspace(&lease, deadline).await?;

        let mut packs = Vec::with_capacity(registered.len());
        for pack in &registered {
            packs.push(VerifiedPackIdentity::new(
                pack.pack_id(),
                pack.registration_id(),
                pack.artifact_set_digest().digest().as_hex(),
                pack.artifact(PackArtifactRole::Pack).verified_sha256().as_str().to_owned(),
                pack.artifact(PackArtifactRole::Pack).verified_length(),
                pack.artifact(PackArtifactRole::Idx).verified_sha256().as_str().to_owned(),
                pack.artifact(PackArtifactRole::Idx).verified_length(),
            ));
        }
        let pairs = registered.len();
        // Every child spawned above is confirmed reaped by the runner. Native
        // capacity returns now; the workspace and view budget stay owned.
        lease.release_native();
        Ok(VerifiedPublicationFacts::mint(&request, probe, packs, pairs, bytes, lease))
    }
}

impl std::fmt::Debug for PublicationFactsEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PublicationFactsEngine").field("git", &"<configured>").finish_non_exhaustive()
    }
}

/// Pure, pre-IO validation of one plan/baseline/registration triple.
struct Request<'a> {
    plan: &'a PackCommitPlan,
    format: GitObjectFormat,
    old: &'a [RegisteredPack],
    new: Vec<RegisteredPack>,
    old_refs: Vec<CapturedRef>,
    head_ref: RefName,
    old_membership_digest: MembershipDigest,
    old_packs_digest: RequestDigest,
    new_packs_digest: RequestDigest,
    realm_digest: RequestDigest,
}

impl<'a> Request<'a> {
    fn check(
        plan: &'a PackCommitPlan,
        baseline: &'a PackCommitBaseline,
        new_packs: Vec<RegisteredPack>,
    ) -> Result<Self, PackCommitError> {
        if baseline.mode() != plan.expected().mode() {
            return Err(rejected(PackCommitRejectCode::ModeMismatch, "facts gate mode differs from the original plan"));
        }
        let gate = baseline.gate();
        if gate.repository_id() != plan.repository_id() || gate.tenant_id() != plan.tenant_id() {
            return Err(rejected(PackCommitRejectCode::TenantMismatch, "captured gate belongs to another scope"));
        }
        if gate.object_format() != plan.object_format() {
            return Err(rejected(PackCommitRejectCode::ObjectFormatMismatch, "captured gate uses another format"));
        }
        if gate.history_incarnation() != plan.history_incarnation()
            || gate.authority_epoch() != plan.authority_epoch()
            || gate.group_epoch() != plan.group_epoch()
        {
            return Err(rejected(PackCommitRejectCode::HistoryIncarnationMismatch, "captured gate epochs changed"));
        }
        if gate.revision() != plan.expected().revision() || gate.digest() != plan.expected().gate_digest() {
            return Err(rejected(PackCommitRejectCode::RevisionMismatch, "captured gate is not the planned one"));
        }
        if baseline.membership_digest() != plan.old_membership_digest() {
            return Err(rejected(PackCommitRejectCode::OldMembershipMismatch, "captured membership set changed"));
        }
        // The plan's captured membership entries must be exactly the baseline packs.
        let actual = membership_rows(baseline.old_packs())?;
        let planned = plan
            .old_memberships()
            .iter()
            .map(|entry| {
                (entry.pack_id(), (entry.registration_id(), entry.artifact_set_digest(), entry.joined_revision()))
            })
            .collect::<BTreeMap<_, _>>();
        if actual != planned {
            return Err(rejected(
                PackCommitRejectCode::OldMembershipMismatch,
                "planned membership is not the baseline",
            ));
        }
        let old = baseline.old_packs();
        if old.len() as i64 > MAX_ACTIVE_MEMBERSHIPS || new_packs.len() > MAX_BATCH_NEW_PACKS {
            return Err(refuse("publication facts exceed a fixed registered bound"));
        }
        if old.len().saturating_add(new_packs.len()) > VERIFIER_MAX_PAIRS {
            return Err(refuse("publication facts exceed the verifier pack-pair bound"));
        }
        if new_packs.len() != plan.packs().len() {
            return Err(rejected(PackCommitRejectCode::RegistrationMissing, "registrations are not the plan"));
        }
        for pack in &new_packs {
            let planned = plan
                .packs()
                .iter()
                .find(|planned| {
                    planned.pack_id() == pack.pack_id() && planned.registration_id() == pack.registration_id()
                })
                .ok_or_else(|| rejected(PackCommitRejectCode::RegistrationMissing, "unplanned pack registration"))?;
            for role in [PackArtifactRole::Pack, PackArtifactRole::Idx] {
                let artifact = pack.artifact(role);
                if artifact.locator().sha256() != planned.artifact(role).content()
                    || artifact.locator().length() != planned.artifact(role).length()
                {
                    return Err(rejected(PackCommitRejectCode::PublicationMismatch, "registered content differs"));
                }
            }
        }
        // CAS is deliberately NOT decided here: a caller's wrong old OID is a
        // per-ref CAS rejection in the selection (`Atomic` rolls the whole batch
        // to rejected). A missing ACTUAL captured old object stays a
        // whole-operation integrity failure, enforced by native ref attestation
        // and the probe below.
        let head_ref = gate.head_ref().clone();
        let realm_digest = RequestDigest::of(
            "core-publication-realm-v1",
            &[
                plan.repository_id().as_bytes(),
                plan.tenant_id().as_bytes(),
                plan.owner_id().as_bytes(),
                plan.object_format().as_str().as_bytes(),
                plan.history_incarnation().as_bytes(),
                &plan.authority_epoch().to_be_bytes(),
                &plan.group_epoch().to_be_bytes(),
            ],
        );
        let new_packs_digest = packs_digest(&new_packs);
        Ok(Self {
            plan,
            format: gate.object_format(),
            old,
            new: new_packs,
            old_refs: baseline.refs().to_vec(),
            head_ref,
            old_membership_digest: baseline.membership_digest(),
            old_packs_digest: packs_digest(old),
            new_packs_digest,
            realm_digest,
        })
    }
}
