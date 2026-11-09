//! Closure context: the immutable, same-revision state one proof must bind.
//!
//! The context is captured in its own short transaction after registration and
//! before any Blob/Git IO. It freezes the plan's parent digest, the expected
//! revision/digest/mode, the exact old refs/HEAD, the old membership digest, the
//! exact resulting refs/HEAD and the complete read-only registered pack data for
//! BOTH the old active memberships and the new planned registrations (role, hold
//! id, pair slot, full Blob locator, provider, backend identity, verified
//! digest/length of exactly one pack + one idx per pack). Nothing here grants
//! write authority: it is input to a native verifier, and the resulting
//! [`super::proof::PackClosureProof`] is the only value `commit_verified_pending`
//! accepts.
//!
//! Accepted-subset mode adds exactly one derived binding: the private
//! [`SelectedPackPlan`] selection digest and the exact accepted update subset. The
//! original whole-batch plan identity and parent digest stay unchanged; only the
//! *resulting ref map* is computed from the selected updates, and the context
//! digest for that path uses its own versioned domain. The atomic context digest
//! is byte-identical to before this change.
use super::artifact::{RegisteredPack, packs_digest};
use super::context::{CapturedRef, MembershipDigest, PackCommitBaseline, refs_digest};
use super::contract::PackArtifactRole;
use super::contract::PackMode;
use super::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use super::plan::PackCommitPlan;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::types::{HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate};
use std::collections::{BTreeMap, BTreeSet};

/// Selected-path binding carried by a subset closure context.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectionBinding {
    digest: RequestDigest,
    accepted: Vec<RefUpdate>,
}

/// Immutable closure context a proof must bind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackClosureContext {
    parent_digest: RequestDigest,
    expected_revision: i64,
    gate_digest: RequestDigest,
    mode: PackMode,
    head_ref: RefName,
    old_refs: Vec<CapturedRef>,
    old_membership_digest: MembershipDigest,
    old_packs: Vec<RegisteredPack>,
    resulting_refs: Vec<CapturedRef>,
    resulting_head: RefName,
    new_packs: Vec<RegisteredPack>,
    selection: Option<SelectionBinding>,
    digest: RequestDigest,
}

impl PackClosureContext {
    /// Builds the context from a complete same-revision capture plus the exact
    /// same-parent durable registrations. Every mismatch is a typed refusal and
    /// no value is produced.
    pub fn capture(
        plan: &PackCommitPlan,
        baseline: &PackCommitBaseline,
        mut new_packs: Vec<RegisteredPack>,
    ) -> Result<Self, PackCommitError> {
        let gate = check_gate(plan, baseline)?;
        let current = apply_updates(baseline.refs(), plan.refs(), plan.object_format())?;
        let resulting_head = result_head(gate.head_ref(), plan.head(), baseline.refs(), plan)?;
        let mut resulting_refs = Vec::with_capacity(current.len());
        for (name, oid) in &current {
            resulting_refs.push(CapturedRef::from_stored(plan.object_format(), name.clone(), oid.clone())?);
        }
        new_packs.sort_by_key(RegisteredPack::pack_id);
        ensure_exact_registrations(plan, &new_packs)?;
        let old_packs = baseline.old_packs().to_vec();
        let digest = context_digest(
            plan,
            gate.revision(),
            gate.digest(),
            baseline.mode(),
            gate.head_ref(),
            baseline.refs(),
            baseline.membership_digest(),
            &old_packs,
            &resulting_refs,
            &resulting_head,
            &new_packs,
        );
        Ok(Self {
            parent_digest: *plan.parent_digest(),
            expected_revision: gate.revision(),
            gate_digest: *gate.digest(),
            mode: baseline.mode(),
            head_ref: gate.head_ref().clone(),
            old_refs: baseline.refs().to_vec(),
            old_membership_digest: baseline.membership_digest(),
            old_packs,
            resulting_refs,
            resulting_head,
            new_packs,
            selection: None,
            digest,
        })
    }

    /// Accepted-subset variant of [`Self::capture`].
    ///
    /// The original plan (whole batch, original identity/parent digest) is NOT
    /// reduced: only the resulting ref map applies the selected accepted updates,
    /// and the context digest additionally binds the private selection digest and
    /// the exact accepted update set (`core-pack-closure-context-subset-v1`).
    ///
    /// `core::subset` wraps this primitive with the opaque `SelectedPackPlan`
    /// capability; this module deliberately does not know about that type, so the
    /// pack-commit slice stays independent of the selection module wiring.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture_selected_parts(
        original: &PackCommitPlan,
        selection_digest: &RequestDigest,
        accepted: &[RefUpdate],
        baseline: &PackCommitBaseline,
        mut new_packs: Vec<RegisteredPack>,
    ) -> Result<Self, PackCommitError> {
        let plan = original;
        let gate = check_gate(plan, baseline)?;
        let accepted = accepted.to_vec();
        ensure_accepted_subset(plan, &accepted)?;
        let current = apply_updates(baseline.refs(), &accepted, plan.object_format())?;
        let resulting_head = result_head_with(gate.head_ref(), plan.head(), baseline.refs(), &accepted)?;
        let mut resulting_refs = Vec::with_capacity(current.len());
        for (name, oid) in &current {
            resulting_refs.push(CapturedRef::from_stored(plan.object_format(), name.clone(), oid.clone())?);
        }
        new_packs.sort_by_key(RegisteredPack::pack_id);
        ensure_exact_registrations(plan, &new_packs)?;
        let old_packs = baseline.old_packs().to_vec();
        let digest = context_digest_selected(
            plan,
            gate.revision(),
            gate.digest(),
            baseline.mode(),
            gate.head_ref(),
            baseline.refs(),
            baseline.membership_digest(),
            &old_packs,
            &resulting_refs,
            &resulting_head,
            &new_packs,
            selection_digest,
            &accepted,
        );
        Ok(Self {
            parent_digest: *plan.parent_digest(),
            expected_revision: gate.revision(),
            gate_digest: *gate.digest(),
            mode: baseline.mode(),
            head_ref: gate.head_ref().clone(),
            old_refs: baseline.refs().to_vec(),
            old_membership_digest: baseline.membership_digest(),
            old_packs,
            resulting_refs,
            resulting_head,
            new_packs,
            selection: Some(SelectionBinding { digest: *selection_digest, accepted }),
            digest,
        })
    }

    pub fn parent_digest(&self) -> &RequestDigest {
        &self.parent_digest
    }
    pub fn expected_revision(&self) -> i64 {
        self.expected_revision
    }
    pub fn gate_digest(&self) -> &RequestDigest {
        &self.gate_digest
    }
    pub fn mode(&self) -> PackMode {
        self.mode
    }
    pub fn head_ref(&self) -> &RefName {
        &self.head_ref
    }
    pub fn old_refs(&self) -> &[CapturedRef] {
        &self.old_refs
    }
    pub fn old_membership_digest(&self) -> MembershipDigest {
        self.old_membership_digest
    }
    /// Complete old active memberships with full locator data.
    pub fn old_packs(&self) -> &[RegisteredPack] {
        &self.old_packs
    }
    pub fn resulting_refs(&self) -> &[CapturedRef] {
        &self.resulting_refs
    }
    pub fn resulting_head(&self) -> &RefName {
        &self.resulting_head
    }
    /// Complete newly registered packs with full locator data.
    pub fn new_packs(&self) -> &[RegisteredPack] {
        &self.new_packs
    }
    /// `None` for the unchanged atomic path; `Some(selection_digest)` for an
    /// accepted-subset closure.
    pub fn selection_digest(&self) -> Option<&RequestDigest> {
        self.selection.as_ref().map(|selection| &selection.digest)
    }
    /// Exact accepted update subset (original plan order), or `None` for atomic.
    pub fn accepted(&self) -> Option<&[RefUpdate]> {
        self.selection.as_ref().map(|selection| selection.accepted.as_slice())
    }
    pub fn digest(&self) -> &RequestDigest {
        &self.digest
    }
}

fn reject(code: PackCommitRejectCode, detail: &'static str) -> PackCommitError {
    PackCommitError::Rejected(PackCommitRejection::new(code, detail))
}

/// Gate/scope/revision/mode/membership agreement shared by both capture paths.
fn check_gate<'a>(
    plan: &'a PackCommitPlan,
    baseline: &'a PackCommitBaseline,
) -> Result<&'a crate::ref_store::core::contract::CoreGateVersion, PackCommitError> {
    let gate = baseline.gate();
    if gate.repository_id() != plan.repository_id() || gate.tenant_id() != plan.tenant_id() {
        return Err(reject(PackCommitRejectCode::TenantMismatch, "captured gate belongs to another scope"));
    }
    if gate.object_format() != plan.object_format() {
        return Err(reject(PackCommitRejectCode::ObjectFormatMismatch, "captured gate uses another object format"));
    }
    if gate.history_incarnation() != plan.history_incarnation()
        || gate.authority_epoch() != plan.authority_epoch()
        || gate.group_epoch() != plan.group_epoch()
    {
        return Err(reject(PackCommitRejectCode::HistoryIncarnationMismatch, "captured gate epochs changed"));
    }
    if gate.revision() != plan.expected().revision() || gate.digest() != plan.expected().gate_digest() {
        return Err(reject(PackCommitRejectCode::RevisionMismatch, "captured revision/digest is not the planned one"));
    }
    if baseline.mode() != plan.expected().mode() {
        return Err(reject(PackCommitRejectCode::ModeMismatch, "captured pack mode is not the planned one"));
    }
    if baseline.membership_digest() != plan.old_membership_digest() {
        return Err(reject(PackCommitRejectCode::OldMembershipMismatch, "captured membership set changed"));
    }
    Ok(gate)
}

/// Apply one update set to the captured old refs, enforcing every precondition.
fn apply_updates(
    old_refs: &[CapturedRef],
    updates: &[RefUpdate],
    format: crate::ref_store::core::types::GitObjectFormat,
) -> Result<BTreeMap<String, String>, PackCommitError> {
    let mut current: BTreeMap<String, String> =
        old_refs.iter().map(|reference| (reference.name().to_owned(), reference.oid_hex().to_owned())).collect();
    for update in updates {
        if let RefPrecondition::Present(oid) = update.precondition()
            && oid.format() != format
        {
            return Err(reject(PackCommitRejectCode::ObjectFormatMismatch, "planned old oid uses another format"));
        }
        let actual = current.get(update.name().as_str()).cloned();
        let matches = match update.precondition() {
            RefPrecondition::Absent => actual.is_none(),
            RefPrecondition::Present(expected) => actual.as_deref() == Some(expected.as_hex().as_str()),
        };
        if !matches {
            return Err(reject(
                PackCommitRejectCode::OldOidMismatch,
                "captured old object id does not satisfy the plan",
            ));
        }
        match update.target() {
            RefTarget::Delete => {
                current.remove(update.name().as_str());
            }
            RefTarget::Oid(oid) => {
                current.insert(update.name().as_str().to_owned(), oid.as_hex());
            }
        }
    }
    Ok(current)
}

/// The exact planned pack/registration ids, and each planned content digest and
/// length, must equal the durable registered artifacts of this context.
fn ensure_exact_registrations(plan: &PackCommitPlan, new_packs: &[RegisteredPack]) -> Result<(), PackCommitError> {
    let planned = plan.packs().iter().map(|pack| (pack.pack_id(), pack.registration_id())).collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for pack in new_packs {
        if !planned.contains(&(pack.pack_id(), pack.registration_id())) || !seen.insert(pack.pack_id()) {
            return Err(reject(PackCommitRejectCode::RegistrationMissing, "registrations are not exactly the plan"));
        }
        let planned_pack = plan
            .packs()
            .iter()
            .find(|planned| planned.pack_id() == pack.pack_id())
            .ok_or_else(|| reject(PackCommitRejectCode::RegistrationMissing, "unplanned pack registration"))?;
        for role in [PackArtifactRole::Pack, PackArtifactRole::Idx] {
            let artifact = pack.artifact(role);
            let planned_artifact = planned_pack.artifact(role);
            if artifact.locator().sha256() != planned_artifact.content()
                || artifact.locator().length() != planned_artifact.length()
            {
                return Err(reject(PackCommitRejectCode::PublicationMismatch, "registered artifact content differs"));
            }
        }
    }
    if seen.len() != planned.len() {
        return Err(reject(PackCommitRejectCode::RegistrationMissing, "a planned pack has no durable registration"));
    }
    Ok(())
}

/// Every accepted update must be one exact plan update, named once.
fn ensure_accepted_subset(plan: &PackCommitPlan, accepted: &[RefUpdate]) -> Result<(), PackCommitError> {
    let mut names = BTreeSet::new();
    for update in accepted {
        if !plan.refs().iter().any(|planned| planned == update) {
            return Err(reject(
                PackCommitRejectCode::ContextMismatch,
                "accepted update is not an original plan update",
            ));
        }
        if !names.insert(update.name().as_str()) {
            return Err(reject(PackCommitRejectCode::ContextMismatch, "accepted set repeats a ref name"));
        }
    }
    Ok(())
}

/// Pure resulting-HEAD helper for the complete plan batch (atomic path).
pub(crate) fn result_head(
    current_head: &RefName,
    head: &HeadUpdate,
    old_refs: &[CapturedRef],
    plan: &PackCommitPlan,
) -> Result<RefName, PackCommitError> {
    result_head_with(current_head, head, old_refs, plan.refs())
}

/// Pure resulting-HEAD helper for one update subset (atomic or selected).
pub(crate) fn result_head_with(
    current_head: &RefName,
    head: &HeadUpdate,
    old_refs: &[CapturedRef],
    updates: &[RefUpdate],
) -> Result<RefName, PackCommitError> {
    let mut current: BTreeMap<String, String> =
        old_refs.iter().map(|reference| (reference.name().to_owned(), reference.oid_hex().to_owned())).collect();
    for update in updates {
        match update.target() {
            RefTarget::Delete => {
                current.remove(update.name().as_str());
            }
            RefTarget::Oid(oid) => {
                current.insert(update.name().as_str().to_owned(), oid.as_hex());
            }
        }
    }
    let resolved = crate::ref_store::core::types::resolve_head(current_head.as_str(), &current, updates, head)
        .map_err(|_| reject(PackCommitRejectCode::HeadTargetMissing, "resulting HEAD is not a live branch"))?;
    RefName::new(resolved).map_err(|_| reject(PackCommitRejectCode::HeadTargetMissing, "resulting HEAD is invalid"))
}

#[allow(clippy::too_many_arguments)]
fn context_digest(
    plan: &PackCommitPlan,
    revision: i64,
    gate_digest: &RequestDigest,
    mode: PackMode,
    head_ref: &RefName,
    old_refs: &[CapturedRef],
    old_membership: MembershipDigest,
    old_packs: &[RegisteredPack],
    resulting_refs: &[CapturedRef],
    resulting_head: &RefName,
    new_packs: &[RegisteredPack],
) -> RequestDigest {
    let mut fields: Vec<Vec<u8>> = vec![
        plan.parent_digest().as_bytes().to_vec(),
        revision.to_be_bytes().to_vec(),
        gate_digest.as_bytes().to_vec(),
        mode.as_str().as_bytes().to_vec(),
        head_ref.as_str().as_bytes().to_vec(),
        refs_digest(old_refs).as_bytes().to_vec(),
        old_membership.digest().as_bytes().to_vec(),
        packs_digest(old_packs).as_bytes().to_vec(),
        refs_digest(resulting_refs).as_bytes().to_vec(),
        resulting_head.as_str().as_bytes().to_vec(),
        packs_digest(new_packs).as_bytes().to_vec(),
    ];
    for pack in new_packs {
        fields.push(pack.registration_id().as_bytes().to_vec());
        fields.push(pack.artifact_set_digest().digest().as_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-pack-closure-context-v2", &parts)
}

/// Subset closure-context digest: the same complete closure binding plus the
/// private selection digest and the exact accepted update subset.
#[allow(clippy::too_many_arguments)]
fn context_digest_selected(
    plan: &PackCommitPlan,
    revision: i64,
    gate_digest: &RequestDigest,
    mode: PackMode,
    head_ref: &RefName,
    old_refs: &[CapturedRef],
    old_membership: MembershipDigest,
    old_packs: &[RegisteredPack],
    resulting_refs: &[CapturedRef],
    resulting_head: &RefName,
    new_packs: &[RegisteredPack],
    selection_digest: &RequestDigest,
    accepted: &[RefUpdate],
) -> RequestDigest {
    let mut fields: Vec<Vec<u8>> = vec![
        plan.parent_digest().as_bytes().to_vec(),
        revision.to_be_bytes().to_vec(),
        gate_digest.as_bytes().to_vec(),
        mode.as_str().as_bytes().to_vec(),
        head_ref.as_str().as_bytes().to_vec(),
        refs_digest(old_refs).as_bytes().to_vec(),
        old_membership.digest().as_bytes().to_vec(),
        packs_digest(old_packs).as_bytes().to_vec(),
        refs_digest(resulting_refs).as_bytes().to_vec(),
        resulting_head.as_str().as_bytes().to_vec(),
        packs_digest(new_packs).as_bytes().to_vec(),
        selection_digest.as_bytes().to_vec(),
        (accepted.len() as u64).to_be_bytes().to_vec(),
    ];
    for update in accepted {
        fields.push(update.name().as_str().as_bytes().to_vec());
        fields.push(update.precondition().canonical_tag().as_bytes().to_vec());
        fields.push(update.precondition().oid().map(|oid| oid.as_hex()).unwrap_or_default().into_bytes());
        fields.push(update.target().canonical_tag().as_bytes().to_vec());
        fields.push(update.target().oid().map(|oid| oid.as_hex()).unwrap_or_default().into_bytes());
    }
    for pack in new_packs {
        fields.push(pack.registration_id().as_bytes().to_vec());
        fields.push(pack.artifact_set_digest().digest().as_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-pack-closure-context-subset-v1", &parts)
}
