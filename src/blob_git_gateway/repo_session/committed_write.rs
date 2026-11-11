//! Opaque admission ticket for a committed push (#174).
use crate::ref_store::{core::pack_commit::PackCommitTerminal, serving::ServingRepository};

use super::SessionTokenError;
use super::realm::SessionRealm;

/// Opaque admission ticket for a committed push: the only input
/// [`super::SessionTokens::issue_from_committed_write`] accepts.
///
/// It is produced only by [`CommittedWriteSessionProof::new`], which validates
/// a durable committed `PackCommitTerminal` against two real writable serving
/// lookups. It has private fields, no public constructor, no `Clone`, no
/// `Serialize` and no way back to a bare revision or realm, so no caller can
/// relabel a token onto another incarnation/revision or reuse one admission.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CommittedWriteSessionProof {
    pub(super) realm: SessionRealm,
    /// The exact durable gate revision of the committed terminal; it is the
    /// signed lower bound and is never the final live revision.
    pub(super) revision: i64,
}

impl CommittedWriteSessionProof {
    /// Admit one committed push terminal.
    ///
    /// * `terminal` must be a committed (`is_committed()`) durable terminal of
    ///   the push being answered; its revision is the exact lower bound and
    ///   must be positive and not ahead of the final lookup's gate.
    /// * `authorized` is the writable lookup that authorized the request
    ///   before the body/native/Blob stages; `final_lookup` is the fresh
    ///   writable lookup taken after the complete response body was encoded
    ///   and after the durable commit.
    /// * The terminal repository must equal each lookup's repository row id
    ///   and each lookup's gate repository id, and both lookups must state the
    ///   identical full realm (tenant, repository, object format, history
    ///   incarnation, authority kind and epochs, group id and epoch, and
    ///   cluster authority incarnation), so a restore between the two lookups
    ///   can never relabel the terminal revision into a new incarnation.
    ///
    /// A higher final gate revision in the same realm is acceptable. The
    /// refusal is the privacy-safe [`SessionTokenError`]; nothing divergent is
    /// named.
    pub(crate) fn new(
        terminal: &PackCommitTerminal,
        authorized: &ServingRepository,
        final_lookup: &ServingRepository,
    ) -> Result<Self, SessionTokenError> {
        if !terminal.is_committed() || terminal.revision <= 0 || terminal.revision > final_lookup.gate.revision() {
            return Err(SessionTokenError::Invalid);
        }
        let repository_id = terminal.repository_id;
        for serving in [authorized, final_lookup] {
            if repository_id != serving.repository.id || repository_id != serving.gate.repository_id() {
                return Err(SessionTokenError::Realm);
            }
        }
        let realm = SessionRealm::from_serving(final_lookup, final_lookup.cluster_incarnation)?;
        if realm != SessionRealm::from_serving(authorized, authorized.cluster_incarnation)? {
            return Err(SessionTokenError::Realm);
        }
        Ok(Self { realm, revision: terminal.revision })
    }
}
