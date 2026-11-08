//! A non-forgeable witness that one native publication never touched a ref.
//!
//! Reconciliation may only mint this after deriving `no_ref_changes` from the
//! operation's own finished and quiescent journal: the managed
//! reference-transaction hook cannot perform its native CAS without a parent
//! publication grant, so an absent grant marker plus empty events/receipt/
//! request proves the child was stopped before any ref update. HTTP bodies,
//! request JSON and database rows can never construct this value, and
//! settlement still re-checks the writer, repository, actor, token, generation
//! and shard epoch it is bound to.
//!
//! The witness also pins the immutable audit identity of the operation
//! (`actor_name`, `sequence`) and requires that the journal carries no CI
//! service principal and no maintenance pin, so a proof minted for one record
//! can never be replayed onto a different audit row of the same refs.
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct NoGrantAbort {
    operation_id: Uuid,
    repository_id: Uuid,
    actor_id: Uuid,
    actor_name: String,
    token_id: Uuid,
    sequence: i64,
    storage_generation: i64,
    shard_epoch: i64,
}

impl NoGrantAbort {
    /// Re-derives every condition from the on-disk journal of `operation`.
    /// `outcome` must be the exact terminal outcome reconciliation computed for
    /// that same journal; anything else (recorded/unknown, another generation,
    /// a live or unfinished journal, any hook evidence or a grant marker)
    /// yields no proof, so settlement keeps verifying authority.
    ///
    /// The liveness lock is checked here, not by the caller: a journal whose
    /// active guard is still held may acquire admission and run the native hook
    /// after any caller-side observation, so `finished` metadata alone is not
    /// quiescence.
    pub(crate) fn from_journal(operation: &crate::journal::Operation, outcome: &str) -> Option<Self> {
        if outcome != "no_ref_changes"
            || !operation.requires_parent_publication
            || operation.id.is_nil()
            || operation.repository_id.is_nil()
            || operation.actor_id.is_nil()
            || operation.token_id.is_nil()
            || operation.storage_generation <= 0
            || operation.shard_epoch <= 0
            // Only a human journal can be proven ungranted here: a CI service
            // principal or a maintenance pin carries its own authority path
            // that this witness never describes.
            || operation.service_principal_id.is_some()
            || operation.ci_pin.is_some()
        {
            return None;
        }
        if crate::journal::ActiveGuard::operation_is_live(operation).ok()? {
            return None;
        }
        if !crate::journal::is_finished(operation).ok()? {
            return None;
        }
        if !crate::journal::events(operation).ok()?.is_empty()
            || crate::journal::receipts(operation).ok()?.is_some()
            || crate::journal::requests(operation).ok()?.is_some()
        {
            return None;
        }
        // Only definite absence of the grant is evidence; any other I/O state
        // (present marker, symlink, permission error) keeps the authority check.
        match std::fs::symlink_metadata(operation.path.join("publication.grant")) {
            Err(ref error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return None,
        }
        Some(Self {
            operation_id: operation.id,
            repository_id: operation.repository_id,
            actor_id: operation.actor_id,
            actor_name: operation.actor_name.clone(),
            token_id: operation.token_id,
            sequence: operation.sequence,
            storage_generation: operation.storage_generation,
            shard_epoch: operation.shard_epoch,
        })
    }

    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// The proof must describe exactly the record being published, including
    /// the immutable audit identity (`actor_name`, `sequence`) and the
    /// admission identity the transaction will settle. A service-principal
    /// record is never the record this witness was minted for.
    pub fn matches_operation(&self, operation: &crate::events::OperationRecord) -> bool {
        self.operation_id == operation.id
            && self.repository_id == operation.repository_id
            && self.actor_id == operation.actor_id
            && self.actor_name == operation.actor_name
            && self.token_id == operation.token_id
            && self.sequence == operation.sequence
            && self.storage_generation == operation.storage_generation
            && operation.service_principal_id.is_none()
            && operation.admission.as_ref().is_some_and(|admission| {
                admission.writer_id == self.operation_id && admission.shard_epoch == self.shard_epoch
            })
    }

    /// Settlement-side identity check inside the publishing transaction.
    pub fn matches_admission(
        &self,
        repository_id: Uuid,
        admission: &crate::events::AdmissionRecord,
        actor_id: Uuid,
        token_id: Uuid,
    ) -> bool {
        admission.writer_id == self.operation_id
            && admission.shard_epoch == self.shard_epoch
            && repository_id == self.repository_id
            && actor_id == self.actor_id
            && token_id == self.token_id
    }
}

#[cfg(test)]
mod tests {
    use super::NoGrantAbort;
    use crate::events::{AdmissionRecord, OperationRecord};
    use crate::journal::{self, ActiveGuard, Operation, RefChange};
    use uuid::Uuid;

    /// Real persisted journal metadata from the production constructor.
    fn live_journal() -> (tempfile::TempDir, Operation, ActiveGuard) {
        let root = tempfile::tempdir().unwrap();
        let (operation, active) = journal::begin_active_with(
            root.path(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "actor".into(),
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            7,
        )
        .unwrap();
        (root, operation, active)
    }

    fn finished_journal() -> (tempfile::TempDir, Operation) {
        let (root, operation, active) = live_journal();
        drop(active);
        journal::finish(&operation).unwrap();
        (root, operation)
    }

    fn change() -> RefChange {
        RefChange { old_oid: "0".repeat(40), new_oid: "a".repeat(40), ref_name: "refs/heads/main".into() }
    }

    fn record(operation: &Operation) -> OperationRecord {
        OperationRecord {
            id: operation.id,
            repository_id: operation.repository_id,
            actor_id: operation.actor_id,
            token_id: operation.token_id,
            service_principal_id: None,
            actor_name: operation.actor_name.clone(),
            sequence: operation.sequence,
            storage_generation: operation.storage_generation,
            outcome: "no_ref_changes".into(),
            evidence: serde_json::json!({"version":1,"ungranted_without_hooks":true}),
            admission: Some(AdmissionRecord { writer_id: operation.id, shard_epoch: operation.shard_epoch }),
        }
    }

    #[test]
    fn live_operation_never_mints_a_proof() {
        let (_root, operation, active) = live_journal();
        // Terminal metadata written by another path must not outrun the child.
        journal::finish(&operation).unwrap();
        assert!(ActiveGuard::operation_is_live(&operation).unwrap(), "guard must hold the liveness lock");
        assert!(
            NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none(),
            "a live operation could still acquire admission and run the hook"
        );
        drop(active);
        assert!(
            NoGrantAbort::from_journal(&operation, "no_ref_changes").is_some(),
            "quiescent finished journal must mint the proof"
        );
    }

    #[test]
    fn unfinished_journal_is_not_a_proof() {
        let (_root, operation, active) = live_journal();
        drop(active);
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none());
        journal::finish(&operation).unwrap();
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_some());
    }

    #[test]
    fn only_a_clean_finished_journal_is_a_proof() {
        let (_root, operation) = finished_journal();
        assert!(NoGrantAbort::from_journal(&operation, "recorded").is_none());
        assert!(NoGrantAbort::from_journal(&operation, "unknown").is_none());
        let proof = NoGrantAbort::from_journal(&operation, "no_ref_changes").expect("clean journal proof");
        assert_eq!(proof.operation_id(), operation.id);

        // A whole-push admission request proves validation only; native CAS can
        // still follow it, so it removes the proof.
        let request = operation.path.join("pre-receive.json");
        std::fs::write(&request, serde_json::to_vec(&vec![change()]).unwrap()).unwrap();
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none());
        std::fs::remove_file(&request).unwrap();

        // A post-receive receipt is direct evidence that refs changed.
        let receipt = operation.path.join("post-receive.json");
        std::fs::write(&receipt, serde_json::to_vec(&vec![change()]).unwrap()).unwrap();
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none());
        std::fs::remove_file(&receipt).unwrap();

        // Unreadable or invalid hook evidence is never treated as absence.
        std::fs::write(operation.path.join("00000000000000000001.event.json"), b"not an event").unwrap();
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none());
    }

    #[test]
    fn a_real_grant_marker_is_never_a_proof() {
        let (_root, operation) = finished_journal();
        let marker = operation.path.join("publication.grant");
        std::fs::write(&marker, b"granted").unwrap();
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none());
        std::fs::remove_file(&marker).unwrap();
        std::os::unix::fs::symlink("missing", &marker).unwrap();
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none());
    }

    #[test]
    fn a_service_principal_journal_never_mints_a_proof() {
        let (_root, mut operation) = finished_journal();
        operation.service_principal_id = Some(Uuid::new_v4());
        assert!(
            NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none(),
            "a CI service principal carries authority this witness does not describe"
        );
        // Control: the same journal mints the proof once the service identity
        // is gone, so the rejection above is not a side effect of any other
        // condition.
        operation.service_principal_id = None;
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_some());
    }

    #[test]
    fn proof_matches_exactly_one_operation_record() {
        let (_root, operation) = finished_journal();
        let proof = NoGrantAbort::from_journal(&operation, "no_ref_changes").expect("clean journal proof");
        let good = record(&operation);
        assert!(proof.matches_operation(&good), "the derived record must bind to its proof");

        let differ = |mutate: &dyn Fn(&mut OperationRecord)| {
            let mut altered = good.clone();
            mutate(&mut altered);
            assert!(!proof.matches_operation(&altered));
        };
        differ(&|r| r.id = Uuid::new_v4());
        differ(&|r| r.repository_id = Uuid::new_v4());
        differ(&|r| r.actor_id = Uuid::new_v4());
        differ(&|r| r.actor_name = "someone-else".into());
        differ(&|r| r.token_id = Uuid::new_v4());
        differ(&|r| r.sequence += 1);
        differ(&|r| r.storage_generation += 1);
        differ(&|r| r.service_principal_id = Some(Uuid::new_v4()));
        differ(&|r| r.admission.as_mut().unwrap().shard_epoch += 1);
        differ(&|r| r.admission.as_mut().unwrap().writer_id = Uuid::new_v4());
        differ(&|r| r.admission = None);

        let admission = good.admission.as_ref().unwrap();
        assert!(proof.matches_admission(good.repository_id, admission, good.actor_id, good.token_id));
        assert!(!proof.matches_admission(Uuid::new_v4(), admission, good.actor_id, good.token_id));
        assert!(!proof.matches_admission(good.repository_id, admission, Uuid::new_v4(), good.token_id));
        assert!(!proof.matches_admission(good.repository_id, admission, good.actor_id, Uuid::new_v4()));
        let other_epoch = AdmissionRecord { writer_id: admission.writer_id, shard_epoch: admission.shard_epoch + 1 };
        assert!(!proof.matches_admission(good.repository_id, &other_epoch, good.actor_id, good.token_id));
    }
}
