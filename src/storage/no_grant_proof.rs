//! A non-forgeable witness that one native publication never touched a ref.
//!
//! Reconciliation may only mint this after deriving `no_ref_changes` from the
//! operation's own finished journal: the managed reference-transaction hook
//! cannot perform its native CAS without a parent publication grant, so an
//! absent grant marker plus empty events/receipt/request proves the child was
//! stopped before any ref update. HTTP bodies, request JSON and database rows
//! can never construct this value, and settlement still re-checks the writer,
//! repository, actor, token, generation and shard epoch it is bound to.
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub struct NoGrantAbort {
    operation_id: Uuid,
    repository_id: Uuid,
    actor_id: Uuid,
    token_id: Uuid,
    storage_generation: i64,
    shard_epoch: i64,
}

impl NoGrantAbort {
    /// Re-derives every condition from the on-disk journal of `operation`.
    /// `outcome` must be the exact terminal outcome reconciliation computed for
    /// that same journal; anything else (recorded/unknown, another generation,
    /// a live or interrupted journal, any hook evidence or a grant marker)
    /// yields no proof, so settlement keeps verifying authority.
    pub fn from_journal(operation: &crate::journal::Operation, outcome: &str) -> Option<Self> {
        if outcome != "no_ref_changes"
            || !operation.requires_parent_publication
            || operation.id.is_nil()
            || operation.repository_id.is_nil()
            || operation.actor_id.is_nil()
            || operation.token_id.is_nil()
            || operation.storage_generation <= 0
            || operation.shard_epoch <= 0
        {
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
            token_id: operation.token_id,
            storage_generation: operation.storage_generation,
            shard_epoch: operation.shard_epoch,
        })
    }

    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// The proof must describe exactly the record being published, including
    /// the admission identity the transaction will settle.
    pub fn matches_operation(&self, operation: &crate::events::OperationRecord) -> bool {
        self.operation_id == operation.id
            && self.repository_id == operation.repository_id
            && self.actor_id == operation.actor_id
            && self.token_id == operation.token_id
            && self.storage_generation == operation.storage_generation
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
    use uuid::Uuid;

    fn finished_journal() -> (tempfile::TempDir, crate::journal::Operation) {
        let root = tempfile::tempdir().unwrap();
        let (mut operation, active) = crate::journal::begin_active(
            root.path(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "actor".into(),
            Uuid::new_v4(),
            1,
        )
        .unwrap();
        drop(active);
        operation.requires_parent_publication = true;
        operation.shard_epoch = 7;
        crate::journal::finish(&operation).unwrap();
        (root, operation)
    }

    #[test]
    fn proof_needs_finished_ungranted_no_ref_change_journal() {
        let (_root, operation) = finished_journal();
        // A different terminal outcome never mints a proof, even with a clean journal.
        assert!(NoGrantAbort::from_journal(&operation, "recorded").is_none());
        assert!(NoGrantAbort::from_journal(&operation, "unknown").is_none());
        let proof = NoGrantAbort::from_journal(&operation, "no_ref_changes").expect("clean journal proof");
        assert_eq!(proof.operation_id(), operation.id);
        // Any real grant marker means the hook could have run: no proof.
        let marker = operation.path.join("publication.grant");
        std::fs::write(&marker, b"granted").unwrap();
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none());
        std::fs::remove_file(&marker).unwrap();
        std::os::unix::fs::symlink("missing", &marker).unwrap();
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none());
    }

    #[test]
    fn proof_requires_parent_publication_and_a_non_live_journal() {
        let (_root, mut operation) = finished_journal();
        operation.requires_parent_publication = false;
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none());
        operation.requires_parent_publication = true;
        operation.shard_epoch = 0;
        assert!(NoGrantAbort::from_journal(&operation, "no_ref_changes").is_none());
    }
}
