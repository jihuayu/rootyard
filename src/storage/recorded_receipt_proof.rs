//! A non-forgeable witness that one operation's refs were already committed by
//! native Git before SQL settlement.
//!
//! Issue #96: after a crash between native Git publication and PostgreSQL
//! settlement, reconciliation holds a real `post-receive.json` receipt and
//! committed `reference-transaction` events for refs that are already part of
//! the durable journal. Re-running the *current* token/RBAC/`ready` check then
//! fails when the repository is temporarily `recovering` or the token was
//! revoked after the push, stranding a fact Git already committed.
//!
//! Only this capability may skip that current-authority recheck, and only to
//! project the past, already-committed transaction. It never authorizes new
//! refs. HTTP bodies, request JSON and database rows can never construct it:
//! the constructor re-reads the real journal and requires a quiescent,
//! finished, parent-publication operation with a valid 32-byte parent grant
//! marker, a unique successful post-receive receipt, a matching pre-receive
//! request and committed reference events that agree with both. Settlement
//! additionally binds it to the exact operation record (including sequence and
//! actor name, with no service principal), the complete admitted ref-name set
//! and the database actor/token identity.
use std::collections::BTreeSet;

use uuid::Uuid;

use crate::{events, journal};

#[derive(Clone, Debug)]
pub struct RecordedReceiptProof {
    operation_id: Uuid,
    repository_id: Uuid,
    actor_id: Uuid,
    actor_name: String,
    token_id: Uuid,
    sequence: i64,
    storage_generation: i64,
    shard_epoch: i64,
    requested_refs: Vec<String>,
    changes: Vec<events::RefEventInput>,
}

fn request_contains(request: &[journal::RefChange], change: &journal::RefChange) -> bool {
    request.iter().any(|item| {
        item.ref_name == change.ref_name && item.old_oid == change.old_oid && item.new_oid == change.new_oid
    })
}

impl RecordedReceiptProof {
    /// Re-derives every condition from `operation`'s own on-disk journal.
    ///
    /// `outcome` must be the exact terminal outcome reconciliation computed for
    /// this journal and `generation` the repository generation it reconciled
    /// against. Anything weaker than a quiescent, finished native transaction
    /// with a valid parent grant marker, matching request, successful receipt
    /// and committed hook set yields no proof, so settlement keeps verifying
    /// current authority.
    pub(crate) fn from_journal(operation: &journal::Operation, outcome: &str, generation: i64) -> Option<Self> {
        if outcome != "recorded"
            || generation <= 0
            || operation.storage_generation != generation
            || !operation.requires_parent_publication
            || operation.shard_epoch <= 0
            || operation.sequence <= 0
            || operation.actor_name.is_empty()
            || operation.id.is_nil()
            || operation.repository_id.is_nil()
            || operation.actor_id.is_nil()
            || operation.token_id.is_nil()
            || operation.ci_pin.is_some()
            || operation.service_principal_id.is_some()
        {
            return None;
        }
        // A still-live child could acquire admission and run the native hook
        // after any caller-side observation; terminal metadata alone is not
        // quiescence.
        if journal::ActiveGuard::operation_is_live(operation).ok()? {
            return None;
        }
        if !journal::is_finished(operation).ok()? {
            return None;
        }
        // The parent's 32-byte grant marker is the only proof that the managed
        // hook could publish. Read it with the journal's no-symlink/regular
        // file convention; a missing, malformed or unsafe marker never mints
        // this capability.
        if journal::read(&operation.path.join("publication.grant")).ok()?.len() != 32 {
            return None;
        }
        // A whole-push admission request proves the exact ref set native Git
        // was allowed to update.
        let requested = journal::requests(operation).ok()??;
        if requested.is_empty() {
            return None;
        }
        // Git post-receive's successful subset; may be a strict subset for a
        // non-atomic push, but it is never empty for a recorded operation.
        let receipt = journal::receipts(operation).ok()??;
        if receipt.is_empty() || receipt.iter().any(|change| !change.ref_name.starts_with("refs/")) {
            return None;
        }
        let mut receipt_names = BTreeSet::new();
        for change in &receipt {
            if !receipt_names.insert(change.ref_name.as_str()) {
                return None;
            }
            // A receipt must not invent a ref, OID or direction that the
            // admitted request never contained.
            if !request_contains(&requested, change) {
                return None;
            }
        }
        // Committed reference-transaction events are the hook's authoritative
        // record of what native Git actually updated. The receipt must be
        // exactly their `refs/*` union (nested transactions split the set).
        let events = journal::events(operation).ok()?;
        let mut committed = BTreeSet::new();
        let mut saw_committed = false;
        for event in events.iter().filter(|event| event.phase == journal::HookPhase::Committed) {
            saw_committed = true;
            for change in &event.changes {
                if !change.ref_name.starts_with("refs/") {
                    continue;
                }
                if !request_contains(&requested, change) {
                    return None;
                }
                committed.insert((change.ref_name.clone(), change.old_oid.clone(), change.new_oid.clone()));
            }
        }
        if !saw_committed {
            return None;
        }
        let receipt_set = receipt
            .iter()
            .map(|change| (change.ref_name.clone(), change.old_oid.clone(), change.new_oid.clone()))
            .collect::<BTreeSet<_>>();
        if committed != receipt_set {
            return None;
        }
        let changes = receipt
            .iter()
            .enumerate()
            .map(|(index, item)| events::RefEventInput {
                transaction_sequence: index as i64 + 1,
                ref_name: item.ref_name.clone(),
                old_oid: item.old_oid.clone(),
                new_oid: item.new_oid.clone(),
            })
            .collect::<Vec<_>>();
        let mut requested_refs = requested.iter().map(|item| item.ref_name.clone()).collect::<Vec<_>>();
        requested_refs.sort();
        Some(Self {
            operation_id: operation.id,
            repository_id: operation.repository_id,
            actor_id: operation.actor_id,
            actor_name: operation.actor_name.clone(),
            token_id: operation.token_id,
            sequence: operation.sequence,
            storage_generation: operation.storage_generation,
            shard_epoch: operation.shard_epoch,
            requested_refs,
            changes,
        })
    }

    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub fn storage_generation(&self) -> i64 {
        self.storage_generation
    }

    /// The proof must describe exactly the record being published, including
    /// the admission identity the transaction will settle and the exact event
    /// payload derived from the receipt.
    pub fn matches_record(&self, operation: &events::OperationRecord, changes: &[events::RefEventInput]) -> bool {
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
            && self.changes.len() == changes.len()
            && self.changes.iter().zip(changes).all(|(proof, given)| {
                proof.transaction_sequence == given.transaction_sequence
                    && proof.ref_name == given.ref_name
                    && proof.old_oid == given.old_oid
                    && proof.new_oid == given.new_oid
            })
    }

    /// Settlement-side identity check inside the publishing transaction. Every
    /// value comes from the journal proof or from rows the transaction itself
    /// re-reads; a proof for another operation, actor, token, generation,
    /// epoch, repository or admitted ref set cannot settle.
    #[allow(clippy::too_many_arguments)]
    pub fn matches_admission(
        &self,
        repository_id: Uuid,
        storage_generation: i64,
        admission: &events::AdmissionRecord,
        actor_id: Uuid,
        token_id: Uuid,
        database_actor_id: Uuid,
        database_token_id: Uuid,
        database_refs: &[String],
    ) -> bool {
        admission.writer_id == self.operation_id
            && admission.shard_epoch == self.shard_epoch
            && repository_id == self.repository_id
            && storage_generation == self.storage_generation
            && actor_id == self.actor_id
            && token_id == self.token_id
            && database_actor_id == self.actor_id
            && database_token_id == self.token_id
            && database_refs == self.requested_refs.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::RecordedReceiptProof;
    use crate::{events, journal};
    use uuid::Uuid;

    fn journal_operation(root: &std::path::Path, writer: Uuid) -> journal::Operation {
        let (operation, active) = journal::begin_active_with(
            root,
            Uuid::new_v4(),
            Uuid::new_v4(),
            "alice".into(),
            Uuid::new_v4(),
            1,
            writer,
            7,
        )
        .unwrap();
        drop(active);
        operation
    }

    const GRANT: [u8; 32] = *b"rootyard-publication-grant-32byt";

    fn grant(operation: &journal::Operation) {
        std::fs::write(operation.path.join("publication.grant"), GRANT).unwrap();
    }

    fn change(name: &str, old: char, new: char) -> journal::RefChange {
        journal::RefChange {
            ref_name: name.into(),
            old_oid: old.to_string().repeat(40),
            new_oid: new.to_string().repeat(40),
        }
    }

    fn recorded_journal() -> (tempfile::TempDir, journal::Operation) {
        let root = tempfile::tempdir().unwrap();
        let operation = journal_operation(root.path(), Uuid::new_v4());
        let requested = vec![change("refs/heads/main", '0', 'a'), change("refs/heads/other", '0', 'b')];
        // Non-atomic push: `other` fails, so the successful subset is `main`.
        journal::record_ref_transaction_intent(&operation, &requested).unwrap();
        journal::record_ref_transaction_receipt(&operation, &[requested[0].clone()]).unwrap();
        grant(&operation);
        journal::finish(&operation).unwrap();
        (root, operation)
    }

    fn proof(operation: &journal::Operation) -> RecordedReceiptProof {
        RecordedReceiptProof::from_journal(operation, "recorded", 1).expect("real receipt proof")
    }

    fn record(operation: &journal::Operation, outcome: &str) -> events::OperationRecord {
        events::OperationRecord {
            id: operation.id,
            repository_id: operation.repository_id,
            actor_id: operation.actor_id,
            token_id: operation.token_id,
            service_principal_id: None,
            actor_name: operation.actor_name.clone(),
            sequence: operation.sequence,
            storage_generation: operation.storage_generation,
            outcome: outcome.into(),
            evidence: serde_json::json!({"version":1}),
            admission: Some(events::AdmissionRecord { writer_id: operation.id, shard_epoch: operation.shard_epoch }),
        }
    }

    #[test]
    fn binds_the_successful_non_atomic_receipt_subset() {
        let (_root, operation) = recorded_journal();
        let proof = proof(&operation);
        assert_eq!(proof.operation_id(), operation.id);
        let record = record(&operation, "recorded");
        let changes = vec![events::RefEventInput {
            transaction_sequence: 1,
            ref_name: "refs/heads/main".into(),
            old_oid: "0".repeat(40),
            new_oid: "a".repeat(40),
        }];
        assert!(proof.matches_record(&record, &changes));
        assert!(proof.matches_admission(
            operation.repository_id,
            1,
            record.admission.as_ref().unwrap(),
            operation.actor_id,
            operation.token_id,
            operation.actor_id,
            operation.token_id,
            &["refs/heads/main".into(), "refs/heads/other".into()]
        ));
    }

    #[test]
    fn rejects_another_outcome_or_generation() {
        let (_root, operation) = recorded_journal();
        assert!(RecordedReceiptProof::from_journal(&operation, "no_ref_changes", 1).is_none());
        assert!(RecordedReceiptProof::from_journal(&operation, "unknown", 1).is_none());
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 2).is_none());
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 0).is_none());
    }

    #[test]
    fn rejects_missing_request_receipt_or_committed_hook() {
        let root = tempfile::tempdir().unwrap();
        let operation = journal_operation(root.path(), Uuid::new_v4());
        // Receipt and committed event without the pre-receive request.
        journal::record_ref_transaction_receipt(&operation, &[change("refs/heads/main", '0', 'a')]).unwrap();
        grant(&operation);
        journal::finish(&operation).unwrap();
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 1).is_none());

        let root = tempfile::tempdir().unwrap();
        let operation = journal_operation(root.path(), Uuid::new_v4());
        // Request only: Git was admitted but never acknowledged a ref.
        journal::record_ref_transaction_intent(&operation, &[change("refs/heads/main", '0', 'a')]).unwrap();
        grant(&operation);
        journal::finish(&operation).unwrap();
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 1).is_none());

        let root = tempfile::tempdir().unwrap();
        let operation = journal_operation(root.path(), Uuid::new_v4());
        let requested = [change("refs/heads/main", '0', 'a')];
        journal::record_ref_transaction_intent(&operation, &requested).unwrap();
        // A bare receipt file with no committed reference-transaction event.
        std::fs::write(operation.path.join("post-receive.json"), serde_json::to_vec(&requested).unwrap())
            .unwrap();
        grant(&operation);
        journal::finish(&operation).unwrap();
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 1).is_none());
    }

    #[test]
    fn rejects_receipt_outside_request_or_committed_set() {
        let root = tempfile::tempdir().unwrap();
        let operation = journal_operation(root.path(), Uuid::new_v4());
        let requested = [change("refs/heads/main", '0', 'a'), change("refs/heads/other", '0', 'b')];
        journal::record_ref_transaction_intent(&operation, &requested).unwrap();
        // Receipt claims a ref that was never requested, even though the
        // committed event agrees with it.
        journal::record_ref_transaction_receipt(&operation, &[change("refs/heads/other", '0', 'b')]).unwrap();
        std::fs::write(
            operation.path.join("post-receive.json"),
            serde_json::to_vec(&[change("refs/heads/main", '0', 'a')]).unwrap(),
        )
        .unwrap();
        grant(&operation);
        journal::finish(&operation).unwrap();
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 1).is_none());
    }

    #[test]
    fn live_finished_journal_never_mints_a_recorded_proof() {
        let root = tempfile::tempdir().unwrap();
        let (operation, active) = journal::begin_active_with(
            root.path(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "alice".into(),
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            7,
        )
        .unwrap();
        let requested = [change("refs/heads/main", '0', 'a')];
        journal::record_ref_transaction_intent(&operation, &requested).unwrap();
        journal::record_ref_transaction_receipt(&operation, &requested).unwrap();
        grant(&operation);
        journal::finish(&operation).unwrap();
        assert!(journal::ActiveGuard::operation_is_live(&operation).unwrap());
        assert!(
            RecordedReceiptProof::from_journal(&operation, "recorded", 1).is_none(),
            "a live child could publish after this observation"
        );
        drop(active);
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 1).is_some());
    }

    #[test]
    fn grant_marker_is_required_and_read_without_symlinks() {
        let (_root, operation) = recorded_journal();
        let marker = operation.path.join("publication.grant");
        std::fs::remove_file(&marker).unwrap();
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 1).is_none());
        std::fs::write(&marker, b"short").unwrap();
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 1).is_none());
        std::fs::remove_file(&marker).unwrap();
        let target = operation.path.parent().unwrap().join("outside-grant");
        std::fs::write(&target, GRANT).unwrap();
        std::os::unix::fs::symlink(&target, &marker).unwrap();
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 1).is_none());
        std::fs::remove_file(&marker).unwrap();
        grant(&operation);
        assert!(RecordedReceiptProof::from_journal(&operation, "recorded", 1).is_some());
    }

    #[test]
    fn binds_journal_sequence_actor_name_and_human_principal() {
        let (_root, operation) = recorded_journal();
        let derived = proof(&operation);
        let record = record(&operation, "recorded");
        let changes = vec![events::RefEventInput {
            transaction_sequence: 1,
            ref_name: "refs/heads/main".into(),
            old_oid: "0".repeat(40),
            new_oid: "a".repeat(40),
        }];
        assert!(derived.matches_record(&record, &changes));
        let mut tampered = record.clone();
        tampered.sequence += 1;
        assert!(!derived.matches_record(&tampered, &changes));
        let mut tampered = record.clone();
        tampered.actor_name = "mallory".into();
        assert!(!derived.matches_record(&tampered, &changes));
        let mut tampered = record.clone();
        tampered.service_principal_id = Some(Uuid::new_v4());
        assert!(!derived.matches_record(&tampered, &changes));
        let mut tampered = proof(&operation);
        tampered.sequence += 1;
        assert!(!tampered.matches_record(&record, &changes));
        let mut tampered = proof(&operation);
        tampered.actor_name.push('x');
        assert!(!tampered.matches_record(&record, &changes));
    }

    #[test]
    fn proof_cannot_be_rebound_to_another_operation_identity() {
        let (_root, operation) = recorded_journal();
        let mut proof = proof(&operation);
        let record = record(&operation, "recorded");
        let changes = vec![events::RefEventInput {
            transaction_sequence: 1,
            ref_name: "refs/heads/main".into(),
            old_oid: "0".repeat(40),
            new_oid: "a".repeat(40),
        }];
        let mut other = record.clone();
        other.id = Uuid::new_v4();
        other.actor_id = Uuid::new_v4();
        other.token_id = Uuid::new_v4();
        assert!(!proof.matches_record(&other, &changes));
        let mut other_changes = changes.clone();
        other_changes[0].new_oid = "c".repeat(40);
        assert!(!proof.matches_record(&record, &other_changes));
        let admission = record.admission.as_ref().unwrap();
        let refs = ["refs/heads/main".to_string(), "refs/heads/other".to_string()];
        assert!(!proof.matches_admission(
            operation.repository_id,
            1,
            admission,
            operation.actor_id,
            operation.token_id,
            operation.actor_id,
            operation.token_id,
            &refs[..1]
        ));
        assert!(!proof.matches_admission(
            operation.repository_id,
            1,
            admission,
            Uuid::new_v4(),
            operation.token_id,
            operation.actor_id,
            operation.token_id,
            &refs
        ));
        assert!(!proof.matches_admission(
            operation.repository_id,
            1,
            admission,
            operation.actor_id,
            operation.token_id,
            operation.actor_id,
            Uuid::new_v4(),
            &refs
        ));
        assert!(!proof.matches_admission(
            operation.repository_id,
            2,
            admission,
            operation.actor_id,
            operation.token_id,
            operation.actor_id,
            operation.token_id,
            &refs
        ));
        proof.actor_id = Uuid::new_v4();
        assert!(!proof.matches_record(&record, &changes));
    }

    async fn postgres_fixture() -> Option<(deadpool_postgres::Pool, crate::db::Identity, Uuid, Uuid)> {
        let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok()?;
        let admin = crate::db::pool(&base_url).unwrap();
        let schema = format!("recorded_receipt_{}", Uuid::new_v4().simple());
        admin.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA \"{schema}\"")).await.unwrap();
        let mut url = reqwest::Url::parse(&base_url).unwrap();
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        let pool = crate::db::pool(url.as_str()).unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let issued = crate::db::issue_token(&pool, "alice", true, false).await.unwrap();
        let actor_id: Uuid = serde_json::from_value(issued["user_id"].clone()).unwrap();
        let token_id: Uuid = serde_json::from_value(issued["token_id"].clone()).unwrap();
        let digest: Vec<u8> = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT digest FROM tokens WHERE id=$1", &[&token_id])
            .await
            .unwrap()
            .get(0);
        let actor =
            crate::db::Identity { id: actor_id, token_id, username: "alice".into(), read_only: false, token_digest: digest };
        let repo = Uuid::new_v4();
        pool.get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'demo','ready')",
                &[&repo, &actor_id],
            )
            .await
            .unwrap();
        pool.get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO shard_nodes(node_id,endpoint,role,status) VALUES('node-a','http://127.0.0.1:1','primary','healthy')",
                &[],
            )
            .await
            .unwrap();
        pool.get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO repository_shard_routes(tenant_id,repository_id,bucket_id,primary_node_id,route_epoch,fencing_token,required_generation) \
                 VALUES($1,$2,0,'node-a',7,7,1)",
                &[&actor_id, &repo],
            )
            .await
            .unwrap();
        Some((pool, actor, repo, token_id))
    }

    async fn admitted(
        pool: &deadpool_postgres::Pool,
        actor: &crate::db::Identity,
        repo: Uuid,
        refs: &[String],
    ) -> crate::storage::ref_admission::Admission {
        crate::storage::ref_admission::admit(
            pool,
            repo,
            1,
            actor,
            refs,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await
        .unwrap()
    }

    fn committed_journal(
        repo: Uuid,
        actor: &crate::db::Identity,
        writer: Uuid,
        name: &str,
    ) -> (tempfile::TempDir, journal::Operation, Vec<events::RefEventInput>) {
        let root = tempfile::tempdir().unwrap();
        let (operation, active) = journal::begin_active_with(
            root.path(),
            repo,
            actor.id,
            actor.username.clone(),
            actor.token_id,
            1,
            writer,
            7,
        )
        .unwrap();
        drop(active);
        let requested = vec![journal::RefChange {
            ref_name: name.into(),
            old_oid: "0".repeat(40),
            new_oid: "a".repeat(40),
        }];
        journal::record_ref_transaction_intent(&operation, &requested).unwrap();
        journal::record_ref_transaction_receipt(&operation, &requested).unwrap();
        grant(&operation);
        journal::finish(&operation).unwrap();
        let changes = vec![events::RefEventInput {
            transaction_sequence: 1,
            ref_name: name.into(),
            old_oid: "0".repeat(40),
            new_oid: "a".repeat(40),
        }];
        (root, operation, changes)
    }

    #[tokio::test]
    #[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
    async fn recorded_proof_settles_recovering_revoked_token() {
        let Some((pool, actor, repo, _)) = postgres_fixture().await else {
            return;
        };
        let refs = vec!["refs/heads/main".to_string()];
        let admission = admitted(&pool, &actor, repo, &refs).await;
        let (_root, operation, changes) = committed_journal(repo, &actor, admission.writer_id, "refs/heads/main");
        let proof = RecordedReceiptProof::from_journal(&operation, "recorded", 1).unwrap();
        // Crash recovery state plus a token revoked after the real push.
        pool.get()
            .await
            .unwrap()
            .execute("UPDATE repositories SET state='recovering',recovery_reason='push_outcome_unknown' WHERE id=$1", &[&repo])
            .await
            .unwrap();
        pool.get().await.unwrap().execute("UPDATE tokens SET revoked=true WHERE id=$1", &[&actor.token_id]).await.unwrap();
        events::publish_with_recorded_receipt(&pool, &record(&operation, "recorded"), &changes, &proof)
            .await
            .unwrap();
        let state: String = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT state FROM git_ref_admissions WHERE writer_id=$1", &[&admission.writer_id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(state, "COMMITTED");
        let outbox: i64 = pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM outbox_events", &[]).await.unwrap().get(0);
        assert_eq!(outbox, 1);
    }

    #[tokio::test]
    #[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
    async fn recorded_proof_rejects_operator_recovery_reason() {
        let Some((pool, actor, repo, _)) = postgres_fixture().await else {
            return;
        };
        let refs = vec!["refs/heads/main".to_string()];
        let admission = admitted(&pool, &actor, repo, &refs).await;
        let (_root, operation, changes) = committed_journal(repo, &actor, admission.writer_id, "refs/heads/main");
        let proof = RecordedReceiptProof::from_journal(&operation, "recorded", 1).unwrap();
        pool.get()
            .await
            .unwrap()
            .execute("UPDATE repositories SET state='recovering',recovery_reason='journal_invalid' WHERE id=$1", &[&repo])
            .await
            .unwrap();
        assert!(
            events::publish_with_recorded_receipt(&pool, &record(&operation, "recorded"), &changes, &proof).await.is_err()
        );
        let state: String = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT state FROM git_ref_admissions WHERE writer_id=$1", &[&admission.writer_id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(state, "ADMITTED");
    }

    #[tokio::test]
    #[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
    async fn recorded_proof_rejects_admitted_ref_or_epoch_drift() {
        let Some((pool, actor, repo, _)) = postgres_fixture().await else {
            return;
        };
        let refs = vec!["refs/heads/main".to_string()];
        let admission = admitted(&pool, &actor, repo, &refs).await;
        let (_root, operation, changes) = committed_journal(repo, &actor, admission.writer_id, "refs/heads/main");
        let proof = RecordedReceiptProof::from_journal(&operation, "recorded", 1).unwrap();
        pool.get()
            .await
            .unwrap()
            .execute("UPDATE repositories SET state='recovering',recovery_reason='push_outcome_unknown' WHERE id=$1", &[&repo])
            .await
            .unwrap();
        pool.get()
            .await
            .unwrap()
            .execute("UPDATE git_ref_admissions SET ref_names=ARRAY['refs/heads/other'] WHERE writer_id=$1", &[&admission.writer_id])
            .await
            .unwrap();
        assert!(
            events::publish_with_recorded_receipt(&pool, &record(&operation, "recorded"), &changes, &proof).await.is_err()
        );
        pool.get()
            .await
            .unwrap()
            .execute("UPDATE git_ref_admissions SET ref_names=$2,shard_epoch=8 WHERE writer_id=$1", &[&admission.writer_id, &refs])
            .await
            .unwrap();
        assert!(
            events::publish_with_recorded_receipt(&pool, &record(&operation, "recorded"), &changes, &proof).await.is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
    async fn read_only_current_writer_still_needs_live_authority() {
        let Some((pool, _actor, repo, _)) = postgres_fixture().await else {
            return;
        };
        let issued = crate::db::issue_token(&pool, "reader", true, true).await.unwrap();
        let reader_id: Uuid = serde_json::from_value(issued["user_id"].clone()).unwrap();
        let reader_token: Uuid = serde_json::from_value(issued["token_id"].clone()).unwrap();
        let reader = crate::db::Identity {
            id: reader_id,
            token_id: reader_token,
            username: "reader".into(),
            read_only: true,
            token_digest: Vec::new(),
        };
        // The admission is honest; only the current token is read-only. An
        // ordinary settlement must still refuse it, unlike journal proof.
        let writer = Uuid::new_v4();
        pool.get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO git_ref_admissions(writer_id,repository_id,shard_epoch,node_id,actor_id,token_id,ref_names,state) \
                 VALUES($1,$2,7,NULL,$3,$4,$5,'ADMITTED')",
                &[&writer, &repo, &reader.id, &reader.token_id, &vec!["refs/heads/main".to_string()]],
            )
            .await
            .unwrap();
        let (_root, operation, changes) = committed_journal(repo, &reader, writer, "refs/heads/main");
        assert!(events::publish(&pool, &record(&operation, "recorded"), &changes).await.is_err());
        let state: String = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT state FROM git_ref_admissions WHERE writer_id=$1", &[&writer])
            .await
            .unwrap()
            .get(0);
        assert_eq!(state, "ADMITTED");
    }
}
