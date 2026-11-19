//! Boot-time re-homing of a restored `pg_refstore` A3/A4 realm.
//!
//! Historical A3/A4 receipts stay byte-for-byte immutable under the source realm. Only the live
//! gate/protocol/serving pointers are rotated; the new realm is re-established by the canonical
//! A3 acquire -> protected upload -> A4 register/verify/commit pipeline for every restored pair.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use deadpool_postgres::Pool;
use tokio::time::Instant;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

use crate::blob_store::opendal::BlobStore;
use crate::blob_store::protected::{ProtectedUploader, UploadSource};
use crate::config::Config;
use crate::ref_store::contract::{IssuerLane, OperationIdentity, RequestDigest};
use crate::ref_store::core::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldError, ArtifactHoldPurpose, ArtifactSpec, HoldScope,
    PgArtifactHoldStore,
};
use crate::ref_store::core::pack_commit::{
    ContentDigest, MAX_BATCH_NEW_PACKS, PackArtifactRole, PackCommitError, PackCommitExpectation, PackCommitPlan,
    PackCommitScope, PackRegistrationRequest, PackVerifier, PgPackCommit, PlannedArtifact, PlannedPack,
};
use crate::ref_store::core::terminal::TerminalKind;
use crate::ref_store::core::types::{
    GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate,
};

use super::backup::stream_sha256_file;
use super::format30_paired::Format30PairedManifest;
use super::pg_cutpoint::pg_err;
use super::types::{ExpectedPackPairSpec, NewIncarnationAuthority, PairedBackupError};

const GATES: &str = "SELECT g.repository_id, g.tenant_id, r.owner_id, g.object_format, \
     COALESCE(p.decision_required, false) FROM public.ref_store_core_gates g \
     JOIN public.repositories r ON r.id = g.repository_id \
     LEFT JOIN public.ref_store_core_protocol_repos p ON p.repository_id = g.repository_id ORDER BY g.repository_id";
const REFS: &str = "SELECT ref_name, oid FROM public.ref_store_core_refs WHERE repository_id = $1 ORDER BY ref_name";
const PACKS: &str = "SELECT m.pack_id, pa.sha256, pa.content_length, ia.sha256, ia.content_length \
     FROM public.ref_store_core_pack_memberships m \
     JOIN public.ref_store_core_pack_artifacts pa ON pa.registration_id = m.registration_id AND pa.role = 'pack' \
     JOIN public.ref_store_core_pack_artifacts ia ON ia.registration_id = m.registration_id AND ia.role = 'idx' \
     WHERE m.repository_id = $1 ORDER BY m.pack_id";
const REALM: [&str; 3] = [
    "UPDATE public.ref_store_core_gates SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
    "UPDATE public.ref_store_core_protocol_repos SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
    "UPDATE public.ref_store_serving_repositories SET history_incarnation = $1, authority_epoch = $2, group_epoch = $3",
];
const PACK_MODE: &str = "UPDATE public.ref_store_core_gates SET pack_mode = 'metadata_only' WHERE repository_id = $1";
const DECISION_OFF: &str =
    "UPDATE public.ref_store_core_protocol_repos SET decision_required = false WHERE repository_id = $1";
const DECISION_ON: &str = "UPDATE public.ref_store_core_protocol_repos SET decision_required = true \
     WHERE repository_id = $1 AND decision_required = false";
const CLEAR_REFS: &str = "DELETE FROM public.ref_store_core_refs WHERE repository_id = $1";
const CLEAR_MEMBERSHIPS: &str = "DELETE FROM public.ref_store_core_pack_memberships WHERE repository_id = $1";
const DEC_REPO_USAGE: &str = "UPDATE public.ref_store_core_pack_repo_usage \
     SET membership_count = GREATEST(0, membership_count - $1) WHERE repository_id = $2";
const DEC_TENANT_USAGE: &str = "UPDATE public.ref_store_core_pack_tenant_usage \
     SET membership_count = GREATEST(0, membership_count - $1) WHERE tenant_id = $2";

/// One localized `.pack` + `.idx` pair restored from the format 30 archive.
#[derive(Clone)]
pub(super) struct RestoredRepoPackFile {
    pub pack_path: PathBuf,
    pub pack_sha256: String,
    pub pack_len: u64,
    pub idx_path: PathBuf,
    pub idx_sha256: String,
    pub idx_len: u64,
}

/// Complete restored repository state needed to re-establish its new-realm packs and refs.
pub(super) struct RestoredRepoCapture {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub object_format: GitObjectFormat,
    pub decision_required: bool,
    pub refs: Vec<(String, String)>,
    pub active_packs: Vec<RestoredRepoPackFile>,
}

/// Capture every restored repository's realm identity, refs and active pack memberships while
/// binding each membership back to the exact archived `.pack`/`.idx` closure entry.
pub(super) async fn capture_restored_repositories_for_rebind(
    client: &Client,
    fmt30_dir: &Path,
    manifest: &Format30PairedManifest,
) -> Result<Vec<RestoredRepoCapture>, PairedBackupError> {
    let rows = client.query(GATES, &[]).await.map_err(pg_err)?;
    let mut captured = Vec::with_capacity(rows.len());
    for row in rows {
        let repository_id: Uuid = row.get(0);
        let tenant_id: Uuid = row.get(1);
        let owner_id: Uuid = row.get(2);
        let format: String = row.get(3);
        let decision_required: bool = row.get(4);
        let object_format =
            GitObjectFormat::parse(&format).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let refs: Vec<(String, String)> = client
            .query(REFS, &[&repository_id])
            .await
            .map_err(pg_err)?
            .into_iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        let entry = |pack_id: Uuid, role: &str| {
            manifest
                .blob_closure
                .entries
                .iter()
                .find(|e| e.repository_id == repository_id && e.pack_id == pack_id && e.role == role)
                .ok_or_else(|| missing(repository_id, pack_id, role))
        };
        let mut active_packs = Vec::new();
        for pack_row in client.query(PACKS, &[&repository_id]).await.map_err(pg_err)? {
            let pack_id: Uuid = pack_row.get(0);
            let pack_sha256: String = pack_row.get(1);
            let idx_sha256: String = pack_row.get(3);
            let pack_len = positive(pack_row.get(2), "pack")?;
            let idx_len = positive(pack_row.get(4), "idx")?;
            let pack_entry = entry(pack_id, "pack")?;
            let idx_entry = entry(pack_id, "idx")?;
            if pack_entry.sha256 != pack_sha256
                || idx_entry.sha256 != idx_sha256
                || pack_entry.length != pack_len
                || idx_entry.length != idx_len
            {
                return Err(PairedBackupError::BlobClosureIncomplete(format!(
                    "restored repository {repository_id} pack {pack_id} differs from the archived closure"
                )));
            }
            active_packs.push(RestoredRepoPackFile {
                pack_path: fmt30_dir.join(&pack_entry.archive_rel_path),
                pack_sha256,
                pack_len,
                idx_path: fmt30_dir.join(&idx_entry.archive_rel_path),
                idx_sha256,
                idx_len,
            });
        }
        captured.push(RestoredRepoCapture {
            repository_id,
            tenant_id,
            owner_id,
            object_format,
            decision_required,
            refs,
            active_packs,
        });
    }
    Ok(captured)
}

/// Rotate only the live gate/protocol/serving pointers and clear the restored refs/memberships so
/// the canonical A3+A4 pipeline can re-establish them under the new realm. The caller already set
/// `session_replication_role = replica` on `tx`; historical A3/A4 rows are never touched.
pub(super) async fn rehome_restored_repositories_realm(
    tx: &Transaction<'_>,
    captured: &[RestoredRepoCapture],
    new_history_inc: Uuid,
    new_authority_epoch: i64,
    new_group_epoch: i64,
) -> Result<(), PairedBackupError> {
    for statement in REALM {
        tx.execute(statement, &[&new_history_inc, &new_authority_epoch, &new_group_epoch]).await.map_err(pg_err)?;
    }
    for repo in captured {
        if repo.active_packs.is_empty() || repo.refs.is_empty() {
            continue;
        }
        let (id, tenant) = (repo.repository_id, repo.tenant_id);
        tx.execute(PACK_MODE, &[&id]).await.map_err(pg_err)?;
        tx.execute(DECISION_OFF, &[&id]).await.map_err(pg_err)?;
        tx.execute(CLEAR_REFS, &[&id]).await.map_err(pg_err)?;
        let cleared = tx.execute(CLEAR_MEMBERSHIPS, &[&id]).await.map_err(pg_err)? as i64;
        if cleared > 0 {
            tx.execute(DEC_REPO_USAGE, &[&cleared, &id]).await.map_err(pg_err)?;
            tx.execute(DEC_TENANT_USAGE, &[&cleared, &tenant]).await.map_err(pg_err)?;
        }
    }
    Ok(())
}

/// Re-run the canonical A3+A4 publication pipeline for every restored pack pair in the new realm.
pub(super) async fn rebind_restored_repositories_in_new_realm(
    client: &mut Client,
    dst_config: &Config,
    target_store: &BlobStore,
    inc: &NewIncarnationAuthority,
    captured: &[RestoredRepoCapture],
) -> Result<BTreeMap<Uuid, Vec<ExpectedPackPairSpec>>, PairedBackupError> {
    let rw_pool = build_rebind_rw_pool(&dst_config.database_url)?;
    let verifier = PackVerifier::new(target_store.clone(), dst_config.git.clone()).map_err(pack_error)?;
    let backend = target_store.backend_identity().clone();
    let mut rebound_packs: BTreeMap<Uuid, Vec<ExpectedPackPairSpec>> = BTreeMap::new();
    let repack_root = captured.iter().any(needs_consolidation).then(RebindTempDir::create).transpose()?;
    for repo in captured {
        if repo.active_packs.is_empty() || repo.refs.is_empty() {
            continue;
        }
        let packs_to_publish: Vec<RestoredRepoPackFile> = if repo.active_packs.len() <= MAX_BATCH_NEW_PACKS {
            repo.active_packs.clone()
        } else {
            let root = repack_root.as_ref().ok_or_else(|| {
                PairedBackupError::StateMachine("restore pack consolidation workspace is missing".into())
            })?;
            let repo_root = root.0.join(repo.repository_id.to_string());
            vec![consolidate_packs_with_git(
                &dst_config.git,
                repo.object_format,
                &repo.refs,
                &repo.active_packs,
                &repo_root,
            )?]
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let baseline = PgPackCommit
            .capture_baseline(client, repo.repository_id, repo.tenant_id, deadline)
            .await
            .map_err(pack_error)?;
        let scope = PackCommitScope::new(
            repo.repository_id,
            repo.tenant_id,
            repo.owner_id,
            repo.object_format,
            inc.new_history_incarnation,
            inc.new_authority_epoch,
            inc.new_group_epoch,
        )
        .map_err(pack_error)?;
        let op_id = Uuid::new_v4();
        let lane =
            IssuerLane::new("paired-restore-rebind").map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let init_identity = OperationIdentity::new(
            repo.repository_id,
            inc.new_history_incarnation,
            lane,
            1,
            op_id,
            RequestDigest::of("restore-rebind-init", &[op_id.as_bytes()]),
        )
        .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let mut ref_updates = Vec::with_capacity(repo.refs.len());
        for (name, oid) in &repo.refs {
            let target =
                GitOid::parse(repo.object_format, oid).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
            let name = RefName::new(name.clone()).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
            ref_updates.push(RefUpdate::new(name, RefPrecondition::Absent, RefTarget::Oid(target)));
        }
        let mut planned_packs = Vec::with_capacity(packs_to_publish.len());
        let mut expected_specs = Vec::with_capacity(packs_to_publish.len());
        for pack_file in &packs_to_publish {
            let (pack_id, registration_id) = (Uuid::new_v4(), Uuid::new_v4());
            let pack_artifact = artifact(PackArtifactRole::Pack, &pack_file.pack_sha256, pack_file.pack_len)?;
            let idx_artifact = artifact(PackArtifactRole::Idx, &pack_file.idx_sha256, pack_file.idx_len)?;
            planned_packs
                .push(PlannedPack::new(pack_id, registration_id, pack_artifact, idx_artifact).map_err(pack_error)?);
            expected_specs.push(ExpectedPackPairSpec {
                pack_id,
                pack_sha256: pack_file.pack_sha256.clone(),
                pack_bytes: pack_file.pack_len,
                idx_sha256: pack_file.idx_sha256.clone(),
                idx_bytes: pack_file.idx_len,
            });
        }
        let expected =
            PackCommitExpectation::new(baseline.gate().revision(), *baseline.gate().digest(), baseline.mode())
                .map_err(pack_error)?;
        let plan = PackCommitPlan::new(
            scope,
            init_identity,
            expected,
            HeadUpdate::Keep,
            ref_updates,
            baseline.membership_digest(),
            Vec::new(),
            planned_packs,
        )
        .map_err(pack_error)?;
        let token = PgPackCommit.begin_pending(client, &plan, deadline).await.map_err(pack_error)?;
        for (planned, pack_file) in plan.packs().iter().zip(packs_to_publish.iter()) {
            let hold_scope = HoldScope::new(
                plan.repository_id(),
                plan.tenant_id(),
                plan.owner_id(),
                ArtifactHoldPurpose::RefPublication,
                plan.object_format(),
                plan.history_incarnation(),
                plan.authority_epoch(),
                plan.group_epoch(),
            )
            .map_err(ledger_error)?;
            let specs = vec![
                ArtifactSpec::new("gateway-pack", pack_file.pack_sha256.clone(), pack_file.pack_len)
                    .map_err(ledger_error)?,
                ArtifactSpec::new("gateway-pack", pack_file.idx_sha256.clone(), pack_file.idx_len)
                    .map_err(ledger_error)?,
            ];
            let hold_request = AcquireArtifactHoldsRequest::new(
                hold_scope,
                plan.identity().clone(),
                Uuid::new_v4(),
                backend.clone(),
                inc.new_storage_authority_id,
                inc.new_storage_generation,
                *baseline.gate().digest(),
                specs,
            )
            .map_err(ledger_error)?;
            let AcquireOutcome::Granted { grant, .. } = PgArtifactHoldStore
                .acquire(client, target_store, &hold_request, deadline)
                .await
                .map_err(ledger_error)?
            else {
                return Err(PairedBackupError::StateMachine(
                    "restore rebind A3 acquire replayed an existing request".into(),
                ));
            };
            let sources = [UploadSource::new(&pack_file.pack_path), UploadSource::new(&pack_file.idx_path)];
            let publication = ProtectedUploader::new(target_store.clone())
                .consume_and_upload(&rw_pool, grant, &sources, deadline.into_std())
                .await
                .map_err(|e| PairedBackupError::StateMachine(format!("restore rebind upload failed: {e}")))?;
            let request = PackRegistrationRequest::new(&plan, planned.pack_id(), &publication).map_err(pack_error)?;
            PgPackCommit.register_publication(client, request, deadline).await.map_err(pack_error)?;
        }
        let context = PgPackCommit.capture_context(client, &plan, deadline).await.map_err(pack_error)?;
        let proof = verifier.verify(&plan, &context, deadline.into_std()).await.map_err(pack_error)?;
        let committed =
            PgPackCommit.commit_verified_pending(client, &plan, &token, &proof, deadline).await.map_err(pack_error)?;
        if committed.terminal.kind != TerminalKind::Committed {
            return Err(PairedBackupError::StateMachine("restore rebind pack commit was rejected".into()));
        }
        if repo.decision_required {
            client.execute(DECISION_ON, &[&repo.repository_id]).await.map_err(pg_err)?;
        }
        rebound_packs.insert(repo.repository_id, expected_specs);
    }
    Ok(rebound_packs)
}

/// Build the one write-enabled pool used only by the protected A3 consume/upload child. Client
/// startup `-c default_transaction_read_only=off` overrides the database default for this pool
/// while every external session keeps the restored database read-only.
fn build_rebind_rw_pool(database_url: &str) -> Result<Pool, PairedBackupError> {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    let rw_url = format!("{database_url}{separator}options=-c%20default_transaction_read_only%3Doff");
    crate::db::pool(&rw_url).map_err(|error| PairedBackupError::Postgres(error.to_string()))
}

/// Consolidate more than [`MAX_BATCH_NEW_PACKS`] restored pairs into one canonical pack by using
/// stock Git in a private temporary bare repository.
fn consolidate_packs_with_git(
    git: &Path,
    object_format: GitObjectFormat,
    refs: &[(String, String)],
    packs: &[RestoredRepoPackFile],
    root: &Path,
) -> Result<RestoredRepoPackFile, PairedBackupError> {
    let init = Command::new(git)
        .args(["init", "--bare", "--object-format", object_format.as_str()])
        .arg(root)
        .output()
        .map_err(PairedBackupError::Io)?;
    if !init.status.success() {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "git init for restore pack consolidation failed: {}",
            String::from_utf8_lossy(&init.stderr)
        )));
    }
    let pack_dir = root.join("objects/pack");
    std::fs::create_dir_all(&pack_dir)?;
    for pack in packs {
        let pack_name = pack
            .pack_path
            .file_name()
            .ok_or_else(|| PairedBackupError::StateMachine("pack file has no name".into()))?;
        let idx_name =
            pack.idx_path.file_name().ok_or_else(|| PairedBackupError::StateMachine("idx file has no name".into()))?;
        std::fs::copy(&pack.pack_path, pack_dir.join(pack_name))?;
        std::fs::copy(&pack.idx_path, pack_dir.join(idx_name))?;
    }
    for (name, oid) in refs {
        if !name.starts_with("refs/") {
            return Err(PairedBackupError::StateMachine(format!("restored ref {name:?} is not repository-relative")));
        }
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, format!("{oid}\n"))?;
    }
    let repack = Command::new(git)
        .arg("--git-dir")
        .arg(root)
        .args(["repack", "-a", "-d", "-q"])
        .output()
        .map_err(PairedBackupError::Io)?;
    if !repack.status.success() {
        return Err(PairedBackupError::GitVerificationFailed(format!(
            "git repack for restore pack consolidation failed: {}",
            String::from_utf8_lossy(&repack.stderr)
        )));
    }
    let (mut pack_path, mut idx_path) = (None, None);
    for entry in std::fs::read_dir(&pack_dir)? {
        let path = entry?.path();
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("pack") => pack_path = Some(path),
            Some("idx") => idx_path = Some(path),
            _ => {}
        }
    }
    let pack_path = pack_path.ok_or_else(|| PairedBackupError::StateMachine("consolidated pack is missing".into()))?;
    let idx_path = idx_path.ok_or_else(|| PairedBackupError::StateMachine("consolidated idx is missing".into()))?;
    let (pack_len, pack_sha256) = stream_sha256_file(&pack_path)?;
    let (idx_len, idx_sha256) = stream_sha256_file(&idx_path)?;
    Ok(RestoredRepoPackFile { pack_path, pack_sha256, pack_len, idx_path, idx_sha256, idx_len })
}

fn missing(repository_id: Uuid, pack_id: Uuid, role: &str) -> PairedBackupError {
    PairedBackupError::BlobClosureIncomplete(format!(
        "restored repository {repository_id} pack {pack_id} has no archive {role} entry"
    ))
}

fn positive(value: i64, role: &str) -> Result<u64, PairedBackupError> {
    u64::try_from(value).map_err(|_| {
        PairedBackupError::BlobClosureIncomplete(format!("restored {role} length is not a positive integer"))
    })
}

fn ledger_error(error: ArtifactHoldError) -> PairedBackupError {
    PairedBackupError::StateMachine(format!("restored A3 new-realm rebind refused: {error}"))
}

fn pack_error(error: PackCommitError) -> PairedBackupError {
    PairedBackupError::StateMachine(format!("restored A4 new-realm rebind refused: {error}"))
}

fn artifact(role: PackArtifactRole, sha256: &str, len: u64) -> Result<PlannedArtifact, PairedBackupError> {
    PlannedArtifact::new(role, ContentDigest::parse(sha256).map_err(pack_error)?, len).map_err(pack_error)
}

fn needs_consolidation(repo: &RestoredRepoCapture) -> bool {
    !repo.active_packs.is_empty() && !repo.refs.is_empty() && repo.active_packs.len() > MAX_BATCH_NEW_PACKS
}

struct RebindTempDir(PathBuf);

impl RebindTempDir {
    fn create() -> Result<Self, PairedBackupError> {
        let path = std::env::temp_dir().join(format!("rootyard-rebind-{}", Uuid::new_v4()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&path)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for RebindTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
