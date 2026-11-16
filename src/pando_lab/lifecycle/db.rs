use super::{
    ENVELOPE_SCHEMA, KmsEnvelopeRecord,
    provider::{KmsKeyPolicy, ManagedKeyStatus},
    rotation::KmsRotationCheckpoint,
};
use super::super::Pack;
use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio_postgres::Client;
use uuid::Uuid;

fn checkpoint_path(kms_dir: &Path) -> PathBuf {
    kms_dir.join("rotation_state.json")
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("missing parent dir for checkpoint")?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".rot-tmp-{}", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) async fn next_write_epoch(c: &Client, repo: Uuid) -> Result<u64> {
    let row = c
        .query_one(
            "SELECT COALESCE(MAX((checkpoint_json->>'write_epoch')::bigint),0) FROM pando_lab.kms_rotations WHERE repo=$1",
            &[&repo],
        )
        .await?;
    let current: i64 = row.get(0);
    ensure!(current >= 0, "invalid Pando rotation write epoch");
    u64::try_from(current)
        .ok()
        .and_then(|v| v.checked_add(1))
        .context("Pando rotation write epoch exhausted")
}

fn validate_current_checkpoint(cp: &KmsRotationCheckpoint, repo: Uuid) -> Result<()> {
    ensure!(
        cp.repo == repo
            && !cp.rotation_id.is_nil()
            && (cp.state == "IN_PROGRESS" || cp.state == "COMPLETED")
            && super::valid_kms_key_id(&cp.from_key_id)
            && super::valid_kms_key_id(&cp.to_key_id)
            && cp.from_key_version >= 1
            && cp.to_key_version >= 1,
        "invalid Pando rotation checkpoint identity"
    );
    ensure!(
        cp.from_provider_kind == super::provider::PROVIDER_KIND_LOCAL
            || cp.from_provider_kind == super::provider::PROVIDER_KIND_VAULT,
        "invalid Pando rotation source provider"
    );
    ensure!(
        cp.to_provider_kind == super::provider::PROVIDER_KIND_LOCAL
            || cp.to_provider_kind == super::provider::PROVIDER_KIND_VAULT,
        "invalid Pando rotation target provider"
    );
    ensure!(
        cp.expected_version() == cp.to_key_version,
        "Pando rotation checkpoint target version mismatch"
    );
    if cp.to_provider_kind == super::provider::PROVIDER_KIND_VAULT {
        ensure!(
            cp.target_contract == super::rotation::EXISTING_TARGET_CONTRACT
                && cp.write_epoch >= 1,
            "invalid legacy Vault rotation checkpoint contract"
        );
    }
    Ok(())
}

fn select_current_checkpoint(
    rows: Vec<(String, serde_json::Value)>,
    repo: Uuid,
) -> Result<Option<KmsRotationCheckpoint>> {
    let mut parsed = Vec::new();
    for (state, value) in rows {
        let cp: KmsRotationCheckpoint = serde_json::from_value(value)?;
        ensure!(cp.state == state, "rotation row/checkpoint state mismatch");
        validate_current_checkpoint(&cp, repo)?;
        parsed.push(cp);
    }
    let active: Vec<_> = parsed.iter().filter(|cp| cp.state == "IN_PROGRESS").collect();
    ensure!(active.len() <= 1, "multiple in-progress Pando rotation checkpoints");
    if let Some(cp) = active.into_iter().next() {
        return Ok(Some(cp.clone()));
    }
    // Legacy Local completion rows predate write_epoch and all decode at epoch 0.
    // They never declared a DB write pin; ignore them for positive-epoch selection
    // and fall back to the existing Local policy file authority when no positive
    // epoch exists. A single IN_PROGRESS legacy Local checkpoint above is still
    // resumable; multiple IN_PROGRESS rows remain ambiguous and fail closed.
    let completed: Vec<_> = parsed
        .iter()
        .filter(|cp| cp.state == "COMPLETED" && cp.write_epoch > 0)
        .collect();
    let Some(max_epoch) = completed.iter().map(|cp| cp.write_epoch).max() else {
        return Ok(None);
    };
    let latest: Vec<_> = completed.iter().filter(|cp| cp.write_epoch == max_epoch).collect();
    ensure!(latest.len() == 1, "ambiguous completed Pando rotation write epoch");
    Ok(Some(latest[0].clone()))
}

pub(super) async fn load_db_checkpoint(c: &Client, repo: Uuid) -> Result<Option<KmsRotationCheckpoint>> {
    let rows = c
        .query(
            "SELECT state, checkpoint_json FROM pando_lab.kms_rotations WHERE repo=$1",
            &[&repo],
        )
        .await?;
    select_current_checkpoint(
        rows.into_iter().map(|row| (row.get(0), row.get(1))).collect(),
        repo,
    )
}

pub(super) fn load_file_checkpoint(kms_dir: &Path) -> Result<Option<KmsRotationCheckpoint>> {
    let path = checkpoint_path(kms_dir);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&std::fs::read(&path)?)?))
}

pub async fn sync_kms_policy_to_db(c: &Client, repo: Uuid, policy: &KmsKeyPolicy) -> Result<()> {
    c.execute(
        "INSERT INTO pando_lab.lifecycle_policies(repo) VALUES($1) ON CONFLICT(repo) DO NOTHING",
        &[&repo],
    )
    .await?;
    c.execute(
        "UPDATE pando_lab.lifecycle_policies SET kms_key_id=$2,kms_key_version=$3,updated_at=now() WHERE repo=$1",
        &[&repo, &policy.active_key_id, &policy.active_key_version],
    )
    .await?;
    c.execute(
        "INSERT INTO pando_lab.kms_key_policies(repo,active_key_id,active_key_version,retain_previous_generations,min_readable_key_version,provider_revoked,encryption_mode) \
         VALUES($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT(repo) DO UPDATE SET active_key_id=EXCLUDED.active_key_id,active_key_version=EXCLUDED.active_key_version,\
         retain_previous_generations=EXCLUDED.retain_previous_generations,min_readable_key_version=EXCLUDED.min_readable_key_version,\
         provider_revoked=EXCLUDED.provider_revoked,encryption_mode=EXCLUDED.encryption_mode,updated_at=now()",
        &[
            &repo,
            &policy.active_key_id,
            &policy.active_key_version,
            &policy.retain_previous_generations,
            &policy.min_readable_key_version,
            &policy.provider_revoked,
            &super::crypto::AUTHENTICATED_ENVELOPE_MODE,
        ],
    )
    .await?;
    for entry in &policy.keys {
        let status_str = match entry.status {
            ManagedKeyStatus::Active => "active",
            ManagedKeyStatus::Retained => "retained",
            ManagedKeyStatus::Revoked => "revoked",
        };
        c.execute(
            "INSERT INTO pando_lab.kms_keys(repo,key_id,key_version,key_sha256,status,revoked_at) \
             VALUES($1,$2,$3,$4,$5,CASE WHEN $5='revoked' THEN now() ELSE NULL END) \
             ON CONFLICT(repo,key_id) DO UPDATE SET key_version=EXCLUDED.key_version,key_sha256=EXCLUDED.key_sha256,\
             status=EXCLUDED.status,revoked_at=CASE WHEN EXCLUDED.status='revoked' THEN COALESCE(pando_lab.kms_keys.revoked_at,now()) ELSE NULL END",
            &[&repo, &entry.key_id, &entry.key_version, &entry.sha256, &status_str],
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn persist_checkpoint(
    c: &Client,
    kms_dir: &Path,
    cp: &KmsRotationCheckpoint,
) -> Result<()> {
    let cp_val = serde_json::to_value(cp)?;
    c.execute(
        "INSERT INTO pando_lab.kms_rotations(id,repo,from_key_id,from_key_version,to_key_id,to_key_version,state,revoke_previous,total_packs,processed_packs,failed_pack_id,checkpoint_json) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
         ON CONFLICT(id) DO UPDATE SET state=EXCLUDED.state,revoke_previous=EXCLUDED.revoke_previous,\
         total_packs=EXCLUDED.total_packs,processed_packs=EXCLUDED.processed_packs,\
         failed_pack_id=EXCLUDED.failed_pack_id,checkpoint_json=EXCLUDED.checkpoint_json,updated_at=now()",
        &[
            &cp.rotation_id,
            &cp.repo,
            &cp.from_key_id,
            &cp.from_key_version,
            &cp.to_key_id,
            &cp.to_key_version,
            &cp.state,
            &cp.revoke_previous,
            &(cp.target_pack_ids.len() as i32),
            &(cp.completed_pack_ids.len() as i32),
            &cp.failed_pack_id,
            &cp_val,
        ],
    )
    .await?;
    let _ = write_private_json(&checkpoint_path(kms_dir), cp);
    Ok(())
}

pub async fn upsert_envelope_in_db(c: &Client, env: &KmsEnvelopeRecord) -> Result<()> {
    c.execute(
        "INSERT INTO pando_lab.kms_envelopes(repo,pack_id,key_id,key_version,cipher_suite,plaintext_sha256,envelope_mac,storage_tier,\
         encryption_mode,envelope_id,nonce_prefix,wrapped_key_json,ciphertext_sha256,ciphertext_bytes,provider_kind) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) \
         ON CONFLICT(repo,pack_id) DO UPDATE SET key_id=EXCLUDED.key_id,key_version=EXCLUDED.key_version,\
         cipher_suite=EXCLUDED.cipher_suite,plaintext_sha256=EXCLUDED.plaintext_sha256,envelope_mac=EXCLUDED.envelope_mac,\
         storage_tier=EXCLUDED.storage_tier,encryption_mode=EXCLUDED.encryption_mode,envelope_id=EXCLUDED.envelope_id,\
         nonce_prefix=EXCLUDED.nonce_prefix,wrapped_key_json=EXCLUDED.wrapped_key_json,\
         ciphertext_sha256=EXCLUDED.ciphertext_sha256,ciphertext_bytes=EXCLUDED.ciphertext_bytes,\
         provider_kind=EXCLUDED.provider_kind",
        &[
            &env.repo,
            &env.pack_id,
            &env.key_id,
            &env.key_version,
            &env.cipher_suite,
            &env.plaintext_sha256,
            &env.envelope_mac,
            &env.storage_tier,
            &env.encryption_mode,
            &env.envelope_id,
            &env.nonce_prefix,
            &env.wrapped_key_json,
            &env.ciphertext_sha256,
            &(env.ciphertext_bytes.map(|v| v as i64)),
            &env.provider_kind,
        ],
    )
    .await?;
    Ok(())
}

pub async fn load_envelope_from_db(
    c: &Client,
    repo: Uuid,
    pack: &Pack,
) -> Result<Option<KmsEnvelopeRecord>> {
    let row = c
        .query_opt(
            "SELECT key_id,key_version,cipher_suite,plaintext_sha256,envelope_mac,storage_tier,\
             encryption_mode,envelope_id,nonce_prefix,wrapped_key_json,ciphertext_sha256,ciphertext_bytes,provider_kind \
             FROM pando_lab.kms_envelopes WHERE repo=$1 AND pack_id=$2",
            &[&repo, &pack.id],
        )
        .await?;
    Ok(row.map(|r| KmsEnvelopeRecord {
        schema: ENVELOPE_SCHEMA.to_owned(),
        repo,
        pack_id: pack.id,
        key_id: r.get(0),
        key_version: r.get(1),
        cipher_suite: r.get(2),
        pack_sha256: pack.pack_sha256.clone(),
        idx_sha256: pack.idx_sha256.clone(),
        plaintext_sha256: r.get(3),
        envelope_mac: r.get(4),
        storage_tier: r.get(5),
        encryption_mode: r.get(6),
        envelope_id: r.get(7),
        nonce_prefix: r.get(8),
        wrapped_key_json: r.get(9),
        ciphertext_sha256: r.get(10),
        ciphertext_bytes: r.get::<_, Option<i64>>(11).map(|v| v as u64),
        provider_kind: r.get(12),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(state: &str, epoch: u64, target: i32, contract: &str) -> KmsRotationCheckpoint {
        KmsRotationCheckpoint {
            rotation_id: Uuid::new_v4(),
            repo: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            from_key_id: "pendo-vault-key".to_owned(),
            from_key_version: 3,
            to_key_id: "pendo-vault-key".to_owned(),
            to_key_version: target,
            state: state.to_owned(),
            revoke_previous: false,
            target_pack_ids: Vec::new(),
            completed_pack_ids: Vec::new(),
            failed_pack_id: None,
            from_provider_kind: super::super::provider::PROVIDER_KIND_VAULT.to_owned(),
            to_provider_kind: super::super::provider::PROVIDER_KIND_VAULT.to_owned(),
            expected_to_version: target,
            external_rotate_issued: false,
            reconcile_stage: super::super::rotation::KmsReconcileStage::TargetObserved,
            target_contract: contract.to_owned(),
            write_epoch: epoch,
        }
    }

    fn local_checkpoint(state: &str, epoch: u64, target: i32) -> KmsRotationCheckpoint {
        KmsRotationCheckpoint {
            rotation_id: Uuid::new_v4(),
            repo: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            from_key_id: "kms-local-a".to_owned(),
            from_key_version: 1,
            to_key_id: "kms-local-b".to_owned(),
            to_key_version: target,
            state: state.to_owned(),
            revoke_previous: false,
            target_pack_ids: Vec::new(),
            completed_pack_ids: Vec::new(),
            failed_pack_id: None,
            from_provider_kind: super::super::provider::PROVIDER_KIND_LOCAL.to_owned(),
            to_provider_kind: super::super::provider::PROVIDER_KIND_LOCAL.to_owned(),
            expected_to_version: target,
            external_rotate_issued: false,
            reconcile_stage: super::super::rotation::KmsReconcileStage::NotIssued,
            target_contract: String::new(),
            write_epoch: epoch,
        }
    }

    #[test]
    fn legacy_local_completed_epoch_zero_has_no_db_write_pin() {
        let repo = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let zero = local_checkpoint("COMPLETED", 0, 2);
        assert!(select_current_checkpoint(
            vec![("COMPLETED".to_owned(), serde_json::to_value(&zero).unwrap())],
            repo,
        )
        .unwrap()
        .is_none());
        let second = local_checkpoint("COMPLETED", 0, 3);
        assert!(select_current_checkpoint(
            vec![
                ("COMPLETED".to_owned(), serde_json::to_value(&zero).unwrap()),
                ("COMPLETED".to_owned(), serde_json::to_value(&second).unwrap()),
            ],
            repo,
        )
        .unwrap()
        .is_none());
        let active = local_checkpoint("IN_PROGRESS", 0, 4);
        assert!(select_current_checkpoint(
            vec![("IN_PROGRESS".to_owned(), serde_json::to_value(&active).unwrap())],
            repo,
        )
        .unwrap()
        .is_some());

        let positive = local_checkpoint("COMPLETED", 1, 5);
        let selected = select_current_checkpoint(
            vec![
                ("COMPLETED".to_owned(), serde_json::to_value(&zero).unwrap()),
                ("COMPLETED".to_owned(), serde_json::to_value(&positive).unwrap()),
            ],
            repo,
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.write_epoch, 1);
        assert_eq!(selected.expected_version(), 5);

        let vault_zero = checkpoint("COMPLETED", 0, 3, super::super::rotation::EXISTING_TARGET_CONTRACT);
        assert!(select_current_checkpoint(
            vec![("COMPLETED".to_owned(), serde_json::to_value(&vault_zero).unwrap())],
            repo,
        )
        .is_err());
    }

    #[test]
    fn completed_epoch_is_current_and_ambiguous_epochs_fail_closed() {
        let repo = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let contract = super::super::rotation::EXISTING_TARGET_CONTRACT;
        let old = checkpoint("COMPLETED", 1, 4, contract);
        let new = checkpoint("COMPLETED", 2, 5, contract);
        let selected = select_current_checkpoint(
            vec![
                ("COMPLETED".to_owned(), serde_json::to_value(&old).unwrap()),
                ("COMPLETED".to_owned(), serde_json::to_value(&new).unwrap()),
            ],
            repo,
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.write_epoch, 2);
        assert_eq!(selected.expected_version(), 5);

        let duplicate = checkpoint("COMPLETED", 2, 6, contract);
        assert!(select_current_checkpoint(
            vec![
                ("COMPLETED".to_owned(), serde_json::to_value(&new).unwrap()),
                ("COMPLETED".to_owned(), serde_json::to_value(&duplicate).unwrap()),
            ],
            repo,
        )
        .is_err());

        let invalid = checkpoint("COMPLETED", 2, 5, "");
        assert!(select_current_checkpoint(
            vec![("COMPLETED".to_owned(), serde_json::to_value(&invalid).unwrap())],
            repo,
        )
        .is_err());

        let first = checkpoint("IN_PROGRESS", 3, 6, contract);
        let second = checkpoint("IN_PROGRESS", 4, 7, contract);
        assert!(select_current_checkpoint(
            vec![
                ("IN_PROGRESS".to_owned(), serde_json::to_value(&first).unwrap()),
                ("IN_PROGRESS".to_owned(), serde_json::to_value(&second).unwrap()),
            ],
            repo,
        )
        .is_err());
    }
}
