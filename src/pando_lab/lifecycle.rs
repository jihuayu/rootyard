use super::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write,
};

pub const DEFAULT_MAX_ACTIVE_PACKS: i32 = 4;
pub const DEFAULT_COLD_TRANSITION_AGE_SECS: i64 = 86_400;
pub const DEFAULT_KMS_KEY_ID: &str = "kms-local-default-v1";
pub const DEFAULT_KMS_KEY_VERSION: i32 = 1;
pub const DEFAULT_CIPHER_SUITE: &str = "AES-256-GCM-HMAC-SHA256";
pub const ENVELOPE_SCHEMA: &str = "rootyard.pando.kms-envelope.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePolicy {
    pub repo: Uuid,
    pub max_active_packs: i32,
    pub cold_transition_age_secs: i64,
    pub auto_repack_enabled: bool,
    pub kms_key_id: String,
    pub kms_key_version: i32,
}

impl LifecyclePolicy {
    pub fn default_for_repo(repo: Uuid) -> Self {
        Self {
            repo,
            max_active_packs: DEFAULT_MAX_ACTIVE_PACKS,
            cold_transition_age_secs: DEFAULT_COLD_TRANSITION_AGE_SECS,
            auto_repack_enabled: true,
            kms_key_id: DEFAULT_KMS_KEY_ID.to_owned(),
            kms_key_version: DEFAULT_KMS_KEY_VERSION,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEvaluateOptions {
    #[serde(default)]
    pub max_active_packs: Option<i32>,
    #[serde(default)]
    pub cold_transition_age_secs: Option<i64>,
    #[serde(default)]
    pub auto_repack_enabled: Option<bool>,
    #[serde(default)]
    pub cold_evict_local: bool,
    #[serde(default)]
    pub kms_key_id: Option<String>,
    #[serde(default)]
    pub cipher_suite: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentationMetrics {
    pub active_packs: usize,
    pub total_pack_bytes: u64,
    pub total_idx_bytes: u64,
    pub total_objects_across_packs: usize,
    pub unique_objects: usize,
    pub duplicate_objects: usize,
    pub duplicate_object_ratio: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsEnvelopeRecord {
    pub schema: String,
    pub repo: Uuid,
    pub pack_id: Uuid,
    pub key_id: String,
    pub key_version: i32,
    pub cipher_suite: String,
    pub pack_sha256: String,
    pub idx_sha256: String,
    pub plaintext_sha256: String,
    pub envelope_mac: String,
    pub storage_tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEvaluationReport {
    pub repo: Uuid,
    pub policy: LifecyclePolicy,
    pub fragmentation_before: FragmentationMetrics,
    pub fragmentation_after: FragmentationMetrics,
    pub compaction_triggered: bool,
    pub repack_report: Option<repack::RepackReport>,
    pub envelopes_recorded: usize,
    pub cold_archive_packs: usize,
    pub local_packs_evicted: usize,
    pub envelopes: Vec<KmsEnvelopeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsRotationReport {
    pub repo: Uuid,
    pub previous_key_id: String,
    pub previous_key_version: i32,
    pub new_key_id: String,
    pub new_key_version: i32,
    pub envelopes_rewrapped: usize,
    pub envelopes_verified: usize,
    pub envelopes: Vec<KmsEnvelopeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStatusReport {
    pub repo: Uuid,
    pub policy: LifecyclePolicy,
    pub fragmentation: FragmentationMetrics,
    pub envelopes: Vec<KmsEnvelopeRecord>,
    pub hot_packs: usize,
    pub cold_archive_packs: usize,
    pub all_envelopes_verified: bool,
}

pub fn valid_kms_key_id(key_id: &str) -> bool {
    let t = key_id.trim();
    t.len() >= 3 && t.len() <= 128
}
pub fn valid_cipher_suite(suite: &str) -> bool {
    matches!(suite, "AES-256-GCM-HMAC-SHA256" | "CHACHA20-POLY1305-SHA256")
}
pub fn valid_storage_tier(tier: &str) -> bool {
    matches!(tier, "hot" | "cold_archive")
}
pub fn valid_sha256_hex(hex_str: &str) -> bool {
    hex_str.len() == 64 && hex_str.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn compute_envelope_mac(key_id: &str, key_version: i32, pack_sha256: &str, idx_sha256: &str) -> Result<String> {
    let trimmed = key_id.trim();
    ensure!(valid_kms_key_id(trimmed) && key_version >= 1, "invalid kms key parameters");
    ensure!(valid_sha256_hex(pack_sha256) && valid_sha256_hex(idx_sha256), "invalid pack/idx sha256");
    Ok(delta::sha256_hex(format!("{trimmed}||{key_version}||{pack_sha256}||{idx_sha256}").as_bytes()))
}

pub fn build_envelope_record(
    repo: Uuid,
    pack: &Pack,
    key_id: &str,
    key_version: i32,
    cipher_suite: &str,
    storage_tier: &str,
) -> Result<KmsEnvelopeRecord> {
    let trimmed = key_id.trim();
    ensure!(valid_kms_key_id(trimmed) && valid_cipher_suite(cipher_suite) && valid_storage_tier(storage_tier), "invalid envelope parameters");
    let envelope_mac = compute_envelope_mac(trimmed, key_version, &pack.pack_sha256, &pack.idx_sha256)?;
    Ok(KmsEnvelopeRecord {
        schema: ENVELOPE_SCHEMA.to_owned(),
        repo,
        pack_id: pack.id,
        key_id: trimmed.to_owned(),
        key_version,
        cipher_suite: cipher_suite.to_owned(),
        pack_sha256: pack.pack_sha256.clone(),
        idx_sha256: pack.idx_sha256.clone(),
        plaintext_sha256: pack.pack_sha256.clone(),
        envelope_mac,
        storage_tier: storage_tier.to_owned(),
    })
}

pub fn verify_envelope_record(env: &KmsEnvelopeRecord) -> Result<()> {
    ensure!(
        env.schema == ENVELOPE_SCHEMA
            && valid_kms_key_id(&env.key_id)
            && env.key_version >= 1
            && valid_cipher_suite(&env.cipher_suite)
            && valid_storage_tier(&env.storage_tier)
            && env.plaintext_sha256 == env.pack_sha256,
        "invalid KMS envelope fields"
    );
    let expected = compute_envelope_mac(&env.key_id, env.key_version, &env.pack_sha256, &env.idx_sha256)?;
    ensure!(env.envelope_mac == expected, "KMS envelope MAC verification failed for pack {}", env.pack_id);
    Ok(())
}

pub fn envelope_file_path(root: &Path, repo: Uuid, pack_id: Uuid) -> PathBuf {
    root.join("object_store").join("envelopes").join(repo.to_string()).join(format!("{pack_id}.json"))
}

pub fn write_envelope_file(root: &Path, env: &KmsEnvelopeRecord) -> Result<PathBuf> {
    verify_envelope_record(env)?;
    let path = envelope_file_path(root, env.repo, env.pack_id);
    let parent = path.parent().context("missing envelope parent directory")?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".env-tmp-{}", Uuid::new_v4()));
    let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(env)?)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, &path)?;
    File::open(parent)?.sync_all()?;
    Ok(path)
}

pub fn read_and_verify_envelope_file(root: &Path, repo: Uuid, pack_id: Uuid) -> Result<KmsEnvelopeRecord> {
    let path = envelope_file_path(root, repo, pack_id);
    ensure!(path.is_file(), "missing KMS envelope file for pack {pack_id}");
    let env: KmsEnvelopeRecord = serde_json::from_slice(&std::fs::read(&path)?)?;
    ensure!(env.repo == repo && env.pack_id == pack_id, "KMS envelope repo/pack_id mismatch");
    verify_envelope_record(&env)?;
    Ok(env)
}

pub fn compute_fragmentation_metrics(root: &Path, store_root_dir: &Path, repo: Uuid, packs: &[Pack]) -> Result<FragmentationMetrics> {
    let objects_root = root.join("objects");
    let bucket = object_store::default_bucket();
    let (mut total_pack_bytes, mut total_idx_bytes, mut total_objs) = (0u64, 0u64, 0usize);
    let mut unique_oids = BTreeSet::new();
    for pack in packs {
        object_store::get_pack_files(store_root_dir, &objects_root, &bucket, repo, pack.id, Some(&pack.pack_sha256), Some(&pack.idx_sha256))?;
        let pfx = objects_root.join(repo.to_string()).join(pack.id.to_string());
        let (pb, ib) = (std::fs::read(pfx.with_extension("pack"))?, std::fs::read(pfx.with_extension("idx"))?);
        total_pack_bytes += pb.len() as u64;
        total_idx_bytes += ib.len() as u64;
        let rep = delta::verify_pack(&pb, &delta::Limits::default())?;
        total_objs += rep.object_count;
        unique_oids.extend(rep.objects.into_iter().map(|o| o.oid));
    }
    let unique_objects = unique_oids.len();
    let duplicate_objects = total_objs.saturating_sub(unique_objects);
    let duplicate_object_ratio = if total_objs == 0 { 0.0 } else { (duplicate_objects as f64) / (total_objs as f64) };
    Ok(FragmentationMetrics { active_packs: packs.len(), total_pack_bytes, total_idx_bytes, total_objects_across_packs: total_objs, unique_objects, duplicate_objects, duplicate_object_ratio })
}

pub fn evict_cold_pack_local(root: &Path, store_root_dir: &Path, repo: Uuid, pack: &Pack) -> Result<bool> {
    let env = read_and_verify_envelope_file(root, repo, pack.id)?;
    ensure!(env.storage_tier == "cold_archive" && env.pack_sha256 == pack.pack_sha256 && env.idx_sha256 == pack.idx_sha256, "pack not eligible for cold eviction");
    ensure!(store_root_dir.join(object_store::manifest_key(repo, pack.id)).is_file(), "remote object-store manifest required before evicting local pack");
    let repo_dir = root.join("objects").join(repo.to_string());
    let (local_idx, local_pack) = (repo_dir.join(format!("{}.idx", pack.id)), repo_dir.join(format!("{}.pack", pack.id)));
    ensure!(local_idx.is_file() && delta::sha256_hex(&std::fs::read(&local_idx)?) == pack.idx_sha256, "local .idx missing or corrupt for cold pack");
    if local_pack.is_file() {
        std::fs::remove_file(&local_pack)?;
        File::open(&repo_dir)?.sync_all()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn hydrate_cold_pack_verified(root: &Path, store_root_dir: &Path, bucket: &str, repo: Uuid, pack: &Pack) -> Result<object_store::ObjectStoreGetReport> {
    let env = read_and_verify_envelope_file(root, repo, pack.id)?;
    ensure!(env.pack_sha256 == pack.pack_sha256 && env.idx_sha256 == pack.idx_sha256, "KMS envelope digest mismatch against pack manifest");
    let local_idx = root.join("objects").join(repo.to_string()).join(format!("{}.idx", pack.id));
    ensure!(local_idx.is_file() && delta::sha256_hex(&std::fs::read(&local_idx)?) == pack.idx_sha256, "local .idx missing or corrupt before cold pack hydration");
    object_store::get_pack_files(store_root_dir, &root.join("objects"), bucket, repo, pack.id, Some(&pack.pack_sha256), Some(&pack.idx_sha256))
}

async fn load_repo_packs(c: &Client, repo: Uuid) -> Result<Vec<Pack>> {
    Ok(c.query("SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 ORDER BY pack_id", &[&repo]).await?
        .into_iter().map(|r| Pack { id: r.get(0), pack_sha256: r.get(1), idx_sha256: r.get(2) }).collect())
}

pub(super) async fn evaluate_lifecycle(config: &Config, repo: Uuid, opts: &LifecycleEvaluateOptions) -> Result<LifecycleEvaluationReport> {
    if let Some(m) = opts.max_active_packs { ensure!((1..=1000).contains(&m), "max_active_packs must be within 1..=1000"); }
    if let Some(age) = opts.cold_transition_age_secs { ensure!(age >= 0, "cold_transition_age_secs must be >= 0"); }
    if let Some(ref k) = opts.kms_key_id { ensure!(valid_kms_key_id(k), "invalid kms_key_id"); }
    let suite = opts.cipher_suite.as_deref().unwrap_or(DEFAULT_CIPHER_SUITE);
    ensure!(valid_cipher_suite(suite), "invalid cipher_suite");

    let c = config.db().await?;
    let meta = c.query_one("SELECT storage_backend,write_paused FROM pando_lab.repositories WHERE id=$1", &[&repo]).await?;
    ensure!(!meta.get::<_, bool>(1) && meta.get::<_, String>(0) == "pando", "lifecycle evaluation requires active pando repository");

    c.execute("INSERT INTO pando_lab.lifecycle_policies(repo) VALUES($1) ON CONFLICT(repo) DO NOTHING", &[&repo]).await?;
    let cur = c.query_one("SELECT max_active_packs,cold_transition_age_secs,auto_repack_enabled,kms_key_id,kms_key_version FROM pando_lab.lifecycle_policies WHERE repo=$1", &[&repo]).await?;
    let mut policy = LifecyclePolicy {
        repo,
        max_active_packs: opts.max_active_packs.unwrap_or_else(|| cur.get(0)),
        cold_transition_age_secs: opts.cold_transition_age_secs.unwrap_or_else(|| cur.get(1)),
        auto_repack_enabled: opts.auto_repack_enabled.unwrap_or_else(|| cur.get(2)),
        kms_key_id: opts.kms_key_id.as_ref().map(|s| s.trim().to_owned()).unwrap_or_else(|| cur.get(3)),
        kms_key_version: cur.get(4),
    };
    if opts.kms_key_id.as_ref().is_some_and(|k| k.trim() != cur.get::<_, String>(3)) { policy.kms_key_version += 1; }
    c.execute(
        "UPDATE pando_lab.lifecycle_policies SET max_active_packs=$2,cold_transition_age_secs=$3,auto_repack_enabled=$4,kms_key_id=$5,kms_key_version=$6,updated_at=now() WHERE repo=$1",
        &[&repo, &policy.max_active_packs, &policy.cold_transition_age_secs, &policy.auto_repack_enabled, &policy.kms_key_id, &policy.kms_key_version],
    ).await?;

    let s_root = object_store::store_root(config);
    let packs_before = load_repo_packs(&c, repo).await?;
    let fragmentation_before = compute_fragmentation_metrics(&config.root, &s_root, repo, &packs_before)?;

    let (compaction_triggered, repack_report) = if policy.auto_repack_enabled && (packs_before.len() as i32) > policy.max_active_packs {
        let rep = repack::repack_repo(config, repo, &repack::RepackOptions { prune_superseded: true, pin_oids: Vec::new(), sync_object_store: true }).await?;
        (true, Some(rep))
    } else {
        (false, None)
    };

    let packs_after = load_repo_packs(&c, repo).await?;
    let fragmentation_after = compute_fragmentation_metrics(&config.root, &s_root, repo, &packs_after)?;
    let active_ids: Vec<Uuid> = packs_after.iter().map(|p| p.id).collect();
    c.execute("DELETE FROM pando_lab.kms_envelopes WHERE repo=$1 AND NOT (pack_id = ANY($2))", &[&repo, &active_ids]).await?;

    let tier = if opts.cold_evict_local || policy.cold_transition_age_secs == 0 { "cold_archive" } else { "hot" };
    let (mut envelopes, mut cold_count, mut evicted_count) = (Vec::new(), 0usize, 0usize);
    for pack in &packs_after {
        if !s_root.join(object_store::manifest_key(repo, pack.id)).is_file() {
            object_store::put_pack(config, repo, pack.id, &object_store::ObjectStorePutOptions::default()).await?;
        }
        let env = build_envelope_record(repo, pack, &policy.kms_key_id, policy.kms_key_version, suite, tier)?;
        c.execute(
            "INSERT INTO pando_lab.kms_envelopes(repo,pack_id,key_id,key_version,cipher_suite,plaintext_sha256,envelope_mac,storage_tier) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(repo,pack_id) DO UPDATE SET key_id=EXCLUDED.key_id,key_version=EXCLUDED.key_version,cipher_suite=EXCLUDED.cipher_suite,plaintext_sha256=EXCLUDED.plaintext_sha256,envelope_mac=EXCLUDED.envelope_mac,storage_tier=EXCLUDED.storage_tier",
            &[&repo, &pack.id, &env.key_id, &env.key_version, &env.cipher_suite, &env.plaintext_sha256, &env.envelope_mac, &env.storage_tier],
        ).await?;
        write_envelope_file(&config.root, &env)?;
        if tier == "cold_archive" {
            cold_count += 1;
            if opts.cold_evict_local && evict_cold_pack_local(&config.root, &s_root, repo, pack)? { evicted_count += 1; }
        }
        envelopes.push(env);
    }

    Ok(LifecycleEvaluationReport { repo, policy, fragmentation_before, fragmentation_after, compaction_triggered, repack_report, envelopes_recorded: envelopes.len(), cold_archive_packs: cold_count, local_packs_evicted: evicted_count, envelopes })
}

pub(super) async fn rotate_kms_key(config: &Config, repo: Uuid, new_key_id: &str) -> Result<KmsRotationReport> {
    let trimmed = new_key_id.trim();
    ensure!(valid_kms_key_id(trimmed), "invalid kms_key_id '{new_key_id}'");
    let c = config.db().await?;
    c.execute("INSERT INTO pando_lab.lifecycle_policies(repo) VALUES($1) ON CONFLICT(repo) DO NOTHING", &[&repo]).await?;
    let row = c.query_one("SELECT kms_key_id,kms_key_version FROM pando_lab.lifecycle_policies WHERE repo=$1", &[&repo]).await?;
    let (prev_key_id, prev_ver): (String, i32) = (row.get(0), row.get(1));
    let new_ver = prev_ver + 1;
    let packs = load_repo_packs(&c, repo).await?;
    let mut envelopes = Vec::with_capacity(packs.len());
    for pack in &packs {
        if envelope_file_path(&config.root, repo, pack.id).is_file() {
            read_and_verify_envelope_file(&config.root, repo, pack.id)?;
        }
        let existing = c.query_opt("SELECT cipher_suite,storage_tier FROM pando_lab.kms_envelopes WHERE repo=$1 AND pack_id=$2", &[&repo, &pack.id]).await?;
        let (suite, tier) = match existing {
            Some(r) => (r.get::<_, String>(0), r.get::<_, String>(1)),
            None => (DEFAULT_CIPHER_SUITE.to_owned(), "hot".to_owned()),
        };
        let env = build_envelope_record(repo, pack, trimmed, new_ver, &suite, &tier)?;
        c.execute(
            "INSERT INTO pando_lab.kms_envelopes(repo,pack_id,key_id,key_version,cipher_suite,plaintext_sha256,envelope_mac,storage_tier) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(repo,pack_id) DO UPDATE SET key_id=EXCLUDED.key_id,key_version=EXCLUDED.key_version,envelope_mac=EXCLUDED.envelope_mac",
            &[&repo, &pack.id, &env.key_id, &env.key_version, &env.cipher_suite, &env.plaintext_sha256, &env.envelope_mac, &env.storage_tier],
        ).await?;
        write_envelope_file(&config.root, &env)?;
        read_and_verify_envelope_file(&config.root, repo, pack.id)?;
        envelopes.push(env);
    }
    c.execute("UPDATE pando_lab.lifecycle_policies SET kms_key_id=$2,kms_key_version=$3,updated_at=now() WHERE repo=$1", &[&repo, &trimmed, &new_ver]).await?;
    Ok(KmsRotationReport { repo, previous_key_id: prev_key_id, previous_key_version: prev_ver, new_key_id: trimmed.to_owned(), new_key_version: new_ver, envelopes_rewrapped: envelopes.len(), envelopes_verified: envelopes.len(), envelopes })
}

pub(super) async fn status(config: &Config, repo: Uuid) -> Result<LifecycleStatusReport> {
    let c = config.db().await?;
    c.execute("INSERT INTO pando_lab.lifecycle_policies(repo) VALUES($1) ON CONFLICT(repo) DO NOTHING", &[&repo]).await?;
    let p = c.query_one("SELECT max_active_packs,cold_transition_age_secs,auto_repack_enabled,kms_key_id,kms_key_version FROM pando_lab.lifecycle_policies WHERE repo=$1", &[&repo]).await?;
    let policy = LifecyclePolicy { repo, max_active_packs: p.get(0), cold_transition_age_secs: p.get(1), auto_repack_enabled: p.get(2), kms_key_id: p.get(3), kms_key_version: p.get(4) };
    let packs = load_repo_packs(&c, repo).await?;
    let fragmentation = compute_fragmentation_metrics(&config.root, &object_store::store_root(config), repo, &packs)?;
    let (mut envelopes, mut hot_packs, mut cold_packs, mut all_verified) = (Vec::new(), 0usize, 0usize, true);
    for pack in &packs {
        if let Some(r) = c.query_opt("SELECT key_id,key_version,cipher_suite,plaintext_sha256,envelope_mac,storage_tier FROM pando_lab.kms_envelopes WHERE repo=$1 AND pack_id=$2", &[&repo, &pack.id]).await? {
            let env = KmsEnvelopeRecord {
                schema: ENVELOPE_SCHEMA.to_owned(), repo, pack_id: pack.id, key_id: r.get(0), key_version: r.get(1),
                cipher_suite: r.get(2), pack_sha256: pack.pack_sha256.clone(), idx_sha256: pack.idx_sha256.clone(),
                plaintext_sha256: r.get(3), envelope_mac: r.get(4), storage_tier: r.get(5),
            };
            if verify_envelope_record(&env).is_err() { all_verified = false; }
            if env.storage_tier == "cold_archive" { cold_packs += 1; } else { hot_packs += 1; }
            envelopes.push(env);
        }
    }
    Ok(LifecycleStatusReport { repo, policy, fragmentation, envelopes, hot_packs, cold_archive_packs: cold_packs, all_envelopes_verified: all_verified })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelope_mac_cold_eviction_hydration_and_tamper_rejection() {
        let tmp = std::env::temp_dir().join(format!("pando-lifecycle-test-{}", Uuid::new_v4()));
        let objects_root = tmp.join("objects");
        let (repo, pack_id) = (Uuid::new_v4(), Uuid::new_v4());
        let dir = objects_root.join(repo.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let mut pack_bytes = Vec::from(&b"PACK\x00\x00\x00\x02\x00\x00\x00\x01\x34"[..]);
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"test").unwrap();
        pack_bytes.extend_from_slice(&enc.finish().unwrap());
        let tr = delta::sha1_digest(&pack_bytes);
        pack_bytes.extend_from_slice(&tr);
        let idx_bytes = b"idx-cold-tier-test".to_vec();
        std::fs::write(dir.join(format!("{pack_id}.pack")), &pack_bytes).unwrap();
        std::fs::write(dir.join(format!("{pack_id}.idx")), &idx_bytes).unwrap();

        let pack = Pack { id: pack_id, pack_sha256: delta::sha256_hex(&pack_bytes), idx_sha256: delta::sha256_hex(&idx_bytes) };
        object_store::put_pack_files(&tmp, &objects_root, repo, pack_id, &Default::default()).unwrap();
        let frag = compute_fragmentation_metrics(&tmp, &tmp, repo, &[pack.clone(), pack.clone()]).unwrap();
        assert_eq!(frag.active_packs, 2);
        assert_eq!(frag.duplicate_objects, 1);

        let env = build_envelope_record(repo, &pack, "kms-test-key-v1", 1, DEFAULT_CIPHER_SUITE, "cold_archive").unwrap();
        write_envelope_file(&tmp, &env).unwrap();
        assert!(evict_cold_pack_local(&tmp, &tmp, repo, &pack).unwrap());
        assert!(!dir.join(format!("{pack_id}.pack")).exists() && dir.join(format!("{pack_id}.idx")).exists());

        let hydrated = hydrate_cold_pack_verified(&tmp, &tmp, "pando-default", repo, &pack).unwrap();
        assert!(hydrated.rehydrated_from_object_store && dir.join(format!("{pack_id}.pack")).exists());

        let mut tampered = env.clone();
        tampered.envelope_mac = "0".repeat(64);
        std::fs::write(envelope_file_path(&tmp, repo, pack_id), serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(hydrate_cold_pack_verified(&tmp, &tmp, "pando-default", repo, &pack).is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
