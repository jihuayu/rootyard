//! Independent multi-voter Ed25519 Ref-CAS cutpoint attestation and HTTP quorum client (#122).
//!
//! A worker never holds voter private keys. Each independent voter seals its own
//! [`VoterCutpointAttestation`] over the exact committed `RefCasSnapshot` bytes it replayed
//! from its own Raft replica, and the worker only aggregates pinned public-key signatures.

use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{AppliedLogId, RefCasSnapshot, RefCasStateMachine};

use super::super::model::{encode_len_bytes, validate_sha256_hex};
use super::super::voter_service::{
    build_mtls_client_config,
    tls::{load_private_bearer_token, request_voter_https},
};
use super::{SafeGcEd25519Signer, SafeGcError, validate_ed25519_pubkey_hex, verify_ed25519_domain};

/// Canonical domain separating independent voter cutpoint transcripts from every other digest.
pub(super) const VOTER_CUTPOINT_DOMAIN: &[u8] = b"rootyard/safe-gc-independent-voter-cutpoint/v1";

const MAX_VOTER_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_VOTER_ENDPOINT_BYTES: usize = 2_048;

/// One independently operated consensus voter pinned by the repository trust bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedConsensusVoter {
    pub voter_id: u64,
    pub key_id: u8,
    pub ed25519_pubkey_hex: String,
    pub endpoint_url: String,
}

/// Ed25519 signature produced by one voter over its committed cutpoint transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoterCutpointSignature {
    pub voter_id: u64,
    pub key_id: u8,
    pub voter_pubkey_hex: String,
    pub signature_hex: String,
}

/// Independently committed cutpoint plus the voter's own Ed25519 authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoterCutpointAttestation {
    pub group_id: i64,
    pub history_incarnation: Uuid,
    pub group_epoch: i64,
    pub authority_epoch: i64,
    pub raft_term: u64,
    pub committed_log_index: u64,
    pub raft_commit_digest_hex: String,
    pub snapshot_sha256: String,
    pub snapshot_bytes: Vec<u8>,
    pub signature: VoterCutpointSignature,
}

/// Identity and committed-coordinate claims a single voter signs.
#[derive(Clone, Debug)]
pub struct VoterCutpointClaims {
    pub voter_id: u64,
    pub key_id: u8,
    pub group_id: i64,
    pub history_incarnation: Uuid,
    pub group_epoch: i64,
    pub authority_epoch: i64,
    pub raft_term: u64,
    pub committed_log_index: u64,
    pub raft_commit_digest_hex: String,
}

/// Canonical transcript shared by voter signing and worker quorum verification.
pub(super) fn voter_cutpoint_transcript(
    group_id: i64,
    history_incarnation: Uuid,
    group_epoch: i64,
    authority_epoch: i64,
    raft_term: u64,
    committed_log_index: u64,
    voter_id: u64,
    key_id: u8,
    raft_commit_digest_hex: &str,
    snapshot_sha256: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VOTER_CUTPOINT_DOMAIN);
    hasher.update([0]);
    hasher.update(group_id.to_be_bytes());
    hasher.update(history_incarnation.as_bytes());
    hasher.update(group_epoch.to_be_bytes());
    hasher.update(authority_epoch.to_be_bytes());
    hasher.update(raft_term.to_be_bytes());
    hasher.update(committed_log_index.to_be_bytes());
    hasher.update(voter_id.to_be_bytes());
    hasher.update([key_id]);
    encode_len_bytes(&mut hasher, raft_commit_digest_hex.as_bytes());
    encode_len_bytes(&mut hasher, snapshot_sha256.as_bytes());
    hasher.finalize().into()
}

fn missing(reason: &'static str) -> SafeGcError {
    SafeGcError::DistributedPrereqsMissing(reason)
}

fn rejected(reason: &'static str) -> SafeGcError {
    SafeGcError::ArmingRejected(reason)
}

/// Validate one independently pinned voter before it enters a repository trust bundle.
pub fn validate_trusted_voter(voter: &TrustedConsensusVoter, arm_pubkey_hex: &str) -> Result<(), SafeGcError> {
    if voter.voter_id == 0 {
        return Err(rejected("trusted consensus voter_id must be non-zero"));
    }
    if validate_ed25519_pubkey_hex(&voter.ed25519_pubkey_hex).is_err() || voter.ed25519_pubkey_hex == arm_pubkey_hex {
        return Err(rejected("trusted consensus voter must use an external distinct Ed25519 public key"));
    }
    let endpoint = voter.endpoint_url.as_bytes();
    if endpoint.is_empty()
        || endpoint.len() > MAX_VOTER_ENDPOINT_BYTES
        || !voter.endpoint_url.starts_with("https://")
        || endpoint.iter().any(|b| b.is_ascii_whitespace() || *b == 0)
    {
        return Err(rejected("trusted consensus voter endpoint_url must be an https:// mTLS URL"));
    }
    Ok(())
}

fn gate_matches(
    snapshot: &RefCasSnapshot,
    history_id: Uuid,
    group_epoch: i64,
    authority_epoch: i64,
) -> Option<&crate::ref_store::core::state_machine::GateState> {
    snapshot.body.gates.iter().find(|gate| {
        gate.history_incarnation == history_id
            && gate.group_epoch == group_epoch
            && gate.authority_epoch == authority_epoch
    })
}

/// Sign one voter's independent cutpoint attestation over the exact snapshot bytes.
pub fn sign_single_voter_cutpoint_attestation(
    voter_signer: &SafeGcEd25519Signer,
    claims: &VoterCutpointClaims,
    snapshot: &RefCasSnapshot,
) -> Result<VoterCutpointAttestation, SafeGcError> {
    if claims.voter_id == 0
        || claims.group_id < 0
        || claims.history_incarnation.is_nil()
        || claims.group_epoch <= 0
        || claims.authority_epoch <= 0
        || claims.raft_term == 0
        || claims.committed_log_index == 0
    {
        return Err(missing("independent voter cutpoint claims are invalid"));
    }
    validate_sha256_hex(&claims.raft_commit_digest_hex)
        .map_err(|_| missing("independent voter committed Raft digest is invalid"))?;
    snapshot.verify_integrity().map_err(|_| missing("independent voter snapshot checksum mismatch"))?;
    if snapshot.body.last_applied != Some(AppliedLogId { term: claims.raft_term, index: claims.committed_log_index }) {
        return Err(missing("independent voter snapshot applied coordinate disagrees with its claims"));
    }
    if gate_matches(snapshot, claims.history_incarnation, claims.group_epoch, claims.authority_epoch).is_none() {
        return Err(missing("independent voter snapshot does not contain the claimed repository gate"));
    }
    let snapshot_bytes =
        serde_json::to_vec(snapshot).map_err(|_| missing("independent voter snapshot encoding failed"))?;
    if snapshot_bytes.is_empty() || snapshot_bytes.len() > MAX_VOTER_SNAPSHOT_BYTES {
        return Err(missing("independent voter snapshot size out of bounds"));
    }
    let snapshot_sha256 = hex::encode(Sha256::digest(&snapshot_bytes));
    let transcript = voter_cutpoint_transcript(
        claims.group_id,
        claims.history_incarnation,
        claims.group_epoch,
        claims.authority_epoch,
        claims.raft_term,
        claims.committed_log_index,
        claims.voter_id,
        claims.key_id,
        &claims.raft_commit_digest_hex,
        &snapshot_sha256,
    );
    Ok(VoterCutpointAttestation {
        group_id: claims.group_id,
        history_incarnation: claims.history_incarnation,
        group_epoch: claims.group_epoch,
        authority_epoch: claims.authority_epoch,
        raft_term: claims.raft_term,
        committed_log_index: claims.committed_log_index,
        raft_commit_digest_hex: claims.raft_commit_digest_hex.clone(),
        snapshot_sha256,
        snapshot_bytes,
        signature: VoterCutpointSignature {
            voter_id: claims.voter_id,
            key_id: claims.key_id,
            voter_pubkey_hex: voter_signer.pubkey_hex().to_owned(),
            signature_hex: voter_signer.sign_domain(VOTER_CUTPOINT_DOMAIN, &transcript),
        },
    })
}

/// Verify one attestation against its pinned voter key and the expected repository binding.
pub fn verify_single_voter_cutpoint_attestation(
    trusted: &TrustedConsensusVoter,
    repo_id: Uuid,
    tenant_id: Uuid,
    history_id: Uuid,
    attestation: &VoterCutpointAttestation,
) -> Result<RefCasSnapshot, SafeGcError> {
    if repo_id.is_nil()
        || tenant_id.is_nil()
        || history_id.is_nil()
        || attestation.group_id < 0
        || attestation.history_incarnation != history_id
        || attestation.group_epoch <= 0
        || attestation.authority_epoch <= 0
        || attestation.raft_term == 0
        || attestation.committed_log_index == 0
    {
        return Err(missing("independent voter cutpoint identity or history does not match the repository"));
    }
    if attestation.signature.voter_id != trusted.voter_id
        || attestation.signature.key_id != trusted.key_id
        || attestation.signature.voter_pubkey_hex != trusted.ed25519_pubkey_hex
    {
        return Err(missing("independent voter attestation is not signed by the pinned trusted voter"));
    }
    validate_sha256_hex(&attestation.raft_commit_digest_hex)
        .map_err(|_| missing("independent voter committed Raft digest is invalid"))?;
    validate_sha256_hex(&attestation.snapshot_sha256)
        .map_err(|_| missing("independent voter snapshot digest is invalid"))?;
    if attestation.snapshot_bytes.is_empty() || attestation.snapshot_bytes.len() > MAX_VOTER_SNAPSHOT_BYTES {
        return Err(missing("independent voter snapshot size out of bounds"));
    }
    if hex::encode(Sha256::digest(&attestation.snapshot_bytes)) != attestation.snapshot_sha256 {
        return Err(missing("independent voter snapshot bytes disagree with their SHA-256 digest"));
    }
    let transcript = voter_cutpoint_transcript(
        attestation.group_id,
        attestation.history_incarnation,
        attestation.group_epoch,
        attestation.authority_epoch,
        attestation.raft_term,
        attestation.committed_log_index,
        attestation.signature.voter_id,
        attestation.signature.key_id,
        &attestation.raft_commit_digest_hex,
        &attestation.snapshot_sha256,
    );
    verify_ed25519_domain(
        &attestation.signature.voter_pubkey_hex,
        VOTER_CUTPOINT_DOMAIN,
        &transcript,
        &attestation.signature.signature_hex,
    )
    .map_err(|_| missing("independent voter cutpoint Ed25519 signature rejected"))?;
    let snapshot: RefCasSnapshot = serde_json::from_slice(&attestation.snapshot_bytes)
        .map_err(|_| missing("independent voter snapshot bytes are not canonical JSON"))?;
    snapshot.verify_integrity().map_err(|_| missing("independent voter snapshot checksum mismatch"))?;
    if snapshot.body.last_applied
        != Some(AppliedLogId { term: attestation.raft_term, index: attestation.committed_log_index })
    {
        return Err(missing("independent voter snapshot applied coordinate disagrees with its attestation"));
    }
    let gate =
        gate_matches(&snapshot, attestation.history_incarnation, attestation.group_epoch, attestation.authority_epoch)
            .ok_or_else(|| missing("independent voter snapshot does not contain the claimed repository gate"))?;
    if gate.repository_id != repo_id || gate.tenant_id != tenant_id {
        return Err(missing("independent voter snapshot gate is bound to a different repository or tenant"));
    }
    Ok(snapshot)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CutpointCoordinate {
    group_id: i64,
    history_incarnation: Uuid,
    group_epoch: i64,
    authority_epoch: i64,
    raft_term: u64,
    committed_log_index: u64,
    raft_commit_digest_hex: String,
    snapshot_sha256: String,
}

struct VerifiedCandidate {
    snapshot: RefCasSnapshot,
    signatures: Vec<VoterCutpointSignature>,
}

/// Aggregate independent voter attestations into one threshold-authorized committed cutpoint.
pub fn verify_quorum_voter_attestations(
    trust: &super::SafeGcRepoTrustConfig,
    repo_id: Uuid,
    attestations: &[VoterCutpointAttestation],
) -> Result<(i64, RefCasStateMachine, super::QuorumCommitEvidence), SafeGcError> {
    let voters = &trust.trusted_consensus_voters;
    let threshold =
        trust.quorum_threshold.ok_or_else(|| missing("repository trust has no independent voter quorum threshold"))?;
    if voters.is_empty() || threshold < 2 || threshold < (voters.len() / 2) + 1 || threshold > voters.len() {
        return Err(missing("repository trust independent voter threshold is not a strict majority"));
    }
    let mut candidates: BTreeMap<CutpointCoordinate, VerifiedCandidate> = BTreeMap::new();
    for attestation in attestations {
        let Some(trusted) = voters.iter().find(|voter| voter.voter_id == attestation.signature.voter_id) else {
            continue;
        };
        if trusted.key_id != attestation.signature.key_id {
            continue;
        }
        let coordinate = CutpointCoordinate {
            group_id: attestation.group_id,
            history_incarnation: attestation.history_incarnation,
            group_epoch: attestation.group_epoch,
            authority_epoch: attestation.authority_epoch,
            raft_term: attestation.raft_term,
            committed_log_index: attestation.committed_log_index,
            raft_commit_digest_hex: attestation.raft_commit_digest_hex.clone(),
            snapshot_sha256: attestation.snapshot_sha256.clone(),
        };
        if candidates
            .get(&coordinate)
            .is_some_and(|candidate| candidate.signatures.iter().any(|s| s.voter_id == trusted.voter_id))
        {
            continue;
        }
        let Ok(snapshot) =
            verify_single_voter_cutpoint_attestation(trusted, repo_id, trust.tenant_id, trust.history_id, attestation)
        else {
            continue;
        };
        candidates
            .entry(coordinate)
            .or_insert_with(|| VerifiedCandidate { snapshot, signatures: Vec::new() })
            .signatures
            .push(attestation.signature.clone());
    }
    let mut authorized: Vec<(CutpointCoordinate, VerifiedCandidate)> =
        candidates.into_iter().filter(|(_, candidate)| candidate.signatures.len() >= threshold).collect();
    authorized.sort_by_key(|(coordinate, _)| (coordinate.raft_term, coordinate.committed_log_index));
    let Some((coordinate, mut candidate)) = authorized.pop() else {
        return Err(missing("independent voter attestations never reach the trusted quorum threshold"));
    };
    candidate.signatures.sort_by_key(|signature| signature.voter_id);
    let group_epoch = u64::try_from(coordinate.group_epoch)
        .map_err(|_| missing("independent voter group epoch exceeds the unsigned range"))?;
    let evidence = super::QuorumCommitEvidence::from_verified_voters(
        repo_id,
        group_epoch,
        super::QuorumCommitSeal {
            group_id: coordinate.group_id,
            history_incarnation: coordinate.history_incarnation,
            authority_epoch: coordinate.authority_epoch,
            raft_term: coordinate.raft_term,
            committed_log_index: coordinate.committed_log_index,
            raft_commit_digest_hex: coordinate.raft_commit_digest_hex,
            snapshot_sha256: coordinate.snapshot_sha256,
            snapshot_checksum: candidate.snapshot.checksum.clone(),
            quorum_threshold: threshold,
            voter_signatures: candidate.signatures,
        },
    )?;
    let state_machine = RefCasStateMachine::restore(&candidate.snapshot)
        .map_err(|_| missing("independent voter snapshot failed state-machine restore"))?;
    Ok((coordinate.group_id, state_machine, evidence))
}

/// Query every pinned independent voter for its committed cutpoint and require a quorum.
pub async fn fetch_quorum_cutpoint_from_voters(
    trust: &super::SafeGcRepoTrustConfig,
    repo_id: Uuid,
) -> Result<(i64, RefCasStateMachine, super::QuorumCommitEvidence), SafeGcError> {
    if repo_id.is_nil() {
        return Err(missing("Ref-CAS voter quorum fetch requires a non-nil repository id"));
    }
    let auth = trust.voter_client_auth.as_ref();
    let message = "Ref-CAS independent voter mTLS + Bearer client auth is not configured";
    let client_auth = auth.ok_or(SafeGcError::DistributedPrereqsMissing(message))?;
    client_auth.validate()?;
    let _ = load_private_bearer_token(&client_auth.auth_token_path)?;
    let _ =
        build_mtls_client_config(&client_auth.ca_cert_pem, &client_auth.client_cert_pem, &client_auth.client_key_pem)?;
    let mut requests = Vec::with_capacity(trust.trusted_consensus_voters.len());
    for voter in &trust.trusted_consensus_voters {
        validate_trusted_voter(voter, &trust.trusted_arm_pubkey_hex)?;
        let path = format!("/v1/safe-gc/cutpoint/{repo_id}");
        requests.push(async move {
            let timeout = Duration::from_secs(5);
            let fetched = request_voter_https(&voter.endpoint_url, &path, client_auth, None, timeout).await;
            let (status, body) = fetched.ok()?;
            if status != 200 {
                return None;
            }
            serde_json::from_slice::<VoterCutpointAttestation>(&body).ok()
        });
    }
    let attestations: Vec<VoterCutpointAttestation> =
        futures_util::future::join_all(requests).await.into_iter().flatten().collect();
    if attestations.is_empty() {
        return Err(missing("no independent Ref-CAS voter returned a committed cutpoint"));
    }
    verify_quorum_voter_attestations(trust, repo_id, &attestations)
}
