//! Source-only same-generation race with two distinct real Active pack/idx candidates.

use std::{
    fs,
    path::Path,
    thread,
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use super::{CP_BEFORE_LOCK, CloneKitPublicationStore, publish_clonekit_versioned, test_seam};
use crate::ci_checkouts::clonekit::{BuiltCloneKitArtifacts, CloneKitError, CloneKitManifest, CloneKitStatus};

#[path = "publication_active_fixture.rs"]
mod fixture;

struct CandidateBytes {
    pack: Vec<u8>,
    idx: Vec<u8>,
}

fn staged_bytes(built: &BuiltCloneKitArtifacts) -> CandidateBytes {
    CandidateBytes {
        pack: fs::read(built.staged_pack_path.as_ref().expect("staged pack")).expect("read staged pack"),
        idx: fs::read(built.staged_idx_path.as_ref().expect("staged idx")).expect("read staged idx"),
    }
}

fn file_digest(path: &Path) -> (String, u64) {
    let bytes = fs::read(path).expect("read artifact");
    (hex::encode(Sha256::digest(&bytes)), bytes.len() as u64)
}

fn attempt_names(store: &CloneKitPublicationStore, repository_id: Uuid) -> Vec<String> {
    fs::read_dir(store.repo_dir(repository_id))
        .expect("repo dir")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".publish-"))
        .collect()
}

fn assert_distinct_candidates(first: &BuiltCloneKitArtifacts, second: &BuiltCloneKitArtifacts) {
    assert_eq!(first.manifest.repository_id, second.manifest.repository_id);
    assert_eq!(first.manifest.kit_generation, second.manifest.kit_generation);
    assert_ne!(first.manifest.base_commit_oid, second.manifest.base_commit_oid);
    let first_pack = first.manifest.pack.as_ref().expect("first pack");
    let second_pack = second.manifest.pack.as_ref().expect("second pack");
    let first_idx = first.manifest.idx.as_ref().expect("first idx");
    let second_idx = second.manifest.idx.as_ref().expect("second idx");
    assert_ne!(first_pack.sha256.as_str(), second_pack.sha256.as_str());
    assert_ne!(first_idx.sha256.as_str(), second_idx.sha256.as_str());
}

#[test]
fn same_generation_active_race_has_one_complete_winner_and_stale_retry() {
    let td = TempDir::new().expect("tempdir");
    let ids = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let candidate_a = fixture::build_active_candidate(&td, ids, 1, "a", b"active-candidate-a-payload")
        .expect("candidate a");
    let candidate_b = fixture::build_active_candidate(
        &td,
        ids,
        1,
        "b",
        b"active-candidate-b-payload-with-a-different-length",
    )
    .expect("candidate b");
    assert_eq!(candidate_a.manifest.status, CloneKitStatus::Active);
    assert_eq!(candidate_b.manifest.status, CloneKitStatus::Active);
    assert_distinct_candidates(&candidate_a, &candidate_b);
    let candidate_a_manifest = candidate_a.manifest.clone();
    let candidate_b_manifest = candidate_b.manifest.clone();
    let candidate_a_bytes = staged_bytes(&candidate_a);
    let candidate_b_bytes = staged_bytes(&candidate_b);
    assert_ne!(candidate_a_bytes.pack, candidate_b_bytes.pack);
    assert_ne!(candidate_a_bytes.idx, candidate_b_bytes.idx);
    let git = fixture::git_binary();
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");

    let _serial = test_seam::serial();
    test_seam::reset();
    test_seam::pause_all_at(CP_BEFORE_LOCK);
    let first_store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("first store");
    let second_store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("second store");
    let first_built = candidate_a.clone();
    let second_built = candidate_b.clone();
    let first_git = git.clone();
    let second_git = git.clone();
    let first = thread::spawn(move || publish_clonekit_versioned(&first_store, &first_built, &first_git, None, None));
    let second =
        thread::spawn(move || publish_clonekit_versioned(&second_store, &second_built, &second_git, None, None));
    test_seam::wait_until(CP_BEFORE_LOCK, 2);
    test_seam::release(CP_BEFORE_LOCK);
    let first = first.join().expect("first join");
    let second = second.join().expect("second join");

    let (winner_manifest, loser_error) = match (first, second) {
        (Ok(winner), Err(loser)) => (winner, loser),
        (Err(loser), Ok(winner)) => (winner, loser),
        _ => panic!("expected exactly one same-generation publication winner"),
    };
    let winner_is_a = winner_manifest == candidate_a_manifest;
    let winner_is_b = winner_manifest == candidate_b_manifest;
    assert!(winner_is_a ^ winner_is_b, "winner manifest must exactly equal one candidate");
    let (loser_built, winner_bytes, loser_bytes) = if winner_is_a {
        (&candidate_b, &candidate_a_bytes, &candidate_b_bytes)
    } else {
        (&candidate_a, &candidate_b_bytes, &candidate_a_bytes)
    };

    let busy = matches!(&loser_error, CloneKitError::GitFailed(message) if message.contains("busy"));
    let stale = matches!(
        &loser_error,
        CloneKitError::StaleGeneration { expected_min, actual }
            if *expected_min == winner_manifest.kit_generation + 1
                && *actual == loser_built.manifest.kit_generation
    );
    assert!(busy || stale, "loser must be publication-busy or stale, got {loser_error:?}");
    if busy {
        match publish_clonekit_versioned(&store, loser_built, &git, None, None) {
            Err(CloneKitError::StaleGeneration { expected_min, actual }) => {
                assert_eq!(expected_min, winner_manifest.kit_generation + 1);
                assert_eq!(actual, loser_built.manifest.kit_generation);
            }
            other => panic!("busy loser retry must be rejected stale, got {other:?}"),
        }
    }

    let current = store.load_latest(ids.1).expect("latest").expect("visible current");
    assert_eq!(current, winner_manifest);
    assert_eq!(current.manifest_sha256, winner_manifest.manifest_sha256);
    assert_ne!(current, loser_built.manifest);

    let (pack_path, idx_path) = store.artifact_paths(ids.1, winner_manifest.kit_generation);
    let (pack_sha, pack_len) = file_digest(&pack_path);
    let (idx_sha, idx_len) = file_digest(&idx_path);
    let winner_pack = winner_manifest.pack.as_ref().expect("winner pack");
    let winner_idx = winner_manifest.idx.as_ref().expect("winner idx");
    assert_eq!(pack_sha.as_str(), winner_pack.sha256.as_str());
    assert_eq!(pack_len, winner_pack.length);
    assert_eq!(idx_sha.as_str(), winner_idx.sha256.as_str());
    assert_eq!(idx_len, winner_idx.length);
    assert_eq!(fs::read(&pack_path).expect("installed pack").as_slice(), winner_bytes.pack.as_slice());
    assert_eq!(fs::read(&idx_path).expect("installed idx").as_slice(), winner_bytes.idx.as_slice());

    let mut entries: Vec<String> = fs::read_dir(store.version_dir(ids.1, winner_manifest.kit_generation))
        .expect("winner generation")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(entries, vec!["clonekit.idx".to_owned(), "clonekit.pack".to_owned(), "manifest.json".to_owned()]);
    let installed_manifest = CloneKitManifest::from_verified_json(
        &fs::read(store.version_dir(ids.1, winner_manifest.kit_generation).join("manifest.json"))
            .expect("installed manifest"),
    )
    .expect("verified installed manifest");
    assert_eq!(installed_manifest, winner_manifest);

    assert!(attempt_names(&store, ids.1).is_empty());
    assert_eq!(
        fs::read(loser_built.staged_pack_path.as_ref().expect("loser staged pack"))
            .expect("loser pack")
            .as_slice(),
        loser_bytes.pack.as_slice()
    );
    assert_eq!(
        fs::read(loser_built.staged_idx_path.as_ref().expect("loser staged idx"))
            .expect("loser idx")
            .as_slice(),
        loser_bytes.idx.as_slice()
    );
    test_seam::reset();
}
