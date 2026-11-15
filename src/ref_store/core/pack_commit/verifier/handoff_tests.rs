use super::budget::metrics_snapshot;
use super::handoff::test_handoff::{HandoffMethod, handoff_verified_file};
use super::handoff::{HANDOFF_CHUNK_BYTES, VerifiedArtifactStream};
use super::lease::VerificationLease;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn write_sealed_source(dir: &Path, name: &str, bytes: &[u8]) -> (std::path::PathBuf, String) {
    let path = dir.join(name);
    let mut file = OpenOptions::new().write(true).create_new(true).open(&path).expect("create source");
    file.write_all(bytes).expect("write source");
    file.sync_all().expect("sync source");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o400)).expect("seal 0400");
    }
    let sha = hex::encode(Sha256::digest(bytes));
    (path, sha)
}

#[test]
fn verified_stream_yields_bounded_64kib_chunks_and_pins_lease_until_finish() {
    let lease = VerificationLease::for_test();
    let total_len = HANDOFF_CHUNK_BYTES * 2 + 1234;
    let payload: Vec<u8> = (0..total_len).map(|i| u8::try_from(i % 251).expect("byte")).collect();
    let incoming = lease.subdirectory("incoming").expect("incoming");
    let (src_path, sha) = write_sealed_source(&incoming, "multi-chunk.pack", &payload);

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = VerifiedArtifactStream::open(
        &src_path,
        u64::try_from(payload.len()).expect("len"),
        Some(&sha),
        Arc::clone(&lease),
    )
    .expect("open verified stream");

    let mut collected = Vec::new();
    let mut chunk_count = 0usize;
    while let Some(chunk) = stream.next_chunk(deadline).expect("chunk ok") {
        assert!(chunk.len() <= HANDOFF_CHUNK_BYTES, "chunk exceeded 64 KiB bound");
        collected.extend_from_slice(&chunk);
        chunk_count += 1;
    }
    assert_eq!(chunk_count, 3);
    assert_eq!(collected, payload);

    // Dropping the lease only releases workspace after stream is dropped too.
    let watcher = Arc::downgrade(&lease);
    drop(lease);
    assert!(watcher.upgrade().is_some(), "stream must hold lease alive until dropped");
    drop(stream);
    assert!(watcher.upgrade().is_none(), "dropping stream frees lease and temp root");
}

#[test]
fn handoff_reflink_or_fallback_verifies_digest_and_commits_atomically() {
    let lease = VerificationLease::for_test();
    let payload = vec![0x5Au8; HANDOFF_CHUNK_BYTES + 777];
    let incoming = lease.subdirectory("incoming").expect("incoming");
    let (src_path, sha) = write_sealed_source(&incoming, "pair-00.pack", &payload);
    let dest = tempdir().expect("dest dir");
    let deadline = Instant::now() + Duration::from_secs(5);
    let before = metrics_snapshot();

    let receipt = handoff_verified_file(
        &src_path,
        dest.path(),
        "pack-canonical.pack",
        u64::try_from(payload.len()).expect("len"),
        &sha,
        &lease,
        deadline,
        None,
    )
    .expect("handoff succeeds");

    assert_eq!(receipt.bytes, u64::try_from(payload.len()).expect("len"));
    assert_eq!(receipt.sha256, sha);
    assert_eq!(std::fs::read(&receipt.dest_path).expect("dest readable"), payload);

    let after = metrics_snapshot();
    match receipt.method {
        HandoffMethod::Reflink => {
            assert!(after.handoff_reflink_files > before.handoff_reflink_files);
        }
        HandoffMethod::StreamingCopy => {
            assert!(after.handoff_fallback_count > before.handoff_fallback_count);
            assert!(after.handoff_stream_files > before.handoff_stream_files);
        }
    }

    // Must refuse to overwrite / clobber an already-committed destination file.
    assert!(
        handoff_verified_file(
            &src_path,
            dest.path(),
            "pack-canonical.pack",
            u64::try_from(payload.len()).expect("len"),
            &sha,
            &lease,
            deadline,
            None,
        )
        .is_err(),
        "duplicate target filename must fail closed without clobbering"
    );
}

#[cfg(unix)]
#[test]
fn handoff_refuses_concurrent_destination_corruption_writable_mode_symlinks_and_extra_hardlinks() {
    use std::os::unix::fs::PermissionsExt;
    let lease = VerificationLease::for_test();
    let payload = vec![0x33u8; 4096];
    let incoming = lease.subdirectory("incoming").expect("incoming");
    let (src_path, sha) = write_sealed_source(&incoming, "pair-01.pack", &payload);
    let dest = tempdir().expect("dest dir");
    let deadline = Instant::now() + Duration::from_secs(5);

    // 1. Concurrent destination mutation right after reflink/copy (flips one byte, stays 0o444).
    let tampered = handoff_verified_file(
        &src_path,
        dest.path(),
        "corrupt.pack",
        4096,
        &sha,
        &lease,
        deadline,
        Some(&|temp_path| {
            std::fs::set_permissions(temp_path, std::fs::Permissions::from_mode(0o600)).expect("chmod write");
            let mut bytes = std::fs::read(temp_path).expect("read temp");
            bytes[0] ^= 0xFF;
            std::fs::write(temp_path, bytes).expect("corrupt temp");
            std::fs::set_permissions(temp_path, std::fs::Permissions::from_mode(0o444)).expect("reseal");
        }),
    );
    assert!(tampered.is_err(), "corrupted handoff temp file must fail SHA-256 verification");
    assert!(!dest.path().join("corrupt.pack").exists(), "failed handoff must never link final destination");
    assert_eq!(std::fs::read_dir(dest.path()).expect("ls").count(), 0, "temp file must be unlinked on failure");

    // 2. Concurrent chmod back to writable mode without even altering bytes must fail closed.
    let writable_temp = handoff_verified_file(
        &src_path,
        dest.path(),
        "writable-temp.pack",
        4096,
        &sha,
        &lease,
        deadline,
        Some(&|temp_path| {
            std::fs::set_permissions(temp_path, std::fs::Permissions::from_mode(0o644)).expect("make writable");
        }),
    );
    assert!(writable_temp.is_err(), "writable destination temp must be refused");

    // 3. Symlink source must be refused.
    let symlink_src = incoming.join("symlink.pack");
    std::os::unix::fs::symlink(&src_path, &symlink_src).expect("create symlink");
    assert!(
        handoff_verified_file(&symlink_src, dest.path(), "from-sym.pack", 4096, &sha, &lease, deadline, None).is_err(),
        "symlink source must be rejected"
    );

    // 4. Source with nlink > 1 must be refused (aliasing/external mutability risk).
    let extra_link = incoming.join("extra-link.pack");
    std::fs::hard_link(&src_path, &extra_link).expect("extra hardlink");
    assert!(
        handoff_verified_file(&src_path, dest.path(), "aliased.pack", 4096, &sha, &lease, deadline, None).is_err(),
        "aliased nlink > 1 source must be rejected"
    );
}
