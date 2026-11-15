//! Bounded 64 KiB streaming reads and Linux `FICLONE` / streaming fallback
//! artifact handoff with strict inode, read-only sealing, and SHA-256 verification.
use super::budget::budgets;
use super::lease::VerificationLease;
use super::refuse;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// Bounded per-chunk read/copy buffer (64 KiB) to avoid large RSS allocations.
pub(super) const HANDOFF_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    len: u64,
}

/// Streaming reader bound to a single sealed `Arc<VerificationLease>` so the
/// underlying workspace cannot be dropped while chunks are still consumed.
pub(super) struct VerifiedArtifactStream {
    file: File,
    path: PathBuf,
    identity: FileIdentity,
    expected_len: u64,
    expected_sha256: Option<String>,
    hasher: Sha256,
    read_bytes: u64,
    finished: bool,
    _lease: Arc<VerificationLease>,
}

impl VerifiedArtifactStream {
    pub(super) fn open(
        path: &Path,
        expected_len: u64,
        expected_sha256: Option<&str>,
        lease: Arc<VerificationLease>,
    ) -> Result<Self, PackCommitError> {
        let (file, identity) = open_verified_readonly(path)?;
        if identity.len != expected_len {
            return Err(refuse("verified artifact length does not match registered length"));
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            identity,
            expected_len,
            expected_sha256: expected_sha256.map(str::to_owned),
            hasher: Sha256::new(),
            read_bytes: 0,
            finished: false,
            _lease: lease,
        })
    }

    pub(super) fn next_chunk(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>, PackCommitError> {
        if self.finished {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            return Err(refuse("materialized copy stream exceeded verifier deadline"));
        }
        let mut buf = vec![0u8; HANDOFF_CHUNK_BYTES];
        let read = self.file.read(&mut buf).map_err(|_| refuse("verified artifact copy cannot be read"))?;
        if read == 0 {
            self.verify_complete()?;
            self.finished = true;
            return Ok(None);
        }
        let read_u64 = u64::try_from(read).map_err(|_| refuse("verified artifact chunk overflowed"))?;
        self.read_bytes =
            self.read_bytes.checked_add(read_u64).ok_or_else(|| refuse("verified artifact byte counter overflowed"))?;
        if self.read_bytes > self.expected_len {
            return Err(refuse("verified artifact copy grew beyond registered length"));
        }
        self.hasher.update(&buf[..read]);
        buf.truncate(read);
        Ok(Some(buf))
    }

    fn verify_complete(&self) -> Result<(), PackCommitError> {
        verify_unchanged_identity(&self.file, &self.path, self.identity)?;
        if self.read_bytes != self.expected_len {
            return Err(refuse("verified artifact copy is shorter than registered length"));
        }
        if let Some(expected_sha) = &self.expected_sha256 {
            let actual = hex::encode(self.hasher.clone().finalize());
            if actual != *expected_sha {
                return Err(refuse("verified artifact copy digest drifted during stream"));
            }
        }
        budgets().record_handoff_stream(self.read_bytes);
        Ok(())
    }
}

/// Read an entire sealed artifact through bounded 64 KiB verified chunks,
/// verifying length, read-only inode invariance, deadline, and optional SHA-256.
pub(super) fn read_verified_streamed(
    path: &Path,
    expected_len: u64,
    expected_sha256: Option<&str>,
    lease: Arc<VerificationLease>,
    deadline: Instant,
) -> Result<Vec<u8>, PackCommitError> {
    let mut stream = VerifiedArtifactStream::open(path, expected_len, expected_sha256, lease)?;
    let capacity = usize::try_from(expected_len).map_err(|_| refuse("materialized copy length does not fit memory"))?;
    let mut out = Vec::with_capacity(capacity);
    while let Some(chunk) = stream.next_chunk(deadline)? {
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn open_verified_readonly(path: &Path) -> Result<(File, FileIdentity), PackCommitError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|_| refuse("verified artifact copy cannot be opened"))?;
    let meta = file.metadata().map_err(|_| refuse("verified artifact metadata cannot be inspected"))?;
    check_sealed_metadata(&meta)?;
    let path_meta =
        std::fs::symlink_metadata(path).map_err(|_| refuse("verified artifact path cannot be inspected"))?;
    check_sealed_metadata(&path_meta)?;
    let identity = metadata_identity(&meta, &path_meta)?;
    Ok((file, identity))
}

fn verify_unchanged_identity(file: &File, path: &Path, expected: FileIdentity) -> Result<(), PackCommitError> {
    let meta = file.metadata().map_err(|_| refuse("verified artifact metadata vanished during read"))?;
    check_sealed_metadata(&meta)?;
    let path_meta =
        std::fs::symlink_metadata(path).map_err(|_| refuse("verified artifact path vanished during read"))?;
    check_sealed_metadata(&path_meta)?;
    let actual = metadata_identity(&meta, &path_meta)?;
    if actual != expected {
        return Err(refuse("verified artifact inode changed concurrently during read"));
    }
    Ok(())
}

fn check_sealed_metadata(meta: &std::fs::Metadata) -> Result<(), PackCommitError> {
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(refuse("verified artifact must be a regular file, not a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.nlink() != 1 {
            return Err(refuse("verified artifact must not have extra hardlinks"));
        }
        // SAFETY: `libc::geteuid()` only reads the current process effective uid.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(refuse("verified artifact is not owned by the verifier process"));
        }
        if (meta.permissions().mode() & 0o222) != 0 {
            return Err(refuse("verified artifact must be sealed read-only before handoff"));
        }
    }
    Ok(())
}

fn metadata_identity(
    file_meta: &std::fs::Metadata,
    path_meta: &std::fs::Metadata,
) -> Result<FileIdentity, PackCommitError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file_meta.dev() != path_meta.dev() || file_meta.ino() != path_meta.ino() {
            return Err(refuse("verified artifact path was replaced before verification finished"));
        }
        Ok(FileIdentity { dev: file_meta.dev(), ino: file_meta.ino(), len: file_meta.len() })
    }
    #[cfg(not(unix))]
    {
        let _ = path_meta;
        Ok(FileIdentity { len: file_meta.len() })
    }
}

#[cfg(test)]
pub(super) mod test_handoff {
    use super::*;
    use std::io::Write;
    use uuid::Uuid;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum HandoffMethod {
        Reflink,
        StreamingCopy,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct HandoffReceipt {
        pub(crate) dest_path: PathBuf,
        pub(crate) bytes: u64,
        pub(crate) sha256: String,
        pub(crate) method: HandoffMethod,
    }

    struct TempUnlinkGuard(Option<PathBuf>);
    impl TempUnlinkGuard {
        fn disarm(&mut self) {
            let _ = self.0.take();
        }
    }
    impl Drop for TempUnlinkGuard {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    pub(crate) fn handoff_verified_file(
        src_path: &Path,
        dest_dir: &Path,
        final_name: &str,
        expected_len: u64,
        expected_sha: &str,
        lease: &Arc<VerificationLease>,
        deadline: Instant,
        after_write_hook: Option<&dyn Fn(&Path)>,
    ) -> Result<HandoffReceipt, PackCommitError> {
        if final_name.is_empty() || final_name == "." || final_name == ".." || final_name.contains(['/', '\\', '\0']) {
            return Err(refuse("handoff target filename is unsafe"));
        }
        let dir_meta =
            std::fs::symlink_metadata(dest_dir).map_err(|_| refuse("handoff destination directory is unavailable"))?;
        if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
            return Err(refuse("handoff destination must be a real directory"));
        }

        let (mut src_file, src_identity) = open_verified_readonly(src_path)?;
        if src_identity.len != expected_len {
            return Err(refuse("source verified artifact length disagrees"));
        }

        let temp_path = dest_dir.join(format!(".tmp-handoff-{}.part", Uuid::new_v4().simple()));
        let mut temp_guard = TempUnlinkGuard(Some(temp_path.clone()));
        let mut dest_opts = OpenOptions::new();
        dest_opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            dest_opts.mode(0o600);
        }
        let mut dest_file =
            dest_opts.open(&temp_path).map_err(|_| refuse("handoff temporary destination cannot be created"))?;

        let method = if try_ficlone(&src_file, &dest_file) {
            budgets().record_handoff_reflink();
            HandoffMethod::Reflink
        } else {
            budgets().record_handoff_fallback();
            stream_copy_bounded(&mut src_file, &mut dest_file, expected_len, deadline)?
        };
        dest_file.sync_all().map_err(|_| refuse("handoff temporary file could not be synced"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            dest_file
                .set_permissions(std::fs::Permissions::from_mode(0o444))
                .map_err(|_| refuse("handoff temporary file could not be sealed read-only"))?;
        }
        drop(dest_file);

        if let Some(hook) = after_write_hook {
            hook(&temp_path);
        }

        // Never skip verification even for zero-copy reflink: verify destination digest + inode + source invariance.
        let _ = read_verified_streamed(&temp_path, expected_len, Some(expected_sha), Arc::clone(lease), deadline)?;
        verify_unchanged_identity(&src_file, src_path, src_identity)?;

        let final_path = dest_dir.join(final_name);
        std::fs::hard_link(&temp_path, &final_path)
            .map_err(|_| refuse("handoff destination already exists or cannot be linked"))?;
        let _ = std::fs::remove_file(&temp_path);
        temp_guard.disarm();
        Ok(HandoffReceipt { dest_path: final_path, bytes: expected_len, sha256: expected_sha.to_owned(), method })
    }

    fn try_ficlone(src: &File, dest: &File) -> bool {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // Linux `_IOW(0x94, 9, int)` (`FICLONE`), positive value fits both i32 and u64 ioctl signatures.
            const FICLONE: libc::Ioctl = 0x4004_9409;
            // SAFETY: Both descriptors are valid open files owned for this call duration.
            unsafe { libc::ioctl(dest.as_raw_fd(), FICLONE, src.as_raw_fd()) == 0 }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (src, dest);
            false
        }
    }

    fn stream_copy_bounded(
        src: &mut File,
        dest: &mut File,
        expected_len: u64,
        deadline: Instant,
    ) -> Result<(), PackCommitError> {
        let mut buf = vec![0u8; HANDOFF_CHUNK_BYTES];
        let mut copied = 0u64;
        loop {
            if Instant::now() >= deadline {
                return Err(refuse("handoff streaming copy exceeded verifier deadline"));
            }
            let read = src.read(&mut buf).map_err(|_| refuse("source verified file read failed during handoff"))?;
            if read == 0 {
                break;
            }
            let read_u64 = u64::try_from(read).map_err(|_| refuse("handoff read size overflowed"))?;
            copied = copied.checked_add(read_u64).ok_or_else(|| refuse("handoff copy byte counter overflowed"))?;
            if copied > expected_len {
                return Err(refuse("source verified file grew beyond registered length during handoff"));
            }
            dest.write_all(&buf[..read]).map_err(|_| refuse("handoff temporary write failed"))?;
        }
        if copied != expected_len {
            return Err(refuse("source verified file truncated during handoff"));
        }
        Ok(())
    }
}
