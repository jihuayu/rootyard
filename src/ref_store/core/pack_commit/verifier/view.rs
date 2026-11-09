//! Owned native Git view: pairs, exact refs/HEAD, object connectivity.
//!
//! The view is one disposable bare repository of the planned object format inside
//! a private 0700 scratch directory. It has no persistent storage authority and
//! is removed after the proof.
//!
//! Steps, all through the closed bounded runner:
//!
//! 1. `git verify-pack <registered idx>` proves the *registered* index belongs to
//!    the *registered* pack file Git reads next to it (mature Git checks the
//!    index checksum, the pack trailer and every indexed object);
//! 2. `git index-pack --stdin` lets Git compute the canonical `pack-<hash>` name
//!    and content-validate the pack (zlib, deltas, per-object hashes); the pack
//!    directory must then hold exactly the expected canonical pairs;
//! 3. the exact resulting refs are written as one sorted, validated `packed-refs`
//!    file with `create_new`/`0600` in the owned `0700` workspace, and HEAD with
//!    `symbolic-ref`; no user-controlled loose-ref directory tree is created, so
//!    a legal deep ref name cannot amplify into nested directories (issue139);
//! 4. `for-each-ref` must reproduce the context's ref map exactly; the branch
//!    targets must be commit objects (one bounded `cat-file --batch-check`);
//! 5. `git fsck --connectivity-only --no-dangling` must report no problem, which
//!    is full object connectivity *from the exact resulting refs and HEAD*;
//! 6. `symbolic-ref HEAD` must name the context's branch and, when that branch
//!    exists, `rev-parse --verify HEAD^{commit}` must be its exact object id. An
//!    unborn HEAD stays unborn: no additional HEAD policy is invented here.
use super::lease::VerificationLease;
use super::process::{GitRunner, Stdin};
use super::refs::{self, RefMap};
use super::refuse;
use super::validate::Checked;
use crate::ref_store::core::pack_commit::contract::VERIFIER_PIPE_BYTES;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::types::{GitObjectFormat, RefName};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// One owned verification repository view.
pub(super) struct NativeView {
    /// The slot + workspace lease travels with the view and with every child it
    /// spawns, so cancellation cannot release capacity on an uncertain stop.
    lease: Arc<VerificationLease>,
    git_dir: PathBuf,
    incoming: PathBuf,
    template: PathBuf,
    runner: GitRunner,
    format: GitObjectFormat,
}

impl NativeView {
    pub(super) fn create(
        binary: &Path,
        lease: Arc<VerificationLease>,
        format: GitObjectFormat,
    ) -> Result<Self, PackCommitError> {
        let home = lease.subdirectory("home")?;
        let template = lease.subdirectory("template")?;
        let incoming = lease.subdirectory("incoming")?;
        let git_dir = lease.root_path().join("verify.git");
        let runner = GitRunner::new(binary.to_path_buf(), home, template.clone());
        Ok(Self { lease, git_dir, incoming, template, runner, format })
    }

    /// Directory holding the verified pack/idx copies.
    pub(super) fn incoming(&self) -> &Path {
        &self.incoming
    }

    /// `git init` of the planned object format, then structural/format checks of
    /// what Git actually created.
    pub(super) async fn init(&self, deadline: Instant) -> Result<(), PackCommitError> {
        let object_format = format!("--object-format={}", self.format.as_str());
        let template = format!("--template={}", self.template.display());
        self.runner
            .run(
                "init",
                &["init", "--bare", "--quiet", object_format.as_str(), template.as_str()],
                None,
                Some(&self.git_dir),
                Stdin::Null,
                deadline,
                &self.lease,
            )
            .await?;
        let metadata =
            std::fs::symlink_metadata(&self.git_dir).map_err(|_| refuse("native Git did not create the owned view"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(refuse("native Git did not create the owned view"));
        }
        let config =
            std::fs::read(self.git_dir.join("config")).map_err(|_| refuse("native Git view has no configuration"))?;
        if config.len() > 8 * 1024 {
            return Err(refuse("native Git view configuration is not bounded"));
        }
        let config = std::str::from_utf8(&config).map_err(|_| refuse("native Git view configuration is not text"))?;
        match self.format {
            GitObjectFormat::Sha256 => {
                if !config.contains("sha256") {
                    return Err(refuse("native Git view did not adopt the planned object format"));
                }
            }
            GitObjectFormat::Sha1 => {
                if config.contains("objectformat") || config.contains("sha256") {
                    return Err(refuse("native Git view adopted another object format"));
                }
            }
        }
        Ok(())
    }

    /// Run one additional fixed-argument native step against this owned view.
    ///
    /// The facts engine uses this only with compiled-literal args plus object ids
    /// that the core already parsed into exact lowercase `GitOid` hex. Revisions
    /// for ancestry checks travel on stdin, never in argv.
    pub(super) async fn step(
        &self,
        step: &'static str,
        args: &[&str],
        stdin: Stdin<'_>,
        deadline: Instant,
    ) -> Result<Vec<u8>, PackCommitError> {
        self.runner.run(step, args, Some(&self.git_dir), None, stdin, deadline, &self.lease).await
    }

    /// Prove the registered index belongs to the registered pack file.
    pub(super) async fn verify_registered_pair(&self, idx: &Path, deadline: Instant) -> Result<(), PackCommitError> {
        self.runner
            .run("verify-pack", &["verify-pack"], Some(&self.git_dir), Some(idx), Stdin::Null, deadline, &self.lease)
            .await?;
        Ok(())
    }

    /// Let Git content-validate one pack and store it under its canonical name.
    ///
    /// `pack.writeReverseIndex=false` is passed explicitly because Git 2.41+ makes
    /// `index-pack`/`repack` write a `pack-<hash>.rev` reverse index next to the
    /// pack and index by default. That file is legitimate for Git but is not part
    /// of the closed file policy this view attests (exactly one
    /// `pack-<hash>.pack` and one `pack-<hash>.idx` per verified pair), so the
    /// reverse index is suppressed for this owned command instead of widening the
    /// policy to extra suffixes or arbitrary files.
    pub(super) async fn index_pack(&self, pack: &Path, deadline: Instant) -> Result<(), PackCommitError> {
        self.runner
            .run(
                "index-pack",
                &["-c", "pack.writeReverseIndex=false", "index-pack", "--stdin"],
                Some(&self.git_dir),
                None,
                Stdin::File(pack),
                deadline,
                &self.lease,
            )
            .await?;
        Ok(())
    }

    /// Require exactly `expected` canonically named pack/idx pairs and nothing else.
    pub(super) fn check_pack_directory(&self, expected: usize) -> Result<(), PackCommitError> {
        let directory = self.git_dir.join("objects").join("pack");
        let entries = std::fs::read_dir(&directory).map_err(|_| refuse("native Git view has no pack directory"))?;
        let hex_len = self.format.oid_hex_len();
        let (mut packs, mut indexes) = (0usize, 0usize);
        for entry in entries {
            let entry = entry.map_err(|_| refuse("native Git view pack directory cannot be listed"))?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| refuse("native Git view holds a non-textual pack name"))?;
            let canonical = name.strip_prefix("pack-").is_some_and(|rest| {
                rest.strip_suffix(".pack").is_some_and(|hex| is_lower_hex(hex, hex_len))
                    || rest.strip_suffix(".idx").is_some_and(|hex| is_lower_hex(hex, hex_len))
            });
            if !canonical {
                return Err(refuse("native Git view holds a non-canonical pack name"));
            }
            if name.ends_with(".pack") {
                packs += 1;
            } else {
                indexes += 1;
            }
        }
        if packs != expected || indexes != expected {
            return Err(refuse("native Git did not store exactly the verified pack pairs"));
        }
        Ok(())
    }

    /// Write the exact resulting refs and HEAD, then re-read and attest them.
    pub(super) async fn attest(&self, checked: &Checked<'_>, deadline: Instant) -> Result<(), PackCommitError> {
        self.attest_refs(&checked.head, checked.head_oid.as_deref(), &checked.resulting, deadline).await
    }

    /// Shared refs/HEAD attestation used by the A4 proof path and the A5b
    /// materialized-read engine. The caller supplies an already validated map
    /// from trusted stored rows or from an independently recomputed closure.
    pub(super) async fn attest_refs(
        &self,
        head: &RefName,
        head_oid: Option<&str>,
        refs: &RefMap,
        deadline: Instant,
    ) -> Result<(), PackCommitError> {
        self.write_refs_bounded(refs, deadline).await?;
        self.runner
            .run(
                "symbolic-ref",
                &["symbolic-ref", "HEAD", head.as_str()],
                Some(&self.git_dir),
                None,
                Stdin::Null,
                deadline,
                &self.lease,
            )
            .await?;
        let listing = self
            .runner
            .run(
                "for-each-ref",
                &["for-each-ref", "--format=%(refname) %(objectname)"],
                Some(&self.git_dir),
                None,
                Stdin::Null,
                deadline,
                &self.lease,
            )
            .await?;
        if refs::parse_ref_listing(&listing, self.format)? != *refs {
            return Err(refuse("native resulting refs are not the verified ref set"));
        }
        self.check_types(refs, deadline).await?;
        self.check_connectivity(deadline).await?;
        self.check_head(head, head_oid, deadline).await
    }

    /// Write the exact resulting refs as one sorted, validated `packed-refs` file.
    ///
    /// The file is created with `create_new` and mode `0600` inside the owned
    /// 0700 workspace. It never creates a loose-ref directory tree, so legal deep
    /// ref names cannot amplify into an attacker-shaped directory hierarchy.
    /// HEAD is not a packed ref: it is written separately as a symbolic ref by
    /// the caller. The created inode and a read-back must match exactly before
    /// native Git is allowed to read it.
    ///
    /// All filesystem work runs in one owned blocking task. That task moves an
    /// `Arc<VerificationLease>`, so a stalled/full scratch filesystem cannot
    /// release the native permit, view budget or workspace while the syscalls
    /// may still be running. The caller's absolute deadline bounds the wait; it
    /// never aborts or drops the owned task.
    async fn write_refs_bounded(&self, refs: &RefMap, deadline: Instant) -> Result<(), PackCommitError> {
        if refs.is_empty() {
            return Ok(());
        }
        if deadline <= Instant::now() {
            return Err(refuse("native Git view packed-refs has no remaining deadline"));
        }
        let contents = refs::packed_refs_file(refs, self.format)?;
        let path = self.git_dir.join("packed-refs");
        let lease = Arc::clone(&self.lease);
        let task = tokio::task::spawn_blocking(move || {
            let _lease = lease;
            write_refs_file(&path, &contents)
        });
        // `deadline` is a `std::time::Instant`; `from_std` keeps the same
        // absolute instant while Tokio can compare it against its own clock.
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(refuse("native Git view packed-refs task failed")),
            Err(_) => Err(refuse("native Git view packed-refs write is retained")),
        }
    }

    #[cfg(test)]
    fn write_refs_sync(&self, refs: &RefMap) -> Result<(), PackCommitError> {
        if refs.is_empty() {
            return Ok(());
        }
        let contents = refs::packed_refs_file(refs, self.format)?;
        write_refs_file(&self.git_dir.join("packed-refs"), &contents)
    }

    /// Branch targets must be commits; other refs may name any object Git stores.
    async fn check_types(&self, refs: &RefMap, deadline: Instant) -> Result<(), PackCommitError> {
        if refs.is_empty() {
            return Ok(());
        }
        let mut oids = refs.values().cloned().collect::<Vec<_>>();
        oids.sort();
        oids.dedup();
        let mut input = oids.join("\n");
        input.push('\n');
        if input.len() > VERIFIER_PIPE_BYTES {
            return Err(refuse("resulting object list exceeds the verifier stdin bound"));
        }
        let listing = self
            .runner
            .run(
                "cat-file",
                &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
                Some(&self.git_dir),
                None,
                Stdin::Bytes(input.as_bytes()),
                deadline,
                &self.lease,
            )
            .await?;
        let listing = std::str::from_utf8(&listing).map_err(|_| refuse("native object type listing is not text"))?;
        if !listing.is_empty() && !listing.ends_with('\n') {
            return Err(refuse("native object type listing is truncated"));
        }
        let lines = listing.lines().collect::<Vec<_>>();
        if lines.len() != oids.len() {
            return Err(refuse("native object type listing is incomplete"));
        }
        let mut kinds = BTreeMap::new();
        for (line, oid) in lines.iter().zip(oids.iter()) {
            let (seen, kind) = line.split_once(' ').ok_or_else(|| refuse("native object type listing is malformed"))?;
            if seen != oid {
                return Err(refuse("native object type listing is out of order"));
            }
            match kind {
                "commit" | "tree" | "blob" | "tag" => {}
                _ => return Err(refuse("native object type listing names a missing object")),
            }
            kinds.insert(oid.clone(), kind.to_owned());
        }
        for (name, oid) in refs {
            let kind = kinds.get(oid).ok_or_else(|| refuse("native object type listing is incomplete"))?;
            if name.starts_with("refs/heads/") && kind != "commit" {
                return Err(refuse("a resulting branch does not name a commit object"));
            }
        }
        Ok(())
    }

    /// Full object connectivity from the exact resulting refs and HEAD.
    async fn check_connectivity(&self, deadline: Instant) -> Result<(), PackCommitError> {
        let output = self
            .runner
            .run(
                "fsck",
                &["fsck", "--connectivity-only", "--no-dangling", "--no-progress"],
                Some(&self.git_dir),
                None,
                Stdin::Null,
                deadline,
                &self.lease,
            )
            .await?;
        if !output.iter().all(|byte| byte.is_ascii_whitespace()) {
            return Err(refuse("native object connectivity check reported a problem"));
        }
        Ok(())
    }

    async fn check_head(
        &self,
        head: &RefName,
        head_oid: Option<&str>,
        deadline: Instant,
    ) -> Result<(), PackCommitError> {
        let observed = self
            .runner
            .run(
                "symbolic-ref",
                &["symbolic-ref", "HEAD"],
                Some(&self.git_dir),
                None,
                Stdin::Null,
                deadline,
                &self.lease,
            )
            .await?;
        let observed = std::str::from_utf8(&observed).map_err(|_| refuse("native HEAD is not text"))?;
        if observed.trim() != head.as_str() {
            return Err(refuse("native HEAD does not name the closure context branch"));
        }
        if let Some(expected) = head_oid {
            let resolved = self
                .runner
                .run(
                    "rev-parse",
                    &["rev-parse", "--verify", "HEAD^{commit}"],
                    Some(&self.git_dir),
                    None,
                    Stdin::Null,
                    deadline,
                    &self.lease,
                )
                .await?;
            let resolved = std::str::from_utf8(&resolved).map_err(|_| refuse("native HEAD object id is not text"))?;
            if resolved.trim() != expected {
                return Err(refuse("native HEAD does not resolve to the closure context object id"));
            }
        }
        Ok(())
    }
}

fn write_refs_file(path: &std::path::Path, contents: &[u8]) -> Result<(), PackCommitError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(refuse("native Git view already holds a packed-refs file"));
        }
        Err(_) => return Err(refuse("native Git view packed-refs file cannot be created")),
    };
    let metadata = file.metadata().map_err(|_| refuse("native Git view packed-refs file cannot be inspected"))?;
    inspect_packed_refs(&metadata)?;
    file.write_all(contents).map_err(|_| refuse("native Git view packed-refs file cannot be written"))?;
    // The file is disposable input inside an owned private view; no fsync is
    // needed, and avoiding it keeps this bounded filesystem section short.
    drop(file);
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| refuse("native Git view packed-refs file cannot be inspected"))?;
    inspect_packed_refs(&metadata)?;
    let observed = std::fs::read(path).map_err(|_| refuse("native Git view packed-refs file cannot be read back"))?;
    if observed != contents {
        return Err(refuse("native Git view packed-refs read-back differs from the exact ref set"));
    }
    Ok(())
}

/// The packed-refs inode must be exactly the private regular file this view
/// created: no symlink, no foreign owner, no extra hard link and no group/other
/// permission.
fn inspect_packed_refs(metadata: &std::fs::Metadata) -> Result<(), PackCommitError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(refuse("native Git view packed-refs is not a regular file"));
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(refuse("native Git view packed-refs is not mode 0600"));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(refuse("native Git view packed-refs is owned by another user"));
    }
    if metadata.nlink() != 1 {
        return Err(refuse("native Git view packed-refs is not singly linked"));
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    /// The packed-refs file is an owned 0600 regular file created with
    /// `create_new`; no loose `refs/` tree is created and a second write refuses.
    #[test]
    fn packed_refs_are_private_created_new_and_create_no_loose_tree() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = slots.try_acquire_owned().expect("slot");
        let lease = VerificationLease::new(permit).expect("lease");
        let view =
            NativeView::create(Path::new("/nonexistent/git"), Arc::clone(&lease), GitObjectFormat::Sha1).expect("view");
        std::fs::DirBuilder::new().mode(0o700).create(&view.git_dir).expect("git dir");
        let mut refs = RefMap::new();
        refs.insert("refs/heads/topic".into(), "a".repeat(40));
        refs.insert("refs/tags/v1".into(), "b".repeat(40));
        view.write_refs_sync(&refs).expect("packed refs");
        let path = view.git_dir.join("packed-refs");
        let metadata = std::fs::symlink_metadata(&path).expect("metadata");
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(
            std::fs::read(&path).expect("read"),
            refs::packed_refs_file(&refs, GitObjectFormat::Sha1).expect("expected")
        );
        assert!(!view.git_dir.join("refs").exists(), "no loose refs tree is created");
        assert!(view.write_refs_sync(&refs).is_err(), "packed-refs is create_new");
        assert!(view.write_refs_sync(&RefMap::new()).is_ok(), "empty refs write nothing");
    }
}
