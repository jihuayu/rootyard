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
//! 3. the exact resulting refs are written with `update-ref --stdin` and HEAD with
//!    `symbolic-ref`, so Git itself rejects invalid names, dangling names and
//!    directory/file conflicts;
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
        self.write_refs(&checked.resulting, deadline).await?;
        self.runner
            .run(
                "symbolic-ref",
                &["symbolic-ref", "HEAD", checked.head.as_str()],
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
        if refs::parse_ref_listing(&listing, self.format)? != checked.resulting {
            return Err(refuse("native resulting refs are not the closure context refs"));
        }
        self.check_types(&checked.resulting, deadline).await?;
        self.check_connectivity(deadline).await?;
        self.check_head(&checked.head, checked.head_oid.as_deref(), deadline).await
    }

    async fn write_refs(&self, refs: &RefMap, deadline: Instant) -> Result<(), PackCommitError> {
        let mut input = String::with_capacity(refs.len() * 96);
        for (name, oid) in refs {
            input.push_str("update ");
            input.push_str(name);
            input.push(' ');
            input.push_str(oid);
            input.push('\n');
        }
        if input.len() > VERIFIER_PIPE_BYTES {
            return Err(refuse("resulting ref batch exceeds the verifier stdin bound"));
        }
        if input.is_empty() {
            return Ok(());
        }
        self.runner
            .run(
                "update-ref",
                &["update-ref", "--stdin", "--no-deref"],
                Some(&self.git_dir),
                None,
                Stdin::Bytes(input.as_bytes()),
                deadline,
                &self.lease,
            )
            .await?;
        Ok(())
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

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
