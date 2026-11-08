//! Trusted-configuration check for the native Git executable path.
//!
//! The verifier never searches `PATH`, never reads an environment variable and
//! has no default binary: the path is supplied once, explicitly, to
//! [`super::PackVerifier::new`] and validated here. Validation is deliberately
//! conservative because that one path is the only non-hermetic input of the whole
//! proof:
//!
//! * it must be absolute and free of `..` components;
//! * it must resolve (symlinks are followed exactly once, by the OS) to a
//!   regular file that the current user may execute;
//! * the file must not be writable by the group or by other users;
//! * no ancestor directory may be group- or other-writable without the sticky
//!   bit, so a shared scratch directory cannot replace the executable.
//!
//! The refusal text is a fixed literal: the rejected path is trusted
//! configuration, but the error surface stays free of any path or provider text.
use super::refuse;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// Validate and canonicalise the configured Git executable.
pub(super) fn validate(configured: &Path) -> Result<PathBuf, PackCommitError> {
    if !configured.is_absolute() {
        return Err(refuse("verifier Git binary must be configured as an absolute path"));
    }
    if configured.components().any(|component| matches!(component, Component::ParentDir)) {
        return Err(refuse("verifier Git binary path must not contain parent traversal"));
    }
    let canonical = std::fs::canonicalize(configured).map_err(|_| refuse("verifier Git binary does not resolve"))?;
    if !canonical.is_absolute() {
        return Err(refuse("verifier Git binary did not resolve to an absolute path"));
    }
    inspect_executable(&canonical)?;
    let mut ancestor = canonical.parent();
    while let Some(directory) = ancestor {
        let metadata =
            std::fs::metadata(directory).map_err(|_| refuse("verifier Git binary directory cannot be inspected"))?;
        if !metadata.is_dir() {
            return Err(refuse("verifier Git binary path component is not a directory"));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(refuse("verifier Git binary lives in a shared writable directory"));
        }
        ancestor = directory.parent();
    }
    Ok(canonical)
}

/// Mode requirement of the trusted executable: the owner must be able to execute
/// it and **nobody else may be able to write it**. Group-writable and
/// other-writable are both refused, because either lets another principal replace
/// the binary that mints a proof. Privilege-changing bits are also refused so
/// process-group inspection can rely on children retaining the verifier's UID.
fn executable_mode_ok(mode: u32) -> bool {
    mode & 0o100 != 0 && mode & 0o6022 == 0
}

/// Inspect one already-resolved regular executable file.
fn inspect_executable(path: &Path) -> Result<(), PackCommitError> {
    let metadata = std::fs::metadata(path).map_err(|_| refuse("verifier Git binary cannot be inspected"))?;
    if !metadata.is_file() {
        return Err(refuse("verifier Git binary is not a regular file"));
    }
    if !executable_mode_ok(metadata.permissions().mode()) {
        return Err(refuse("verifier Git binary must be owner-executable and not group/other writable"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_and_traversing_paths_are_refused() {
        assert!(validate(Path::new("git")).is_err());
        assert!(validate(Path::new("/usr/../bin/git")).is_err());
        assert!(validate(Path::new("./git")).is_err());
    }

    #[test]
    fn a_missing_absolute_path_is_refused() {
        assert!(validate(Path::new("/nonexistent-rootyard-verifier/git")).is_err());
    }

    #[test]
    fn only_owner_executable_non_writable_modes_are_trusted() {
        assert!(executable_mode_ok(0o700));
        assert!(executable_mode_ok(0o750));
        assert!(executable_mode_ok(0o755));
        // Group- or other-writable binaries can be replaced by another principal.
        assert!(!executable_mode_ok(0o770));
        assert!(!executable_mode_ok(0o775));
        assert!(!executable_mode_ok(0o757));
        assert!(!executable_mode_ok(0o702));
        assert!(!executable_mode_ok(0o766));
        // Without owner execute there is nothing to run.
        assert!(!executable_mode_ok(0o644));
        assert!(!executable_mode_ok(0o600));
    }

    #[test]
    fn a_real_file_is_judged_by_its_mode_bits() {
        let directory = tempfile::tempdir().expect("scratch directory");
        let file = directory.path().join("git");
        std::fs::write(&file, b"#!/bin/sh\nexit 1\n").expect("seed file");
        for (mode, trusted) in [
            (0o750u32, true),
            (0o755, true),
            (0o770, false),
            (0o757, false),
            (0o644, false),
            (0o4755, false),
            (0o2755, false),
            (0o6755, false),
        ] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).expect("set mode");
            assert_eq!(inspect_executable(&file).is_ok(), trusted, "mode {mode:o}");
        }
    }

    #[test]
    fn a_trusted_system_shell_is_accepted() {
        // `/bin/sh` is a real regular executable file in a root-owned directory;
        // the verifier only ever checks the path, it never runs it here.
        let validated = validate(Path::new("/bin/sh")).expect("system shell path");
        assert!(validated.is_absolute());
        assert!(validated.is_file());
    }
}
