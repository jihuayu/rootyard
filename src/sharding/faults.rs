//! Opt-in native fault injection for crash-phase tests only.
//!
//! Hooks are inert unless both `ROOTYARD_TEST_FAULT_ALLOW=1` and
//! `ROOTYARD_TEST_FAULT=<phase>` are set. They persist a small diagnostic
//! marker under the data directory and can then self-deliver SIGKILL so a test
//! observes a real process death at a deterministic durable boundary. They
//! never mutate repository, route, journal or sidecar state, so a production
//! process with these variables absent behaves exactly like the normal binary.
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_PAUSE_MS: u64 = 15_000;

const PHASES: &[&str] = &[
    "copy-before-transfer",
    "copy-after-transfer",
    "final-delta-before-transfer",
    "cutover-before-commit",
    "cutover-after-commit",
    "cutover-before-sidecar-finalize",
    "target-copy-after-receive",
    "target-verify-before-publish",
    "target-delta-before-verified",
    "target-sidecar-before-publish",
    "recover-before-reconcile",
    "takeover-after-source-verify",
    "takeover-before-promote",
];

fn marker_directory(root: &Path) -> Result<PathBuf, std::io::Error> {
    let dir = root.join(".native-test-faults");
    match fs::symlink_metadata(&dir) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(dir),
        Ok(_) => Err(std::io::Error::other("unsafe fault marker directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            File::open(root)?.sync_all()?;
            Ok(dir)
        }
        Err(error) => Err(error),
    }
}

fn write_marker(root: &Path, phase: &str, detail: &Value) -> Result<(), std::io::Error> {
    let dir = marker_directory(root)?;
    let record = json!({
        "version": 1,
        "phase": phase,
        "pid": std::process::id(),
        "unix": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        "detail": detail,
    });
    let bytes = serde_json::to_vec_pretty(&record).map_err(std::io::Error::other)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let token = now.as_nanos() ^ ((std::process::id() as u128) << 96);
    let temporary = dir.join(format!(".tmp-{}-{token:032x}", std::process::id()));
    let mut file =
        OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, dir.join(format!("{phase}.json")))?;
    File::open(&dir)?.sync_all()?;
    Ok(())
}

/// Emit an opt-in marker at a durable phase boundary. `root` is the data root.
pub(crate) fn hit(root: &Path, phase: &str, detail: Value) {
    if std::env::var("ROOTYARD_TEST_FAULT_ALLOW").as_deref() != Ok("1") {
        return;
    }
    let Ok(configured) = std::env::var("ROOTYARD_TEST_FAULT") else {
        return;
    };
    if configured != phase || !PHASES.contains(&phase) {
        return;
    }
    if let Err(error) = write_marker(root, phase, &detail) {
        eprintln!("rootyard: test fault marker could not be persisted: {error}");
        return;
    }
    match std::env::var("ROOTYARD_TEST_FAULT_ACTION").as_deref() {
        Ok("kill") => unsafe {
            libc::kill(std::process::id() as i32, libc::SIGKILL);
        },
        Ok("pause") => {
            let millis = std::env::var("ROOTYARD_TEST_FAULT_PAUSE_MS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(5_000)
                .min(MAX_PAUSE_MS);
            std::thread::sleep(Duration::from_millis(millis));
        }
        _ => {}
    }
}
