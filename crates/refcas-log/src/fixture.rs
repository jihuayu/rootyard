//! Device, filesystem, and writability qualification run before durable store fixtures.

use std::fs::OpenOptions;
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{E, Res};

/// Minimum default free disk space required before running a persistent fault fixture (8 MiB).
pub const DEFAULT_MIN_FREE_BYTES: u64 = 8 * 1024 * 1024;

/// Observed device and filesystem properties of a qualified store directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedFixture {
    pub path: PathBuf,
    pub device: Option<String>,
    pub fstype: Option<String>,
    pub mount_point: Option<String>,
    pub metadata_dev: Option<u64>,
    pub available_bytes: u64,
    pub probe_fsync_ok: bool,
}

/// Ensures `dir` exists, passes available-space and fsync probe checks, and on Linux passes
/// mountinfo network-filesystem and FUSE exclusions before tests or probes touch it.
pub fn qualify_store_dir(dir: &Path, require_temp_prefix: bool, min_free_bytes: u64) -> Res<QualifiedFixture> {
    std::fs::create_dir_all(dir)?;
    let canonical = dir.canonicalize()?;
    if require_temp_prefix {
        let temp = std::env::temp_dir().canonicalize()?;
        if !canonical.starts_with(&temp) {
            return Err(E::Refused(format!(
                "fixture {} is outside the temp directory {}",
                canonical.display(),
                temp.display()
            )));
        }
    }

    let available_bytes = fs2::available_space(&canonical)?;
    if available_bytes < min_free_bytes {
        return Err(E::Refused(format!(
            "fixture {} has only {available_bytes} free bytes (< {min_free_bytes})",
            canonical.display()
        )));
    }

    probe_write_and_fsync(&canonical)?;
    qualify_platform_mount(canonical, available_bytes)
}

/// Verifies `artifact` resides on the same backing device as `dir` on Linux.
pub fn verify_same_device(dir: &Path, artifact: &Path) -> Res<()> {
    #[cfg(target_os = "linux")]
    {
        let dir_dev = std::fs::metadata(dir)?.dev();
        let art_dev = std::fs::metadata(artifact)?.dev();
        if dir_dev != art_dev {
            return Err(E::Refused(format!(
                "artifact {} (dev {art_dev}) crossed device boundary from {} (dev {dir_dev})",
                artifact.display(),
                dir.display()
            )));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dir, artifact);
    }
    Ok(())
}

fn probe_write_and_fsync(dir: &Path) -> Res<()> {
    let probe_path = dir.join(format!(".refcas-probe-{}", std::process::id()));
    let write_res = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&probe_path)?;
        f.write_all(b"refcas-fsync-probe\n")?;
        f.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&probe_path);
    write_res?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn qualify_platform_mount(canonical: PathBuf, available_bytes: u64) -> Res<QualifiedFixture> {
    let (device, fstype, mount_point) = fixture_mount(&canonical)
        .ok_or_else(|| E::Refused(format!("unable to resolve mountinfo for {}", canonical.display())))?;
    const NETWORK: &[&str] = &[
        "nfs",
        "nfs4",
        "cifs",
        "smb",
        "smb3",
        "smbfs",
        "9p",
        "ceph",
        "glusterfs",
        "afs",
        "davfs",
        "davfs2",
        "lustre",
        "gpfs",
        "fuse.sshfs",
        "fuse.rclone",
        "fuse.glusterfs",
        "fuse.ceph",
        "fuse.smbnetfs",
        "fuse.davfs",
        "fuse.davfs2",
        "fuse.s3fs",
        "fuse.gcsfuse",
        "fuse.goofys",
        "fuse.juicefs",
    ];
    let lowered = fstype.to_ascii_lowercase();
    if NETWORK.iter().any(|kind| lowered == *kind || lowered.starts_with(&format!("{kind}."))) {
        return Err(E::Refused(format!("fixture filesystem {fstype} at {mount_point} is a network filesystem")));
    }
    if matches!(lowered.as_str(), "fuse" | "fuseblk") || lowered.starts_with("fuse.") {
        return Err(E::Refused(format!("fixture filesystem {fstype} at {mount_point} is an unqualified FUSE mount")));
    }
    let metadata_dev = std::fs::metadata(&canonical)?.dev();
    Ok(QualifiedFixture {
        path: canonical,
        device: Some(device),
        fstype: Some(fstype),
        mount_point: Some(mount_point),
        metadata_dev: Some(metadata_dev),
        available_bytes,
        probe_fsync_ok: true,
    })
}

#[cfg(not(target_os = "linux"))]
fn qualify_platform_mount(canonical: PathBuf, available_bytes: u64) -> Res<QualifiedFixture> {
    Ok(QualifiedFixture {
        path: canonical,
        device: None,
        fstype: None,
        mount_point: None,
        metadata_dev: None,
        available_bytes,
        probe_fsync_ok: true,
    })
}

#[cfg(target_os = "linux")]
fn fixture_mount(path: &Path) -> Option<(String, String, String)> {
    let data = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut best: Option<(usize, (String, String, String))> = None;
    for line in data.lines() {
        let Some((left, right)) = line.split_once(" - ") else { continue };
        let left: Vec<&str> = left.split_whitespace().collect();
        let right: Vec<&str> = right.split_whitespace().collect();
        if left.len() < 5 || right.is_empty() {
            continue;
        }
        let mount_point = decode_mount_escape(left[4]);
        if !path.starts_with(Path::new(&mount_point)) {
            continue;
        }
        let len = mount_point.len();
        if best.as_ref().is_none_or(|(best_len, _)| len > *best_len) {
            best = Some((len, (left[2].to_owned(), right[0].to_owned(), mount_point)));
        }
    }
    best.map(|(_, mount)| mount)
}

#[cfg(target_os = "linux")]
fn decode_mount_escape(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..index + 4].iter().all(|byte| byte.is_ascii_digit())
        {
            let value = u16::from(bytes[index + 1] - b'0') * 64
                + u16::from(bytes[index + 2] - b'0') * 8
                + u16::from(bytes[index + 3] - b'0');
            if let Ok(byte) = u8::try_from(value) {
                out.push(byte);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
