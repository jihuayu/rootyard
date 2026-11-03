use crate::config::Config;
use anyhow::{Context, Result, bail};
use fs2::FileExt;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use uuid::Uuid;

pub struct Storage {
    pub root: PathBuf,
    pub lock_file: File,
    pub volume_id: Uuid,
    locks: Mutex<HashMap<Uuid, Weak<AsyncMutex<()>>>>,
}

impl Storage {
    pub fn open(config: &Config) -> Result<Self> {
        crate::backup::ensure_not_restoring(&config.data_dir)?;
        std::fs::create_dir_all(&config.data_dir)?;
        let root = config.data_dir.canonicalize()?;
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(root.join(".rootyard.lock"))?;
        lock_file
            .try_lock_exclusive()
            .context("data directory already in use; do not start another writer")?;
        crate::backup::ensure_not_restoring(&root)?;
        let identity_path = root.join(".volume-id");
        let volume_id = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&identity_path)
        {
            Ok(file) => {
                use std::io::Read;
                if !file.metadata()?.is_file() || file.metadata()?.len() != 36 {
                    bail!("invalid volume identity file");
                }
                let mut bytes = String::new();
                file.take(128).read_to_string(&mut bytes)?;
                bytes.parse().context("invalid volume identity")?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                use std::io::Write;
                let id = Uuid::new_v4();
                let temporary = root.join(format!(".volume-id-{}.tmp", Uuid::new_v4()));
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&temporary)?;
                file.write_all(id.to_string().as_bytes())?;
                file.sync_all()?;
                std::fs::rename(&temporary, &identity_path)?;
                File::open(&root)?.sync_all()?;
                id
            }
            Err(error) => return Err(error.into()),
        };
        let repos = root.join("repos");
        std::fs::create_dir_all(&repos)?;
        if std::fs::symlink_metadata(&repos)?.file_type().is_symlink() {
            bail!("repos directory cannot be a symlink");
        }
        std::fs::set_permissions(&repos, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            root,
            lock_file,
            volume_id,
            locks: Mutex::new(HashMap::new()),
        })
    }
    pub fn repo_path(&self, id: Uuid) -> PathBuf {
        self.root.join("repos").join(format!("{id}.git"))
    }
    pub async fn write_lock(&self, id: Uuid) -> OwnedMutexGuard<()> {
        let lock = {
            let mut map = self.locks.lock().expect("lock map poisoned");
            map.retain(|_, v| v.strong_count() > 0);
            if let Some(lock) = map.get(&id).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(AsyncMutex::new(()));
                map.insert(id, Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }
    pub fn verify_path(&self, id: Uuid) -> Result<PathBuf> {
        let path = self.repo_path(id);
        let meta = std::fs::symlink_metadata(&path).context("repository volume is missing")?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            bail!("repository is not a real directory");
        }
        if path.canonicalize()?.parent() != Some(self.root.join("repos").as_path()) {
            bail!("repository escaped data root");
        }
        Ok(path)
    }
    pub async fn provision(&self, config: &Config, id: Uuid) -> Result<()> {
        let _lock = self.write_lock(id).await;
        let final_path = self.repo_path(id);
        if final_path.exists() {
            let path = self.verify_path(id)?;
            let out = self
                .git(config)
                .arg("--git-dir")
                .arg(path)
                .args(["config", "--get", "rootyard.repositoryId"])
                .output()
                .await?;
            if !out.status.success()
                || String::from_utf8_lossy(&out.stdout).trim() != id.to_string()
            {
                bail!("existing repository identity does not match metadata");
            }
            return Ok(());
        }
        let staging = self.root.join("repos").join(format!("{id}.init"));
        if let Ok(meta) = std::fs::symlink_metadata(&staging) {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                bail!("invalid staging directory");
            }
            // No request can access a provisioning directory. The process holds the
            // exclusive volume lock (also inherited by Git children), so a stale
            // staging tree and its config.lock cannot belong to an active writer.
            std::fs::remove_dir_all(&staging)?;
        }
        checked(
            self.git(config)
                .args([
                    "init",
                    "--bare",
                    "--object-format=sha1",
                    "--initial-branch=main",
                    "--template=",
                ])
                .arg(&staging),
        )
        .await?;
        let settings = [
            ("rootyard.repositoryId", id.to_string()),
            ("http.receivepack", "true".into()),
            ("http.getanyfile", "false".into()),
            ("receive.denyNonFastForwards", "true".into()),
            ("receive.denyDeleteCurrent", "true".into()),
            ("receive.fsckObjects", "true".into()),
            ("transfer.fsckObjects", "true".into()),
            ("receive.maxInputSize", config.max_request_bytes.to_string()),
            ("uploadpack.allowFilter", "false".into()),
            ("uploadpack.allowAnySHA1InWant", "false".into()),
            ("uploadpack.allowTipSHA1InWant", "false".into()),
            ("uploadpack.allowReachableSHA1InWant", "false".into()),
            ("core.logAllRefUpdates", "true".into()),
            ("core.fsync", "committed".into()),
            ("core.fsyncMethod", "fsync".into()),
            ("gc.auto", "0".into()),
            ("maintenance.auto", "false".into()),
            ("pack.threads", "1".into()),
            ("pack.windowMemory", "32m".into()),
            ("pack.deltaCacheSize", "32m".into()),
        ];
        for (key, value) in settings {
            checked(
                self.git(config)
                    .arg("--git-dir")
                    .arg(&staging)
                    .args(["config", key, &value]),
            )
            .await?;
        }
        // No arbitrary hooks or inherited template. The service OS identity owns this private tree.
        let stage = staging.clone();
        tokio::task::spawn_blocking(move || sync_tree(&stage)).await??;
        std::fs::rename(&staging, &final_path)?;
        File::open(self.root.join("repos"))?.sync_all()?;
        Ok(())
    }
    pub fn git(&self, config: &Config) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&config.git);
        cmd.env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("LC_ALL", "C")
            .env("GIT_TERMINAL_PROMPT", "0");
        let fd = self.lock_file.as_raw_fd();
        // Inherit the volume lock through Git descendants: after SIGKILL of the server,
        // a surviving receiver still prevents another process from taking the volume.
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.kill_on_drop(true);
        cmd
    }
}

async fn checked(cmd: &mut tokio::process::Command) -> Result<()> {
    let output = tokio::time::timeout(std::time::Duration::from_secs(30), cmd.output()).await??;
    if !output.status.success() {
        bail!("Git repository initialization failed");
    }
    Ok(())
}
fn sync_tree(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        bail!("unexpected symlink during initialization");
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            sync_tree(&entry?.path())?;
        }
    }
    File::open(path)?.sync_all()?;
    Ok(())
}
pub fn disk_bytes(path: &Path, limit: u64) -> Result<u64> {
    let mut total = 0u64;
    let mut dirs = vec![path.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if entry.file_type()?.is_symlink() {
                bail!("unexpected symlink in repository");
            }
            if meta.is_dir() {
                dirs.push(entry.path());
            } else {
                total = total.saturating_add(meta.len());
            }
            if total > limit {
                return Ok(total);
            }
        }
    }
    Ok(total)
}
