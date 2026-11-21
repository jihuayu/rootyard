//! Bounded filesystem hints for workspace reconciliation.
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[cfg(any(target_os = "linux", test))]
const MAX_DIRTY: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Hint {
    Dirty(Vec<Uuid>),
    Sweep,
}

#[derive(Default)]
struct Pending {
    sweep: bool,
    ids: BTreeSet<Uuid>,
}

impl Pending {
    #[cfg(any(target_os = "linux", test))]
    fn mark(&mut self, id: Uuid) {
        if !self.sweep {
            self.ids.insert(id);
            if self.ids.len() > MAX_DIRTY {
                self.require_sweep();
            }
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn require_sweep(&mut self) {
        self.ids.clear();
        self.sweep = true;
    }

    fn take(&mut self) -> Option<Hint> {
        if std::mem::take(&mut self.sweep) {
            Some(Hint::Sweep)
        } else if self.ids.is_empty() {
            None
        } else {
            Some(Hint::Dirty(std::mem::take(&mut self.ids).into_iter().collect()))
        }
    }
}

#[derive(Default)]
struct Mailbox {
    pending: std::sync::Mutex<Pending>,
    wake: Notify,
}

pub(super) struct Watch {
    mailbox: Arc<Mailbox>,
    stop: CancellationToken,
    worker: Option<tokio::task::JoinHandle<()>>,
}

impl Watch {
    pub(super) fn start(root: PathBuf, stop: CancellationToken) -> Self {
        let mailbox = Arc::new(Mailbox::default());
        let stop = stop.child_token();
        #[cfg(target_os = "linux")]
        let worker = {
            let mailbox = mailbox.clone();
            let stop = stop.clone();
            Some(tokio::task::spawn_blocking(move || {
                if linux::run(&root, &mailbox, &stop).is_err() && !stop.is_cancelled() {
                    mailbox.sweep();
                }
            }))
        };
        #[cfg(not(target_os = "linux"))]
        let worker = {
            let _ = root;
            None
        };
        Self { mailbox, stop, worker }
    }

    pub(super) async fn recv(&self) -> Hint {
        loop {
            if let Some(hint) = self.mailbox.pending.lock().unwrap().take() {
                return hint;
            }
            self.mailbox.wake.notified().await;
        }
    }

    pub(super) async fn shutdown(mut self) {
        self.stop.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.await;
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

#[cfg(target_os = "linux")]
impl Mailbox {
    fn sweep(&self) {
        self.pending.lock().unwrap().require_sweep();
        self.wake.notify_one();
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Mailbox;
    use std::{
        collections::HashMap,
        ffi::{CString, OsStr},
        fs::{self, File, OpenOptions},
        io::{self, Read},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        },
        path::{Path, PathBuf},
        time::Duration,
    };
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    const MAX_WATCHES: usize = 4096;
    const MAX_ENTRIES: usize = 16_384;
    const MAX_DEPTH: usize = 64;
    const MASK: u32 = libc::IN_ATTRIB
        | libc::IN_CLOSE_WRITE
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO
        | libc::IN_DELETE_SELF
        | libc::IN_MOVE_SELF
        | libc::IN_ONLYDIR
        | libc::IN_EXCL_UNLINK;
    const DIRECTORY_CHANGE: u32 = libc::IN_CREATE | libc::IN_DELETE | libc::IN_MOVED_FROM | libc::IN_MOVED_TO;
    const INVALIDATED: u32 = libc::IN_IGNORED | libc::IN_UNMOUNT | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF;

    #[derive(Clone, Copy)]
    enum Scope {
        ServiceRoot,
        Layer,
        Workspace(Uuid),
    }

    struct Registry<'a> {
        fd: File,
        scopes: HashMap<i32, Scope>,
        entries_left: usize,
        stop: &'a CancellationToken,
    }

    impl<'a> Registry<'a> {
        fn new(stop: &'a CancellationToken) -> io::Result<Self> {
            // SAFETY: successful initialization returns a new owned descriptor.
            let fd = owned_file(unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) })?;
            Ok(Self { fd, scopes: HashMap::new(), entries_left: MAX_ENTRIES, stop })
        }

        fn add(&mut self, directory: &File, scope: Scope) -> bool {
            if self.scopes.len() >= MAX_WATCHES || self.stop.is_cancelled() {
                return false;
            }
            let path = CString::new(fd_path(directory).as_os_str().as_bytes()).expect("descriptor path");
            // SAFETY: the descriptor path is NUL-terminated and remains valid during the syscall.
            let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), path.as_ptr(), MASK) };
            if wd < 0 {
                return false;
            }
            self.scopes.insert(wd, scope);
            true
        }

        fn visit_entry(&mut self) -> bool {
            if self.entries_left == 0 || self.scopes.len() >= MAX_WATCHES || self.stop.is_cancelled() {
                return false;
            }
            self.entries_left -= 1;
            true
        }

        fn layer(&mut self, service: &File, name: &str) {
            let Ok(layer) = open_child(service, OsStr::new(name)) else { return };
            if !self.add(&layer, Scope::Layer) {
                return;
            }
            let Ok(entries) = fs::read_dir(fd_path(&layer)) else { return };
            for entry in entries {
                if !self.visit_entry() {
                    break;
                }
                let Ok(entry) = entry else { continue };
                let name = entry.file_name();
                let Some(id) = name.to_str().and_then(|name| name.parse::<Uuid>().ok()) else { continue };
                if name != OsStr::new(&id.to_string()) {
                    continue;
                }
                if let Ok(directory) = open_child(&layer, &name) {
                    self.walk(&directory, id, false, 0);
                }
            }
        }

        fn walk(&mut self, directory: &File, id: Uuid, git: bool, depth: usize) {
            if !self.add(directory, Scope::Workspace(id)) || depth == MAX_DEPTH {
                return;
            }
            let Ok(entries) = fs::read_dir(fd_path(directory)) else { return };
            for entry in entries {
                if !self.visit_entry() {
                    break;
                }
                let Ok(entry) = entry else { continue };
                let name = entry.file_name();
                if (git && name == "objects") || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    continue;
                }
                if let Ok(child) = open_child(directory, &name) {
                    self.walk(&child, id, name == ".git", depth + 1);
                }
            }
        }

        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let mut poll = libc::pollfd { fd: self.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            // SAFETY: poll points to one initialized descriptor and the wait is bounded.
            let ready = unsafe { libc::poll(&mut poll, 1, 100) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                return if error.kind() == io::ErrorKind::Interrupted { Ok(0) } else { Err(error) };
            }
            if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("workspace inotify descriptor unavailable"));
            }
            if poll.revents & libc::POLLIN == 0 {
                return Ok(0);
            }
            match self.fd.read(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(0),
                result => result,
            }
        }

        // Rebuild on any relevant directory movement or loss rather than
        // retaining stale paths or letting retired kernel watches consume the cap.
        fn collect(&self, mut bytes: &[u8], mailbox: &Mailbox) -> bool {
            let mut pending = mailbox.pending.lock().unwrap();
            let header = std::mem::size_of::<libc::inotify_event>();
            while bytes.len() >= header {
                // SAFETY: the kernel event header fits in bytes and need not be aligned.
                let event = unsafe { bytes.as_ptr().cast::<libc::inotify_event>().read_unaligned() };
                let Some((name, rest)) = bytes[header..].split_at_checked(event.len as usize) else { return true };
                bytes = rest;
                if event.mask & libc::IN_Q_OVERFLOW != 0 {
                    return true;
                }
                let Some(scope) = self.scopes.get(&event.wd).copied() else { continue };
                if event.mask & INVALIDATED != 0 {
                    return true;
                }
                let topology = event.mask & libc::IN_ISDIR != 0 && event.mask & DIRECTORY_CHANGE != 0;
                match scope {
                    Scope::ServiceRoot => {
                        if topology && matches!(name.split(|byte| *byte == 0).next(), Some(b"workspaces" | b"uppers")) {
                            return true;
                        }
                    }
                    Scope::Layer if topology => return true,
                    Scope::Workspace(_) if topology => return true,
                    Scope::Workspace(id) => pending.mark(id),
                    Scope::Layer => {}
                }
            }
            drop(pending);
            mailbox.wake.notify_one();
            !bytes.is_empty()
        }
    }

    pub(super) fn run(root: &Path, mailbox: &Mailbox, stop: &CancellationToken) -> io::Result<()> {
        let mut buffer = vec![0; 64 * 1024];
        while !stop.is_cancelled() {
            let Ok(service) =
                OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY).open(root)
            else {
                // The application may not have created the service root yet.
                std::thread::sleep(Duration::from_millis(250));
                continue;
            };
            let mut registry = Registry::new(stop)?;
            if !registry.add(&service, Scope::ServiceRoot) {
                return Err(io::Error::other("workspace inotify root unavailable"));
            }
            registry.layer(&service, "workspaces");
            registry.layer(&service, "uppers");
            if stop.is_cancelled() {
                break;
            }
            // Establish watches before requesting the full reconciliation.
            mailbox.sweep();
            while !stop.is_cancelled() {
                let count = registry.read(&mut buffer)?;
                if count > 0 && registry.collect(&buffer[..count], mailbox) {
                    break;
                }
            }
            drop(registry);
            // Coalesce bursts of mkdir/rename/overflow across a bounded rebuild interval.
            if !stop.is_cancelled() {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        Ok(())
    }

    #[test]
    fn queue_overflow_requests_a_registry_rebuild() {
        let stop = CancellationToken::new();
        let registry = Registry::new(&stop).unwrap();
        let mailbox = Mailbox::default();
        let mut event = Vec::new();
        event.extend_from_slice(&(-1_i32).to_ne_bytes());
        event.extend_from_slice(&libc::IN_Q_OVERFLOW.to_ne_bytes());
        event.extend_from_slice(&0_u32.to_ne_bytes()); // cookie
        event.extend_from_slice(&0_u32.to_ne_bytes()); // no file name
        assert!(registry.collect(&event, &mailbox));
    }

    fn fd_path(directory: &File) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
    }

    fn open_child(parent: &File, name: &OsStr) -> io::Result<File> {
        let name = CString::new(name.as_bytes())?;
        // SAFETY: name is one directory entry relative to a live, pinned directory.
        // O_NOFOLLOW rejects symlinks even if the entry changed after read_dir.
        owned_file(unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })
    }

    fn owned_file(fd: i32) -> io::Result<File> {
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: callers pass only descriptors returned by an allocating syscall.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_many_dirty_workspaces_request_one_full_sweep() {
        let mut pending = Pending::default();
        for id in 0..=MAX_DIRTY {
            pending.mark(Uuid::from_u128(id as u128));
        }
        pending.mark(Uuid::from_u128(999));
        assert_eq!(pending.take(), Some(Hint::Sweep));
        assert_eq!(pending.take(), None);
        let id = Uuid::from_u128(1);
        pending.mark(id);
        pending.mark(id);
        assert_eq!(pending.take(), Some(Hint::Dirty(vec![id])));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn detects_editor_replacement_and_new_subdirectory() {
        use std::{fs, time::Duration};
        let root = tempfile::tempdir().unwrap();
        let id = Uuid::from_u128(1);
        let workspace = root.path().join("workspaces").join(id.to_string());
        let upper = root.path().join("uppers").join(id.to_string());
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&upper).unwrap();
        fs::write(workspace.join("README"), b"before").unwrap();
        fs::write(workspace.join("README.tmp"), b"after").unwrap();
        let stop = CancellationToken::new();
        let watch = Watch::start(root.path().to_owned(), stop);
        let next = || tokio::time::timeout(Duration::from_secs(5), watch.recv());
        assert_eq!(next().await.unwrap(), Hint::Sweep);

        fs::rename(workspace.join("README.tmp"), workspace.join("README")).unwrap();
        assert_eq!(next().await.unwrap(), Hint::Dirty(vec![id]));

        let child = upper.join("new-subdirectory");
        fs::create_dir(&child).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async { while watch.recv().await != Hint::Sweep {} })
            .await
            .unwrap();
        fs::write(child.join("child"), b"captured").unwrap();
        assert_eq!(next().await.unwrap(), Hint::Dirty(vec![id]));
        tokio::time::timeout(Duration::from_secs(2), watch.shutdown()).await.unwrap();
    }
}
