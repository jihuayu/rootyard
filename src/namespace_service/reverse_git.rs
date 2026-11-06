//! Bounded Git subprocesses for projected View import.
use crate::Error;
use axum::http::StatusCode;
use std::{
    cell::RefCell,
    io::{Read, Write},
    os::unix::process::CommandExt,
    path::Path as FsPath,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

const MAX_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_PROCESS_FILE: u64 = 256 * 1024 * 1024;
const MAX_WALL_SECONDS: u64 = 60;
struct ReadContext {
    cancel: Arc<AtomicBool>,
    volume_lock_fd: i32,
}
thread_local! {
    static READ_CONTEXT: RefCell<Option<ReadContext>> = const { RefCell::new(None) };
}

pub(super) fn with_read_cancel<T>(
    flag: Arc<AtomicBool>,
    volume_lock_fd: i32,
    work: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            READ_CONTEXT.with(|slot| *slot.borrow_mut() = None);
        }
    }
    READ_CONTEXT.with(|slot| {
        *slot.borrow_mut() = Some(ReadContext {
            cancel: flag,
            volume_lock_fd,
        })
    });
    let _reset = Reset;
    work()
}

fn read_cancelled() -> bool {
    READ_CONTEXT.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|ctx| ctx.cancel.load(Ordering::Acquire))
    })
}

fn lease_lost() -> Error {
    Error(StatusCode::SERVICE_UNAVAILABLE, "storage read lease lost")
}

fn limit(resource: libc::__rlimit_resource_t, value: u64) -> std::io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    if unsafe { libc::setrlimit(resource, &lim) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn command(repo: &FsPath, args: &[&str]) -> Command {
    let parent_pid = unsafe { libc::getpid() };
    let volume_lock_fd =
        READ_CONTEXT.with(|slot| slot.borrow().as_ref().map(|ctx| ctx.volume_lock_fd));
    let mut cmd = Command::new("git");
    cmd.arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(fd) = volume_lock_fd {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::getppid() != parent_pid {
                return Err(std::io::Error::other("Git parent exited before exec"));
            }
            limit(libc::RLIMIT_CPU, MAX_WALL_SECONDS + 2)?;
            limit(libc::RLIMIT_AS, 1024 * 1024 * 1024)?;
            limit(libc::RLIMIT_FSIZE, MAX_PROCESS_FILE)?;
            Ok(())
        });
    }
    cmd
}
fn run(mut cmd: Command, input: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    if read_cancelled() {
        return Err(lease_lost());
    }
    let cancel = READ_CONTEXT.with(|slot| slot.borrow().as_ref().map(|ctx| ctx.cancel.clone()));
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd.spawn().map_err(Error::internal)?;
    let pid = child.id() as i32;
    let (done, stop) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(MAX_WALL_SECONDS);
        loop {
            if cancel
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Acquire))
                || std::time::Instant::now() >= deadline
            {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                break;
            }
            if stop.recv_timeout(Duration::from_millis(50)).is_ok() {
                break;
            }
        }
    });
    // The writer must run while stdout is drained. cat-file emits output for
    // each input OID and otherwise deadlocks when both OS pipes fill.
    let writer = input.map(|bytes| {
        let bytes = bytes.to_vec();
        let mut stdin = child.stdin.take().expect("piped Git stdin");
        thread::spawn(move || stdin.write_all(&bytes))
    });
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::internal("missing Git stdout"))?;
    let mut output = Vec::new();
    let read_result = stdout
        .by_ref()
        .take((MAX_OUTPUT + 1) as u64)
        .read_to_end(&mut output);
    let oversized = output.len() > MAX_OUTPUT;
    if oversized || read_result.is_err() {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    // Leave the leader unreaped while killing and draining the process group.
    // Otherwise a lease-loss read could outlive its local GC gate.
    loop {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as u32,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc != 0 {
            return Err(Error::internal(std::io::Error::last_os_error()));
        }
        if unsafe { info.assume_init().si_pid() != 0 } {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let started = std::time::Instant::now();
    let mut reported = false;
    while !matches!(crate::git_http::group_quiescent(pid), Ok(true)) {
        if !reported && started.elapsed() > Duration::from_secs(5) {
            eprintln!("rootyard: reverse Git group cleanup blocked; retaining source gate");
            reported = true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let status = child.wait().map_err(Error::internal)?;
    let _ = done.send(());
    let _ = watchdog.join();
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| Error::internal("Git stdin worker panicked"))?
            .map_err(Error::internal)?;
    }
    if read_cancelled() {
        return Err(lease_lost());
    }
    read_result.map_err(Error::internal)?;
    if oversized {
        return Err(Error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Git output exceeds 16 MiB",
        ));
    }
    if !status.success() {
        return Err(Error(
            StatusCode::CONFLICT,
            "Git View reverse mapping conflict",
        ));
    }
    Ok(output)
}

pub(super) fn git(repo: &FsPath, args: &[&str]) -> Result<Vec<u8>, Error> {
    run(command(repo, args), None)
}
pub(super) fn git_oid(repo: &FsPath, args: &[&str]) -> Result<String, Error> {
    String::from_utf8(git(repo, args)?)
        .map(|s| s.trim().to_owned())
        .map_err(Error::internal)
}
pub(super) fn git_input(
    repo: &FsPath,
    args: &[&str],
    input: &[u8],
    actor: Option<&str>,
) -> Result<String, Error> {
    let mut cmd = command(repo, args);
    if let Some(actor) = actor {
        cmd.env("GIT_AUTHOR_NAME", actor)
            .env("GIT_COMMITTER_NAME", actor)
            .env(
                "GIT_AUTHOR_EMAIL",
                format!("{actor}@users.rootyard.invalid"),
            )
            .env(
                "GIT_COMMITTER_EMAIL",
                format!("{actor}@users.rootyard.invalid"),
            );
    }
    String::from_utf8(run(cmd, Some(input))?)
        .map(|s| s.trim().to_owned())
        .map_err(Error::internal)
}
pub(super) fn verify_candidate_budget(
    repo: &FsPath,
    candidate: &str,
    base: &str,
) -> Result<u64, Error> {
    let raw = git(
        repo,
        &["rev-list", "--objects", candidate, &format!("^{base}")],
    )?;
    let mut input = Vec::new();
    let mut count = 0usize;
    for row in raw.split(|b| *b == b'\n').filter(|r| !r.is_empty()) {
        let oid = row.split(|b| *b == b' ').next().unwrap_or_default();
        if oid.len() != 40 && oid.len() != 64 {
            return Err(Error::bad_request());
        }
        input.extend_from_slice(oid);
        input.push(b'\n');
        count += 1;
        if count > 100_000 {
            return Err(Error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "proposal has too many Git objects",
            ));
        }
    }
    let sizes = git_input(
        repo,
        &["cat-file", "--batch-check=%(objectsize)"],
        &input,
        None,
    )?;
    let mut total = 0u64;
    for size in sizes.lines() {
        total = total
            .checked_add(size.parse::<u64>().map_err(Error::internal)?)
            .ok_or_else(Error::bad_request)?;
        if total > MAX_PROCESS_FILE {
            return Err(Error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "proposal objects exceed 256 MiB",
            ));
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cat_file_drains_more_than_pipe_capacity() {
        let repo =
            std::env::temp_dir().join(format!("rootyard-reverse-git-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "--bare"]).unwrap();
        let oid = git_input(&repo, &["hash-object", "-w", "--stdin"], b"x", None).unwrap();
        let mut input = Vec::new();
        for _ in 0..60_000 {
            input.extend_from_slice(oid.as_bytes());
            input.push(b'\n');
        }
        let output = git_input(
            &repo,
            &["cat-file", "--batch-check=%(objectsize)"],
            &input,
            None,
        )
        .unwrap();
        assert_eq!(output.lines().count(), 60_000);
        std::fs::remove_dir_all(repo).unwrap();
    }
}
