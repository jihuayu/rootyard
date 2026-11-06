//! Bounded Git subprocesses for projected View import.
use crate::Error;
use axum::http::StatusCode;
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    path::Path as FsPath,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

const MAX_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_PROCESS_FILE: u64 = 256 * 1024 * 1024;
const MAX_WALL_SECONDS: u64 = 60;

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
        cmd.pre_exec(|| {
            limit(libc::RLIMIT_CPU, MAX_WALL_SECONDS + 2)?;
            limit(libc::RLIMIT_AS, 1024 * 1024 * 1024)?;
            limit(libc::RLIMIT_FSIZE, MAX_PROCESS_FILE)?;
            Ok(())
        });
    }
    cmd
}
fn run(mut cmd: Command, input: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd.spawn().map_err(Error::internal)?;
    let pid = child.id() as i32;
    let (done, stop) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if stop
            .recv_timeout(Duration::from_secs(MAX_WALL_SECONDS))
            .is_err()
        {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
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
    let status = child.wait().map_err(Error::internal)?;
    let _ = done.send(());
    let _ = watchdog.join();
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| Error::internal("Git stdin worker panicked"))?
            .map_err(Error::internal)?;
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
