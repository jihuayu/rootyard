//! Git subprocess group lifecycle and bounded maintenance output.
use super::*;

pub(super) struct Process {
    pub(super) child: Child,
    pub(super) input: Option<JoinHandle<io::Result<()>>>,
    pub(super) stderr: JoinHandle<()>,
    pub(super) pid: i32,
}
impl Process {
    pub(super) async fn finish(&mut self) -> io::Result<std::process::ExitStatus> {
        // Observe leader exit without reaping it: the unreaped PID reserves the
        // process-group ID while we clean any surviving descendants. Tokio's
        // Child::wait would reap too early for a safe group signal afterwards.
        loop {
            let exited = {
                let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        self.pid as u32,
                        info.as_mut_ptr(),
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
                unsafe { info.assume_init().si_pid() != 0 }
            };
            if exited {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        unsafe {
            libc::kill(-self.pid, libc::SIGKILL);
        }
        self.wait_group_quiescent().await;
        let status = self.child.wait().await?;
        self.pid = 0;
        Ok(status)
    }
    async fn wait_group_quiescent(&self) {
        // Keep leader unreaped, reserving PGID, until every member is dead or
        // zombie. SIGKILL delivery alone is not proof a descendant stopped.
        let started = Instant::now();
        let mut reported = false;
        while !matches!(group_quiescent(self.pid), Ok(true)) {
            if !reported && started.elapsed() > std::time::Duration::from_secs(5) {
                eprintln!("rootyard: process group cleanup blocked; retaining write lock and capacity");
                reported = true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    pub(super) async fn stop(&mut self) {
        if let Some(input) = &self.input {
            input.abort();
        }
        if self.pid <= 0 {
            return;
        }
        // Keep the leader unreaped for the entire grace period. Otherwise an
        // early leader exit could permit PGID reuse while descendants remain.
        unsafe {
            libc::kill(-self.pid, libc::SIGTERM);
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        unsafe {
            libc::kill(-self.pid, libc::SIGKILL);
        }
        self.wait_group_quiescent().await;
        let _ = self.child.wait().await;
        self.pid = 0;
    }
}
pub(crate) fn group_quiescent(group: i32) -> io::Result<bool> {
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        // Controlled Git children never change user identity. A restricted
        // /proc may deny other users' processes; they cannot belong to our group.
        use std::os::unix::fs::MetadataExt;
        match entry.metadata() {
            Ok(meta) if meta.uid() != unsafe { libc::geteuid() } => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
            _ => {}
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH) => {
                continue;
            }
            Err(error) => return Err(error),
        };
        let Some((_, rest)) = stat.rsplit_once(") ") else {
            return Err(io::Error::other("invalid proc stat"));
        };
        let fields: Vec<_> = rest.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(io::Error::other("invalid proc stat"));
        }
        if fields[2].parse::<i32>().ok() == Some(group) && fields[0] != "Z" && fields[0] != "X" {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Reap a native Git leader only after every member of its process group is
/// dead. The unreaped leader reserves the PGID and prevents signaling reuse.
pub(crate) async fn finish_group_child(child: &mut Child) -> io::Result<std::process::ExitStatus> {
    let pid = child.id().ok_or_else(|| io::Error::other("missing Git PID"))? as i32;
    loop {
        let exited = {
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            let rc = unsafe {
                libc::waitid(libc::P_PID, pid as u32, info.as_mut_ptr(), libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { info.assume_init().si_pid() != 0 }
        };
        if exited {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    wait_group_child_quiescent(pid).await;
    child.wait().await
}

/// Cancellation and timeout path for a Git leader and all descendants.
pub(crate) async fn stop_group_child(child: &mut Child) -> io::Result<()> {
    let pid = child.id().ok_or_else(|| io::Error::other("missing Git PID"))? as i32;
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
    }
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    wait_group_child_quiescent(pid).await;
    let _ = child.wait().await?;
    Ok(())
}

/// Lease-loss path: SIGKILL immediately, then retain the unreaped leader until
/// every descendant stops. The caller keeps its local data guard throughout.
pub(crate) async fn kill_group_child(child: &mut Child) -> io::Result<()> {
    let pid = child.id().ok_or_else(|| io::Error::other("missing Git PID"))? as i32;
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    wait_group_child_quiescent(pid).await;
    let _ = child.wait().await?;
    Ok(())
}

async fn wait_group_child_quiescent(pid: i32) {
    let started = Instant::now();
    let mut reported = false;
    while !matches!(group_quiescent(pid), Ok(true)) {
        if !reported && started.elapsed() > std::time::Duration::from_secs(5) {
            eprintln!("rootyard: process group cleanup blocked; retaining maintenance guard");
            reported = true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        // The process group covers http-backend, receive/upload-pack and their workers.
        // A cancelled read future drops this Process before its caller releases
        // the local snapshot gate. Wait here, even on a Tokio worker thread:
        // SIGKILL delivery alone does not stop descendants before physical GC.
        if self.pid > 0 {
            unsafe {
                libc::kill(-self.pid, libc::SIGKILL);
            }
            let started = Instant::now();
            let mut reported = false;
            while !matches!(group_quiescent(self.pid), Ok(true)) {
                if !reported && started.elapsed() > std::time::Duration::from_secs(5) {
                    eprintln!("rootyard: cancelled Git process group cleanup blocked; retaining snapshot gate");
                    reported = true;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // The unreaped leader reserved the process-group ID throughout the
            // wait. Reaping is safe only after the group is quiescent.
            let _ = self.child.try_wait();
            self.pid = 0;
        }
        if let Some(input) = &self.input {
            input.abort();
        }
        self.stderr.abort();
    }
}

/// Fixed, secret-free description of a failed read-only Git invocation.
///
/// Only the process exit code leaves the child. Command-line arguments, stdout
/// and stderr stay inside the process group, so a credential, an object id or
/// repository content can never reach an HTTP body, a log record or a test
/// artifact through this type.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GitCommandFailed {
    pub(crate) exit: Option<i32>,
}

impl std::fmt::Display for GitCommandFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.exit {
            Some(code) => write!(formatter, "read-only Git command failed (exit {code})"),
            None => formatter.write_str("read-only Git command failed (signal)"),
        }
    }
}

impl std::error::Error for GitCommandFailed {}

/// Hard bounds for one streamed native read.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamLimits {
    /// Maximum number of records handed to the sink.
    pub(crate) max_records: usize,
    /// Maximum number of stdout bytes consumed from one child.
    pub(crate) max_bytes: usize,
    /// Maximum size of a single record line.
    pub(crate) max_record_bytes: usize,
}

/// Read chunk size for one streamed native read.
///
/// Deliberately independent of the per-record cap: a record is rejected the
/// moment it crosses `max_record_bytes`, so an unterminated record can never
/// make the reader hold more than one chunk beyond the per-record limit.
const STREAM_CHUNK_BYTES: usize = 4 * 1024;

/// Stream one Git command's stdout records through `sink`.
///
/// The sink receives one newline-delimited line at a time and returns `false`
/// when it has everything it needs; the child process group is then killed and
/// reaped before this function returns, so no producer is left writing into a
/// closed pipe. Records, total bytes and record size are bounded *while*
/// reading, and the read, the leader's exit and the process-group quiescence
/// all share one deadline: a child that closes stdout and then hangs cannot
/// park the caller past the timeout. On expiry the existing cancellation path
/// ([`Process::stop`]) signals the group and keeps the unreaped leader as the
/// PGID reservation until every member is dead. Only the exit code of a failed
/// child is reported; stdout, stderr and argv never leave the process group.
pub(crate) async fn stream_git_lines<F>(
    mut command: tokio::process::Command,
    limits: StreamLimits,
    timeout: std::time::Duration,
    mut sink: F,
) -> anyhow::Result<()>
where
    F: FnMut(&[u8]) -> bool,
{
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = child.id().ok_or_else(|| io::Error::other("missing Git PID"))? as i32;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let drain = tokio::spawn(async move {
        let mut bytes = [0u8; 4096];
        while matches!(stderr.read(&mut bytes).await,Ok(n) if n>0) {}
    });
    let mut process = Process { child, input: None, stderr: drain, pid };
    let outcome = tokio::time::timeout(timeout, async {
        let mut reader = stdout.take(limits.max_bytes as u64 + 1);
        let mut chunk = [0u8; STREAM_CHUNK_BYTES];
        let mut line = Vec::new();
        let mut consumed = 0usize;
        let mut records = 0usize;
        let mut satisfied = false;
        loop {
            let read = reader.read(&mut chunk[..]).await?;
            if read == 0 {
                break;
            }
            consumed = consumed.saturating_add(read);
            if consumed > limits.max_bytes {
                return Err(anyhow::anyhow!("maintenance output exceeds limit"));
            }
            let mut start = 0usize;
            while start < read {
                let available = &chunk[start..read];
                let newline = available.iter().position(|byte| *byte == b'\n');
                let take = newline.map_or(available.len(), |index| index + 1);
                // Bound the record before it grows: checking only after an
                // unbounded `read_until` would allocate the whole stream limit
                // first and would never return for an unterminated record.
                if line.len().saturating_add(take) > limits.max_record_bytes {
                    return Err(anyhow::anyhow!("maintenance output exceeds limit"));
                }
                line.extend_from_slice(&available[..take]);
                start += take;
                if newline.is_some() {
                    records = records.saturating_add(1);
                    if records > limits.max_records {
                        return Err(anyhow::anyhow!("maintenance output exceeds limit"));
                    }
                    let keep = sink(&line);
                    line.clear();
                    if !keep {
                        satisfied = true;
                        break;
                    }
                }
            }
            if satisfied {
                break;
            }
        }
        // A trailing record without a newline still reaches the sink.
        if !satisfied && !line.is_empty() {
            records = records.saturating_add(1);
            if records > limits.max_records {
                return Err(anyhow::anyhow!("maintenance output exceeds limit"));
            }
            satisfied = !sink(&line);
        }
        // Close our read end before the leader is reaped: a satisfied producer
        // gets EPIPE instead of blocking on a pipe nobody reads.
        drop(reader);
        if satisfied {
            unsafe {
                libc::kill(-process.pid, libc::SIGKILL);
            }
        }
        // The leader's exit and the process-group quiescence belong to the same
        // logical timeout as the read: a child that closes stdout but keeps
        // running must be cancelled below, never waited on forever.
        let status = process.finish().await?;
        // An early stop is an intentional termination: the sink already had what
        // it needed, so the group was killed on purpose and its exit status says
        // nothing about the read. Only a drained stream must prove that the
        // leader itself succeeded, so a failing native read still reports its
        // exit code instead of looking like a satisfied page.
        if !satisfied && !status.success() {
            return Err(anyhow::Error::new(GitCommandFailed { exit: status.code() }));
        }
        Ok::<(), anyhow::Error>(())
    })
    .await;
    match outcome {
        Ok(Ok(())) => Ok(()),
        // Every other outcome still needs the cancellation path. `stop` is a
        // no-op once `finish` reaped the leader, so a late failure is safe.
        Ok(Err(error)) => {
            process.stop().await;
            Err(error)
        }
        Err(_) => {
            process.stop().await;
            Err(anyhow::anyhow!("maintenance Git command timed out"))
        }
    }
}

/// Bounded read-only maintenance command using the same process-group cleanup.
pub(crate) async fn collect_git_output(
    command: tokio::process::Command,
    limit: usize,
    timeout: std::time::Duration,
) -> anyhow::Result<Vec<u8>> {
    collect_git_output_input(command, limit, timeout, Stdio::null()).await
}

pub(crate) async fn collect_git_output_input(
    mut command: tokio::process::Command,
    limit: usize,
    timeout: std::time::Duration,
    input: Stdio,
) -> anyhow::Result<Vec<u8>> {
    command.stdin(input).stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = child.id().ok_or_else(|| io::Error::other("missing Git PID"))? as i32;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let drain = tokio::spawn(async move {
        let mut bytes = [0u8; 4096];
        while matches!(stderr.read(&mut bytes).await,Ok(n) if n>0) {}
    });
    let mut process = Process { child, input: None, stderr: drain, pid };
    let mut output = Vec::new();
    let result = tokio::time::timeout(timeout, async {
        (&mut stdout).take(limit as u64 + 1).read_to_end(&mut output).await?;
        if output.len() > limit {
            return Err(anyhow::Error::new(io::Error::other("maintenance output exceeds limit")));
        }
        let status = process.finish().await?;
        if !status.success() {
            // Keep the historical "Git command failed" wording (existing
            // callers classify on it) and add only the exit code.
            return Err(anyhow::Error::new(GitCommandFailed { exit: status.code() }));
        }
        Ok::<(), anyhow::Error>(())
    })
    .await;
    process.stop().await;
    result.map_err(|_| io::Error::other("maintenance Git command timed out"))??;
    Ok(output)
}

#[cfg(test)]
mod process_tests {
    use super::*;

    async fn orphan_group() -> (Process, i32) {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("child.pid");
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.args([
            "-c",
            "sh -c 'trap \"\" TERM; echo $$ > \"$1\"; while :; do sleep 1; done' child \"$1\" & exit 0",
            "leader",
        ])
        .arg(&pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        let process = Process { child, input: None, stderr: tokio::spawn(async {}), pid };
        let started = Instant::now();
        let child_pid = loop {
            if let Ok(text) = std::fs::read_to_string(&pid_file)
                && let Ok(pid) = text.trim().parse::<i32>()
            {
                break pid;
            }
            assert!(started.elapsed().as_secs() < 5, "test child failed to start");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        (process, child_pid)
    }
    async fn assert_not_running(pid: i32) {
        let started = Instant::now();
        loop {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(_) => return,
                Ok(text) if text.rsplit_once(") ").is_some_and(|(_, tail)| tail.starts_with('Z')) => {
                    return;
                }
                _ => {}
            }
            assert!(started.elapsed().as_secs() < 5, "descendant survived group cleanup");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    #[tokio::test]
    async fn successful_leader_does_not_leave_descendants() {
        let (mut process, child_pid) = orphan_group().await;
        let leader = process.pid;
        assert!(process.finish().await.unwrap().success());
        assert_not_running(child_pid).await;
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists(), "leader was not reaped");
    }
    #[tokio::test]
    async fn timeout_cleans_term_ignoring_descendants_before_reaping() {
        let (mut process, child_pid) = orphan_group().await;
        let leader = process.pid;
        process.stop().await;
        assert_not_running(child_pid).await;
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists(), "leader was not reaped");
    }
    #[tokio::test]
    async fn maintenance_helpers_wait_for_descendant_quiescence() {
        let (mut finished, finished_child) = orphan_group().await;
        let leader = finished.pid;
        assert!(finish_group_child(&mut finished.child).await.unwrap().success());
        finished.pid = 0;
        assert_not_running(finished_child).await;
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists());

        let (mut cancelled, cancelled_child) = orphan_group().await;
        let leader = cancelled.pid;
        stop_group_child(&mut cancelled.child).await.unwrap();
        cancelled.pid = 0;
        assert_not_running(cancelled_child).await;
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists());
    }
    #[tokio::test]
    async fn cancellation_drop_waits_for_all_descendants() {
        let (process, descendant) = orphan_group().await;
        let leader = process.pid;
        drop(process);
        assert_not_running(descendant).await;
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists());
    }
    /// The per-record cap is enforced while reading: an unterminated record must
    /// end the read, not buffer the whole stream limit and then block until the
    /// deadline.
    #[tokio::test]
    async fn unterminated_record_is_rejected_while_reading() {
        // 4 MiB of a single record with no newline is far below the 64 MiB total
        // cap, and the writer then sleeps, so no EOF can end `read_until`-style
        // accumulation. Only a cap applied in-read can answer here.
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "head -c 4194304 /dev/zero | tr '\\0' x; exec sleep 300"]);
        let limits = StreamLimits { max_records: 1024, max_bytes: 64 * 1024 * 1024, max_record_bytes: 64 * 1024 };
        let started = Instant::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            stream_git_lines(command, limits, std::time::Duration::from_secs(30), |_| true),
        )
        .await
        .expect("the record cap must end the read before the stream deadline");
        let error = result.expect_err("an unterminated 4 MiB record must be rejected");
        assert!(error.to_string().contains("exceeds limit"), "unexpected error: {error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "the per-record cap was applied only after buffering the stream limit"
        );
    }
    /// The record cap counts the delimiter, exactly like the released limit.
    #[tokio::test]
    async fn record_cap_counts_the_trailing_newline() {
        let limits = StreamLimits { max_records: 8, max_bytes: 64, max_record_bytes: 8 };
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "printf 'abcdefg\\n'"]);
        let mut seen = Vec::new();
        stream_git_lines(command, limits, std::time::Duration::from_secs(10), |line| {
            seen.extend_from_slice(line);
            true
        })
        .await
        .unwrap();
        assert_eq!(seen, b"abcdefg\n".to_vec());

        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "printf 'abcdefgh\\n'"]);
        let error = stream_git_lines(command, limits, std::time::Duration::from_secs(10), |_| true)
            .await
            .expect_err("one byte over the cap must be rejected");
        assert!(error.to_string().contains("exceeds limit"), "unexpected error: {error}");
    }
    /// A child that closes stdout and then hangs must still be stopped at the
    /// logical deadline: EOF on stdout is not proof that the leader exited.
    #[tokio::test]
    async fn child_that_closes_stdout_and_hangs_is_stopped_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("hang.pid");
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "echo $$ > \"$1\"; printf 'a\\n'; exec 1>&-; sleep 300", "hang"]).arg(&pid_file);
        let limits = StreamLimits { max_records: 16, max_bytes: 1024 * 1024, max_record_bytes: 4096 };
        let mut lines = 0usize;
        let started = Instant::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream_git_lines(command, limits, std::time::Duration::from_millis(500), |_| {
                lines += 1;
                true
            }),
        )
        .await
        .expect("EOF on stdout must not leave the leader running past the deadline");
        let error = result.expect_err("a hung leader must not be reported as a finished read");
        assert!(error.to_string().contains("timed out"), "unexpected error: {error}");
        assert_eq!(lines, 1, "the complete line before EOF must still reach the sink");
        assert!(started.elapsed() < std::time::Duration::from_secs(20), "the deadline was not enforced");
        let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
        assert_not_running(pid).await;
    }
    /// A sink that already has what it needs ends the read successfully: the
    /// group is killed on purpose, so the producer's signal status is not a
    /// failed Git command.
    #[tokio::test]
    async fn satisfied_sink_returns_success_and_leaves_no_live_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("producer.pid");
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "echo $$ > \"$1\"; printf 'a\\nb\\nc\\n'; exec sleep 300", "producer"]).arg(&pid_file);
        let limits = StreamLimits { max_records: 16, max_bytes: 1024 * 1024, max_record_bytes: 4096 };
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let started = Instant::now();
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream_git_lines(command, limits, std::time::Duration::from_secs(10), |line| {
                seen.push(line.to_vec());
                seen.len() < 2
            }),
        )
        .await
        .expect("a satisfied sink must stop the producer, not wait for it")
        .expect("an intentional early stop is a success, not a failed Git command");
        assert_eq!(seen.len(), 2, "the sink must stop the stream after its second record");
        assert_eq!(seen[0].as_slice(), &b"a\n"[..]);
        assert_eq!(seen[1].as_slice(), &b"b\n"[..]);
        assert!(started.elapsed() < std::time::Duration::from_secs(20), "the producer was not stopped early");
        let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
        assert_not_running(pid).await;
    }
}
