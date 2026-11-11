//! The headless Chromium client: the Playwright interpreter of the browser
//! image, a cleared environment, path-only arguments and exactly one sanitized
//! JSON summary line on stdout.
//!
//! The interpreter's own stderr shares one private mode-`0600` log file with
//! anything Chromium prints through it; that file is never read back or
//! printed, so a traceback or a log line can never reach the test output.
use std::{path::Path, process::Stdio, time::Duration};

use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

use super::{BROWSER_SECONDS, browser_python};

/// Run the script and return its one summary object.
pub(super) async fn run(script: &Path, config: &Path, log: &Path) -> Result<Value> {
    let python = browser_python()?;
    let name = script.file_name().ok_or_else(|| anyhow!("the browser script has no file name"))?;
    let stderr = std::fs::OpenOptions::new().append(true).open(log)?;
    ensure!(
        std::os::unix::fs::PermissionsExt::mode(&stderr.metadata()?.permissions()) & 0o077 == 0,
        "the browser log is not private"
    );
    let mut command = tokio::process::Command::new(&python);
    command
        .arg(name)
        .arg(config)
        .current_dir(script.parent().ok_or_else(|| anyhow!("the browser script has no directory"))?)
        .env_clear()
        .env("HOME", std::env::temp_dir())
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("PYTHONHASHSEED", "0")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(BROWSER_SECONDS), command.output())
        .await
        .map_err(|_| anyhow!("the headless Chromium run exceeded its bound"))??;
    ensure!(output.status.success(), "the headless Chromium client exited unsuccessfully");
    let stdout = String::from_utf8(output.stdout).map_err(|_| anyhow!("the browser summary was not UTF-8"))?;
    let lines: Vec<&str> = stdout.lines().filter(|line| !line.trim().is_empty()).collect();
    ensure!(lines.len() == 1, "the Chromium client did not print exactly one summary line");
    parse(lines[0])
}

fn parse(line: &str) -> Result<Value> {
    ensure!(line.len() <= 16 * 1024, "the browser summary is oversized");
    let summary: Value =
        serde_json::from_str(line).map_err(|_| anyhow!("the Chromium client printed no JSON summary"))?;
    ensure!(summary.is_object(), "the Chromium client printed no JSON summary object");
    Ok(summary)
}
