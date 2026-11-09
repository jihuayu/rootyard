//! Process kill/reopen of a real persisted vote; no quorum or Git ACK claim.
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn line(child: &mut Child) -> String {
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = tx.send(result);
    });
    let result = rx.recv_timeout(Duration::from_secs(10)).expect("probe output deadline").unwrap();
    reader.join().unwrap();
    result.trim().to_owned()
}

#[test]
fn acknowledged_vote_survives_sigkill_and_a_fresh_process() {
    let directory = tempfile::tempdir().unwrap();
    let executable = env!("CARGO_BIN_EXE_vote-probe");
    let mut writer = OwnedChild(
        Command::new(executable)
            .arg("write")
            .arg(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let ack = line(&mut writer.0);
    let durable = ack.strip_prefix("ACK ").expect("write did not acknowledge durability");
    let expected = serde_json::to_string(&Some(openraft::Vote::new(3_u64, 7_u64))).unwrap();
    assert_eq!(durable, expected);
    writer.0.kill().unwrap(); // std::process::Child::kill is SIGKILL on Unix.
    assert!(!writer.0.wait().unwrap().success());
    drop(writer);
    let mut reader =
        OwnedChild(Command::new(executable).arg("read").arg(directory.path()).stdout(Stdio::piped()).spawn().unwrap());
    assert_eq!(line(&mut reader.0), expected);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = reader.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "reopen process exit deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
}
