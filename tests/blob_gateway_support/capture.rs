//! Byte-exact views of real Git request bodies captured by [`super::proxy`].
//!
//! Nothing here fabricates a Git request: [`CommandSection::parse`] reads the
//! pkt-line command section of a body a stock Git client really sent, and
//! [`CommandSection::without_atomic`] drops only the `atomic` capability.
use anyhow::{Result, anyhow, ensure};

/// The command/capability pkt-lines at the head of one receive-pack body.
#[derive(Debug, Clone)]
pub struct CommandSection {
    pub lines: Vec<String>,
}

impl CommandSection {
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut position = 0usize;
        let mut lines = Vec::new();
        loop {
            ensure!(position + 4 <= body.len(), "receive-pack body is truncated before its command flush");
            let length = usize::from_str_radix(&String::from_utf8_lossy(&body[position..position + 4]), 16)
                .map_err(|_| anyhow!("receive-pack command pkt-line length is invalid"))?;
            if length == 0 {
                let section = Self { lines };
                ensure!(!section.lines.is_empty(), "receive-pack command section is empty");
                return Ok(section);
            }
            ensure!(length >= 4 && position + length <= body.len(), "receive-pack command pkt-line is malformed");
            let payload = &body[position + 4..position + length];
            let text = std::str::from_utf8(payload).map_err(|_| anyhow!("receive-pack command is not UTF-8"))?;
            lines.push(text.trim_end_matches('\n').to_owned());
            position += length;
        }
    }

    /// The same commands without the `atomic` capability, like a stock client
    /// sends when it did not ask for an atomic transaction.
    pub fn without_atomic(&self) -> Result<Self> {
        let mut lines = Vec::with_capacity(self.lines.len());
        for line in &self.lines {
            let (command, capabilities) = match line.split_once('\0') {
                Some((command, capabilities)) => (command, Some(capabilities)),
                None => (line.as_str(), None),
            };
            let kept = capabilities
                .map(|value| value.split_whitespace().filter(|cap| *cap != "atomic").collect::<Vec<_>>().join(" "))
                .filter(|value| !value.is_empty());
            let rebuilt = match kept {
                Some(value) => format!("{command}\0{value}\n"),
                None => format!("{command}\n"),
            };
            lines.push(rebuilt);
        }
        Ok(Self { lines })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command section of a real stock client: two commands under
    /// `report-status` and `atomic`, followed by a body that stands for the
    /// client's PACK.
    const REAL: &[u8] = b"008d1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\0report-status side-band-64k atomic\n00671111111111111111111111111111111111111111 3333333333333333333333333333333333333333 refs/heads/stale\n0000PACK-UNTOUCHED";

    #[test]
    fn without_atomic_removes_only_the_capability() {
        let section = CommandSection::parse(REAL).unwrap().without_atomic().unwrap();
        assert!(section.lines[0].ends_with("report-status side-band-64k\n"));
        assert!(section.lines[0].contains('\0'));
        assert_eq!(
            section.lines[1],
            "1111111111111111111111111111111111111111 3333333333333333333333333333333333333333 refs/heads/stale\n"
        );
    }
}
