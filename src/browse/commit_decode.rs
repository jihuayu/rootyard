use crate::{
    Error,
    browse::models::{self, CommitSummary, TreeEntry},
};

use super::command::{GitStep, invalid_output};

/// A required object read that the verified object could not satisfy.
///
/// The object name has already been proved to exist by a precise quiet probe
/// (or came from a successful `rev-list`), so a malformed batch header, a
/// `missing` record, a truncated body or a missing mandatory header is a broken
/// native read: an internal failure with a fixed message, never a 404. The
/// diagnostic carries only the compiled step label, never Git text or
/// repository content.
fn corrupt_object(step: GitStep) -> Error {
    invalid_output(step)
}

fn parse_signature(sig: &str) -> (String, String, i64) {
    let Some(lt) = sig.rfind('<') else {
        return (sig.trim().to_owned(), String::new(), 0);
    };
    let name = sig[..lt].trim().to_owned();
    let rest = &sig[lt + 1..];
    let Some(gt) = rest.find('>') else {
        return (name, String::new(), 0);
    };
    let email = rest[..gt].trim().to_owned();
    let ts = rest[gt + 1..].split_whitespace().next().and_then(|t| t.parse::<i64>().ok()).unwrap_or(0);
    (name, email, ts)
}

pub fn parse_commit_raw(oid: &str, raw: &[u8]) -> Result<CommitSummary, Error> {
    let text = String::from_utf8_lossy(raw);
    let (header_block, body_block) = text.split_once("\n\n").unwrap_or((text.as_ref(), ""));
    let mut tree_oid = String::new();
    let mut parents = Vec::new();
    let (mut author_name, mut author_email, mut authored_at) = (String::new(), String::new(), 0);
    let (mut committer_name, mut committer_email, mut committed_at) = (String::new(), String::new(), 0);

    for line in header_block.lines() {
        if let Some(rest) = line.strip_prefix("tree ") {
            tree_oid = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("parent ") {
            let p = rest.trim();
            if models::valid_non_zero_oid(p) {
                parents.push(p.to_owned());
            }
        } else if let Some(rest) = line.strip_prefix("author ") {
            (author_name, author_email, authored_at) = parse_signature(rest);
        } else if let Some(rest) = line.strip_prefix("committer ") {
            (committer_name, committer_email, committed_at) = parse_signature(rest);
        }
    }
    if !models::valid_non_zero_oid(&tree_oid) {
        // Every commit object names a mandatory tree. This commit came from a
        // verified read (probe or successful rev-list), so a header without a
        // tree is a damaged object, not an absent one.
        return Err(corrupt_object(GitStep::CommitRead));
    }
    let message = body_block.trim_end_matches(['\r', '\n']).to_owned();
    let subject = message.lines().next().unwrap_or("").to_owned();
    Ok(CommitSummary {
        oid: oid.to_owned(),
        tree_oid,
        parents,
        author_name,
        author_email,
        authored_at,
        committer_name,
        committer_email,
        committed_at,
        subject,
        message,
    })
}

/// A malformed `cat-file --batch` answer for an object `rev-list` listed.
fn batch_corrupt() -> Error {
    corrupt_object(GitStep::CommitBatch)
}

/// Decode `cat-file --batch` output for object ids that came from a successful
/// `rev-list`.
///
/// `--batch` happily exits 0 while answering `"<oid> missing"`, and it can print
/// truncated or malformed records, so no failure here proves absence: each one
/// is an internal failure with a fixed message. Only the precise quiet
/// existence probes elsewhere may answer 404.
pub(super) fn parse_batch_commits(raw: &[u8], oids: &[String]) -> Result<Vec<CommitSummary>, Error> {
    let mut offset = 0usize;
    let mut result = Vec::with_capacity(oids.len());
    for oid in oids {
        let end = raw[offset..].iter().position(|&b| b == b'\n').ok_or_else(batch_corrupt)? + offset;
        let header = std::str::from_utf8(&raw[offset..end]).map_err(|_| batch_corrupt())?;
        let mut parts = header.split(' ');
        if parts.next() != Some(oid.as_str()) || parts.next() != Some("commit") {
            return Err(batch_corrupt());
        }
        let size: usize = parts.next().and_then(|s| s.parse().ok()).ok_or_else(batch_corrupt)?;
        if parts.next().is_some() || size > 256 * 1024 || size > raw.len().saturating_sub(end + 1) {
            return Err(batch_corrupt());
        }
        let start = end + 1;
        let finish = start + size;
        if raw.get(finish) != Some(&b'\n') {
            return Err(batch_corrupt());
        }
        result.push(parse_commit_raw(oid, &raw[start..finish])?);
        offset = finish + 1;
    }
    if offset != raw.len() {
        return Err(batch_corrupt());
    }
    Ok(result)
}

pub fn parse_ls_tree_output(raw: &[u8], rel_path: &str) -> Result<Vec<TreeEntry>, Error> {
    let mut entries = Vec::new();
    for record in raw.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        let line = String::from_utf8_lossy(record);
        let Some((meta, name)) = line.split_once('\t') else { continue };
        let parts: Vec<&str> = meta.split_whitespace().collect();
        if name.is_empty() || parts.len() < 4 || !models::valid_non_zero_oid(parts[2]) {
            continue;
        }
        let path = if rel_path.is_empty() { name.to_owned() } else { format!("{rel_path}/{name}") };
        entries.push(TreeEntry {
            name: name.to_owned(),
            path,
            mode: parts[0].to_owned(),
            kind: parts[1].to_owned(),
            oid: parts[2].to_owned(),
            size: parts[3].parse::<u64>().ok(),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    const OID: &str = "1111111111111111111111111111111111111111";
    const TREE: &str = "2222222222222222222222222222222222222222";
    const PARENT: &str = "3333333333333333333333333333333333333333";

    /// Corruption inside a required decode is a fixed internal failure (this
    /// service's internal class is 503) and never a 404.
    fn assert_internal(err: &Error) {
        assert!(err.0.is_server_error(), "broken read must be internal, got {}", err.0);
        assert_ne!(err.0, StatusCode::NOT_FOUND, "corruption is never an absent object");
        assert_eq!(err.1, "service temporarily unavailable", "fixed, secret-free message");
    }

    fn commit_body() -> String {
        format!(
            "tree {TREE}\nparent {PARENT}\nauthor A <a@example.invalid> 1700000000 +0000\n\
             committer C <c@example.invalid> 1700000001 +0000\n\nsubject line\n\nbody\n"
        )
    }

    fn batch(oid: &str, kind: &str, body: &str) -> Vec<u8> {
        format!("{oid} {kind} {}\n{body}\n", body.len()).into_bytes()
    }

    #[test]
    fn valid_commit_decode_is_preserved() {
        let summary = parse_commit_raw(OID, commit_body().as_bytes()).expect("valid commit");
        assert_eq!(summary.oid, OID);
        assert_eq!(summary.tree_oid, TREE);
        assert_eq!(summary.parents, vec![PARENT.to_owned()]);
        assert_eq!(summary.subject, "subject line");
        let decoded = parse_batch_commits(&batch(OID, "commit", &commit_body()), &[OID.to_owned()])
            .expect("valid batch");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].tree_oid, TREE);
    }

    #[test]
    fn commit_without_mandatory_tree_is_internal_not_missing() {
        let body = format!("parent {PARENT}\nauthor A <a@example.invalid> 1 +0000\n\nsubject\n");
        assert_internal(&parse_commit_raw(OID, body.as_bytes()).expect_err("missing tree"));
        assert_internal(&parse_batch_commits(&batch(OID, "commit", &body), &[OID.to_owned()])
            .expect_err("batch commit without tree"));
    }

    #[test]
    fn batch_missing_record_is_internal_not_missing() {
        // `cat-file --batch` exits 0 for an object it cannot find.
        let raw = format!("{OID} missing\n");
        assert_internal(&parse_batch_commits(raw.as_bytes(), &[OID.to_owned()]).expect_err("missing"));
    }

    #[test]
    fn batch_truncated_or_malformed_record_is_internal() {
        let truncated = format!("{OID} commit 4096\nshort body");
        assert_internal(&parse_batch_commits(truncated.as_bytes(), &[OID.to_owned()])
            .expect_err("truncated body"));
        let wrong_type = batch(OID, "blob", "abc");
        assert_internal(&parse_batch_commits(&wrong_type, &[OID.to_owned()]).expect_err("wrong type"));
        let no_record = b"".as_slice();
        assert_internal(&parse_batch_commits(no_record, &[OID.to_owned()]).expect_err("empty output"));
        let trailing = [batch(OID, "commit", &commit_body()), b"junk".to_vec()].concat();
        assert_internal(&parse_batch_commits(&trailing, &[OID.to_owned()]).expect_err("trailing bytes"));
    }
}
