use crate::{
    Error,
    browse::models::{self, CommitSummary},
};

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
        return Err(Error::not_found());
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

pub(super) fn parse_batch_commits(raw: &[u8], oids: &[String]) -> Result<Vec<CommitSummary>, Error> {
    let mut offset = 0usize;
    let mut result = Vec::with_capacity(oids.len());
    for oid in oids {
        let end = raw[offset..].iter().position(|&b| b == b'\n').ok_or_else(Error::not_found)? + offset;
        let header = std::str::from_utf8(&raw[offset..end]).map_err(|_| Error::not_found())?;
        let mut parts = header.split(' ');
        if parts.next() != Some(oid.as_str()) || parts.next() != Some("commit") {
            return Err(Error::not_found());
        }
        let size: usize = parts.next().and_then(|s| s.parse().ok()).ok_or_else(Error::not_found)?;
        if parts.next().is_some() || size > 256 * 1024 || size > raw.len().saturating_sub(end + 1) {
            return Err(Error::not_found());
        }
        let start = end + 1;
        let finish = start + size;
        if raw.get(finish) != Some(&b'\n') {
            return Err(Error::not_found());
        }
        result.push(parse_commit_raw(oid, &raw[start..finish])?);
        offset = finish + 1;
    }
    if offset != raw.len() {
        return Err(Error::not_found());
    }
    Ok(result)
}
