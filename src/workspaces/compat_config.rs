//! Strict allowlist `.git/config` validation for hosted workspaces.

use super::{CONFLICT_CONFIG, CONFLICT_FILTERS, CONFLICT_HEAD, CONFLICT_INDEX, CONFLICT_SUBMODULE};
use crate::Error;
use axum::http::StatusCode;

/// Validate `.git/config` using an allowlist matching safe `git clone` and local workflow keys.
/// Any `include`, `filter.*`, `diff.*`, `merge.*`, `extensions.*`, `core.hooksPath`,
/// `core.worktree`, `core.fsmonitor`, `core.untrackedCache`, `core.sparseCheckout`, or
/// `core.splitIndex` is rejected deterministically with `409 Conflict`.
pub(in crate::workspaces) fn validate_config_bytes(bytes: &[u8]) -> Result<(), Error> {
    if bytes.contains(&0) {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
    };
    let mut section: Option<(String, Option<String>)> = None;
    let mut saw_format_v0 = false;
    let mut saw_bare_true = false;

    for raw in text.lines() {
        let stripped = strip_unquoted_comment(raw).trim();
        if stripped.is_empty() {
            continue;
        }
        if stripped.starts_with('[') {
            let parsed = parse_section_header(stripped)?;
            let sec_lower = parsed.0.to_ascii_lowercase();
            if sec_lower == "include" || sec_lower == "includeif" {
                return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
            }
            if sec_lower == "extensions" {
                return Err(Error(StatusCode::CONFLICT, CONFLICT_HEAD));
            }
            if sec_lower == "filter" {
                return Err(Error(StatusCode::CONFLICT, CONFLICT_FILTERS));
            }
            section = Some((sec_lower, parsed.1));
            continue;
        }
        let Some((sec, sub)) = section.as_ref() else {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
        };
        let (key_raw, val_raw) = match stripped.split_once('=') {
            Some((k, v)) => (k.trim(), unquote_config_value(v.trim())?),
            None => (stripped, "true".to_owned()),
        };
        if key_raw.is_empty() {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
        }
        let key = key_raw.to_ascii_lowercase();
        let val = val_raw.as_str();
        if sec == "core" && sub.is_none() && key == "repositoryformatversion" {
            if val != "0" {
                return Err(Error(StatusCode::CONFLICT, CONFLICT_HEAD));
            }
            saw_format_v0 = true;
            continue;
        }
        if sec == "core" && sub.is_none() && key == "bare" && val != "false" {
            saw_bare_true = true;
        }
        if !allowed_config_entry(sec, sub.as_deref(), &key, val) {
            let msg = config_rejection_message(sec, &key);
            return Err(Error(StatusCode::CONFLICT, msg));
        }
    }
    if !saw_format_v0 || saw_bare_true {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
    }
    Ok(())
}

fn allowed_config_entry(sec: &str, sub: Option<&str>, key: &str, val: &str) -> bool {
    match (sec, sub, key) {
        (
            "core",
            None,
            "filemode" | "logallrefupdates" | "symlinks" | "ignorecase" | "precomposeunicode" | "quotepath",
        ) => {
            matches!(val.to_ascii_lowercase().as_str(), "true" | "false")
        }
        (
            "core",
            None,
            "bare" | "splitindex" | "sparsecheckout" | "sparsecheckoutcone" | "fsmonitor" | "untrackedcache",
        ) => val.eq_ignore_ascii_case("false"),
        ("core", None, "autocrlf") => matches!(val.to_ascii_lowercase().as_str(), "false" | "true" | "input"),
        ("core", None, "eol") => matches!(val.to_ascii_lowercase().as_str(), "native" | "lf" | "crlf"),
        ("core", None, "safecrlf") => matches!(val.to_ascii_lowercase().as_str(), "false" | "true" | "warn"),
        ("user", None, "name" | "email") => !val.contains(['\r', '\n']),
        ("init", None, "defaultbranch") => !val.is_empty() && !val.contains(['\r', '\n']),
        ("remote", Some(name), "url" | "fetch") => !name.is_empty() && !val.contains(['\r', '\n']),
        ("branch", Some(name), "remote" | "merge") => !name.is_empty() && !val.contains(['\r', '\n']),
        _ => false,
    }
}

fn config_rejection_message(sec: &str, key: &str) -> &'static str {
    if sec == "submodule" {
        return CONFLICT_SUBMODULE;
    }
    if sec == "core"
        && matches!(key, "splitindex" | "sparsecheckout" | "sparsecheckoutcone" | "fsmonitor" | "untrackedcache")
    {
        return CONFLICT_INDEX;
    }
    if matches!(sec, "filter" | "diff" | "merge") {
        return CONFLICT_FILTERS;
    }
    CONFLICT_CONFIG
}

fn strip_unquoted_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            in_quotes = !in_quotes;
        } else if !in_quotes && matches!(ch, '#' | ';') {
            return &line[..idx];
        }
    }
    line
}

fn parse_section_header(header: &str) -> Result<(String, Option<String>), Error> {
    let inner = header
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(Error(StatusCode::CONFLICT, CONFLICT_CONFIG))?
        .trim();
    if inner.is_empty() {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
    }
    if let Some((sec, rest)) = inner.split_once(char::is_whitespace) {
        if !valid_section_ident(sec) {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
        }
        let quoted = rest.trim();
        let sub = unquote_exact_quoted(quoted)?;
        return Ok((sec.to_owned(), Some(sub)));
    }
    if !valid_section_ident(inner) {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
    }
    Ok((inner.to_owned(), None))
}

fn valid_section_ident(sec: &str) -> bool {
    !sec.is_empty() && sec.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
}

fn unquote_exact_quoted(raw: &str) -> Result<String, Error> {
    let body =
        raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')).ok_or(Error(StatusCode::CONFLICT, CONFLICT_CONFIG))?;
    let mut out = String::with_capacity(body.len());
    let mut escaped = false;
    for ch in body.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
        } else {
            out.push(ch);
        }
    }
    if escaped {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
    }
    Ok(out)
}

fn unquote_config_value(raw: &str) -> Result<String, Error> {
    if raw.starts_with('"') {
        return unquote_exact_quoted(raw);
    }
    if raw.ends_with('\\') {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_CONFIG));
    }
    Ok(raw.to_owned())
}
