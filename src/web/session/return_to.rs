//! Strict, same-origin browser return-to parsing.
//!
//! A candidate is rejected unless it passes the header-safe ASCII allowlist and
//! exactly one strict percent-decode yields a `/web/` or `/ui/` path with no
//! controls, backslashes, double slashes, dot segments, fragments, or residual
//! percent escapes. There is no permissive rewrite: unsafe input falls back to
//! [`DEFAULT_RETURN_TO`].

const DEFAULT_RETURN_TO: &str = "/web/repos";

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_ascii(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let decoded = hex_value(bytes[index + 1])? * 16 + hex_value(bytes[index + 2])?;
            if decoded > 0x7f {
                return None;
            }
            out.push(decoded);
            index += 3;
        } else {
            if byte > 0x7f {
                return None;
            }
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn header_safe_ascii(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'_'
                        | b'.'
                        | b'~'
                        | b'/'
                        | b'?'
                        | b'&'
                        | b'='
                        | b'%'
                        | b':'
                        | b'+'
                        | b'!'
                        | b'$'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'@'
                        | b','
                        | b';'
                        | b'['
                        | b']'
                )
        })
}

pub(super) fn is_safe_return_to(value: &str) -> bool {
    if !header_safe_ascii(value) || value.starts_with("//") || value.contains("//") {
        return false;
    }
    let raw_path = value.split('?').next().unwrap_or("");
    let (Some(decoded_path), Some(decoded_whole)) = (percent_decode_ascii(raw_path), percent_decode_ascii(value))
    else {
        return false;
    };
    if !decoded_whole.is_ascii()
        || decoded_whole.contains('\\')
        || decoded_whole.contains('%')
        || decoded_whole.contains('#')
        || decoded_whole.chars().any(char::is_control)
    {
        return false;
    }
    if !(decoded_path.starts_with("/web/") || decoded_path.starts_with("/ui/"))
        || decoded_path.starts_with("/web/login")
        || decoded_path.contains("//")
        || decoded_path.contains('\\')
        || decoded_path.contains('%')
        || decoded_path.chars().any(char::is_control)
    {
        return false;
    }
    !decoded_path.split('/').any(|segment| segment == "." || segment == "..")
}

pub(super) fn safe_return_to(value: Option<&str>) -> &str {
    value.filter(|candidate| is_safe_return_to(candidate)).unwrap_or(DEFAULT_RETURN_TO)
}

pub(super) fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub(super) fn login_target(path: &str, query: Option<&str>) -> String {
    match query.filter(|q| !q.is_empty()) {
        Some(q) => format!("{path}?{q}"),
        None => path.to_owned(),
    }
}
