//! Smart HTTP request and response syntax validation.
use super::*;

pub(super) struct ReceiveCommands {
    pub bytes: Vec<u8>,
    pub refs: Vec<String>,
    pub changes: Vec<journal::RefChange>,
}

/// Read only the bounded command pkt-lines, before Git sees the pack. The
/// exact bytes are replayed to http-backend after the parent owns every ref
/// lease. A malformed/unsupported request fails before any native child runs.
pub(super) async fn receive_commands(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    oid_len: usize,
) -> Result<ReceiveCommands, Error> {
    if !matches!(oid_len, 40 | 64) {
        return Err(Error::bad_request());
    }
    let mut bytes = Vec::new();
    let mut refs = Vec::new();
    let mut changes = Vec::new();
    loop {
        if bytes.len() + 4 > 128 * 1024 {
            return Err(Error::bad_request());
        }
        let mut header = [0u8; 4];
        reader.read_exact(&mut header).await.map_err(Error::internal)?;
        bytes.extend_from_slice(&header);
        let length = std::str::from_utf8(&header)
            .ok()
            .and_then(|h| usize::from_str_radix(h, 16).ok())
            .ok_or_else(Error::bad_request)?;
        if length == 0 {
            break;
        }
        if !(4..=65520).contains(&length) || bytes.len() + length - 4 > 128 * 1024 || refs.len() >= 128 {
            return Err(Error::bad_request());
        }
        let start = bytes.len();
        bytes.resize(start + length - 4, 0);
        reader.read_exact(&mut bytes[start..]).await.map_err(Error::internal)?;
        let packet = &bytes[start..];
        let command = packet.split(|b| *b == 0).next().ok_or_else(Error::bad_request)?;
        let command = command.strip_suffix(b"\n").unwrap_or(command);
        let command = std::str::from_utf8(command).map_err(|_| Error::bad_request())?;
        // Shallow lines precede commands, but never confer a publication key.
        if refs.is_empty() && command.starts_with("shallow ") {
            continue;
        }
        let mut fields = command.split(' ');
        let (Some(old), Some(new), Some(name), None) = (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(Error::bad_request());
        };
        if old.len() != oid_len
            || new.len() != oid_len
            || !old.bytes().chain(new.bytes()).all(|b| b.is_ascii_hexdigit())
            || !crate::journal::valid_ref(name)
            || !name.starts_with("refs/")
            || refs.iter().any(|prior| prior == name)
        {
            return Err(Error::bad_request());
        }
        refs.push(name.to_string());
        changes.push(journal::RefChange {
            ref_name: name.to_string(),
            old_oid: old.to_ascii_lowercase(),
            new_oid: new.to_ascii_lowercase(),
        });
    }
    Ok(ReceiveCommands { bytes, refs, changes })
}

#[cfg(test)]
mod receive_tests {
    use super::*;

    fn packet(command: &[u8]) -> Vec<u8> {
        let mut bytes = format!("{:04x}", command.len() + 4).into_bytes();
        bytes.extend_from_slice(command);
        bytes
    }

    #[tokio::test]
    async fn command_prefix_tracks_exact_refs_and_replays_pack() {
        let oid = "1".repeat(40);
        let zero = "0".repeat(40);
        let first = format!("{zero} {oid} refs/heads/a\0report-status atomic\n");
        let second = format!("{zero} {oid} refs/heads/b\n");
        let mut source = packet(first.as_bytes());
        source.extend(packet(second.as_bytes()));
        source.extend(b"0000PACK");
        let mut reader = source.as_slice();
        let parsed = receive_commands(&mut reader, 40).await.unwrap();
        assert_eq!(parsed.refs, ["refs/heads/a", "refs/heads/b"]);
        assert_eq!(parsed.changes[0].old_oid, zero);
        assert_eq!(parsed.changes[0].new_oid, oid);
        assert_eq!(&source[..source.len() - 4], parsed.bytes);
        assert_eq!(reader, b"PACK");
        let mut duplicate = packet(first.as_bytes());
        duplicate.extend(packet(first.as_bytes()));
        duplicate.extend(b"0000");
        assert!(receive_commands(&mut duplicate.as_slice(), 40).await.is_err());
        let mut wrong_format = source.as_slice();
        assert!(receive_commands(&mut wrong_format, 64).await.is_err());
    }
}

/// Buffer at most one protocol pkt-line (65,520 bytes, including its header).
/// Only a complete initial ERR packet is a refusal. Raw PACK, delimiters and
/// successful protocol packets remain ordinary streamed output; malformed or
/// truncated prefixes fail rather than masquerading as a clean Git response.
pub(super) async fn job_response_prefix(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    maximum: u64,
) -> io::Result<(Vec<u8>, bool)> {
    if maximum < 4 {
        return Err(io::Error::other("Git response size limit exceeded"));
    }
    let mut prefix = vec![0; 4];
    reader.read_exact(&mut prefix).await?;
    let length = std::str::from_utf8(&prefix).ok().and_then(|v| usize::from_str_radix(v, 16).ok());
    if let Some(length) = length {
        if length == 3 || length > 65520 || length as u64 > maximum {
            return Err(io::Error::other("invalid or oversized Git response packet"));
        }
        if length >= 4 {
            prefix.resize(length, 0);
            reader.read_exact(&mut prefix[4..]).await?;
        }
    } else if prefix != b"PACK" {
        return Err(io::Error::other("invalid Git response packet prefix"));
    }
    let denied = prefix.get(4..).is_some_and(|payload| payload.starts_with(b"ERR "));
    Ok((prefix, denied))
}

pub(super) fn route<'a>(
    method: &Method,
    path: &'a str,
    query: Option<&str>,
) -> Result<(&'a str, &'a str, &'a str, &'static str), Error> {
    // Validate the raw URL before any percent decoding. Repository paths are never
    // concatenated from this input: DB UUIDs choose directories.
    let segments: Vec<_> = path.split('/').collect();
    if segments.len() < 5 || !segments[0].is_empty() || segments[1] != "git" {
        return Err(Error::not_found());
    }
    let owner = segments[2];
    let name = segments[3].strip_suffix(".git").ok_or_else(Error::not_found)?;
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    if segments.len() == 6 && segments[4] == "info" && segments[5] == "refs" && method == Method::GET {
        let service = match query {
            Some("service=git-upload-pack") => "git-upload-pack",
            Some("service=git-receive-pack") => "git-receive-pack",
            _ => return Err(Error::bad_request()),
        };
        Ok((owner, name, "info/refs", service))
    } else if segments.len() == 5 && method == Method::POST && query.is_none() {
        let service = match segments[4] {
            "git-upload-pack" => "git-upload-pack",
            "git-receive-pack" => "git-receive-pack",
            _ => return Err(Error::not_found()),
        };
        Ok((owner, name, segments[4], service))
    } else {
        Err(Error::not_found())
    }
}
pub(super) fn validate_headers(headers: &HeaderMap, method: &Method, service: &str, limit: u64) -> Result<(), Error> {
    if let Some(value) = headers.get(header::CONTENT_ENCODING)
        && value != "identity"
        && value != "gzip"
        && value != "x-gzip"
    {
        return Err(Error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported request encoding"));
    }
    if let Some(value) = headers.get(header::CONTENT_LENGTH) {
        let size = value.to_str().ok().and_then(|v| v.parse::<u64>().ok()).ok_or_else(Error::bad_request)?;
        if size > limit {
            return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded"));
        }
    }
    if let Some(value) = headers.get("git-protocol")
        && !matches!(value.to_str(), Ok("version=0" | "version=1" | "version=2"))
    {
        return Err(Error::bad_request());
    }
    if method == Method::POST {
        let expected = format!("application/x-{service}-request");
        if headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
            return Err(Error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid Git content type"));
        }
    }
    Ok(())
}
pub(super) async fn read_headers(
    reader: &mut BufReader<tokio::process::ChildStdout>,
) -> io::Result<(StatusCode, HeaderValue)> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        bytes.push(reader.read_u8().await?);
        if bytes.ends_with(b"\r\n\r\n") || bytes.ends_with(b"\n\n") {
            break;
        }
    }
    if bytes.len() >= 8192 {
        return Err(io::Error::other("oversized CGI headers"));
    }
    let text = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    let mut status = StatusCode::OK;
    let mut content_type = HeaderValue::from_static("application/octet-stream");
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            if key.eq_ignore_ascii_case("status") {
                status = value
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u16>().ok())
                    .and_then(|v| StatusCode::from_u16(v).ok())
                    .ok_or_else(|| io::Error::other("invalid CGI status"))?;
            } else if key.eq_ignore_ascii_case("content-type") {
                content_type = HeaderValue::from_str(value).map_err(io::Error::other)?;
            }
        }
    }
    Ok((status, content_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn job_refusal_prefix_is_bounded_complete_and_preserves_success() {
        for bytes in [b"0008NAK\nPACKpartial".as_slice(), b"PACKpartial", b"0000"] {
            let mut source = bytes;
            let (prefix, denied) = job_response_prefix(&mut source, 1024).await.unwrap();
            assert!(!denied);
            assert_eq!([prefix, source.to_vec()].concat(), bytes);
        }
        let packet = b"0013ERR not our ref";
        let mut err_then_pack = &b"0013ERR not our refPACKmust-not-be-served"[..];
        assert_eq!(job_response_prefix(&mut err_then_pack, 1024).await.unwrap(), (packet.to_vec(), true));
        assert_eq!(err_then_pack, b"PACKmust-not-be-served");
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let write = tokio::spawn(async move {
            for byte in packet {
                writer.write_all(&[*byte]).await.unwrap();
            }
        });
        assert_eq!(job_response_prefix(&mut reader, 1024).await.unwrap(), (packet.to_vec(), true));
        write.await.unwrap();
        for bytes in [b"0013ERR short".as_slice(), b"00", b"ffff", b"0008NA", b"0003", b"oops"] {
            assert!(job_response_prefix(&mut &bytes[..], 1024).await.is_err());
        }
        assert!(job_response_prefix(&mut &packet[..], 8).await.is_err());
        assert!(job_response_prefix(&mut &packet[..], 3).await.is_err());
    }
    #[test]
    fn rejects_unsafe_routes() {
        for path in [
            "/git/alice/../config",
            "/git/alice/demo.git/config",
            "/git/alice/a%2fb.git/info/refs",
            "/git/alice/demo.git/objects/abc",
            "/git/alice/demo.git/info/refs/",
        ] {
            assert!(route(&Method::GET, path, Some("service=git-upload-pack")).is_err());
        }
        assert!(route(&Method::GET, "/git/alice/demo.git/info/refs", Some("service=git-upload-pack")).is_ok());
    }
}
