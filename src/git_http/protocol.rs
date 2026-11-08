//! Smart HTTP request and response syntax validation.
use super::*;

pub(super) struct ReceiveCommands {
    pub bytes: Vec<u8>,
    pub refs: Vec<String>,
    pub changes: Vec<journal::RefChange>,
    pub capabilities: ReceiveCapabilities,
}

/// Capabilities the client requested on its first receive command. A report
/// format the client did not negotiate is never invented: without any
/// report-status a refusal must stay an HTTP error rather than become an
/// unparseable success or a status line the client will not read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ReceiveCapabilities {
    pub report_status: bool,
    pub report_status_v2: bool,
    pub sideband_64k: bool,
    pub atomic: bool,
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
    let mut capabilities = ReceiveCapabilities::default();
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
        let separator = packet.iter().position(|byte| *byte == 0);
        let command = separator.map_or(packet, |index| &packet[..index]);
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
        if refs.is_empty()
            && let Some(separator) = separator
        {
            // Capabilities travel only on the first command packet, after the
            // NUL separator. Unknown and valued tokens are deliberately ignored.
            let list = &packet[separator + 1..];
            let list = list.strip_suffix(b"\n").unwrap_or(list);
            for token in list.split(|byte| *byte == b' ') {
                match token {
                    b"report-status" => capabilities.report_status = true,
                    b"report-status-v2" => capabilities.report_status_v2 = true,
                    b"side-band-64k" => capabilities.sideband_64k = true,
                    b"atomic" => capabilities.atomic = true,
                    _ => {}
                }
            }
        }
        refs.push(name.to_string());
        changes.push(journal::RefChange {
            ref_name: name.to_string(),
            old_oid: old.to_ascii_lowercase(),
            new_oid: new.to_ascii_lowercase(),
        });
    }
    Ok(ReceiveCommands { bytes, refs, changes, capabilities })
}

fn push_pktline(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), Error> {
    let length = payload.len() + 4;
    if length > 65520 {
        return Err(Error::internal("receive-pack pkt-line exceeds protocol bound"));
    }
    out.extend_from_slice(format!("{length:04x}").as_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// The exact pkt-line report a receive-pack server sends when every requested
/// ref was refused before commit: `unpack ok`, one `ng` per ref, then a flush.
/// report-status-v2 uses these same ref status lines (its `option` lines are
/// optional). With `side-band-64k` the inner report travels on band 1 exactly
/// as native receive-pack sends it. Without a negotiated report-status this
/// returns the unchanged refusal instead of fabricating protocol output.
pub(super) fn rejected_refs_report(
    capabilities: &ReceiveCapabilities,
    refs: &[String],
    reason: &str,
) -> Result<Vec<u8>, Error> {
    if refs.is_empty()
        || reason.is_empty()
        || reason.bytes().any(|byte| byte < 32 || byte == 127)
        || refs.iter().any(|name| !name.starts_with("refs/") || name.bytes().any(|byte| byte <= 32 || byte == 127))
    {
        return Err(Error::internal("invalid receive-pack rejection"));
    }
    if !(capabilities.report_status || capabilities.report_status_v2) {
        return Err(Error(StatusCode::CONFLICT, "Pando refs changed; retry from current refs"));
    }
    let mut inner = Vec::new();
    push_pktline(&mut inner, b"unpack ok\n")?;
    for name in refs {
        push_pktline(&mut inner, format!("ng {name} {reason}\n").as_bytes())?;
    }
    inner.extend_from_slice(b"0000");
    if !capabilities.sideband_64k {
        return Ok(inner);
    }
    let mut outer = Vec::new();
    for chunk in inner.chunks(65515) {
        let mut payload = Vec::with_capacity(chunk.len() + 1);
        payload.push(1);
        payload.extend_from_slice(chunk);
        push_pktline(&mut outer, &payload)?;
    }
    // Native receive-pack terminates its sideband report with an outer flush.
    outer.extend_from_slice(b"0000");
    Ok(outer)
}

/// Largest status report worth parsing. A native report costs a few short
/// lines, so this only bounds hostile buffered native output.
const MAX_STATUS_REPORT: usize = 1024 * 1024;
/// Protocol maximum for one pkt-line, header included.
const MAX_PKT_LINE: usize = 65_520;

/// Split one pkt-line stream into its payloads. The stream must be well-formed
/// pkt-lines terminated by exactly one flush packet with nothing after it;
/// truncation, a `0001`/`0002` special packet, a non-hex header, an oversized
/// packet, a missing flush or trailing bytes are all malformed.
fn pkt_line_payloads(stream: &[u8], max_packets: usize) -> Option<Vec<&[u8]>> {
    if stream.len() > MAX_STATUS_REPORT {
        return None;
    }
    let mut payloads = Vec::new();
    let mut rest = stream;
    loop {
        if rest.len() < 4 {
            return None;
        }
        let header = std::str::from_utf8(&rest[..4]).ok()?;
        if !header.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let length = usize::from_str_radix(header, 16).ok()?;
        rest = &rest[4..];
        if length == 0 {
            // A single terminating flush must end the stream exactly.
            return rest.is_empty().then_some(payloads);
        }
        if !(4..=MAX_PKT_LINE).contains(&length) || length - 4 > rest.len() || payloads.len() >= max_packets {
            return None;
        }
        payloads.push(&rest[..length - 4]);
        rest = &rest[length - 4..];
    }
}

/// True only when native receive-pack itself reported `ng` for every requested
/// ref, in the exact status format the client negotiated. Callers invoke this
/// after proving the disposable snapshot changed no ref, so a pass-through
/// report cannot be an acknowledgement of a commit.
///
/// The buffered reply is parsed as bounded real pkt-lines instead of searched
/// for the text `ng <ref>`: progress text, an `ng` embedded in another ref's
/// reason, a duplicated or unknown ref, an `ok` line, a truncated or
/// trailing-byte stream, a sideband error band and any malformed encoding are
/// all "not a proven rejection" and can never become an HTTP 200.
pub(super) fn reports_rejection(report: &[u8], refs: &[String], capabilities: &ReceiveCapabilities) -> bool {
    // Without a negotiated report format native receive-pack sends no status at
    // all, so nothing could prove a per-ref refusal.
    if refs.is_empty()
        || !(capabilities.report_status || capabilities.report_status_v2)
        || report.len() > MAX_STATUS_REPORT
    {
        return false;
    }
    let max_packets = refs.len().saturating_mul(4).saturating_add(16);
    let inner = if capabilities.sideband_64k {
        // Only a negotiated side-band-64k demultiplexes the reply. Band 1 carries
        // the status bytes; band 2 is progress and can never establish an `ng`;
        // band 3 (fatal error), an empty packet, an unknown band or malformed
        // framing ends the proof.
        let Some(outer) = pkt_line_payloads(report, max_packets) else {
            return false;
        };
        let mut inner = Vec::new();
        for payload in outer {
            let Some((band, body)) = payload.split_first() else {
                return false;
            };
            match *band {
                1 => {
                    if inner.len() + body.len() > MAX_STATUS_REPORT {
                        return false;
                    }
                    inner.extend_from_slice(body);
                }
                2 => {}
                _ => return false,
            }
        }
        inner
    } else {
        report.to_vec()
    };
    let Some(packets) = pkt_line_payloads(&inner, max_packets) else {
        return false;
    };
    let mut statuses = packets.into_iter();
    // The unpack status is mandatory and must be `ok`: an unpack failure is a
    // transport-level error, never a proven per-ref refusal.
    let unpack = statuses.next().unwrap_or_default();
    if unpack.strip_suffix(b"\n").unwrap_or(unpack) != b"unpack ok" {
        return false;
    }
    let mut rejected: Vec<&str> = Vec::new();
    let mut previous_was_status = false;
    for payload in statuses {
        if payload.contains(&0u8) {
            return false;
        }
        let line = payload.strip_suffix(b"\n").unwrap_or(payload);
        let mut fields = line.splitn(2, |byte| *byte == b' ');
        let kind = fields.next().unwrap_or_default();
        let rest = fields.next().unwrap_or_default();
        if kind == b"ok" {
            // A native acknowledgement is never a refusal.
            return false;
        } else if kind == b"ng" {
            let mut fields = rest.splitn(2, |byte| *byte == b' ');
            let name = fields.next().unwrap_or_default();
            let reason = fields.next().unwrap_or_default();
            let Ok(name) = std::str::from_utf8(name) else {
                return false;
            };
            if name.is_empty()
                || reason.is_empty()
                || !refs.iter().any(|requested| requested == name)
                || rejected.contains(&name)
            {
                return false;
            }
            rejected.push(name);
            previous_was_status = true;
        } else if kind != b"option" || !capabilities.report_status_v2 || !previous_was_status {
            // report-status-v2 `option` lines are advisory metadata for the
            // preceding ref status: they can never establish a rejection and are
            // only legal in the v2 format, after a status line. Everything else
            // is malformed.
            return false;
        }
    }
    // Exactly one `ng` per requested ref, with no duplicate or unknown names.
    rejected.len() == refs.len()
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

    #[tokio::test]
    async fn capabilities_parse_only_from_the_first_command_packet() {
        let oid = "1".repeat(40);
        let zero = "0".repeat(40);
        let first = format!(
            "{zero} {oid} refs/heads/a\0 report-status-v2 side-band-64k quiet atomic ofs-delta agent=git/2.52.0\n"
        );
        let second = format!("{zero} {oid} refs/heads/b\n");
        let mut source = packet(first.as_bytes());
        source.extend(packet(second.as_bytes()));
        source.extend(b"0000");
        let parsed = receive_commands(&mut source.as_slice(), 40).await.unwrap();
        assert_eq!(
            parsed.capabilities,
            ReceiveCapabilities { report_status: false, report_status_v2: true, sideband_64k: true, atomic: true }
        );
        assert_eq!(parsed.refs, ["refs/heads/a", "refs/heads/b"]);
        let mut bare = packet(second.as_bytes());
        bare.extend(b"0000");
        let parsed = receive_commands(&mut bare.as_slice(), 40).await.unwrap();
        assert_eq!(parsed.capabilities, ReceiveCapabilities::default());
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

    fn pkt(payload: &[u8]) -> Vec<u8> {
        let mut bytes = format!("{:04x}", payload.len() + 4).into_bytes();
        bytes.extend_from_slice(payload);
        bytes
    }

    fn pkt_payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut payloads = Vec::new();
        let mut rest = bytes;
        loop {
            assert!(rest.len() >= 4, "truncated pkt-line header");
            let length = usize::from_str_radix(std::str::from_utf8(&rest[..4]).unwrap(), 16).unwrap();
            rest = &rest[4..];
            if length == 0 {
                break;
            }
            assert!(length >= 4 && length - 4 <= rest.len(), "invalid pkt-line length");
            payloads.push(rest[..length - 4].to_vec());
            rest = &rest[length - 4..];
        }
        assert!(rest.is_empty(), "trailing bytes after flush");
        payloads
    }

    fn lines(payloads: &[Vec<u8>]) -> Vec<String> {
        payloads.iter().map(|payload| String::from_utf8(payload.clone()).unwrap()).collect()
    }

    #[test]
    fn rejection_report_is_plain_without_sideband_and_never_acknowledges() {
        let refs = vec!["refs/heads/main".to_owned()];
        let capabilities = ReceiveCapabilities { report_status: true, ..ReceiveCapabilities::default() };
        let reply = rejected_refs_report(&capabilities, &refs, "ref changed; retry from current refs").unwrap();
        let lines = lines(&pkt_payloads(&reply));
        assert_eq!(lines[0], "unpack ok\n");
        assert_eq!(lines[1], "ng refs/heads/main ref changed; retry from current refs\n");
        assert_eq!(lines.iter().filter(|line| line.starts_with("ng ")).count(), 1);
        assert!(!lines.iter().any(|line| line.starts_with("ok ")));
    }

    #[test]
    fn rejection_report_uses_band_one_only_when_sideband_is_negotiated() {
        let refs = vec!["refs/heads/a".to_owned(), "refs/heads/b".to_owned()];
        let capabilities =
            ReceiveCapabilities { report_status: false, report_status_v2: true, sideband_64k: true, atomic: true };
        let reply = rejected_refs_report(&capabilities, &refs, "ref changed; retry from current refs").unwrap();
        let outer = pkt_payloads(&reply);
        assert!(outer.iter().all(|payload| payload.first() == Some(&1)));
        let inner: Vec<u8> = outer.iter().flat_map(|payload| payload[1..].to_vec()).collect();
        let lines = lines(&pkt_payloads(&inner));
        assert_eq!(lines[0], "unpack ok\n");
        assert_eq!(lines.iter().filter(|line| line.starts_with("ng ")).count(), 2);
        assert!(!lines.iter().any(|line| line.starts_with("ok ")));
    }

    #[test]
    fn rejection_report_requires_a_negotiated_status_format() {
        let refs = vec!["refs/heads/main".to_owned()];
        let error = rejected_refs_report(&ReceiveCapabilities::default(), &refs, "ref changed").unwrap_err();
        assert_eq!(error.0, StatusCode::CONFLICT);
        assert!(rejected_refs_report(&ReceiveCapabilities::default(), &[], "ref changed").is_err());
        assert!(rejected_refs_report(&ReceiveCapabilities::default(), &refs, "bad\nreason").is_err());
        assert!(rejected_refs_report(&ReceiveCapabilities::default(), &refs, "new\0line").is_err());
    }

    fn status_caps(report_status: bool, report_status_v2: bool, sideband_64k: bool) -> ReceiveCapabilities {
        ReceiveCapabilities { report_status, report_status_v2, sideband_64k, atomic: false }
    }

    fn report(lines: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for line in lines {
            bytes.extend(pkt(line));
        }
        bytes.extend_from_slice(b"0000");
        bytes
    }

    #[test]
    fn native_refusal_detection_requires_exact_pkt_lines() {
        let v1 = status_caps(true, false, false);
        let refs = vec!["refs/heads/a".to_owned(), "refs/heads/b".to_owned()];
        let refused = report(&[b"unpack ok\n", b"ng refs/heads/a stale info\n", b"ng refs/heads/b stale info\n"]);
        assert!(reports_rejection(&refused, &refs, &v1));
        // Every rejection needs the negotiated report format.
        assert!(!reports_rejection(&refused, &refs, &ReceiveCapabilities::default()));
        assert!(!reports_rejection(&refused, &[], &v1));
        // One `ok` line means the native result was a partial success.
        let mixed = report(&[b"unpack ok\n", b"ng refs/heads/a stale info\n", b"ok refs/heads/b\n"]);
        assert!(!reports_rejection(&mixed, &refs, &v1));
        // Duplicates do not stand in for the missing ref.
        let duplicated = report(&[b"unpack ok\n", b"ng refs/heads/a x\n", b"ng refs/heads/a y\n"]);
        assert!(!reports_rejection(&duplicated, &refs, &v1));
        let repeated = report(&[
            b"unpack ok\n",
            b"ng refs/heads/a x\n",
            b"ng refs/heads/a x\n",
            b"ng refs/heads/b y\n",
        ]);
        assert!(!reports_rejection(&repeated, &refs, &v1));
        // An unknown ref is never substituted for a requested one.
        let extra = report(&[b"unpack ok\n", b"ng refs/heads/a x\n", b"ng refs/heads/b y\n", b"ng refs/heads/c z\n"]);
        assert!(!reports_rejection(&extra, &refs, &v1));
        // A missing or failed unpack status is not a per-ref refusal.
        assert!(!reports_rejection(&report(&[b"ng refs/heads/a x\n", b"ng refs/heads/b y\n"]), &refs, &v1));
        let unpack_failed = report(&[b"unpack eof before pack\n", b"ng refs/heads/a x\n", b"ng refs/heads/b y\n"]);
        assert!(!reports_rejection(&unpack_failed, &refs, &v1));
        // An empty ng reason is malformed.
        let no_reason = report(&[b"unpack ok\n", b"ng refs/heads/a \n", b"ng refs/heads/b y\n"]);
        assert!(!reports_rejection(&no_reason, &refs, &v1));
        // The stream must be complete: no flush, or bytes after the flush.
        let mut unterminated = pkt(b"unpack ok\n");
        unterminated.extend(pkt(b"ng refs/heads/a x\n"));
        unterminated.extend(pkt(b"ng refs/heads/b y\n"));
        assert!(!reports_rejection(&unterminated, &refs, &v1));
        let mut trailing = refused.clone();
        trailing.extend_from_slice(b"PACK");
        assert!(!reports_rejection(&trailing, &refs, &v1));
        let mut second_flush = refused.clone();
        second_flush.extend_from_slice(b"0000");
        assert!(!reports_rejection(&second_flush, &refs, &v1));
        // A truncated final packet is malformed, never a silent flush.
        assert!(!reports_rejection(&refused[..refused.len() - 1], &refs, &v1));
        assert!(!reports_rejection(b"0000", &refs, &v1));
        // Special packets, a bad header and an oversized length are rejected.
        let mut delimiter = pkt(b"unpack ok\n");
        delimiter.extend_from_slice(b"0001");
        delimiter.extend(pkt(b"ng refs/heads/a x\n"));
        delimiter.extend(pkt(b"ng refs/heads/b y\n"));
        delimiter.extend_from_slice(b"0000");
        assert!(!reports_rejection(&delimiter, &refs, &v1));
        let mut bad_hex = b"zzzzunpack ok\n".to_vec();
        bad_hex.extend(pkt(b"ng refs/heads/a x\n"));
        bad_hex.extend(pkt(b"ng refs/heads/b y\n"));
        bad_hex.extend_from_slice(b"0000");
        assert!(!reports_rejection(&bad_hex, &refs, &v1));
        let mut oversized = b"ffffunpack ok\n".to_vec();
        oversized.extend(pkt(b"ng refs/heads/a x\n"));
        oversized.extend_from_slice(b"0000");
        assert!(!reports_rejection(&oversized, &refs, &v1));
    }

    #[test]
    fn embedded_ng_text_and_progress_never_prove_a_rejection() {
        let v1 = status_caps(true, false, false);
        let refs = vec!["refs/heads/a".to_owned(), "refs/heads/b".to_owned()];
        // `refs/heads/a` appears only inside refs/heads/b's error message.
        let embedded = report(&[b"unpack ok\n", b"ng refs/heads/b see ng refs/heads/a stale\n"]);
        assert!(!reports_rejection(&embedded, &refs, &v1));
        // ... and here only inside band 2 progress, which is not status bytes.
        let banded = report(&[
            b"\x01unpack ok\n",
            b"\x02ng refs/heads/a stale ng refs/heads/b stale\n",
            b"\x01ng refs/heads/b stale\n",
        ]);
        assert!(!reports_rejection(&banded, &refs, &status_caps(true, false, true)));
        // Raw progress text is not a status line either.
        let raw_progress = report(&[b"unpack ok\n", b"remote: ng refs/heads/a nope\n"]);
        assert!(!reports_rejection(&raw_progress, &refs, &v1));
    }

    #[test]
    fn sideband_needs_negotiation_and_band_one_status_bytes() {
        let banded = status_caps(true, false, true);
        let plain = status_caps(true, false, false);
        let refs = vec!["refs/heads/a".to_owned(), "refs/heads/b".to_owned()];
        let refused = report(&[b"\x01unpack ok\n", b"\x01ng refs/heads/a stale\n", b"\x01ng refs/heads/b stale\n"]);
        assert!(reports_rejection(&refused, &refs, &banded));
        // Sideband framing is required once negotiated, and never invented.
        let plain_report = report(&[b"unpack ok\n", b"ng refs/heads/a x\n", b"ng refs/heads/b y\n"]);
        assert!(!reports_rejection(&plain_report, &refs, &banded));
        assert!(!reports_rejection(&refused, &refs, &plain));
        // Band 2 progress is ignored but cannot break a valid band-1 report.
        let with_progress = report(&[
            b"\x02Resolving deltas\n",
            b"\x01unpack ok\n",
            b"\x01ng refs/heads/a stale\n",
            b"\x02ng refs/heads/b stale\n",
            b"\x01ng refs/heads/b stale\n",
        ]);
        assert!(reports_rejection(&with_progress, &refs, &banded));
        // Band 1 payloads may split any inner pkt-line.
        let split = report(&[b"\x01unpack", b"\x01 ok\n\x01ng refs/heads/a stale\n", b"\x01ng refs/heads/b stale\n"]);
        assert!(reports_rejection(&split, &refs, &banded));
        // Band 3, an empty band payload or an unknown band is fatal, not approval.
        for fatal in [b"\x03fatal: something\n".as_slice(), b"".as_slice(), b"\x04weird\n".as_slice()] {
            let mut lines: Vec<&[u8]> =
                vec![b"\x01unpack ok\n", b"\x01ng refs/heads/a stale\n", b"\x01ng refs/heads/b stale\n"];
            lines.push(fatal);
            assert!(!reports_rejection(&report(&lines), &refs, &banded));
        }
        // Malformed outer framing is not a proof either.
        let mut truncated = refused.clone();
        truncated.truncate(truncated.len() - 2);
        assert!(!reports_rejection(&truncated, &refs, &banded));
        let mut trailing = refused.clone();
        trailing.extend_from_slice(b"0000");
        assert!(!reports_rejection(&trailing, &refs, &banded));
    }

    #[test]
    fn report_status_v2_option_lines_are_advisory_only() {
        let v2 = status_caps(false, true, false);
        let v1 = status_caps(true, false, false);
        let refs = vec!["refs/heads/a".to_owned()];
        let with_options = report(&[
            b"unpack ok\n",
            b"ng refs/heads/a stale\n",
            b"option old-oid 1111111111111111111111111111111111111111\n",
            b"option new-oid 2222222222222222222222222222222222222222\n",
        ]);
        assert!(reports_rejection(&with_options, &refs, &v2));
        // `option` lines are not legal in report-status v1 ...
        assert!(!reports_rejection(&with_options, &refs, &v1));
        // ... nor before any ref status, even in v2.
        let leading_option = report(&[b"unpack ok\n", b"option old-oid 1111\n", b"ng refs/heads/a stale\n"]);
        assert!(!reports_rejection(&leading_option, &refs, &v2));
        // A v2 report still may not acknowledge a ref.
        assert!(!reports_rejection(&report(&[b"unpack ok\n", b"ok refs/heads/a\n"]), &refs, &v2));
        // v1 and v2 share the plain framing for status lines.
        assert!(reports_rejection(&report(&[b"unpack ok\n", b"ng refs/heads/a stale\n"]), &refs, &v1));
    }

    #[test]
    fn generated_rejection_reports_round_trip_through_the_parser() {
        let refs = vec!["refs/heads/a".to_owned(), "refs/heads/b".to_owned()];
        for capabilities in [
            status_caps(true, false, false),
            status_caps(false, true, false),
            status_caps(true, false, true),
            status_caps(false, true, true),
        ] {
            let reply = rejected_refs_report(&capabilities, &refs, "ref changed; retry from current refs").unwrap();
            assert!(reports_rejection(&reply, &refs, &capabilities));
            assert!(!reports_rejection(&reply, &refs[..1], &capabilities));
        }
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
