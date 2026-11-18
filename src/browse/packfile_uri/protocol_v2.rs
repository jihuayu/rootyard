//! Git Protocol v2 `packfile-uris` capability negotiation, bounded pkt-line
//! `fetch` request parsing, and response section encoding.

use crate::cache_wake::replica_cache::error::is_lower_hex_exact;

use super::types::{DeliveryMode, PackObjectFormat, PackfileUriError};

pub const MAX_PKT_LINE_BYTES: usize = 65_520;
pub const MAX_SIDEBAND_DATA_BYTES: usize = 65_515;
pub const MAX_FETCH_V2_WIRE_BYTES: usize = 1024 * 1024;
pub const MAX_FETCH_V2_PKTS: usize = 16_384;
const MAX_PROTOCOL_TOKENS: usize = 8;

/// Advertised Protocol v2 `fetch` capability line (`packfile-uris` opt-in).
pub fn format_fetch_capability_line(offload_advertised: bool) -> String {
    fetch_capability_tokens(offload_advertised).join(" ")
}

/// Ordered feature tokens advertised on the `fetch=` capability line.
pub fn fetch_capability_tokens(offload_advertised: bool) -> Vec<&'static str> {
    let mut tokens = vec!["shallow", "filter", "wait-for-done"];
    if offload_advertised {
        tokens.push("packfile-uris");
    }
    tokens
}

/// Parsed client `packfile-uris <comma-separated-protocols>` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUriProtocolSet {
    pub supports_https: bool,
    pub supports_http: bool,
    pub raw_tokens: Vec<String>,
}

/// Parses and validates the comma-separated protocol list from a `packfile-uris` line.
pub fn parse_uri_protocol_list(csv: &str) -> Result<ParsedUriProtocolSet, PackfileUriError> {
    let trimmed = csv.trim();
    if trimmed.is_empty() {
        return Err(PackfileUriError::ProtocolSyntax("empty packfile-uris protocol list".to_owned()));
    }
    let mut supports_https = false;
    let mut supports_http = false;
    let mut raw_tokens = Vec::new();
    for raw in trimmed.split(',') {
        let token = raw.trim();
        if token.is_empty()
            || raw_tokens.len() >= MAX_PROTOCOL_TOKENS
            || !token.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(PackfileUriError::ProtocolSyntax(
                "invalid protocol token in packfile-uris argument".to_owned(),
            ));
        }
        if token == "https" {
            supports_https = true;
        } else if token == "http" {
            supports_http = true;
        }
        if !raw_tokens.iter().any(|existing| existing == token) {
            raw_tokens.push(token.to_owned());
        }
    }
    Ok(ParsedUriProtocolSet { supports_https, supports_http, raw_tokens })
}

/// Decoded Protocol v2 `command=fetch` request parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchV2Request {
    pub object_format: PackObjectFormat,
    pub wants: Vec<String>,
    pub haves: Vec<String>,
    pub done: bool,
    pub thin_pack: bool,
    pub no_progress: bool,
    pub ofs_delta: bool,
    pub include_tag: bool,
    pub uri_protocols: Option<ParsedUriProtocolSet>,
}

impl FetchV2Request {
    /// Returns `true` only when the client explicitly opted into `https` offload URIs.
    pub fn client_supports_https_offload(&self) -> bool {
        self.uri_protocols.as_ref().is_some_and(|p| p.supports_https)
    }
}

/// Appends one pkt-line frame (`4-hex length + payload`).
pub fn push_pkt_line(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), PackfileUriError> {
    let len = payload.len() + 4;
    if len > MAX_PKT_LINE_BYTES {
        return Err(PackfileUriError::ProtocolSyntax("pkt-line exceeds 65520 byte bound".to_owned()));
    }
    out.extend_from_slice(format!("{len:04x}").as_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawPkt<'a> {
    Data(&'a [u8]),
    Delim,
    Flush,
}

fn split_v2_pkt_lines(stream: &[u8]) -> Result<Vec<RawPkt<'_>>, PackfileUriError> {
    if stream.len() > MAX_FETCH_V2_WIRE_BYTES {
        return Err(PackfileUriError::CapacityExceeded("protocol v2 request exceeds 1 MiB".to_owned()));
    }
    let mut out = Vec::new();
    let mut rest = stream;
    while !rest.is_empty() {
        if out.len() >= MAX_FETCH_V2_PKTS || rest.len() < 4 {
            return Err(PackfileUriError::ProtocolSyntax("truncated or oversized pkt-line stream".to_owned()));
        }
        let hdr = std::str::from_utf8(&rest[..4])
            .map_err(|_| PackfileUriError::ProtocolSyntax("non-utf8 pkt-line length".to_owned()))?;
        if !hdr.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PackfileUriError::ProtocolSyntax("invalid pkt-line hex length".to_owned()));
        }
        let length = usize::from_str_radix(hdr, 16)
            .map_err(|_| PackfileUriError::ProtocolSyntax("invalid pkt-line length".to_owned()))?;
        rest = &rest[4..];
        match length {
            0 => {
                out.push(RawPkt::Flush);
                if !rest.is_empty() {
                    return Err(PackfileUriError::ProtocolSyntax("trailing bytes after flush-pkt".to_owned()));
                }
                return Ok(out);
            }
            1 => out.push(RawPkt::Delim),
            2..=3 => {
                return Err(PackfileUriError::ProtocolSyntax("reserved pkt-line control packet".to_owned()));
            }
            n if n > MAX_PKT_LINE_BYTES || n - 4 > rest.len() => {
                return Err(PackfileUriError::ProtocolSyntax("pkt-line payload truncated or oversized".to_owned()));
            }
            n => {
                let payload_len = n - 4;
                out.push(RawPkt::Data(&rest[..payload_len]));
                rest = &rest[payload_len..];
            }
        }
    }
    Err(PackfileUriError::ProtocolSyntax("missing terminating flush-pkt".to_owned()))
}

/// Parses a Git Protocol v2 `command=fetch` request stream with strict format/bounds checking.
pub fn parse_fetch_v2_request(
    stream: &[u8],
    expected_format: PackObjectFormat,
) -> Result<FetchV2Request, PackfileUriError> {
    let pkts = split_v2_pkt_lines(stream)?;
    let mut saw_command_fetch = false;
    let mut in_args = false;
    let mut req = FetchV2Request {
        object_format: expected_format,
        wants: Vec::new(),
        haves: Vec::new(),
        done: false,
        thin_pack: false,
        no_progress: false,
        ofs_delta: false,
        include_tag: false,
        uri_protocols: None,
    };
    let oid_len = expected_format.oid_hex_len();
    for pkt in pkts {
        match pkt {
            RawPkt::Delim => in_args = true,
            RawPkt::Flush => break,
            RawPkt::Data(raw) => {
                let text = std::str::from_utf8(raw)
                    .map_err(|_| PackfileUriError::ProtocolSyntax("non-utf8 fetch argument".to_owned()))?;
                let line = text.strip_suffix('\n').unwrap_or(text);
                if !in_args {
                    if line == "command=fetch" {
                        saw_command_fetch = true;
                    } else if let Some(fmt) = line.strip_prefix("object-format=")
                        && fmt != expected_format.as_str()
                    {
                        return Err(PackfileUriError::ScopeMismatch(format!(
                            "object-format={fmt} mismatches repository {}",
                            expected_format.as_str()
                        )));
                    }
                    continue;
                }
                apply_fetch_arg(&mut req, line, oid_len)?;
            }
        }
    }
    if !saw_command_fetch {
        return Err(PackfileUriError::ProtocolSyntax("missing command=fetch header".to_owned()));
    }
    Ok(req)
}

fn apply_fetch_arg(req: &mut FetchV2Request, line: &str, oid_len: usize) -> Result<(), PackfileUriError> {
    if let Some(oid) = line.strip_prefix("want ") {
        if !is_lower_hex_exact(oid, oid_len) {
            return Err(PackfileUriError::ProtocolSyntax("invalid want oid".to_owned()));
        }
        req.wants.push(oid.to_owned());
    } else if let Some(oid) = line.strip_prefix("have ") {
        if !is_lower_hex_exact(oid, oid_len) {
            return Err(PackfileUriError::ProtocolSyntax("invalid have oid".to_owned()));
        }
        req.haves.push(oid.to_owned());
    } else if let Some(protos) = line.strip_prefix("packfile-uris ") {
        if req.uri_protocols.is_some() {
            return Err(PackfileUriError::ProtocolSyntax("duplicate packfile-uris line".to_owned()));
        }
        req.uri_protocols = Some(parse_uri_protocol_list(protos)?);
    } else if line == "done" {
        req.done = true;
    } else if line == "thin-pack" {
        req.thin_pack = true;
    } else if line == "no-progress" {
        req.no_progress = true;
    } else if line == "ofs-delta" {
        req.ofs_delta = true;
    } else if line == "include-tag" {
        req.include_tag = true;
    }
    Ok(())
}

/// Encodes a Protocol v2 `fetch` response supporting optional `packfile-uris` + residual inline pack.
pub fn encode_fetch_v2_response(
    delivery: &DeliveryMode,
    inline_pack_bytes: &[u8],
    client_supports_https: bool,
) -> Result<Vec<u8>, PackfileUriError> {
    let mut out = Vec::with_capacity(inline_pack_bytes.len() + 512);
    if let DeliveryMode::OffloadPlusResidual { offloaded, .. } = delivery
        && client_supports_https
        && !offloaded.is_empty()
    {
        push_pkt_line(&mut out, b"packfile-uris\n")?;
        for desc in offloaded {
            if !desc.uri.starts_with("https://") {
                return Err(PackfileUriError::UnsupportedProtocol("refusing non-https offload uri".to_owned()));
            }
            let line = format!("{} {}\n", desc.pack_hash_hex, desc.uri);
            push_pkt_line(&mut out, line.as_bytes())?;
        }
        out.extend_from_slice(b"0001");
    }
    push_pkt_line(&mut out, b"packfile\n")?;
    for chunk in inline_pack_bytes.chunks(MAX_SIDEBAND_DATA_BYTES) {
        let mut frame = Vec::with_capacity(chunk.len() + 1);
        frame.push(1);
        frame.extend_from_slice(chunk);
        push_pkt_line(&mut out, &frame)?;
    }
    out.extend_from_slice(b"0000");
    Ok(out)
}

/// Extracts `(pack_hash, uri)` pairs from the `packfile-uris` section of a v2 fetch response.
pub fn decode_packfile_uris_section(
    response_stream: &[u8],
    expected_format: PackObjectFormat,
) -> Result<Vec<(String, String)>, PackfileUriError> {
    let pkts = split_v2_pkt_lines(response_stream)?;
    let mut in_section = false;
    let mut uris = Vec::new();
    let expected_hash_len = expected_format.oid_hex_len();
    for pkt in pkts {
        match pkt {
            RawPkt::Delim | RawPkt::Flush => {
                if in_section {
                    break;
                }
            }
            RawPkt::Data(raw) => {
                let Ok(text) = std::str::from_utf8(raw) else {
                    continue;
                };
                let line = text.strip_suffix('\n').unwrap_or(text);
                if line == "packfile-uris" {
                    in_section = true;
                } else if line == "packfile" {
                    break;
                } else if in_section {
                    let Some((hash, uri)) = line.split_once(' ') else {
                        return Err(PackfileUriError::ProtocolSyntax("malformed packfile-uri entry".to_owned()));
                    };
                    if !is_lower_hex_exact(hash, expected_hash_len) {
                        return Err(PackfileUriError::ProtocolSyntax("invalid packfile-uri pack hash".to_owned()));
                    }
                    uris.push((hash.to_owned(), uri.to_owned()));
                }
            }
        }
    }
    Ok(uris)
}
