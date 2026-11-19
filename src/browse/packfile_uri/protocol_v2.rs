//! Git Protocol v2 `packfile-uris` capability negotiation, bounded pkt-line
//! `fetch` request parsing, and policy-gated response section encoding.

use crate::cache_wake::replica_cache::error::is_lower_hex_exact;

use super::types::{DeliveryMode, OffloadPolicyConfig, PackObjectFormat, PackfileUriError};

pub const MAX_PKT_LINE_BYTES: usize = 65_520;
pub const MAX_SIDEBAND_DATA_BYTES: usize = 65_515;
pub const MAX_FETCH_V2_WIRE_BYTES: usize = 1024 * 1024;
pub const MAX_FETCH_V2_PKTS: usize = 16_384;
pub const MAX_FETCH_WANTS: usize = 1_024;
pub const MAX_FETCH_HAVES: usize = 4_096;
pub const MAX_UNSUPPORTED_FETCH_ARGS: usize = 64;
const MAX_PROTOCOL_TOKENS: usize = 8;

/// Returns `true` strictly when policy both enables offload and allows capability advertisement.
pub const fn should_advertise_packfile_uris(policy: &OffloadPolicyConfig) -> bool {
    policy.enabled && policy.advertise_in_capabilities
}

/// Advertised Protocol v2 `fetch` capability line gated by [`OffloadPolicyConfig`].
pub fn format_fetch_capability_line_for_policy(policy: &OffloadPolicyConfig) -> String {
    format_fetch_capability_line(should_advertise_packfile_uris(policy))
}

/// Advertised Protocol v2 `fetch` capability line (`packfile-uris` opt-in).
pub fn format_fetch_capability_line(offload_advertised: bool) -> String {
    fetch_capability_tokens(offload_advertised).join(" ")
}

/// Ordered feature tokens advertised on the `fetch=` capability line.
pub fn fetch_capability_tokens(offload_advertised: bool) -> Vec<&'static str> {
    if offload_advertised {
        vec!["shallow", "filter", "wait-for-done", "packfile-uris"]
    } else {
        vec!["shallow", "filter", "wait-for-done"]
    }
}

/// Rewrites a native `git upload-pack --advertise-refs` v2 stream to append `packfile-uris`
/// on the `fetch=...` capability line strictly when `policy.enabled && policy.advertise_in_capabilities`.
pub fn inject_packfile_uris_into_v2_advertisement(
    raw_adv: &[u8],
    policy: &OffloadPolicyConfig,
) -> Result<Vec<u8>, PackfileUriError> {
    if !should_advertise_packfile_uris(policy) {
        return Ok(raw_adv.to_vec());
    }
    let pkts = split_v2_pkt_lines(raw_adv)?;
    let mut out = Vec::with_capacity(raw_adv.len() + 32);
    for pkt in pkts {
        match pkt {
            RawPkt::Delim => out.extend_from_slice(b"0001"),
            RawPkt::Flush => out.extend_from_slice(b"0000"),
            RawPkt::Data(raw) => {
                if let Ok(text) = std::str::from_utf8(raw) {
                    let trimmed = text.strip_suffix('\n').unwrap_or(text);
                    if trimmed == "fetch" {
                        push_pkt_line(&mut out, b"fetch=packfile-uris\n")?;
                        continue;
                    }
                    if let Some(features) = trimmed.strip_prefix("fetch=")
                        && !features.split_whitespace().any(|t| t == "packfile-uris")
                    {
                        let updated = format!("fetch={features} packfile-uris\n");
                        push_pkt_line(&mut out, updated.as_bytes())?;
                        continue;
                    }
                }
                push_pkt_line(&mut out, raw)?;
            }
        }
    }
    Ok(out)
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
    pub wait_for_done: bool,
    pub thin_pack: bool,
    pub no_progress: bool,
    pub ofs_delta: bool,
    pub include_tag: bool,
    pub uri_protocols: Option<ParsedUriProtocolSet>,
    pub unsupported_args: Vec<String>,
}

impl FetchV2Request {
    fn empty(object_format: PackObjectFormat) -> Self {
        let (wants, haves, unsupported_args) = (Vec::new(), Vec::new(), Vec::new());
        Self {
            object_format, wants, haves, done: false, wait_for_done: false, thin_pack: false,
            no_progress: false, ofs_delta: false, include_tag: false, uri_protocols: None, unsupported_args,
        }
    }

    pub fn client_supports_https_offload(&self) -> bool {
        self.uri_protocols.as_ref().is_some_and(|p| p.supports_https)
    }

    pub fn has_unsupported_args(&self) -> bool {
        !self.unsupported_args.is_empty()
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

fn parse_pkt_header_len(rest: &[u8]) -> Result<usize, PackfileUriError> {
    if rest.len() < 4 {
        return Err(PackfileUriError::ProtocolSyntax("truncated pkt-line header".to_owned()));
    }
    let hdr = std::str::from_utf8(&rest[..4])
        .ok()
        .filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| PackfileUriError::ProtocolSyntax("invalid pkt-line hex length".to_owned()))?;
    usize::from_str_radix(hdr, 16).map_err(|_| PackfileUriError::ProtocolSyntax("invalid pkt-line length".to_owned()))
}

fn split_v2_pkt_lines(stream: &[u8]) -> Result<Vec<RawPkt<'_>>, PackfileUriError> {
    if stream.len() > MAX_FETCH_V2_WIRE_BYTES {
        return Err(PackfileUriError::CapacityExceeded("protocol v2 stream exceeds 1 MiB".to_owned()));
    }
    let (mut out, mut rest, mut saw_flush) = (Vec::new(), stream, false);
    while !rest.is_empty() {
        if out.len() >= MAX_FETCH_V2_PKTS {
            return Err(PackfileUriError::ProtocolSyntax("oversized pkt-line stream".to_owned()));
        }
        let length = parse_pkt_header_len(rest)?;
        rest = &rest[4..];
        match length {
            0 => {
                out.push(RawPkt::Flush);
                saw_flush = true;
                if rest.is_empty() {
                    return Ok(out);
                }
            }
            1 => out.push(RawPkt::Delim),
            2..=3 => return Err(PackfileUriError::ProtocolSyntax("reserved pkt-line control packet".to_owned())),
            n if n > MAX_PKT_LINE_BYTES || n - 4 > rest.len() => {
                return Err(PackfileUriError::ProtocolSyntax("pkt-line payload truncated or oversized".to_owned()));
            }
            n => {
                out.push(RawPkt::Data(&rest[..n - 4]));
                rest = &rest[n - 4..];
                saw_flush = false;
            }
        }
    }
    saw_flush.then_some(out).ok_or_else(|| PackfileUriError::ProtocolSyntax("missing terminating flush-pkt".to_owned()))
}

/// Returns `true` strictly when a pre-`0001` Protocol v2 capability header pkt-line is `command=fetch`.
pub fn is_v2_fetch_command_request(stream: &[u8]) -> bool {
    let mut rest = stream;
    for _ in 0..MAX_FETCH_V2_PKTS {
        let Ok(len) = parse_pkt_header_len(rest) else { return false };
        if len <= 3 || len > MAX_PKT_LINE_BYTES || len > rest.len() {
            return false;
        }
        let payload = &rest[4..len];
        rest = &rest[len..];
        if payload.strip_suffix(b"\n").unwrap_or(payload) == b"command=fetch" {
            return true;
        }
    }
    false
}

/// Parses a Git Protocol v2 `command=fetch` request stream with strict format & count bounds.
pub fn parse_fetch_v2_request(
    stream: &[u8],
    expected_format: PackObjectFormat,
) -> Result<FetchV2Request, PackfileUriError> {
    let pkts = split_v2_pkt_lines(stream)?;
    if pkts.iter().filter(|&&p| p == RawPkt::Flush).count() != 1 {
        return Err(PackfileUriError::ProtocolSyntax("fetch request requires single flush-pkt".to_owned()));
    }
    let mut saw_command_fetch = false;
    let mut in_args = false;
    let mut req = FetchV2Request::empty(expected_format);
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
                    apply_capability_header(&mut req, &mut saw_command_fetch, line, expected_format)?;
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

fn push_unsupported_arg(req: &mut FetchV2Request, line: &str) -> Result<(), PackfileUriError> {
    if line.is_empty() || line.bytes().any(|b| b < 32 || b == 127) {
        return Err(PackfileUriError::ProtocolSyntax("malformed control/empty fetch line".to_owned()));
    }
    if req.unsupported_args.len() >= MAX_UNSUPPORTED_FETCH_ARGS {
        return Err(PackfileUriError::CapacityExceeded("unsupported fetch argument count exceeds bound".to_owned()));
    }
    req.unsupported_args.push(line.to_owned());
    Ok(())
}

fn apply_capability_header(
    req: &mut FetchV2Request,
    saw_command_fetch: &mut bool,
    line: &str,
    expected_format: PackObjectFormat,
) -> Result<(), PackfileUriError> {
    if line == "command=fetch" {
        if *saw_command_fetch {
            return Err(PackfileUriError::ProtocolSyntax("duplicate command=fetch header".to_owned()));
        }
        *saw_command_fetch = true;
    } else if let Some(fmt) = line.strip_prefix("object-format=") {
        if fmt != expected_format.as_str() {
            return Err(PackfileUriError::ScopeMismatch(format!(
                "object-format={fmt} mismatches repository {}",
                expected_format.as_str()
            )));
        }
    } else if let Some(val) = line.strip_prefix("agent=").or_else(|| line.strip_prefix("session-id=")) {
        if val.is_empty() || val.len() > 256 || val.bytes().any(|b| b < 32 || b == 127) {
            return Err(PackfileUriError::ProtocolSyntax("invalid v2 client metadata header".to_owned()));
        }
    } else {
        push_unsupported_arg(req, line)?;
    }
    Ok(())
}

fn push_hex_oid(dst: &mut Vec<String>, oid: &str, oid_len: usize, cap: usize, label: &str) -> Result<(), PackfileUriError> {
    if dst.len() >= cap {
        return Err(PackfileUriError::CapacityExceeded(format!("fetch {label} count exceeds bound")));
    }
    if !is_lower_hex_exact(oid, oid_len) {
        return Err(PackfileUriError::ProtocolSyntax(format!("invalid {label} oid")));
    }
    dst.push(oid.to_owned());
    Ok(())
}

fn apply_fetch_arg(req: &mut FetchV2Request, line: &str, oid_len: usize) -> Result<(), PackfileUriError> {
    if let Some(oid) = line.strip_prefix("want ") {
        push_hex_oid(&mut req.wants, oid, oid_len, MAX_FETCH_WANTS, "want")?;
    } else if let Some(oid) = line.strip_prefix("have ") {
        push_hex_oid(&mut req.haves, oid, oid_len, MAX_FETCH_HAVES, "have")?;
    } else if let Some(protos) = line.strip_prefix("packfile-uris ") {
        if req.uri_protocols.is_some() {
            return Err(PackfileUriError::ProtocolSyntax("duplicate packfile-uris line".to_owned()));
        }
        req.uri_protocols = Some(parse_uri_protocol_list(protos)?);
    } else {
        match line {
            "done" => req.done = true,
            "wait-for-done" => req.wait_for_done = true,
            "thin-pack" => req.thin_pack = true,
            "no-progress" => req.no_progress = true,
            "ofs-delta" => req.ofs_delta = true,
            "include-tag" => req.include_tag = true,
            _ => push_unsupported_arg(req, line)?,
        }
    }
    Ok(())
}

/// Strips any `packfile-uris ...` argument line from a Protocol v2 `command=fetch`
/// stream before handing inline fallback / negotiation to native `git upload-pack`.
pub fn strip_packfile_uris_from_v2_request(stream: &[u8]) -> Option<Vec<u8>> {
    let pkts = split_v2_pkt_lines(stream).ok()?;
    let mut stripped_any = false;
    let mut out = Vec::with_capacity(stream.len());
    for pkt in pkts {
        match pkt {
            RawPkt::Delim => out.extend_from_slice(b"0001"),
            RawPkt::Flush => out.extend_from_slice(b"0000"),
            RawPkt::Data(raw) => {
                if let Ok(text) = std::str::from_utf8(raw)
                    && text.strip_suffix('\n').unwrap_or(text).starts_with("packfile-uris ")
                {
                    stripped_any = true;
                    continue;
                }
                push_pkt_line(&mut out, raw).ok()?;
            }
        }
    }
    stripped_any.then_some(out)
}

/// Encodes a Protocol v2 `fetch` response; refuses `packfile-uris` emission unless `policy.enabled`.
pub fn encode_fetch_v2_response(
    policy: &OffloadPolicyConfig,
    delivery: &DeliveryMode,
    inline_pack_bytes: &[u8],
    client_supports_https: bool,
) -> Result<Vec<u8>, PackfileUriError> {
    encode_fetch_v2_response_with_acks(policy, delivery, &[], inline_pack_bytes, client_supports_https)
}

/// Encodes a Protocol v2 `fetch` response with optional `acknowledgments` + `ready` section.
pub fn encode_fetch_v2_response_with_acks(
    policy: &OffloadPolicyConfig,
    delivery: &DeliveryMode,
    acked_haves: &[String],
    inline_pack_bytes: &[u8],
    client_supports_https: bool,
) -> Result<Vec<u8>, PackfileUriError> {
    let max_b = policy.max_v2_response_bytes;
    encode_fetch_v2_response_bounded(policy, delivery, acked_haves, inline_pack_bytes, client_supports_https, max_b)
}

fn ensure_within_cap(len: usize, cap: u64) -> Result<(), PackfileUriError> {
    if len as u64 > cap {
        Err(PackfileUriError::CapacityExceeded("v2 fetch response exceeds byte bound".to_owned()))
    } else {
        Ok(())
    }
}

/// Encodes a Protocol v2 `fetch` response enforcing a hard byte ceiling on total output size.
pub fn encode_fetch_v2_response_bounded(
    policy: &OffloadPolicyConfig,
    delivery: &DeliveryMode,
    acked_haves: &[String],
    inline_pack_bytes: &[u8],
    client_supports_https: bool,
    max_response_bytes: u64,
) -> Result<Vec<u8>, PackfileUriError> {
    let cap = max_response_bytes.min(policy.max_v2_response_bytes);
    if cap == 0 || inline_pack_bytes.len() as u64 >= cap {
        return Err(PackfileUriError::CapacityExceeded("v2 fetch response exceeds byte bound".to_owned()));
    }
    let mut out = Vec::with_capacity(inline_pack_bytes.len().saturating_add(512));
    if !acked_haves.is_empty() {
        push_pkt_line(&mut out, b"acknowledgments\n")?;
        for h in acked_haves {
            push_pkt_line(&mut out, format!("ACK {h}\n").as_bytes())?;
            ensure_within_cap(out.len(), cap)?;
        }
        push_pkt_line(&mut out, b"ready\n")?;
        out.extend_from_slice(b"0001");
    }
    if let DeliveryMode::OffloadPlusResidual { offloaded, .. } = delivery {
        if !policy.enabled {
            return Err(PackfileUriError::InvalidPolicy(
                "refusing packfile-uris response emission while policy is disabled".to_owned(),
            ));
        }
        if client_supports_https && !offloaded.is_empty() {
            push_pkt_line(&mut out, b"packfile-uris\n")?;
            for desc in offloaded {
                if !desc.uri.starts_with("https://") {
                    return Err(PackfileUriError::UnsupportedProtocol("refusing non-https offload uri".to_owned()));
                }
                push_pkt_line(&mut out, format!("{} {}\n", desc.pack_hash_hex, desc.uri).as_bytes())?;
                ensure_within_cap(out.len(), cap)?;
            }
            out.extend_from_slice(b"0001");
        }
    }
    push_pkt_line(&mut out, b"packfile\n")?;
    for chunk in inline_pack_bytes.chunks(MAX_SIDEBAND_DATA_BYTES) {
        let mut frame = Vec::with_capacity(chunk.len() + 1);
        frame.push(1);
        frame.extend_from_slice(chunk);
        push_pkt_line(&mut out, &frame)?;
        ensure_within_cap(out.len(), cap)?;
    }
    out.extend_from_slice(b"0000");
    ensure_within_cap(out.len(), cap)?;
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
