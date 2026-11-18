//! Bounded Smart HTTP `receive-pack` pkt-line framing, capability-checked
//! advertisement policy, and `report-status` / `report-status-v2` wire encoder.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use async_compression::tokio::bufread::GzipDecoder;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

use crate::ref_store::core::types::{GitObjectFormat, GitOid, RefName};

use super::receipt::validate_wire_reason;
use super::types::{
    PushAuthContext, PushCausalError, PushedRefCommand, ReceiveCapabilities, STREAM_CHUNK_BYTES, StreamIngestLimits,
};

const MAX_PKT_LINE_BYTES: usize = 65_520;

/// Remaining body reader cleanly carrying unconsumed prefix bytes before the socket stream.
pub struct DecodedReceiveStream {
    pub commands: Vec<PushedRefCommand>,
    pub capabilities: ReceiveCapabilities,
    pub command_bytes_read: usize,
    pub remainder: Box<dyn AsyncRead + Unpin + Send>,
}

/// Client capability and request-intent profile checked BEFORE narrowing ref advertisement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPushCapabilityProfile {
    pub protocol_version: u8,
    pub supports_narrowed_advertisement: bool,
    pub compatibility_proof_id: Option<String>,
    pub supports_ofs_delta: bool,
    pub supports_delete_refs: bool,
    pub supports_atomic: bool,
    pub object_format: GitObjectFormat,
    pub requested_targets: BTreeSet<String>,
    pub stacked_parent_refs: BTreeMap<String, Vec<String>>,
    pub force_with_lease_refs: BTreeMap<String, String>,
}

/// Visible or protected ref inventory passed into the push advertisement planner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VisibleRefEntry {
    pub ref_name: String,
    pub oid: String,
    pub visible_to_principal: bool,
    pub is_shared_base: bool,
    pub is_default_head: bool,
}

/// Advertisement optimization strategy evaluated against authorization and client semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvertisementStrategy {
    FullAuthorizedFallback,
    NarrowedSharedBases,
}

/// Input bundle for [`build_push_ref_advertisement`].
#[derive(Clone, Debug)]
pub struct AdvertisementRequest {
    pub repository_format: GitObjectFormat,
    pub desired_strategy: AdvertisementStrategy,
    pub client: ClientPushCapabilityProfile,
    pub auth: PushAuthContext,
    pub refs: Vec<VisibleRefEntry>,
}

/// Result of push ref advertisement proving no unauthorized ref leaks and no silent omissions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvertisementDecision {
    pub strategy_used: AdvertisementStrategy,
    pub advertised_refs: Vec<VisibleRefEntry>,
    pub suppressed_unauthorized_count: usize,
    pub compatibility_proven: bool,
    pub fallback_reason: Option<String>,
}

async fn read_exact_until<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    buf: &mut [u8],
    deadline: Instant,
    eof_context: &'static str,
) -> Result<(), PushCausalError> {
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(PushCausalError::DeadlineExceeded)?;
    tokio::time::timeout(remaining, reader.read_exact(buf))
        .await
        .map_err(|_| PushCausalError::DeadlineExceeded)?
        .map(|_| ())
        .map_err(|e| PushCausalError::MalformedProtocol(format!("{eof_context}: {e}")))
}

/// Stream only the Smart HTTP `receive-pack` pkt-line command block without buffering
/// the trailing pack bytes into RAM, enforcing the shared end-to-end `deadline` across
/// every header and payload read. Returns the remaining reader positioned at `PACK`.
pub async fn decode_receive_pack_stream<R>(
    reader: R,
    gzipped: bool,
    object_format: GitObjectFormat,
    limits: &StreamIngestLimits,
    deadline: Instant,
) -> Result<DecodedReceiveStream, PushCausalError>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let bounded = reader.take(limits.max_stream_bytes.saturating_add(1));
    let mut decoder: Box<dyn AsyncRead + Unpin + Send> = if gzipped {
        let mut gz = GzipDecoder::new(BufReader::with_capacity(STREAM_CHUNK_BYTES, bounded));
        gz.multiple_members(false);
        Box::new(gz)
    } else {
        Box::new(BufReader::with_capacity(STREAM_CHUNK_BYTES, bounded))
    };

    let mut commands = Vec::new();
    let mut capabilities = ReceiveCapabilities::default();
    let mut seen_refs = BTreeSet::new();
    let mut command_bytes_read = 0usize;

    loop {
        let mut len_buf = [0u8; 4];
        read_exact_until(decoder.as_mut(), &mut len_buf, deadline, "incomplete pkt-line header").await?;
        command_bytes_read = command_bytes_read.saturating_add(4);
        if command_bytes_read > limits.max_command_bytes || (command_bytes_read as u64) > limits.max_stream_bytes {
            return Err(PushCausalError::LimitExceeded("receive-pack command block exceeded stream/command budget"));
        }
        let header = std::str::from_utf8(&len_buf)
            .map_err(|_| PushCausalError::MalformedProtocol("non-utf8 pkt-line length".into()))?;
        if !header.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PushCausalError::MalformedProtocol("non-hex pkt-line length".into()));
        }
        let length = usize::from_str_radix(header, 16)
            .map_err(|_| PushCausalError::MalformedProtocol("invalid pkt-line hex length".into()))?;
        if length == 0 {
            break;
        }
        if !(4..=MAX_PKT_LINE_BYTES).contains(&length) {
            return Err(PushCausalError::MalformedProtocol("pkt-line length out of protocol bounds".into()));
        }
        let payload_len = length - 4;
        command_bytes_read = command_bytes_read.saturating_add(payload_len);
        if command_bytes_read > limits.max_command_bytes || (command_bytes_read as u64) > limits.max_stream_bytes {
            return Err(PushCausalError::LimitExceeded("receive-pack command block exceeded stream/command budget"));
        }
        let mut payload = vec![0u8; payload_len];
        read_exact_until(decoder.as_mut(), &mut payload, deadline, "truncated pkt-line payload").await?;
        let text = payload.strip_suffix(b"\n").unwrap_or(&payload);
        if text.starts_with(b"shallow ") {
            if !limits.allow_shallow {
                return Err(PushCausalError::ShallowRejected);
            }
            continue;
        }
        if commands.len() >= limits.max_commands {
            return Err(PushCausalError::LimitExceeded("receive-pack command count exceeded max_commands"));
        }
        let (cmd_bytes, cap_bytes) = match text.iter().position(|b| *b == 0) {
            Some(pos) => {
                if !commands.is_empty() {
                    return Err(PushCausalError::MalformedProtocol(
                        "capabilities NUL separator allowed only on first command".into(),
                    ));
                }
                (&text[..pos], Some(&text[pos + 1..]))
            }
            None => (text, None),
        };
        if let Some(caps_raw) = cap_bytes {
            capabilities = parse_capabilities(caps_raw, object_format)?;
        }
        let cmd = parse_command_line(cmd_bytes, object_format)?;
        if !seen_refs.insert(cmd.ref_name.clone()) {
            return Err(PushCausalError::MalformedProtocol(format!("duplicate ref command `{}`", cmd.ref_name)));
        }
        commands.push(cmd);
    }

    if commands.is_empty() {
        return Err(PushCausalError::MalformedProtocol("receive-pack contained zero ref commands".into()));
    }
    if limits.require_report_status && !(capabilities.report_status || capabilities.report_status_v2) {
        return Err(PushCausalError::MalformedProtocol(
            "client omitted required report-status / report-status-v2 capability".into(),
        ));
    }
    if let Some(fmt) = capabilities.object_format
        && fmt != object_format
    {
        return Err(PushCausalError::ObjectFormatMismatch);
    }

    Ok(DecodedReceiveStream { commands, capabilities, command_bytes_read, remainder: decoder })
}

fn parse_capabilities(raw: &[u8], expected_format: GitObjectFormat) -> Result<ReceiveCapabilities, PushCausalError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| PushCausalError::MalformedProtocol("non-utf8 receive-pack capabilities".into()))?;
    let mut caps = ReceiveCapabilities::default();
    for token in text.split(' ').filter(|t| !t.is_empty()) {
        if token.bytes().any(|b| b < 32 || b == 127) {
            return Err(PushCausalError::MalformedProtocol("control character in capabilities".into()));
        }
        match token {
            "report-status" => caps.report_status = true,
            "report-status-v2" => caps.report_status_v2 = true,
            "side-band-64k" => caps.sideband_64k = true,
            "atomic" => caps.atomic = true,
            "ofs-delta" => caps.ofs_delta = true,
            "delete-refs" => caps.delete_refs = true,
            "quiet" => caps.quiet = true,
            _ if token.starts_with("agent=") => {
                caps.agent = Some(token.trim_start_matches("agent=").to_owned());
            }
            _ if token.starts_with("object-format=") => {
                let fmt = GitObjectFormat::parse(token.trim_start_matches("object-format="))
                    .map_err(|_| PushCausalError::ObjectFormatMismatch)?;
                if fmt != expected_format {
                    return Err(PushCausalError::ObjectFormatMismatch);
                }
                caps.object_format = Some(fmt);
            }
            _ => {}
        }
    }
    Ok(caps)
}

fn parse_command_line(raw: &[u8], object_format: GitObjectFormat) -> Result<PushedRefCommand, PushCausalError> {
    let line =
        std::str::from_utf8(raw).map_err(|_| PushCausalError::MalformedProtocol("non-utf8 ref command line".into()))?;
    if line.bytes().any(|b| b < 32 || b == 127) {
        return Err(PushCausalError::MalformedProtocol("control byte in ref command line".into()));
    }
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.len() != 3 {
        return Err(PushCausalError::MalformedProtocol("command line must contain <old> <new> <ref>".into()));
    }
    let (old_oid, new_oid, ref_name) = (parts[0], parts[1], parts[2]);
    validate_wire_oid(object_format, old_oid)?;
    validate_wire_oid(object_format, new_oid)?;
    if old_oid.bytes().all(|b| b == b'0') && new_oid.bytes().all(|b| b == b'0') {
        return Err(PushCausalError::MalformedProtocol(format!("both old and new OIDs zero for `{ref_name}`")));
    }
    RefName::new(ref_name).map_err(|e| PushCausalError::MalformedProtocol(e.to_string()))?;
    Ok(PushedRefCommand { ref_name: ref_name.to_owned(), old_oid: old_oid.to_owned(), new_oid: new_oid.to_owned() })
}

fn validate_wire_oid(format: GitObjectFormat, value: &str) -> Result<(), PushCausalError> {
    if value.len() == format.oid_hex_len() && value.bytes().all(|b| b == b'0') {
        return Ok(());
    }
    GitOid::parse(format, value).map(|_| ()).map_err(|e| PushCausalError::MalformedProtocol(e.to_string()))
}

/// Evaluate ref advertisement narrowing safely: verifies authorization and client capability
/// across existing branches, create/delete, stacked branches, and force-with-lease. Falls back
/// to full authorized refs when compatibility proof is absent and never leaks unauthorized refs.
pub fn build_push_ref_advertisement(req: &AdvertisementRequest) -> Result<AdvertisementDecision, PushCausalError> {
    req.auth.check_active()?;
    if req.client.object_format != req.repository_format {
        return Err(PushCausalError::ObjectFormatMismatch);
    }

    let mut by_name = BTreeMap::new();
    let mut suppressed_unauthorized_count = 0usize;
    let mut authorized_refs = Vec::new();
    for entry in &req.refs {
        RefName::new(entry.ref_name.as_str()).map_err(|e| PushCausalError::MalformedProtocol(e.to_string()))?;
        validate_wire_oid(req.repository_format, &entry.oid)?;
        let principal_visible = entry.visible_to_principal
            && (req.auth.visible_refs.is_empty() || req.auth.visible_refs.contains(&entry.ref_name));
        by_name.insert(entry.ref_name.as_str(), (entry, principal_visible));
        if principal_visible {
            authorized_refs.push(entry.clone());
        } else {
            suppressed_unauthorized_count = suppressed_unauthorized_count.saturating_add(1);
        }
    }

    // Fail closed if stacked branch parent or force-with-lease expectation references an unauthorized ref.
    for parents in req.client.stacked_parent_refs.values() {
        for parent in parents {
            if let Some((_, visible)) = by_name.get(parent.as_str())
                && !*visible
            {
                return Err(PushCausalError::UnauthorizedBaseDependency(format!(
                    "stacked branch base `{parent}` is not authorized for principal"
                )));
            }
        }
    }
    for lease_ref in req.client.force_with_lease_refs.keys() {
        if let Some((_, visible)) = by_name.get(lease_ref.as_str())
            && !*visible
        {
            return Err(PushCausalError::AuthorizationDenied("force-with-lease targets an unauthorized ref"));
        }
    }

    if req.desired_strategy == AdvertisementStrategy::FullAuthorizedFallback {
        return Ok(AdvertisementDecision {
            strategy_used: AdvertisementStrategy::FullAuthorizedFallback,
            advertised_refs: authorized_refs,
            suppressed_unauthorized_count,
            compatibility_proven: false,
            fallback_reason: Some("configured to full authorized advertisement".into()),
        });
    }

    let compat_ok = req.client.supports_narrowed_advertisement
        && req.client.compatibility_proof_id.as_deref().is_some_and(|s| !s.is_empty());
    if !compat_ok {
        return Ok(AdvertisementDecision {
            strategy_used: AdvertisementStrategy::FullAuthorizedFallback,
            advertised_refs: authorized_refs,
            suppressed_unauthorized_count,
            compatibility_proven: false,
            fallback_reason: Some(
                "missing client capability compatibility proof; using full authorized fallback".into(),
            ),
        });
    }

    // Preserve every ref needed for shared bases, default HEAD, existing/target updates,
    // stacked branch bases, and force-with-lease CAS expectations without silent hiding.
    let mut required_names: BTreeSet<String> = BTreeSet::new();
    for entry in &authorized_refs {
        if entry.is_shared_base || entry.is_default_head {
            required_names.insert(entry.ref_name.clone());
        }
    }
    for target in &req.client.requested_targets {
        required_names.insert(target.clone());
    }
    for (child, parents) in &req.client.stacked_parent_refs {
        required_names.insert(child.clone());
        for parent in parents {
            required_names.insert(parent.clone());
        }
    }
    for lease_ref in req.client.force_with_lease_refs.keys() {
        required_names.insert(lease_ref.clone());
    }

    let narrowed: Vec<VisibleRefEntry> =
        authorized_refs.into_iter().filter(|e| required_names.contains(&e.ref_name)).collect();

    Ok(AdvertisementDecision {
        strategy_used: AdvertisementStrategy::NarrowedSharedBases,
        advertised_refs: narrowed,
        suppressed_unauthorized_count,
        compatibility_proven: true,
        fallback_reason: None,
    })
}

/// Encode Smart HTTP `git-receive-pack` advertisement pkt-lines cleanly.
pub fn encode_ref_advertisement(
    decision: &AdvertisementDecision,
    format: GitObjectFormat,
    service_banner: bool,
) -> Result<Vec<u8>, PushCausalError> {
    let mut out = Vec::new();
    if service_banner {
        push_pktline(&mut out, b"# service=git-receive-pack\n")?;
        out.extend_from_slice(b"0000");
    }
    let caps = format!(
        "report-status report-status-v2 delete-refs side-band-64k ofs-delta atomic object-format={}",
        format.as_str()
    );
    if decision.advertised_refs.is_empty() {
        let zero = "0".repeat(format.oid_hex_len());
        let line = format!("{zero} capabilities^{{}}\0{caps}\n");
        push_pktline(&mut out, line.as_bytes())?;
    } else {
        for (idx, item) in decision.advertised_refs.iter().enumerate() {
            let line = if idx == 0 {
                format!("{} {}\0{caps}\n", item.oid, item.ref_name)
            } else {
                format!("{} {}\n", item.oid, item.ref_name)
            };
            push_pktline(&mut out, line.as_bytes())?;
        }
    }
    out.extend_from_slice(b"0000");
    Ok(out)
}

/// Encode canonical Git `report-status` / `report-status-v2` response (with optional `side-band-64k`).
pub fn encode_receive_pack_report(
    caps: &ReceiveCapabilities,
    unpack_ok: Result<(), &str>,
    ref_statuses: &[(&str, Result<(), &str>)],
) -> Result<Vec<u8>, PushCausalError> {
    if !(caps.report_status || caps.report_status_v2) {
        return Ok(Vec::new());
    }
    let mut inner = Vec::new();
    match unpack_ok {
        Ok(()) => push_pktline(&mut inner, b"unpack ok\n")?,
        Err(reason) => {
            validate_wire_reason(reason)?;
            push_pktline(&mut inner, format!("unpack {reason}\n").as_bytes())?;
        }
    }
    for (ref_name, status) in ref_statuses {
        RefName::new(*ref_name).map_err(|e| PushCausalError::MalformedProtocol(e.to_string()))?;
        match status {
            Ok(()) => push_pktline(&mut inner, format!("ok {ref_name}\n").as_bytes())?,
            Err(reason) => {
                validate_wire_reason(reason)?;
                push_pktline(&mut inner, format!("ng {ref_name} {reason}\n").as_bytes())?;
            }
        }
    }
    inner.extend_from_slice(b"0000");
    if !caps.sideband_64k {
        return Ok(inner);
    }
    let mut outer = Vec::new();
    for chunk in inner.chunks(65_515) {
        let mut frame = Vec::with_capacity(chunk.len() + 1);
        frame.push(1);
        frame.extend_from_slice(chunk);
        push_pktline(&mut outer, &frame)?;
    }
    outer.extend_from_slice(b"0000");
    Ok(outer)
}

fn push_pktline(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), PushCausalError> {
    let length = payload.len() + 4;
    if length > MAX_PKT_LINE_BYTES {
        return Err(PushCausalError::LimitExceeded("pkt-line payload exceeded 65520 bytes"));
    }
    out.extend_from_slice(format!("{length:04x}").as_bytes());
    out.extend_from_slice(payload);
    Ok(())
}
