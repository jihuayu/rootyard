//! Bounded Smart-HTTP wire syntax used by the receive-pack path.
//!
//! Only pkt-line structures the gateway actually emits/accepts are decoded.
//! Command parsing happens on a bounded prefix before any native/Blob work;
//! `report-status` output is generated from the durable terminal, never from a
//! caller boolean or from the temporary local Git view.
use crate::ref_store::GitObjectFormat;

use super::error::GatewayError;

/// One receive command as sent by the client. `old`/`new` stay wire hex here;
/// the receive path converts them through the sealed `GitOid` vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PushCommand {
    pub old: String,
    pub new: String,
    pub name: String,
}

impl PushCommand {
    pub(super) fn is_delete(&self) -> bool {
        self.new.bytes().all(|byte| byte == b'0')
    }
}

/// Parsed command section plus the capability request of the first pkt-line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PushRequest {
    pub commands: Vec<PushCommand>,
    pub capabilities: Vec<String>,
}

impl PushRequest {
    pub(super) fn wants_report(&self) -> bool {
        self.capabilities.iter().any(|capability| capability == "report-status")
    }

    pub(super) fn wants_atomic(&self) -> bool {
        self.capabilities.iter().any(|capability| capability == "atomic")
    }
}

/// Maximum capability-request bytes and command count, matching the core batch
/// bound without importing a private constant.
pub(super) const MAX_COMMAND_BYTES: usize = 128 * 1024;
pub(super) const MAX_COMMANDS: usize = 128;

/// Decode the bounded command prefix. A missing flush, a malformed pkt-line, an
/// unsupported capability, a duplicate/unsafe ref or a foreign object id fails
/// closed before any native child, Blob IO or PostgreSQL write.
pub(super) fn parse_push(prefix: &[u8], format: GitObjectFormat) -> Result<PushRequest, GatewayError> {
    let oid_len = format.oid_hex_len();
    let mut position = 0usize;
    let mut commands: Vec<PushCommand> = Vec::new();
    let mut capabilities: Vec<String> = Vec::new();
    let mut first = true;
    loop {
        if position + 4 > prefix.len() {
            return Err(GatewayError::BadRequest("truncated push command pkt-line"));
        }
        let header = &prefix[position..position + 4];
        let length = std::str::from_utf8(header)
            .ok()
            .and_then(|value| usize::from_str_radix(value, 16).ok())
            .ok_or(GatewayError::BadRequest("invalid push command pkt-line length"))?;
        position += 4;
        if length == 0 {
            break;
        }
        if !(4..=65520).contains(&length) {
            return Err(GatewayError::BadRequest("invalid push command pkt-line length"));
        }
        let payload_len = length - 4;
        if position + payload_len > prefix.len() || position + payload_len > MAX_COMMAND_BYTES {
            return Err(GatewayError::BadRequest("push command section exceeds its byte bound"));
        }
        let payload = &prefix[position..position + payload_len];
        position += payload_len;
        if commands.len() >= MAX_COMMANDS {
            return Err(GatewayError::BadRequest("push command count exceeds its bound"));
        }
        let (line, caps) = match payload.iter().position(|byte| *byte == 0) {
            Some(index) => (&payload[..index], Some(&payload[index + 1..])),
            None => (payload, None),
        };
        if first {
            if let Some(caps) = caps {
                let text = std::str::from_utf8(caps)
                    .map_err(|_| GatewayError::BadRequest("push capabilities are not UTF-8"))?;
                for capability in text.split_whitespace() {
                    if !supported_capability(capability, format) {
                        return Err(GatewayError::BadRequest("unsupported push capability"));
                    }
                    capabilities.push(capability.to_owned());
                }
            }
        } else if caps.is_some() {
            return Err(GatewayError::BadRequest("push capabilities may appear only once"));
        }
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        if line.starts_with(b"shallow ") {
            return Err(GatewayError::BadRequest("shallow push is not supported"));
        }
        let text = std::str::from_utf8(line).map_err(|_| GatewayError::BadRequest("push command is not UTF-8"))?;
        let mut fields = text.split(' ');
        let (Some(old), Some(new), Some(name), None) = (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(GatewayError::BadRequest("malformed push command"));
        };
        if !valid_oid(old, oid_len) || !valid_oid(new, oid_len) {
            return Err(GatewayError::BadRequest("push command object id has the wrong format"));
        }
        let ref_name = crate::ref_store::RefName::new(name.to_owned())
            .map_err(|_| GatewayError::BadRequest("push command names an invalid ref"))?;
        if commands.iter().any(|command| command.name == ref_name.as_str()) {
            return Err(GatewayError::BadRequest("duplicate ref in one push"));
        }
        commands.push(PushCommand { old: old.to_owned(), new: new.to_owned(), name: ref_name.as_str().to_owned() });
        first = false;
    }
    if commands.is_empty() {
        return Err(GatewayError::BadRequest("push contains no ref commands"));
    }
    Ok(PushRequest { commands, capabilities })
}

fn valid_oid(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The gateway advertises only capabilities it actually implements. `atomic`
/// maps to the core all-or-nothing commit mode; without it the original batch is
/// still handled by the accepted-subset facade (never a quiet local filter).
fn supported_capability(capability: &str, format: GitObjectFormat) -> bool {
    // `agent=` is identification only and has no server-side effect. Anything
    // that would change the response framing (side-band, push-options, v2
    // report) is refused because this gateway does not advertise it.
    matches!(capability, "report-status" | "delete-refs" | "atomic" | "quiet")
        || capability.starts_with("agent=")
        || capability == format!("object-format={}", format.as_str())
}

fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{:04x}", payload.len() + 4).into_bytes();
    bytes.extend_from_slice(payload);
    bytes
}

/// v0 receive-pack advertisement built from the sealed snapshot refs. The
/// capability list is exactly what this gateway supports; it never mirrors
/// native capabilities that the gateway does not honour itself.
pub(super) fn advertise_refs(refs: &[(String, String)], format: GitObjectFormat) -> Vec<u8> {
    let capabilities = format!("report-status delete-refs atomic object-format={}", format.as_str());
    let mut bytes = Vec::new();
    if refs.is_empty() {
        let line = format!("{} capabilities^{{}}\0{}\n", "0".repeat(format.oid_hex_len()), capabilities);
        bytes.extend_from_slice(&pkt_line(line.as_bytes()));
    } else {
        for (index, (name, oid)) in refs.iter().enumerate() {
            let line = if index == 0 { format!("{oid} {name}\0{capabilities}\n") } else { format!("{oid} {name}\n") };
            bytes.extend_from_slice(&pkt_line(line.as_bytes()));
        }
    }
    bytes.extend_from_slice(b"0000");
    bytes
}

/// `report-status` body. `results` must cover every command exactly once; the
/// caller verifies that against the durable terminal before calling.
pub(super) fn report_status(requested: bool, results: &[(String, Result<(), &'static str>)]) -> Vec<u8> {
    if !requested {
        return Vec::new();
    }
    let mut bytes = pkt_line(b"unpack ok\n");
    for (name, outcome) in results {
        let line = match outcome {
            Ok(()) => format!("ok {name}\n"),
            Err(reason) => format!("ng {name} {reason}\n"),
        };
        bytes.extend_from_slice(&pkt_line(line.as_bytes()));
    }
    bytes.extend_from_slice(b"0000");
    bytes
}

/// A native receive-pack refusal is passed through only when its stdout is a
/// complete, bounded pkt-line report with a trailing flush. Anything else is an
/// internal failure, never a guessed report.
pub(super) fn valid_native_report(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_COMMAND_BYTES {
        return false;
    }
    let mut position = 0usize;
    let mut packets = 0usize;
    loop {
        if position + 4 > bytes.len() {
            return false;
        }
        let length = std::str::from_utf8(&bytes[position..position + 4])
            .ok()
            .and_then(|value| usize::from_str_radix(value, 16).ok());
        let Some(length) = length else { return false };
        position += 4;
        if length == 0 {
            return position == bytes.len() && packets > 0;
        }
        if !(4..=65520).contains(&length) || position + length - 4 > bytes.len() {
            return false;
        }
        position += length - 4;
        packets += 1;
    }
}

/// Accept a native refusal as a definite no-effect result only when the report
/// is structurally complete, contains an `unpack` line and never claims that a
/// ref was applied locally (`ok <ref>`). The fresh-operation probe already ran,
/// so nothing was published; this guards against passing through a local report
/// that would look like durable success.
pub(super) fn native_report_is_rejection(bytes: &[u8]) -> bool {
    if !valid_native_report(bytes) {
        return false;
    }
    let mut position = 0usize;
    let mut saw_unpack = false;
    loop {
        let length = std::str::from_utf8(&bytes[position..position + 4])
            .ok()
            .and_then(|value| usize::from_str_radix(value, 16).ok());
        let Some(length) = length else { return false };
        position += 4;
        if length == 0 {
            return saw_unpack && position == bytes.len();
        }
        let payload = &bytes[position..position + length - 4];
        position += length - 4;
        if payload.starts_with(b"unpack ") {
            saw_unpack = true;
        } else if !payload.starts_with(b"ng ") {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(payload: &str) -> Vec<u8> {
        pkt_line(payload.as_bytes())
    }

    #[test]
    fn parses_ordered_commands_and_capabilities() {
        let oid = "a".repeat(40);
        let zero = "0".repeat(40);
        let mut bytes = packet(&format!("{zero} {oid} refs/heads/main\0report-status atomic object-format=sha1\n"));
        bytes.extend(packet(&format!("{oid} {zero} refs/heads/old\n")));
        bytes.extend(b"0000PACK");
        let parsed = parse_push(&bytes, GitObjectFormat::Sha1).expect("valid push prefix");
        assert_eq!(parsed.commands.len(), 2);
        assert!(parsed.commands[1].is_delete());
        assert!(parsed.wants_report() && parsed.wants_atomic());
    }

    #[test]
    fn refuses_unsupported_shapes() {
        let oid = "a".repeat(40);
        let zero = "0".repeat(40);
        let mut sideband = packet(&format!("{zero} {oid} refs/heads/main\0side-band-64k\n"));
        sideband.extend(b"0000");
        assert!(parse_push(&sideband, GitObjectFormat::Sha1).is_err());
        let mut duplicate = packet(&format!("{zero} {oid} refs/heads/main\n"));
        duplicate.extend(packet(&format!("{oid} {oid} refs/heads/main\n")));
        duplicate.extend(b"0000");
        assert!(parse_push(&duplicate, GitObjectFormat::Sha1).is_err());
        assert!(parse_push(b"{bad", GitObjectFormat::Sha1).is_err());
    }

    #[test]
    fn report_and_advertisement_are_parseable() {
        let refs = vec![("refs/heads/main".to_owned(), "b".repeat(40))];
        let advert = advertise_refs(&refs, GitObjectFormat::Sha1);
        assert!(advert.ends_with(b"0000"));
        let report = report_status(
            true,
            &[("refs/heads/main".to_owned(), Ok(())), ("refs/heads/old".to_owned(), Err("stale info"))],
        );
        assert!(valid_native_report(&report));
        assert!(!valid_native_report(b""));
        assert!(!valid_native_report(b"00"));
    }

    #[test]
    fn only_an_all_ng_native_report_counts_as_a_definite_rejection() {
        let mut rejected = packet("unpack ok\n");
        rejected.extend(packet("ng refs/heads/main stale info\n"));
        rejected.extend(b"0000");
        assert!(native_report_is_rejection(&rejected));

        let mut mixed = packet("unpack ok\n");
        mixed.extend(packet("ok refs/heads/main\n"));
        mixed.extend(b"0000");
        assert!(!native_report_is_rejection(&mixed), "a locally applied ref is not a durable success");

        let mut broken = packet("unpack error bad pack\n");
        broken.extend(b"0000");
        assert!(native_report_is_rejection(&broken));

        assert!(!native_report_is_rejection(b""));
        assert!(!native_report_is_rejection(b"0000"));
    }
}
