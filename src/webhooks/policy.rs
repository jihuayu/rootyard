//! Egress policy for webhook targets.
//!
//! Loopback targets are denied for every caller (owner, direct collaborator, team
//! member or organization administrator) because a hook URL is untrusted input
//! that would otherwise let a tenant reach services that rely on a loopback bind
//! for isolation. Only an explicit operator/test opt-in enables loopback targets;
//! there is deliberately no per-request body override. The policy is re-read for
//! creation, update and every delivery attempt, so withdrawing the opt-in also
//! stops deliveries for rows that already exist.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Operator/test switch. Read on every validation; unset means "deny".
pub const ALLOW_LOOPBACK_ENV: &str = "ROOTYARD_WEBHOOK_ALLOW_LOOPBACK";

/// Parses the operator flag. Anything other than a case-insensitive `true`
/// (unset, empty, `false`, `1`, `yes`) keeps the secure default.
pub fn parse_allow_loopback(value: Option<&str>) -> bool {
    value.is_some_and(|raw| raw.trim().eq_ignore_ascii_case("true"))
}

/// Current process egress policy for loopback webhook targets.
pub fn loopback_targets_allowed() -> bool {
    parse_allow_loopback(std::env::var(ALLOW_LOOPBACK_ENV).ok().as_deref())
}

/// Canonical loopback host forms accepted by the `forge_webhooks.url` column
/// check: `127.0.0.1`, `[::1]`, `localhost` and `*.localhost`. Other loopback
/// literals (for example `127.0.0.2`) stay blocked by the IP range checks, so
/// the opt-in can never widen the persisted URL contract.
pub fn host_is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "localhost") || host.ends_with(".localhost")
}

pub(crate) fn ipv4_is_blocked_non_loopback(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_unspecified()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || octets[0] == 0
        || octets[0] == 127
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || octets[0] >= 240
}

pub(crate) fn ipv6_is_blocked_non_loopback(ip: Ipv6Addr) -> bool {
    let segs = ip.segments();
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return ipv4_is_blocked_non_loopback(mapped);
    }
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segs[0] & 0xfe00) == 0xfc00
        || (segs[0] & 0xffc0) == 0xfe80
        || (segs[0] == 0x2001 && segs[1] == 0x0db8)
}

/// DNS answers are validated at connection time, then pinned into the HTTP client's
/// resolver so a second lookup cannot substitute a private address. A canonical
/// loopback host is only permitted while the operator opt-in is active, and every
/// answer of a non-loopback name must be publicly routable.
pub fn permitted_peer(host_is_loopback: bool, ip: IpAddr, loopback_allowed: bool) -> bool {
    if host_is_loopback {
        return loopback_allowed && ip.is_loopback();
    }
    match ip {
        IpAddr::V4(v4) => !ipv4_is_blocked_non_loopback(v4),
        IpAddr::V6(v6) => !ipv6_is_blocked_non_loopback(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhooks::models::validate_webhook_url_with_policy;

    #[test]
    fn operator_flag_defaults_to_deny() {
        assert!(!parse_allow_loopback(None));
        assert!(!parse_allow_loopback(Some("")));
        assert!(!parse_allow_loopback(Some("false")));
        assert!(!parse_allow_loopback(Some("0")));
        assert!(!parse_allow_loopback(Some("yes")));
        assert!(!parse_allow_loopback(Some("2")));
        assert!(parse_allow_loopback(Some("true")));
        assert!(parse_allow_loopback(Some(" TRUE ")));
        assert!(parse_allow_loopback(Some("True")));
    }

    #[test]
    fn loopback_host_forms_are_canonical() {
        for host in ["127.0.0.1", "::1", "localhost", "ci.localhost"] {
            assert!(host_is_loopback(host), "expected loopback host: {host}");
        }
        for host in ["127.0.0.2", "example.com", "localhost.example.com", "::2"] {
            assert!(!host_is_loopback(host), "expected non-loopback host: {host}");
        }
    }

    #[test]
    fn permitted_peer_denies_loopback_without_operator_opt_in() {
        let lo4: IpAddr = "127.0.0.1".parse().unwrap();
        let lo6: IpAddr = "::1".parse().unwrap();
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let public: IpAddr = "93.184.216.34".parse().unwrap();
        let private: IpAddr = "10.1.2.3".parse().unwrap();
        let metadata: IpAddr = "169.254.169.254".parse().unwrap();

        assert!(!permitted_peer(true, lo4, false));
        assert!(!permitted_peer(true, lo6, false));
        assert!(permitted_peer(true, lo4, true));
        assert!(permitted_peer(true, lo6, true));
        // A name that resolves to loopback stays blocked even when the literal
        // host was not classified as loopback.
        assert!(!permitted_peer(false, lo4, false));
        assert!(!permitted_peer(false, mapped, true));
        assert!(permitted_peer(false, public, true));
        assert!(!permitted_peer(false, private, true));
        assert!(!permitted_peer(false, metadata, true));
    }

    #[test]
    fn ssrf_url_matrix_distinguishes_default_deny_from_operator_opt_in() {
        for valid in ["https://ci.example.com/webhooks/rootyard", "https://hooks.example.org:8443/v1/events?env=prod"] {
            assert!(
                validate_webhook_url_with_policy(valid, false).is_ok(),
                "expected valid URL without loopback opt-in: {valid}"
            );
            assert!(
                validate_webhook_url_with_policy(valid, true).is_ok(),
                "expected valid URL with loopback opt-in: {valid}"
            );
        }

        for loopback in [
            "http://127.0.0.1:9000/hook",
            "http://[::1]:9001/callback",
            "http://localhost:8080/ci",
            "https://127.0.0.1/hook",
            "https://[::1]/hook",
            "https://localhost/hook",
            "https://ci.localhost/hook",
        ] {
            assert!(
                validate_webhook_url_with_policy(loopback, false).is_err(),
                "expected default loopback denial: {loopback}"
            );
            let parsed = validate_webhook_url_with_policy(loopback, true)
                .unwrap_or_else(|_| panic!("expected opt-in loopback acceptance: {loopback}"));
            assert!(parsed.is_loopback, "expected loopback classification: {loopback}");
        }

        // The opt-in is narrow: private, link-local, metadata and non-canonical
        // loopback literals stay rejected in both modes.
        for invalid in [
            "http://ci.example.com/webhooks",
            "http://127.0.0.2/hook",
            "https://127.0.0.2/hook",
            "https://0.0.0.0/hook",
            "https://10.0.0.1/hook",
            "https://172.16.0.1/hook",
            "https://192.168.1.1/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://[fe80::1]/hook",
            "https://[fc00::1]/hook",
            "https://user:pass@ci.example.com/hook",
            "https://ci.example.com/hook#frag",
            "https://metadata.google.internal/computeMetadata/v1/",
        ] {
            assert!(
                validate_webhook_url_with_policy(invalid, true).is_err(),
                "expected SSRF rejection with opt-in: {invalid}"
            );
            assert!(
                validate_webhook_url_with_policy(invalid, false).is_err(),
                "expected SSRF rejection by default: {invalid}"
            );
        }
    }

    #[test]
    fn process_policy_only_allows_loopback_after_explicit_opt_in() {
        let expected = parse_allow_loopback(std::env::var(ALLOW_LOOPBACK_ENV).ok().as_deref());
        assert_eq!(loopback_targets_allowed(), expected);
        if !expected {
            assert!(crate::webhooks::models::validate_webhook_url("http://127.0.0.1:9000/hook").is_err());
            assert!(crate::webhooks::models::validate_webhook_url("https://localhost/hook").is_err());
            assert!(crate::webhooks::models::validate_webhook_url("https://ci.example.com/hook").is_ok());
        }
    }
}
