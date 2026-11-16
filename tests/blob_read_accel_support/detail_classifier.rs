//! Private finite detail classifier for cached read-acceleration fallbacks.
//!
//! Only exact source-owned strings and anchored numeric templates are accepted.
//! The original detail text is never printed or retained: provider/stream kinds
//! and numeric relations are reduced to finite labels, with `unknown` otherwise.

use rootyard::blob_store::read_accel::{ReadAccelArtifactKind, ReadAccelFallbackReason, ReadAccelSidecarStatus};

pub(super) fn cached_fallback_detail_class(status: &ReadAccelSidecarStatus) -> &'static str {
    if let ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(ReadAccelFallbackReason::SidecarArtifactCorrupt {
        detail,
        ..
    }) = status
    {
        match detail.as_str() {
            "blob operation deadline exceeded" => "blob-deadline",
            "read-acceleration operation deadline exceeded" => "read-accel-deadline",
            "blob digest mismatch" => "blob-digest",
            "read-acceleration sidecar integrity failed: local sidecar SHA-256 or length mismatch" => {
                "local-digest-or-length"
            }
            "invalid bitmap header magic or length" => "bitmap-header",
            "blob provider error: blob readback task failed" => "readback-task",
            "blob provider error: blob destination directory failed" => "destination-directory",
            "blob provider error: blob staging file creation failed" => "staging-create",
            "blob provider error: blob staging write failed" => "staging-write",
            "blob provider error: blob staging fsync failed" => "staging-fsync",
            "blob provider error: blob destination rename failed" => "destination-rename",
            "blob provider error: blob destination fsync failed" => "destination-fsync",
            "blob resource limits conflict with the initialized process-wide context" => "resource-context-conflict",
            "blob locator already exists" => "blob-already-exists",
            other => classify_generated_detail(other),
        }
    } else {
        "none"
    }
}

fn classify_generated_detail(detail: &str) -> &'static str {
    if let Some(kind) = detail.strip_prefix("blob provider error: provider error kind ") {
        return provider_kind_class(kind);
    }
    if let Some(kind) = detail.strip_prefix("blob provider error: provider byte stream error kind ") {
        return stream_kind_class(kind);
    }
    if let Some(rest) = detail.strip_prefix("blob length mismatch: expected ") {
        return length_mismatch_class(rest);
    }
    if let Some(rest) = detail.strip_prefix("blob staging lease of ") {
        return staging_budget_class(rest);
    }
    "unknown"
}

macro_rules! finite_kind_class {
    ($name:ident, $list:ident, $prefix:literal; $($kind:literal),+ $(,)?) => {
        fn $name(kind: &str) -> &'static str {
            match kind {
                $($kind => concat!($prefix, $kind)),+,
                _ => "unknown",
            }
        }

        const $list: &[&str] = &[$($kind),+];
    };
}

// Exact `opendal-core 0.57.0` `ErrorKind` Display values.
finite_kind_class!(provider_kind_class, PROVIDER_KINDS, "provider-kind/";
    "Unexpected",
    "Unsupported",
    "ConfigInvalid",
    "NotFound",
    "PermissionDenied",
    "IsADirectory",
    "NotADirectory",
    "AlreadyExists",
    "RateLimited",
    "IsSameFile",
    "ConditionNotMatch",
    "RangeNotSatisfied",
);

// Explicit public stable `std::io::ErrorKind` Debug-name allowlist.
finite_kind_class!(stream_kind_class, STREAM_KINDS, "stream-kind/";
    "NotFound",
    "PermissionDenied",
    "ConnectionRefused",
    "ConnectionReset",
    "HostUnreachable",
    "NetworkUnreachable",
    "ConnectionAborted",
    "NotConnected",
    "AddrInUse",
    "AddrNotAvailable",
    "NetworkDown",
    "BrokenPipe",
    "AlreadyExists",
    "WouldBlock",
    "NotADirectory",
    "IsADirectory",
    "DirectoryNotEmpty",
    "ReadOnlyFilesystem",
    "FilesystemLoop",
    "StaleNetworkFileHandle",
    "InvalidInput",
    "InvalidData",
    "TimedOut",
    "WriteZero",
    "StorageFull",
    "NotSeekable",
    "QuotaExceeded",
    "FileTooLarge",
    "ResourceBusy",
    "ExecutableFileBusy",
    "Deadlock",
    "CrossesDevices",
    "TooManyLinks",
    "InvalidFilename",
    "ArgumentListTooLong",
    "Interrupted",
    "Unsupported",
    "UnexpectedEof",
    "OutOfMemory",
    "InProgress",
    "Other",
);

fn parse_canonical_u64(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
        return None;
    }
    let mut value = 0u64;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

fn length_mismatch_class(rest: &str) -> &'static str {
    let Some((expected_text, actual_text)) = rest.split_once(", got ") else {
        return "unknown";
    };
    let Some(expected) = parse_canonical_u64(expected_text) else {
        return "unknown";
    };
    let Some(actual) = parse_canonical_u64(actual_text) else {
        return "unknown";
    };
    match expected.cmp(&actual) {
        std::cmp::Ordering::Less => "blob-length-mismatch/expected-lt-actual",
        std::cmp::Ordering::Equal => "blob-length-mismatch/expected-eq-actual",
        std::cmp::Ordering::Greater => "blob-length-mismatch/expected-gt-actual",
    }
}

fn staging_budget_class(rest: &str) -> &'static str {
    let Some((requested_text, limit_text)) = rest.split_once(" bytes exceeds the process staging budget ") else {
        return "unknown";
    };
    let Some(requested) = parse_canonical_u64(requested_text) else {
        return "unknown";
    };
    let Some(limit) = parse_canonical_u64(limit_text) else {
        return "unknown";
    };
    if requested > limit { "blob-staging-budget" } else { "unknown" }
}

pub(super) fn assert_detail_classifier_contract() {
    assert_eq!(cached_fallback_detail_class(&ReadAccelSidecarStatus::Applied), "none");
    assert_eq!(cached_fallback_detail_class(&ReadAccelSidecarStatus::Disabled), "none");

    for (detail, expected) in [
        ("blob operation deadline exceeded", "blob-deadline"),
        ("read-acceleration operation deadline exceeded", "read-accel-deadline"),
        ("blob digest mismatch", "blob-digest"),
        (
            "read-acceleration sidecar integrity failed: local sidecar SHA-256 or length mismatch",
            "local-digest-or-length",
        ),
        ("invalid bitmap header magic or length", "bitmap-header"),
        ("blob provider error: blob readback task failed", "readback-task"),
        ("blob provider error: blob destination directory failed", "destination-directory"),
        ("blob provider error: blob staging file creation failed", "staging-create"),
        ("blob provider error: blob staging write failed", "staging-write"),
        ("blob provider error: blob staging fsync failed", "staging-fsync"),
        ("blob provider error: blob destination rename failed", "destination-rename"),
        ("blob provider error: blob destination fsync failed", "destination-fsync"),
        ("blob resource limits conflict with the initialized process-wide context", "resource-context-conflict"),
        ("blob locator already exists", "blob-already-exists"),
    ] {
        assert_eq!(detail_class(detail), expected);
    }

    for &kind in PROVIDER_KINDS {
        assert_eq!(
            detail_class(&format!("blob provider error: provider error kind {kind}")).to_owned(),
            format!("provider-kind/{kind}")
        );
        for tail in [" trailing", ": path=/tmp/secret", " SQL=select * from t", " credential=secret"] {
            assert_eq!(detail_class(&format!("blob provider error: provider error kind {kind}{tail}")), "unknown");
        }
    }

    for &kind in STREAM_KINDS {
        assert_eq!(
            detail_class(&format!("blob provider error: provider byte stream error kind {kind}")).to_owned(),
            format!("stream-kind/{kind}")
        );
        for tail in [" trailing", ": path=/tmp/secret", " SQL=select * from t", " credential=secret"] {
            assert_eq!(
                detail_class(&format!("blob provider error: provider byte stream error kind {kind}{tail}")),
                "unknown"
            );
        }
    }

    for (detail, expected) in [
        ("blob length mismatch: expected 1, got 2", "blob-length-mismatch/expected-lt-actual"),
        ("blob length mismatch: expected 2, got 2", "blob-length-mismatch/expected-eq-actual"),
        ("blob length mismatch: expected 3, got 2", "blob-length-mismatch/expected-gt-actual"),
        ("blob length mismatch: expected 0, got 18446744073709551615", "blob-length-mismatch/expected-lt-actual"),
        ("blob length mismatch: expected 18446744073709551615, got 0", "blob-length-mismatch/expected-gt-actual"),
    ] {
        assert_eq!(detail_class(detail), expected);
    }

    for detail in [
        "blob length mismatch: expected 01, got 2",
        "blob length mismatch: expected +1, got 2",
        "blob length mismatch: expected -1, got 2",
        "blob length mismatch: expected 1, got 02",
        "blob length mismatch: expected 1, got +2",
        "blob length mismatch: expected 1, got -2",
        "blob length mismatch: expected 1, got 2 ",
        "blob length mismatch: expected 1, got 2 trailing",
        "blob length mismatch: expected 1, got 2, got 3",
        "blob length mismatch: expected 1.0, got 2",
        "blob length mismatch: expected 0x1, got 2",
        "blob length mismatch: expected 18446744073709551616, got 2",
        "blob length mismatch: expected 1, got 18446744073709551616",
        "blob length mismatch: expected , got 2",
        "blob length mismatch: expected 1",
        "blob length mismatch: expected 1 got 2",
    ] {
        assert_eq!(detail_class(detail), "unknown");
    }

    assert_eq!(
        detail_class("blob staging lease of 2 bytes exceeds the process staging budget 1"),
        "blob-staging-budget"
    );
    assert_eq!(
        detail_class("blob staging lease of 18446744073709551615 bytes exceeds the process staging budget 0"),
        "blob-staging-budget"
    );

    for detail in [
        "blob staging lease of 01 bytes exceeds the process staging budget 1",
        "blob staging lease of 1 bytes exceeds the process staging budget 01",
        "blob staging lease of 1 bytes exceeds the process staging budget 1",
        "blob staging lease of 0 bytes exceeds the process staging budget 1",
        "blob staging lease of 18446744073709551616 bytes exceeds the process staging budget 1",
        "blob staging lease of 1 bytes exceeds the process staging budget 18446744073709551616",
        "blob staging lease of 1 bytes exceeds the process staging budget 0 trailing",
        "blob staging lease of 1 bytes exceeds the process staging budget 0 SQL=select",
        "blob staging lease of +1 bytes exceeds the process staging budget 0",
        "blob staging lease of 1.0 bytes exceeds the process staging budget 0",
    ] {
        assert_eq!(detail_class(detail), "unknown");
    }

    for detail in [
        "blob provider error: provider error kind",
        "blob provider error: provider byte stream error kind",
        "some arbitrary detail",
        "",
    ] {
        assert_eq!(detail_class(detail), "unknown");
    }
}

fn detail_class(detail: &str) -> &'static str {
    let status =
        ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(ReadAccelFallbackReason::SidecarArtifactCorrupt {
            kind: ReadAccelArtifactKind::Bitmap,
            detail: detail.to_owned(),
        });
    cached_fallback_detail_class(&status)
}
