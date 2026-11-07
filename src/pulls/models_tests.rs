
use super::*;
use axum::extract::Query;

#[test]
fn pull_filter_query_contract() {
    for (query, expected) in [
        ("", None),
        ("?state=open", Some("open")),
        ("?state=closed&after=4&limit=2", Some("closed")),
        ("?state=merged&limit=10", Some("merged")),
    ] {
        let uri = format!("/pulls{query}").parse().unwrap();
        let Query(page) = Query::<PullPage>::try_from_uri(&uri).unwrap();
        assert_eq!(page.state.as_ref().map(PullStateFilter::as_str), expected);
        assert!(page.bounds().is_ok());
    }
    for query in ["?state=", "?state=all", "?state=Open", "?state=open&state=closed", "?state=open&unknown=1"] {
        let uri = format!("/pulls{query}").parse().unwrap();
        assert!(Query::<PullPage>::try_from_uri(&uri).is_err());
    }
    for query in ["?state=open&after=-1", "?state=closed&limit=0", "?state=merged&limit=101"] {
        let uri = format!("/pulls{query}").parse().unwrap();
        let Query(page) = Query::<PullPage>::try_from_uri(&uri).unwrap();
        assert!(page.bounds().is_err());
    }
}

#[test]
fn branch_ref_normalization_and_validation() {
    assert_eq!(normalize_branch_ref("main").unwrap(), "refs/heads/main");
    assert_eq!(normalize_branch_ref("refs/heads/feature/x").unwrap(), "refs/heads/feature/x");
    for bad in [
        "",
        "HEAD",
        "refs/heads/HEAD",
        "refs/tags/v1",
        "refs/rootyard-ci/jobs/1",
        "refs/heads/",
        "refs/heads/.hidden",
        "refs/heads/foo..bar",
        "refs/heads/foo.lock",
        "refs/heads/foo/",
        "refs/heads/foo@{1}",
        "refs/heads/foo bar",
    ] {
        assert!(normalize_branch_ref(bad).is_err(), "expected error for {bad}");
    }
}

#[test]
fn oid_and_check_state_validators() {
    assert!(valid_oid("0123456789abcdef0123456789abcdef01234567"));
    for bad_oid in [
        "",
        ZERO_OID,
        "0123456789ABCDEF0123456789abcdef01234567",
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef0123456g",
    ] {
        assert!(!valid_oid(bad_oid));
    }
    let sha1 = "a".repeat(40);
    let sha256 = "b".repeat(64);
    assert!(valid_oid_for_format(&sha1, "sha1"));
    assert!(!valid_oid_for_format(&sha1, "sha256"));
    assert!(valid_oid_for_format(&sha256, "sha256"));
    assert!(!valid_oid_for_format(&sha256, "sha1"));
    assert!(!valid_oid_for_format(&sha1, "sha512"));
    assert_eq!(zero_oid("sha1").as_deref(), Some(ZERO_OID));
    assert_eq!(zero_oid("sha256").as_deref(), Some(ZERO_OID_SHA256));
    assert!(zero_oid("sha512").is_none());
    assert!(valid_check_status_and_conclusion("queued", None));
    assert!(valid_check_status_and_conclusion("in_progress", None));
    assert!(!valid_check_status_and_conclusion("queued", Some("success")));
    assert!(!valid_check_status_and_conclusion("completed", None));
    assert!(valid_check_status_and_conclusion("completed", Some("success")));
    assert!(valid_check_status_and_conclusion("completed", Some("failure")));
    assert!(!valid_check_status_and_conclusion("completed", Some("unknown")));
}
