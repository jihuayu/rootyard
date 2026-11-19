use super::*;

#[test]
fn validate_mirror_url_rejects_origin_spoof_and_paths() {
    assert_eq!(validate_mirror_url("origin").unwrap_err().0, StatusCode::BAD_REQUEST);
    assert_eq!(validate_mirror_url("ORIGIN").unwrap_err().0, StatusCode::BAD_REQUEST);
    assert_eq!(validate_mirror_url("https://mirror.example/sub").unwrap_err().0, StatusCode::BAD_REQUEST);
    assert_eq!(validate_mirror_url("http://mirror.example").unwrap_err().0, StatusCode::BAD_REQUEST);
    assert_eq!(validate_mirror_url("https://mirror.example").unwrap(), "https://mirror.example");
    assert_eq!(validate_mirror_url("http://127.0.0.1:8080/").unwrap(), "http://127.0.0.1:8080");
}

#[test]
fn prewarm_allowlist_filters_invalid_and_rejects_source_token_reuse() {
    let origins = parse_prewarm_origins(
        "https://mirror1.example/, http://169.254.169.254, origin, https://mirror2.example:8443/sub, http://127.0.0.1:18101/",
    );
    assert_eq!(origins, BTreeSet::from(["http://127.0.0.1:18101".to_owned(), "https://mirror1.example".to_owned()]));
    assert_eq!(validate_prewarm_token(Some("ryt_same"), Some("ryt_same")), None);
    assert_eq!(validate_prewarm_token(None, Some("ryt_source_secret")), None);
    assert_eq!(
        validate_prewarm_token(Some("ryt_prewarm_scoped"), Some("ryt_source_secret")).as_deref(),
        Some("ryt_prewarm_scoped")
    );
}
