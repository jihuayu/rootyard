use super::*;

#[test]
fn event_context_and_secret_validators() {
    assert_eq!(validate_secret("whsec_valid_secret_12345").unwrap().len(), 64);
    assert!(validate_secret("short").is_err());
    assert_eq!(
        validate_events(&["push".into(), "pull_request".into(), "push".into()]).unwrap(),
        vec!["push".to_string(), "pull_request".to_string()]
    );
    assert_eq!(validate_events(&["*".into()]).unwrap(), vec!["push", "pull_request", "check_run"]);
    assert_eq!(
        validate_ci_contexts(&["ci/build".into(), "ci/test".into(), "ci/build".into()]).unwrap(),
        vec!["ci/build".to_string(), "ci/test".to_string()]
    );
}

#[test]
fn loopback_is_denied_unless_the_caller_passes_the_explicit_opt_in() {
    assert!(validate_webhook_url_with_policy("http://127.0.0.1:9000/hook", false).is_err());
    assert!(validate_webhook_url_with_policy("https://localhost/hook", false).is_err());
    assert!(validate_webhook_url_with_policy("http://127.0.0.1:9000/hook", true).is_ok());
    assert!(validate_webhook_url_with_policy("https://ci.example.com/hook", false).is_ok());
}
