//! Typed remote object error regression tests.
use super::*;

#[test]
fn status_error_keeps_fixed_op_and_bounded_status() {
    let error = RemoteStoreError::http(RemoteOp::Get, 502);
    assert_eq!(error.op(), RemoteOp::Get);
    assert_eq!(error.http_status(), Some(502));
    let display = error.to_string();
    assert!(display.contains("get") && display.contains("502"));
    assert!(!display.contains("http://") && !display.contains("://"));
    assert!(!display.contains("Authorization"));
}

#[test]
fn timeout_and_transport_never_expose_a_status_or_url() {
    let timeout = RemoteStoreError::timeout(RemoteOp::Put);
    assert_eq!(timeout.http_status(), None);
    assert!(!timeout.to_string().contains("://"));
    assert!(!format!("{timeout:?}").contains("://"));
    let client = Client::new();
    let transport = client.request(Method::GET, "http://[").build().unwrap_err();
    let error = RemoteStoreError::transport(RemoteOp::Head, Box::new(transport));
    assert_eq!(error.http_status(), None);
    assert_eq!(error.op().as_str(), "head");
    assert!(!error.to_string().contains("://"));
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn generic_boxed_transport_source_survives_without_a_reqwest_type() {
    let error = RemoteStoreError::transport(RemoteOp::Put, Box::new(std::io::Error::other("opaque transport failure")));
    assert_eq!(error.http_status(), None);
    assert_eq!(error.op(), RemoteOp::Put);
    assert!(std::error::Error::source(&error).is_some());
    let rendered = format!("{error} {error:?}");
    assert!(rendered.contains("transport failed"));
    assert!(!rendered.contains("opaque transport failure"));
}

#[tokio::test]
async fn body_boundary_exhaustion_maps_to_typed_remote_timeout() {
    let mut empty = futures_util::stream::iter(Vec::<reqwest::Result<bytes::Bytes>>::new());
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    assert!(remote_chunk(&mut empty, RemoteOp::Get, ready_deadline).await.unwrap().is_none());

    let mut pending = futures_util::stream::pending::<reqwest::Result<bytes::Bytes>>();
    let error = remote_chunk(&mut pending, RemoteOp::MultipartPart, Instant::now()).await.unwrap_err();
    let typed = error.downcast_ref::<RemoteStoreError>().expect("typed remote body timeout");
    assert_eq!(typed.op(), RemoteOp::MultipartPart);
    assert_eq!(typed.http_status(), None);
    let display = typed.to_string();
    assert!(display.contains("timed out") && display.contains("multipart_part"));
    assert!(!display.contains("://") && !display.contains("Authorization"));
}

#[test]
fn operation_labels_are_a_fixed_enumeration() {
    let labels = [
        RemoteOp::Get,
        RemoteOp::Head,
        RemoteOp::Put,
        RemoteOp::Delete,
        RemoteOp::MultipartInitiate,
        RemoteOp::MultipartPart,
        RemoteOp::MultipartComplete,
        RemoteOp::MultipartAbort,
    ]
    .map(RemoteOp::as_str);
    assert_eq!(
        labels,
        [
            "get",
            "head",
            "put",
            "delete",
            "multipart_initiate",
            "multipart_part",
            "multipart_complete",
            "multipart_abort",
        ]
    );
}
