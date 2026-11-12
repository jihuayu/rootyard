use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use futures_util::TryStreamExt;
use opendal::Operator;
use opendal::layers::{HttpClientLayer, RetryLayer};
use opendal::services::S3;

use super::*;

fn classify(error: opendal::Error) -> RemoteStoreError {
    RemoteFailure::classify(error, RemoteOp::Put).into_error()
}

fn classify_failure(error: opendal::Error) -> RemoteFailure {
    RemoteFailure::classify(error, RemoteOp::Put)
}

fn upstream_parse(status: u16, body: &str) -> opendal::Error {
    let mut response = Response::new(Buffer::from(body.as_bytes().to_vec()));
    *response.status_mut() = axum::http::StatusCode::from_u16(status).expect("test status");
    parsed_http_failure(parse_error_response(response), status, RemoteOp::Get)
}

#[test]
fn no_such_bucket_404_is_config_invalid() {
    let failure = classify_failure(upstream_parse(
        404,
        r#"<Error><Code>NoSuchBucket</Code><Message>no such bucket</Message><Resource>/private/bucket</Resource><RequestId>x</RequestId></Error>"#,
    ));
    assert_eq!(failure.kind, ErrorKind::ConfigInvalid);
    assert!(!failure.is_not_found());
    let error = failure.into_error();
    assert_eq!(error.http_status(), Some(404));
    assert_eq!(error.op(), RemoteOp::Get);
}

#[test]
fn request_timeout_400_stays_retryable() {
    let failure = classify_failure(upstream_parse(
        400,
        r#"<Error><Code>RequestTimeout</Code><Message>request timed out</Message></Error>"#,
    ));
    assert_eq!(failure.kind, ErrorKind::Unexpected);
    assert!(!failure.is_conflict());
    let error = failure.into_error();
    assert_eq!(error.http_status(), Some(400));
}

#[test]
fn operation_aborted_409_is_unexpected_not_conditional() {
    let failure = classify_failure(upstream_parse(
        409,
        r#"<Error><Code>OperationAborted</Code><Message>conflicting operation</Message></Error>"#,
    ));
    assert_eq!(failure.kind, ErrorKind::Unexpected);
    assert!(!failure.is_conflict());
    let error = failure.into_error();
    assert_eq!(error.http_status(), Some(409));
}

#[test]
fn normal_412_remains_permanent_condition_not_match() {
    let failure = classify_failure(upstream_parse(
        412,
        r#"<Error><Code>PreconditionFailed</Code><Message>precondition failed</Message></Error>"#,
    ));
    assert_eq!(failure.kind, ErrorKind::ConditionNotMatch);
    assert!(failure.is_conflict());
    let error = failure.into_error();
    assert_eq!(error.http_status(), Some(412));
}

#[test]
fn exact_failed_response_keeps_status_and_request_stage() {
    let part = classify(upstream_parse(503, "<Error><Code>InternalError</Code></Error>"));
    assert_eq!(part.http_status(), Some(503));
    assert_eq!(part.op(), RemoteOp::Get);
}

#[tokio::test]
async fn oversized_and_unreadable_error_bodies_preserve_status_defaults() {
    let oversized = HttpBody::new(
        futures_util::stream::iter([
            Ok(Buffer::from(vec![b'x'; MAX_ERROR_BODY_BYTES])),
            Ok(Buffer::from(vec![b'y'; 1])),
        ]),
        None,
    );
    assert!(collect_error_body(oversized).await.is_none());
    let unreadable = HttpBody::new(
        futures_util::stream::iter([Err(opendal::Error::new(ErrorKind::Unexpected, "private provider body error"))]),
        None,
    );
    assert!(collect_error_body(unreadable).await.is_none());
    let retry = unparsed_http_failure(503, RemoteOp::MultipartComplete);
    assert!(retry.is_temporary());
    let typed = classify(retry);
    assert_eq!(typed.http_status(), Some(503));
    assert_eq!(typed.op(), RemoteOp::MultipartComplete);
    let conflict = classify_failure(unparsed_http_failure(412, RemoteOp::MultipartComplete));
    assert!(conflict.is_conflict());
    assert_eq!(conflict.into_error().http_status(), Some(412));
    let missing = classify_failure(unparsed_http_failure(404, RemoteOp::Get));
    assert!(missing.is_not_found());
}

#[test]
fn transport_marker_is_finite_and_carries_the_exact_request_stage() {
    let error = network_failure(
        opendal::Error::new(ErrorKind::Unexpected, "connection reset at https://example.invalid/private")
            .with_context("url", "https://user:secret@example.invalid/private/object?token=secret"),
        RemoteOp::MultipartPart,
    );
    let failure = classify_failure(error);
    assert_eq!(failure.kind, ErrorKind::Unexpected);
    let typed = failure.into_error();
    assert_eq!(typed.http_status(), None);
    assert_eq!(typed.op(), RemoteOp::MultipartPart);
    let display = typed.to_string();
    let debug = format!("{typed:?}");
    assert!(display.contains("transport failed"));
    for rendered in [display, debug] {
        assert!(!rendered.contains("://"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("/private"));
        assert!(!rendered.contains("token"));
    }
}

#[test]
fn a_prior_503_is_not_reused_for_a_later_transport_failure() {
    let stale = classify(upstream_parse(503, "<Error><Code>InternalError</Code></Error>"));
    assert_eq!(stale.http_status(), Some(503));

    let transport = network_failure(opendal::Error::new(ErrorKind::Unexpected, "connection reset"), RemoteOp::Put);
    let later = classify(transport);
    assert_eq!(later.http_status(), None);
    assert_eq!(later.op(), RemoteOp::Put);
    assert!(later.to_string().contains("transport failed"));
}

#[test]
fn a_prior_503_is_not_reused_for_a_200_embedded_provider_error() {
    let stale = classify(upstream_parse(503, "<Error><Code>InternalError</Code></Error>"));
    assert_eq!(stale.http_status(), Some(503));

    // The SDK parsed an error document carried by HTTP 200: no source and
    // no numeric response status are available.
    let embedded = classify(opendal::Error::new(ErrorKind::Unexpected, "provider error document"));
    assert_eq!(embedded.http_status(), None);
    assert!(embedded.to_string().contains("provider kind other"));
}

#[test]
fn concurrent_requests_keep_their_own_status_and_stage() {
    let complete = classify(upstream_parse(429, "<Error><Code>SlowDown</Code></Error>"));
    let part = classify(upstream_parse(403, "<Error><Code>AccessDenied</Code></Error>"));
    assert_eq!((complete.http_status(), complete.op()), (Some(429), RemoteOp::Get));
    assert_eq!((part.http_status(), part.op()), (Some(403), RemoteOp::Get));
}

#[test]
fn initial_body_get_failure_keeps_the_exact_http_tag() {
    let error = std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        upstream_parse(503, "<Error><Code>InternalError</Code></Error>"),
    );
    let typed = classify_io_error(RemoteOp::Get, error);
    assert_eq!(typed.http_status(), Some(503));
    assert_eq!(typed.op(), RemoteOp::Get);
}

#[test]
fn mid_body_failure_after_200_has_no_http_status_and_no_unsafe_source() {
    let inner = opendal::Error::new(ErrorKind::Unexpected, "read body")
        .set_source(std::io::Error::other("connection reset at https://example.invalid/private"));
    let error = std::io::Error::new(std::io::ErrorKind::Interrupted, inner);
    let typed = classify_io_error(RemoteOp::Get, error);
    assert_eq!(typed.http_status(), None);
    assert!(typed.to_string().contains("provider kind stream"));
    assert!(!typed.to_string().contains("://"));
    assert!(!format!("{typed:?}").contains("://"));
}

#[tokio::test]
async fn non_retrying_2xx_body_strips_temporary_flag_and_url_on_truncation_and_stream_error() {
    let mut truncated = non_retrying_success_body(HttpBody::new(
        futures_util::stream::iter([Ok(Buffer::from(b"partial-chunk".to_vec()))]),
        Some(64),
    ));
    let first = truncated.read().await.expect("initial body chunk");
    assert_eq!(first.to_bytes().as_ref(), b"partial-chunk");
    let eof_error = truncated.read().await.expect_err("short Content-Length must fail at EOF");
    assert!(!eof_error.is_temporary(), "post-200 truncation must not be temporary");
    assert!(eof_error.is_persistent());
    let classified = classify_io_error(RemoteOp::Get, std::io::Error::other(eof_error));
    assert_eq!(classified.http_status(), None);
    assert_eq!(classified.op(), RemoteOp::Get);
    assert!(classified.to_string().contains("provider kind stream"));

    let mut broken = non_retrying_success_body(HttpBody::new(
        futures_util::stream::iter([Err(opendal::Error::new(
            ErrorKind::Unexpected,
            "read data from https://user:secret@example.invalid/private/key?token=secret",
        )
        .with_context("url", "https://user:secret@example.invalid/private/key?token=secret")
        .set_temporary())]),
        Some(64),
    ));
    let stream_error = broken.read().await.expect_err("broken body chunk must fail");
    assert!(!stream_error.is_temporary(), "post-200 chunk error must not be temporary");
    assert!(stream_error.is_persistent());
    for rendered in [stream_error.to_string(), format!("{stream_error:?}")] {
        assert!(!rendered.contains("://"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("/private/key"));
        assert!(!rendered.contains("token"));
    }
}

#[derive(Clone)]
enum ScriptedMode {
    PreBody502,
    Truncated200,
}

#[derive(Clone)]
struct ScriptedFetch {
    gets: Arc<AtomicUsize>,
    mode: ScriptedMode,
}

impl HttpFetch for ScriptedFetch {
    async fn fetch(&self, request: Request<Buffer>) -> SdkResult<Response<HttpBody>> {
        assert_eq!(request.method(), Method::GET);
        self.gets.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            ScriptedMode::PreBody502 => Ok(Response::builder()
                .status(502)
                .body(HttpBody::new(
                    futures_util::stream::iter([Ok(Buffer::from(
                        b"<Error><Code>InternalError</Code></Error>".to_vec(),
                    ))]),
                    None,
                ))
                .expect("test 502 response")),
            ScriptedMode::Truncated200 => Ok(Response::builder()
                .status(200)
                .header("content-length", "64")
                .body(HttpBody::new(futures_util::stream::iter([Ok(Buffer::from(vec![b'a'; 16]))]), Some(64)))
                .expect("test 200 response")),
        }
    }
}

fn scripted_operator(fetch: ScriptedFetch) -> Operator {
    crate::blob_store::opendal::ensure_crypto_provider();
    let builder = S3::default()
        .bucket("unit-bucket")
        .region("garage")
        .endpoint("http://127.0.0.1:9")
        .disable_config_load()
        .disable_ec2_metadata()
        .access_key_id("test-key")
        .secret_access_key("test-secret");
    let client = HttpClient::with(StatusAttributingFetch { inner: HttpClient::with(fetch) });
    Operator::new(builder)
        .expect("s3 operator builder")
        .finish()
        .layer(HttpClientLayer::new(client))
        .layer(RetryLayer::new().with_max_times(2))
}

#[tokio::test]
async fn retry_layer_retries_pre_body_502_but_never_restarts_truncated_200_stream() {
    let pre_body_gets = Arc::new(AtomicUsize::new(0));
    let op_502 = scripted_operator(ScriptedFetch { gets: pre_body_gets.clone(), mode: ScriptedMode::PreBody502 });
    let reader = op_502.reader("obj").await.expect("lazy reader handle");
    let err_502 = match observe(RemoteOp::Get, reader.into_bytes_stream(..)).await {
        Ok(mut stream) => match observe_body_poll(RemoteOp::Get, stream.try_next()).await {
            Err(BlobError::Remote(remote)) => remote,
            other => panic!("expected remote 502 error, got {other:?}"),
        },
        Err(failure) => failure.into_error(),
    };
    assert_eq!(pre_body_gets.load(Ordering::SeqCst), 3, "pre-body 502 must retry 1 + 2 times");
    assert_eq!(err_502.http_status(), Some(502));
    assert_eq!(err_502.op(), RemoteOp::Get);

    let truncated_gets = Arc::new(AtomicUsize::new(0));
    let op_200 = scripted_operator(ScriptedFetch { gets: truncated_gets.clone(), mode: ScriptedMode::Truncated200 });
    let reader = op_200.reader("obj").await.expect("lazy reader handle");
    let mut stream = observe(RemoteOp::Get, reader.into_bytes_stream(..)).await.ok().expect("200 head stream");
    let first = observe_body_poll(RemoteOp::Get, stream.try_next())
        .await
        .expect("first partial chunk")
        .expect("non-empty chunk");
    assert_eq!(first.len(), 16);
    let err_truncated = match observe_body_poll(RemoteOp::Get, stream.try_next()).await {
        Err(BlobError::Remote(remote)) => remote,
        other => panic!("expected post-200 stream error, got {other:?}"),
    };
    assert_eq!(
        truncated_gets.load(Ordering::SeqCst),
        1,
        "a body-boundary truncation after 200 OK must never issue a second ranged GET"
    );
    assert_eq!(err_truncated.http_status(), None);
    assert_eq!(err_truncated.op(), RemoteOp::Get);
    assert!(err_truncated.to_string().contains("provider kind stream"));
}

#[test]
fn dropped_sdk_source_uses_a_bounded_unknown_kind() {
    let typed = classify(opendal::Error::new(ErrorKind::Unexpected, "no source"));
    assert_eq!(typed.http_status(), None);
    assert!(typed.to_string().contains("provider kind other"));
}

#[test]
fn request_stage_uses_method_and_fixed_query_keys_only() {
    let uri = |raw: &'static str| raw.parse::<Uri>().expect("test uri");
    assert_eq!(request_stage(&Method::GET, &uri("https://example.invalid/secret/path")), RemoteOp::Get);
    assert_eq!(request_stage(&Method::HEAD, &uri("https://example.invalid/secret/path")), RemoteOp::Head);
    assert_eq!(request_stage(&Method::DELETE, &uri("https://example.invalid/secret/path")), RemoteOp::Delete);
    assert_eq!(
        request_stage(&Method::DELETE, &uri("https://example.invalid/secret/path?uploadId=private-value")),
        RemoteOp::MultipartAbort
    );
    assert_eq!(
        request_stage(&Method::POST, &uri("https://example.invalid/secret/path?uploads")),
        RemoteOp::MultipartInitiate
    );
    assert_eq!(
        request_stage(&Method::POST, &uri("https://example.invalid/secret/path?uploadId=private-value")),
        RemoteOp::MultipartComplete
    );
    assert_eq!(
        request_stage(&Method::PUT, &uri("https://example.invalid/secret/path?partNumber=1&uploadId=private-value")),
        RemoteOp::MultipartPart
    );
    assert_eq!(request_stage(&Method::PUT, &uri("https://example.invalid/secret/path")), RemoteOp::Put);
}

#[test]
fn safe_diagnostics_never_format_a_source_url_or_path() {
    let source = opendal::Error::new(ErrorKind::Unexpected, "request failed")
        .with_context("url", "https://user:secret@example.invalid/private/object?token=secret")
        .set_source(std::io::Error::other("connection reset at https://example.invalid/private/object"));
    let typed = classify(source);
    let display = typed.to_string();
    let debug = format!("{typed:?}");
    for rendered in [display, debug] {
        assert!(!rendered.contains("://"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("/private/object"));
        assert!(!rendered.contains("token"));
    }
}
