//! Immutable stored object and standard byte-range replies for the loopback S3 fixture.

use axum::body::Body;
use axum::http::header;
use axum::response::Response;
use bytes::Bytes;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct StoredObject {
    pub(crate) bytes: Bytes,
    pub(crate) etag: String,
}

impl StoredObject {
    pub(crate) fn new(bytes: Bytes) -> Self {
        let etag = format!("\"{}\"", &hex::encode(Sha256::digest(&bytes))[..32]);
        Self { bytes, etag }
    }
}

pub(crate) fn range_reply(object: &StoredObject, raw: &str) -> Response {
    let Some((start, end)) = parse_byte_range(raw, object.bytes.len()) else {
        return Response::builder()
            .status(416u16)
            .header(header::CONNECTION, "close")
            .header(header::CONTENT_RANGE, format!("bytes */{}", object.bytes.len()))
            .body(Body::empty())
            .unwrap();
    };
    Response::builder()
        .status(206u16)
        .header(header::CONNECTION, "close")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::ETAG, object.etag.clone())
        .header(header::CONTENT_LENGTH, end - start + 1)
        .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{}", object.bytes.len()))
        .body(Body::from(object.bytes.slice(start..=end)))
        .unwrap()
}

fn parse_byte_range(raw: &str, total: usize) -> Option<(usize, usize)> {
    let spec = raw.strip_prefix("bytes=")?;
    let spec = (total > 0 && !spec.contains(',')).then_some(spec)?;
    let (start, end) = spec.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<usize>().ok()?;
        return (suffix > 0).then_some((total.saturating_sub(suffix), total - 1));
    }
    let start = start.parse::<usize>().ok().filter(|start| *start < total)?;
    let end = if end.is_empty() { total - 1 } else { end.parse::<usize>().ok()?.min(total - 1) };
    (start <= end).then_some((start, end))
}
