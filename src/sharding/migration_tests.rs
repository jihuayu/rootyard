//! Unit tests for the bounded peer receipt reader.

use super::migration_transport::collect_bounded;
use bytes::Bytes;

fn chunks(parts: &[&'static [u8]]) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Unpin {
    futures_util::stream::iter(parts.iter().map(|part| Ok(Bytes::from_static(part))).collect::<Vec<_>>())
}

#[tokio::test]
async fn receipt_reader_accepts_unknown_length_within_cap() {
    let body = collect_bounded(chunks(&[br#"{"error":"x","#, br#""#]), 64).await.unwrap();
    assert_eq!(body, br#"{"error":"x","#);
    let exact = collect_bounded(chunks(&[b"1234", b"5678"]), 8).await.unwrap();
    assert_eq!(exact, b"12345678");
}

#[tokio::test]
async fn receipt_reader_rejects_chunked_overflow_before_appending_it() {
    let error = collect_bounded(chunks(&[b"1234", b"56789"]), 8).await.unwrap_err();
    assert_eq!(error.1, "replica receipt too large");
}

#[tokio::test]
async fn receipt_reader_rejects_oversized_single_chunk() {
    let error = collect_bounded(chunks(&[b"0123456789"]), 4).await.unwrap_err();
    assert_eq!(error.1, "replica receipt too large");
}
