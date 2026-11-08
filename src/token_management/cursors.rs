//! Typed keyset cursor codec for token and browser-session lists.
//!
//! The ordering key is PostgreSQL's `(created_at timestamptz, id uuid)` tuple.
//! A cursor stores the timestamp as exact signed UNIX microseconds and the id
//! as canonical UUID text, so decoding produces the native `SystemTime` and
//! `Uuid` values used directly as `$2::timestamptz` / `$3::uuid` parameters.
//! This avoids both lossy floating point and text parameters that would fail
//! PostgreSQL's parameter type check on a malformed client cursor.
//!
//! All client-facing decode failures are a fixed 400 `invalid pagination
//! cursor`; range checks use PostgreSQL's own timestamp bounds so an accepted
//! value can always be sent back through `SystemTime`'s `ToSql`.

use crate::{Error, pagination};
use axum::http::StatusCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_postgres::Row;
use uuid::Uuid;

/// PostgreSQL timestamp bounds as UNIX microseconds: 4713-11-24 00:00:00 UTC
/// (inclusive) through 294276-12-31 23:59:59.999999 UTC (exclusive). These are
/// the post-2000-offset bounds shifted by 946_684_800 seconds; they also fit
/// `i64`, so `SystemTime`'s `ToSql` cannot overflow for an accepted cursor.
const PG_MIN_UNIX_MICROS: i128 = -210_866_803_200_000_000;
const PG_MAX_UNIX_MICROS: i128 = 9_224_318_016_000_000_000;

fn bad_cursor() -> Error {
    Error(StatusCode::BAD_REQUEST, "invalid pagination cursor")
}

/// Exact UNIX microseconds, including pre-epoch instants. No float conversion
/// is involved, so microsecond precision and keyset ordering are preserved.
fn system_time_micros(at: SystemTime) -> i128 {
    let magnitude = |duration: Duration| i128::try_from(duration.as_micros()).unwrap_or(i128::MAX);
    match at.duration_since(UNIX_EPOCH) {
        Ok(duration) => magnitude(duration),
        Err(error) => -magnitude(error.duration()),
    }
}

/// Encode one already-validated keyset position. Kept separate from [`encode`]
/// so the codec can be unit-tested without constructing a database `Row`.
fn encode_position(scope: &str, created_at: SystemTime, id: Uuid) -> Result<String, Error> {
    let micros = system_time_micros(created_at);
    if !(PG_MIN_UNIX_MICROS..PG_MAX_UNIX_MICROS).contains(&micros) {
        // A database-returned `created_at` outside PostgreSQL's own range is an
        // internal invariant violation, never a client error.
        return Err(Error::internal("cursor timestamp outside PostgreSQL range"));
    }
    let micros = micros.to_string();
    let id = id.to_string();
    Ok(pagination::encode(scope, &[&micros, &id]))
}

/// Encode the row's `cursor_ts timestamptz` and canonical `id uuid`.
pub fn encode(scope: &str, row: &Row) -> Result<String, Error> {
    encode_position(scope, row.get("cursor_ts"), row.get("id"))
}

fn parse_timestamp(raw: &str) -> Result<SystemTime, Error> {
    let micros: i128 = raw.parse().map_err(|_| bad_cursor())?;
    if !(PG_MIN_UNIX_MICROS..PG_MAX_UNIX_MICROS).contains(&micros) {
        return Err(bad_cursor());
    }
    if micros >= 0 {
        let micros = u64::try_from(micros).map_err(|_| bad_cursor())?;
        UNIX_EPOCH.checked_add(Duration::from_micros(micros)).ok_or_else(bad_cursor)
    } else {
        let micros = u64::try_from(micros.unsigned_abs()).map_err(|_| bad_cursor())?;
        UNIX_EPOCH.checked_sub(Duration::from_micros(micros)).ok_or_else(bad_cursor)
    }
}

/// Decode a scoped cursor into the exact typed keyset parameters. `None` is the
/// first page and returns untyped absent bounds; every malformed field, foreign
/// scope or out-of-range instant is a deterministic 400.
pub fn decode(after: Option<&String>, scope: &str) -> Result<(Option<SystemTime>, Option<Uuid>), Error> {
    match after {
        Some(raw) => {
            let fields = pagination::decode(raw, scope, 2)?;
            let timestamp = parse_timestamp(&fields[0])?;
            let id = Uuid::parse_str(&fields[1]).map_err(|_| bad_cursor())?;
            Ok((Some(timestamp), Some(id)))
        }
        None => Ok((None, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_bad(cursor: &str, scope: &str) {
        match decode(Some(&cursor.to_owned()), scope) {
            Err(Error(status, message)) => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(message, "invalid pagination cursor");
            }
            Ok(value) => panic!("expected invalid cursor, got {value:?}"),
        }
    }

    #[test]
    fn round_trips_signed_microseconds_and_uses_uuid_as_stable_tiebreak() {
        let scope = "tokens:api:11111111-2222-3333-4444-555555555555";
        let first = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let second = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        for micros in [-2_000_000i64, -1, 0, 1, 999_999, 1_000_001, 1_700_000_000_123_456] {
            let at = if micros < 0 {
                UNIX_EPOCH - Duration::from_micros(micros.unsigned_abs())
            } else {
                UNIX_EPOCH + Duration::from_micros(micros as u64)
            };
            let cursor = encode_position(scope, at, first).unwrap();
            assert_eq!(decode(Some(&cursor), scope).unwrap(), (Some(at), Some(first)));
        }
        let at = UNIX_EPOCH + Duration::from_micros(1_700_000_000_123_456);
        let a = encode_position(scope, at, first).unwrap();
        let b = encode_position(scope, at, second).unwrap();
        let (ts_a, id_a) = decode(Some(&a), scope).unwrap();
        let (ts_b, id_b) = decode(Some(&b), scope).unwrap();
        assert_eq!((ts_a, id_a), (Some(at), Some(first)));
        assert_eq!((ts_b, id_b), (Some(at), Some(second)));
        assert!((ts_a.unwrap(), id_a.unwrap()) < (ts_b.unwrap(), id_b.unwrap()));
        assert_eq!(pagination::decode(&a, scope, 2).unwrap()[0], "1700000000123456");
    }

    #[test]
    fn rejects_invalid_typed_timestamp_uuid_and_out_of_range_values_as_400() {
        let scope = "tokens:api:11111111-2222-3333-4444-555555555555";
        let id = "00000000-0000-0000-0000-000000000001";
        for timestamp in [
            "",
            " ",
            "1.5",
            "1e6",
            "abc",
            "1700000000123456x",
            "-210866803200000001",
            "9224318016000000000",
            "999999999999999999999999999999999999999999",
        ] {
            assert_bad(&pagination::encode(scope, &[timestamp, id]), scope);
        }
        for bad_id in ["", "not-a-uuid", "00000000-0000-0000-0000-00000000000"] {
            assert_bad(&pagination::encode(scope, &["1700000000123456", bad_id]), scope);
        }
        assert_bad("not-a-cursor", scope);
    }

    #[test]
    fn rejects_foreign_actor_kind_and_malformed_scopes_as_400() {
        let at = UNIX_EPOCH + Duration::from_micros(42);
        let cursor = encode_position("tokens:api:alice", at, Uuid::nil()).unwrap();
        assert_eq!(decode(Some(&cursor), "tokens:api:alice").unwrap(), (Some(at), Some(Uuid::nil())));
        assert_bad(&cursor, "tokens:api:bob");
        assert_bad(&cursor, "sessions:alice");
        assert_bad(&cursor, "tokens:api:alice:extra");
    }
}
