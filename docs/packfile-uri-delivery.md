# Optional `packfile-uris` Offload & Safe Inline Fallback Delivery

Refs #185

## Overview

`src/browse/packfile_uri.rs` (and submodules under `src/browse/packfile_uri/`) implements optional Git Protocol v2 `packfile-uris` offload paired with deterministic inline fallback inside `rootyard::browse::packfile_uri`.

When enabled for a tenant/repository and advertised in `fetch` capabilities (`shallow filter wait-for-done packfile-uris`), clients advertising `packfile-uris https` receive short-lived HMAC-SHA256 signed `https://` descriptors referencing immutable pre-materialized `.pack` objects (`40`-hex SHA-1 or `64`-hex SHA-256 pack trailer hash) plus only the small residual inline delta closure over the multiplexed `packfile` band.

## Architecture & Security Invariants

1. **Opt-in Protocol v2 Negotiation (`protocol_v2.rs`)**
   - Server capability `packfile-uris` is emitted only when policy enables and advertises offload.
   - `parse_fetch_v2_request` strictly validates Git Protocol v2 `command=fetch` pkt-lines (`0001` delim / `0000` flush), enforces `object-format` matching (`sha1`/`sha256`), and rejects duplicate `packfile-uris` lines.
   - Only `https` offload URIs are emitted; HTTP-only client requests (`packfile-uris http`) deterministically select full inline fallback.
2. **SSRF, Host Allowlist & Query Tampering Guard (`ssrf_guard.rs`)**
   - `validate_policy_config` and `validate_offload_uri` enforce HTTPS-only scheme, explicit lowercase multi-label DNS host allowlist (`allowed_hosts`), default port (`443` / omitted), clean traversal-free paths inside `path_prefix`, and no userinfo (`@`), backslashes, fragments, IP literals, or internal suffixes (`.local`, `.internal`, `.localhost`, `metadata.google.internal`).
   - Resolved peer IPs are checked via `crate::webhooks::policy::permitted_peer(..., false)` so loopback (`127.0.0.0/8`, `::1`), link-local metadata (`169.254.169.254`, `fe80::/10`), RFC1918, ULA (`fc00::/7`), and IPv4-mapped private addresses fail closed.
   - HTTP redirects are refused (`redirect::Policy::none()`) rather than blindly followed.
   - `redact_uri_for_log` strips signed query parameters before logging or returning error strings.
3. **Short-lived Signing & Mandatory Live Authorization (`signing.rs`)**
   - `PackUriKeyring` binds each download URL via domain-separated HMAC-SHA256 (`rootyard-packfile-uri-v1`) across `(tenant_id, repository_id, pack_oid, object_format, "https", allowed_host, 443, canonical_path, expires_at_unix, key_id, scope_nonce, pin_id)` using zeroizing `SigningKeyMaterial` and supports key rotation (`retire_for_signing`) plus instant revocation (`revoke_key`).
   - Query parsing rejects duplicate query keys and unknown parameters (`#[serde(deny_unknown_fields)]`).
   - `verify_signed_download_request` always calls `LivePackReadAuthorizer::authorize_pack_download` before streaming bytes; a signed URL or cache hit never substitutes for live authorization.
4. **Active Retention Pins & Compaction Safety (`retention.rs`)**
   - `PackDeliveryLeaseRegistry` wraps Issue #163 `DurablePinRegistry` (`DurablePinHold`) across the offload lease lifetime `[now .. expires_at + retention_grace_secs]` and increments `inflight_downloads` via `InflightDownloadGuard`.
   - `can_sweep_pack` returns `false` while any active lease, grace window, guard ref, or live download remains active so concurrent GC, compaction, or history switches never drop needed packs mid-fetch.
   - Pin revocation invalidates streaming mid-chunk (`is_hold_still_valid`) and fails HTTP fetches closed (`410 Gone`).
5. **Deterministic Inline Fallback & Bounded Delivery (`planner.rs`, `delivery.rs`)**
   - `DeliveryPlanner` triggers clean full-inline fallback when the feature is disabled, client omits `packfile-uris` or omits `https`, closure coverage is incomplete, queue capacity is saturated, CDN health is unavailable, `CdnCircuitBreaker` is open, pin acquisition fails, or candidate packs fall below `min_pack_bytes_for_offload`.
   - Unauthorized callers always fail closed (`Unauthorized`) before fallback selection.
   - Client downloads (`fetch_pack_with_integrity_and_retry`) enforce bounded concurrency, byte limits, request deadline, bounded retries (`<= 3`), exact `.pack` trailer hash check, and SHA-256 verification before accepting pack data. Failed HTTP `401`/`403`/`410` responses fail closed immediately instead of masking auth/pin failures.

## Measured Baseline (#164 Inline) vs Offload (#185) Comparison

Generated via [eval_packfile_uri_delivery.py](../scripts/eval_packfile_uri_delivery.py) (`--profiles small,medium --formats sha1,sha256`) using real stock Git (`git version 2.45.1.windows.1`), Smart HTTP v2, and local TLS `CONNECT` proxy:

| Profile | Format | Baseline (#164) Origin Egress | Offload (#185) Origin Egress | Origin Reduction | CDN Cache Hits | Blob GET Count (Base -> Offload) | Inline P50 / P95 (ms) | Offload P50 / P95 (ms) | `git fsck` |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `small` | `sha1` | 265,812 B | 2,464 B | 99.07% | 3 / 4 | 4 -> 1 | 236.2 / 244.1 | 318.9 / 325.3 | Pass |
| `small` | `sha256` | 266,704 B | 3,104 B | 98.84% | 3 / 4 | 4 -> 1 | 233.0 / 239.6 | 317.0 / 414.4 | Pass |
| `medium` | `sha1` | 1,318,060 B | 4,835 B | 99.63% | 4 / 5 | 5 -> 1 | 216.9 / 225.8 | 343.0 / 371.7 | Pass |
| `medium` | `sha256` | 1,319,985 B | 6,180 B | 99.53% | 4 / 5 | 5 -> 1 | 238.6 / 270.0 | 328.8 / 346.9 | Pass |

**Scope & Topology Notes**:
- All benchmarks ran in a single-host loopback harness with real stock `git clone` and TLS `CONNECT` termination; results measure origin egress offload, Blob storage GET amplification reduction (`N -> 1` cache misses), and warm CDN cache reuse, and make no claims regarding cross-region WAN CDN latency or multi-region SLAs.
- On tiny packs (`min_pack_bytes_for_offload`), a separate TLS handshake adds single-host overhead compared with a single-stream inline fetch, which is why small candidates stay inline below `min_pack_bytes_for_offload`.
