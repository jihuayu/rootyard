# Optional `packfile-uris` Offload & Safe Inline Fallback Delivery

Refs #185

## Overview

`src/browse/packfile_uri.rs` (with submodules under `src/browse/packfile_uri/`) and optional wiring in `src/blob_git_gateway/{state.rs, smart_http.rs}` implement default-off Git Protocol v2 `packfile-uris` offload paired with deterministic inline fallback.

`OffloadPolicyConfig::default()` returns `OffloadPolicyConfig::disabled()` (`enabled: false`, `advertise_in_capabilities: false`), and `BlobGitState::new` leaves `packfile_offload: None` unless explicitly configured via `BlobGitState::with_packfile_offload`. When disabled, capability advertisement omits `packfile-uris` and every mint, verification, streaming, router (`503`), response-encoder, and downloader boundary fails closed.

## Architecture & Security Invariants

1. **Default-Off Policy & Protocol v2 Negotiation (`types.rs`, `protocol_v2.rs`, `smart_http.rs`)**
   - `should_advertise_packfile_uris` and `inject_packfile_uris_into_v2_advertisement` advertise `packfile-uris` strictly when `policy.enabled && policy.advertise_in_capabilities`.
   - `parse_fetch_v2_request` enforces pkt-line framing, repository `object-format` (`sha1`/`sha256`), `MAX_FETCH_WANTS = 1024`, `MAX_FETCH_HAVES = 4096`, and single `packfile-uris` protocol declaration, while capturing any unsupported or unrecognized v2 capabilities/arguments (`filter`, `deepen*`, `shallow*`, `want-ref`, `sideband-all`, `server-option`, or unknown args) in `unsupported_args` so the gateway deterministically falls back (`FallbackReason::UnsupportedFetchArgs`) to native `git upload-pack`.
   - `encode_fetch_v2_response_bounded` refuses `OffloadPlusResidual` emission if `!policy.enabled` or non-`https://`, and enforces hard byte ceilings (`max_response_bytes` / `policy.max_v2_response_bytes`).
2. **Pinned Single-Resolution SSRF & Host Allowlist Guard (`ssrf_guard.rs`, `downloader.rs`)**
   - `validate_policy_config` and `validate_offload_uri_and_resolve` fail closed when `!policy.enabled`, enforce `https` on port `443` in `strict_production` (`loopback_allowed = false`), reject empty resolved peer address sets (`SsrfBlocked`), reject raw IP literals/wildcards/userinfo/traversal, and validate every resolved `SocketAddr` via `crate::webhooks::policy::permitted_peer`.
   - `fetch_pack_with_integrity_and_retry` resolves once via `PackUriDnsResolver` and pins those exact `SocketAddr`s into `reqwest::Client::builder().resolve_to_addrs(&validated.host, &validated.pinned_addrs)` with `redirect::Policy::none()`, eliminating DNS rebinding TOCTOU between validation and connect.
3. **Subject- & `Host`-Bound HMAC Signing + Live Per-Request/Chunk Re-Authorization (`signing.rs`, `delivery.rs`, `gateway_bridge.rs`)**
   - `DownloadSubjectContext` rejects nil `actor_id` / `token_id` UUIDs and `auth_epoch == 0`.
   - `SignedDownloadClaims` binds `(tenant_id, repository_id, pack_oid, object_format, "https", allowed_host, port, canonical_path, actor_id, token_id, auth_epoch, expires_at_unix, key_id, scope_nonce, pin_id)` inside domain-separated HMAC-SHA256 (`rootyard-packfile-uri-v1`).
   - `axum_serve_handler` extracts and validates the real inbound HTTP `Host` / authority header against `allowed_hosts` and the signed `allowed_host`, validates optional `x-rootyard-actor` / `x-rootyard-token-id` / `x-rootyard-auth-epoch` headers, and invokes `LivePackReadAuthorizer::authorize_pack_download` (`ReadAuthorization::revalidate` against live PostgreSQL tokens/RBAC/scope/realm/backend) before streaming and on every 32 KiB chunk.
4. **Real `#184` `VerifiedFetchPlanProof` & Whole-Pack Advertised-Ref Closure (`cover_builder.rs`, `cover_git.rs`, `pack_bijection.rs`, `planner.rs`)**
   - `smart_http::upload_pack` binds requested `wants` strictly to the authoritative `advertised_refs` captured in `RefView` (`FallbackReason::UnadvertisedWant` on any unadvertised OID).
   - `discover_repo_packs`, `verify_raw_pack_stream_bijection` (`git index-pack --strict -o` byte-for-byte `.idx` verification), and `build_verified_cover_proof_from_repo` enforce `.pack` raw-stream + `.idx` v2 OID-table bijection, cap helper `git` subprocess timeouts/stdout/stderr and scanned `.pack`/`.idx` counts/bytes/objects (`HelperResourceLimits` / `run_git_bounded`), and verify that **every object inside any offloaded `.pack`** belongs to the authorized reachable `wants` closure (`whole_pack_in_authorized_wants` / `FallbackReason::PackContainsUnauthorizedObjects`).
   - `PinnedPackDir` verifies `repo_dir -> objects -> pack` with step-wise `openat(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` hops and retains the verified `objects/pack` **directory descriptor** (plus its `(dev, ino)` identity) open across enumeration and every `.pack`/`.idx` read: the listing is taken through `/proc/self/fd/<fd>` and single-component artifacts are opened strictly via `libc::openat(dir_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)`, so a swapped parent path is never re-resolved. Platforms without Unix directory/file handle confinement (`#[cfg(not(unix))]`, where `PinnedPackDir` is uninhabited via `Infallible`) never fall back to path-based directory/file checks or opens and instead deterministically fall back (`FallbackReason::HandleConfinementUnavailable`) to the standard inline `git upload-pack` response. Any directory/handle failure deterministically falls back to inline `git upload-pack` (`Ok(None)`), and reads stream bounded chunks under per-file and cumulative byte caps.
   - The exact in-memory `Bytes` that passes bijection is the same allocation handed to `PackHttpServerState` (zero-TOCTOU single-read verification and serving, never a second `repo_dir` read).
   - `DeliveryPlanner::plan_fetch` requires `#184` `AuthorizationContext`, `FetchPlan`, `VerifiedFetchPlanProof`, `CoverHierarchyIndex`, and `RetentionClassificationIndex` (`proof.binds_live_auth(auth)` and `proof.binds(plan)`), capping candidates to `MAX_CLOSURE_PACKS` and selecting only non-thin `PlannableForFetch` covers (`>= min_pack_bytes_for_offload`).
5. **Bounded Streaming, Lease Sweeping & Cancellation-Safe RAII Preflight/Pin Guards (`retention.rs`, `preflight_guard.rs`, `delivery.rs`, `downloader.rs`)**
   - `GatewayLiveAuthorizer` bounds concurrent preflight evaluations with a hard `Semaphore` (`max_concurrent_preflights`, falling back with `OverloadedOrQueueSaturated`) and cleans up preflight auth entries and staged pin leases automatically on future cancellation/drop via `PreflightSessionGuard` and `StagedPinBatchGuard`.
   - `PackDeliveryLeaseRegistry` auto-sweeps expired unreferenced leases in `acquire_offload_pin`, enforces `max_active_leases`, binds `DownloadSubjectContext` on `begin_download_hold`, and rolls back/revokes+sweeps earlier pins in `DeliveryPlanner` on partial mint/pin failure.
   - `serve_signed_packfile_stream` streams 32 KiB chunks via `Body::from_stream` holding `OwnedSemaphorePermit`, `InflightBytesGuard`, `InflightDownloadGuard`, and stream `deadline` until EOF or drop, aborting mid-stream on policy disable, pin revocation, or live auth revocation.
   - `fetch_pack_with_integrity_and_retry` streams response chunks via `resp.chunk().await` bounded by `min(desc.byte_len, max_pack_bytes)` and `InflightBytesLimiter`, verifying exact byte length, SHA-256, and `.pack` trailer hash.

## Measured Baseline (#164 Inline) vs Offload (#185) Comparison

Generated via [eval_packfile_uri_delivery.py](../scripts/eval_packfile_uri_delivery.py) (`--profiles small,medium --formats sha1,sha256`) using real stock Git, Smart HTTP v2, and local TLS termination:

| Profile | Format | Baseline (#164) Origin Egress | Offload (#185) Origin Egress | Origin Reduction | CDN Cache Hits | Blob GET Count (Base -> Offload) | Inline P50 / P95 (ms) | Offload P50 / P95 (ms) | `git fsck` |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `small` | `sha1` | 265,812 B | 2,464 B | 99.07% | 3 / 4 | 4 -> 1 | 236.2 / 244.1 | 318.9 / 325.3 | Pass |
| `small` | `sha256` | 266,704 B | 3,104 B | 98.84% | 3 / 4 | 4 -> 1 | 233.0 / 239.6 | 317.0 / 414.4 | Pass |
| `medium` | `sha1` | 1,318,060 B | 4,835 B | 99.63% | 4 / 5 | 5 -> 1 | 216.9 / 225.8 | 343.0 / 371.7 | Pass |
| `medium` | `sha256` | 1,319,985 B | 6,180 B | 99.53% | 4 / 5 | 5 -> 1 | 238.6 / 270.0 | 328.8 / 346.9 | Pass |

**Scope & Topology Notes**:
- Benchmarks ran in a single-host loopback harness with real stock `git clone` and TLS termination; results measure origin egress offload, Blob storage GET amplification reduction (`N -> 1` cache misses), and warm CDN cache reuse, and make no claims regarding cross-region WAN CDN latency or multi-region SLAs.
