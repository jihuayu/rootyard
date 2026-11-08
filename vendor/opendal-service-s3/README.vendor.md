# Vendored `opendal-service-s3` 0.57.0

This directory is an exact copy of the Apache OpenDAL `opendal-service-s3`
0.57.0 crate as published on crates.io. The root `Cargo.toml` points
`[patch.crates-io]` and a direct dependency at this path so the adapter can
reuse the upstream S3 error parser instead of reimplementing S3 protocol
semantics.

## Provenance

* Crate: `opendal-service-s3`
* Version: `0.57.0`
* crates.io package checksum (`.crate` SHA-256):
  `313d46c9f5ae70bca26b7c3e3fbb9b639292625f28af73aa016f47e788af9deb`
* Upstream VCS revision (`.cargo_vcs_info.json`):
  `1e0fc73190afb7e221c7badda7ef43fe40592940`
* Upstream path: `core/services/s3`
* License: Apache-2.0 (see `LICENSE`)
* Notice: see `NOTICE`
* Local registry source copied from:
  `$CARGO_HOME/registry/src/index.crates.io-*/opendal-service-s3-0.57.0`

`Cargo.toml` (normalized by crates.io) and `Cargo.toml.orig` are preserved
byte-for-byte from the published crate. Every file in this directory except
the local additions listed below is also preserved byte-for-byte.

## Local additions

Only two source/manifest changes exist:

1. `src/lib.rs` adds one documented public function,
   `parse_error_response(Response<Buffer>) -> Error`, which calls the existing
   private `error::parse_error`. It adds no protocol logic.
2. This README, `NOTICE`, and `SHA256SUMS` are provenance files. `LICENSE` is
   the Apache-2.0 text shipped with Apache OpenDAL 0.57.0.

No signing, TLS, retry, multipart, XML or request code was modified.
`SHA256SUMS` records the checksum of every vendored file after these additions.

## Update policy

Do not edit the vendored protocol code. To move to a new upstream release,
replace the whole directory from the official crate archive and regenerate
`SHA256SUMS`, then re-apply only the one-function shim and these provenance
files. Lockfile resolution is owned by the repository root; workers must not
run Cargo or edit `Cargo.lock`.
