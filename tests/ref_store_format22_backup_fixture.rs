//! Source-bound fixture for the issue #169 positive format22 paired archive.
//!
//! This target is declared with `harness = false` in `Cargo.toml`: its modes are
//! programs (argv, exit status), not libtest cases. `scripts/build_native_test.py`
//! builds it from the same candidate as the executed binary and records a
//! receipt (`<binary>.build.json`); the Python drill refuses a fixture built from
//! another commit or another source-input digest.
//!
//! * `--digest-vector` (offline): prints one JSON vector of
//!   `ArtifactSetDigest::of` results over fixed rows, pinning the drill's
//!   independent Python rebuild to the production type.
//! * `--seed <marker> --data-dir <dir> --git <abs git> --blob-root <prefix>`
//!   (native): creates the real PostgreSQL 17 / S3 / Git source through
//!   production APIs and writes a secret-free seed marker. Environment:
//!   `ROOTYARD_TEST_DATABASE_URL` and the strict `ROOTYARD_BLOB_{SERVICE=s3,
//!   ENDPOINT,REGION,BUCKET,ACCESS_KEY_ID,SECRET_ACCESS_KEY}` profile;
//!   `ROOTYARD_BLOB_ROOT` must equal `--blob-root` and
//!   `ROOTYARD_EXPECTED_SOURCE_COMMIT` must name the candidate commit.

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match format22_support::run(&args) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            // A refusal is returned to the drill; no credential or DSN is echoed.
            eprintln!("format22 fixture refused: {error:#}");
            std::process::exit(1);
        }
    }
}

// Module path is explicit: the modules live in the `format22_support/` directory.
#[path = "format22_support/mod.rs"]
mod format22_support;
