//! Fixed-stack regression for the legacy S3 operator used by Pando pushes.
//!
//! The real regression aborted a 2 MiB Tokio worker while it polled the legacy
//! OpenDAL operator. This test builds that operator through the production
//! constructor with static dummy credentials and a closed loopback endpoint:
//! no object, credential, HTTP server or external network is required.

use std::time::Duration;

use reqwest::Url;
use rootyard::blob_store::BlobError;
use rootyard::storage::remote_provider::LegacyS3Store;
use tokio::time::Instant;

/// The worker stack size the legacy publication path must survive.
const WORKER_STACK_BYTES: usize = 2 * 1024 * 1024;

#[test]
fn legacy_s3_operator_polls_on_two_mib_worker_stack() {
    // Reserve and immediately release a loopback port. Connecting to it fails
    // fast and deterministically, so the fully layered operator future is
    // constructed and polled without any HTTP server or external network.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
        listener.local_addr().expect("loopback address").port()
    };
    let endpoint = Url::parse(&format!("http://127.0.0.1:{port}")).expect("loopback endpoint");

    let worker = std::thread::Builder::new()
        .name("legacy-s3-2mib".into())
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build single-thread Tokio runtime");
            runtime.block_on(async move {
                let store = LegacyS3Store::open(
                    &endpoint,
                    "rootyard-stack-regression",
                    "us-east-1",
                    "dummy-access-key-id".to_owned(),
                    "dummy-secret-access-key".to_owned(),
                    None,
                )
                .expect("legacy S3 operator must build on a 2 MiB worker");
                let error = store
                    .head("stack-regression/missing", Instant::now() + Duration::from_secs(10))
                    .await
                    .expect_err("closed loopback port cannot serve an object");
                assert!(
                    matches!(&error, BlobError::Remote(_)),
                    "closed loopback endpoint must stay a typed remote failure: {error:?}"
                );
            });
        })
        .expect("spawn 2 MiB worker");

    worker.join().expect("2 MiB worker must not overflow its stack");
}
