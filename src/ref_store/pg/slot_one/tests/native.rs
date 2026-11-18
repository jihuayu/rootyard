//! Real PostgreSQL 17 + S3-compatible Blob + native Git fixture for the
//! crate-private slot-zero retirement and slot-one rotation foundation.
//!
//! The production primitives are crate-private, so the only way to exercise the
//! actual `admit_slot_zero_in_tx`, authorized refusal, terminal mirror and
//! `rotate_slot_one_in_tx` methods without changing visibility is this
//! `#[cfg(test)]` library module. The A3/A4/A5 support below is the already
//! reviewed `tests/retention_roots_support` fixture, path-included unchanged.
//! `extern crate self as rootyard` in `src/lib.rs` makes its `rootyard::`
//! imports resolve inside the crate's own test build.
//!
//! Every case is `#[ignore]`, hard-fails when PostgreSQL, the Blob profile, the
//! trusted Git binary, the disposable-database attestation or the
//! disposable-bucket attestation is absent, and never skips once explicitly
//! invoked. The test writes no gate, authority, decision, terminal, approval or
//! event row directly: P0 is admitted and staged, an
//! unrelated ref B advances the gate through a real authorized P1 commit, P0 is
//! durably refused and mirrored as retirement-required without wrapper mutation,
//! and P2 re-executes the identical P0 wire ref command with a fresh private
//! identity/sequence/plan/proof/registration before a real authorized commit and
//! A5 snapshot. Collaboration uses separate ref A for P0/P2 and ref B for P1 so
//! the retried wire command remains exactly the original one.
//!
//! The PostgreSQL marker attests one dedicated database disposed whole, never a
//! shared schema, even when the configured URL is valid; the included fixture
//! seeds `public.cluster_authority` outside its random schema and does not claim
//! shared-schema cleanup.
//!
//! Run explicitly (with an owned disposable PostgreSQL database and Blob
//! bucket/prefix):
//!
//! ```text
//! ROOTYARD_TEST_OWNED_DISPOSABLE_POSTGRES=1 \
//! ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB=1 \
//! ROOTYARD_TEST_DATABASE_URL=postgresql://... \
//! ROOTYARD_BLOB_DRIVER=opendal ROOTYARD_BLOB_SERVICE=s3 \
//! ROOTYARD_BLOB_ENDPOINT=... ROOTYARD_BLOB_BUCKET=... ROOTYARD_BLOB_REGION=... \
//! ROOTYARD_BLOB_ACCESS_KEY_ID=... ROOTYARD_BLOB_SECRET_ACCESS_KEY=... \
//! ROOTYARD_BLOB_ROOT=slot-one-proof-<unique> ROOTYARD_TEST_GIT=/absolute/git \
//! cargo test --locked --no-default-features --lib \
//!   ref_store::pg::slot_one::tests::native::slot_one_rotation_replays_identical_wire_command_on_real_a3_a4_a5 \
//!   -- --ignored --exact --test-threads=1
//! ```
//!
//! The smaller `slot_zero_rejection_selects_retirement_on_real_a3_a4` case covers
//! the same P0/P1/refusal/mirror prefix and can be selected by its exact name.

#![allow(clippy::too_many_arguments)]
#![allow(dead_code)]

#[path = "../../../../../tests/retention_roots_support/common.rs"]
mod common;
#[path = "../../../../../tests/retention_roots_support/db.rs"]
mod db;
#[path = "../../../../../tests/retention_roots_support/git.rs"]
mod git;
#[path = "../../../../../tests/retention_roots_support/pack.rs"]
mod pack;
#[path = "../../../../../tests/retention_roots_support/serving.rs"]
mod serving;

mod publication;
mod readback;
mod retirement;
mod rotation;
mod setup;

use anyhow::{Result, ensure};
use rootyard::db::{Identity, Repository};
use rootyard::ref_store::{
    CoreGateVersion,
    core::pack_commit::PackCommitPlan,
    pg::{public_attempt::PublicAttemptRequest, public_terminal::PublicAttemptRetirement, slot_zero::SlotZeroReceipt},
};

use readback::{assert_a5_after_rotation, assert_no_registry_promotion, publication_for, stored_ref};
use retirement::retire_p0;
use rotation::{assert_current_pending_wrapper_gap, mirror_p2_terminal_and_prove_replay, rotate_and_commit};
use setup::{require_owned_disposable_fixture, require_postgres_17};

const REF_RETRY: &str = "refs/heads/retry";
const REF_SIDE: &str = "refs/heads/side";
const SLOT_ZERO_LANE: &str = "slot-zero-rotation";
const WIRE_DOMAIN: &str = "rootyard-test-wire-ref-command-v1";
const WIRE_BODY: &[u8] = b"identical logical receive-pack ref update";

/// The durable state through P0 admission, P0 artifact staging, the real P1
/// authorized advance, the production superseded refusal and the read-only
/// retirement selection. The wrapper is still pending slot zero here.
struct Retired {
    verified: pack::Verified,
    actor: Identity,
    repository: Repository,
    retry_oid: String,
    side_oid: String,
    p0_files: git::PairFiles,
    public: PublicAttemptRequest,
    admission: SlotZeroReceipt,
    plan: PackCommitPlan,
    retirement: PublicAttemptRetirement,
    gate: CoreGateVersion,
}

#[tokio::test]
#[ignore = "requires real PostgreSQL 17, S3/Garage Blob and native Git"]
async fn slot_zero_rejection_selects_retirement_on_real_a3_a4() -> Result<()> {
    require_owned_disposable_fixture()?;
    let db = db::Db::setup().await?;
    let outcome: Result<()> = async {
        require_postgres_17(&db).await?;
        let store = common::open_store()?;
        let git = git::git_binary()?;
        let retired = retire_p0(&db, &store, &git).await?;

        ensure!(
            retired.gate.revision() == retired.verified.gate.revision() + 1,
            "P1 did not advance the gate exactly one revision"
        );
        ensure!(
            retired.retirement.event_revision == retired.gate.revision(),
            "retirement event revision differs from the advanced gate"
        );
        ensure!(
            stored_ref(&db, retired.repository.id, REF_RETRY).await?.is_none(),
            "the refused P0 wire command became visible on ref A"
        );
        ensure!(
            stored_ref(&db, retired.repository.id, REF_SIDE).await?.as_deref() == Some(retired.side_oid.as_str()),
            "the real P1 ref B advance is not visible"
        );
        ensure!(
            stored_ref(&db, retired.repository.id, "refs/heads/main").await?.as_deref()
                == Some(retired.verified.commit_oid.as_str()),
            "P1 changed the unrelated main ref"
        );
        Ok(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL 17, S3/Garage Blob and native Git"]
async fn slot_one_rotation_replays_identical_wire_command_on_real_a3_a4_a5() -> Result<()> {
    require_owned_disposable_fixture()?;
    let db = db::Db::setup().await?;
    let outcome: Result<()> = async {
        require_postgres_17(&db).await?;
        let store = common::open_store()?;
        let git = git::git_binary()?;
        let retired = retire_p0(&db, &store, &git).await?;
        let p0_publication = publication_for(&db, retired.repository.id, retired.admission.private_id).await?;

        let (plan, rotation, gate) = rotate_and_commit(&db, &store, &git, &retired).await?;
        assert_a5_after_rotation(&db, &store, &retired, &plan).await?;
        assert_no_registry_promotion(&db, &retired, &plan, &rotation, &p0_publication).await?;
        assert_current_pending_wrapper_gap(&db, &retired).await?;
        mirror_p2_terminal_and_prove_replay(&db, &retired, &rotation).await?;
        ensure!(gate.revision() == retired.gate.revision() + 1, "P2 did not advance the gate exactly one revision");
        Ok(())
    }
    .await;
    db.finish(outcome).await
}
