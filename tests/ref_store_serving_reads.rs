//! Real-PostgreSQL contract tests for the bounded TRANSIENT serving read pin
//! (#107/#114/#144).
//!
//! Every case is `#[ignore]`-gated and requires actual PostgreSQL plus the
//! production Blob profile (no provider IO is performed for the empty-repository
//! cases, and no Git object is fabricated anywhere). A missing service is a hard
//! failure, never a silent skip, because a fake pass would prove nothing.
//!
//! What these cases prove:
//!
//! * >128 capture/materialize/release cycles on a real provisioned
//!   > `metadata_only` repository keep **zero** durable snapshot/pin/receipt/
//!   > history/usage rows and **zero** transient rows: the retained 64-per-repo
//!   > A5a quota is untouched and the gateway can no longer fail after 64 GETs;
//! * the empty capture is typed (`is_empty()`, no `PackReadSnapshot`, no pin id)
//!   and materializes to `Ok(None)` instead of a fabricated verified snapshot;
//! * a foreign Blob backend identity and a changed history incarnation are
//!   refused before any row is written;
//! * leases are bounded and release is exact and idempotent;
//! * a `metadata_only` gate that already has refs is refused (no metadata flag
//!   is ever promoted into a byte proof);
//! * the migration-146 rows are immutable but deleatable, with the guards
//!   actually installed;
//! * a transient read's refs/pack/artifact rows can be deleted **only** by the
//!   header's own `ON DELETE CASCADE`: a direct child `DELETE` is refused while
//!   the header is live, so a live lease cannot silently lose its GC protection;
//! * a bounded expired backlog keeps draining through the **separately
//!   committed** cleanup even though every capture attempt against the same gate
//!   is refused, so a tenant can never be wedged by its own expired rows;
//! * a capture whose cleanup and own transaction are blocked on a usage-row lock
//!   fails inside its absolute deadline and rolls that cleanup back instead of
//!   hanging past it.
//!
//! Registered-pack/native closure cases additionally require the A4 S3+Git
//! fixture (the same one `ref_store_materialized_reads.rs` builds) and are run
//! by the Root runner with that stack; see `target/task-context/serving-read-api.md`.
mod serving_reads_support;
mod serving_support;

use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::RefStoreError;
use rootyard::ref_store::core::pack_snapshot::{PgServingReads, ReadSnapshotSourceKind};
use serving_reads_support::{
    add_serving_read_children, backend_for_bucket, child_row_count, count_for_repo, ensure_migration_146,
    expired_row_count, force_gate_pack_verified, hold_tenant_usage_lock, insert_serving_read_headers,
    operation_deadline, protection_count, provision_ready,
};
use serving_support::{Fixture, actor, backend_identity};
use std::time::{Duration, Instant as StdInstant};
use uuid::Uuid;

const LEASE_SECONDS: u32 = 120;
const CYCLES: usize = 130;

fn hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn transient_row_count(fixture: &Fixture, repository_id: Uuid) -> Result<i64> {
    count_for_repo(fixture, "ref_store_core_serving_reads", repository_id).await
}

async fn durable_row_count(fixture: &Fixture, table: &str, repository_id: Uuid) -> Result<i64> {
    count_for_repo(fixture, table, repository_id).await
}

/// Drop this case's schema on success and on every error path (the teardown
/// error never masks the original failure).
async fn finish(fixture: Fixture, outcome: Result<()>) -> Result<()> {
    match outcome {
        Ok(()) => fixture.teardown().await,
        Err(error) => {
            let _ = fixture.teardown().await;
            Err(error)
        }
    }
}

/// How many transient repository usage rows exist for one repository.
async fn usage_row_count(fixture: &Fixture, repository_id: Uuid) -> Result<i64> {
    Ok(fixture
        .pool
        .get()
        .await?
        .query_one(
            "SELECT count(*)::bigint FROM ref_store_core_serving_read_repo_usage WHERE repository_id=$1",
            &[&repository_id],
        )
        .await?
        .get(0))
}

/// `(stored tenant, (active_count, logical_bytes))` of the repository usage row.
async fn read_usage_row(fixture: &Fixture, repository_id: Uuid) -> Result<(Option<Uuid>, (i64, i64))> {
    let row = fixture
        .pool
        .get()
        .await?
        .query_opt(
            "SELECT tenant_id,active_count,logical_bytes FROM ref_store_core_serving_read_repo_usage
             WHERE repository_id=$1",
            &[&repository_id],
        )
        .await?;
    Ok(match row {
        Some(row) => (Some(row.get(0)), (row.get(1), row.get(2))),
        None => (None, (0, 0)),
    })
}

/// `(active_count, logical_bytes)` of the tenant usage row, if it exists.
async fn read_tenant_usage_row(fixture: &Fixture, tenant_id: Uuid) -> Result<Option<(i64, i64)>> {
    let row = fixture
        .pool
        .get()
        .await?
        .query_opt(
            "SELECT active_count,logical_bytes FROM ref_store_core_serving_read_tenant_usage WHERE tenant_id=$1",
            &[&tenant_id],
        )
        .await?;
    Ok(row.map(|row| (row.get::<_, i64>(0), row.get::<_, i64>(1))))
}

/// The actual PostgreSQL refusal of a direct transient child `DELETE`: the
/// migration-146 `cascade_only` guard raises a plain `P0001` with a fixed
/// message. Any other database error (FK, permission, syntax) is rejected.
fn child_guard_refusal(error: &tokio_postgres::Error) -> Option<String> {
    let database = error.as_db_error()?;
    (database.code().code() == "P0001").then(|| database.message().to_owned())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the production Blob profile"]
async fn empty_repository_cycles_are_bounded_and_never_touch_the_retained_quota() -> Result<()> {
    let fixture = Fixture::new().await?;
    ensure_migration_146(&fixture).await?;
    let owner = actor(&fixture.pool, false).await?;
    let repo = provision_ready(&fixture, &owner.identity, "serving-reads-empty").await?;
    let scope = repo.ready.scope()?;
    let reads = PgServingReads;
    let materializer = repo.materializer()?;

    let mut first_digest: Option<String> = None;
    for cycle in 0..CYCLES {
        let capture = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await?;
        ensure!(capture.is_empty(), "cycle {cycle}: a metadata_only repository must capture as empty");
        ensure!(
            capture.registered_snapshot().is_none(),
            "cycle {cycle}: an empty capture must never expose a PackReadSnapshot"
        );
        ensure!(capture.pin_id().is_none() && capture.pin_generation().is_none(), "cycle {cycle}: empty owns no pin");
        ensure!(capture.head_ref().starts_with("refs/heads/"), "cycle {cycle}: HEAD must be a branch ref");
        ensure!(hex64(&capture.capture_digest_hex()), "cycle {cycle}: capture digest must be sha256 hex");
        match &first_digest {
            None => first_digest = Some(capture.capture_digest_hex()),
            Some(expected) => ensure!(
                *expected == capture.capture_digest_hex(),
                "cycle {cycle}: the same empty gate must produce a stable capture digest"
            ),
        }
        // The real A5b materializer must return None (nothing to verify) rather
        // than a fabricated verified snapshot.
        let materialized = materializer.materialize_serving_read(&fixture.pool, &capture, operation_deadline()).await?;
        ensure!(materialized.is_none(), "cycle {cycle}: an empty capture cannot materialize packs");
        reads.release(&fixture.pool, &capture, operation_deadline()).await?;
        // A second release is an idempotent success: nothing is protected.
        reads.release(&fixture.pool, &capture, operation_deadline()).await?;
    }

    // The retained A5a family is untouched: no snapshot, no pin, no pack history
    // and no permanent pack-snapshot usage row was ever created.
    for table in ["ref_store_core_snapshots", "ref_store_core_pins", "ref_store_core_pack_snapshot_history"] {
        ensure!(
            durable_row_count(&fixture, table, repo.ready.repository_id).await? == 0,
            "{table} gained a durable row from a transient serving read"
        );
    }
    let pack_usage: i64 = fixture
        .pool
        .get()
        .await?
        .query_one(
            "SELECT count(*)::bigint FROM ref_store_core_pack_snapshot_repo_usage WHERE repository_id=$1",
            &[&repo.ready.repository_id],
        )
        .await?
        .get(0);
    ensure!(pack_usage == 0, "the permanent pack-snapshot counters were charged by a serving read");

    // The transient family is empty again, so neither the lease nor the byte
    // bound can be consumed by empty GETs.
    ensure!(transient_row_count(&fixture, repo.ready.repository_id).await? == 0, "transient rows leaked");
    fixture.teardown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the production Blob profile"]
async fn foreign_backend_and_changed_history_are_refused_before_any_row() -> Result<()> {
    let fixture = Fixture::new().await?;
    ensure_migration_146(&fixture).await?;
    let owner = actor(&fixture.pool, false).await?;
    let repo = provision_ready(&fixture, &owner.identity, "serving-reads-refuse").await?;
    let scope = repo.ready.scope()?;
    let reads = PgServingReads;

    // A real, distinct physical backend (different bucket) is not the bound one.
    let foreign = backend_for_bucket("serving-reads-foreign-bucket")?;
    let refused = reads.capture(&fixture.pool, &scope, &foreign, LEASE_SECONDS, operation_deadline()).await;
    ensure!(refused.is_err(), "a foreign Blob backend identity must never capture a serving read");
    ensure!(transient_row_count(&fixture, repo.ready.repository_id).await? == 0, "a refusal wrote rows");

    // A changed history incarnation is a different authority realm.
    let moved_history = repo.ready.with_history(Uuid::new_v4())?;
    let refused =
        reads.capture(&fixture.pool, &moved_history, &repo.backend, LEASE_SECONDS, operation_deadline()).await;
    ensure!(refused.is_err(), "a changed history incarnation must never capture a serving read");
    ensure!(transient_row_count(&fixture, repo.ready.repository_id).await? == 0, "a refusal wrote rows");

    // The exact binding still captures (and, being metadata_only, captures empty).
    let ok = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await?;
    ensure!(ok.is_empty(), "the provisioned empty repository must capture as empty");
    reads.release(&fixture.pool, &ok, operation_deadline()).await?;
    ensure!(transient_row_count(&fixture, repo.ready.repository_id).await? == 0, "transient rows leaked");
    fixture.teardown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the production Blob profile"]
async fn lease_bounds_are_enforced_and_release_is_idempotent() -> Result<()> {
    let fixture = Fixture::new().await?;
    ensure_migration_146(&fixture).await?;
    let owner = actor(&fixture.pool, false).await?;
    let repo = provision_ready(&fixture, &owner.identity, "serving-reads-lease").await?;
    let scope = repo.ready.scope()?;
    let reads = PgServingReads;

    for lease in [0_u32, 301_u32, 3_600] {
        let refused = reads.capture(&fixture.pool, &scope, &repo.backend, lease, operation_deadline()).await;
        ensure!(refused.is_err(), "out-of-range lease {lease} must be refused before any SQL row");
    }
    let capture = reads
        .capture(
            &fixture.pool,
            &scope,
            &repo.backend,
            rootyard::ref_store::core::pack_snapshot::MAX_SERVING_READ_LEASE_SECONDS as u32,
            operation_deadline(),
        )
        .await?;
    reads.release(&fixture.pool, &capture, operation_deadline()).await?;
    reads.release(&fixture.pool, &capture, operation_deadline()).await?;
    ensure!(transient_row_count(&fixture, repo.ready.repository_id).await? == 0, "release must delete the row");
    fixture.teardown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the production Blob profile"]
async fn metadata_only_gate_with_refs_is_refused_instead_of_faking_a_snapshot() -> Result<()> {
    let fixture = Fixture::new().await?;
    ensure_migration_146(&fixture).await?;
    let owner = actor(&fixture.pool, false).await?;
    let repo = provision_ready(&fixture, &owner.identity, "serving-reads-refs").await?;
    let scope = repo.ready.scope()?;
    let reads = PgServingReads;

    // Fault injection in this task-owned schema: one A1 ref row at the current
    // gate revision, with no verified pack bytes at all.
    fixture
        .pool
        .get()
        .await?
        .execute(
            "INSERT INTO ref_store_core_refs(repository_id,ref_name,oid,revision) VALUES($1,'refs/heads/main',$2,$3)",
            &[&repo.ready.repository_id, &"a".repeat(40), &repo.ready.gate_revision],
        )
        .await?;
    let refused = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await;
    match refused {
        Err(RefStoreError::Unsupported(reason)) => {
            ensure!(reason.contains("no verified pack bytes"), "unexpected refusal: {reason}")
        }
        Err(other) => return Err(anyhow::anyhow!("unexpected refusal: {other}")),
        Ok(_) => return Err(anyhow::anyhow!("refs without verified pack bytes must never capture")),
    }
    ensure!(transient_row_count(&fixture, repo.ready.repository_id).await? == 0, "a refusal wrote rows");
    fixture
        .pool
        .get()
        .await?
        .execute(
            "DELETE FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name='refs/heads/main'",
            &[&repo.ready.repository_id],
        )
        .await?;
    fixture.teardown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL directly (no Blob provider IO)"]
async fn migration_146_rows_are_immutable_but_deletable() -> Result<()> {
    let fixture = Fixture::new().await?;
    ensure_migration_146(&fixture).await?;
    let client = fixture.pool.get().await?;
    for (table, update_guard, truncate_guard) in [
        (
            "ref_store_core_serving_reads",
            "ref_store_core_serving_reads_immutable",
            "ref_store_core_serving_reads_no_truncate",
        ),
        (
            "ref_store_core_serving_read_refs",
            "ref_store_core_serving_read_refs_immutable",
            "ref_store_core_serving_read_refs_no_truncate",
        ),
        (
            "ref_store_core_serving_read_packs",
            "ref_store_core_serving_read_packs_immutable",
            "ref_store_core_serving_read_packs_no_truncate",
        ),
        (
            "ref_store_core_serving_read_artifacts",
            "ref_store_core_serving_read_artifacts_immutable",
            "ref_store_core_serving_read_artifacts_no_truncate",
        ),
    ] {
        let installed: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
                 WHERE c.oid=to_regclass($1) AND t.tgname=$2 AND NOT t.tgisinternal",
                &[&table, &update_guard],
            )
            .await?
            .get(0);
        ensure!(installed == 1, "{update_guard} is not installed on {table}");
        let installed: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
                 WHERE c.oid=to_regclass($1) AND t.tgname=$2 AND NOT t.tgisinternal",
                &[&table, &truncate_guard],
            )
            .await?
            .get(0);
        ensure!(installed == 1, "{truncate_guard} is not installed on {table}");
    }
    // Transient rows are deletable (no forever read-receipt ledger): only a
    // durable-row delete guard would refuse this, and migration 146 installs
    // none.
    let delete_guards: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
             WHERE c.oid='ref_store_core_serving_reads'::regclass AND t.tgtype & 8 = 8 AND NOT t.tgisinternal",
            &[],
        )
        .await?
        .get(0);
    ensure!(delete_guards == 0, "transient serving read rows must stay deletable");
    let protection: i64 = client
        .query_one("SELECT count(*)::bigint FROM ref_store_core_serving_read_protection($1)", &[&Uuid::new_v4()])
        .await?
        .get(0);
    ensure!(protection == 0, "the GC protection enumeration must be empty for an unknown repository");
    fixture.teardown().await?;
    Ok(())
}

// Keep the unused-but-real backend identity import honest: the empty cases open
// the production profile through the support module, and this assertion proves
// the fixture identity really is a 64-hex digest.
#[tokio::test]
#[ignore = "requires the production Blob profile only"]
async fn fixture_backend_identity_is_a_digest() -> Result<()> {
    let identity = backend_identity("serving-reads-identity")?;
    ensure!(hex64(identity.as_hex()), "Blob backend identity must be a 64-hex digest");
    Ok(())
}

// The source kind is part of the public vocabulary the gateway and the
// materializer switch on.
#[test]
fn source_kinds_are_distinguishable() -> Result<()> {
    ensure!(ReadSnapshotSourceKind::ServingTransient != ReadSnapshotSourceKind::RetainedDurable);
    ensure!(ReadSnapshotSourceKind::ServingTransient.as_str() == "serving_transient");
    ensure!(ReadSnapshotSourceKind::RetainedDurable.as_str() == "retained_durable");
    Ok(())
}

// ---------------------------------------------------------------------------
// Regression cases (review findings 1-3).
// ---------------------------------------------------------------------------

/// A live transient read must keep its full GC protection: the captured
/// refs/pack/artifact rows are removable **only** by the header's own
/// `ON DELETE CASCADE`.
///
/// Finding: migration 146 guarded `UPDATE`/`TRUNCATE` on the child tables but
/// installed no `DELETE` guard, so a direct `DELETE FROM
/// ref_store_core_serving_read_packs` removed that pack from
/// `ref_store_core_serving_read_protection` while the lease was still live. A
/// future GC could then delete bytes an unexpired serving read still protects
/// (the T2 recheck refuses the damaged capture afterwards, but the byte
/// protection would already be gone).
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the production Blob profile"]
async fn child_rows_are_deletable_only_through_the_header_cascade() -> Result<()> {
    let fixture = Fixture::new().await?;
    ensure_migration_146(&fixture).await?;
    let owner = actor(&fixture.pool, false).await?;
    let repo = provision_ready(&fixture, &owner.identity, "serving-reads-cascade").await?;
    let backend_hex = repo.backend.as_hex();
    // One LIVE transient header (ten minutes of lease left) with a full child set.
    let pins = insert_serving_read_headers(&fixture, &repo.ready, backend_hex, 1, 4096, 600_000_000).await?;
    let pin = pins[0];
    let (_pack_id, _registration_id) = add_serving_read_children(&fixture, &repo.ready, pin, backend_hex).await?;
    let client = fixture.pool.get().await?;

    for (table, guard) in [
        ("ref_store_core_serving_read_refs", "ref_store_core_serving_read_refs_cascade_only"),
        ("ref_store_core_serving_read_packs", "ref_store_core_serving_read_packs_cascade_only"),
        ("ref_store_core_serving_read_artifacts", "ref_store_core_serving_read_artifacts_cascade_only"),
    ] {
        let installed: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
                 WHERE c.oid=to_regclass($1) AND t.tgname=$2 AND NOT t.tgisinternal AND t.tgtype & 8 = 8",
                &[&table, &guard],
            )
            .await?
            .get(0);
        ensure!(installed == 1, "{guard} is not installed as a row DELETE guard on {table}");
    }
    ensure!(
        protection_count(&fixture, repo.ready.repository_id).await? == 1,
        "a live transient read must protect its captured pack"
    );

    for table in [
        "ref_store_core_serving_read_refs",
        "ref_store_core_serving_read_packs",
        "ref_store_core_serving_read_artifacts",
    ] {
        let sql = format!("DELETE FROM {table} WHERE pin_id=$1");
        match client.execute(&sql, &[&pin]).await {
            Ok(deleted) => {
                return Err(anyhow!("a direct DELETE of {table} removed {deleted} row(s) while the header was live"));
            }
            Err(error) => {
                // `to_string()` only reports the opaque driver text ("db error");
                // the real refusal lives in the database error.
                let message = child_guard_refusal(&error);
                ensure!(
                    message.as_deref()
                        == Some("ref-store core serving read child rows may only be deleted by their header cascade"),
                    "unexpected refusal from {table}: {:?}",
                    message.unwrap_or_else(|| error.to_string())
                );
            }
        }
        ensure!(
            child_row_count(&fixture, table, pin).await? > 0,
            "a refused direct delete still removed rows from {table}"
        );
    }
    ensure!(
        protection_count(&fixture, repo.ready.repository_id).await? == 1,
        "a refused direct child delete changed the protected pack set"
    );

    // The header itself stays deletable (release/reclaim/repository cascade) and
    // its cascade is the only way the children can disappear.
    let deleted = client.execute("DELETE FROM ref_store_core_serving_reads WHERE pin_id=$1", &[&pin]).await?;
    ensure!(deleted == 1, "the transient header must stay deletable");
    for table in [
        "ref_store_core_serving_read_refs",
        "ref_store_core_serving_read_packs",
        "ref_store_core_serving_read_artifacts",
    ] {
        ensure!(child_row_count(&fixture, table, pin).await? == 0, "{table} survived the header cascade");
    }
    ensure!(
        protection_count(&fixture, repo.ready.repository_id).await? == 0,
        "a deleted header must not protect anything"
    );
    fixture.teardown().await?;
    Ok(())
}

/// An expired backlog must keep draining even when the capture that triggered the
/// cleanup is refused afterwards.
///
/// Finding: `capture_registered` reclaimed at most 64 expired rows and then
/// admitted inside the SAME transaction, so a refused admission rolled the
/// reclaim back and every retry deleted the same oldest batch. A tenant whose
/// expired rows push it over the byte bound could never drain them.
///
/// Here the byte bound is genuinely exceeded by expired rows (100 rows of 83,876
/// conservative bytes = 8,387,600 <= the 8 MiB row CHECK, leaving less than one
/// read of headroom) and the gate is `pack_verified` with no registered
/// membership, so every capture attempt is refused after the reclaim. Each
/// refused attempt must still commit exactly one bounded batch.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the production Blob profile"]
async fn refused_capture_still_drains_its_expired_backlog_in_committed_batches() -> Result<()> {
    let fixture = Fixture::new().await?;
    ensure_migration_146(&fixture).await?;
    let owner = actor(&fixture.pool, false).await?;
    let repo = provision_ready(&fixture, &owner.identity, "serving-reads-backlog").await?;
    let backend_hex = repo.backend.as_hex();
    let scope = repo.ready.scope()?;
    let reads = PgServingReads;
    let batch = 64_i64;
    let rows = 100_usize;
    let bytes = 83_876_i64;
    force_gate_pack_verified(&fixture, repo.ready.repository_id).await?;
    insert_serving_read_headers(&fixture, &repo.ready, backend_hex, rows, bytes, -3_600_000_000).await?;
    ensure!(
        expired_row_count(&fixture, repo.ready.repository_id).await? == rows as i64,
        "the expired backlog was not seeded"
    );

    // First refused attempt: the bounded batch must survive the rollback.
    let refused = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await;
    ensure!(refused.is_err(), "a pack_verified gate without a registered membership must never capture");
    ensure!(
        expired_row_count(&fixture, repo.ready.repository_id).await? == rows as i64 - batch,
        "a refused capture rolled its bounded reclaim back instead of committing it"
    );

    // The rest of the backlog drains through further refused attempts; the batch
    // bound means this terminates in a bounded number of calls.
    let mut calls = 1_usize;
    while expired_row_count(&fixture, repo.ready.repository_id).await? > 0 {
        calls += 1;
        ensure!(calls <= 4, "the bounded cleanup did not drain {rows} expired rows in bounded batches");
        let refused = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await;
        ensure!(refused.is_err(), "a pack_verified gate without a registered membership must never capture");
    }
    ensure!(expired_row_count(&fixture, repo.ready.repository_id).await? == 0, "the expired backlog was not drained");
    let usage = fixture
        .pool
        .get()
        .await?
        .query_one(
            "SELECT active_count,logical_bytes FROM ref_store_core_serving_read_repo_usage WHERE repository_id=$1",
            &[&repo.ready.repository_id],
        )
        .await?;
    ensure!(
        usage.get::<_, i64>(0) == 0 && usage.get::<_, i64>(1) == 0,
        "the drained repository kept phantom transient usage"
    );
    fixture.teardown().await?;
    Ok(())
}

/// Regression: the transient usage counters decode from their actual columns.
///
/// `lock_usage` selects `active_count,logical_bytes` (two columns) from the
/// tenant row and `tenant_id,active_count,logical_bytes` (three columns) from
/// the repository row; decoding the two-column tenant row at indices 1/2 used to
/// panic (`invalid column 2`) in the request task as soon as *any* path took the
/// usage locks.
///
/// A `metadata_only` capture is deliberately read-only: it returns a checked
/// empty capture BEFORE `lock_usage` and creates/changes no usage row, so it can
/// never be the thing that exercises these locks. The path that legitimately does
/// is the separately committed, bounded expired-row cleanup: it probes
/// `has_expired`, then `lock_usage` -> `reclaim_expired` -> `recompute_usage`
/// -> COMMIT, and runs before every capture. So: seed expired rows first, let a
/// capture trigger that cleanup, and assert the exact drained state and exact
/// zeroed counters (in both families) plus the untouched read-only capture.
///
/// The seeded rows are negative metadata rows that satisfy the migration-146
/// CHECKs; this is a counter decode/cleanup regression, never a registered-read
/// or byte-proof success.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the production Blob profile"]
async fn usage_counter_rows_decode_from_their_actual_columns() -> Result<()> {
    let fixture = Fixture::new().await?;
    let outcome = async {
        ensure_migration_146(&fixture).await?;
        let owner = actor(&fixture.pool, false).await?;
        let repo = provision_ready(&fixture, &owner.identity, "serving-reads-usage-decode").await?;
        let backend_hex = repo.backend.as_hex();
        let scope = repo.ready.scope()?;
        let reads = PgServingReads;
        let repository_id = repo.ready.repository_id;
        let expired_rows = 2_usize;
        let expired_bytes = 83_876_i64;

        // A metadata_only capture is read-only: no usage row, no transient row.
        let empty = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await?;
        ensure!(empty.is_empty(), "the provisioned metadata_only repository must capture as empty");
        reads.release(&fixture.pool, &empty, operation_deadline()).await?;
        ensure!(
            usage_row_count(&fixture, repository_id).await? == 0,
            "a metadata_only capture must not create usage rows"
        );
        ensure!(transient_row_count(&fixture, repository_id).await? == 0, "an empty capture wrote transient rows");

        // Seed the expired backlog FIRST so the committed cleanup (not the
        // read-only capture) is what creates and locks the usage rows.
        insert_serving_read_headers(&fixture, &repo.ready, backend_hex, expired_rows, expired_bytes, -3_600_000_000)
            .await?;
        ensure!(
            expired_row_count(&fixture, repository_id).await? == expired_rows as i64,
            "the expired backlog was not seeded"
        );

        // The capture's bounded cleanup takes both usage locks over the freshly
        // created rows and drains the whole (sub-batch) backlog.
        let after = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await?;
        ensure!(after.is_empty(), "the provisioned metadata_only repository must capture as empty");
        // Releasing the empty capture owns no row and changes no counter.
        reads.release(&fixture.pool, &after, operation_deadline()).await?;
        ensure!(
            usage_row_count(&fixture, repository_id).await? == 1,
            "the cleanup must create exactly one repository usage row"
        );
        let tenant_rows: i64 = fixture
            .pool
            .get()
            .await?
            .query_one(
                "SELECT count(*)::bigint FROM ref_store_core_serving_read_tenant_usage WHERE tenant_id=$1",
                &[&repo.ready.tenant_id],
            )
            .await?
            .get(0);
        ensure!(tenant_rows == 1, "the cleanup must create exactly one tenant usage row");
        ensure!(
            expired_row_count(&fixture, repository_id).await? == 0,
            "the committed cleanup must drain the entire expired backlog"
        );
        ensure!(transient_row_count(&fixture, repository_id).await? == 0, "the drained backlog kept rows");
        let repository_usage = read_usage_row(&fixture, repository_id).await?;
        ensure!(
            repository_usage == (Some(repo.ready.tenant_id), (0, 0)),
            "the drained repository usage must keep its tenant and recount to exactly 0/0, got {repository_usage:?}"
        );
        let tenant_usage = read_tenant_usage_row(&fixture, repo.ready.tenant_id).await?;
        ensure!(
            tenant_usage == Some((0, 0)),
            "the drained tenant usage must recount to exactly 0/0, got {tenant_usage:?}"
        );

        ensure!(
            read_usage_row(&fixture, repository_id).await? == (Some(repo.ready.tenant_id), (0, 0)),
            "releasing an empty capture changed the repository counters"
        );
        Ok(())
    }
    .await;
    finish(fixture, outcome).await
}

/// A blocked usage-row lock can never push a capture (or its bounded cleanup)
/// past the caller's absolute deadline, and the cleanup it could not finish is
/// rolled back rather than half-applied.
///
/// Finding: the serving-read write paths must apply the database-side
/// `lock_timeout`/`statement_timeout` from the caller deadline and bound their
/// rollback by that same instant; otherwise a usage-row lock wait outlives the
/// deadline and the cleanup/release can hang while the server-side wait is still
/// unresolved.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the production Blob profile"]
async fn blocked_usage_lock_fails_inside_the_absolute_deadline() -> Result<()> {
    let fixture = Fixture::new().await?;
    ensure_migration_146(&fixture).await?;
    let owner = actor(&fixture.pool, false).await?;
    let repo = provision_ready(&fixture, &owner.identity, "serving-reads-deadline").await?;
    let backend_hex = repo.backend.as_hex();
    let scope = repo.ready.scope()?;
    let reads = PgServingReads;
    // One expired row, so the separately committed cleanup really has to take
    // the usage locks this test is blocking.
    insert_serving_read_headers(&fixture, &repo.ready, backend_hex, 1, 4096, -3_600_000_000).await?;
    let blocker = hold_tenant_usage_lock(&fixture, repo.ready.tenant_id).await?;

    let started = StdInstant::now();
    let blocked = reads
        .capture(
            &fixture.pool,
            &scope,
            &repo.backend,
            LEASE_SECONDS,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await;
    let elapsed = started.elapsed();
    ensure!(blocked.is_err(), "a capture blocked past its deadline must fail, not succeed");
    ensure!(elapsed < Duration::from_secs(5), "the capture outlived its absolute deadline by {elapsed:?}");
    ensure!(
        matches!(blocked, Err(RefStoreError::Timeout)),
        "a blocked capture must report the deadline, not a generic failure"
    );
    ensure!(
        expired_row_count(&fixture, repo.ready.repository_id).await? == 1,
        "a cleanup that could not run to completion must roll back, not half-delete"
    );

    blocker.batch_execute("ROLLBACK").await?;
    drop(blocker);
    let still_ok = reads.capture(&fixture.pool, &scope, &repo.backend, LEASE_SECONDS, operation_deadline()).await?;
    ensure!(still_ok.is_empty(), "the provisioned metadata_only repository must capture as empty");
    reads.release(&fixture.pool, &still_ok, operation_deadline()).await?;
    ensure!(
        expired_row_count(&fixture, repo.ready.repository_id).await? == 0,
        "the unblocked capture must drain the expired row it found"
    );
    fixture.teardown().await?;
    Ok(())
}
