//! Real PostgreSQL coverage for the paired-archive source validator (issue #169).
//!
//! Run against the API-seeded format22 database written by
//! `ref_store_format22_backup_fixture --seed`:
//!
//! ```text
//! ROOTYARD_TEST_DATABASE_URL=postgresql://.../rootyard_fmt22 \
//! cargo test --locked --lib --features pando-lab \
//!   backup::ledger_validation::pg_tests -- --ignored --nocapture
//! ```
//!
//! The positive case validates the clean seeded cut and enumerates its exact
//! pair inventory on the same `REPEATABLE READ` transaction. Every negative case
//! opens its own `REPEATABLE READ` transaction, disables replication triggers
//! with `SET LOCAL session_replication_role=replica`, mutates exactly one
//! registered pack and rolls back, so each case starts from the clean source.
use super::{LedgerValidationRefusal, validate_source};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::time::Instant;
use tokio_postgres::{Client, IsolationLevel, NoTls, Transaction};
use uuid::Uuid;

const DECLARED: &str = "WITH declared AS (
       SELECT p.registration_id,p.repository_id FROM public.ref_store_core_pack_memberships p
        UNION SELECT p.registration_id,p.repository_id FROM public.ref_store_core_snapshot_packs p
        UNION SELECT p.registration_id,p.repository_id FROM public.ref_store_core_root_packs p
        UNION SELECT p.registration_id,s.repository_id FROM public.ref_store_core_serving_read_packs p
               JOIN public.ref_store_core_serving_reads s ON s.pin_id=p.pin_id)
     SELECT d.registration_id FROM declared d
       JOIN public.repositories r ON r.id=d.repository_id AND r.storage_backend='pg_refstore'";

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set to run the seeded format22 pg_tests")
}

async fn connect() -> Result<Client> {
    let (client, connection) = tokio_postgres::connect(&database_url(), NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

async fn repeatable_read<'a>(client: &'a mut Client) -> Result<Transaction<'a>> {
    let tx = client.build_transaction().isolation_level(IsolationLevel::RepeatableRead).start().await?;
    let level: String = tx.query_one("SHOW transaction_isolation", &[]).await?.get(0);
    ensure!(level == "repeatable read", "seed transaction is not REPEATABLE READ");
    Ok(tx)
}

/// The first declared registration with exactly one legal `pack`/`idx` pair,
/// read independently of the production declared-set SQL.
async fn registered_pack() -> Result<Uuid> {
    let sql = format!(
        "WITH declared AS (SELECT d.registration_id FROM ({DECLARED}) d)
         SELECT a.registration_id
           FROM public.ref_store_core_pack_artifacts a JOIN declared d USING (registration_id)
          GROUP BY a.registration_id
         HAVING count(*)=2
            AND count(*) FILTER (WHERE a.role='pack' AND a.slot=0)=1
            AND count(*) FILTER (WHERE a.role='idx' AND a.slot=1)=1
         ORDER BY a.registration_id LIMIT 1"
    );
    let client = connect().await?;
    Ok(client.query_one(&sql, &[]).await?.get(0))
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL seeded by ref_store_format22_backup_fixture"]
async fn clean_seeded_format22_passes_and_inventory_lists_exact_pairs() -> Result<()> {
    let mut client = connect().await?;
    let tx = client.build_transaction().isolation_level(IsolationLevel::RepeatableRead).read_only(true).start().await?;
    let level: String = tx.query_one("SHOW transaction_isolation", &[]).await?.get(0);
    ensure!(level == "repeatable read", "positive cut is not REPEATABLE READ");
    tx.query_one("SELECT pg_advisory_xact_lock(16900169)", &[]).await?;

    // The real fixture shape, observed on this same cut: a multi-pack bound
    // repository, genuinely empty/unrelated repositories, both root states, a
    // producer owner distinct from the repository tenant, and a live serving
    // read with at least one captured pack.
    let shape = tx
        .query_one(
            "SELECT (SELECT count(*) FROM public.repositories WHERE storage_backend='pg_refstore'),
                    (SELECT count(DISTINCT registration_id) FROM public.ref_store_core_pack_artifacts),
                    (SELECT count(*) FROM public.repositories r WHERE r.storage_backend='pg_refstore'
                       AND NOT EXISTS (SELECT 1 FROM public.ref_store_core_pack_artifacts a WHERE a.repository_id=r.id)),
                    (SELECT count(*) FROM public.ref_store_core_root_heads WHERE state='active'),
                    (SELECT count(*) FROM public.ref_store_core_root_heads WHERE state='released'),
                    (SELECT count(*) FROM public.ref_store_core_pack_publications p
                       JOIN public.repositories r ON r.id=p.repository_id WHERE p.owner_id<>r.owner_id),
                    (SELECT count(*) FROM public.ref_store_core_serving_reads s
                       WHERE EXISTS (SELECT 1 FROM public.ref_store_core_serving_read_packs p WHERE p.pin_id=s.pin_id))",
            &[],
        )
        .await?;
    ensure!(shape.get::<_, i64>(0) >= 3, "fixture has fewer than three pg_refstore repositories");
    ensure!(shape.get::<_, i64>(1) >= 3, "fixture is not multi-pack");
    ensure!(shape.get::<_, i64>(2) >= 1, "fixture has no empty repository");
    ensure!(shape.get::<_, i64>(3) >= 1, "fixture has no active root");
    ensure!(shape.get::<_, i64>(4) >= 1, "fixture has no released root");
    ensure!(shape.get::<_, i64>(5) >= 1, "fixture producer owner equals the repository tenant");
    ensure!(shape.get::<_, i64>(6) >= 1, "fixture has no live serving-read pack capture");

    validate_source(&tx, deadline()).await.context("clean API-seeded format22 state was refused")?;

    let declared = tx.query(DECLARED, &[]).await?.into_iter().map(|row| row.get::<_, Uuid>(0)).collect::<BTreeSet<_>>();
    ensure!(!declared.is_empty(), "fixture declares no pack");
    let backend: String =
        tx.query_one("SELECT backend_identity FROM public.ref_store_serving_repositories LIMIT 1", &[]).await?.get(0);
    let provider: String =
        tx.query_one("SELECT provider FROM public.ref_store_core_pack_artifacts LIMIT 1", &[]).await?.get(0);
    let registrations = declared.iter().copied().collect::<Vec<_>>();
    let expected = tx
        .query(
            "SELECT a.registration_id,a.repository_id,a.pack_id,a.role,a.slot
               FROM public.ref_store_core_pack_artifacts a
              WHERE a.registration_id=ANY($1) ORDER BY a.registration_id,a.role",
            &[&registrations as &(dyn tokio_postgres::types::ToSql + Sync)],
        )
        .await?
        .into_iter()
        .map(|row| {
            (
                row.get::<_, Uuid>(0),
                row.get::<_, Uuid>(1),
                row.get::<_, Uuid>(2),
                row.get::<_, String>(3),
                row.get::<_, i32>(4),
            )
        })
        .collect::<BTreeSet<_>>();
    ensure!(
        expected.len() == declared.len() * 2,
        "the seeded artifacts are not exactly one pack+idx pair per registration"
    );
    for registration in &declared {
        let rows = expected.iter().filter(|row| row.0 == *registration).collect::<Vec<_>>();
        ensure!(
            rows.len() == 2
                && rows.iter().any(|row| row.3 == "pack" && row.4 == 0)
                && rows.iter().any(|row| row.3 == "idx" && row.4 == 1),
            "registration {registration} is not exactly pack/0 + idx/1"
        );
    }
    let actual = super::super::ledger::inventory(&tx, &backend, &provider, deadline())
        .await?
        .into_iter()
        .map(|artifact| {
            (artifact.registration_id, artifact.repository_id, artifact.pack_id, artifact.role, artifact.slot)
        })
        .collect::<BTreeSet<_>>();
    ensure!(actual == expected, "inventory did not enumerate the exact declared pack+idx pairs");
    tx.rollback().await?;
    Ok(())
}

/// One isolated corruption: mutate, validate on that transaction, then roll
/// back before inspecting the typed refusal so the next case starts clean.
async fn assert_refused(sql: &str, registration: Uuid, expected: &str) -> Result<()> {
    let mut client = connect().await?;
    let tx = repeatable_read(&mut client).await?;
    tx.query_one("SELECT pg_advisory_xact_lock(16900169)", &[]).await?;
    tx.batch_execute("SET LOCAL session_replication_role = replica").await?;
    let changed = tx.execute(sql, &[&registration as &(dyn tokio_postgres::types::ToSql + Sync)]).await?;
    ensure!(changed >= 1, "corruption matched no row for {registration}");
    let outcome = validate_source(&tx, deadline()).await;
    tx.rollback().await?;
    let error = outcome.expect_err("a corrupted source must be refused");
    let refusal = error.downcast::<LedgerValidationRefusal>().map_err(|error| {
        error.context(format!("validator did not return the typed ledger refusal (expected {expected})"))
    })?;
    ensure!(
        refusal.codes().contains(&expected),
        "expected violation token {expected}, got {:?} ({})",
        refusal.codes(),
        refusal.diagnostic()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL seeded by ref_store_format22_backup_fixture"]
async fn missing_pack_artifact_is_refused() -> Result<()> {
    let registration = registered_pack().await?;
    assert_refused(
        "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id=$1 AND role='pack'",
        registration,
        "incomplete_pair",
    )
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL seeded by ref_store_format22_backup_fixture"]
async fn missing_idx_artifact_is_refused() -> Result<()> {
    let registration = registered_pack().await?;
    assert_refused(
        "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id=$1 AND role='idx'",
        registration,
        "incomplete_pair",
    )
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL seeded by ref_store_format22_backup_fixture"]
async fn missing_all_artifacts_is_refused() -> Result<()> {
    let registration = registered_pack().await?;
    assert_refused(
        "DELETE FROM public.ref_store_core_pack_artifacts WHERE registration_id=$1",
        registration,
        "missing_artifacts",
    )
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL seeded by ref_store_format22_backup_fixture"]
async fn tampered_artifact_set_digest_is_refused() -> Result<()> {
    let registration = registered_pack().await?;
    assert_refused(
        "UPDATE public.ref_store_core_pack_publications
            SET artifact_set_digest=CASE WHEN artifact_set_digest=repeat('0',64)
                THEN repeat('1',64) ELSE repeat('0',64) END
          WHERE registration_id=$1",
        registration,
        "declared_set_digest_mismatch",
    )
    .await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL seeded by ref_store_format22_backup_fixture"]
async fn mismatched_hold_locator_and_slot_are_refused() -> Result<()> {
    let registration = registered_pack().await?;
    for sql in [
        "UPDATE public.artifact_holds h SET storage_tenant_id=gen_random_uuid()
           WHERE h.hold_id IN (SELECT hold_id FROM public.ref_store_core_pack_artifacts
                                WHERE registration_id=$1 AND role='pack')",
        "UPDATE public.artifact_holds h SET sha256=CASE WHEN sha256=repeat('a',64)
             THEN repeat('b',64) ELSE repeat('a',64) END
           WHERE h.hold_id IN (SELECT hold_id FROM public.ref_store_core_pack_artifacts
                                WHERE registration_id=$1 AND role='pack')",
        "UPDATE public.artifact_holds h SET slot=h.slot+2
           WHERE h.hold_id IN (SELECT hold_id FROM public.ref_store_core_pack_artifacts
                                WHERE registration_id=$1 AND role='pack')",
    ] {
        assert_refused(sql, registration, "hold_mismatch").await?;
    }
    Ok(())
}

/// The durable hold is LEFT JOINed, so deleting it makes every `h.*` column
/// NULL. The decoder must fail closed with the typed ledger refusal instead of
/// calling `Row::get` for a non-Option locator column.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL seeded by ref_store_format22_backup_fixture"]
async fn deleted_hold_row_is_refused_without_panicking() -> Result<()> {
    let registration = registered_pack().await?;
    assert_refused(
        "DELETE FROM public.artifact_holds h
           WHERE h.hold_id IN (SELECT hold_id FROM public.ref_store_core_pack_artifacts
                                WHERE registration_id=$1 AND role='pack')",
        registration,
        "hold_mismatch",
    )
    .await
}

/// A tampered `request_id` breaks the hold's join key on the LEFT JOIN exactly
/// like a missing row, yielding NULL `h.*` columns for every locator field.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL seeded by ref_store_format22_backup_fixture"]
async fn repointed_hold_request_id_is_refused_without_panicking() -> Result<()> {
    let registration = registered_pack().await?;
    assert_refused(
        "UPDATE public.artifact_holds h SET request_id=gen_random_uuid()
           WHERE h.hold_id IN (SELECT hold_id FROM public.ref_store_core_pack_artifacts
                                WHERE registration_id=$1 AND role='pack')",
        registration,
        "hold_mismatch",
    )
    .await
}
