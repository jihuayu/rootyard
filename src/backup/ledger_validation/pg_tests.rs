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

/// Step-7 `undeclared` fallback when `declared_query(false)` cannot see a
/// repository's packs because `repositories.storage_backend != 'pg_refstore'`
/// (`missing.len() >= 2`) or the `public.repositories` row is absent
/// (`missing.len() == 1`). Both must bind `$1::uuid[]` cleanly, recover the
/// `scoped` rows via `declared_query(true)` and return a typed
/// `LedgerValidationRefusal` rather than a SQL parameter/read error.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL seeded by ref_store_format22_backup_fixture"]
async fn non_pg_refstore_and_missing_repository_undeclared_packs_are_refused() -> Result<()> {
    // 1. Multi-item `missing.len() >= 2`: flip every `pg_refstore` repository to `gitfs`.
    {
        let mut client = connect().await?;
        let tx = repeatable_read(&mut client).await?;
        tx.query_one("SELECT pg_advisory_xact_lock(16900169)", &[]).await?;
        tx.batch_execute("SET LOCAL session_replication_role = replica").await?;
        let undeclared_count: i64 = tx
            .query_one(
                "SELECT count(DISTINCT registration_id) FROM (
                   SELECT p.registration_id FROM public.ref_store_core_snapshot_packs p
                     JOIN public.ref_store_core_snapshots s ON s.snapshot_id=p.snapshot_id
                    WHERE s.pack_mode='pack_verified'
                   UNION SELECT registration_id FROM public.ref_store_core_root_packs
                   UNION SELECT p.registration_id FROM public.ref_store_core_serving_read_packs p
                     JOIN public.ref_store_core_serving_reads s ON s.pin_id=p.pin_id
                 ) u",
                &[],
            )
            .await?
            .get(0);
        ensure!(
            undeclared_count >= 2,
            "expected >= 2 declared snapshot/root/serving registrations, got {undeclared_count}"
        );
        let changed = tx
            .execute("UPDATE public.repositories SET storage_backend='gitfs' WHERE storage_backend='pg_refstore'", &[])
            .await?;
        ensure!(changed >= 1, "expected at least one pg_refstore repository");
        let outcome = validate_source(&tx, deadline()).await;
        tx.rollback().await?;
        let error = outcome.expect_err("non-pg_refstore repository owning RefStore packs must be refused");
        let refusal = error.downcast::<LedgerValidationRefusal>().map_err(|error| {
            error.context("validator did not return typed refusal for non-pg_refstore undeclared packs")
        })?;
        ensure!(
            refusal.codes().contains(&"publication_binding_mismatch"),
            "expected publication_binding_mismatch, got {:?} ({})",
            refusal.codes(),
            refusal.diagnostic()
        );
    }

    // 2. Single-item `missing.len() == 1` present in `scoped`: isolate one snapshot
    // registration on its repository and delete that repository row.
    {
        let mut client = connect().await?;
        let tx = repeatable_read(&mut client).await?;
        tx.query_one("SELECT pg_advisory_xact_lock(16900169)", &[]).await?;
        tx.batch_execute("SET LOCAL session_replication_role = replica").await?;
        let row = tx
            .query_one(
                "SELECT s.repository_id,p.registration_id
                   FROM public.ref_store_core_snapshots s
                   JOIN public.ref_store_core_snapshot_packs p ON p.snapshot_id=s.snapshot_id
                   JOIN public.repositories r ON r.id=s.repository_id AND r.storage_backend='pg_refstore'
                  WHERE s.pack_mode='pack_verified'
                  ORDER BY s.repository_id,p.registration_id LIMIT 1",
                &[],
            )
            .await?;
        let repo_id: Uuid = row.get(0);
        let reg_id: Uuid = row.get(1);
        tx.execute(
            "DELETE FROM public.ref_store_core_snapshot_packs WHERE repository_id=$1 AND registration_id<>$2",
            &[&repo_id, &reg_id],
        )
        .await?;
        for table in [
            "ref_store_core_root_packs",
            "ref_store_core_root_refs",
            "ref_store_core_root_oids",
            "ref_store_core_roots",
            "ref_store_core_root_heads",
            "ref_store_core_root_tombstones",
        ] {
            tx.execute(&format!("DELETE FROM public.{table} WHERE repository_id=$1"), &[&repo_id]).await?;
        }
        for child in [
            "ref_store_core_serving_read_packs",
            "ref_store_core_serving_read_artifacts",
            "ref_store_core_serving_read_refs",
        ] {
            tx.execute(
                &format!(
                    "DELETE FROM public.{child} c USING public.ref_store_core_serving_reads s
                      WHERE c.pin_id=s.pin_id AND s.repository_id=$1"
                ),
                &[&repo_id],
            )
            .await?;
        }
        tx.execute("DELETE FROM public.ref_store_core_serving_reads WHERE repository_id=$1", &[&repo_id]).await?;
        let deleted = tx.execute("DELETE FROM public.repositories WHERE id=$1", &[&repo_id]).await?;
        ensure!(deleted == 1, "expected to delete exactly one repository row");
        let outcome = validate_source(&tx, deadline()).await;
        tx.rollback().await?;
        let error = outcome.expect_err("deleted repository row owning a snapshot pack must be refused");
        let refusal = error
            .downcast::<LedgerValidationRefusal>()
            .map_err(|error| error.context("validator did not return typed refusal for missing repository row"))?;
        ensure!(
            refusal.codes().contains(&"publication_binding_mismatch"),
            "expected publication_binding_mismatch, got {:?} ({})",
            refusal.codes(),
            refusal.diagnostic()
        );
    }
    Ok(())
}

/// Step-7 `undeclared` fallback when `missing` contains 1 or >= 2 registration
/// ids absent from `scoped` altogether, plus an orphan `serving_read_packs`
/// child row whose `ref_store_core_serving_reads` header was deleted.
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL seeded by ref_store_format22_backup_fixture"]
async fn repointed_undeclared_registrations_and_orphan_serving_read_packs_are_refused() -> Result<()> {
    let registration = registered_pack().await?;
    // 1. Single unknown registration_id (`missing.len() == 1`, 0 rows in `scoped`).
    assert_refused(
        "UPDATE public.ref_store_core_snapshot_packs SET registration_id=gen_random_uuid()
          WHERE ctid=(SELECT ctid FROM public.ref_store_core_snapshot_packs WHERE registration_id=$1 LIMIT 1)",
        registration,
        "unregistered_publication",
    )
    .await?;

    // 2. Multiple unknown registration_ids (`missing.len() >= 2`, 0 rows in `scoped`).
    {
        let mut client = connect().await?;
        let tx = repeatable_read(&mut client).await?;
        tx.query_one("SELECT pg_advisory_xact_lock(16900169)", &[]).await?;
        tx.batch_execute("SET LOCAL session_replication_role = replica").await?;
        let c1 = tx
            .execute(
                "UPDATE public.ref_store_core_snapshot_packs SET registration_id=gen_random_uuid()
                  WHERE ctid=(SELECT ctid FROM public.ref_store_core_snapshot_packs LIMIT 1)",
                &[],
            )
            .await?;
        let c2 = tx
            .execute(
                "UPDATE public.ref_store_core_serving_read_packs SET registration_id=gen_random_uuid()
                  WHERE ctid=(SELECT ctid FROM public.ref_store_core_serving_read_packs LIMIT 1)",
                &[],
            )
            .await?;
        ensure!(c1 == 1 && c2 == 1, "expected to re-point one snapshot pack and one serving-read pack");
        let outcome = validate_source(&tx, deadline()).await;
        tx.rollback().await?;
        let error = outcome.expect_err("re-pointed undeclared registrations must be refused");
        let refusal = error
            .downcast::<LedgerValidationRefusal>()
            .map_err(|error| error.context("validator did not return typed refusal for >= 2 unknown registrations"))?;
        ensure!(
            refusal.codes().contains(&"unregistered_publication"),
            "expected unregistered_publication, got {:?} ({})",
            refusal.codes(),
            refusal.diagnostic()
        );
    }

    // 3. Orphan `serving_read_packs` row whose `pin_id` has no header in `ref_store_core_serving_reads`.
    {
        let mut client = connect().await?;
        let tx = repeatable_read(&mut client).await?;
        tx.query_one("SELECT pg_advisory_xact_lock(16900169)", &[]).await?;
        tx.batch_execute("SET LOCAL session_replication_role = replica").await?;
        let deleted = tx
            .execute(
                "DELETE FROM public.ref_store_core_serving_reads
                  WHERE pin_id IN (SELECT pin_id FROM public.ref_store_core_serving_read_packs)",
                &[],
            )
            .await?;
        ensure!(deleted >= 1, "expected at least one serving read header with pack rows");
        let outcome = validate_source(&tx, deadline()).await;
        tx.rollback().await?;
        let error = outcome.expect_err("orphan serving_read_packs row must be refused");
        let refusal = error
            .downcast::<LedgerValidationRefusal>()
            .map_err(|error| error.context("validator did not return typed refusal for orphan serving_read_packs"))?;
        ensure!(
            refusal.codes().contains(&"serving_read_orphan"),
            "expected serving_read_orphan, got {:?} ({})",
            refusal.codes(),
            refusal.diagnostic()
        );
    }
    Ok(())
}
