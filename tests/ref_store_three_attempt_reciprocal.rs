//! Reciprocal operation locking through the native adapter and candidate M152.
use anyhow::{Context, Result, ensure};
use rootyard::{
    db,
    ref_store::{IssuerLane, OperationIdentity, OperationState, PgRefStore, RefStoreError, RequestDigest},
};
use std::{future::Future, pin::Pin, time::Duration};
use tokio::time::{Instant, sleep, timeout};
use tokio_postgres::{IsolationLevel, Transaction, error::SqlState};
use uuid::Uuid;

const WIRE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const PLAN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROOF: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[derive(Clone, Copy)]
struct Repository {
    id: Uuid,
    issuer: Uuid,
}

impl Repository {
    async fn ready(tx: &Transaction<'_>, issuer: Uuid, name: &str) -> Result<Self> {
        let id = Uuid::new_v4();
        let history = Uuid::new_v4();
        tx.execute(
            "INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format)
             VALUES ($1,$2,$3,'provisioning','pg_refstore','sha1')",
            &[&id, &issuer, &name],
        )
        .await?;
        tx.execute(
            "INSERT INTO ref_store_core_gates(repository_id,tenant_id,object_format,history_incarnation,
                  authority_epoch,group_epoch,head_ref,revision)
             VALUES ($1,$2,'sha1',$3,1,1,'refs/heads/main',6)",
            &[&id, &issuer, &history],
        )
        .await?;
        tx.execute(
            "INSERT INTO ref_store_core_protocol_repos(repository_id,tenant_id,object_format,
                  history_incarnation,authority_epoch,group_epoch,decision_required)
             VALUES ($1,$2,'sha1',$3,1,1,true)",
            &[&id, &issuer, &history],
        )
        .await?;
        tx.execute(
            "INSERT INTO ref_store_serving_repositories(repository_id,owner_id,name,object_format,
                  history_incarnation,authority_epoch,group_epoch,backend_identity,state)
             VALUES ($1,$2,$3,'sha1',$4,1,1,repeat('a',64),'pending')",
            &[&id, &issuer, &name, &history],
        )
        .await?;
        tx.execute("UPDATE ref_store_serving_repositories SET state='ready' WHERE repository_id=$1", &[&id]).await?;
        tx.execute("UPDATE repositories SET state='ready' WHERE id=$1", &[&id]).await?;
        Ok(Self { id, issuer })
    }
}

async fn wrapper(tx: &Transaction<'_>, repo: Repository, public: Uuid, private: Uuid) -> Result<()> {
    tx.query_one("SELECT rootyard_ref_store_lock_public_operation($1,$2,$3)", &[&repo.id, &public, &private]).await?;
    tx.execute(
        "INSERT INTO ref_store_public_operations(repository_id,public_id,admission_owner_id,issuer_id,wire_digest,
              request_mode,backend_identity,object_format,history_incarnation,authority_epoch,group_epoch,restore_incarnation)
         SELECT g.repository_id,$2,$3,$3,$4,'atomic',s.backend_identity,g.object_format,
                g.history_incarnation,g.authority_epoch,g.group_epoch,c.incarnation
         FROM ref_store_core_gates g JOIN ref_store_serving_repositories s USING (repository_id)
         CROSS JOIN cluster_authority c WHERE g.repository_id=$1 AND c.singleton",
        &[&repo.id, &public, &repo.issuer, &WIRE],
    )
    .await?;
    tx.execute(
        "INSERT INTO ref_store_private_attempts(repository_id,public_id,slot,private_id,plan_digest,proof_digest,base_revision)
         VALUES ($1,$2,0,$3,$4,$5,6)",
        &[&repo.id, &public, &private, &PLAN, &PROOF],
    )
    .await?;
    // Seed the private side under its normalized M152 locks. Calling the
    // legacy API for the already claimed private id would correctly refuse.
    let sequence: i64 = tx
        .query_one(
            "INSERT INTO ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence)
         VALUES ($1,$2,'stored-attempt',1) ON CONFLICT (repository_id,issuer_id,lane)
         DO UPDATE SET last_reserved_sequence=ref_store_issuer_lanes.last_reserved_sequence+1
         RETURNING last_reserved_sequence",
            &[&repo.id, &repo.issuer],
        )
        .await?
        .get(0);
    tx.execute(
        "INSERT INTO ref_store_operations(repository_id,issuer_id,lane,sequence,operation_id,request_digest,state)
         VALUES ($1,$2,'stored-attempt',$3,$4,$5,'pending')",
        &[&repo.id, &repo.issuer, &sequence, &private, &PLAN],
    )
    .await?;
    tx.execute(
        "INSERT INTO ref_store_serving_operations(repository_id,operation_id,issuer_id,producer_request_digest,plan_parent_digest)
         VALUES ($1,$2,$3,$4,$5)",
        &[&repo.id, &private, &repo.issuer, &WIRE, &PLAN],
    )
    .await?;
    Ok(())
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

async fn claimed(tx: &Transaction<'_>, repo: Uuid, operation: Uuid) -> Result<bool> {
    Ok(tx
        .query_one(
            "SELECT EXISTS (SELECT FROM ref_store_public_operations WHERE (repository_id,public_id)=($1,$2))
                 OR EXISTS (SELECT FROM ref_store_private_attempts WHERE (repository_id,private_id)=($1,$2))",
            &[&repo, &operation],
        )
        .await?
        .get(0))
}

#[derive(Clone, Copy, Debug)]
enum LegacyMutation {
    Reserve,
    Begin,
    Cancel,
}

impl LegacyMutation {
    fn lane_name(self) -> &'static str {
        match self {
            Self::Reserve => "refused-reserve",
            Self::Begin => "refused-begin",
            Self::Cancel => "refused-cancel",
        }
    }

    async fn invoke(self, tx: &Transaction<'_>, repo: Repository, operation: Uuid) -> Result<(), RefStoreError> {
        let lane = self.lane_name().parse()?;
        match self {
            Self::Reserve => {
                PgRefStore.reserve_sequence(tx, repo.id, repo.issuer, operation, &lane, deadline()).await?;
            }
            Self::Begin => {
                let identity = OperationIdentity::new(repo.id, repo.issuer, lane, 1, operation, WIRE.parse()?)?;
                PgRefStore.begin(tx, &identity, deadline()).await?;
            }
            Self::Cancel => {
                let identity = OperationIdentity::new(repo.id, repo.issuer, lane, 1, operation, WIRE.parse()?)?;
                PgRefStore.cancel(tx, &identity, deadline()).await?;
            }
        }
        Ok(())
    }
}

async fn legacy_begin(tx: &Transaction<'_>, repo: Repository, operation: Uuid) -> Result<()> {
    let lane: IssuerLane = "legacy-begin".parse()?;
    let reservation = PgRefStore.reserve_sequence(tx, repo.id, repo.issuer, operation, &lane, deadline()).await?;
    let identity = reservation.identity(WIRE.parse()?)?;
    let receipt = PgRefStore.begin(tx, &identity, deadline()).await?;
    ensure!(receipt.created && receipt.record.state() == OperationState::Pending);
    Ok(())
}

async fn legacy_cancel(tx: &Transaction<'_>, repo: Repository, operation: Uuid) -> Result<()> {
    let identity = OperationIdentity::new(repo.id, repo.issuer, "legacy-cancel".parse()?, 1, operation, WIRE.parse()?)?;
    ensure!(PgRefStore.cancel(tx, &identity, deadline()).await?.tombstone_created);
    Ok(())
}

async fn blocked<F: Future>(
    observer: &tokio_postgres::Client,
    blocked_pid: i32,
    winner_pid: i32,
    mut contender: Pin<&mut F>,
) -> Result<()> {
    let observe = async {
        loop {
            if observer
                .query_one("SELECT $2 = ANY(pg_blocking_pids($1))", &[&blocked_pid, &winner_pid])
                .await?
                .get::<_, bool>(0)
            {
                return Ok::<(), anyhow::Error>(());
            }
            sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::select! {
        result = timeout(Duration::from_secs(3), observe) => result.context("operation never waited on its reciprocal lock")?,
        _ = &mut contender => anyhow::bail!("contender completed before the winner released the operation lock"),
    }
}

async fn pid(tx: &Transaction<'_>) -> Result<i32> {
    Ok(tx.query_one("SELECT pg_backend_pid()", &[]).await?.get(0))
}

async fn nil_evidence(tx: &Transaction<'_>) -> Result<serde_json::Value> {
    Ok(tx
        .query_one(
            "SELECT jsonb_build_array(to_jsonb(o),to_jsonb(c))
             FROM ref_store_operations o JOIN ref_store_cancellations c USING(repository_id,operation_id)
             WHERE o.operation_id=$1",
            &[&Uuid::nil()],
        )
        .await?
        .get(0))
}

#[tokio::test]
#[ignore = "requires a fresh disposable loopback PostgreSQL 17 database"]
async fn actual_m138_adapter_and_three_attempt_wrapper_serialize_reciprocal_claims() -> Result<()> {
    ensure!(std::env::var("ROOTYARD_TEST_OWNED_DISPOSABLE_POSTGRES").as_deref() == Ok("1"));
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let config: tokio_postgres::Config = url.parse()?;
    ensure!(config.get_hosts() == [tokio_postgres::config::Host::Tcp("127.0.0.1".to_owned())]);
    ensure!(config.get_dbname().is_some_and(|name| name.starts_with("issue42_reciprocal_")));
    let pool = db::pool(&url)?;
    let mut observer = pool.get().await?;
    let version: i32 = observer.query_one("SHOW server_version_num", &[]).await?.get::<_, String>(0).parse()?;
    ensure!(version / 10_000 == 17);
    ensure!(
        observer.query_one("SELECT count(*) FROM pg_tables WHERE schemaname='public'", &[]).await?.get::<_, i64>(0)
            == 0
    );
    let initial = observer.transaction().await?;
    initial.batch_execute(include_str!("../migrations/001_initial.sql")).await?;
    for &(version, migration) in db::MIGRATIONS {
        if version <= 151 {
            initial.batch_execute(migration).await?;
        }
    }
    ensure!(initial.query_one("SELECT max(version) FROM schema_migrations", &[]).await?.get::<_, i32>(0) == 151);
    let issuer = Uuid::new_v4();
    initial.execute("INSERT INTO users(id,username) VALUES($1,'issue42-reciprocal')", &[&issuer]).await?;
    let repo = Repository::ready(&initial, issuer, "issue42-race").await?;
    let peer = Repository::ready(&initial, issuer, "issue42-peer").await?;
    initial.execute(
        "INSERT INTO ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence) VALUES ($1,$2,'historic-nil',1)",
        &[&repo.id, &issuer],
    ).await?;
    initial
        .execute(
            "INSERT INTO ref_store_cancellations(repository_id,issuer_id,lane,sequence,operation_id,request_digest)
         VALUES ($1,$2,'historic-nil',1,$3,$4)",
            &[&repo.id, &issuer, &Uuid::nil(), &PLAN],
        )
        .await?;
    initial.execute(
        "INSERT INTO ref_store_operations(repository_id,issuer_id,lane,sequence,operation_id,request_digest,state,terminal_result,terminal_at)
         VALUES ($1,$2,'historic-nil',1,$3,$4,'cancelled','{\"state\":\"cancelled\",\"reason\":\"cancel_requested\"}'::jsonb,clock_timestamp())",
        &[&repo.id, &issuer, &Uuid::nil(), &PLAN],
    ).await?;
    let historic = nil_evidence(&initial).await?;
    initial.commit().await?;
    db::migrate(&pool).await?;
    ensure!(observer.query_one("SELECT max(version) FROM schema_migrations", &[]).await?.get::<_, i32>(0) == 152);
    ensure!(
        observer
            .query_one("SELECT to_regclass('ref_store_attempt_retirements') IS NOT NULL", &[],)
            .await?
            .get::<_, bool>(0)
    );
    ensure!(
        OperationIdentity::new(
            repo.id,
            issuer,
            "historic-nil".parse()?,
            1,
            Uuid::nil(),
            PLAN.parse::<RequestDigest>()?
        )
        .is_err()
    );

    let mut first = pool.get().await?;
    let mut second = pool.get().await?;
    for action in [LegacyMutation::Reserve, LegacyMutation::Begin, LegacyMutation::Cancel] {
        for claim_public in [true, false] {
            let [public, private] = [Uuid::new_v4(), Uuid::new_v4()];
            let shared = if claim_public { public } else { private };
            let win = first.transaction().await?;
            wrapper(&win, repo, public, private).await?;
            let lose = second.transaction().await?;
            ensure!(!claimed(&lose, repo.id, shared).await?, "uncommitted candidate claim was visible");
            {
                let task = action.invoke(&lose, repo, shared);
                tokio::pin!(task);
                blocked(&observer, pid(&lose).await?, pid(&win).await?, task.as_mut()).await?;
                win.commit().await?;
                let error = task.await.expect_err("legacy guard admitted a current wrapper identity");
                ensure!(matches!(error, RefStoreError::IdentityConflict), "{action:?} refused for a different reason");
            }
            ensure!(claimed(&lose, repo.id, shared).await?);
            ensure!(
                lose.query_one(
                    "SELECT NOT EXISTS(SELECT FROM ref_store_issuer_lanes
                         WHERE repository_id=$1 AND issuer_id=$2 AND lane=$3)",
                    &[&repo.id, &repo.issuer, &action.lane_name()],
                )
                .await?
                .get::<_, bool>(0),
                "refused {action:?} allocated its issuer lane before rollback"
            );
            lose.rollback().await?;
            let reused = second.transaction().await?;
            legacy_begin(&reused, peer, shared).await?;
            reused.commit().await?;
        }
    }

    for claim_public in [true, false] {
        let [public, private] = [Uuid::new_v4(), Uuid::new_v4()];
        let shared = if claim_public { public } else { private };
        let win = first.transaction().await?;
        if claim_public {
            legacy_begin(&win, repo, shared).await?;
        } else {
            legacy_cancel(&win, repo, shared).await?;
        }
        let lose = second.transaction().await?;
        {
            let task = wrapper(&lose, repo, public, private);
            tokio::pin!(task);
            blocked(&observer, pid(&lose).await?, pid(&win).await?, task.as_mut()).await?;
            win.commit().await?;
            let error = task.await.expect_err("candidate claimed an existing legacy identifier");
            let postgres = error.downcast_ref::<tokio_postgres::Error>().context("expected database refusal")?;
            ensure!(postgres.code() == Some(&SqlState::UNIQUE_VIOLATION));
        }
        lose.rollback().await?;
        let read = first.transaction().await?;
        ensure!(!claimed(&read, repo.id, public).await?);
        ensure!(!claimed(&read, repo.id, private).await?);
        read.rollback().await?;
    }

    let repeatable = first.build_transaction().isolation_level(IsolationLevel::RepeatableRead).start().await?;
    let error = LegacyMutation::Reserve
        .invoke(&repeatable, repo, Uuid::new_v4())
        .await
        .expect_err("stale transaction admitted");
    ensure!(
        matches!(error, RefStoreError::Database(message) if message == "legacy operation UUID checks require read committed")
    );
    repeatable.rollback().await?;
    let last = first.transaction().await?;
    ensure!(nil_evidence(&last).await? == historic);
    last.rollback().await?;
    println!(
        "verified eight PG17 waits: native reserve, begin and cancel each refused public/private owners; M152 refused prior legacy begin(public) and cancel(private)"
    );
    println!("verified cross-repository identity reuse, repeatable-read refusal, and unchanged historical nil rows");
    Ok(())
}
