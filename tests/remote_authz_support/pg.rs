//! Ephemeral isolated PostgreSQL 17 schema helpers for #152 remote authz bridge tests.

use anyhow::{Context, Result};
use deadpool_postgres::{Manager, Pool};
use rootyard::db;
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub struct TestPgEnv {
    admin: Pool,
    pub pool: Pool,
    schema: String,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
}

pub struct SeedPgDecision<'a> {
    pub decision_id: Uuid,
    pub actor_id: Uuid,
    pub operation_id: Uuid,
    pub issuer_id: Uuid,
    pub lane: &'a str,
    pub sequence: i64,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub base_revision: i64,
    pub base_gate_digest: &'a str,
    pub command_digest: &'a str,
    pub ref_name: &'a str,
    pub new_oid_hex: &'a str,
    pub scope_kind: &'a str,
    pub scope_id: Uuid,
    pub observed_version: i64,
    pub observed_digest: &'a str,
    pub state: &'a str,
}

impl TestPgEnv {
    pub async fn setup() -> Result<Self> {
        let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")
            .context("ROOTYARD_TEST_DATABASE_URL must be set for ignored PG17 E2E tests")?;
        let admin = db::pool(&url)?;
        let schema = format!("raft_authz152_{}", Uuid::new_v4().simple());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
        let mut cfg: tokio_postgres::Config = url.parse()?;
        cfg.options(format!(
            "-c search_path={schema} -c timezone=UTC -c statement_timeout=15000 -c lock_timeout=10000"
        ));
        let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(10)
            .build()?;
        db::migrate(&pool).await?;
        let tenant_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let slug = format!("a152_{}", &tenant_id.simple().to_string()[..10]);
        let client = pool.get().await?;
        client.execute("INSERT INTO users(id, username) VALUES($1, $2)", &[&tenant_id, &slug]).await?;
        client
            .execute(
                "INSERT INTO repositories(id, owner_id, name, state, object_format) VALUES($1, $2, 'authz-demo', 'ready', 'sha256')",
                &[&repo_id, &tenant_id],
            )
            .await?;
        Ok(Self { admin, pool, schema, tenant_id, repo_id })
    }

    pub async fn teardown(self) {
        if let Ok(c) = self.admin.get().await {
            let _ = c.batch_execute(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema)).await;
        }
    }

    pub async fn seed_scope(
        &self,
        scope_kind: &str,
        scope_id: Uuid,
        version: i64,
        state: &str,
        change_id: Option<Uuid>,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id)
                 VALUES($1, $2, $3, $4, $5)
                 ON CONFLICT (scope_kind, scope_id) DO UPDATE
                 SET version = EXCLUDED.version, state = EXCLUDED.state, change_id = EXCLUDED.change_id",
                &[&scope_kind, &scope_id, &version, &state, &change_id],
            )
            .await?;
        Ok(())
    }

    pub async fn transition_scope_closing(
        &self,
        scope_kind: &str,
        scope_id: Uuid,
        version: i64,
        change_id: Uuid,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE ref_store_decision_scopes
                 SET state = 'CLOSING', version = $3, change_id = $4, updated_at = clock_timestamp()
                 WHERE scope_kind = $1 AND scope_id = $2",
                &[&scope_kind, &scope_id, &version, &change_id],
            )
            .await?;
        Ok(())
    }

    pub async fn seed_decision(&self, d: &SeedPgDecision<'_>) -> Result<()> {
        let client = self.pool.get().await?;
        self.seed_decision_on(&**client, d).await
    }

    pub async fn seed_decision_on<C: GenericClient + Sync>(&self, client: &C, d: &SeedPgDecision<'_>) -> Result<()> {
        let d_zero = super::fixtures::hex_digest(0xaa);
        let tok_id = Uuid::new_v4();
        let receipt_opt: Option<Uuid> = (d.state == "CONSUMED").then(Uuid::new_v4);
        client
            .execute(
                "INSERT INTO ref_store_publication_decisions(
                    decision_id, repository_id, tenant_id, owner_id, actor_id, token_id, token_digest,
                    operation_id, issuer_id, lane, sequence, mode, action, object_format,
                    history_incarnation, authority_epoch, group_epoch, base_revision,
                    base_gate_digest, command_digest, refs_digest, selected_refs_digest,
                    selection_digest, policy_digest, facts_digest, authz_digest,
                    dependencies_digest, packs_digest, hold_receipts_digest, captured_oid_digest,
                    not_after_millis, created_db_millis, state, consume_receipt_id,
                    consumed_at, rejected_at
                ) VALUES (
                    $1, $2, $3, $3, $4, $5, $6,
                    $7, $8, $9, $10, 'atomic', 'push', 'sha256',
                    $11, $12, $13, $14,
                    $18, $15, $6, $6,
                    $6, $6, $6, $6,
                    $6, $6, $6, $6,
                    2000000000, 1000000000, $16, $17,
                    CASE WHEN $16 = 'CONSUMED' THEN clock_timestamp() ELSE NULL END,
                    CASE WHEN $16 = 'REJECTED' THEN clock_timestamp() ELSE NULL END
                )",
                &[
                    &d.decision_id,
                    &self.repo_id,
                    &self.tenant_id,
                    &d.actor_id,
                    &tok_id,
                    &d_zero,
                    &d.operation_id,
                    &d.issuer_id,
                    &d.lane,
                    &d.sequence,
                    &d.history_incarnation,
                    &d.authority_epoch,
                    &d.group_epoch,
                    &d.base_revision,
                    &d.command_digest,
                    &d.state,
                    &receipt_opt,
                    &d.base_gate_digest,
                ],
            )
            .await?;

        let old_zero = "00".repeat(32);
        client
            .execute(
                "INSERT INTO ref_store_decision_refs(
                    decision_id, ref_ordinal, ref_name, verdict, reject_code, old_oid, new_oid, selection_verdict
                ) VALUES ($1, 0, $2, 'accept', NULL, $3, $4, 'accepted')",
                &[&d.decision_id, &d.ref_name, &old_zero, &d.new_oid_hex],
            )
            .await?;

        client
            .execute(
                "INSERT INTO ref_store_decision_dependencies(
                    decision_id, scope_kind, scope_id, observed_version, observed_digest
                ) VALUES ($1, $2, $3, $4, $5)",
                &[&d.decision_id, &d.scope_kind, &d.scope_id, &d.observed_version, &d.observed_digest],
            )
            .await?;
        Ok(())
    }

    pub async fn insert_cancellation(
        &self,
        op_id: Uuid,
        decision_id: Option<Uuid>,
        req_digest: &str,
        actor_id: Uuid,
        reason: &str,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO ref_store_decision_cancellations(
                    repository_id, operation_id, decision_id, request_digest, actor_id, reason
                ) VALUES ($1, $2, $3, $4, $5, $6)",
                &[&self.repo_id, &op_id, &decision_id, &req_digest, &actor_id, &reason],
            )
            .await?;
        Ok(())
    }

    pub async fn skew_clock_and_timezone(&self, tz: &str, hours_offset: i32) -> Result<()> {
        let client = self.pool.get().await?;
        client.batch_execute(&format!("SET TIME ZONE '{tz}'")).await?;
        client
            .execute(
                "UPDATE ref_store_decision_scopes SET updated_at = updated_at + make_interval(hours => $1)",
                &[&hours_offset],
            )
            .await?;
        Ok(())
    }
}
