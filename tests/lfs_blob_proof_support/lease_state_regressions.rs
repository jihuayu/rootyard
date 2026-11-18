//! Late-commit lease expiry, post-staging reauthorization, and chunked reopen regressions (`Refs #145`).

use deadpool_postgres::Pool;

use rootyard::lfs::blob_proof_publication::{LfsBlobRuntimeGate, LfsRepoRealm, PgLfsBlobStore};

use super::{RunningProdLfsServer, TestActor};

mod harness;
mod late_commit;
mod revocation_cases;

pub struct LeaseStateRegressionInput<'a> {
    pub srv: &'a RunningProdLfsServer,
    pub gate: &'a LfsBlobRuntimeGate,
    pub pool: &'a Pool,
    pub realm: &'a LfsRepoRealm,
    pub alice: &'a TestActor,
}

pub async fn exercise_lease_loss_late_commit_and_unprecreated_mid_upload_revocation(
    inp: LeaseStateRegressionInput<'_>,
) -> anyhow::Result<()> {
    let LeaseStateRegressionInput { srv, gate, pool, realm, alice } = inp;
    let pg = PgLfsBlobStore::new(pool.clone());
    late_commit::scenario_late_commit(&pg, pool, gate, realm, alice).await?;
    late_commit::scenario_http_late_completion(srv, &pg, pool, realm, alice).await?;
    for token_revocation in [false, true] {
        revocation_cases::scenario_unprecreated_revocation(srv, pool, realm, alice, token_revocation).await?;
    }
    revocation_cases::scenario_chunked_reopen(srv, pool, realm, alice).await
}
