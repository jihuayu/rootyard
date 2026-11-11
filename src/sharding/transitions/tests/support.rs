use crate::{
    AppState, config::Config, db, dispatch, metrics,
    sharding::{
        models::{RepoShardRoute, VolumeFenceMarker},
        router::load_or_init_repo_route,
    },
    storage::Storage,
};
use deadpool_postgres::{Pool, Transaction};
use std::{path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;

pub(super) static FENCE_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(super) fn state(pool: Pool, root: PathBuf) -> AppState {
    let config = Config {
        database_url: String::new(), data_dir: root, bind: "127.0.0.1:0".parse().unwrap(),
        git: PathBuf::from("/usr/local/bin/git"), max_request_bytes: 1024 * 1024,
        max_output_bytes: 1024 * 1024, max_concurrent_git: 1, git_timeout: Duration::from_secs(10),
        git_memory_bytes: 1024 * 1024 * 1024, max_repo_bytes: 1024 * 1024,
        max_pending_deliveries: 100, outbox_worker: false, metrics_bind: None,
    };
    let storage = Storage::open(&config).unwrap();
    AppState {
        mirror_primary: None, dispatch: dispatch::Signals::default(), config, pool, storage,
        hooks: None, transfer_metrics: Arc::new(metrics::TransferCounters::default()),
        git_slots: Arc::new(tokio::sync::Semaphore::new(1)),
    }
}

pub(super) async fn db_fixture() -> Option<(Pool, Pool, String, tempfile::TempDir)> {
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok()?;
    let schema = format!("cluster_transition_{}", Uuid::new_v4().simple());
    let base = db::pool(&base_url).unwrap();
    base.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA \"{schema}\"")).await.unwrap();
    let mut url = reqwest::Url::parse(&base_url).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = db::pool(url.as_str()).unwrap();
    db::migrate(&pool).await.unwrap();
    Some((base, pool, schema, tempfile::tempdir().unwrap()))
}

pub(super) async fn seed_repo(tx: &Transaction<'_>, owner: Uuid, name: &str) -> Uuid {
    let repo_id = Uuid::new_v4();
    tx.execute("INSERT INTO users(id,username) VALUES($1,'fixture') ON CONFLICT DO NOTHING", &[&owner]).await.unwrap();
    tx.execute("INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,$3,'ready')", &[&repo_id,&owner,&name]).await.unwrap();
    repo_id
}

pub(super) async fn seed_route(
    tx: &Transaction<'_>,
    owner: Uuid,
    name: &str,
) -> (Uuid, RepoShardRoute) {
    let repo_id = seed_repo(tx, owner, name).await;
    (repo_id, load_or_init_repo_route(tx, owner, repo_id).await.unwrap())
}

pub(super) fn route_marker(
    route: &RepoShardRoute,
    route_epoch: i64,
    fencing_token: i64,
    fenced_epoch: i64,
    storage_generation: i64,
    read_only_degraded: bool,
) -> VolumeFenceMarker {
    VolumeFenceMarker {
        version: 1, repository_id: route.repository_id,
        primary_node_id: route.primary_node_id.clone(), route_epoch, fencing_token, fenced_epoch,
        storage_generation, read_only_degraded,
        fenced_node_id: read_only_degraded.then(|| route.primary_node_id.clone()), updated_unix: 1,
    }
}

pub(super) fn read_marker(state: &AppState, repo_id: Uuid) -> VolumeFenceMarker {
    crate::sharding::fencing::read_volume_marker_at(&state.storage.repo_path(repo_id))
        .unwrap().unwrap()
}

pub(super) async fn transition_state(pool: &Pool, repo_id: Uuid) -> String {
    pool.get().await.unwrap().query_one(
        "SELECT state FROM shard_marker_transitions WHERE repository_id=$1 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
        &[&repo_id],
    ).await.unwrap().get(0)
}

pub(super) async fn drop_schema(base: Pool, schema: &str) {
    base.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
        .await
        .unwrap();
}
