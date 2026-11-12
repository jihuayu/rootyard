//! The seed entrypoint: real API-produced format22 source in fixture order.
use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::core::retention_root::PgRetentionRoots;
use serde_json::{Value, json};
use uuid::Uuid;

use super::super::db::{Db, deadline};
use super::super::{http, marker, pack, repo, roots};
use super::identity::{authenticate, grant_producer, issued_user, provision_with, write_volume_identity};
use super::packs::{current_gate, packs, serving_read_capture};
use super::{Options, PACKS, ROOT_SLOTS};

pub async fn run(options: &Options) -> Result<Value> {
    ensure!(options.git.is_absolute() && options.git.is_file(), "--git must be an absolute existing Git binary");
    ensure!(
        std::env::var("ROOTYARD_BLOB_ROOT").ok().as_deref() == Some(options.blob_root.as_str()),
        "ROOTYARD_BLOB_ROOT must equal --blob-root"
    );
    let profile = BlobProfile::from_env().map_err(|_| anyhow!("a supported Blob profile is required"))?;
    let store = BlobStore::open(profile).map_err(|_| anyhow!("the Blob backend could not be opened"))?;
    write_volume_identity(&options.data_dir)?;
    // The paired harness already migrated this fresh run-owned database in
    // `public`; the product backup source validator reads explicit `public.*`
    // tables, so the seed must live there too (never in a random schema).
    let db = Db::setup_public().await?;
    let http = http::Http::open(&db, &options.git, &options.data_dir).await?;

    // 1. The bound repository through the real create path. Every user row
    //    exists before its token: a refusal never orphans a credential.
    let owner_user = issued_user(&db.pool, "fmt22owner").await?;
    let producer_user = issued_user(&db.pool, "fmt22producer").await?;
    let reader_user = issued_user(&db.pool, "fmt22reader").await?;
    let owner = authenticate(&db.pool, &owner_user).await?;
    let producer_identity = authenticate(&db.pool, &producer_user).await?;
    let reader = authenticate(&db.pool, &reader_user).await?;
    let producer = producer_user.user_id;
    ensure!(producer != owner.id, "the producer must be a different real user than the repository owner");
    ensure!(
        reader.id != owner.id && reader.id != producer,
        "the serving-read requester must be a third real user, distinct from the tenant and the producer"
    );
    let repo_id = provision_with(&db.pool, &owner, "bound", &store).await?;
    let tenant = owner.id;
    // The A3/A4 producer owner of every plan is this collaborator, never the
    // tenant: `select` resolves RBAC for the actor and must not equate the two.
    ensure!(
        producer_identity.id == producer && producer != tenant,
        "the pack producer/issuer is not a distinct real user from the repository tenant"
    );
    // The producer is a collaborator with `write`, through the owner's real HTTP
    // route, before any of its packs commits: the decision-gated `select`
    // resolves exactly this live role and refuses anything lower.
    let collaborator = grant_producer(&http, &owner_user.token, &owner.username, &producer_user).await?;
    let (target, fixture) = repo::open(&db, repo_id, tenant, &options.git).await?;
    // The pack producer (durable hold/publication/acquirer owner) is the real
    // token user, while the storage tenant/RAM-prefix identity of every blob
    // locator stays the repository tenant's; both are read from the real rows
    // by the drill and never assumed equal.
    let (registrations, last_plan, head) =
        packs(&db, &store, &target, &options.git, &fixture, &producer_identity).await?;
    ensure!(registrations.len() as i64 == PACKS, "not every planned pack registered");

    // 2. A5 snapshot + pin of the multi-pack membership, owned by the producer.
    let verified = pack::Verified {
        tenant,
        repo: repo_id,
        gate: current_gate(&db.pool, repo_id, tenant).await?,
        fixture,
        commit_oid: head,
        plan: last_plan.clone(),
        new_packs: registrations.clone(),
    };
    // Diagnostic only: an unchanged typed error behind this boundary names the
    // A5 snapshot step and the verified gate revision it expects.
    let snapshot = repo::producer_snapshot(&db, &verified, producer, ROOT_SLOTS).await.map_err(|error| {
        anyhow!("stage=producer_snapshot expected_revision={}: {error:#}", verified.gate.revision())
    })?;
    let source = repo::as_source(&snapshot);

    // 3. Roots registered by the same producer owner as the snapshot/pin.
    let adapter = PgRetentionRoots::new(store.clone(), options.git.clone())
        .map_err(|error| anyhow!("retention roots adapter rejected the Blob/Git configuration: {error:?}"))?;
    let scope = roots::producer_scope(repo_id, tenant, producer, &verified.gate)?;
    let mut root_rows = Vec::new();
    for state in ["active", "released"] {
        let root_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let ids = roots::RootRequestIds { root_id, operation_id, request_id: Uuid::new_v4() };
        let candidate = roots::prepare(&adapter, &db.pool, scope, &source, ids, deadline())
            .await
            .map_err(|error| anyhow!("{state} root prepare refused: {error:?}"))?;
        ensure!(candidate.pack_count() == PACKS, "a root candidate does not cover every registered pack");
        let register_digest = candidate.register_digest().as_hex();
        let receipt = roots::register(&adapter, &db.pool, candidate, Uuid::new_v4(), deadline())
            .await
            .map_err(|error| anyhow!("{state} root register refused: {error:?}"))?;
        if state == "released" {
            let release_digest = marker::release_digest("format22-released");
            let request = roots::ReleaseRequest {
                scope,
                root_id,
                request_id: Uuid::new_v4(),
                expected_register_digest: &register_digest,
                release_digest: &release_digest,
            };
            let released = roots::release(&adapter, &db.pool, request, deadline())
                .await
                .map_err(|error| anyhow!("released root release refused: {error:?}"))?;
            ensure!(released.state() == "released", "the released root did not reach released");
        } else {
            ensure!(
                receipt.state() == "active" && !receipt.replayed(),
                "the active root is not a fresh active capture"
            );
        }
        root_rows.push(json!({
            "root_id": root_id.to_string(),
            "operation_id": operation_id.to_string(),
            "state": state,
            "tenant_id": tenant.to_string(),
            "owner_id": producer.to_string(),
            "register_digest": register_digest,
        }));
    }
    // The source pin is released, but the pin is not what retains the packs:
    // the immutable snapshot descriptor survives (migration 143 keeps
    // `snapshot_packs` with the snapshot), so both roots and that retained
    // snapshot still declare every registration; the transient serving read
    // below adds the third declaring set.
    repo::release_snapshot_pin(&db, &snapshot, &verified.gate).await.map_err(|error| {
        anyhow!("stage=release_snapshot_pin expected_revision={}: {error:#}", verified.gate.revision())
    })?;

    // 3b. One nonempty transient serving read by the third real user, over the
    //     same verified gate, captured only by the production
    //     `PgServingReads::capture` (its SQL loader/decoder writes every row).
    //     The capture is intentionally NOT released: the immediate format22
    //     backup must archive a live serving-read pack declaration, so the row
    //     survives until the drill's own lease (bounded, reclaimed afterwards).
    let serving_read = serving_read_capture(&db, &store, &verified, &reader).await?;

    // 4. Empty and unrelated repositories last: created through the same API and
    //    never written, so they stay genuinely empty.
    let empty_owner = authenticate(&db.pool, &issued_user(&db.pool, "fmt22owner").await?).await?;
    let empty = provision_with(&db.pool, &empty_owner, "empty", &store).await?;
    let unrelated = provision_with(&db.pool, &owner, "unrelated", &store).await?;

    let badges = repo::registration_badges(&db, repo_id, tenant, &verified.gate, &registrations).await?;
    let mut retainable = Vec::new();
    for badge in &badges {
        let counts = marker::retainable_counts(&db.pool, badge.registration_id).await?;
        // Two root captures (one active, one released), one retained snapshot
        // descriptor (migration 143, kept after the pin release) and one live
        // transient serving read descriptor (the unreleased capture above).
        let root_packs = counts["root_packs"].as_i64().unwrap_or(0);
        let snapshot_packs = counts["snapshot_packs"].as_i64().unwrap_or(0);
        let serving_read_packs = counts["serving_read_packs"].as_i64().unwrap_or(0);
        let declared = root_packs + snapshot_packs + serving_read_packs;
        ensure!(declared > 0, "a fixture registration is not retained by any root/snapshot/read declaration");
        ensure!(root_packs == 2, "a fixture registration is declared by {root_packs} root_packs rows, expected 2");
        ensure!(
            snapshot_packs == 1,
            "a fixture registration is declared by {snapshot_packs} snapshot_packs rows, expected 1"
        );
        ensure!(
            serving_read_packs == 1,
            "a fixture registration is declared by {serving_read_packs} serving_read_packs rows, expected 1"
        );
        ensure!(declared == 4, "a fixture registration has {declared} declared rows, expected 4");
        retainable.push(json!({"registration_id": badge.registration_id.to_string(), "declared": counts}));
    }
    let registration_json = badges
        .iter()
        .map(|badge| {
            json!({
                "registration_id": badge.registration_id.to_string(),
                "pack_id": badge.pack_id.to_string(),
                "artifact_set_digest": badge.artifact_set_digest,
                "pack_sha256": badge.pack_sha256,
                "idx_sha256": badge.idx_sha256,
                "roles": ["idx", "pack"],
            })
        })
        .collect::<Vec<_>>();
    let repository = |id: Uuid, owner: Uuid| {
        json!({"id": id.to_string(), "owner_id": owner.to_string(), "tenant_id": owner.to_string(),
               "state": "ready", "storage_backend": "pg_refstore"})
    };
    let marker = json!({
        "kind": marker::KIND,
        "format": 22,
        "schema_version": 147,
        "bound_repository_id": repo_id.to_string(),
        "empty_repository_id": empty.to_string(),
        "unrelated_repository_id": unrelated.to_string(),
        "repositories": [
            repository(repo_id, tenant),
            repository(empty, empty_owner.id),
            repository(unrelated, tenant),
        ],
        "tenant_id": tenant.to_string(),
        "producer_owner_id": producer.to_string(),
        "producer_collaborator": collaborator,
        "pack_owner_id": producer.to_string(),
        "storage_tenant_id": tenant.to_string(),
        "root_owner_id": producer.to_string(),
        "gate_revision": verified.gate.revision(),
        "source_snapshot_id": snapshot.snapshot_id.to_string(),
        "source_pin_id": snapshot.pin_id.to_string(),
        // Secret-free identity of the transient serving read: no credential,
        // DSN, Blob root, endpoint or expiry is recorded here.
        "serving_read": {
            "pin_id": serving_read.pin_id.to_string(),
            "repository_id": repo_id.to_string(),
            "tenant_id": tenant.to_string(),
            "owner_id": reader.id.to_string(),
            "pack_count": serving_read.pack_count,
        },
        "registrations": registration_json,
        "retainable": retainable,
        "packs": PACKS,
        "roots": root_rows,
        "data_dir": options.data_dir.to_string_lossy(),
        "blob_root": options.blob_root,
    });
    marker::write(&options.seed, &marker)?;
    Ok(marker)
}
