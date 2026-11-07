//! Test-only grant helpers and regressions for [`crate::token_scopes`].
//!
//! The production half of the module lives in `src/token_scopes.rs`. This file
//! is compiled only under `cfg(test)`; the grant helpers here never reach a
//! production build.

use super::*;
use anyhow::ensure;

/// Insert a grant for the module's own real-PostgreSQL tests.
///
/// Test-only and never compiled into production builds: there is deliberately
/// no issuance helper in this module while the issuance API/CLI/UI and browser
/// inheritance policy are unwired. `is_restricted` must already be true.
async fn grant_repository_for_test(
    tx: &Transaction<'_>,
    token_id: Uuid,
    repository_id: Uuid,
    action: RepoAction,
) -> Result<()> {
    let restricted: Option<bool> = tx
        .query_opt("SELECT is_restricted FROM tokens WHERE id = $1 FOR UPDATE", &[&token_id])
        .await
        .map_err(|_| store_error())?
        .map(|row| row.get(0));
    ensure!(restricted == Some(true), "test grant requires an existing restricted token");
    tx.execute(
        "INSERT INTO token_repository_scopes(token_id, repository_id, action) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
        &[&token_id, &repository_id, &action.as_str()],
    )
    .await
    .map_err(|_| store_error())?;
    tx.execute("UPDATE tokens SET scope_version = scope_version + 1 WHERE id = $1", &[&token_id])
        .await
        .map_err(|_| store_error())?;
    Ok(())
}

async fn grant_namespace_for_test(
    tx: &Transaction<'_>,
    token_id: Uuid,
    organization_id: Uuid,
    action: NamespaceAction,
) -> Result<()> {
    let restricted: Option<bool> = tx
        .query_opt("SELECT is_restricted FROM tokens WHERE id = $1 FOR UPDATE", &[&token_id])
        .await
        .map_err(|_| store_error())?
        .map(|row| row.get(0));
    ensure!(restricted == Some(true), "test grant requires an existing restricted token");
    tx.execute(
        "INSERT INTO token_namespace_scopes(token_id, organization_id, action) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
        &[&token_id, &organization_id, &action.as_str()],
    )
    .await
    .map_err(|_| store_error())?;
    tx.execute("UPDATE tokens SET scope_version = scope_version + 1 WHERE id = $1", &[&token_id])
        .await
        .map_err(|_| store_error())?;
    Ok(())
}

mod tests {
    use super::*;

    fn authority(restricted: bool, read_only: bool) -> TokenAuthority {
        TokenAuthority {
            token_id: Uuid::nil(),
            actor_id: Uuid::nil(),
            read_only,
            restricted,
            repositories: BTreeMap::new(),
            namespaces: BTreeMap::new(),
        }
    }

    #[test]
    fn action_text_is_stable_and_parses_back() {
        for action in RepoAction::ALL {
            assert_eq!(RepoAction::parse(action.as_str()), Some(action));
        }
        for action in NamespaceAction::ALL {
            assert_eq!(NamespaceAction::parse(action.as_str()), Some(action));
        }
        assert_eq!(RepoAction::parse("contents:*"), None);
        assert_eq!(RepoAction::parse("*"), None);
        assert_eq!(NamespaceAction::parse("org:admin"), None);
        assert_eq!(RepoAction::parse("Contents_Read"), None);
    }

    #[test]
    fn mutating_actions_are_exactly_the_write_side() {
        for action in RepoAction::ALL {
            assert_eq!(
                action.is_mutating(),
                action.as_str().ends_with("_write")
                    || matches!(
                        action,
                        RepoAction::HooksAdmin
                            | RepoAction::MembersAdmin
                            | RepoAction::CiDispatch
                            | RepoAction::RepoAdmin
                    )
            );
        }
        assert!(RepoAction::ContentsRead.is_mutating() == false);
        assert!(RepoAction::CiRead.is_mutating() == false);
        assert!(RepoAction::ChecksRead.is_mutating() == false);
        assert!(NamespaceAction::OrgRead.is_mutating() == false);
        assert!(NamespaceAction::OrgMembersWrite.is_mutating());
        assert!(NamespaceAction::OrgTeamsWrite.is_mutating());
    }

    #[test]
    fn restricted_token_without_grants_is_denied_everywhere() {
        let token = authority(true, false);
        for action in RepoAction::ALL {
            assert_eq!(token.check_repository(Uuid::nil(), action), Err(ScopeDenial::Forbidden));
        }
        for action in NamespaceAction::ALL {
            assert_eq!(token.check_namespace(Uuid::nil(), action), Err(ScopeDenial::Forbidden));
        }
        assert_eq!(ScopeDenial::Forbidden.status_code(), 403);
        assert_eq!(ScopeDenial::InvalidToken.status_code(), 401);
        assert_eq!(ScopeDenial::Unavailable.status_code(), 500);
    }

    #[test]
    fn restricted_token_grants_are_per_repository_and_exact() {
        let repository = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        let mut token = authority(true, false);
        token.repositories.entry(repository).or_default().insert(RepoAction::ContentsRead);

        assert_eq!(token.check_repository(repository, RepoAction::ContentsRead), Ok(()));
        assert_eq!(token.check_repository(repository, RepoAction::ContentsWrite), Err(ScopeDenial::Forbidden));
        assert_eq!(token.check_repository(other, RepoAction::ContentsRead), Err(ScopeDenial::Forbidden));
        // A repository grant never implies namespace administration.
        assert_eq!(token.check_namespace(repository, NamespaceAction::OrgRead), Err(ScopeDenial::Forbidden));
    }

    #[test]
    fn read_only_intersects_with_scope_grants() {
        let repository = Uuid::from_u128(1);
        let mut token = authority(true, true);
        token.repositories.entry(repository).or_default().extend([
            RepoAction::ContentsRead,
            RepoAction::ContentsWrite,
            RepoAction::RepoAdmin,
        ]);
        assert_eq!(token.check_repository(repository, RepoAction::ContentsRead), Ok(()));
        assert_eq!(token.check_repository(repository, RepoAction::ContentsWrite), Err(ScopeDenial::Forbidden));
        assert_eq!(token.check_repository(repository, RepoAction::RepoAdmin), Err(ScopeDenial::Forbidden));

        // Legacy read_only tokens stay read-only for writes.
        let legacy = authority(false, true);
        assert_eq!(legacy.check_repository(repository, RepoAction::ContentsRead), Ok(()));
        assert_eq!(legacy.check_repository(repository, RepoAction::ContentsWrite), Err(ScopeDenial::Forbidden));
    }

    #[test]
    fn legacy_token_is_account_wide_but_still_read_only_aware() {
        let legacy = authority(false, false);
        assert_eq!(legacy.check_repository(Uuid::from_u128(9), RepoAction::RepoAdmin), Ok(()));
        // Legacy tokens are unchanged: their account-wide 'api' semantics do
        // not silently become namespace grants here; callers still do RBAC.
        assert_eq!(legacy.check_namespace(Uuid::from_u128(9), NamespaceAction::OrgMembersWrite), Ok(()));
    }

    #[test]
    fn display_name_bounds() {
        assert!(valid_display_name("laptop"));
        assert!(!valid_display_name(""));
        assert!(valid_display_name(&"a".repeat(80)));
        assert!(!valid_display_name(&"a".repeat(81)));
        assert!(!valid_display_name("bad\nname"));
    }

    #[test]
    fn denials_do_not_leak_internals() {
        assert_eq!(format!("{:?}", ScopeDenial::InvalidToken), "InvalidToken");
        assert_eq!(format!("{:?}", ScopeDenial::Forbidden), "Forbidden");
    }

    #[test]
    fn unused_parse_helper_is_not_a_wildcard_surface() {
        // No wildcard or dynamic user label can be represented.
        assert!(RepoAction::ALL.iter().all(|action| !action.as_str().contains('*')));
        assert!(NamespaceAction::ALL.iter().all(|action| !action.as_str().contains('*')));
    }
}

mod postgres_tests {
    //! Real PostgreSQL coverage for migration 135 and the authorisation path.
    //! Run explicitly, never in the default test pass:
    //! `ROOTYARD_TEST_DATABASE_URL=postgresql://... cargo test token_scopes -- --ignored`
    use super::*;
    use crate::db;
    use std::time::Duration;

    fn base_url() -> String {
        std::env::var("ROOTYARD_TEST_DATABASE_URL")
            .expect("ROOTYARD_TEST_DATABASE_URL must be set to run --ignored PAT scope tests")
    }

    async fn connect_in(schema: &str) -> tokio_postgres::Client {
        let mut config: tokio_postgres::Config =
            base_url().parse().expect("ROOTYARD_TEST_DATABASE_URL must be a PostgreSQL URL");
        config.options(&format!("-csearch_path={schema}"));
        let (client, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
        tokio::spawn(connection);
        client
    }

    /// Create a random owned schema, migrate it, and return an admin client for
    /// cleanup plus a client whose `search_path` is that schema.
    async fn owned_schema() -> (String, tokio_postgres::Client, tokio_postgres::Client) {
        let (admin, admin_connection) = tokio_postgres::connect(&base_url(), tokio_postgres::NoTls).await.unwrap();
        tokio::spawn(admin_connection);
        let schema = format!("pat_scopes_{}", Uuid::new_v4().simple());
        admin.batch_execute(&format!("CREATE SCHEMA \"{schema}\"")).await.unwrap();
        let mut client = connect_in(&schema).await;
        db::migrate_client(&mut client).await.unwrap();
        (schema, admin, client)
    }

    async fn drop_schema(admin: &tokio_postgres::Client, schema: &str) {
        admin.batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await.unwrap();
    }

    async fn seed_token(client: &tokio_postgres::Client, restricted: bool) -> (Uuid, Uuid) {
        let actor = Uuid::new_v4();
        let token = Uuid::new_v4();
        let slug = format!("u{}", actor.simple());
        client.execute("INSERT INTO users(id, username) VALUES ($1, $2)", &[&actor, &slug]).await.unwrap();
        // Migration 120 has a trigger that creates the personal namespace, but
        // the namespace is a real FK target, so make the dependency explicit.
        client
            .execute(
                "INSERT INTO namespaces(id, slug, kind, user_id) VALUES ($1, $2, 'user', $1) \
                 ON CONFLICT DO NOTHING",
                &[&actor, &slug],
            )
            .await
            .unwrap();
        let mut digest = [0u8; 32];
        digest[..16].copy_from_slice(actor.as_bytes());
        digest[16..].copy_from_slice(token.as_bytes());
        client
            .execute(
                "INSERT INTO tokens(id, user_id, digest, is_restricted) VALUES ($1, $2, $3, $4)",
                &[&token, &actor, &digest.to_vec(), &restricted],
            )
            .await
            .unwrap();
        (actor, token)
    }

    async fn seed_repo(client: &tokio_postgres::Client, actor: Uuid, name: &str) -> Uuid {
        let repository = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO repositories(id, owner_id, name, state) VALUES ($1, $2, $3, 'ready')",
                &[&repository, &actor, &name],
            )
            .await
            .unwrap();
        repository
    }

    fn assert_live_authority(authority: &TokenAuthority) {
        assert!(authority.is_restricted());
        assert!(!authority.read_only());
    }

    #[tokio::test]
    #[ignore = "requires ROOTYARD_TEST_DATABASE_URL and PostgreSQL schema creation permission"]
    async fn restricted_scopes_follow_exact_grants_and_reject_dead_tokens() {
        let (schema, admin, mut client) = owned_schema().await;
        let (actor, token) = seed_token(&client, true).await;
        let repo_a = seed_repo(&client, actor, "alpha").await;
        let repo_b = seed_repo(&client, actor, "beta").await;

        // Empty grant set denies everything, even the actor's own repository.
        let tx = client.transaction().await.unwrap();
        assert_live_authority(&load_authority(&tx, token, actor).await.unwrap());
        assert_eq!(
            authorize_repository(&tx, token, actor, repo_a, RepoAction::ContentsRead).await,
            Err(ScopeDenial::Forbidden)
        );
        assert_eq!(
            authorize_namespace(&tx, token, actor, Uuid::new_v4(), NamespaceAction::OrgRead).await,
            Err(ScopeDenial::Forbidden)
        );
        tx.commit().await.unwrap();

        // A real grant, applied through the locked mutation helper path.
        let tx = client.transaction().await.unwrap();
        grant_repository_for_test(&tx, token, repo_a, RepoAction::ContentsRead).await.unwrap();
        tx.commit().await.unwrap();

        let tx = client.transaction().await.unwrap();
        assert_eq!(authorize_repository(&tx, token, actor, repo_a, RepoAction::ContentsRead).await, Ok(()));
        // Exact action and exact repository only.
        assert_eq!(
            authorize_repository(&tx, token, actor, repo_a, RepoAction::ContentsWrite).await,
            Err(ScopeDenial::Forbidden)
        );
        assert_eq!(
            authorize_repository(&tx, token, actor, repo_b, RepoAction::ContentsRead).await,
            Err(ScopeDenial::Forbidden)
        );
        // Repository grants never imply namespace administration.
        assert_eq!(
            authorize_namespace(&tx, token, actor, Uuid::new_v4(), NamespaceAction::OrgMembersWrite).await,
            Err(ScopeDenial::Forbidden)
        );
        tx.commit().await.unwrap();

        // Namespace grants are separate, exact and cannot be inferred from
        // repository grants (nor turned into cluster operator authority).
        let organization = Uuid::new_v4();
        client
            .execute("INSERT INTO organizations(id, created_by) VALUES ($1, $2)", &[&organization, &actor])
            .await
            .unwrap();
        let tx = client.transaction().await.unwrap();
        grant_namespace_for_test(&tx, token, organization, NamespaceAction::OrgRead).await.unwrap();
        tx.commit().await.unwrap();
        let tx = client.transaction().await.unwrap();
        assert_eq!(authorize_namespace(&tx, token, actor, organization, NamespaceAction::OrgRead).await, Ok(()));
        assert_eq!(
            authorize_namespace(&tx, token, actor, organization, NamespaceAction::OrgMembersWrite).await,
            Err(ScopeDenial::Forbidden)
        );
        assert_eq!(
            authorize_namespace(&tx, token, actor, Uuid::new_v4(), NamespaceAction::OrgRead).await,
            Err(ScopeDenial::Forbidden)
        );
        // Namespace grants still cannot authorise repository actions.
        assert_eq!(
            authorize_repository(&tx, token, actor, repo_b, RepoAction::ContentsRead).await,
            Err(ScopeDenial::Forbidden)
        );
        tx.commit().await.unwrap();

        // read_only intersects: the same content write grant is still refused.
        client.execute("UPDATE tokens SET read_only = true WHERE id = $1", &[&token]).await.unwrap();
        let tx = client.transaction().await.unwrap();
        grant_repository_for_test(&tx, token, repo_a, RepoAction::ContentsWrite).await.unwrap();
        tx.commit().await.unwrap();
        let tx = client.transaction().await.unwrap();
        assert_eq!(authorize_repository(&tx, token, actor, repo_a, RepoAction::ContentsRead).await, Ok(()));
        assert_eq!(
            authorize_repository(&tx, token, actor, repo_a, RepoAction::ContentsWrite).await,
            Err(ScopeDenial::Forbidden)
        );
        tx.rollback().await.unwrap();
        client.execute("UPDATE tokens SET read_only = false WHERE id = $1", &[&token]).await.unwrap();

        // Rolled back grants never take effect.
        let tx = client.transaction().await.unwrap();
        grant_repository_for_test(&tx, token, repo_b, RepoAction::RepoAdmin).await.unwrap();
        tx.rollback().await.unwrap();
        let tx = client.transaction().await.unwrap();
        assert_eq!(
            authorize_repository(&tx, token, actor, repo_b, RepoAction::RepoAdmin).await,
            Err(ScopeDenial::Forbidden)
        );
        tx.commit().await.unwrap();

        // A narrowing helper can only shrink; it cannot add repo_admin back.
        let tx = client.transaction().await.unwrap();
        assert!(narrow_repository_scope(&tx, token, actor, repo_a, &[]).await.unwrap());
        tx.commit().await.unwrap();
        let tx = client.transaction().await.unwrap();
        assert_eq!(
            authorize_repository(&tx, token, actor, repo_a, RepoAction::ContentsRead).await,
            Err(ScopeDenial::Forbidden)
        );
        tx.commit().await.unwrap();
        let version: i64 =
            client.query_one("SELECT scope_version FROM tokens WHERE id = $1", &[&token]).await.unwrap().get(0);
        assert!(version > 1);

        // Revoked and expired tokens are 401, not 403.
        client.execute("UPDATE tokens SET revoked = true WHERE id = $1", &[&token]).await.unwrap();
        let tx = client.transaction().await.unwrap();
        assert_eq!(
            authorize_repository(&tx, token, actor, repo_a, RepoAction::ContentsRead).await,
            Err(ScopeDenial::InvalidToken)
        );
        tx.commit().await.unwrap();
        client
            .execute(
                "UPDATE tokens SET revoked = false, expires_at = clock_timestamp() - interval '1 second' WHERE id = $1",
                &[&token],
            )
            .await
            .unwrap();
        let tx = client.transaction().await.unwrap();
        assert_eq!(
            authorize_repository(&tx, token, actor, repo_a, RepoAction::ContentsRead).await,
            Err(ScopeDenial::InvalidToken)
        );
        tx.commit().await.unwrap();
        client.execute("UPDATE tokens SET expires_at = NULL WHERE id = $1", &[&token]).await.unwrap();

        // Wrong actor and browser-kind children are also invalid.
        let other_actor = Uuid::new_v4();
        let other_slug = format!("v{}", other_actor.simple());
        client.execute("INSERT INTO users(id, username) VALUES ($1, $2)", &[&other_actor, &other_slug]).await.unwrap();
        client
            .execute(
                "INSERT INTO namespaces(id, slug, kind, user_id) VALUES ($1, $2, 'user', $1) \
                 ON CONFLICT DO NOTHING",
                &[&other_actor, &other_slug],
            )
            .await
            .unwrap();
        let tx = client.transaction().await.unwrap();
        assert_eq!(
            authorize_repository(&tx, token, other_actor, repo_a, RepoAction::ContentsRead).await,
            Err(ScopeDenial::InvalidToken)
        );
        tx.commit().await.unwrap();
        client.execute("UPDATE tokens SET expires_at = NULL, kind = 'browser' WHERE id = $1", &[&token]).await.unwrap();
        let tx = client.transaction().await.unwrap();
        assert_eq!(
            authorize_repository(&tx, token, actor, repo_a, RepoAction::ContentsRead).await,
            Err(ScopeDenial::InvalidToken)
        );
        tx.rollback().await.unwrap();
        drop_schema(&admin, &schema).await;
    }

    #[tokio::test]
    #[ignore = "requires ROOTYARD_TEST_DATABASE_URL and PostgreSQL schema creation permission"]
    async fn legacy_tokens_keep_their_preexisting_scope() {
        let (schema, admin, mut client) = owned_schema().await;
        let (actor, token) = seed_token(&client, false).await;
        let repo = seed_repo(&client, actor, "legacy").await;
        let tx = client.transaction().await.unwrap();
        // Historical behaviour: account-wide read/write, still read_only aware.
        assert_eq!(authorize_repository(&tx, token, actor, repo, RepoAction::RepoAdmin).await, Ok(()));
        tx.commit().await.unwrap();
        client.execute("UPDATE tokens SET read_only = true WHERE id = $1", &[&token]).await.unwrap();
        let tx = client.transaction().await.unwrap();
        assert_eq!(authorize_repository(&tx, token, actor, repo, RepoAction::ContentsRead).await, Ok(()));
        assert_eq!(
            authorize_repository(&tx, token, actor, repo, RepoAction::ContentsWrite).await,
            Err(ScopeDenial::Forbidden)
        );
        tx.rollback().await.unwrap();
        drop_schema(&admin, &schema).await;
    }

    /// `now()` is fixed at transaction start, so a request that began just
    /// before expiry would keep being authorised by the old predicate. The
    /// helper uses `clock_timestamp()`; this proves the difference with a token
    /// whose expiry is after the reader transaction timestamp but before the
    /// clock time of the check.
    #[tokio::test]
    #[ignore = "requires ROOTYARD_TEST_DATABASE_URL and PostgreSQL schema creation permission"]
    async fn expired_token_is_rejected_inside_a_transaction_started_before_expiry() {
        let (schema, admin, client) = owned_schema().await;
        let (actor, token) = seed_token(&client, true).await;
        let mut reader = connect_in(&schema).await;
        let writer = connect_in(&schema).await;

        let reader_tx = reader.transaction().await.unwrap();
        let transaction_started: std::time::SystemTime =
            reader_tx.query_one("SELECT transaction_timestamp()", &[]).await.unwrap().get(0);
        writer
            .execute(
                "UPDATE tokens SET expires_at = clock_timestamp() - interval '1 microsecond' WHERE id = $1",
                &[&token],
            )
            .await
            .unwrap();
        let row = reader_tx
            .query_one(
                "SELECT expires_at > $1, expires_at < clock_timestamp() FROM tokens WHERE id = $2",
                &[&transaction_started, &token],
            )
            .await
            .unwrap();
        let still_after_start: bool = row.get(0);
        let already_expired: bool = row.get(1);
        assert!(
            still_after_start,
            "fixture must place expiry after the reader transaction timestamp so the old now() predicate would have passed"
        );
        assert!(already_expired, "fixture must already be expired by clock_timestamp() when the check runs");
        assert_eq!(load_authority(&reader_tx, token, actor).await.err(), Some(ScopeDenial::InvalidToken));
        reader_tx.commit().await.unwrap();
        drop_schema(&admin, &schema).await;
    }

    /// A grant writer takes `FOR UPDATE` on the token row. While a reader holds
    /// `FOR SHARE` from `load_authority`, the writer must be genuinely blocked by
    /// the reader's backend PID (observed through `pg_blocking_pids`), not merely
    /// slow. After the reader commits the narrowing completes, bumps
    /// `scope_version`, and the old grant is gone.
    #[tokio::test]
    #[ignore = "requires ROOTYARD_TEST_DATABASE_URL and PostgreSQL schema creation permission"]
    async fn grant_mutation_waits_for_reader_share_lock() {
        let (schema, admin, mut setup) = owned_schema().await;
        let (actor, token) = seed_token(&setup, true).await;
        let repo = seed_repo(&setup, actor, "locked").await;
        let tx = setup.transaction().await.unwrap();
        grant_repository_for_test(&tx, token, repo, RepoAction::ContentsRead).await.unwrap();
        tx.commit().await.unwrap();

        let mut reader = connect_in(&schema).await;
        let mut writer = connect_in(&schema).await;
        let observer = connect_in(&schema).await;
        let reader_pid: i32 = reader.query_one("SELECT pg_backend_pid()", &[]).await.unwrap().get(0);
        let writer_pid: i32 = writer.query_one("SELECT pg_backend_pid()", &[]).await.unwrap().get(0);

        let reader_tx = reader.transaction().await.unwrap();
        let authority = load_authority(&reader_tx, token, actor).await.unwrap();
        assert_eq!(authority.repository_actions(repo), BTreeSet::from([RepoAction::ContentsRead]));

        let narrow = async {
            let tx = writer.transaction().await.unwrap();
            let changed = narrow_repository_scope(&tx, token, actor, repo, &[]).await.unwrap();
            tx.commit().await.unwrap();
            changed
        };
        tokio::pin!(narrow);

        let mut blocked_by_reader = false;
        for _ in 0..250 {
            tokio::select! {
                finished = &mut narrow => panic!("writer finished before reader released FOR SHARE: {finished:?}"),
                _ = tokio::time::sleep(Duration::from_millis(20)) => {
                    let blockers: Vec<i32> = observer
                        .query_one("SELECT pg_blocking_pids($1)", &[&writer_pid])
                        .await
                        .unwrap()
                        .get(0);
                    if blockers.contains(&reader_pid) {
                        blocked_by_reader = true;
                        break;
                    }
                }
            }
        }
        assert!(blocked_by_reader, "writer {writer_pid} was never blocked by reader {reader_pid}");

        reader_tx.commit().await.unwrap();
        assert!(narrow.await, "narrowing must succeed once the reader releases its lock");

        let version: i64 =
            setup.query_one("SELECT scope_version FROM tokens WHERE id = $1", &[&token]).await.unwrap().get(0);
        assert!(version >= 2, "scope_version must increase when grants are narrowed");
        let tx = setup.transaction().await.unwrap();
        assert_eq!(
            authorize_repository(&tx, token, actor, repo, RepoAction::ContentsRead).await,
            Err(ScopeDenial::Forbidden)
        );
        tx.commit().await.unwrap();
        drop_schema(&admin, &schema).await;
    }
}
