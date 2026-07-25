//! Integration tests against a live libSQL server.
//!
//! Gated on `MSB_TEST_LIBSQL_URL` pointing at a running `sqld` with a fresh
//! database, e.g.:
//!
//! ```text
//! sqld --db-path /tmp/msb-libsql-test --http-listen-addr 127.0.0.1:8890
//! MSB_TEST_LIBSQL_URL=http://127.0.0.1:8890 cargo test -p microsandbox-db \
//!     --features libsql -- --ignored
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
};

use crate::connection::{DbReadConnection, DbWriteConnection};
use crate::entity::sandbox;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const READ_CONNECTIONS: u32 = 4;

static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn server_url() -> String {
    std::env::var("MSB_TEST_LIBSQL_URL")
        .expect("MSB_TEST_LIBSQL_URL must point at a running sqld instance")
}

fn unique_name(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    format!("{prefix}-{nanos}")
}

fn new_sandbox(name: &str) -> sandbox::ActiveModel {
    // Truncate to milliseconds: the text format stores what chrono formats,
    // and equality below asserts an exact round trip.
    let now = chrono::Utc::now().naive_utc();
    let now = now
        - chrono::Duration::nanoseconds(i64::from(
            now.and_utc().timestamp_subsec_nanos() % 1_000_000,
        ));

    sandbox::ActiveModel {
        name: Set(name.to_owned()),
        config: Set("{}".to_owned()),
        active_config: Set(None),
        status: Set(sandbox::SandboxStatus::Created),
        ephemeral: Set(false),
        created_at: Set(Some(now)),
        updated_at: Set(None),
        ..Default::default()
    }
}

async fn setup() -> (DbReadConnection, DbWriteConnection) {
    let url = server_url();

    let write = DbWriteConnection::open_url(&url, ACQUIRE_TIMEOUT, BUSY_TIMEOUT)
        .await
        .expect("open write proxy");

    MIGRATED
        .get_or_init(|| async {
            use microsandbox_migration::MigratorTrait;
            microsandbox_migration::Migrator::up(write.inner(), None)
                .await
                .expect("apply migrations against sqld");
        })
        .await;

    let read = DbReadConnection::open_url(&url, READ_CONNECTIONS, ACQUIRE_TIMEOUT, BUSY_TIMEOUT)
        .await
        .expect("open read proxy");

    (read, write)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
async fn migrations_apply_and_are_idempotent() {
    use microsandbox_migration::MigratorTrait;

    let (_read, write) = setup().await;

    // A second run must be a no-op, not an error.
    microsandbox_migration::Migrator::up(write.inner(), None)
        .await
        .expect("re-running migrations is idempotent");

    let applied = microsandbox_migration::Migrator::get_applied_migrations(write.inner())
        .await
        .expect("list applied migrations");
    assert!(!applied.is_empty());
}

#[tokio::test]
#[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
async fn entity_crud_round_trips() {
    let (read, write) = setup().await;
    let name = unique_name("crud");

    let inserted = new_sandbox(&name).insert(&write).await.expect("insert");
    assert!(inserted.id > 0, "insert reports the assigned rowid");

    let found = sandbox::Entity::find_by_id(inserted.id)
        .one(&read)
        .await
        .expect("select")
        .expect("row exists via the read proxy");
    assert_eq!(found, inserted, "typed round trip through the server");
    assert!(found.created_at.is_some(), "timestamp survives conversion");

    let mut update: sandbox::ActiveModel = found.into();
    update.status = Set(sandbox::SandboxStatus::Running);
    let updated = update.update(&write).await.expect("update");
    assert_eq!(updated.status, sandbox::SandboxStatus::Running);

    sandbox::Entity::delete_by_id(inserted.id)
        .exec(&write)
        .await
        .expect("delete");
    let gone = sandbox::Entity::find_by_id(inserted.id)
        .one(&read)
        .await
        .expect("select after delete");
    assert!(gone.is_none());
}

#[tokio::test]
#[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
async fn transaction_commit_is_durable() {
    let (read, write) = setup().await;
    let name_a = unique_name("txn-a");
    let name_b = unique_name("txn-b");

    write
        .transaction(|txn| {
            let (name_a, name_b) = (name_a.clone(), name_b.clone());
            async move {
                new_sandbox(&name_a).insert(&txn).await?;
                new_sandbox(&name_b).insert(&txn).await?;
                Ok::<_, sea_orm::DbErr>((txn, ()))
            }
        })
        .await
        .expect("transaction commits");

    let committed = sandbox::Entity::find()
        .filter(sandbox::Column::Name.is_in([name_a, name_b]))
        .count(&read)
        .await
        .expect("count");
    assert_eq!(committed, 2, "both writes visible after commit");
}

#[tokio::test]
#[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
async fn transaction_error_rolls_back() {
    let (read, write) = setup().await;
    let name = unique_name("rollback");

    let result: Result<(), sea_orm::DbErr> = write
        .transaction(|txn| {
            let name = name.clone();
            async move {
                new_sandbox(&name).insert(&txn).await?;
                Err(sea_orm::DbErr::Custom("abort on purpose".into()))
            }
        })
        .await;
    assert!(result.is_err());

    let rows = sandbox::Entity::find()
        .filter(sandbox::Column::Name.eq(name))
        .count(&read)
        .await
        .expect("count");
    assert_eq!(rows, 0, "aborted transaction leaves no rows");
}

#[tokio::test]
#[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
async fn concurrent_reads_respect_admission() {
    let (read, write) = setup().await;
    let name = unique_name("concurrent");
    new_sandbox(&name).insert(&write).await.expect("insert");

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..(READ_CONNECTIONS * 8) {
        let read = read.clone();
        let name = name.clone();
        tasks.spawn(async move {
            sandbox::Entity::find()
                .filter(sandbox::Column::Name.eq(name))
                .one(&read)
                .await
        });
    }

    while let Some(result) = tasks.join_next().await {
        let row = result.expect("task").expect("query under admission");
        assert!(row.is_some());
    }
}

#[tokio::test]
#[ignore = "requires a running sqld (MSB_TEST_LIBSQL_URL)"]
async fn count_decodes_the_paginator_alias() {
    let (read, _write) = setup().await;
    // Regression guard: sea-orm decodes its COUNT alias as i32 on SQLite.
    sandbox::Entity::find()
        .count(&read)
        .await
        .expect("count all");
}
