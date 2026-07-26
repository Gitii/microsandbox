//! Remote database backend over a self-hosted libSQL server (`sqld`).
//!
//! Deployments where several host processes share one database can run one
//! server process that exclusively owns the SQLite file; every process then
//! talks to it over the libSQL remote protocol, which centralizes write
//! serialization and admission instead of coordinating through file locks.
//!
//! The backend plugs in beneath [`crate::DbReadConnection`] /
//! [`crate::DbWriteConnection`] via sea-orm's proxy connection, so entities,
//! query builders, and migrations keep working unchanged.

mod backend;
mod convert;
#[cfg(test)]
mod integration;

use std::time::Duration;

use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbBackend, DbErr, ProxyDatabaseTrait, Statement,
};

pub(crate) use backend::{WriteControl, with_txn_scope};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a read-side proxy connection: `max_connections` server connections
/// behind bounded admission. Verifies the server answers a real query.
pub(crate) async fn open_read(
    url: &str,
    max_connections: u32,
    acquire_timeout: Duration,
    request_timeout: Duration,
) -> Result<DatabaseConnection, DbErr> {
    let database = connect_database(url).await?;

    let mut conns = Vec::new();
    for _ in 0..max_connections.max(1) {
        conns.push(database.connect().map_err(connect_err)?);
    }

    let proxy = backend::ReadProxy::new(database, conns, acquire_timeout, request_timeout);
    let conn = into_proxy_connection(Box::new(proxy)).await?;

    // A read consumer must find an existing database, mirroring the file
    // backend's refusal to create one: probe the schema, not just the port.
    let probe = Statement::from_string(
        DbBackend::Sqlite,
        "SELECT count(*) FROM sqlite_master".to_owned(),
    );
    conn.query_one(probe).await?;
    Ok(conn)
}

/// Open the write-side proxy connection (single server connection) plus the
/// transaction control handle used by `DbWriteConnection::transaction`.
pub(crate) async fn open_write(
    url: &str,
    acquire_timeout: Duration,
    request_timeout: Duration,
) -> Result<(DatabaseConnection, WriteControl), DbErr> {
    let database = connect_database(url).await?;
    let server_conn = database.connect().map_err(connect_err)?;

    let proxy = backend::WriteProxy::new(database, server_conn, acquire_timeout, request_timeout);
    let control = proxy.control();
    let conn = into_proxy_connection(Box::new(proxy)).await?;

    conn.ping().await?;
    Ok((conn, control))
}

/// Build the libsql database handle for a server URL.
///
/// Loopback deployments run without authentication; token support can ride
/// on the URL's userinfo later if a deployment ever needs it.
async fn connect_database(url: &str) -> Result<libsql::Database, DbErr> {
    libsql::Builder::new_remote(url.to_owned(), String::new())
        .build()
        .await
        .map_err(connect_err)
}

/// Wrap a proxy backend into a sea-orm `DatabaseConnection`.
async fn into_proxy_connection(
    proxy: Box<dyn ProxyDatabaseTrait>,
) -> Result<DatabaseConnection, DbErr> {
    Database::connect_proxy(DbBackend::Sqlite, std::sync::Arc::new(proxy)).await
}

/// Contextual error for connection establishment failures.
fn connect_err(err: libsql::Error) -> DbErr {
    DbErr::Conn(sea_orm::RuntimeErr::Internal(format!(
        "connect to database server: {err}"
    )))
}
