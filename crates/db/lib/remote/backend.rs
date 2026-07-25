//! sea-orm proxy backends over a remote libSQL server connection.
//!
//! One process-wide server owns the database file; this module gives the
//! existing entity/repository layer a `sea_orm::DatabaseConnection` whose
//! statements execute on that server. Admission is bounded here (a
//! semaphore per backend) so overload surfaces as the same
//! pool-acquisition timeout the file backend reports, never as an
//! unbounded wait.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sea_orm::{
    ConnAcquireErr, DbErr, ProxyDatabaseTrait, ProxyExecResult, ProxyRow, RuntimeErr, Statement,
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use super::convert;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Prefix marking a server-reported SQLite busy condition; the retry layer
/// classifies on it (see [`crate::retry::is_sqlite_busy`]).
pub(crate) const BUSY_SENTINEL: &str = "SQLITE_BUSY";

/// Server messages meaning a request was rejected because its hrana stream
/// no longer exists — typically after a server restart. The statement did
/// NOT execute, so retrying it on a fresh connection cannot double-apply.
const STREAM_DEAD_MARKERS: &[&str] = &[
    "invalid baton",
    "stream closed",
    "stream not found",
    "stream expired",
];

tokio::task_local! {
    /// Set while a write transaction drives statements through the proxy;
    /// those statements already hold the admission permit and must not
    /// re-acquire it (that would deadlock a single-permit writer).
    ///
    /// The cell is the transaction's poison flag: once a statement loses
    /// its server stream, every later statement in the same transaction
    /// fails fast instead of executing non-transactionally on a fresh
    /// connection.
    static IN_WRITE_TXN: std::cell::Cell<bool>;
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Write-side proxy: one server connection, one admission permit.
///
/// Keeps the database handle so a connection whose server stream died
/// (e.g. across a server restart) can be replaced with a fresh one.
pub(crate) struct WriteProxy {
    database: libsql::Database,
    conn: Mutex<libsql::Connection>,
    control: WriteControl,
    request_timeout: Duration,
    stale: AtomicBool,
}

/// Read-side proxy: a fixed set of server connections handed out under a
/// semaphore sized to match.
pub(crate) struct ReadProxy {
    database: libsql::Database,
    conns: Mutex<Vec<libsql::Connection>>,
    admission: Arc<Semaphore>,
    acquire_timeout: Duration,
    request_timeout: Duration,
}

/// Transaction control shared between the write proxy and
/// `DbWriteConnection::transaction`: the admission permit plus a dirty
/// marker for transactions abandoned mid-flight.
#[derive(Clone, Debug)]
pub(crate) struct WriteControl {
    admission: Arc<Semaphore>,
    acquire_timeout: Duration,
    dirty: Arc<AtomicBool>,
}

/// Holds the writer's admission permit for the duration of a transaction.
///
/// Dropping without [`TxnPermit::disarm`] marks the connection dirty, so
/// the next checkout rolls back whatever the abandoned transaction left
/// open on the server connection.
pub(crate) struct TxnPermit {
    _permit: OwnedSemaphorePermit,
    dirty: Arc<AtomicBool>,
    armed: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WriteProxy {
    /// Build a write proxy over one server connection.
    pub(crate) fn new(
        database: libsql::Database,
        conn: libsql::Connection,
        acquire_timeout: Duration,
        request_timeout: Duration,
    ) -> Self {
        Self {
            database,
            conn: Mutex::new(conn),
            control: WriteControl {
                admission: Arc::new(Semaphore::new(1)),
                acquire_timeout,
                dirty: Arc::new(AtomicBool::new(false)),
            },
            request_timeout,
            stale: AtomicBool::new(false),
        }
    }

    /// Transaction control handle for `DbWriteConnection::transaction`.
    pub(crate) fn control(&self) -> WriteControl {
        self.control.clone()
    }

    /// Run `op` on the write connection, respecting admission unless the
    /// calling task is inside a transaction scope (which holds the permit).
    ///
    /// A connection whose server stream died is replaced with a fresh one:
    /// immediately (with a single retry of `op`) outside a transaction —
    /// stream-dead requests were rejected before executing, so the retry
    /// cannot double-apply — or at the next checkout when the death happened
    /// mid-transaction, where the transaction itself is poisoned instead.
    async fn with_conn<T, F, Fut>(&self, op_name: &'static str, op: F) -> Result<T, DbErr>
    where
        F: Fn(libsql::Connection) -> Fut,
        Fut: Future<Output = Result<T, libsql::Error>>,
    {
        let in_txn = IN_WRITE_TXN.try_with(|_| ()).is_ok();
        let poisoned = IN_WRITE_TXN.try_with(|cell| cell.get()).unwrap_or(false);

        if poisoned {
            return Err(poisoned_txn_err(op_name));
        }

        let _permit = if in_txn {
            None
        } else {
            Some(acquire(&self.control.admission, self.control.acquire_timeout).await?)
        };

        let conn = {
            let mut guard = self.conn.lock().await;

            if self.stale.swap(false, Ordering::AcqRel) {
                *guard = self.database.connect().map_err(reconnect_err)?;
            }

            if self.control.dirty.swap(false, Ordering::AcqRel) {
                // Best effort: clears a transaction abandoned by a cancelled
                // caller; errors ("no transaction is active") are expected.
                let _ = guard.execute("ROLLBACK", ()).await;
            }

            guard.clone()
        };

        let result = bounded(op_name, self.request_timeout, op(conn)).await;

        let Err(err) = &result else { return result };
        if !is_stream_dead_db(err) {
            return result;
        }

        if in_txn {
            // The server-side transaction died with the stream. Poison the
            // scope so later statements (including COMMIT) fail fast, and
            // replace the connection at the next checkout. Tagged as busy:
            // the transaction rolled back atomically, so retrying the whole
            // transaction on a fresh connection is the correct recovery.
            let _ = IN_WRITE_TXN.try_with(|cell| cell.set(true));
            self.stale.store(true, Ordering::Release);
            return Err(DbErr::Exec(RuntimeErr::Internal(format!(
                "{BUSY_SENTINEL}: catalog stream reset mid-transaction \
                 (server restarted); transaction rolled back"
            ))));
        }

        let fresh = self.database.connect().map_err(reconnect_err)?;
        *self.conn.lock().await = fresh.clone();
        bounded(op_name, self.request_timeout, op(fresh)).await
    }
}

impl ReadProxy {
    /// Build a read proxy over a fixed set of server connections.
    pub(crate) fn new(
        database: libsql::Database,
        conns: Vec<libsql::Connection>,
        acquire_timeout: Duration,
        request_timeout: Duration,
    ) -> Self {
        let admission = Arc::new(Semaphore::new(conns.len()));
        Self {
            database,
            conns: Mutex::new(conns),
            admission,
            acquire_timeout,
            request_timeout,
        }
    }

    /// Run `op` on a checked-out read connection.
    ///
    /// A connection whose server stream died is dropped and replaced with a
    /// fresh one, retrying `op` once — reads are idempotent, so the retry
    /// is always safe.
    async fn with_conn<T, F, Fut>(&self, op_name: &'static str, op: F) -> Result<T, DbErr>
    where
        F: Fn(libsql::Connection) -> Fut,
        Fut: Future<Output = Result<T, libsql::Error>>,
    {
        let _permit = acquire(&self.admission, self.acquire_timeout).await?;

        // A permit guarantees a connection is available.
        let mut conn = {
            let mut conns = self.conns.lock().await;
            conns.pop().expect("read connection available per permit")
        };

        let mut result = bounded(op_name, self.request_timeout, op(conn.clone())).await;

        if result.as_ref().is_err_and(is_stream_dead_db) {
            match self.database.connect().map_err(reconnect_err) {
                Ok(fresh) => {
                    conn = fresh;
                    result = bounded(op_name, self.request_timeout, op(conn.clone())).await;
                }
                Err(err) => result = Err(err),
            }
        }

        self.conns.lock().await.push(conn);
        result
    }
}

impl WriteControl {
    /// Acquire the writer's admission permit for a whole transaction.
    pub(crate) async fn begin_txn(&self) -> Result<TxnPermit, DbErr> {
        let permit = acquire(&self.admission, self.acquire_timeout).await?;
        Ok(TxnPermit {
            _permit: permit,
            dirty: self.dirty.clone(),
            armed: true,
        })
    }
}

impl TxnPermit {
    /// Mark the transaction cleanly finished (committed or rolled back).
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for TxnPermit {
    fn drop(&mut self) {
        if self.armed {
            self.dirty.store(true, Ordering::Release);
        }
    }
}

impl fmt::Debug for WriteProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteProxy").finish_non_exhaustive()
    }
}

impl fmt::Debug for ReadProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadProxy").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl ProxyDatabaseTrait for WriteProxy {
    async fn query(&self, statement: Statement) -> Result<Vec<ProxyRow>, DbErr> {
        self.with_conn("query", |conn| run_query(conn, statement.clone()))
            .await
    }

    async fn execute(&self, statement: Statement) -> Result<ProxyExecResult, DbErr> {
        self.with_conn("execute", |conn| run_execute(conn, statement.clone()))
            .await
    }

    // `begin`/`commit`/`rollback` stay no-ops on purpose: these hooks
    // cannot return errors, and a swallowed COMMIT failure would report a
    // write as durable when it isn't. `DbWriteConnection::transaction`
    // issues BEGIN/COMMIT as ordinary statements instead, where errors
    // propagate. A sea-orm `begin()` outside that path (e.g. the migrator)
    // therefore executes its statements without a server-side transaction.

    async fn ping(&self) -> Result<(), DbErr> {
        self.with_conn("ping", |conn| async move {
            conn.query("SELECT 1", ()).await.map(|_| ())
        })
        .await
    }
}

#[async_trait::async_trait]
impl ProxyDatabaseTrait for ReadProxy {
    async fn query(&self, statement: Statement) -> Result<Vec<ProxyRow>, DbErr> {
        self.with_conn("query", |conn| run_query(conn, statement.clone()))
            .await
    }

    async fn execute(&self, statement: Statement) -> Result<ProxyExecResult, DbErr> {
        self.with_conn("execute", |conn| run_execute(conn, statement.clone()))
            .await
    }

    async fn ping(&self) -> Result<(), DbErr> {
        self.with_conn("ping", |conn| async move {
            conn.query("SELECT 1", ()).await.map(|_| ())
        })
        .await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Enter the write-transaction statement scope for `fut`.
pub(crate) async fn with_txn_scope<T>(fut: impl Future<Output = T>) -> T {
    IN_WRITE_TXN.scope(std::cell::Cell::new(false), fut).await
}

/// Acquire an admission permit within `acquire_timeout`, mapping expiry to
/// the same error the sqlx pool reports so classification stays uniform.
async fn acquire(
    semaphore: &Arc<Semaphore>,
    acquire_timeout: Duration,
) -> Result<OwnedSemaphorePermit, DbErr> {
    match timeout(acquire_timeout, semaphore.clone().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err(DbErr::ConnectionAcquire(ConnAcquireErr::ConnectionClosed)),
        Err(_) => Err(DbErr::ConnectionAcquire(ConnAcquireErr::Timeout)),
    }
}

/// Bound a server call to `request_timeout`.
async fn bounded<T>(
    op_name: &'static str,
    request_timeout: Duration,
    fut: impl Future<Output = Result<T, libsql::Error>>,
) -> Result<T, DbErr> {
    match timeout(request_timeout, fut).await {
        Ok(result) => result.map_err(|e| map_libsql_err(op_name, e)),
        Err(_) => Err(DbErr::Custom(format!(
            "catalog {op_name} timed out after {}s",
            request_timeout.as_secs()
        ))),
    }
}

/// Execute a statement and report affected rows + last insert id.
async fn run_execute(
    conn: libsql::Connection,
    statement: Statement,
) -> Result<ProxyExecResult, libsql::Error> {
    let params = bind_params(&statement)?;
    let rows_affected = conn.execute(&statement.sql, params).await?;

    // Same connection, same guard scope — no interleaving writer between
    // the statement and reading its rowid.
    Ok(ProxyExecResult {
        last_insert_id: conn.last_insert_rowid() as u64,
        rows_affected,
    })
}

/// Run a query and convert every row through the schema-derived kinds.
async fn run_query(
    conn: libsql::Connection,
    statement: Statement,
) -> Result<Vec<ProxyRow>, libsql::Error> {
    let params = bind_params(&statement)?;
    let mut rows = conn.query(&statement.sql, params).await?;

    let names: Vec<String> = (0..rows.column_count())
        .map(|i| rows.column_name(i).unwrap_or_default().to_owned())
        .collect();

    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        let mut values = std::collections::BTreeMap::new();
        for (i, name) in names.iter().enumerate() {
            let value = row.get_value(i as i32)?;
            values.insert(name.clone(), convert::to_sea_value(name, value));
        }
        out.push(ProxyRow { values });
    }

    Ok(out)
}

/// Translate a statement's bind values into libsql positional params.
fn bind_params(statement: &Statement) -> Result<libsql::params::Params, libsql::Error> {
    let Some(values) = &statement.values else {
        return Ok(libsql::params::Params::None);
    };

    let converted: Result<Vec<libsql::Value>, DbErr> =
        values.0.iter().map(convert::to_libsql_value).collect();
    let converted =
        converted.map_err(|e| libsql::Error::ToSqlConversionFailure(e.to_string().into()))?;

    Ok(libsql::params::Params::Positional(converted))
}

/// Whether a mapped error reports a dead server stream (see
/// [`STREAM_DEAD_MARKERS`]).
fn is_stream_dead_db(err: &DbErr) -> bool {
    let DbErr::Custom(message) = err else {
        return false;
    };

    let lower = message.to_ascii_lowercase();
    STREAM_DEAD_MARKERS.iter().any(|m| lower.contains(m))
}

/// Contextual error for a failed replacement of a dead server connection.
fn reconnect_err(err: libsql::Error) -> DbErr {
    DbErr::Custom(format!("catalog reconnect: {err}"))
}

/// Error for statements attempted after their transaction lost its stream.
fn poisoned_txn_err(op_name: &'static str) -> DbErr {
    DbErr::Custom(format!(
        "catalog {op_name} skipped: transaction lost its server stream"
    ))
}

/// Map a libsql error into `DbErr`, tagging server-side busy conditions
/// with [`BUSY_SENTINEL`] so the retry layer treats them as transient.
fn map_libsql_err(op_name: &'static str, err: libsql::Error) -> DbErr {
    let busy = match &err {
        libsql::Error::RemoteSqliteFailure(code, _, _) => *code == 5 || *code == 517,
        libsql::Error::Hrana(inner) => {
            let text = inner.to_string();
            text.contains("SQLITE_BUSY") || text.contains("database is locked")
        }
        _ => false,
    };

    if busy {
        return DbErr::Exec(RuntimeErr::Internal(format!("{BUSY_SENTINEL}: {err}")));
    }

    DbErr::Custom(format!("catalog {op_name}: {err}"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_dead_classification_matches_rejected_stream_errors() {
        let baton = DbErr::Custom("catalog execute: Hrana: `api error: `Invalid baton``".into());
        let closed = DbErr::Custom("catalog query: Hrana: `stream closed: `gone``".into());

        assert!(is_stream_dead_db(&baton));
        assert!(is_stream_dead_db(&closed));
    }

    #[test]
    fn stream_dead_classification_ignores_statement_and_busy_errors() {
        let sql =
            DbErr::Custom("catalog execute: Hrana: `api error: `no such table: runs``".into());
        let busy = DbErr::Exec(RuntimeErr::Internal(format!(
            "{BUSY_SENTINEL}: database is locked"
        )));

        assert!(!is_stream_dead_db(&sql));
        assert!(!is_stream_dead_db(&busy));
    }
}
