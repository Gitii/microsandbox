//! Shared database entity definitions and connection helpers for the
//! microsandbox project.
//!
//! Used by both `microsandbox` (host CLI) and `microsandbox-runtime`
//! (in-VM supervisor). They share the same SQLite file, so the connection
//! builder lives here to keep PRAGMAs in one place.

#![warn(missing_docs)]

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod connection;
#[allow(missing_docs)]
pub mod entity;
pub mod pool;
#[cfg(feature = "libsql")]
mod remote;
pub mod retry;
pub mod stats;

pub use connection::{DbReadConnection, DbWriteConnection};
pub use stats::{DbStats, DbStatsSnapshot};

/// Whether a catalog target is a remote server URL rather than a file path.
///
/// Always available so callers can give a clear error when a URL target is
/// configured but the `libsql` backend isn't compiled in.
pub fn is_remote_url(target: &str) -> bool {
    target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("libsql://")
}
