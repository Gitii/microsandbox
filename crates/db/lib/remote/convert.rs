//! Value conversion between sea-orm statements and the libSQL wire protocol.
//!
//! The remote protocol only carries SQLite's storage classes (integer, real,
//! text, blob, null), while sea-orm's `ValueType` conversions are exact on
//! the `sea_query::Value` variant. Result cells are therefore mapped through
//! a schema-derived column-kind table built from this crate's entities, so
//! an `i32` primary key comes back as `Value::Int` and a timestamp column as
//! `Value::ChronoDateTime` — exactly what the entity models expect.

use std::collections::HashMap;
use std::sync::OnceLock;

use chrono::NaiveDateTime;
use sea_orm::sea_query::{ColumnType, Value};
use sea_orm::{ColumnTrait, DbErr, EntityTrait, IdenStatic, Iterable};

use crate::entity;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Timestamp format sqlx-sqlite writes for `NaiveDateTime` binds; rows
/// written by the file backend and the remote backend must stay identical.
const DATETIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.f";

/// Lenient fallback for ISO-8601 timestamps with a `T` separator.
const DATETIME_FORMAT_T: &str = "%Y-%m-%dT%H:%M:%S%.f";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The Rust-side shape a catalog column converts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColumnKind {
    /// 32-bit integer columns (`i32` model fields).
    I32,
    /// 64-bit integer columns (`i64` model fields).
    I64,
    /// Floating-point columns.
    F64,
    /// Boolean columns (stored as SQLite integers).
    Bool,
    /// Text columns, including string-backed enums.
    Text,
    /// Binary blob columns.
    Blob,
    /// Naive datetime columns (stored as SQLite text).
    DateTime,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Column-name → kind table derived from every entity in this crate.
///
/// Names are unambiguous across the catalog schema today (enforced by a
/// test below); a future column reusing an existing name with a different
/// type must extend the lookup with a table qualifier.
pub(crate) fn column_kinds() -> &'static HashMap<String, ColumnKind> {
    static KINDS: OnceLock<HashMap<String, ColumnKind>> = OnceLock::new();
    KINDS.get_or_init(|| {
        let mut kinds = HashMap::new();
        for (name, kind) in all_entity_kinds() {
            if let Some(previous) = kinds.insert(name.clone(), kind) {
                // Enforced unambiguous by a test; keep the first kind if
                // two tables ever disagree so behavior is deterministic.
                if previous != kind {
                    tracing::warn!(
                        column = name.as_str(),
                        "ambiguous column kind across tables"
                    );
                    kinds.insert(name, previous);
                }
            }
        }
        kinds
    })
}

/// Every (column name, kind) pair across the catalog schema, one entry per
/// entity column.
fn all_entity_kinds() -> Vec<(String, ColumnKind)> {
    let mut all = Vec::new();
    collect::<entity::config::Entity>(&mut all);
    collect::<entity::image_ref::Entity>(&mut all);
    collect::<entity::layer::Entity>(&mut all);
    collect::<entity::maintenance_lease::Entity>(&mut all);
    collect::<entity::manifest::Entity>(&mut all);
    collect::<entity::manifest_layer::Entity>(&mut all);
    collect::<entity::run::Entity>(&mut all);
    collect::<entity::sandbox::Entity>(&mut all);
    collect::<entity::sandbox_label::Entity>(&mut all);
    collect::<entity::sandbox_rootfs::Entity>(&mut all);
    collect::<entity::snapshot::Entity>(&mut all);
    collect::<entity::volume::Entity>(&mut all);
    all
}

/// Look up the kind for a result column, tolerating sea-orm's `A_`/`B_`
/// relation-query prefixes.
pub(crate) fn kind_for_column(name: &str) -> Option<ColumnKind> {
    // sea-orm's paginator decodes its COUNT alias as i32 on SQLite.
    if name == "num_items" {
        return Some(ColumnKind::I32);
    }

    let kinds = column_kinds();
    if let Some(kind) = kinds.get(name) {
        return Some(*kind);
    }

    let stripped = name
        .strip_prefix("A_")
        .or_else(|| name.strip_prefix("B_"))?;
    kinds.get(stripped).copied()
}

/// Convert one sea-orm bind value into a libsql parameter.
pub(crate) fn to_libsql_value(value: &Value) -> Result<libsql::Value, DbErr> {
    use libsql::Value as Lv;

    let converted = match value {
        Value::Bool(v) => v.map_or(Lv::Null, |b| Lv::Integer(b.into())),
        Value::TinyInt(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::SmallInt(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::Int(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::BigInt(v) => v.map_or(Lv::Null, Lv::Integer),
        Value::TinyUnsigned(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::SmallUnsigned(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::Unsigned(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::BigUnsigned(Some(v)) => {
            let signed = i64::try_from(*v)
                .map_err(|_| DbErr::Custom(format!("u64 bind {v} exceeds SQLite integer range")))?;
            Lv::Integer(signed)
        }
        Value::BigUnsigned(None) => Lv::Null,
        Value::Float(v) => v.map_or(Lv::Null, |f| Lv::Real(f.into())),
        Value::Double(v) => v.map_or(Lv::Null, Lv::Real),
        Value::String(v) => v
            .as_ref()
            .map_or(Lv::Null, |s| Lv::Text(s.as_str().to_owned())),
        Value::Char(v) => v.map_or(Lv::Null, |c| Lv::Text(c.to_string())),
        Value::Bytes(v) => v.as_ref().map_or(Lv::Null, |b| Lv::Blob(b.to_vec())),
        Value::ChronoDate(v) => v
            .as_deref()
            .map_or(Lv::Null, |d| Lv::Text(d.format("%Y-%m-%d").to_string())),
        Value::ChronoTime(v) => v
            .as_deref()
            .map_or(Lv::Null, |t| Lv::Text(t.format("%H:%M:%S%.f").to_string())),
        Value::ChronoDateTime(v) => v.as_deref().map_or(Lv::Null, |dt| {
            Lv::Text(dt.format(DATETIME_FORMAT).to_string())
        }),
        Value::ChronoDateTimeUtc(v) => v.as_ref().map_or(Lv::Null, |dt| {
            Lv::Text(dt.naive_utc().format(DATETIME_FORMAT).to_string())
        }),
        Value::ChronoDateTimeLocal(v) => v.as_ref().map_or(Lv::Null, |dt| {
            Lv::Text(dt.naive_utc().format(DATETIME_FORMAT).to_string())
        }),
        Value::ChronoDateTimeWithTimeZone(v) => v.as_ref().map_or(Lv::Null, |dt| {
            Lv::Text(dt.naive_utc().format(DATETIME_FORMAT).to_string())
        }),
        // Reachable only when extra sea-orm value features (json, uuid,
        // decimal, ...) are unified into this build by another crate.
        #[allow(unreachable_patterns)]
        other => {
            return Err(DbErr::Custom(format!(
                "unsupported bind type for the libSQL backend: {other:?}"
            )));
        }
    };

    Ok(converted)
}

/// Convert one result cell into the `sea_query::Value` variant the entity
/// model expects for that column.
pub(crate) fn to_sea_value(name: &str, value: libsql::Value) -> Value {
    use libsql::Value as Lv;

    let kind = kind_for_column(name);

    match (kind, value) {
        // NULL must carry the column's variant so `Option<T>` decodes to None.
        (kind, Lv::Null) => null_value(kind),
        (Some(ColumnKind::I32), Lv::Integer(i)) => match i32::try_from(i) {
            Ok(v) => Value::Int(Some(v)),
            Err(_) => Value::BigInt(Some(i)),
        },
        (Some(ColumnKind::I64), Lv::Integer(i)) => Value::BigInt(Some(i)),
        (Some(ColumnKind::Bool), Lv::Integer(i)) => Value::Bool(Some(i != 0)),
        (Some(ColumnKind::F64), Lv::Integer(i)) => Value::Double(Some(i as f64)),
        (Some(ColumnKind::F64), Lv::Real(f)) => Value::Double(Some(f)),
        (Some(ColumnKind::Text), Lv::Text(s)) => Value::String(Some(Box::new(s))),
        (Some(ColumnKind::DateTime), Lv::Text(s)) => parse_datetime(name, s),
        (Some(ColumnKind::Blob), Lv::Blob(b)) => Value::Bytes(Some(Box::new(b))),
        // Unknown column (expression/alias) or unexpected shape: keep the
        // wire shape so plain text/integer consumers still work.
        (_, Lv::Integer(i)) => Value::BigInt(Some(i)),
        (_, Lv::Real(f)) => Value::Double(Some(f)),
        (_, Lv::Text(s)) => Value::String(Some(Box::new(s))),
        (_, Lv::Blob(b)) => Value::Bytes(Some(Box::new(b))),
    }
}

/// The typed NULL for a column kind.
fn null_value(kind: Option<ColumnKind>) -> Value {
    match kind {
        Some(ColumnKind::I32) => Value::Int(None),
        Some(ColumnKind::I64) => Value::BigInt(None),
        Some(ColumnKind::F64) => Value::Double(None),
        Some(ColumnKind::Bool) => Value::Bool(None),
        Some(ColumnKind::DateTime) => Value::ChronoDateTime(None),
        Some(ColumnKind::Blob) => Value::Bytes(None),
        Some(ColumnKind::Text) | None => Value::String(None),
    }
}

/// Parse a stored timestamp back into a chrono value, falling back to the
/// wire string if the text doesn't parse (surfaces as a loud decode error
/// for non-nullable columns instead of silently corrupting data).
fn parse_datetime(name: &str, text: String) -> Value {
    let parsed = NaiveDateTime::parse_from_str(&text, DATETIME_FORMAT)
        .or_else(|_| NaiveDateTime::parse_from_str(&text, DATETIME_FORMAT_T));

    match parsed {
        Ok(dt) => Value::ChronoDateTime(Some(Box::new(dt))),
        Err(_) => {
            tracing::warn!(column = name, "unparseable timestamp from catalog server");
            Value::String(Some(Box::new(text)))
        }
    }
}

/// Record every column of `E` with its conversion kind.
fn collect<E: EntityTrait>(all: &mut Vec<(String, ColumnKind)>) {
    for column in E::Column::iter() {
        let name = column.as_str().to_owned();
        let kind = kind_of(column.def().get_column_type());
        all.push((name, kind));
    }
}

/// Map a schema column type onto the conversion kind.
fn kind_of(column_type: &ColumnType) -> ColumnKind {
    match column_type {
        ColumnType::TinyInteger | ColumnType::SmallInteger | ColumnType::Integer => ColumnKind::I32,
        ColumnType::BigInteger => ColumnKind::I64,
        ColumnType::Float | ColumnType::Double | ColumnType::Decimal(_) => ColumnKind::F64,
        ColumnType::Boolean => ColumnKind::Bool,
        ColumnType::DateTime | ColumnType::Timestamp | ColumnType::TimestampWithTimeZone => {
            ColumnKind::DateTime
        }
        ColumnType::Binary(_) | ColumnType::VarBinary(_) | ColumnType::Blob => ColumnKind::Blob,
        _ => ColumnKind::Text,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_kinds_are_unambiguous() {
        // A column name mapping to two kinds would make result conversion
        // depend on table order; force a rename or a qualified lookup.
        let mut seen: HashMap<String, ColumnKind> = HashMap::new();
        let mut conflicts = Vec::new();

        for (name, kind) in all_entity_kinds() {
            if let Some(previous) = seen.insert(name.clone(), kind) {
                if previous != kind {
                    conflicts.push(name);
                }
            }
        }

        assert!(conflicts.is_empty(), "ambiguous columns: {conflicts:?}");
        assert!(!column_kinds().is_empty());
    }

    #[test]
    fn timestamp_columns_resolve_to_datetime() {
        assert_eq!(kind_for_column("created_at"), Some(ColumnKind::DateTime));
        assert_eq!(kind_for_column("updated_at"), Some(ColumnKind::DateTime));
        assert_eq!(kind_for_column("A_created_at"), Some(ColumnKind::DateTime));
    }

    #[test]
    fn datetime_round_trips_through_text() {
        let dt = NaiveDateTime::parse_from_str("2026-01-02 03:04:05.678", DATETIME_FORMAT).unwrap();

        let bound = to_libsql_value(&Value::ChronoDateTime(Some(Box::new(dt)))).unwrap();
        let libsql::Value::Text(text) = bound else {
            panic!("datetime must bind as text");
        };
        let back = to_sea_value("created_at", libsql::Value::Text(text));

        assert_eq!(back, Value::ChronoDateTime(Some(Box::new(dt))));
    }

    #[test]
    fn integer_widths_follow_schema() {
        assert_eq!(
            to_sea_value("id", libsql::Value::Integer(7)),
            Value::Int(Some(7))
        );
    }

    #[test]
    fn null_carries_column_variant() {
        assert_eq!(
            to_sea_value("created_at", libsql::Value::Null),
            Value::ChronoDateTime(None)
        );
    }

    #[test]
    fn unknown_columns_fall_back_to_wire_shape() {
        assert_eq!(
            to_sea_value("count(*)", libsql::Value::Integer(3)),
            Value::BigInt(Some(3))
        );
    }
}
