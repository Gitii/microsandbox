//! Local offline disk operations.

use napi::bindgen_prelude::BigInt;
use napi_derive::napi;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[napi(object)]
pub struct DiskInfo {
    pub uuid: String,
    pub capacity_bytes: BigInt,
    pub file_bytes: BigInt,
    pub allocated_bytes: Option<BigInt>,
    pub needs_recovery: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn convert(
    result: Result<microsandbox::disk::DiskInfo, microsandbox::disk::DiskError>,
) -> napi::Result<DiskInfo> {
    let info = result.map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(DiskInfo {
        uuid: info.uuid,
        capacity_bytes: info.capacity_bytes.into(),
        file_bytes: info.file_bytes.into(),
        allocated_bytes: info.allocated_bytes.map(Into::into),
        needs_recovery: info.needs_recovery,
    })
}

fn size(value: BigInt) -> napi::Result<u64> {
    let (negative, value, lossless) = value.get_u64();
    if negative || !lossless {
        return Err(napi::Error::from_reason(
            "size must fit an unsigned 64-bit integer",
        ));
    }
    Ok(value)
}

#[napi]
pub fn disk_create(path: String, size_bytes: BigInt) -> napi::Result<DiskInfo> {
    convert(microsandbox::disk::create(path, size(size_bytes)?))
}

#[napi]
pub fn disk_inspect(path: String) -> napi::Result<DiskInfo> {
    convert(microsandbox::disk::inspect(path))
}

#[napi]
pub fn disk_grow_copy(
    source: String,
    destination: String,
    size_bytes: BigInt,
) -> napi::Result<DiskInfo> {
    convert(microsandbox::disk::grow_copy(
        source,
        destination,
        size(size_bytes)?,
    ))
}
