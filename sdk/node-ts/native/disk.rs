//! Local offline disk operations.

use napi::bindgen_prelude::{AsyncTask, BigInt};
use napi::{Env, Task};
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

/// Creating, inspecting and growing an image are multi-gigabyte copies plus an
/// `fsync`. Each runs on libuv's thread pool so the JS thread stays free.
pub enum DiskTask {
    /// Create a sparse ext4 image of `size_bytes` at `path`.
    Create { path: String, size_bytes: Size },

    /// Read the ext4 metadata at `path`.
    Inspect { path: String },

    /// Publish a larger verified copy of `source` at `destination`.
    GrowCopy {
        source: String,
        destination: String,
        size_bytes: Size,
    },
}

/// A size argument as JavaScript handed it over, checked in `compute` so a
/// rejected value surfaces as a rejected promise rather than a synchronous
/// throw from an otherwise asynchronous call.
pub struct Size {
    negative: bool,
    value: u64,
    lossless: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Size {
    fn get(&self) -> napi::Result<u64> {
        if self.negative || !self.lossless {
            return Err(napi::Error::from_reason(
                "size must fit an unsigned 64-bit integer",
            ));
        }
        Ok(self.value)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Task for DiskTask {
    type Output = microsandbox::disk::DiskInfo;
    type JsValue = DiskInfo;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let result = match self {
            Self::Create { path, size_bytes } => {
                microsandbox::disk::create(std::mem::take(path), size_bytes.get()?)
            }
            Self::Inspect { path } => microsandbox::disk::inspect(std::mem::take(path)),
            Self::GrowCopy {
                source,
                destination,
                size_bytes,
            } => microsandbox::disk::grow_copy(
                std::mem::take(source),
                std::mem::take(destination),
                size_bytes.get()?,
            ),
        };
        result.map_err(|e| napi::Error::from_reason(e.to_string()))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(DiskInfo {
            uuid: output.uuid,
            capacity_bytes: output.capacity_bytes.into(),
            file_bytes: output.file_bytes.into(),
            allocated_bytes: output.allocated_bytes.map(Into::into),
            needs_recovery: output.needs_recovery,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[napi(ts_return_type = "Promise<DiskInfo>")]
pub fn disk_create(path: String, size_bytes: BigInt) -> AsyncTask<DiskTask> {
    AsyncTask::new(DiskTask::Create {
        path,
        size_bytes: size(size_bytes),
    })
}

#[napi(ts_return_type = "Promise<DiskInfo>")]
pub fn disk_inspect(path: String) -> AsyncTask<DiskTask> {
    AsyncTask::new(DiskTask::Inspect { path })
}

#[napi(ts_return_type = "Promise<DiskInfo>")]
pub fn disk_grow_copy(
    source: String,
    destination: String,
    size_bytes: BigInt,
) -> AsyncTask<DiskTask> {
    AsyncTask::new(DiskTask::GrowCopy {
        source,
        destination,
        size_bytes: size(size_bytes),
    })
}

fn size(value: BigInt) -> Size {
    let (negative, value, lossless) = value.get_u64();
    Size {
        negative,
        value,
        lossless,
    }
}
