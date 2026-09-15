//! Synchronous local disk maintenance FFI.

use std::os::raw::{c_char, c_uchar};

use super::{FfiError, cstr, run};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run an offline disk operation (create, inspect, grow_copy). The caller holds
/// the stopped/detached lifecycle lock. Output uses the standard FFI JSON ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_disk_operation(
    operation: *const c_char,
    source: *const c_char,
    destination: *const c_char,
    size_bytes: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let operation = unsafe { cstr(operation) }?;
        let source = unsafe { cstr(source) }?;
        let destination = unsafe { cstr(destination) }?;
        let result = match operation.as_str() {
            "create" => microsandbox::disk::create(destination, size_bytes),
            "inspect" => microsandbox::disk::inspect(source),
            "grow_copy" => microsandbox::disk::grow_copy(source, destination, size_bytes),
            _ => return Err(FfiError::internal("unknown disk operation")),
        }
        .map_err(|e| FfiError::internal(e.to_string()))?;
        serde_json::to_string(&result).map_err(|e| FfiError::internal(e.to_string()))
    })
}
