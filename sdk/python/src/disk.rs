//! Local offline disk maintenance.

use std::path::PathBuf;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[pyclass(name = "DiskInfo", frozen, get_all)]
pub struct PyDiskInfo {
    uuid: String,
    capacity_bytes: u64,
    file_bytes: u64,
    allocated_bytes: Option<u64>,
    needs_recovery: bool,
}

/// Synchronous offline maintenance; caller holds a stopped/detached lifecycle lock.
#[pyclass(name = "Disk")]
pub struct PyDisk;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyDisk {
    /// Create and durably publish a sparse ext4 image without clobbering a path.
    #[staticmethod]
    fn create(py: Python<'_>, path: PathBuf, size_bytes: u64) -> PyResult<PyDiskInfo> {
        convert(py.allow_threads(|| microsandbox::disk::create(path, size_bytes)))
    }

    /// Read and validate metadata without modifying an image.
    #[staticmethod]
    fn inspect(py: Python<'_>, path: PathBuf) -> PyResult<PyDiskInfo> {
        convert(py.allow_threads(|| microsandbox::disk::inspect(path)))
    }

    /// Grow a private copy and publish it exclusively, preserving the source.
    #[staticmethod]
    fn grow_copy(
        py: Python<'_>,
        source: PathBuf,
        destination: PathBuf,
        size_bytes: u64,
    ) -> PyResult<PyDiskInfo> {
        convert(py.allow_threads(|| microsandbox::disk::grow_copy(source, destination, size_bytes)))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn convert(
    result: Result<microsandbox::disk::DiskInfo, microsandbox::disk::DiskError>,
) -> PyResult<PyDiskInfo> {
    let info = result.map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok(PyDiskInfo {
        uuid: info.uuid,
        capacity_bytes: info.capacity_bytes,
        file_bytes: info.file_bytes,
        allocated_bytes: info.allocated_bytes,
        needs_recovery: info.needs_recovery,
    })
}
