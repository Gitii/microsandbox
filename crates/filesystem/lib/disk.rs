//! Offline maintenance of caller-owned extra disks. Stop and detach every user of
//! an image and hold an exclusive lifecycle lock across maintenance and manifest
//! adoption. These functions do not coordinate with running VMs or take locks.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use microsandbox_image::ext4::{self, Ext4FormatOptions};
use serde::Serialize;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Validated formatter-compatible ext4 image metadata (not a payload checksum).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskInfo {
    /// Filesystem UUID, preserved by grow-copy; not a unique artifact identifier.
    pub uuid: String,
    /// Filesystem capacity in bytes.
    pub capacity_bytes: u64,
    /// Host file logical length in bytes.
    pub file_bytes: u64,
    /// Host allocated bytes, or None when unavailable on this platform.
    pub allocated_bytes: Option<u64>,
    /// Whether an unclean journal needs recovery before use.
    pub needs_recovery: bool,
}

/// Offline disk maintenance failure.
#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    /// Host filesystem operation failed.
    #[error("disk I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Invalid or unsupported ext4 image.
    #[error("disk ext4: {0}")]
    Ext4(#[from] ext4::Ext4Error),
    /// The artifact failed verification.
    #[error("disk verification: {0}")]
    Verification(String),
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Inspect a stopped, detached ext4 disk without changing any bytes.
pub fn inspect(path: impl AsRef<Path>) -> Result<DiskInfo, DiskError> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(DiskError::Verification(
            "expected a regular file, not a symlink or device".into(),
        ));
    }
    let ext4::Ext4Inspection {
        uuid,
        capacity_bytes,
        needs_recovery,
    } = ext4::inspect_image(path)?;
    if metadata.len() != capacity_bytes {
        return Err(DiskError::Verification(
            "file length differs from ext4 capacity".into(),
        ));
    }
    #[cfg(unix)]
    let allocated_bytes = {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.blocks() * 512)
    };
    #[cfg(not(unix))]
    let allocated_bytes = None;
    let uuid = uuid
        .iter()
        .enumerate()
        .fold(String::new(), |mut s, (i, b)| {
            if [4, 6, 8, 10].contains(&i) {
                s.push('-');
            }
            s.push_str(&format!("{b:02x}"));
            s
        });
    Ok(DiskInfo {
        uuid,
        capacity_bytes,
        file_bytes: metadata.len(),
        allocated_bytes,
        needs_recovery,
    })
}

/// Create a sparse ext4 disk and durably publish it without replacing any path.
/// Sizes are bytes, aligned to 4096, subject to the ext4 formatter's limits.
pub fn create(path: impl AsRef<Path>, size_bytes: u64) -> Result<DiskInfo, DiskError> {
    publish(path.as_ref(), |temporary| {
        ext4::format_ext4(
            temporary,
            &Ext4FormatOptions {
                size_bytes,
                ..Default::default()
            },
        )?;
        let info = inspect(temporary)?;
        if info.capacity_bytes != size_bytes || info.needs_recovery {
            return Err(DiskError::Verification(
                "new filesystem geometry or journal state mismatch".into(),
            ));
        }
        Ok(info)
    })
}

/// Grow a private sparse copy, verify its ext4 metadata, UUID and capacity, then
/// durably publish it at an exclusive destination. Source is only ever read.
/// The caller adopts its manifest pointer after success and later removes the
/// old artifact. An interruption can leave a temporary file or a complete
/// destination; neither authorizes manifest adoption. A directory-sync error
/// can return an error after a complete destination is visible.
pub fn grow_copy(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    size_bytes: u64,
) -> Result<DiskInfo, DiskError> {
    let source = source.as_ref();
    let before = inspect(source)?;
    if size_bytes <= before.capacity_bytes || !size_bytes.is_multiple_of(4096) {
        return Err(DiskError::Verification(
            "growth requires a larger, 4096-byte-aligned capacity".into(),
        ));
    }
    publish(destination.as_ref(), |temporary| {
        let mut input = File::open(source)?;
        let mut output = File::options().write(true).open(temporary)?;
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            if buffer[..n].iter().all(|b| *b == 0) {
                output.seek(SeekFrom::Current(n as i64))?;
            } else {
                output.write_all(&buffer[..n])?;
            }
        }
        output.set_len(before.file_bytes)?;
        drop(output);
        ext4::grow_image(temporary, size_bytes)?;
        let after = inspect(temporary)?;
        if after.uuid != before.uuid || after.capacity_bytes != size_bytes || after.needs_recovery {
            return Err(DiskError::Verification(
                "replacement identity, capacity or journal state mismatch".into(),
            ));
        }
        Ok(after)
    })
}

fn publish(
    destination: &Path,
    build: impl FnOnce(&Path) -> Result<DiskInfo, DiskError>,
) -> Result<DiskInfo, DiskError> {
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "disk destination already exists",
            )
            .into());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Fail before doing work if directory synchronization is unavailable.
    let directory = File::open(parent)?;
    directory.sync_all()?;
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    let info = build(temporary.path())?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(destination)
        .map_err(|e| e.error)?;
    directory.sync_all()?;
    Ok(info)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grow_preserves_source_and_identity() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.ext4");
        let target = dir.path().join("target.ext4");
        let before = create(&source, 128 * 1024 * 1024).unwrap();
        #[cfg(unix)]
        assert!(before.allocated_bytes.unwrap() < before.file_bytes);
        let bytes = fs::read(&source).unwrap();
        let after = grow_copy(&source, &target, 256 * 1024 * 1024).unwrap();
        assert_eq!(before.uuid, after.uuid);
        assert_eq!(after.capacity_bytes, 256 * 1024 * 1024);
        assert_eq!(bytes, fs::read(&source).unwrap());
        assert!(grow_copy(&source, dir.path().join("shrink"), 64 * 1024 * 1024).is_err());
        assert!(!dir.path().join("shrink").exists());
        assert!(grow_copy(&source, &target, 512 * 1024 * 1024).is_err());
        assert_eq!(after, inspect(&target).unwrap());
        assert!(create(&source, 128 * 1024 * 1024).is_err());
        assert_eq!(bytes, fs::read(&source).unwrap());
    }

    #[test]
    fn failures_never_publish_a_blank_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");
        assert!(grow_copy(&source, &target, 64 * 1024 * 1024).is_err());
        fs::write(&source, b"corrupt").unwrap();
        assert!(grow_copy(&source, &target, 64 * 1024 * 1024).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"corrupt");
        assert!(!target.exists());
        assert!(
            publish(&target, |p| {
                fs::write(p, b"partial")?;
                Err(DiskError::Verification("interrupted build".into()))
            })
            .is_err()
        );
        assert!(!target.exists());
    }

    #[test]
    fn publication_race_does_not_clobber_winner() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let result = publish(&target, |temporary| {
            ext4::format_ext4(
                temporary,
                &Ext4FormatOptions {
                    size_bytes: 128 * 1024 * 1024,
                    ..Default::default()
                },
            )?;
            let info = inspect(temporary)?;
            fs::write(&target, b"another publisher won")?;
            Ok(info)
        });
        assert!(
            matches!(result, Err(DiskError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(&target).unwrap(), b"another publisher won");
    }

    #[test]
    fn interrupted_publication_preserves_source() {
        const CHILD_DIRECTORY: &str = "MSB_DISK_TEST_INTERRUPT_DIRECTORY";
        if let Some(directory) = std::env::var_os(CHILD_DIRECTORY) {
            let directory = std::path::PathBuf::from(directory);
            let _: Result<DiskInfo, DiskError> = publish(&directory.join("target"), |temporary| {
                fs::copy(directory.join("source"), temporary)?;
                ext4::grow_image(temporary, 256 * 1024 * 1024)?;
                // Abrupt process termination skips tempfile destructors and publication.
                std::process::exit(73);
            });
            panic!("child should terminate during private replacement preparation");
        }
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        create(&source, 128 * 1024 * 1024).unwrap();
        let before = fs::read(&source).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "disk::tests::interrupted_publication_preserves_source",
            ])
            .env(CHILD_DIRECTORY, directory.path())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        assert_eq!(before, fs::read(&source).unwrap());
        assert!(!directory.path().join("target").exists());
        assert_eq!(inspect(&source).unwrap().capacity_bytes, 128 * 1024 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_maintenance_targets() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let alias = directory.path().join("alias");
        create(&source, 128 * 1024 * 1024).unwrap();
        symlink(&source, &alias).unwrap();
        assert!(inspect(&alias).is_err());
        assert!(grow_copy(&source, &alias, 256 * 1024 * 1024).is_err());
        let dangling = directory.path().join("dangling");
        symlink(directory.path().join("absent"), &dangling).unwrap();
        assert!(create(&dangling, 128 * 1024 * 1024).is_err());
        assert!(fs::symlink_metadata(&dangling).unwrap().is_symlink());
    }
}
