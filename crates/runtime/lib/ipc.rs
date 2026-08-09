//! Host-side per-sandbox IPC endpoint paths and lifecycle cleanup.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Bytes of SHA-256 used by the canonical per-sandbox socket directory.
pub const CANONICAL_SOCKET_HASH_BYTES: usize = 12;

/// Bytes of SHA-256 used by the legacy flat agent socket names.
pub const LEGACY_SOCKET_HASH_BYTES: usize = 16;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Canonical and compatibility Unix socket paths owned by one sandbox name.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxSocketPaths {
    /// Canonical directory containing the sandbox's runtime sockets.
    pub canonical_dir: PathBuf,
    /// Canonical agent relay socket.
    pub agent: PathBuf,
    /// Canonical host-control socket.
    pub control: PathBuf,
    /// Legacy flat agent socket path used by older clients.
    pub legacy_agent: PathBuf,
    /// Legacy flat control socket path used by older clients.
    pub legacy_control: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Derive the canonical agent endpoint for a sandbox name.
pub fn canonical_agent_endpoint(run_dir: &Path, name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        sandbox_socket_paths(run_dir, name).agent
    }

    #[cfg(windows)]
    {
        let _ = run_dir;
        PathBuf::from(format!(
            r"\\.\pipe\msb-agent-{}",
            socket_hash(name, LEGACY_SOCKET_HASH_BYTES)
        ))
    }
}

/// Derive the control endpoint belonging to an agent endpoint.
pub fn control_socket_path_for(agent_sock: &Path) -> PathBuf {
    #[cfg(unix)]
    if is_canonical_agent_socket(agent_sock) {
        return agent_sock.with_file_name("control.sock");
    }

    agent_sock.with_extension(crate::control::CONTROL_SOCKET_EXTENSION)
}

/// Derive every canonical and compatibility Unix socket path for a sandbox.
#[cfg(unix)]
pub fn sandbox_socket_paths(run_dir: &Path, name: &str) -> SandboxSocketPaths {
    let digest = Sha256::digest(name.as_bytes());
    let canonical_id = encode_hash(&digest, CANONICAL_SOCKET_HASH_BYTES);
    let legacy_id = encode_hash(&digest, LEGACY_SOCKET_HASH_BYTES);
    let canonical_dir = run_dir.join("sandboxes").join(canonical_id);
    let agent = canonical_dir.join("agent.sock");
    let control = control_socket_path_for(&agent);
    let legacy_agent = run_dir.join("agent").join(format!("{legacy_id}.sock"));
    let legacy_control = control_socket_path_for(&legacy_agent);

    SandboxSocketPaths {
        canonical_dir,
        agent,
        control,
        legacy_agent,
        legacy_control,
    }
}

/// Return whether a Unix socket path fits the platform `sockaddr_un` field.
#[cfg(unix)]
pub fn socket_path_fits(path: &Path) -> bool {
    socket_path_len(path) < unix_socket_path_capacity()
}

/// Validate both endpoints in an agent/control socket pair.
#[cfg(unix)]
pub fn validate_socket_pair(agent_sock: &Path) -> std::io::Result<()> {
    let control_sock = control_socket_path_for(agent_sock);
    for path in [agent_sock, control_sock.as_path()] {
        if !socket_path_fits(path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Unix socket path is too long: {} bytes at {}; paths must be shorter than {} bytes",
                    socket_path_len(path),
                    path.display(),
                    unix_socket_path_capacity()
                ),
            ));
        }
    }
    Ok(())
}

/// Prepare the canonical socket directory when `agent_sock` uses that layout.
#[cfg(unix)]
pub fn prepare_canonical_socket_dir(
    run_dir: &Path,
    name: &str,
    agent_sock: &Path,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let paths = sandbox_socket_paths(run_dir, name);
    if agent_sock != paths.agent {
        return Ok(());
    }

    let parent = paths.canonical_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "canonical socket directory has no parent: {}",
                paths.canonical_dir.display()
            ),
        )
    })?;
    std::fs::create_dir_all(parent)?;
    match std::fs::create_dir(&paths.canonical_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(&paths.canonical_dir)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "canonical socket path is not a directory: {}",
                        paths.canonical_dir.display()
                    ),
                ));
            }
        }
        Err(error) => return Err(error),
    }
    std::fs::set_permissions(&paths.canonical_dir, std::fs::Permissions::from_mode(0o700))
}

/// Publish the legacy agent symlink for an already-bound runtime endpoint.
#[cfg(unix)]
pub fn publish_legacy_agent_link(
    run_dir: &Path,
    name: &str,
    agent_sock: &Path,
) -> std::io::Result<()> {
    let paths = sandbox_socket_paths(run_dir, name);
    if agent_sock == paths.legacy_agent {
        // An older launcher asks the new runtime to bind the compatibility
        // path directly. The endpoint already satisfies that client contract.
        return Ok(());
    }
    validate_compatibility_path(&paths.legacy_agent)?;
    publish_compatibility_link(run_dir, &paths.legacy_agent, agent_sock)
}

/// Publish the legacy control symlink for an already-bound runtime endpoint.
#[cfg(unix)]
pub fn publish_legacy_control_link(
    run_dir: &Path,
    name: &str,
    control_sock: &Path,
) -> std::io::Result<()> {
    let paths = sandbox_socket_paths(run_dir, name);
    if control_sock == paths.legacy_control {
        return Ok(());
    }
    validate_compatibility_path(&paths.legacy_control)?;
    publish_compatibility_link(run_dir, &paths.legacy_control, control_sock)
}

/// Remove one agent/control socket pair, treating missing files as success.
pub fn remove_socket_pair(agent_sock: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let control_sock = control_socket_path_for(agent_sock);
        let control_result = remove_file_if_exists(&control_sock);
        let agent_result = remove_file_if_exists(agent_sock);
        control_result.and(agent_result)
    }

    #[cfg(windows)]
    {
        let _ = agent_sock;
        Ok(())
    }
}

/// Remove only the canonical socket namespace for one sandbox name.
pub fn remove_canonical_socket_artifacts(run_dir: &Path, name: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        remove_canonical_socket_dir(&sandbox_socket_paths(run_dir, name))
    }

    #[cfg(windows)]
    {
        let _ = (run_dir, name);
        Ok(())
    }
}

/// Remove canonical and compatibility socket artifacts for one sandbox name.
pub fn remove_sandbox_socket_artifacts(run_dir: &Path, name: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let paths = sandbox_socket_paths(run_dir, name);
        let mut first_error = None;

        for path in [&paths.legacy_control, &paths.legacy_agent] {
            if let Err(error) = remove_file_if_exists(path)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }

        if let Err(error) = remove_canonical_socket_artifacts(run_dir, name)
            && first_error.is_none()
        {
            first_error = Some(error);
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    #[cfg(windows)]
    {
        let _ = (run_dir, name);
        Ok(())
    }
}

#[cfg(unix)]
fn publish_compatibility_link(run_dir: &Path, link: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::symlink;

    let parent = link.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("compatibility link has no parent: {}", link.display()),
        )
    })?;
    std::fs::create_dir_all(parent)?;

    // Prefer a relative target for endpoints under the same run directory so
    // compatibility links do not bake the absolute MSB_HOME into the tree.
    let link_target = target
        .strip_prefix(run_dir)
        .map(|relative| PathBuf::from("..").join(relative))
        .unwrap_or_else(|_| target.to_path_buf());

    match symlink(&link_target, link) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::symlink_metadata(link)?.file_type().is_symlink()
                && std::fs::read_link(link)? == link_target
            {
                return Ok(());
            }

            // Publication is deliberately no-replace. Lifecycle cleanup owns
            // stale files; startup must never unlink a possibly-live legacy
            // endpoint merely because the sandbox name matches.
            Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "legacy runtime endpoint already exists at {}",
                    link.display()
                ),
            ))
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn validate_compatibility_path(path: &Path) -> std::io::Result<()> {
    if socket_path_fits(path) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "legacy Unix socket path is too long: {} bytes at {}; paths must be shorter than {} bytes",
                socket_path_len(path),
                path.display(),
                unix_socket_path_capacity()
            ),
        ))
    }
}

#[cfg(windows)]
fn socket_hash(name: &str, bytes: usize) -> String {
    encode_hash(&Sha256::digest(name.as_bytes()), bytes)
}

fn encode_hash(digest: &[u8], bytes: usize) -> String {
    let mut hash = String::with_capacity(bytes * 2);
    for byte in digest.iter().take(bytes) {
        let _ = write!(hash, "{byte:02x}");
    }
    hash
}

#[cfg(unix)]
fn is_canonical_agent_socket(path: &Path) -> bool {
    let Some(id) = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|id| id.to_str())
    else {
        return false;
    };

    path.file_name().is_some_and(|name| name == "agent.sock")
        && path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .is_some_and(|name| name == "sandboxes")
        && id.len() == CANONICAL_SOCKET_HASH_BYTES * 2
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn remove_file_if_exists(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn remove_canonical_socket_dir(paths: &SandboxSocketPaths) -> std::io::Result<()> {
    let metadata = match std::fs::symlink_metadata(&paths.canonical_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    if metadata.file_type().is_symlink() {
        // Remove the unexpected namespace entry itself without following it
        // to attacker-controlled socket names elsewhere on the host.
        return std::fs::remove_file(&paths.canonical_dir);
    }
    if !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "canonical socket path is not a directory: {}",
                paths.canonical_dir.display()
            ),
        ));
    }

    let control_result = remove_file_if_exists(&paths.control);
    let agent_result = remove_file_if_exists(&paths.agent);
    control_result.and(agent_result)?;
    std::fs::remove_dir(&paths.canonical_dir)
}

#[cfg(unix)]
fn socket_path_len(path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().len()
}

#[cfg(unix)]
fn unix_socket_path_capacity() -> usize {
    let storage = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    storage.sun_path.len()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn derives_canonical_and_legacy_hashes_from_one_name() {
        let paths = sandbox_socket_paths(Path::new("/tmp/msb/run"), "worker");

        assert_eq!(
            paths.agent,
            Path::new("/tmp/msb/run/sandboxes/87eba76e7f3164534045ba92/agent.sock")
        );
        assert_eq!(
            paths.control,
            Path::new("/tmp/msb/run/sandboxes/87eba76e7f3164534045ba92/control.sock")
        );
        assert_eq!(
            paths.legacy_agent,
            Path::new("/tmp/msb/run/agent/87eba76e7f3164534045ba922e7770fb.sock")
        );
        assert_eq!(
            paths.legacy_control,
            Path::new("/tmp/msb/run/agent/87eba76e7f3164534045ba922e7770fb.control.sock")
        );
        assert_eq!(control_socket_path_for(&paths.agent), paths.control);
        assert_eq!(
            control_socket_path_for(Path::new("/tmp/msb/sandboxes/worker/runtime/agent.sock")),
            Path::new("/tmp/msb/sandboxes/worker/runtime/agent.control.sock")
        );
    }

    #[test]
    #[cfg(unix)]
    fn derives_hashes_from_utf8_name_bytes() {
        let paths = sandbox_socket_paths(Path::new("/tmp/msb/run"), "工作");

        assert_eq!(
            paths.agent,
            Path::new("/tmp/msb/run/sandboxes/bc62d1b6b936c78dbbd0bbe5/agent.sock")
        );
        assert_eq!(
            paths.legacy_agent,
            Path::new("/tmp/msb/run/agent/bc62d1b6b936c78dbbd0bbe5572e32d0.sock")
        );
    }

    #[test]
    #[cfg(unix)]
    fn validates_the_control_endpoint_at_the_unix_path_boundary() {
        let capacity = unix_socket_path_capacity();
        let accepted = PathBuf::from(format!(
            "/{}.sock",
            "a".repeat(capacity - "/.control.sock".len() - 1)
        ));
        let rejected = PathBuf::from(format!(
            "/{}.sock",
            "a".repeat(capacity - "/.control.sock".len())
        ));

        assert_eq!(
            socket_path_len(&control_socket_path_for(&accepted)),
            capacity - 1
        );
        assert!(validate_socket_pair(&accepted).is_ok());
        assert_eq!(
            socket_path_len(&control_socket_path_for(&rejected)),
            capacity
        );
        assert_eq!(
            validate_socket_pair(&rejected).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    #[cfg(unix)]
    fn compatibility_links_reach_canonical_unix_sockets() {
        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = sandbox_socket_paths(&run_dir, "compat");
        std::fs::create_dir_all(&paths.canonical_dir).unwrap();
        let _agent = std::os::unix::net::UnixListener::bind(&paths.agent).unwrap();
        let _control = std::os::unix::net::UnixListener::bind(&paths.control).unwrap();

        publish_legacy_agent_link(&run_dir, "compat", &paths.agent).unwrap();
        publish_legacy_control_link(&run_dir, "compat", &paths.control).unwrap();

        assert_eq!(
            std::fs::read_link(&paths.legacy_agent).unwrap(),
            Path::new("../sandboxes")
                .join(paths.canonical_dir.file_name().unwrap())
                .join("agent.sock")
        );
        assert_eq!(
            std::fs::read_link(&paths.legacy_control).unwrap(),
            Path::new("../sandboxes")
                .join(paths.canonical_dir.file_name().unwrap())
                .join("control.sock")
        );
        std::os::unix::net::UnixStream::connect(&paths.legacy_agent).unwrap();
        std::os::unix::net::UnixStream::connect(&paths.legacy_control).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn compatibility_publication_never_replaces_a_live_legacy_socket() {
        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = sandbox_socket_paths(&run_dir, "collision");
        std::fs::create_dir_all(&paths.canonical_dir).unwrap();
        std::fs::create_dir_all(paths.legacy_agent.parent().unwrap()).unwrap();
        let _canonical = std::os::unix::net::UnixListener::bind(&paths.agent).unwrap();
        let _legacy = std::os::unix::net::UnixListener::bind(&paths.legacy_agent).unwrap();

        let error = publish_legacy_agent_link(&run_dir, "collision", &paths.agent).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        std::os::unix::net::UnixStream::connect(&paths.legacy_agent).unwrap();
        assert!(
            !std::fs::symlink_metadata(&paths.legacy_agent)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    #[cfg(unix)]
    fn new_runtime_accepts_legacy_paths_supplied_by_an_old_launcher() {
        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = sandbox_socket_paths(&run_dir, "old-launcher");
        std::fs::create_dir_all(paths.legacy_agent.parent().unwrap()).unwrap();
        let _agent = std::os::unix::net::UnixListener::bind(&paths.legacy_agent).unwrap();
        let _control = std::os::unix::net::UnixListener::bind(&paths.legacy_control).unwrap();

        publish_legacy_agent_link(&run_dir, "old-launcher", &paths.legacy_agent).unwrap();
        publish_legacy_control_link(&run_dir, "old-launcher", &paths.legacy_control).unwrap();

        assert!(
            !std::fs::symlink_metadata(&paths.legacy_agent)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            !std::fs::symlink_metadata(&paths.legacy_control)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::os::unix::net::UnixStream::connect(&paths.legacy_agent).unwrap();
        std::os::unix::net::UnixStream::connect(&paths.legacy_control).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn sandbox_cleanup_removes_canonical_and_compatibility_artifacts() {
        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = sandbox_socket_paths(&run_dir, "cleanup");
        std::fs::create_dir_all(&paths.canonical_dir).unwrap();
        let agent = std::os::unix::net::UnixListener::bind(&paths.agent).unwrap();
        let control = std::os::unix::net::UnixListener::bind(&paths.control).unwrap();
        publish_legacy_agent_link(&run_dir, "cleanup", &paths.agent).unwrap();
        publish_legacy_control_link(&run_dir, "cleanup", &paths.control).unwrap();

        remove_sandbox_socket_artifacts(&run_dir, "cleanup").unwrap();

        assert!(!paths.agent.exists());
        assert!(!paths.control.exists());
        assert!(std::fs::symlink_metadata(&paths.legacy_agent).is_err());
        assert!(std::fs::symlink_metadata(&paths.legacy_control).is_err());
        assert!(!paths.canonical_dir.exists());

        drop((agent, control));
        remove_sandbox_socket_artifacts(&run_dir, "cleanup").unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn sandbox_cleanup_does_not_follow_a_canonical_directory_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = sandbox_socket_paths(&run_dir, "symlink");
        let external = temp.path().join("external");
        std::fs::create_dir_all(paths.canonical_dir.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&external).unwrap();
        std::fs::write(external.join("agent.sock"), b"do not remove").unwrap();
        symlink(&external, &paths.canonical_dir).unwrap();

        remove_sandbox_socket_artifacts(&run_dir, "symlink").unwrap();

        assert!(external.join("agent.sock").exists());
        assert!(std::fs::symlink_metadata(&paths.canonical_dir).is_err());
    }
}
