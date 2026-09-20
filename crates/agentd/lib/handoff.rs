//! PID 1 handoff to a guest init.
//!
//! After [`init::init`] returns, agentd may be configured to hand off
//! PID 1 to a user-supplied init binary (typically `systemd`, but any
//! init works). This module implements the fork+exec dance:
//!
//! - **Parent** keeps PID 1 (execve preserves it), execs the target
//!   init, and is supervised by the kernel as the new PID 1.
//! - **Child** continues as a normal grandchild process and runs the
//!   agent loop, serving host requests over virtio-serial.
//!
//! The handoff happens before any tokio runtime is built and before
//! virtio-serial is opened, keeping the fork single-threaded and
//! free of duplicated runtime state.
//!
//! [`init::init`]: crate::init::init
//!
//! ### Performance constraint
//!
//! The fork point relies on agentd's RSS being tiny (<5MB) so
//! copy-on-write page-table duplication is cheap (~1µs/page). If
//! agentd ever grows large in-memory caches before this point, fork
//! cost scales linearly with mapped memory. Keep init::init light and
//! don't move the fork point later.

use std::ffi::{CString, OsString};
use std::fs::{Metadata, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process;

use nix::sys::signal::{SigSet, SigmaskHow, Signal, sigprocmask};
use nix::unistd::{ForkResult, fork, setsid};

use microsandbox_protocol::{HANDOFF_INIT_AUTO, HANDOFF_INIT_AUTO_CANDIDATES};

use crate::config::HandoffInit;
use crate::error::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Post-handoff agentd stderr log path.
///
/// Without this redirect, agentd and the new init both write to the VM
/// serial console and their output interleaves. The directory is
/// created in `init::init` (see `create_run_dir`).
const POST_HANDOFF_STDERR: &str = "/run/microsandbox/agentd.log";

/// Directories searched for `systemctl` when `PATH` does not resolve it.
/// agentd runs with whatever environment the VMM handed it, which on a
/// handoff boot may carry no `PATH` at all.
const SYSTEMCTL_FALLBACK_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// systemd's private control socket. `systemctl` connects to this (or to the
/// system bus, which appears later still), so until it exists no shutdown
/// request can be delivered to the manager.
const SYSTEMD_CONTROL_SOCKET: &str = "/run/systemd/private";

/// How long a shutdown request waits for systemd to be able to take it.
///
/// A handoff boot answers agentd's exec channel as soon as agentd is up, which
/// is before it has even executed the image's init: a shutdown asked for in
/// that gap reaches a manager that is not listening. The host gives a handoff
/// guest `HANDOFF_SHUTDOWN_FLUSH_TIMEOUT` (120s) to power off before it kills
/// the VM, so this waits well inside that window — a guest whose systemd has
/// not opened its control socket in 30 seconds is broken, not slow.
const SYSTEMD_CONTROL_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// How often the wait above looks for the socket. systemd offers nothing to
/// wait on before the socket exists, so the wait polls.
const SYSTEMD_CONTROL_POLL: std::time::Duration = std::time::Duration::from_millis(50);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Forks and execs the configured init binary, returning to the caller
/// only in the child process.
///
/// In the **parent** (which becomes the new PID 1), this function calls
/// `execve` and never returns on success. On execve failure, it writes
/// to the console and exits non-zero — the kernel panics PID 1, the
/// VMM exits, and the host hits its connect timeout. The pre-flight
/// check below makes this rare.
///
/// In the **child**, this function redirects stderr to a log file and
/// returns `Ok(())`, after which the caller falls through to the
/// runtime build and the agent loop.
pub fn do_handoff(spec: HandoffInit) -> AgentdResult<()> {
    let cmd = resolve_cmd(&spec.cmd)?;
    preflight(&cmd)?;
    if let Some(ref cwd) = spec.cwd {
        preflight_cwd(cwd)?;
    }

    let argv = build_argv(&cmd, &spec.argv);
    let envp = build_envp(&spec.env);
    let cmd_c = path_to_cstring(&cmd)?;

    // SAFETY: `fork()` in a single-threaded process with no opened
    // serial fds and no async runtime. The agent loop has not started
    // yet; tls/init writes are complete; only stdin/stdout/stderr are
    // inherited from the kernel.
    match unsafe { fork() }? {
        ForkResult::Parent { .. } => {
            // We are now the new PID 1's pre-image. Restore default
            // signal disposition + clear blocked mask before exec so
            // the new init starts with kernel defaults.
            reset_signals();
            if let Some(ref cwd) = spec.cwd
                && let Err(err) = nix::unistd::chdir(cwd)
            {
                let _ = writeln!(
                    std::io::stderr(),
                    "agentd: chdir({}) before handoff failed: {err}",
                    cwd.display()
                );
                process::exit(126);
            }
            // SAFETY: arrays are NUL-terminated; pointers live until
            // execve consumes them or returns with an error.
            let err = nix::unistd::execve(&cmd_c, &argv, &envp).unwrap_err();
            // Past this point, exec has failed. Write a diagnostic to
            // the kernel console and exit non-zero so the kernel
            // panics PID 1 and the VMM tears the guest down.
            let _ = writeln!(
                std::io::stderr(),
                "agentd: execve({}) failed: {err}",
                cmd.display()
            );
            process::exit(127);
        }
        ForkResult::Child => {
            isolate_child_from_init()?;
            redirect_child_stderr();
            Ok(())
        }
    }
}

/// Resolves the user-supplied cmd, expanding the `auto` sentinel
/// into the first executable regular file from
/// [`HANDOFF_INIT_AUTO_CANDIDATES`].
///
/// Non-`auto` paths are returned unchanged; downstream `preflight`
/// validates them.
fn resolve_cmd(cmd: &Path) -> AgentdResult<PathBuf> {
    if cmd != Path::new(HANDOFF_INIT_AUTO) {
        return Ok(cmd.to_path_buf());
    }

    resolve_auto_cmd(HANDOFF_INIT_AUTO_CANDIDATES)
}

fn resolve_auto_cmd(candidates: &[&str]) -> AgentdResult<PathBuf> {
    for candidate in candidates {
        let p = Path::new(candidate);
        if init_candidate_is_executable_file(p) {
            return Ok(p.to_path_buf());
        }
    }

    Err(AgentdError::Init(format!(
        "{HANDOFF_INIT_AUTO}: no init binary found, checked: {}",
        candidates.join(", ")
    )))
}

/// Verifies the init binary exists and is executable. Runs in the
/// parent (pre-fork) so failures surface via the normal init-failure
/// path rather than a kernel panic on PID 1 exit.
fn preflight(cmd: &Path) -> AgentdResult<()> {
    let metadata = std::fs::metadata(cmd).map_err(|e| {
        AgentdError::Init(format!(
            "handoff init binary not found at {}: {e}",
            cmd.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(AgentdError::Init(format!(
            "handoff init path is not a regular file: {}",
            cmd.display()
        )));
    }
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(AgentdError::Init(format!(
            "handoff init binary is not executable: {}",
            cmd.display()
        )));
    }
    Ok(())
}

fn preflight_cwd(cwd: &Path) -> AgentdResult<()> {
    let metadata = std::fs::metadata(cwd).map_err(|e| {
        AgentdError::Init(format!(
            "handoff init cwd not found at {}: {e}",
            cwd.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(AgentdError::Init(format!(
            "handoff init cwd is not a directory: {}",
            cwd.display()
        )));
    }
    Ok(())
}

fn init_candidate_is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata_is_executable_file(&metadata))
        .unwrap_or(false)
}

fn metadata_is_executable_file(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

/// Builds the C argv list for execve.
///
/// `argv[0]` is the cmd path itself; supplemental args follow.
/// argv values come from the host SDK's validated wire format and from
/// the cmd path which `path_to_cstring` already screens for NUL, so
/// the [`CString::new`] calls here are infallible in practice. Any
/// NUL-bearing value is silently skipped rather than corrupting argv.
fn build_argv(cmd: &Path, supplemental: &[OsString]) -> Vec<CString> {
    let mut out = Vec::with_capacity(1 + supplemental.len());
    if let Ok(c) = CString::new(cmd.as_os_str().as_encoded_bytes()) {
        out.push(c);
    }
    for arg in supplemental {
        if let Ok(c) = CString::new(arg.as_bytes()) {
            out.push(c);
        }
    }
    out
}

/// Builds the C envp list: inherited env + spec.env, with later
/// entries overriding earlier ones by key. Order is unspecified
/// (execve doesn't care).
///
/// Entries whose `KEY=VALUE` encoding contains a NUL byte are skipped
/// rather than substituted — a malformed entry would confuse the new
/// init in subtle ways.
fn build_envp(extras: &[(OsString, OsString)]) -> Vec<CString> {
    use std::collections::HashMap;

    let mut env: HashMap<OsString, OsString> = std::env::vars_os().collect();

    // Strip our own boot params from the inherited env so the new
    // init doesn't see stale MSB_* values that referred to agentd's
    // boot, not its own runtime.
    for var in [
        microsandbox_protocol::ENV_HANDOFF_INIT,
        microsandbox_protocol::ENV_HANDOFF_INIT_ARGS,
        microsandbox_protocol::ENV_HANDOFF_INIT_CWD,
        microsandbox_protocol::ENV_HANDOFF_INIT_ENV,
    ] {
        env.remove(&OsString::from(var));
    }

    for (k, v) in extras {
        env.insert(k.clone(), v.clone());
    }

    env.into_iter()
        .filter_map(|(k, v)| {
            let mut bytes = k.into_vec();
            bytes.push(b'=');
            bytes.extend(v.into_vec());
            CString::new(bytes).ok()
        })
        .collect()
}

/// Converts a `Path` to a `CString` for execve, returning a config
/// error on interior NUL.
fn path_to_cstring(path: &Path) -> AgentdResult<CString> {
    CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        AgentdError::Config(format!("init path contains NUL byte: {}", path.display()))
    })
}

/// Resets all signal dispositions to SIG_DFL and clears the blocked
/// signal mask so the new init starts with kernel defaults.
fn reset_signals() {
    use nix::sys::signal::{SigHandler, sigaction};
    let dfl = nix::sys::signal::SigAction::new(
        SigHandler::SigDfl,
        nix::sys::signal::SaFlags::empty(),
        SigSet::empty(),
    );
    for signum in 1..=31 {
        // SIGKILL (9) and SIGSTOP (19) cannot be reset, but
        // sigaction returns EINVAL silently — ignore.
        let Ok(sig) = Signal::try_from(signum) else {
            continue;
        };
        // SAFETY: setting SIG_DFL is always safe.
        let _ = unsafe { sigaction(sig, &dfl) };
    }
    let empty = SigSet::empty();
    let _ = sigprocmask(SigmaskHow::SIG_SETMASK, Some(&empty), None);
}

/// Moves the surviving agentd process into a new session so init
/// systems that manage their original session/process group do not
/// accidentally signal the agent relay.
fn isolate_child_from_init() -> AgentdResult<()> {
    setsid().map_err(|e| AgentdError::Init(format!("failed to isolate agentd session: {e}")))?;
    Ok(())
}

/// Redirects the child's stderr to the post-handoff log file. Best
/// effort — a failure here just leaves stderr pointing at the serial
/// console (interleaved with the new init's output). The agent loop
/// keeps working either way.
fn redirect_child_stderr() {
    let Ok(file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(POST_HANDOFF_STDERR)
    else {
        return;
    };
    // SAFETY: dup2 onto stderr (fd=2) is well-defined; the source fd
    // is owned by `file` until the function returns.
    unsafe {
        libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO);
    }
}

/// Returns true when the current process is PID 1 in its PID
/// namespace. After handoff, agentd is no longer PID 1, and any code
/// path that relied on that (e.g. `reboot()`) needs to take a different
/// route.
pub fn is_pid_1() -> bool {
    nix::unistd::getpid().as_raw() == 1
}

/// Locate the image's `systemctl`, searching `PATH` first and then the
/// directories a distribution is most likely to install it in.
///
/// The path is the image's to choose: a merged-`/usr` distribution puts it in
/// `/usr/bin`, others in `/bin`, and a minimal image may ship none at all.
///
/// A candidate counts only when it is an executable file. A non-executable
/// `systemctl` — a stub, a leftover, a file mode the image never fixed — would
/// otherwise be spawned and fail, taking the poweroff with it instead of
/// falling back to the signal path.
fn find_systemctl() -> Option<PathBuf> {
    let path_dirs = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();

    path_dirs
        .into_iter()
        .chain(SYSTEMCTL_FALLBACK_DIRS.iter().map(PathBuf::from))
        .map(|dir| dir.join("systemctl"))
        .find(|candidate| is_executable_file(candidate))
}

/// Whether `path` is a regular file with at least one execute bit set.
///
/// agentd runs as root, so any execute bit is enough for it to spawn.
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Ask the image's init to power off without forcing running services down.
///
/// systemd's control client belongs to the image: it knows its manager's
/// shutdown protocol independently of agentd's libc. In particular, musl's
/// SIGRTMIN+4 is glibc systemd's reboot signal, not its poweroff signal.
/// Other init implementations retain the existing realtime-signal contract.
pub fn signal_init_shutdown() -> AgentdResult<()> {
    let init_name = std::fs::read_to_string("/proc/1/comm")?;
    if init_name.trim() == "systemd" {
        // Delivery, not politeness: systemctl exits non-zero when the manager
        // is not listening yet, which used to lose the request entirely and
        // leave the host to kill the VM two minutes later.
        if !wait_for_control_socket(Path::new(SYSTEMD_CONTROL_SOCKET), SYSTEMD_CONTROL_WAIT) {
            eprintln!(
                "agentd: systemd is PID 1 but opened no control socket at {} within {}s; \
                 falling back to the realtime-signal shutdown",
                SYSTEMD_CONTROL_SOCKET,
                SYSTEMD_CONTROL_WAIT.as_secs()
            );
            return signal_pid_1_shutdown();
        }
        match find_systemctl() {
            Some(systemctl) => {
                let status = process::Command::new(&systemctl)
                    .args(["--no-block", "poweroff"])
                    .status()
                    .map_err(|e| AgentdError::Init(format!("request systemd poweroff: {e}")))?;
                if !status.success() {
                    return Err(AgentdError::Init(format!(
                        "systemd rejected poweroff request: {status}"
                    )));
                }
                return Ok(());
            }
            None => {
                // The image says systemd is PID 1 but ships no control
                // client we can find. The realtime signal is the weaker
                // contract (musl's SIGRTMIN+4 is glibc systemd's reboot,
                // not its poweroff) but it is the only route left.
                eprintln!(
                    "agentd: systemd is PID 1 but no systemctl was found on PATH or in {}; \
                     falling back to the realtime-signal shutdown",
                    SYSTEMCTL_FALLBACK_DIRS.join(", ")
                );
            }
        }
    }
    signal_pid_1_shutdown()
}

/// The realtime-signal shutdown contract every other init keeps, and the only
/// route left when systemd's control client cannot be reached.
fn signal_pid_1_shutdown() -> AgentdResult<()> {
    let sig = libc::SIGRTMIN() + 4;
    // SAFETY: kill(2) is signal-safe and pid=1 is always valid.
    let ret = unsafe { libc::kill(1, sig) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Waits for `path` to be a socket, up to `timeout`, and says whether it is.
///
/// Returns as soon as the socket is there; a path that exists as something
/// else is not one, so a leftover file cannot pass for a listening manager.
fn wait_for_control_socket(path: &Path, timeout: std::time::Duration) -> bool {
    use std::os::unix::fs::FileTypeExt;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::fs::metadata(path)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
        {
            return true;
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        std::thread::sleep(SYSTEMD_CONTROL_POLL.min(left));
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "microsandbox-agentd-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    #[test]
    fn resolve_cmd_passes_explicit_path_through() {
        let p = Path::new("/lib/systemd/systemd");
        let resolved = resolve_cmd(p).unwrap();
        assert_eq!(resolved, PathBuf::from("/lib/systemd/systemd"));
    }

    #[test]
    fn resolve_cmd_passes_through_non_existent_explicit_paths() {
        // Resolution intentionally doesn't `stat` non-`auto` paths;
        // `preflight` is responsible for that. This keeps the resolver
        // testable without a real filesystem layout.
        let p = Path::new("/no/such/init");
        let resolved = resolve_cmd(p).unwrap();
        assert_eq!(resolved, PathBuf::from("/no/such/init"));
    }

    #[test]
    fn resolve_cmd_auto_returns_first_existing_candidate_or_errors() {
        // Whichever happens on the host running the test: at least one
        // of the candidates likely exists on a real Linux box, but the
        // test box may also be macOS where none do. Either branch is
        // a valid outcome — assert only that the API behaves correctly.
        match resolve_cmd(Path::new(HANDOFF_INIT_AUTO)) {
            Ok(p) => {
                assert!(
                    HANDOFF_INIT_AUTO_CANDIDATES
                        .iter()
                        .any(|c| Path::new(c) == p),
                    "resolved path {p:?} not in candidate list"
                );
                assert!(p.exists(), "resolved path must exist");
            }
            Err(AgentdError::Init(msg)) => {
                assert!(msg.contains("no init binary found"));
                for c in HANDOFF_INIT_AUTO_CANDIDATES {
                    assert!(msg.contains(c), "error should list {c}");
                }
            }
            Err(e) => panic!("unexpected error variant: {e}"),
        }
    }

    #[test]
    fn resolve_auto_cmd_skips_non_executable_candidates() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_test_dir("auto-skip");
        let non_executable = dir.join("sbin-init");
        let executable = dir.join("systemd");

        std::fs::write(&non_executable, b"not executable").expect("write non-executable");
        std::fs::set_permissions(&non_executable, std::fs::Permissions::from_mode(0o644))
            .expect("chmod non-executable");
        std::fs::write(&executable, b"#!/bin/sh\n").expect("write executable");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("chmod executable");

        let candidates = [
            non_executable.to_str().expect("utf-8 temp path"),
            executable.to_str().expect("utf-8 temp path"),
        ];
        let resolved = resolve_auto_cmd(&candidates).expect("resolve executable candidate");

        assert_eq!(resolved, executable);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn control_socket_wait_returns_when_the_socket_is_already_there() {
        let dir = unique_test_dir("control-present");
        let socket = dir.join("private");
        let listener =
            std::os::unix::net::UnixListener::bind(&socket).expect("bind control socket");

        assert!(wait_for_control_socket(
            &socket,
            std::time::Duration::from_secs(5)
        ));

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn control_socket_wait_returns_when_the_socket_appears() {
        let dir = unique_test_dir("control-late");
        let socket = dir.join("private");
        let late = socket.clone();
        let manager = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            std::os::unix::net::UnixListener::bind(&late).expect("bind control socket")
        });

        assert!(wait_for_control_socket(
            &socket,
            std::time::Duration::from_secs(5)
        ));

        drop(manager.join().expect("manager thread"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn control_socket_wait_gives_up_and_never_takes_a_file_for_a_manager() {
        let dir = unique_test_dir("control-absent");
        let missing = dir.join("private");
        let regular = dir.join("not-a-socket");
        std::fs::write(&regular, b"leftover").expect("write regular file");

        let started = std::time::Instant::now();
        assert!(!wait_for_control_socket(
            &missing,
            std::time::Duration::from_millis(200)
        ));
        assert!(started.elapsed() >= std::time::Duration::from_millis(200));
        assert!(!wait_for_control_socket(
            &regular,
            std::time::Duration::from_millis(100)
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
