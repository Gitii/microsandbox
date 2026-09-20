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
///
/// It cannot be stale: `init::mount_run` mounts /run as a fresh tmpfs before
/// the handoff, so nothing an earlier boot wrote survives into this one.
const SYSTEMD_CONTROL_SOCKET: &str = "/run/systemd/private";

/// The signal number systemd reads as "power off", named rather than computed.
///
/// systemd documents this as `SIGRTMIN+4` (systemd(1), SIGNALS) and resolves it
/// against its own libc, which is glibc in every image we boot: glibc reserves
/// two realtime signals and starts at 34, so poweroff is 38 and reboot is 39.
/// agentd is a static musl binary and musl reserves three, starting at 35, so
/// `libc::SIGRTMIN() + 4` here is 39 — systemd's *reboot*, which brings the
/// guest back up instead of letting the VM exit. The raw number is the only
/// thing both sides agree on.
const SYSTEMD_POWEROFF_SIGNAL: i32 = 38;

/// How long a shutdown request waits for systemd to be able to take it.
///
/// A handoff boot answers agentd's exec channel as soon as agentd is up, which
/// is before it has even executed the image's init: a shutdown asked for in
/// that gap reaches a manager that is not listening.
///
/// Spent out of the same budget as the stop jobs. The host allows a handoff
/// guest `HANDOFF_SHUTDOWN_FLUSH_TIMEOUT` — 120 seconds, documented as room for
/// systemd's 90-second default service stop deadline — and the host may be told
/// to allow less (`MSB_SHUTDOWN_FLUSH_TIMEOUT_MS`), which agentd cannot see. So
/// this and [`SYSTEMD_POWEROFF_CALL_TIMEOUT`] together stay well under the 30
/// seconds that budget has to spare, and a guest whose systemd has not opened
/// its control socket in 10 seconds is broken rather than slow: the measured
/// wait on a real boot is about 300 milliseconds.
const SYSTEMD_CONTROL_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long `systemctl` is given to hand the request over.
///
/// `--no-block` returns as soon as the job is queued, in milliseconds. What
/// this bounds is a manager that accepts the connection and then does not
/// answer: sd-bus would wait out its own 25-second method timeout, and a
/// `systemctl` that never returns would hold the shutdown until the host's
/// backstop killed the VM — the failure this whole path exists to remove.
const SYSTEMD_POWEROFF_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How often the wait above looks for the socket. Polling rather than an
/// inotify watch on /run and then /run/systemd: the wait is a few hundred
/// milliseconds once and a two-level watch is more moving parts than it saves.
const SYSTEMD_CONTROL_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// How long a shutdown waits for a script init to become the init it execs.
///
/// A shutdown can arrive before PID 1 is what it is going to be: agentd
/// answers the host as soon as it is up, which on a handoff boot is while the
/// parent is still on its way into the image's init. An image whose init is a
/// script — masking units, checking mounts, then `exec`ing systemd — is PID 1
/// under its own name for the first tens of milliseconds, and a shutdown
/// decided there asks the wrong thing of the wrong process.
///
/// Only a script init waits, because only a script init is going to change
/// into something else; a compiled init is the answer already and pays
/// nothing. Three seconds against a measured forty milliseconds, and it comes
/// out of the same budget as everything else on this path: three here, ten
/// waiting for systemd's socket, ten for the `systemctl` call and systemd's
/// own ninety-second stop deadline still leave the host's 120 with room.
const INIT_EXEC_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// How often that wait looks at PID 1. An exec is not something a process can
/// be notified of, so this polls too, at the rate the socket wait does.
const INIT_EXEC_POLL: std::time::Duration = std::time::Duration::from_millis(10);

/// How long the realtime-signal route keeps asking.
///
/// PID 1 receives only the signals it has installed a handler for — the kernel
/// discards the rest, which is how an init is protected from being killed by
/// accident. An init that has just been exec'd has not installed anything yet,
/// so a single signal at that moment is a signal thrown away. Repeating is
/// free: a guest that took the first one is already on its way down and its
/// agentd goes with it, and a handler installed later catches the next.
const GENERIC_SIGNAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// How often that route repeats itself, within the window above.
const GENERIC_SIGNAL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Where PID 1's current program name is read from.
const PID_1_COMM: &str = "/proc/1/comm";

/// What the kernel keeps of a program's name: 16 bytes including the NUL, so
/// `distributed-init` is `distributed-ini` in `/proc/1/comm`. Compared against
/// the same truncation of the init agentd exec'd, never the whole name.
const COMM_LEN: usize = 15;

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
/// returns the init path it resolved, after which the caller falls through to
/// the runtime build and the agent loop. The caller keeps that path: the
/// shutdown request has to tell PID 1 still being the init agentd exec'd from
/// PID 1 having become whatever that init exec'd next.
pub fn do_handoff(spec: HandoffInit) -> AgentdResult<PathBuf> {
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
            Ok(cmd)
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

/// Which of the two shutdown contracts this guest's PID 1 keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShutdownRoute {
    /// systemd, asked through its own control client.
    Systemd,

    /// Anything else, asked with the realtime signal agentd defines.
    Generic,
}

/// Ask the image's init to power off without forcing running services down.
///
/// systemd's control client belongs to the image: it knows its manager's
/// shutdown protocol independently of agentd's libc, so `systemctl` is the
/// route taken whenever the manager can be reached. Every other init keeps the
/// realtime-signal contract agentd defines in its own terms.
pub async fn signal_init_shutdown(handoff_init: Option<&Path>) -> AgentdResult<()> {
    match shutdown_route(handoff_init, Path::new(PID_1_COMM), INIT_EXEC_WAIT).await? {
        ShutdownRoute::Systemd => request_systemd_poweroff().await,
        ShutdownRoute::Generic => signal_generic_init().await,
    }
}

/// Decides what PID 1 turned out to be.
///
/// `handoff_init` is the init agentd exec'd, and it is here to answer one
/// question: is the process in `/proc/1` still that one? A shutdown can arrive
/// while an image's script init is between masking its units and `exec`ing
/// systemd — our own image's does exactly that — and a route chosen then is
/// chosen on a name that is about to change. So a script init is given a
/// moment to become what it execs.
///
/// Only a script waits. An init that is a binary is the init this guest has,
/// and making every stop of a busybox or a test init wait for a change that is
/// never coming would charge the guests that need it least. Bounded either
/// way: a script still in `/proc/1` when the bound runs out is this guest's
/// init after all, and is read as one.
pub(crate) async fn shutdown_route(
    handoff_init: Option<&Path>,
    comm_path: &Path,
    timeout: std::time::Duration,
) -> AgentdResult<ShutdownRoute> {
    if let Some(init) = handoff_init
        && is_shebang_script(init)
        && let Some(name) = comm_of(init)
    {
        let deadline = tokio::time::Instant::now() + timeout;
        while read_comm(comm_path)? == name {
            if tokio::time::Instant::now() >= deadline {
                eprintln!(
                    "agentd: {} is still PID 1 after {:?}; taking it for this guest's init",
                    init.display(),
                    timeout
                );
                break;
            }
            tokio::time::sleep(INIT_EXEC_POLL.min(timeout)).await;
        }
    }
    if read_comm(comm_path)? == "systemd" {
        return Ok(ShutdownRoute::Systemd);
    }
    Ok(ShutdownRoute::Generic)
}

/// The realtime-signal route, repeated inside its window.
///
/// One signal is enough for an init that is already listening, and nothing at
/// all for one that has not installed its handler yet — the kernel drops what
/// PID 1 has no handler for, which is how an init is kept from being killed by
/// accident. Repeating covers the second case without costing the first
/// anything: the guest that took the first signal is powering off, and this
/// process goes down with it part way through the loop.
async fn signal_generic_init() -> AgentdResult<()> {
    let signal = generic_init_poweroff_signal();
    signal_pid_1(signal)?;
    let deadline = tokio::time::Instant::now() + GENERIC_SIGNAL_WINDOW;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(GENERIC_SIGNAL_INTERVAL).await;
        // A PID 1 that can no longer be signalled is not a failure here: the
        // guest is on its way down, which is what was asked of it.
        if signal_pid_1(signal).is_err() {
            return Ok(());
        }
    }
    Ok(())
}

/// A program name as the kernel keeps it, with the newline `/proc` adds
/// stripped.
fn read_comm(path: &Path) -> AgentdResult<String> {
    Ok(std::fs::read_to_string(path)?.trim_end().to_string())
}

/// What `/proc/1/comm` reads for a process exec'd from `path`.
fn comm_of(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    Some(name.chars().take(COMM_LEN).collect())
}

/// Whether `path` starts with a shebang, and so cannot be the last word on
/// what PID 1 is: the kernel runs the interpreter the line names, and the
/// script is free to `exec` something else once it has run.
fn is_shebang_script(path: &Path) -> bool {
    use std::io::Read;

    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut start = [0u8; 2];
    match file.read_exact(&mut start) {
        Ok(()) => &start == b"#!",
        Err(_) => false,
    }
}

/// Asks systemd to power off, and never returns without having asked.
///
/// Every route out of here either delivered the request to the manager or sent
/// it [`SYSTEMD_POWEROFF_SIGNAL`]: a request that is merely reported as failed
/// leaves the host to kill the VM when its flush window runs out, which is a
/// forced exit the caller records as an unclean shutdown.
async fn request_systemd_poweroff() -> AgentdResult<()> {
    if !wait_for_control_socket(Path::new(SYSTEMD_CONTROL_SOCKET), SYSTEMD_CONTROL_WAIT).await {
        // The weakest route of the three. A systemd this far from ready may not
        // have installed its signal handlers either, and the kernel discards a
        // realtime signal that PID 1 does not handle — so "sent" here can be a
        // no-op, and the host's backstop is what is left. It still beats
        // returning an error, which asks nothing of anybody.
        eprintln!(
            "agentd: systemd is PID 1 but opened no control socket at {} within {}s; \
             falling back to the poweroff signal",
            SYSTEMD_CONTROL_SOCKET,
            SYSTEMD_CONTROL_WAIT.as_secs()
        );
        return signal_pid_1(SYSTEMD_POWEROFF_SIGNAL);
    }
    let Some(systemctl) = find_systemctl() else {
        // The image says systemd is PID 1 but ships no control client we can
        // find. The signal carries less than `systemctl` does — no job mode,
        // no reply — but it is the only route left.
        eprintln!(
            "agentd: systemd is PID 1 but no systemctl was found on PATH or in {}; \
             falling back to the poweroff signal",
            SYSTEMCTL_FALLBACK_DIRS.join(", ")
        );
        return signal_pid_1(SYSTEMD_POWEROFF_SIGNAL);
    };
    match run_systemctl_poweroff(&systemctl).await {
        Ok(0) => Ok(()),
        Ok(code) => {
            eprintln!(
                "agentd: {} --no-block poweroff exited {code}; \
                 falling back to the poweroff signal",
                systemctl.display()
            );
            signal_pid_1(SYSTEMD_POWEROFF_SIGNAL)
        }
        Err(error) => {
            eprintln!(
                "agentd: could not run {} --no-block poweroff: {error}; \
                 falling back to the poweroff signal",
                systemctl.display()
            );
            signal_pid_1(SYSTEMD_POWEROFF_SIGNAL)
        }
    }
}

/// Runs `systemctl --no-block poweroff` and answers with its exit code.
async fn run_systemctl_poweroff(systemctl: &Path) -> AgentdResult<i32> {
    run_tracked_child(
        systemctl,
        &["--no-block", "poweroff"],
        SYSTEMD_POWEROFF_CALL_TIMEOUT,
    )
    .await
}

/// Spawns `cmd` with `args`, answers with its exit code, and kills it and fails
/// if it has not finished within `timeout`.
///
/// Spawned through the process manager, which owns `waitpid(-1, ...)` for this
/// process: waiting on the child here would race its reaper for the status and
/// usually lose. Awaiting it does not free the agent loop — the shutdown
/// message is handled inline — but it does leave the runtime's other tasks, the
/// session readers and the relay's output among them, running meanwhile.
///
/// Dropping the watcher on expiry leaks nothing: the reaper drops a
/// registration whose exit notification can no longer be delivered.
async fn run_tracked_child(
    cmd: &Path,
    args: &[&str],
    timeout: std::time::Duration,
) -> AgentdResult<i32> {
    let manager = crate::process::ProcessManager::get()?;
    let watcher = {
        let guard = manager.spawn_guard()?;
        let child = process::Command::new(cmd)
            .args(args)
            .spawn()
            .map_err(|e| AgentdError::Init(format!("spawn {}: {e}", cmd.display())))?;
        guard.track(child.id() as i32)?
    };
    let identity = watcher.identity();
    match tokio::time::timeout(timeout, watcher).await {
        Ok(code) => Ok(code),
        Err(_) => {
            let _ = manager.signal_process_group(identity, libc::SIGKILL);
            Err(AgentdError::Init(format!(
                "{} did not finish within {timeout:?}",
                cmd.display()
            )))
        }
    }
}

/// The realtime signal a non-systemd handoff init is asked to power off with.
///
/// Computed with agentd's own libc on purpose: this contract is agentd's, and
/// the init on the other side of it — `crates/test-init` — is built from this
/// workspace against the same musl. systemd is the init that does not share
/// agentd's libc, and it is asked by number above instead.
fn generic_init_poweroff_signal() -> i32 {
    libc::SIGRTMIN() + 4
}

/// Sends `signum` to PID 1.
fn signal_pid_1(signum: i32) -> AgentdResult<()> {
    // SAFETY: kill(2) is signal-safe and pid=1 is always valid.
    let ret = unsafe { libc::kill(1, signum) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Waits for `path` to be a socket, up to `timeout`, and says whether it is.
///
/// Returns as soon as the socket is there; a path that exists as something
/// else is not one, so a leftover file cannot pass for a listening manager.
async fn wait_for_control_socket(path: &Path, timeout: std::time::Duration) -> bool {
    use std::os::unix::fs::FileTypeExt;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if std::fs::metadata(path)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
        {
            return true;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        tokio::time::sleep(SYSTEMD_CONTROL_POLL.min(left)).await;
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

    #[tokio::test]
    async fn control_socket_wait_returns_when_the_socket_is_already_there() {
        let dir = unique_test_dir("control-present");
        let socket = dir.join("private");
        let listener =
            std::os::unix::net::UnixListener::bind(&socket).expect("bind control socket");

        assert!(wait_for_control_socket(&socket, std::time::Duration::from_secs(5)).await);

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn control_socket_wait_returns_when_the_socket_appears() {
        let dir = unique_test_dir("control-late");
        let socket = dir.join("private");
        let late = socket.clone();
        let manager = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            std::os::unix::net::UnixListener::bind(&late).expect("bind control socket")
        });

        assert!(wait_for_control_socket(&socket, std::time::Duration::from_secs(5)).await);

        drop(manager.join().expect("manager thread"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn control_socket_wait_gives_up_after_its_timeout() {
        let dir = unique_test_dir("control-absent");
        let missing = dir.join("private");

        let started = std::time::Instant::now();
        assert!(!wait_for_control_socket(&missing, std::time::Duration::from_millis(200)).await);
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_millis(200),
            "returned early after {waited:?}"
        );
        // A wait that ignored its argument would sit here for the 10 seconds
        // the real one is given, so the upper bound is the assertion.
        assert!(
            waited < std::time::Duration::from_secs(5),
            "waited {waited:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn control_socket_wait_never_takes_a_regular_file_for_a_manager() {
        let dir = unique_test_dir("control-regular");
        let regular = dir.join("not-a-socket");
        std::fs::write(&regular, b"leftover").expect("write regular file");

        assert!(!wait_for_control_socket(&regular, std::time::Duration::from_millis(100)).await);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The number systemd reads as poweroff, and the one agentd's own libc
    /// would have computed for it. They differ, which is the whole point of
    /// naming the systemd signal outright: musl starts its realtime range one
    /// signal above glibc, so the computed value is systemd's reboot.
    #[test]
    fn systemd_poweroff_signal_is_not_what_agentds_libc_computes() {
        if cfg!(target_env = "musl") {
            assert_eq!(generic_init_poweroff_signal(), 39);
            assert_ne!(generic_init_poweroff_signal(), SYSTEMD_POWEROFF_SIGNAL);
        } else {
            assert_eq!(generic_init_poweroff_signal(), SYSTEMD_POWEROFF_SIGNAL);
        }
    }

    /// The status this path reads is the process manager's to hand over, and
    /// the child runs under the manager's real reaper here, not beside it.
    #[tokio::test]
    async fn systemctl_poweroff_answers_with_the_child_exit_code() {
        // Both ignore the poweroff arguments, so the real call shape is kept.
        let ok = run_systemctl_poweroff(Path::new("/bin/true"))
            .await
            .expect("run a child that succeeds");
        assert_eq!(ok, 0);
        let failed = run_systemctl_poweroff(Path::new("/bin/false"))
            .await
            .expect("run a child that fails");
        assert_eq!(failed, 1);
    }

    /// A child that never finishes is killed rather than awaited forever: an
    /// unbounded wait here is the host's forced exit by another route.
    #[tokio::test]
    async fn a_child_that_does_not_finish_is_killed_and_reported() {
        // Distinctive enough to find this test's own sleep among any others.
        const MARKER: &str = "987654";

        let started = std::time::Instant::now();
        let error = run_tracked_child(
            Path::new("/bin/sleep"),
            &[MARKER],
            std::time::Duration::from_millis(200),
        )
        .await
        .expect_err("a sleep outliving its timeout must not report an exit code");
        let waited = started.elapsed();

        assert!(
            waited < std::time::Duration::from_secs(5),
            "waited {waited:?}"
        );
        assert!(
            error.to_string().contains("did not finish"),
            "unexpected error: {error}"
        );

        // The kill is asynchronous in the reaper; an unkilled sleep would still
        // be there in eleven days, so a bounded look is enough to tell them apart.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while running_with_argument(MARKER) {
            assert!(
                std::time::Instant::now() < deadline,
                "the child outlived its timeout"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Whether any live process was started with `argument`. A killed child
    /// awaiting its reaper is a zombie and reads as an empty command line.
    fn running_with_argument(argument: &str) -> bool {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            panic!("/proc is required to observe the child");
        };
        for entry in entries.flatten() {
            let Ok(command) = std::fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            if command
                .split(|byte| *byte == 0)
                .any(|word| word == argument.as_bytes())
            {
                return true;
            }
        }
        false
    }

    /// The image's own shape: a script init that masks units and then execs
    /// systemd. The route has to be the one PID 1 ends up keeping, not the one
    /// it was on its way through.
    #[tokio::test]
    async fn a_script_init_is_given_time_to_exec_what_it_runs() {
        let dir = unique_test_dir("script-execs");
        let init = dir.join("distributed-init");
        std::fs::write(&init, b"#!/bin/bash\nexec /sbin/init\n").expect("write script init");
        let comm = dir.join("comm");
        // Truncated the way the kernel truncates it: sixteen bytes with the NUL.
        std::fs::write(&comm, b"distributed-ini\n").expect("write comm");

        let handoff = init.clone();
        let becomes_systemd = comm.clone();
        let init_execs = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            std::fs::write(&becomes_systemd, b"systemd\n").expect("rewrite comm");
        });

        let route = shutdown_route(Some(&handoff), &comm, std::time::Duration::from_secs(5))
            .await
            .expect("decide a route");

        init_execs.await.expect("init exec task");
        assert_eq!(route, ShutdownRoute::Systemd);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A guest whose init is a binary has the init it is going to have. It must
    /// not pay for the wait above on every stop.
    #[tokio::test]
    async fn a_binary_init_waits_for_nothing() {
        let dir = unique_test_dir("binary-init");
        let init = dir.join("init");
        std::fs::write(&init, b"\x7fELF not really, but not a shebang either")
            .expect("write binary init");
        let comm = dir.join("comm");
        std::fs::write(&comm, b"init\n").expect("write comm");

        let started = std::time::Instant::now();
        let route = shutdown_route(Some(&init), &comm, std::time::Duration::from_secs(30))
            .await
            .expect("decide a route");
        let waited = started.elapsed();

        assert_eq!(route, ShutdownRoute::Generic);
        assert!(
            waited < std::time::Duration::from_millis(500),
            "a binary init waited {waited:?} for a change that was never coming"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A script that never execs anything is this guest's init after all. The
    /// wait ends and the route is read off what PID 1 still is.
    #[tokio::test]
    async fn a_script_that_stays_put_is_taken_for_the_init() {
        let dir = unique_test_dir("script-stays");
        let init = dir.join("rc.init");
        std::fs::write(&init, b"#!/bin/sh\nwhile true; do sleep 1; done\n")
            .expect("write script init");
        let comm = dir.join("comm");
        std::fs::write(&comm, b"rc.init\n").expect("write comm");

        let started = std::time::Instant::now();
        let route = shutdown_route(Some(&init), &comm, std::time::Duration::from_millis(200))
            .await
            .expect("decide a route");
        let waited = started.elapsed();

        assert_eq!(route, ShutdownRoute::Generic);
        assert!(
            waited >= std::time::Duration::from_millis(200),
            "gave up after {waited:?}"
        );
        assert!(
            waited < std::time::Duration::from_secs(5),
            "waited {waited:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A script init that has already exec'd systemd by the time the shutdown
    /// arrives, which is every stop after the first moments of a boot.
    #[tokio::test]
    async fn a_script_init_already_gone_decides_at_once() {
        let dir = unique_test_dir("script-gone");
        let init = dir.join("distributed-init");
        std::fs::write(&init, b"#!/bin/bash\nexec /sbin/init\n").expect("write script init");
        let comm = dir.join("comm");
        std::fs::write(&comm, b"systemd\n").expect("write comm");

        let started = std::time::Instant::now();
        let route = shutdown_route(Some(&init), &comm, std::time::Duration::from_secs(30))
            .await
            .expect("decide a route");

        assert_eq!(route, ShutdownRoute::Systemd);
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No handoff at all: agentd kept PID 1 and there is nothing to wait for.
    #[tokio::test]
    async fn no_handoff_decides_on_pid_1_alone() {
        let dir = unique_test_dir("no-handoff");
        let comm = dir.join("comm");
        std::fs::write(&comm, b"systemd\n").expect("write comm");

        let route = shutdown_route(None, &comm, std::time::Duration::from_secs(30))
            .await
            .expect("decide a route");

        assert_eq!(route, ShutdownRoute::Systemd);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The kernel keeps fifteen characters of a name, and the comparison has to
    /// use the same fifteen or a long-named init never matches itself.
    #[test]
    fn a_name_is_compared_the_way_the_kernel_keeps_it() {
        assert_eq!(
            comm_of(Path::new("/usr/local/libexec/distributed-init")).as_deref(),
            Some("distributed-ini")
        );
        assert_eq!(comm_of(Path::new("/sbin/init")).as_deref(), Some("init"));
        assert_eq!(comm_of(Path::new("/")), None);
    }

    /// What tells a step on the way from a destination.
    #[test]
    fn a_shebang_is_what_makes_an_init_a_step_on_the_way() {
        let dir = unique_test_dir("shebang");
        let script = dir.join("script");
        std::fs::write(&script, b"#!/bin/sh\n").expect("write script");
        let binary = dir.join("binary");
        std::fs::write(&binary, b"\x7fELF").expect("write binary");
        let empty = dir.join("empty");
        std::fs::write(&empty, b"").expect("write empty");

        assert!(is_shebang_script(&script));
        assert!(!is_shebang_script(&binary));
        assert!(!is_shebang_script(&empty));
        assert!(!is_shebang_script(&dir.join("absent")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
