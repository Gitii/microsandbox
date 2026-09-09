//! Agent relay for the sandbox process.
//!
//! The [`AgentRelay`] reads from the console backend's ring buffers (data
//! written by agentd in the guest via virtio-console), listens on the local
//! platform IPC endpoint for SDK client connections, and transparently relays
//! protocol frames between clients and the guest agent.
//!
//! Each client is assigned a non-overlapping correlation ID range during
//! handshake so that the relay can route agent responses back to the correct
//! client without rewriting frame headers.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Bytes, BytesMut};
#[cfg(unix)]
use microsandbox_filesystem::{BindIdentityMap, BindIdentityMapHandle};
use microsandbox_protocol::codec::{self, MAX_FRAME_SIZE};
use microsandbox_protocol::core::{InitAck, InitResolved, RelayClientDisconnected};
use microsandbox_protocol::exec::{ExecRequest, ExecSignal, ExecStderr, ExecStdout};
use microsandbox_protocol::message::{
    FLAG_SESSION_START, FLAG_SHUTDOWN, FLAG_TERMINAL, FRAME_HEADER_SIZE, Message, MessageType,
};
use microsandbox_protocol::{AGENT_RELAY_ID_RANGE_STEP, AGENT_RELAY_MAX_CLIENTS};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::{Mutex, mpsc, watch};

use crate::clock::spawn_clock_sync_task;
use crate::console::ConsoleSharedState;
use crate::exec_log::{LogSource, LogWriter};
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Types: capture
//--------------------------------------------------------------------------------------------------

/// Metadata recorded for each observed exec session. Populated by
/// `client_reader_task` when an `ExecRequest` arrives, consumed by
/// the ring reader's tap, and removed on `ExecExited`.
#[derive(Debug, Clone, Copy)]
struct SessionInfo {
    /// Monotonic per-relay session id. Distinct from the protocol
    /// correlation id, which can be reused across slot recycling
    /// (each `msb exec` is a separate client; slot 0 is freed and
    /// reassigned, so the same correlation id can appear twice
    /// within a sandbox lifetime). The monotonic counter gives every
    /// session a unique id within the relay's lifetime, which is
    /// what users see in `exec.log` entries.
    session_id: u64,

    /// Whether the session was opened in pty mode (drives
    /// `LogSource::Output` vs `Stdout` tagging).
    is_pty: bool,
}

/// Per-session bookkeeping for the log tap. Keyed by protocol
/// correlation id (which is what subsequent `Exec*` frames carry).
type SessionRegistry = std::sync::Mutex<HashMap<u32, SessionInfo>>;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Size of the length prefix in the wire format.
const LEN_PREFIX_SIZE: usize = 4;

/// Limit each routing turn so producers cannot keep extending one batch forever.
const RING_READ_BATCH_CHUNKS: usize = 64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// State for a connected client.
struct ClientState {
    /// Active session IDs owned by this client (tracked for disconnect cleanup).
    active_sessions: HashSet<u32>,
    /// Channel for sending frames to this client's writer task.
    /// Using a channel avoids holding the client mutex across async writes.
    /// Owns each frame's bytes rather than retaining a shared ring-buffer slab.
    write_tx: microsandbox_protocol::queue::Sender<Bytes>,
    stop: tokio::sync::watch::Sender<bool>,
}

/// The agent relay running in the sandbox process.
///
/// Reads agent frames from the console backend's ring buffers and listens
/// for client connections on a Unix domain socket. Frames are routed between
/// clients and the guest agent, preserving their encoding. Client envelopes are
/// checked so only the relay can issue owner-range cleanup controls.
pub struct AgentRelay {
    /// Shared ring buffers + wake pipes for console backend communication.
    shared: Arc<ConsoleSharedState>,
    /// Local IPC listener for client connections.
    listener: AgentListener,
    /// Local IPC endpoint address.
    endpoint: PathBuf,
    /// Cached `core.ready` frame bytes (length-prefixed wire format).
    ready_frame: Option<Vec<u8>>,
    /// Optional `exec.log` writer. When set, the ring reader task
    /// captures the primary session's stdout/stderr to JSON Lines.
    log_writer: Option<Arc<LogWriter>>,
    /// Shared user-volume bind identity map to install before `core.ready`.
    #[cfg(unix)]
    bind_identity_map: Option<BindIdentityMapHandle>,
    /// Number of user-volume mounts that use the shared bind identity map.
    #[cfg(unix)]
    bind_identity_map_mount_count: usize,
}

/// Platform-specific listener for SDK client connections.
struct AgentListener {
    #[cfg(unix)]
    inner: UnixListener,
    #[cfg(windows)]
    pipe_name: PathBuf,
    #[cfg(windows)]
    first_pipe_instance: bool,
}

#[cfg(unix)]
type AgentConnection = tokio::net::UnixStream;

#[cfg(windows)]
type AgentConnection = NamedPipeServer;

/// A frame extracted from the byte stream, kept as raw bytes for transparent
/// forwarding.
struct RawFrame {
    /// The complete frame bytes including the 4-byte length prefix.
    /// Uses `Bytes` for zero-copy extraction from the ring buffer.
    data: Bytes,
    /// The correlation ID extracted from the frame header.
    id: u32,
    /// The flags byte extracted from the frame header.
    flags: u8,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentListener {
    fn bind(endpoint: &Path) -> RuntimeResult<Self> {
        #[cfg(unix)]
        {
            // Remove stale socket file if it exists.
            if endpoint.exists() {
                let _ = std::fs::remove_file(endpoint);
            }

            // Ensure the parent directory exists.
            if let Some(parent) = endpoint.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let inner = UnixListener::bind(endpoint)?;
            Ok(Self { inner })
        }

        #[cfg(windows)]
        {
            Ok(Self {
                pipe_name: endpoint.to_path_buf(),
                first_pipe_instance: true,
            })
        }
    }

    async fn accept(&mut self) -> std::io::Result<AgentConnection> {
        #[cfg(unix)]
        {
            let (stream, _addr) = self.inner.accept().await?;
            Ok(stream)
        }

        #[cfg(windows)]
        {
            let mut options = ServerOptions::new();
            options.pipe_mode(PipeMode::Byte);
            let first_pipe_instance = self.first_pipe_instance;
            if first_pipe_instance {
                options.first_pipe_instance(true);
            }

            let server = options.create(&self.pipe_name)?;
            if first_pipe_instance {
                self.first_pipe_instance = false;
            }
            server.connect().await?;
            Ok(server)
        }
    }

    fn cleanup(&self, endpoint: &Path) {
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(endpoint);
        }

        #[cfg(windows)]
        {
            let _ = endpoint;
        }
    }
}

impl AgentRelay {
    /// Create a new agent relay.
    ///
    /// Takes the shared console state (ring buffers) and the local IPC endpoint
    /// where client connections will be accepted.
    pub async fn new(
        agent_sock_path: &Path,
        shared: Arc<ConsoleSharedState>,
    ) -> RuntimeResult<Self> {
        let listener = AgentListener::bind(agent_sock_path)?;
        tracing::info!("agent relay listening on {}", agent_sock_path.display());

        Ok(Self {
            shared,
            listener,
            endpoint: agent_sock_path.to_path_buf(),
            ready_frame: None,
            log_writer: None,
            #[cfg(unix)]
            bind_identity_map: None,
            #[cfg(unix)]
            bind_identity_map_mount_count: 0,
        })
    }

    /// Attach a log writer for `exec.log` capture.
    ///
    /// Must be called before [`run()`](Self::run). When attached, the
    /// ring reader captures the primary session's stdout/stderr into
    /// the writer's JSON Lines file (see
    /// `design/runtime/sandbox-logs.md` D3 / D3a). The
    /// `--- sandbox started ---` marker is **not** written here — it
    /// is written from [`wait_ready`](Self::wait_ready) once agentd
    /// signals `core.ready`, so the marker only appears when the
    /// guest has actually finished booting.
    pub fn with_log_writer(mut self, writer: Arc<LogWriter>) -> Self {
        self.log_writer = Some(writer);
        self
    }

    /// Attach a pending bind identity map for the early init handshake.
    #[cfg(unix)]
    pub fn with_bind_identity_map(
        mut self,
        handle: Option<BindIdentityMapHandle>,
        mount_count: usize,
    ) -> Self {
        self.bind_identity_map = handle;
        self.bind_identity_map_mount_count = mount_count;
        self
    }

    #[cfg(unix)]
    fn install_bind_identity_map(&self, resolved: InitResolved) -> RuntimeResult<()> {
        let Some(handle) = &self.bind_identity_map else {
            return Ok(());
        };

        let host_owner_uid = unsafe { libc::getuid() as u32 };
        let map = BindIdentityMap::new(
            host_owner_uid,
            resolved.default_user.uid,
            resolved.default_user.gid,
        );

        handle
            .set(map)
            .map_err(|_| RuntimeError::Custom("bind identity map already installed".into()))?;

        tracing::info!(
            host_owner_uid,
            guest_uid = resolved.default_user.uid,
            guest_gid = resolved.default_user.gid,
            mounts = self.bind_identity_map_mount_count,
            "agent relay: installed bind identity maps"
        );

        Ok(())
    }

    fn send_init_ack(&self) -> RuntimeResult<()> {
        let msg = Message::with_payload(MessageType::InitAck, 0, &InitAck {})
            .map_err(|e| RuntimeError::Custom(format!("encode init ack: {e}")))?;
        let mut frame = Vec::new();
        codec::encode_to_buf(&msg, &mut frame)
            .map_err(|e| RuntimeError::Custom(format!("encode init ack frame: {e}")))?;
        push_guest_frame_blocking(&self.shared, frame)
    }

    /// Read frames from the console ring buffer until `core.ready` is
    /// received.
    ///
    /// This is a **blocking** call (uses `libc::poll` on the wake pipe).
    /// Must be called before [`run()`](Self::run). The ready frame is cached
    /// so it can be sent to clients during handshake.
    pub fn wait_ready(&mut self) -> RuntimeResult<()> {
        const READY_TIMEOUT_SECS: i32 = 180;

        let mut buf = BytesMut::new();
        #[cfg(unix)]
        let mut init_resolved = false;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(READY_TIMEOUT_SECS as u64);

        loop {
            // Drain the wake pipe and pop all available chunks.
            self.shared.tx_wake.drain();
            while let Some(chunk) = self.shared.tx_ring.pop() {
                buf.extend_from_slice(&chunk);
            }

            // Try to extract complete frames.
            while let Some(frame) = try_extract_frame(&mut buf) {
                let msg = decode_frame(frame.data.as_ref())?;

                if msg.t == MessageType::Ready {
                    #[cfg(unix)]
                    if self.bind_identity_map.is_some() && !init_resolved {
                        return Err(RuntimeError::Custom(
                            "agent relay: received core.ready before init context resolution"
                                .into(),
                        ));
                    }
                    tracing::info!("agent relay: received core.ready from agentd");
                    self.ready_frame = Some(frame.data.to_vec());
                    // Now that agentd has signalled readiness, mark the
                    // exec.log lifecycle. Doing this here (rather than
                    // in `with_log_writer`) means the marker only shows
                    // up when the guest actually came up — pre-relay
                    // failures (mount errors, etc.) leave exec.log empty
                    // and let `boot-error.json` carry the story alone.
                    if let Some(ref writer) = self.log_writer {
                        writer.write_system("--- sandbox started ---");
                    }
                    return Ok(());
                }

                if msg.t == MessageType::InitResolved {
                    let resolved: InitResolved = msg.payload().map_err(|e| {
                        RuntimeError::Custom(format!("decode init context payload: {e}"))
                    })?;
                    #[cfg(unix)]
                    self.install_bind_identity_map(resolved)?;
                    #[cfg(windows)]
                    let _ = resolved;
                    #[cfg(unix)]
                    {
                        init_resolved = true;
                    }
                    self.send_init_ack()?;
                    continue;
                }

                tracing::debug!(
                    "agent relay: discarding pre-ready frame type={:?} id={}",
                    msg.t,
                    msg.id
                );
            }

            // Check timeout.
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(RuntimeError::Custom(
                    "agent relay: timed out waiting for core.ready from agentd".into(),
                ));
            }

            // Block until the wake primitive is readable or timeout expires.
            let _ = self.shared.tx_wake.wait_timeout(remaining);
        }
    }

    /// Run the main relay loop.
    ///
    /// Accepts client connections, relays frames between clients and the
    /// console ring buffers, and handles client disconnects with session
    /// cleanup.
    ///
    /// When a client sends a `core.shutdown` message (identified by
    /// `FLAG_SHUTDOWN` in the frame header), the relay notifies the caller
    /// via `drain_tx` after forwarding the frame to agentd. The caller is
    /// expected to give agentd a flush window before forcing host-side
    /// teardown.
    pub async fn run(
        mut self,
        mut shutdown: watch::Receiver<bool>,
        drain_tx: mpsc::Sender<()>,
    ) -> RuntimeResult<()> {
        let ready_frame = self.ready_frame.ok_or_else(|| {
            RuntimeError::Custom("agent relay: run() called before wait_ready()".into())
        })?;

        // Shared state: map from client slot index to client state.
        let clients: Arc<Mutex<HashMap<u32, ClientState>>> = Arc::new(Mutex::new(HashMap::new()));

        // Bounded channel for client reader tasks to send frames to the ring writer.
        // Backpressure prevents unbounded memory growth from client floods.
        let (agent_tx, agent_rx) = microsandbox_protocol::queue::channel::<Vec<u8>>(
            microsandbox_protocol::queue::TRANSPORT_QUEUE_BYTES,
        );

        // Track which client slots are in use.
        let used_slots: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

        // Spawn the ring writer task (client frames → rx_ring → guest).
        let shared_for_writer = Arc::clone(&self.shared);
        let ring_writer_handle = tokio::spawn(ring_writer_task(shared_for_writer, agent_rx));
        let clock_sync_handle = spawn_clock_sync_task(agent_tx.clone());

        // Spawn the ring reader task (tx_ring → guest frames → clients).
        // When a log writer is attached, the reader also captures
        // every exec session's stdout/stderr into `exec.log` (tagged
        // with a relay-monotonic session id so readers can group or
        // filter by session — the protocol correlation id can be
        // reused across slot recycling, so we mint our own).
        //
        // `session_registry` is shared between the per-client reader
        // (records pty flag and assigns the monotonic id from
        // `next_session_id` on observed ExecRequest payloads) and
        // the ring reader's tap (looks up the session info for each
        // Exec* frame).
        let session_registry: Arc<SessionRegistry> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        // Counter starts at 1 so 0 is unambiguously "not a session"
        // for any out-of-band tooling that might compare against it.
        let next_session_id: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
        let clients_for_reader = Arc::clone(&clients);
        let shared_for_reader = Arc::clone(&self.shared);
        let log_writer_for_reader = self.log_writer.clone();
        let registry_for_reader = Arc::clone(&session_registry);
        let ring_reader_handle = tokio::spawn(ring_reader_task(
            shared_for_reader,
            clients_for_reader,
            log_writer_for_reader,
            registry_for_reader,
            Arc::clone(&used_slots),
        ));

        // Accept loop.
        loop {
            tokio::select! {
                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok(stream) => {
                            // Allocate a client slot.
                            let slot = {
                                let mut slots = used_slots.lock().await;
                                let mut found = None;
                                for i in 0..AGENT_RELAY_MAX_CLIENTS {
                                    if !slots.contains(&i) {
                                        slots.insert(i);
                                        found = Some(i);
                                        break;
                                    }
                                }
                                found
                            };

                            let slot = match slot {
                                Some(s) => s,
                                None => {
                                    tracing::error!("agent relay: max clients reached, rejecting connection");
                                    drop(stream);
                                    continue;
                                }
                            };

                            let id_offset = slot * AGENT_RELAY_ID_RANGE_STEP;
                            let id_start = id_offset.saturating_add(1);
                            let id_end_exclusive = id_offset.saturating_add(AGENT_RELAY_ID_RANGE_STEP);
                            tracing::info!(
                                "agent relay: client connected slot={slot} id_start={id_start} id_end_exclusive={id_end_exclusive}"
                            );

                            // Perform handshake: send
                            // [id_start: u32 BE][id_end_exclusive: u32 BE][ready_frame_bytes...].
                            let (reader_half, mut writer_half) = tokio::io::split(stream);

                            let mut handshake = Vec::with_capacity(8 + ready_frame.len());
                            handshake.extend_from_slice(&id_start.to_be_bytes());
                            handshake.extend_from_slice(&id_end_exclusive.to_be_bytes());
                            handshake.extend_from_slice(&ready_frame);

                            if let Err(e) = writer_half.write_all(&handshake).await {
                                tracing::error!(
                                    "agent relay: handshake write failed slot={slot}: {e}"
                                );
                                used_slots.lock().await.remove(&slot);
                                continue;
                            }

                            // Spawn a per-client writer task so the ring reader
                            // never holds the mutex across async writes.
                            let (write_tx, mut write_rx) = microsandbox_protocol::queue::channel::<Bytes>(
                                microsandbox_protocol::queue::TRANSPORT_QUEUE_BYTES,
                            );
                            let (stop, mut writer_stop) = tokio::sync::watch::channel(false);
                            let stop_on_writer_exit = stop.clone();
                            tokio::spawn(async move {
                                tokio::select! {
                                    biased;
                                    _ = writer_stop.wait_for(|closed| *closed) => {},
                                    _ = async {
                                        while let Some(data) = write_rx.recv().await {
                                            if let Err(e) = writer_half.write_all(&data).await {
                                                tracing::error!("agent relay: client writer slot={slot} failed: {e}");
                                                break;
                                            }
                                        }
                                    } => {},
                                }
                                stop_on_writer_exit.send_replace(true);
                            });

                            // Register the client.
                            {
                                let mut map = clients.lock().await;
                                map.insert(slot, ClientState {
                                    active_sessions: HashSet::new(),
                                    write_tx,
                                    stop: stop.clone(),
                                });
                            }

                            // Spawn a reader task for this client.
                            let agent_tx_clone = agent_tx.clone();
                            let clients_clone = Arc::clone(&clients);
                            let drain_tx_clone = drain_tx.clone();
                            let registry_clone = Arc::clone(&session_registry);
                            let next_id_clone = Arc::clone(&next_session_id);

                            tokio::spawn(client_reader_task(
                                slot,
                                reader_half,
                                agent_tx_clone,
                                clients_clone,
                                drain_tx_clone,
                                registry_clone,
                                next_id_clone,
                                id_start,
                                id_end_exclusive,
                                stop,
                            ));
                        }
                        Err(e) => {
                            tracing::error!("agent relay: accept error: {e}");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("agent relay: shutdown signal received");
                        break;
                    }
                }
            }
        }

        // The "--- sandbox stopped ---" marker is written by the VMM's
        // `on_exit` observer (runs before `_exit()`), so we don't
        // double-write it here.

        // Clean up the local IPC endpoint.
        self.listener.cleanup(&self.endpoint);

        // Abort background tasks.
        for client in clients.lock().await.values() {
            client.stop.send_replace(true);
        }
        clock_sync_handle.abort();
        ring_writer_handle.abort();
        ring_reader_handle.abort();

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn push_guest_frame_blocking(
    shared: &ConsoleSharedState,
    frame: Vec<u8>,
) -> RuntimeResult<()> {
    push_guest_frame_until(shared, frame, std::time::Duration::from_secs(60))
}

pub(crate) fn push_guest_frame_until(
    shared: &ConsoleSharedState,
    mut frame: Vec<u8>,
    timeout: std::time::Duration,
) -> RuntimeResult<()> {
    let deadline = std::time::Instant::now() + timeout;

    loop {
        match shared.rx_ring.push(frame) {
            Ok(()) => {
                shared.rx_wake.wake();
                return Ok(());
            }
            Err(returned) => {
                frame = returned;
                if std::time::Instant::now() >= deadline {
                    return Err(RuntimeError::Custom(
                        "timed out sending frame to agentd".into(),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
}

/// Try to extract a complete frame from a byte buffer.
///
/// Returns `None` if the buffer doesn't contain a full frame yet. On
/// success, the consumed bytes are removed from `buf`.
fn try_extract_frame(buf: &mut BytesMut) -> Option<RawFrame> {
    if buf.len() < LEN_PREFIX_SIZE {
        return None;
    }

    let frame_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    // Sanity checks.
    if frame_len > MAX_FRAME_SIZE as usize {
        // Corrupt data — clear the entire buffer. Nibbling just 4 bytes would
        // re-interpret frame body bytes as a new length, cascading failures.
        tracing::error!(
            "agent relay: frame too large ({frame_len} bytes), clearing {} bytes of buffer",
            buf.len()
        );
        buf.clear();
        return None;
    }

    if buf.len() < LEN_PREFIX_SIZE + frame_len {
        return None; // Need more data.
    }

    if frame_len < FRAME_HEADER_SIZE {
        // Corrupt frame — discard.
        tracing::error!("agent relay: frame too short ({frame_len} bytes), discarding");
        let _ = buf.split_to(LEN_PREFIX_SIZE + frame_len);
        return None;
    }

    // Split off the complete frame — zero-copy via freeze().
    let data = buf.split_to(LEN_PREFIX_SIZE + frame_len).freeze();

    let id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let flags = data[8];

    Some(RawFrame { data, id, flags })
}

/// Decode raw frame bytes into a protocol `Message`.
fn decode_frame(buf: &[u8]) -> RuntimeResult<Message> {
    codec::decode_message_frame(buf).map_err(|e| RuntimeError::Custom(format!("decode frame: {e}")))
}

/// Tap a guest-originated frame into `exec.log` if it belongs to the
/// primary session. Best-effort: any decode error is logged and
/// dropped — capture failures must never disrupt the routing path.
fn tap_frame_into_log(frame: &RawFrame, writer: &LogWriter, session_registry: &SessionRegistry) {
    // Decode the message envelope to learn the type. The full CBOR
    // decode is small (the envelope is a 3-field map; the heavy
    // payload is left as opaque bytes in `Message::p`).
    let msg = match decode_frame(frame.data.as_ref()) {
        Ok(m) => m,
        Err(err) => {
            tracing::debug!(error = %err, "exec_log: skipping frame with decode error");
            return;
        }
    };

    // Look up the session info recorded by `client_reader_task` when
    // the ExecRequest arrived. Returns `None` for frames whose
    // session predates the relay's lifetime or whose ExecRequest
    // we missed (defensive — shouldn't happen in normal operation).
    let session_info = session_registry
        .lock()
        .ok()
        .and_then(|m| m.get(&msg.id).copied());

    match msg.t {
        // ExecRequest flows host→guest, observed in `client_reader_task`.
        MessageType::ExecStdout => {
            let Some(info) = session_info else { return };
            // pty mode merges stdout+stderr into a single stream
            // shipped over ExecStdout frames; tag as `Output`
            // accordingly.
            let tag = if info.is_pty {
                LogSource::Output
            } else {
                LogSource::Stdout
            };
            match msg.payload::<ExecStdout>() {
                Ok(p) => writer.write_chunk(tag, info.session_id, &p.data),
                Err(err) => tracing::debug!(error = %err, "exec_log: stdout payload decode failed"),
            }
        }
        MessageType::ExecStderr => {
            // ExecStderr frames are pipe-mode-only by construction.
            let Some(info) = session_info else { return };
            match msg.payload::<ExecStderr>() {
                Ok(p) => writer.write_chunk(LogSource::Stderr, info.session_id, &p.data),
                Err(err) => tracing::debug!(error = %err, "exec_log: stderr payload decode failed"),
            }
        }
        _ => {}
    }

    // Drop the registry entry on any terminal frame (ExecExited,
    // ExecFailed) so we don't leak `SessionInfo` for the lifetime of
    // the relay. The flag is set on both — checking it here covers
    // every terminal exec frame uniformly.
    if (frame.flags & FLAG_TERMINAL) != 0
        && let Ok(mut registry) = session_registry.lock()
    {
        registry.remove(&msg.id);
    }
}

/// Background task that pushes client frames into the rx_ring for the guest.
/// Retries on full ring with backoff to avoid dropping frames.
async fn ring_writer_task(
    shared: Arc<ConsoleSharedState>,
    mut rx: microsandbox_protocol::queue::Receiver<Vec<u8>>,
) {
    while let Some(frame_bytes) = rx.recv().await {
        let mut data = frame_bytes;
        let mut attempts = 0u64;
        loop {
            match shared.rx_ring.push(data) {
                Ok(()) => {
                    shared.rx_wake.wake();
                    break;
                }
                Err(returned) => {
                    attempts = attempts.saturating_add(1);
                    if attempts == 50 || attempts.is_multiple_of(500) {
                        tracing::warn!(
                            attempts,
                            "agent relay: rx_ring full, waiting to deliver frame"
                        );
                    }
                    data = returned;
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
        }
    }
    tracing::debug!("agent relay: ring writer task exiting");
}

/// Background task that reads frames from the tx_ring (written by the guest
/// agent) and routes them to the correct client based on correlation ID range.
///
/// When `log_writer` is `Some`, the task also taps the primary session's
/// `ExecStdout` / `ExecStderr` payloads into `exec.log`. The "primary"
/// session is the first one whose `ExecRequest` arrives after the relay
/// starts, recorded via CAS into `primary_session_id`. See
/// `design/runtime/sandbox-logs.md` D3a.
async fn ring_reader_task(
    shared: Arc<ConsoleSharedState>,
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    log_writer: Option<Arc<LogWriter>>,
    session_registry: Arc<SessionRegistry>,
    used_slots: Arc<Mutex<HashSet<u32>>>,
) {
    // Wrap the tx_wake read fd in AsyncFd for tokio-driven notification.
    #[cfg(unix)]
    let wake_fd = shared.tx_wake.as_raw_fd();
    #[cfg(unix)]
    let async_fd = match AsyncFd::new(wake_fd) {
        Ok(fd) => fd,
        Err(e) => {
            tracing::error!("agent relay: failed to create AsyncFd for tx_wake: {e}");
            return;
        }
    };

    let mut buf = BytesMut::new();
    let mut frames = Vec::new();

    loop {
        // Wait for the wake pipe to become readable.
        #[cfg(unix)]
        {
            let mut guard = match async_fd.readable().await {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!("agent relay: AsyncFd readable error: {e}");
                    break;
                }
            };
            guard.clear_ready();
        }

        #[cfg(windows)]
        {
            let shared_for_wait = Arc::clone(&shared);
            let woke = tokio::task::spawn_blocking(move || {
                shared_for_wait
                    .tx_wake
                    .wait_timeout(std::time::Duration::from_millis(100))
            })
            .await
            .unwrap_or(false);
            if !woke {
                continue;
            }
        }

        // Drain the wake pipe and pop all available chunks.
        shared.tx_wake.drain();
        for index in 0..RING_READ_BATCH_CHUNKS {
            let Some(chunk) = shared.tx_ring.pop() else {
                break;
            };
            buf.extend_from_slice(&chunk);
            if index + 1 == RING_READ_BATCH_CHUNKS {
                shared.tx_wake.wake();
            }
        }

        // Extract all complete frames first, then route them.
        // This avoids holding the client mutex across async writes.
        while let Some(frame) = try_extract_frame(&mut buf) {
            frames.push(frame);
        }

        for frame in frames.drain(..) {
            if frame.id == 0 {
                if let Ok(message) = decode_frame(&frame.data)
                    && message.t == MessageType::RelayClientReleased
                    && let Ok(released) = message.payload::<RelayClientDisconnected>()
                {
                    used_slots
                        .lock()
                        .await
                        .remove(&(released.id_start / AGENT_RELAY_ID_RANGE_STEP));
                }
                continue;
            }
            let client_slot = frame.id / AGENT_RELAY_ID_RANGE_STEP;
            let client_slot = client_slot.min(AGENT_RELAY_MAX_CLIENTS - 1);

            let is_terminal = (frame.flags & FLAG_TERMINAL) != 0;

            // Tap every exec session's stdout/stderr into `exec.log`
            // when a log writer is attached. The CBOR decode is only
            // done when there is a writer, so the no-capture path is
            // unchanged.
            if let Some(writer) = log_writer.as_ref() {
                tap_frame_into_log(&frame, writer, &session_registry);
            }

            // Acquire lock briefly to get session bookkeeping + clone writer.
            // Then release before the async write to avoid blocking other clients.
            let writer_result = {
                let mut map = clients.lock().await;
                if let Some(client) = map.get_mut(&client_slot) {
                    if is_terminal {
                        client.active_sessions.remove(&frame.id);
                    }
                    Ok((client.write_tx.clone(), client.stop.clone()))
                } else {
                    Err(frame.id)
                }
            };

            match writer_result {
                Ok((write_tx, stop)) => {
                    let bytes = frame.data.len();
                    // A small slice must not pin a large batch allocation behind
                    // a paused consumer while being charged only for its length.
                    let data = Bytes::copy_from_slice(&frame.data);
                    if write_tx.try_send(data, bytes).is_err() {
                        // Defend other clients and the host's byte budget. A
                        // failed route is disconnected, never silently truncated.
                        tracing::error!(
                            "agent relay: output byte budget exhausted or closed for slot={client_slot}"
                        );
                        stop.send_replace(true);
                    }
                }
                Err(id) => {
                    tracing::debug!(
                        "agent relay: no client for slot={client_slot} id={id} (frame dropped)"
                    );
                }
            }
        }
    }
}

/// Read a single raw frame from an async reader (used for client connections).
async fn read_raw_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> RuntimeResult<RawFrame> {
    // Read the 4-byte length prefix.
    let mut len_buf = [0u8; LEN_PREFIX_SIZE];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(RuntimeError::Custom("agent relay: unexpected EOF".into()));
        }
        Err(e) => return Err(RuntimeError::Io(e)),
    }

    let frame_len = u32::from_be_bytes(len_buf);

    if frame_len > MAX_FRAME_SIZE {
        return Err(RuntimeError::Custom(format!(
            "agent relay: frame too large: {frame_len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let frame_len = frame_len as usize;

    if frame_len < FRAME_HEADER_SIZE {
        return Err(RuntimeError::Custom(format!(
            "agent relay: frame too short: {frame_len} bytes"
        )));
    }

    // Single allocation: length prefix + payload in one Vec.
    let mut data = Vec::with_capacity(LEN_PREFIX_SIZE + frame_len);
    data.extend_from_slice(&len_buf);
    data.resize(LEN_PREFIX_SIZE + frame_len, 0);
    reader.read_exact(&mut data[LEN_PREFIX_SIZE..]).await?;

    let id = u32::from_be_bytes([
        data[LEN_PREFIX_SIZE],
        data[LEN_PREFIX_SIZE + 1],
        data[LEN_PREFIX_SIZE + 2],
        data[LEN_PREFIX_SIZE + 3],
    ]);
    let flags = data[LEN_PREFIX_SIZE + 4];

    Ok(RawFrame {
        data: Bytes::from(data),
        id,
        flags,
    })
}

/// Background task that reads frames from a client and forwards them to the
/// ring writer channel. Handles client disconnect with session cleanup.
///
/// The argument count is over the clippy default (7) because the task
/// shares per-relay state across both tasks: client routing
/// (`agent_tx`, `clients`, `stop`, `drain_tx`) plus the
/// session registry / monotonic id atomic for the log capture path.
/// Bundling them into a struct would be more boilerplate than the
/// lint guards against — there's a single call site.
#[allow(clippy::too_many_arguments)]
async fn client_reader_task(
    slot: u32,
    mut reader: impl AsyncRead + Unpin + Send + 'static,
    agent_tx: microsandbox_protocol::queue::Sender<Vec<u8>>,
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    drain_tx: mpsc::Sender<()>,
    session_registry: Arc<SessionRegistry>,
    next_session_id: Arc<AtomicU64>,
    id_start: u32,
    id_end_exclusive: u32,
    stop: tokio::sync::watch::Sender<bool>,
) {
    let mut cancelled = stop.subscribe();
    loop {
        let incoming = tokio::select! {
            biased;
            _ = cancelled.wait_for(|closed| *closed) => break,
            frame = read_raw_frame(&mut reader) => frame,
        };
        let frame = match incoming {
            Ok(f) => f,
            Err(_) => {
                tracing::info!("agent relay: client disconnected slot={slot}");
                break;
            }
        };

        // Track session starts for disconnect cleanup.
        let is_session_start = (frame.flags & FLAG_SESSION_START) != 0;
        let is_terminal = (frame.flags & FLAG_TERMINAL) != 0;
        let is_shutdown = (frame.flags & FLAG_SHUTDOWN) != 0;

        if !is_client_frame_allowed(frame.id, frame.flags, id_start, id_end_exclusive) {
            tracing::warn!(
                "agent relay: client slot={slot} sent out-of-range id={} range=[{}, {})",
                frame.id,
                id_start,
                id_end_exclusive
            );
            break;
        }

        let message = match decode_frame(&frame.data) {
            Ok(message) => message,
            Err(error) => {
                tracing::warn!(%error, slot, "agent relay: malformed client envelope");
                break;
            }
        };
        // Defend other owners: only the relay may issue owner-range cleanup or
        // its release barrier. A caller's own correlation ID is not authority.
        if matches!(
            message.t,
            MessageType::RelayClientDisconnected | MessageType::RelayClientReleased
        ) {
            tracing::warn!(
                slot,
                "agent relay: client attempted an internal ownership control"
            );
            break;
        }

        // Forward shutdown to agentd (via the agent_tx send below) so the
        // guest can sync filesystems and power off cleanly. Also notify the
        // caller so it can start the flush-grace fallback timer — if the
        // guest's clean poweroff doesn't reach VMM exit within that window,
        // the caller force-exits as a backstop.
        if is_shutdown {
            tracing::info!("agent relay: client slot={slot} sent core.shutdown, notifying drain");
            let _ = drain_tx.try_send(());
        }

        // Register each ExecRequest in the session registry: assign a
        // relay-monotonic session id and record the pty flag. The
        // monotonic id is what users see in `exec.log` entries — it's
        // unique per session within the relay's lifetime, unlike the
        // protocol correlation id which can be reused after slot
        // recycling.
        //
        // FLAG_SESSION_START is set on both ExecRequest and FsRequest,
        // so we decode the type to disambiguate.
        let mut is_exec_session_start = false;
        if is_session_start && message.t == MessageType::ExecRequest {
            is_exec_session_start = true;
            let pty = message
                .payload::<ExecRequest>()
                .map(|r| r.tty)
                .unwrap_or(false);
            let session_id = next_session_id.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut registry) = session_registry.lock() {
                registry.insert(
                    frame.id,
                    SessionInfo {
                        session_id,
                        is_pty: pty,
                    },
                );
            }
        }

        // Only acquire the lock when session bookkeeping is needed.
        // Data frames (the vast majority) skip the lock entirely.
        if is_exec_session_start || is_terminal {
            let mut map = clients.lock().await;
            if let Some(client) = map.get_mut(&slot) {
                if is_exec_session_start {
                    client.active_sessions.insert(frame.id);
                }
                if is_terminal {
                    client.active_sessions.remove(&frame.id);
                }
            }
        }

        // Forward frame to ring writer (bounded — applies backpressure).
        let sent = tokio::select! {
            biased;
            _ = cancelled.wait_for(|closed| *closed) => break,
            sent = agent_tx.send(frame.data.to_vec(), frame.data.len()) => sent,
        };
        if sent.is_err() {
            tracing::error!("agent relay: ring writer channel closed");
            break;
        }
    }

    stop.send_replace(true);
    drop(reader);

    // Client disconnected — send SIGKILL for each active session.
    let active_sessions = {
        let mut map = clients.lock().await;
        if let Some(client) = map.remove(&slot) {
            client.active_sessions
        } else {
            HashSet::new()
        }
    };

    if !active_sessions.is_empty() {
        tracing::info!(
            "agent relay: cleaning up {} active sessions for slot={slot}",
            active_sessions.len()
        );

        for session_id in active_sessions {
            let kill_msg = match Message::with_payload(
                MessageType::ExecSignal,
                session_id,
                &ExecSignal { signal: 9 }, // SIGKILL
            ) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::error!(
                        "agent relay: failed to encode SIGKILL for session {session_id}: {e}"
                    );
                    continue;
                }
            };

            let mut buf = Vec::new();
            if let Err(e) = codec::encode_to_buf(&kill_msg, &mut buf) {
                tracing::error!(
                    "agent relay: failed to encode SIGKILL frame for session {session_id}: {e}"
                );
                continue;
            }

            let bytes = buf.len();
            if agent_tx.send(buf, bytes).await.is_err() {
                tracing::error!("agent relay: ring writer channel closed during cleanup");
                break;
            }
        }
    }

    let disconnected = RelayClientDisconnected {
        id_start,
        id_end_exclusive,
    };
    let disconnect_msg =
        match Message::with_payload(MessageType::RelayClientDisconnected, 0, &disconnected) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::error!("agent relay: failed to encode relay disconnect event: {e}");
                return;
            }
        };
    let mut buf = Vec::new();
    match codec::encode_to_buf(&disconnect_msg, &mut buf) {
        Ok(()) => {
            let bytes = buf.len();
            if agent_tx.send(buf, bytes).await.is_err() {
                tracing::error!("agent relay: ring writer channel closed during fs cleanup");
            }
        }
        Err(e) => {
            tracing::error!("agent relay: failed to encode relay disconnect frame: {e}");
        }
    }

    // Reuse only after the guest's release barrier, which follows every old
    // socket task and its queued output. Otherwise late terminals can hit a new owner.
}

/// Return whether a client-originated frame may be forwarded to agentd.
///
/// Most client frames must use a correlation ID from the relay-assigned
/// range so responses route back to the owning client. `core.shutdown` is a
/// process-level control frame, not a correlated request, and the SDK sends it
/// with ID 0.
fn is_client_frame_allowed(id: u32, flags: u8, id_start: u32, id_end_exclusive: u32) -> bool {
    let is_shutdown_control = (flags & FLAG_SHUTDOWN) != 0 && id == 0;
    is_shutdown_control || (id >= id_start && id < id_end_exclusive)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use microsandbox_protocol::core::Ready;

    #[cfg(unix)]
    #[tokio::test]
    async fn paused_client_does_not_block_other_connect_close_or_disconnect() {
        use microsandbox_protocol::tcp::{
            TCP_WINDOW_BYTES, TcpClose, TcpClosed, TcpConnect, TcpConnected, TcpData,
        };
        use tokio::net::UnixStream;

        async fn connect(path: &PathBuf) -> (UnixStream, u32) {
            let mut socket = UnixStream::connect(path).await.unwrap();
            let mut range = [0; 8];
            socket.read_exact(&mut range).await.unwrap();
            assert_eq!(
                codec::read_message(&mut socket).await.unwrap().t,
                MessageType::Ready
            );
            (socket, u32::from_be_bytes(range[..4].try_into().unwrap()))
        }
        async fn host_frame(shared: &ConsoleSharedState, wake: &AsyncFd<i32>) -> Message {
            loop {
                if let Some(frame) = shared.rx_ring.pop() {
                    let message = decode_frame(&frame).unwrap();
                    if message.t == MessageType::ClockSync {
                        continue;
                    }
                    return message;
                }
                let mut ready = wake.readable().await.unwrap();
                shared.rx_wake.drain();
                ready.clear_ready();
            }
        }
        fn guest_frame(shared: &ConsoleSharedState, message: Message) {
            let mut frame = Vec::new();
            codec::encode_to_buf(&message, &mut frame).unwrap();
            shared.tx_ring.push(frame).unwrap();
            shared.tx_wake.wake();
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("relay.sock");
            let shared = Arc::new(ConsoleSharedState::with_capacity(16));
            let mut relay = AgentRelay::new(&path, Arc::clone(&shared)).await.unwrap();
            guest_frame(
                &shared,
                Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap(),
            );
            relay.wait_ready().unwrap();
            let wake = AsyncFd::new(shared.rx_wake.as_raw_fd()).unwrap();
            let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
            let (drain, _drain_rx) = mpsc::channel(1);
            let running = tokio::spawn(relay.run(shutdown_rx, drain));
            let (mut paused, paused_id) = connect(&path).await;
            let (mut active, active_id) = connect(&path).await;
            let request = TcpConnect {
                host: "127.0.0.1".into(),
                port: 80,
            };
            codec::write_message(
                &mut paused,
                &Message::with_payload(MessageType::TcpConnect, paused_id, &request).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(host_frame(&shared, &wake).await.id, paused_id);
            guest_frame(
                &shared,
                Message::with_payload(MessageType::TcpConnected, paused_id, &TcpConnected {})
                    .unwrap(),
            );
            // One valid byte window fragmented into one-byte frames exceeds both
            // the old 64-frame channel and the Unix socket's write buffer.
            let data =
                Message::with_payload(MessageType::TcpData, paused_id, &TcpData { data: vec![1] })
                    .unwrap();
            let mut window = Vec::new();
            for _ in 0..TCP_WINDOW_BYTES {
                codec::encode_to_buf(&data, &mut window).unwrap();
            }
            shared.tx_ring.push(window).unwrap();
            shared.tx_wake.wake();
            codec::write_message(
                &mut active,
                &Message::with_payload(MessageType::TcpConnect, active_id, &request).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(host_frame(&shared, &wake).await.id, active_id);
            guest_frame(
                &shared,
                Message::with_payload(MessageType::TcpConnected, active_id, &TcpConnected {})
                    .unwrap(),
            );
            assert_eq!(
                codec::read_message(&mut active).await.unwrap().t,
                MessageType::TcpConnected
            );
            codec::write_message(
                &mut active,
                &Message::with_payload(MessageType::TcpClose, active_id, &TcpClose {}).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(host_frame(&shared, &wake).await.t, MessageType::TcpClose);
            guest_frame(
                &shared,
                Message::with_payload(MessageType::TcpClosed, active_id, &TcpClosed {}).unwrap(),
            );
            assert_eq!(
                codec::read_message(&mut active).await.unwrap().t,
                MessageType::TcpClosed
            );
            drop(paused);
            let disconnected = host_frame(&shared, &wake).await;
            assert_eq!(disconnected.t, MessageType::RelayClientDisconnected);
            let owner: RelayClientDisconnected = disconnected.payload().unwrap();
            assert_eq!(owner.id_start, paused_id);
            let (mut before_barrier, before_id) = connect(&path).await;
            assert_ne!(before_id, paused_id);
            codec::write_message(
                &mut before_barrier,
                &Message::with_payload(MessageType::RelayClientDisconnected, before_id, &owner)
                    .unwrap(),
            )
            .await
            .unwrap();
            let refused = host_frame(&shared, &wake).await;
            assert_eq!(refused.t, MessageType::RelayClientDisconnected);
            assert_eq!(
                refused
                    .payload::<RelayClientDisconnected>()
                    .unwrap()
                    .id_start,
                before_id
            );
            guest_frame(
                &shared,
                Message::with_payload(MessageType::RelayClientReleased, 0, &owner).unwrap(),
            );
            // An ordered control frame witnesses that the release barrier passed.
            guest_frame(
                &shared,
                Message::with_payload(MessageType::TcpConnected, active_id, &TcpConnected {})
                    .unwrap(),
            );
            assert_eq!(
                codec::read_message(&mut active).await.unwrap().t,
                MessageType::TcpConnected
            );
            let (reused, reused_id) = connect(&path).await;
            assert_eq!(reused_id, paused_id);
            drop((before_barrier, reused, active));
            shutdown.send_replace(true);
            running.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    fn test_agent_endpoint(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        #[cfg(unix)]
        {
            // These tests instantiate the relay directly, bypassing the SDK's
            // hashed runtime socket resolver. Keep the synthetic socket short
            // enough for macOS sockaddr_un limits.
            PathBuf::from("/tmp")
                .join(format!(
                    "msb-runtime-relay-{name}-{}-{nanos}",
                    std::process::id()
                ))
                .join("agent.sock")
        }

        #[cfg(windows)]
        {
            PathBuf::from(format!(
                r"\\.\pipe\msb-runtime-relay-{name}-{}-{nanos}",
                std::process::id()
            ))
        }
    }

    fn encoded_message<T: serde::Serialize>(t: MessageType, payload: &T) -> Vec<u8> {
        let msg = Message::with_payload(t, 0, payload).unwrap();
        let mut frame = Vec::new();
        codec::encode_to_buf(&msg, &mut frame).unwrap();
        frame
    }

    #[test]
    fn client_frame_validation_allows_ids_in_assigned_range() {
        assert!(is_client_frame_allowed(10, 0, 10, 20));
        assert!(is_client_frame_allowed(19, FLAG_SESSION_START, 10, 20));
    }

    #[test]
    fn client_frame_validation_rejects_non_shutdown_ids_outside_range() {
        assert!(!is_client_frame_allowed(0, 0, 10, 20));
        assert!(!is_client_frame_allowed(9, FLAG_SESSION_START, 10, 20));
        assert!(!is_client_frame_allowed(20, FLAG_TERMINAL, 10, 20));
    }

    #[test]
    fn client_frame_validation_allows_shutdown_control_id_zero() {
        assert!(is_client_frame_allowed(0, FLAG_SHUTDOWN, 10, 20));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn wait_ready_rejects_ready_before_init_when_maps_are_pending() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(8));
        let handle = Arc::new(std::sync::OnceLock::new());
        let sock_path = test_agent_endpoint("ready-before-init");
        let mut relay = AgentRelay::new(&sock_path, Arc::clone(&shared))
            .await
            .unwrap()
            .with_bind_identity_map(Some(Arc::clone(&handle)), 1);

        shared
            .tx_ring
            .push(encoded_message(
                MessageType::Ready,
                &Ready {
                    boot_time_ns: 0,
                    init_time_ns: 0,
                    ready_time_ns: 0,
                    ..Default::default()
                },
            ))
            .unwrap();
        shared.tx_wake.wake();

        let err = relay.wait_ready().unwrap_err();
        assert!(
            err.to_string()
                .contains("received core.ready before init context resolution")
        );
        assert!(handle.get().is_none());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn wait_ready_installs_init_map_before_ready() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(8));
        let handle = Arc::new(std::sync::OnceLock::new());
        let sock_path = test_agent_endpoint("init-map");
        let mut relay = AgentRelay::new(&sock_path, Arc::clone(&shared))
            .await
            .unwrap()
            .with_bind_identity_map(Some(Arc::clone(&handle)), 2);

        shared
            .tx_ring
            .push(encoded_message(
                MessageType::InitResolved,
                &InitResolved {
                    default_user: microsandbox_protocol::core::ResolvedUser {
                        uid: 1000,
                        gid: 1001,
                    },
                },
            ))
            .unwrap();
        shared
            .tx_ring
            .push(encoded_message(
                MessageType::Ready,
                &Ready {
                    boot_time_ns: 0,
                    init_time_ns: 0,
                    ready_time_ns: 0,
                    ..Default::default()
                },
            ))
            .unwrap();
        shared.tx_wake.wake();

        relay.wait_ready().unwrap();

        assert_eq!(
            handle.get().copied(),
            Some(BindIdentityMap::new(
                unsafe { libc::getuid() as u32 },
                1000,
                1001
            ))
        );
        assert!(shared.rx_ring.pop().is_some(), "host should ack agentd");
    }

    #[tokio::test]
    async fn wait_ready_skips_init_requirement_when_no_bind_map_pending() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(8));
        let sock_path = test_agent_endpoint("no-bind-map");
        let mut relay = AgentRelay::new(&sock_path, Arc::clone(&shared))
            .await
            .unwrap();
        #[cfg(unix)]
        {
            relay = relay.with_bind_identity_map(None, 0);
        }

        let ready = encoded_message(
            MessageType::Ready,
            &Ready {
                boot_time_ns: 0,
                init_time_ns: 0,
                ready_time_ns: 0,
                ..Default::default()
            },
        );
        shared.tx_ring.push(ready.clone()).unwrap();
        shared.tx_wake.wake();

        relay.wait_ready().unwrap();

        assert_eq!(relay.ready_frame, Some(ready));
        assert!(
            shared.rx_ring.pop().is_none(),
            "no init context means no ack should be sent"
        );
    }
}
