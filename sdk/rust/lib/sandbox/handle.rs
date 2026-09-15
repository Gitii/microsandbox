//! Lightweight sandbox handle for metadata and signal-based lifecycle management.
//!
//! Per the SDK local-cloud parity plan (D6.4) `SandboxHandle` stays a single
//! type regardless of backend. It carries an `Arc<dyn Backend>` plus a
//! backend-private [`SandboxHandleInner`](crate::backend::SandboxHandleInner)
//! enum. Users reach variant-specific data via [`SandboxHandle::local`] /
//! [`SandboxHandle::cloud`].

use std::sync::Arc;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::{
    MicrosandboxError, MicrosandboxResult,
    backend::{
        Backend, CloudCreateSandboxResponse, SandboxCloudState, SandboxHandleCloudState,
        SandboxHandleInner, SandboxHandleLocalState,
    },
    db::entity::{run as run_entity, sandbox as sandbox_entity},
    error::Operation,
};

use super::{Sandbox, SandboxConfig, SandboxModificationBuilder, SandboxStatus, SandboxStopResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default timeout for the eager local agent connection made by
/// [`SandboxHandle::connect`].
pub const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Default graceful-stop deadline, including guest shutdown and runtime handoff.
pub const DEFAULT_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);

/// Default timeout for observing stopped state after force termination.
pub const DEFAULT_KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long [`SandboxHandle::wait_for_clean_stop_within`] waits for the runtime
/// process to disappear *after* its run row has gone terminal.
///
/// Up to that point the wait is the guest's shutdown window and belongs to the
/// caller's stop deadline. Once the exit observer has written the terminal row
/// the process is already leaving, so a PID that lingers is either wedged or —
/// on Unix, where the SDK cannot prove a PID's identity — recycled. Either way
/// there is nothing more to observe.
const RUNTIME_EXIT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// How often the observation loop re-reads the run row.
const CLEAN_STOP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What a graceful-stop request actually did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopRequest {
    /// The sandbox was already `Stopped` or `Crashed` before we asked. No
    /// shutdown was requested, so this call has nothing to judge clean.
    AlreadyTerminal,

    /// A graceful shutdown was requested of a running or draining sandbox.
    Dispatched,
}

/// A lightweight handle to a sandbox.
///
/// Provides metadata access and signal-based lifecycle management (stop, kill,
/// remove) without requiring a live agent bridge. Obtained via
/// [`Sandbox::get`] or [`Sandbox::list`].
///
/// For full runtime capabilities (exec, shell, fs), call
/// [`connect`](SandboxHandle::connect) when the sandbox is already running, or
/// [`start`](SandboxHandle::start) to boot a stopped sandbox.
pub struct SandboxHandle {
    backend: Arc<dyn Backend>,
    inner: SandboxHandleInner,
    name: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxHandle {
    /// Build a handle from a local sandbox DB row + active PID.
    pub(crate) fn from_local_model(
        backend: Arc<dyn Backend>,
        model: sandbox_entity::Model,
        pid: Option<i32>,
    ) -> Self {
        let name = model.name.clone();
        Self {
            backend,
            inner: SandboxHandleInner::Local(SandboxHandleLocalState {
                db_id: model.id,
                status: model.status,
                config_json: model.config,
                active_config_json: model.active_config,
                created_at: model.created_at.map(|dt| dt.and_utc()),
                updated_at: model.updated_at.map(|dt| dt.and_utc()),
                pid,
            }),
            name,
        }
    }

    /// Build a handle from a [`CloudCreateSandboxResponse`] HTTP response.
    ///
    /// Preserves the cloud's optional curated spec as JSON for the
    /// `config_json()` inspection view. An absent spec is represented as JSON
    /// `null`; it is not replaced with a fabricated SDK configuration.
    pub(crate) fn from_cloud(
        backend: Arc<dyn Backend>,
        cloud: CloudCreateSandboxResponse,
    ) -> MicrosandboxResult<Self> {
        let status = crate::backend::sandbox::cloud_status_to_sandbox_status(cloud.status);
        let config_json = serde_json::to_string(&cloud.spec)?;
        let name = cloud.name.clone();
        Ok(Self {
            backend,
            inner: SandboxHandleInner::Cloud(SandboxHandleCloudState {
                id: cloud.id,
                org_id: cloud.org_id,
                status,
                config_json,
                created_at: Some(cloud.created_at),
                started_at: cloud.started_at,
                stopped_at: cloud.stopped_at,
                last_failure_message: cloud.last_failure_message,
            }),
            name,
        })
    }

    /// Unique name identifying this sandbox.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Which backend variant this handle is bound to.
    pub fn backend_kind(&self) -> crate::backend::BackendKind {
        self.backend.kind()
    }

    /// Local-only handle state. Returns `Some` for local-backed handles.
    pub fn local(&self) -> Option<&SandboxHandleLocalState> {
        match &self.inner {
            SandboxHandleInner::Local(s) => Some(s),
            SandboxHandleInner::Cloud(_) => None,
        }
    }

    /// Cloud-only handle state. Returns `Some` for cloud-backed handles.
    pub fn cloud(&self) -> Option<&SandboxHandleCloudState> {
        match &self.inner {
            SandboxHandleInner::Cloud(s) => Some(s),
            SandboxHandleInner::Local(_) => None,
        }
    }

    /// Snapshot of sandbox status captured when this handle was created.
    ///
    /// **Not live** — call [`Sandbox::status`](super::Sandbox::status) on the
    /// live `Sandbox` (or re-fetch via [`Sandbox::get`](super::Sandbox::get))
    /// for a fresh reading. The `_snapshot` suffix is deliberate to avoid
    /// confusion with `Sandbox::status()` which is async + fetch-live.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handle = Sandbox::get("agent-1").await?;
    /// // Cheap, in-memory; reflects state at handle-creation time.
    /// let snap = handle.status_snapshot();
    ///
    /// // For a fresh reading, drive through the live Sandbox:
    /// let sb = handle.start().await?;
    /// let live = sb.status().await?;
    /// ```
    pub fn status_snapshot(&self) -> SandboxStatus {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.status,
            SandboxHandleInner::Cloud(s) => s.status,
        }
    }

    /// Snapshot of the cloud `last_failure_message`, if any. Returns `None`
    /// for local handles (local errors flow through the typed error stack).
    pub fn last_failure_message_snapshot(&self) -> Option<String> {
        match &self.inner {
            SandboxHandleInner::Cloud(s) => s.last_failure_message.clone(),
            SandboxHandleInner::Local(_) => None,
        }
    }

    /// The serialized sandbox configuration as stored in the database (local)
    /// or returned by msb-cloud (cloud). Use [`config()`](Self::config) for a
    /// deserialized [`SandboxConfig`].
    pub fn config_json(&self) -> &str {
        match &self.inner {
            SandboxHandleInner::Local(s) => &s.config_json,
            SandboxHandleInner::Cloud(s) => &s.config_json,
        }
    }

    /// The serialized configuration used by the active VM, when known.
    ///
    /// Local handles return `Some` only while a sandbox has started under a
    /// runtime that records active config snapshots. Stopped sandboxes and
    /// older running sandboxes may return `None`.
    pub fn active_config_json(&self) -> Option<&str> {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.active_config_json.as_deref(),
            SandboxHandleInner::Cloud(_) => None,
        }
    }

    /// Parse the stored configuration. Returns an error if the JSON
    /// is malformed (e.g., schema changed since the sandbox was created).
    ///
    /// For local handles this deserializes the persisted [`SandboxConfig`].
    /// For cloud handles this returns an `Unsupported` error: the cloud wire
    /// shape is [`CloudCreateSandboxRequest`](crate::backend::CloudCreateSandboxRequest),
    /// not `SandboxConfig`. Use [`config_json`](Self::config_json) to read the
    /// raw JSON, or [`cloud`](Self::cloud) to access the typed cloud state.
    pub fn config(&self) -> MicrosandboxResult<SandboxConfig> {
        match &self.inner {
            SandboxHandleInner::Local(s) => Ok(serde_json::from_str(&s.config_json)?),
            SandboxHandleInner::Cloud(_) => Err(MicrosandboxError::local_only(
                Operation::SandboxHandleConfig,
            )),
        }
    }

    /// Parse the active configuration snapshot, when one is available.
    pub fn active_config(&self) -> MicrosandboxResult<Option<SandboxConfig>> {
        self.active_config_json()
            .map(serde_json::from_str)
            .transpose()
            .map_err(Into::into)
    }

    /// Start planning a sandbox modification from this handle.
    ///
    /// The builder fetches a fresh handle during [`dry_run`](SandboxModificationBuilder::dry_run)
    /// so planning uses current status and persisted config rather than this
    /// handle's possibly stale snapshot.
    pub fn modify(&self) -> SandboxModificationBuilder {
        SandboxModificationBuilder::new(self.backend.clone(), self.name.clone())
    }

    /// Fail with a typed error when the sandbox is not running.
    fn require_running(&self, operation: &str) -> MicrosandboxResult<()> {
        let status = self.status_snapshot();
        if matches!(
            status,
            super::SandboxStatus::Running | super::SandboxStatus::Draining
        ) {
            return Ok(());
        }
        Err(MicrosandboxError::SandboxNotRunning(format!(
            "'{}' is not running (status: {status:?}); cannot {operation}",
            self.name
        )))
    }

    /// Return a fresh handle for the same sandbox name.
    pub async fn refresh(&self) -> MicrosandboxResult<SandboxHandle> {
        self.backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await
    }

    /// When this sandbox was first created, if recorded.
    pub fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.created_at,
            SandboxHandleInner::Cloud(s) => s.created_at,
        }
    }

    /// Best-effort "last activity" timestamp.
    ///
    /// - Local: the database row's `updated_at` (modification time of the
    ///   persisted record).
    /// - Cloud: the most recent of `stopped_at` / `started_at` / `created_at`
    ///   from the msb-cloud response. msb-cloud has no dedicated
    ///   `updated_at` column, so this is synthesised on the client.
    pub fn updated_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.inner {
            SandboxHandleInner::Local(s) => s.updated_at,
            SandboxHandleInner::Cloud(s) => s.stopped_at.or(s.started_at).or(s.created_at),
        }
    }

    /// Read captured output from `exec.log` for this sandbox.
    ///
    /// Same backing data as [`Sandbox::logs`](super::Sandbox::logs).
    /// Works without starting the sandbox. **Local handles only**.
    pub async fn logs(
        &self,
        opts: &crate::logs::LogOptions,
    ) -> MicrosandboxResult<Vec<crate::logs::LogEntry>> {
        self.backend
            .sandboxes()
            .logs(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Stream captured output for this sandbox.
    ///
    /// Same backing data as [`Sandbox::log_stream`](super::Sandbox::log_stream).
    /// Works without starting the sandbox.
    pub async fn log_stream(
        &self,
        opts: &crate::logs::LogStreamOptions,
    ) -> MicrosandboxResult<crate::backend::sandbox::LogStream> {
        self.backend
            .sandboxes()
            .log_stream(self.backend.clone(), &self.name, opts)
            .await
    }

    /// Get the latest metrics snapshot for this sandbox. **Local handles only**.
    pub async fn metrics(&self) -> MicrosandboxResult<super::SandboxMetrics> {
        let local = self
            .local()
            .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxHandleMetrics))?;

        if local.status != SandboxStatus::Running && local.status != SandboxStatus::Draining {
            return Err(MicrosandboxError::SandboxNotRunning(format!(
                "'{}' is not running (status: {:?})",
                self.name, local.status
            )));
        }

        let config = self.config()?;
        if config.effective_metrics_interval().is_none() {
            return Err(MicrosandboxError::MetricsDisabled(self.name.clone()));
        }

        let local_backend = self
            .backend
            .as_local()
            .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxHandleMetrics))?;
        let db = local_backend.db().await?.read();
        super::metrics::metrics_for_sandbox(db, local_backend, local.db_id, &config).await
    }

    /// Start this sandbox and return a live handle.
    ///
    /// Boots the VM using the persisted configuration and pinned rootfs state
    /// for local; routes through `POST /v1/sandboxes/by-name/:name/start` for
    /// cloud. The handle remains usable if start fails.
    pub async fn start(&self) -> MicrosandboxResult<Sandbox> {
        self.backend
            .sandboxes()
            .start(self.backend.clone(), &self.name)
            .await
    }

    /// Start this sandbox in detached/background mode.
    ///
    /// The handle remains usable if start fails.
    pub async fn start_detached(&self) -> MicrosandboxResult<Sandbox> {
        self.backend
            .sandboxes()
            .start_detached(self.backend.clone(), &self.name)
            .await
    }

    /// Connect to a running sandbox and return a live handle.
    ///
    /// Local sandboxes establish the agent relay connection eagerly. Cloud
    /// sandboxes return a backend-bound handle whose exec, SSH, and filesystem
    /// operations open authenticated agent WebSockets on demand.
    pub async fn connect(&self) -> MicrosandboxResult<Sandbox> {
        self.connect_with_timeout(DEFAULT_CONNECT_TIMEOUT).await
    }

    /// Connect to a running sandbox with an explicit local agent handshake
    /// timeout.
    ///
    /// Cloud reconnect is lazy and does not open an agent WebSocket here, so
    /// this timeout applies only to local handles.
    pub async fn connect_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> MicrosandboxResult<Sandbox> {
        if !matches!(
            self.status_snapshot(),
            SandboxStatus::Running | SandboxStatus::Draining
        ) {
            return Err(MicrosandboxError::SandboxNotRunning(format!(
                "'{}' is not running (status: {:?})",
                self.name,
                self.status_snapshot()
            )));
        }

        match &self.inner {
            SandboxHandleInner::Local(local) => {
                let local_backend = self.backend.as_local().ok_or_else(|| {
                    MicrosandboxError::local_only(Operation::SandboxHandleConnect)
                })?;
                let client = crate::sandbox::fs::agent::connect_agent_with_timeout(
                    local_backend,
                    &self.name,
                    timeout,
                )
                .await?;
                let config: SandboxConfig = serde_json::from_str(&local.config_json)?;

                Ok(Sandbox::from_local(
                    self.backend.clone(),
                    crate::backend::SandboxLocalState {
                        db_id: local.db_id,
                        handle: None,
                        client: Arc::new(client),
                    },
                    config,
                ))
            }
            SandboxHandleInner::Cloud(cloud) => {
                // The cloud handle stores the optional curated spec exactly as
                // returned by the API. Decode it on reconnect, falling back to
                // SDK defaults when the server intentionally omitted it.
                let spec = serde_json::from_str(&cloud.config_json)?;
                let config =
                    crate::backend::sandbox::sandbox_config_from_cloud_spec(&self.name, spec);
                let created_at = cloud.created_at.ok_or_else(|| {
                    MicrosandboxError::Runtime(format!(
                        "cloud sandbox {:?} is missing its creation timestamp",
                        self.name
                    ))
                })?;

                Ok(Sandbox::from_cloud_state(
                    self.backend.clone(),
                    SandboxCloudState {
                        id: cloud.id.clone(),
                        org_id: cloud.org_id.clone(),
                        created_at,
                    },
                    self.name.clone(),
                    config,
                ))
            }
        }
    }

    /// Check whether agentd is reachable without refreshing the sandbox idle timer.
    ///
    /// Connects to the running sandbox and sends `core.ping`. Stopped sandboxes
    /// are not started implicitly; call [`start`](Self::start) first when that
    /// is the desired behavior.
    pub async fn ping(&self) -> MicrosandboxResult<super::SandboxPingResult> {
        self.require_running("ping")?;
        self.connect().await?.ping().await
    }

    /// Explicitly refresh the sandbox idle timer.
    ///
    /// Connects to the running sandbox and sends `core.touch`. Stopped sandboxes
    /// are not started implicitly; call [`start`](Self::start) first when that
    /// is the desired behavior.
    pub async fn touch(&self) -> MicrosandboxResult<super::SandboxTouchResult> {
        self.require_running("touch")?;
        self.connect().await?.touch().await
    }

    /// Snapshot this sandbox to a bare name under the default snapshots
    /// directory (`~/.microsandbox/snapshots/<name>/`).
    ///
    /// The sandbox must be stopped (or crashed); running sandboxes are
    /// rejected with `MicrosandboxError::SnapshotSandboxRunning`. **Local
    /// handles only** — cloud snapshot semantics are deferred.
    pub async fn snapshot(
        &self,
        name: &str,
    ) -> MicrosandboxResult<super::super::snapshot::Snapshot> {
        if self.local().is_none() {
            return Err(MicrosandboxError::local_only(
                Operation::SandboxHandleSnapshot,
            ));
        }
        use super::super::snapshot::Snapshot;
        Snapshot::builder(name)
            .from_sandbox(&self.name)
            .create()
            .await
    }

    /// Stop the sandbox gracefully using the default stop timeout.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        self.stop_with_timeout(DEFAULT_STOP_TIMEOUT).await
    }

    /// Stop gracefully within a deadline. Timeout or unclean exit is an error;
    /// force termination requires an explicit call to [`kill`](Self::kill).
    /// A sandbox that was already terminal before the call returns `Ok`: stop
    /// stays idempotent, and this call cannot vouch for a shutdown it never
    /// requested. Only a shutdown this call dispatched is held to the clean-exit
    /// evidence below.
    pub async fn stop_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
        match tokio::time::timeout(timeout, async {
            if self.dispatch_stop().await? == StopRequest::AlreadyTerminal {
                return Ok(());
            }
            self.wait_for_clean_stop_within(timeout).await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(MicrosandboxError::Runtime(format!(
                "graceful stop deadline expired for sandbox '{}'; clean shutdown is unconfirmed",
                self.name
            ))),
        }
    }

    /// Wait for positive evidence that the sandbox shut down cleanly, within
    /// `bound` — the caller's whole stop deadline, since the guest's shutdown
    /// window lives inside it. The wait for the runtime process to exit after
    /// the row goes terminal is bounded more tightly, by [`RUNTIME_EXIT_WAIT`].
    ///
    /// Two conditions must hold, not one. The runtime writes the terminal run
    /// row from inside its exit observer, while it is still running and still
    /// holding the flock on every disk image it attached, so the row alone
    /// says nothing about the images. The PID is checked, and then each image
    /// is probed by taking its lock the way the next boot would: only once
    /// that succeeds is the sandbox provably detached from its disks.
    pub(crate) async fn wait_for_clean_stop_within(
        &self,
        bound: std::time::Duration,
    ) -> MicrosandboxResult<()> {
        let Some(local) = self.local() else {
            let result = self.wait_until_stopped().await?;
            return if result.status == SandboxStatus::Stopped {
                Ok(())
            } else {
                Err(MicrosandboxError::Runtime(format!(
                    "sandbox '{}' stopped uncleanly",
                    self.name
                )))
            };
        };
        let backend = self
            .backend
            .as_local()
            .ok_or_else(|| MicrosandboxError::Runtime("missing local backend".into()))?;
        let disk_images = self.attached_disk_images(backend).await;
        let deadline = tokio::time::Instant::now() + bound;
        let mut runtime_exit_deadline = None;
        let mut locked_image = None;
        loop {
            let run = run_entity::Entity::find()
                .filter(run_entity::Column::SandboxId.eq(local.db_id))
                .order_by_desc(run_entity::Column::Id)
                .one(backend.db().await?.read())
                .await?;
            let Some(run) = run else {
                // An ephemeral sandbox is self-cleaned by the runtime's exit
                // observer, which deletes the sandbox row and its runs. The
                // missing evidence *is* the evidence that it reached a
                // terminal state — the same exemption that
                // `Sandbox::stop_with_timeout` applies before it ever asks
                // for a handle.
                if self.is_local_ephemeral() {
                    return Ok(());
                }
                return Err(MicrosandboxError::Runtime(format!(
                    "no run evidence for sandbox '{}'",
                    self.name
                )));
            };
            if run.status == run_entity::RunStatus::Terminated {
                ensure_clean_run(&run)?;
                if !self.runtime_process_is_live(&run).await? {
                    locked_image = first_locked_disk_image(&disk_images);
                    if locked_image.is_none() {
                        return Ok(());
                    }
                } else {
                    // The PID keeps its own, tighter bound: past it the
                    // process is either wedged or — on Unix, where the SDK
                    // cannot prove a PID's identity — recycled.
                    let runtime_exit_deadline = *runtime_exit_deadline
                        .get_or_insert_with(|| tokio::time::Instant::now() + RUNTIME_EXIT_WAIT);
                    if tokio::time::Instant::now() >= runtime_exit_deadline {
                        return Err(MicrosandboxError::Runtime(format!(
                            "sandbox '{}' reached a terminal run but its VM process is still alive",
                            self.name
                        )));
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                if let Some(image) = locked_image {
                    return Err(MicrosandboxError::Runtime(format!(
                        "sandbox '{}' still holds disk image '{}'; its runtime has not released it",
                        self.name,
                        image.display()
                    )));
                }
                return Err(MicrosandboxError::Runtime(format!(
                    "sandbox '{}' did not confirm a clean stop within {:?}",
                    self.name, bound
                )));
            }
            tokio::time::sleep(CLEAN_STOP_POLL_INTERVAL).await;
        }
    }

    /// Whether the VM process recorded on `run` is still running.
    ///
    /// On Windows a terminal row can still be backed by a VM process that
    /// never finished exiting, so the identity-checked reap terminates it —
    /// and leaves a recycled PID alone, which for this loop's purposes means
    /// the runtime is gone. On Unix the SDK has no process-identity probe, so
    /// the recorded PID is taken at face value and [`RUNTIME_EXIT_WAIT`] is
    /// what keeps a recycled PID from holding the loop open.
    async fn runtime_process_is_live(&self, run: &run_entity::Model) -> MicrosandboxResult<bool> {
        #[cfg(windows)]
        {
            let _ = run;
            let (Some(local), Some(local_backend)) = (self.local(), self.backend.as_local()) else {
                return Ok(false);
            };
            super::reap_leaked_runtime_process(local_backend, local.db_id, &self.name).await?;
            Ok(false)
        }
        #[cfg(not(windows))]
        {
            Ok(run
                .pid
                .is_some_and(microsandbox_utils::process::pid_is_alive))
        }
    }

    /// The disk images this sandbox attaches, as the spawn path resolves them.
    /// Empty when the handle is not local or its stored spec cannot be read —
    /// there is then nothing the probe can prove either way.
    async fn attached_disk_images(
        &self,
        backend: &crate::backend::LocalBackend,
    ) -> Vec<(std::path::PathBuf, bool)> {
        let SandboxHandleInner::Local(state) = &self.inner else {
            return Vec::new();
        };
        match serde_json::from_str::<SandboxConfig>(&state.config_json) {
            Ok(config) => crate::runtime::spawn::attached_disk_images(backend, &config).await,
            Err(error) => {
                tracing::debug!(%error, sandbox = %self.name, "reading the stored spec for the disk release probe");
                Vec::new()
            }
        }
    }

    /// Request graceful shutdown without waiting for observed stopped state.
    pub async fn request_stop(&self) -> MicrosandboxResult<()> {
        self.dispatch_stop().await.map(|_| ())
    }

    /// Request graceful shutdown, reporting whether the sandbox was already
    /// terminal before the request.
    pub(crate) async fn dispatch_stop(&self) -> MicrosandboxResult<StopRequest> {
        let current = match self.refresh().await {
            Ok(current) => current,
            // An ephemeral sandbox whose row the runtime already deleted is
            // terminal by definition; the same exemption `wait_until_stopped`
            // applies.
            Err(error)
                if self.is_local_ephemeral()
                    && super::sandbox_not_found_for_name(&error, &self.name) =>
            {
                return Ok(StopRequest::AlreadyTerminal);
            }
            Err(error) => return Err(error),
        };
        if sandbox_status_is_terminal(current.status_snapshot()) {
            return Ok(StopRequest::AlreadyTerminal);
        }

        current
            .backend
            .sandboxes()
            .stop(current.backend.clone(), &current.name)
            .await?;

        Ok(StopRequest::Dispatched)
    }

    /// Kill the sandbox immediately and wait until it is observed stopped.
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.kill_with_timeout(DEFAULT_KILL_TIMEOUT).await
    }

    /// Request force termination without waiting for observed stopped state.
    pub async fn request_kill(&self) -> MicrosandboxResult<()> {
        let current = self.refresh().await?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            return Ok(());
        }

        current
            .backend
            .sandboxes()
            .kill(current.backend.clone(), &current.name)
            .await
    }

    /// Force-kill the sandbox and wait up to `timeout` for stopped-state observation.
    pub async fn kill_with_timeout(&self, timeout: std::time::Duration) -> MicrosandboxResult<()> {
        let current = self.refresh().await?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            return Ok(());
        }

        current.request_kill().await?;
        match tokio::time::timeout(timeout, current.wait_until_stopped()).await {
            Ok(result) => {
                result?;
                Ok(())
            }
            Err(_) => Err(MicrosandboxError::Runtime(format!(
                "timed out observing stopped state for sandbox '{}'",
                current.name
            ))),
        }
    }

    /// Request drain without waiting for observed stopped state.
    pub async fn request_drain(&self) -> MicrosandboxResult<()> {
        let current = self.refresh().await?;
        if sandbox_status_is_terminal(current.status_snapshot()) {
            return Ok(());
        }

        current
            .backend
            .sandboxes()
            .drain(current.backend.clone(), &current.name)
            .await
    }

    /// Wait until this sandbox is observed in a terminal non-running state.
    pub async fn wait_until_stopped(&self) -> MicrosandboxResult<SandboxStopResult> {
        loop {
            let current = match self.refresh().await {
                Ok(current) => current,
                Err(error)
                    if self.is_local_ephemeral()
                        && super::sandbox_not_found_for_name(&error, &self.name) =>
                {
                    return Ok(super::ephemeral_cleanup_stop_result(&self.name));
                }
                Err(error) => return Err(error),
            };
            let status = current.status_snapshot();
            if sandbox_status_is_terminal(status) {
                return Ok(SandboxStopResult {
                    name: current.name,
                    status,
                    exit_code: None,
                    signal: None,
                    observed_at: chrono::Utc::now(),
                    source: Some("refreshed backend state".to_string()),
                });
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Remove this sandbox.
    ///
    /// The sandbox must be stopped first. Use [`stop`](Self::stop) or
    /// [`kill`](Self::kill) to stop it before removing. Routes through the
    /// backend trait so cloud handles hit `DELETE /v1/sandboxes/by-name/:name`.
    pub async fn remove(&self) -> MicrosandboxResult<()> {
        match &self.inner {
            SandboxHandleInner::Local(_) => {
                let refreshed = self.refresh().await?;
                let local = refreshed
                    .local()
                    .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxHandleRemove))?;
                if matches!(
                    local.status,
                    SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
                ) {
                    return Err(MicrosandboxError::SandboxStillRunning(format!(
                        "cannot remove sandbox '{}': still running",
                        self.name
                    )));
                }

                let local_backend = self
                    .backend
                    .as_local()
                    .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxHandleRemove))?;

                // Windows: a terminal row can still be backed by a leaked VM
                // process. Deleting the row and run records now would orphan
                // it while it keeps serving this name's agent pipes, so kill
                // it (identity-checked) or fail before touching any state.
                #[cfg(windows)]
                super::reap_leaked_runtime_process(local_backend, local.db_id, &self.name).await?;
                let pools = local_backend.db().await?;

                super::remove_dir_if_exists(&local_backend.sandboxes_dir().join(&self.name))?;
                sandbox_entity::Entity::delete_by_id(local.db_id)
                    .exec(pools.write())
                    .await?;

                Ok(())
            }
            SandboxHandleInner::Cloud(_) => {
                self.backend
                    .sandboxes()
                    .remove(self.backend.clone(), &self.name)
                    .await
            }
        }
    }

    fn is_local_ephemeral(&self) -> bool {
        is_local_ephemeral_handle(&self.inner)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn is_local_ephemeral_handle(inner: &SandboxHandleInner) -> bool {
    let SandboxHandleInner::Local(state) = inner else {
        return false;
    };

    serde_json::from_str::<SandboxConfig>(&state.config_json)
        .map(|config| config.spec.lifecycle.ephemeral)
        .unwrap_or(false)
}

/// The first disk image the stopped runtime has not released yet, if any.
///
/// Windows keeps its disk locks in a sidecar file opened by the *parent*, which
/// holds that handle for as long as this process lives, so probing there would
/// always conflict with ourselves. The Windows equivalent is the identity-checked
/// reap in [`SandboxHandle::runtime_process_is_live`].
fn first_locked_disk_image(images: &[(std::path::PathBuf, bool)]) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let _ = images;
        None
    }
    #[cfg(not(windows))]
    {
        images
            .iter()
            .find(|(path, readonly)| {
                !crate::runtime::spawn::disk_image_is_released(path, *readonly)
            })
            .map(|(path, _)| path.clone())
    }
}

fn sandbox_status_is_terminal(status: SandboxStatus) -> bool {
    matches!(status, SandboxStatus::Stopped | SandboxStatus::Crashed)
}

fn ensure_clean_run(run: &run_entity::Model) -> MicrosandboxResult<()> {
    if run.exit_code == Some(0)
        && run.exit_signal.is_none()
        && matches!(
            run.termination_reason,
            Some(
                run_entity::TerminationReason::Completed
                    | run_entity::TerminationReason::ShutdownRequested
                    | run_entity::TerminationReason::DrainRequested
            )
        )
    {
        Ok(())
    } else {
        Err(MicrosandboxError::Runtime(format!(
            "sandbox run {} did not confirm clean shutdown: reason {:?}, exit code {:?}, signal {:?}",
            run.id, run.termination_reason, run.exit_code, run.exit_signal
        )))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for SandboxHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxHandle")
            .field("name", &self.name)
            .field("backend_kind", &self.backend.kind())
            .field("status", &self.status_snapshot())
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendKind, CloudBackend, CloudSandboxStatus};

    #[test]
    fn clean_stop_requires_positive_run_evidence() {
        let mut run = run_entity::Model {
            id: 1,
            sandbox_id: 1,
            pid: None,
            status: run_entity::RunStatus::Terminated,
            exit_code: Some(0),
            exit_signal: None,
            termination_reason: Some(run_entity::TerminationReason::ShutdownRequested),
            termination_detail: None,
            signals_sent: None,
            started_at: None,
            terminated_at: None,
        };
        assert!(ensure_clean_run(&run).is_ok());
        run.termination_reason = Some(run_entity::TerminationReason::Failed);
        assert!(ensure_clean_run(&run).is_err());
        run.termination_reason = Some(run_entity::TerminationReason::ShutdownRequested);
        run.exit_code = None;
        assert!(ensure_clean_run(&run).is_err());
        run.exit_code = Some(1);
        assert!(ensure_clean_run(&run).is_err());
        run.exit_code = Some(0);
        run.exit_signal = Some(9);
        assert!(ensure_clean_run(&run).is_err());
    }

    #[tokio::test]
    async fn cloud_connect_rebuilds_live_sandbox_without_http_request() {
        let handle = cloud_handle(CloudSandboxStatus::Running);

        let sandbox = handle.connect().await.unwrap();

        assert_eq!(sandbox.name(), "cloud-connect-test");
        assert_eq!(sandbox.backend_kind(), BackendKind::Cloud);
        assert_eq!(sandbox.cloud().unwrap().id, "sandbox-id");
        assert_eq!(sandbox.config().spec.name, "cloud-connect-test");
    }

    #[tokio::test]
    async fn cloud_connect_rejects_stopped_sandbox() {
        let handle = cloud_handle(CloudSandboxStatus::Stopped);

        let result = handle.connect().await;

        assert!(matches!(
            result,
            Err(MicrosandboxError::SandboxNotRunning(_))
        ));
    }

    fn cloud_handle(status: CloudSandboxStatus) -> SandboxHandle {
        let backend: Arc<dyn Backend> =
            Arc::new(CloudBackend::new("https://unused.invalid", "msb_test_connect").unwrap());
        SandboxHandle::from_cloud(
            backend,
            CloudCreateSandboxResponse {
                id: "sandbox-id".into(),
                org_id: "org-id".into(),
                name: "cloud-connect-test".into(),
                slug: "cloud-connect-test".into(),
                status,
                status_reason: None,
                spec: None,
                ephemeral: false,
                created_at: chrono::Utc::now(),
                started_at: None,
                stopped_at: None,
                last_failure_message: None,
            },
        )
        .unwrap()
    }
}
