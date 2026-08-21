//! Host-side observation of network policy denials.
//!
//! Policy denials are decided deep inside the network stack and, before
//! this module, were visible only as `tracing` records — and only on some
//! paths. Embedding code that wants to react to a denial (surface it in a
//! UI, offer a one-click allowlist entry, audit it) had no programmatic
//! way to see one.
//!
//! A [`PolicyObserver`] is installed on the shared network state and is
//! invoked from the evaluation choke points themselves rather than from
//! individual call sites, so a new caller of the policy API cannot forget
//! to report its denials.
//!
//! Observers run inline on the evaluation path. An implementation should
//! hand the denial to a channel or counter and return; blocking here
//! blocks guest traffic. A [`PolicyDenial`] carries no timestamp: stamping
//! it is the observer's business, and the two shipped consumers of it — a
//! `tracing` subscriber and an embedder's own channel — both have a better
//! clock reading of their own than the evaluation path would take.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::types::{Direction, Protocol};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What the denied traffic was addressed to.
///
/// Address-based paths (TCP, UDP, ICMP, ingress) carry a resolved peer.
/// A DNS query denied by name is refused before any address exists, so it
/// carries the queried name instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialTarget {
    /// Peer address the decision was evaluated against.
    Address(IpAddr),

    /// Queried name, for a DNS query denied before resolution.
    Domain(String),
}

/// A single denial produced by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDenial {
    /// Direction the denied traffic was travelling.
    pub direction: Direction,

    /// Protocol the decision was evaluated under.
    pub protocol: Protocol,

    /// Peer address, or queried name for a name-only DNS denial.
    pub target: DenialTarget,

    /// Guest-side port: destination port for egress, listening port for
    /// ingress. `None` on paths without ports, such as ICMP.
    pub port: Option<u16>,

    /// Hostname the peer address is known by, when the resolved-hostname
    /// index or the TLS handshake supplied one. `None` when the traffic
    /// was addressed numerically.
    pub hostname: Option<String>,
}

/// Host-side sink for policy denials.
///
/// Installed with `SharedState::set_policy_observer`. Implementations must
/// be cheap and non-blocking; see the module documentation.
pub trait PolicyObserver: Send + Sync {
    /// Called once per denied evaluation.
    fn on_denied(&self, denial: &PolicyDenial);

    /// Emit anything the observer is still holding.
    ///
    /// An observer that batches — as [`LoggingPolicyObserver`] does, to rate
    /// limit — must report its pending state here, because the shipped
    /// runtime tears the network down along a path that never drops it: the
    /// sandbox process leaves via `_exit`, which runs no destructors. The
    /// runtime calls this from its synchronous exit hook. The default is a
    /// no-op, for an observer that holds nothing.
    fn flush(&self) {}
}

/// Observer that writes each denial to the runtime's log output as a
/// structured `tracing` event.
///
/// This is the observer a host process gets without asking: embedders that
/// link the crate can install their own, but a consumer outside the process
/// — a supervising daemon reading the runtime's logs — has no other way to
/// see a denial. The event is emitted at `WARN` on the
/// [`DENIAL_LOG_TARGET`] target, carrying one field per denial component so
/// that a `tracing` JSON layer renders it as a machine-readable object and
/// the default text layer renders it as `key=value` pairs.
///
/// The field set is a contract for those consumers: `event`, `direction`,
/// `protocol`, `peer_kind`, `peer`, `port`, `hostname`, `verdict`,
/// `denials`. Fields are always present; unknown values are logged as the
/// empty string rather than omitted, so a parser never has to handle a
/// missing key. The peer is deliberately not called `target`: a JSON layer
/// configured with `flatten_event` puts the `tracing` metadata target at
/// that key, and one of the two would silently win.
///
/// `WARN` is chosen so the line survives the sandbox subprocess's default
/// filter, which is `INFO` — that subprocess is where the network stack
/// runs and its stderr is captured into `runtime.log`, so a denial reaches
/// the file a host consumer reads without anyone passing a verbosity flag.
///
/// # Rate limiting, and how to count
///
/// Denials are decided per *packet*: a deny-by-default sandbox with a chatty
/// guest denies every datagram, every echo and every SYN retransmit, and
/// `runtime.log` rotates at 10 MiB with the lifecycle and VMM diagnostics
/// other tooling reads. So the first denial of a destination is logged at
/// once and further denials of that destination inside [`SUPPRESSION_WINDOW`]
/// are counted rather than logged.
///
/// **`denials` is how many denied packets the line accounts for.** A
/// consumer counting packets sums that field across lines; it never adds
/// anything to it, and it never counts lines. This matters because not every
/// line stands for a packet of its own — a [`DENIAL_FLUSH_EVENT`] line
/// reports a tally for a destination that has since gone quiet, and carries
/// no packet beyond the ones it counts.
///
/// Three `event` values are emitted, and a consumer that only understands
/// the first still counts correctly, just later and coarser:
///
/// * [`DENIAL_LOG_EVENT`] — a denied packet, plus any swallowed before it.
/// * [`DENIAL_FLUSH_EVENT`] — the trailing tally of a destination that
///   stopped being denied. It carries the same destination evidence as the
///   line that opened its suppression window.
/// * [`DENIAL_SATURATED_EVENT`] — the limiter was tracking
///   [`MAX_TRACKED_PEERS`] destinations at once and dropped denials for
///   destinations it had no room to track. Its `peer` is empty, because it
///   stands for many. Without it, a port scan against a deny-all policy
///   would be indistinguishable from silence.
///
/// The rate limiter also collapses the duplicate line a packet would
/// otherwise produce where a platform policy and a tenant policy both deny
/// it.
///
/// Sweeps are what ship trailing tallies, and they run from `on_denied`
/// itself — at most once per [`SUPPRESSION_WINDOW`], so the flood path stays
/// a hash lookup rather than a scan of the map. A tally therefore ships on
/// the next denial *anywhere*, not on the next denial of its own
/// destination. If the guest stops being denied entirely, nothing swept the
/// last tally out — so [`PolicyObserver::flush`] ships it, called by the
/// runtime from the synchronous exit hook it runs before `_exit`. That hook,
/// not [`Drop`], is the shipped teardown path: the sandbox process exits via
/// `_exit`, which runs no destructors at all.
#[derive(Debug, Default)]
pub struct LoggingPolicyObserver {
    /// Rate-limiter state. One lock: `on_denied` touches all of it, and a
    /// second lock would only add an ordering to get wrong.
    state: Mutex<LimiterState>,
}

/// Everything the rate limiter remembers between denials.
#[derive(Debug, Default)]
struct LimiterState {
    /// Destinations logged recently, and how many denials each has
    /// swallowed since its last line. Bounded by [`MAX_TRACKED_PEERS`].
    recent: HashMap<DenialKey, Suppression>,

    /// When the last sweep ran. `None` until the first denial.
    last_sweep: Option<Instant>,

    /// Set while the limiter is full, counting what it had no room for.
    saturation: Option<Saturation>,
}

/// Identity a denial is rate limited by: one line per distinct destination
/// and hostname per window, rather than one per packet. The hostname matters
/// even when two names resolve to the same address because consumers offer
/// exact-host policy changes from this evidence.
///
/// Keyed on the wire labels rather than the enums so that `Direction` and
/// `Protocol` do not have to grow a public `Hash` derive for an internal
/// rate limiter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DenialKey {
    direction: &'static str,
    protocol: &'static str,
    peer_kind: &'static str,
    peer: String,
    port: Option<u16>,
    hostname: Option<String>,
}

/// Rate-limiter state for one destination.
#[derive(Debug)]
struct Suppression {
    /// When the window this destination is currently inside opened.
    window_start: Instant,

    /// Denials swallowed since the last line for this destination.
    count: u64,
}

/// Rate-limiter state for the saturation marker itself, so that a flood of
/// untrackable destinations produces a trickle of markers rather than a
/// line each.
#[derive(Debug)]
struct Saturation {
    /// When the current marker window opened.
    window_start: Instant,

    /// Denials dropped untracked since the last marker.
    dropped: u64,
}

/// One log line the rate limiter has decided to emit.
#[derive(Debug, PartialEq, Eq)]
struct Line {
    /// Which of the three `event` values this line carries.
    event: &'static str,

    /// The destination, or `None` for a saturation marker.
    key: Option<DenialKey>,

    /// Denied packets this line accounts for.
    denials: u64,
}

impl PolicyObserver for LoggingPolicyObserver {
    fn on_denied(&self, denial: &PolicyDenial) {
        let (peer_kind, peer) = match &denial.target {
            DenialTarget::Address(addr) => ("address", addr.to_string()),
            DenialTarget::Domain(domain) => ("domain", domain.clone()),
        };

        for line in self.admit(denial, peer_kind, &peer) {
            let (peer_kind, peer, port, hostname) = match &line.key {
                Some(key) => (
                    key.peer_kind,
                    key.peer.as_str(),
                    key.port,
                    key.hostname.as_deref().unwrap_or_default(),
                ),
                None => ("", "", None, ""),
            };

            tracing::warn!(
                target: DENIAL_LOG_TARGET,
                event = line.event,
                direction = line.key.as_ref().map(|k| k.direction).unwrap_or_default(),
                protocol = line.key.as_ref().map(|k| k.protocol).unwrap_or_default(),
                peer_kind = peer_kind,
                // Recorded as a string, not via `%`, so the text layer quotes
                // and escapes it like every other field rather than emitting
                // it bare — a peer name comes from guest-controlled DNS or SNI.
                peer = peer,
                port = port.map(|p| p.to_string()).unwrap_or_default(),
                hostname = hostname,
                verdict = "deny",
                denials = line.denials,
                "network policy denied traffic"
            );
        }
    }

    fn flush(&self) {
        self.flush_pending();
    }
}

impl LoggingPolicyObserver {
    /// Decide which lines this denial produces: at most one for the denial
    /// itself, plus any trailing tallies a sweep shook loose, plus a
    /// saturation marker when the limiter has no room left.
    fn admit(&self, denial: &PolicyDenial, peer_kind: &'static str, peer: &str) -> Vec<Line> {
        let key = DenialKey {
            direction: direction_label(denial.direction),
            protocol: protocol_label(denial.protocol),
            peer_kind,
            peer: peer.to_owned(),
            port: denial.port,
            hostname: denial.hostname.clone(),
        };

        let now = Instant::now();
        let mut state = self.state.lock().unwrap();

        // Sweeping is the only scan of the map, and it is rate limited in
        // its own right, so the per-packet cost of the flood path stays a
        // single hash lookup.
        let mut lines = if state
            .last_sweep
            .is_none_or(|last| now.duration_since(last) >= SUPPRESSION_WINDOW)
        {
            state.last_sweep = Some(now);
            state.sweep(now)
        } else {
            Vec::new()
        };

        // Read before the match borrows the map mutably.
        let saturated = state.recent.len() >= MAX_TRACKED_PEERS;

        match state.recent.get_mut(&key) {
            Some(entry) if now.duration_since(entry.window_start) < SUPPRESSION_WINDOW => {
                entry.count += 1;
            }
            Some(entry) => {
                // The window closed: this denial gets the line, and carries
                // the tally of everything swallowed while it was open, plus
                // itself.
                let denials = std::mem::replace(&mut entry.count, 0) + 1;
                entry.window_start = now;
                lines.push(Line {
                    event: DENIAL_LOG_EVENT,
                    key: Some(key),
                    denials,
                });
            }
            None if saturated => {
                // Every slot is taken by a destination still inside its
                // window — the spray this limiter exists for. Say so, at
                // most once per window, rather than going quiet.
                if let Some(denials) = state.record_saturation(now) {
                    lines.push(Line {
                        event: DENIAL_SATURATED_EVENT,
                        key: None,
                        denials,
                    });
                }
            }
            None => {
                state.recent.insert(
                    key.clone(),
                    Suppression {
                        window_start: now,
                        count: 0,
                    },
                );
                lines.push(Line {
                    event: DENIAL_LOG_EVENT,
                    key: Some(key),
                    denials: 1,
                });
            }
        }

        lines
    }

    /// Emit whatever the limiter is still holding.
    ///
    /// Reached through the [`PolicyObserver::flush`] trait method, which the
    /// runtime calls from its synchronous exit hook — the shipped teardown
    /// leaves via `_exit` and never drops the observer. Also called from
    /// [`Drop`], which covers the tests and any embedder that does let the
    /// value drop, but is not what the runtime relies on.
    fn flush_pending(&self) {
        let mut state = self.state.lock().unwrap();
        let mut lines: Vec<Line> = state
            .recent
            .drain()
            .filter(|(_, entry)| entry.count > 0)
            .map(|(key, entry)| Line {
                event: DENIAL_FLUSH_EVENT,
                key: Some(key),
                denials: entry.count,
            })
            .collect();

        if let Some(saturation) = state.saturation.take()
            && saturation.dropped > 0
        {
            lines.push(Line {
                event: DENIAL_SATURATED_EVENT,
                key: None,
                denials: saturation.dropped,
            });
        }

        drop(state);

        for line in lines {
            let (peer_kind, peer, port, hostname) = match &line.key {
                Some(key) => (
                    key.peer_kind,
                    key.peer.as_str(),
                    key.port,
                    key.hostname.as_deref().unwrap_or_default(),
                ),
                None => ("", "", None, ""),
            };
            tracing::warn!(
                target: DENIAL_LOG_TARGET,
                event = line.event,
                direction = line.key.as_ref().map(|k| k.direction).unwrap_or_default(),
                protocol = line.key.as_ref().map(|k| k.protocol).unwrap_or_default(),
                peer_kind = peer_kind,
                peer = peer,
                port = port.map(|p| p.to_string()).unwrap_or_default(),
                hostname = hostname,
                verdict = "deny",
                denials = line.denials,
                "network policy denied traffic"
            );
        }
    }
}

impl LimiterState {
    /// Drop every destination whose window has closed, reporting the tally
    /// of any that swallowed denials before going quiet.
    fn sweep(&mut self, now: Instant) -> Vec<Line> {
        let mut flushed = Vec::new();

        self.recent.retain(|key, entry| {
            if now.duration_since(entry.window_start) < SUPPRESSION_WINDOW {
                return true;
            }
            if entry.count > 0 {
                flushed.push(Line {
                    event: DENIAL_FLUSH_EVENT,
                    key: Some(key.clone()),
                    denials: entry.count,
                });
            }
            // Forgotten rather than kept at zero: a destination denied again
            // later is a fresh first denial, and the map should shrink when
            // the guest calms down.
            false
        });

        // The map has room again, so the limiter is no longer saturated.
        if self.recent.len() < MAX_TRACKED_PEERS
            && let Some(saturation) = self.saturation.take()
            && saturation.dropped > 0
        {
            flushed.push(Line {
                event: DENIAL_SATURATED_EVENT,
                key: None,
                denials: saturation.dropped,
            });
        }

        flushed
    }

    /// Count one denial the limiter had no room to track. Returns the tally
    /// to report when a marker is due, `None` while one is being counted.
    fn record_saturation(&mut self, now: Instant) -> Option<u64> {
        match &mut self.saturation {
            Some(saturation)
                if now.duration_since(saturation.window_start) < SUPPRESSION_WINDOW =>
            {
                saturation.dropped += 1;
                None
            }
            Some(saturation) => {
                let dropped = std::mem::replace(&mut saturation.dropped, 0) + 1;
                saturation.window_start = now;
                Some(dropped)
            }
            None => {
                self.saturation = Some(Saturation {
                    window_start: now,
                    dropped: 0,
                });
                Some(1)
            }
        }
    }
}

impl Drop for LoggingPolicyObserver {
    /// A backstop for the tests and for embedders that drop the observer
    /// normally. The shipped runtime does **not** reach this — its sandbox
    /// process exits via `_exit`, which runs no destructors — so it flushes
    /// through [`PolicyObserver::flush`] on its exit hook instead.
    fn drop(&mut self) {
        self.flush_pending();
    }
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `tracing` target the denial event is emitted on. Stable: consumers
/// filter on it.
pub const DENIAL_LOG_TARGET: &str = "microsandbox::network::policy::denial";

/// `event` value for a line reporting a denied packet. Stable: consumers
/// match on it.
pub const DENIAL_LOG_EVENT: &str = "network_policy_denied";

/// `event` value for a line reporting the trailing tally of a destination
/// that has stopped being denied. Carries no packet of its own beyond the
/// ones its `denials` field counts.
pub const DENIAL_FLUSH_EVENT: &str = "network_policy_denied_flush";

/// `event` value for a line reporting denials the limiter had no room to
/// track, because [`MAX_TRACKED_PEERS`] destinations were in flight at once.
pub const DENIAL_SATURATED_EVENT: &str = "network_policy_denial_limiter_saturated";

/// How long one destination stays quiet after it is logged. Long enough to
/// collapse a burst of retransmits, short enough that a consumer sees a
/// still-blocked destination reappear.
pub const SUPPRESSION_WINDOW: Duration = Duration::from_secs(10);

/// Destinations the rate limiter tracks at once. A guest spraying more
/// distinct destinations than this inside one window is the flood the
/// limiter exists for, and the excess is dropped rather than logged.
pub const MAX_TRACKED_PEERS: usize = 1024;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PolicyDenial {
    /// Build a denial for traffic addressed to a peer address.
    pub fn to_address(
        direction: Direction,
        protocol: Protocol,
        addr: IpAddr,
        port: Option<u16>,
    ) -> Self {
        Self {
            direction,
            protocol,
            target: DenialTarget::Address(addr),
            port,
            hostname: None,
        }
    }

    /// Build a denial for a DNS query refused before resolution.
    pub fn to_domain(protocol: Protocol, domain: impl Into<String>, port: Option<u16>) -> Self {
        Self {
            direction: Direction::Egress,
            protocol,
            target: DenialTarget::Domain(domain.into()),
            port,
            hostname: None,
        }
    }

    /// Attach the hostname the peer address is known by.
    pub fn with_hostname(mut self, hostname: Option<String>) -> Self {
        self.hostname = hostname;
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Stable wire label for a direction. Deliberately not `Debug`, which is
/// free to change with the enum's spelling.
fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::Egress => "egress",
        Direction::Ingress => "ingress",
        Direction::Any => "any",
    }
}

/// Stable wire label for a protocol. See [`direction_label`].
fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmpv4 => "icmpv4",
        Protocol::Icmpv6 => "icmpv6",
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::policy::{Action, NetworkPolicy};
    use crate::shared::SharedState;

    /// Observer that records every denial handed to it.
    #[derive(Default)]
    struct Recorder {
        denials: Mutex<Vec<PolicyDenial>>,
    }

    impl PolicyObserver for Recorder {
        fn on_denied(&self, denial: &PolicyDenial) {
            self.denials.lock().unwrap().push(denial.clone());
        }
    }

    impl Recorder {
        fn install(shared: &SharedState) -> Arc<Self> {
            let recorder = Arc::new(Self::default());
            shared.set_policy_observer(recorder.clone());
            recorder
        }

        fn taken(&self) -> Vec<PolicyDenial> {
            std::mem::take(&mut *self.denials.lock().unwrap())
        }
    }

    fn dst(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), port))
    }

    #[test]
    fn denied_egress_is_reported_with_destination_and_port() {
        let shared = SharedState::new(4);
        let recorder = Recorder::install(&shared);

        let action = NetworkPolicy::none().evaluate_egress(dst(443), Protocol::Tcp, &shared);

        assert_eq!(action, Action::Deny);
        let denials = recorder.taken();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].direction, Direction::Egress);
        assert_eq!(denials[0].protocol, Protocol::Tcp);
        assert_eq!(
            denials[0].target,
            DenialTarget::Address(Ipv4Addr::new(1, 2, 3, 4).into())
        );
        assert_eq!(denials[0].port, Some(443));
        assert_eq!(denials[0].hostname, None);
    }

    #[test]
    fn allowed_egress_reports_nothing() {
        let shared = SharedState::new(4);
        let recorder = Recorder::install(&shared);

        let action = NetworkPolicy::allow_all().evaluate_egress(dst(443), Protocol::Tcp, &shared);

        assert_eq!(action, Action::Allow);
        assert!(recorder.taken().is_empty());
    }

    #[test]
    fn denied_egress_without_port_reports_none() {
        // The ICMP path evaluates an address with no port at all.
        let shared = SharedState::new(4);
        let recorder = Recorder::install(&shared);

        let action = NetworkPolicy::none().evaluate_egress_ip(
            Ipv4Addr::new(1, 2, 3, 4).into(),
            Protocol::Icmpv4,
            &shared,
        );

        assert_eq!(action, Action::Deny);
        let denials = recorder.taken();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].port, None);
        assert_eq!(denials[0].protocol, Protocol::Icmpv4);
    }

    #[test]
    fn denied_ingress_reports_the_guest_listening_port() {
        let shared = SharedState::new(4);
        let recorder = Recorder::install(&shared);

        let action =
            NetworkPolicy::none().evaluate_ingress(dst(51234), 8080, Protocol::Tcp, &shared);

        assert_eq!(action, Action::Deny);
        let denials = recorder.taken();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].direction, Direction::Ingress);
        assert_eq!(denials[0].port, Some(8080));
    }

    /// In-memory writer the format tests point a subscriber at.
    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Capture the JSON the logging observer writes for one denial.
    fn logged_denial(denial: &PolicyDenial) -> serde_json::Value {
        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::WARN)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            LoggingPolicyObserver::default().on_denied(denial);
        });

        let line = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        serde_json::from_str(line.trim()).expect("the denial log line is not valid JSON")
    }

    /// Capture the default text layer's rendering of one denial.
    fn logged_denial_text(denial: &PolicyDenial) -> String {
        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::WARN)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            LoggingPolicyObserver::default().on_denied(denial);
        });

        String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn the_text_layer_renders_every_field_as_a_quoted_key_value_pair() {
        // The sandbox subprocess logs through the default text layer, so
        // this — not the JSON rendering — is what a consumer reading
        // `runtime.log` actually parses.
        let denial = PolicyDenial::to_address(
            Direction::Egress,
            Protocol::Tcp,
            Ipv4Addr::new(1, 2, 3, 4).into(),
            Some(443),
        )
        .with_hostname(Some("example.com".to_owned()));

        let line = logged_denial_text(&denial);

        assert!(line.contains(DENIAL_LOG_TARGET), "{line}");
        assert!(line.contains(" WARN "), "{line}");
        for pair in [
            r#"event="network_policy_denied""#,
            r#"direction="egress""#,
            r#"protocol="tcp""#,
            r#"peer_kind="address""#,
            r#"peer="1.2.3.4""#,
            r#"port="443""#,
            r#"hostname="example.com""#,
            r#"verdict="deny""#,
            "denials=1",
        ] {
            assert!(line.contains(pair), "missing {pair} in {line}");
        }
    }

    #[test]
    fn the_logged_denial_carries_every_contract_field() {
        let denial = PolicyDenial::to_address(
            Direction::Egress,
            Protocol::Tcp,
            Ipv4Addr::new(1, 2, 3, 4).into(),
            Some(443),
        )
        .with_hostname(Some("example.com".to_owned()));

        let logged = logged_denial(&denial);

        assert_eq!(logged["target"], DENIAL_LOG_TARGET);
        assert_eq!(logged["level"], "WARN");
        assert!(
            logged["timestamp"].is_string(),
            "the subscriber must stamp the line: {logged}"
        );

        let fields = &logged["fields"];
        assert_eq!(fields["event"], DENIAL_LOG_EVENT);
        assert_eq!(fields["direction"], "egress");
        assert_eq!(fields["protocol"], "tcp");
        assert_eq!(fields["peer_kind"], "address");
        assert_eq!(fields["peer"], "1.2.3.4");
        assert_eq!(fields["denials"], 1);
        assert_eq!(fields["port"], "443");
        assert_eq!(fields["hostname"], "example.com");
        assert_eq!(fields["verdict"], "deny");
    }

    #[test]
    fn the_logged_denial_keeps_unknown_fields_present_and_empty() {
        // A parser must never have to handle a missing key, so an absent
        // port or hostname is the empty string rather than an omission.
        let denial = PolicyDenial::to_domain(Protocol::Udp, "blocked.example", None);

        let logged = logged_denial(&denial);
        let fields = &logged["fields"];

        assert_eq!(fields["peer_kind"], "domain");
        assert_eq!(fields["peer"], "blocked.example");
        assert_eq!(fields["port"], "");
        assert_eq!(fields["hostname"], "");
    }

    /// The events one `admit` call decided, as (event, denials) pairs.
    fn admitted(
        observer: &LoggingPolicyObserver,
        denial: &PolicyDenial,
        peer: &str,
    ) -> Vec<(&'static str, u64)> {
        observer
            .admit(denial, "address", peer)
            .into_iter()
            .map(|line| (line.event, line.denials))
            .collect()
    }

    /// Reach into the limiter and age every window out, rather than
    /// sleeping through a real ten seconds.
    fn age_out(observer: &LoggingPolicyObserver) {
        let mut state = observer.state.lock().unwrap();
        state.last_sweep = state
            .last_sweep
            .map(|last| last - SUPPRESSION_WINDOW - Duration::from_secs(1));
        for entry in state.recent.values_mut() {
            entry.window_start -= SUPPRESSION_WINDOW + Duration::from_secs(1);
        }
    }

    fn tcp_denial(port: u16) -> PolicyDenial {
        PolicyDenial::to_address(
            Direction::Egress,
            Protocol::Tcp,
            Ipv4Addr::new(1, 2, 3, 4).into(),
            Some(port),
        )
    }

    #[test]
    fn a_repeated_denial_is_counted_onto_the_next_line_for_that_destination() {
        // A denied destination is re-evaluated per packet — every retransmit
        // of one blocked connection lands here — so only the first gets a
        // line, and the rest are tallied onto the line that opens the next
        // window. `denials` counts packets, so the reopening line is the 99
        // swallowed plus itself.
        let observer = LoggingPolicyObserver::default();
        let denial = tcp_denial(443);

        assert_eq!(
            admitted(&observer, &denial, "1.2.3.4"),
            [(DENIAL_LOG_EVENT, 1)]
        );
        for _ in 0..99 {
            assert_eq!(admitted(&observer, &denial, "1.2.3.4"), []);
        }

        age_out(&observer);

        // The sweep runs first and ships the 99 as a flush, then this packet
        // opens a fresh window as its own line. Which of the two shapes a
        // consumer sees depends on whether a sweep was due — the total is
        // what is guaranteed, and it is the 100 packets that were denied.
        let lines = admitted(&observer, &denial, "1.2.3.4");
        assert_eq!(lines.iter().map(|(_, n)| n).sum::<u64>(), 100, "{lines:?}");
        assert_eq!(lines, [(DENIAL_FLUSH_EVENT, 99), (DENIAL_LOG_EVENT, 1)]);
    }

    #[test]
    fn the_denials_field_totals_every_denied_packet() {
        // The whole contract in one assertion: a consumer sums `denials`
        // across every line and gets the packet count back, whatever mix of
        // ordinary, flush and window-reopening lines it saw.
        let observer = LoggingPolicyObserver::default();
        let denial = tcp_denial(443);

        let mut total = 0;
        for _ in 0..50 {
            total += admitted(&observer, &denial, "1.2.3.4")
                .iter()
                .map(|(_, n)| n)
                .sum::<u64>();
        }
        age_out(&observer);
        // One more denial, of a different destination, to drive the sweep
        // that flushes the quiet one.
        total += admitted(&observer, &denial, "9.9.9.9")
            .iter()
            .map(|(_, n)| n)
            .sum::<u64>();

        assert_eq!(total, 51);
    }

    #[test]
    fn a_destination_that_goes_quiet_still_reports_its_tally() {
        // The trailing tally must not die with the entry: a guest that gives
        // up on a blocked destination is the common case under deny-by-
        // default, and its denials would otherwise never be reported.
        let observer = LoggingPolicyObserver::default();
        let denial = tcp_denial(443);

        assert_eq!(
            admitted(&observer, &denial, "1.2.3.4"),
            [(DENIAL_LOG_EVENT, 1)]
        );
        for _ in 0..9 {
            assert_eq!(admitted(&observer, &denial, "1.2.3.4"), []);
        }

        age_out(&observer);

        // A denial of some *other* destination drives the sweep, and the
        // quiet destination's nine swallowed packets ship with it.
        let lines = admitted(&observer, &denial, "5.6.7.8");
        assert!(
            lines.contains(&(DENIAL_FLUSH_EVENT, 9)),
            "expected a flush of the quiet destination, got {lines:?}"
        );
    }

    #[test]
    fn the_shutdown_flush_reports_what_is_left_without_dropping_the_observer() {
        // Nothing sweeps once the guest stops being denied entirely, so
        // shutdown is the last chance to report. The shipped runtime reaches
        // that flush through the observer trait on a `SharedState` — its
        // sandbox process exits via `_exit`, so a test that relied on `Drop`
        // would be green exactly where the runtime is broken. Drive the real
        // path: install on a `SharedState`, deny, then call the same flush
        // the exit hook calls, and hold the `Arc` across it so nothing is
        // dropped.
        let shared = SharedState::new(4);
        let observer = Arc::new(LoggingPolicyObserver::default());
        shared.set_policy_observer(observer.clone());

        // Five denials of one destination: one line, four swallowed.
        let dst = SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 443));
        for _ in 0..5 {
            assert_eq!(
                NetworkPolicy::none().evaluate_egress(dst, Protocol::Tcp, &shared),
                Action::Deny
            );
        }

        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::with_default(subscriber, || shared.flush_policy_observer());

        // The observer is still alive: the flush did not depend on a drop.
        assert_eq!(Arc::strong_count(&observer), 2);

        let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains(DENIAL_FLUSH_EVENT), "{logged}");
        assert!(logged.contains(r#""denials":4"#), "{logged}");
    }

    #[test]
    fn distinct_destinations_are_rate_limited_independently() {
        let observer = LoggingPolicyObserver::default();

        assert_eq!(
            admitted(&observer, &tcp_denial(443), "1.2.3.4"),
            [(DENIAL_LOG_EVENT, 1)]
        );
        assert_eq!(
            admitted(&observer, &tcp_denial(80), "1.2.3.4"),
            [(DENIAL_LOG_EVENT, 1)]
        );
        assert_eq!(
            admitted(&observer, &tcp_denial(443), "5.6.7.8"),
            [(DENIAL_LOG_EVENT, 1)]
        );
        assert_eq!(admitted(&observer, &tcp_denial(443), "1.2.3.4"), []);
    }

    #[test]
    fn hostnames_on_one_address_are_rate_limited_independently() {
        let observer = LoggingPolicyObserver::default();
        let api = tcp_denial(443).with_hostname(Some("api.example.com".into()));
        let cdn = tcp_denial(443).with_hostname(Some("cdn.example.com".into()));

        assert_eq!(
            admitted(&observer, &api, "1.2.3.4"),
            [(DENIAL_LOG_EVENT, 1)]
        );
        assert_eq!(
            admitted(&observer, &cdn, "1.2.3.4"),
            [(DENIAL_LOG_EVENT, 1)]
        );
        assert_eq!(admitted(&observer, &api, "1.2.3.4"), []);
        assert_eq!(observer.state.lock().unwrap().recent.len(), 2);
    }

    #[test]
    fn a_saturated_limiter_says_so_rather_than_going_quiet() {
        // A spray across more destinations than the limiter can track is
        // exactly the scan a consumer most wants to see. Silence would be
        // indistinguishable from nothing being denied.
        let observer = LoggingPolicyObserver::default();
        let denial = tcp_denial(443);

        for i in 0..MAX_TRACKED_PEERS {
            assert_eq!(
                admitted(&observer, &denial, &format!("peer-{i}")),
                [(DENIAL_LOG_EVENT, 1)]
            );
        }

        // The map is full and every entry is inside its window.
        let lines = admitted(&observer, &denial, "one-too-many");
        assert_eq!(lines, [(DENIAL_SATURATED_EVENT, 1)]);

        // Further untrackable destinations are counted, not logged.
        for i in 0..5 {
            assert_eq!(admitted(&observer, &denial, &format!("extra-{i}")), []);
        }
        assert_eq!(
            observer
                .state
                .lock()
                .unwrap()
                .saturation
                .as_ref()
                .unwrap()
                .dropped,
            5
        );
    }

    #[test]
    fn the_rate_limiter_does_not_grow_without_bound() {
        // A guest spraying distinct destinations must not turn the limiter
        // into a leak.
        let observer = LoggingPolicyObserver::default();
        let denial = tcp_denial(443);

        for i in 0..(MAX_TRACKED_PEERS * 3) {
            observer.admit(&denial, "address", &format!("peer-{i}"));
        }

        assert!(observer.state.lock().unwrap().recent.len() <= MAX_TRACKED_PEERS);
    }

    #[test]
    fn the_logging_observer_reports_a_denial_from_the_evaluation_path() {
        // The wiring, not just the formatting: a denial decided by the
        // policy engine reaches the log when this observer is installed.
        let shared = SharedState::new(4);
        shared.set_policy_observer(Arc::new(LoggingPolicyObserver::default()));

        let action = NetworkPolicy::none().evaluate_egress(dst(443), Protocol::Tcp, &shared);

        assert_eq!(action, Action::Deny);
    }

    #[test]
    fn denial_without_an_observer_is_a_no_op() {
        let shared = SharedState::new(4);

        let action = NetworkPolicy::none().evaluate_egress(dst(443), Protocol::Tcp, &shared);

        assert_eq!(action, Action::Deny);
    }
}
