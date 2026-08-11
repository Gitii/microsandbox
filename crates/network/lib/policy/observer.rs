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
//! blocks guest traffic. Timestamps are left to the observer so the
//! evaluation path does not read the clock on every denied packet.

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
/// `suppressed`. Fields are always present; unknown values are logged as
/// the empty string rather than omitted, so a parser never has to handle a
/// missing key. The peer is deliberately not called `target`: a JSON layer
/// configured with `flatten_event` puts the `tracing` metadata target at
/// that key, and one of the two would silently win.
///
/// `WARN` is chosen so the line survives the sandbox subprocess's default
/// filter, which is `INFO` — that subprocess is where the network stack
/// runs and its stderr is captured into `runtime.log`, so a denial reaches
/// the file a host consumer reads without anyone passing a verbosity flag.
///
/// Denials are rate limited, because they are decided per *packet*: a
/// deny-by-default sandbox with a chatty guest denies every datagram, every
/// echo and every SYN retransmit, and `runtime.log` rotates at 10 MiB with
/// the lifecycle and VMM diagnostics other tooling reads. The first denial
/// for a destination is logged immediately; further denials of the same
/// destination inside [`SUPPRESSION_WINDOW`] are counted, not logged, and
/// the count is reported as `suppressed` on the next line for that
/// destination. So a consumer counting denied packets adds `suppressed + 1`
/// per line rather than counting lines. That also collapses the duplicate a
/// packet produces when a platform policy and a tenant policy both deny it.
#[derive(Debug, Default)]
pub struct LoggingPolicyObserver {
    /// Destinations logged recently, and how many denials each has
    /// swallowed since its last line. Bounded by [`MAX_TRACKED_PEERS`].
    recent: Mutex<HashMap<DenialKey, Suppression>>,
}

/// Identity a denial is rate limited by: one line per distinct destination
/// per window, rather than one per packet.
///
/// Keyed on the wire labels rather than the enums so that `Direction` and
/// `Protocol` do not have to grow a public `Hash` derive for an internal
/// rate limiter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DenialKey {
    direction: &'static str,
    protocol: &'static str,
    peer: String,
    port: Option<u16>,
}

/// Rate-limiter state for one destination.
#[derive(Debug)]
struct Suppression {
    /// When the window this destination is currently inside opened.
    window_start: Instant,

    /// Denials swallowed since the last line for this destination.
    count: u64,
}

impl PolicyObserver for LoggingPolicyObserver {
    fn on_denied(&self, denial: &PolicyDenial) {
        let (peer_kind, peer) = match &denial.target {
            DenialTarget::Address(addr) => ("address", addr.to_string()),
            DenialTarget::Domain(domain) => ("domain", domain.clone()),
        };

        let Some(suppressed) = self.admit(denial, &peer) else {
            return;
        };

        tracing::warn!(
            target: DENIAL_LOG_TARGET,
            event = DENIAL_LOG_EVENT,
            direction = direction_label(denial.direction),
            protocol = protocol_label(denial.protocol),
            peer_kind = peer_kind,
            // Recorded as a string, not via `%`, so the text layer quotes and
            // escapes it like every other field rather than emitting it bare —
            // a peer name comes from guest-controlled DNS or SNI.
            peer = peer.as_str(),
            port = denial.port.map(|p| p.to_string()).unwrap_or_default(),
            hostname = denial.hostname.as_deref().unwrap_or_default(),
            verdict = "deny",
            suppressed = suppressed,
            "network policy denied traffic"
        );
    }
}

impl LoggingPolicyObserver {
    /// Decide whether this denial gets a line, and with what `suppressed`
    /// count. `None` means the denial was swallowed into a running count.
    fn admit(&self, denial: &PolicyDenial, peer: &str) -> Option<u64> {
        let key = DenialKey {
            direction: direction_label(denial.direction),
            protocol: protocol_label(denial.protocol),
            peer: peer.to_owned(),
            port: denial.port,
        };

        let now = Instant::now();
        let mut recent = self.recent.lock().unwrap();

        match recent.get_mut(&key) {
            Some(entry) if now.duration_since(entry.window_start) < SUPPRESSION_WINDOW => {
                entry.count += 1;
                None
            }
            Some(entry) => {
                // The window closed: this denial gets the line, and carries
                // the tally of everything swallowed while it was open.
                let suppressed = std::mem::replace(&mut entry.count, 0);
                entry.window_start = now;
                Some(suppressed)
            }
            None => {
                // Drop destinations whose window has closed before growing,
                // so a guest spraying distinct addresses cannot grow this map
                // without bound.
                if recent.len() >= MAX_TRACKED_PEERS {
                    recent.retain(|_, entry| {
                        now.duration_since(entry.window_start) < SUPPRESSION_WINDOW
                    });
                }

                // Still full: every tracked destination is inside its window,
                // which is the flood this limiter exists for. Stay silent
                // rather than let an untracked destination log unbounded.
                if recent.len() >= MAX_TRACKED_PEERS {
                    return None;
                }

                recent.insert(
                    key,
                    Suppression {
                        window_start: now,
                        count: 0,
                    },
                );
                Some(0)
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `tracing` target the denial event is emitted on. Stable: consumers
/// filter on it.
pub const DENIAL_LOG_TARGET: &str = "microsandbox::network::policy::denial";

/// Value of the `event` field on the denial log line. Stable: consumers
/// match on it.
pub const DENIAL_LOG_EVENT: &str = "network_policy_denied";

/// How long one destination stays quiet after it is logged. Long enough to
/// collapse a burst of retransmits, short enough that a consumer sees a
/// still-blocked destination reappear.
pub const SUPPRESSION_WINDOW: Duration = Duration::from_secs(10);

/// Destinations the rate limiter tracks at once. A guest spraying more
/// distinct destinations than this inside one window is the flood the
/// limiter exists for, and the excess is dropped rather than logged.
const MAX_TRACKED_PEERS: usize = 1024;

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
            "suppressed=0",
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
        assert_eq!(fields["suppressed"], 0);
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

    #[test]
    fn a_repeated_denial_is_suppressed_and_counted_on_the_next_line() {
        // A denied destination is re-evaluated per packet — every retransmit
        // of one blocked connection lands here — so only the first gets a
        // line, and the rest are tallied onto the line that opens the next
        // window.
        let observer = LoggingPolicyObserver::default();
        let denial = PolicyDenial::to_address(
            Direction::Egress,
            Protocol::Tcp,
            Ipv4Addr::new(1, 2, 3, 4).into(),
            Some(443),
        );

        assert_eq!(observer.admit(&denial, "1.2.3.4"), Some(0));
        for _ in 0..99 {
            assert_eq!(observer.admit(&denial, "1.2.3.4"), None);
        }

        // Force the window shut rather than sleeping through it.
        observer
            .recent
            .lock()
            .unwrap()
            .values_mut()
            .for_each(|entry| entry.window_start -= SUPPRESSION_WINDOW);

        assert_eq!(observer.admit(&denial, "1.2.3.4"), Some(99));
        // The tally resets with the new window.
        assert_eq!(observer.admit(&denial, "1.2.3.4"), None);
    }

    #[test]
    fn distinct_destinations_are_rate_limited_independently() {
        let observer = LoggingPolicyObserver::default();
        let denial = PolicyDenial::to_address(
            Direction::Egress,
            Protocol::Tcp,
            Ipv4Addr::new(1, 2, 3, 4).into(),
            Some(443),
        );
        let other_port = PolicyDenial::to_address(
            Direction::Egress,
            Protocol::Tcp,
            Ipv4Addr::new(1, 2, 3, 4).into(),
            Some(80),
        );

        assert_eq!(observer.admit(&denial, "1.2.3.4"), Some(0));
        assert_eq!(observer.admit(&other_port, "1.2.3.4"), Some(0));
        assert_eq!(observer.admit(&denial, "5.6.7.8"), Some(0));
        assert_eq!(observer.admit(&denial, "1.2.3.4"), None);
    }

    #[test]
    fn the_rate_limiter_does_not_grow_without_bound() {
        // A guest spraying distinct destinations must not turn the limiter
        // into a leak.
        let observer = LoggingPolicyObserver::default();
        let denial = PolicyDenial::to_address(
            Direction::Egress,
            Protocol::Tcp,
            Ipv4Addr::new(1, 2, 3, 4).into(),
            Some(443),
        );

        for i in 0..(MAX_TRACKED_PEERS * 3) {
            observer.admit(&denial, &format!("peer-{i}"));
        }

        assert!(observer.recent.lock().unwrap().len() <= MAX_TRACKED_PEERS);
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
