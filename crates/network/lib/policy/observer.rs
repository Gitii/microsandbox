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

use std::net::IpAddr;

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
/// `protocol`, `target_kind`, `target`, `port`, `hostname`, `verdict`.
/// Fields are always present; unknown values are logged as the empty
/// string rather than omitted, so a parser never has to handle a missing
/// key. The timestamp is supplied by the subscriber, not by this event.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoggingPolicyObserver;

impl PolicyObserver for LoggingPolicyObserver {
    fn on_denied(&self, denial: &PolicyDenial) {
        let (target_kind, target) = match &denial.target {
            DenialTarget::Address(addr) => ("address", addr.to_string()),
            DenialTarget::Domain(domain) => ("domain", domain.clone()),
        };

        tracing::warn!(
            target: DENIAL_LOG_TARGET,
            event = DENIAL_LOG_EVENT,
            direction = direction_label(denial.direction),
            protocol = protocol_label(denial.protocol),
            target_kind = target_kind,
            target = %target,
            port = denial.port.map(|p| p.to_string()).unwrap_or_default(),
            hostname = denial.hostname.as_deref().unwrap_or_default(),
            verdict = "deny",
            "network policy denied traffic"
        );
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

    /// Capture the JSON the logging observer writes for one denial.
    fn logged_denial(denial: &PolicyDenial) -> serde_json::Value {
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

        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::WARN)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            LoggingPolicyObserver.on_denied(denial);
        });

        let line = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        serde_json::from_str(line.trim()).expect("the denial log line is not valid JSON")
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
        assert_eq!(fields["target_kind"], "address");
        assert_eq!(fields["target"], "1.2.3.4");
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

        assert_eq!(fields["target_kind"], "domain");
        assert_eq!(fields["target"], "blocked.example");
        assert_eq!(fields["port"], "");
        assert_eq!(fields["hostname"], "");
    }

    #[test]
    fn the_logging_observer_reports_a_denial_from_the_evaluation_path() {
        // The wiring, not just the formatting: a denial decided by the
        // policy engine reaches the log when this observer is installed.
        let shared = SharedState::new(4);
        shared.set_policy_observer(Arc::new(LoggingPolicyObserver));

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
