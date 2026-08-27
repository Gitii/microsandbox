//! Detection of credential-shaped responses no grant is watching.
//!
//! An OAuth grant protects the endpoints its configuration names. That makes
//! the configuration the whole of the protection: a catalogue that names the
//! wrong host, or that was written before a provider moved its token endpoint,
//! switches the protection off without failing anything. Nothing breaks, no
//! request is refused, and the credential simply arrives in the sandbox.
//!
//! This module is the smoke alarm for that. On a TLS connection that no grant
//! is relevant to — the pass-through branch of the intercepting proxy, where
//! the bytes are forwarded exactly as they arrive — a 2xx JSON response whose
//! top-level object carries a key named like a credential is reported as a
//! `tracing` event. Nothing is blocked, nothing is rewritten, and the value is
//! never logged: the finding is that an endpoint *looks like* it hands out
//! credentials and no grant covers it, which is a question for whoever wrote
//! the catalogue.
//!
//! # The event
//!
//! One `WARN` event on the [`DETECTOR_LOG_TARGET`] target, carrying
//! `event`, `sni`, `port`, `path`, `fields` and `status`. As with the policy
//! denial observer, the field set is a contract: every field is always
//! present, an unknown one is the empty string rather than an omitted key, and
//! none of them is called `target`, which is where a `tracing` JSON layer
//! configured with `flatten_event` puts the event's own target.
//!
//! `WARN` is chosen for the same reason denials are. The network stack runs in
//! the sandbox subprocess, whose stderr is captured into the runtime log a
//! host-side consumer reads, and whose default filter is `off` with one
//! `=warn` directive per target that has to survive it — this one among them,
//! in `crates/cli/lib/log_args.rs`. A finding nobody asked for a verbosity
//! flag to see is the whole point of the module.
//!
//! Repeats are suppressed per `(sni, path)` for [`SUPPRESSION_WINDOW`], so a
//! polling client produces a line rather than a stream of them. Suppression is
//! the only thing that ever silences the detector: when it is tracking
//! [`MAX_TRACKED_ENDPOINTS`] endpoints at once it logs anyway rather than
//! going quiet.
//!
//! # What it does not see
//!
//! The detector follows framed HTTP/1.1: a body it cannot find the end of (no
//! `Content-Length`, no `chunked`), a body larger than [`MAX_BODY_BYTES`], a
//! compressed body, and anything that is not JSON are all skipped rather than
//! parsed, and a stream it can no longer follow is dropped for the rest of the
//! connection. A missed body is a missed warning, never a wrong one.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::config::OAuthSecret;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `tracing` target every detector event carries.
pub const DETECTOR_LOG_TARGET: &str = "microsandbox::network::secrets::detector";

/// `event` field of a credential-shaped response line.
pub const CREDENTIAL_SHAPED_RESPONSE_EVENT: &str = "credential_shaped_response";

/// How long one `(sni, path)` stays suppressed after it is reported.
pub const SUPPRESSION_WINDOW: Duration = Duration::from_secs(10);

/// Largest response body parsed. A larger one is skipped, not parsed.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// How many `(sni, path)` pairs the suppression map holds at once.
pub const MAX_TRACKED_ENDPOINTS: usize = 256;

/// Field names that look like a credential wherever they appear.
const DEFAULT_CREDENTIAL_FIELDS: [&str; 5] = [
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "raw_key",
];

/// Largest header block followed. Past it the stream is dropped: a header
/// block this size is not one this detector can say anything useful about.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Longest request path kept, and so reported. A path is guest-controlled
/// and unbounded; past this it is truncated, which bounds both the log line
/// and the memory the pending queue holds.
const MAX_LOGGED_PATH_BYTES: usize = 256;

/// How many requests may be outstanding before the detector stops pairing
/// responses with paths. A pipelining client past this loses the path, not
/// the warning.
const MAX_PENDING_REQUESTS: usize = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-connection detector for credential-shaped responses.
///
/// Inactive — every method a no-op — on a connection some grant is relevant
/// to, because there the response is already being sanitized and a warning
/// about it would be noise.
pub(crate) struct CredentialDetector {
    active: bool,
    sni: String,
    port: u16,
    /// Field names that make a response credential-shaped: the defaults plus
    /// every field any grant of this sandbox names. Sorted and deduplicated.
    fields: Vec<String>,
    /// Requests whose responses have not arrived, oldest first.
    pending: VecDeque<PendingRequest>,
    request: Scan,
    response: Scan,
    /// The response body currently being collected.
    body: Option<CollectedBody>,
}

/// A request the detector is waiting on the response to.
struct PendingRequest {
    path: String,
    /// Whether it was a `HEAD`, whose response carries no body.
    head: bool,
}

/// Where the detector is in one direction of the connection.
enum Scan {
    /// Accumulating a header block.
    Head { buffer: Vec<u8> },
    /// Inside a fixed-length body.
    Body { remaining: usize },
    /// Reading a chunk size line.
    ChunkSize { buffer: Vec<u8> },
    /// Inside one chunk's data.
    ChunkData { remaining: usize },
    /// Reading the CRLF that closes one chunk.
    ChunkEnd { buffer: Vec<u8> },
    /// Reading the trailer block after the last chunk.
    ChunkTrailers { buffer: Vec<u8> },
    /// The stream is no longer followed.
    Stopped,
}

/// A response body being collected for inspection.
struct CollectedBody {
    path: String,
    status: u16,
    bytes: Vec<u8>,
    /// Set once the body has outgrown [`MAX_BODY_BYTES`]. The rest of it is
    /// still walked, so the connection stays followed, but nothing is parsed.
    oversize: bool,
}

/// What a response's header block says about its body.
struct ResponseHead {
    status: u16,
    /// Whether the body, if any, is worth collecting.
    inspect: bool,
    body: BodyFraming,
}

/// How a message says where its body ends.
enum BodyFraming {
    Empty,
    Length(usize),
    Chunked,
    /// Ends at EOF, so nothing marks where the next message begins.
    Unframed,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CredentialDetector {
    /// Build a detector for one intercepted connection.
    ///
    /// `active` is whether the connection is one *no* grant is relevant to,
    /// which is the only place this detector belongs. Pass `false` for a
    /// connection a grant covers — its responses are already sanitized — and
    /// every method here is a no-op.
    pub(crate) fn new(oauth: &[OAuthSecret], sni: &str, port: u16, active: bool) -> Self {
        let mut fields: Vec<String> = DEFAULT_CREDENTIAL_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect();
        for grant in oauth {
            fields.push(grant.access_token_field.clone());
            fields.push(grant.refresh_token_field.clone());
            fields.extend(grant.poll_secret_fields.iter().cloned());
            fields.extend(grant.mint_endpoints.iter().map(|mint| mint.field.clone()));
        }
        fields.retain(|field| !field.is_empty());
        fields.sort();
        fields.dedup();
        Self {
            active,
            sni: sni.to_string(),
            port,
            fields,
            pending: VecDeque::new(),
            request: Scan::head(),
            response: Scan::head(),
            body: None,
        }
    }

    /// Follow guest request bytes, remembering the path of each request so the
    /// response that answers it can be reported against it.
    pub(crate) fn observe_request(&mut self, data: &[u8]) {
        if !self.active {
            return;
        }
        let mut state = std::mem::replace(&mut self.request, Scan::Stopped);
        let mut pending = data;
        while !pending.is_empty() {
            let next = match &mut state {
                Scan::Stopped => break,
                Scan::Head { buffer } => {
                    let Some(head) = take_head(buffer, &mut pending) else {
                        if buffer.len() > MAX_HEAD_BYTES {
                            state = Scan::Stopped;
                        }
                        break;
                    };
                    match request_line(&head) {
                        Some((method, path)) => {
                            if self.pending.len() >= MAX_PENDING_REQUESTS {
                                self.pending.pop_front();
                            }
                            self.pending.push_back(PendingRequest {
                                path: truncate_path(&path),
                                head: method.eq_ignore_ascii_case("HEAD"),
                            });
                            match request_framing(&head) {
                                BodyFraming::Empty | BodyFraming::Length(0) => Scan::head(),
                                BodyFraming::Length(length) => Scan::Body { remaining: length },
                                BodyFraming::Chunked => Scan::chunk_size(),
                                // A request body that ends at EOF ends the
                                // conversation; no later request to pair.
                                BodyFraming::Unframed => Scan::Stopped,
                            }
                        }
                        None => Scan::Stopped,
                    }
                }
                scan => {
                    if !scan.advance_body(&mut pending, None) {
                        Scan::Stopped
                    } else if scan.body_done() {
                        Scan::head()
                    } else {
                        continue;
                    }
                }
            };
            state = next;
        }
        self.request = state;
    }

    /// Follow upstream response bytes, reporting any credential-shaped body.
    pub(crate) fn observe_response(&mut self, data: &[u8]) {
        if !self.active {
            return;
        }
        let mut state = std::mem::replace(&mut self.response, Scan::Stopped);
        let mut pending = data;
        let mut completed = false;
        while !pending.is_empty() {
            let next = match &mut state {
                Scan::Stopped => break,
                Scan::Head { buffer } => {
                    let Some(head) = take_head(buffer, &mut pending) else {
                        if buffer.len() > MAX_HEAD_BYTES {
                            state = Scan::Stopped;
                        }
                        break;
                    };
                    let Some(parsed) = response_head(&head) else {
                        state = Scan::Stopped;
                        break;
                    };
                    // `101` hands the connection to another protocol, so
                    // nothing after it is an HTTP message to follow.
                    if parsed.status == 101 {
                        state = Scan::Stopped;
                        break;
                    }
                    // Any other informational response is a prelude: the
                    // request it belongs to still awaits its real answer.
                    if (100..200).contains(&parsed.status) {
                        state = Scan::head();
                        continue;
                    }
                    let request = self.pending.pop_front();
                    let path = request
                        .as_ref()
                        .map(|request| request.path.clone())
                        .unwrap_or_default();
                    let head_request = request.is_some_and(|request| request.head);
                    let framing = if head_request {
                        BodyFraming::Empty
                    } else {
                        parsed.body
                    };
                    let collect = parsed.inspect
                        && !matches!(framing, BodyFraming::Empty | BodyFraming::Length(0));
                    self.body = collect.then(|| CollectedBody {
                        path,
                        status: parsed.status,
                        bytes: Vec::new(),
                        oversize: false,
                    });
                    match framing {
                        BodyFraming::Empty | BodyFraming::Length(0) => Scan::head(),
                        BodyFraming::Length(length) => Scan::Body { remaining: length },
                        BodyFraming::Chunked => Scan::chunk_size(),
                        // Nothing marks where the next response begins, so the
                        // connection cannot be followed past this one.
                        BodyFraming::Unframed => Scan::Stopped,
                    }
                }
                scan => {
                    if !scan.advance_body(&mut pending, self.body.as_mut()) {
                        Scan::Stopped
                    } else if scan.body_done() {
                        completed = true;
                        Scan::head()
                    } else {
                        continue;
                    }
                }
            };
            state = next;
            if completed {
                completed = false;
                self.report();
            }
        }
        self.response = state;
    }

    /// Report the collected body, if it turned out to be credential-shaped.
    fn report(&mut self) {
        let Some(body) = self.body.take() else {
            return;
        };
        if body.oversize {
            return;
        }
        let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(&body.bytes) else {
            return;
        };
        let found = object
            .keys()
            .filter(|key| self.fields.iter().any(|field| field == *key))
            .cloned()
            .collect::<Vec<_>>();
        if found.is_empty() || !admit(&self.sni, &body.path) {
            return;
        }
        // Only the key names are recorded. The value is the thing this event
        // exists to say has escaped; writing it to a log would be worse than
        // saying nothing.
        tracing::warn!(
            target: DETECTOR_LOG_TARGET,
            event = CREDENTIAL_SHAPED_RESPONSE_EVENT,
            sni = self.sni.as_str(),
            port = self.port.to_string(),
            path = body.path.as_str(),
            fields = found.join(","),
            status = body.status.to_string(),
            "response carries credential-shaped fields and no grant covers it"
        );
    }
}

impl Scan {
    fn head() -> Self {
        Scan::Head { buffer: Vec::new() }
    }

    fn chunk_size() -> Self {
        Scan::ChunkSize { buffer: Vec::new() }
    }

    /// Consume body bytes, collecting them into `body` when one is being
    /// inspected. Returns `false` when the stream can no longer be followed.
    fn advance_body(&mut self, pending: &mut &[u8], body: Option<&mut CollectedBody>) -> bool {
        match self {
            Scan::Body { remaining } | Scan::ChunkData { remaining } => {
                let consumed = (*remaining).min(pending.len());
                if let Some(body) = body {
                    body.collect(&pending[..consumed]);
                }
                *pending = &pending[consumed..];
                *remaining -= consumed;
                if *remaining == 0 && matches!(self, Scan::ChunkData { .. }) {
                    *self = Scan::ChunkEnd { buffer: Vec::new() };
                }
                true
            }
            Scan::ChunkSize { buffer } => {
                let Some(line) = take_line(buffer, pending) else {
                    return buffer.len() <= MAX_HEAD_BYTES;
                };
                let Some(size) = chunk_size(&line) else {
                    return false;
                };
                *self = if size == 0 {
                    Scan::ChunkTrailers { buffer: Vec::new() }
                } else {
                    Scan::ChunkData { remaining: size }
                };
                true
            }
            Scan::ChunkEnd { buffer } => {
                let Some(line) = take_line(buffer, pending) else {
                    return buffer.len() <= 2;
                };
                if line != b"\r\n" {
                    return false;
                }
                *self = Scan::chunk_size();
                true
            }
            Scan::ChunkTrailers { buffer } => {
                let Some(line) = take_line(buffer, pending) else {
                    return buffer.len() <= MAX_HEAD_BYTES;
                };
                // The blank line ends the trailers; anything before it is a
                // trailer field, which carries nothing this detector reads.
                if line == b"\r\n" {
                    *self = Scan::Body { remaining: 0 };
                }
                true
            }
            Scan::Head { .. } | Scan::Stopped => false,
        }
    }

    /// Whether the message body just ended.
    fn body_done(&self) -> bool {
        matches!(self, Scan::Body { remaining: 0 })
    }
}

impl CollectedBody {
    fn collect(&mut self, data: &[u8]) {
        if self.oversize {
            return;
        }
        if self.bytes.len() + data.len() > MAX_BODY_BYTES {
            self.oversize = true;
            self.bytes = Vec::new();
            return;
        }
        self.bytes.extend_from_slice(data);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether this `(sni, path)` may be reported now, or is still inside the
/// window opened by the last line for it.
///
/// The map is swept on every admitted finding rather than on a timer: findings
/// are rare by construction, so the sweep costs nothing and the map never
/// holds an endpoint past its window. When it is full anyway the finding is
/// admitted: a detector that goes quiet under load is the failure this whole
/// module is about.
fn admit(sni: &str, path: &str) -> bool {
    static REPORTED: LazyLock<Mutex<HashMap<(String, String), Instant>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    admit_into(&mut REPORTED.lock().unwrap(), Instant::now(), sni, path)
}

/// The decision itself, over a map the caller owns.
fn admit_into(
    reported: &mut HashMap<(String, String), Instant>,
    now: Instant,
    sni: &str,
    path: &str,
) -> bool {
    reported.retain(|_, seen| now.duration_since(*seen) < SUPPRESSION_WINDOW);
    let key = (sni.to_string(), path.to_string());
    if reported.contains_key(&key) {
        return false;
    }
    if reported.len() < MAX_TRACKED_ENDPOINTS {
        reported.insert(key, now);
    }
    true
}

/// Cut a path to [`MAX_LOGGED_PATH_BYTES`], on a character boundary.
fn truncate_path(path: &str) -> String {
    if path.len() <= MAX_LOGGED_PATH_BYTES {
        return path.to_string();
    }
    let mut end = MAX_LOGGED_PATH_BYTES;
    while end > 0 && !path.is_char_boundary(end) {
        end -= 1;
    }
    path[..end].to_string()
}

/// Take a complete header block out of `pending`, buffering a partial one.
fn take_head(buffer: &mut Vec<u8>, pending: &mut &[u8]) -> Option<Vec<u8>> {
    let start = buffer.len().saturating_sub(3);
    buffer.extend_from_slice(pending);
    let boundary = match buffer[start..]
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
    {
        Some(offset) => start + offset + 4,
        None => {
            *pending = &[];
            return None;
        }
    };
    let rest = buffer.len() - boundary;
    *pending = &pending[pending.len() - rest..];
    let head = buffer[..boundary].to_vec();
    buffer.clear();
    Some(head)
}

/// Take one CRLF-terminated line out of `pending`, buffering a partial one.
fn take_line(buffer: &mut Vec<u8>, pending: &mut &[u8]) -> Option<Vec<u8>> {
    let start = buffer.len().saturating_sub(1);
    buffer.extend_from_slice(pending);
    let boundary = match buffer[start..]
        .windows(2)
        .position(|window| window == b"\r\n")
    {
        Some(offset) => start + offset + 2,
        None => {
            *pending = &[];
            return None;
        }
    };
    let rest = buffer.len() - boundary;
    *pending = &pending[pending.len() - rest..];
    let line = buffer[..boundary].to_vec();
    buffer.clear();
    Some(line)
}

/// The method and request target of a request line.
fn request_line(head: &[u8]) -> Option<(String, String)> {
    let line = std::str::from_utf8(head).ok()?.split("\r\n").next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    Some((method, path))
}

/// What a request's header block says about its body.
fn request_framing(head: &[u8]) -> BodyFraming {
    let Ok(text) = std::str::from_utf8(head) else {
        return BodyFraming::Unframed;
    };
    match (
        header(text, "transfer-encoding"),
        header(text, "content-length"),
    ) {
        (Some(encoding), _) if encoding.eq_ignore_ascii_case("chunked") => BodyFraming::Chunked,
        (Some(_), _) => BodyFraming::Unframed,
        (None, Some(length)) => length
            .parse::<usize>()
            .map_or(BodyFraming::Unframed, BodyFraming::Length),
        // A request with neither header has no body at all, unlike a response.
        (None, None) => BodyFraming::Empty,
    }
}

/// What a response's header block says about its body, and whether that body
/// is one this detector reads.
fn response_head(head: &[u8]) -> Option<ResponseHead> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.split("\r\n").next()?;
    let status = line.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    let json = header(text, "content-type").is_some_and(|value| {
        value.split(';').next().unwrap_or_default().trim() == "application/json"
    });
    let identity = header(text, "content-encoding")
        .is_none_or(|encoding| encoding.eq_ignore_ascii_case("identity"));
    let body = match (
        header(text, "transfer-encoding"),
        header(text, "content-length"),
    ) {
        _ if matches!(status, 204 | 304) => BodyFraming::Empty,
        (Some(encoding), _) if encoding.eq_ignore_ascii_case("chunked") => BodyFraming::Chunked,
        (Some(_), _) => BodyFraming::Unframed,
        (None, Some(length)) => length
            .parse::<usize>()
            .map_or(BodyFraming::Unframed, BodyFraming::Length),
        (None, None) => BodyFraming::Unframed,
    };
    let inspect = (200..300).contains(&status)
        && json
        && identity
        && !matches!(body, BodyFraming::Length(length) if length > MAX_BODY_BYTES);
    Some(ResponseHead {
        status,
        inspect,
        body,
    })
}

/// The first value of a header, trimmed.
fn header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

/// The size a chunk size line declares.
fn chunk_size(line: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(line).ok()?;
    let size = text.strip_suffix("\r\n")?.split(';').next()?;
    usize::from_str_radix(size.trim(), 16).ok()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::secrets::config::HostPattern;

    /// In-memory writer the capture tests point a subscriber at.
    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
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

    fn grant() -> OAuthSecret {
        OAuthSecret {
            broker_endpoint: "/tmp/broker.sock".into(),
            grant_id: "grant".into(),
            token_endpoint: "https://auth.example.com/oauth/token".into(),
            device_code_endpoint: None,
            poll_endpoint: Some("https://auth.example.com/oauth/device".into()),
            poll_secret_fields: vec!["authorization_code".into()],
            mint_endpoints: vec![],
            inject_hosts: vec![HostPattern::Exact("api.example.com".into())],
            access_token_field: "access_token".into(),
            refresh_token_field: "refresh_token".into(),
            access_env_var: "ACCESS_TOKEN".into(),
            refresh_env_var: "REFRESH_TOKEN".into(),
            access_sentinel: "$ACCESS".into(),
            refresh_sentinel: "$REFRESH".into(),
        }
    }

    fn json_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// Run one request/response exchange through a detector and return
    /// whatever it wrote to the log.
    ///
    /// Each test uses an SNI of its own: suppression is keyed on `(sni, path)`
    /// and outlives a single detector, so two tests sharing one would suppress
    /// each other depending on the order they ran in.
    fn exchange(sni: &str, active: bool, request: &[u8], response: &[&[u8]]) -> String {
        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::WARN)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut detector = CredentialDetector::new(&[grant()], sni, 443, active);
            detector.observe_request(request);
            for chunk in response {
                detector.observe_response(chunk);
            }
        });

        String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn a_credential_shaped_response_is_reported_without_its_value() {
        let response = json_response(r#"{"access_token":"the-real-token","expires_in":3600}"#);
        assert!(
            response.contains("the-real-token"),
            "the body carries a value"
        );

        let logged = exchange(
            "unwatched.example.com",
            true,
            b"GET /v1/session HTTP/1.1\r\nHost: unwatched.example.com\r\n\r\n",
            &[response.as_bytes()],
        );

        assert!(
            logged.contains("event=\"credential_shaped_response\""),
            "{logged}"
        );
        assert!(logged.contains("sni=\"unwatched.example.com\""), "{logged}");
        assert!(logged.contains("port=\"443\""), "{logged}");
        assert!(logged.contains("path=\"/v1/session\""), "{logged}");
        assert!(logged.contains("fields=\"access_token\""), "{logged}");
        assert!(logged.contains("status=\"200\""), "{logged}");
        assert!(!logged.contains("the-real-token"), "{logged}");
    }

    #[test]
    fn a_response_without_credential_fields_is_not_reported() {
        let logged = exchange(
            "ordinary.example.com",
            true,
            b"GET /v1/models HTTP/1.1\r\nHost: ordinary.example.com\r\n\r\n",
            &[json_response(r#"{"models":["a","b"],"total":2}"#).as_bytes()],
        );

        assert!(logged.is_empty(), "{logged}");
    }

    #[test]
    fn a_connection_a_grant_covers_is_not_reported() {
        // The same body, on a connection whose grant already sanitizes it.
        let logged = exchange(
            "covered.example.com",
            false,
            b"GET /v1/session HTTP/1.1\r\nHost: covered.example.com\r\n\r\n",
            &[json_response(r#"{"access_token":"the-real-token"}"#).as_bytes()],
        );

        assert!(logged.is_empty(), "{logged}");
    }

    #[test]
    fn a_body_past_the_size_cap_is_not_parsed() {
        let padding = "x".repeat(MAX_BODY_BYTES);
        let body = format!(r#"{{"access_token":"tok","padding":"{padding}"}}"#);
        assert!(body.len() > MAX_BODY_BYTES);

        let logged = exchange(
            "huge.example.com",
            true,
            b"GET /v1/session HTTP/1.1\r\nHost: huge.example.com\r\n\r\n",
            &[json_response(&body).as_bytes()],
        );

        assert!(logged.is_empty(), "{logged}");
    }

    #[test]
    fn a_field_a_grant_configures_is_credential_shaped_too() {
        // `authorization_code` is in no default set; this sandbox's grant is
        // what makes it a credential.
        let logged = exchange(
            "configured.example.com",
            true,
            b"GET /v1/device HTTP/1.1\r\nHost: configured.example.com\r\n\r\n",
            &[json_response(r#"{"authorization_code":"code"}"#).as_bytes()],
        );

        assert!(logged.contains("fields=\"authorization_code\""), "{logged}");
    }

    #[test]
    fn a_chunked_body_split_across_reads_is_reported_once_per_window() {
        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::WARN)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut detector =
                CredentialDetector::new(&[grant()], "chunked.example.com", 443, true);
            for _ in 0..2 {
                detector.observe_request(
                    b"GET /v1/session HTTP/1.1\r\nHost: chunked.example.com\r\n\r\n",
                );
                detector.observe_response(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n12\r\n{\"api_key\":\"kkkk",
                );
                detector.observe_response(b"\"}\r\n0\r\n\r\n");
            }
        });

        let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            logged.matches("credential_shaped_response").count(),
            1,
            "the repeat inside the window is suppressed: {logged}"
        );
        assert!(logged.contains("fields=\"api_key\""), "{logged}");
        assert!(!logged.contains("kkkk"), "{logged}");
    }

    #[test]
    fn nothing_after_a_protocol_upgrade_is_read_as_http() {
        // `101` hands the connection to another protocol; whatever follows is
        // that protocol's framing, and reading it as HTTP would be guesswork.
        let logged = exchange(
            "upgraded.example.com",
            true,
            b"GET /v1/socket HTTP/1.1\r\nHost: upgraded.example.com\r\nUpgrade: websocket\r\n\r\n",
            &[
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
                json_response(r#"{"access_token":"the-real-token"}"#).as_bytes(),
            ],
        );

        assert!(logged.is_empty(), "{logged}");
    }

    #[test]
    fn a_chunked_body_past_the_size_cap_is_not_parsed() {
        let padding = "x".repeat(MAX_BODY_BYTES);
        let body = format!(r#"{{"access_token":"tok","padding":"{padding}"}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len(),
        );

        let logged = exchange(
            "hugechunks.example.com",
            true,
            b"GET /v1/session HTTP/1.1\r\nHost: hugechunks.example.com\r\n\r\n",
            &[response.as_bytes()],
        );

        assert!(logged.is_empty(), "{logged}");
    }

    #[test]
    fn a_long_path_is_cut_to_the_bound_rather_than_logged_whole() {
        let path = format!("/v1/{}", "p".repeat(MAX_LOGGED_PATH_BYTES));
        let request = format!("GET {path} HTTP/1.1\r\nHost: long.example.com\r\n\r\n");

        let logged = exchange(
            "long.example.com",
            true,
            request.as_bytes(),
            &[json_response(r#"{"api_key":"k"}"#).as_bytes()],
        );

        assert!(
            logged.contains(&format!("path=\"{}\"", &path[..MAX_LOGGED_PATH_BYTES])),
            "{logged}"
        );
    }

    #[test]
    fn a_full_limiter_reports_rather_than_going_quiet() {
        let mut reported = HashMap::new();
        let now = Instant::now();
        for index in 0..MAX_TRACKED_ENDPOINTS {
            assert!(admit_into(
                &mut reported,
                now,
                "host.example.com",
                &format!("/path/{index}")
            ));
        }
        assert_eq!(reported.len(), MAX_TRACKED_ENDPOINTS);

        // No room to remember it, so it is reported every time rather than
        // being dropped.
        assert!(admit_into(
            &mut reported,
            now,
            "host.example.com",
            "/one-more"
        ));
        assert!(admit_into(
            &mut reported,
            now,
            "host.example.com",
            "/one-more"
        ));
        assert_eq!(reported.len(), MAX_TRACKED_ENDPOINTS);

        // One it did remember stays suppressed until its window closes.
        assert!(!admit_into(
            &mut reported,
            now,
            "host.example.com",
            "/path/0"
        ));
        assert!(admit_into(
            &mut reported,
            now + SUPPRESSION_WINDOW,
            "host.example.com",
            "/path/0"
        ));
    }
}
