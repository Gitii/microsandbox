//! OAuth token substitution and host-broker coordination.

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::config::{MAX_OAUTH_SENTINEL_BYTES, OAuthSecret};
use super::handler::host_pattern_allowed_for_tls;
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_OAUTH_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BROKER_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_OUTSTANDING_API_REQUESTS: usize = 1024;
const MAX_RESPONSE_SCRUB_FRAMING_BYTES: usize = MAX_OAUTH_MESSAGE_BYTES;
const MAX_SEEN_TOKENS: usize = MAX_OUTSTANDING_API_REQUESTS * 2;
const BROKER_TIMEOUT: Duration = Duration::from_secs(5);

/// Kind, and so the prefix, of every minted poll secret sentinel. Sentinels
/// are per-connection, so one that survives substitution belongs to a
/// connection that is gone and must not leave the sandbox.
const POLL_SENTINEL_KIND: &str = "POLL";
const POLL_SENTINEL_PREFIX: &str = "$MSB_OAUTH_POLL_";

/// RFC 8628 poll errors that say the device flow has not produced a token.
/// None of them is a failure of the grant the broker holds, so the response is
/// forwarded to the guest untouched and nothing is committed.
const POLL_WAITING_ERRORS: [&str; 4] = [
    "authorization_pending",
    "slow_down",
    "expired_token",
    "access_denied",
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-connection OAuth request/response transformer.
pub(crate) struct OAuthConnection {
    grants: Vec<LoadedGrant>,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    exchanges: VecDeque<Exchange>,
    token_connection: Option<bool>,
    connection_port: u16,
    response_scrub_buffer: Vec<u8>,
    response_scrub_framing: Vec<u8>,
    response_scrub_tail: Vec<u8>,
    response_scrub_state: ResponseScrubState,
    response_head_requests: VecDeque<bool>,
    seen_tokens: Vec<Zeroizing<String>>,
    request_state: RequestState,
}

struct LoadedGrant {
    config: OAuthSecret,
    token: Endpoint,
    device_code: Option<Endpoint>,
    poll: Option<Endpoint>,
    access: Zeroizing<String>,
    refresh: Zeroizing<String>,
    /// The sentinel the guest currently holds for the access token. It starts
    /// as the configured one and is replaced whenever the broker mints a new
    /// one, which a JWT-shaped sentinel does on every login or refresh.
    access_sentinel: String,
    /// The sentinel the guest currently holds for the refresh token.
    refresh_sentinel: String,
    generation: u64,
    lease: Option<UnixStream>,
    poll_secrets: Vec<PollSecret>,
}

/// One exact HTTPS endpoint a request line is matched against.
struct Endpoint {
    host: String,
    port: u16,
    target: String,
}

/// An extra secret a poll response carried, held for the connection's life so
/// the token request that follows can carry it back upstream.
struct PollSecret {
    field: String,
    sentinel: String,
    value: Zeroizing<String>,
}

/// The result of scrubbing one streamed chunk of response bytes.
struct Scrubbed {
    output: Vec<u8>,
    remaining: Vec<u8>,
    complete: bool,
}

/// A request whose response is still outstanding on a token connection.
enum Exchange {
    /// Forwarded unchanged; the response carries no grant material.
    PassThrough,
    /// A token or poll request for the grant at this index.
    Token { grant: usize, poll: bool },
}

/// How a poll (RFC 8628) response body ends the polling loop.
enum PollOutcome {
    /// The device flow has not produced a token yet, or has ended without one.
    Waiting,
    /// The response carries the access token field.
    Granted,
    /// The response carries only configured poll secret fields.
    Secrets,
    /// Anything else, including a malformed body: a failed exchange.
    Failed,
}

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum BrokerRequest<'a> {
    Load {
        grant_id: &'a str,
    },
    Acquire {
        grant_id: &'a str,
    },
    Commit {
        grant_id: &'a str,
        generation: u64,
        access: &'a str,
        refresh: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        expires_at: Option<u64>,
    },
}

#[derive(Deserialize)]
struct LoadResponse {
    access: String,
    refresh: String,
    generation: u64,
    /// The sentinel the broker currently stands behind for the access token.
    /// Absent means the configured sentinel still applies.
    #[serde(default)]
    access_sentinel: Option<String>,
    /// The sentinel the broker currently stands behind for the refresh token.
    #[serde(default)]
    refresh_sentinel: Option<String>,
}

#[derive(Deserialize)]
struct CommitResponse {
    ok: bool,
    #[serde(default)]
    conflict: bool,
    generation: Option<u64>,
    /// The sentinel minted for the access token just committed. Absent means
    /// the sentinel this connection already uses is still the right one.
    #[serde(default)]
    access_sentinel: Option<String>,
    /// The sentinel minted for the refresh token just committed.
    #[serde(default)]
    refresh_sentinel: Option<String>,
}

/// What a successful broker commit reports back.
struct Committed {
    generation: u64,
    access_sentinel: Option<String>,
    refresh_sentinel: Option<String>,
}

struct HttpMessage<'a> {
    headers: &'a [u8],
    body: &'a [u8],
    total_len: usize,
}

enum ResponseScrubState {
    Headers,
    ContentLength(usize),
    ChunkSize,
    ChunkData(usize),
    ChunkDataEnd,
    ChunkTrailers,
    CloseDelimited,
}

enum RequestState {
    Headers,
    ContentLength(usize),
    ChunkSize,
    ChunkData(usize),
    ChunkDataEnd,
    ChunkTrailers,
}

enum RequestBodyFraming {
    None,
    ContentLength(usize),
    Chunked,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OAuthConnection {
    /// Load grants relevant to this TLS SNI. Broker failures reject the connection.
    pub(crate) async fn new_tls_intercepted(
        configs: &[OAuthSecret],
        sni: &str,
        port: u16,
        guest_ip: IpAddr,
        shared: &SharedState,
    ) -> io::Result<Self> {
        Self::new(configs, sni, port, Some((guest_ip, shared))).await
    }

    pub(crate) async fn new_tls_intercepted_via_connect(
        configs: &[OAuthSecret],
        sni: &str,
        port: u16,
    ) -> io::Result<Self> {
        Self::new(configs, sni, port, None).await
    }

    async fn new(
        configs: &[OAuthSecret],
        sni: &str,
        port: u16,
        identity: Option<(IpAddr, &SharedState)>,
    ) -> io::Result<Self> {
        let mut grants = Vec::new();
        let mut seen_tokens = Vec::new();
        for config in configs {
            let token = parse_https_endpoint(&config.token_endpoint)?;
            let device_code = config
                .device_code_endpoint
                .as_deref()
                .map(parse_https_endpoint)
                .transpose()?;
            let poll = config
                .poll_endpoint
                .as_deref()
                .map(parse_https_endpoint)
                .transpose()?;
            let host_allowed = |matches: bool| {
                matches
                    && identity.is_none_or(|(guest_ip, shared)| {
                        shared.any_resolved_hostname(guest_ip, |hostname| {
                            hostname.eq_ignore_ascii_case(sni)
                        })
                    })
            };
            // Every endpoint of the flow makes the grant relevant: the device
            // code endpoint carries no secret, but the connection that reaches
            // it also carries the poll and token requests that do.
            let is_relevant = |endpoint: &Endpoint| {
                port == endpoint.port && host_allowed(endpoint.host.eq_ignore_ascii_case(sni))
            };
            let endpoint_relevant = is_relevant(&token)
                || device_code.as_ref().is_some_and(&is_relevant)
                || poll.as_ref().is_some_and(&is_relevant);
            let inject_relevant = config.inject_hosts.iter().any(|host| {
                identity.map_or_else(
                    || host.matches(sni),
                    |(guest_ip, shared)| host_pattern_allowed_for_tls(host, sni, guest_ip, shared),
                )
            });
            let relevant = endpoint_relevant || inject_relevant;
            if !relevant {
                continue;
            }
            let loaded = broker_load(config).await?;
            remember_token(&mut seen_tokens, &loaded.access)?;
            remember_token(&mut seen_tokens, &loaded.refresh)?;
            let mut grant = LoadedGrant {
                config: config.clone(),
                token,
                device_code,
                poll,
                access: Zeroizing::new(loaded.access),
                refresh: Zeroizing::new(loaded.refresh),
                access_sentinel: config.access_sentinel.clone(),
                refresh_sentinel: config.refresh_sentinel.clone(),
                generation: loaded.generation,
                lease: None,
                poll_secrets: Vec::new(),
            };
            // The guest may already hold a sentinel minted after this sandbox
            // was configured, so the broker's answer wins over the config.
            grant.adopt_sentinels(
                loaded.access_sentinel,
                loaded.refresh_sentinel,
                &seen_tokens,
            )?;
            grants.push(grant);
        }
        Ok(Self {
            token_connection: None,
            connection_port: port,
            grants,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            exchanges: VecDeque::new(),
            response_scrub_buffer: Vec::new(),
            response_scrub_framing: Vec::new(),
            response_scrub_tail: Vec::new(),
            response_scrub_state: ResponseScrubState::Headers,
            response_head_requests: VecDeque::new(),
            seen_tokens,
            request_state: RequestState::Headers,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    pub(crate) fn is_token_host(&self) -> bool {
        self.token_connection == Some(true)
    }

    pub(crate) fn scrub_response_chunk(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        Ok(self.scrub_stream(data, false)?.output)
    }

    /// Scrub a streamed response, optionally stopping at the end of the first
    /// complete message and handing the rest back to the caller.
    fn scrub_stream(&mut self, data: &[u8], stop_at_message_end: bool) -> io::Result<Scrubbed> {
        let mut output = Vec::new();
        let mut pending = data.to_vec();
        let mut complete = false;
        while !pending.is_empty() {
            match self.response_scrub_state {
                ResponseScrubState::Headers => {
                    self.response_scrub_buffer.extend_from_slice(&pending);
                    pending.clear();
                    enforce_limit(&self.response_scrub_buffer)?;
                    let Some(boundary) = header_boundary(&self.response_scrub_buffer) else {
                        break;
                    };
                    let headers = self.response_scrub_buffer[..boundary].to_vec();
                    pending = self.response_scrub_buffer.split_off(boundary);
                    self.response_scrub_buffer.clear();
                    let status = response_status(&headers)?;
                    if status == 101 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "OAuth API protocol upgrades are unsupported",
                        ));
                    }
                    self.response_scrub_state = response_body_state(
                        &headers,
                        self.response_head_requests
                            .front()
                            .copied()
                            .unwrap_or(false),
                    )?;
                    // A close-delimited response ends at EOF, so nothing marks
                    // where the next response starts. On a token connection
                    // that would stream whatever follows it -- a token
                    // response among it -- straight to the guest.
                    if stop_at_message_end
                        && matches!(
                            self.response_scrub_state,
                            ResponseScrubState::CloseDelimited
                        )
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "OAuth device code responses require Content-Length or chunked framing",
                        ));
                    }
                    self.scrub_stream_bytes(&headers, &mut output);
                    self.flush_scrub_tail(&mut output);
                    if !(100..200).contains(&status) {
                        self.response_head_requests.pop_front();
                    }
                    if matches!(
                        self.response_scrub_state,
                        ResponseScrubState::ContentLength(0)
                    ) {
                        self.response_scrub_state = ResponseScrubState::Headers;
                        complete = true;
                        if stop_at_message_end {
                            break;
                        }
                    }
                }
                ResponseScrubState::ContentLength(remaining) => {
                    let consumed = remaining.min(pending.len());
                    self.scrub_stream_bytes(&pending[..consumed], &mut output);
                    pending.drain(..consumed);
                    if consumed == remaining {
                        self.flush_scrub_tail(&mut output);
                        self.response_scrub_state = ResponseScrubState::Headers;
                        complete = true;
                        if stop_at_message_end {
                            break;
                        }
                    } else {
                        self.response_scrub_state =
                            ResponseScrubState::ContentLength(remaining - consumed);
                    }
                }
                ResponseScrubState::ChunkSize => {
                    self.response_scrub_buffer.extend_from_slice(&pending);
                    pending.clear();
                    enforce_limit(&self.response_scrub_buffer)?;
                    let Some(end) = line_boundary(&self.response_scrub_buffer) else {
                        break;
                    };
                    let mut line = self.response_scrub_buffer[..end].to_vec();
                    pending = self.response_scrub_buffer.split_off(end);
                    self.response_scrub_buffer.clear();
                    let size = parse_chunk_size(&line)?;
                    scrub_seen_tokens(&mut line, &self.seen_tokens);
                    if self.response_scrub_tail.is_empty() && self.response_scrub_framing.is_empty()
                    {
                        output.extend_from_slice(&line);
                    } else {
                        extend_response_scrub_framing(&mut self.response_scrub_framing, &line)?;
                    }
                    self.response_scrub_state = if size == 0 {
                        ResponseScrubState::ChunkTrailers
                    } else {
                        ResponseScrubState::ChunkData(size)
                    };
                }
                ResponseScrubState::ChunkData(remaining) => {
                    let consumed = remaining.min(pending.len());
                    self.scrub_stream_bytes(&pending[..consumed], &mut output);
                    pending.drain(..consumed);
                    self.response_scrub_state = if consumed == remaining {
                        ResponseScrubState::ChunkDataEnd
                    } else {
                        ResponseScrubState::ChunkData(remaining - consumed)
                    };
                }
                ResponseScrubState::ChunkDataEnd => {
                    self.response_scrub_buffer.extend_from_slice(&pending);
                    pending.clear();
                    if self.response_scrub_buffer.len() < 2 {
                        break;
                    }
                    if !self.response_scrub_buffer.starts_with(b"\r\n") {
                        return Err(invalid_http());
                    }
                    extend_response_scrub_framing(&mut self.response_scrub_framing, b"\r\n")?;
                    pending = self.response_scrub_buffer.split_off(2);
                    self.response_scrub_buffer.clear();
                    self.response_scrub_state = ResponseScrubState::ChunkSize;
                }
                ResponseScrubState::ChunkTrailers => {
                    self.response_scrub_buffer.extend_from_slice(&pending);
                    pending.clear();
                    enforce_limit(&self.response_scrub_buffer)?;
                    let boundary = if self.response_scrub_buffer.starts_with(b"\r\n") {
                        Some(2)
                    } else {
                        header_boundary(&self.response_scrub_buffer)
                    };
                    let Some(boundary) = boundary else {
                        break;
                    };
                    let trailers = self.response_scrub_buffer[..boundary].to_vec();
                    pending = self.response_scrub_buffer.split_off(boundary);
                    self.response_scrub_buffer.clear();
                    self.flush_scrub_tail(&mut output);
                    self.scrub_stream_bytes(&trailers, &mut output);
                    self.flush_scrub_tail(&mut output);
                    self.response_scrub_state = ResponseScrubState::Headers;
                    complete = true;
                    if stop_at_message_end {
                        break;
                    }
                }
                ResponseScrubState::CloseDelimited => {
                    self.scrub_stream_bytes(&pending, &mut output);
                    pending.clear();
                }
            }
        }
        Ok(Scrubbed {
            output,
            remaining: pending,
            complete,
        })
    }

    pub(crate) fn finish_response_scrubbing(&mut self) -> io::Result<Vec<u8>> {
        if self.token_connection == Some(true) {
            if !self.response_buffer.is_empty() || !self.exchanges.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete OAuth token response",
                ));
            }
            let mut output = Vec::new();
            self.flush_scrub_tail(&mut output);
            return Ok(output);
        }
        if !self.response_scrub_buffer.is_empty()
            || matches!(
                self.response_scrub_state,
                ResponseScrubState::ContentLength(_)
                    | ResponseScrubState::ChunkSize
                    | ResponseScrubState::ChunkData(_)
                    | ResponseScrubState::ChunkDataEnd
                    | ResponseScrubState::ChunkTrailers
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete OAuth API response",
            ));
        }
        let mut output = Vec::new();
        self.flush_scrub_tail(&mut output);
        Ok(output)
    }

    fn scrub_stream_bytes(&mut self, data: &[u8], output: &mut Vec<u8>) {
        let mut combined = std::mem::take(&mut self.response_scrub_tail);
        let old_tail_len = combined.len();
        combined.extend_from_slice(data);
        scrub_seen_tokens(&mut combined, &self.seen_tokens);
        let keep = longest_token_prefix_suffix(&combined, &self.seen_tokens);
        let split = combined.len() - keep;
        let tail = combined.split_off(split);
        if self.response_scrub_framing.is_empty() {
            output.extend(combined);
        } else {
            let before_framing = old_tail_len.min(combined.len());
            output.extend_from_slice(&combined[..before_framing]);
            if before_framing == old_tail_len {
                output.extend(std::mem::take(&mut self.response_scrub_framing));
                output.extend_from_slice(&combined[before_framing..]);
            }
        }
        self.response_scrub_tail = tail;
    }

    fn flush_scrub_tail(&mut self, output: &mut Vec<u8>) {
        output.extend(std::mem::take(&mut self.response_scrub_tail));
        output.extend(std::mem::take(&mut self.response_scrub_framing));
    }

    /// Transform complete HTTP/1.1 requests and record token exchanges.
    pub(crate) async fn transform_requests(
        &mut self,
        data: &[u8],
        sni: &str,
    ) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut pending = data.to_vec();
        while !pending.is_empty() {
            match self.request_state {
                RequestState::Headers => {
                    self.request_buffer.extend_from_slice(&pending);
                    pending.clear();
                    enforce_limit(&self.request_buffer)?;
                    let Some(header_end) = header_boundary(&self.request_buffer) else {
                        break;
                    };
                    let headers = self.request_buffer[..header_end].to_vec();
                    let request_line = first_header_line(&headers)?;
                    let method = request_line
                        .split_whitespace()
                        .next()
                        .ok_or_else(invalid_http)?;
                    let target = request_line
                        .split_whitespace()
                        .nth(1)
                        .ok_or_else(invalid_http)?;
                    let port = self.connection_port;
                    // A grant matches at most once even when its poll endpoint
                    // is its token endpoint, which is what a device flow with a
                    // refresh grant looks like.
                    let endpoint_grants = self
                        .grants
                        .iter()
                        .enumerate()
                        .filter(|(_, grant)| {
                            grant.token.matches(sni, port, target)
                                || grant
                                    .poll
                                    .as_ref()
                                    .is_some_and(|poll| poll.matches(sni, port, target))
                        })
                        .collect::<Vec<_>>();
                    let endpoint_request = !endpoint_grants.is_empty();
                    let device_code_request = !endpoint_request
                        && self.grants.iter().any(|grant| {
                            grant
                                .device_code
                                .as_ref()
                                .is_some_and(|device_code| device_code.matches(sni, port, target))
                        });
                    let framing = request_body_framing(&headers)?;
                    let body_len = match framing {
                        RequestBodyFraming::None | RequestBodyFraming::Chunked => 0,
                        RequestBodyFraming::ContentLength(length) => length,
                    };
                    let total_len = header_end.checked_add(body_len).ok_or_else(invalid_http)?;
                    if endpoint_request || device_code_request {
                        let endpoint = if endpoint_request {
                            "token"
                        } else {
                            "device code"
                        };
                        if !method.eq_ignore_ascii_case("POST") {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("OAuth {endpoint} endpoint requests must use POST"),
                            ));
                        }
                        reject_expect_100_continue(&headers)?;
                        if matches!(framing, RequestBodyFraming::Chunked) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "OAuth {endpoint} endpoint chunked requests are unsupported"
                                ),
                            ));
                        }
                        if self.request_buffer.len() < total_len {
                            break;
                        }
                    }
                    let matching_grants = if endpoint_request {
                        let framed_request = &self.request_buffer[..total_len];
                        endpoint_grants
                            .iter()
                            .filter(|(_, grant)| {
                                contains_bytes(framed_request, grant.access_sentinel.as_bytes())
                                    || contains_bytes(
                                        framed_request,
                                        grant.refresh_sentinel.as_bytes(),
                                    )
                            })
                            .map(|(index, _)| *index)
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };
                    let token_grant = match matching_grants.as_slice() {
                        [index] => Some(*index),
                        [] if endpoint_grants.len() == 1 => Some(endpoint_grants[0].0),
                        [] if endpoint_grants.is_empty() => None,
                        [] => return Err(invalid_http()),
                        _ => return Err(invalid_http()),
                    };
                    // A device code poll carries a device code, never a
                    // sentinel. When the poll endpoint is also the token
                    // endpoint, that is what separates a poll from the refresh
                    // requests that share the URL.
                    let poll_request = matching_grants.is_empty()
                        && token_grant.is_some_and(|index| {
                            self.grants[index]
                                .poll
                                .as_ref()
                                .is_some_and(|poll| poll.matches(sni, port, target))
                        });
                    // A device code request holds no secret, but it belongs to
                    // the same conversation: buffered whole, forwarded
                    // unchanged, and its response released only once parsed.
                    let is_token_request = token_grant.is_some() || device_code_request;
                    if self
                        .token_connection
                        .is_some_and(|token_connection| token_connection != is_token_request)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "mixing OAuth API and token requests on one connection is unsupported",
                        ));
                    }
                    self.token_connection = Some(is_token_request);
                    if !is_token_request {
                        reject_protocol_upgrade(&headers)?;
                        if self.response_head_requests.len() >= MAX_OUTSTANDING_API_REQUESTS {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "too many outstanding OAuth API requests",
                            ));
                        }
                        self.response_head_requests
                            .push_back(method.eq_ignore_ascii_case("HEAD"));
                    }
                    if device_code_request && self.exchanges.len() >= MAX_OUTSTANDING_API_REQUESTS {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "too many outstanding OAuth API requests",
                        ));
                    }
                    if token_grant.is_some()
                        && self
                            .exchanges
                            .iter()
                            .any(|exchange| matches!(exchange, Exchange::Token { .. }))
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "OAuth token request pipelining is unsupported",
                        ));
                    }
                    let request_len = if is_token_request {
                        total_len
                    } else {
                        header_end
                    };
                    let mut rewritten =
                        remove_header(&self.request_buffer[..request_len], "accept-encoding")?;
                    if let Some(index) = token_grant
                        && self.grants[index].lease.is_none()
                    {
                        let (loaded, lease) = broker_acquire(&self.grants[index].config).await?;
                        remember_token(&mut self.seen_tokens, &loaded.access)?;
                        remember_token(&mut self.seen_tokens, &loaded.refresh)?;
                        let grant = &mut self.grants[index];
                        grant.access = Zeroizing::new(loaded.access);
                        grant.refresh = Zeroizing::new(loaded.refresh);
                        grant.generation = loaded.generation;
                        grant.lease = Some(lease);
                        grant.adopt_sentinels(
                            loaded.access_sentinel,
                            loaded.refresh_sentinel,
                            &self.seen_tokens,
                        )?;
                    }
                    for (index, grant) in self.grants.iter_mut().enumerate() {
                        let inject = grant
                            .config
                            .inject_hosts
                            .iter()
                            .any(|host| host.matches(sni));
                        if inject && token_grant != Some(index) {
                            let loaded = broker_load(&grant.config).await?;
                            remember_token(&mut self.seen_tokens, &loaded.access)?;
                            remember_token(&mut self.seen_tokens, &loaded.refresh)?;
                            grant.access = Zeroizing::new(loaded.access);
                            grant.refresh = Zeroizing::new(loaded.refresh);
                            grant.generation = loaded.generation;
                            grant.adopt_sentinels(
                                loaded.access_sentinel,
                                loaded.refresh_sentinel,
                                &self.seen_tokens,
                            )?;
                        }
                        if inject || token_grant == Some(index) {
                            rewritten = if inject && token_grant != Some(index) {
                                replace_bearer_header(
                                    &rewritten,
                                    grant.access_sentinel.as_bytes(),
                                    grant.access.as_bytes(),
                                )
                            } else {
                                replace_all(
                                    &rewritten,
                                    grant.access_sentinel.as_bytes(),
                                    grant.access.as_bytes(),
                                )
                            };
                        }
                        if token_grant == Some(index) {
                            rewritten = replace_all(
                                &rewritten,
                                grant.refresh_sentinel.as_bytes(),
                                grant.refresh.as_bytes(),
                            );
                            for secret in &grant.poll_secrets {
                                rewritten = replace_all(
                                    &rewritten,
                                    secret.sentinel.as_bytes(),
                                    secret.value.as_bytes(),
                                );
                            }
                        }
                    }
                    if is_token_request
                        && contains_bytes(&rewritten, POLL_SENTINEL_PREFIX.as_bytes())
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "OAuth poll secret sentinel is unknown to this connection",
                        ));
                    }
                    if let Some(index) = token_grant {
                        validate_token_request_content_type(&headers)?;
                        rewritten = update_content_length(&rewritten)?;
                        self.exchanges.push_back(Exchange::Token {
                            grant: index,
                            poll: poll_request,
                        });
                    } else if device_code_request {
                        self.exchanges.push_back(Exchange::PassThrough);
                    }
                    output.extend_from_slice(&rewritten);
                    pending = self.request_buffer.split_off(request_len);
                    self.request_buffer.clear();
                    self.request_state = if is_token_request {
                        RequestState::Headers
                    } else {
                        match framing {
                            RequestBodyFraming::None | RequestBodyFraming::ContentLength(0) => {
                                RequestState::Headers
                            }
                            RequestBodyFraming::ContentLength(length) => {
                                RequestState::ContentLength(length)
                            }
                            RequestBodyFraming::Chunked => RequestState::ChunkSize,
                        }
                    };
                }
                RequestState::ContentLength(remaining) => {
                    let consumed = remaining.min(pending.len());
                    output.extend_from_slice(&pending[..consumed]);
                    pending.drain(..consumed);
                    self.request_state = if consumed == remaining {
                        RequestState::Headers
                    } else {
                        RequestState::ContentLength(remaining - consumed)
                    };
                }
                RequestState::ChunkSize => {
                    self.request_buffer.extend_from_slice(&pending);
                    pending.clear();
                    enforce_limit(&self.request_buffer)?;
                    let Some(end) = line_boundary(&self.request_buffer) else {
                        break;
                    };
                    let line = self.request_buffer[..end].to_vec();
                    pending = self.request_buffer.split_off(end);
                    self.request_buffer.clear();
                    let size = parse_chunk_size(&line)?;
                    output.extend_from_slice(&line);
                    self.request_state = if size == 0 {
                        RequestState::ChunkTrailers
                    } else {
                        RequestState::ChunkData(size)
                    };
                }
                RequestState::ChunkData(remaining) => {
                    let consumed = remaining.min(pending.len());
                    output.extend_from_slice(&pending[..consumed]);
                    pending.drain(..consumed);
                    self.request_state = if consumed == remaining {
                        RequestState::ChunkDataEnd
                    } else {
                        RequestState::ChunkData(remaining - consumed)
                    };
                }
                RequestState::ChunkDataEnd => {
                    self.request_buffer.extend_from_slice(&pending);
                    pending.clear();
                    if self.request_buffer.len() < 2 {
                        break;
                    }
                    if !self.request_buffer.starts_with(b"\r\n") {
                        return Err(invalid_http());
                    }
                    output.extend_from_slice(b"\r\n");
                    pending = self.request_buffer.split_off(2);
                    self.request_buffer.clear();
                    self.request_state = RequestState::ChunkSize;
                }
                RequestState::ChunkTrailers => {
                    self.request_buffer.extend_from_slice(&pending);
                    pending.clear();
                    enforce_limit(&self.request_buffer)?;
                    let boundary = if self.request_buffer.starts_with(b"\r\n") {
                        Some(2)
                    } else {
                        header_boundary(&self.request_buffer)
                    };
                    let Some(boundary) = boundary else {
                        break;
                    };
                    output.extend_from_slice(&self.request_buffer[..boundary]);
                    pending = self.request_buffer.split_off(boundary);
                    self.request_buffer.clear();
                    self.request_state = RequestState::Headers;
                }
            }
        }
        Ok(output)
    }

    /// Buffer and sanitize token endpoint responses before releasing them.
    pub(crate) async fn transform_responses(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        self.response_buffer.extend_from_slice(data);
        enforce_limit(&self.response_buffer)?;
        let mut output = Vec::new();
        loop {
            // A device code response holds no grant material and is forwarded
            // as it arrives, so it is streamed like an ordinary API response
            // rather than held to the token response's framing rules.
            if matches!(self.exchanges.front(), Some(Exchange::PassThrough)) {
                let buffered = std::mem::take(&mut self.response_buffer);
                let scrubbed = self.scrub_stream(&buffered, true)?;
                self.response_buffer = scrubbed.remaining;
                output.extend_from_slice(&scrubbed.output);
                if !scrubbed.complete {
                    break;
                }
                self.exchanges.pop_front();
                continue;
            }
            let Some(message) = parse_token_response(&self.response_buffer)? else {
                break;
            };
            let total_len = message.total_len;
            let headers = message.headers.to_vec();
            let body = message.body.to_vec();
            let exchange = self.exchanges.pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "OAuth response without request")
            })?;
            let response = self.response_buffer[..total_len].to_vec();
            let status = response_status(&headers)?;
            if (100..200).contains(&status) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OAuth informational responses are unsupported",
                ));
            }
            let rewritten = match exchange {
                Exchange::Token { grant, poll } => {
                    self.finish_exchange(grant, poll, status, &headers, &body, response)
                        .await?
                }
                Exchange::PassThrough => response,
            };
            output.extend_from_slice(&self.scrub_tokens(rewritten));
            self.response_buffer.drain(..total_len);
        }
        Ok(output)
    }

    /// Complete a token or poll exchange for the grant at `index`.
    async fn finish_exchange(
        &mut self,
        index: usize,
        poll: bool,
        status: u16,
        headers: &[u8],
        body: &[u8],
        response: Vec<u8>,
    ) -> io::Result<Vec<u8>> {
        if poll {
            match poll_outcome(status, body, &self.grants[index].config) {
                PollOutcome::Waiting => {
                    // Nothing was committed, so the broker lease is released
                    // rather than held across the guest's polling interval.
                    self.grants[index].lease = None;
                    return Ok(response);
                }
                PollOutcome::Secrets => return self.sanitize_poll_secrets(index, headers, body),
                PollOutcome::Granted | PollOutcome::Failed => {}
            }
        }
        if (200..300).contains(&status) {
            return self.sanitize_token_response(index, headers, body).await;
        }
        let rewritten = self.sanitize_token_error(index, headers, body)?;
        self.grants[index].lease = None;
        Ok(rewritten)
    }

    /// Replace a poll response's extra secret fields with sentinels, holding
    /// the real values for the token request that follows on this connection.
    fn sanitize_poll_secrets(
        &mut self,
        index: usize,
        headers: &[u8],
        body: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut json: Value = serde_json::from_slice(body).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed OAuth poll response")
        })?;
        let object = json.as_object_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "OAuth poll response must be an object",
            )
        })?;
        self.replace_poll_secrets(index, object)?;
        // No token was committed, so the grant keeps its material and the
        // lease goes back to the broker.
        self.grants[index].lease = None;
        let body = serde_json::to_vec(&json).map_err(io::Error::other)?;
        let mut response = rebuild_message(headers, &body)?;
        scrub_seen_tokens(&mut response, &self.seen_tokens);
        Ok(response)
    }

    fn replace_poll_secrets(
        &mut self,
        index: usize,
        object: &mut serde_json::Map<String, Value>,
    ) -> io::Result<()> {
        let fields = self.grants[index].config.poll_secret_fields.clone();
        for field in fields {
            let Some(Value::String(value)) = object.get(&field) else {
                continue;
            };
            let value = value.clone();
            let sentinel = self.remember_poll_secret(index, &field, &value)?;
            object.insert(field, Value::String(sentinel));
        }
        Ok(())
    }

    /// Mint or refresh the sentinel standing in for one poll secret field. The
    /// sentinel is stable for the life of the connection so a request that
    /// echoes an earlier one still substitutes.
    fn remember_poll_secret(
        &mut self,
        index: usize,
        field: &str,
        value: &str,
    ) -> io::Result<String> {
        remember_token(&mut self.seen_tokens, value)?;
        let grant = &mut self.grants[index];
        if let Some(secret) = grant
            .poll_secrets
            .iter_mut()
            .find(|secret| secret.field == field)
        {
            secret.value = Zeroizing::new(value.to_string());
            return Ok(secret.sentinel.clone());
        }
        let sentinel = random_sentinel(POLL_SENTINEL_KIND);
        grant.poll_secrets.push(PollSecret {
            field: field.to_string(),
            sentinel: sentinel.clone(),
            value: Zeroizing::new(value.to_string()),
        });
        Ok(sentinel)
    }

    async fn sanitize_token_response(
        &mut self,
        index: usize,
        headers: &[u8],
        body: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut json: Value = serde_json::from_slice(body)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed OAuth response"))?;
        let object = json.as_object_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "OAuth response must be an object",
            )
        })?;
        let grant = &mut self.grants[index];
        let access = object
            .get(&grant.config.access_token_field)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "OAuth access token is missing")
            })?
            .to_string();
        let refresh = match object.get(&grant.config.refresh_token_field) {
            Some(Value::String(value)) => value.clone(),
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OAuth refresh token is not a string",
                ));
            }
            None => grant.refresh.to_string(),
        };
        let expires_at = object
            .get("expires_in")
            .and_then(Value::as_u64)
            .map(|seconds| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64
                    + seconds.saturating_mul(1000)
            });
        let committed = broker_commit(grant, &access, &refresh, expires_at).await?;
        remember_token(&mut self.seen_tokens, &access)?;
        remember_token(&mut self.seen_tokens, &refresh)?;
        // A JWT-shaped sentinel mirrors the claims of the token it stands for,
        // so the commit that replaces the token also replaces the sentinel the
        // guest is handed here and substitutes for the rest of the connection.
        // The broker's answer is checked before any of it is adopted.
        let grant = &mut self.grants[index];
        grant.adopt_sentinels(
            committed.access_sentinel,
            committed.refresh_sentinel,
            &self.seen_tokens,
        )?;
        grant.access = Zeroizing::new(access);
        grant.refresh = Zeroizing::new(refresh);
        grant.generation = committed.generation;
        grant.lease = None;
        // A device flow without a refresh grant names one field for both
        // tokens; the access sentinel is the one the guest gets back.
        if object.contains_key(&grant.config.refresh_token_field)
            && grant.config.refresh_token_field != grant.config.access_token_field
        {
            object.insert(
                grant.config.refresh_token_field.clone(),
                Value::String(grant.refresh_sentinel.clone()),
            );
        }
        object.insert(
            grant.config.access_token_field.clone(),
            Value::String(grant.access_sentinel.clone()),
        );
        self.replace_poll_secrets(index, object)?;
        let body = serde_json::to_vec(&json).map_err(io::Error::other)?;
        rebuild_message(headers, &body)
    }

    fn sanitize_token_error(
        &mut self,
        index: usize,
        headers: &[u8],
        body: &[u8],
    ) -> io::Result<Vec<u8>> {
        let grant = &self.grants[index];
        let mut json: Value = serde_json::from_slice(body).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed OAuth error response")
        })?;
        let object = json.as_object_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "OAuth error response must be an object",
            )
        })?;
        if object.contains_key(&grant.config.refresh_token_field)
            && grant.config.refresh_token_field != grant.config.access_token_field
        {
            object.insert(
                grant.config.refresh_token_field.clone(),
                Value::String(grant.refresh_sentinel.clone()),
            );
        }
        if object.contains_key(&grant.config.access_token_field) {
            object.insert(
                grant.config.access_token_field.clone(),
                Value::String(grant.access_sentinel.clone()),
            );
        }
        self.replace_poll_secrets(index, object)?;
        let body = serde_json::to_vec(&json).map_err(io::Error::other)?;
        let mut response = rebuild_message(headers, &body)?;
        scrub_seen_tokens(&mut response, &self.seen_tokens);
        Ok(response)
    }

    fn scrub_tokens(&self, mut response: Vec<u8>) -> Vec<u8> {
        scrub_seen_tokens(&mut response, &self.seen_tokens);
        response
    }
}

impl LoadedGrant {
    /// Adopt sentinels the broker minted for the tokens it just handed back.
    /// An absent field keeps the sentinel this connection already uses, which
    /// is what a broker that mints opaque sentinels once, at configuration
    /// time, always sends.
    fn adopt_sentinels(
        &mut self,
        access: Option<String>,
        refresh: Option<String>,
        seen: &[Zeroizing<String>],
    ) -> io::Result<()> {
        let access = access
            .map(|access| validate_sentinel(access, seen))
            .transpose()?;
        let refresh = refresh
            .map(|refresh| validate_sentinel(refresh, seen))
            .transpose()?;
        let next_access = access.unwrap_or_else(|| self.access_sentinel.clone());
        let next_refresh = refresh.unwrap_or_else(|| self.refresh_sentinel.clone());
        if next_access == next_refresh {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OAuth broker sentinels must differ",
            ));
        }
        self.access_sentinel = next_access;
        self.refresh_sentinel = next_refresh;
        Ok(())
    }
}

impl Endpoint {
    /// Whether a request line on this connection reached exactly this endpoint.
    fn matches(&self, sni: &str, port: u16, target: &str) -> bool {
        self.port == port && self.target == target && self.host.eq_ignore_ascii_case(sni)
    }
}

fn remember_token(tokens: &mut Vec<Zeroizing<String>>, token: &str) -> io::Result<()> {
    if token.is_empty() || tokens.iter().any(|seen| seen.as_str() == token) {
        return Ok(());
    }
    if tokens.len() >= MAX_SEEN_TOKENS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many OAuth tokens seen on one connection",
        ));
    }
    tokens.push(Zeroizing::new(token.to_string()));
    Ok(())
}

fn scrub_seen_tokens(data: &mut Vec<u8>, tokens: &[Zeroizing<String>]) {
    for token in tokens {
        *data = replace_same_length(data, token.as_bytes());
    }
}

fn longest_token_prefix_suffix(data: &[u8], tokens: &[Zeroizing<String>]) -> usize {
    let mut longest = 0;
    for token in tokens {
        for length in 1..token.len() {
            if data.ends_with(&token.as_bytes()[..length]) {
                longest = longest.max(length);
            }
        }
    }
    longest
}

/// Check one broker-supplied sentinel before it is used for substitution.
///
/// A sentinel may be JWT-shaped — the real token's header and payload copied
/// verbatim with only the signature replaced — so it carries base64url bytes
/// (`.`, `-`, `_` included) and runs to at most
/// [`MAX_OAUTH_SENTINEL_BYTES`] bytes. It is matched and replaced byte for
/// byte, so only bytes that could not survive an HTTP message are rejected,
/// along with any value this connection has seen as a real token.
fn validate_sentinel(sentinel: String, seen: &[Zeroizing<String>]) -> io::Result<String> {
    if sentinel.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth broker sentinel is empty",
        ));
    }
    if sentinel.len() > MAX_OAUTH_SENTINEL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth broker sentinel exceeds limit",
        ));
    }
    if sentinel.contains(['\0', '\r', '\n']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth broker sentinel contains a control character",
        ));
    }
    // A sentinel that is one of the real tokens would be written into the
    // guest's response body as itself, and the body the token response takes
    // is the one path that is not scrubbed afterwards.
    if seen.iter().any(|token| token.as_str() == sentinel) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth broker sentinel is a live token",
        ));
    }
    Ok(sentinel)
}

/// Fill omitted sentinels with independent random per-sandbox values.
pub(crate) fn ensure_sentinels(oauth: &mut OAuthSecret) {
    if oauth.access_sentinel.is_empty() {
        oauth.access_sentinel = random_sentinel("ACCESS");
    }
    if oauth.refresh_sentinel.is_empty() {
        oauth.refresh_sentinel = random_sentinel("REFRESH");
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn broker_load(config: &OAuthSecret) -> io::Result<LoadResponse> {
    broker_call(
        &config.broker_endpoint,
        &BrokerRequest::Load {
            grant_id: &config.grant_id,
        },
    )
    .await
}

async fn broker_acquire(config: &OAuthSecret) -> io::Result<(LoadResponse, UnixStream)> {
    let mut stream = broker_connect(
        &config.broker_endpoint,
        &BrokerRequest::Acquire {
            grant_id: &config.grant_id,
        },
    )
    .await?;
    let response = broker_read(&mut stream).await?;
    Ok((response, stream))
}

async fn broker_commit(
    grant: &mut LoadedGrant,
    access: &str,
    refresh: &str,
    expires_at: Option<u64>,
) -> io::Result<Committed> {
    let stream = grant.lease.as_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth grant has no refresh lease",
        )
    })?;
    let response: CommitResponse = broker_exchange(
        stream,
        &BrokerRequest::Commit {
            grant_id: &grant.config.grant_id,
            generation: grant.generation,
            access,
            refresh,
            expires_at,
        },
    )
    .await?;
    if !response.ok || response.conflict {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OAuth broker commit conflict",
        ));
    }
    let generation = response.generation.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth broker omitted generation",
        )
    })?;
    Ok(Committed {
        generation,
        access_sentinel: response.access_sentinel,
        refresh_sentinel: response.refresh_sentinel,
    })
}

async fn broker_call<T: for<'de> Deserialize<'de>>(
    endpoint: &str,
    request: &BrokerRequest<'_>,
) -> io::Result<T> {
    let mut stream = broker_connect(endpoint, request).await?;
    broker_read(&mut stream).await
}

async fn broker_connect(endpoint: &str, request: &BrokerRequest<'_>) -> io::Result<UnixStream> {
    tokio::time::timeout(BROKER_TIMEOUT, async {
        let mut stream = UnixStream::connect(endpoint).await?;
        broker_write(&mut stream, request).await?;
        Ok::<_, io::Error>(stream)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "OAuth broker timed out"))?
}

async fn broker_exchange<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
    request: &BrokerRequest<'_>,
) -> io::Result<T> {
    tokio::time::timeout(BROKER_TIMEOUT, async {
        broker_write(stream, request).await?;
        broker_read(stream).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "OAuth broker timed out"))?
}

async fn broker_write(stream: &mut UnixStream, request: &BrokerRequest<'_>) -> io::Result<()> {
    let mut line = serde_json::to_vec(request).map_err(io::Error::other)?;
    line.push(b'\n');
    stream.write_all(&line).await
}

async fn broker_read<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> io::Result<T> {
    let response = tokio::time::timeout(BROKER_TIMEOUT, async {
        let mut response = String::new();
        BufReader::new(&mut *stream)
            .take(MAX_BROKER_RESPONSE_BYTES + 1)
            .read_line(&mut response)
            .await?;
        Ok::<_, io::Error>(response)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "OAuth broker timed out"))??;
    parse_broker_response(&response)
}

fn parse_broker_response<T: for<'de> Deserialize<'de>>(response: &str) -> io::Result<T> {
    if response.len() as u64 > MAX_BROKER_RESPONSE_BYTES || !response.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid OAuth broker response",
        ));
    }
    serde_json::from_str(response).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed OAuth broker response",
        )
    })
}

/// Classify a poll (RFC 8628) response body.
///
/// Secret material outranks the waiting set: only a body that carries none of
/// the fields this grant treats as secret is ever forwarded to the guest as it
/// arrived, so a waiting error cannot smuggle a token past sanitizing.
fn poll_outcome(status: u16, body: &[u8], config: &OAuthSecret) -> PollOutcome {
    let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(body) else {
        return PollOutcome::Failed;
    };
    let has_string = |field: &str| object.get(field).and_then(Value::as_str).is_some();
    let success = (200..300).contains(&status);
    if has_string(&config.access_token_field) || has_string(&config.refresh_token_field) {
        return if success {
            PollOutcome::Granted
        } else {
            PollOutcome::Failed
        };
    }
    if config
        .poll_secret_fields
        .iter()
        .any(|field| has_string(field))
    {
        return if success {
            PollOutcome::Secrets
        } else {
            PollOutcome::Failed
        };
    }
    // GitHub answers a pending poll with HTTP 200 and RFC 8628 answers it with
    // 400, so the body decides, not the status.
    if let Some(error) = object.get("error").and_then(Value::as_str)
        && POLL_WAITING_ERRORS.contains(&error)
    {
        return PollOutcome::Waiting;
    }
    PollOutcome::Failed
}

fn parse_https_endpoint(endpoint: &str) -> io::Result<Endpoint> {
    let rest = endpoint.strip_prefix("https://").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "OAuth endpoint is not HTTPS")
    })?;
    let (authority, target) = rest
        .split_once('/')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "OAuth endpoint has no path"))?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid OAuth endpoint port")
            })?,
        ),
        None => (authority, 443),
    };
    if host.is_empty() || authority.contains('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid OAuth endpoint authority",
        ));
    }
    Ok(Endpoint {
        host: host.to_ascii_lowercase(),
        port,
        target: format!("/{target}"),
    })
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn replace_same_length(data: &[u8], token: &[u8]) -> Vec<u8> {
    if token.is_empty() {
        return data.to_vec();
    }
    let replacement = vec![b'*'; token.len()];
    replace_all(data, token, &replacement)
}

/// Replace a sentinel that stands alone as an `Authorization: Bearer` value.
///
/// The header name and scheme are matched case-insensitively, as HTTP defines
/// them, but the sentinel itself is matched byte for byte: a JWT-shaped
/// sentinel is base64url, where case is significant.
fn replace_bearer_header(data: &[u8], sentinel: &[u8], token: &[u8]) -> Vec<u8> {
    const MARKER: &[u8] = b"authorization: bearer ";
    if sentinel.is_empty() || data.len() < MARKER.len() {
        return data.to_vec();
    }
    let lower = data.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    let mut searched = 0;
    while let Some(offset) = lower[searched..]
        .windows(MARKER.len())
        .position(|window| window == MARKER)
    {
        let value_start = searched + offset + MARKER.len();
        let value_end = value_start + sentinel.len();
        if data.len() >= value_end && &data[value_start..value_end] == sentinel {
            let mut output = data.to_vec();
            output.splice(value_start..value_end, token.iter().copied());
            return output;
        }
        searched = value_start;
        if searched + MARKER.len() > lower.len() {
            break;
        }
    }
    data.to_vec()
}

fn response_body_state(headers: &[u8], head_response: bool) -> io::Result<ResponseScrubState> {
    let text = std::str::from_utf8(headers).map_err(|_| invalid_http())?;
    if !first_header_line(headers)?.starts_with("HTTP/1.1 ") {
        return Err(invalid_http());
    }
    let status = response_status(headers)?;
    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut content_encoding = None;
    for (name, value) in text.lines().filter_map(|line| line.split_once(':')) {
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(invalid_http());
            }
            content_length = Some(value.trim().parse::<usize>().map_err(|_| invalid_http())?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(invalid_http());
            }
            transfer_encoding = Some(value.trim());
        } else if name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding.is_some() {
                return Err(invalid_http());
            }
            content_encoding = Some(value.trim());
        }
    }
    if content_encoding.is_some_and(|encoding| !encoding.eq_ignore_ascii_case("identity")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encoded OAuth responses are unsupported",
        ));
    }
    if transfer_encoding.is_some() && content_length.is_some() {
        return Err(invalid_http());
    }
    if head_response || (100..200).contains(&status) || matches!(status, 204 | 304) {
        return Ok(ResponseScrubState::ContentLength(0));
    }
    match (transfer_encoding, content_length) {
        (Some(encoding), None) if encoding.eq_ignore_ascii_case("chunked") => {
            Ok(ResponseScrubState::ChunkSize)
        }
        (Some(_), None) => Err(invalid_http()),
        (None, Some(length)) => Ok(ResponseScrubState::ContentLength(length)),
        (None, None) => Ok(ResponseScrubState::CloseDelimited),
        (Some(_), Some(_)) => Err(invalid_http()),
    }
}

fn parse_chunk_size(line: &[u8]) -> io::Result<usize> {
    let text = std::str::from_utf8(line).map_err(|_| invalid_http())?;
    let size = text
        .strip_suffix("\r\n")
        .and_then(|line| line.split(';').next())
        .ok_or_else(invalid_http)?;
    usize::from_str_radix(size.trim(), 16).map_err(|_| invalid_http())
}

fn header_boundary(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|boundary| boundary + 4)
}

fn line_boundary(data: &[u8]) -> Option<usize> {
    data.windows(2)
        .position(|window| window == b"\r\n")
        .map(|boundary| boundary + 2)
}

fn parse_token_response(data: &[u8]) -> io::Result<Option<HttpMessage<'_>>> {
    let Some(header_end) = header_boundary(data) else {
        return Ok(None);
    };
    let headers = &data[..header_end];
    let text = std::str::from_utf8(headers).map_err(|_| invalid_http())?;
    let mut content_encoding = None;
    let mut transfer_encoding = None;
    let mut content_length = None;
    for (name, value) in text.lines().filter_map(|line| line.split_once(':')) {
        if name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding.replace(value.trim()).is_some() {
                return Err(invalid_http());
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.replace(value.trim()).is_some() {
                return Err(invalid_http());
            }
        } else if name.eq_ignore_ascii_case("content-length")
            && content_length
                .replace(value.trim().parse::<usize>().map_err(|_| invalid_http())?)
                .is_some()
        {
            return Err(invalid_http());
        }
    }
    if content_encoding.is_some_and(|encoding| !encoding.eq_ignore_ascii_case("identity")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encoded OAuth responses are unsupported",
        ));
    }
    if transfer_encoding.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth token response transfer encoding is unsupported",
        ));
    }
    let content_length = content_length.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth token response requires Content-Length",
        )
    })?;
    let total_len = header_end
        .checked_add(content_length)
        .ok_or_else(invalid_http)?;
    if total_len > MAX_OAUTH_MESSAGE_BYTES {
        return Err(invalid_http());
    }
    if data.len() < total_len {
        return Ok(None);
    }
    Ok(Some(HttpMessage {
        headers,
        body: &data[header_end..total_len],
        total_len,
    }))
}

fn request_body_framing(headers: &[u8]) -> io::Result<RequestBodyFraming> {
    let text = std::str::from_utf8(headers).map_err(|_| invalid_http())?;
    let mut content_length = None;
    let mut transfer_encoding = None;
    for (name, value) in text.lines().filter_map(|line| line.split_once(':')) {
        if name.eq_ignore_ascii_case("content-length") {
            if content_length
                .replace(value.trim().parse::<usize>().map_err(|_| invalid_http())?)
                .is_some()
            {
                return Err(invalid_http());
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && transfer_encoding.replace(value.trim()).is_some()
        {
            return Err(invalid_http());
        }
    }
    if transfer_encoding.is_some() && content_length.is_some() {
        return Err(invalid_http());
    }
    match (transfer_encoding, content_length) {
        (Some(encoding), None) if encoding.eq_ignore_ascii_case("chunked") => {
            Ok(RequestBodyFraming::Chunked)
        }
        (Some(_), None) => Err(invalid_http()),
        (None, Some(length)) => Ok(RequestBodyFraming::ContentLength(length)),
        (None, None) => Ok(RequestBodyFraming::None),
        (Some(_), Some(_)) => Err(invalid_http()),
    }
}

fn remove_header(headers: &[u8], removed_name: &str) -> io::Result<Vec<u8>> {
    let boundary = header_boundary(headers).ok_or_else(invalid_http)?;
    let text = std::str::from_utf8(&headers[..boundary]).map_err(|_| invalid_http())?;
    let mut output = Vec::with_capacity(headers.len());
    for line in text.trim_end_matches("\r\n\r\n").split("\r\n") {
        if line
            .split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case(removed_name))
        {
            continue;
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&headers[boundary..]);
    Ok(output)
}

fn validate_token_request_content_type(headers: &[u8]) -> io::Result<()> {
    let text = std::str::from_utf8(headers).map_err(|_| invalid_http())?;
    reject_expect_100_continue(headers)?;
    let supported = text.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && matches!(
                    value.trim().split(';').next().unwrap_or_default(),
                    "application/json" | "application/x-www-form-urlencoded"
                )
        })
    });
    supported.then_some(()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported OAuth request content type",
        )
    })
}

fn reject_expect_100_continue(headers: &[u8]) -> io::Result<()> {
    let text = std::str::from_utf8(headers).map_err(|_| invalid_http())?;
    if text.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("expect") && value.trim().eq_ignore_ascii_case("100-continue")
        })
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth Expect: 100-continue is unsupported",
        ));
    }
    Ok(())
}

fn reject_protocol_upgrade(headers: &[u8]) -> io::Result<()> {
    let text = std::str::from_utf8(headers).map_err(|_| invalid_http())?;
    let upgrade = text.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("upgrade")
                || name.eq_ignore_ascii_case("connection")
                    && value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    });
    if upgrade {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth API protocol upgrades are unsupported",
        ));
    }
    Ok(())
}

fn response_status(headers: &[u8]) -> io::Result<u16> {
    let status = first_header_line(headers)?
        .split_whitespace()
        .nth(1)
        .ok_or_else(invalid_http)?
        .parse::<u16>()
        .map_err(|_| invalid_http())?;
    Ok(status)
}

fn first_header_line(headers: &[u8]) -> io::Result<&str> {
    std::str::from_utf8(headers)
        .map_err(|_| invalid_http())?
        .split("\r\n")
        .next()
        .ok_or_else(invalid_http)
}

fn rebuild_message(headers: &[u8], body: &[u8]) -> io::Result<Vec<u8>> {
    let text = std::str::from_utf8(headers).map_err(|_| invalid_http())?;
    let mut output = String::new();
    for line in text.trim_end_matches("\r\n\r\n").split("\r\n") {
        if line
            .split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        {
            output.push_str(&format!("Content-Length: {}\r\n", body.len()));
        } else {
            output.push_str(line);
            output.push_str("\r\n");
        }
    }
    output.push_str("\r\n");
    let mut bytes = output.into_bytes();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

fn update_content_length(message: &[u8]) -> io::Result<Vec<u8>> {
    let boundary = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(invalid_http)?
        + 4;
    rebuild_message(&message[..boundary], &message[boundary..])
}

fn replace_all(input: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return input.to_vec();
    }
    let mut output = Vec::with_capacity(input.len());
    let mut remaining = input;
    while let Some(index) = remaining
        .windows(needle.len())
        .position(|window| window == needle)
    {
        output.extend_from_slice(&remaining[..index]);
        output.extend_from_slice(replacement);
        remaining = &remaining[index + needle.len()..];
    }
    output.extend_from_slice(remaining);
    output
}

fn enforce_limit(buffer: &[u8]) -> io::Result<()> {
    if buffer.len() > MAX_OAUTH_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth HTTP message exceeds limit",
        ));
    }
    Ok(())
}

fn extend_response_scrub_framing(buffer: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
    let length = buffer
        .len()
        .checked_add(data.len())
        .ok_or_else(invalid_http)?;
    if length > MAX_RESPONSE_SCRUB_FRAMING_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth response scrub framing exceeds limit",
        ));
    }
    buffer.extend_from_slice(data);
    Ok(())
}

fn invalid_http() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid OAuth HTTP/1 message")
}

fn random_sentinel(kind: &str) -> String {
    let random: [u8; 16] = rand::random();
    let hex = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("$MSB_OAUTH_{kind}_{hex}")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use tokio::net::UnixListener;

    use super::*;
    use crate::secrets::config::HostPattern;

    fn config() -> OAuthSecret {
        OAuthSecret {
            broker_endpoint: "/tmp/broker.sock".into(),
            grant_id: "opaque-grant".into(),
            token_endpoint: "https://auth.example.com/oauth/token".into(),
            device_code_endpoint: None,
            poll_endpoint: None,
            poll_secret_fields: vec![],
            inject_hosts: vec![HostPattern::Exact("api.example.com".into())],
            access_token_field: "access_token".into(),
            refresh_token_field: "refresh_token".into(),
            access_env_var: "ACCESS_TOKEN".into(),
            refresh_env_var: "REFRESH_TOKEN".into(),
            access_sentinel: "$MSB_OAUTH_ACCESS_123".into(),
            refresh_sentinel: "$MSB_OAUTH_REFRESH_123".into(),
        }
    }

    fn connection() -> OAuthConnection {
        connection_for(vec![config()])
    }

    struct BrokerState {
        access: String,
        refresh: String,
        generation: u64,
        commits: Vec<Value>,
        /// Sentinels reported on `load` and `acquire`, when the broker mints
        /// them rather than leaving the configured ones in place.
        sentinels: Option<(String, String)>,
        /// Sentinels the next `commit` mints for the tokens it stores.
        commit_sentinels: Option<(String, String)>,
    }

    /// A JWT-shaped sentinel: a real header and payload, a random signature.
    const JWT_ACCESS_SENTINEL: &str = concat!(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.",
        "eyJzdWIiOiJhY2N0XzEyMyIsImV4cCI6MjUzMzcwNzY0ODAwfQ.",
        "c2VudGluZWwtc2lnbmF0dXJlLXJhbmRvbQ"
    );

    const JWT_REFRESH_SENTINEL: &str = concat!(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.",
        "eyJzdWIiOiJhY2N0XzEyMyIsInR5cCI6InJlZnJlc2gifQ.",
        "YW5vdGhlci1yYW5kb20tc2lnbmF0dXJl"
    );

    /// A stand-in host broker: it answers `load` and `acquire` with the grant
    /// it currently holds, and records every `commit`.
    struct FakeBroker {
        socket: PathBuf,
        state: Arc<std::sync::Mutex<BrokerState>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl FakeBroker {
        fn commits(&self) -> Vec<Value> {
            self.state.lock().unwrap().commits.clone()
        }

        /// Answer `load` and `acquire` with these sentinels.
        fn set_sentinels(&self, access: &str, refresh: &str) {
            self.state.lock().unwrap().sentinels = Some((access.into(), refresh.into()));
        }

        /// Mint these sentinels on the next `commit`, and report them from
        /// then on, the way a broker that copies the new token's claims does.
        fn set_commit_sentinels(&self, access: &str, refresh: &str) {
            self.state.lock().unwrap().commit_sentinels = Some((access.into(), refresh.into()));
        }
    }

    impl Drop for FakeBroker {
        fn drop(&mut self) {
            self.task.abort();
            std::fs::remove_file(&self.socket).ok();
        }
    }

    fn start_broker(access: &str, refresh: &str) -> FakeBroker {
        let socket = std::env::temp_dir().join(format!(
            "msb-oauth-device-{}-{}.sock",
            std::process::id(),
            rand::random::<u64>()
        ));
        let listener = UnixListener::bind(&socket).unwrap();
        let state = Arc::new(std::sync::Mutex::new(BrokerState {
            access: access.into(),
            refresh: refresh.into(),
            generation: 7,
            commits: Vec::new(),
            sentinels: None,
            commit_sentinels: None,
        }));
        let task = tokio::spawn({
            let state = Arc::clone(&state);
            async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let mut stream = BufReader::new(stream);
                        let mut line = String::new();
                        while stream.read_line(&mut line).await.unwrap() > 0 {
                            let request: Value = serde_json::from_str(&line).unwrap();
                            line.clear();
                            let reply = {
                                let mut state = state.lock().unwrap();
                                match request["action"].as_str().unwrap() {
                                    "load" | "acquire" => {
                                        let mut reply = serde_json::json!({
                                            "access": state.access,
                                            "refresh": state.refresh,
                                            "generation": state.generation,
                                        });
                                        if let Some((access, refresh)) = state.sentinels.clone() {
                                            reply["access_sentinel"] = access.into();
                                            reply["refresh_sentinel"] = refresh.into();
                                        }
                                        reply
                                    }
                                    "commit" => {
                                        assert_eq!(request["generation"], state.generation);
                                        state.access =
                                            request["access"].as_str().unwrap().to_string();
                                        state.refresh =
                                            request["refresh"].as_str().unwrap().to_string();
                                        state.generation += 1;
                                        let generation = state.generation;
                                        state.commits.push(request);
                                        let mut reply = serde_json::json!({"ok": true, "generation": generation});
                                        if let Some((access, refresh)) =
                                            state.commit_sentinels.take()
                                        {
                                            state.sentinels =
                                                Some((access.clone(), refresh.clone()));
                                            reply["access_sentinel"] = access.into();
                                            reply["refresh_sentinel"] = refresh.into();
                                        }
                                        reply
                                    }
                                    other => panic!("unexpected broker action {other}"),
                                }
                            };
                            let mut bytes = serde_json::to_vec(&reply).unwrap();
                            bytes.push(b'\n');
                            stream.get_mut().write_all(&bytes).await.unwrap();
                        }
                    });
                }
            }
        });
        FakeBroker {
            socket,
            state,
            task,
        }
    }

    fn broker_config(broker: &FakeBroker) -> OAuthSecret {
        let mut config = config();
        config.broker_endpoint = broker.socket.to_string_lossy().into_owned();
        config
    }

    fn json_request(target: &str, body: &str) -> String {
        format!(
            "POST {target} HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn form_request(target: &str, body: &str) -> String {
        format!(
            "POST {target} HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn json_response(status: u16, body: &str) -> String {
        let reason = if (200..300).contains(&status) {
            "OK"
        } else {
            "Bad Request"
        };
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn loaded(config: OAuthSecret) -> LoadedGrant {
        let token = parse_https_endpoint(&config.token_endpoint).unwrap();
        let device_code = config
            .device_code_endpoint
            .as_deref()
            .map(|endpoint| parse_https_endpoint(endpoint).unwrap());
        let poll = config
            .poll_endpoint
            .as_deref()
            .map(|endpoint| parse_https_endpoint(endpoint).unwrap());
        LoadedGrant {
            token,
            device_code,
            poll,
            access: Zeroizing::new("real-access".into()),
            refresh: Zeroizing::new("real-refresh".into()),
            access_sentinel: config.access_sentinel.clone(),
            refresh_sentinel: config.refresh_sentinel.clone(),
            config,
            generation: 4,
            lease: None,
            poll_secrets: Vec::new(),
        }
    }

    fn connection_for(configs: Vec<OAuthSecret>) -> OAuthConnection {
        OAuthConnection {
            grants: configs.into_iter().map(loaded).collect(),
            request_buffer: vec![],
            response_buffer: vec![],
            exchanges: VecDeque::new(),
            token_connection: None,
            connection_port: 443,
            response_scrub_buffer: Vec::new(),
            response_scrub_framing: Vec::new(),
            response_scrub_tail: Vec::new(),
            response_scrub_state: ResponseScrubState::Headers,
            response_head_requests: VecDeque::new(),
            seen_tokens: vec![
                Zeroizing::new("real-access".into()),
                Zeroizing::new("real-refresh".into()),
            ],
            request_state: RequestState::Headers,
        }
    }

    #[tokio::test]
    async fn substitutes_access_only_on_inject_host() {
        let socket = std::env::temp_dir().join(format!(
            "msb-oauth-load-{}-{}.sock",
            std::process::id(),
            rand::random::<u64>()
        ));
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = tokio::spawn(async move {
            for _ in 0..1 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                stream
                    .get_mut()
                    .write_all(
                        b"{\"access\":\"real-access\",\"refresh\":\"real-refresh\",\"generation\":4}\n",
                    )
                    .await
                    .unwrap();
            }
        });
        let request = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nAccept-Encoding: gzip\r\nAuthorization: Bearer $MSB_OAUTH_ACCESS_123\r\n\r\n";
        let mut allowed = connection();
        allowed.token_connection = None;
        allowed.grants[0].config.broker_endpoint = socket.to_string_lossy().into_owned();
        let output = allowed
            .transform_requests(request, "api.example.com")
            .await
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Bearer real-access"));
        assert!(!output.to_ascii_lowercase().contains("accept-encoding"));

        let mut denied = connection();
        denied.token_connection = None;
        denied.grants[0].config.broker_endpoint = socket.to_string_lossy().into_owned();
        let output = denied
            .transform_requests(request, "evil.example.com")
            .await
            .unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("$MSB_OAUTH_ACCESS_123")
        );
        broker.await.unwrap();
        std::fs::remove_file(socket).ok();
    }

    #[tokio::test]
    async fn token_json_request_replaces_both_sentinels_and_length() {
        let body = r#"{"access":"$MSB_OAUTH_ACCESS_123","refresh":"$MSB_OAUTH_REFRESH_123"}"#;
        let request = format!(
            "POST /oauth/token HTTP/1.1\r\nHost: auth.example.com\r\nAccept-Encoding: gzip\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut connection = connection();
        connection.grants[0].lease = Some(UnixStream::pair().unwrap().0);
        let output = connection
            .transform_requests(request.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("real-access"));
        assert!(output.contains("real-refresh"));
        assert!(!output.contains("$MSB_OAUTH_"));
        assert!(!output.to_ascii_lowercase().contains("accept-encoding"));
    }

    #[tokio::test]
    async fn token_form_request_replaces_refresh_sentinel() {
        let body = "grant_type=refresh_token&refresh_token=$MSB_OAUTH_REFRESH_123";
        let request = format!(
            "POST /oauth/token HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut connection = connection();
        connection.grants[0].lease = Some(UnixStream::pair().unwrap().0);
        let output = connection
            .transform_requests(request.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("refresh_token=real-refresh")
        );
    }

    #[tokio::test]
    async fn second_token_request_in_one_buffer_is_rejected() {
        let body = "refresh_token=$MSB_OAUTH_REFRESH_123";
        let request = format!(
            "POST /oauth/token HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut connection = connection();
        connection.grants[0].lease = Some(UnixStream::pair().unwrap().0);
        let error = connection
            .transform_requests(format!("{request}{request}").as_bytes(), "auth.example.com")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn api_keep_alive_does_not_wait_for_response_parsing() {
        let request = b"GET /v1 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let mut connection = connection();
        connection.token_connection = None;
        let output = connection
            .transform_requests(
                &[request.as_slice(), request.as_slice()].concat(),
                "other.example.com",
            )
            .await
            .unwrap();
        assert_eq!(output.len(), request.len() * 2);
        assert!(connection.exchanges.is_empty());
    }

    #[tokio::test]
    async fn api_request_metadata_is_bounded_before_forwarding() {
        let mut connection = connection();
        connection
            .response_head_requests
            .resize(MAX_OUTSTANDING_API_REQUESTS, false);

        let error = connection
            .transform_requests(
                b"GET /v1 HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
                "api.example.com",
            )
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "too many outstanding OAuth API requests");
        assert_eq!(
            connection.response_head_requests.len(),
            MAX_OUTSTANDING_API_REQUESTS
        );
    }

    #[tokio::test]
    async fn content_length_api_request_streams_after_headers() {
        let mut connection = connection();
        let headers = b"POST /v1 HTTP/1.1\r\nContent-Length: 5\r\nAccept-Encoding: br\r\n\r\n";

        let first = connection
            .transform_requests(headers, "other.example.com")
            .await
            .unwrap();
        let second = connection
            .transform_requests(b"hello", "other.example.com")
            .await
            .unwrap();

        assert_eq!(first, b"POST /v1 HTTP/1.1\r\nContent-Length: 5\r\n\r\n");
        assert_eq!(second, b"hello");
    }

    #[tokio::test]
    async fn chunked_api_request_streams_and_preserves_keep_alive() {
        let mut connection = connection();
        let first = connection
            .transform_requests(
                b"POST /v1 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\nte",
                "other.example.com",
            )
            .await
            .unwrap();
        let second = connection
            .transform_requests(
                b"st\r\n0\r\nX-End: yes\r\n\r\nGET /next HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
                "other.example.com",
            )
            .await
            .unwrap();

        assert_eq!(
            [first, second].concat(),
            b"POST /v1 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=bar\r\ntest\r\n0\r\nX-End: yes\r\n\r\nGET /next HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn expect_continue_api_request_forwards_headers_before_body() {
        let mut connection = connection();
        let headers = b"POST /v1 HTTP/1.1\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n";

        let output = connection
            .transform_requests(headers, "other.example.com")
            .await
            .unwrap();

        assert_eq!(output, headers);
        assert_eq!(
            connection
                .transform_requests(b"body", "other.example.com")
                .await
                .unwrap(),
            b"body"
        );
    }

    #[tokio::test]
    async fn api_protocol_upgrade_requests_are_rejected_before_forwarding() {
        for request in [
            b"GET /v1 HTTP/1.1\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /v1 HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\n\r\n".as_slice(),
        ] {
            let mut connection = connection();
            let error = connection
                .transform_requests(request, "api.example.com")
                .await
                .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "OAuth API protocol upgrades are unsupported"
            );
            assert!(connection.response_head_requests.is_empty());
        }
    }

    #[tokio::test]
    async fn chunked_token_request_is_rejected_after_headers() {
        let mut connection = connection();
        let error = connection
            .transform_requests(
                b"POST /oauth/token HTTP/1.1\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
                "auth.example.com",
            )
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "OAuth token endpoint chunked requests are unsupported"
        );
    }

    #[tokio::test]
    async fn token_endpoint_rejects_head_requests() {
        let mut connection = connection();
        let error = connection
            .transform_requests(
                b"HEAD /oauth/token HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
                "auth.example.com",
            )
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "OAuth token endpoint requests must use POST"
        );
    }

    #[tokio::test]
    async fn api_then_token_request_fails_closed() {
        let mut connection = connection();
        connection
            .transform_requests(
                b"GET /v1 HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
                "auth.example.com",
            )
            .await
            .unwrap();

        let error = connection
            .transform_requests(
                b"POST /oauth/token HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                "auth.example.com",
            )
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "mixing OAuth API and token requests on one connection is unsupported"
        );
    }

    #[tokio::test]
    async fn exact_token_endpoint_does_not_match_other_path() {
        let request = b"POST /oauth/token/other HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let mut connection = connection();
        let output = connection
            .transform_requests(request, "auth.example.com")
            .await
            .unwrap();
        assert_eq!(output, request);
        assert_eq!(connection.token_connection, Some(false));
    }

    #[tokio::test]
    async fn exact_token_endpoint_does_not_match_other_port() {
        let request = b"POST /oauth/token HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let mut connection = connection();
        connection.connection_port = 8443;
        let output = connection
            .transform_requests(request, "auth.example.com")
            .await
            .unwrap();
        assert_eq!(output, request);
        assert_eq!(connection.token_connection, Some(false));
    }

    #[test]
    fn response_rebuild_preserves_unrelated_json() {
        let headers =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n";
        let body = br#"{"access_token":"secret","refresh_token":"refresh","scope":"read","expires_in":3600}"#;
        let mut json: Value = serde_json::from_slice(body).unwrap();
        let object = json.as_object_mut().unwrap();
        object.insert("access_token".into(), Value::String("ACCESS".into()));
        object.insert("refresh_token".into(), Value::String("REFRESH".into()));
        let rebuilt = rebuild_message(headers, &serde_json::to_vec(&json).unwrap()).unwrap();
        let parsed = parse_token_response(&rebuilt).unwrap().unwrap();
        let output: Value = serde_json::from_slice(parsed.body).unwrap();
        assert_eq!(output["scope"], "read");
        assert_eq!(output["expires_in"], 3600);
        assert_eq!(output["access_token"], "ACCESS");
    }

    #[test]
    fn endpoint_parser_requires_https_and_preserves_exact_target() {
        let endpoint = parse_https_endpoint("https://auth.example.com/oauth/token?aud=x").unwrap();
        assert!(endpoint.matches("auth.example.com", 443, "/oauth/token?aud=x"));
        assert!(!endpoint.matches("auth.example.com", 443, "/oauth/token"));
        let endpoint = parse_https_endpoint("https://auth.example.com:8443/oauth/token").unwrap();
        assert!(endpoint.matches("AUTH.example.com", 8443, "/oauth/token"));
        assert!(!endpoint.matches("auth.example.com", 443, "/oauth/token"));
        assert!(parse_https_endpoint("http://auth.example.com/token").is_err());
    }

    #[test]
    fn omitted_sentinels_are_independent() {
        let mut oauth = config();
        oauth.access_sentinel.clear();
        oauth.refresh_sentinel.clear();
        ensure_sentinels(&mut oauth);
        assert!(oauth.access_sentinel.starts_with("$MSB_OAUTH_ACCESS_"));
        assert!(oauth.refresh_sentinel.starts_with("$MSB_OAUTH_REFRESH_"));
        assert_ne!(oauth.access_sentinel, oauth.refresh_sentinel);
    }

    #[tokio::test]
    async fn broker_load_commit_and_response_rewrite_never_release_tokens() {
        let socket = std::env::temp_dir().join(format!(
            "msb-oauth-broker-{}-{}.sock",
            std::process::id(),
            rand::random::<u64>()
        ));
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut line = String::new();
            let mut stream = BufReader::new(stream);
            stream.read_line(&mut line).await.unwrap();
            let load: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(
                load,
                serde_json::json!({"action":"load","grant_id":"opaque-grant"})
            );
            stream
                .get_mut()
                .write_all(
                    b"{\"access\":\"old-access\",\"refresh\":\"old-refresh\",\"generation\":7}\n",
                )
                .await
                .unwrap();

            let (stream, _) = listener.accept().await.unwrap();
            line.clear();
            let mut stream = BufReader::new(stream);
            stream.read_line(&mut line).await.unwrap();
            let acquire: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(
                acquire,
                serde_json::json!({"action":"acquire","grant_id":"opaque-grant"})
            );
            stream
                .get_mut()
                .write_all(
                    b"{\"access\":\"old-access\",\"refresh\":\"old-refresh\",\"generation\":7}\n",
                )
                .await
                .unwrap();
            line.clear();
            stream.read_line(&mut line).await.unwrap();
            let commit: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(commit["action"], "commit");
            assert_eq!(commit["grant_id"], "opaque-grant");
            assert_eq!(commit["generation"], 7);
            assert_eq!(commit["access"], "new-access");
            assert_eq!(commit["refresh"], "new-refresh");
            stream
                .get_mut()
                .write_all(b"{\"ok\":true,\"generation\":8}\n")
                .await
                .unwrap();
        });

        let mut oauth = config();
        oauth.broker_endpoint = socket.to_string_lossy().into_owned();
        let mut connection = OAuthConnection::new(&[oauth], "auth.example.com", 443, None)
            .await
            .unwrap();
        let request_body = "refresh_token=$MSB_OAUTH_REFRESH_123";
        let request = format!(
            "POST /oauth/token HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{request_body}",
            request_body.len()
        );
        let upstream = connection
            .transform_requests(request.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        assert!(String::from_utf8(upstream).unwrap().contains("old-refresh"));

        let body = r#"{"access_token":"new-access","refresh_token":"new-refresh","scope":"read","expires_in":3600}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let guest = connection
            .transform_responses(response.as_bytes())
            .await
            .unwrap();
        let guest = String::from_utf8(guest).unwrap();
        assert!(guest.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(guest.contains("$MSB_OAUTH_REFRESH_123"));
        assert!(guest.contains("\"scope\":\"read\""));
        assert!(!guest.contains("new-access"));
        assert!(!guest.contains("new-refresh"));
        broker.await.unwrap();
        std::fs::remove_file(socket).ok();
    }

    #[tokio::test]
    async fn malformed_success_fails_closed_without_output() {
        let mut connection = connection();
        connection.exchanges.push_back(Exchange::Token {
            grant: 0,
            poll: false,
        });
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnot-json";
        assert!(connection.transform_responses(response).await.is_err());
    }

    #[tokio::test]
    async fn non_object_token_errors_fail_closed_without_output() {
        for body in ["not-json", r#""credential""#, r#"["credential"]"#] {
            let mut connection = connection();
            connection.exchanges.push_back(Exchange::Token {
                grant: 0,
                poll: false,
            });
            let response = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );

            let error = connection
                .transform_responses(response.as_bytes())
                .await
                .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn token_responses_require_identity_content_length_framing() {
        let chunked = "HTTP/1.1 400 Bad Request\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let unframed = "HTTP/1.1 400 Bad Request\r\n\r\nsecret";
        let encoded = concat!(
            "HTTP/1.1 400 Bad Request\r\n",
            "Content-Encoding: gzip\r\n",
            "Content-Length: 6\r\n\r\nsecret"
        );
        for response in [chunked, unframed, encoded] {
            let mut connection = connection();
            connection.token_connection = Some(true);
            connection.exchanges.push_back(Exchange::Token {
                grant: 0,
                poll: false,
            });
            assert!(
                connection
                    .transform_responses(response.as_bytes())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn eof_with_buffered_token_response_fails_closed() {
        let mut connection = connection();
        connection.token_connection = Some(true);
        connection.exchanges.push_back(Exchange::Token {
            grant: 0,
            poll: false,
        });
        assert!(
            connection
                .transform_responses(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nreal-access"
                )
                .await
                .is_ok()
        );

        let error = connection.finish_response_scrubbing().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn error_response_token_fields_are_never_released() {
        let mut connection = connection();
        let headers = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n";
        let body = br#"{"error":"invalid_grant","access_token":"novel-access","refresh_token":"novel-refresh","error_description":"real-access and real-refresh","error_uri":"https://auth.example.com/errors/invalid-grant","retry_after":30,"nested":{"access":"real-access"}}"#;
        let output = connection.sanitize_token_error(0, headers, body).unwrap();
        let message = parse_token_response(&output).unwrap().unwrap();
        let json: Value = serde_json::from_slice(message.body).unwrap();
        assert_eq!(json["error"], "invalid_grant");
        assert_eq!(json["access_token"], "$MSB_OAUTH_ACCESS_123");
        assert_eq!(json["refresh_token"], "$MSB_OAUTH_REFRESH_123");
        assert_eq!(
            json["error_uri"],
            "https://auth.example.com/errors/invalid-grant"
        );
        assert_eq!(json["retry_after"], 30);
        assert_eq!(json["error_description"], "*********** and ************");
        assert_eq!(json["nested"]["access"], "***********");
    }

    #[test]
    fn api_response_echoes_are_scrubbed() {
        let mut connection = connection();
        let input =
            b"HTTP/1.1 200 OK\r\nContent-Length: 35\r\n\r\nechoed real-access and real-refresh";
        let mut output = connection
            .scrub_response_chunk(b"HTTP/1.1 200 OK\r\nContent-Length: 35\r\n\r\nechoed real-ac")
            .unwrap();
        output.extend(
            connection
                .scrub_response_chunk(b"cess and real-refresh")
                .unwrap(),
        );
        assert_eq!(output.len(), input.len());
        assert!(connection.finish_response_scrubbing().unwrap().is_empty());
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("***********"));
        assert!(output.contains("************"));
        assert!(!output.contains("real-access"));
        assert!(!output.contains("real-refresh"));
    }

    #[tokio::test]
    async fn failed_refresh_releases_lease() {
        let mut connection = connection();
        connection.grants[0].lease = Some(UnixStream::pair().unwrap().0);
        connection.exchanges.push_back(Exchange::Token {
            grant: 0,
            poll: false,
        });
        let body = r#"{"error":"invalid_grant"}"#;
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        connection
            .transform_responses(response.as_bytes())
            .await
            .unwrap();
        assert!(connection.grants[0].lease.is_none());
    }

    #[tokio::test]
    async fn shared_endpoint_selects_the_grant_whose_sentinel_is_present() {
        let first = config();
        let mut second = config();
        second.grant_id = "other-grant".into();
        second.access_sentinel = "$OTHER_ACCESS".into();
        second.refresh_sentinel = "$OTHER_REFRESH".into();
        let mut connection = connection_for(vec![first, second]);
        connection.grants[1].lease = Some(UnixStream::pair().unwrap().0);
        let body = "refresh_token=$OTHER_REFRESH";
        let request = format!(
            "POST /oauth/token HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let output = connection
            .transform_requests(request.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        assert!(String::from_utf8(output).unwrap().contains("real-refresh"));
        assert!(matches!(
            connection.exchanges.pop_front(),
            Some(Exchange::Token {
                grant: 1,
                poll: false
            })
        ));
    }

    #[tokio::test]
    async fn shared_endpoint_without_a_sentinel_is_rejected() {
        let first = config();
        let mut second = config();
        second.grant_id = "other-grant".into();
        second.access_sentinel = "$OTHER_ACCESS".into();
        second.refresh_sentinel = "$OTHER_REFRESH".into();
        let mut connection = connection_for(vec![first, second]);
        connection.seen_tokens.clear();
        let request = b"POST /oauth/token HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";

        let error = connection
            .transform_requests(request, "auth.example.com")
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(connection.exchanges.is_empty());
    }

    #[tokio::test]
    async fn shared_endpoint_ignores_sentinel_in_partial_pipelined_request() {
        let first = config();
        let mut second = config();
        second.grant_id = "other-grant".into();
        second.access_sentinel = "$OTHER_ACCESS".into();
        second.refresh_sentinel = "$OTHER_REFRESH".into();
        let mut connection = connection_for(vec![first, second]);
        connection.seen_tokens.clear();
        let first_request = b"POST /oauth/token HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let partial_second = b"POST /oauth/token HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 64\r\n\r\nrefresh_token=$OTHER_REFRESH";

        let error = connection
            .transform_requests(
                &[first_request.as_slice(), partial_second.as_slice()].concat(),
                "auth.example.com",
            )
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(connection.exchanges.is_empty());
    }

    #[tokio::test]
    async fn expect_continue_is_rejected_after_headers_without_waiting_for_body() {
        let request = b"POST /oauth/token HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n";
        let mut connection = connection();

        let error = connection
            .transform_requests(request, "auth.example.com")
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "OAuth Expect: 100-continue is unsupported"
        );
    }

    #[test]
    fn response_scrubbing_preserves_innocent_token_prefix_at_response_end() {
        let mut connection = connection();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\ninnocent real-ac";
        let output = connection.scrub_response_chunk(response).unwrap();

        assert_eq!(output, response);
    }

    #[test]
    fn response_scrubbing_redacts_a_token_split_across_reads() {
        let mut connection = connection();
        let mut output = connection
            .scrub_response_chunk(b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\necho real-ac")
            .unwrap();
        output.extend(connection.scrub_response_chunk(b"cess done").unwrap());

        assert_eq!(
            output,
            b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\necho *********** done"
        );
    }

    #[test]
    fn response_boundary_flushes_matcher_tail_on_keep_alive() {
        let mut connection = connection();
        let responses = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nreal-acHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ncess";
        let output = connection.scrub_response_chunk(responses).unwrap();

        assert_eq!(output, responses);
    }

    #[test]
    fn chunked_response_redacts_token_split_across_chunks() {
        let mut connection = connection();
        let first = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nreal-\r\n";
        let second = b"6\r\naccess\r\n0\r\n\r\n";
        let mut output = connection.scrub_response_chunk(first).unwrap();
        output.extend(connection.scrub_response_chunk(second).unwrap());

        assert_eq!(
            output,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n*****\r\n6\r\n******\r\n0\r\n\r\n"
        );
    }

    #[test]
    fn chunked_response_redacts_tokens_in_extensions() {
        let mut connection = connection();
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;token=real-access\r\nbody\r\n0\r\n\r\n";

        let output = connection.scrub_response_chunk(response).unwrap();

        assert_eq!(output.len(), response.len());
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("token=***********")
        );
    }

    #[test]
    fn unresolved_token_prefix_cannot_grow_chunk_framing_past_limit() {
        let mut connection = connection();
        connection.seen_tokens = vec![Zeroizing::new("aaa".into())];
        let extension = "x".repeat(MAX_RESPONSE_SCRUB_FRAMING_BYTES / 2);
        let chunk = format!("1;x={extension}\r\na\r\n");

        connection
            .scrub_response_chunk(
                format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunk}").as_bytes(),
            )
            .unwrap();
        connection.scrub_response_chunk(chunk.as_bytes()).unwrap();
        let framing_len = connection.response_scrub_framing.len();
        let error = connection
            .scrub_response_chunk(chunk.as_bytes())
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "OAuth response scrub framing exceeds limit"
        );
        assert_eq!(connection.response_scrub_framing.len(), framing_len);
        assert!(framing_len <= MAX_RESPONSE_SCRUB_FRAMING_BYTES);
    }

    #[test]
    fn seen_token_limit_fails_closed_without_evicting_redaction_history() {
        let mut tokens = Vec::new();
        for index in 0..MAX_SEEN_TOKENS {
            remember_token(&mut tokens, &format!("token-{index}")).unwrap();
        }

        let error = remember_token(&mut tokens, "overflow-token").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "too many OAuth tokens seen on one connection"
        );
        assert_eq!(tokens.len(), MAX_SEEN_TOKENS);
        let mut response = b"token-0 overflow-token".to_vec();
        scrub_seen_tokens(&mut response, &tokens);
        assert_eq!(response, b"******* overflow-token");
    }

    #[test]
    fn encoded_api_response_is_rejected_before_headers_are_released() {
        let mut connection = connection();
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 11\r\n\r\nreal-access";

        let error = connection.scrub_response_chunk(response).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "encoded OAuth responses are unsupported");
    }

    #[test]
    fn switching_protocols_response_is_rejected_before_release() {
        let mut connection = connection();
        connection.response_head_requests.push_back(false);
        let response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

        let error = connection.scrub_response_chunk(response).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "OAuth API protocol upgrades are unsupported"
        );
    }

    #[test]
    fn head_response_completes_at_headers_on_keep_alive() {
        let mut connection = connection();
        connection.response_head_requests.push_back(true);
        connection.response_head_requests.push_back(false);
        let responses = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";

        let output = connection.scrub_response_chunk(responses).unwrap();

        assert_eq!(output, responses);
    }

    #[tokio::test]
    async fn copilot_device_flow_commits_only_once_the_poll_grants_a_token() {
        let broker = start_broker("old-access", "old-access");
        let mut config = broker_config(&broker);
        config.token_endpoint = "https://github.com/login/oauth/access_token".into();
        config.device_code_endpoint = Some("https://github.com/login/device/code".into());
        config.poll_endpoint = Some("https://github.com/login/oauth/access_token".into());
        // Copilot has no refresh grant: the same field carries both tokens.
        config.access_token_field = "access_token".into();
        config.refresh_token_field = "access_token".into();
        config.inject_hosts = vec![HostPattern::Exact("api.github.com".into())];
        let mut connection = OAuthConnection::new(&[config], "github.com", 443, None)
            .await
            .unwrap();

        let device = json_request(
            "/login/device/code",
            r#"{"client_id":"Iv1.b507","scope":"repo"}"#,
        );
        let upstream = connection
            .transform_requests(device.as_bytes(), "github.com")
            .await
            .unwrap();
        assert_eq!(upstream, device.as_bytes());
        let device_response = json_response(
            200,
            r#"{"device_code":"dc","user_code":"WDJB-MJHT","verification_uri":"https://github.com/login/device","interval":5}"#,
        );
        let guest = connection
            .transform_responses(device_response.as_bytes())
            .await
            .unwrap();
        assert_eq!(guest, device_response.as_bytes());

        let poll = json_request(
            "/login/oauth/access_token",
            r#"{"client_id":"Iv1.b507","device_code":"dc","grant_type":"urn:ietf:params:oauth:grant-type:device_code"}"#,
        );
        let upstream = connection
            .transform_requests(poll.as_bytes(), "github.com")
            .await
            .unwrap();
        assert_eq!(upstream, poll.as_bytes());
        assert!(connection.grants[0].lease.is_some());
        // GitHub answers a pending poll with HTTP 200 and an error body.
        let pending = json_response(200, r#"{"error":"authorization_pending"}"#);
        let guest = connection
            .transform_responses(pending.as_bytes())
            .await
            .unwrap();
        assert_eq!(guest, pending.as_bytes());
        assert!(connection.grants[0].lease.is_none());
        assert!(broker.commits().is_empty());

        connection
            .transform_requests(poll.as_bytes(), "github.com")
            .await
            .unwrap();
        let granted = json_response(
            200,
            r#"{"access_token":"gho_new","token_type":"bearer","scope":"repo"}"#,
        );
        let guest = String::from_utf8(
            connection
                .transform_responses(granted.as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(guest.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(!guest.contains("$MSB_OAUTH_REFRESH_123"));
        assert!(!guest.contains("gho_new"));
        assert!(guest.contains(r#""token_type":"bearer""#));
        let commits = broker.commits();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0]["access"], "gho_new");
        assert_eq!(commits[0]["refresh"], "gho_new");
    }

    #[tokio::test]
    async fn xai_device_flow_shares_one_endpoint_for_polling_and_refresh() {
        let broker = start_broker("old-access", "old-refresh");
        let mut config = broker_config(&broker);
        config.token_endpoint = "https://auth.x.ai/oauth2/token".into();
        config.device_code_endpoint = Some("https://auth.x.ai/oauth2/device/code".into());
        config.poll_endpoint = Some("https://auth.x.ai/oauth2/token".into());
        let mut connection = OAuthConnection::new(&[config], "auth.x.ai", 443, None)
            .await
            .unwrap();

        let poll = form_request(
            "/oauth2/token",
            "client_id=xai&device_code=dc&grant_type=urn:ietf:params:oauth:grant-type:device_code",
        );
        let upstream = connection
            .transform_requests(poll.as_bytes(), "auth.x.ai")
            .await
            .unwrap();
        assert_eq!(upstream, poll.as_bytes());
        // RFC 8628 answers a pending poll with HTTP 400: the body decides.
        let pending = json_response(400, r#"{"error":"slow_down","interval":10}"#);
        let guest = connection
            .transform_responses(pending.as_bytes())
            .await
            .unwrap();
        assert_eq!(guest, pending.as_bytes());
        assert!(broker.commits().is_empty());

        connection
            .transform_requests(poll.as_bytes(), "auth.x.ai")
            .await
            .unwrap();
        let granted = json_response(
            200,
            r#"{"access_token":"xai-access","refresh_token":"xai-refresh","expires_in":3600}"#,
        );
        let guest = String::from_utf8(
            connection
                .transform_responses(granted.as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(guest.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(guest.contains("$MSB_OAUTH_REFRESH_123"));
        assert!(!guest.contains("xai-access"));
        assert!(!guest.contains("xai-refresh"));
        assert_eq!(broker.commits().len(), 1);

        // The refresh grant lives at the poll URL: the sentinel is replaced
        // with the token the poll just committed.
        let refresh = form_request(
            "/oauth2/token",
            "grant_type=refresh_token&refresh_token=$MSB_OAUTH_REFRESH_123",
        );
        let upstream = String::from_utf8(
            connection
                .transform_requests(refresh.as_bytes(), "auth.x.ai")
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(upstream.contains("refresh_token=xai-refresh"));
    }

    #[tokio::test]
    async fn openai_poll_secrets_are_sentineled_and_substituted_back() {
        let broker = start_broker("old-access", "old-refresh");
        let mut config = broker_config(&broker);
        config.token_endpoint = "https://auth.openai.com/oauth/token".into();
        config.device_code_endpoint = Some("https://auth.openai.com/oauth/device/code".into());
        config.poll_endpoint = Some("https://auth.openai.com/oauth/device/token".into());
        config.poll_secret_fields = vec!["authorization_code".into(), "code_verifier".into()];
        let mut connection = OAuthConnection::new(&[config], "auth.openai.com", 443, None)
            .await
            .unwrap();

        let poll = json_request("/oauth/device/token", r#"{"device_code":"dc"}"#);
        connection
            .transform_requests(poll.as_bytes(), "auth.openai.com")
            .await
            .unwrap();
        let secrets = json_response(
            200,
            r#"{"authorization_code":"ac-real","code_verifier":"cv-real","expires_in":600}"#,
        );
        let guest = String::from_utf8(
            connection
                .transform_responses(secrets.as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!guest.contains("ac-real"));
        assert!(!guest.contains("cv-real"));
        assert!(broker.commits().is_empty());
        assert!(connection.grants[0].lease.is_none());
        let message = parse_token_response(guest.as_bytes()).unwrap().unwrap();
        let json: Value = serde_json::from_slice(message.body).unwrap();
        let code = json["authorization_code"].as_str().unwrap().to_string();
        let verifier = json["code_verifier"].as_str().unwrap().to_string();
        assert!(code.starts_with(POLL_SENTINEL_PREFIX));
        assert!(verifier.starts_with(POLL_SENTINEL_PREFIX));
        assert_ne!(code, verifier);
        assert_eq!(json["expires_in"], 600);

        let exchange = json_request(
            "/oauth/token",
            &format!(r#"{{"authorization_code":"{code}","code_verifier":"{verifier}"}}"#),
        );
        let upstream = String::from_utf8(
            connection
                .transform_requests(exchange.as_bytes(), "auth.openai.com")
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(upstream.contains(r#""authorization_code":"ac-real""#));
        assert!(upstream.contains(r#""code_verifier":"cv-real""#));

        let granted = json_response(
            200,
            r#"{"access_token":"oa-access","refresh_token":"oa-refresh"}"#,
        );
        let guest = String::from_utf8(
            connection
                .transform_responses(granted.as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(guest.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(!guest.contains("oa-access"));
        assert_eq!(broker.commits().len(), 1);
    }

    #[tokio::test]
    async fn poll_error_outside_the_waiting_set_fails_closed() {
        let broker = start_broker("old-access", "old-refresh");
        let mut config = broker_config(&broker);
        config.token_endpoint = "https://auth.example.com/oauth/token".into();
        config.poll_endpoint = Some("https://auth.example.com/oauth/device/token".into());
        let poll = json_request("/oauth/device/token", r#"{"device_code":"dc"}"#);

        let mut connection = OAuthConnection::new(&[config.clone()], "auth.example.com", 443, None)
            .await
            .unwrap();
        connection
            .transform_requests(poll.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        let denied = json_response(
            400,
            r#"{"error":"unauthorized_client","access_token":"leaked"}"#,
        );
        let guest = String::from_utf8(
            connection
                .transform_responses(denied.as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(guest.contains("unauthorized_client"));
        assert!(guest.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(!guest.contains("leaked"));
        assert!(connection.grants[0].lease.is_none());
        assert!(broker.commits().is_empty());

        let mut connection = OAuthConnection::new(&[config], "auth.example.com", 443, None)
            .await
            .unwrap();
        connection
            .transform_requests(poll.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        let error = connection
            .transform_responses(json_response(200, r#"{"interval":5}"#).as_bytes())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "OAuth access token is missing");
        assert!(broker.commits().is_empty());
    }

    #[tokio::test]
    async fn waiting_poll_error_carrying_secret_material_is_never_forwarded_raw() {
        let broker = start_broker("old-access", "old-refresh");
        let mut base = broker_config(&broker);
        base.token_endpoint = "https://auth.example.com/oauth/token".into();
        base.poll_endpoint = Some("https://auth.example.com/oauth/device/token".into());
        let poll = json_request("/oauth/device/token", r#"{"device_code":"dc"}"#);

        // A pending error that also carries a token is a token response.
        let mut connection = OAuthConnection::new(&[base.clone()], "auth.example.com", 443, None)
            .await
            .unwrap();
        connection
            .transform_requests(poll.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        let guest = String::from_utf8(
            connection
                .transform_responses(
                    json_response(
                        200,
                        r#"{"error":"authorization_pending","access_token":"gho-real"}"#,
                    )
                    .as_bytes(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!guest.contains("gho-real"));
        assert!(guest.contains("$MSB_OAUTH_ACCESS_123"));
        assert_eq!(broker.commits().len(), 1);

        // The same body on a failing status is sanitized, not committed.
        let mut connection = OAuthConnection::new(&[base.clone()], "auth.example.com", 443, None)
            .await
            .unwrap();
        connection
            .transform_requests(poll.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        let guest = String::from_utf8(
            connection
                .transform_responses(
                    json_response(
                        400,
                        r#"{"error":"authorization_pending","access_token":"gho-real"}"#,
                    )
                    .as_bytes(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!guest.contains("gho-real"));
        assert!(guest.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(guest.contains("authorization_pending"));
        assert!(connection.grants[0].lease.is_none());
        assert_eq!(broker.commits().len(), 1);

        // A pending error carrying a poll secret is a secret response.
        let mut config = base;
        config.poll_secret_fields = vec!["authorization_code".into()];
        let mut connection = OAuthConnection::new(&[config], "auth.example.com", 443, None)
            .await
            .unwrap();
        connection
            .transform_requests(poll.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        let guest = String::from_utf8(
            connection
                .transform_responses(
                    json_response(
                        200,
                        r#"{"error":"slow_down","authorization_code":"ac-real"}"#,
                    )
                    .as_bytes(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!guest.contains("ac-real"));
        assert!(guest.contains(POLL_SENTINEL_PREFIX));
        assert_eq!(broker.commits().len(), 1);
    }

    #[tokio::test]
    async fn refresh_failure_at_a_shared_poll_endpoint_is_sanitized() {
        let broker = start_broker("old-access", "old-refresh");
        let mut config = broker_config(&broker);
        config.token_endpoint = "https://auth.x.ai/oauth2/token".into();
        config.poll_endpoint = Some("https://auth.x.ai/oauth2/token".into());
        let mut connection = OAuthConnection::new(&[config], "auth.x.ai", 443, None)
            .await
            .unwrap();

        // The sentinel makes this a refresh rather than a device code poll,
        // even though both use the same URL.
        let refresh = form_request(
            "/oauth2/token",
            "grant_type=refresh_token&refresh_token=$MSB_OAUTH_REFRESH_123",
        );
        connection
            .transform_requests(refresh.as_bytes(), "auth.x.ai")
            .await
            .unwrap();
        assert!(connection.grants[0].lease.is_some());

        let denied = json_response(400, r#"{ "error" : "access_denied" }"#);
        let guest = String::from_utf8(
            connection
                .transform_responses(denied.as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();

        // Sanitizing re-serializes the body; a forwarded response would not.
        assert!(guest.ends_with(r#"{"error":"access_denied"}"#));
        assert!(connection.grants[0].lease.is_none());
        assert!(broker.commits().is_empty());
    }

    #[tokio::test]
    async fn chunked_device_code_response_streams_to_the_guest() {
        let broker = start_broker("old-access", "old-refresh");
        let mut config = broker_config(&broker);
        config.token_endpoint = "https://github.com/login/oauth/access_token".into();
        config.device_code_endpoint = Some("https://github.com/login/device/code".into());
        config.poll_endpoint = Some("https://github.com/login/oauth/access_token".into());
        let mut connection = OAuthConnection::new(&[config], "github.com", 443, None)
            .await
            .unwrap();

        let device = json_request("/login/device/code", r#"{"client_id":"Iv1.b507"}"#);
        connection
            .transform_requests(device.as_bytes(), "github.com")
            .await
            .unwrap();

        let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n14\r\n{\"device_code\":\"dc\",\r\n";
        let tail = "d\r\n\"interval\":5}\r\n0\r\n\r\n";
        let mut guest = connection
            .transform_responses(head.as_bytes())
            .await
            .unwrap();
        guest.extend(
            connection
                .transform_responses(tail.as_bytes())
                .await
                .unwrap(),
        );
        assert_eq!(guest, format!("{head}{tail}").as_bytes());
        assert!(connection.exchanges.is_empty());

        // The connection carries on with the poll the device code was for.
        let poll = json_request("/login/oauth/access_token", r#"{"device_code":"dc"}"#);
        connection
            .transform_requests(poll.as_bytes(), "github.com")
            .await
            .unwrap();
        let granted = json_response(200, r#"{"access_token":"gho_new","refresh_token":"r"}"#);
        let guest = String::from_utf8(
            connection
                .transform_responses(granted.as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(guest.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(!guest.contains("gho_new"));
        assert!(connection.finish_response_scrubbing().unwrap().is_empty());
        assert_eq!(broker.commits().len(), 1);
    }

    #[tokio::test]
    async fn outstanding_device_code_requests_are_bounded() {
        let broker = start_broker("old-access", "old-refresh");
        let mut config = broker_config(&broker);
        config.token_endpoint = "https://github.com/login/oauth/access_token".into();
        config.device_code_endpoint = Some("https://github.com/login/device/code".into());
        let mut connection = OAuthConnection::new(&[config], "github.com", 443, None)
            .await
            .unwrap();
        connection
            .exchanges
            .resize_with(MAX_OUTSTANDING_API_REQUESTS, || Exchange::PassThrough);

        let device = json_request("/login/device/code", r#"{"client_id":"Iv1.b507"}"#);
        let error = connection
            .transform_requests(device.as_bytes(), "github.com")
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "too many outstanding OAuth API requests");
        assert_eq!(connection.exchanges.len(), MAX_OUTSTANDING_API_REQUESTS);
    }

    #[tokio::test]
    async fn close_delimited_device_code_response_fails_closed_before_the_poll() {
        let broker = start_broker("old-access", "old-refresh");
        let mut config = broker_config(&broker);
        config.token_endpoint = "https://github.com/login/oauth/access_token".into();
        config.device_code_endpoint = Some("https://github.com/login/device/code".into());
        config.poll_endpoint = Some("https://github.com/login/oauth/access_token".into());
        let mut connection = OAuthConnection::new(&[config], "github.com", 443, None)
            .await
            .unwrap();

        let device = json_request("/login/device/code", r#"{"client_id":"Iv1.b507"}"#);
        connection
            .transform_requests(device.as_bytes(), "github.com")
            .await
            .unwrap();
        let poll = json_request("/login/oauth/access_token", r#"{"device_code":"dc"}"#);
        connection
            .transform_requests(poll.as_bytes(), "github.com")
            .await
            .unwrap();
        assert_eq!(connection.exchanges.len(), 2);

        // Unframed, so the poll response behind it would be streamed out with
        // it rather than committed and sanitized.
        let unframed =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"device_code\":\"dc\"}";
        let granted = json_response(200, r#"{"access_token":"gho_new"}"#);
        let error = connection
            .transform_responses(format!("{unframed}{granted}").as_bytes())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "OAuth device code responses require Content-Length or chunked framing"
        );
        assert!(broker.commits().is_empty());
    }

    #[tokio::test]
    async fn a_poll_sentinel_from_another_connection_is_rejected() {
        let broker = start_broker("old-access", "old-refresh");
        let mut config = broker_config(&broker);
        config.token_endpoint = "https://auth.openai.com/oauth/token".into();
        config.poll_endpoint = Some("https://auth.openai.com/oauth/device/token".into());
        config.poll_secret_fields = vec!["authorization_code".into()];
        let mut connection = OAuthConnection::new(&[config], "auth.openai.com", 443, None)
            .await
            .unwrap();

        let stale = format!("{POLL_SENTINEL_PREFIX}0123456789abcdef");
        let exchange = json_request(
            "/oauth/token",
            &format!(r#"{{"authorization_code":"{stale}"}}"#),
        );
        let error = connection
            .transform_requests(exchange.as_bytes(), "auth.openai.com")
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "OAuth poll secret sentinel is unknown to this connection"
        );
    }

    #[tokio::test]
    async fn commit_response_sentinels_replace_the_ones_the_guest_holds() {
        let broker = start_broker("old-access", "old-refresh");
        broker.set_commit_sentinels(JWT_ACCESS_SENTINEL, JWT_REFRESH_SENTINEL);
        let config = broker_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "auth.example.com", 443, None)
            .await
            .unwrap();

        // Before the commit the guest holds the configured sentinel.
        let refresh = form_request(
            "/oauth/token",
            "grant_type=refresh_token&refresh_token=$MSB_OAUTH_REFRESH_123",
        );
        let upstream = String::from_utf8(
            connection
                .transform_requests(refresh.as_bytes(), "auth.example.com")
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(upstream.contains("refresh_token=old-refresh"));

        let granted = json_response(
            200,
            r#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}"#,
        );
        let guest = String::from_utf8(
            connection
                .transform_responses(granted.as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(guest.contains(JWT_ACCESS_SENTINEL));
        assert!(guest.contains(JWT_REFRESH_SENTINEL));
        assert!(!guest.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(!guest.contains("$MSB_OAUTH_REFRESH_123"));
        assert!(!guest.contains("new-access"));
        assert!(!guest.contains("new-refresh"));
        assert_eq!(connection.grants[0].access_sentinel, JWT_ACCESS_SENTINEL);
        assert_eq!(connection.grants[0].refresh_sentinel, JWT_REFRESH_SENTINEL);

        // The sentinel the commit minted substitutes for the rest of the
        // connection, and the configured one no longer does.
        let body = format!("grant_type=refresh_token&refresh_token={JWT_REFRESH_SENTINEL}");
        let next = format!(
            "POST /oauth/token HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nAuthorization: Bearer {JWT_ACCESS_SENTINEL}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let upstream = String::from_utf8(
            connection
                .transform_requests(next.as_bytes(), "auth.example.com")
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(upstream.contains("Authorization: Bearer new-access"));
        assert!(upstream.contains("refresh_token=new-refresh"));
        assert!(!upstream.contains("eyJ"));
    }

    #[tokio::test]
    async fn load_response_sentinels_override_the_configured_ones() {
        let broker = start_broker("real-access", "real-refresh");
        broker.set_sentinels(JWT_ACCESS_SENTINEL, JWT_REFRESH_SENTINEL);
        let config = broker_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.example.com", 443, None)
            .await
            .unwrap();

        assert_eq!(connection.grants[0].access_sentinel, JWT_ACCESS_SENTINEL);
        assert_eq!(connection.grants[0].refresh_sentinel, JWT_REFRESH_SENTINEL);

        let request = format!(
            "GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer {JWT_ACCESS_SENTINEL}\r\n\r\n"
        );
        let upstream = String::from_utf8(
            connection
                .transform_requests(request.as_bytes(), "api.example.com")
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(upstream.contains("Authorization: Bearer real-access"));

        // The configured sentinel is stale once the broker names another one.
        let stale =
            b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer $MSB_OAUTH_ACCESS_123\r\n\r\n";
        let upstream = String::from_utf8(
            connection
                .transform_requests(stale, "api.example.com")
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(upstream.contains("Bearer $MSB_OAUTH_ACCESS_123"));
    }

    #[tokio::test]
    async fn broker_responses_without_sentinels_keep_the_configured_ones() {
        let broker = start_broker("old-access", "old-refresh");
        let config = broker_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "auth.example.com", 443, None)
            .await
            .unwrap();

        assert_eq!(
            connection.grants[0].access_sentinel,
            "$MSB_OAUTH_ACCESS_123"
        );

        let refresh = form_request(
            "/oauth/token",
            "grant_type=refresh_token&refresh_token=$MSB_OAUTH_REFRESH_123",
        );
        connection
            .transform_requests(refresh.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        let granted = json_response(
            200,
            r#"{"access_token":"new-access","refresh_token":"new-refresh"}"#,
        );
        let guest = String::from_utf8(
            connection
                .transform_responses(granted.as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(guest.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(guest.contains("$MSB_OAUTH_REFRESH_123"));
        assert!(!guest.contains("new-access"));
        assert_eq!(
            connection.grants[0].access_sentinel,
            "$MSB_OAUTH_ACCESS_123"
        );
        assert_eq!(
            connection.grants[0].refresh_sentinel,
            "$MSB_OAUTH_REFRESH_123"
        );
        assert_eq!(broker.commits().len(), 1);
    }

    #[test]
    fn jwt_shaped_sentinel_survives_substitution_byte_for_byte() {
        let body = format!("grant_type=refresh_token&refresh_token={JWT_REFRESH_SENTINEL}");
        let request = format!(
            "POST /oauth/token HTTP/1.1\r\nAuthorization: Bearer {JWT_ACCESS_SENTINEL}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );

        let bearer = replace_bearer_header(
            request.as_bytes(),
            JWT_ACCESS_SENTINEL.as_bytes(),
            b"real-access",
        );
        let bearer = String::from_utf8(bearer).unwrap();
        assert!(bearer.contains("Authorization: Bearer real-access\r\n"));
        assert!(bearer.contains(JWT_REFRESH_SENTINEL));

        let both = replace_all(
            bearer.as_bytes(),
            JWT_REFRESH_SENTINEL.as_bytes(),
            b"real-refresh",
        );
        let both = String::from_utf8(both).unwrap();
        assert!(both.contains("refresh_token=real-refresh"));
        assert!(!both.contains("eyJ"));

        // base64url is case-sensitive, so a lowercased sentinel is a different
        // sentinel even though the header name and scheme are not.
        let lowercased = replace_bearer_header(
            request.as_bytes(),
            JWT_ACCESS_SENTINEL.to_ascii_lowercase().as_bytes(),
            b"real-access",
        );
        assert_eq!(lowercased, request.as_bytes());
    }

    #[test]
    fn scrubbing_carries_a_split_token_without_touching_a_jwt_sentinel() {
        let body = format!(r#"{{"token":"real-access","sentinel":"{JWT_ACCESS_SENTINEL}"}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = response.as_bytes();
        let mut connection = connection();

        // Split inside the real token and again inside the sentinel, so the
        // scrubber has to carry a partial match across both writes.
        let first = response.iter().position(|byte| *byte == b'a').unwrap() + 40;
        let second = response.len() - 12;
        let mut output = connection.scrub_response_chunk(&response[..first]).unwrap();
        output.extend(
            connection
                .scrub_response_chunk(&response[first..second])
                .unwrap(),
        );
        output.extend(
            connection
                .scrub_response_chunk(&response[second..])
                .unwrap(),
        );
        output.extend(connection.finish_response_scrubbing().unwrap());

        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains("real-access"));
        assert!(output.contains("***********"));
        assert!(output.contains(JWT_ACCESS_SENTINEL));
        assert_eq!(output.len(), response.len());
    }

    #[test]
    fn broker_sentinels_are_checked_before_they_are_adopted() {
        let mut grant = loaded(config());
        let seen = vec![
            Zeroizing::new("real-access".to_string()),
            Zeroizing::new("real-refresh".to_string()),
        ];

        let error = grant
            .adopt_sentinels(Some(String::new()), None, &seen)
            .unwrap_err();
        assert_eq!(error.to_string(), "OAuth broker sentinel is empty");

        let error = grant
            .adopt_sentinels(Some("x".repeat(MAX_OAUTH_SENTINEL_BYTES + 1)), None, &seen)
            .unwrap_err();
        assert_eq!(error.to_string(), "OAuth broker sentinel exceeds limit");

        for broken in ["a\0b", "a\rb", "a\nb"] {
            let error = grant
                .adopt_sentinels(Some(broken.into()), None, &seen)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "OAuth broker sentinel contains a control character"
            );
        }

        // A sentinel that is one of the real tokens would hand that token to
        // the guest as its own stand-in.
        let error = grant
            .adopt_sentinels(Some("real-access".into()), None, &seen)
            .unwrap_err();
        assert_eq!(error.to_string(), "OAuth broker sentinel is a live token");

        let error = grant
            .adopt_sentinels(Some("same".into()), Some("same".into()), &seen)
            .unwrap_err();
        assert_eq!(error.to_string(), "OAuth broker sentinels must differ");

        assert_eq!(grant.access_sentinel, "$MSB_OAUTH_ACCESS_123");
        grant
            .adopt_sentinels(Some("x".repeat(MAX_OAUTH_SENTINEL_BYTES)), None, &seen)
            .unwrap();
        assert_eq!(grant.access_sentinel.len(), MAX_OAUTH_SENTINEL_BYTES);
        assert_eq!(grant.refresh_sentinel, "$MSB_OAUTH_REFRESH_123");
    }

    #[tokio::test]
    async fn acquire_response_sentinels_are_adopted_before_substitution() {
        let broker = start_broker("real-access", "real-refresh");
        let config = broker_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "auth.example.com", 443, None)
            .await
            .unwrap();

        // The load that opened this connection named no sentinel.
        assert_eq!(
            connection.grants[0].access_sentinel,
            "$MSB_OAUTH_ACCESS_123"
        );

        // The grant was re-minted elsewhere before this connection's first
        // token request, so `acquire` is where the sentinel is learned.
        broker.set_sentinels(JWT_ACCESS_SENTINEL, JWT_REFRESH_SENTINEL);
        let refresh = form_request(
            "/oauth/token",
            &format!("grant_type=refresh_token&refresh_token={JWT_REFRESH_SENTINEL}"),
        );
        let upstream = String::from_utf8(
            connection
                .transform_requests(refresh.as_bytes(), "auth.example.com")
                .await
                .unwrap(),
        )
        .unwrap();

        assert_eq!(connection.grants[0].access_sentinel, JWT_ACCESS_SENTINEL);
        assert_eq!(connection.grants[0].refresh_sentinel, JWT_REFRESH_SENTINEL);
        assert!(upstream.contains("refresh_token=real-refresh"));
        assert!(!upstream.contains("eyJ"));
    }

    #[tokio::test]
    async fn a_committed_token_is_never_adopted_as_its_own_sentinel() {
        let broker = start_broker("old-access", "old-refresh");
        broker.set_commit_sentinels("new-access", JWT_REFRESH_SENTINEL);
        let config = broker_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "auth.example.com", 443, None)
            .await
            .unwrap();

        let refresh = form_request(
            "/oauth/token",
            "grant_type=refresh_token&refresh_token=$MSB_OAUTH_REFRESH_123",
        );
        connection
            .transform_requests(refresh.as_bytes(), "auth.example.com")
            .await
            .unwrap();
        let granted = json_response(
            200,
            r#"{"access_token":"new-access","refresh_token":"new-refresh"}"#,
        );
        let error = connection
            .transform_responses(granted.as_bytes())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "OAuth broker sentinel is a live token");
    }
}
