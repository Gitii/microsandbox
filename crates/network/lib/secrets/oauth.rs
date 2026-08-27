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

use super::config::{MAX_OAUTH_SENTINEL_BYTES, MintEndpoint, OAuthSecret};
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
/// How many superseded sentinels one grant keeps live as aliases. Each is one
/// more pass over every request body, and a connection that mints this many
/// new sentinels is not a session any client runs.
const MAX_GRANT_SENTINEL_ALIASES: usize = 64;
const BROKER_TIMEOUT: Duration = Duration::from_secs(5);
/// Port a configured endpoint is on when it does not say otherwise.
const DEFAULT_HTTPS_PORT: u16 = 443;
/// How many secrets one grant may hold minted at once. A session mints an API
/// key, not a stream of them, and every one of them is another pass over every
/// request; past this the connection fails closed.
const MAX_GRANT_MINTED_SECRETS: usize = 16;
/// Largest request body held whole so a minted sentinel inside it can be
/// substituted. A body past this streams to the upstream host as it arrives,
/// with only its headers substituted, rather than being buffered wholesale.
const MAX_MINTED_REQUEST_BODY_BYTES: usize = 256 * 1024;

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
    pending_responses: VecDeque<PendingResponse>,
    seen_tokens: Vec<Zeroizing<String>>,
    request_state: RequestState,
    /// Whether any grant on this connection configures a mint endpoint. It
    /// decides how responses are read: without one the scrubber streams as it
    /// always did, with one every response is followed to its end so a mint
    /// response cannot slip past unrecognised.
    mints_configured: bool,
}

struct LoadedGrant {
    config: OAuthSecret,
    token: Endpoint,
    device_code: Option<Endpoint>,
    poll: Option<Endpoint>,
    access: Zeroizing<String>,
    refresh: Zeroizing<String>,
    /// The current access-token sentinel: the configured one until the broker
    /// names another, which a JWT-shaped sentinel does on every login or
    /// refresh. This is the one written into sanitized responses.
    access_sentinel: String,
    /// The current refresh-token sentinel.
    refresh_sentinel: String,
    /// Access sentinels this connection was told earlier, oldest first. They
    /// stay live: a guest still holding one — in the environment variable it
    /// was started with, or a file written before the last refresh — has it
    /// substituted with the current real token rather than sending a stale
    /// sentinel, whose claims are the real token's, upstream.
    access_aliases: Vec<String>,
    /// Superseded refresh sentinels, under the same rule.
    refresh_aliases: Vec<String>,
    generation: u64,
    lease: Option<UnixStream>,
    poll_secrets: Vec<PollSecret>,
    /// Secrets minted on this grant, held by the broker and substituted back
    /// into requests to the grant's inject hosts and its token endpoint.
    minted: Vec<MintedSecret>,
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

/// A secret a mint endpoint handed back, now stored by the broker.
struct MintedSecret {
    sentinel: String,
    value: Zeroizing<String>,
}

/// An API request whose response has not been read yet.
struct PendingResponse {
    /// Whether the request was a `HEAD`, whose response carries no body.
    head: bool,
    /// The mint this response may complete, when the request reached a
    /// configured mint endpoint.
    mint: Option<PendingMint>,
}

/// The grant and field a mint response is expected to carry.
#[derive(Clone)]
struct PendingMint {
    grant: usize,
    field: String,
}

/// The result of scrubbing one streamed chunk of response bytes.
struct Scrubbed {
    output: Vec<u8>,
    remaining: Vec<u8>,
    complete: bool,
}

/// How far the response scrubber reads before handing bytes back.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    /// Stream to the guest as the bytes arrive. A response that ends at EOF
    /// is fine: nothing on this connection has to be read whole.
    Continuous,
    /// Stop at the end of each message, because a device code exchange is
    /// interleaved with responses that are held and rewritten.
    DeviceCode,
    /// Stop at the end of each message, because a mint response is.
    Mint,
}

/// How a request target relates to a configured endpoint.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PathMatch {
    /// The target's path is the endpoint's, whatever query follows it.
    Exact,
    /// The target is another spelling of the endpoint's path — a doubled
    /// slash, a percent-encoded separator — which the upstream host may well
    /// route to the same handler while a byte comparison here does not.
    Equivalent,
    /// Somewhere else entirely.
    None,
}

/// Which of a grant's secrets a sentinel stands for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SentinelKind {
    Access,
    Refresh,
    /// A secret minted on an inject host, which has no configured sentinel and
    /// no aliases: the broker names it once and it stays that name.
    Minted,
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
    Mint {
        grant_id: &'a str,
        field: &'a str,
        value: &'a str,
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
    /// Secrets already minted for this grant, so a connection opened after the
    /// one that minted them still substitutes them.
    #[serde(default)]
    minted: Vec<MintedEntry>,
}

/// One minted secret as the broker reports it.
#[derive(Deserialize)]
struct MintedEntry {
    sentinel: String,
    value: String,
}

/// What the broker answers a `mint` with. An `error` it may send alongside
/// `ok: false` is not read: the connection fails closed either way, and the
/// text is the broker's to log.
#[derive(Deserialize)]
struct MintResponse {
    ok: bool,
    #[serde(default)]
    sentinel: Option<String>,
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

/// One complete response to a mint request, with any chunked framing undone.
///
/// Both framings are read: a minted key is small enough to arrive in a single
/// chunk, and an endpoint that streams JSON is not obliged to say how long it
/// is up front. The body comes back de-chunked and the response handed to the
/// guest is rebuilt with a `Content-Length`, since rewriting the field changes
/// its length anyway and re-chunking to preserve a framing no client depends
/// on would only add a way to get it wrong.
struct MintMessage {
    headers: Vec<u8>,
    body: Vec<u8>,
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
        let mut reported = Vec::new();
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
            let grant = LoadedGrant {
                config: config.clone(),
                token,
                device_code,
                poll,
                access: Zeroizing::new(loaded.access),
                refresh: Zeroizing::new(loaded.refresh),
                access_sentinel: config.access_sentinel.clone(),
                refresh_sentinel: config.refresh_sentinel.clone(),
                access_aliases: Vec::new(),
                refresh_aliases: Vec::new(),
                generation: loaded.generation,
                lease: None,
                poll_secrets: Vec::new(),
                minted: Vec::new(),
            };
            grants.push(grant);
            reported.push((
                loaded.access_sentinel,
                loaded.refresh_sentinel,
                loaded.minted,
            ));
        }
        // The guest may already hold a sentinel minted after this sandbox was
        // configured, so the broker's answer wins over the config. Adoption
        // waits for every grant to be loaded: a sentinel is checked against
        // the whole connection, and half a connection is not the whole of it.
        for (index, (access, refresh, minted)) in reported.into_iter().enumerate() {
            adopt_minted(&mut grants, index, &minted, &mut seen_tokens)?;
            adopt_sentinels(&mut grants, index, access, refresh, &seen_tokens)?;
        }
        let mints_configured = grants
            .iter()
            .any(|grant| !grant.config.mint_endpoints.is_empty());
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
            pending_responses: VecDeque::new(),
            seen_tokens,
            request_state: RequestState::Headers,
            mints_configured,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    pub(crate) fn is_token_host(&self) -> bool {
        self.token_connection == Some(true)
    }

    /// Scrub a streamed API response, minting any secret a mint endpoint just
    /// handed back.
    ///
    /// Without a mint endpoint this is the streaming scrubber and nothing
    /// else. With one, responses are followed message by message so that the
    /// mint response is recognised, held whole and rewritten before any of it
    /// reaches the guest — which is why a close-delimited response is refused
    /// on such a connection: nothing marks where the next response begins, so
    /// a minted secret could stream past inside what followed.
    pub(crate) async fn scrub_response_chunk(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        if !self.mints_configured {
            return Ok(self.scrub_stream(data, StreamMode::Continuous)?.output);
        }
        self.response_buffer.extend_from_slice(data);
        enforce_limit(&self.response_buffer)?;
        let mut output = Vec::new();
        while !self.response_buffer.is_empty() {
            let Some(mint) = self.pending_mint() else {
                let buffered = std::mem::take(&mut self.response_buffer);
                let scrubbed = self.scrub_stream(&buffered, StreamMode::Mint)?;
                self.response_buffer = scrubbed.remaining;
                output.extend_from_slice(&scrubbed.output);
                if !scrubbed.complete {
                    break;
                }
                continue;
            };
            // A `100 Continue` ahead of the mint response would be counted as
            // the response itself by the framing below, so it is refused here
            // rather than misread there.
            if let Some(boundary) = header_boundary(&self.response_buffer)
                && (100..200).contains(&response_status(&self.response_buffer[..boundary])?)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OAuth informational responses are unsupported",
                ));
            }
            let Some(message) = parse_mint_response(&self.response_buffer)? else {
                break;
            };
            let total_len = message.total_len;
            let response = self.response_buffer[..total_len].to_vec();
            let rewritten = self
                .finish_mint(mint, &message.headers, &message.body, response)
                .await?;
            output.extend_from_slice(&rewritten);
            self.response_buffer.drain(..total_len);
            self.pending_responses.pop_front();
        }
        Ok(output)
    }

    /// The mint this connection is waiting on, when the next byte in the
    /// buffer starts the response to a mint request.
    fn pending_mint(&self) -> Option<PendingMint> {
        if !matches!(self.response_scrub_state, ResponseScrubState::Headers)
            || !self.response_scrub_buffer.is_empty()
        {
            return None;
        }
        self.pending_responses.front()?.mint.clone()
    }

    /// Scrub a streamed response, stopping at the end of the first complete
    /// message and handing the rest back to the caller when the mode says to.
    fn scrub_stream(&mut self, data: &[u8], mode: StreamMode) -> io::Result<Scrubbed> {
        let stop_at_message_end = mode != StreamMode::Continuous;
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
                        self.pending_responses
                            .front()
                            .is_some_and(|pending| pending.head),
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
                            match mode {
                                StreamMode::Mint => {
                                    "OAuth responses on a minting connection require Content-Length or chunked framing"
                                }
                                _ => {
                                    "OAuth device code responses require Content-Length or chunked framing"
                                }
                            },
                        ));
                    }
                    self.scrub_stream_bytes(&headers, &mut output);
                    self.flush_scrub_tail(&mut output);
                    if !(100..200).contains(&status) {
                        self.pending_responses.pop_front();
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
            || !self.response_buffer.is_empty()
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
                    // Where a protected endpoint lives on this connection,
                    // every target on it has to be one this proxy can compare
                    // with confidence. Anything else is refused rather than
                    // decoded: the spellings of one path are not a list that
                    // ends, and each one we do not recognise is a request
                    // whose response would reach the guest unread.
                    if self.has_protected_endpoint(sni) {
                        reject_unnormalized_target(target)?;
                        if let Some(kind) = self.equivalent_endpoint(sni, target) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "OAuth {kind} endpoint request target is not the configured path"
                                ),
                            ));
                        }
                    }
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
                    // A mint endpoint is an ordinary API request whose
                    // response has to be held and rewritten, so it is
                    // recognised here and remembered against its response.
                    let mint = (!endpoint_request
                        && !device_code_request
                        && method.eq_ignore_ascii_case("POST"))
                    .then(|| self.mint_match(sni, target))
                    .flatten();
                    // An inject-host request may carry a minted sentinel in
                    // its body as well as its headers, and substituting it
                    // changes the body's length, so the body is held whole
                    // instead of streamed. Only where minting is configured,
                    // only up to a bound, and never where the client is
                    // waiting for a `100 Continue` before it sends the body.
                    let buffered_body = !endpoint_request
                        && !device_code_request
                        && self.mints_configured
                        && matches!(
                            framing,
                            RequestBodyFraming::ContentLength(1..=MAX_MINTED_REQUEST_BODY_BYTES)
                        )
                        && !expects_100_continue(&headers)?;
                    if buffered_body && self.request_buffer.len() < total_len {
                        break;
                    }
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
                                grant.sentinels().any(|sentinel| {
                                    contains_bytes(framed_request, sentinel.as_bytes())
                                })
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
                        if self.pending_responses.len() >= MAX_OUTSTANDING_API_REQUESTS {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "too many outstanding OAuth API requests",
                            ));
                        }
                        self.pending_responses.push_back(PendingResponse {
                            head: method.eq_ignore_ascii_case("HEAD"),
                            mint,
                        });
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
                    let request_len = if is_token_request || buffered_body {
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
                        adopt_minted(
                            &mut self.grants,
                            index,
                            &loaded.minted,
                            &mut self.seen_tokens,
                        )?;
                        adopt_sentinels(
                            &mut self.grants,
                            index,
                            loaded.access_sentinel,
                            loaded.refresh_sentinel,
                            &self.seen_tokens,
                        )?;
                    }
                    for index in 0..self.grants.len() {
                        let inject = self.grants[index]
                            .config
                            .inject_hosts
                            .iter()
                            .any(|host| host.matches(sni));
                        if inject && token_grant != Some(index) {
                            let loaded = broker_load(&self.grants[index].config).await?;
                            remember_token(&mut self.seen_tokens, &loaded.access)?;
                            remember_token(&mut self.seen_tokens, &loaded.refresh)?;
                            let grant = &mut self.grants[index];
                            grant.access = Zeroizing::new(loaded.access);
                            grant.refresh = Zeroizing::new(loaded.refresh);
                            grant.generation = loaded.generation;
                            adopt_minted(
                                &mut self.grants,
                                index,
                                &loaded.minted,
                                &mut self.seen_tokens,
                            )?;
                            adopt_sentinels(
                                &mut self.grants,
                                index,
                                loaded.access_sentinel,
                                loaded.refresh_sentinel,
                                &self.seen_tokens,
                            )?;
                        }
                        // Every sentinel this connection was told for the
                        // grant substitutes, not only the newest: a guest that
                        // still holds an earlier one gets the current token
                        // rather than sending the sentinel upstream.
                        let grant = &self.grants[index];
                        if inject || token_grant == Some(index) {
                            for sentinel in grant.access_sentinels() {
                                rewritten = if inject && token_grant != Some(index) {
                                    replace_bearer_header(
                                        &rewritten,
                                        sentinel.as_bytes(),
                                        grant.access.as_bytes(),
                                    )
                                } else {
                                    replace_all(
                                        &rewritten,
                                        sentinel.as_bytes(),
                                        grant.access.as_bytes(),
                                    )
                                };
                            }
                        }
                        if token_grant == Some(index) {
                            for sentinel in grant.refresh_sentinels() {
                                rewritten = replace_all(
                                    &rewritten,
                                    sentinel.as_bytes(),
                                    grant.refresh.as_bytes(),
                                );
                            }
                            for secret in &grant.poll_secrets {
                                rewritten = replace_all(
                                    &rewritten,
                                    secret.sentinel.as_bytes(),
                                    secret.value.as_bytes(),
                                );
                            }
                        }
                        // A minted secret substitutes in any header, not only
                        // a bearer one: an API key travels as `x-api-key` as
                        // often as it does as `Authorization`. It substitutes
                        // in a held body too, which is where a form or JSON
                        // field carrying it would be.
                        if inject || token_grant == Some(index) {
                            for secret in &grant.minted {
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
                    } else if buffered_body {
                        rewritten = update_content_length(&rewritten)?;
                    }
                    output.extend_from_slice(&rewritten);
                    pending = self.request_buffer.split_off(request_len);
                    self.request_buffer.clear();
                    self.request_state = if is_token_request || buffered_body {
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
                let scrubbed = self.scrub_stream(&buffered, StreamMode::DeviceCode)?;
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

    /// Turn the secret a mint endpoint handed back into a sentinel.
    ///
    /// A 2xx JSON body is the shape this endpoint was configured for, so it
    /// has to carry the named field as a top-level string; one that does not
    /// fails the connection. The alternative is forwarding a body nothing
    /// understood from an endpoint known to hand out credentials — and the
    /// credential-shaped-response detector, which would otherwise be the net
    /// under that, does not run here: a grant is relevant to this connection,
    /// which is exactly what switches the detector off.
    ///
    /// A non-2xx response is an error, and a 2xx that is not JSON at all is
    /// not this endpoint answering the call it was configured for. Both are
    /// scrubbed and forwarded like any other response.
    ///
    /// A broker that will not store the value fails the connection too: a
    /// secret the broker never saw is one nothing can substitute back or
    /// revoke.
    async fn finish_mint(
        &mut self,
        mint: PendingMint,
        headers: &[u8],
        body: &[u8],
        response: Vec<u8>,
    ) -> io::Result<Vec<u8>> {
        let status = response_status(headers)?;
        let mut json = match serde_json::from_slice::<Value>(body) {
            Ok(json) if (200..300).contains(&status) => json,
            _ => return Ok(self.scrub_tokens(response)),
        };
        let missing = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "OAuth mint endpoint response did not carry field {}",
                    mint.field
                ),
            )
        };
        let object = json.as_object_mut().ok_or_else(missing)?;
        let Some(Value::String(value)) = object.get(&mint.field) else {
            return Err(missing());
        };
        let value = value.clone();
        let sentinel = broker_mint(&self.grants[mint.grant].config, &mint.field, &value).await?;
        adopt_minted(
            &mut self.grants,
            mint.grant,
            &[MintedEntry {
                sentinel: sentinel.clone(),
                value,
            }],
            &mut self.seen_tokens,
        )?;
        object.insert(mint.field, Value::String(sentinel));
        let body = serde_json::to_vec(&json).map_err(io::Error::other)?;
        let mut response = rebuild_identity_message(headers, &body)?;
        scrub_seen_tokens(&mut response, &self.seen_tokens);
        Ok(response)
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
        adopt_sentinels(
            &mut self.grants,
            index,
            committed.access_sentinel,
            committed.refresh_sentinel,
            &self.seen_tokens,
        )?;
        let grant = &mut self.grants[index];
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

    /// Whether a grant on this connection has an endpoint of its own here,
    /// rather than only an inject host.
    ///
    /// It is the endpoints that are compared with a request target, so it is
    /// their presence that makes the target's spelling matter. An inject-host
    /// connection carries ordinary API traffic whose targets are the client's
    /// business.
    fn has_protected_endpoint(&self, sni: &str) -> bool {
        let port = self.connection_port;
        let here =
            |endpoint: &Endpoint| endpoint.port == port && endpoint.host.eq_ignore_ascii_case(sni);
        self.grants.iter().any(|grant| {
            here(&grant.token)
                || grant.device_code.as_ref().is_some_and(&here)
                || grant.poll.as_ref().is_some_and(&here)
                || grant
                    .config
                    .mint_endpoints
                    .iter()
                    .any(|endpoint| mint_endpoint_here(endpoint, sni, port))
        })
    }

    /// The kind of protected endpoint this target is only a near-miss for.
    ///
    /// Scanned across every grant on the connection, because any of them
    /// answers with material the guest may not have.
    fn equivalent_endpoint(&self, sni: &str, target: &str) -> Option<&'static str> {
        let port = self.connection_port;
        let equivalent =
            |endpoint: &Endpoint| endpoint.match_target(sni, port, target) == PathMatch::Equivalent;
        for grant in &self.grants {
            let named = [
                (Some(&grant.token), "token"),
                (grant.device_code.as_ref(), "device code"),
                (grant.poll.as_ref(), "poll"),
            ];
            for (endpoint, kind) in named {
                if endpoint.is_some_and(&equivalent) {
                    return Some(kind);
                }
            }
            let mint = grant.config.mint_endpoints.iter().any(|endpoint| {
                mint_endpoint_matches(endpoint, sni, port, target) == PathMatch::Equivalent
            });
            if mint {
                return Some("mint");
            }
        }
        None
    }

    /// The mint endpoint this request line reached, if any.
    fn mint_match(&self, sni: &str, target: &str) -> Option<PendingMint> {
        self.grants.iter().enumerate().find_map(|(grant, loaded)| {
            loaded
                .config
                .mint_endpoints
                .iter()
                .find(|endpoint| {
                    mint_endpoint_matches(endpoint, sni, self.connection_port, target)
                        == PathMatch::Exact
                })
                .map(|endpoint| PendingMint {
                    grant,
                    field: endpoint.field.clone(),
                })
        })
    }

    fn scrub_tokens(&self, mut response: Vec<u8>) -> Vec<u8> {
        scrub_seen_tokens(&mut response, &self.seen_tokens);
        response
    }
}

impl LoadedGrant {
    /// Every access-token sentinel live for this grant, current one first.
    fn access_sentinels(&self) -> impl Iterator<Item = &str> {
        self.sentinels_of(SentinelKind::Access)
    }

    /// Every refresh-token sentinel live for this grant, current one first.
    fn refresh_sentinels(&self) -> impl Iterator<Item = &str> {
        self.sentinels_of(SentinelKind::Refresh)
    }

    /// Every sentinel live for this grant, of any kind.
    fn sentinels(&self) -> impl Iterator<Item = &str> {
        self.access_sentinels()
            .chain(self.refresh_sentinels())
            .chain(self.sentinels_of(SentinelKind::Minted))
    }

    /// Every sentinel live for one of this grant's secrets, current one first.
    fn sentinels_of(&self, kind: SentinelKind) -> impl Iterator<Item = &str> {
        let aliased = self.aliased(kind);
        let minted = matches!(kind, SentinelKind::Minted).then_some(&self.minted);
        aliased
            .map(|(current, _)| current.as_str())
            .into_iter()
            .chain(
                aliased
                    .into_iter()
                    .flat_map(|(_, aliases)| aliases.iter().map(String::as_str)),
            )
            .chain(
                minted
                    .into_iter()
                    .flatten()
                    .map(|secret| secret.sentinel.as_str()),
            )
    }

    /// The current sentinel and the aliases of a kind that has them.
    ///
    /// [`SentinelKind::Minted`] has neither: the broker names a minted
    /// sentinel once, and a second name for the same secret is another entry
    /// in `minted` rather than an alias of the first.
    fn aliased(&self, kind: SentinelKind) -> Option<(&String, &Vec<String>)> {
        match kind {
            SentinelKind::Access => Some((&self.access_sentinel, &self.access_aliases)),
            SentinelKind::Refresh => Some((&self.refresh_sentinel, &self.refresh_aliases)),
            SentinelKind::Minted => None,
        }
    }

    /// Whether adopting `sentinel` would grow this kind's alias set past its
    /// bound. Checked for both kinds before either is adopted, so a rejected
    /// pair leaves the grant as it was.
    fn exceeds_alias_limit(&self, kind: SentinelKind, sentinel: &str) -> bool {
        // Only `adopt_sentinels` reaches this, and only for the two token
        // sentinels; a minted one is bounded by `adopt_minted` instead.
        let Some((current, aliases)) = self.aliased(kind) else {
            return false;
        };
        current != sentinel
            && !aliases.iter().any(|alias| alias == sentinel)
            && aliases.len() >= MAX_GRANT_SENTINEL_ALIASES
    }

    /// Make `sentinel` the current one of a kind, keeping the one it replaces
    /// live as an alias. The caller has already checked the alias bound.
    fn supersede(&mut self, kind: SentinelKind, sentinel: String) {
        let (current, aliases) = match kind {
            SentinelKind::Access => (&mut self.access_sentinel, &mut self.access_aliases),
            SentinelKind::Refresh => (&mut self.refresh_sentinel, &mut self.refresh_aliases),
            // A minted sentinel supersedes nothing: `adopt_minted` appends.
            SentinelKind::Minted => return,
        };
        if *current == sentinel {
            return;
        }
        aliases.retain(|alias| *alias != sentinel);
        aliases.push(std::mem::replace(current, sentinel));
    }
}

impl Endpoint {
    /// Whether a request line on this connection reached exactly this endpoint.
    fn matches(&self, sni: &str, port: u16, target: &str) -> bool {
        self.match_target(sni, port, target) == PathMatch::Exact
    }

    /// How a request line on this connection relates to this endpoint.
    ///
    /// A configured endpoint whose own target carries a query string is
    /// compared whole: the query is part of what was configured, so nothing
    /// about it can be dropped. Otherwise only the path is compared, and the
    /// request's own query is ignored — a guest that appends one to the token
    /// endpoint must not thereby have the response forwarded unsanitized.
    fn match_target(&self, sni: &str, port: u16, target: &str) -> PathMatch {
        if self.port != port || !self.host.eq_ignore_ascii_case(sni) {
            return PathMatch::None;
        }
        if self.target.contains('?') {
            return if self.target == target {
                PathMatch::Exact
            } else {
                PathMatch::None
            };
        }
        match_endpoint_path(&self.target, target)
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

/// Adopt sentinels the broker named for the grant at `index`.
///
/// An absent field keeps the sentinel already in use, which is what a broker
/// that mints opaque sentinels once, at configuration time, always sends. What
/// is replaced is not discarded: the previous sentinel stays live as an alias,
/// so a guest holding it substitutes rather than leaking it upstream.
///
/// Either both sentinels are adopted or neither is: everything that can
/// refuse the pair runs before anything is written.
fn adopt_sentinels(
    grants: &mut [LoadedGrant],
    index: usize,
    access: Option<String>,
    refresh: Option<String>,
    seen: &[Zeroizing<String>],
) -> io::Result<()> {
    let access = access
        .map(|access| validate_sentinel(access, grants, index, SentinelKind::Access, seen))
        .transpose()?;
    let refresh = refresh
        .map(|refresh| validate_sentinel(refresh, grants, index, SentinelKind::Refresh, seen))
        .transpose()?;
    // Neither is live yet, so this pair is the one case the scan in
    // `validate_sentinel` cannot see.
    if let (Some(access), Some(refresh)) = (&access, &refresh)
        && overlaps(access, refresh)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth broker sentinels must differ",
        ));
    }
    let grant = &grants[index];
    let exceeded = access
        .as_deref()
        .is_some_and(|access| grant.exceeds_alias_limit(SentinelKind::Access, access))
        || refresh
            .as_deref()
            .is_some_and(|refresh| grant.exceeds_alias_limit(SentinelKind::Refresh, refresh));
    if exceeded {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many OAuth sentinels for one grant",
        ));
    }
    let grant = &mut grants[index];
    if let Some(access) = access {
        grant.supersede(SentinelKind::Access, access);
    }
    if let Some(refresh) = refresh {
        grant.supersede(SentinelKind::Refresh, refresh);
    }
    Ok(())
}

/// Adopt the secrets the broker reports as minted for the grant at `index`.
///
/// A minted sentinel joins the same substitution set as the token sentinels,
/// so it is checked on the same terms: bounds, control characters, and no
/// overlap with a live token or another live sentinel. The value is remembered
/// as a seen token first, which is both what scrubs an echo of it out of later
/// responses and what makes a sentinel that shares bytes with its own secret a
/// rejection rather than a half-substitution.
///
/// The same entry arriving again — every `load` on the connection reports the
/// whole list — refreshes the value it stands for and costs no slot.
fn adopt_minted(
    grants: &mut [LoadedGrant],
    index: usize,
    minted: &[MintedEntry],
    seen: &mut Vec<Zeroizing<String>>,
) -> io::Result<()> {
    for entry in minted {
        if entry.value.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OAuth minted secret is empty",
            ));
        }
        remember_token(seen, &entry.value)?;
        let sentinel = validate_sentinel(
            entry.sentinel.clone(),
            grants,
            index,
            SentinelKind::Minted,
            seen,
        )?;
        let grant = &mut grants[index];
        if let Some(held) = grant
            .minted
            .iter_mut()
            .find(|held| held.sentinel == sentinel)
        {
            held.value = Zeroizing::new(entry.value.clone());
            continue;
        }
        if grant.minted.len() >= MAX_GRANT_MINTED_SECRETS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many OAuth minted secrets for one grant",
            ));
        }
        grant.minted.push(MintedSecret {
            sentinel,
            value: Zeroizing::new(entry.value.clone()),
        });
    }
    Ok(())
}

/// Check one broker-supplied sentinel before it is used for substitution.
///
/// A sentinel may be JWT-shaped — the real token's header and payload copied
/// verbatim with only the signature replaced — so it carries base64url bytes
/// (`.`, `-`, `_` included) and runs to at most [`MAX_OAUTH_SENTINEL_BYTES`]
/// bytes. It is matched and replaced byte for byte, so the bytes themselves
/// are only rejected when they could not survive an HTTP message.
///
/// What it may not do is overlap something else the connection substitutes.
/// Sharing bytes with a real token would write that token into the one body
/// that is never scrubbed, and sharing them with another live sentinel — of
/// this grant or any other — makes substitution depend on which the proxy
/// reaches first, which can leave the other half-replaced or send it upstream
/// under the wrong grant. Only the identical value already held for this same
/// token is allowed through, which is what re-naming a current sentinel or
/// promoting one of its aliases looks like.
fn validate_sentinel(
    sentinel: String,
    grants: &[LoadedGrant],
    index: usize,
    kind: SentinelKind,
    seen: &[Zeroizing<String>],
) -> io::Result<String> {
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
    if seen.iter().any(|token| overlaps(&sentinel, token)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth broker sentinel overlaps a live token",
        ));
    }
    for (other, grant) in grants.iter().enumerate() {
        let same_grant = other == index;
        // The same value already held for this same token is the one repeat
        // that means nothing new, rather than an overlap.
        let repeat = same_grant && grant.sentinels_of(kind).any(|held| held == sentinel);
        let clash = grant
            .sentinels()
            .any(|held| !(repeat && held == sentinel) && overlaps(&sentinel, held));
        if clash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                if same_grant {
                    "OAuth broker sentinels must differ"
                } else {
                    "OAuth broker sentinel belongs to another grant"
                },
            ));
        }
    }
    Ok(sentinel)
}

/// Whether either of two values occurs inside the other.
///
/// Substitution walks one sentinel at a time, so an overlapping pair is not
/// merely ambiguous: replacing the longer one first leaves nothing of the
/// shorter, and replacing the shorter one first leaves the rest of the longer
/// wrapped around a real token.
fn overlaps(left: &str, right: &str) -> bool {
    contains_bytes(left.as_bytes(), right.as_bytes())
        || contains_bytes(right.as_bytes(), left.as_bytes())
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

/// Ask the broker to store a secret an endpoint just minted, and to name the
/// sentinel that stands for it.
async fn broker_mint(config: &OAuthSecret, field: &str, value: &str) -> io::Result<String> {
    let response: MintResponse = broker_call(
        &config.broker_endpoint,
        &BrokerRequest::Mint {
            grant_id: &config.grant_id,
            field,
            value,
        },
    )
    .await?;
    if !response.ok {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OAuth broker refused to mint a secret",
        ));
    }
    response.sentinel.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth broker omitted the minted sentinel",
        )
    })
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
        None => (authority, DEFAULT_HTTPS_PORT),
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
/// sentinel is base64url, where case is significant. Every `Authorization`
/// header carrying the sentinel is replaced, not just the first.
///
/// The name has to start a header line — the request line and every header
/// before it end in CRLF — so a header whose name merely ends in
/// `authorization`, such as `X-Retry-Authorization`, is not one of ours and
/// keeps whatever it carries.
fn replace_bearer_header(data: &[u8], sentinel: &[u8], token: &[u8]) -> Vec<u8> {
    const MARKER: &[u8] = b"authorization: bearer ";
    if sentinel.is_empty() || data.len() < MARKER.len() {
        return data.to_vec();
    }
    let lower = data.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    let mut output = Vec::with_capacity(data.len());
    let mut cursor = 0;
    while cursor + MARKER.len() <= data.len() {
        let Some(offset) = lower[cursor..]
            .windows(MARKER.len())
            .position(|window| window == MARKER)
        else {
            break;
        };
        let name_start = cursor + offset;
        let value_start = name_start + MARKER.len();
        let value_end = value_start + sentinel.len();
        let starts_header_line = name_start >= 2 && &data[name_start - 2..name_start] == b"\r\n";
        output.extend_from_slice(&data[cursor..value_start]);
        if starts_header_line
            && data.len() >= value_end
            && &data[value_start..value_end] == sentinel
        {
            output.extend_from_slice(token);
            cursor = value_end;
        } else {
            cursor = value_start;
        }
    }
    output.extend_from_slice(&data[cursor..]);
    output
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

fn parse_mint_response(data: &[u8]) -> io::Result<Option<MintMessage>> {
    let Some(header_end) = header_boundary(data) else {
        return Ok(None);
    };
    let headers = data[..header_end].to_vec();
    match response_body_state(&headers, false)? {
        ResponseScrubState::ContentLength(length) => {
            let total_len = header_end.checked_add(length).ok_or_else(invalid_http)?;
            if total_len > MAX_OAUTH_MESSAGE_BYTES {
                return Err(invalid_http());
            }
            if data.len() < total_len {
                return Ok(None);
            }
            Ok(Some(MintMessage {
                headers,
                body: data[header_end..total_len].to_vec(),
                total_len,
            }))
        }
        ResponseScrubState::ChunkSize => {
            let Some((body, consumed)) = collect_chunked_body(&data[header_end..])? else {
                return Ok(None);
            };
            Ok(Some(MintMessage {
                headers,
                body,
                total_len: header_end + consumed,
            }))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth mint endpoint responses require Content-Length or chunked framing",
        )),
    }
}

/// De-chunk a body, reporting how many bytes of `data` it took. `None` means
/// the terminating chunk and its trailers have not arrived yet.
fn collect_chunked_body(data: &[u8]) -> io::Result<Option<(Vec<u8>, usize)>> {
    let mut body = Vec::new();
    let mut cursor = 0;
    loop {
        let Some(end) = line_boundary(&data[cursor..]) else {
            return Ok(None);
        };
        let size = parse_chunk_size(&data[cursor..cursor + end])?;
        cursor += end;
        if size == 0 {
            // The trailers, if any, end at the first blank line.
            loop {
                let Some(end) = line_boundary(&data[cursor..]) else {
                    return Ok(None);
                };
                let line = &data[cursor..cursor + end];
                cursor += end;
                if line == b"\r\n" {
                    return Ok(Some((body, cursor)));
                }
            }
        }
        let chunk_end = cursor.checked_add(size).ok_or_else(invalid_http)?;
        if chunk_end > MAX_OAUTH_MESSAGE_BYTES {
            return Err(invalid_http());
        }
        if data.len() < chunk_end + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&data[cursor..chunk_end]);
        cursor = chunk_end;
        if &data[cursor..cursor + 2] != b"\r\n" {
            return Err(invalid_http());
        }
        cursor += 2;
    }
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

/// Whether a request line reached exactly this mint endpoint. The endpoint
/// names a host and a target rather than a URL, because that is what a request
/// on an intercepted connection carries: the TLS SNI and the request target.
fn mint_endpoint_matches(endpoint: &MintEndpoint, sni: &str, port: u16, target: &str) -> PathMatch {
    if !mint_endpoint_here(endpoint, sni, port) {
        return PathMatch::None;
    }
    match_endpoint_path(&endpoint.path, target)
}

/// Whether a mint endpoint is served by the host and port of this connection.
///
/// A mint endpoint names a host and a path rather than a URL, so its port is
/// its own optional field, defaulting to the HTTPS port the rest of the
/// configuration's URLs default to.
fn mint_endpoint_here(endpoint: &MintEndpoint, sni: &str, port: u16) -> bool {
    endpoint.port.unwrap_or(DEFAULT_HTTPS_PORT) == port && endpoint.host.eq_ignore_ascii_case(sni)
}

/// Refuse a request target this proxy would have to normalise to compare.
///
/// The comparison against a configured path is a byte comparison, and the
/// number of ways to spell one path — percent-encoding, dot segments, doubled
/// slashes, an absolute-form target, a stray parameter — is not a list that
/// can be completed. So the target is held to the already-normalised
/// origin form instead: a path that is what it looks like. Everything else is
/// refused on a connection carrying a protected endpoint, where guessing
/// wrong in either direction ends with a credential in the sandbox.
///
/// Only the path is judged. A query string may hold anything a client wants
/// to put in it, because nothing here is compared with it.
fn reject_unnormalized_target(target: &str) -> io::Result<()> {
    let refuse = || {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth request target is not an already-normalised origin-form path",
        ))
    };
    let path = target.split('?').next().unwrap_or(target);
    // An absolute-form (`https://host/path`) or authority-form target does not
    // start with a slash, and neither does the asterisk-form of OPTIONS.
    if !path.starts_with('/') {
        return refuse();
    }
    if path.contains('%') || path.contains("//") || path.contains(';') || path.contains('#') {
        return refuse();
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return refuse();
    }
    Ok(())
}

/// Compare a request target with a configured endpoint path.
///
/// The query string is not part of the path, so it is dropped before the
/// comparison: an endpoint reached with `?retry=1` is still that endpoint, and
/// treating it as somewhere else is how a guest would have a token or a minted
/// key forwarded to it unread.
///
/// What is left is compared byte for byte, on a target
/// [`reject_unnormalized_target`] has already held to the origin form. Two
/// differences survive that: a trailing slash, and letter case. Neither is the
/// same path by the letter of RFC 3986, and both are the same handler in
/// plenty of routers, so each is reported as [`PathMatch::Equivalent`] —
/// neither accepted nor ignored, because which of the two the upstream host
/// agrees with is not ours to guess when a credential rides on the answer.
fn match_endpoint_path(path: &str, target: &str) -> PathMatch {
    let target_path = target.split('?').next().unwrap_or(target);
    if target_path == path {
        return PathMatch::Exact;
    }
    if without_trailing_slash(target_path).eq_ignore_ascii_case(without_trailing_slash(path)) {
        return PathMatch::Equivalent;
    }
    PathMatch::None
}

/// A path without the trailing slash it may or may not carry.
fn without_trailing_slash(path: &str) -> &str {
    match path.strip_suffix('/') {
        Some("") | None => path,
        Some(trimmed) => trimmed,
    }
}

fn expects_100_continue(headers: &[u8]) -> io::Result<bool> {
    let text = std::str::from_utf8(headers).map_err(|_| invalid_http())?;
    Ok(text.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("expect") && value.trim().eq_ignore_ascii_case("100-continue")
        })
    }))
}

fn reject_expect_100_continue(headers: &[u8]) -> io::Result<()> {
    if expects_100_continue(headers)? {
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

/// Rebuild a message around an identity-framed body, dropping whatever
/// framing the original carried.
fn rebuild_identity_message(headers: &[u8], body: &[u8]) -> io::Result<Vec<u8>> {
    let boundary = header_boundary(headers).ok_or_else(invalid_http)?;
    let text = std::str::from_utf8(&headers[..boundary]).map_err(|_| invalid_http())?;
    let mut output = String::new();
    for line in text.trim_end_matches("\r\n\r\n").split("\r\n") {
        if line.split_once(':').is_some_and(|(name, _)| {
            name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
        }) {
            continue;
        }
        output.push_str(line);
        output.push_str("\r\n");
    }
    output.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
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
            mint_endpoints: vec![],
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
        /// Secrets minted so far, reported back on every `load` and `acquire`.
        minted: Vec<(String, String)>,
        /// Every `mint` request the broker was sent.
        mints: Vec<Value>,
        /// Whether the broker refuses to store a minted secret.
        refuse_mint: bool,
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

        fn mints(&self) -> Vec<Value> {
            self.state.lock().unwrap().mints.clone()
        }

        /// Refuse the next `mint`, the way a broker with no room for the
        /// grant, or no grant at all, answers.
        fn refuse_mint(&self) {
            self.state.lock().unwrap().refuse_mint = true;
        }

        /// Report this secret as already minted, as it would be to a
        /// connection opened after the one that minted it.
        fn add_minted(&self, sentinel: &str, value: &str) {
            self.state
                .lock()
                .unwrap()
                .minted
                .push((sentinel.into(), value.into()));
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
            minted: Vec::new(),
            mints: Vec::new(),
            refuse_mint: false,
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
                                        if !state.minted.is_empty() {
                                            reply["minted"] = state
                                                .minted
                                                .iter()
                                                .map(|(sentinel, value)| {
                                                    serde_json::json!({
                                                        "sentinel": sentinel,
                                                        "value": value,
                                                    })
                                                })
                                                .collect::<Vec<_>>()
                                                .into();
                                        }
                                        reply
                                    }
                                    "mint" => {
                                        state.mints.push(request.clone());
                                        if state.refuse_mint {
                                            serde_json::json!({
                                                "ok": false,
                                                "error": "grant may not mint",
                                            })
                                        } else {
                                            let sentinel = format!(
                                                "$MSB_OAUTH_MINT_{:02}",
                                                state.minted.len()
                                            );
                                            let value =
                                                request["value"].as_str().unwrap().to_string();
                                            state.minted.push((sentinel.clone(), value));
                                            serde_json::json!({"ok": true, "sentinel": sentinel})
                                        }
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
            access_aliases: Vec::new(),
            refresh_aliases: Vec::new(),
            config,
            generation: 4,
            lease: None,
            poll_secrets: Vec::new(),
            minted: Vec::new(),
        }
    }

    fn connection_for(configs: Vec<OAuthSecret>) -> OAuthConnection {
        let grants: Vec<LoadedGrant> = configs.into_iter().map(loaded).collect();
        let mints_configured = grants
            .iter()
            .any(|grant| !grant.config.mint_endpoints.is_empty());
        OAuthConnection {
            grants,
            request_buffer: vec![],
            response_buffer: vec![],
            exchanges: VecDeque::new(),
            token_connection: None,
            connection_port: 443,
            response_scrub_buffer: Vec::new(),
            response_scrub_framing: Vec::new(),
            response_scrub_tail: Vec::new(),
            response_scrub_state: ResponseScrubState::Headers,
            pending_responses: VecDeque::new(),
            seen_tokens: vec![
                Zeroizing::new("real-access".into()),
                Zeroizing::new("real-refresh".into()),
            ],
            request_state: RequestState::Headers,
            mints_configured,
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
            .pending_responses
            .resize_with(MAX_OUTSTANDING_API_REQUESTS, || PendingResponse {
                head: false,
                mint: None,
            });

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
            connection.pending_responses.len(),
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
            assert!(connection.pending_responses.is_empty());
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

    #[tokio::test]
    async fn api_response_echoes_are_scrubbed() {
        let mut connection = connection();
        let input =
            b"HTTP/1.1 200 OK\r\nContent-Length: 35\r\n\r\nechoed real-access and real-refresh";
        let mut output = connection
            .scrub_response_chunk(b"HTTP/1.1 200 OK\r\nContent-Length: 35\r\n\r\nechoed real-ac")
            .await
            .unwrap();
        output.extend(
            connection
                .scrub_response_chunk(b"cess and real-refresh")
                .await
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

    #[tokio::test]
    async fn response_scrubbing_preserves_innocent_token_prefix_at_response_end() {
        let mut connection = connection();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\ninnocent real-ac";
        let output = connection.scrub_response_chunk(response).await.unwrap();

        assert_eq!(output, response);
    }

    #[tokio::test]
    async fn response_scrubbing_redacts_a_token_split_across_reads() {
        let mut connection = connection();
        let mut output = connection
            .scrub_response_chunk(b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\necho real-ac")
            .await
            .unwrap();
        output.extend(connection.scrub_response_chunk(b"cess done").await.unwrap());

        assert_eq!(
            output,
            b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\necho *********** done"
        );
    }

    #[tokio::test]
    async fn response_boundary_flushes_matcher_tail_on_keep_alive() {
        let mut connection = connection();
        let responses = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nreal-acHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ncess";
        let output = connection.scrub_response_chunk(responses).await.unwrap();

        assert_eq!(output, responses);
    }

    #[tokio::test]
    async fn chunked_response_redacts_token_split_across_chunks() {
        let mut connection = connection();
        let first = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nreal-\r\n";
        let second = b"6\r\naccess\r\n0\r\n\r\n";
        let mut output = connection.scrub_response_chunk(first).await.unwrap();
        output.extend(connection.scrub_response_chunk(second).await.unwrap());

        assert_eq!(
            output,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n*****\r\n6\r\n******\r\n0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn chunked_response_redacts_tokens_in_extensions() {
        let mut connection = connection();
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;token=real-access\r\nbody\r\n0\r\n\r\n";

        let output = connection.scrub_response_chunk(response).await.unwrap();

        assert_eq!(output.len(), response.len());
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("token=***********")
        );
    }

    #[tokio::test]
    async fn unresolved_token_prefix_cannot_grow_chunk_framing_past_limit() {
        let mut connection = connection();
        connection.seen_tokens = vec![Zeroizing::new("aaa".into())];
        let extension = "x".repeat(MAX_RESPONSE_SCRUB_FRAMING_BYTES / 2);
        let chunk = format!("1;x={extension}\r\na\r\n");

        connection
            .scrub_response_chunk(
                format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunk}").as_bytes(),
            )
            .await
            .unwrap();
        connection
            .scrub_response_chunk(chunk.as_bytes())
            .await
            .unwrap();
        let framing_len = connection.response_scrub_framing.len();
        let error = connection
            .scrub_response_chunk(chunk.as_bytes())
            .await
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

    #[tokio::test]
    async fn encoded_api_response_is_rejected_before_headers_are_released() {
        let mut connection = connection();
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 11\r\n\r\nreal-access";

        let error = connection.scrub_response_chunk(response).await.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "encoded OAuth responses are unsupported");
    }

    #[tokio::test]
    async fn switching_protocols_response_is_rejected_before_release() {
        let mut connection = connection();
        connection.pending_responses.push_back(PendingResponse {
            head: false,
            mint: None,
        });
        let response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

        let error = connection.scrub_response_chunk(response).await.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "OAuth API protocol upgrades are unsupported"
        );
    }

    #[tokio::test]
    async fn head_response_completes_at_headers_on_keep_alive() {
        let mut connection = connection();
        connection.pending_responses.push_back(PendingResponse {
            head: true,
            mint: None,
        });
        connection.pending_responses.push_back(PendingResponse {
            head: false,
            mint: None,
        });
        let responses = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";

        let output = connection.scrub_response_chunk(responses).await.unwrap();

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
    async fn load_response_sentinels_lead_and_the_configured_one_stays_live() {
        let broker = start_broker("real-access", "real-refresh");
        broker.set_sentinels(JWT_ACCESS_SENTINEL, JWT_REFRESH_SENTINEL);
        let config = broker_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.example.com", 443, None)
            .await
            .unwrap();

        // What the broker named leads: it is what sanitized responses carry.
        assert_eq!(connection.grants[0].access_sentinel, JWT_ACCESS_SENTINEL);
        assert_eq!(connection.grants[0].refresh_sentinel, JWT_REFRESH_SENTINEL);
        assert_eq!(
            connection.grants[0].access_aliases,
            ["$MSB_OAUTH_ACCESS_123"]
        );

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

        // The guest's environment variable still holds the configured
        // sentinel, so it has to keep substituting rather than travel.
        let stale =
            b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer $MSB_OAUTH_ACCESS_123\r\n\r\n";
        let upstream = String::from_utf8(
            connection
                .transform_requests(stale, "api.example.com")
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(upstream.contains("Authorization: Bearer real-access"));
        assert!(!upstream.contains("$MSB_OAUTH_ACCESS_123"));
    }

    #[tokio::test]
    async fn a_superseded_sentinel_still_substitutes_after_a_commit() {
        let broker = start_broker("old-access", "old-refresh");
        broker.set_commit_sentinels(JWT_ACCESS_SENTINEL, JWT_REFRESH_SENTINEL);
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
        connection
            .transform_responses(granted.as_bytes())
            .await
            .unwrap();
        assert_eq!(connection.grants[0].refresh_sentinel, JWT_REFRESH_SENTINEL);

        // A client that kept the sentinel it was given before the refresh —
        // in its environment, or a file it wrote — gets the current token,
        // and the superseded sentinel never reaches the provider.
        let stale = form_request(
            "/oauth/token",
            "grant_type=refresh_token&refresh_token=$MSB_OAUTH_REFRESH_123",
        );
        let upstream = String::from_utf8(
            connection
                .transform_requests(stale.as_bytes(), "auth.example.com")
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(upstream.contains("refresh_token=new-refresh"));
        assert!(!upstream.contains("$MSB_OAUTH_REFRESH_123"));
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

    #[tokio::test]
    async fn scrubbing_carries_a_split_token_without_touching_a_jwt_sentinel() {
        let body = format!(r#"{{"token":"real-access","sentinel":"{JWT_ACCESS_SENTINEL}"}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = response.as_bytes();
        let mut connection = connection();

        // Split inside the real token, and again inside the sentinel, so the
        // scrubber has to carry a partial match of the token across a write
        // and leave a partial match of the sentinel alone across another.
        let token_at = response
            .windows(b"real-access".len())
            .position(|window| window == b"real-access")
            .unwrap();
        let first = token_at + 5;
        let second = response.len() - 12;
        assert!(first > token_at && first < token_at + b"real-access".len());
        assert!(second > response.len() - JWT_ACCESS_SENTINEL.len());
        let mut output = connection
            .scrub_response_chunk(&response[..first])
            .await
            .unwrap();
        output.extend(
            connection
                .scrub_response_chunk(&response[first..second])
                .await
                .unwrap(),
        );
        output.extend(
            connection
                .scrub_response_chunk(&response[second..])
                .await
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
        let mut other = config();
        other.access_sentinel = "$OTHER_ACCESS".into();
        other.refresh_sentinel = "$OTHER_REFRESH".into();
        let mut grants = vec![loaded(config()), loaded(other)];
        let seen = vec![
            Zeroizing::new("real-access".to_string()),
            Zeroizing::new("real-refresh".to_string()),
        ];
        let adopt = |grants: &mut Vec<LoadedGrant>, access: Option<&str>, refresh: Option<&str>| {
            adopt_sentinels(
                grants,
                0,
                access.map(str::to_string),
                refresh.map(str::to_string),
                &seen,
            )
        };

        let error = adopt(&mut grants, Some(""), None).unwrap_err();
        assert_eq!(error.to_string(), "OAuth broker sentinel is empty");

        let long = "x".repeat(MAX_OAUTH_SENTINEL_BYTES + 1);
        let error = adopt(&mut grants, Some(&long), None).unwrap_err();
        assert_eq!(error.to_string(), "OAuth broker sentinel exceeds limit");

        for broken in ["a\0b", "a\rb", "a\nb"] {
            let error = adopt(&mut grants, Some(broken), None).unwrap_err();
            assert_eq!(
                error.to_string(),
                "OAuth broker sentinel contains a control character"
            );
        }

        // A sentinel that is one of the real tokens would hand that token to
        // the guest as its own stand-in — and so would one that merely
        // carries a token inside it, since the body it goes into is the one
        // that is never scrubbed.
        let error = adopt(&mut grants, Some("real-access"), None).unwrap_err();
        assert_eq!(
            error.to_string(),
            "OAuth broker sentinel overlaps a live token"
        );

        let error = adopt(&mut grants, Some("Bearer real-access."), None).unwrap_err();
        assert_eq!(
            error.to_string(),
            "OAuth broker sentinel overlaps a live token"
        );

        // The other direction too: a sentinel a token contains would be
        // half-substituted wherever that token appears.
        let error = adopt(&mut grants, Some("real-acc"), None).unwrap_err();
        assert_eq!(
            error.to_string(),
            "OAuth broker sentinel overlaps a live token"
        );

        // A sentinel another grant on this connection holds would substitute
        // that grant's token instead, and one that contains another grant's
        // sentinel would swallow it.
        let error = adopt(&mut grants, Some("$OTHER_REFRESH"), None).unwrap_err();
        assert_eq!(
            error.to_string(),
            "OAuth broker sentinel belongs to another grant"
        );

        let error = adopt(&mut grants, Some("$OTHER_ACCESS_AND_MORE"), None).unwrap_err();
        assert_eq!(
            error.to_string(),
            "OAuth broker sentinel belongs to another grant"
        );

        let error = adopt(&mut grants, Some("same"), Some("same")).unwrap_err();
        assert_eq!(error.to_string(), "OAuth broker sentinels must differ");

        // Nothing above changed the grant, and the accepted value leads while
        // the one it replaces stays live.
        assert_eq!(grants[0].access_sentinel, "$MSB_OAUTH_ACCESS_123");
        assert!(grants[0].access_aliases.is_empty());
        adopt(&mut grants, Some(JWT_ACCESS_SENTINEL), None).unwrap();
        assert_eq!(grants[0].access_sentinel, JWT_ACCESS_SENTINEL);
        assert_eq!(grants[0].access_aliases, ["$MSB_OAUTH_ACCESS_123"]);
        assert_eq!(grants[0].refresh_sentinel, "$MSB_OAUTH_REFRESH_123");

        // A sentinel this grant already holds as an alias may not be adopted
        // for the other token either, nor may one that overlaps it.
        let error = adopt(&mut grants, None, Some("$MSB_OAUTH_ACCESS_123")).unwrap_err();
        assert_eq!(error.to_string(), "OAuth broker sentinels must differ");

        let error = adopt(&mut grants, None, Some("$MSB_OAUTH_ACCESS_123_TOO")).unwrap_err();
        assert_eq!(error.to_string(), "OAuth broker sentinels must differ");

        // A substring of the sentinel this grant just adopted is no better:
        // substituting one would leave the rest of the other behind.
        let error = adopt(&mut grants, None, Some(&JWT_ACCESS_SENTINEL[..20])).unwrap_err();
        assert_eq!(error.to_string(), "OAuth broker sentinels must differ");

        // Re-naming the sentinel it already holds is not a collision with
        // itself.
        adopt(&mut grants, Some(JWT_ACCESS_SENTINEL), None).unwrap();
        assert_eq!(grants[0].access_aliases, ["$MSB_OAUTH_ACCESS_123"]);
    }

    #[test]
    fn live_sentinels_per_grant_are_bounded() {
        let mut grants = vec![loaded(config())];
        let seen: Vec<Zeroizing<String>> = vec![];

        for round in 0..MAX_GRANT_SENTINEL_ALIASES {
            adopt_sentinels(
                &mut grants,
                0,
                Some(format!("$ACCESS_{round:03}")),
                None,
                &seen,
            )
            .unwrap();
        }
        assert_eq!(grants[0].access_aliases.len(), MAX_GRANT_SENTINEL_ALIASES);

        let error =
            adopt_sentinels(&mut grants, 0, Some("$ACCESS_OVER".into()), None, &seen).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "too many OAuth sentinels for one grant");
        // Re-naming one the grant already holds is not a new sentinel.
        adopt_sentinels(&mut grants, 0, Some("$ACCESS_000".into()), None, &seen).unwrap();
        assert_eq!(grants[0].access_sentinel, "$ACCESS_000");
    }

    #[test]
    fn a_pair_that_cannot_be_adopted_leaves_the_grant_untouched() {
        let mut grants = vec![loaded(config())];
        let seen: Vec<Zeroizing<String>> = vec![];
        for round in 0..MAX_GRANT_SENTINEL_ALIASES {
            adopt_sentinels(
                &mut grants,
                0,
                None,
                Some(format!("$REFRESH_{round:03}")),
                &seen,
            )
            .unwrap();
        }

        // The access half is adoptable, the refresh half is one too many.
        let error = adopt_sentinels(
            &mut grants,
            0,
            Some("$NEW_ACCESS".into()),
            Some("$REFRESH_OVER".into()),
            &seen,
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "too many OAuth sentinels for one grant");
        assert_eq!(grants[0].access_sentinel, "$MSB_OAUTH_ACCESS_123");
        assert!(grants[0].access_aliases.is_empty());
        assert_eq!(grants[0].refresh_sentinel, "$REFRESH_063");
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
        assert_eq!(
            error.to_string(),
            "OAuth broker sentinel overlaps a live token"
        );
    }

    #[test]
    fn every_bearer_header_carrying_the_sentinel_is_replaced() {
        // One request, three Authorization headers: a client retrying with a
        // second one, and a third holding something else entirely.
        let request = format!(
            "GET /v1 HTTP/1.1\r\nAuthorization: Bearer {JWT_ACCESS_SENTINEL}\r\nAuthorization: Bearer {JWT_ACCESS_SENTINEL}\r\nAuthorization: Bearer someone-elses\r\n\r\n"
        );

        let output = replace_bearer_header(
            request.as_bytes(),
            JWT_ACCESS_SENTINEL.as_bytes(),
            b"real-access",
        );

        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.matches("Bearer real-access").count(), 2);
        assert!(output.contains("Bearer someone-elses"));
        assert!(!output.contains("eyJ"));
    }

    #[test]
    fn a_header_whose_name_merely_ends_in_authorization_is_left_alone() {
        let request = format!(
            "GET /v1 HTTP/1.1\r\nX-Retry-Authorization: Bearer {JWT_ACCESS_SENTINEL}\r\nAuthorization: Bearer {JWT_ACCESS_SENTINEL}\r\n\r\n"
        );

        let output = replace_bearer_header(
            request.as_bytes(),
            JWT_ACCESS_SENTINEL.as_bytes(),
            b"real-access",
        );

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(&format!(
            "X-Retry-Authorization: Bearer {JWT_ACCESS_SENTINEL}\r\n"
        )));
        assert!(output.contains("\r\nAuthorization: Bearer real-access\r\n"));
        assert_eq!(output.matches("real-access").count(), 1);
    }

    #[tokio::test]
    async fn a_grant_may_not_take_a_sentinel_another_grant_was_configured_with() {
        let first_broker = start_broker("first-access", "first-refresh");
        let second_broker = start_broker("second-access", "second-refresh");
        let first = broker_config(&first_broker);
        let mut second = broker_config(&second_broker);
        second.access_sentinel = "$OTHER_ACCESS".into();
        second.refresh_sentinel = "$OTHER_REFRESH".into();
        // The first grant's broker names the sentinel the second grant's
        // guest already holds in its environment.
        first_broker.set_sentinels("$OTHER_ACCESS", JWT_REFRESH_SENTINEL);

        let Err(error) = OAuthConnection::new(&[first, second], "api.example.com", 443, None).await
        else {
            panic!("the connection must not open with a colliding sentinel");
        };

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "OAuth broker sentinel belongs to another grant"
        );
    }

    #[tokio::test]
    async fn a_grant_may_not_take_a_sentinel_that_is_another_grants_token() {
        let first_broker = start_broker("first-access", "first-refresh");
        let second_broker = start_broker("second-access", "second-refresh");
        let first = broker_config(&first_broker);
        let mut second = broker_config(&second_broker);
        second.access_sentinel = "$OTHER_ACCESS".into();
        second.refresh_sentinel = "$OTHER_REFRESH".into();
        // The second grant is loaded after the first, so only a check that
        // waits for the whole connection sees this.
        first_broker.set_sentinels("second-access", JWT_REFRESH_SENTINEL);

        let Err(error) = OAuthConnection::new(&[first, second], "api.example.com", 443, None).await
        else {
            panic!("the connection must not open with a colliding sentinel");
        };

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "OAuth broker sentinel overlaps a live token"
        );
    }

    /// Anthropic's console mode: the CLI posts to an inject host with the
    /// access token and is handed a brand new API key in `raw_key`.
    fn anthropic_config(broker: &FakeBroker) -> OAuthSecret {
        let mut config = broker_config(broker);
        config.token_endpoint = "https://console.anthropic.com/v1/oauth/token".into();
        config.inject_hosts = vec![HostPattern::Exact("api.anthropic.com".into())];
        config.mint_endpoints = vec![MintEndpoint {
            host: "api.anthropic.com".into(),
            path: "/api/oauth/claude_cli/create_api_key".into(),
            field: "raw_key".into(),
            port: None,
        }];
        config
    }

    const RAW_KEY: &str = "sk-ant-api03-real-minted-key";

    #[tokio::test]
    async fn a_minted_api_key_is_sentineled_and_substituted_back() {
        let broker = start_broker("real-access", "real-refresh");
        let config = anthropic_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();

        let request = json_request(
            "/api/oauth/claude_cli/create_api_key",
            r#"{"scopes":["user:inference"]}"#,
        );
        connection
            .transform_requests(request.as_bytes(), "api.anthropic.com")
            .await
            .unwrap();

        let response = json_response(200, &format!(r#"{{"raw_key":"{RAW_KEY}"}}"#));
        assert!(
            response.contains(RAW_KEY),
            "the upstream body carries the key"
        );
        let output = connection
            .scrub_response_chunk(response.as_bytes())
            .await
            .unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(!output.contains(RAW_KEY), "guest body: {output}");
        assert!(
            output.contains("$MSB_OAUTH_MINT_00"),
            "guest body: {output}"
        );
        assert_eq!(broker.mints().len(), 1);
        assert_eq!(broker.mints()[0]["action"], "mint");
        assert_eq!(broker.mints()[0]["grant_id"], "opaque-grant");
        assert_eq!(broker.mints()[0]["field"], "raw_key");
        assert_eq!(broker.mints()[0]["value"], RAW_KEY);
        assert!(
            connection
                .seen_tokens
                .iter()
                .any(|token| token.as_str() == RAW_KEY),
            "the real key is scrubbed out of later responses",
        );

        // The guest sends the sentinel back in the header an API key travels
        // in, and the real key goes upstream.
        let keyed = "GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nx-api-key: $MSB_OAUTH_MINT_00\r\n\r\n";
        let upstream = connection
            .transform_requests(keyed.as_bytes(), "api.anthropic.com")
            .await
            .unwrap();
        let upstream = String::from_utf8(upstream).unwrap();
        assert!(
            upstream.contains(&format!("x-api-key: {RAW_KEY}")),
            "{upstream}"
        );

        // And in a JSON body, whose length is corrected on the way out.
        let body = r#"{"key":"$MSB_OAUTH_MINT_00"}"#;
        let bodied = json_request("/v1/messages", body);
        let upstream = connection
            .transform_requests(bodied.as_bytes(), "api.anthropic.com")
            .await
            .unwrap();
        let upstream = String::from_utf8(upstream).unwrap();
        let expected = format!(r#"{{"key":"{RAW_KEY}"}}"#);
        assert!(upstream.ends_with(&expected), "{upstream}");
        assert!(
            upstream.contains(&format!("Content-Length: {}", expected.len())),
            "{upstream}"
        );
    }

    #[tokio::test]
    async fn a_broker_that_will_not_mint_fails_the_response_closed() {
        let broker = start_broker("real-access", "real-refresh");
        let config = anthropic_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();
        broker.refuse_mint();

        let request = json_request("/api/oauth/claude_cli/create_api_key", "{}");
        connection
            .transform_requests(request.as_bytes(), "api.anthropic.com")
            .await
            .unwrap();

        let response = json_response(200, &format!(r#"{{"raw_key":"{RAW_KEY}"}}"#));
        let error = connection
            .scrub_response_chunk(response.as_bytes())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "OAuth broker refused to mint a secret");
    }

    #[tokio::test]
    async fn a_minted_secret_the_broker_reports_substitutes_on_a_fresh_connection() {
        let broker = start_broker("real-access", "real-refresh");
        broker.add_minted("$MSB_OAUTH_MINT_00", RAW_KEY);
        let config = anthropic_config(&broker);

        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();

        assert_eq!(connection.grants[0].minted.len(), 1);
        let keyed = "GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer $MSB_OAUTH_MINT_00\r\n\r\n";
        let upstream = connection
            .transform_requests(keyed.as_bytes(), "api.anthropic.com")
            .await
            .unwrap();

        let upstream = String::from_utf8(upstream).unwrap();
        assert!(
            upstream.contains(&format!("Bearer {RAW_KEY}")),
            "{upstream}"
        );
    }

    #[tokio::test]
    async fn minted_secrets_per_grant_are_bounded() {
        let broker = start_broker("real-access", "real-refresh");
        for index in 0..=MAX_GRANT_MINTED_SECRETS {
            broker.add_minted(
                &format!("$MSB_OAUTH_MINT_{index:02}"),
                &format!("minted-secret-{index:02}"),
            );
        }
        let config = anthropic_config(&broker);

        let Err(error) = OAuthConnection::new(&[config], "api.anthropic.com", 443, None).await
        else {
            panic!("the connection must not open past the minted secret bound");
        };

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "too many OAuth minted secrets for one grant"
        );
    }

    #[tokio::test]
    async fn a_target_carrying_a_query_still_reaches_the_configured_endpoint() {
        // The query is not part of the path, so appending one must not turn a
        // token request into an API request whose response nothing sanitizes.
        let body = r#"{"refresh":"$MSB_OAUTH_REFRESH_123"}"#;
        let request = format!(
            "POST /oauth/token?retry=1 HTTP/1.1\r\nHost: auth.example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut connection = connection();
        connection.grants[0].lease = Some(UnixStream::pair().unwrap().0);

        let output = connection
            .transform_requests(request.as_bytes(), "auth.example.com")
            .await
            .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("real-refresh"), "{output}");
        assert!(!output.contains("$MSB_OAUTH_"), "{output}");
        assert_eq!(connection.exchanges.len(), 1);
    }

    #[tokio::test]
    async fn a_mint_target_carrying_a_query_still_mints() {
        let broker = start_broker("real-access", "real-refresh");
        let config = anthropic_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();

        let request = json_request("/api/oauth/claude_cli/create_api_key?source=cli", "{}");
        connection
            .transform_requests(request.as_bytes(), "api.anthropic.com")
            .await
            .unwrap();
        let response = json_response(200, &format!(r#"{{"raw_key":"{RAW_KEY}"}}"#));
        let output = connection
            .scrub_response_chunk(response.as_bytes())
            .await
            .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains(RAW_KEY), "{output}");
        assert!(output.contains("$MSB_OAUTH_MINT_00"), "{output}");
    }

    #[tokio::test]
    async fn a_chunked_mint_response_is_read_and_handed_back_with_a_length() {
        let broker = start_broker("real-access", "real-refresh");
        let config = anthropic_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();
        connection
            .transform_requests(
                json_request("/api/oauth/claude_cli/create_api_key", "{}").as_bytes(),
                "api.anthropic.com",
            )
            .await
            .unwrap();

        let body = format!(r#"{{"raw_key":"{RAW_KEY}"}}"#);
        let (first, second) = body.split_at(10);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\n\r\n",
            first.len(),
            second.len(),
        );
        // Split mid-body: the response is only rewritten once all of it is in.
        let split = response.len() - 12;
        let held = connection
            .scrub_response_chunk(&response.as_bytes()[..split])
            .await
            .unwrap();
        assert!(held.is_empty(), "nothing is released before the last chunk");

        let output = connection
            .scrub_response_chunk(&response.as_bytes()[split..])
            .await
            .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains(RAW_KEY), "{output}");
        assert!(output.contains("$MSB_OAUTH_MINT_00"), "{output}");
        assert!(
            !output.to_ascii_lowercase().contains("transfer-encoding"),
            "{output}"
        );
        let minted = r#"{"raw_key":"$MSB_OAUTH_MINT_00"}"#;
        assert!(output.ends_with(minted), "{output}");
        assert!(
            output.contains(&format!("Content-Length: {}", minted.len())),
            "{output}"
        );
    }

    #[tokio::test]
    async fn an_unframed_response_on_a_minting_connection_fails_closed() {
        let broker = start_broker("real-access", "real-refresh");
        let config = anthropic_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();

        // An ordinary API response, which the scrubber has to follow to its
        // end so that it knows where the mint response begins.
        connection
            .transform_requests(
                b"GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
                "api.anthropic.com",
            )
            .await
            .unwrap();
        let error = connection
            .scrub_response_chunk(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}")
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "OAuth responses on a minting connection require Content-Length or chunked framing"
        );

        // And the mint response itself, which is read whole or not at all.
        let mut connection =
            OAuthConnection::new(&[anthropic_config(&broker)], "api.anthropic.com", 443, None)
                .await
                .unwrap();
        connection
            .transform_requests(
                json_request("/api/oauth/claude_cli/create_api_key", "{}").as_bytes(),
                "api.anthropic.com",
            )
            .await
            .unwrap();
        let error = connection
            .scrub_response_chunk(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}")
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "OAuth mint endpoint responses require Content-Length or chunked framing"
        );
    }

    #[tokio::test]
    async fn an_unframed_response_without_a_mint_endpoint_streams_untouched() {
        // Nothing on a connection without mint endpoints has to be read
        // whole, so the framing rule above must not reach it.
        let mut connection = connection();
        connection.pending_responses.push_back(PendingResponse {
            head: false,
            mint: None,
        });
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";

        let output = connection.scrub_response_chunk(response).await.unwrap();

        assert_eq!(output, response);
        assert!(connection.finish_response_scrubbing().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_held_request_body_is_not_a_new_place_to_substitute_the_access_sentinel() {
        // Holding the body so a minted sentinel in it can be substituted must
        // not widen where the access token goes: on an inject host it belongs
        // in a bearer header and nowhere else.
        let broker = start_broker("real-access", "real-refresh");
        let config = anthropic_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();
        let body = r#"{"token":"$MSB_OAUTH_ACCESS_123"}"#;
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer $MSB_OAUTH_ACCESS_123\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );

        let output = connection
            .transform_requests(request.as_bytes(), "api.anthropic.com")
            .await
            .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Bearer real-access"), "{output}");
        assert!(output.ends_with(body), "{output}");
    }

    /// A grant whose whole device flow lives on one host, so the near-miss
    /// arms for the device code and poll endpoints have something to hit.
    fn device_flow_config() -> OAuthSecret {
        let mut config = config();
        config.device_code_endpoint = Some("https://auth.example.com/oauth/device/code".into());
        config.poll_endpoint = Some("https://auth.example.com/oauth/device/token".into());
        config
    }

    #[tokio::test]
    async fn a_target_this_proxy_would_have_to_normalise_is_refused() {
        // Every one of these is a spelling of a path, and which of them the
        // upstream host resolves to the token endpoint is its business, not a
        // guess to make with a refresh token riding on the answer.
        for target in [
            "//oauth/token",
            "/oauth%2Ftoken",
            "/%2e/oauth/token",
            "/oauth/./token",
            "/oauth/x/../token",
            "/oauth/token%20",
            "https://auth.example.com/oauth/token",
            "auth.example.com:443",
            "*",
            "/oauth/token;v=1",
            "/oauth/token#fragment",
            "//oauth/token?retry=1",
        ] {
            let request = format!(
                "POST {target} HTTP/1.1\r\nHost: auth.example.com\r\nContent-Length: 0\r\n\r\n"
            );
            let mut connection = connection_for(vec![device_flow_config()]);

            let error = connection
                .transform_requests(request.as_bytes(), "auth.example.com")
                .await
                .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "OAuth request target is not an already-normalised origin-form path",
                "target {target}"
            );
        }
    }

    #[tokio::test]
    async fn a_trailing_slash_or_a_change_of_case_fails_closed() {
        // The two differences the origin-form rule lets through, and the two
        // plenty of routers treat as the same handler.
        for (target, kind) in [
            ("/oauth/token/", "token"),
            ("/oauth/device/code/", "device code"),
            ("/oauth/device/token/", "poll"),
            ("/OAUTH/TOKEN", "token"),
            ("/oauth/Device/code", "device code"),
            ("/oauth/device/TOKEN/", "poll"),
        ] {
            let request = format!(
                "POST {target} HTTP/1.1\r\nHost: auth.example.com\r\nContent-Length: 0\r\n\r\n"
            );
            let mut connection = connection_for(vec![device_flow_config()]);

            let error = connection
                .transform_requests(request.as_bytes(), "auth.example.com")
                .await
                .unwrap_err();

            assert_eq!(
                error.to_string(),
                format!("OAuth {kind} endpoint request target is not the configured path"),
                "target {target}"
            );
        }
    }

    #[tokio::test]
    async fn an_inject_host_without_an_endpoint_keeps_its_own_targets() {
        // Nothing on this connection is compared with a request target, so
        // the origin-form rule has no business narrowing what the guest may
        // ask an ordinary API for.
        let broker = start_broker("real-access", "real-refresh");
        let mut connection = connection_for(vec![broker_config(&broker)]);
        let request = "GET /v1/files/a%20b//c HTTP/1.1\r\nHost: api.example.com\r\n\r\n";

        let output = connection
            .transform_requests(request.as_bytes(), "api.example.com")
            .await
            .unwrap();

        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("/v1/files/a%20b//c"),
            "the target reaches the upstream host as it was written",
        );
    }

    #[tokio::test]
    async fn a_near_miss_mint_target_fails_closed() {
        let broker = start_broker("real-access", "real-refresh");
        for (target, expected) in [
            (
                "//api/oauth/claude_cli/create_api_key",
                "OAuth request target is not an already-normalised origin-form path",
            ),
            (
                "/api%2Foauth/claude_cli/create_api_key",
                "OAuth request target is not an already-normalised origin-form path",
            ),
            (
                "/api/oauth/claude_cli/../claude_cli/create_api_key",
                "OAuth request target is not an already-normalised origin-form path",
            ),
            (
                "/api/oauth/claude_cli/create_api_key/",
                "OAuth mint endpoint request target is not the configured path",
            ),
            (
                "/api/oauth/claude_cli/Create_API_Key",
                "OAuth mint endpoint request target is not the configured path",
            ),
        ] {
            let config = anthropic_config(&broker);
            let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
                .await
                .unwrap();
            let request = json_request(target, "{}");

            let error = connection
                .transform_requests(request.as_bytes(), "api.anthropic.com")
                .await
                .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), expected, "target {target}");
        }
        assert!(broker.mints().is_empty());
    }

    #[tokio::test]
    async fn a_mint_endpoint_on_another_port_is_not_this_connection() {
        // The other endpoints match on the port in their URL; a mint endpoint
        // says its port itself, and a connection to another one is not it.
        let broker = start_broker("real-access", "real-refresh");
        let mut config = anthropic_config(&broker);
        config.mint_endpoints[0].port = Some(8443);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();

        connection
            .transform_requests(
                json_request("/api/oauth/claude_cli/create_api_key", "{}").as_bytes(),
                "api.anthropic.com",
            )
            .await
            .unwrap();
        let response = json_response(200, &format!(r#"{{"raw_key":"{RAW_KEY}"}}"#));
        let output = connection
            .scrub_response_chunk(response.as_bytes())
            .await
            .unwrap();

        assert_eq!(String::from_utf8(output).unwrap(), response);
        assert!(broker.mints().is_empty());

        // On the port it names, the same request mints.
        let mut config = anthropic_config(&broker);
        config.mint_endpoints[0].port = Some(8443);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 8443, None)
            .await
            .unwrap();
        connection
            .transform_requests(
                json_request("/api/oauth/claude_cli/create_api_key", "{}").as_bytes(),
                "api.anthropic.com",
            )
            .await
            .unwrap();
        let output = connection
            .scrub_response_chunk(response.as_bytes())
            .await
            .unwrap();

        assert!(!String::from_utf8(output).unwrap().contains(RAW_KEY));
        assert_eq!(broker.mints().len(), 1);
    }

    #[tokio::test]
    async fn a_mint_response_without_the_field_fails_closed() {
        // The detector that would otherwise notice a credential in an
        // unrecognised body is off here: a grant is relevant to this
        // connection. So the endpoint answers in the shape it was configured
        // for, or the connection ends.
        let broker = start_broker("real-access", "real-refresh");
        for body in [
            r#"{"ok":true}"#,
            r#"{"raw_key":{"nested":"no"}}"#,
            r#"["raw_key"]"#,
        ] {
            let config = anthropic_config(&broker);
            let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
                .await
                .unwrap();
            connection
                .transform_requests(
                    json_request("/api/oauth/claude_cli/create_api_key", "{}").as_bytes(),
                    "api.anthropic.com",
                )
                .await
                .unwrap();

            let error = connection
                .scrub_response_chunk(json_response(200, body).as_bytes())
                .await
                .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "OAuth mint endpoint response did not carry field raw_key",
                "body {body}"
            );
        }
        assert!(broker.mints().is_empty());
    }

    #[tokio::test]
    async fn a_mint_endpoint_error_or_non_json_response_is_forwarded_as_it_is() {
        let broker = start_broker("real-access", "real-refresh");
        let config = anthropic_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();

        let responses = [
            json_response(400, r#"{"error":"invalid_scope"}"#),
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 8\r\n\r\nnot json"
                .to_string(),
        ];
        for response in responses {
            connection
                .transform_requests(
                    json_request("/api/oauth/claude_cli/create_api_key", "{}").as_bytes(),
                    "api.anthropic.com",
                )
                .await
                .unwrap();

            let output = connection
                .scrub_response_chunk(response.as_bytes())
                .await
                .unwrap();

            assert_eq!(String::from_utf8(output).unwrap(), response);
        }
        assert!(
            broker.mints().is_empty(),
            "neither response minted anything",
        );
    }

    #[tokio::test]
    async fn a_response_before_the_mint_response_reaches_the_guest_unchanged() {
        let broker = start_broker("real-access", "real-refresh");
        let config = anthropic_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();
        connection
            .transform_requests(
                b"GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
                "api.anthropic.com",
            )
            .await
            .unwrap();
        connection
            .transform_requests(
                json_request("/api/oauth/claude_cli/create_api_key", "{}").as_bytes(),
                "api.anthropic.com",
            )
            .await
            .unwrap();

        // Both responses arrive in one read, the way a pipelining server's do.
        let first = json_response(200, r#"{"models":["a"]}"#);
        let second = json_response(200, &format!(r#"{{"raw_key":"{RAW_KEY}"}}"#));
        let output = connection
            .scrub_response_chunk(format!("{first}{second}").as_bytes())
            .await
            .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with(&first), "{output}");
        assert!(!output.contains(RAW_KEY), "{output}");
        assert!(output.contains("$MSB_OAUTH_MINT_00"), "{output}");
    }

    #[tokio::test]
    async fn a_chunked_mint_response_drops_its_trailers() {
        let broker = start_broker("real-access", "real-refresh");
        let config = anthropic_config(&broker);
        let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
            .await
            .unwrap();
        connection
            .transform_requests(
                json_request("/api/oauth/claude_cli/create_api_key", "{}").as_bytes(),
                "api.anthropic.com",
            )
            .await
            .unwrap();

        let body = format!(r#"{{"raw_key":"{RAW_KEY}"}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTrailer: X-Checksum\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\nX-Checksum: abc\r\n\r\n",
            body.len(),
        );

        let output = connection
            .scrub_response_chunk(response.as_bytes())
            .await
            .unwrap();

        let output = String::from_utf8(output).unwrap();
        // The body is identity-framed now, so a trailer has nowhere to live.
        assert!(!output.contains("X-Checksum: abc"), "{output}");
        assert!(
            output.ends_with(r#"{"raw_key":"$MSB_OAUTH_MINT_00"}"#),
            "{output}"
        );
    }

    #[tokio::test]
    async fn an_oversized_or_malformed_chunked_mint_response_fails_closed() {
        let broker = start_broker("real-access", "real-refresh");
        for chunks in [
            // A chunk that claims more than any OAuth message may carry.
            "fffffffff\r\n",
            // A size line that is not a size.
            "zz\r\nbody\r\n0\r\n\r\n",
            // A chunk whose data is not followed by CRLF.
            "4\r\nbodyX0\r\n\r\n",
        ] {
            let config = anthropic_config(&broker);
            let mut connection = OAuthConnection::new(&[config], "api.anthropic.com", 443, None)
                .await
                .unwrap();
            connection
                .transform_requests(
                    json_request("/api/oauth/claude_cli/create_api_key", "{}").as_bytes(),
                    "api.anthropic.com",
                )
                .await
                .unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}"
            );

            let error = connection
                .scrub_response_chunk(response.as_bytes())
                .await
                .unwrap_err();

            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "chunks {chunks:?}"
            );
        }
        assert!(broker.mints().is_empty());
    }
}
