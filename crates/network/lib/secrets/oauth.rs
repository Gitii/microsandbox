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

use super::config::OAuthSecret;
use super::handler::host_pattern_allowed_for_tls;
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_OAUTH_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BROKER_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_OUTSTANDING_API_REQUESTS: usize = 1024;
const BROKER_TIMEOUT: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-connection OAuth request/response transformer.
pub(crate) struct OAuthConnection {
    grants: Vec<LoadedGrant>,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    exchanges: VecDeque<Option<usize>>,
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
    endpoint_host: String,
    endpoint_port: u16,
    endpoint_target: String,
    access: Zeroizing<String>,
    refresh: Zeroizing<String>,
    generation: u64,
    lease: Option<UnixStream>,
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
}

#[derive(Deserialize)]
struct CommitResponse {
    ok: bool,
    #[serde(default)]
    conflict: bool,
    generation: Option<u64>,
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
            let (endpoint_host, endpoint_port, endpoint_target) =
                parse_https_endpoint(&config.token_endpoint)?;
            let host_allowed = |matches: bool| {
                matches
                    && identity.is_none_or(|(guest_ip, shared)| {
                        shared.any_resolved_hostname(guest_ip, |hostname| {
                            hostname.eq_ignore_ascii_case(sni)
                        })
                    })
            };
            let endpoint_relevant =
                port == endpoint_port && host_allowed(endpoint_host.eq_ignore_ascii_case(sni));
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
            remember_token(&mut seen_tokens, &loaded.access);
            remember_token(&mut seen_tokens, &loaded.refresh);
            grants.push(LoadedGrant {
                config: config.clone(),
                endpoint_host,
                endpoint_port,
                endpoint_target,
                access: Zeroizing::new(loaded.access),
                refresh: Zeroizing::new(loaded.refresh),
                generation: loaded.generation,
                lease: None,
            });
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
        let mut output = Vec::new();
        let mut pending = data.to_vec();
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
                    }
                }
                ResponseScrubState::ContentLength(remaining) => {
                    let consumed = remaining.min(pending.len());
                    self.scrub_stream_bytes(&pending[..consumed], &mut output);
                    pending.drain(..consumed);
                    if consumed == remaining {
                        self.flush_scrub_tail(&mut output);
                        self.response_scrub_state = ResponseScrubState::Headers;
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
                        self.response_scrub_framing.extend_from_slice(&line);
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
                    self.response_scrub_framing.extend_from_slice(b"\r\n");
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
                }
                ResponseScrubState::CloseDelimited => {
                    self.scrub_stream_bytes(&pending, &mut output);
                    break;
                }
            }
        }
        Ok(output)
    }

    pub(crate) fn finish_response_scrubbing(&mut self) -> io::Result<Vec<u8>> {
        if self.token_connection == Some(true) {
            if !self.response_buffer.is_empty() || !self.exchanges.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete OAuth token response",
                ));
            }
            return Ok(Vec::new());
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
                    let endpoint_grants = self
                        .grants
                        .iter()
                        .enumerate()
                        .filter(|(_, grant)| {
                            grant.endpoint_host.eq_ignore_ascii_case(sni)
                                && grant.endpoint_port == self.connection_port
                                && grant.endpoint_target == target
                        })
                        .collect::<Vec<_>>();
                    let framing = request_body_framing(&headers)?;
                    let body_len = match framing {
                        RequestBodyFraming::None | RequestBodyFraming::Chunked => 0,
                        RequestBodyFraming::ContentLength(length) => length,
                    };
                    let total_len = header_end.checked_add(body_len).ok_or_else(invalid_http)?;
                    let endpoint_request = !endpoint_grants.is_empty();
                    if endpoint_request {
                        if !method.eq_ignore_ascii_case("POST") {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "OAuth token endpoint requests must use POST",
                            ));
                        }
                        reject_expect_100_continue(&headers)?;
                        if matches!(framing, RequestBodyFraming::Chunked) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "OAuth token endpoint chunked requests are unsupported",
                            ));
                        }
                        if self.request_buffer.len() < total_len {
                            break;
                        }
                    }
                    let matching_grants = endpoint_grants
                        .iter()
                        .filter(|(_, grant)| {
                            contains_bytes(
                                &self.request_buffer,
                                grant.config.access_sentinel.as_bytes(),
                            ) || contains_bytes(
                                &self.request_buffer,
                                grant.config.refresh_sentinel.as_bytes(),
                            )
                        })
                        .map(|(index, _)| *index)
                        .collect::<Vec<_>>();
                    let token_grant = match matching_grants.as_slice() {
                        [index] => Some(*index),
                        [] if endpoint_grants.len() == 1 => Some(endpoint_grants[0].0),
                        [] if endpoint_grants.is_empty() => None,
                        [] => return Err(invalid_http()),
                        _ => return Err(invalid_http()),
                    };
                    let is_token_request = token_grant.is_some();
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
                    if token_grant.is_some() && self.exchanges.iter().any(Option::is_some) {
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
                        remember_token(&mut self.seen_tokens, &loaded.access);
                        remember_token(&mut self.seen_tokens, &loaded.refresh);
                        let grant = &mut self.grants[index];
                        grant.access = Zeroizing::new(loaded.access);
                        grant.refresh = Zeroizing::new(loaded.refresh);
                        grant.generation = loaded.generation;
                        grant.lease = Some(lease);
                    }
                    for (index, grant) in self.grants.iter_mut().enumerate() {
                        let inject = grant
                            .config
                            .inject_hosts
                            .iter()
                            .any(|host| host.matches(sni));
                        if inject && token_grant != Some(index) {
                            let loaded = broker_load(&grant.config).await?;
                            remember_token(&mut self.seen_tokens, &loaded.access);
                            remember_token(&mut self.seen_tokens, &loaded.refresh);
                            grant.access = Zeroizing::new(loaded.access);
                            grant.refresh = Zeroizing::new(loaded.refresh);
                            grant.generation = loaded.generation;
                        }
                        if inject || token_grant == Some(index) {
                            rewritten = if inject && token_grant != Some(index) {
                                replace_bearer_header(
                                    &rewritten,
                                    grant.config.access_sentinel.as_bytes(),
                                    grant.access.as_bytes(),
                                )
                            } else {
                                replace_all(
                                    &rewritten,
                                    grant.config.access_sentinel.as_bytes(),
                                    grant.access.as_bytes(),
                                )
                            };
                        }
                        if token_grant == Some(index) {
                            rewritten = replace_all(
                                &rewritten,
                                grant.config.refresh_sentinel.as_bytes(),
                                grant.refresh.as_bytes(),
                            );
                        }
                    }
                    if let Some(index) = token_grant {
                        validate_token_request_content_type(&headers)?;
                        rewritten = update_content_length(&rewritten)?;
                        self.exchanges.push_back(Some(index));
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
                Some(index) if (200..300).contains(&status) => {
                    self.sanitize_token_response(index, &headers, &body).await?
                }
                Some(index) => {
                    let rewritten = self.sanitize_token_error(index, &headers, &body)?;
                    self.grants[index].lease = None;
                    rewritten
                }
                _ => response,
            };
            output.extend_from_slice(&self.scrub_tokens(rewritten));
            self.response_buffer.drain(..total_len);
        }
        Ok(output)
    }

    async fn sanitize_token_response(
        &mut self,
        index: usize,
        headers: &[u8],
        body: &[u8],
    ) -> io::Result<Vec<u8>> {
        let grant = &mut self.grants[index];
        let mut json: Value = serde_json::from_slice(body)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed OAuth response"))?;
        let object = json.as_object_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "OAuth response must be an object",
            )
        })?;
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
        let generation = broker_commit(grant, &access, &refresh, expires_at).await?;
        remember_token(&mut self.seen_tokens, &access);
        remember_token(&mut self.seen_tokens, &refresh);
        grant.access = Zeroizing::new(access);
        grant.refresh = Zeroizing::new(refresh);
        grant.generation = generation;
        grant.lease = None;
        object.insert(
            grant.config.access_token_field.clone(),
            Value::String(grant.config.access_sentinel.clone()),
        );
        if object.contains_key(&grant.config.refresh_token_field) {
            object.insert(
                grant.config.refresh_token_field.clone(),
                Value::String(grant.config.refresh_sentinel.clone()),
            );
        }
        let body = serde_json::to_vec(&json).map_err(io::Error::other)?;
        rebuild_message(headers, &body)
    }

    fn sanitize_token_error(
        &self,
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
        if object.contains_key(&grant.config.access_token_field) {
            object.insert(
                grant.config.access_token_field.clone(),
                Value::String(grant.config.access_sentinel.clone()),
            );
        }
        if object.contains_key(&grant.config.refresh_token_field) {
            object.insert(
                grant.config.refresh_token_field.clone(),
                Value::String(grant.config.refresh_sentinel.clone()),
            );
        }
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

fn remember_token(tokens: &mut Vec<Zeroizing<String>>, token: &str) {
    if !token.is_empty() && !tokens.iter().any(|seen| seen.as_str() == token) {
        tokens.push(Zeroizing::new(token.to_string()));
    }
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
) -> io::Result<u64> {
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
    response.generation.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth broker omitted generation",
        )
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

fn parse_https_endpoint(endpoint: &str) -> io::Result<(String, u16, String)> {
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
    Ok((host.to_ascii_lowercase(), port, format!("/{target}")))
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

fn replace_bearer_header(data: &[u8], sentinel: &[u8], token: &[u8]) -> Vec<u8> {
    let marker = [b"authorization: bearer ".as_slice(), sentinel].concat();
    let marker = marker
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let lower = data.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    let Some(start) = lower
        .windows(marker.len())
        .position(|window| window == marker)
    else {
        return data.to_vec();
    };
    let value_start = start + b"authorization: bearer ".len();
    let mut output = data.to_vec();
    output.splice(
        value_start..value_start + sentinel.len(),
        token.iter().copied(),
    );
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
    use super::*;
    use crate::secrets::config::HostPattern;
    use tokio::net::UnixListener;

    fn config() -> OAuthSecret {
        OAuthSecret {
            broker_endpoint: "/tmp/broker.sock".into(),
            grant_id: "opaque-grant".into(),
            token_endpoint: "https://auth.example.com/oauth/token".into(),
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
        OAuthConnection {
            grants: vec![loaded(config())],
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

    fn loaded(config: OAuthSecret) -> LoadedGrant {
        LoadedGrant {
            config,
            endpoint_host: "auth.example.com".into(),
            endpoint_port: 443,
            endpoint_target: "/oauth/token".into(),
            access: Zeroizing::new("real-access".into()),
            refresh: Zeroizing::new("real-refresh".into()),
            generation: 4,
            lease: None,
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
        assert_eq!(
            parse_https_endpoint("https://auth.example.com/oauth/token?aud=x").unwrap(),
            ("auth.example.com".into(), 443, "/oauth/token?aud=x".into())
        );
        assert_eq!(
            parse_https_endpoint("https://auth.example.com:8443/oauth/token").unwrap(),
            ("auth.example.com".into(), 8443, "/oauth/token".into())
        );
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
        connection.exchanges.push_back(Some(0));
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnot-json";
        assert!(connection.transform_responses(response).await.is_err());
    }

    #[tokio::test]
    async fn non_object_token_errors_fail_closed_without_output() {
        for body in ["not-json", r#""credential""#, r#"["credential"]"#] {
            let mut connection = connection();
            connection.exchanges.push_back(Some(0));
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
        for response in [
            b"HTTP/1.1 400 Bad Request\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".as_slice(),
            b"HTTP/1.1 400 Bad Request\r\n\r\nsecret".as_slice(),
            b"HTTP/1.1 400 Bad Request\r\nContent-Encoding: gzip\r\nContent-Length: 6\r\n\r\nsecret".as_slice(),
        ] {
            let mut connection = connection();
            connection.token_connection = Some(true);
            connection.exchanges.push_back(Some(0));
            assert!(connection.transform_responses(response).await.is_err());
        }
    }

    #[tokio::test]
    async fn eof_with_buffered_token_response_fails_closed() {
        let mut connection = connection();
        connection.token_connection = Some(true);
        connection.exchanges.push_back(Some(0));
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
        let connection = connection();
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
        connection.exchanges.push_back(Some(0));
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
        let mut connection = OAuthConnection {
            grants: vec![loaded(first), loaded(second)],
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
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
        };
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
        assert_eq!(connection.exchanges.pop_front(), Some(Some(1)));
    }

    #[tokio::test]
    async fn shared_endpoint_without_a_sentinel_is_rejected() {
        let first = config();
        let mut second = config();
        second.grant_id = "other-grant".into();
        second.access_sentinel = "$OTHER_ACCESS".into();
        second.refresh_sentinel = "$OTHER_REFRESH".into();
        let mut connection = OAuthConnection {
            grants: vec![loaded(first), loaded(second)],
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            exchanges: VecDeque::new(),
            token_connection: None,
            connection_port: 443,
            response_scrub_buffer: Vec::new(),
            response_scrub_framing: Vec::new(),
            response_scrub_tail: Vec::new(),
            response_scrub_state: ResponseScrubState::Headers,
            response_head_requests: VecDeque::new(),
            seen_tokens: vec![],
            request_state: RequestState::Headers,
        };
        let request = b"POST /oauth/token HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";

        let error = connection
            .transform_requests(request, "auth.example.com")
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
}
