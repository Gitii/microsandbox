//! OAuth token substitution and host-broker coordination.

use std::collections::VecDeque;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::config::OAuthSecret;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_OAUTH_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BROKER_RESPONSE_BYTES: u64 = 1024 * 1024;
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
}

struct LoadedGrant {
    config: OAuthSecret,
    endpoint_host: String,
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

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OAuthConnection {
    /// Load grants relevant to this TLS SNI. Broker failures reject the connection.
    pub(crate) async fn new(configs: &[OAuthSecret], sni: &str) -> io::Result<Self> {
        let mut grants = Vec::new();
        for config in configs {
            let (endpoint_host, endpoint_target) = parse_https_endpoint(&config.token_endpoint)?;
            let relevant = endpoint_host.eq_ignore_ascii_case(sni)
                || config.inject_hosts.iter().any(|host| host.matches(sni));
            if !relevant {
                continue;
            }
            let loaded = broker_load(config).await?;
            grants.push(LoadedGrant {
                config: config.clone(),
                endpoint_host,
                endpoint_target,
                access: Zeroizing::new(loaded.access),
                refresh: Zeroizing::new(loaded.refresh),
                generation: loaded.generation,
                lease: None,
            });
        }
        Ok(Self {
            grants,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            exchanges: VecDeque::new(),
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Transform complete HTTP/1.1 requests and record token exchanges.
    pub(crate) async fn transform_requests(
        &mut self,
        data: &[u8],
        sni: &str,
    ) -> io::Result<Vec<u8>> {
        self.request_buffer.extend_from_slice(data);
        enforce_limit(&self.request_buffer)?;
        let mut output = Vec::new();
        loop {
            let Some(message) = parse_http_message(&self.request_buffer)? else {
                break;
            };
            let request = &self.request_buffer[..message.total_len];
            let request_line = first_header_line(message.headers)?;
            let target = request_line
                .split_whitespace()
                .nth(1)
                .ok_or_else(invalid_http)?;
            let endpoint_grants = self
                .grants
                .iter()
                .enumerate()
                .filter(|(_, grant)| {
                    grant.endpoint_host.eq_ignore_ascii_case(sni) && grant.endpoint_target == target
                })
                .collect::<Vec<_>>();
            let matching_grants = endpoint_grants
                .iter()
                .filter(|(_, grant)| {
                    contains_bytes(request, grant.config.access_sentinel.as_bytes())
                        || contains_bytes(request, grant.config.refresh_sentinel.as_bytes())
                })
                .map(|(index, _)| *index)
                .collect::<Vec<_>>();
            let token_grant = match matching_grants.as_slice() {
                [index] => Some(*index),
                [] if endpoint_grants.len() == 1 => Some(endpoint_grants[0].0),
                [] => None,
                _ => return Err(invalid_http()),
            };
            let mut rewritten = request.to_vec();
            if let Some(index) = token_grant
                && self.grants[index].lease.is_none()
            {
                let (loaded, lease) = broker_acquire(&self.grants[index].config).await?;
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
                validate_token_request_content_type(message.headers)?;
                rewritten = update_content_length(&rewritten)?;
                self.exchanges.push_back(Some(index));
            } else {
                self.exchanges.push_back(None);
            }
            output.extend_from_slice(&rewritten);
            self.request_buffer.drain(..message.total_len);
        }
        Ok(output)
    }

    /// Buffer and sanitize token endpoint responses before releasing them.
    pub(crate) async fn transform_responses(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        self.response_buffer.extend_from_slice(data);
        enforce_limit(&self.response_buffer)?;
        let mut output = Vec::new();
        loop {
            let Some(message) = parse_http_message(&self.response_buffer)? else {
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
        let mut response = [headers, body].concat();
        response = replace_all(
            &response,
            grant.access.as_bytes(),
            grant.config.access_sentinel.as_bytes(),
        );
        response = replace_all(
            &response,
            grant.refresh.as_bytes(),
            grant.config.refresh_sentinel.as_bytes(),
        );
        update_content_length(&response)
    }

    fn scrub_tokens(&self, mut response: Vec<u8>) -> Vec<u8> {
        for grant in &self.grants {
            response = replace_all(
                &response,
                grant.access.as_bytes(),
                grant.config.access_sentinel.as_bytes(),
            );
            response = replace_all(
                &response,
                grant.refresh.as_bytes(),
                grant.config.refresh_sentinel.as_bytes(),
            );
        }
        response
    }
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

fn parse_https_endpoint(endpoint: &str) -> io::Result<(String, String)> {
    let rest = endpoint.strip_prefix("https://").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "OAuth endpoint is not HTTPS")
    })?;
    let (authority, target) = rest
        .split_once('/')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "OAuth endpoint has no path"))?;
    let host = authority.split(':').next().unwrap_or_default();
    if host.is_empty() || authority.contains('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid OAuth endpoint authority",
        ));
    }
    Ok((host.to_ascii_lowercase(), format!("/{target}")))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
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

fn parse_http_message(data: &[u8]) -> io::Result<Option<HttpMessage<'_>>> {
    let Some(boundary) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(None);
    };
    let header_end = boundary + 4;
    let headers = &data[..header_end];
    let text = std::str::from_utf8(headers).map_err(|_| invalid_http())?;
    if text.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && !value.trim().eq_ignore_ascii_case("identity")
        })
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OAuth HTTP/1 chunked messages are unsupported",
        ));
    }
    let mut lengths = text.lines().filter_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
    });
    let content_length = match lengths.next() {
        Some(Ok(length)) => length,
        Some(Err(_)) => return Err(invalid_http()),
        None => 0,
    };
    if lengths.next().is_some() {
        return Err(invalid_http());
    }
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

fn validate_token_request_content_type(headers: &[u8]) -> io::Result<()> {
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
        }
    }

    fn loaded(config: OAuthSecret) -> LoadedGrant {
        LoadedGrant {
            config,
            endpoint_host: "auth.example.com".into(),
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
        let request = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer $MSB_OAUTH_ACCESS_123\r\n\r\n";
        let mut allowed = connection();
        allowed.grants[0].config.broker_endpoint = socket.to_string_lossy().into_owned();
        let output = allowed
            .transform_requests(request, "api.example.com")
            .await
            .unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("Bearer real-access")
        );

        let mut denied = connection();
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
            "POST /oauth/token HTTP/1.1\r\nHost: auth.example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
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
    async fn exact_token_endpoint_does_not_match_other_path() {
        let request = b"POST /oauth/token/other HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let mut connection = connection();
        connection
            .transform_requests(request, "auth.example.com")
            .await
            .unwrap();
        assert_eq!(connection.exchanges.pop_front(), Some(None));
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
        let parsed = parse_http_message(&rebuilt).unwrap().unwrap();
        let output: Value = serde_json::from_slice(parsed.body).unwrap();
        assert_eq!(output["scope"], "read");
        assert_eq!(output["expires_in"], 3600);
        assert_eq!(output["access_token"], "ACCESS");
    }

    #[test]
    fn endpoint_parser_requires_https_and_preserves_exact_target() {
        assert_eq!(
            parse_https_endpoint("https://auth.example.com/oauth/token?aud=x").unwrap(),
            ("auth.example.com".into(), "/oauth/token?aud=x".into())
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
        let mut connection = OAuthConnection::new(&[oauth], "auth.example.com")
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

    #[test]
    fn error_response_token_fields_are_never_released() {
        let connection = connection();
        let headers = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n";
        let body = br#"{"error":"invalid_grant","error_description":"real-access and real-refresh","nested":{"access":"real-access"}}"#;
        let output = connection.sanitize_token_error(0, headers, body).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("invalid_grant"));
        assert!(output.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(output.contains("$MSB_OAUTH_REFRESH_123"));
        assert!(!output.contains("real-access"));
        assert!(!output.contains("real-refresh"));
    }

    #[test]
    fn api_response_echoes_are_scrubbed() {
        let connection = connection();
        let output = connection.scrub_tokens(b"echoed real-access and real-refresh".to_vec());
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("$MSB_OAUTH_ACCESS_123"));
        assert!(output.contains("$MSB_OAUTH_REFRESH_123"));
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
}
