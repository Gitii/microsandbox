//! HTTP and SSE plumbing for the cloud backend.
//!
//! Route-level methods on [`CloudBackend`] (sandbox lifecycle, volumes, log
//! streaming), the SSE parser behind the log stream, and the shared
//! decode/error helpers they route through. Connection construction (URL,
//! API key, HTTP client) stays in the parent module.

use std::pin::Pin;

use bytes::Bytes;
use futures::{StreamExt, stream};
use reqwest::Response;
use reqwest::header::{ACCEPT, HeaderName, HeaderValue};
use serde::Deserialize;
use tokio::sync::mpsc;

use super::{CloudBackend, sandbox::CloudCreateBody, volume::CloudVolume};
use crate::backend::sandbox::LogStream;
use crate::error::{Operation, UnsupportedReason};
use crate::logs::{LogCursor, LogEntry, LogOptions, LogSource, LogStreamOptions, LogStreamStart};
use crate::{MicrosandboxError, MicrosandboxResult};
use microsandbox_types::{
    CloudCreateSandboxResponse, CloudErrorBody, CloudMessageResponse, CloudPaginated,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CloudLogPayload {
    source: String,
    ts: chrono::DateTime<chrono::Utc>,
    text: String,
}

#[derive(Default)]
struct CloudSseEvent {
    id: Option<String>,
    event: Option<String>,
    data: String,
}

enum CloudSseItem {
    Entry(LogEntry),
    End,
    Ignore,
}

//--------------------------------------------------------------------------------------------------
// Methods: Sandbox lifecycle
//
// HTTP dispatch for the SDK's sandbox lifecycle ops, hitting msb-cloud's
// API-key-authenticated routes (`/v1/sandboxes/*` and `/v1/sandboxes/by-name/*`).
//--------------------------------------------------------------------------------------------------

impl CloudBackend {
    /// `POST /v1/sandboxes` (optionally `?start=true`).
    ///
    /// Pass `start=true` to atomically create-and-start in a single round-trip
    /// — mirrors the `POST /v1/sandboxes?start=true` shorthand on msb-cloud.
    pub(in crate::backend) async fn create_sandbox(
        &self,
        req: &CloudCreateBody,
        start: bool,
    ) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let path = if start {
            "/v1/sandboxes?start=true"
        } else {
            "/v1/sandboxes"
        };
        let url = format!("{}{}", self.url, path);
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| cloud_io_error("POST /v1/sandboxes", e))?;
        decode_json(resp, "POST /v1/sandboxes").await
    }

    /// `GET /v1/sandboxes` — paginated.
    pub async fn list_sandboxes(
        &self,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> MicrosandboxResult<CloudPaginated<CloudCreateSandboxResponse>> {
        let mut url = format!("{}/v1/sandboxes", self.url);
        let mut query = Vec::new();
        if let Some(c) = cursor {
            query.push(format!("cursor={}", urlencoding(c)));
        }
        if let Some(l) = limit {
            query.push(format!("limit={l}"));
        }
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| cloud_io_error("GET /v1/sandboxes", e))?;
        decode_json(resp, "GET /v1/sandboxes").await
    }

    /// `GET /v1/sandboxes/by-name/:name`.
    pub async fn get_sandbox(&self, name: &str) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let url = format!("{}/v1/sandboxes/by-name/{}", self.url, urlencoding(name));
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| cloud_io_error("GET /v1/sandboxes/by-name/:name", e))?;
        decode_json(resp, "GET /v1/sandboxes/by-name/:name").await
    }

    /// `POST /v1/sandboxes/by-name/:name/start`.
    pub async fn start_sandbox(
        &self,
        name: &str,
    ) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let url = format!(
            "{}/v1/sandboxes/by-name/{}/start",
            self.url,
            urlencoding(name)
        );
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| cloud_io_error("POST start", e))?;
        decode_json(resp, "POST /v1/sandboxes/by-name/:name/start").await
    }

    /// `POST /v1/sandboxes/by-name/:name/stop`.
    pub async fn stop_sandbox(&self, name: &str) -> MicrosandboxResult<CloudCreateSandboxResponse> {
        let url = format!(
            "{}/v1/sandboxes/by-name/{}/stop",
            self.url,
            urlencoding(name)
        );
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| cloud_io_error("POST stop", e))?;
        decode_json(resp, "POST /v1/sandboxes/by-name/:name/stop").await
    }

    /// `DELETE /v1/sandboxes/by-name/:name`. Returns the typed `MessageResponse`
    /// msb-cloud emits.
    pub async fn destroy_sandbox(&self, name: &str) -> MicrosandboxResult<CloudMessageResponse> {
        let url = format!("{}/v1/sandboxes/by-name/{}", self.url, urlencoding(name));
        let resp = self
            .http
            .delete(&url)
            .send()
            .await
            .map_err(|e| cloud_io_error("DELETE /v1/sandboxes/by-name/:name", e))?;
        decode_json(resp, "DELETE /v1/sandboxes/by-name/:name").await
    }

    /// Stream logs from `GET /v1/sandboxes/:id/logs`.
    ///
    /// msb-cloud exposes logs as Server-Sent Events keyed by sandbox UUID, so
    /// the SDK resolves the current name to a cloud sandbox first. The cloud
    /// endpoint is streaming-only and requires a running sandbox, so callers
    /// must set `follow: true`.
    pub async fn log_stream(
        &self,
        name: &str,
        opts: &LogStreamOptions,
    ) -> MicrosandboxResult<LogStream> {
        if !opts.follow {
            return Err(MicrosandboxError::unsupported(
                Operation::SandboxLogStreamNoFollow,
                UnsupportedReason::UseInstead(Operation::SandboxLogStreamFollow),
            ));
        }

        let sandbox = self.get_sandbox(name).await?;
        self.open_log_stream_by_id(&sandbox.id, opts).await
    }

    /// Read a bounded log snapshot.
    pub async fn logs(&self, _name: &str, _opts: &LogOptions) -> MicrosandboxResult<Vec<LogEntry>> {
        Err(MicrosandboxError::unsupported(
            Operation::SandboxLogs,
            UnsupportedReason::UseInstead(Operation::SandboxLogStreamFollow),
        ))
    }

    async fn open_log_stream_by_id(
        &self,
        sandbox_id: &str,
        opts: &LogStreamOptions,
    ) -> MicrosandboxResult<LogStream> {
        let mut query = Vec::new();
        let cloud_sources = cloud_log_sources(&opts.sources)?;
        if !cloud_sources.is_empty() {
            query.push(format!("sources={}", cloud_sources.join(",")));
        }

        let mut url = format!("{}/v1/sandboxes/{}/logs", self.url, urlencoding(sandbox_id));
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }

        let mut request = self
            .http
            .get(&url)
            .header(ACCEPT, HeaderValue::from_static("text/event-stream"));
        if let LogStreamStart::From(cursor) = &opts.start {
            request = request.header(HeaderName::from_static("last-event-id"), cursor.to_string());
        }

        let resp = request
            .send()
            .await
            .map_err(|e| cloud_io_error("GET /v1/sandboxes/:id/logs", e))?;
        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            let typed: Option<CloudErrorBody> = serde_json::from_str(&body_text).ok();
            return Err(cloud_http_error(
                status.as_u16(),
                typed.as_ref(),
                &body_text,
                "GET /v1/sandboxes/:id/logs",
            ));
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let opts = opts.clone();
        tokio::spawn(async move {
            parse_cloud_log_sse(Box::pin(resp.bytes_stream()), opts, tx).await;
        });

        Ok(Box::pin(stream::unfold(rx, |mut rx| async {
            rx.recv().await.map(|item| (item, rx))
        })))
    }

    //--------------------------------------------------------------------------------------------------
    // Methods: Volumes
    //--------------------------------------------------------------------------------------------------

    /// `GET /v1/volumes`.
    pub(in crate::backend) async fn list_volumes(&self) -> MicrosandboxResult<Vec<CloudVolume>> {
        let url = format!("{}/v1/volumes", self.url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| cloud_io_error("GET /v1/volumes", e))?;
        decode_json(resp, "GET /v1/volumes").await
    }

    /// `POST /v1/volumes`.
    pub(in crate::backend) async fn create_volume(
        &self,
        name: &str,
        capacity_gib: Option<u32>,
        labels: &[(String, String)],
    ) -> MicrosandboxResult<CloudVolume> {
        let labels: std::collections::BTreeMap<&str, &str> = labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut body = serde_json::json!({ "name": name, "labels": labels });
        if let Some(gib) = capacity_gib {
            body["capacity_gib"] = gib.into();
        }
        let url = format!("{}/v1/volumes", self.url);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| cloud_io_error("POST /v1/volumes", e))?;
        decode_json(resp, "POST /v1/volumes").await
    }

    /// `DELETE /v1/volumes/:id`.
    pub(in crate::backend) async fn delete_volume(
        &self,
        id: &str,
    ) -> MicrosandboxResult<CloudMessageResponse> {
        let url = format!("{}/v1/volumes/{}", self.url, urlencoding(id));
        let resp = self
            .http
            .delete(&url)
            .send()
            .await
            .map_err(|e| cloud_io_error("DELETE /v1/volumes/:id", e))?;
        decode_json(resp, "DELETE /v1/volumes/:id").await
    }

    /// Resolve a named volume. The cloud addresses volumes by id, so the SDK's
    /// name-based calls list and match on the user-facing name.
    pub(in crate::backend) async fn find_volume(
        &self,
        name: &str,
    ) -> MicrosandboxResult<CloudVolume> {
        let volumes = self.list_volumes().await?;
        volumes
            .into_iter()
            .find(|volume| volume.name.as_deref() == Some(name))
            .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.to_string()))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: HTTP helpers
//--------------------------------------------------------------------------------------------------

/// Parse a JSON response into `T`, mapping HTTP errors to typed
/// `MicrosandboxError` variants. Tries to decode msb-cloud's typed error body
/// for richer messages on 4xx/5xx.
async fn decode_json<T: serde::de::DeserializeOwned>(
    resp: Response,
    op: &str,
) -> MicrosandboxResult<T> {
    let status = resp.status();
    if status.is_success() {
        return resp
            .json::<T>()
            .await
            .map_err(|e| MicrosandboxError::Custom(format!("{op}: failed to decode body: {e}")));
    }
    let body_text = resp.text().await.unwrap_or_default();
    let typed: Option<CloudErrorBody> = serde_json::from_str(&body_text).ok();
    Err(cloud_http_error(
        status.as_u16(),
        typed.as_ref(),
        &body_text,
        op,
    ))
}

fn cloud_io_error(op: &str, e: reqwest::Error) -> MicrosandboxError {
    tracing::debug!(operation = op, error = %e, "cloud backend transport error");
    MicrosandboxError::Http(e)
}

fn cloud_http_error(
    status: u16,
    body: Option<&CloudErrorBody>,
    raw_body: &str,
    op: &str,
) -> MicrosandboxError {
    let code = cloud_error_code(body).map(ToOwned::to_owned);
    let summary = cloud_error_message(body)
        .or_else(|| (!raw_body.trim().is_empty()).then_some(raw_body.trim()))
        .unwrap_or("no response body");
    let message = format!("{op}: {summary}");

    match code.as_deref() {
        Some("sandbox_not_found") => return MicrosandboxError::SandboxNotFound(message),
        Some("name_already_exists") => return MicrosandboxError::SandboxAlreadyExists(message),
        Some("invalid_request") | Some("invalid_sandbox_config") => {
            return MicrosandboxError::InvalidConfig(message);
        }
        Some("orchestrator_unreachable") | Some("nomad_job_failed") => {
            return MicrosandboxError::Runtime(message);
        }
        _ => {}
    }

    match status {
        400 | 422 => MicrosandboxError::InvalidConfig(message),
        404 if op.contains("/v1/volumes") => MicrosandboxError::VolumeNotFound(message),
        404 => MicrosandboxError::SandboxNotFound(message),
        409 if op == "POST /v1/sandboxes" => MicrosandboxError::SandboxAlreadyExists(message),
        409 if op == "POST /v1/volumes" => MicrosandboxError::VolumeAlreadyExists(message),
        502 => MicrosandboxError::Runtime(message),
        _ => MicrosandboxError::CloudHttp {
            status,
            code,
            message,
        },
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Logs
//--------------------------------------------------------------------------------------------------

async fn parse_cloud_log_sse(
    mut chunks: Pin<Box<dyn futures::Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    opts: LogStreamOptions,
    tx: mpsc::UnboundedSender<MicrosandboxResult<LogEntry>>,
) {
    let mut buffer = Vec::new();

    while let Some(chunk) = chunks.next().await {
        match chunk {
            Ok(bytes) => buffer.extend_from_slice(&bytes),
            Err(error) => {
                let _ = tx.send(Err(MicrosandboxError::Http(error)));
                return;
            }
        }

        while let Some((block, consumed)) = take_sse_block(&buffer) {
            buffer.drain(..consumed);
            match parse_cloud_sse_item(&block, &opts) {
                Ok(CloudSseItem::Entry(entry)) => {
                    if tx.send(Ok(entry)).is_err() {
                        return;
                    }
                }
                Ok(CloudSseItem::End) => return,
                Ok(CloudSseItem::Ignore) => {}
                Err(error) => {
                    let _ = tx.send(Err(error));
                    return;
                }
            }
        }
    }
}

fn take_sse_block(buffer: &[u8]) -> Option<(Vec<u8>, usize)> {
    for i in 0..buffer.len() {
        if i + 3 < buffer.len() && &buffer[i..i + 4] == b"\r\n\r\n" {
            return Some((buffer[..i].to_vec(), i + 4));
        }
        if i + 1 < buffer.len() && &buffer[i..i + 2] == b"\n\n" {
            return Some((buffer[..i].to_vec(), i + 2));
        }
    }
    None
}

fn parse_cloud_sse_item(block: &[u8], opts: &LogStreamOptions) -> MicrosandboxResult<CloudSseItem> {
    let event = parse_cloud_sse_event(block)?;
    match event.event.as_deref().unwrap_or("message") {
        "log" => cloud_log_event_to_entry(event, opts),
        "end" => Ok(CloudSseItem::End),
        _ => Ok(CloudSseItem::Ignore),
    }
}

fn parse_cloud_sse_event(block: &[u8]) -> MicrosandboxResult<CloudSseEvent> {
    let text = std::str::from_utf8(block)
        .map_err(|e| MicrosandboxError::Custom(format!("invalid cloud log SSE utf-8: {e}")))?;
    let mut event = CloudSseEvent::default();

    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = line
            .split_once(':')
            .map(|(field, value)| (field, value.strip_prefix(' ').unwrap_or(value)))
            .unwrap_or((line, ""));
        match field {
            "id" => event.id = Some(value.to_string()),
            "event" => event.event = Some(value.to_string()),
            "data" => {
                if !event.data.is_empty() {
                    event.data.push('\n');
                }
                event.data.push_str(value);
            }
            _ => {}
        }
    }

    Ok(event)
}

fn cloud_log_event_to_entry(
    event: CloudSseEvent,
    opts: &LogStreamOptions,
) -> MicrosandboxResult<CloudSseItem> {
    let payload: CloudLogPayload = serde_json::from_str(&event.data)
        .map_err(|e| MicrosandboxError::Custom(format!("invalid cloud log event payload: {e}")))?;

    if let Some(until) = opts.until
        && payload.ts >= until
    {
        return Ok(CloudSseItem::End);
    }
    if let LogStreamStart::Since(since) = opts.start
        && payload.ts < since
    {
        return Ok(CloudSseItem::Ignore);
    }

    let source = parse_cloud_log_source(&payload.source)?;
    let cursor = match event.id {
        Some(id) if !id.is_empty() => id
            .parse::<LogCursor>()
            .map_err(|e| MicrosandboxError::InvalidCursor(e.to_string()))?,
        _ => LogCursor::empty(),
    };

    Ok(CloudSseItem::Entry(LogEntry {
        timestamp: payload.ts,
        source,
        session_id: None,
        data: Bytes::from(payload.text),
        cursor,
    }))
}

fn cloud_log_sources(requested: &[LogSource]) -> MicrosandboxResult<Vec<String>> {
    if requested.is_empty() {
        return Ok(Vec::new());
    }

    LogSource::effective(requested)
        .into_iter()
        .map(|source| match source {
            LogSource::Stdout => Ok("stdout".to_string()),
            LogSource::Stderr => Ok("stderr".to_string()),
            LogSource::System => Ok("system".to_string()),
            LogSource::Output => Err(MicrosandboxError::unsupported(
                Operation::SandboxLogStream,
                UnsupportedReason::ConfigField("LogSource::Output"),
            )),
        })
        .collect()
}

fn parse_cloud_log_source(source: &str) -> MicrosandboxResult<LogSource> {
    match source {
        "stdout" => Ok(LogSource::Stdout),
        "stderr" => Ok(LogSource::Stderr),
        "system" => Ok(LogSource::System),
        "output" => Ok(LogSource::Output),
        other => Err(MicrosandboxError::Custom(format!(
            "unknown cloud log source: {other}"
        ))),
    }
}

fn cloud_error_code(body: Option<&CloudErrorBody>) -> Option<&str> {
    body.and_then(|body| {
        body.error
            .as_ref()
            .and_then(|err| err.code.as_deref())
            .or(body.code.as_deref())
    })
}

fn cloud_error_message(body: Option<&CloudErrorBody>) -> Option<&str> {
    body.and_then(|body| {
        body.error
            .as_ref()
            .and_then(|err| err.message.as_deref())
            .or(body.message.as_deref())
    })
}

/// Minimal percent-encoding for path segments. Avoids pulling in another crate
/// for one call site. Encodes characters outside the unreserved set per RFC
/// 3986 (`ALPHA / DIGIT / "-" / "." / "_" / "~"`).
pub(super) fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_http_error_uses_nested_error_body() {
        let body: CloudErrorBody = serde_json::from_str(
            r#"{"error":{"code":"sandbox_not_found","message":"sandbox missing"}}"#,
        )
        .unwrap();
        let err = cloud_http_error(404, Some(&body), "", "GET /v1/sandboxes/by-name/:name");
        assert!(
            matches!(err, MicrosandboxError::SandboxNotFound(msg) if msg.contains("sandbox missing"))
        );
    }

    #[test]
    fn cloud_http_error_maps_create_conflict_to_already_exists() {
        let body: CloudErrorBody = serde_json::from_str(
            r#"{"error":{"code":"name_already_exists","message":"name taken"}}"#,
        )
        .unwrap();
        let err = cloud_http_error(409, Some(&body), "", "POST /v1/sandboxes");
        assert!(
            matches!(err, MicrosandboxError::SandboxAlreadyExists(msg) if msg.contains("name taken"))
        );
    }

    #[test]
    fn cloud_log_sse_event_maps_to_log_entry() {
        let cursor = LogCursor::empty().to_string();
        let block = format!(
            "id: {cursor}\nevent: log\ndata: {{\"source\":\"stdout\",\"ts\":\"2026-05-31T10:00:00Z\",\"text\":\"hello\"}}"
        );

        let item = parse_cloud_sse_item(block.as_bytes(), &LogStreamOptions::default()).unwrap();

        let CloudSseItem::Entry(entry) = item else {
            panic!("expected log entry");
        };
        assert_eq!(entry.source, LogSource::Stdout);
        assert_eq!(entry.data, Bytes::from_static(b"hello"));
        assert_eq!(entry.cursor.to_string(), cursor);
    }

    #[test]
    fn cloud_log_sse_since_filters_old_entries() {
        let opts = LogStreamOptions {
            start: LogStreamStart::Since(
                "2026-05-31T10:00:01Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap(),
            ),
            ..Default::default()
        };
        let block =
            b"event: log\ndata: {\"source\":\"stderr\",\"ts\":\"2026-05-31T10:00:00Z\",\"text\":\"old\"}";

        let item = parse_cloud_sse_item(block, &opts).unwrap();

        assert!(matches!(item, CloudSseItem::Ignore));
    }

    #[test]
    fn cloud_log_sources_rejects_output_until_cloud_supports_it() {
        let err = cloud_log_sources(&[LogSource::Output]).unwrap_err();

        assert!(matches!(err, MicrosandboxError::Unsupported { .. }));
    }
}
